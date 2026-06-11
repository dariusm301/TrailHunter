from __future__ import annotations
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
)

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _ts(event: NormalizedEvent) -> datetime:
    return event.timestamp or None

def _action(event: NormalizedEvent) -> str:
    return (event.event.action or "") if event.event else ""

def _process_name(event: NormalizedEvent) -> str:
    return (event.process.name or "").lower() if event.process else ""

def _src_port(event: NormalizedEvent) -> Optional[int]:
    return event.source.port if event.source else None

def _dst_port(event: NormalizedEvent) -> Optional[int]:
    return event.destination.port if event.destination else None

def _dst_ip(event: NormalizedEvent) -> Optional[str]:
    return event.destination.address if event.destination else None

def _src_ip(event: NormalizedEvent) -> Optional[str]:
    return event.source.address if event.source else None


# ─────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────

_SUSPICIOUS_PROCESSES = re.compile(
    r"^(cmd|powershell|wscript|cscript|mshta|regsvr32"
    r"|rundll32|certutil|bitsadmin|wmic|msiexec|nc|ncat|netcat)"
    r"(\.exe)?$", 
    re.IGNORECASE
)

_SUSPICIOUS_PORTS = {
    4444, 4445, 4446, 1234, 5555, 5554,
    8888, 9001, 9999, 6666, 2222, 31337,
    1337, 8080, 8443, 8000
}

_LEGITIMATE_PORTS = {80, 443, 53, 8080, 8443, 3389, 445, 139, 135}


# ═════════════════════════════════════════════
# PER-EVENT RULES
# ═════════════════════════════════════════════

class SuspiciousProcessListeningRule(PerEventRule):
    """Suspicious process in LISTEN state — potential backdoor."""
    rule_id = "NET_SUSPICIOUS_LISTENER_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _action(event) not in ("tcp_listen", "listening_port"):
            return None

        process = _process_name(event)
        if not _SUSPICIOUS_PROCESSES.match(process):
            return None

        port = _src_port(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Process Listening",
            rule_type="per_event",
            severity=Severity.CRITICAL,
            confidence=0.92,
            technique_id="T1571",
            technique_name="Non-Standard Port",
            tactic=MitreTactic.COMMAND_AND_CONTROL,
            kill_chain_phase=KillChainPhase.COMMAND_AND_CONTROL,
            tags=["backdoor", "listening", "network", "live"],
            source="network",
            description=f"'{process}' is listening on port {port} — possible backdoor",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "process": process,
                "pid": event.process.pid if event.process else None,
                "listening_port": port,
            }
        )


class SuspiciousPortListeningRule(PerEventRule):
    """Known port for reverse shell in state LISTEN."""
    rule_id = "NET_SUSPICIOUS_PORT_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _action(event) not in ("tcp_listen", "listening_port"):
            return None

        port = _src_port(event)
        if port not in _SUSPICIOUS_PORTS:
            return None

        process = _process_name(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Port Listening",
            rule_type="per_event",
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1571",
            technique_name="Non-Standard Port",
            tactic=MitreTactic.COMMAND_AND_CONTROL,
            kill_chain_phase=KillChainPhase.COMMAND_AND_CONTROL,
            tags=["reverse_shell", "listening", "network", "live"],
            source="network",
            description=f"Suspicious port {port} in LISTEN — process: '{process}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "port": port,
                "process": process,
                "pid": event.process.pid if event.process else None,
            }
        )


class ReverseShellConnectionRule(PerEventRule):
    """ESTABLISHED Connection: suspect process + suspicious port."""
    rule_id = "NET_REVERSE_SHELL_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _action(event) not in ("tcp_established", "tcp_closewait"):
            return None

        process = _process_name(event)
        dst_port = _dst_port(event)
        dst_ip = _dst_ip(event)

        is_suspicious_process = bool(_SUSPICIOUS_PROCESSES.match(process))
        is_suspicious_port = dst_port in _SUSPICIOUS_PORTS

        score = sum([is_suspicious_process, is_suspicious_port])
        if score < 2:
            return None

        if score == 3:
            severity = Severity.CRITICAL
            confidence = 0.97
            description = f"Reverse shell active: '{process}' → {dst_ip}:{dst_port}"
        elif is_suspicious_process and is_suspicious_port:
            severity = Severity.CRITICAL
            confidence = 0.93
            description = f"Possible reverse shell: '{process}' → {dst_ip}:{dst_port}"
        else:
            severity = Severity.HIGH
            confidence = 0.80
            description = f"Active suspicious connection: '{process}' → {dst_ip}:{dst_port}"

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Active Reverse Shell Connection",
            rule_type="per_event",
            severity=severity,
            confidence=confidence,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MitreTactic.COMMAND_AND_CONTROL,
            kill_chain_phase=KillChainPhase.COMMAND_AND_CONTROL,
            tags=["reverse_shell", "established", "network", "live"],
            source="network",
            description=description,
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "process": process,
                "pid": event.process.pid if event.process else None,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "suspicious_process": is_suspicious_process,
                "suspicious_port": is_suspicious_port,
            }
        )


class SuspiciousOutboundConnectionRule(PerEventRule):
    """Suspicious process with active outbound connection — even on legitimate ports."""
    rule_id = "NET_SUSPICIOUS_OUTBOUND_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _action(event) not in ("tcp_established", "tcp_closewait"):
            return None

        process = _process_name(event)
        if not _SUSPICIOUS_PROCESSES.match(process):
            return None

        dst_port = _dst_port(event)
        dst_ip = _dst_ip(event)

        if dst_port in _SUSPICIOUS_PORTS:
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Process Outbound Connection",
            rule_type="per_event",
            severity=Severity.HIGH,
            confidence=0.78,
            technique_id="T1071.001",
            technique_name="Application Layer Protocol: Web Protocols",
            tactic=MitreTactic.COMMAND_AND_CONTROL,
            kill_chain_phase=KillChainPhase.COMMAND_AND_CONTROL,
            tags=["outbound", "c2", "network", "live"],
            source="network",
            description=f"'{process}' has an active outbound connection → {dst_ip}:{dst_port}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "process": process,
                "pid": event.process.pid if event.process else None,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            }
        )


class SuspiciousInboundSSHRule(PerEventRule):
    rule_id = "NET_SUSPICIOUS_SSH_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _action(event) != "tcp_established":
            return None
        if _process_name(event) != "sshd":
            return None

        dst_ip = _dst_ip(event)
        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Inbound SSH Connection",
            rule_type="per_event",
            severity=Severity.MEDIUM,
            confidence=0.75,
            technique_id="T1021.004",
            technique_name="Remote Services: SSH",
            tactic=MitreTactic.LATERAL_MOVEMENT,
            kill_chain_phase=KillChainPhase.COMMAND_AND_CONTROL,
            tags=["ssh", "inbound", "network", "live"],
            source="network",
            description=f"SSH connection from {dst_ip}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={"remote_ip": dst_ip, "process": "sshd"}
        )

# ═════════════════════════════════════════════
# AGGREGATE RULES
# ═════════════════════════════════════════════

class ArpPoisoningRule(AggregateRule):
    """ More IP addresses → same MAC address = ARP poisoning."""
    rule_id = "NET_ARP_POISONING_001"

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []
        mac_to_ips: dict[str, list[tuple[int, str]]] = defaultdict(list)

        for i, e in enumerate(events):
            if not e.event or e.event.action != "arp_entry":
                continue
            original = e.event.original or ""
            import ast
            try:
                data = ast.literal_eval(original)
                mac = data.get("mac_address", "").lower()
                ip = data.get("ip_address", "")
                if mac and ip and mac != "ff:ff:ff:ff:ff:ff":
                    mac_to_ips[mac].append((e.id, ip))
            except Exception:
                continue

        for mac, entries in mac_to_ips.items():
            if len(entries) < 2:
                continue

            ids = [event_id for event_id, _ in entries]
            ips = [ip for _, ip in entries]

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="ARP Poisoning Detected",
                rule_type="aggregate",
                severity=Severity.HIGH,
                confidence=0.85,
                technique_id="T1557.002",
                technique_name="ARP Cache Poisoning",
                tactic=MitreTactic.LATERAL_MOVEMENT,
                kill_chain_phase= KillChainPhase.EXPLOITATION,
                tags=["arp", "poisoning", "network", "live"],
                source="network",
                description=f"MAC '{mac}' associated with {len(ips)} IP addresses: {ips}",
                timestamp=events[ids[0]].timestamp if events[ids[0]] else None,
                triggered_by=ids,
                event_count=len(entries),
                extra={"mac": mac, "ip_addresses": ips}
            ))

        return findings


# ─────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────

def get_network_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        SuspiciousProcessListeningRule(),
        SuspiciousPortListeningRule(),
        ReverseShellConnectionRule(),
        SuspiciousOutboundConnectionRule(),
        SuspiciousInboundSSHRule(),
    ]
    aggregate = [
        ArpPoisoningRule(),
    ]
    return per_event, aggregate