from __future__ import annotations
import re
from collections import defaultdict
from typing import Optional

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
)
from ..helpers import _ts, _action, _process_name, _dst_port, _dst_ip, _src_port, _src_ip


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


class SuspiciousProcessListeningRule(PerEventRule):
    rule_id = "NET_SUSPICIOUS_LISTENER_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not (event.network and event.process):
            return None

        process = _process_name(event)
        if not _SUSPICIOUS_PROCESSES.match(process):
            return None

        port = _src_port(event)
        if port and port > 49152:
            return None
        
        state = (event.event.action or "").lower()
        if "bound" in state and "listen" not in state:
            return None 

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
            description=f"'{process}' listening on port {port} — possible backdoor",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "process": process,
                "pid": event.process.pid if event.process else None,
                "listening_port": port,
            }
        )


class SuspiciousPortListeningRule(PerEventRule):
    rule_id = "NET_SUSPICIOUS_PORT_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not event.network:
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
            description=f"Suspicious port {port} open — process: '{process}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "port": port,
                "process": process,
                "pid": event.process.pid if event.process else None,
            }
        )


class ReverseShellConnectionRule(PerEventRule):
    rule_id = "NET_REVERSE_SHELL_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not (event.network and event.destination):
            return None

        process = _process_name(event)
        dst_port = _dst_port(event)
        dst_ip = _dst_ip(event)

        is_suspicious_process = bool(_SUSPICIOUS_PROCESSES.match(process))
        is_suspicious_port = dst_port in _SUSPICIOUS_PORTS

        if not (is_suspicious_process and is_suspicious_port):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Active Reverse Shell Connection",
            rule_type="per_event",
            severity=Severity.CRITICAL,
            confidence=0.93,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MitreTactic.COMMAND_AND_CONTROL,
            kill_chain_phase=KillChainPhase.COMMAND_AND_CONTROL,
            tags=["reverse_shell", "established", "network", "live"],
            source="network",
            description=f"Possible reverse shell: '{process}' → {dst_ip}:{dst_port}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "process": process,
                "pid": event.process.pid if event.process else None,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            }
        )


class SuspiciousOutboundConnectionRule(PerEventRule):
    rule_id = "NET_SUSPICIOUS_OUTBOUND_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not (event.network and event.destination):
            return None

        process = _process_name(event)
        if not _SUSPICIOUS_PROCESSES.match(process):
            return None

        dst_port = _dst_port(event)
        dst_ip = _dst_ip(event)

        if dst_port not in _SUSPICIOUS_PORTS:
            return None
        
        state = (event.event.action or "").lower()
        if "bound" in state and "listen" not in state:
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
            description=f"'{process}' outbound → {dst_ip}:{dst_port}",
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
        if not event.network:
            return None

        process = _process_name(event)
        if process.lower() not in ("sshd", "sshd.exe"):
            return None
        
        src_ip = _src_ip(event)
        if src_ip is None or src_ip.startswith("127.") or src_ip.startswith("::") or src_ip.startswith("0.0.0.0"):
            return None

        dst_ip = _dst_ip(event)
        if dst_ip is None or dst_ip.startswith("127.") or dst_ip.startswith("::") or dst_ip.startswith("0.0.0.0"):
            return None

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

class WebServerInboundConnectionRule(PerEventRule):
    rule_id = "NET_WEBSERVER_INBOUND_001"

    _WEB_SERVER_PROCESSES = re.compile(
        r"^(httpd|apache|apache2|nginx|w3wp|php-cgi)(\.exe)?$",
        re.IGNORECASE
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not (event.network and event.process):
            return None

        process = _process_name(event)
        if not self._WEB_SERVER_PROCESSES.match(process):
            return None

        state = (event.event.action or "").lower()
        if "listen" in state or "bound" in state:
            return None  

        src_ip = _src_ip(event)
        if src_ip is None or src_ip.startswith("127.") or src_ip.startswith("::1") or\
            src_ip.startswith("0.0.0.0") or src_ip.startswith("0:0:0"):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Web Server Inbound Connection",
            rule_type="per_event",
            fusion_key=[("INBOUND_CON_WITH_LOGON", "IP_ADDRESS", src_ip)],
            severity=Severity.INFO,  
            confidence=0.95,              
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic=MitreTactic.INITIAL_ACCESS,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["provenance", "web", "network", "anchor"],
            source="network",
            description=f"Inbound connection to '{process}' from {src_ip}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "process": process,
                "pid": event.process.pid if event.process else None,
                "src_ip": src_ip,
            }
        )


class ArpPoisoningRule(AggregateRule):
    rule_id = "NET_ARP_POISONING_001"

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []
        mac_to_ips: dict[str, list[tuple[int, str]]] = defaultdict(list)

        for e in events:
            mac = (e.source.mac or "").lower() if e.source else ""
            ip  = e.destination.ip if e.destination else ""
            if mac and ip and mac != "ff:ff:ff:ff:ff:ff":
                mac_to_ips[mac].append((e.id, ip))

        for mac, entries in mac_to_ips.items():
            if len(entries) < 2:
                continue

            ids = [eid for eid, _ in entries]
            ips = [ip  for _,  ip in entries]

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="ARP Poisoning Detected",
                rule_type="aggregate",
                severity=Severity.HIGH,
                confidence=0.85,
                technique_id="T1557.002",
                technique_name="ARP Cache Poisoning",
                tactic=MitreTactic.LATERAL_MOVEMENT,
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                tags=["arp", "poisoning", "network", "live"],
                source="network",
                description=f"MAC '{mac}' associated with {len(ips)} IPs: {ips}",
                timestamp=_ts(events[ids[0]]),
                triggered_by=ids,
                event_count=len(entries),
                extra={"mac": mac, "ip_addresses": ips}
            ))

        return findings

    

def get_connection_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        SuspiciousProcessListeningRule(),
        SuspiciousPortListeningRule(),
        ReverseShellConnectionRule(),
        SuspiciousOutboundConnectionRule(),
        SuspiciousInboundSSHRule(),
        WebServerInboundConnectionRule()
    ]
    aggregate = [
        ArpPoisoningRule(),
    ]
    return per_event, aggregate