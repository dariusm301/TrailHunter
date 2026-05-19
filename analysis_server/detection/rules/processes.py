# detection/rules/processes.py

from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict

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
    return event.timestamp or datetime.now(timezone.utc)

def _process_name(event: NormalizedEvent) -> str:
    return (event.process.name or "").lower() if event.process else ""

def _cmdline(event: NormalizedEvent) -> str:
    return (event.process.command_line or "").lower() if event.process else ""

def _username(event: NormalizedEvent) -> str:
    return (event.user.name or "").lower() if event.user else ""

def _pid(event: NormalizedEvent) -> Optional[int]:
    return event.process.pid if event.process else None

def _parent_pid(event: NormalizedEvent) -> Optional[int]:
    if event.process and event.process.parent:
        return event.process.parent.pid
    return None

def _action(event: NormalizedEvent) -> str:
    return (event.event.action or "") if event.event else ""


# ─────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────

_SUSPICIOUS_PROCESSES = re.compile(
    r"^(cmd|powershell|wscript|cscript|mshta|regsvr32"
    r"|rundll32|certutil|bitsadmin|wmic|msiexec|nc|ncat"
    r"|netcat|whoami|net|net1|schtasks|reg)(\.exe)?$",
    re.IGNORECASE
)

_SUSPICIOUS_CMDLINE = re.compile(
    r"(net\s+user\s+\w+|net\s+localgroup\s+administrators"
    r"|schtasks\s+/create|reg\s+add.*\\run"
    r"|add-mppreference\s+-exclusion"
    r"|invoke-webrequest|iex\s*\(|downloadstring"
    r"|encodedcommand|-enc\s|frombase64string"
    r"|-windowstyle\s+hidden|-w\s+hidden)",
    re.IGNORECASE
)

# Processes that should always run as SYSTEM — never as regular user
_SYSTEM_ONLY_PROCESSES = re.compile(
    r"^(lsass|csrss|wininit|smss|services|winlogon)(\.exe)?$",
    re.IGNORECASE
)

# Web server processes — children are suspicious
_WEB_SERVER_PROCESSES = re.compile(
    r"^(httpd|apache|php-cgi|php|w3wp|nginx|tomcat)(\.exe)?$",
    re.IGNORECASE
)


# ═════════════════════════════════════════════
# PER-EVENT RULES
# ═════════════════════════════════════════════

class SuspiciousProcessSnapshotRule(PerEventRule):
    """Suspicious process found active in snapshot."""
    rule_id = "PROC_SUSPICIOUS_ACTIVE_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        if _action(event) != "process_snapshot":
            return None

        process = _process_name(event)
        if not _SUSPICIOUS_PROCESSES.match(process):
            return None

        cmdline = _cmdline(event)
        has_suspicious_cmd = bool(_SUSPICIOUS_CMDLINE.search(cmdline)) if cmdline else False

        if not has_suspicious_cmd:
            return None

        severity = Severity.HIGH if has_suspicious_cmd else Severity.MEDIUM
        confidence = 0.85 if has_suspicious_cmd else 0.60

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Process Active in Snapshot",
            severity=severity,
            confidence=confidence,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["process", "snapshot", "live"],
            source="processes",
            description=f"Suspicious process '{process}' active at collection time",
            timestamp=_ts(event),
            triggered_by=[index],
            extra={
                "process": process,
                "pid": _pid(event),
                "command_line": cmdline or None,
                "username": _username(event),
                "has_suspicious_cmdline": has_suspicious_cmd,
            }
        )


class SystemProcessWrongOwnerRule(PerEventRule):
    """System process running as non-SYSTEM user = process hollowing indicator."""
    rule_id = "PROC_WRONG_OWNER_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        if _action(event) != "process_snapshot":
            return None

        process = _process_name(event)
        if not _SYSTEM_ONLY_PROCESSES.match(process):
            return None

        username = _username(event)
        if "system" in username or "local service" in username or "network service" in username:
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="System Process Running as Wrong User",
            severity=Severity.CRITICAL,
            confidence=0.95,
            technique_id="T1055",
            technique_name="Process Injection",
            tactic=MitreTactic.DEFENSE_EVASION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["process_injection", "hollowing", "live"],
            source="processes",
            description=f"'{process}' running as '{_username(event)}' — expected SYSTEM",
            timestamp=_ts(event),
            triggered_by=[index],
            extra={
                "process": process,
                "pid": _pid(event),
                "actual_owner": _username(event),
            }
        )


class WebServerChildProcessRule(PerEventRule):
    """Suspicious process with parent PID matching a web server — webshell indicator."""
    rule_id = "PROC_WEBSHELL_CHILD_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        if _action(event) != "process_snapshot":
            return None

        process = _process_name(event)
        if not _SUSPICIOUS_PROCESSES.match(process):
            return None

        # Needs parent PID to correlate — handled in aggregate
        return None


# ═════════════════════════════════════════════
# AGGREGATE RULES
# ═════════════════════════════════════════════

class WebshellChildProcessAggregateRule(AggregateRule):
    """Cross-reference: suspicious process whose parent PID = web server PID."""
    rule_id = "PROC_WEBSHELL_CHILD_001"

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []

        # Build PID → process name map
        pid_to_name: dict[int, str] = {}
        for e in events:
            if _action(e) == "process_snapshot" and _pid(e):
                pid_to_name[_pid(e)] = _process_name(e)

        # Find suspicious processes whose parent is a web server
        for i, e in enumerate(events):
            if _action(e) != "process_snapshot":
                continue

            process = _process_name(e)
            if not _SUSPICIOUS_PROCESSES.match(process):
                continue

            parent_pid = _parent_pid(e)
            if not parent_pid:
                continue

            parent_name = pid_to_name.get(parent_pid, "")
            if not _WEB_SERVER_PROCESSES.match(parent_name):
                continue

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Webshell Child Process Detected in Snapshot",
                severity=Severity.CRITICAL,
                confidence=0.95,
                technique_id="T1505.003",
                technique_name="Web Shell",
                tactic=MitreTactic.EXECUTION,
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                tags=["webshell", "process", "live"],
                source="processes",
                description=f"'{process}' (PID {_pid(e)}) is child of web server '{parent_name}' (PID {parent_pid})",
                timestamp=_ts(e),
                triggered_by=[i],
                extra={
                    "child_process": process,
                    "child_pid": _pid(e),
                    "parent_process": parent_name,
                    "parent_pid": parent_pid,
                    "command_line": _cmdline(e) or None,
                }
            ))

        return findings


class SuspiciousCmdlineSnapshotRule(AggregateRule):
    """Processes with suspicious command lines active at collection time."""
    rule_id = "PROC_SUSPICIOUS_CMDLINE_001"

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []

        for i, e in enumerate(events):
            if _action(e) != "process_snapshot":
                continue

            cmdline = _cmdline(e)
            if not cmdline or not _SUSPICIOUS_CMDLINE.search(cmdline):
                continue

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Suspicious Command Line in Process Snapshot",
                severity=Severity.HIGH,
                confidence=0.88,
                technique_id="T1059.001",
                technique_name="Command and Scripting Interpreter: PowerShell",
                tactic=MitreTactic.EXECUTION,
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                tags=["cmdline", "process", "live"],
                source="processes",
                description=f"Active process with suspicious cmdline: '{cmdline[:120]}'",
                timestamp=_ts(e),
                triggered_by=[i],
                extra={
                    "process": _process_name(e),
                    "pid": _pid(e),
                    "command_line": cmdline,
                    "username": _username(e),
                }
            ))

        return findings


# ─────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────

def get_process_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        SuspiciousProcessSnapshotRule(),
        SystemProcessWrongOwnerRule(),
    ]
    aggregate = [
        WebshellChildProcessAggregateRule(),
        SuspiciousCmdlineSnapshotRule(),
    ]
    return per_event, aggregate