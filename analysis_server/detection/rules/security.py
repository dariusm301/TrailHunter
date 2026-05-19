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

MAX_INDICES = 50

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _ts(event: NormalizedEvent) -> Optional[datetime]:
    return event.event.created if event.event else None

def _event_id(event: NormalizedEvent) -> Optional[int]:
    return event.winlog.event_id if event.winlog else None

def _username(event: NormalizedEvent) -> Optional[str]:
    return event.user.name if event.user else None

def _process_name(event: NormalizedEvent) -> str:
    if event.process and event.process.name:
        return event.process.name.lower()
    return ""

def _parent_name(event: NormalizedEvent) -> str:
    if event.process and event.process.parent and event.process.parent.name:
        return event.process.parent.name.lower()
    return ""

def _cmdline(event: NormalizedEvent) -> str:
    if event.process and event.process.command_line:
        return event.process.command_line.lower()
    return ""

def _group_name(event: NormalizedEvent) -> str:
    if event.group and event.group.name:
        return event.group.name.lower()
    return ""


# ─────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────

# Procese care nu ar trebui să fie spawned de un web server
_SUSPICIOUS_CHILDREN = re.compile(
    r"^(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe"
    r"|whoami\.exe|net\.exe|net1\.exe|certutil\.exe|mshta\.exe"
    r"|regsvr32\.exe|rundll32\.exe|wmic\.exe|bitsadmin\.exe"
    r"|msiexec\.exe|sc\.exe|schtasks\.exe|reg\.exe)$",
    re.IGNORECASE
)

# Procese web server — nu ar trebui să spawneze nimic suspect
_WEB_SERVER_PROCESSES = re.compile(
    r"^(httpd\.exe|apache\.exe|php-cgi\.exe|php\.exe"
    r"|w3wp\.exe|nginx\.exe|tomcat\.exe)$",
    re.IGNORECASE
)

# Comenzi suspecte în command line
_SUSPICIOUS_CMDLINE = re.compile(
    r"(net\s+user\s+\w+|net\s+localgroup\s+administrators"
    r"|schtasks\s+/create|reg\s+add.*\\run"
    r"|add-mppreference\s+-exclusion"
    r"|invoke-webrequest|iex\s*\(|downloadstring"
    r"|encodedcommand|-enc\s|frombase64string"
    r"|sekurlsa|mimikatz|dumpcreds)",
    re.IGNORECASE
)

# Task-uri legitime Windows — reduci false positives
_LEGITIMATE_TASK_PATHS = re.compile(
    r"^\\(microsoft|windows)\\",
    re.IGNORECASE
)

_HIGH_PRIVILEGE_GROUPS = {"administrators", "remote desktop users", "backup operators"}


# ═════════════════════════════════════════════
# PER-EVENT RULES
# ═════════════════════════════════════════════

class UserCreatedRule(PerEventRule):
    rule_id = "WIN_USER_CREATED_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        if _event_id(event) != 4720:
            return None

        username = _username(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="User Account Created",
            severity=Severity.HIGH,
            confidence=0.95,
            technique_id="T1136.001",
            technique_name="Create Account: Local Account",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["account", "persistence", "windows"],
            source="windows_events",
            description=f"New account created: '{username}'",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "username": username,
                "domain": event.user.domain if event.user else None,
                "user_sid": event.user.id if event.user else None,
            }
        )


class UserAddedToGroupRule(PerEventRule):
    rule_id = "WIN_GROUP_ADD_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        if _event_id(event) != 4732:
            return None

        group = _group_name(event)
        is_high_priv = group in _HIGH_PRIVILEGE_GROUPS
        severity = Severity.CRITICAL if is_high_priv else Severity.MEDIUM

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="User Added to Privileged Group",
            severity=severity,
            confidence=0.97,
            technique_id="T1098",
            technique_name="Account Manipulation",
            tactic=MitreTactic.PRIVILEGE_ESCALATION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["privilege_escalation", "account", "windows"],
            source="windows_events",
            description=f"User added to group '{group}'",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "group_name": group,
                "member_sid": event.group.member_id if event.group else None,
                "is_high_privilege": is_high_priv,
            }
        )


class ScheduledTaskCreatedRule(PerEventRule):
    rule_id = "WIN_SCHTASK_CREATED_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        if _event_id(event) != 4698:
            return None

        task_name = (event.process.command_line or "") if event.process else ""
        is_legitimate = bool(_LEGITIMATE_TASK_PATHS.match(task_name))
        uses_com = event.winlog.extra.get("uses_com_handler") if (
            event.winlog and event.winlog.extra
        ) else False

        if is_legitimate and not uses_com:
            return None  # task Windows legitim, ignorat

        severity = Severity.CRITICAL if uses_com else Severity.HIGH
        confidence = 0.93 if uses_com else 0.80

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Scheduled Task Created",
            severity=severity,
            confidence=confidence,
            technique_id="T1053.005",
            technique_name="Scheduled Task/Job: Scheduled Task",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["persistence", "scheduled_task", "windows"],
            source="windows_events",
            description=f"Suspicious scheduled task created: '{task_name}'",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "task_name": task_name,
                "uses_com_handler": uses_com,
                "executable": event.process.executable if event.process else None,
            }
        )


class LogClearedRule(PerEventRule):
    rule_id = "WIN_LOG_CLEARED_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        if _event_id(event) != 104:
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Event Log Cleared",
            severity=Severity.CRITICAL,
            confidence=1.0,
            technique_id="T1070.001",
            technique_name="Indicator Removal: Clear Windows Event Logs",
            tactic=MitreTactic.DEFENSE_EVASION,
            kill_chain_phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            tags=["defense_evasion", "anti_forensics", "windows"],
            source="windows_events",
            description=f"Windows logs cleared by '{_username(event)}'",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "username": _username(event),
                "channel_cleared": (
                    event.winlog.extra.get("channel_cleared")
                    if event.winlog and event.winlog.extra else None
                ),
            }
        )


class WebshellSpawnedProcessRule(PerEventRule):
    """4688 with parent web server = webshell execution."""
    rule_id = "WIN_WEBSHELL_PROCESS_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        if _event_id(event) != 4688:
            return None

        parent = _parent_name(event)
        child = _process_name(event)

        if not _WEB_SERVER_PROCESSES.match(parent):
            return None
        if not _SUSPICIOUS_CHILDREN.match(child):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Webshell Process Execution",
            severity=Severity.CRITICAL,
            confidence=0.95,
            technique_id="T1505.003",
            technique_name="Web Shell",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["webshell", "execution", "windows", "process"],
            source="windows_events",
            description=f"'{child}' spawned by web server '{parent}'",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "parent_process": parent,
                "child_process": child,
                "command_line": _cmdline(event),
                "pid": event.process.pid if event.process else None,
                "parent_pid": event.process.parent.pid if (
                    event.process and event.process.parent
                ) else None,
            }
        )


class SuspiciousCommandLineRule(PerEventRule):
    """4688 with suspicious command line."""
    rule_id = "WIN_SUSPICIOUS_CMDLINE_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        if _event_id(event) != 4688:
            return None

        cmdline = _cmdline(event)
        if not cmdline or not _SUSPICIOUS_CMDLINE.search(cmdline):
            return None

        parent = _parent_name(event)
        if _WEB_SERVER_PROCESSES.match(parent):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Command Line Execution",
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1059.001",
            technique_name="Command and Scripting Interpreter: PowerShell",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["execution", "cmdline", "windows"],
            source="windows_events",
            description=f"Suspicious command line executed: '{cmdline[:120]}'",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "command_line": cmdline,
                "process": _process_name(event),
                "parent": parent,
                "username": _username(event),
            }
        )


# ═════════════════════════════════════════════
# AGGREGATE RULES
# ═════════════════════════════════════════════

class BruteForceLoginRule(AggregateRule):
    """many 4625 in show timeframe for same user = possible brute force attack."""
    rule_id = "WIN_BRUTE_FORCE_001"
    THRESHOLD = 5

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []
        by_user: dict[str, list[tuple[int, NormalizedEvent]]] = defaultdict(list)

        for i, e in enumerate(events):
            if _event_id(e) != 4625:
                continue
            user = _username(e) or "unknown"
            by_user[user].append((i, e))

        for user, hits in by_user.items():
            if len(hits) < self.THRESHOLD:
                continue

            indices = [i for i, _ in hits]
            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Brute Force Login Attempt",
                severity=Severity.HIGH,
                confidence=0.90,
                technique_id="T1110.001",
                technique_name="Brute Force: Password Guessing",
                tactic=MitreTactic.CREDENTIAL_ACCESS,
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                tags=["bruteforce", "authentication", "windows"],
                source="windows_events",
                description=f"{len(hits)} failed login attempts for '{user}'",
                timestamp=_ts(hits[0][1]) or datetime.now(timezone.utc),
                triggered_by=indices[:MAX_INDICES],
                event_count=len(hits),
                extra={"target_user": user}
            ))

        return findings


# ─────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────

def get_security_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        UserCreatedRule(),
        UserAddedToGroupRule(),
        ScheduledTaskCreatedRule(),
        LogClearedRule(),
        WebshellSpawnedProcessRule(),
        SuspiciousCommandLineRule(),
    ]
    aggregate = [
        BruteForceLoginRule(),
    ]
    return per_event, aggregate