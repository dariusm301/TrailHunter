from __future__ import annotations
import re
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    Capability, DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
)


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
        return event.process.command_line
    return ""

def _group_name(event: NormalizedEvent) -> str:
    if event.group and event.group.name:
        return event.group.name.lower()
    return ""

def _extract_command(event: NormalizedEvent) -> Optional[str]:
    """Extract the main command being executed, stripping common wrappers like 'cmd /c' or 'powershell -command'."""
    cmd = event.process.command_line if event.process else None
    if not cmd:
        return None
    stripped = _CMD_WRAPPER.sub("", cmd).strip().strip('"\'').lower()
    return stripped or None

# ─────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────

_SUSPICIOUS_CHILDREN = re.compile(
    r"^(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe"
    r"|whoami\.exe|net\.exe|net1\.exe|certutil\.exe|mshta\.exe"
    r"|regsvr32\.exe|rundll32\.exe|wmic\.exe|bitsadmin\.exe"
    r"|msiexec\.exe|sc\.exe|schtasks\.exe|reg\.exe)$",
    re.IGNORECASE
)

_WEB_SERVER_PROCESSES = re.compile(
    r"^(httpd\.exe|apache\.exe|php-cgi\.exe|php\.exe"
    r"|w3wp\.exe|nginx\.exe|tomcat\.exe)$",
    re.IGNORECASE
)

_SUSPICIOUS_CMDLINE = re.compile(
    r"(net\s+user\s+\w+|net\s+localgroup\s+administrators"
    r"|schtasks\s+/create|reg\s+add.*\\run"
    r"|add-mppreference\s+-exclusion"
    r"|invoke-webrequest|iex\s*\(|downloadstring"
    r"|encodedcommand|-enc\s|frombase64string"
    r"|sekurlsa|mimikatz|dumpcreds)",
    re.IGNORECASE
)

_LEGITIMATE_TASK_PATHS = re.compile(
    r"^(\\"
    r"\\microsoft\\|\\windows\\"           
    r"|%systemroot%\\|%windir%\\"          
    r"|%localappdata%\\microsoft\\onedrive\\" 
    r"|%programfiles%\\|%programfiles(x86)%\\" 
    r")",
    re.IGNORECASE
)

_CMD_WRAPPER = re.compile(
    r'^cmd(?:\.exe)?\s+/[sc]\s+(?:/[sc]\s+)?"?'
    r'|^powershell(?:\.exe)?\s+(?:-\w+\s+)*-[Cc]ommand\s+"?'
    r'|^/bin/sh\s+-c\s+"?'
    r'|^bash\s+-c\s+"?',
    re.IGNORECASE
)

# schtasks /create ... /tn NAME   (handles 'NAME', "NAME", NAME; /tn X or /tn:X)
_SCHTASKS_CREATE_TN = re.compile(
    r"schtasks\s+/create\b.*?/tn[\s:]+['\"]?([^'\"\s/]+)",
    re.IGNORECASE | re.DOTALL,
)
 
# reg add ...\Run... /v NAME
_REG_RUNKEY_ADD = re.compile(
    r"reg\s+add\b.*?\\run\b.*?/v[\s:]+['\"]?([^'\"\s/]+)",
    re.IGNORECASE | re.DOTALL,
)

_LEGITIMATE_COM_TASKS = re.compile(
    r"^\\PostponeDeviceSetupToast_S-1-5-.*", 
    re.IGNORECASE
)

_LEGITIMATE_COM_CLASSES = {
    "{5ded83ef-1e99-48cf-bf83-676d2a6db408}",  # Windows Device Setup Toast Notification Handler
}

_GENERIC_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}

# --------------------------------
# HELPERS
# --------------------------------
def _logon_type(event) -> Optional[int]:
    """LogonType lives in winlog.extra for 4624; adjust key to your normalizer."""
    if event.winlog and event.winlog.extra:
        raw = event.winlog.extra.get("logon_type")
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                return None
    return None

# ═════════════════════════════════════════════
# PER-EVENT RULES
# ═════════════════════════════════════════════

class UserCreatedRule(PerEventRule):
    rule_id = "WIN_USER_CREATED_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 4720:
            return None

        username = _username(event)
        sid = event.user.id if event.user else None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="User Account Created",
            rule_type="per_event",
            provides=[Capability("account_created", bind=("user_sid",), values=(sid,))],
            severity=Severity.HIGH,
            confidence=0.95,
            technique_id="T1136.001",
            technique_name="Create Account: Local Account",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["account", "persistence", "windows"],
            source="windows_events",
            description=f"New account created: '{username}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "created_user": username,
                "domain": event.user.domain if event.user else None,
                "user_sid": event.user.id if event.user else None,
            }
        )


class UserAddedToGroupRule(PerEventRule):
    rule_id = "WIN_GROUP_ADD_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 4732:
            return None
        _PRIVILEGED_GROUPS = {"administrators", "domain admins", "enterprise admins",
                            "backup operators", "remote desktop users"}
        group = _group_name(event)
        is_privileged = group in _PRIVILEGED_GROUPS
        severity = Severity.MEDIUM 
        member_sid = event.group.member_id if event.group else None
        requires = []
        provides = []
        if member_sid:
            requires = [Capability("account_created",    bind=("user_sid",), values=(member_sid,))]
            if is_privileged:
                provides = [Capability("account_privileged", bind=("user_sid",), values=(member_sid,))]

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="User Added to Privileged Group",
            rule_type="per_event",
            requires=requires,
            provides=provides,
            severity=severity,
            confidence=0.97,
            technique_id="T1098",
            technique_name="Account Manipulation",
            tactic=MitreTactic.PRIVILEGE_ESCALATION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["privilege_escalation", "account", "windows"],
            source="windows_events",
            description=f"User added to group '{group}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "group_name": group,
                "member_sid": event.group.member_id if event.group else None,
            }
        )


class ScheduledTaskCreatedRule(PerEventRule):
    rule_id = "WIN_SCHTASK_CREATED_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 4698:
            return None

        executable = ""
        if event.winlog and event.winlog.extra:
            executable = event.winlog.extra.get("executable") or event.process.executable or ""

        is_legitimate = bool(_LEGITIMATE_TASK_PATHS.match(executable))
        task_name = event.winlog.extra.get("task_name") if (
            event.winlog and event.winlog.extra
        ) else "-"
        uses_com = event.winlog.extra.get("uses_com_handler") if (
            event.winlog and event.winlog.extra
        ) else False

        if is_legitimate and not uses_com:
            return None  
        
        com_class = event.winlog.extra.get("com_class") if (
            event.winlog and event.winlog.extra
        ) else None
        
        if task_name != "-" and _LEGITIMATE_COM_TASKS.match(task_name):
            return None

        if uses_com and com_class in _LEGITIMATE_COM_CLASSES:
            return None

        severity = Severity.CRITICAL if uses_com else Severity.HIGH
        confidence = 0.93 if uses_com else 0.80
        command = _cmdline(event)
        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Scheduled Task Created",
            rule_type="per_event",
            requires=(),
            provides=(),
            fusion_key=("scheduled_task", task_name, executable, command),
            severity=severity,
            confidence=confidence,
            technique_id="T1053.005",
            technique_name="Scheduled Task/Job: Scheduled Task",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["persistence", "scheduled_task", "windows"],
            source="windows_events",
            description=f"Suspicious scheduled task created: '{task_name}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "task_name": task_name,
                "uses_com_handler": uses_com,
                "executable": executable,
                "command": command,
            },
        )


class LogClearedRule(PerEventRule):
    rule_id = "WIN_LOG_CLEARED_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 104:
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Event Log Cleared",
            rule_type="per_event",
            severity=Severity.CRITICAL,
            confidence=1.0,
            technique_id="T1070.001",
            technique_name="Indicator Removal: Clear Windows Event Logs",
            tactic=MitreTactic.DEFENSE_EVASION,
            kill_chain_phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            tags=["defense_evasion", "anti_forensics", "windows"],
            source="windows_events",
            description=f"Windows logs cleared by '{_username(event)}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "username": _username(event),
                "channel_cleared": (
                    event.winlog.extra.get("channel_cleared")
                    if event.winlog and event.winlog.extra else None
                ),
            }
        )


_BENIGN_WEBSERVER_TOOLCHAIN = re.compile(
    r"config\.awk\b"                                 # scriptul de path-rewrite XAMPP
    r"|\\install\\[^\\\"']+\.(?:exe|bat|awk)\b"      # tooling din \xampp\...\install\
    r"|\\xampp\\(?:apache|php|perl|mysql)\\bin\\",   # binare bundle-uite
    re.IGNORECASE,
)

class WebshellSpawnedProcessRule(PerEventRule):
    """4688 with parent web server = webshell execution."""
    rule_id = "WIN_WEBSHELL_PROCESS_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 4688:
            return None

        parent = _parent_name(event)
        child = _process_name(event)

        if not _WEB_SERVER_PROCESSES.match(parent):
            return None
        if not _SUSPICIOUS_CHILDREN.match(child):
            return None
        if _BENIGN_WEBSERVER_TOOLCHAIN.search(_cmdline(event)):
            return None


        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Webshell Process Execution",
            rule_type="per_event",
            requires=[Capability("code_execution", bind=("command",), values=(_extract_command(event),))],
            provides=[],
            severity=Severity.CRITICAL,
            confidence=0.95,
            technique_id="T1505.003",
            technique_name="Web Shell",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["webshell", "execution", "windows", "process"],
            source="windows_events",
            description=f"'{child}' spawned by web server '{parent}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "parent_process": parent,
                "child_process": child,
                "command_line": _cmdline(event),
                "pid": event.process.pid if event.process else None,
                "parent_pid": event.process.parent.pid if (
                    event.process and event.process.parent
                ) else None,
            },
            entities={
                "command": _extract_command(event),
            }
        )
    

_REMOTE_SESSION_PARENTS = re.compile(r"^(sshd\.exe|sshd)$", re.IGNORECASE)

class SuspiciousCommandLineRule(PerEventRule):
    """4688 with suspicious command line."""
    rule_id = "WIN_SUSPICIOUS_CMDLINE_001"
 
    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 4688:
            return None
 
        command = _cmdline(event)
        if not command or not _SUSPICIOUS_CMDLINE.search(command):
            return None
 
        parent = _parent_name(event)
        if _WEB_SERVER_PROCESSES.match(parent):
            return None
 
        # If this command runs under an SSH session shell, it consumes the
        # session established by the remote logon (links SSH → post-login activity).
        requires = []
        sid = event.user.id if event.user else None
        if sid and _REMOTE_SESSION_PARENTS.match(parent):
            requires = [Capability("session_established", bind=("user_sid",), values=(sid,))]
 
        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Command Line Execution",
            rule_type="per_event",
            requires=requires,
            provides=[],
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1059.001",
            technique_name="Command and Scripting Interpreter: PowerShell",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["execution", "cmdline", "windows"],
            source="windows_events",
            description=f"Suspicious command line executed: '{command[:120]}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "command": command,
                "process": _process_name(event),
                "parent": parent,
                "username": _username(event),
                "user_sid": sid,
            }
        )

    
class RemoteLoginRule(PerEventRule):
    """
    4624 successful logon, remote type (3 or 10), by a non-generic account.
    Bridges the privileged account to a remote session
    """
    rule_id = "WIN_REMOTE_LOGIN_001"
 
    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 4624:
            return None
        logon_type = _logon_type(event)
        if logon_type not in (3, 8, 10): 
            return None
        sid = event.user.id if event.user else None
        logon_id = event.logon.id if event.logon else None
        username = _username(event)
 
        if sid in _GENERIC_SIDS:
            return None
 
        requires = []
        if sid:
            requires = [Capability("account_privileged", bind=("user_sid",), values=(sid,))]
 
        provides = []
        if logon_id:
            provides = [Capability("session_established", bind=("logon_id",), values=(logon_id,))]
 
        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Remote Interactive Logon",
            rule_type="per_event",
            requires=requires,
            provides=provides,
            fusion_key=("remote_logon", "session", sid),
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1021",          # Remote Services (T1021.004 SSH / .001 RDP)
            technique_name="Remote Services",
            tactic=MitreTactic.LATERAL_MOVEMENT,
            kill_chain_phase=KillChainPhase.LATERAL_MOVEMENT
                if hasattr(KillChainPhase, "LATERAL_MOVEMENT")
                else KillChainPhase.COMMAND_AND_CONTROL,
            tags=["remote_logon", "lateral_movement", "valid_accounts", "windows"],
            source="windows_events",
            description=(
                f"— possible use of attacker-created account"
            ),
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "logon_user": username,
                "user_sid": sid,
                "source_ip": (event.source.address if event.source else None),
                "logon_id": logon_id,
            },
        )

class CommandPersistenceArtifactRule(PerEventRule):
    """
    """
    rule_id = "WIN_CMD_PERSISTENCE_ARTIFACT_001"
 
    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 4688:
            return None
 
        cmdline = _cmdline(event)
        if not cmdline:
            return None
 
        provides = []
        artifacts = {}
        process = _process_name(event)
        m = _SCHTASKS_CREATE_TN.search(cmdline)
        if m:
            task_name = m.group(1).strip("'\"")
            if process in ("cmd.exe", "powershell.exe"):
                pass
            else:
                provides.append(
                    Capability("task_created", bind=("task_name",), values=(task_name,))
                )
                artifacts["task_name"] = task_name
 
        m = _REG_RUNKEY_ADD.search(cmdline)
        if m:
            value_name = m.group(1).strip("'\"")
            if process in ("cmd.exe", "powershell.exe"):
                pass
            else:
                provides.append(
                    Capability("runkey_created", bind=("value_name",), values=(value_name,))
                )
                artifacts["runkey_value"] = value_name
 
        if not provides:
            return None
 
        kinds = ", ".join(artifacts.keys())
        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Persistence Artifact Created via Command",
            rule_type="per_event",
            requires=[],
            provides=provides,
            severity=Severity.HIGH,
            confidence=0.88,
            technique_id="T1053.005" if "task_name" in artifacts else "T1547.001",
            technique_name=(
                "Scheduled Task/Job: Scheduled Task" if "task_name" in artifacts
                else "Boot or Logon Autostart: Registry Run Keys"
            ),
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["persistence", "cmdline", "windows"],
            source="windows_events",
            description=f"Persistence artifact created via command ({kinds}): '{cmdline[:100]}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "command_line": cmdline,
                "process": _process_name(event),
                "parent": _parent_name(event),
                "username": _username(event),
                **artifacts,
            },
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
                rule_type="aggregate",
                severity=Severity.HIGH,
                confidence=0.90,
                technique_id="T1110.001",
                technique_name="Brute Force: Password Guessing",
                tactic=MitreTactic.CREDENTIAL_ACCESS,
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                tags=["bruteforce", "authentication", "windows"],
                source="windows_events",
                description=f"{len(hits)} failed login attempts for '{user}'",
                timestamp=_ts(hits[0][1]) or None,
                triggered_by=[e.id for _, e in hits],
                event_count=len(hits),
                extra={"target_user": user}
            ))

        return findings
    
class WebShellUserCreationRule(AggregateRule):
    """
    4688 (net user /add) spawned by a web server process
    followed by 4720 (account created) for the same username
    within a short time window — indicates webshell-driven persistence.
    """
    rule_id = "SEC_WEBSHELL_USERADD_001"
    TIME_WINDOW = 10  
    _NET_USER_ADD = re.compile(
        r"net[\s+]user[\s+](\S+).*\/add", re.IGNORECASE
    )
    _WEB_PROCS = {"httpd.exe", "nginx.exe", "w3wp.exe", "php-cgi.exe", "tomcat.exe"}

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []

        candidates: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in events:
            if e.winlog and e.winlog.event_id == 4688 and e.process:
                cmdline = e.process.command_line or ""
                m = self._NET_USER_ADD.search(cmdline)
                if not m:
                    continue
                parent_exe = (
                    e.process.parent.executable or ""
                ).lower() if e.process.parent else ""
                if not any(wp in parent_exe for wp in self._WEB_PROCS):
                    continue
                username = m.group(1).lower()
                candidates[username].append(e)

        if not candidates:
            return findings

        for e in events:
            if not (e.winlog and e.winlog.event_id == 4720 and e.user):
                continue
            username = (e.user.name or "").lower()
            if username not in candidates:
                continue

            for proc_event in candidates[username]:
                ts_proc = proc_event.event.created
                ts_create = e.event.created
                if not ts_proc or not ts_create:
                    continue
                delta = abs((ts_create - ts_proc).total_seconds())
                if delta > self.TIME_WINDOW:
                    continue

                findings.append(DetectionFinding(
                    rule_id=self.rule_id,
                    rule_name="Webshell-Driven User Account Creation",
                    rule_type="aggregate",
                    requires=[],
                    provides=[Capability("account_created", bind=("user_sid",),
                     values=(e.user.id if e.user else None,))],
                    severity=Severity.CRITICAL,
                    confidence=0.97,
                    technique_id="T1136.001",
                    technique_name="Create Account: Local Account",
                    tactic=MitreTactic.PERSISTENCE,
                    kill_chain_phase=KillChainPhase.INSTALLATION,
                    tags=["webshell", "useradd", "persistence", "security"],
                    source="security",
                    description=(
                        f"User '{username}' created via 'net user /add' "
                        f"executed by {proc_event.process.parent.executable} "
                        f"(webshell indicator)"
                    ),
                    timestamp=ts_proc,
                    triggered_by=[proc_event.id, e.id],
                    event_count=2,
                    extra={
                        "created_user": username,
                        "parent_process": proc_event.process.parent.executable,
                        "command_line": proc_event.process.command_line,
                        "delta_seconds": delta,
                    }
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
        RemoteLoginRule(),
        CommandPersistenceArtifactRule(),
    ]
    aggregate = [
        BruteForceLoginRule(),
        WebShellUserCreationRule()
    ]
    return per_event, aggregate