from __future__ import annotations
import re
from typing import Optional, defaultdict

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase, Capability
)
from ..helpers import (
    _ts,  _username, _pid, _parent_name, _parent_pid, _process_name, _get_args, 
    _logon_id, _extract_command, _parent_command_line, _src_ip
)


_SUSPICIOUS_CHILDREN = re.compile(
    r"^(cmd|powershell|wscript|cscript|whoami|net|net1|certutil|mshta"
    r"|regsvr32|rundll32|wmic|bitsadmin|msiexec|sc|schtasks|reg)(\.exe)?$",
    re.IGNORECASE
)

_WEB_SERVER_PROCESSES = re.compile(
    r"^(httpd|apache|php-cgi|php|w3wp|nginx|tomcat)(\.exe)?$",
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

_BENIGN_PHP_PROBES = re.compile(
    r"echo\s+['\"]?%\w+%['\"]?"  
    r"|php(\.exe)?\s+-[rv]"      
    r"|php-cgi(\.exe)?\s+-b",    
    re.IGNORECASE
)

_REMOTE_SESSION_PARENTS = re.compile(r"^(sshd|sshd\.exe)$", re.IGNORECASE)

_NET_USER_ADD = re.compile(
    r"net\d?\s+user\s+([^\s/]+).*?/add\b",
    re.IGNORECASE | re.DOTALL,
)

_SCHTASKS_CREATE_TN = re.compile(
    r"schtasks\s+/create\b.*?/tn[\s:]+['\"]?([^'\"\s/]+)",
    re.IGNORECASE | re.DOTALL,
)

_REG_RUNKEY_ADD = re.compile(
    r"reg\s+add\b.*?\\run\b.*?/v[\s:]+['\"]?([^'\"\s/]+)",
    re.IGNORECASE | re.DOTALL,
)

_BENIGN_WEBSERVER_TOOLCHAIN = re.compile(
    r"config\.awk\b"
    r"|\\install\\[^\\\"']+\.(?:exe|bat|awk)\b"
    r"|\\xampp\\(?:apache|php|perl|mysql)\\bin\\",
    re.IGNORECASE,
)

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

_SYSTEM_ONLY_PROCESSES = re.compile(
    r"^(lsass|csrss|wininit|smss|services|winlogon)(\.exe)?$",
    re.IGNORECASE
)

_WEB_SERVER_PROCESSES = re.compile(
    r"^(httpd|apache|php-cgi|w3wp|nginx|tomcat)(\.exe)?$",
    re.IGNORECASE
)

_SYSTEM_ACCOUNTS = {"system", "local service", "network service"}


class SuspiciousProcessRule(PerEventRule):
    rule_id = "PROC_SUSPICIOUS_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not event.process:
            return None

        process = _process_name(event)
        if not _SUSPICIOUS_PROCESSES.match(process):
            return None

        cmdline = _extract_command(event)
        if not cmdline or not _SUSPICIOUS_CMDLINE.search(cmdline):
            return None

        fusion_key = [("command_execution", _extract_command(event))] if _extract_command(event) else []
        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Process Execution",
            rule_type="per_event",
            requires=[Capability("code_execution", bind=("command_line",), values=(_extract_command(event),))],
            provides=[],
            fusion_key=fusion_key,
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["process", "cmdline"],
            source="process",
            description=f"'{process}' executed with suspicious command line",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "process": process,
                "pid": _pid(event),
                "command_line": cmdline,
                "username": _username(event),
            }
        )


_XAMPP_INSTALL_PATHS = re.compile(
    r'(?i)[/\\]xampp[/\\]',
)

_XAMPP_TOOLS = re.compile(
    r'(?i)^(awk|sed|grep|gzip|perl|php|mysqld?|httpd)\.exe$'
)

_XAMPP_CMD_WRAPPER = re.compile(r'(?i)^cmd(\.exe)?$')

def _is_xampp_installer_fp(process: str, cmdline: Optional[str], parent_cmdline: Optional[str]) -> bool:
    if not cmdline:
        return False

    if parent_cmdline and re.search(r"install[/\\]install\.php", parent_cmdline, re.IGNORECASE):
        return True

    if _XAMPP_TOOLS.match(process) and _XAMPP_INSTALL_PATHS.search(cmdline):
        return True

    if _XAMPP_CMD_WRAPPER.match(process):
        first_token = cmdline.split()[0] if cmdline.split() else ""
        tool_name = re.search(r'(?i)([\w]+\.exe)', first_token)
        if tool_name and _XAMPP_TOOLS.match(tool_name.group(1)):
            if _XAMPP_INSTALL_PATHS.search(cmdline):
                return True

    if _BENIGN_PHP_PROBES.search(cmdline):
        return True

    return False

class WebshellChildProcessRule(PerEventRule):
    rule_id = "PROC_WEBSHELL_CHILD_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not event.process:
            return None
        process = _process_name(event)
        if not _SUSPICIOUS_PROCESSES.match(process):
            return None
        parent = _parent_name(event)
        if not parent or not _WEB_SERVER_PROCESSES.match(parent):
            return None

        cmdline = _extract_command(event)
        parent_cmdline = _parent_command_line(event)
        if _is_xampp_installer_fp(process, cmdline, parent_cmdline):
            return None
        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Webshell Child Process",
            rule_type="per_event",
            requires=[Capability("web_command", bind=("command_line", ), values=(cmdline,))] if cmdline else [],
            provides=[Capability("code_execution", bind=("command_line",), values=(cmdline,))] if cmdline else [],
            fusion_key=[("webshell_process", cmdline)] if cmdline else [],
            severity=Severity.CRITICAL,
            confidence=0.95,
            technique_id="T1505.003",
            technique_name="Web Shell",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["webshell", "process"],
            source="process",
            description=f"'{process}' spawned by web server '{parent}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "child_process": process,
                "child_pid": _pid(event),
                "parent_process": parent,
                "parent_pid": _parent_pid(event),
                "command_line": cmdline or None,
            }
        )
class SuspiciousCommandLineRule(PerEventRule):
    rule_id = "WIN_SUSPICIOUS_CMDLINE_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not event.process:
            return None

        command = _extract_command(event)
        if not command or not _SUSPICIOUS_CMDLINE.search(command):
            return None

        parent = _parent_name(event)
        if _WEB_SERVER_PROCESSES.match(parent):
            return None

        sid = event.user.id if event.user else None
        requires = []
        if sid and _REMOTE_SESSION_PARENTS.match(parent):
            requires = [Capability("session_established", bind=("logon_id",), values=(_logon_id(event),))]

        if command is not None:
            requires = [Capability("code_execution", bind=("command_line",), values=(command,))]

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Command Line Execution",
            rule_type="per_event",
            requires=requires,
            provides=[],
            fusion_key=[("command_execution", command)] if command else [],
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["execution", "cmdline"],
            source="process",
            description=f"Suspicious command line: '{command[:120]}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
            }
        )


class CommandUserCreationRule(PerEventRule):
    rule_id = "WIN_CMD_USER_CREATION_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not event.process:
            return None

        process = _process_name(event)
        if process not in ("net.exe", "net1.exe"):
            return None

        cmdline = _extract_command(event)
        if not cmdline:
            return None
        m = _NET_USER_ADD.search(cmdline)
        if not m:
            return None

        created_user = m.group(1).strip("'\"").lower()

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Local Account Created via Command",
            rule_type="per_event",
            requires=[],
            provides=[Capability("local_account_created", bind=("username",),
                                 values=(created_user,))],
            fusion_key=[("command_line", cmdline)],
            severity=Severity.HIGH,
            confidence=0.90,
            technique_id="T1136.001",
            technique_name="Create Account: Local Account",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["account", "persistence", "cmdline"],
            source="process",
            description=f"Local account '{created_user}' created via command",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "created_user": created_user,
                "command_line": cmdline,
                "process":      process,
                "parent":       _parent_name(event),
            }
        )


class CommandPersistenceArtifactRule(PerEventRule):
    rule_id = "WIN_CMD_PERSISTENCE_ARTIFACT_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not event.process:
            return None

        cmdline = _extract_command(event)
        if not cmdline:
            return None

        process   = _process_name(event)
        provides  = []
        artifacts = {}
        fusion_key = []
        m = _SCHTASKS_CREATE_TN.search(cmdline)

        if m and process not in ("cmd.exe", "powershell.exe"):
            task_name = m.group(1).strip("'\"")
            provides.append(Capability("task_created", bind=("task_name",),
                                       values=(task_name,)))
            fusion_key.append(("task_name", task_name))
            artifacts["task_name"] = task_name

        m = _REG_RUNKEY_ADD.search(cmdline)
        if m and process not in ("cmd.exe", "powershell.exe"):
            value_name = m.group(1).strip("'\"")
            provides.append(Capability("runkey_created", bind=("value_name",),
                                       values=(value_name,)))
            fusion_key.append(("value_name", value_name))
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
            fusion_key=fusion_key,
            severity=Severity.HIGH,
            confidence=0.88,
            technique_id="T1053.005" if "task_name" in artifacts else "T1547.001",
            technique_name=(
                "Scheduled Task/Job: Scheduled Task" if "task_name" in artifacts
                else "Boot or Logon Autostart: Registry Run Keys"
            ),
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["persistence", "cmdline"],
            source="process",
            description=f"Persistence artifact via command ({kinds}): '{cmdline[:100]}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "command_line": cmdline,
                "process":      process,
                "parent":       _parent_name(event),
                "username":     _username(event),
                **artifacts,
            }
        )



class SuspiciousCmdlineRule(AggregateRule):
    rule_id = "PROC_SUSPICIOUS_CMDLINE_001"

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []

        for e in events:
            if not e.process:
                continue

            cmdline = _extract_command(e)
            if not cmdline or not _SUSPICIOUS_CMDLINE.search(cmdline):
                continue

            process = _process_name(e)
            if _SUSPICIOUS_PROCESSES.match(process):
                continue

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Suspicious Command Line",
                rule_type="aggregate",
                requires=[Capability("code_execution", bind=("command_line",), values=(cmdline,))],
                provides=[],
                fusion_key=[("command_execution", cmdline.lower())],
                severity=Severity.HIGH,
                confidence=0.80,
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                tactic=MitreTactic.EXECUTION,
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                tags=["cmdline", "process", "lotl"],
                source="process",
                description=f"Suspicious cmdline on '{process}': '{cmdline[:120]}'",
                timestamp=_ts(e),
                triggered_by=[e.id],
                extra={
                    "process": process,
                    "pid": _pid(e),
                    "command_line": cmdline,
                    "username": _username(e),
                }
            ))

        return findings


def get_processes_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        SuspiciousProcessRule(),
        WebshellChildProcessRule(),
        SuspiciousCommandLineRule(),
        CommandUserCreationRule(),
        CommandPersistenceArtifactRule(),
    ]
    aggregate = [
        SuspiciousCmdlineRule(),
    ]
    return per_event, aggregate