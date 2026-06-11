
from __future__ import annotations
from importlib.metadata import requires
from importlib.metadata import requires
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from detection.rules.security import _extract_command
from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
    Capability
)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _ts(event: NormalizedEvent) -> Optional[datetime]:
    return event.event.created if event.event else None

def _event_id(event: NormalizedEvent) -> Optional[int]:
    return event.winlog.event_id if event.winlog else None

def _process_name(event: NormalizedEvent) -> str:
    return (event.process.name or "").lower() if event.process else ""

def _parent_name(event: NormalizedEvent) -> str:
    if event.process and event.process.parent:
        return (event.process.parent.name or "").lower()
    return ""

def _cmdline(event: NormalizedEvent) -> str:
    return (event.process.command_line or "").lower() if event.process else ""

def _target_name(event: NormalizedEvent) -> str:
    if event.target and event.target.process:
        return (event.target.process.name or "").lower()
    return ""

def _target_executable(event: NormalizedEvent) -> str:
    if event.target and event.target.process:
        return (event.target.process.executable or "").lower()
    return ""

def _dst_port(event: NormalizedEvent) -> Optional[int]:
    return event.destination.port if event.destination else None

def _dst_ip(event: NormalizedEvent) -> Optional[str]:
    return event.destination.address if event.destination else None

def _registry_path(event: NormalizedEvent) -> str:
    return (event.registry.path or "").lower() if event.registry else ""

def _host(event: NormalizedEvent) -> Optional[str]:
    if event.host and event.host.name:
        return event.host.name
    if event.winlog and event.winlog.computer_name:
        return event.winlog.computer_name
    return None

def _logon_id(event: NormalizedEvent) -> Optional[str]:
    if event.logon and event.logon.id:
        return event.logon.id
    return None

# ─────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────

_WEB_SERVER_PROCESSES = re.compile(
    r"^(httpd\.exe|apache\.exe|php-cgi\.exe|php\.exe"
    r"|w3wp\.exe|nginx\.exe|tomcat\.exe)$",
    re.IGNORECASE
)

_SUSPICIOUS_CHILDREN = re.compile(
    r"^(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe"
    r"|whoami\.exe|net\.exe|net1\.exe|certutil\.exe|mshta\.exe"
    r"|regsvr32\.exe|rundll32\.exe|wmic\.exe|bitsadmin\.exe"
    r"|msiexec\.exe|sc\.exe|schtasks\.exe|reg\.exe)$",
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

_RUN_KEYS = re.compile(
    r"(\\currentversion\\run\\|\\currentversion\\runonce\\"
    r"|\\currentversion\\runservices\\)",
    re.IGNORECASE
)

_DEFENDER_EXCLUSION = re.compile(
    r"(add-mppreference|exclusionpath|exclusionextension"
    r"|exclusionprocess|disablerealtimemonitoring)",
    re.IGNORECASE
)

_SUSPICIOUS_PORTS = {4444, 4445, 1234, 5555, 8888, 9001, 9999, 6666, 2222, 31337}

_SUSPICIOUS_NETWORK_PROCESSES = re.compile(
    r"^(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe"
    r"|mshta\.exe|regsvr32\.exe|rundll32\.exe|certutil\.exe"
    r"|msiexec\.exe|schtasks\.exe|wmic\.exe)$",
    re.IGNORECASE
)

_SUSPICIOUS_FILE_PATHS = re.compile(
    r"(\\temp\\|\\tmp\\|\\appdata\\local\\temp\\"
    r"|\\users\\public\\|\\programdata\\"
    r"|\\windows\\temp\\)",
    re.IGNORECASE
)

_EXECUTABLE_EXTENSIONS = re.compile(
    r"\.(exe|dll|bat|ps1|vbs|msi|scr|com|pif)$",
    re.IGNORECASE
)

_BENIGN_FILE_PROCESSES = re.compile(
    r"^(dismhost\.exe|tiworker\.exe|mscorsvw\.exe|taskhostw\.exe"
    r"|sdiagnhost\.exe|msiexec\.exe|trustedinstaller\.exe)$",
    re.IGNORECASE
)

_BENIGN_FILE_PATHS = re.compile(
    r"(\\\$winreagent\\"
    r"|\\winsxs\\temp\\"
    r"|\\assembly\\nativeimages_"
    r"|\\temp\\sdiag_"
    r"|__psscriptpolicytest_)",
    re.IGNORECASE
)


# ═════════════════════════════════════════════
# PER-EVENT RULES
# ═════════════════════════════════════════════

class SysmonWebshellProcessRule(PerEventRule):
    """Event 1 — process spawned by web server."""
    rule_id = "SYS_WEBSHELL_PROCESS_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 1:
            return None

        parent = _parent_name(event)
        child = _process_name(event)

        if not _WEB_SERVER_PROCESSES.match(parent):
            return None
        if not _SUSPICIOUS_CHILDREN.match(child):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Webshell Process Execution (Sysmon)",
            rule_type="per_event",
            requires=[Capability("code_execution", bind=("command",),
                     values=(_extract_command(event),))],
            provides=[],
            fusion_key=("sysmon_process", event.id),
            severity=Severity.CRITICAL,
            confidence=0.97,
            technique_id="T1505.003",
            technique_name="Web Shell",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["webshell", "execution", "sysmon"],
            source="sysmon",
            description=f"'{child}' spawned by '{parent}' — webshell execution",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "parent": parent,
                "child": child,
                "command_line": _cmdline(event),
                "hash_sha256": event.process.hash_sha256 if event.process else None,
                "pid": event.process.pid if event.process else None,
            },
            entities={"host": _host(event)},
        )

_REMOTE_PARENTS = ["sshd.exe"]

class SysmonSuspiciousCmdlineRule(PerEventRule):
    """Event 1 — suspect command line."""
    rule_id = "SYS_SUSPICIOUS_CMDLINE_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        event_id = _event_id(event)
        if event_id != 1:
            return None

        cmdline = _cmdline(event)
        if not cmdline or not _SUSPICIOUS_CMDLINE.search(cmdline):
            return None

        if _WEB_SERVER_PROCESSES.match(_parent_name(event)):
            return None
        
        logon_id = _logon_id(event)
        parent = _parent_name(event)
        requires = []
        if logon_id and parent in _REMOTE_PARENTS:
            requires.extend([Capability("session_established", bind=("logon_id",), values=(logon_id,))])

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Command Line (Sysmon)",
            rule_type="per_event", 
            requires=requires,
            provides=(),
            fusion_key=("sysmon_process", event.id),
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["cmdline", "execution", "sysmon"],
            source="sysmon",
            description=f"Suspicious command: '{cmdline[:120]}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "command_line": cmdline,
                "process": _process_name(event),
                "parent": _parent_name(event),
                "hash_sha256": event.process.hash_sha256 if event.process else None,
            },
            entities={"host": _host(event)},
        )

_LSASS_WHITELIST = {
    "svchost.exe",
    "lsm.exe", 
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "antimalware service executable",
    "mssense.exe",        # Microsoft Defender ATP
    "msmpeng.exe",        # Windows Defender
    "taskmgr.exe",
    "wmiprvse.exe",
    "microsoftedgeupdate.exe",
    "googleupdate.exe",
}

_SAFE_READONLY_ACCESS = {"0x1000", "0x400"} 

class LsassAccessRule(PerEventRule):
    """Event 10 — LSASS access = credential dumping."""
    rule_id = "SYS_LSASS_ACCESS_001"

    _DANGEROUS_ACCESS = {
        "0x1010", "0x1410", "0x1fffff", "0x143a",
        "0x1438", "0x1418", "0x1038"
    }

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 10:
            return None

        target_exe = _target_executable(event)
        if "lsass.exe" not in target_exe:
            return None

        process = _process_name(event)
        if process in _LSASS_WHITELIST:
            return None

        granted_access = ""
        if event.winlog and event.winlog.extra:
            granted_access = (event.winlog.extra.get("granted_access") or "").lower()

        if granted_access in _SAFE_READONLY_ACCESS:
            return None
        confidence = 0.97 if granted_access in self._DANGEROUS_ACCESS else 0.85

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="LSASS Memory Access",
            rule_type="per_event",
            requires=[],
            provides=[],
            severity=Severity.CRITICAL,
            confidence=confidence,
            technique_id="T1003.001",
            technique_name="OS Credential Dumping: LSASS Memory",
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["credential_dumping", "lsass", "sysmon"],
            source="sysmon",
            description=f"'{_process_name(event)}' accessed LSASS with mask '{granted_access}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "source_process": _process_name(event),
                "source_pid": event.process.pid if event.process else None,
                "granted_access": granted_access,
                "call_trace": (
                    event.winlog.extra.get("call_trace") if event.winlog and event.winlog.extra else None
                ),
            },
            entities={"host": _host(event)},
        )


class SuspiciousNetworkConnectionRule(PerEventRule):
    """Event 3 — outbound connection from a suspicious process or on a suspicious port."""
    rule_id = "SYS_SUSPICIOUS_NETWORK_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 3:
            return None

        process = _process_name(event)
        dst_port = _dst_port(event)
        dst_ip = _dst_ip(event)

        is_suspicious_process = bool(_SUSPICIOUS_NETWORK_PROCESSES.match(process))
        is_suspicious_port = dst_port in _SUSPICIOUS_PORTS

        if not (is_suspicious_process or is_suspicious_port):
            return None

        if is_suspicious_process and is_suspicious_port:
            severity = Severity.CRITICAL
            confidence = 0.95
            description = f"Possible reverse shell: '{process}' → {dst_ip}:{dst_port}"
        elif is_suspicious_process:
            severity = Severity.HIGH
            confidence = 0.80
            description = f"Suspicious process made outbound connection: '{process}' → {dst_ip}:{dst_port}"
        else:
            severity = Severity.MEDIUM
            confidence = 0.75
            description = f"Suspicious port connection {dst_port} → {dst_ip}"

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Network Connection",
            rule_type="per_event",
            requires=[],
            provides=[],
            severity=severity,
            confidence=confidence,
            technique_id="T1071.001",
            technique_name="Application Layer Protocol: Web Protocols",
            tactic=MitreTactic.COMMAND_AND_CONTROL,
            kill_chain_phase=KillChainPhase.COMMAND_AND_CONTROL,
            tags=["network", "c2", "sysmon"],
            source="sysmon",
            description=description,
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "process": process,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "suspicious_process": is_suspicious_process,
                "suspicious_port": is_suspicious_port,
            },
            entities={"host": _host(event)},
        )


class RunKeyPersistenceRule(PerEventRule):
    """Event 12/13 — writing to Run keys = persistence."""
    rule_id = "SYS_RUNKEY_PERSISTENCE_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) not in (12, 13):
            return None

        reg_path = _registry_path(event)
        if not reg_path or not _RUN_KEYS.search(reg_path):
            return None

        value = (event.registry.value or "") if event.registry else ""

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Registry Run Key Modification",
            requires=[],
            provides=[],
            severity=Severity.HIGH,
            confidence=0.92,
            technique_id="T1547.001",
            technique_name="Boot or Logon Autostart: Registry Run Keys",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["persistence", "registry", "sysmon"],
            source="sysmon",
            description=f"Run key modified: '{reg_path}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "registry_path": reg_path,
                "value": value,
                "process": _process_name(event),
            },
            entities={"host": _host(event)},
        )


class DefenderExclusionRule(PerEventRule):
    """Event 1/13 — excludere din Defender = defense evasion."""
    rule_id = "SYS_DEFENDER_EXCLUSION_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        eid = _event_id(event)

        if eid == 1:
            if not _DEFENDER_EXCLUSION.search(_cmdline(event)):
                return None
        elif eid == 13:
            reg_path = _registry_path(event)
            if "windows defender" not in reg_path or "exclusion" not in reg_path:
                return None
        else:
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Windows Defender Exclusion Added",
            requires=(),
            provides=(),
            fusion_key=(),
            severity=Severity.CRITICAL,
            confidence=0.95,
            technique_id="T1562.001",
            technique_name="Impair Defenses: Disable or Modify Tools",
            tactic=MitreTactic.DEFENSE_EVASION,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["defense_evasion", "defender", "sysmon"],
            source="sysmon",
            description=f"Defender exclusion added by '{_process_name(event)}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "process": _process_name(event),
                "command_line": _cmdline(event) if eid == 1 else None,
                "registry_path": _registry_path(event) if eid == 13 else None,
            },
            entities={"host": _host(event)},
        )


class SuspiciousFileDropRule(PerEventRule):
    """Event 11 — executable created in suspicious location."""
    rule_id = "SYS_SUSPICIOUS_FILE_DROP_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 11:
            return None

        file_path = (event.file.path or "").lower() if event.file else ""
        if not file_path:
            return None

        # Early exit pentru FP cunoscute
        process = _process_name(event)
        if _BENIGN_FILE_PROCESSES.match(process):
            return None
        if _BENIGN_FILE_PATHS.search(file_path):
            return None

        in_suspicious_path = bool(_SUSPICIOUS_FILE_PATHS.search(file_path))
        is_executable = bool(_EXECUTABLE_EXTENSIONS.search(file_path))

        if not (in_suspicious_path and is_executable):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Executable Dropped in Suspicious Location",
            rule_type="per_event",
            requires=[],
            provides=[],
            severity=Severity.HIGH,
            confidence=0.88,
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            tactic=MitreTactic.COMMAND_AND_CONTROL,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["file_drop", "executable", "sysmon"],
            source="sysmon",
            description=f"Executable created in suspicious location: '{file_path}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "file_path": file_path,
                "process": _process_name(event),
            },
            entities={"host": _host(event)},
        )


class SuspiciousPipeRule(PerEventRule):
    """Event 17/18 — suspect named pipe = C2 framework."""
    rule_id = "SYS_SUSPICIOUS_PIPE_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) not in (17, 18):
            return None

        severity_raw = event.event.severity if event.event else 0
        if severity_raw < 5:
            return None

        pipe_name = ""
        if event.winlog and event.winlog.extra:
            pipe_name = event.winlog.extra.get("pipe_name") or ""

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Named Pipe",
            requires=[],
            provides=[],
            severity=Severity.CRITICAL,
            confidence=0.93,
            technique_id="T1559.001",
            technique_name="Inter-Process Communication: Component Object Model",
            tactic=MitreTactic.COMMAND_AND_CONTROL,
            kill_chain_phase=KillChainPhase.COMMAND_AND_CONTROL,
            tags=["c2", "pipe", "sysmon"],
            source="sysmon",
            description=f"Suspicious named pipe detected: '{pipe_name}'",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "pipe_name": pipe_name,
                "process": _process_name(event),
                "event_type": "created" if _event_id(event) == 17 else "connected",
            },
            entities={"host": _host(event)},
        )


# ─────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────

def get_sysmon_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        SysmonWebshellProcessRule(),
        SysmonSuspiciousCmdlineRule(),
        LsassAccessRule(),
        SuspiciousNetworkConnectionRule(),
        RunKeyPersistenceRule(),
        DefenderExclusionRule(),
        SuspiciousFileDropRule(),
        SuspiciousPipeRule(),
    ]
    aggregate = []
    return per_event, aggregate