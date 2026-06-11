from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Optional

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
)
from detection.models import Capability

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _ts(event: NormalizedEvent) -> datetime:
    return event.timestamp or None

def _is_scheduled_task(event: NormalizedEvent) -> bool:
    return (event.event and event.event.dataset == "windows_scheduled_tasks")

def _cmdline(event: NormalizedEvent) -> str:
    return (event.process.command_line or "").strip() if event.process else ""

def _executable(event: NormalizedEvent) -> str:
    return (event.process.executable or "").lower() if event.process else ""

def _task_name(event: NormalizedEvent) -> str:
    # process.name holds the task name in this context
    return (event.process.name or "").strip("'\" ") if event.process else ""

def _state(event: NormalizedEvent) -> str:
    return (event.event.action or "").lower() if event.event else ""

def _has_command(event: NormalizedEvent) -> bool:
    return bool(_cmdline(event) and _cmdline(event) not in ("", " "))

def _get_original(event: NormalizedEvent) -> str:
    if not event.event:
        return ""
    original = event.event.original or ""
    if isinstance(original, bytes):
        original = original.decode("utf-8", errors="ignore")
    return original
# ─────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────

_SUSPICIOUS_PATH = re.compile(
    r"(\\htdocs\\|\\wwwroot\\|\\inetpub\\|\\uploads\\|\\xampp\\"
    r"|\\temp\\|\\tmp\\|\\appdata\\local\\temp\\"
    r"|\\downloads\\|\\public\\|\\users\\public\\)",
    re.IGNORECASE,
)

_SUSPICIOUS_PS_TASK = re.compile(
    r"(powershell|pwsh).*"
    r"(-windowstyle\s+hidden|-w\s+hidden|-enc\s|-encodedcommand"
    r"|iex\s*[\(\$]|invoke-expression|downloadstring|frombase64string"
    r"|-nop\s|-noprofile\s|-exec\s+bypass)",
    re.IGNORECASE,
)

_MASQUERADE_NAMES = re.compile(
    r"^(windowsupdate|windows.?update|svchost|system32|winsvc"
    r"|microsoftupdate|windows.?defender|winlogon|lsass"
    r"|csrss|updater|update|maintenance|security.?center)$",
    re.IGNORECASE,
)

_LEGIT_TASK_PATH_PREFIX = re.compile(
    r"\\Microsoft\\Windows\\",
    re.IGNORECASE,
)

_LOLBINS = re.compile(
    r"(certutil|bitsadmin|mshta|wscript|cscript|regsvr32|rundll32"
    r"|msiexec|wmic|forfiles|pcalua|presentationhost)\.exe",
    re.IGNORECASE,
)

_KNOWN_SYSTEM_DLLS = re.compile(
    r"^(?:"
    r"acproxy|sysmain|bfe|dfdts|startupscan|pcasvc|wmpnscfg|"
    r"appxdeploymentclient|capabilityaccessmanager|"
    r"windows\.staterepositoryc|pcrpf|"
    r"windows\.storage\.applicationdata"
    r")\.dll$",
    re.IGNORECASE,
)


# ═════════════════════════════════════════════
# PER-EVENT RULES
# ═════════════════════════════════════════════

class TaskWebRootExecutionRule(PerEventRule):
    """
    Task that executes a binary or script from web root (htdocs, wwwroot, uploads etc.)
    classic indicator of webshell persistence.
    """
    rule_id = "TASK_WEBROOT_EXEC_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not _is_scheduled_task(event) or not _has_command(event):
            return None

        command = _cmdline(event)
        if not _SUSPICIOUS_PATH.search(command):
            return None
        task_name = _task_name(event)
        executable = _executable(event)
        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Scheduled Task Executes from Web Root",
            rule_type="per_event",
            requires=(Capability("task_created", bind=("task_name",), values=[task_name,]),),
            provides=(),
            fusion_key=("scheduled_task", task_name, executable, command),
            severity=Severity.CRITICAL,
            confidence=0.97,
            technique_id="T1053.005",
            technique_name="Scheduled Task/Job: Scheduled Task",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["scheduled_task", "webshell", "persistence", "web_root"],
            source="scheduled_tasks",
            description=f"Task '{_task_name(event)}' executes from web-accessible path: {command[:120]}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "task_name": task_name,
                "command": command,
                "executable": executable,
                "state": _state(event),
            }
        )


class TaskPowerShellHiddenRule(PerEventRule):
    """
    Task that launches PowerShell with hidden window or evasion flags — T1059.001 combined with T1053.005.
    """
    rule_id = "TASK_PS_HIDDEN_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not _is_scheduled_task(event) or not _has_command(event):
            return None

        command = _cmdline(event)
        if not _SUSPICIOUS_PS_TASK.search(command):
            return None
        task_name = _task_name(event)
        executable = _executable(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Scheduled Task with Hidden PowerShell",
            rule_type="per_event",
            requires=(),
            provides=(),
            fusion_key=("scheduled_task", task_name, executable, command),
            severity=Severity.HIGH,
            confidence=0.92,
            technique_id="T1053.005",
            technique_name="Scheduled Task/Job: Scheduled Task",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["scheduled_task", "powershell", "hidden", "evasion"],
            source="scheduled_tasks",
            description=f"Task '{_task_name(event)}' runs PowerShell with evasion flags: {command[:120]}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "task_name": task_name,
                "executable": executable,
                "command": command,
                "state": _state(event),
            }
        )


class TaskMasqueradingRule(PerEventRule):
    """
    Task with a name that mimics legitimate Windows processes/services but is not in a standard Microsoft path — T1036.004.
    """
    rule_id = "TASK_MASQUERADE_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not _is_scheduled_task(event):
            return None

        task_name = _task_name(event)
        if not _MASQUERADE_NAMES.match(task_name):
            return None

        original = _get_original(event)
        if _LEGIT_TASK_PATH_PREFIX.search(original):
            return None
        
        executable = _executable(event)
        command = _cmdline(event) or None
        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Scheduled Task Masquerading as System Process",
            rule_type="per_event",
            requires=(),
            provides=(),
            fusion_key=("scheduled_task", task_name, executable, command),
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1036.004",
            technique_name="Masquerading: Match Legitimate Name or Location",
            tactic=MitreTactic.DEFENSE_EVASION,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["scheduled_task", "masquerade", "evasion", "persistence"],
            source="scheduled_tasks",
            description=f"Task named '{task_name}' mimics a system process but is not in a Microsoft path",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "task_name": task_name,
                "executable": executable,
                "command": command,
                "state": _state(event),
            }
        )


class TaskLolbinRule(PerEventRule):
    """
    Task that executes a LOLBin (certutil, mshta, bitsadmin etc.) — sign of living-off-the-land persistence.
    """
    rule_id = "TASK_LOLBIN_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not _is_scheduled_task(event) or not _has_command(event):
            return None

        cmdline = _cmdline(event)
        exe     = _executable(event)

        if not cmdline or not cmdline.strip():
            return None

        match = _LOLBINS.search(exe) or _LOLBINS.search(cmdline)
        if not match:
            return None

        lolbin = match.group(1).lower()

        if lolbin == "rundll32":
            dll_args = " ".join(event.process.args or []) if event.process else cmdline
            
            # Bypass dacă se folosește o cale nativă evidentă în argumente
            if re.search(r"(%windir%|%systemroot%|c:\\windows)", dll_args, re.IGNORECASE):
                return None
                
            args = event.process.args or [] if event.process else []
            
            # Extragerea corectă a DLL-ului din argumente
            target_dll = ""
            if args:
                # Reunit toate argumentele într-un singur string pentru a curăța flag-urile ca /d sau -d
                full_args_str = " ".join(args)
                # Eliminăm flag-ul /d sau -d (și variațiile case-insensitive) de la început
                cleaned_args = re.sub(r'^[/\-][dD]\s+', '', full_args_str).strip()
                # Extragem doar numele DLL-ului dinaintea primei virgule
                target_dll = cleaned_args.split(",")[0].strip()

            # Dacă nu am putut extrage din args, încercăm o curățare sumară din cmdline
            if not target_dll and cmdline:
                # Căutăm ce urmează după rundll32.exe (și eventualele flag-uri)
                dll_match = re.search(r'rundll32(?:\.exe)?\s+(?:[/\-][dD]\s+)?([^,\s]+)', cmdline, re.IGNORECASE)
                if dll_match:
                    target_dll = dll_match.group(1).strip()

            # 1. Bypass dacă argumentul seamănă cu o cale (deja existent în logica ta)
            if target_dll and re.search(r"[/\\]", target_dll):
                return None

            # 2. Verificare în lista de DLL-uri sigure (va prinde corect 'acproxy.dll')
            if target_dll and _KNOWN_SYSTEM_DLLS.match(target_dll):
                return None

        confidence = 0.80

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Scheduled Task Uses LOLBin",
            rule_type="per_event",
            severity=Severity.MEDIUM,
            confidence=confidence,
            technique_id="T1218",
            technique_name="System Binary Proxy Execution",
            tactic=MitreTactic.DEFENSE_EVASION,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["scheduled_task", "lolbin", "defense_evasion"],
            source="scheduled_tasks",
            description=f"Task '{_task_name(event)}' uses LOLBin '{lolbin}': {cmdline[:120]}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "task_name": _task_name(event),
                "lolbin": lolbin,
                "command": cmdline,
                "state": _state(event),
            }
        )


# ═════════════════════════════════════════════
# AGGREGATE RULES
# ═════════════════════════════════════════════

class TaskNonSystemExecutableRule(AggregateRule):
    """
    Tasks whose execution target lives outside system paths — webshell / dropped
    payload persistence. Distinguishes:
      - executable : the BINARY only ('powershell') — consistent across rules/sources,
                     used for the fusion key and display.
      - target     : what the binary actually runs (the script/file). For interpreters
                     this is the path in the arguments ('C:\\xampp\\...\\update.ps1').
                     Used ONLY for the detection decision (is it non-system?), because
                     checking the interpreter itself would always look system-legit.
    """
    rule_id = "TASK_NON_SYSTEM_EXEC_001"
 
    _INTERPRETERS = {"powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe",
                     "wscript", "cscript", "mshta", "rundll32"}
 
    _SYSTEM_PATH = re.compile(
        r"(%windir%|%systemroot%|c:\\windows|c:\\program files"
        r"|%programfiles%|c:\\programdata\\microsoft\\windows defender"
        r"|onedrive|microsoftedge|edgeupdate)",
        re.IGNORECASE,
    )
 
    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []
 
        for e in events:
            if not _is_scheduled_task(e) or not _has_command(e):
                continue
            if _state(e) == "disabled":
                continue
 
            # Target drives the DETECTION decision (the real thing being run).
            target = self._execution_target(e)
            if not target:
                continue
            # Only care about path-like targets (a bare binary name is ambiguous).
            if "\\" not in target and "/" not in target:
                continue
            # Skip targets inside system paths.
            if self._SYSTEM_PATH.search(target):
                continue
 
            command = _cmdline(e)
            executable = _executable(e)          # BINARY only — 'powershell'
            task_name = _task_name(e)
 
            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Scheduled Task with Non-System Executable",
                rule_type="aggregate",
                requires=(),
                provides=(),
                fusion_key=("scheduled_task", task_name,
                            executable, command),
                severity=Severity.MEDIUM,
                confidence=0.72,
                technique_id="T1053.005",
                technique_name="Scheduled Task/Job: Scheduled Task",
                tactic=MitreTactic.PERSISTENCE,
                kill_chain_phase=KillChainPhase.INSTALLATION,
                tags=["scheduled_task", "persistence", "non_standard_path"],
                source="scheduled_tasks",
                description=f"Task '{task_name}' runs from a non-system path: {target}",
                timestamp=_ts(e),
                triggered_by=[e.id],
                extra={
                    "task_name":  task_name,
                    "executable": executable,    # 'powershell' — consistent binary
                    "target":     target,        # 'c:\\xampp\\...\\update.ps1' — what it runs
                    "command":    command,        # full command line
                    "state":      _state(e),
                }
            ))
 
        return findings
 
    def _execution_target(self, e) -> str | None:
        """
        What the task actually runs. For an interpreter, the file path in the
        arguments; otherwise the binary itself. Returns None only when an
        interpreter has no path-like argument (e.g. inline -Command) — such cases
        aren't "non-system executable" detections and are skipped by the caller.
        """
        exe = _executable(e)
        args = (e.process.args if e.process else None) or []
        base = exe.split("\\")[-1].split("/")[-1]
        if base in self._INTERPRETERS:
            for a in args:
                last = a.split("\\")[-1].split("/")[-1]
                if ("\\" in a or "/" in a) and "." in last:
                    return a.lower()
            return None
        return exe
     


# ─────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────

def get_scheduled_task_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        TaskWebRootExecutionRule(),
        TaskPowerShellHiddenRule(),
        TaskMasqueradingRule(),
        TaskLolbinRule(),
    ]
    aggregate = [
        TaskNonSystemExecutableRule(),
    ]
    return per_event, aggregate