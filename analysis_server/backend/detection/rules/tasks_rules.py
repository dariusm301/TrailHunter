from __future__ import annotations
import re
from typing import Optional

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
    Capability,
)
from ..helpers import _ts, _extract_command, _executable, _task_name, _state, _get_original


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

_SYSTEM_PATH = re.compile(
    r"(%windir%|%systemroot%|c:\\windows|c:\\program files"
    r"|%programfiles%|c:\\programdata\\microsoft\\windows defender"
    r"|onedrive|microsoftedge|edgeupdate)",
    re.IGNORECASE,
)

_INTERPRETERS = {
    "powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe",
    "wscript", "cscript", "mshta", "rundll32",
}



def _is_scheduled_task(event: NormalizedEvent) -> bool:
    return bool(event.event and event.event.dataset == "windows.scheduled_tasks")

def _has_command(event: NormalizedEvent) -> bool:
    return bool(_extract_command(event))

def _execution_target(e: NormalizedEvent) -> Optional[str]:
    exe  = _executable(e)
    args = (e.process.args or []) if e.process else []
    base = exe.split("\\")[-1].split("/")[-1]

    if base in _INTERPRETERS:
        for a in args:
            last = a.split("\\")[-1].split("/")[-1]
            if ("\\" in a or "/" in a) and "." in last:
                return a.lower()
        return None

    return exe


# ═════════════════════════════════════════════
# PER-EVENT RULES
# ═════════════════════════════════════════════

class TaskWebRootExecutionRule(PerEventRule):
    rule_id = "TASK_WEBROOT_EXEC_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not _is_scheduled_task(event) or not _has_command(event):
            return None

        command = _extract_command(event)
        if not _SUSPICIOUS_PATH.search(command):
            return None

        task_name  = _task_name(event)
        executable = _executable(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Scheduled Task Executes from Web Root",
            rule_type="per_event",
            requires=(Capability("task_created", bind=("task_name",), values=[task_name,]),),
            provides=(),
            fusion_key=[("scheduled_task", task_name)],
            severity=Severity.CRITICAL,
            confidence=0.97,
            technique_id="T1053.005",
            technique_name="Scheduled Task/Job: Scheduled Task",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["scheduled_task", "webshell", "persistence", "web_root"],
            source="scheduled_tasks",
            description=f"Task '{task_name}' executes from web-accessible path: {command}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "task_name":  task_name,
                "command":    command,
                "executable": executable,
                "state":      _state(event),
            }
        )


class TaskPowerShellHiddenRule(PerEventRule):
    rule_id = "TASK_PS_HIDDEN_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not _is_scheduled_task(event) or not _has_command(event):
            return None

        command = _extract_command(event)
        if not _SUSPICIOUS_PS_TASK.search(command):
            return None

        task_name  = _task_name(event)
        executable = _executable(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Scheduled Task with Hidden PowerShell",
            rule_type="per_event",
            requires=(),
            provides=(),
            fusion_key=[("scheduled_task", task_name.lower())],
            severity=Severity.HIGH,
            confidence=0.92,
            technique_id="T1053.005",
            technique_name="Scheduled Task/Job: Scheduled Task",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["scheduled_task", "powershell", "hidden", "evasion"],
            source="scheduled_tasks",
            description=f"Task '{task_name}' runs PowerShell with evasion flags: {command[:120]}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "task_name":  task_name,
                "executable": executable,
                "command":    command,
                "state":      _state(event),
            }
        )


class TaskMasqueradingRule(PerEventRule):
    rule_id = "TASK_MASQUERADE_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not _is_scheduled_task(event):
            return None

        task_name = _task_name(event)
        if not _MASQUERADE_NAMES.match(task_name):
            return None

        if _LEGIT_TASK_PATH_PREFIX.search(_get_original(event)):
            return None

        executable = _executable(event)
        command    = _extract_command(event) or None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Scheduled Task Masquerading as System Process",
            rule_type="per_event",
            requires=(),
            provides=(),
            fusion_key=[("scheduled_task", task_name)],
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1036.004",
            technique_name="Masquerading: Match Legitimate Name or Location",
            tactic=MitreTactic.DEFENSE_EVASION,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["scheduled_task", "masquerade", "evasion", "persistence"],
            source="scheduled_tasks",
            description=f"Task '{task_name}' mimics a system process but not in Microsoft path",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "task_name":  task_name,
                "executable": executable,
                "command":    command,
                "state":      _state(event),
            }
        )


class TaskLolbinRule(PerEventRule):
    rule_id = "TASK_LOLBIN_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not _is_scheduled_task(event) or not _has_command(event):
            return None

        cmdline = _extract_command(event)
        exe     = _executable(event)

        match = _LOLBINS.search(exe) or _LOLBINS.search(cmdline)
        if not match:
            return None

        lolbin = match.group(1).lower()

        if lolbin == "rundll32":
            dll_args = " ".join((event.process.args or []) if event.process else []) or cmdline

            if re.search(r"(%windir%|%systemroot%|c:\\windows)", dll_args, re.IGNORECASE):
                return None

            args       = (event.process.args or []) if event.process else []
            target_dll = ""

            if args:
                full_args_str = " ".join(args)
                cleaned_args  = re.sub(r'^[/\-][dD]\s+', '', full_args_str).strip()
                target_dll    = cleaned_args.split(",")[0].strip()

            if not target_dll and cmdline:
                dll_match = re.search(
                    r'rundll32(?:\.exe)?\s+(?:[/\-][dD]\s+)?([^,\s]+)',
                    cmdline, re.IGNORECASE
                )
                if dll_match:
                    target_dll = dll_match.group(1).strip()

            if target_dll and re.search(r"[/\\]", target_dll):
                return None

            if target_dll and _KNOWN_SYSTEM_DLLS.match(target_dll):
                return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Scheduled Task Uses LOLBin",
            rule_type="per_event",
            severity=Severity.MEDIUM,
            confidence=0.80,
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
                "lolbin":    lolbin,
                "command":   cmdline,
                "state":     _state(event),
            }
        )
    
class ScheduledTaskCreatedRule(PerEventRule):
    rule_id = "WIN_SCHTASK_CREATED_001"

    _LEGITIMATE_TASK_PATHS = re.compile(
        r"^(\\microsoft\\|\\windows\\"
        r"|%systemroot%\\|%windir%\\"
        r"|%localappdata%\\microsoft\\onedrive\\"
        r"|%programfiles%\\|%programfiles\(x86\)%\\)",
        re.IGNORECASE
    )
    _LEGITIMATE_COM_TASKS = re.compile(
        r"^\\PostponeDeviceSetupToast_S-1-5-.*"
        r"|^\\SoftLanding\\S-1-5-.*",
        re.IGNORECASE
    )

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not (event.event and event.event.action == "scheduled_task_created"):
            return None

        extra     = event.winlog.extra if event.winlog else {}
        executable = extra.get("executable") or _executable(event)
        task_name  = extra.get("task_name", "-")
        uses_com   = extra.get("uses_com_handler", False)
        com_class  = extra.get("com_class")

        if self._LEGITIMATE_TASK_PATHS.match(executable or "") and not uses_com:
            return None
        if task_name != "-" and self._LEGITIMATE_COM_TASKS.match(task_name):
            return None

        severity   = Severity.CRITICAL if uses_com else Severity.HIGH
        confidence = 0.93 if uses_com else 0.80
        command    = _extract_command(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Scheduled Task Created",
            rule_type="per_event",
            requires=[],
            provides=[],
            fusion_key=[("task_name", task_name)],
            severity=severity,
            confidence=confidence,
            technique_id="T1053.005",
            technique_name="Scheduled Task/Job: Scheduled Task",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["persistence", "scheduled_task"],
            source="process",
            description=f"Suspicious scheduled task created: '{task_name}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "task_name":        task_name,
                "uses_com_handler": uses_com,
                "executable":       executable,
                "command":          command,
            }
        )


class TaskNonSystemExecutableRule(AggregateRule):
    rule_id = "TASK_NON_SYSTEM_EXEC_001"

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []

        for e in events:
            if not _is_scheduled_task(e) or not _has_command(e):
                continue
            if _state(e) == "disabled":
                continue

            target = _execution_target(e)
            if not target:
                continue
            if "\\" not in target and "/" not in target:
                continue
            if _SYSTEM_PATH.search(target):
                continue

            command    = _extract_command(e)
            executable = _executable(e)
            task_name  = _task_name(e)

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Scheduled Task with Non-System Executable",
                rule_type="aggregate",
                requires=(),
                provides=(),
                fusion_key=[("scheduled_task", task_name)],
                severity=Severity.MEDIUM,
                confidence=0.72,
                technique_id="T1053.005",
                technique_name="Scheduled Task/Job: Scheduled Task",
                tactic=MitreTactic.PERSISTENCE,
                kill_chain_phase=KillChainPhase.INSTALLATION,
                tags=["scheduled_task", "persistence", "non_standard_path"],
                source="scheduled_tasks",
                description=f"Task '{task_name}' runs from non-system path: {target}",
                timestamp=_ts(e),
                triggered_by=[e.id],
                extra={
                    "task_name":  task_name,
                    "executable": executable,
                    "target":     target,
                    "command":    command,
                    "state":      _state(e),
                }
            ))

        return findings



def get_scheduled_task_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        TaskWebRootExecutionRule(),
        TaskPowerShellHiddenRule(),
        TaskMasqueradingRule(),
        TaskLolbinRule(),
        ScheduledTaskCreatedRule(),
    ]
    aggregate = [
        TaskNonSystemExecutableRule(),
    ]
    return per_event, aggregate