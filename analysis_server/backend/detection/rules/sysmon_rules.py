from __future__ import annotations
from typing import Optional
import re

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
    Capability,
)
from ..helpers import _ts, _process_name, _winlog_extra, _host, _event_id, _target_executable, _logon_id


_LSASS_WHITELIST = {
    "svchost.exe", "lsm.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "taskmgr.exe", "wmiprvse.exe",
    "antimalware service executable", "mssense.exe", "msmpeng.exe",
    "microsoftedgeupdate.exe", "googleupdate.exe",
}

_LSASS_SAFE_ACCESS = {"0x1000", "0x400"}

_LSASS_DANGEROUS_ACCESS = {
    "0x1010", "0x1410", "0x1fffff", "0x143a",
    "0x1438", "0x1418", "0x1038",
}

_SUSPICIOUS_FILE_PATHS = re.compile(
    r"(\\temp\\|\\tmp\\|\\appdata\\local\\temp\\"
    r"|\\users\\public\\|\\programdata\\"
    r"|\\windows\\temp\\"
    r"|\\inetpub\\wwwroot\\|\\xampp\\htdocs\\"
    r"|\\apache-tomcat\\|\\uploads\\)",
    re.IGNORECASE
)

_EXECUTABLE_EXTENSIONS = re.compile(
    r"\.(exe|dll|bat|ps1|vbs|msi|scr|com|pif)$",
    re.IGNORECASE
)

_BENIGN_FILE_PROCESSES = re.compile(
    r"^(dismhost|tiworker|mscorsvw|taskhostw"
    r"|sdiagnhost|msiexec|trustedinstaller)(\.exe)?$",
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


class LsassAccessRule(PerEventRule):
    rule_id = "SYS_LSASS_ACCESS_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 10:
            return None

        if "lsass.exe" not in _target_executable(event):
            return None

        process = _process_name(event)
        if process in _LSASS_WHITELIST:
            return None

        granted_access = (_winlog_extra(event, "granted_access") or "").lower()

        if granted_access in _LSASS_SAFE_ACCESS:
            return None

        confidence = 0.97 if granted_access in _LSASS_DANGEROUS_ACCESS else 0.85

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
            description=f"'{process}' a accesat LSASS cu mask '{granted_access}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "source_process":  process,
                "source_pid":      event.process.pid if event.process else None,
                "granted_access":  granted_access,
                "call_trace":      _winlog_extra(event, "call_trace"),
            },
            entities={"host": _host(event)},
        )


class SuspiciousFileDropRule(PerEventRule):
    rule_id = "SYS_SUSPICIOUS_FILE_DROP_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 11:
            return None

        if not event.file:
            return None

        file_path = (event.file.path or "").lower()
        if not file_path:
            return None

        process = _process_name(event)
        if _BENIGN_FILE_PROCESSES.match(process):
            return None
        if _BENIGN_FILE_PATHS.search(file_path):
            return None

        if not (_SUSPICIOUS_FILE_PATHS.search(file_path) and
                _EXECUTABLE_EXTENSIONS.search(file_path)):
            return None
        requires = []
        if _logon_id(event):
            requires.append(Capability("session_established", bind=("logon.id"), values=(_logon_id(event))))

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="File Dropped in Suspicious Location",
            rule_type="per_event",
            requires=requires,
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
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "file_path": file_path,
                "process":   process,
            },
            entities={"host": _host(event)},
        )


class SuspiciousPipeRule(PerEventRule):
    rule_id = "SYS_SUSPICIOUS_PIPE_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) not in (17, 18):
            return None

        severity_raw = event.event.severity if event.event else 0
        if severity_raw < 5:
            return None

        pipe_name = _winlog_extra(event, "pipe_name") or ""

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Named Pipe",
            rule_type="per_event",
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
            description=f"Named pipe suspect detectat: '{pipe_name}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "pipe_name":  pipe_name,
                "process":    _process_name(event),
                "event_type": "created" if _event_id(event) == 17 else "connected",
            },
            entities={"host": _host(event)},
        )



def get_sysmon_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        LsassAccessRule(),
        SuspiciousFileDropRule(),
        SuspiciousPipeRule(),
    ]
    aggregate = []
    return per_event, aggregate