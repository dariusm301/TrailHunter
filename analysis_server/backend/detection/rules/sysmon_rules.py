from __future__ import annotations
from collections import defaultdict
from datetime import timedelta
from typing import Optional
import re

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
    Capability,
)
from ..helpers import _ip, _parent_name, _ts, _process_name, _winlog_extra, _host, _event_id, _target_executable, _logon_id, _target_path, _target_name


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

_SENSITIVE_EXTENSIONS = re.compile(
    r'\.(db|sqlite|sqlite3|sql|mdb|ldf|mdf|'
    r'bak|backup|dump|'
    r'config|cfg|ini|env|'
    r'exe|dll|ps1|bat|cmd|vbs|js|hta)$',
    re.IGNORECASE
)

_SENSITIVE_PATHS = re.compile(
    r'\\(htdocs|wwwroot|inetpub|xampp|www|webroot|uploads|public_html)\\',
    re.IGNORECASE
)

_SYSTEM_PATHS = re.compile(
    r'^[A-Za-z]:\\(Windows|Program Files|ProgramData)\\',
    re.IGNORECASE
)

def _is_sensitive(path: str) -> bool:
    return bool(_SENSITIVE_EXTENSIONS.search(path)) or bool(_SENSITIVE_PATHS.search(path))

def _is_system_path(path: str) -> bool:
    return bool(_SYSTEM_PATHS.match(path))


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

class SensitiveFileDeletionRule(PerEventRule):
    rule_id = "WIN_SENSITIVE_FILE_DELETE_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 26:
            return None

        path = _target_path(event)
        if not path or not _is_sensitive(path):
            return None

        logon_id = _logon_id(event)
        file_name = _target_name(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Sensitive File Deletion",
            rule_type="per_event",
            requires=[
                Capability("session_established", bind=("logon_id",), values=(logon_id,))
            ] if logon_id else [],
            provides=[
                Capability("file_deleted", bind=("file_name",), values=(file_name,))
            ] if file_name else [],
            fusion_key=[("file_deletion", path.lower())],
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1485",
            technique_name="Data Destruction",
            tactic=MitreTactic.IMPACT,
            kill_chain_phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            tags=["file_deletion", "sensitive_file", "anti_forensics", "impact"],
            source="sysmon",
            description=f"Deletion of sensitive file: {path}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "file_path": path,
                "file_name": file_name,
                "process": _process_name(event),
                "logon_id": logon_id,
                "source_ip": _ip(event),
            },
            entities={
                "file_name": file_name,
                "file_path": path,
            }
        )
    
class SystemFileDeletionRule(PerEventRule):
    rule_id = "WIN_SYSTEM_FILE_DELETE_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _event_id(event) != 26:
            return None

        path = _target_path(event)
        if not path:
            return None

        ext_match = bool(_SENSITIVE_EXTENSIONS.search(path))
        sys_match = _is_system_path(path)
        if not (ext_match and sys_match):
            return None

        logon_id = _logon_id(event)
        file_name = _target_name(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="System File Deletion",
            rule_type="per_event",
            requires=[
                Capability("session_established", bind=("logon_id",), values=(logon_id,))
            ] if logon_id else [],
            provides=[
                Capability("file_deleted", bind=("file_name",), values=(file_name,))
            ] if file_name else [],
            fusion_key=[("file_deletion", path.lower())],
            severity=Severity.CRITICAL,
            confidence=0.9,
            technique_id="T1485",
            technique_name="Data Destruction",
            tactic=MitreTactic.IMPACT,
            kill_chain_phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            tags=["file_deletion", "system_file", "defense_evasion", "impact"],
            source="sysmon",
            description=f"Deletion of system/critical binary: {path}",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "file_path": path,
                "file_name": file_name,
                "process": _process_name(event),
                "parent_process": _parent_name(event),
                "logon_id": logon_id,
            },
            entities={
                "file_name": file_name,
                "file_path": path,
            }
        )
    
class MassFileDeletionRule(AggregateRule):
    rule_id = "WIN_MASS_FILE_DELETE_001"
    THRESHOLD = 3
    WINDOW = timedelta(minutes=5)

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        deletes = [e for e in events if _event_id(e) == 26 and _target_path(e)]
        if not deletes:
            return []

        by_actor: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in deletes:
            lid = _logon_id(e)
            eid = e.process.entity_id if e.process else None
            key = lid or eid
            if key:
                by_actor[key].append(e)

        findings = []
        for actor_key, evs in by_actor.items():
            evs.sort(key=lambda e: e.timestamp)
            if len(evs) < self.THRESHOLD:
                continue

            window = evs[-1].timestamp - evs[0].timestamp
            if window > self.WINDOW:
                continue

            paths = [_target_path(e) for e in evs if _target_path(e)]
            logon_id = _logon_id(evs[0])

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Mass File Deletion",
                rule_type="aggregate",
                requires=[
                    Capability("session_established", bind=("logon_id",), values=(logon_id,))
                ] if logon_id else [],
                provides=[],
                fusion_key=[("mass_deletion", actor_key)],
                severity=Severity.HIGH,
                confidence=0.8,
                technique_id="T1485",
                technique_name="Data Destruction",
                tactic=MitreTactic.IMPACT,
                kill_chain_phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
                tags=["file_deletion", "mass_deletion", "anti_forensics", "impact"],
                source="sysmon",
                description=(
                    f"{len(evs)} file deletions in {window.seconds}s "
                    f"by actor {actor_key}"
                ),
                timestamp=evs[0].timestamp,
                triggered_by=[e.id for e in evs],
                extra={
                    "file_count": len(evs),
                    "window_seconds": window.seconds,
                    "files_deleted": paths[:20],  
                    "logon_id": logon_id,
                    "actor_key": actor_key,
                },
                entities={
                    "files_deleted": paths,
                }
            ))

        return findings



def get_sysmon_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        SuspiciousFileDropRule(),
        SensitiveFileDeletionRule(),
        SystemFileDeletionRule()
    ]
    aggregate = [
        MassFileDeletionRule()
    ]
    return per_event, aggregate