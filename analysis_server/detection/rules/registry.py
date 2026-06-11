from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Optional

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

def _ts(event: NormalizedEvent) -> datetime:
    return event.timestamp or None

def _path(event: NormalizedEvent) -> str:
    return (event.registry.path or "").lower() if event.registry else ""

def _value(event: NormalizedEvent) -> str: 
    v = event.registry.value if event.registry else None
    if isinstance(v, list):
        v = v[0] if v else None
    return (v or "")

def _data(event: NormalizedEvent) -> str:
    return (event.registry.data or "").lower() if event.registry else ""


# ─────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────

_RUN_KEYS = re.compile(
    r"(\\currentversion\\run$|\\currentversion\\runonce$"
    r"|\\currentversion\\runservices$)",
    re.IGNORECASE
)

_DEFENDER_EXCLUSION_PATHS = re.compile(
    r"windows defender.*(exclusion|disabled|real.?time)",
    re.IGNORECASE
)

_SUSPICIOUS_DATA_PATHS = re.compile(
    r"(\\temp\\|\\tmp\\|\\appdata\\local\\temp\\"
    r"|\\users\\public\\|\\programdata\\"
    r"|\\windows\\temp\\|%temp%|%appdata%)",
    re.IGNORECASE
)

_SUSPICIOUS_EXTENSIONS = re.compile(
    r"\.(exe|dll|bat|ps1|vbs|msi|scr|com|pif|cmd)(\s|\"|\\'|$)",
    re.IGNORECASE
)

_SUSPICIOUS_SERVICE_PATHS = re.compile(
    r"(\\temp\\|\\tmp\\|\\users\\public\\"
    r"|cmd\.exe|powershell\.exe|wscript\.exe"
    r"|certutil|mshta|rundll32)",
    re.IGNORECASE
)

_LEGITIMATE_SERVICE_NAMES = re.compile(
    r"^\.(net|wow|clr)|^(wlan|audio|event|print|rpc|dns|dhcp"
    r"|bits|w32|spooler|lanman|netlogon|plug)",
    re.IGNORECASE
)

_SUSPICIOUS_DATA_PATHS = re.compile(
    r"(\\temp\\|\\tmp\\"
    r"|\\appdata\\local\\temp\\"  # doar Temp, nu AppData generic
    r"|\\users\\public\\"
    r"|\\programdata\\"
    r"|\\windows\\temp\\"
    r"|%temp%)",
    re.IGNORECASE
)

_SUSPICIOUS_RUN_COMMANDS = re.compile(
    r"(powershell|cmd|wscript|mshta|rundll32|certutil)"
    r".*(hidden|windowstyle|-enc|-w\s+hidden|bypass)",
    re.IGNORECASE
)

_WEBSERVER_PATHS = re.compile(
    r"(\\htdocs\\|\\wwwroot\\|\\inetpub\\|\\uploads\\"
    r"|/htdocs/|/wwwroot/|/uploads/)",
    re.IGNORECASE
)

# ═════════════════════════════════════════════
# PER-EVENT RULES
# ═════════════════════════════════════════════

class RunKeyPersistenceRule(PerEventRule):
    """Suspicious executable in Run key — persistence."""
    rule_id = "REG_RUNKEY_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        path = _path(event)
        
        data = _data(event)
        value = _value(event)

        if not _RUN_KEYS.search(path):
            return None

        in_suspicious_path = bool(_SUSPICIOUS_DATA_PATHS.search(data))
        in_webserver_path = bool(_WEBSERVER_PATHS.search(data))
        has_suspicious_cmd = bool(_SUSPICIOUS_RUN_COMMANDS.search(data))

        if not any([in_suspicious_path, in_webserver_path, has_suspicious_cmd]):
            return None

        if in_webserver_path or (has_suspicious_cmd and in_suspicious_path):
            severity = Severity.CRITICAL
            confidence = 0.97
        elif has_suspicious_cmd:
            severity = Severity.CRITICAL
            confidence = 0.93
        else:
            severity = Severity.HIGH
            confidence = 0.80
        
        value_name = value

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Run Key Entry",
            rule_type="per_event",
            requires=(Capability("runkey_created", bind=("value_name",), values=(value_name,)),),
            provides=(),
            severity=severity,
            confidence=confidence,
            technique_id="T1547.001",
            technique_name="Boot or Logon Autostart: Registry Run Keys",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["persistence", "registry", "run_key"],
            source="registry",
            description=f"Run key suspect: '{value}' → '{data[:100]}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "registry_path": path,
                "value_name": value,
                "executable": data,
                "in_suspicious_path": in_suspicious_path,
            }
        )


class DefenderExclusionRegistryRule(PerEventRule):
    """Defender exclusion set in registry — defense evasion."""
    rule_id = "REG_DEFENDER_EXCLUSION_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        path = _path(event)
        if not _DEFENDER_EXCLUSION_PATHS.search(path):
            return None

        data = _data(event)
        value = _value(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Windows Defender Exclusion in Registry",
            rule_type="per_event",
            severity=Severity.CRITICAL,
            confidence=0.95,
            technique_id="T1562.001",
            technique_name="Impair Defenses: Disable or Modify Tools",
            tactic=MitreTactic.DEFENSE_EVASION,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["defense_evasion", "defender", "registry"],
            source="registry",
            description=f"Defender exclusion detected in registry: '{value}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "registry_path": path,
                "value_name": value,
                "excluded_path": data,
            }
        )


class SuspiciousServiceRegistryRule(PerEventRule):
    """Suspect service in HKLM\\Services."""
    rule_id = "REG_SUSPICIOUS_SERVICE_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        path = _path(event)
        if "currentcontrolset\\services" not in path:
            return None

        data = _data(event)
        value = _value(event)

        if not data or not _SUSPICIOUS_EXTENSIONS.search(data):
            return None

        if _LEGITIMATE_SERVICE_NAMES.match(value):
            return None

        if not _SUSPICIOUS_SERVICE_PATHS.search(data):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Service Registry Entry",
            rule_type="per_event",
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1543.003",
            technique_name="Create or Modify System Process: Windows Service",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["persistence", "service", "registry"],
            source="registry",
            description=f"Suspect service in registry: '{value}' → '{data[:100]}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "registry_path": path,
                "service_name": value,
                "image_path": data,
            }
        )


# ─────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────

def get_registry_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        RunKeyPersistenceRule(),
        DefenderExclusionRegistryRule(),
        SuspiciousServiceRegistryRule(),
    ]
    aggregate = []
    return per_event, aggregate