from __future__ import annotations
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class KillChainPhase(str, Enum):
    RECONNAISSANCE       = "reconnaissance"
    WEAPONIZATION        = "weaponization"
    DELIVERY             = "delivery"
    EXPLOITATION         = "exploitation"
    INSTALLATION         = "installation"
    COMMAND_AND_CONTROL  = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class MitreTactic(str, Enum):
    INITIAL_ACCESS      = "initial_access"
    EXECUTION           = "execution"
    PERSISTENCE         = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION     = "defense_evasion"
    CREDENTIAL_ACCESS   = "credential_access"
    DISCOVERY           = "discovery"
    LATERAL_MOVEMENT    = "lateral_movement"
    COLLECTION          = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION        = "exfiltration"
    IMPACT              = "impact"


class RuleMeta(BaseModel):
    rule_id:          str
    name:             str
    description:      str
    severity:         Severity
    technique_id:     Optional[str] = None   # ex: "T1053.005"
    technique_name:   Optional[str] = None   # ex: "Scheduled Task/Job"
    tactic:           Optional[MitreTactic] = None
    kill_chain_phase: Optional[KillChainPhase] = None
    tags:             list[str] = []         # ex: ["persistence", "evasion"]


class DetectionFinding(BaseModel):
    id:        str      = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Metadata
    rule_id:          str
    rule_name:        str
    severity:         Severity
    confidence:       float             # 0.0 – 1.0
    technique_id:     Optional[str]     = None
    technique_name:   Optional[str]     = None
    tactic:           Optional[MitreTactic]      = None
    kill_chain_phase: Optional[KillChainPhase]   = None
    tags:             list[str]         = []

    # Source
    source:      str                    # "windows_events" | "web_logs" | "processes" | "registry"
    description: str                    # Description of the finding, with context from the rule

    triggered_by: list[int] = []        # index in NormalizedEvent list
    event_count:  int = 1               

    # Additional context
    extra: dict[str, Any] = {}



class DetectionReport(BaseModel):
    collection_id: str
    analyzed_at:   datetime = Field(default_factory=datetime.utcnow)
    source:        str                      
    total_events:  int
    findings:      list[DetectionFinding] = []

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for s in order:
            if any(f.severity == s for f in self.findings):
                return s