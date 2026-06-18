from __future__ import annotations
from typing import Optional

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
)
from ..helpers import _ts, _username, _event_id


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
            tags=["defense_evasion", "anti_forensics"],
            source="windows_events",
            description=f"Windows logs cleared by '{_username(event)}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "username": _username(event),
                "channel_cleared": (
                    event.winlog.extra.get("channel_cleared")
                    if event.winlog and event.winlog.extra else None
                ),
            }
        )


def get_defense_evasion_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        LogClearedRule(),
    ]
    aggregate = []
    return per_event, aggregate