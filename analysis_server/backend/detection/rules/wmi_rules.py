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
from ..helpers import _ts, _username, _pid, _host, _get_original


_SUSPICIOUS_SUBSCRIPTION_CONTENT = re.compile(
    r"(powershell|cmd\.exe|wscript|mshta|certutil"
    r"|downloadstring|iex\s*\(|encodedcommand"
    r"|-enc\s|-windowstyle\s+hidden|bypass)",
    re.IGNORECASE
)

_LEGITIMATE_SUBSCRIPTIONS = re.compile(
    r"(SCM Event Log Filter|NTEventLogEventConsumer"
    r"|BVTFilter|TSlogonEvents|RAevent)",
    re.IGNORECASE
)



class WmiSubscriptionCreatedRule(PerEventRule):
    rule_id = "WMI_SUBSCRIPTION_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if not (event.event and event.event.action == "wmi_event_subscription_created"):
            return None

        original = _get_original(event)
        if _LEGITIMATE_SUBSCRIPTIONS.search(original):
            return None

        has_suspicious_content = bool(_SUSPICIOUS_SUBSCRIPTION_CONTENT.search(original))
        severity   = Severity.CRITICAL if has_suspicious_content else Severity.HIGH
        confidence = 0.97 if has_suspicious_content else 0.85

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="WMI Event Subscription Created",
            rule_type="per_event",
            requires=[Capability("code_execution", bind=("host",), values=(_host(event),))],
            provides=[Capability("persistence",     bind=("host",), values=(_host(event),))],
            severity=severity,
            confidence=confidence,
            technique_id="T1546.003",
            technique_name="Event Triggered Execution: WMI Event Subscription",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["persistence", "wmi", "subscription"],
            source="wmi",
            description=f"WMI event subscription created by '{_username(event)}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "username":               _username(event),
                "pid":                    _pid(event),
                "has_suspicious_content": has_suspicious_content,
                "raw":                    original[:300],
            },
            entities={
                "host": _host(event),
                "user": _username(event),
            }
        )



def get_wmi_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        WmiSubscriptionCreatedRule(),
    ]
    aggregate = []
    return per_event, aggregate