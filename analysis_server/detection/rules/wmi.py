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
    return event.event.created or event.timestamp or None

def _action(event: NormalizedEvent) -> str:
    return (event.event.action or "") if event.event else ""

def _original(event: NormalizedEvent) -> str:
    if not event.event or not event.event.original:
        return ""
    raw = event.event.original
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="ignore")
    return raw

def _username(event: NormalizedEvent) -> Optional[str]:
    return event.user.name if event.user else None

def _pid(event: NormalizedEvent) -> Optional[int]:
    return event.process.pid if event.process else None

def _host(event: NormalizedEvent) -> Optional[str]:
    return event.host.name if event.host else None  

# ─────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────

# Suspicious WMI query namespaces / classes
_SUSPICIOUS_WMI_QUERIES = re.compile(
    r"(win32_process|win32_product|win32_service"
    r"|win32_startupcommand|win32_useraccount"
    r"|select\s+\*\s+from\s+win32_shadow"
    r"|__eventfilter|__eventconsumer|__filtertoconsumerbinding"
    r"|activescripteventconsumer|commandlineeventconsumer)",
    re.IGNORECASE
)

# Suspicious content in WMI subscriptions
_SUSPICIOUS_SUBSCRIPTION_CONTENT = re.compile(
    r"(powershell|cmd\.exe|wscript|mshta|certutil"
    r"|downloadstring|iex\s*\(|encodedcommand"
    r"|-enc\s|-windowstyle\s+hidden|bypass)",
    re.IGNORECASE
)

# Legitimate WMI providers — reduces false positives on 5857
_LEGITIMATE_PROVIDERS = re.compile(
    r"^(cimwin32|wmiprov|ntevtlog|secrcw32"
    r"|msvds|wmipdskq|wmipdskq|wmipjobj"
    r"|wbemcore|repdrvfs)",
    re.IGNORECASE
)

_LEGITIMATE_SUBSCRIPTIONS = re.compile(
    r"(SCM Event Log Filter|NTEventLogEventConsumer"
    r"|BVTFilter|TSlogonEvents|RAevent)",
    re.IGNORECASE
)

# ═════════════════════════════════════════════
# PER-EVENT RULES
# ═════════════════════════════════════════════

class WmiSubscriptionCreatedRule(PerEventRule):
    """Event 5861 — WMI event subscription created = persistence mechanism."""
    rule_id = "WMI_SUBSCRIPTION_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _action(event) != "wmi_event_subscription_created":
            return None

        original = _original(event)

        has_suspicious_content = bool(
            _SUSPICIOUS_SUBSCRIPTION_CONTENT.search(original)
        )
        
        if _LEGITIMATE_SUBSCRIPTIONS.search(original):
            return None

        severity = Severity.CRITICAL if has_suspicious_content else Severity.HIGH
        confidence = 0.97 if has_suspicious_content else 0.85

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="WMI Event Subscription Created",
            requires=[Capability("code_execution", bind=("host",))],
            provides=[Capability("persistence", bind=("host",))],
            severity=severity,
            confidence=confidence,
            technique_id="T1546.003",
            technique_name="Event Triggered Execution: Windows Management Instrumentation Event Subscription",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["persistence", "wmi", "subscription"],
            source="wmi",
            description=f"WMI event subscription created by '{_username(event)}'",
            timestamp=_ts(event),
            triggered_by=[event.id],
            extra={
                "username": _username(event),
                "pid": _pid(event),
                "has_suspicious_content": has_suspicious_content,
                "raw": original[:300],
            },
            entities={
                "host": _host(event),
                "user": _username(event),
            }
        )


# ─────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────

def get_wmi_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        WmiSubscriptionCreatedRule(),
    ]
    aggregate = []
    return per_event, aggregate