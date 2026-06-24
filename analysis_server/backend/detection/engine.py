from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional
from models.events import NormalizedEvent
from detection.models import DetectionFinding, DetectionReport, Severity, Capability
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class PerEventRule(ABC):
    @property
    @abstractmethod
    def rule_id(self) -> str: ...

    @abstractmethod
    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]: ...


class AggregateRule(ABC):
    @property
    @abstractmethod
    def rule_id(self) -> str: ...

    @abstractmethod
    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]: ...


# ─────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────

class DetectionEngine:
    def __init__(
        self,
        per_event_rules: list[PerEventRule] = [],
        aggregate_rules: list[AggregateRule] = [],
    ):
        self._per_event  = per_event_rules
        self._aggregate  = aggregate_rules

    def register(self, rule: PerEventRule | AggregateRule) -> None:
        if isinstance(rule, PerEventRule):
            self._per_event.append(rule)
        elif isinstance(rule, AggregateRule):
            self._aggregate.append(rule)

    def analyze(self, events, collection_id, source) -> DetectionReport:
        findings: list[DetectionFinding] = []
        seen_event_rule: set[tuple[str, str]] = set()
        events_list = list(events.values())
        for event in events.values():
            for rule in self._per_event:
                try:
                    finding = rule.match(event)
                    if finding:
                        finding.is_probe = resolve_is_probe(finding, events)
                        key = (event.id, rule.rule_id)
                        if key not in seen_event_rule:
                            seen_event_rule.add(key)
                            logon_id = resolve_logon_id(finding, events)

                            if logon_id:
                                finding.requires.append(Capability("session_established", bind=("logon.id",), values=(logon_id,)))
                            findings.append(finding)
                except Exception as e:
                    logger.warning(f"[{rule.rule_id}] event error: {e}")

        for rule in self._aggregate:
            try:
                results = rule.match(events_list)
                for finding in results:
                    finding.is_probe = resolve_is_probe(finding, events)
                findings.extend(results)
            except Exception as e:
                logger.warning(f"[{rule.rule_id}] aggregate error: {e}")

        return DetectionReport(
            collection_id=collection_id,
            source=source,
            total_events=len(events),
            findings=findings,
        )
    
# HELPERS
def resolve_logon_id(finding: DetectionFinding, all_events: dict[str, NormalizedEvent]) -> str | None:
    for event_id in finding.triggered_by:
        event = all_events.get(event_id)
        if not event:
            continue
        
        entity_id = event.process.entity_id if event.process else None
        if not entity_id:
            continue
        
        for candidate in all_events.values():
            if (
                candidate.process
                and candidate.process.entity_id == entity_id
                and candidate.event.code == "1" 
                and candidate.logon
                and candidate.logon.id
            ):
                return candidate.logon.id
    
    return None

def resolve_is_probe(finding: DetectionFinding, all_events: dict[str, NormalizedEvent]) -> bool:
    for event_id in finding.triggered_by:
        event = all_events.get(event_id)
        if event is not None and getattr(event, "is_probe", False):
            return True
    return False