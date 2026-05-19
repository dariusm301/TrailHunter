from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional
from models.events import NormalizedEvent
from detection.models import DetectionFinding, DetectionReport, Severity
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class PerEventRule(ABC):
    @property
    @abstractmethod
    def rule_id(self) -> str: ...

    @abstractmethod
    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]: ...


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

    def analyze(
        self,
        events: list[NormalizedEvent],
        collection_id: str,
        source: str,
    ) -> DetectionReport:
        findings: list[DetectionFinding] = []

        for i, event in enumerate(events):
            for rule in self._per_event:
                try:
                    finding = rule.match(event, index=i)
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    logger.warning(f"[{rule.rule_id}] event error {i}: {e}")

        for rule in self._aggregate:
            try:
                results = rule.match(events)
                findings.extend(results)
            except Exception as e:
                logger.warning(f"[{rule.rule_id}] aggregate error: {e}")

        return DetectionReport(
            collection_id=collection_id,
            source=source,
            total_events=len(events),
            findings=findings,
        )