"""
Finding fusion (signal aggregation).

Runs BETWEEN detection and correlation:

    raw_findings  ->  fuse_findings()  ->  fused_findings  ->  Correlator

Multiple rules can detect the SAME fact about the SAME entity from different
angles (e.g. four scheduled-task rules all describing one task creation, seen
across 4698 + Sysmon). Those collapse into ONE composite finding, so the graph
shows one node per fact instead of four redundant ones pointing at the same
effect.

KEY PRINCIPLE — only fuse findings that describe the SAME (entity, event_kind):
  - same task, all "created"      -> fuse
  - same task, "created" vs "executed" -> DO NOT fuse (different facts, that's a
    causal relationship, handled later by the correlator)

The entity key is rule-family specific. For scheduled tasks it is
(task_name, executable, command) AFTER normalization — which is why the
normalizer must clean these identically across 4698 and Sysmon.
"""

from __future__ import annotations

from collections import defaultdict
from detection.models import DetectionFinding

# ─────────────────────────────────────────────────────────────────────────────
# Fusion
# ─────────────────────────────────────────────────────────────────────────────

_SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_value(f: DetectionFinding):
    return _SEV_ORDER.get(f.severity.value if f.severity else "", 0)


def _merge_group(findings: list[DetectionFinding]) -> DetectionFinding:
    """
    """
    base = max(findings, key=lambda f: (_sev_value(f), f.confidence or 0))

    triggered_by: list[str] = []
    tags: list[str] = []
    requires = []
    provides = []
    entities: dict = {}
    extra: dict = {}
    signals: list[str] = []
    event_count = 0

    seen_trig = set()
    for f in findings:
        signals.append(f.rule_name)
        for t in (f.triggered_by or []):
            if t not in seen_trig:
                seen_trig.add(t)
                triggered_by.append(t)
        for tag in (f.tags or []):
            if tag not in tags:
                tags.append(tag)
        for c in (f.requires or []):
            if c not in requires:
                requires.append(c)
        for c in (f.provides or []):
            if c not in provides:
                provides.append(c)

        for k, v in (f.entities or {}).items():
            entities.setdefault(k, v)
        for k, v in (f.extra or {}).items():
            extra.setdefault(k, v)
        event_count += (f.event_count or len(f.triggered_by or []))

    extra["fused_signals"] = signals
    extra["fused_rule_ids"] = sorted({f.rule_id for f in findings})

    confidence = max((f.confidence or 0) for f in findings)

    composite_name = (
        f"{base.rule_name}  (+{len(findings) - 1} signals)"
        if len(findings) > 1 else base.rule_name
    )

    return base.model_copy(update={
        "confidence":   confidence,
        "requires":     requires,
        "provides":     provides,
        "tags":         tags,
        "triggered_by": triggered_by,
        "event_count":  event_count,
        "entities":     entities,
        "extra":        extra,
        "rule_name":    composite_name,
    })


def fuse_findings(findings):
    groups = defaultdict(list)
    passthrough = []
    for f in findings:
        if f.fusion_key is None:
            passthrough.append(f)
        else:
            groups[f.fusion_key].append(f)
    fused = []
    for group in groups.values():
        fused.append(group[0] if len(group) == 1 else _merge_group(group))
    return passthrough + fused