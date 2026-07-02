
from __future__ import annotations

from collections import defaultdict
from detection.models import DetectionFinding


_SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_value(f: DetectionFinding):
    return _SEV_ORDER.get(f.severity.value if f.severity else "", 0)

_IDENTITY_KEYS = frozenset({"logon_id", "user_sid", "member_sid"})

def _merge_group(findings: list[DetectionFinding]) -> DetectionFinding:
    base = max(findings, key=lambda f: (_sev_value(f), f.confidence or 0))
    triggered_by: list[str] = []
    tags: list[str] = []
    requires = []
    provides = []
    entities: dict = {}
    extra: dict = {}
    identity_values: dict[str, set] = defaultdict(set)
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
            if v is None:
                continue
            if k in _IDENTITY_KEYS:
                identity_values[k].add(v)
            elif k not in extra:
                extra[k] = v
        event_count += (f.event_count or len(f.triggered_by or []))

    for k, values in identity_values.items():
        if len(values) == 1:
            extra[k] = next(iter(values))
        else:
            extra[k] = sorted(values)
            extra[f"{k}_conflict"] = True

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
    passthrough = []
    key_to_findings = defaultdict(list)

    def get_keys(f):
        raw = getattr(f, "fusion_key", None) or []
        if isinstance(raw, tuple):        
            raw = [raw]
        return [tuple(k) if isinstance(k, (list, tuple)) else (k,) for k in raw]

    for f in findings:
        keys = get_keys(f)
        if not keys:
            passthrough.append(f)
        else:
            for key in keys:
                key_to_findings[key].append(f)

    visited = set()
    fused = []

    for f in findings:
        if not get_keys(f) or id(f) in visited:
            continue

        cluster = []
        queue = [f]
        visited.add(id(f))

        while queue:
            current = queue.pop(0)
            cluster.append(current)
            for key in get_keys(current):
                for neighbor in key_to_findings[key]:
                    if id(neighbor) not in visited:
                        visited.add(id(neighbor))
                        queue.append(neighbor)

        fused.append(cluster[0] if len(cluster) == 1 else _merge_group(cluster))

    return passthrough + fused