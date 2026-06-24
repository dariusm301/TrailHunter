import json
import networkx as nx
from collections import defaultdict
from models.events import NormalizedEvent
from detection.models import DetectionFinding
from datetime import timedelta, timezone, datetime
from dataclasses import dataclass, field
from detection.fusion import fuse_findings


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

TEMPORAL_WINDOW = timedelta(hours=6)

TIGHT_WINDOW = timedelta(minutes=2)

TIGHT_CONTRACTS: frozenset[str] = frozenset({"code_execution"})

GENERIC_SIDS: frozenset[str] = frozenset({
    "S-1-5-18",   # LOCAL SYSTEM
    "S-1-5-19",   # LOCAL SERVICE
    "S-1-5-20",   # NETWORK SERVICE
})


# ─────────────────────────────────────────────────────────────────────────────
# Correlator
# ─────────────────────────────────────────────────────────────────────────────

class Correlator:

    def __init__(self, events: dict[str, NormalizedEvent], findings: list[DetectionFinding]):
        self.events      = events
        self.findings    = findings
        self.finding_map = {f.id: f for f in findings}
        self.graph       = nx.DiGraph()
        self.diagnostics: dict[str, list] = {
            "matched_contracts": [],  
            "orphan_requires":   [],   
            "orphan_provides":   [],   
            "poisoned_none":     [],   
        }

    # ── Public API ────────────────────────────────────────────────────────────

    def build_graph(self) -> nx.DiGraph:
        self.add_findings()
        self.correlate_provenance()      
        self.correlate_lineage()        
        self.actor_groups = self.partition_actors()
        self._run_diagnostics()
        self.print_diagnostics()
        return self.graph

    # ── Graph construction ────────────────────────────────────────────────────

    def add_findings(self) -> None:
        for finding in self.findings:
            self.graph.add_node(
                finding.id,
                type   = "AlertNode",
                label  = finding.rule_name,
                fields = self._get_key_fields(finding),
            )

    def _finding_ip(self, finding) -> str | None:
        for tid in finding.triggered_by:
            ev = self.events.get(tid)
            if ev and ev.source and ev.source.ip:
                return ev.source.ip
        return None
    
    @staticmethod
    def _serialize_event(ev: NormalizedEvent) -> dict:
        return ev.model_dump(exclude_none=True, mode="json")
    
    def _prune(self, o):
        if isinstance(o, dict):
            return {k: pv for k, v in o.items()
                    if (pv := self._prune(v)) not in (None, {}, [], "")}
        if isinstance(o, list):
            return [pv for v in o if (pv := self._prune(v)) not in (None, {}, [], "")]
        return o

    def serialize(self, collector_ip: list[str] | None = None) -> dict:
        actor_of = {fid: idx for idx, g in enumerate(self.actor_groups) for fid in g}
        event_payload: dict[str, dict] = {}
        nodes = []
        for nid, attrs in self.graph.nodes(data=True):
            finding = self.finding_map[nid]
            fields = dict(attrs.get("fields", {}))
            fields["source_ip"] = self._finding_ip(finding)
            event_ids = []
            for tid in finding.triggered_by:
                ev = self.events.get(tid)
                if ev is None:
                    continue
                event_ids.append(tid)
                if tid not in event_payload:
                    event_payload[tid] = self._serialize_event(ev)  
            requires, provides, fusion_key = self._node_caps([finding])
            nodes.append({
                "id": nid, "type": attrs.get("type"), "label": attrs.get("label"),
                "actor": actor_of.get(nid), "fields": fields,
                "event_ids": event_ids,
                "requires": requires,
                "provides": provides,
                "fusion_key": fusion_key,
                "is_probe": getattr(finding, "is_probe", False),
            })
        edges = [
            {"source": s, "target": t, "relation": a.get("relation"),
            "nature": a.get("nature"), "cap": a.get("cap")}
            for s, t, a in self.graph.edges(data=True)
        ]
        return {"nodes": nodes, "edges": edges, "events": event_payload,
                "actor_count": len(self.actor_groups), "collector_ip": collector_ip or []}

    # ── Provenance: requires/provides contracts (CAUSAL) ───────────────────────

    @staticmethod
    def _cap_window(cap) -> timedelta:
        return TIGHT_WINDOW if cap.name in TIGHT_CONTRACTS else TEMPORAL_WINDOW

    @staticmethod
    def _cap_has_none(cap) -> bool:
        """A contract is poisoned if any bound value is None — never match on None."""
        return any(v is None for v in (cap.values or ()))

    def correlate_provenance(self) -> None:
        """
        """
        provider_index: dict[tuple, list[DetectionFinding]] = defaultdict(list)
        for f in self.findings:
            for cap in (f.provides or []):
                if self._cap_has_none(cap):
                    self.diagnostics["poisoned_none"].append((f.id, cap))
                    continue
                provider_index[(cap.name, cap.bind, cap.values)].append(f)
        _MISSING_TS = datetime.min.replace(tzinfo=timezone.utc)
        for consumer in self.findings:
            for req in (consumer.requires or []):
                if self._cap_has_none(req):
                    self.diagnostics["poisoned_none"].append((consumer.id, req))
                    continue
                window = self._cap_window(req)
                providers = provider_index.get((req.name, req.bind, req.values), [])
                matched_any = False
                for provider in providers:
                    if provider.id == consumer.id:
                        continue
                    p_ts = self._get_finding_ts(provider)
                    c_ts = self._get_finding_ts(consumer)
                    if p_ts != _MISSING_TS and c_ts != _MISSING_TS:
                        if abs(p_ts - c_ts) > window:
                            continue
                    self.graph.add_edge(
                        provider.id, consumer.id,
                        relation="requires/provides",
                        nature="causal",
                        cap=req.name,
                    )
                    self.diagnostics["matched_contracts"].append((provider.id, consumer.id, req))
                    matched_any = True
                if not matched_any:
                    self.diagnostics["orphan_requires"].append((consumer.id, req))

    # ── Lineage: process parent/child (CAUSAL) ─────────────────────────────────

    def _trigger_event(self, finding: DetectionFinding) -> NormalizedEvent | None:
        for trigger_id in finding.triggered_by:
            ev = self.events.get(trigger_id)
            if ev is not None:
                return ev
        return None

    def correlate_lineage(self) -> None:
        """
        Correlates parent→child process relationships using Sysmon ProcessGUID
        (entity_id) where available, falling back to PID for non-Sysmon events.
        """
        pid_to_findings: dict[int, list[str]] = defaultdict(list)
        guid_to_findings: dict[str, list[str]] = defaultdict(list)

        for f in self.findings:
            ev = self._trigger_event(f)
            if not (ev and ev.process):
                continue
            if ev.process.pid is not None:
                pid_to_findings[ev.process.pid].append(f.id)
            if ev.process.entity_id:
                guid_to_findings[ev.process.entity_id].append(f.id)

        seen: set[tuple[str, str]] = set()

        for f in self.findings:
            ev = self._trigger_event(f)
            if not (ev and ev.process and ev.process.parent):
                continue

            parent = ev.process.parent

            # Prefer GUID (Sysmon), fallback to PID
            if parent.entity_id:
                parent_fids = guid_to_findings.get(parent.entity_id, [])
            elif parent.pid is not None:
                parent_fids = pid_to_findings.get(parent.pid, [])
            else:
                continue

            for parent_fid in parent_fids:
                if parent_fid == f.id:
                    continue
                pair = (parent_fid, f.id)
                if pair in seen:
                    continue
                if abs(self._get_finding_ts(self.finding_map[parent_fid])
                    - self._get_finding_ts(f)) > TEMPORAL_WINDOW:
                    continue
                seen.add(pair)
                self.graph.add_edge(
                    parent_fid, f.id,
                    relation="parent",
                    nature="causal",
                )

    # ── Identity / co-derivation: GROUPING (no edges) ──────────────────────────


    def _network_groups(self) -> list[set[str]]:
        """Findings sharing a remote source IP (network-level identity)."""
        ip_to_ids: dict[str, set[str]] = defaultdict(set)
        for f in self.findings:
            ip = self._finding_ip(f)         
            if ip:
                ip_to_ids[ip].add(f.id)
        return [ids for ids in ip_to_ids.values() if len(ids) > 1]

    def _process_groups(self) -> list[set[str]]:
        """Findings sharing process identity (process_guid preferred, pid fallback)."""
        key_to_ids: dict[str, set[str]] = defaultdict(set)
        for f in self.findings:
            ev = self._trigger_event(f)
            if not ev or not ev.process:
                continue
            guid = getattr(ev.process, "entity_id", None) or getattr(ev.process, "guid", None)
            pid = ev.process.pid
            key = f"guid:{guid}" if guid else (f"pid:{pid}" if pid is not None else None)
            if key:
                key_to_ids[key].add(f.id)
        return [ids for ids in key_to_ids.values() if len(ids) > 1]

    def _account_groups(self) -> list[set[str]]:
        """Findings sharing a non-generic SID."""
        SID_KEYS = ("user_sid", "member_sid")
        sid_to_ids: dict[str, set[str]] = defaultdict(set)
        for f in self.findings:
            extra = f.extra or {}
            for key in SID_KEYS:
                sid = extra.get(key)
                if isinstance(sid, str) and sid and sid not in GENERIC_SIDS:
                    sid_to_ids[sid].add(f.id)
                    break
        return [ids for ids in sid_to_ids.values() if len(ids) > 1]

    def _coderivation_groups(self) -> list[set[str]]:
        return self._process_groups() + self._account_groups() + self._network_groups()

    # ── Actor partitioning: WCC + union-find over co-derivation groups ─────────

    def partition_actors(self) -> list[set[str]]:
        components = list(nx.weakly_connected_components(self.graph))
        parent = list(range(len(components)))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        fid_to_comp: dict[str, int] = {}
        for idx, comp in enumerate(components):
            for fid in comp:
                fid_to_comp[fid] = idx

        for group in self._coderivation_groups():
            idxs = list({fid_to_comp[f] for f in group if f in fid_to_comp})
            for other in idxs[1:]:
                union(idxs[0], other)

        merged: dict[int, set[str]] = defaultdict(set)
        for idx, comp in enumerate(components):
            merged[find(idx)] |= comp
        return list(merged.values())

    # ── Diagnostics ────────────────────────────────────────────────────────────

    def _run_diagnostics(self) -> None:
        """Flag provides that were never consumed (dead/planned contracts)."""
        consumed: set[tuple] = {
            (cap.name, cap.bind, cap.values)
            for (_p, _c, cap) in self.diagnostics["matched_contracts"]
        }
        for f in self.findings:
            for cap in (f.provides or []):
                if self._cap_has_none(cap):
                    continue
                if (cap.name, cap.bind, cap.values) not in consumed:
                    self.diagnostics["orphan_provides"].append((f.id, cap))

    def print_diagnostics(self) -> None:
        """DEV: human-readable summary of what correlated and what didn't."""
        d = self.diagnostics
        print(f"\n{'='*60}\nCORRELATION DIAGNOSTICS\n{'='*60}")
        print(f"Findings:           {len(self.findings)}")
        print(f"Causal edges:       {self.graph.number_of_edges()}")
        print(f"Actors (partitions):{len(getattr(self, 'actor_groups', []))}")
        print(f"\nMatched contracts ({len(d['matched_contracts'])}):")
        for p, c, cap in d["matched_contracts"]:
            print(f"  {self._label(p)} ──[{cap.name}]──▶ {self._label(c)}")
        print(f"\nOrphan REQUIRES — wanted a provider, none matched ({len(d['orphan_requires'])}):")
        for fid, cap in d["orphan_requires"]:
            print(f"  {self._label(fid)} needs {cap.name}{cap.bind}={cap.values}")
        print(f"\nOrphan PROVIDES — offered, never consumed ({len(d['orphan_provides'])}):")
        for fid, cap in d["orphan_provides"]:
            print(f"  {self._label(fid)} offers {cap.name}{cap.bind}={cap.values}")
        print(f"\nPoisoned (None value, skipped) ({len(d['poisoned_none'])}):")
        for fid, cap in d["poisoned_none"]:
            print(f"  {self._label(fid)} {cap.name}{cap.bind}={cap.values}")
        print(f"{'='*60}\n")

    def _label(self, fid: str) -> str:
        f = self.finding_map.get(fid)
        return f.rule_name if f else fid

    # ── Helpers — timestamps & labels ─────────────────────────────────────────

    def _normalize_ts(self, ts: datetime) -> datetime:
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts

    def _get_finding_ts(self, finding: DetectionFinding) -> datetime:
        for trigger_id in finding.triggered_by:
            if trigger_id in self.events:
                ts = self.events[trigger_id].timestamp
                if ts:
                    return self._normalize_ts(ts)
        return datetime.min.replace(tzinfo=timezone.utc)

    def _serialize_cap(self, cap) -> dict:
        return {
            "name": getattr(cap, "name", None),
            "bind": list(getattr(cap, "bind", ()) or ()),
            "values": [str(v) for v in (getattr(cap, "values", ()) or ())],
        }

    def _node_caps(self, findings):
        requires, provides, fusion = [], [], []
        for f in findings:
            requires += [self._serialize_cap(c) for c in (f.requires or [])]
            provides += [self._serialize_cap(c) for c in (f.provides or [])]
            for key in (f.fusion_key or []):           # list[tuple]
                fusion.append([str(x) for x in key])   # tuple -> list ca sa fie JSON
        return requires, provides, fusion

    def _get_key_fields(self, obj) -> dict:
        _missing = datetime.min.replace(tzinfo=timezone.utc)
        if isinstance(obj, DetectionFinding):
            fused = obj.extra.get("fused_signals", []) if obj.extra else []
            ts = self._get_finding_ts(obj)
            ev = self._trigger_event(obj)
            return {
                "timestamp":  ts.isoformat() if ts != _missing else "—",
                "rule":       obj.rule_name or "—",
                "severity":   obj.severity.value if obj.severity else "—",
                "kill_chain": obj.kill_chain_phase.value if obj.kill_chain_phase else "—",
                "user":       (ev.user.name if ev and ev.user else None) or "—",
                "process":    (ev.process.name if ev and ev.process else None) or "—",
                "events":     str(len(obj.triggered_by)),
                "fused_signals": fused,
            }
        ts = obj.timestamp
        return {
            "timestamp": self._normalize_ts(ts).isoformat() if ts else "—",
            "action":    (obj.event.action if obj.event else None) or "—",
            "user":      (obj.user.name if obj.user else None) or "—",
            "process":   (obj.process.name if obj.process else None) or "—",
        }

    # ── Helpers — sessions (viewer only) ───────────────────────────────────────

    def _group_by_session(self) -> dict[str, list[str]]:
        ip_to_findings: dict[str, set[str]] = defaultdict(set)
        for finding in self.findings:
            for trigger_id in finding.triggered_by:
                event = self.events.get(trigger_id)
                if event and event.source and event.source.ip:
                    ip_to_findings[event.source.ip].add(finding.id)
                    break
        return {ip: list(ids) for ip, ids in ip_to_findings.items() if len(ids) > 1}