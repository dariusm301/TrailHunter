import json
import networkx as nx
from collections import defaultdict
from models.events import NormalizedEvent
from detection.models import DetectionFinding
from datetime import timedelta, timezone, datetime
from dataclasses import dataclass, field


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Default window for value-rich contracts (file_name, sid — highly discriminant).
TEMPORAL_WINDOW = timedelta(hours=6)
# Tight window for weak-value contracts (command — common, needs proximity).
TIGHT_WINDOW = timedelta(minutes=2)

# Capability names whose values are weak/common and need the tight window.
TIGHT_CONTRACTS: frozenset[str] = frozenset({"code_execution"})

# SIDs too generic to group actors by (would collapse partitioning).
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
        # Diagnostics filled during build — inspect after build_graph().
        self.diagnostics: dict[str, list] = {
            "matched_contracts": [],   # (provider_id, consumer_id, capability)
            "orphan_requires":   [],   # (finding_id, capability) needing a provider that never came
            "orphan_provides":   [],   # (finding_id, capability) offered but never consumed
            "poisoned_none":     [],   # (finding_id, capability) with a None value (skipped)
        }

    # ── Public API ────────────────────────────────────────────────────────────

    def build_graph(self) -> nx.DiGraph:
        self.add_findings()
        self.correlate_provenance()      # requires/provides → causal edges
        self.correlate_lineage()         # parent pid → child pid → causal edges
        self.actor_groups = self.partition_actors()
        self._run_diagnostics()
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
        provider.provides[c] satisfies consumer.requires[c] when name, bind AND
        values are equal (Capability is frozen → exact tuple equality), within the
        per-contract temporal window. Edge direction: provider ──▶ consumer.
        """
        # Index providers by the capability they offer, for O(providers + consumers).
        # Key = (name, bind, values); only non-poisoned capabilities are indexed.
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
        A(pid=X) ──▶ B(parent_pid=X). Genuine spawn causality.
        pid index keeps a list (collisions are real with pid reuse).
        """
        pid_to_findings: dict[int, list[str]] = defaultdict(list)
        for f in self.findings:
            ev = self._trigger_event(f)
            pid = ev.process.pid if (ev and ev.process) else None
            if pid is not None:
                pid_to_findings[pid].append(f.id)

        seen: set[tuple[str, str]] = set()
        for f in self.findings:
            ev = self._trigger_event(f)
            parent_pid = (
                ev.process.parent.pid
                if ev and ev.process and ev.process.parent else None
            )
            if parent_pid is None:
                continue
            for parent_fid in pid_to_findings.get(parent_pid, []):
                if parent_fid == f.id:
                    continue
                pair = (parent_fid, f.id)
                if pair in seen:
                    continue
                if abs(self._get_finding_ts(self.finding_map[parent_fid])
                       - self._get_finding_ts(f)) > TEMPORAL_WINDOW:
                    continue
                seen.add(pair)
                self.graph.add_edge(parent_fid, f.id, relation="parent", nature="causal")

    # ── Identity / co-derivation: GROUPING (no edges) ──────────────────────────

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
        return self._process_groups() + self._account_groups()

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

    def _get_key_fields(self, obj) -> dict:
        _missing = datetime.min.replace(tzinfo=timezone.utc)
        if isinstance(obj, DetectionFinding):
            ts = self._get_finding_ts(obj)
            return {
                "timestamp":  ts.isoformat() if ts != _missing else "—",
                "action":     obj.rule_name or "—",
                "severity":   obj.severity.value if obj.severity else "—",
                "kill_chain": obj.kill_chain_phase.value if obj.kill_chain_phase else "—",
                "user":       "—",
                "process":    "—",
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
                if event and event.source and event.source.address:
                    ip_to_findings[event.source.address].add(finding.id)
                    break
        return {ip: list(ids) for ip, ids in ip_to_findings.items() if len(ids) > 1}

    # ── Development export ────────────────────────────────────────────────────

    """
    Replacement for _dev_export_html + _HTML_TEMPLATE in correlator.py.

    Changes vs the old viewer:
    - Containers are KILL CHAIN PHASES, not source-IP sessions. Phases are ordered
        along the attack lifecycle, so the layout reads left→right as the chain
        progresses. No more lying IP grouping.
    - Edges are visually distinct by `nature`/`relation`:
        causal requires/provides  → solid red
        lineage (parent)          → dashed blue (process spawned process)
        so the webshell→cmd→net-user lineage is readable as process tree, while the
        account_privileged→remote_login pivot stands out as a causal bridge.
    - The pivot edge (account_privileged / session_established) is highlighted
        amber+thick so the channel switch (web → SSH) is obvious.
    - Panel shows Requires/Provides as readable contract strings, with proper
        em-dash (fixes the literal \\u2014 bug), and a "what unlocked this" /
        "what this unlocked" split driven by edge nature.

    Drop the two definitions below into correlator.py, replacing the existing
    _dev_export_html method and the _HTML_TEMPLATE string.
    """

    # Canonical kill-chain ordering for left→right column layout in the viewer.
    # Adjust the strings to match your KillChainPhase.value outputs exactly.



    def _dev_export_html(self, output_path: str = "graph.html") -> str:
        """Export the graph to a self-contained HTML viewer. DEVELOPMENT ONLY.

        Containers = kill chain phases (ordered). Each finding node is parented into
        its phase container. No source-IP grouping.
        """
        finding_map = {f.id: f for f in self.findings}

        # Which phases are actually present, in canonical order.
        present_phases: list[str] = []
        for f in self.findings:
            phase = f.kill_chain_phase.value if f.kill_chain_phase else "unknown"
            if phase not in present_phases:
                present_phases.append(phase)
        present_phases.sort(
            key=lambda p: _PHASE_ORDER.index(p) if p in _PHASE_ORDER else len(_PHASE_ORDER)
        )

        nodes = []

        # Phase container nodes, carrying an order index for column placement.
        for idx, phase in enumerate(present_phases):
            nodes.append({"data": {
                "id":    f"phase_{phase}",
                "label": phase.replace("_", " ").title(),
                "type":  "PhaseNode",
                "order": idx,
            }})

        # Finding nodes.
        for node_id, data in self.graph.nodes(data=True):
            finding = finding_map.get(str(node_id))
            phase = (finding.kill_chain_phase.value
                    if finding and finding.kill_chain_phase else "unknown")

            node_data = {
                "id":     str(node_id),
                "label":  data.get("label", str(node_id)),
                "type":   data.get("type", "EventNode"),
                "parent": f"phase_{phase}",
                **data.get("fields", {}),
            }

            if finding:
                node_data["_confidence"]   = finding.confidence
                node_data["_technique"]    = (f"{finding.technique_id} · {finding.technique_name}"
                                            if finding.technique_id else "—")
                node_data["_tactic"]       = finding.tactic.value if finding.tactic else "—"
                node_data["_source"]       = finding.source or "—"
                node_data["_description"]  = finding.description or "—"
                node_data["_severity"]     = finding.severity.value if finding.severity else "—"
                node_data["_tags"]         = ", ".join(finding.tags) if finding.tags else "—"
                node_data["_event_count"]  = finding.event_count or len(finding.triggered_by)
                node_data["_triggered_by"] = finding.triggered_by[:20]
                node_data["_entities"]     = finding.entities or {}
                node_data["_extra"]        = {k: v for k, v in (finding.extra or {}).items()
                                            if k not in ("source_ip",)}
                node_data["_requires"]     = [f"{c.name} {list(c.bind)}={list(c.values)}"
                                            for c in (finding.requires or [])]
                node_data["_provides"]     = [f"{c.name} {list(c.bind)}={list(c.values)}"
                                            for c in (finding.provides or [])]
                # Split graph context by edge nature.
                causal_in, lineage_in = [], []
                for p in self.graph.predecessors(str(node_id)):
                    ed = self.graph.get_edge_data(p, str(node_id)) or {}
                    (lineage_in if ed.get("relation") == "parent" else causal_in).append(p)
                causal_out, lineage_out = [], []
                for c in self.graph.successors(str(node_id)):
                    ed = self.graph.get_edge_data(str(node_id), c) or {}
                    (lineage_out if ed.get("relation") == "parent" else causal_out).append(c)
                node_data["_causal_in"]   = causal_in
                node_data["_causal_out"]  = causal_out
                node_data["_lineage_in"]  = lineage_in
                node_data["_lineage_out"] = lineage_out

            nodes.append({"data": node_data})

        # Edges, tagged with nature/relation and a pivot flag for highlighting.
        PIVOT_CAPS = {"account_privileged", "session_established"}
        edges = []
        for src, dst, data in self.graph.edges(data=True):
            relation = data.get("relation", "")
            nature   = data.get("nature", "causal")
            cap      = data.get("cap", "")
            edge_kind = "lineage" if relation == "parent" else "causal"
            is_pivot  = cap in PIVOT_CAPS
            edges.append({"data": {
                "source":   str(src),
                "target":   str(dst),
                "relation": relation,
                "kind":     edge_kind,
                "pivot":    "yes" if is_pivot else "no",
            }})

        graph_json = json.dumps(nodes + edges, indent=2, default=str)
        html = _HTML_TEMPLATE.replace("__GRAPH_DATA__", graph_json)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return output_path

_PHASE_ORDER = [
    "reconnaissance",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "lateral_movement",
    "actions_on_objectives",
    "unknown",
]

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>TrailHunter — Attack Graph</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:        #0a0c10;
    --bg-2:      #0d1016;
    --surface:   #12151d;
    --surface-2: #171b25;
    --border:    #1f2430;
    --border-2:  #2a3142;
    --text:      #d4d8e2;
    --text-dim:  #8a91a8;
    --muted:     #545b72;
    --causal:    #ff4757;
    --lineage:   #2d8cff;
    --pivot:     #ffb020;
    --provides:  #2ed573;
    --requires:  #ff6b7a;
    --font:      'JetBrains Mono', monospace;
  }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    display: flex;
    height: 100vh;
    overflow: hidden;
  }
  #cy {
    flex: 1;
    height: 100vh;
    background:
      radial-gradient(ellipse at 15% 20%, rgba(45,140,255,.05) 0%, transparent 55%),
      radial-gradient(ellipse at 85% 80%, rgba(255,71,87,.04) 0%, transparent 55%),
      var(--bg);
  }

  /* ── Top toolbar ───────────────────────────────────────── */
  #toolbar {
    position: absolute; top: 0; left: 0;
    display: flex; align-items: center; gap: 16px;
    padding: 12px 18px;
    font-size: 11px; color: var(--text-dim);
    z-index: 10;
  }
  #toolbar .brand { font-weight: 700; letter-spacing: .14em; color: var(--text); font-size: 12px; }
  #toolbar .stat { display: flex; gap: 5px; align-items: baseline; }
  #toolbar .stat b { color: var(--text); font-weight: 600; font-size: 13px; }
  #toolbar .edge-key { display: flex; gap: 14px; margin-left: 8px; }
  #toolbar .ek { display: flex; align-items: center; gap: 6px; }
  #toolbar .ek .line { width: 22px; height: 0; }
  .line-causal  { border-top: 2px solid var(--causal); }
  .line-lineage { border-top: 2px dashed var(--lineage); }
  .line-pivot   { border-top: 3px solid var(--pivot); }

  /* ── Side panel ────────────────────────────────────────── */
  #panel {
    width: 340px; min-width: 340px; height: 100vh;
    background: linear-gradient(180deg, var(--surface) 0%, var(--bg-2) 100%);
    border-left: 1px solid var(--border);
    display: flex; flex-direction: column; overflow: hidden;
  }
  #panel-header {
    padding: 20px 22px 14px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  #panel-header .label {
    font-size: 9px; font-weight: 600; letter-spacing: .16em;
    color: var(--muted); text-transform: uppercase; margin-bottom: 7px;
  }
  #panel-header .node-name {
    font-size: 15px; font-weight: 600; color: var(--text);
    word-break: break-word; line-height: 1.3;
  }
  #panel-body {
    flex: 1; overflow-y: auto; padding: 18px 22px;
    scrollbar-width: thin; scrollbar-color: var(--border-2) transparent;
  }
  #panel-body::-webkit-scrollbar { width: 6px; }
  #panel-body::-webkit-scrollbar-thumb { background: var(--border-2); border-radius: 3px; }
  .placeholder { color: var(--muted); font-size: 11px; line-height: 1.8; margin-top: 6px; }

  .badge {
    display: inline-block; padding: 3px 10px; border-radius: 3px;
    font-size: 9px; font-weight: 700; letter-spacing: .1em;
    text-transform: uppercase; margin-bottom: 18px;
  }
  .badge-AlertNode { background: rgba(255,71,87,.14); color: var(--causal); border: 1px solid rgba(255,71,87,.32); }
  .badge-PhaseNode { background: rgba(180,100,255,.12); color: #b78bff; border: 1px solid rgba(180,100,255,.3); }

  .sev-row { display: flex; gap: 8px; margin-bottom: 18px; }
  .sev-chip {
    flex: 1; text-align: center; padding: 7px 4px; border-radius: 4px;
    font-size: 9px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
  }
  .sev-critical { background: rgba(255,71,87,.16); color: #ff5e6c; border: 1px solid rgba(255,71,87,.3); }
  .sev-high     { background: rgba(255,176,32,.14); color: var(--pivot); border: 1px solid rgba(255,176,32,.28); }
  .sev-medium   { background: rgba(45,140,255,.13); color: var(--lineage); border: 1px solid rgba(45,140,255,.26); }
  .sev-low      { background: rgba(46,213,115,.12); color: var(--provides); border: 1px solid rgba(46,213,115,.24); }

  .field { margin-bottom: 15px; }
  .field-label {
    font-size: 9px; font-weight: 600; letter-spacing: .12em;
    text-transform: uppercase; color: var(--muted); margin-bottom: 4px;
  }
  .field-value { font-size: 12px; color: var(--text); word-break: break-word; line-height: 1.55; }
  .field-value.mono { font-size: 10px; color: var(--text-dim); }

  .section-divider { border: none; border-top: 1px solid var(--border); margin: 16px 0; }

  .conf-bar-wrap { display: flex; align-items: center; gap: 9px; margin-top: 3px; }
  .conf-bar-bg { flex: 1; height: 5px; background: var(--border); border-radius: 3px; overflow: hidden; }
  .conf-bar-fill { height: 100%; border-radius: 3px; transition: width .3s; }

  .pill-list { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 4px; }
  .pill {
    font-size: 9px; padding: 2px 8px; border-radius: 3px;
    background: rgba(255,255,255,.04); border: 1px solid var(--border-2); color: var(--text-dim);
    word-break: break-all;
  }
  .pill.provides { border-color: rgba(46,213,115,.32); color: var(--provides); background: rgba(46,213,115,.07); }
  .pill.requires { border-color: rgba(255,107,122,.32); color: var(--requires); background: rgba(255,107,122,.07); }
  .pill.tag      { color: var(--muted); }

  .rel-group { margin-bottom: 12px; }
  .rel-head {
    font-size: 9px; font-weight: 600; letter-spacing: .1em; text-transform: uppercase;
    margin-bottom: 5px; display: flex; align-items: center; gap: 7px;
  }
  .rel-head .swatch { width: 18px; height: 0; }
  .edge-ref {
    font-size: 11px; color: var(--text-dim); margin-bottom: 4px; padding: 4px 8px;
    border-radius: 4px; cursor: pointer; background: rgba(255,255,255,.02);
    border: 1px solid transparent; transition: all .12s;
    display: flex; align-items: center; gap: 7px;
  }
  .edge-ref:hover { color: var(--text); background: rgba(255,255,255,.05); border-color: var(--border-2); }
  .edge-ref .arr { font-size: 9px; opacity: .6; }

  .trigger-id {
    font-size: 9px; color: var(--muted); opacity: .55;
    word-break: break-all; margin-bottom: 2px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .kv-row { display: flex; gap: 8px; margin-bottom: 5px; font-size: 10px; }
  .kv-key { color: var(--muted); flex-shrink: 0; min-width: 90px; }
  .kv-value { color: var(--text-dim); word-break: break-all; }
  .empty { opacity: .4; font-size: 10px; }
  .member-item { margin-bottom: 5px; opacity: .8; font-size: 11px; color: var(--text-dim); }
</style>
</head>
<body>

<div id="cy"></div>

<div id="toolbar">
  <span class="brand">TRAILHUNTER</span>
  <span class="stat"><b id="stat-findings">0</b> findings</span>
  <span class="stat"><b id="stat-edges">0</b> links</span>
  <span class="stat"><b id="stat-actors">0</b> phases</span>
  <span class="edge-key">
    <span class="ek"><span class="line line-causal"></span>requires/provides</span>
    <span class="ek"><span class="line line-lineage"></span>process lineage</span>
    <span class="ek"><span class="line line-pivot"></span>channel pivot</span>
  </span>
</div>

<div id="panel">
  <div id="panel-header">
    <div class="label">Inspector</div>
    <div class="node-name">Attack Graph</div>
  </div>
  <div id="panel-body">
    <p class="placeholder">Select a node to inspect its detection,<br>capabilities and causal links.</p>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js"></script>
<script>
const graphData = __GRAPH_DATA__;
cytoscape.use(cytoscapeDagre);

const cy = cytoscape({
  container: document.getElementById('cy'),
  elements: graphData,
  style: [
    {
      selector: 'node',
      style: {
        'label': 'data(label)', 'text-wrap': 'wrap', 'text-max-width': '120px',
        'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 7,
        'font-size': '10px', 'font-family': "'JetBrains Mono', monospace",
        'font-weight': 500, 'color': '#aab1c6',
        'text-outline-color': '#0a0c10', 'text-outline-width': 3,
        'width': 34, 'height': 34, 'border-width': 0,
        'transition-property': 'border-width border-color background-color', 'transition-duration': '160ms',
      }
    },
    { selector: 'node[type = "AlertNode"]', style: { 'background-color': '#ff4757', 'shape': 'diamond', 'width': 42, 'height': 42 } },
    { selector: 'node[type = "EventNode"]', style: { 'background-color': '#2ed573', 'shape': 'round-rectangle' } },
    {
      selector: 'node[type = "PhaseNode"]',
      style: {
        'background-color': 'rgba(180,100,255,0.035)', 'background-opacity': 1,
        'border-width': 1, 'border-color': 'rgba(180,100,255,0.28)', 'border-style': 'solid',
        'label': 'data(label)', 'text-valign': 'top', 'text-halign': 'center',
        'font-size': '10px', 'font-weight': 700, 'letter-spacing': 2,
        'color': 'rgba(190,150,255,0.7)', 'padding': '22px', 'shape': 'round-rectangle',
        'text-margin-y': -4,
      }
    },
    { selector: 'node.dim', style: { 'opacity': 0.18 } },
    { selector: 'node.focus', style: { 'border-width': 3, 'border-color': '#ffb020', 'border-opacity': 1 } },

    {
      selector: 'edge',
      style: {
        'width': 1.6, 'curve-style': 'bezier',
        'target-arrow-shape': 'triangle', 'arrow-scale': 0.9,
        'label': 'data(relation)', 'font-size': '8px',
        'font-family': "'JetBrains Mono', monospace", 'color': '#586079',
        'color': '#586079', 'text-rotation': 'autorotate',
        'text-background-color': '#0a0c10', 'text-background-opacity': 1, 'text-background-padding': '2px',
      }
    },
    {
      selector: 'edge[kind = "causal"]',
      style: { 'line-color': '#ff4757', 'target-arrow-color': '#ff4757', 'line-opacity': 0.55 }
    },
    {
      selector: 'edge[kind = "lineage"]',
      style: { 'line-color': '#2d8cff', 'target-arrow-color': '#2d8cff', 'line-style': 'dashed', 'line-opacity': 0.5 }
    },
    {
      selector: 'edge[pivot = "yes"]',
      style: { 'line-color': '#ffb020', 'target-arrow-color': '#ffb020', 'width': 3, 'line-opacity': 1, 'z-index': 10 }
    },
    { selector: 'edge.dim', style: { 'opacity': 0.08 } },
    { selector: 'edge.focus', style: { 'width': 3, 'line-opacity': 1, 'z-index': 20 } },
  ],
  layout: { name: 'dagre', rankDir: 'LR', nodeSep: 55, rankSep: 95, padding: 50, animate: false }
});

cy.ready(() => {
  cy.fit(undefined, 50);
  document.getElementById('stat-findings').textContent = cy.nodes('[type = "AlertNode"]').length;
  document.getElementById('stat-edges').textContent = cy.edges().length;
  document.getElementById('stat-actors').textContent = cy.nodes('[type = "PhaseNode"]').length;
});

const panelBody = document.getElementById('panel-body');
const panelName = document.querySelector('#panel-header .node-name');

function field(label, value, cls='') {
  return `<div class="field"><div class="field-label">${label}</div><div class="field-value ${cls}">${value}</div></div>`;
}
function pills(items, cls='') {
  if (!items || !items.length) return '<span class="empty">— none —</span>';
  return `<div class="pill-list">${items.map(i => `<span class="pill ${cls}">${i}</span>`).join('')}</div>`;
}
function confBar(v) {
  const pct = Math.round((v || 0) * 100);
  const color = v >= .9 ? '#ff4757' : v >= .7 ? '#ffb020' : '#2ed573';
  return `<div class="conf-bar-wrap"><div class="conf-bar-bg"><div class="conf-bar-fill" style="width:${pct}%;background:${color}"></div></div><span style="font-size:10px;color:var(--muted)">${pct}%</span></div>`;
}
function kvTable(obj) {
  if (!obj || !Object.keys(obj).length) return '<span class="empty">— none —</span>';
  return Object.entries(obj).map(([k, v]) =>
    `<div class="kv-row"><span class="kv-key">${k}</span><span class="kv-value">${Array.isArray(v) ? v.join(', ') : v}</span></div>`
  ).join('');
}
function relGroup(title, color, dashed, ids, arrow) {
  if (!ids || !ids.length) return '';
  let h = `<div class="rel-group"><div class="rel-head"><span class="swatch" style="border-top:2px ${dashed?'dashed':'solid'} ${color}"></span>${title}</div>`;
  ids.forEach(id => {
    const lbl = cy.getElementById(id).data('label') || id;
    h += `<div class="edge-ref" onclick="focusNode('${id}')"><span class="arr">${arrow}</span>${lbl}</div>`;
  });
  return h + `</div>`;
}

function focusNode(id) {
  const node = cy.getElementById(id);
  if (node.empty()) return;
  node.trigger('tap');
  cy.animate({ fit: { eles: node.closedNeighborhood(), padding: 120 } }, { duration: 300 });
}

function renderAlert(d) {
  let h = `<span class="badge badge-AlertNode">Detection</span>`;
  const sev = (d._severity || '').toLowerCase();
  h += `<div class="sev-row">
    <div class="sev-chip ${sev==='critical'?'sev-critical':''}" style="${sev!=='critical'?'opacity:.25':''}">Critical</div>
    <div class="sev-chip ${sev==='high'?'sev-high':''}" style="${sev!=='high'?'opacity:.25':''}">High</div>
    <div class="sev-chip ${sev==='medium'?'sev-medium':''}" style="${sev!=='medium'?'opacity:.25':''}">Medium</div>
    <div class="sev-chip ${sev==='low'?'sev-low':''}" style="${sev!=='low'?'opacity:.25':''}">Low</div>
  </div>`;

  h += field('Description', d._description || '—');
  h += `<div class="field"><div class="field-label">Confidence</div>${confBar(d._confidence)}</div>`;
  h += `<hr class="section-divider">`;

  h += field('Source', d._source || '—');
  h += field('Technique', d._technique || '—');
  h += field('Tactic', d._tactic || '—');
  h += field('Kill Chain', d.kill_chain || '—');
  h += field('Timestamp', d.timestamp || '—', 'mono');
  h += `<hr class="section-divider">`;

  h += `<div class="field"><div class="field-label">Requires</div>${pills(d._requires, 'requires')}</div>`;
  h += `<div class="field"><div class="field-label">Provides</div>${pills(d._provides, 'provides')}</div>`;
  h += `<hr class="section-divider">`;

  // Causal + lineage context, split.
  const ci = relGroup('Unlocked by (causal)', '#ff4757', false, d._causal_in,  '▲');
  const co = relGroup('Unlocks (causal)',     '#ff4757', false, d._causal_out, '▼');
  const li = relGroup('Parent process',       '#2d8cff', true,  d._lineage_in,  '▲');
  const lo = relGroup('Spawned',              '#2d8cff', true,  d._lineage_out, '▼');
  const ctx = ci + co + li + lo;
  if (ctx) { h += ctx + `<hr class="section-divider">`; }

  h += `<div class="field"><div class="field-label">Entities</div>${kvTable(d._entities)}</div>`;
  if (d._extra && Object.keys(d._extra).length)
    h += `<div class="field"><div class="field-label">Extra</div>${kvTable(d._extra)}</div>`;
  h += `<hr class="section-divider">`;

  h += `<div class="field"><div class="field-label">Tags</div>${pills((d._tags||'').split(', ').filter(Boolean), 'tag')}</div>`;

  const trig = d._triggered_by || [];
  h += `<div class="field"><div class="field-label">Triggered by (${d._event_count || trig.length} events)</div>`;
  trig.slice(0, 8).forEach(eid => { h += `<div class="trigger-id">${eid}</div>`; });
  if (trig.length > 8) h += `<div style="font-size:9px;opacity:.4;margin-top:3px">+ ${trig.length - 8} more</div>`;
  h += `</div>`;
  return h;
}

cy.on('tap', 'node', function(evt) {
  const d = evt.target.data();
  const node = evt.target;

  cy.elements().removeClass('focus dim');

  if (d.type === 'PhaseNode') {
    panelName.textContent = d.label;
    let h = `<span class="badge badge-PhaseNode">Kill Chain Phase</span>`;
    const kids = node.children();
    h += field('Findings in phase', kids.length);
    h += `<div class="field"><div class="field-label">Members</div>`;
    kids.forEach(c => { h += `<div class="member-item" onclick="focusNode('${c.id()}')" style="cursor:pointer">${c.data('label') || c.id()}</div>`; });
    h += `</div>`;
    panelBody.innerHTML = h;
    return;
  }

  // Highlight node + its connected edges/neighbours; dim the rest.
  const nb = node.closedNeighborhood();
  cy.elements().not(nb).addClass('dim');
  node.addClass('focus');
  node.connectedEdges().addClass('focus');

  panelName.textContent = d.label || d.id;
  if (d.type === 'AlertNode') { panelBody.innerHTML = renderAlert(d); return; }

  let h = `<span class="badge badge-AlertNode">${d.type || 'Node'}</span>`;
  h += field('ID', d.id, 'mono');
  h += field('Timestamp', d.timestamp || '—', 'mono');
  h += field('Action', d.action || '—');
  panelBody.innerHTML = h;
});

cy.on('tap', function(evt) {
  if (evt.target === cy) {
    cy.elements().removeClass('focus dim');
    panelName.textContent = 'Attack Graph';
    panelBody.innerHTML = '<p class="placeholder">Select a node to inspect its detection,<br>capabilities and causal links.</p>';
  }
});
</script>
</body>
</html>"""