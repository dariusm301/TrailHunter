import type cytoscape from 'cytoscape'
import type { CorrelationGraph, GraphNode } from '@/types/graph'
import { phaseColor, phaseLegend } from '@/lib/phaseColor'

const SEVERITY_BORDER: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const COL_W = 280 
const MIN_LANE_H = 150 
const NODE_STEP = 55 
const PAD = 80

const LEGEND = phaseLegend()
function normalizePhase(p: string): string {
  return p.trim().toLowerCase().replace(/[\s_]+/g, '-')
}
const PHASE_ROW = new Map<string, number>(
  LEGEND.map((s, i) => [normalizePhase(s.phase), i]),
)
const FALLBACK_COLOR = phaseColor(null) 

function laneIndex(phase: string | null | undefined): number {
  if (!phase) return -1
  return PHASE_ROW.get(normalizePhase(phase)) ?? -1
}

export function makeIsCollector(
  graph: CorrelationGraph,
): (n: GraphNode) => boolean {
  const set = new Set(graph.collector_ips ?? [])
  return (n) => n.fields.source_ip != null && set.has(n.fields.source_ip)
}

export function toElements(
  graph: CorrelationGraph,
  include: (n: GraphNode) => boolean,
): cytoscape.ElementDefinition[] {
  const nodes = graph.nodes.filter(include)
  const ids = new Set(nodes.map((n) => n.id))
  const nodeEls: cytoscape.ElementDefinition[] = nodes.map((n) => ({
    data: {
      id: n.id,
      label: n.label,
      is_probe: n.is_probe,
      phase: n.fields.kill_chain,
      requires: n.requires,
      provides: n.provides,
      fusion_key: n.fusion_key,
      color: phaseColor(n.fields.kill_chain),
      severity: n.fields.severity,
      border: SEVERITY_BORDER[(n.fields.severity || '').toLowerCase()] ?? 1,
    },
  }))
  const edgeEls: cytoscape.ElementDefinition[] = graph.edges
    .filter((e) => ids.has(e.source) && ids.has(e.target))
    .map((e) => ({
      data: {
        id: `${e.source}->${e.target}:${e.relation}:${e.cap ?? ''}`,
        source: e.source,
        target: e.target,
        relation: e.relation,
        cap: e.cap ?? '',
      },
    }))
  return [...nodeEls, ...edgeEls]
}


function layer(
  nodeIds: string[],
  edges: { source: string; target: string }[],
): Map<string, number> {
  const adj = new Map<string, string[]>()
  const indeg = new Map<string, number>()
  nodeIds.forEach((id) => {
    adj.set(id, [])
    indeg.set(id, 0)
  })
  for (const e of edges) {
    if (!adj.has(e.source) || !indeg.has(e.target)) continue
    adj.get(e.source)!.push(e.target)
    indeg.set(e.target, (indeg.get(e.target) ?? 0) + 1)
  }
  const rank = new Map<string, number>(nodeIds.map((id) => [id, 0]))
  const deg = new Map(indeg)
  const q = nodeIds.filter((id) => (deg.get(id) ?? 0) === 0)
  while (q.length) {
    const u = q.shift()!
    for (const v of adj.get(u)!) {
      rank.set(v, Math.max(rank.get(v)!, rank.get(u)! + 1))
      deg.set(v, deg.get(v)! - 1)
      if (deg.get(v) === 0) q.push(v)
    }
  }
  return rank
}


export function toSwimlane(
  graph: CorrelationGraph,
  include: (n: GraphNode) => boolean,
): cytoscape.ElementDefinition[] {
  const nodes = graph.nodes.filter(include)
  if (nodes.length === 0) return []
  const ids = new Set(nodes.map((n) => n.id))
  const edges = graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target))

  const rank = layer([...ids], edges)
  const maxRank = Math.max(0, ...rank.values())

  const present = new Set<number>()
  let hasUnknown = false
  for (const n of nodes) {
    const li = laneIndex(n.fields.kill_chain)
    if (li < 0) hasUnknown = true
    else present.add(li)
  }
  const orderedLanes: number[] = [...present].sort((a, b) => a - b)
  if (hasUnknown) orderedLanes.push(Number.POSITIVE_INFINITY)
  const laneRow = new Map<number, number>()
  orderedLanes.forEach((li, row) => laneRow.set(li, row))

  function rowFor(phase: string | null | undefined): number {
    const li = laneIndex(phase)
    const key = li < 0 ? Number.POSITIVE_INFINITY : li
    return laneRow.get(key) ?? orderedLanes.length - 1
  }

  const placed = nodes.map((n) => ({
    n,
    r: rank.get(n.id) ?? 0,
    row: rowFor(n.fields.kill_chain),
  }))

  const cellTotal = new Map<string, number>()
  for (const p of placed) {
    const key = `${p.row}:${p.r}`
    cellTotal.set(key, (cellTotal.get(key) ?? 0) + 1)
  }

  const rowMaxTotal = new Map<number, number>()
  for (const [key, total] of cellTotal.entries()) {
    const row = parseInt(key.split(':')[0], 10)
    rowMaxTotal.set(row, Math.max(rowMaxTotal.get(row) ?? 0, total))
  }

  const rowHeight = new Map<number, number>()
  const rowCenterY = new Map<number, number>()
  let currentY = PAD

  orderedLanes.forEach((_, row) => {
    const maxInThisRow = rowMaxTotal.get(row) ?? 1
    const neededHeight = (maxInThisRow * NODE_STEP) + 40
    const h = Math.max(MIN_LANE_H, neededHeight)
    
    rowHeight.set(row, h)
    rowCenterY.set(row, currentY + h / 2)
    currentY += h 
  })

  const cellSeen = new Map<string, number>()
  const nodeEls: cytoscape.ElementDefinition[] = placed.map(({ n, r, row }) => {
    const key = `${row}:${r}`
    const total = cellTotal.get(key)!
    const k = cellSeen.get(key) ?? 0
    cellSeen.set(key, k + 1)

    const yOff = (k - (total - 1) / 2) * NODE_STEP
    const centerY = rowCenterY.get(row)!

    return {
      data: {
        id: n.id,
        kind: 'finding',
        label: n.label,
        is_probe: n.is_probe,
        phase: n.fields.kill_chain,
        fields: n.fields,
        actor: n.actor,
        event_ids: n.event_ids,
        requires: n.requires,
        provides: n.provides,
        fusion_key: n.fusion_key,
        color: phaseColor(n.fields.kill_chain),
        severity: n.fields.severity,
        border: SEVERITY_BORDER[(n.fields.severity || '').toLowerCase()] ?? 1,
      },
      position: { x: PAD + r * COL_W, y: centerY + yOff },
    }
  })

  const xMin = PAD - COL_W * 0.5
  const xMax = PAD + maxRank * COL_W + COL_W * 0.5
  const bandW = xMax - xMin
  const cx = (xMin + xMax) / 2
  const bandEls: cytoscape.ElementDefinition[] = []

  orderedLanes.forEach((li, row) => {
    const unknown = !isFinite(li)
    const color = unknown ? FALLBACK_COLOR : LEGEND[li].color
    const label = unknown ? 'unknown' : LEGEND[li].phase
    const centerY = rowCenterY.get(row)!
    const h = rowHeight.get(row)!

    bandEls.push({
      data: { id: `lane:${row}`, isLane: 1, label, laneColor: color, w: bandW, h: h * 0.93 },
      position: { x: cx, y: centerY },
      selectable: false,
      grabbable: false,
    })
    bandEls.push({
      data: { id: `rail:${row}`, isRail: 1, laneColor: color, w: 8, h: h * 0.93 },
      position: { x: xMin + 8, y: centerY },
      selectable: false,
      grabbable: false,
    })
  })

  const edgeEls: cytoscape.ElementDefinition[] = edges.map((e) => ({
    data: {
      id: `${e.source}->${e.target}:${e.relation}:${e.cap ?? ''}`,
      source: e.source,
      target: e.target,
      relation: e.relation,
      cap: e.cap ?? '',
    },
  }))

  return [...bandEls, ...nodeEls, ...edgeEls]
}