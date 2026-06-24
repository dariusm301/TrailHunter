import { useMemo, useState, useEffect } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import type { GraphNode, CorrelationGraph } from '@/types/graph'
import type { DetectResult } from '@/types/alerts'
import GraphCanvas from './GraphCanvas'
import { makeIsCollector, toSwimlane } from './adapter'
import { phaseColor } from '@/lib/phaseColor'
import { useCorrelation } from '@/lib/useCorrelation'
import { runDetection, deleteCollection, fetchFindings } from '@/api/collections'
import TopMenu from '@/components/TopMenu'
import CollectionActionBar from '@/components/CollectionActionBar'
import { DetailsPanel } from '@/components/DetailsPanel'
import AllAlertsDrawer from '@/components/AllAlertsDrawer'
import { ConfirmDeleteModal } from '@/components/ConfirmDeleteModal'
import logo from '@/assets/logo.svg'
import AccountMenu from '@/components/AccountMenu'


const SEV_ORDER = ['low', 'medium', 'high', 'critical'] as const
type Severity = typeof SEV_ORDER[number]
const PHASES = [
  'reconnaissance', 'weaponization', 'delivery', 'exploitation',
  'installation', 'command_and_control', 'actions_on_objectives',
] as const
const SEV_COLORS: Record<string, string> = {
  low: '#22c55e', medium: '#f59e0b', high: '#f97316', critical: '#ef4444',
}
type EventFields = Record<string, unknown>

function byTime(a: GraphNode, b: GraphNode) {
  return (a.fields.timestamp || '').localeCompare(b.fields.timestamp || '')
}
function maxSeverity(nodes: GraphNode[]): string {
  let best = -1
  let label = '—'
  for (const n of nodes) {
    const i = SEV_ORDER.indexOf((n.fields.severity || '').toLowerCase() as Severity)
    if (i > best) { best = i; label = n.fields.severity || '—' }
  }
  return label
}
function phaseSpan(nodes: GraphNode[]): string {
  const sorted = [...nodes].sort(byTime)
  const first = sorted[0]?.fields.kill_chain || '—'
  const last = sorted[sorted.length - 1]?.fields.kill_chain || '—'
  return first === last ? first : `${first} → ${last}`
}
function collectStrings(obj: unknown): string[] {
  if (obj === null || obj === undefined) return []
  if (typeof obj === 'string') return [obj]
  if (typeof obj === 'number' || typeof obj === 'boolean') return [String(obj)]
  if (Array.isArray(obj)) return obj.flatMap(collectStrings)
  if (typeof obj === 'object') return Object.values(obj as Record<string, unknown>).flatMap(collectStrings)
  return []
}
const EMPTY_GRAPH: CorrelationGraph = { nodes: [], edges: [], actor_count: 0, collector_ips: [] }
function eventMatches(fields: EventFields, q: string): boolean {
  return collectStrings(fields).some((s) => s.toLowerCase().includes(q))
}

interface Selected { kind: 'node' | 'edge'; id: string }

export default function GraphPage() {
  const { collectionId } = useParams<{ collectionId: string }>()
  const navigate = useNavigate()

  useEffect(() => {
    if (!collectionId) navigate('/scans')
  }, [collectionId, navigate])

  const { graph: data, status, phaseLabel, error, recorrelate } = useCorrelation(collectionId)
  const loading = status === 'running'

  const safeGraph: CorrelationGraph = useMemo(() => {
    const g = data ?? EMPTY_GRAPH
    return { ...g, nodes: g.nodes ?? [], edges: g.edges ?? [] }
  }, [data])
  const safeNodes = safeGraph.nodes
  const safeEdges = safeGraph.edges
  const eventsMap: Record<string, EventFields> =
    (safeGraph as unknown as { events?: Record<string, EventFields> }).events ?? {}

  const isCollector = useMemo(() => makeIsCollector(safeGraph), [safeGraph])
  const collectorNodes = useMemo(() => safeNodes.filter(isCollector), [safeNodes, isCollector])

  const [selectedActor, setSelectedActor] = useState<number | 'general' | null>(null)
  const [selected, setSelected] = useState<Selected | null>(null)
  const [viewMode, setViewMode] = useState<'graph' | 'alerts'>('graph')
  const [alertSearch, setAlertSearch] = useState('')
  const [sevFilters, setSevFilters] = useState<Set<string>>(new Set())
  const [phaseFilters, setPhaseFilters] = useState<Set<string>>(new Set())
  const [detectResult, setDetectResult] = useState<DetectResult | null>(null)

  useEffect(() => {
    if (!collectionId) return
    fetchFindings(collectionId).then((result) => {
      if (result) setDetectResult(result)
    })
  }, [collectionId])

  const [allAlertsOpen, setAllAlertsOpen] = useState(false)
  const [processingAction, setProcessingAction] = useState<'detect' | 'delete' | null>(null)
  const [showDeleteModal, setShowDeleteModal] = useState(false)

  const handleRunDetection = async () => {
    setProcessingAction('detect')
    try {
      const result = await runDetection(collectionId!) as DetectResult
      setDetectResult(result)
      setAllAlertsOpen(true)
    } catch (err) {
      setDetectResult({
        status: 'error',
        total_findings: 0,
        max_severity: '',
        findings: [],
        error: err instanceof Error ? err.message : String(err),
      })
      setAllAlertsOpen(true)
    } finally {
      setProcessingAction(null)
    }
  }

  const handleCorrelate = () => {
    recorrelate()
  }

  const handleDelete = async () => {
    setProcessingAction('delete')
    try {
      await deleteCollection(collectionId!)
      navigate('/scans')
    } catch (err) {
      alert(`Error deleting: ${err instanceof Error ? err.message : String(err)}`)
      setProcessingAction(null)
      setShowDeleteModal(false)
    }
  }

  const barAction = processingAction ?? (loading ? 'correlate' : null)

  const toggleSev = (v: string) => setSevFilters((prev) => {
    const next = new Set(prev); next.has(v) ? next.delete(v) : next.add(v); return next
  })
  const togglePhase = (v: string) => setPhaseFilters((prev) => {
    const next = new Set(prev); next.has(v) ? next.delete(v) : next.add(v); return next
  })
  const clearFilters = () => { setAlertSearch(''); setSevFilters(new Set()); setPhaseFilters(new Set()) }

  const { realActors, isolatedNodes } = useMemo(() => {
    const map = new Map<number, GraphNode[]>()
    for (const n of safeNodes) {
      if (isCollector(n) || n.actor == null) continue
      const arr = map.get(n.actor) ?? []
      arr.push(n)
      map.set(n.actor, arr)
    }
    const realActors: { id: number; nodes: GraphNode[]; linked: boolean; ip: string }[] = []
    const isolatedNodes: GraphNode[] = []
    for (const [id, nodes] of map.entries()) {
      const ids = new Set(nodes.map((n) => n.id))
      const internalEdges = safeEdges.filter((e) => ids.has(e.source) && ids.has(e.target))
      const sortedBySeverity = [...nodes].sort((a, b) => {
        const idxA = SEV_ORDER.indexOf((a.fields.severity || '').toLowerCase() as Severity)
        const idxB = SEV_ORDER.indexOf((b.fields.severity || '').toLowerCase() as Severity)
        return idxB - idxA
      })
      const nodeWithIp = sortedBySeverity.find((n) => n.fields && n.fields.source_ip != null)
      const ip = nodeWithIp ? String(nodeWithIp.fields.source_ip) : `ID: ${id}`
      if (internalEdges.length >= 3) {
        realActors.push({ id, nodes, linked: true, ip })
      } else {
        isolatedNodes.push(...nodes)
      }
    }
    realActors.sort((a, b) => a.id - b.id)
    isolatedNodes.sort(byTime)
    return { realActors, isolatedNodes }
  }, [safeNodes, isCollector, safeEdges])

  const effectiveActor = useMemo(() => {
    if (selectedActor != null) {
      if (selectedActor === 'general' && isolatedNodes.length > 0) return 'general'
      if (realActors.some((a) => a.id === selectedActor)) return selectedActor
    }
    return realActors.length > 0 ? realActors[0].id : isolatedNodes.length > 0 ? 'general' : null
  }, [selectedActor, realActors, isolatedNodes])

  const effectiveActorObj =
    typeof effectiveActor === 'number'
      ? realActors.find((a) => a.id === effectiveActor) ?? null
      : null

  useEffect(() => {
    if (effectiveActor === 'general' && viewMode === 'graph') setViewMode('alerts')
  }, [effectiveActor, viewMode])
  useEffect(() => { clearFilters() }, [effectiveActor])

  const canvasElements = useMemo(
    () =>
      typeof effectiveActor !== 'number'
        ? []
        : toSwimlane(safeGraph, (n) => !isCollector(n) && n.actor === effectiveActor),
    [safeGraph, isCollector, effectiveActor],
  )
  const collectorElements = useMemo(() => toSwimlane(safeGraph, isCollector), [safeGraph, isCollector])
  const alertNodes = effectiveActor === 'general' ? isolatedNodes : effectiveActorObj?.nodes ?? []

  const availableSevs = useMemo(() => {
    const s = new Set<string>()
    alertNodes.forEach((n) => { if (n.fields.severity && n.fields.severity !== '—') s.add(n.fields.severity.toLowerCase()) })
    return SEV_ORDER.filter((v) => s.has(v))
  }, [alertNodes])
  const availablePhases = useMemo(() => {
    const s = new Set<string>()
    alertNodes.forEach((n) => { if (n.fields.kill_chain && n.fields.kill_chain !== '—') s.add(n.fields.kill_chain) })
    return PHASES.filter((v) => s.has(v))
  }, [alertNodes])
  const filteredAlerts = useMemo(() => {
    const q = alertSearch.trim().toLowerCase()
    return alertNodes.filter((n) => {
      if (sevFilters.size > 0 && !sevFilters.has((n.fields.severity || '').toLowerCase())) return false
      if (phaseFilters.size > 0 && !phaseFilters.has(n.fields.kill_chain || '')) return false
      if (q) {
        const topMatch =
          n.label.toLowerCase().includes(q) ||
          n.fields.kill_chain?.toLowerCase().includes(q) ||
          n.fields.severity?.toLowerCase().includes(q) ||
          n.fields.user?.toLowerCase().includes(q) ||
          n.fields.process?.toLowerCase().includes(q) ||
          n.fields.source_ip?.toLowerCase().includes(q) ||
          n.fields.timestamp?.toLowerCase().includes(q)
        if (topMatch) return true
        return (n.event_ids ?? []).some((eid) => {
          const f = eventsMap[eid]
          return f ? eventMatches(f, q) : false
        })
      }
      return true
    })
  }, [alertNodes, alertSearch, sevFilters, phaseFilters, eventsMap])

  const hasAlertFilters = alertSearch.trim() !== '' || sevFilters.size > 0 || phaseFilters.size > 0

  const selectedNode = selected?.kind === 'node' ? safeNodes.find((n) => n.id === selected.id) : undefined
  const selectedEdge = selected?.kind === 'edge'
    ? safeEdges.find((e) => `${e.source}->${e.target}:${e.relation}:${e.cap ?? ''}` === selected.id)
    : undefined

  const allAlertsTotal = detectResult?.total_findings ?? 0

  if (loading && !data) {
    return (
      <div style={S.root}>
        <header style={S.header}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <Link to="/scans" style={S.back}>← Scans</Link>
            <img src={logo} alt="TrailHunter" style={{ height: 28 }} />
            {collectionId && <span style={S.meta}>{collectionId}</span>}
          </div>
        </header>
        <div style={S.body}>
          <div style={{ ...S.empty, width: '100%', flexDirection: 'column', gap: 10 }}>
            <div style={{ fontSize: 14 }}>{phaseLabel || 'Loading...'}</div>
            <div style={S.meta}>Loading...</div>
          </div>
        </div>
      </div>
    )
  }

  if (error && !data) {
    return (
      <div style={S.root}>
        <header style={S.header}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <Link to="/scans" style={S.back}>← Scans</Link>
            <img src={logo} alt="TrailHunter" style={{ height: 45 }} />
          </div>
        </header>
        <div style={S.body}>
          <div style={{ ...S.empty, width: '100%', color: 'var(--color-critical)' }}>Error: {error}</div>
        </div>
      </div>
    )
  }

  return (
    <div style={S.root}>
      <header style={S.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <Link to="/scans" style={S.back}>← Scans</Link>
          <img src={logo} alt="TrailHunter" style={{ height: 45 }} />
          {collectionId && <span style={S.meta}>{collectionId}</span>}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <CollectionActionBar
            onRunDetection={handleRunDetection}
            onCorrelate={handleCorrelate}
            onDeleteClick={() => setShowDeleteModal(true)}
            onAllAlerts={() => setAllAlertsOpen(true)}
            allAlertsCount={allAlertsTotal > 0 ? allAlertsTotal : undefined}
            allAlertsHasFindings={detectResult !== null}
            processingAction={barAction}
            isLoading={loading}
          />
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, borderLeft: '1px solid var(--color-line)', paddingLeft: 16 }}>
            <span style={S.meta}>{realActors.length} active actor{realActors.length === 1 ? '' : 's'}</span>
            <AccountMenu />
          </div>
        </div>
      </header>
      <div style={S.body}>
        <aside style={S.left}>
          <div style={S.sideLabel}>Actors</div>
          {realActors.map(({ id, nodes, ip }) => {
            const active = id === effectiveActor
            return (
              <button
                key={id}
                onClick={() => { setSelectedActor(id); setSelected(null); setViewMode('graph') }}
                style={{ ...S.actorBtn, ...(active ? S.actorBtnActive : null) }}
              >
                <div style={S.actorTop}>
                  <span style={S.actorName}>Actor {ip}</span>
                  <span style={S.actorCount}>{nodes.length}</span>
                </div>
                <div style={S.actorSub}>{phaseSpan(nodes)}</div>
                <div style={S.actorSub}>severity {maxSeverity(nodes)}</div>
              </button>
            )
          })}
          {isolatedNodes.length > 0 && (
            <>
              {realActors.length > 0 && <div style={{ height: 1, background: 'var(--color-line)', margin: '16px 0 8px' }} />}
              <div style={S.sideLabel}>Unlinked</div>
              <button
                onClick={() => { setSelectedActor('general'); setSelected(null) }}
                style={{ ...S.actorBtn, ...(effectiveActor === 'general' ? S.actorBtnActive : null) }}
              >
                <div style={S.actorTop}>
                  <span style={S.actorName}>General Alerts</span>
                  <span style={S.actorCount}>{isolatedNodes.length}</span>
                </div>
                <div style={S.actorSub}>isolated events</div>
                <div style={S.actorSub}>severity {maxSeverity(isolatedNodes)}</div>
              </button>
            </>
          )}
        </aside>
        <section style={{ ...S.center, display: 'flex', flexDirection: 'column' }}>
          <TopMenu
            viewMode={viewMode}
            onViewChange={setViewMode}
            disableGraph={effectiveActor === 'general' || effectiveActor == null}
          />
          <div style={{ flex: 1, position: 'relative', minHeight: 0 }}>
            {loading && data && (
              <div style={S.workingBanner}>
                <span style={S.workingDot} />
                {phaseLabel || 'Correlating...'}
              </div>
            )}
            {error && data && (
              <div style={S.errorBanner}>Correlation failed: {error}</div>
            )}
            {viewMode === 'graph' && (
              effectiveActor == null ? (
                <div style={S.empty}>No actors to display. Please run Detection and Correlate.</div>
              ) : effectiveActor === 'general' ? (
                <div style={S.empty}>General alerts don't have a graph view.</div>
              ) : (
                <GraphCanvas
                  elements={canvasElements}
                  onSelect={(kind, id) => setSelected({ kind, id })}
                  onClear={() => setSelected(null)}
                />
              )
            )}
            {viewMode === 'alerts' && (
              <div style={S.alertList} onClick={() => setSelected(null)}>
                <div style={S.filterBar} onClick={(e) => e.stopPropagation()}>
                  <div style={S.searchWrap}>
                    <input
                      style={S.alertSearchInput}
                      type="text"
                      placeholder="Search labels, IPs, users, processes, events…"
                      value={alertSearch}
                      onChange={(e) => setAlertSearch(e.target.value)}
                    />
                    {alertSearch && (
                      <button style={S.alertSearchClear} onClick={() => setAlertSearch('')}>✕</button>
                    )}
                  </div>
                  {availableSevs.length > 0 && (
                    <div style={S.chipRow}>
                      {availableSevs.map((sev) => {
                        const active = sevFilters.has(sev)
                        return (
                          <button key={sev} style={{
                            ...S.chip,
                            borderColor: SEV_COLORS[sev] ?? 'var(--color-line)',
                            background: active ? (SEV_COLORS[sev] ?? 'transparent') : 'transparent',
                            color: active ? '#000' : (SEV_COLORS[sev] ?? 'var(--color-fg)'),
                            fontWeight: active ? 700 : 500,
                          }} onClick={() => toggleSev(sev)}>{sev}</button>
                        )
                      })}
                    </div>
                  )}
                  {availablePhases.length > 0 && (
                    <div style={S.chipRow}>
                      {availablePhases.map((phase) => {
                        const active = phaseFilters.has(phase)
                        const col = phaseColor(phase)
                        return (
                          <button key={phase} style={{
                            ...S.chip, borderColor: col,
                            background: active ? col : 'transparent',
                            color: active ? '#000' : col,
                            fontWeight: active ? 700 : 500,
                          }} onClick={() => togglePhase(phase)}>{phase}</button>
                        )
                      })}
                    </div>
                  )}
                  <div style={S.filterMeta}>
                    <span style={S.meta}>{filteredAlerts.length} / {alertNodes.length}</span>
                    {hasAlertFilters && (
                      <button style={S.clearAll} onClick={clearFilters}>clear all</button>
                    )}
                  </div>
                </div>
                {filteredAlerts.map((n) => {
                  const isSelected = selected?.kind === 'node' && selected.id === n.id
                  return (
                    <div
                      key={n.id}
                      onClick={(e) => { e.stopPropagation(); setSelected(isSelected ? null : { kind: 'node', id: n.id }) }}
                      style={{
                        ...S.alertCard,
                        cursor: 'pointer',
                        borderLeft: `3px solid ${phaseColor(n.fields.kill_chain ?? 'unknown')}`,
                        ...(isSelected ? { borderColor: 'var(--color-accent)' } : {}),
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div style={S.detailTitle}>
                          {n.label}
                          {n.is_probe && <span style={{ color: 'var(--color-muted)', fontWeight: 400 }}> (probe)</span>}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 12, fontSize: 12, color: 'var(--color-muted)', marginTop: 8 }}>
                        <span>{n.fields.kill_chain !== '—' ? n.fields.kill_chain : 'unknown phase'}</span>
                        <span>·</span>
                        <span style={{ color: SEV_COLORS[(n.fields.severity || '').toLowerCase()] }}>
                          {n.fields.severity !== '—' ? n.fields.severity : 'unknown severity'}
                        </span>
                        <span>·</span>
                        <span>{n.fields.timestamp !== '—' ? n.fields.timestamp : ''}</span>
                      </div>
                    </div>
                  )
                })}
                {filteredAlerts.length === 0 && hasAlertFilters && (
                  <div style={{ ...S.empty, height: 'auto', paddingTop: 40 }}>
                    No results for the active filters. Try clearing some filters or search terms.
                  </div>
                )}
              </div>
            )}
          </div>
        </section>
        {collectorNodes.length > 0 && (
          <aside style={S.right}>
            <div style={S.sideLabel}>Collector activity</div>
            <div style={S.rightCanvas}><GraphCanvas elements={collectorElements} /></div>
            <p style={S.rightNote}>
              {collectorNodes.length} findings from the probe ({(safeGraph.collector_ips || []).join(', ')}). Shown apart from attacker actors.
            </p>
          </aside>
        )}
      </div>
      <AllAlertsDrawer
        open={allAlertsOpen}
        onClose={() => setAllAlertsOpen(false)}
        detectResult={detectResult}
        eventsMap={eventsMap}
      />
      <DetailsPanel
        node={selectedNode}
        edge={selectedEdge}
        eventsMap={eventsMap}
        onClose={() => setSelected(null)}
      />
      {showDeleteModal && (
        <ConfirmDeleteModal
          title="Delete Collection?"
          message={
            <>
              Are you sure you want to permanently delete data for <strong>{collectionId}</strong>?
              All raw files, metadata, and generated graphs will be wiped from the disk. This action cannot be undone.
            </>
          }
          isProcessing={processingAction === 'delete'}
          onConfirm={handleDelete}
          onCancel={() => setShowDeleteModal(false)}
        />
      )}
    </div>
  )
}

const S: Record<string, React.CSSProperties> = {
  root: { height: '100vh', display: 'flex', flexDirection: 'column', color: 'var(--color-fg)' },
  header: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    height: 64, padding: '0 24px', borderBottom: '1px solid var(--color-line)', flexShrink: 0,
  },
  wordmark: { fontWeight: 800, letterSpacing: '-0.01em', fontSize: 18 },
  back: { color: 'var(--color-muted)', textDecoration: 'none', fontSize: 13 },
  meta: { fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-muted)' },
  signout: { background: 'transparent', border: 'none', color: 'var(--color-muted)', cursor: 'pointer', fontSize: 13, textDecoration: 'none' },
  body: { flex: 1, display: 'flex', minHeight: 0 },
  left: { width: 248, flexShrink: 0, borderRight: '1px solid var(--color-line)', overflowY: 'auto', padding: 12 },
  sideLabel: {
    fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.16em', textTransform: 'uppercase',
    color: 'var(--color-muted)', padding: '4px 4px 12px',
  },
  actorBtn: {
    display: 'block', width: '100%', textAlign: 'left', cursor: 'pointer', marginBottom: 8,
    padding: '10px 12px', borderRadius: 8, border: '1px solid var(--color-line)',
    background: 'var(--color-surface)', color: 'var(--color-fg)',
  },
  actorBtnActive: { borderColor: 'var(--color-accent)', background: '#00224d' },
  actorTop: { display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' },
  actorName: { fontWeight: 600, fontSize: 13 },
  actorCount: { fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-muted)' },
  actorSub: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-muted)', marginTop: 3 },
  center: { flex: 1, position: 'relative', minWidth: 0 },
  empty: { height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-muted)' },
  workingBanner: {
    position: 'absolute', top: 12, right: 12, zIndex: 20,
    display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
    borderRadius: 8, background: 'rgba(0,18,51,0.92)', border: '1px solid var(--color-line)',
    backdropFilter: 'blur(6px)', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-fg)',
  },
  workingDot: {
    width: 8, height: 8, borderRadius: '50%', background: 'var(--color-accent)',
    flexShrink: 0, animation: 'th-pulse 1s ease-in-out infinite',
  },
  errorBanner: {
    position: 'absolute', top: 12, right: 12, zIndex: 20,
    padding: '8px 12px', borderRadius: 8, background: 'rgba(51,0,0,0.92)',
    border: '1px solid var(--color-critical)', backdropFilter: 'blur(6px)',
    fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-critical)', maxWidth: 360,
  },
  alertList: {
    position: 'absolute', inset: 0, overflowY: 'auto', padding: 20,
    display: 'flex', flexDirection: 'column', gap: 10,
  },
  filterBar: {
    display: 'flex', flexDirection: 'column', gap: 8,
    width: '100%', maxWidth: 560, flexShrink: 0, marginBottom: 4,
  },
  searchWrap: { display: 'flex', alignItems: 'center', gap: 6 },
  alertSearchInput: {
    flex: 1, background: 'var(--color-surface)', border: '1px solid var(--color-line)',
    borderRadius: 6, padding: '6px 10px', fontFamily: 'var(--font-mono)',
    fontSize: 12, color: 'var(--color-fg)', outline: 'none',
  },
  alertSearchClear: {
    background: 'transparent', border: 'none', color: 'var(--color-muted)',
    cursor: 'pointer', fontSize: 12, padding: '4px 6px', flexShrink: 0,
  },
  chipRow: { display: 'flex', flexWrap: 'wrap', gap: 6 },
  chip: {
    fontFamily: 'var(--font-mono)', fontSize: 11, padding: '3px 8px',
    borderRadius: 20, border: '1px solid', cursor: 'pointer',
    transition: 'background 0.12s, color 0.12s', letterSpacing: '0.04em',
  },
  filterMeta: { display: 'flex', alignItems: 'center', gap: 12 },
  clearAll: {
    fontFamily: 'var(--font-mono)', fontSize: 11, background: 'transparent',
    border: 'none', color: 'var(--color-muted)', cursor: 'pointer',
    textDecoration: 'underline', padding: 0,
  },
  alertCard: {
    width: '100%', maxWidth: 560, padding: 14, borderRadius: 10,
    border: '1px solid var(--color-line)', background: 'var(--color-surface)', flexShrink: 0,
  },
  detailTitle: { fontWeight: 600, fontSize: 13, wordBreak: 'break-word', flex: 1, paddingRight: 10 },
  right: {
    width: 300, flexShrink: 0, borderLeft: '1px solid var(--color-line)',
    display: 'flex', flexDirection: 'column', padding: 12,
  },
  rightCanvas: { height: 280, border: '1px solid var(--color-line)', borderRadius: 8, overflow: 'hidden' },
  rightNote: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-muted)', lineHeight: 1.5, marginTop: 10 },
}