import { useMemo, useState, useEffect, type ReactNode} from 'react'
import type { DetectResult, DetectionFinding } from '@/types/alerts'
import { phaseColor } from '@/lib/phaseColor'
import type React from 'react'

const DRAWER_W = 600
const PANEL_W = 500
const BG = '#002855'
const TEXT = '#e8eef7'
const MUTED = '#8ba3c4'
const HAIRLINE = 'rgba(255,255,255,0.08)'

const SEV_ORDER = ['low', 'medium', 'high', 'critical'] as const
type Severity = typeof SEV_ORDER[number]

const PHASES = [
  'reconnaissance', 'weaponization', 'delivery', 'exploitation',
  'installation', 'command_and_control', 'actions_on_objectives',
] as const

const SEV_COLORS: Record<string, string> = {
  low: '#22c55e', medium: '#f59e0b', high: '#f97316', critical: '#ef4444',
}

const SEV_COLOR_PANEL: Record<string, string> = {
  critical: '#ff5b6e', high: '#ff9f43', medium: '#ffd23f', low: '#4dd4ac',
}


type FindingItem = {
  kind: 'finding'
  id: string
  label: string
  severity: string
  kill_chain_phase: string
  timestamp: string
  source: string
  technique_id?: string
  description?: string
  tags: string[]
  event_count: number
  raw: DetectionFinding
  is_probe: boolean
}

type Item = FindingItem

function findingToItem(f: DetectionFinding): FindingItem {
  return {
    kind: 'finding',
    id: f.id,
    label: f.rule_name ,
    severity: f.severity,
    kill_chain_phase: f.kill_chain_phase ?? '',
    timestamp: f.timestamp ?? '',
    source: f.source,
    technique_id: f.technique_id ?? '',
    description: f.description,
    tags: f.tags,
    event_count: f.event_count,
    raw: f,
    is_probe: f.is_probe ?? false,
  }
}

function sevIndex(s: string) {
  return SEV_ORDER.indexOf(s.toLowerCase() as Severity)
}

function Chip({ children }: { children: ReactNode }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      padding: '4px 9px', borderRadius: 6, fontSize: 12,
      background: 'rgba(255,255,255,0.08)', border: '1px solid rgba(255,255,255,0.18)',
      color: TEXT, fontFamily: 'ui-monospace, SFMono-Regular, monospace',
      margin: '0 6px 6px 0', wordBreak: 'break-all',
    }}>
      {children}
    </span>
  )
}

function Section({ title, count, children }: { title: string; count?: number; children: ReactNode }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{
        fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.6,
        color: MUTED, marginBottom: 8, display: 'flex', gap: 8, alignItems: 'center',
        borderBottom: `1px solid ${HAIRLINE}`, paddingBottom: 6,
      }}>
        <span>{title}</span>
        {count != null && <span style={{ opacity: 0.6 }}>({count})</span>}
      </div>
      {children}
    </div>
  )
}

function Row({ label, value, dot }: { label: string; value: ReactNode; dot?: string }) {
  return (
    <div style={{ display: 'flex', gap: 12, padding: '6px 0', fontSize: 13, borderBottom: `1px solid ${HAIRLINE}` }}>
      <span style={{ width: 100, flexShrink: 0, color: MUTED }}>{label}</span>
      <span style={{ color: TEXT, wordBreak: 'break-word', fontFamily: 'ui-monospace, monospace', display: 'flex', alignItems: 'center', gap: 8 }}>
        {dot && <span style={{ width: 8, height: 8, borderRadius: 2, background: dot, flexShrink: 0 }} />}
        {value || '—'}
      </span>
    </div>
  )
}

type EventFields = Record<string, unknown>

interface SidePanelProps {
  item: Item | null
  eventsMap: Record<string, EventFields>
  onClose: () => void
}

function SidePanel({ item, onClose }: SidePanelProps) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])

  const open = item != null
  const severity = item?.severity ?? ''
  const phase = item?.kill_chain_phase?? 'unknown'

  return (
    <aside style={{
      position: 'fixed', top: 0, right: 0, height: '100vh', width: PANEL_W,
      background: BG, borderLeft: '1px solid rgba(255,255,255,0.1)',
      boxShadow: open ? '-14px 0 36px rgba(0,0,0,0.5)' : 'none',
      transform: open ? 'translateX(0)' : `translateX(${PANEL_W}px)`,
      transition: 'transform 180ms ease',
      display: 'flex', flexDirection: 'column',
      zIndex: 202, color: TEXT, fontFamily: 'system-ui, sans-serif',
    }}>
      {item && (
        <>
          <header style={{
            padding: '16px 18px', borderBottom: `1px solid ${HAIRLINE}`,
            display: 'flex', alignItems: 'flex-start', gap: 12,
          }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 16, fontWeight: 600, lineHeight: 1.3, wordBreak: 'break-word' }}>
                {item.label}
                {item.is_probe && <span style={{ color: MUTED, fontWeight: 400 }}> (probe)</span>}

              </div>
              <div style={{ fontSize: 12, color: MUTED, marginTop: 8, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                {severity && severity !== '—' && (
                  <span style={{
                    padding: '2px 7px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                    textTransform: 'uppercase', color: BG,
                    background: SEV_COLOR_PANEL[severity] ?? '#9fb3cc',
                  }}>
                    {severity}
                  </span>
                )}
                {phase !== '—' && <span>{phase}</span>}
                {item.technique_id && (
                  <span style={{
                    fontFamily: 'ui-monospace, monospace', fontSize: 11,
                    background: 'rgba(255,255,255,0.08)', padding: '2px 6px',
                    borderRadius: 4, border: `1px solid ${HAIRLINE}`,
                  }}>
                    {item.technique_id}
                  </span>
                )}
              </div>
            </div>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: MUTED, fontSize: 24, cursor: 'pointer', lineHeight: 1 }}>
              ×
            </button>
          </header>

          <div style={{ padding: 18, overflowY: 'auto', flex: 1 }}>
                <Section title="General Information">
                  <Row 
                    label="rule" 
                    value={
                      <>
                        {item.raw.rule_name}
                        {item.raw.is_probe && <span style={{ color: MUTED }}> (probe)</span>}
                      </>
                    } 
                  />
                  <Row label="source" value={item.raw.source} />
                  <Row label="phase" value={item.kill_chain_phase|| '—'} dot={phase && phase !== '—' ? phaseColor(phase) : undefined} />
                  <Row label="severity" value={item.raw.severity} />
                  <Row label="technique" value={item.raw.technique_id ?? '—'} />
                  <Row label="events" value={String(item.raw.event_count)} />
                  <Row label="timestamp" value={item.raw.timestamp ?? '—'} />
                </Section>

                {item.raw.description && (
                  <Section title="Description">
                    <div style={{ fontSize: 13, color: TEXT, lineHeight: 1.6 }}>
                      {item.raw.description}
                    </div>
                  </Section>
                )}

                {Object.keys(item.raw.entities ?? {}).length > 0 && (
                  <Section title="Entities">
                    {Object.entries(item.raw.entities).map(([k, v]) => (
                      <Row key={k} label={k} value={String(v)} />
                    ))}
                  </Section>
                )}

                {item.raw.tags.length > 0 && (
                  <Section title="Tags">
                    <div style={{ display: 'flex', flexWrap: 'wrap' }}>
                      {item.raw.tags.map((t: string) => <Chip key={t}>{t}</Chip>)}
                    </div>
                  </Section>
                )}

                <Section title="Finding ID">
                  <div style={{ fontSize: 11, color: MUTED, fontFamily: 'ui-monospace, monospace', wordBreak: 'break-all' }}>
                    {item.raw.id}
                  </div>
                </Section>
          </div>
        </>
      )}
    </aside>
  )
}


interface AllAlertsDrawerProps {
  open: boolean
  onClose: () => void
  detectResult: DetectResult | null
  eventsMap: Record<string, EventFields>
}


export default function AllAlertsDrawer({
  open,
  onClose,
  detectResult,
  eventsMap,
}: AllAlertsDrawerProps) {
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set())
  const [phaseFilter, setPhaseFilter] = useState<Set<string>>(new Set())
  const [selectedItem, setSelectedItem] = useState<Item | null>(null)

  useEffect(() => { if (!open) setSelectedItem(null) }, [open])

  const items: Item[] = useMemo(() => {
    return (detectResult?.findings.map(findingToItem) ?? []).sort((a, b) => {
      const sd = sevIndex(b.severity) - sevIndex(a.severity)
      if (sd !== 0) return sd
      return b.timestamp.localeCompare(a.timestamp)
    })
  }, [detectResult])

  const availableSevs = useMemo(() => {
    const s = new Set(items.map((i) => i.severity).filter(Boolean))
    return SEV_ORDER.filter((v) => s.has(v))
  }, [items])

  const availablePhases = useMemo(() => {
    const s = new Set(items.map((i) => i.kill_chain_phase).filter(Boolean))
    return PHASES.filter((v) => s.has(v))
  }, [items])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return items.filter((item) => {
      if (sevFilter.size > 0 && !sevFilter.has(item.severity)) return false
      if (phaseFilter.size > 0 && !phaseFilter.has(item.kill_chain_phase)) return false
      if (q) {
        return (
          item.label.toLowerCase().includes(q) ||
          item.kill_chain_phase.toLowerCase().includes(q) ||
          item.severity.toLowerCase().includes(q) ||
          item.timestamp.toLowerCase().includes(q) ||
          item.source.toLowerCase().includes(q) ||
          (item.technique_id?.toLowerCase().includes(q) ?? false) ||
          (item.description?.toLowerCase().includes(q) ?? false) ||
          item.tags.some((t) => t.toLowerCase().includes(q))
        )
      }
      return true
    })
  }, [items, search, sevFilter, phaseFilter])

  const toggleSev = (v: string) => setSevFilter((p) => { const n = new Set(p); n.has(v) ? n.delete(v) : n.add(v); return n })
  const togglePhase = (v: string) => setPhaseFilter((p) => { const n = new Set(p); n.has(v) ? n.delete(v) : n.add(v); return n })
  const clearAll = () => { setSearch(''); setSevFilter(new Set()); setPhaseFilter(new Set()) }
  const hasFilters = search.trim() !== '' || sevFilter.size > 0 || phaseFilter.size > 0

  const findingCount = items.length

  if (!open) return null

  return (
    <>
      <div style={S.backdrop} onClick={() => { setSelectedItem(null); onClose() }} />

      <div style={{ ...S.drawer, width: DRAWER_W }}>
        <div style={S.drawerHeader}>
          <div>
            <div style={S.drawerTitle}>All Alerts</div>
            <div style={S.drawerSub}>
              {findingCount} detection finding{findingCount !== 1 ? 's' : ''}
            </div>
          </div>
          <button style={S.closeBtn} onClick={() => { setSelectedItem(null); onClose() }}>✕</button>
        </div>

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>
          <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden', flex: 1 }}>
            <div style={S.filterArea}>
              <div style={S.searchWrap}>
                <input
                  style={S.searchInput}
                  type="text"
                  placeholder="Search for IP, rule, phase, severity, source, technique, description, tags..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  autoFocus
                />
                {search && <button style={S.clearBtn} onClick={() => setSearch('')}>✕</button>}
              </div>

              {availableSevs.length > 0 && (
                <div style={S.chipRow}>
                  {availableSevs.map((sev) => {
                    const active = sevFilter.has(sev)
                    return (
                      <button key={sev} style={{
                        ...S.chip,
                        borderColor: SEV_COLORS[sev],
                        background: active ? SEV_COLORS[sev] : 'transparent',
                        color: active ? '#000' : SEV_COLORS[sev],
                        fontWeight: active ? 700 : 500,
                      }} onClick={() => toggleSev(sev)}>{sev}</button>
                    )
                  })}
                </div>
              )}

              {availablePhases.length > 0 && (
                <div style={S.chipRow}>
                  {availablePhases.map((phase) => {
                    const active = phaseFilter.has(phase)
                    const col = phaseColor(phase)
                    return (
                      <button key={phase} style={{
                        ...S.chip,
                        borderColor: col,
                        background: active ? col : 'transparent',
                        color: active ? '#000' : col,
                        fontWeight: active ? 700 : 500,
                      }} onClick={() => togglePhase(phase)}>{phase}</button>
                    )
                  })}
                </div>
              )}

              <div style={S.filterMeta}>
                <span style={S.metaMono}>{filtered.length} / {items.length}</span>
                {hasFilters && <button style={S.clearAllBtn} onClick={clearAll}>clear all</button>}
              </div>
            </div>

            <div style={S.list}>
              {filtered.length === 0 ? (
                <div style={S.empty}>No result for the selected filters.</div>
              ) : (
                filtered.map((item) => {
                  const isSelected = selectedItem?.id === item.id
                  return <FindingCard key={`f-${item.id}`} item={item} selected={isSelected} onClick={() => setSelectedItem(isSelected ? null : item)} />
                })
              )}
            </div>
          </div>
        </div>

        <SidePanel
          item={selectedItem}
          eventsMap={eventsMap}
          onClose={() => setSelectedItem(null)}
        />
      </div>
    </>
  )
}


function FindingCard({ item, selected, onClick }: { item: FindingItem; selected: boolean; onClick: () => void }) {
  const col = phaseColor(item.kill_chain_phase|| 'unknown')
  return (
    <div onClick={onClick} style={{
      ...S.card,
      borderLeft: `3px solid ${col}`,
      cursor: 'pointer',
      outline: selected ? '1px solid rgba(245,158,11,0.6)' : 'none',
      background: selected ? 'rgba(245,158,11,0.06)' : 'var(--color-surface)',
    }}>
      <div style={S.cardTop}>
        <span style={S.cardTitle}>
            {item.label}
           {item.is_probe && <span style={S.probeTag}> (probe)</span>}
        </span>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
          {item.technique_id && <span style={S.techniqueTag}>{item.technique_id}</span>}
          <span style={{ ...S.kindBadge, borderColor: 'rgba(245,158,11,0.4)', color: '#f59e0b' }}>finding</span>
        </div>
      </div>
      <div style={S.cardMeta}>
        <span>{item.kill_chain_phase|| 'unknown phase'}</span>
        <span>·</span>
        <span style={{ color: SEV_COLORS[item.severity] ?? 'var(--color-fg)' }}>{item.severity || '—'}</span>
        <span>·</span>
        <span style={S.mono}>{item.source}</span>
        {item.event_count > 1 && <><span>·</span><span>{item.event_count} events</span></>}
        {item.timestamp && <><span>·</span><span style={S.mono}>{item.timestamp}</span></>}
      </div>
      {item.description && (
        <div style={{ ...S.cardMeta, marginTop: 4, fontSize: 11, lineHeight: 1.5 }}>{item.description}</div>
      )}
      {item.tags.length > 0 && (
        <div style={{ display: 'flex', gap: 4, marginTop: 6, flexWrap: 'wrap' }}>
          {item.tags.map((t) => <span key={t} style={S.tagChip}>{t}</span>)}
        </div>
      )}
    </div>
  )
}



const S: Record<string, React.CSSProperties> = {
  probeTag: {
    color: 'var(--color-muted)',
    fontWeight: 400,
    fontSize: 12,
  },
  backdrop: {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
    backdropFilter: 'blur(2px)', zIndex: 200,
  },
  drawer: {
    position: 'fixed', top: 0, right: 0, bottom: 0,
    background: 'var(--color-bg, #020d1f)',
    borderLeft: '1px solid var(--color-line)',
    zIndex: 201, display: 'flex', flexDirection: 'column',
    boxShadow: '-8px 0 32px rgba(0,0,0,0.4)',
  },
  drawerHeader: {
    display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
    padding: '20px 20px 16px', borderBottom: '1px solid var(--color-line)', flexShrink: 0,
  },
  drawerTitle: { fontWeight: 700, fontSize: 16, color: 'var(--color-fg)' },
  drawerSub: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-muted)', marginTop: 4 },
  closeBtn: {
    background: 'transparent', border: 'none', color: 'var(--color-muted)',
    cursor: 'pointer', fontSize: 16, padding: '2px 4px', lineHeight: 1,
  },
  filterArea: {
    padding: '14px 20px', borderBottom: '1px solid var(--color-line)',
    display: 'flex', flexDirection: 'column', gap: 8, flexShrink: 0,
  },
  searchWrap: { display: 'flex', alignItems: 'center', gap: 6 },
  searchInput: {
    flex: 1, background: 'var(--color-surface)', border: '1px solid var(--color-line)',
    borderRadius: 6, padding: '6px 10px', fontFamily: 'var(--font-mono)',
    fontSize: 12, color: 'var(--color-fg)', outline: 'none',
  },
  clearBtn: {
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
  metaMono: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-muted)' },
  clearAllBtn: {
    fontFamily: 'var(--font-mono)', fontSize: 11, background: 'transparent',
    border: 'none', color: 'var(--color-muted)', cursor: 'pointer',
    textDecoration: 'underline', padding: 0,
  },
  list: { flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 8 },
  empty: { color: 'var(--color-muted)', fontSize: 13, paddingTop: 32, textAlign: 'center' },
  card: {
    padding: '12px 14px', borderRadius: 8,
    border: '1px solid var(--color-line)',
    flexShrink: 0, transition: 'background 0.12s, outline 0.12s',
  },
  cardTop: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 },
  cardTitle: { fontWeight: 600, fontSize: 13, wordBreak: 'break-word', flex: 1 },
  cardMeta: { display: 'flex', gap: 8, fontSize: 12, color: 'var(--color-muted)', marginTop: 5, flexWrap: 'wrap' },
  kindBadge: {
    fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 6px',
    borderRadius: 4, border: '1px solid', flexShrink: 0,
  },
  techniqueTag: {
    fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-muted)',
    background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: 4,
    flexShrink: 0, border: '1px solid var(--color-line)',
  },
  tagChip: {
    fontFamily: 'var(--font-mono)', fontSize: 10, padding: '1px 6px', borderRadius: 10,
    background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-line)', color: 'var(--color-muted)',
  },
  mono: { fontFamily: 'var(--font-mono)', fontSize: 11 },
}