import { useEffect, useState, useMemo, type ReactNode } from 'react'
import type { GraphNode, GraphEdge } from '@/types/graph'
import { phaseColor } from '@/lib/phaseColor'

type EventFields = Record<string, unknown>

interface Props {
  node?: GraphNode
  edge?: GraphEdge
  eventsMap: Record<string, EventFields>
  onClose: () => void
}

const PANEL_W = 600
const BG = '#002855'
const TEXT = '#e8eef7'
const MUTED = '#8ba3c4'
const HAIRLINE = 'rgba(255,255,255,0.08)'

const SEV_COLOR: Record<string, string> = {
  critical: '#ff5b6e',
  high: '#ff9f43',
  medium: '#ffd23f',
  low: '#4dd4ac',
}

type CapabilityDef = NonNullable<GraphNode['requires']>[0]

function capLabel(c: CapabilityDef): { name: string; detail: string | null } {
  const name = c.name ?? 'capability'
  const bind = c.bind?.join(', ') ?? ''
  const values = c.values?.join(', ') ?? ''
  const detail = bind || values ? `${bind}${bind && values ? '=' : ''}${values}` : null
  return { name, detail }
}

function Chip({ children }: { children: ReactNode }) {
  return (
    <span
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 6,
        padding: '4px 9px', borderRadius: 6, fontSize: 12,
        background: 'rgba(255,255,255,0.08)', border: '1px solid rgba(255,255,255,0.18)',
        color: TEXT, fontFamily: 'ui-monospace, SFMono-Regular, monospace',
        margin: '0 6px 6px 0', wordBreak: 'break-all',
      }}
    >
      {children}
    </span>
  )
}

function Section({ title, count, children }: { title: string; count?: number; children: ReactNode }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div
        style={{
          fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.6,
          color: MUTED, marginBottom: 8, display: 'flex', gap: 8, alignItems: 'center',
          borderBottom: `1px solid ${HAIRLINE}`, paddingBottom: 6
        }}
      >
        <span>{title}</span>
        {count != null && <span style={{ opacity: 0.6 }}>({count})</span>}
      </div>
      {children}
    </div>
  )
}

function Row({ label, value, dot }: { label: string; value: ReactNode; dot?: string }) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'minmax(120px, 35%) 1fr',
      gap: 12,
      padding: '6px 0',
      fontSize: 13,
      borderBottom: `1px solid ${HAIRLINE}`,
      alignItems: 'flex-start',
    }}>
      <span style={{
        color: MUTED,
        wordBreak: 'break-word',
        paddingTop: 1,
      }}>
        {label}
      </span>
      <span style={{
        color: TEXT,
        wordBreak: 'break-word',
        fontFamily: 'ui-monospace, monospace',
        display: 'flex',
        alignItems: 'flex-start',
        gap: 8,
        minWidth: 0,
      }}>
        {dot && <span style={{ width: 8, height: 8, borderRadius: 2, background: dot, flexShrink: 0, marginTop: 4 }} />}
        {value || '—'}
      </span>
    </div>
  )
}

function FieldTree({ obj, prefix = '' }: { obj: Record<string, unknown>; prefix?: string }) {
  const rows: ReactNode[] = []
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) continue
    const key = prefix ? `${prefix}.${k}` : k
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      rows.push(<FieldTree key={key} obj={v as Record<string, unknown>} prefix={key} />)
    } else {
      const val = Array.isArray(v)
        ? v.map((x) => (x && typeof x === 'object' ? JSON.stringify(x) : String(x))).join(', ')
        : String(v)
      rows.push(<Row key={key} label={key} value={val} />)
    }
  }
  return <>{rows}</>
}

export function DetailsPanel({ node, edge, eventsMap, onClose }: Props) {
  const [activeEventId, setActiveEventId] = useState<string | null>(null)

  useEffect(() => {
    setActiveEventId(null)
  }, [node, edge])

  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])

  const open = node != null || edge != null
  const f = node?.fields ?? {}
  const severity = (f.severity ?? '').toLowerCase()
  const phase = f.kill_chain ?? 'unknown'
  const eventIds = node?.event_ids ?? []
  const isProbe = Boolean(node?.is_probe)

  const fusedSignals = f.fused_signals as string[] | undefined
  const hasFused = Array.isArray(fusedSignals) && fusedSignals.length > 1
  const groupedFused = useMemo(() => {
    if (!hasFused) return []
    const counts: Record<string, number> = {}
    for (const sig of fusedSignals) {
      counts[sig] = (counts[sig] || 0) + 1
    }
    return Object.entries(counts).map(([name, count]) => ({ name, count }))
  }, [fusedSignals, hasFused])

  return (
    <aside
      aria-hidden={!open}
      style={{
        position: 'fixed', top: 0, right: 0, height: '100vh', width: PANEL_W,
        background: BG, borderLeft: '1px solid rgba(255,255,255,0.1)',
        boxShadow: open ? '-14px 0 36px rgba(0,0,0,0.5)' : 'none',
        transform: open ? 'translateX(0)' : `translateX(${PANEL_W}px)`,
        transition: 'transform 180ms ease', display: 'flex', flexDirection: 'column',
        zIndex: 50, color: TEXT, fontFamily: 'system-ui, sans-serif',
      }}
    >
      {(node || edge) && (
        <>
          <header style={{ padding: '16px 18px', borderBottom: `1px solid ${HAIRLINE}`, display: 'flex', alignItems: 'flex-start', gap: 12 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 16, fontWeight: 600, lineHeight: 1.3, wordBreak: 'break-word' }}>
                {activeEventId ? 'Event details' : (node?.label ?? node?.id ?? edge?.relation)}
                {!activeEventId && node && isProbe && (
                  <span style={{ color: MUTED, fontWeight: 400 }}> (probe)</span>
                )}
              </div>

              {!activeEventId && node && (
                <div style={{ fontSize: 12, color: MUTED, marginTop: 8, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  {severity && severity !== '—' && (
                    <span style={{ padding: '2px 7px', borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: BG, background: SEV_COLOR[severity] ?? '#9fb3cc' }}>
                      {severity}
                    </span>
                  )}
                  {phase !== '—' && <span>{phase}</span>}
                  {node.actor != null && <span>· actor #{node.actor}</span>}
                </div>
              )}
            </div>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: MUTED, fontSize: 24, cursor: 'pointer', lineHeight: 1 }}>
              ×
            </button>
          </header>
          <div style={{ padding: 18, overflowY: 'auto', flex: 1 }}>
            {activeEventId && eventsMap[activeEventId] ? (
              <div>
                <button
                  onClick={() => setActiveEventId(null)}
                  style={{
                    background: 'rgba(255,255,255,0.05)', border: `1px solid ${HAIRLINE}`, color: TEXT,
                    padding: '6px 12px', borderRadius: 6, cursor: 'pointer', marginBottom: 20,
                    display: 'flex', alignItems: 'center', gap: 6, fontSize: 13
                  }}
                >
                  ← Back to finding node
                </button>
                <Section title={`Fields: ${activeEventId}`}>
                  <FieldTree obj={eventsMap[activeEventId]} />
                </Section>
              </div>
            ) : node ? (
              <>
                <Section title="General Information">
                  <Row
                    label="rule"
                    value={
                      <>
                        {f.rule}
                        {isProbe && <span style={{ color: MUTED }}> (probe)</span>}
                      </>
                    }
                  />
                  <Row label="phase" value={f.kill_chain} dot={f.kill_chain && f.kill_chain !== '—' ? phaseColor(f.kill_chain) : undefined} />
                  <Row label="severity" value={f.severity} />
                  <Row label="timestamp" value={f.timestamp} />
                  <Row label="user" value={f.user} />
                  <Row label="process" value={f.process} />
                  <Row label="source ip" value={f.source_ip} />
                  <Row label="logon id" value={f.logon_id} />
                </Section>
                {hasFused && (
                  <Section title="Fused Rules" count={fusedSignals.length}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {groupedFused.map((sig, idx) => (
                        <div
                          key={idx}
                          style={{
                            background: 'rgba(255, 255, 255, 0.03)',
                            border: `1px solid ${HAIRLINE}`,
                            borderRadius: 6,
                            padding: '8px 12px',
                            fontFamily: 'ui-monospace, monospace',
                            fontSize: 12,
                            color: TEXT,
                            wordBreak: 'break-word',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'flex-start',
                            gap: 12
                          }}
                        >
                          <span>{sig.name}</span>
                          {sig.count > 1 && (
                            <span style={{
                              color: MUTED,
                              fontSize: 11,
                              background: 'rgba(255,255,255,0.08)',
                              padding: '2px 6px',
                              borderRadius: 4,
                              whiteSpace: 'nowrap'
                            }}>
                              x{sig.count}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </Section>
                )}
                {eventIds.length > 0 && (
                  <Section title="Associated Events" count={eventIds.length}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {eventIds.map((eid) => {
                        const evFields = eventsMap[eid] || {}
                        const ts = String((evFields['@timestamp'] ?? evFields.timestamp) ?? '')
                        const action = String((evFields.event as any)?.action ?? evFields.action ?? eid)

                        return (
                          <button
                            key={eid}
                            onClick={() => setActiveEventId(eid)}
                            style={{
                              textAlign: 'left', background: 'rgba(255,255,255,0.03)', border: `1px solid ${HAIRLINE}`,
                              padding: '10px 12px', borderRadius: 8, color: TEXT, cursor: 'pointer',
                              display: 'flex', flexDirection: 'column', gap: 4, transition: 'background 0.2s'
                            }}
                            onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
                            onMouseOut={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                          >
                            <span style={{ fontSize: 13, fontWeight: 500, wordBreak: 'break-word' }}>{action}</span>
                            <span style={{ fontSize: 11, color: MUTED, fontFamily: 'ui-monospace, monospace' }}>{ts}</span>
                          </button>
                        )
                      })}
                    </div>
                  </Section>
                )}
                <Section title="Capabilities">
                  {((node.requires ?? []).length > 0 || (node.provides ?? []).length > 0) ? (
                    <>
                      {(node.requires ?? []).map((c, i) => {
                        const { name, detail } = capLabel(c)
                        return <Chip key={`req-${i}`}>Req: {name} {detail ? `(${detail})` : ''}</Chip>
                      })}
                      {(node.provides ?? []).map((c, i) => {
                        const { name, detail } = capLabel(c)
                        return <Chip key={`prov-${i}`}>Prov: {name} {detail ? `(${detail})` : ''}</Chip>
                      })}
                    </>
                  ) : (
                    <span style={{ color: MUTED, fontSize: 13 }}>—</span>
                  )}
                </Section>
                <Section title="Fusion Key">
                  {(node.fusion_key ?? []).length === 0 ? (
                    <span style={{ color: MUTED, fontSize: 13 }}>—</span>
                  ) : (
                    (node.fusion_key ?? []).map((k, i) => (
                      <Chip key={i}>{k.join(' · ')}</Chip>
                    ))
                  )}
                </Section>
                <Section title="Node ID">
                  <div style={{ fontSize: 11, color: MUTED, fontFamily: 'ui-monospace, monospace', wordBreak: 'break-all' }}>
                    {node.id}
                  </div>
                </Section>
              </>
            ) : edge ? (
              <Section title="Edge Information">
                <Row label="relation" value={edge.relation} />
                <Row label="from" value={edge.source} />
                <Row label="to" value={edge.target} />
                {edge.cap && <Row label="capability" value={edge.cap} />}
                <Row label="nature" value={edge.nature} />
              </Section>
            ) : null}
          </div>
        </>
      )}
    </aside>
  )
}