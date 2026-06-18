import { useEffect, type ReactNode } from 'react'

type Capability =
  | string
  | {
      name?: string
      bind?: string[] | string
      values?: unknown[]
    }

interface NodeFields {
  timestamp?: string
  rule?: string
  severity?: string
  kill_chain?: string
  user?: string
  process?: string
  events?: string
  source_ip?: string | null
}

export interface NodeInfoData {
  id: string
  label?: string
  kind?: string
  color?: string 
  phase?: string | null
  severity?: string
  fields?: NodeFields
  actor?: number | null
  event_ids?: string[]
  requires?: Capability[] | null
  provides?: Capability[] | null
  fusion_key?: Array<Array<string | number> | string> | null
}

interface Props {
  node: NodeInfoData | null
  onClose: () => void
}

const PANEL_W = 460
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

function capLabel(c: Capability): { name: string; detail: string | null } {
  if (typeof c === 'string') return { name: c, detail: null }
  const name = c.name  ?? 'capability'
  const bind = Array.isArray(c.bind) ? c.bind.join(', ') : (c.bind ?? '')
  const values = Array.isArray(c.values) ? c.values.map(String).join(', ') : ''
  const detail =
    bind || values ? `${bind}${bind && values ? '=' : ''}${values}` : null
  return { name, detail }
}

function Chip({ children }: { children: ReactNode }) {
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '4px 9px',
        borderRadius: 6,
        fontSize: 12,
        background: 'rgba(255,255,255,0.08)',
        border: '1px solid rgba(255,255,255,0.18)',
        color: TEXT,
        fontFamily: 'ui-monospace, SFMono-Regular, monospace',
        margin: '0 6px 6px 0',
        wordBreak: 'break-all',
      }}
    >
      {children}
    </span>
  )
}

function Section({
  title,
  count,
  children,
}: {
  title: string
  count?: number
  children: ReactNode
}) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div
        style={{
          fontSize: 11,
          textTransform: 'uppercase',
          letterSpacing: 0.6,
          color: MUTED,
          marginBottom: 8,
          display: 'flex',
          gap: 8,
          alignItems: 'center',
        }}
      >
        <span>{title}</span>
        {count != null && <span style={{ opacity: 0.6 }}>({count})</span>}
      </div>
      {children}
    </div>
  )
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div
      style={{
        display: 'flex',
        gap: 12,
        padding: '6px 0',
        fontSize: 13,
        borderBottom: `1px solid ${HAIRLINE}`,
      }}
    >
      <span style={{ width: 92, flexShrink: 0, color: MUTED }}>{label}</span>
      <span
        style={{
          color: TEXT,
          wordBreak: 'break-word',
          fontFamily: 'ui-monospace, monospace',
        }}
      >
        {value || '—'}
      </span>
    </div>
  )
}

function CapList({ items }: { items: Capability[] }) {
  if (items.length === 0)
    return <span style={{ color: MUTED, fontSize: 13, opacity: 0.6 }}>—</span>
  return (
    <>
      {items.map((c, i) => {
        const { name, detail } = capLabel(c)
        return (
          <Chip key={i}>
            {name}
            {detail && <span style={{ opacity: 0.6 }}>· {detail}</span>}
          </Chip>
        )
      })}
    </>
  )
}

export function NodeInfoPanel({ node, onClose }: Props) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])

  const open = node != null
  const f = node?.fields ?? {}
  const requires = node?.requires ?? []
  const provides = node?.provides ?? []
  const fusion = node?.fusion_key ?? []
  const severity = (node?.severity ?? f.severity ?? '').toLowerCase()
  const phase = node?.phase ?? f.kill_chain ?? 'unknown'

  return (
    <aside
      aria-hidden={!open}
      style={{
        position: 'fixed',
        top: 0,
        right: 0,
        height: '100vh',
        width: PANEL_W,
        background: BG,
        borderLeft: '1px solid rgba(255,255,255,0.1)',
        boxShadow: open ? '-14px 0 36px rgba(0,0,0,0.5)' : 'none',
        transform: open ? 'translateX(0)' : `translateX(${PANEL_W}px)`,
        transition: 'transform 180ms ease',
        display: 'flex',
        flexDirection: 'column',
        zIndex: 50,
        color: TEXT,
        fontFamily: 'system-ui, sans-serif',
      }}
    >
      {node && (
        <>
          <header
            style={{
              padding: '16px 18px',
              borderBottom: `1px solid ${HAIRLINE}`,
              display: 'flex',
              alignItems: 'flex-start',
              gap: 12,
            }}
          >
            <span
              style={{
                width: 12,
                height: 12,
                borderRadius: 3,
                marginTop: 5,
                flexShrink: 0,
                background: node.color ?? '#888',
              }}
            />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div
                style={{
                  fontSize: 15,
                  fontWeight: 600,
                  lineHeight: 1.3,
                  wordBreak: 'break-word',
                }}
              >
                {node.label ?? f.rule ?? node.id}
              </div>
              <div
                style={{
                  fontSize: 12,
                  color: MUTED,
                  marginTop: 6,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  flexWrap: 'wrap',
                }}
              >
                {severity && (
                  <span
                    style={{
                      padding: '2px 7px',
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      color: BG,
                      background: SEV_COLOR[severity] ?? '#9fb3cc',
                    }}
                  >
                    {severity}
                  </span>
                )}
                <span>{phase}</span>
                {node.actor != null && <span>· actor #{node.actor}</span>}
              </div>
            </div>
            <button
              onClick={onClose}
              aria-label="Close"
              style={{
                background: 'none',
                border: 'none',
                color: MUTED,
                fontSize: 20,
                cursor: 'pointer',
                lineHeight: 1,
                padding: 2,
              }}
            >
              ×
            </button>
          </header>

          <div style={{ padding: 18, overflowY: 'auto', flex: 1 }}>
            <Section title="Details">
              <Row label="rule" value={f.rule} />
              <Row label="timestamp" value={f.timestamp} />
              <Row label="user" value={f.user} />
              <Row label="process" value={f.process} />
              <Row label="source ip" value={f.source_ip} />
              <Row label="events" value={f.events} />
            </Section>

            <Section title="requires" count={requires.length}>
              <CapList items={requires} />
            </Section>

            <Section title="provides" count={provides.length}>
              <CapList items={provides} />
            </Section>

            <Section title="fusion_key" count={fusion.length}>
              {fusion.length === 0 ? (
                <span style={{ color: MUTED, fontSize: 13, opacity: 0.6 }}>—</span>
              ) : (
                fusion.map((k, i) => (
                  <Chip key={i}>
                    {Array.isArray(k) ? k.map(String).join(' · ') : String(k)}
                  </Chip>
                ))
              )}
            </Section>

            {node.event_ids && node.event_ids.length > 0 && (
              <Section title="event_ids" count={node.event_ids.length}>
                <div
                  style={{
                    fontSize: 11,
                    color: MUTED,
                    fontFamily: 'ui-monospace, monospace',
                    lineHeight: 1.6,
                    wordBreak: 'break-all',
                  }}
                >
                  {node.event_ids.map((e) => (
                    <div key={e}>{e}</div>
                  ))}
                </div>
              </Section>
            )}

            <Section title="id">
              <div
                style={{
                  fontSize: 12,
                  color: MUTED,
                  fontFamily: 'ui-monospace, monospace',
                  wordBreak: 'break-all',
                }}
              >
                {node.id}
              </div>
            </Section>
          </div>
        </>
      )}
    </aside>
  )
}