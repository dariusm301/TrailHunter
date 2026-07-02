import { useEffect, useState } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import logo from '@/assets/logo.svg'
import AccountMenu from '@/components/AccountMenu'
import { fetchCollectionSummary, type CollectionSummary } from '@/api/collections'

const SEV_COLORS: Record<string, string> = {
  low: '#22c55e', medium: '#f59e0b', high: '#f97316', critical: '#ef4444',
}

function formatBytes(b: number): string {
  if (b >= 1024 * 1024 * 1024) return `${(b / (1024 ** 3)).toFixed(2)} GB`
  if (b >= 1024 * 1024) return `${(b / (1024 ** 2)).toFixed(2)} MB`
  if (b >= 1024) return `${(b / 1024).toFixed(2)} KB`
  return `${b} B`
}

export default function SummaryPage() {
  const { collectionId } = useParams<{ collectionId: string }>()
  const navigate = useNavigate()
  const [summary, setSummary] = useState<CollectionSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!collectionId) { navigate('/scans'); return }
    fetchCollectionSummary(collectionId)
      .then(setSummary)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [collectionId, navigate])

  return (
    <div style={S.root}>
      <header style={S.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <Link to={`/scans/${collectionId}`} style={S.back}>← Graph</Link>
          <img src={logo} alt="TrailHunter" style={{ height: 45 }} />
          {collectionId && <span style={S.mono}>{collectionId}</span>}
        </div>
        <AccountMenu />
      </header>

      <div style={S.body}>
        <div style={S.card}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
            <div style={S.cardTitle}>Collection Summary</div>
            {summary && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                {summary.probe && (
                  <span style={S.badge}>A probe was used</span>
                )}
                {summary.max_severity && (
                  <span style={{
                    ...S.badge,
                    borderColor: SEV_COLORS[summary.max_severity] ?? 'var(--color-line)',
                    color: SEV_COLORS[summary.max_severity] ?? 'var(--color-fg)',
                  }}>
                    {summary.max_severity}
                  </span>
                )}
                {summary.actor_count != null && (
                  <span style={S.mono}>{summary.actor_count} actor{summary.actor_count !== 1 ? 's' : ''}</span>
                )}
              </div>
            )}
          </div>

          {loading && <div style={S.muted}>Loading...</div>}
          {error && <div style={{ color: 'var(--color-critical)' }}>Error: {error}</div>}

          {summary && (
            <div style={S.grid}>

              <Section title="Metadata">
                <Row label="Hostname" value={summary.hostname} />
                <Row label="Collected at" value={summary.collected_at} />
                <Row label="OS Version" value={summary.os_version} />
                <Row label="Size" value={summary.size_bytes != null ? formatBytes(summary.size_bytes) : undefined} />
              </Section>

              <Section title="Integrity">
                <Row label="SHA-256" value={summary.sha256} mono break />
              </Section>

              <Section title="Collector IPs">
                {summary.collector_ip && Object.keys(summary.collector_ip).length > 0
                  ? Object.entries(summary.collector_ip).map(([iface, ips]) => (
                    <Row key={iface} label={iface} value={ips.join(', ')} mono />
                  ))
                  : <div style={S.muted}>—</div>
                }
              </Section>

              {summary.token_id && (
                <Section title="Probe Token">
                  <Row label="Token ID" value={summary.token_id} mono />
                  <Row label="Name" value={summary.token_name} />
                  <Row label="Type" value={summary.token_type} />
                </Section>
              )}

              {summary.event_counts && (
                <Section title="Event Counts">
                  <div style={S.countGrid}>
                    {Object.entries(summary.event_counts)
                      .sort((a, b) => b[1] - a[1])
                      .map(([channel, count]) => (
                        <div key={channel} style={S.countCell}>
                          <div style={S.countValue}>{count.toLocaleString()}</div>
                          <div style={S.countLabel}>{channel}</div>
                        </div>
                      ))}
                  </div>
                </Section>
              )}

              {summary.finding_counts && (
                <Section title="Findings per Channel">
                  <div style={S.countGrid}>
                    {Object.entries(summary.finding_counts)
                      .sort((a, b) => b[1] - a[1])
                      .map(([channel, count]) => (
                        <div key={channel} style={{
                          ...S.countCell,
                          borderColor: count > 0 ? 'rgba(245,158,11,0.3)' : 'var(--color-line)',
                        }}>
                          <div style={{
                            ...S.countValue,
                            color: count > 0 ? '#f59e0b' : 'var(--color-muted)',
                          }}>{count}</div>
                          <div style={S.countLabel}>{channel}</div>
                        </div>
                      ))}
                  </div>
                </Section>
              )}

              {summary.hashes && (
                <Section title="Module Hashes">
                  {Object.entries(summary.hashes).map(([module, hash]) => (
                    <Row key={module} label={module} value={hash} mono break />
                  ))}
                </Section>
              )}

            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 32 }}>
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.14em',
        textTransform: 'uppercase', color: 'var(--color-muted)', marginBottom: 12,
        paddingBottom: 8, borderBottom: '1px solid var(--color-line)',
      }}>
        {title}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {children}
      </div>
    </div>
  )
}

function Row({ label, value, mono, break: brk }: {
  label: string; value?: string; mono?: boolean; break?: boolean
}) {
  return (
    <div style={{ display: 'flex', gap: 16, alignItems: brk ? 'flex-start' : 'center' }}>
      <span style={{
        fontFamily: 'var(--font-mono)', fontSize: 11, width: 160, flexShrink: 0,
        color: 'var(--color-muted)', letterSpacing: '0.02em',
      }}>
        {label}
      </span>
      <span style={{
        fontFamily: mono ? 'var(--font-mono)' : undefined,
        fontSize: mono ? 11 : 13,
        color: value ? 'var(--color-fg)' : 'var(--color-muted)',
        wordBreak: brk ? 'break-all' : undefined,
      }}>
        {value ?? '—'}
      </span>
    </div>
  )
}

const S: Record<string, React.CSSProperties> = {
  root: { height: '100vh', display: 'flex', flexDirection: 'column', color: 'var(--color-fg)' },
  header: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    height: 64, padding: '0 24px', borderBottom: '1px solid var(--color-line)', flexShrink: 0,
  },
  back: { color: 'var(--color-muted)', textDecoration: 'none', fontSize: 13 },
  mono: { fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-muted)' },
  muted: { color: 'var(--color-muted)', fontSize: 13 },
  body: {
    flex: 1, display: 'flex', justifyContent: 'center',
    padding: '40px 24px', overflowY: 'auto',
  },
  card: {
    width: '100%', maxWidth: 780, background: 'var(--color-surface)',
    border: '1px solid var(--color-line)', borderRadius: 12, padding: '32px 36px',
    alignSelf: 'flex-start',
  },
  cardTitle: { fontSize: 18, fontWeight: 700 },
  grid: { display: 'flex', flexDirection: 'column' },
  badge: {
    fontFamily: 'var(--font-mono)', fontSize: 11, padding: '3px 8px',
    borderRadius: 20, border: '1px solid var(--color-line)',
    color: 'var(--color-muted)', letterSpacing: '0.04em',
  },
  countGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(110px, 1fr))',
    gap: 8,
  },
  countCell: {
    padding: '10px 12px', borderRadius: 8,
    border: '1px solid var(--color-line)',
    background: 'rgba(255,255,255,0.02)',
  },
  countValue: {
    fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 700,
    color: 'var(--color-fg)', marginBottom: 4,
  },
  countLabel: {
    fontFamily: 'var(--font-mono)', fontSize: 10,
    color: 'var(--color-muted)', letterSpacing: '0.06em',
  },
}