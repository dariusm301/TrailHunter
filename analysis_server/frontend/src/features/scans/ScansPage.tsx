import React, { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/auth/useAuth'
import type { ScanSummary } from '@/types/scan'
import { useAsync } from '@/lib/useAsync'
import { fetchScans } from '@/api/collections'
import logo from '@/assets/logo.svg'
import AccountMenu from '@/components/AccountMenu'

const SEV_ORDER = ['low', 'medium', 'high', 'critical']

const SEV_COLOR: Record<string, string> = {
  low: '#5c677d',
  medium: '#e0b94e',
  high: '#e8853c',
  critical: '#db4444',
}

function fmtDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export default function ScansPage() {
  
  const navigate = useNavigate()

  const { data, loading, error } = useAsync(() => fetchScans(), [])
  
  const [expandedHosts, setExpandedHosts] = useState<Record<string, boolean>>({})
  
  const [searchInputValue, setSearchInputValue] = useState('')
  const [searchQuery, setSearchQuery] = useState('')

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setSearchQuery(searchInputValue)
  }

  const handleCreateNewScan = () => {
    navigate('/scans/new')
  }

  const groupedScans = useMemo(() => {
    const rawScans = data ?? []
    const groups: Record<string, ScanSummary[]> = {}

    for (const s of rawScans) {
      if (!groups[s.host]) {
        groups[s.host] = []
      }
      groups[s.host].push(s)
    }

    return Object.entries(groups)
      .filter(([host]) => host.toLowerCase().includes(searchQuery.toLowerCase()))
      .map(([host, hostScans]) => {
        const history = [...hostScans].sort((a, b) => b.collected_at.localeCompare(a.collected_at))
        const latestScan = history[0]

        // const severities = history.map((s) => s.max_severity).filter(Boolean) as string[]
        // const maxSeverity = severities.length > 0 
        //   ? severities.reduce((max, curr) => (SEV_ORDER.indexOf(curr) > SEV_ORDER.indexOf(max) ? curr : max), 'low')
        //   : null

        const findingsList = history.map(s => s.finding_count).filter((c): c is number => c !== null && c !== undefined)
        const maxFindings = findingsList.length > 0 ? Math.max(...findingsList) : null

        // const actorsList = history.map(s => s.actor_count).filter((c): c is number => c !== null && c !== undefined)
        // const maxActors = actorsList.length > 0 ? Math.max(...actorsList) : null

        return {
          host,
          latestScan,
          history,
        //  maxSeverity,
          maxFindings,
          // maxActors,
          totalScans: history.length
        }
      }).sort((a, b) => b.latestScan.collected_at.localeCompare(a.latestScan.collected_at))
  }, [data, searchQuery])

  const toggleHost = (host: string) => {
    setExpandedHosts((prev) => ({
      ...prev,
      [host]: !prev[host],
    }))
  }

  return (
    <div style={S.root}>
      <header style={S.header}>
        <img src={logo} alt="TrailHunter" style={{ height: 45 }} />
        <AccountMenu/>
      </header>

      <main style={S.main}>
        <h1 style={S.title}>Scans</h1>

        <div style={S.actionRow}>
          <form onSubmit={handleSearch} style={S.searchForm}>
            <div style={S.searchContainer}>
              <input
                type="text"
                placeholder="Search by host name..."
                value={searchInputValue}
                onChange={(e) => setSearchInputValue(e.target.value)}
                style={S.searchInput}
              />
              <button type="submit" style={S.searchBtn}>
                Search
              </button>
              {searchQuery && (
                <button 
                  type="button" 
                  onClick={() => { setSearchInputValue(''); setSearchQuery(''); }} 
                  style={S.clearBtn}
                >
                  Clear
                </button>
              )}
            </div>
          </form>

          <button onClick={handleCreateNewScan} style={S.newScanBtn}>
            <span style={S.plusIcon}>+</span> New Scan
          </button>
        </div>

        {error && <div style={S.empty}>Error: {error}</div>}
        {loading && <div style={S.empty}>Loading...</div>}
        
        {!loading && groupedScans.length === 0 ? (
          <div style={S.empty}>
            {searchQuery ? 'No hosts match your search criteria.' : 'No collections yet. Run a probe to ingest one.'}
          </div>
        ) : (
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Host / Scan History</th>
                <th style={S.th}>Collected</th>
                <th style={{ ...S.th, ...S.num }}>Events</th>
                <th style={{ ...S.th, ...S.num }}>Findings</th>
                <th style={S.th}>Probe</th>
              </tr>
            </thead>
            <tbody>
              {groupedScans.map((g) => {
                const isExpanded = !!expandedHosts[g.host]
                return (
                  <React.Fragment key={g.host}>
                    <tr
                      style={{ ...S.tr, ...S.trHostHeader }}
                      onClick={() => toggleHost(g.host)}
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') toggleHost(g.host)
                      }}
                    >
                      <td style={S.tdHost}>
                        <div style={S.hostTitleContainer}>
                          <span style={S.chevron}>{isExpanded ? '▾' : '▸'}</span>
                          <span style={S.hostName}>{g.host}</span>
                          <span style={S.historyBadge}>
                            {g.totalScans} {g.totalScans === 1 ? 'scan' : 'scans'}
                          </span>
                        </div>
                      </td>
                      <td style={S.td}>
                        <span style={S.latestLabel}>Latest:</span> {fmtDate(g.latestScan.collected_at)}
                      </td>
                      <td style={{ ...S.td, ...S.num }}>{g.latestScan.event_count.toLocaleString()}</td>
                      
                      <td style={{ ...S.td, ...S.num, fontWeight: 600 }}>
                        {g.maxFindings !== null ? g.maxFindings.toLocaleString() : '—'}
                      </td>
                      
                      <td style={S.td}>{g.latestScan.has_collector ? 'yes' : '—'}</td>
                    </tr>

                    {isExpanded && g.history.map((s) => (
                      <tr
                        key={s.id}
                        style={{ ...S.tr, ...S.trSubRow }}
                        onClick={(e) => {
                          e.stopPropagation()
                          navigate(`/scans/${encodeURIComponent(s.id)}`)
                        }}
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.stopPropagation()
                            navigate(`/scans/${encodeURIComponent(s.id)}`)
                          }
                        }}
                      >
                        <td style={{ ...S.td, paddingLeft: 36 }}>
                          <div style={S.subRowIdContainer}>
                            <span style={S.subRowIdLabel}>ID:</span>
                            <span style={S.idInline}>{s.id}</span>
                          </div>
                        </td>
                        <td style={S.td}>{fmtDate(s.collected_at)}</td>
                        <td style={{ ...S.td, ...S.num, color: 'var(--color-muted)' }}>{s.event_count.toLocaleString()}</td>
                        <td style={{ ...S.td, ...S.num, color: 'var(--color-muted)' }}>{s.finding_count ?? '—'}</td>
                        <td style={S.td}>{s.has_collector ? 'yes' : '—'}</td>
                      </tr>
                    ))}
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>
        )}
      </main>
    </div>
  )
}

const S: Record<string, React.CSSProperties> = {
  root: { minHeight: '100vh', display: 'flex', flexDirection: 'column', color: 'var(--color-fg)' },
  header: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    height: 56, padding: '0 20px', borderBottom: '1px solid var(--color-line)', flexShrink: 0,
  },
  wordmark: { fontWeight: 800, letterSpacing: '-0.01em', fontSize: 18 },
  signout: { background: 'transparent', border: 'none', color: 'var(--color-muted)', cursor: 'pointer', fontSize: 13 },
  main: { padding: '28px 24px', maxWidth: 1000, width: '100%', margin: '0 auto' },
  title: { fontSize: 22, fontWeight: 700, marginBottom: 20 },
  actionRow: { 
    display: 'flex', 
    justifyContent: 'space-between', 
    alignItems: 'center', 
    marginBottom: 24,
    gap: 16 
  },
  searchForm: { flex: 1, maxWidth: 450 },
  searchContainer: { display: 'flex', gap: 8, width: '100%' },
  searchInput: {
    flex: 1,
    background: 'var(--color-surface, #0f172a)',
    border: '1px solid var(--color-line, #33415c)',
    borderRadius: 6,
    padding: '8px 12px',
    color: 'var(--color-fg, #fff)',
    fontSize: 13,
    outline: 'none',
  },
  searchBtn: {
    background: '#1e293b',
    color: 'var(--color-fg, #fff)',
    border: '1px solid var(--color-line, #33415c)',
    borderRadius: 6,
    padding: '8px 16px',
    fontSize: 13,
    fontWeight: 500,
    cursor: 'pointer',
  },
  clearBtn: {
    background: 'transparent',
    color: 'var(--color-muted, #94a3b8)',
    border: 'none',
    fontSize: 13,
    cursor: 'pointer',
    padding: '0 4px',
  },
  newScanBtn: {
    background: '#004494',
    color: '#fff',
    border: '1px solid #005ce6',
    borderRadius: 6,
    padding: '8px 16px',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    transition: 'background 0.2s',
    flexShrink: 0,
  },
  plusIcon: { fontSize: 16, fontWeight: 'bold', lineHeight: '12px' },
  empty: { color: 'var(--color-muted)', padding: '40px 0', textAlign: 'center' },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 13 },
  th: {
    textAlign: 'left', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
    letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--color-muted)',
    padding: '0 12px 10px', borderBottom: '1px solid var(--color-line)',
  },
  num: { textAlign: 'right' },
  tr: { cursor: 'pointer', borderBottom: '1px solid var(--color-line)' },
  trHostHeader: { background: 'rgba(255, 255, 255, 0.01)' },
  trSubRow: {
    background: 'rgba(0, 0, 0, 0.18)',
    borderLeft: '3px solid var(--color-accent, #00224d)',
  },
  td: { padding: '12px', color: 'var(--color-fg)' },
  tdHost: { padding: '12px' },
  hostTitleContainer: { display: 'flex', alignItems: 'center', gap: 10 },
  hostName: { fontWeight: 600 },
  chevron: { color: 'var(--color-muted)', width: 12, display: 'inline-block', fontFamily: 'var(--font-mono)' },
  historyBadge: {
    fontSize: 11,
    background: '#1e293b',
    color: '#94a3b8',
    padding: '2px 7px',
    borderRadius: 6,
    fontWeight: 500,
  },
  latestLabel: { color: 'var(--color-muted)', fontSize: 11, marginRight: 4 },
  subRowIdContainer: { display: 'flex', gap: 6, alignItems: 'center' },
  subRowIdLabel: { color: 'var(--color-muted)', fontSize: 11 },
  idInline: { fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-fg)' },
  badge: {
    fontFamily: 'var(--font-mono)', fontSize: 11, padding: '2px 8px',
    border: '1px solid', borderRadius: 6, textTransform: 'uppercase',
  },
  dash: { color: 'var(--color-muted)' },
}