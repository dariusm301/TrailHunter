import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { listProbeTokens, createProbeToken, revokeProbeToken, deleteProbeToken, type ProbeToken } from '@/api/probeTokens'
import logo from '@/assets/logo.svg'
import AccountMenu from '@/components/AccountMenu'

type TokenType = 'hardware' | 'software'

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function tokenStatus(t: ProbeToken): { label: string; variant: 'active' | 'revoked' | 'used' | 'expired' } {
  if (t.revoked) return { label: 'revoked', variant: 'revoked' }
  if (t.single_use && t.last_used_at) return { label: 'used', variant: 'used' }
  if (t.expires_at && new Date(t.expires_at).getTime() < Date.now()) return { label: 'expired', variant: 'expired' }
  return { label: 'active', variant: 'active' }
}

export function ProbeTokensPage() {
  const [tokens, setTokens] = useState<ProbeToken[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [newToken, setNewToken] = useState<{ token: string; name: string; tokenType: TokenType; serverUrl: string } | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      setTokens(await listProbeTokens())
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  const handleRevoke = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this token? The probe will no longer be able to send data.')) return
    await revokeProbeToken(id)
    refresh()
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Permanently delete this token? This action cannot be undone.')) return
    await deleteProbeToken(id)
    refresh()
  }

  return (
    <div style={S.root}>
      <header style={S.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <Link to="/scans" style={S.back}>← Scans</Link>
          <img src={logo} alt="TrailHunter" style={{ height: 45 }} />
        </div>
        <AccountMenu />
      </header>
      <main style={S.main}>
        <div style={S.actionRow}>
          <h1 style={S.title}>Probe Tokens</h1>
          <button onClick={() => setShowCreateForm(true)} style={S.newBtn}>
            <span style={S.plusIcon}>+</span> New token
          </button>
        </div>
        {error && <div style={S.empty}>Error: {error}</div>}
        {loading && <div style={S.empty}>Loading...</div>}
        {!loading && tokens.length === 0 ? (
          <div style={S.empty}>You do not have any probe tokens yet.</div>
        ) : !loading && (
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Name</th>
                <th style={S.th}>Type</th>
                <th style={S.th}>Device</th>
                <th style={S.th}>Created</th>
                <th style={S.th}>Last used</th>
                <th style={S.th}>Expires</th>
                <th style={S.th}>Status</th>
                <th style={S.th} />
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => {
                const status = tokenStatus(t)
                return (
                  <tr key={t.id} style={S.tr}>
                    <td style={{ ...S.td, fontWeight: 600 }}>{t.name}</td>
                    <td style={S.td}>{t.token_type ?? 'hardware'}</td>
                    <td style={S.td}>{t.device_identifier ?? '—'}</td>
                    <td style={S.td}>{fmtDate(t.created_at)}</td>
                    <td style={{ ...S.td, color: 'var(--color-muted)' }}>
                      {t.last_used_at ? fmtDate(t.last_used_at) : 'Never'}
                    </td>
                    <td style={{ ...S.td, color: 'var(--color-muted)' }}>
                      {t.expires_at ? fmtDate(t.expires_at) : 'No expiration'}
                    </td>
                    <td style={S.td}>
                      <span style={{ ...S.statusBadge, ...S.statusVariants[status.variant] }}>
                        {status.label}
                      </span>
                    </td>
                    <td style={{ ...S.td, textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                        {!t.revoked && (
                          <button onClick={() => handleRevoke(t.id)} style={S.revokeBtn}>
                            Revoke
                          </button>
                        )}
                        <button onClick={() => handleDelete(t.id)} style={S.deleteBtn}>
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </main>
      {showCreateForm && (
        <CreateTokenModal
          onClose={() => setShowCreateForm(false)}
          onCreated={(token, name, tokenType, serverUrl) => {
            setShowCreateForm(false)
            setNewToken({ token, name, tokenType, serverUrl })
            refresh()
          }}
        />
      )}
      {newToken && (
        <RevealTokenModal
          token={newToken.token}
          name={newToken.name}
          tokenType={newToken.tokenType}
          serverUrl={newToken.serverUrl}
          onClose={() => setNewToken(null)}
        />
      )}
    </div>
  )
}

function CreateTokenModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (token: string, name: string, tokenType: TokenType, serverUrl: string) => void
}) {
  const [tokenType, setTokenType] = useState<TokenType>('hardware')
  const [name, setName] = useState('')
  const [deviceIdentifier, setDeviceIdentifier] = useState('')
  const [expiresInDays, setExpiresInDays] = useState('30')
  const [expiresInMinutes, setExpiresInMinutes] = useState('15')
  const [serverUrl, setServerUrl] = useState(window.location.origin)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async () => {
    if (!name.trim()) {
      setError('Name is required')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const res = await createProbeToken(
        tokenType === 'hardware'
          ? {
              name: name.trim(),
              token_type: 'hardware',
              device_identifier: deviceIdentifier.trim() || undefined,
              expires_in_days: expiresInDays === 'never' ? null : Number(expiresInDays),
            }
          : {
              name: name.trim(),
              token_type: 'software',
              single_use: true,
              expires_in_minutes: Number(expiresInMinutes),
            }
      )
      onCreated(res.token, res.name, tokenType, serverUrl)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div style={S.modalOverlay}>
      <div style={S.modalContent}>
        <h2 style={S.modalTitle}>New probe token</h2>
        <label style={S.label}>Type</label>
        <div style={S.typeToggle}>
          <button
            type="button"
            onClick={() => setTokenType('hardware')}
            style={{ ...S.typeBtn, ...(tokenType === 'hardware' ? S.typeBtnActive : {}) }}
          >
            Hardware (RPi)
          </button>
          <button
            type="button"
            onClick={() => setTokenType('software')}
            style={{ ...S.typeBtn, ...(tokenType === 'software' ? S.typeBtnActive : {}) }}
          >
            Software (network)
          </button>
        </div>
        <label style={S.label}>Name</label>
        <input
          style={S.input}
          placeholder='ex: "My Probe"'
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        {tokenType === 'hardware' ? (
          <>
            <label style={S.label}>Device identifier (optional)</label>
            <input
              style={S.input}
              placeholder="serial number / MAC"
              value={deviceIdentifier}
              onChange={(e) => setDeviceIdentifier(e.target.value)}
            />
            <label style={S.label}>Expiration</label>
            <select
              style={{ ...S.input, marginBottom: 20 }}
              value={expiresInDays}
              onChange={(e) => setExpiresInDays(e.target.value)}
            >
              <option value="30">30 days</option>
              <option value="90">90 days</option>
              <option value="365">1 year</option>
              <option value="never">No expiration</option>
            </select>
          </>
        ) : (
          <>
            <label style={S.label}>Analysis server URL</label>
            <input
              style={S.input}
              placeholder="http://172.28.112.1:8000"
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
            />
            <label style={S.label}>Valid for</label>
            <select
              style={{ ...S.input, marginBottom: 6 }}
              value={expiresInMinutes}
              onChange={(e) => setExpiresInMinutes(e.target.value)}
            >
              <option value="5">5 minutes</option>
              <option value="15">15 minutes</option>
              <option value="30">30 minutes</option>
              <option value="60">1 hour</option>
            </select>
            <p style={S.hint}>Single-use — invalidated after the first successful collection, or when it expires.</p>
          </>
        )}
        {error && <p style={S.modalError}>{error}</p>}
        <div style={S.modalActions}>
          <button onClick={onClose} style={S.modalCancelBtn} disabled={submitting}>
            Cancel
          </button>
          <button onClick={handleSubmit} style={S.modalConfirmBtn} disabled={submitting}>
            {submitting ? 'Creating...' : 'Create token'}
          </button>
        </div>
      </div>
    </div>
  )
}

function RevealTokenModal({
  token,
  name,
  tokenType,
  serverUrl,
  onClose,
}: {
  token: string
  name: string
  tokenType: TokenType
  serverUrl: string
  onClose: () => void
}) {
  const [copiedToken, setCopiedToken] = useState(false)
  const [copiedCommand, setCopiedCommand] = useState(false)

  const command = `& ([scriptblock]::Create((Invoke-RestMethod -Uri "${serverUrl}/windows/collector.ps1" -Headers @{"X-Probe-Token"="${token}"}))) -ServerUrl "${serverUrl}" -TimeRangeHours 48 -Token "${token}"`

  const handleCopyToken = async () => {
    await navigator.clipboard.writeText(token)
    setCopiedToken(true)
    setTimeout(() => setCopiedToken(false), 2000)
  }

  const handleCopyCommand = async () => {
    await navigator.clipboard.writeText(command)
    setCopiedCommand(true)
    setTimeout(() => setCopiedCommand(false), 2000)
  }

  return (
    <div style={S.modalOverlay}>
      <div style={{ ...S.modalContent, maxWidth: 560 }}>
        <h2 style={S.modalTitle}>Token created: {name}</h2>
        <p style={S.warningText}>
          This is the only time you will see the full token.
          {tokenType === 'hardware'
            ? ' Copy it now and enter it into the probe configuration.'
            : ' Copy the command and run it through the WinRM/SSH session on the target.'}
        </p>
        {tokenType === 'software' && (
          <>
            <label style={S.label}>Collection command</label>
            <div style={{ ...S.tokenBox, marginBottom: 10 }}>{command}</div>
            <button onClick={handleCopyCommand} style={{ ...S.modalCancelBtn, marginBottom: 16, width: '100%' }}>
              {copiedCommand ? 'Copied!' : 'Copy command'}
            </button>
          </>
        )}
        <label style={S.label}>Raw token</label>
        <div style={S.tokenBox}>{token}</div>
        <div style={S.modalActions}>
          <button onClick={handleCopyToken} style={S.modalCancelBtn}>
            {copiedToken ? 'Copied!' : 'Copy token'}
          </button>
          <button onClick={onClose} style={S.modalConfirmBtn}>
            I have saved the token
          </button>
        </div>
      </div>
    </div>
  )
}

const S: Record<string, any> = {
  root: { minHeight: '100vh', display: 'flex', flexDirection: 'column', color: 'var(--color-fg)' },
  header: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    height: 56, padding: '0 20px', borderBottom: '1px solid var(--color-line)', flexShrink: 0,
  },
  back: { color: 'var(--color-muted)', textDecoration: 'none', fontSize: 13 },
  main: { padding: '28px 24px', maxWidth: 1000, width: '100%', margin: '0 auto' },
  title: { fontSize: 22, fontWeight: 700 },
  actionRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 },
  newBtn: {
    background: '#004494', color: '#fff', border: '1px solid #005ce6', borderRadius: 6,
    padding: '8px 16px', fontSize: 13, fontWeight: 600, cursor: 'pointer',
    display: 'flex', alignItems: 'center', gap: 6,
  },
  plusIcon: { fontSize: 16, fontWeight: 'bold', lineHeight: '12px' },
  empty: { color: 'var(--color-muted)', padding: '40px 0', textAlign: 'center' },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 13 },
  th: {
    textAlign: 'left', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
    letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--color-muted)',
    padding: '0 12px 10px', borderBottom: '1px solid var(--color-line)',
  },
  tr: { borderBottom: '1px solid var(--color-line)' },
  td: { padding: '12px', color: 'var(--color-fg)' },
  statusBadge: {
    fontFamily: 'var(--font-mono)', fontSize: 11, padding: '2px 8px',
    border: '1px solid', borderRadius: 6, textTransform: 'uppercase',
  },
  statusVariants: {
    active: { color: '#22c55e', borderColor: '#22c55e' },
    revoked: { color: '#ef4444', borderColor: '#ef4444' },
    used: { color: '#64748b', borderColor: '#64748b' },
    expired: { color: '#f59e0b', borderColor: '#f59e0b' },
  },
  revokeBtn: {
    background: 'transparent', border: 'none', color: '#f87171',
    cursor: 'pointer', fontSize: 12, textDecoration: 'underline', padding: 0,
    opacity: 0.7,
  },
  deleteBtn: {
    background: 'transparent', border: 'none', color: '#ef4444',
    cursor: 'pointer', fontSize: 12, textDecoration: 'underline', padding: 0,
  },
  modalOverlay: {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(3px)',
    zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center',
  },
  modalContent: {
    background: 'var(--color-surface, #0f172a)', border: '1px solid var(--color-line)',
    padding: 24, borderRadius: 12, width: '100%', maxWidth: 400,
    boxShadow: '0 10px 25px -5px rgba(0,0,0,0.5)',
  },
  modalTitle: { margin: '0 0 16px', fontSize: 16, fontWeight: 600, color: 'var(--color-fg)' },
  label: { display: 'block', fontSize: 12, color: 'var(--color-muted)', marginBottom: 6 },
  input: {
    width: '100%', background: '#1e293b', border: '1px solid var(--color-line, #33415c)',
    borderRadius: 6, padding: '8px 10px', color: 'var(--color-fg)', fontSize: 13,
    outline: 'none', marginBottom: 14, boxSizing: 'border-box',
  },
  hint: { fontSize: 11, color: 'var(--color-muted)', margin: '0 0 16px' },
  modalError: { color: '#ef4444', fontSize: 12, marginBottom: 12 },
  modalActions: { display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 4 },
  modalCancelBtn: {
    background: 'transparent', border: '1px solid var(--color-line)',
    color: 'var(--color-fg)', padding: '8px 16px', borderRadius: 6, fontSize: 13, cursor: 'pointer',
  },
  modalConfirmBtn: {
    background: '#004494', border: '1px solid #005ce6', color: '#fff',
    padding: '8px 16px', borderRadius: 6, fontSize: 13, fontWeight: 600, cursor: 'pointer',
  },
  warningText: { fontSize: 13, color: '#f59e0b', lineHeight: 1.5, margin: '0 0 16px' },
  tokenBox: {
    background: '#1e293b', border: '1px solid var(--color-line)', borderRadius: 6,
    padding: 12, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-fg)',
    wordBreak: 'break-all',
  },
  typeToggle: { display: 'flex', gap: 8, marginBottom: 16 },
  typeBtn: {
    flex: 1, padding: '8px 10px', borderRadius: 6, border: '1px solid var(--color-line)',
    background: 'transparent', color: 'var(--color-muted)', fontSize: 12, cursor: 'pointer',
  },
  typeBtnActive: { background: '#004494', color: '#fff', borderColor: '#005ce6' },
}