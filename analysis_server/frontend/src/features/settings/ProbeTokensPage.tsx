import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { listProbeTokens, createProbeToken, revokeProbeToken, type ProbeToken } from '@/api/probeTokens'
import logo from '@/assets/logo.svg'
import AccountMenu from '@/components/AccountMenu'

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export function ProbeTokensPage() {
  const [tokens, setTokens] = useState<ProbeToken[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [newToken, setNewToken] = useState<{ token: string; name: string } | null>(null)

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
                <th style={S.th}>Device</th>
                <th style={S.th}>Created</th>
                <th style={S.th}>Last used</th>
                <th style={S.th}>Expires</th>
                <th style={S.th}>Status</th>
                <th style={S.th} />
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id} style={S.tr}>
                  <td style={{ ...S.td, fontWeight: 600 }}>{t.name}</td>
                  <td style={S.td}>{t.device_identifier ?? '—'}</td>
                  <td style={S.td}>{fmtDate(t.created_at)}</td>
                  <td style={{ ...S.td, color: 'var(--color-muted)' }}>
                    {t.last_used_at ? fmtDate(t.last_used_at) : 'Never'}
                  </td>
                  <td style={{ ...S.td, color: 'var(--color-muted)' }}>
                    {t.expires_at ? fmtDate(t.expires_at) : 'No expiration'}
                  </td>
                  <td style={S.td}>
                    <span style={{ ...S.statusBadge, ...(t.revoked ? S.statusRevoked : S.statusActive) }}>
                      {t.revoked ? 'revoked' : 'active'}
                    </span>
                  </td>
                  <td style={{ ...S.td, textAlign: 'right' }}>
                    {!t.revoked && (
                      <button onClick={() => handleRevoke(t.id)} style={S.revokeBtn}>
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </main>

      {showCreateForm && (
        <CreateTokenModal
          onClose={() => setShowCreateForm(false)}
          onCreated={(token, name) => {
            setShowCreateForm(false)
            setNewToken({ token, name })
            refresh()
          }}
        />
      )}

      {newToken && (
        <RevealTokenModal token={newToken.token} name={newToken.name} onClose={() => setNewToken(null)} />
      )}
    </div>
  )
}

function CreateTokenModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (token: string, name: string) => void
}) {
  const [name, setName] = useState('')
  const [deviceIdentifier, setDeviceIdentifier] = useState('')
  const [expiresInDays, setExpiresInDays] = useState('30')
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
      const res = await createProbeToken({
        name: name.trim(),
        device_identifier: deviceIdentifier.trim() || undefined,
        expires_in_days: expiresInDays === 'never' ? null : Number(expiresInDays),
      })
      onCreated(res.token, res.name)
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

        <label style={S.label}>Name</label>
        <input
          style={S.input}
          placeholder='ex: "My Probe"'
          value={name}
          onChange={(e) => setName(e.target.value)}
        />

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

function RevealTokenModal({ token, name, onClose }: { token: string; name: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(token)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div style={S.modalOverlay}>
      <div style={{ ...S.modalContent, maxWidth: 480 }}>
        <h2 style={S.modalTitle}>Token created: {name}</h2>
        <p style={S.warningText}>
          This is the only time you will see the full token. Copy it now and enter it into the probe configuration.
        </p>
        <div style={S.tokenBox}>{token}</div>
        <div style={S.modalActions}>
          <button onClick={handleCopy} style={S.modalCancelBtn}>
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <button onClick={onClose} style={S.modalConfirmBtn}>
            I have saved the token
          </button>
        </div>
      </div>
    </div>
  )
}

const S: Record<string, React.CSSProperties> = {
  root: { minHeight: '100vh', display: 'flex', flexDirection: 'column', color: 'var(--color-fg)' },
  header: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    height: 56, padding: '0 20px', borderBottom: '1px solid var(--color-line)', flexShrink: 0,
  },
  back: { color: 'var(--color-muted)', textDecoration: 'none', fontSize: 13 },
  signout: { background: 'transparent', border: 'none', color: 'var(--color-muted)', cursor: 'pointer', fontSize: 13 },
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
  statusActive: { color: '#22c55e', borderColor: '#22c55e' },
  statusRevoked: { color: '#ef4444', borderColor: '#ef4444' },
  revokeBtn: {
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
    wordBreak: 'break-all', marginBottom: 16,
  },
}