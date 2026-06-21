import { useEffect, useState, useCallback } from 'react'
import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '@/auth/useAuth'
import { listUsers, createUser, toggleUserActive, type AppUser } from '@/api/users'
import AccountMenu from '@/components/AccountMenu'
import logo from '@/assets/logo.svg'

function fmtDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export function UsersPage() {
  const { user } = useAuth()
  const [users, setUsers] = useState<AppUser[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreateForm, setShowCreateForm] = useState(false)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      setUsers(await listUsers())
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  if (!user?.is_admin) {
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
          <div style={S.empty}>You do not have access to this page.</div>
        </main>
      </div>
    )
  }

  const handleToggleActive = async (id: string) => {
    if (!confirm('Are you sure you want to change the status of this account?')) return
    await toggleUserActive(id)
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
          <h1 style={S.title}>Users</h1>
          <button onClick={() => setShowCreateForm(true)} style={S.newBtn}>
            <span style={S.plusIcon}>+</span> New account
          </button>
        </div>

        {error && <div style={S.empty}>Error: {error}</div>}
        {loading && <div style={S.empty}>Loading...</div>}

        {!loading && (
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Username</th>
                <th style={S.th}>Role</th>
                <th style={S.th}>Created</th>
                <th style={S.th}>Status</th>
                <th style={S.th} />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} style={S.tr}>
                  <td style={{ ...S.td, fontWeight: 600 }}>
                    {u.username} {u.id === user?.id && <span style={S.youTag}>(you)</span>}
                  </td>
                  <td style={S.td}>
                    <span style={{ ...S.statusBadge, ...(u.is_admin ? S.adminBadge : S.userBadge) }}>
                      {u.is_admin ? 'admin' : 'investigator'}
                    </span>
                  </td>
                  <td style={{ ...S.td, color: 'var(--color-muted)' }}>{fmtDate(u.created_at)}</td>
                  <td style={S.td}>
                    <span style={{ ...S.statusBadge, ...(u.is_active ? S.statusActive : S.statusRevoked) }}>
                      {u.is_active ? 'active' : 'disabled'}
                    </span>
                  </td>
                  <td style={{ ...S.td, textAlign: 'right' }}>
                    {u.id !== user?.id && (
                      <button onClick={() => handleToggleActive(u.id)} style={S.revokeBtn}>
                        {u.is_active ? 'Disable' : 'Re-enable'}
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
        <CreateUserModal
          onClose={() => setShowCreateForm(false)}
          onCreated={() => { setShowCreateForm(false); refresh() }}
        />
      )}
    </div>
  )
}

function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [isAdmin, setIsAdmin] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async () => {
    if (!username.trim() || !password) {
      setError('Username and password are required')
      return
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      await createUser({ username: username.trim(), password, is_admin: isAdmin })
      onCreated()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div style={S.modalOverlay}>
      <div style={S.modalContent}>
        <h2 style={S.modalTitle}>New account</h2>

        <label style={S.label}>Username</label>
        <input style={S.input} value={username} onChange={(e) => setUsername(e.target.value)} />

        <label style={S.label}>Password</label>
        <input style={S.input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} />

        <label style={S.label}>Confirm password</label>
        <input style={S.input} type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />

        <label style={{ ...S.label, display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
          <input type="checkbox" checked={isAdmin} onChange={(e) => setIsAdmin(e.target.checked)} />
          Grant admin privileges
        </label>

        {error && <p style={S.modalError}>{error}</p>}

        <div style={S.modalActions}>
          <button onClick={onClose} style={S.modalCancelBtn} disabled={submitting}>
            Cancel
          </button>
          <button onClick={handleSubmit} style={S.modalConfirmBtn} disabled={submitting}>
            {submitting ? 'Creating...' : 'Create account'}
          </button>
        </div>
      </div>
    </div>
  )
}

const S: Record<string, CSSProperties> = {
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
  youTag: { color: 'var(--color-muted)', fontWeight: 400, fontSize: 12 },
  statusBadge: {
    fontFamily: 'var(--font-mono)', fontSize: 11, padding: '2px 8px',
    border: '1px solid', borderRadius: 6, textTransform: 'uppercase',
  },
  adminBadge: { color: '#3b82f6', borderColor: '#3b82f6' },
  userBadge: { color: 'var(--color-muted)', borderColor: 'var(--color-line)' },
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
}