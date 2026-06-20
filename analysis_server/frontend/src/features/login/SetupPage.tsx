import { useState } from 'react'
import type { FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/auth/useAuth'
import { FingerprintBackdrop } from '@/components/AuthBackdrop'
import logo from '@/assets/logo.svg'

export default function SetupPage() {
  const { register } = useAuth()
  const navigate = useNavigate()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)

    if (password !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters.')
      return
    }

    setBusy(true)
    try {
      await register({ username: username.trim(), password })
      navigate('/login', { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong.')
      setBusy(false)
    }
  }

  return (
    <div className="auth-screen">
      <FingerprintBackdrop />
      <div className="login-card">
        <img src={logo} alt="TrailHunter" style={{ height: 50, marginLeft: -20 }} />
        <p className="eyebrow">Initial Setup</p>
        <form onSubmit={handleSubmit} noValidate>
          <div className="field">
            <label htmlFor="username" className="field-label">
              Administrator username
            </label>
            <input
              id="username"
              className="field-input"
              type="text"
              autoComplete="username"
              autoFocus
              spellCheck={false}
              placeholder="analyst"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="password" className="field-label">
              Password
            </label>
            <input
              id="password"
              className="field-input"
              type="password"
              autoComplete="new-password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="confirm-password" className="field-label">
              Confirm password
            </label>
            <input
              id="confirm-password"
              className="field-input"
              type="password"
              autoComplete="new-password"
              placeholder="••••••••"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>
          {error && (
            <p role="alert" className="login-error">
              {error}
            </p>
          )}
          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? 'Creating account…' : 'Create administrator account'}
          </button>
        </form>
      </div>
    </div>
  )
}