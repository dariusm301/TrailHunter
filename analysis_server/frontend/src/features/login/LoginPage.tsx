import { useState } from 'react'
import type { FormEvent } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/auth/useAuth'
import logo from '@/assets/logo.svg'

const RIDGE_COUNT = 13
const PRINT_CX = 300
const PRINT_CY = 430
const ACCENT_RIDGE = 6

function ridgePath(i: number): string {
  const rx = 34 + i * 24
  const ry = 44 + i * 27
  const tail = 24 + i * 4
  const left = PRINT_CX - rx
  const right = PRINT_CX + rx
  return `M ${left} ${PRINT_CY + tail} L ${left} ${PRINT_CY} A ${rx} ${ry} 0 0 1 ${right} ${PRINT_CY} L ${right} ${PRINT_CY + tail}`
}

function FingerprintBackdrop() {
  const ridges = Array.from({ length: RIDGE_COUNT }, (_, i) => i)
  return (
    <svg
      className="auth-backdrop"
      viewBox="0 0 900 800"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
    >
      <defs>
        <radialGradient id="th-fade" cx="36%" cy="54%" r="72%">
          <stop offset="0%" stopColor="#001233" stopOpacity="0" />
          <stop offset="100%" stopColor="#001233" stopOpacity="0.94" />
        </radialGradient>
      </defs>

      <g fill="none" strokeLinecap="round">
        {ridges.map((i) =>
          i === ACCENT_RIDGE ? (
            <path
              key={i}
              id="th-trail"
              d={ridgePath(i)}
              stroke="#0466c8"
              strokeWidth={1.6}
              strokeOpacity={0.55}
            />
          ) : (
            <path
              key={i}
              d={ridgePath(i)}
              stroke="#33415c"
              strokeWidth={1.4}
              strokeOpacity={0.3}
            />
          ),
        )}
      </g>

      <circle r={3.5} fill="#5b9bd5">
        <animateMotion dur="6.5s" repeatCount="indefinite" rotate="auto">
          <mpath href="#th-trail" />
        </animateMotion>
        <animate
          attributeName="opacity"
          values="0;1;1;0"
          keyTimes="0;0.12;0.88;1"
          dur="6.5s"
          repeatCount="indefinite"
        />
      </circle>

      <rect x="0" y="0" width="900" height="800" fill="url(#th-fade)" />
    </svg>
  )
}

interface FromState {
  from?: { pathname?: string }
}

export default function LoginPage() {
  const { signIn } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as FromState | null)?.from?.pathname ?? '/console'

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await signIn({ username: username.trim(), password })
      navigate(from, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong.')
      setBusy(false)
    }
  }

  return (
    <div className="auth-screen">
      <FingerprintBackdrop />

      <div className="login-card">
        <img src={logo} alt="TrailHunter" style={{ height: 50, marginLeft: -20}} />
        <p className="eyebrow">Forensic Console</p>

        <form onSubmit={handleSubmit} noValidate>
          <div className="field">
            <label htmlFor="username" className="field-label">
              Username
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
              autoComplete="current-password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {error && (
            <p role="alert" className="login-error">
              {error}
            </p>
          )}

          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

      </div>
    </div>
  )
}