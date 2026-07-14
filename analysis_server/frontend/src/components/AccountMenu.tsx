import { useEffect, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '@/auth/useAuth'

export default function AccountMenu() {
  const { user, signOut } = useAuth()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  return (
    <div style={S.wrap} ref={ref}>
      <button onClick={() => setOpen((o) => !o)} style={S.trigger}>
        {user?.username}
        <span style={S.caret}>{open ? '▾' : '▸'}</span>
      </button>
      
      {open && (
        <div style={S.menu}>
          {user?.is_admin && (
            <>
              <Link to="/settings/users" style={S.menuItem} onClick={() => setOpen(false)}>
                Users
              </Link>
              <div style={S.divider} />
            </>
          )}
          <Link to="/settings/probe-tokens" style={S.menuItem} onClick={() => setOpen(false)}>
            Probe Tokens
          </Link>
          <div style={S.divider} />
          <button onClick={signOut} style={{ ...S.menuItem, color: '#ef4444' }}>
            Sign out
          </button>
        </div>
      )}
    </div>
  )
}

const S: Record<string, CSSProperties> = {
  wrap: { position: 'relative' },
  trigger: {
    background: 'transparent', border: 'none', color: 'var(--color-muted)',
    cursor: 'pointer', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6,
  },
  caret: { fontSize: 10, fontFamily: 'var(--font-mono)' },
  menu: {
    position: 'absolute', top: 'calc(100% + 8px)', right: 0, minWidth: 160,
    background: 'var(--color-surface, #0f172a)', border: '1px solid var(--color-line)',
    borderRadius: 8, boxShadow: '0 10px 25px -5px rgba(0,0,0,0.5)', overflow: 'hidden', zIndex: 50,
  },
  menuItem: {
    display: 'block', width: '100%', textAlign: 'left', background: 'transparent',
    border: 'none', color: 'var(--color-fg)', fontSize: 13, padding: '10px 14px',
    cursor: 'pointer', textDecoration: 'none', boxSizing: 'border-box',
  },
  divider: { height: 1, background: 'var(--color-line)' },
}