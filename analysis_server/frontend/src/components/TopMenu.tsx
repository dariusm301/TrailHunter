import React from 'react'

interface TopMenuProps {
  viewMode: 'graph' | 'alerts'
  onViewChange: (mode: 'graph' | 'alerts') => void
  disableGraph?: boolean
}

export default function TopMenu({ viewMode, onViewChange, disableGraph }: TopMenuProps) {
  return (
    <div style={S.container}>
      <div style={S.tabs}>
        <button
          style={{
            ...S.tabBtn,
            ...(viewMode === 'graph' ? S.activeTab : {}),
            ...(disableGraph ? S.disabledTab : {}),
          }}
          onClick={() => !disableGraph && onViewChange('graph')}
          disabled={disableGraph}
          title={disableGraph ? 'Not enough edges to generate a graph (< 3)' : ''}
        >
          Graph View
        </button>
        <button
          style={{ ...S.tabBtn, ...(viewMode === 'alerts' ? S.activeTab : {}) }}
          onClick={() => onViewChange('alerts')}
        >
          Alerts View
        </button>
      </div>
      <div style={S.actions} />
    </div>
  )
}

const S: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '12px 20px',
    borderBottom: '1px solid var(--color-line)',
    background: 'var(--color-surface)',
    flexShrink: 0,
  },
  tabs: { display: 'flex', gap: 8 },
  tabBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    padding: '6px 14px',
    borderRadius: 6,
    border: '1px solid var(--color-line)',
    background: 'transparent',
    color: 'var(--color-muted)',
    cursor: 'pointer',
    fontSize: 13,
    fontWeight: 500,
    transition: 'all 0.2s',
  },
  activeTab: {
    background: '#00224d',
    color: 'var(--color-fg)',
    borderColor: 'var(--color-accent)',
  },
  disabledTab: { opacity: 0.4, cursor: 'not-allowed' },
  actions: { display: 'flex', gap: 8 },
}