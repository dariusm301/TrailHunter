import React from 'react'

type ProcessingAction = 'detect' | 'correlate' | 'delete' | null

interface CollectionActionBarProps {
  onRunDetection: () => void
  onCorrelate: () => void
  onDeleteClick: () => void
  onAllAlerts: () => void
  allAlertsCount?: number
  allAlertsHasFindings?: boolean
  processingAction: ProcessingAction
  isLoading: boolean
}

export default function CollectionActionBar({
  onRunDetection,
  onCorrelate,
  onDeleteClick,
  onAllAlerts,
  allAlertsCount,
  allAlertsHasFindings,
  processingAction,
  isLoading,
}: CollectionActionBarProps) {
  return (
    <div style={S.actionBar}>
      <button
        onClick={onRunDetection}
        disabled={processingAction !== null}
        style={{ ...S.actionBtn, ...(processingAction === 'detect' ? S.actionBtnLoading : {}) }}
      >
        {processingAction === 'detect' ? 'Detecting...' : 'Run Detection'}
      </button>

      <button
        onClick={onCorrelate}
        disabled={processingAction !== null || isLoading}
        style={{ ...S.actionBtn, ...(processingAction === 'correlate' || isLoading ? S.actionBtnLoading : {}) }}
      >
        {processingAction === 'correlate' || isLoading ? 'Working...' : 'Correlate'}
      </button>

      <div style={S.actionDivider} />

      <button
        onClick={onAllAlerts}
        style={S.actionBtn}
      >
        All Alerts
        {allAlertsCount != null && allAlertsCount > 0 && (
          <span style={{
            ...S.badge,
            background: allAlertsHasFindings ? 'rgba(245,158,11,0.2)' : 'rgba(255,255,255,0.08)',
            borderColor: allAlertsHasFindings ? 'rgba(245,158,11,0.5)' : 'var(--color-line)',
            color: allAlertsHasFindings ? '#f59e0b' : 'var(--color-muted)',
          }}>
            {allAlertsCount}
          </span>
        )}
      </button>

      <div style={S.actionDivider} />

      <button
        onClick={onDeleteClick}
        disabled={processingAction !== null}
        style={{ ...S.actionBtn, color: '#ef4444' }}
      >
        Delete
      </button>
    </div>
  )
}

const S: Record<string, React.CSSProperties> = {
  actionBar: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    background: 'rgba(255, 255, 255, 0.03)',
    padding: '4px 6px',
    borderRadius: 8,
    border: '1px solid var(--color-line, #33415c)',
  },
  actionBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    background: 'transparent',
    border: 'none',
    color: 'var(--color-fg, #fff)',
    fontSize: 12,
    fontWeight: 500,
    padding: '6px 12px',
    borderRadius: 6,
    cursor: 'pointer',
    transition: 'background 0.15s',
  },
  actionBtnLoading: {
    opacity: 0.5,
    cursor: 'not-allowed',
  },
  actionIcon: {
    fontSize: 14,
  },
  actionDivider: {
    width: 1,
    height: 16,
    background: 'var(--color-line, #33415c)',
    margin: '0 4px',
  },
  badge: {
    fontFamily: 'ui-monospace, SFMono-Regular, monospace',
    fontSize: 10,
    fontWeight: 700,
    padding: '1px 5px',
    borderRadius: 10,
    border: '1px solid',
    lineHeight: 1.4,
  },
}