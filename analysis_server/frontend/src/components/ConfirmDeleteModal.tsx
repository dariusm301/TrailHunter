// components/ConfirmDeleteModal.tsx
import React from 'react'

interface ConfirmDeleteModalProps {
  title: string
  message: React.ReactNode
  isProcessing: boolean
  onConfirm: () => void
  onCancel: () => void
}

export function ConfirmDeleteModal({ title, message, isProcessing, onConfirm, onCancel }: ConfirmDeleteModalProps) {
  return (
    <div style={S.modalOverlay}>
      <div style={S.modalContent}>
        <h2 style={S.modalTitle}>{title}</h2>
        <p style={S.modalText}>{message}</p>
        <div style={S.modalActions}>
          <button onClick={onCancel} style={S.modalCancelBtn} disabled={isProcessing}>
            Cancel
          </button>
          <button onClick={onConfirm} style={S.modalDeleteBtn} disabled={isProcessing}>
            {isProcessing ? 'Deleting...' : 'Yes, delete'}
          </button>
        </div>
      </div>
    </div>
  )
}

const S: Record<string, React.CSSProperties> = {
  modalOverlay: {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(3px)',
    zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center',
  },
  modalContent: {
    background: 'var(--color-surface,#0f172a)', border: '1px solid var(--color-line)',
    padding: 24, borderRadius: 12, width: '100%', maxWidth: 400,
    boxShadow: '0 10px 25px -5px rgba(0,0,0,0.5)',
  },
  modalTitle: { margin: '0 0 12px', fontSize: 16, fontWeight: 600, color: '#fff' },
  modalText: { margin: '0 0 24px', fontSize: 13, color: 'var(--color-muted)', lineHeight: 1.5 },
  modalActions: { display: 'flex', justifyContent: 'flex-end', gap: 12 },
  modalCancelBtn: {
    background: 'transparent', border: '1px solid var(--color-line)',
    color: 'var(--color-fg)', padding: '8px 16px', borderRadius: 6, fontSize: 13, cursor: 'pointer',
  },
  modalDeleteBtn: {
    background: '#ef4444', border: '1px solid #dc2626', color: '#fff',
    padding: '8px 16px', borderRadius: 6, fontSize: 13, fontWeight: 600, cursor: 'pointer',
  },
}