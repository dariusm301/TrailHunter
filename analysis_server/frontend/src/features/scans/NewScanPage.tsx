import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '@/auth/useAuth'
import { ingestProbePackage } from '@/api/collections'

async function calculateFileHash(file: File): Promise<string> {
  const arrayBuffer = await file.arrayBuffer()
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer)
  
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  return hashHex
}

export default function NewScanPage() {
  const { user, signOut } = useAuth()
  const navigate = useNavigate()
  
  const [probePackage, setProbePackage] = useState<File | null>(null)
  const [summaryFile, setSummaryFile] = useState<File | null>(null)

  const [isSubmitting, setIsSubmitting] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!probePackage || !summaryFile) {
      alert('Please select both the binary file (.bin) and the metadata file (summary.json).')
      return
    }

    setIsSubmitting(true)

    try {
      const finalHash = await calculateFileHash(probePackage)
      
      const rawSummaryText = await summaryFile.text()
      const compactSummary = JSON.stringify(JSON.parse(rawSummaryText))

      await ingestProbePackage(probePackage, finalHash, compactSummary)

      setIsSubmitting(false)
      navigate('/scans')
    } catch (err) {
      console.error("Ingestion failed", err)
      setIsSubmitting(false)
      
      if (err instanceof Error) {
        alert(`Error uploading data: ${err.message}`)
      } else {
        alert("Unknown error occurred while communicating with the server.")
      }
    }
  }

  return (
    <div style={S.root}>
      <header style={S.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <Link to="/scans" style={S.back}>← Scans</Link>
          <span style={S.wordmark}>
            <span style={{ color: 'var(--color-trail)' }}>Trail</span>
            <span style={{ color: '#fff' }}>Hunter</span>
          </span>
        </div>
        <button onClick={signOut} style={S.signout}>
          {user?.username} · Sign out
        </button>
      </header>

      <main style={S.main}>
        <div style={S.formContainer}>
          <h1 style={S.title}>New Scan Collection</h1>
          <p style={S.subtitle}>Upload the probe payload and collection summary to create a new scan collection.</p>

          <form onSubmit={handleSubmit}>
           

            <div style={S.uploadSection}>
              <div style={S.packageGrid}>
                <div style={S.formGroup}>
                  <label style={S.label}>1. Probe Payload (.bin) *</label>
                  <div style={S.dropzone}>
                    <input
                      type="file"
                      accept=".bin"
                      onChange={(e) => setProbePackage(e.target.files?.[0] || null)}
                      style={S.fileInputHidden}
                      id="file-package"
                      disabled={isSubmitting}
                    />
                    <label htmlFor="file-package" style={{...S.fileLabel, ...(isSubmitting ? { cursor: 'not-allowed' } : {})}}>
                      {probePackage ? (
                        <span style={S.fileName}>{probePackage.name}</span>
                      ) : (
                        <>
                          <strong>Upload data payload</strong>
                          <span style={S.fileHint}>Binary data collected with the probe</span>
                        </>
                      )}
                    </label>
                  </div>
                </div>

                <div style={S.formGroup}>
                  <label style={S.label}>2. Collection Summary (.json) *</label>
                  <div style={S.dropzone}>
                    <input
                      type="file"
                      accept=".json"
                      onChange={(e) => setSummaryFile(e.target.files?.[0] || null)}
                      style={S.fileInputHidden}
                      id="file-summary"
                      disabled={isSubmitting}
                    />
                    <label htmlFor="file-summary" style={{...S.fileLabel, ...(isSubmitting ? { cursor: 'not-allowed' } : {})}}>
                      {summaryFile ? (
                        <span style={S.fileName}>{summaryFile.name}</span>
                      ) : (
                        <>
                          <strong>Upload summary</strong>
                          <span style={S.fileHint}>Summary of the collected data</span>
                        </>
                      )}
                    </label>
                  </div>
                </div>
              </div>
            </div>

            <div style={S.actions}>
              <Link to="/scans" style={{ ...S.cancelBtn, ...(isSubmitting ? { pointerEvents: 'none', opacity: 0.5 } : {}) }}>
                Cancel
              </Link>
              <button type="submit" disabled={isSubmitting} style={{ ...S.submitBtn, ...(isSubmitting ? S.submitBtnLoading : {}) }}>
                {isSubmitting ? 'Uploading Data...' : 'Ingest Collection'}
              </button>
            </div>
          </form>
        </div>
      </main>
    </div>
  )
}

const S: Record<string, React.CSSProperties> = {
  root: { minHeight: '100vh', display: 'flex', flexDirection: 'column', color: 'var(--color-fg, #fff)' },
  header: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    height: 56, padding: '0 20px', borderBottom: '1px solid var(--color-line, #33415c)', flexShrink: 0,
  },
  wordmark: { fontWeight: 800, letterSpacing: '-0.01em', fontSize: 18 },
  back: { color: 'var(--color-muted, #94a3b8)', textDecoration: 'none', fontSize: 13 },
  signout: { background: 'transparent', border: 'none', color: 'var(--color-muted, #94a3b8)', cursor: 'pointer', fontSize: 13 },
  
  main: { flex: 1, padding: '40px 24px', display: 'flex', justifyContent: 'center', alignItems: 'flex-start' },
  formContainer: { width: '100%', maxWidth: 750, background: 'rgba(30, 41, 59, 0.25)', padding: 32, borderRadius: 12, border: '1px solid var(--color-line, #33415c)' },
  title: { fontSize: 22, fontWeight: 700, margin: '0 0 6px' },
  subtitle: { color: 'var(--color-muted, #94a3b8)', fontSize: 13, marginBottom: 28 },
  
  formGroup: { marginBottom: 24, display: 'flex', flexDirection: 'column', gap: 8 },
  label: { fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase', color: 'var(--color-muted, #94a3b8)' },
  subLabel: { fontSize: 12, fontWeight: 500, color: '#e2e8f0' },
  input: {
    background: 'var(--color-surface, #0f172a)',
    border: '1px solid var(--color-line, #33415c)',
    borderRadius: 6,
    padding: '10px 14px',
    color: '#fff',
    fontSize: 13,
    outline: 'none',
  },
  
  uploadSection: { background: 'rgba(15, 23, 42, 0.4)', padding: 20, borderRadius: 8, marginBottom: 24, border: '1px solid rgba(51, 65, 85, 0.5)' },
  
  packageGrid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 },
  
  dropzone: {
    border: '2px dashed var(--color-line, #33415c)',
    borderRadius: 8,
    background: 'var(--color-surface, #0f172a)',
    padding: '30px 16px',
    textAlign: 'center',
    cursor: 'pointer',
    height: '110px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  fileInputHidden: { display: 'none' },
  fileLabel: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 12, color: 'var(--color-fg, #fff)' },
  uploadIcon: { fontSize: 22 },
  fileHint: { fontSize: 10, color: 'var(--color-muted, #94a3b8)', marginTop: 2, lineHeight: 1.3 },
  fileName: { color: '#e0b94e', fontWeight: 600, fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' },

  actions: { display: 'flex', justifyContent: 'flex-end', gap: 12, borderTop: '1px solid var(--color-line, #33415c)', paddingTop: 20 },
  cancelBtn: {
    textDecoration: 'none',
    color: 'var(--color-muted, #94a3b8)',
    padding: '10px 20px',
    fontSize: 13,
    fontWeight: 500,
    display: 'flex',
    alignItems: 'center',
  },
  submitBtn: {
    background: '#004494',
    color: '#fff',
    border: '1px solid #005ce6',
    borderRadius: 6,
    padding: '10px 20px',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'background 0.2s, opacity 0.2s',
  },
  submitBtnLoading: {
    opacity: 0.8,
    cursor: 'not-allowed',
  }
}