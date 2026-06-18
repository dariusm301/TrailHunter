import type { ScanSummary } from '@/types/scan'
import { apiGet, apiPost } from './client'
import type { CorrelationGraph } from '@/types/graph'
import type { DetectResult } from '@/types/alerts'

export function fetchScans(): Promise<ScanSummary[]> {
  return apiGet<ScanSummary[]>('/collections')
}

export async function fetchFindings(collectionId: string): Promise<DetectResult | null> {
  const res = await fetch(`/api/collections/${encodeURIComponent(collectionId)}/findings`)
  if (res.status === 404) return null
  if (!res.ok) return null
  const data = await res.json()
  if (data?.error) return null
  return data as DetectResult
}

export function fetchCorrelation(
  collectionId: string,
  refresh = false,
): Promise<CorrelationGraph> {
  return apiPost<CorrelationGraph>('/correlate', {
    collection_id: collectionId,
    refresh: refresh,
  })
}

import { apiUploadRaw } from './client'

export interface IngestResponse {
  status: string
  hash: string
  host?: string
}

export function ingestProbePackage(
  payloadFile: File,
  hash: string,
  summaryJsonString: string,
): Promise<IngestResponse> {
  return apiUploadRaw<IngestResponse>('/ingest', payloadFile, {
    'X-Collection-Hash': hash,
    'X-Collection-Summary': summaryJsonString,
  })
}

export function runDetection(collectionId: string): Promise<{ status: string }> {
  return apiPost<{ status: string }>('/detect', {
    collection_id: collectionId,
  })
}

export function deleteCollection(collectionId: string): Promise<{ status: string }> {
  return apiPost<{ status: string }>('/delete', {
    collection_id: collectionId,
  })
}

export interface CorrelationEnvelope {
  status: 'idle' | 'running' | 'done' | 'error'
  phase: string
  progress: number | null
  error: string | null
  graph: CorrelationGraph | null
  elapsed?: number
}

export async function startCorrelation(
  collectionId: string,
  force = false,
): Promise<CorrelationEnvelope> {
  const res = await fetch(`/api/correlate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ collection_id: collectionId, force }),
  })
  if (!res.ok && res.status !== 202) throw new Error(`Correlate failed: ${res.status}`)
  return res.json()
}

export async function pollCorrelation(
  collectionId: string,
): Promise<CorrelationEnvelope> {
  const res = await fetch(`/api/correlate/${encodeURIComponent(collectionId)}/status`)

  if (res.status === 404) {
    return { status: 'idle', phase: 'not_correlated', progress: null, error: null, graph: null }
  }

  const text = await res.text()

  if (!res.ok) throw new Error(`Status failed: ${res.status}`)

  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`Invalid JSON: ${text.slice(0, 200)}`)
  }
}