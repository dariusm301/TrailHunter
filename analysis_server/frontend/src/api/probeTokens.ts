import { apiGet, apiPost, apiDelete, apiFetch } from './client'

export interface ProbeToken {
  id: string
  name: string
  token_type: 'hardware' | 'software'
  device_identifier: string | null
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  single_use: boolean
  used_at: string | null
  revoked: boolean
}

export interface CreateProbeTokenRequest {
  name: string
  token_type: 'hardware' | 'software'
  device_identifier?: string
  expires_in_days?: number | null
  expires_in_minutes?: number
  single_use?: boolean
}

export interface CreateProbeTokenResponse {
  id: string
  name: string
  token: string
  token_type: 'hardware' | 'software'
  expires_at: string | null
}

export function listProbeTokens(): Promise<ProbeToken[]> {
  return apiGet<ProbeToken[]>('/probes/tokens')
}

export function createProbeToken(req: CreateProbeTokenRequest): Promise<CreateProbeTokenResponse> {
  return apiPost<CreateProbeTokenResponse>('/probes/tokens', req)
}

export function revokeProbeToken(tokenId: string): Promise<void> {
  return apiDelete<void>(`/probes/tokens/${tokenId}`)
}

export async function deleteProbeToken(id: string): Promise<void> {
  await apiFetch(`/probes/tokens/${id}/permanent`, { method: 'DELETE' })
}