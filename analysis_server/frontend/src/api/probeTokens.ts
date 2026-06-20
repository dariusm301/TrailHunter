import { apiGet, apiPost, apiDelete } from './client'

export interface ProbeToken {
  id: string
  name: string
  device_identifier: string | null
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  revoked: boolean
}

export interface CreateProbeTokenRequest {
  name: string
  device_identifier?: string
  expires_in_days?: number | null
}

export interface CreateProbeTokenResponse {
  id: string
  name: string
  token: string
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