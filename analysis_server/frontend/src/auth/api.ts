import { BASE } from '@/api/client'
import { getAccessToken, setAccessToken } from './tokenStore'

export interface AuthUser {
  id: string
  username: string
  is_admin: boolean
}

export interface SignInParams {
  username: string
  password: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
}

async function parseErrorDetail(res: Response): Promise<string> {
  let detail = String(res.status)
  try {
    const err = (await res.json()) as { detail?: string }
    if (err?.detail) detail = err.detail
  } catch {
  }
  return detail
}

export async function login({ username, password }: SignInParams): Promise<TokenResponse> {
  const body = new URLSearchParams({ username, password })

  const res = await fetch(`${BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    credentials: 'include', 
    body,
  })

  if (!res.ok) {
    throw new Error(await parseErrorDetail(res))
  }

  const data = (await res.json()) as TokenResponse
  setAccessToken(data.access_token)
  return data
}

export async function refreshAccessToken(): Promise<TokenResponse | null> {
  const res = await fetch(`${BASE}/auth/refresh`, {
    method: 'POST',
    credentials: 'include', 
  })

  if (!res.ok) {
    setAccessToken(null)
    return null
  }

  const data = (await res.json()) as TokenResponse
  setAccessToken(data.access_token)
  return data
}

export async function logout(): Promise<void> {
  await fetch(`${BASE}/auth/logout`, {
    method: 'POST',
    credentials: 'include',
  }).catch(() => {
  })
  setAccessToken(null)
}

export async function fetchMe(): Promise<AuthUser> {
  const token = getAccessToken()
  const res = await fetch(`${BASE}/auth/me`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) {
    throw new Error(await parseErrorDetail(res))
  }
  return (await res.json()) as AuthUser
}

export async function register({ username, password }: SignInParams): Promise<AuthUser> {
  const token = getAccessToken()
  const res = await fetch(`${BASE}/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ username, password }),
  })
  if (!res.ok) {
    throw new Error(await parseErrorDetail(res))
  }
  return (await res.json()) as AuthUser
}

export async function checkSetupRequired(): Promise<boolean> {
  const res = await fetch(`${BASE}/auth/setup-required`)
  if (!res.ok) return false
  const data = (await res.json()) as { setup_required: boolean }
  return data.setup_required
}