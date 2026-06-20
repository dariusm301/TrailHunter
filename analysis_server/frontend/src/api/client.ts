import { getAccessToken, setAccessToken, notifyUnauthorized } from '@/auth/tokenStore'

export const BASE = '/api'

export class ApiError extends Error {
  public status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'ApiError'
  }
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

async function tryRefresh(): Promise<string | null> {
  const res = await fetch(`${BASE}/auth/refresh`, {
    method: 'POST',
    credentials: 'include',
  })
  if (!res.ok) return null
  const data = (await res.json()) as { access_token: string }
  setAccessToken(data.access_token)
  return data.access_token
}

function authHeaders(token: string | null): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  _isRetry = false,
): Promise<T> {
  const token = getAccessToken()

  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...authHeaders(token),
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  if (res.status === 401 && !_isRetry) {
    const newToken = await tryRefresh()
    if (newToken) {
      return request<T>(method, path, body, true)
    }
    notifyUnauthorized()
    throw new ApiError(401, `${method} ${path} → session expired`)
  }

  if (!res.ok) {
    throw new ApiError(res.status, `${method} ${path} → ${await parseErrorDetail(res)}`)
  }

  return (await res.json()) as T
}

export const apiGet = <T>(path: string) => request<T>('GET', path)
export const apiPost = <T>(path: string, body?: unknown) => request<T>('POST', path, body)

export async function apiUploadRaw<T>(
  path: string,
  file: File,
  customHeaders: Record<string, string> = {},
  _isRetry = false,
): Promise<T> {
  const token = getAccessToken()

  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/octet-stream',
      ...authHeaders(token),
      ...customHeaders,
    },
    body: file,
  })

  if (res.status === 401 && !_isRetry) {
    const newToken = await tryRefresh()
    if (newToken) {
      return apiUploadRaw<T>(path, file, customHeaders, true)
    }
    notifyUnauthorized()
    throw new ApiError(401, `POST ${path} → session expired`)
  }

  if (!res.ok) {
    throw new ApiError(res.status, `POST ${path} → ${await parseErrorDetail(res)}`)
  }

  return (await res.json()) as T
}

export async function apiFetch(
  path: string,
  init: RequestInit = {},
  _isRetry = false,
): Promise<Response> {
  const token = getAccessToken()

  const res = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...authHeaders(token),
      ...(init.headers ?? {}),
    },
  })

  if (res.status === 401 && !_isRetry) {
    const newToken = await tryRefresh()
    if (newToken) {
      return apiFetch(path, init, true)
    }
    notifyUnauthorized()
  }

  return res
}

export const apiDelete = <T>(path: string) => request<T>('DELETE', path)

export const apiPatch = <T>(path: string, body?: unknown) => request<T>('PATCH', path, body)