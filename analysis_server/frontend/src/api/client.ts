const BASE = 'http://127.0.0.1:80/api'

export class ApiError extends Error {
  public status: number

  constructor(
    status: number,
    message: string,
  ) {
    super(message)
    this.status = status
    this.name = 'ApiError'
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      Accept: 'application/json',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  if (!res.ok) {
    let detail = String(res.status)
    try {
      const err = (await res.json()) as { detail?: string }
      if (err?.detail) detail = err.detail 
    } catch {
    }
    throw new ApiError(res.status, `${method} ${path} → ${detail}`)
  }

  return (await res.json()) as T
}

export const apiGet = <T>(path: string) => request<T>('GET', path)
export const apiPost = <T>(path: string, body?: unknown) =>
  request<T>('POST', path, body)

export async function apiUploadRaw<T>(
  path: string,
  file: File,
  customHeaders: Record<string, string> = {}
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/octet-stream', 
      ...customHeaders,
    },
    body: file, 
  })

  if (!res.ok) {
    let detail = String(res.status)
    try {
      const err = (await res.json()) as { detail?: string }
      if (err?.detail) detail = err.detail
    } catch {
    }
    throw new ApiError(res.status, `POST ${path} → ${detail}`)
  }

  return (await res.json()) as T
}