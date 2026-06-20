let accessToken: string | null = null
let onUnauthorized: (() => void) | null = null

export function getAccessToken(): string | null {
  return accessToken
}

export function setAccessToken(token: string | null): void {
  accessToken = token
}

export function setOnUnauthorized(callback: (() => void) | null): void {
  onUnauthorized = callback
}

export function notifyUnauthorized(): void {
  accessToken = null
  onUnauthorized?.()
}