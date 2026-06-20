import { apiGet, apiPost, apiPatch } from './client'

export interface AppUser {
  id: string
  username: string
  is_admin: boolean
  is_active: boolean
  created_at: string
}

export interface CreateUserRequest {
  username: string
  password: string
  is_admin: boolean
}

export function listUsers(): Promise<AppUser[]> {
  return apiGet<AppUser[]>('/users')
}

export function createUser(req: CreateUserRequest): Promise<AppUser> {
  return apiPost<AppUser>('/users', req)
}

export function toggleUserActive(userId: string): Promise<{ id: string; is_active: boolean }> {
  return apiPatch(`/users/${userId}/toggle-active`)
}