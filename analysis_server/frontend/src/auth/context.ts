import { createContext } from 'react'

export interface AuthUser {
  id: string
  username: string
  is_admin: boolean
}

export interface SignInParams {
  username: string
  password: string
}

export interface AuthContextValue {
  user: AuthUser | null
  accessToken: string | null
  loading: boolean
  setupRequired: boolean
  isAuthenticated: boolean
  signIn: (params: SignInParams) => Promise<void>
  signOut: () => Promise<void>
  register: (params: SignInParams) => Promise<void>
}



export const AuthContext = createContext<AuthContextValue | null>(null)