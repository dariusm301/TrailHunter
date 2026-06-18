import { createContext } from 'react'

export interface Operator {
  username: string
}

export interface AuthContextValue {
  operator: Operator | null
  isAuthenticated: boolean
  signIn: (creds: { username: string; password: string }) => Promise<Operator>
  signOut: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)