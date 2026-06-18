import { useState } from 'react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/auth/context'
import type { AuthContextValue, Operator } from '@/auth/context'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [operator, setOperator] = useState<Operator | null>(null)

  const signIn: AuthContextValue['signIn'] = async ({ username, password }) => {
    await new Promise((r) => setTimeout(r, 450))
    if (!username || !password) {
      throw new Error('Enter a username and password.')
    }
    const session: Operator = { username }
    setOperator(session)
    return session
  }

  const signOut = () => setOperator(null)

  const value: AuthContextValue = {
    operator,
    isAuthenticated: !!operator,
    signIn,
    signOut,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}