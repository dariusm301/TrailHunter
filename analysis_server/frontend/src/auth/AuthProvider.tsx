import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { AuthContext, type AuthUser, type SignInParams } from './context'
import {
  checkSetupRequired,
  fetchMe,
  login as apiLogin,
  logout as apiLogout,
  refreshAccessToken,
  register as apiRegister,
} from './api'
import { getAccessToken, setOnUnauthorized } from './tokenStore'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [accessToken, setAccessTokenState] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [setupRequired, setSetupRequired] = useState(false)

  useEffect(() => {
    setOnUnauthorized(() => {
      setUser(null)
      setAccessTokenState(null)
    })
    return () => setOnUnauthorized(null)
  }, [])

  useEffect(() => {
    let cancelled = false

    async function bootstrap() {
      const required = await checkSetupRequired()
      if (cancelled) return

      if (required) {
        setSetupRequired(true)
        setLoading(false)
        return
      }

      const refreshed = await refreshAccessToken()
      if (cancelled) return

      if (!refreshed) {
        setLoading(false)
        return
      }

      setAccessTokenState(getAccessToken())

      try {
        const me = await fetchMe()
        if (!cancelled) setUser(me)
      } catch {
        if (!cancelled) setUser(null)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    bootstrap()
    return () => {
      cancelled = true
    }
  }, [])

  const signIn = useCallback(async (params: SignInParams) => {
    await apiLogin(params)
    setAccessTokenState(getAccessToken())
    const me = await fetchMe()
    setUser(me)
  }, [])

  const signOut = useCallback(async () => {
    await apiLogout()
    setUser(null)
    setAccessTokenState(null)
  }, [])

  const register = useCallback(
    async (params: SignInParams) => {
      await apiRegister(params)
      if (setupRequired) {
        setSetupRequired(false)
      }
    },
    [setupRequired],
  )

  return (
      <AuthContext.Provider
        value={{
          user,
          accessToken,
          loading,
          setupRequired,
          isAuthenticated: user !== null,
          signIn,
          signOut,
          register,
        }}
      >
        {children}
      </AuthContext.Provider>
    )
}