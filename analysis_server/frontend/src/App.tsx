import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import './App.css'
import { AuthProvider } from '@/auth/AuthProvider'
import { useAuth } from '@/auth/useAuth'
import RequireAuth from '@/components/RequireAuth'
import LoginPage from '@/features/login/LoginPage'
import SetupPage from '@/features/login/SetupPage'
import ScansPage from '@/features/scans/ScansPage'
import GraphPage from '@/features/graph/GraphPage'
import NewScanPage from '@/features/scans/NewScanPage'
import { UsersPage } from '@/features/login/UsersPage'
import { ProbeTokensPage } from './features/settings/ProbeTokensPage'

function AppRoutes() {
  const { loading, setupRequired } = useAuth()

  if (loading) {
    return null
  }

  if (setupRequired) {
    return (
      <Routes>
        <Route path="*" element={<SetupPage />} />
      </Routes>
    )
  }

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/scans"
        element={
          <RequireAuth>
            <ScansPage />
          </RequireAuth>
        }
      />
      <Route
        path="/scans/:collectionId"
        element={
          <RequireAuth>
            <GraphPage />
          </RequireAuth>
        }
      />
      <Route
        path="/scans/new"
        element={
          <RequireAuth>
            <NewScanPage />
          </RequireAuth>
        }
      />
      <Route 
        path="/settings/probe-tokens"
        element={
          <RequireAuth>
            <ProbeTokensPage />
          </RequireAuth>
        }
      />
      <Route
        path="/settings/users"
        element={
          <RequireAuth>
            <UsersPage />
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/scans" replace />} />

    </Routes>
  )
}

function App() {
  return (
    <AuthProvider>
      <Router>
        <AppRoutes />
      </Router>
    </AuthProvider>
  )
}

export default App