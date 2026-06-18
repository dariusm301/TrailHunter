import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import './App.css'
import { AuthProvider } from '@/auth/AuthProvider'
import RequireAuth from '@/components/RequireAuth'
import LoginPage from '@/features/login/LoginPage'
import ScansPage from '@/features/scans/ScansPage'
import GraphPage from '@/features/graph/GraphPage'
import NewScanPage from '@/features/scans/NewScanPage'

function App() {
  return (
    <AuthProvider>
      <Router>
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
          <Route path="*" element={<Navigate to="/scans" replace />} />
          <Route
            path="/scans/new"
            element={
              <RequireAuth>
                <NewScanPage />
              </RequireAuth>
            }
          />
        </Routes>
      </Router>
    </AuthProvider>
  )
}

export default App