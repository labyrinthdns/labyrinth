import { useState, useEffect, useCallback, Suspense, lazy } from 'react'
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom'
import { AuthContext, useAuth } from '@/hooks/useAuth'
import { api } from '@/api/client'
import Layout from '@/components/Layout'
import ErrorBoundary from '@/components/ErrorBoundary'

const LoginPage = lazy(() => import('@/pages/LoginPage'))
const SetupWizard = lazy(() => import('@/pages/SetupWizard'))
const DashboardPage = lazy(() => import('@/pages/DashboardPage'))
const QueriesPage = lazy(() => import('@/pages/QueriesPage'))
const CachePage = lazy(() => import('@/pages/CachePage'))
const ConfigPage = lazy(() => import('@/pages/ConfigPage'))
const BlocklistPage = lazy(() => import('@/pages/BlocklistPage'))
const AboutPage = lazy(() => import('@/pages/AboutPage'))
const OperationsPage = lazy(() => import('@/pages/OperationsPage'))
const ReportsPage = lazy(() => import('@/pages/ReportsPage'))
const GuidePage = lazy(() => import('@/pages/GuidePage'))
const DiagnosticsPage = lazy(() => import('@/pages/DiagnosticsPage'))
const DNSSECPage = lazy(() => import('@/pages/DNSSECPage'))
const SecurityPage = lazy(() => import('@/pages/SecurityPage'))
const AuditPage = lazy(() => import('@/pages/AuditPage'))
const CompliancePage = lazy(() => import('@/pages/CompliancePage'))

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }
  return <Layout>{children}</Layout>
}

function SetupRoute({ setupRequired }: { setupRequired: boolean }) {
  if (!setupRequired) {
    return <Navigate to="/login" replace />
  }
  return <Outlet />
}

function InstalledRoute({ setupRequired }: { setupRequired: boolean }) {
  if (setupRequired) {
    return <Navigate to="/setup" replace />
  }
  return <Outlet />
}

function RouteFallback() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-slate-50 dark:bg-slate-950">
      <div className="flex flex-col items-center gap-3">
        <div className="w-8 h-8 border-4 border-amber-600 border-t-transparent rounded-full animate-spin" />
        <p className="text-slate-500 dark:text-slate-400 text-sm">Loading...</p>
      </div>
    </div>
  )
}

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [username, setUsername] = useState<string | null>(null)
  const [setupRequired, setSetupRequired] = useState(false)
  const [checking, setChecking] = useState(true)

  const login = useCallback((name: string) => {
    setIsAuthenticated(true)
    setUsername(name)
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } catch {
      // server round-trip failure is non-fatal — clear locally anyway
    }
    setIsAuthenticated(false)
    setUsername(null)
  }, [])

  useEffect(() => {
    let cancelled = false

    async function check() {
      try {
        // Check if setup is required first
        const status = await api.setupStatus()
        if (status.setup_required) {
          if (!cancelled) {
            setSetupRequired(true)
            setChecking(false)
          }
          return
        }
      } catch {
        // Setup endpoint might fail if already configured, continue
      }

      // The labyrinth_token cookie is sent automatically by the
      // browser. No need to read from localStorage.
      try {
        const user = await api.me()
        if (!cancelled) {
          setIsAuthenticated(true)
          setUsername(user.username)
        }
      } catch {
        // Not authenticated — stay false
      }

      if (!cancelled) {
        setChecking(false)
      }
    }

    check()
    return () => {
      cancelled = true
    }
  }, [])

  if (checking) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-slate-50 dark:bg-slate-950">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-4 border-amber-600 border-t-transparent rounded-full animate-spin" />
          <p className="text-slate-500 dark:text-slate-400 text-sm">Loading...</p>
        </div>
      </div>
    )
  }

  return (
    <ErrorBoundary>
    <AuthContext.Provider value={{ isAuthenticated, username, login, logout }}>
      <BrowserRouter>
        <Suspense fallback={<RouteFallback />}>
          <Routes>
            <Route element={<SetupRoute setupRequired={setupRequired} />}>
              <Route path="/setup" element={<SetupWizard onComplete={() => setSetupRequired(false)} />} />
            </Route>
            <Route element={<InstalledRoute setupRequired={setupRequired} />}>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/guide" element={<GuidePage />} />
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <DashboardPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/queries"
              element={
                <ProtectedRoute>
                  <QueriesPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/cache"
              element={
                <ProtectedRoute>
                  <CachePage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/blocklist"
              element={
                <ProtectedRoute>
                  <BlocklistPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/config"
              element={
                <ProtectedRoute>
                  <ConfigPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/about"
              element={
                <ProtectedRoute>
                  <AboutPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/operations"
              element={
                <ProtectedRoute>
                  <OperationsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/reports"
              element={
                <ProtectedRoute>
                  <ReportsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/diagnostics"
              element={
                <ProtectedRoute>
                  <DiagnosticsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dnssec"
              element={
                <ProtectedRoute>
                  <DNSSECPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/security"
              element={
                <ProtectedRoute>
                  <SecurityPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/audit"
              element={
                <ProtectedRoute>
                  <AuditPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/compliance"
              element={
                <ProtectedRoute>
                  <CompliancePage />
                </ProtectedRoute>
              }
            />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </Suspense>
      </BrowserRouter>
    </AuthContext.Provider>
    </ErrorBoundary>
  )
}
