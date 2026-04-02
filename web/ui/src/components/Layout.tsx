import { useState, useEffect, useCallback } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Activity,
  Database,
  Settings,
  Sun,
  Moon,
  LogOut,
  ChevronLeft,
  ChevronRight,
  User,
  Menu,
  X,
  ArrowUpCircle,
  ExternalLink,
  Loader2,
} from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { useTheme } from '@/hooks/useTheme'
import { cn } from '@/lib/utils'
import { api } from '@/api/client'
import type { UpdateInfo } from '@/api/types'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/queries', icon: Activity, label: 'Queries' },
  { to: '/cache', icon: Database, label: 'Cache' },
  { to: '/config', icon: Settings, label: 'Config' },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null)
  const [currentVersion, setCurrentVersion] = useState('')
  const [updating, setUpdating] = useState(false)
  const [updateConfirm, setUpdateConfirm] = useState(false)
  const { username, logout } = useAuth()
  const { dark, toggle } = useTheme()
  const navigate = useNavigate()

  useEffect(() => {
    api.checkUpdate().then(setUpdateInfo).catch(() => {})
    api.version().then((v) => setCurrentVersion(v.version)).catch(() => {})
  }, [])

  const handleApplyUpdate = useCallback(async () => {
    setUpdating(true)
    try {
      await api.applyUpdate()
      setTimeout(() => {
        window.location.reload()
      }, 5000)
    } catch {
      setUpdating(false)
    }
  }, [])

  function handleLogout() {
    logout()
    navigate('/login')
  }

  return (
    <div className="flex h-screen overflow-hidden bg-slate-100 dark:bg-slate-950">
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed lg:static inset-y-0 left-0 z-50 flex flex-col transition-all duration-300',
          'bg-slate-900 text-slate-200 dark:bg-slate-900 dark:text-slate-200',
          'lg:bg-slate-50 lg:text-slate-800 lg:dark:bg-slate-900 lg:dark:text-slate-200',
          'border-r border-slate-200 dark:border-slate-800',
          collapsed ? 'w-16' : 'w-60',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
        )}
      >
        {/* Sidebar header */}
        <div className="flex items-center justify-between h-14 px-4 border-b border-slate-200 dark:border-slate-800">
          {!collapsed && (
            <span className="font-bold text-lg text-amber-600 tracking-tight">
              Labyrinth
            </span>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="hidden lg:flex items-center justify-center w-8 h-8 rounded-md hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
          </button>
          <button
            onClick={() => setMobileOpen(false)}
            className="lg:hidden flex items-center justify-center w-8 h-8 rounded-md hover:bg-slate-800 text-slate-400"
            aria-label="Close sidebar"
          >
            <X size={18} />
          </button>
        </div>

        {/* Nav links */}
        <nav className="flex-1 py-4 space-y-1 px-2">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                  collapsed && 'justify-center',
                  isActive
                    ? 'bg-amber-600/10 text-amber-600 dark:text-amber-500'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100',
                )
              }
            >
              <Icon size={20} />
              {!collapsed && <span>{label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* Version info */}
        {currentVersion && (
          <div className="px-4 py-3 border-t border-slate-200 dark:border-slate-800">
            {!collapsed ? (
              <p className="text-xs text-slate-400 dark:text-slate-500">
                v{currentVersion}
              </p>
            ) : (
              <p className="text-[10px] text-slate-400 dark:text-slate-500 text-center" title={`v${currentVersion}`}>
                v{currentVersion.split('.').slice(0, 2).join('.')}
              </p>
            )}
          </div>
        )}
      </aside>

      {/* Main area */}
      <div className="flex flex-col flex-1 min-w-0">
        {/* Top header */}
        <header className="flex items-center justify-between h-14 px-4 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 shrink-0">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(true)}
              className="lg:hidden flex items-center justify-center w-8 h-8 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500"
              aria-label="Open sidebar"
            >
              <Menu size={20} />
            </button>
            <h1 className="text-lg font-semibold text-slate-900 dark:text-slate-100 hidden sm:block">
              Labyrinth
            </h1>
          </div>

          <div className="flex items-center gap-2">
            {/* Theme toggle */}
            <button
              onClick={toggle}
              className="flex items-center justify-center w-9 h-9 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 transition-colors"
              aria-label="Toggle theme"
            >
              {dark ? <Sun size={18} /> : <Moon size={18} />}
            </button>

            {/* User dropdown */}
            <div className="relative">
              <button
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-sm text-slate-700 dark:text-slate-300 transition-colors"
              >
                <User size={16} />
                <span className="hidden sm:inline">{username || 'User'}</span>
              </button>
              {userMenuOpen && (
                <>
                  <div
                    className="fixed inset-0 z-30"
                    onClick={() => setUserMenuOpen(false)}
                  />
                  <div className="absolute right-0 mt-1 w-44 bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 shadow-lg z-40 py-1">
                    <div className="px-3 py-2 text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                      Signed in as <span className="font-medium text-slate-700 dark:text-slate-200">{username}</span>
                    </div>
                    <button
                      onClick={handleLogout}
                      className="flex items-center gap-2 w-full px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                    >
                      <LogOut size={14} />
                      Sign out
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        {/* Update banner */}
        {updateInfo?.update_available && !updating && (
          <div className="bg-amber-50 dark:bg-amber-900/20 border-b border-amber-200 dark:border-amber-800 px-4 py-2.5 flex items-center justify-between gap-3 shrink-0">
            <div className="flex items-center gap-2 text-sm text-amber-700 dark:text-amber-400">
              <ArrowUpCircle size={16} />
              <span>
                Update available: <span className="font-semibold">v{updateInfo.latest_version}</span>
              </span>
              {updateInfo.release_url && (
                <a
                  href={updateInfo.release_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-amber-600 dark:text-amber-400 hover:underline"
                >
                  Release notes <ExternalLink size={12} />
                </a>
              )}
            </div>
            {!updateConfirm ? (
              <button
                onClick={() => setUpdateConfirm(true)}
                className="bg-amber-600 hover:bg-amber-700 text-white px-3 py-1 rounded-lg text-sm font-medium transition-colors shrink-0"
              >
                Update Now
              </button>
            ) : (
              <div className="flex items-center gap-2 shrink-0">
                <span className="text-xs text-amber-600 dark:text-amber-400">Are you sure?</span>
                <button
                  onClick={handleApplyUpdate}
                  className="bg-amber-600 hover:bg-amber-700 text-white px-3 py-1 rounded-lg text-sm font-medium transition-colors"
                >
                  Confirm
                </button>
                <button
                  onClick={() => setUpdateConfirm(false)}
                  className="bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300 px-3 py-1 rounded-lg text-sm font-medium hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        )}

        {/* Updating banner */}
        {updating && (
          <div className="bg-blue-50 dark:bg-blue-900/20 border-b border-blue-200 dark:border-blue-800 px-4 py-3 flex items-center gap-2 text-sm text-blue-700 dark:text-blue-400 shrink-0">
            <Loader2 size={16} className="animate-spin" />
            Restarting... the page will refresh automatically.
          </div>
        )}

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
