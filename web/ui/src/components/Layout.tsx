import { useState, useEffect } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Activity,
  Database,
  Shield,
  Settings,
  Info,
  Sun,
  Moon,
  LogOut,
  ChevronLeft,
  ChevronRight,
  User,
  Menu,
  X,
  ExternalLink,
} from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { useTheme } from '@/hooks/useTheme'
import { cn, formatVersion, normalizeVersion } from '@/lib/utils'
import { api } from '@/api/client'

const mainNavItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/queries', icon: Activity, label: 'Queries' },
  { to: '/cache', icon: Database, label: 'Cache' },
  { to: '/blocklist', icon: Shield, label: 'Blocklist' },
  { to: '/config', icon: Settings, label: 'Config' },
]
const aboutNavItem = { to: '/about', icon: Info, label: 'About & Updates' }

export default function Layout({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [currentVersion, setCurrentVersion] = useState('')
  const [updateAvailable, setUpdateAvailable] = useState(false)
  const { username, logout } = useAuth()
  const { dark, toggle } = useTheme()
  const navigate = useNavigate()

  useEffect(() => {
    api.version().then((v) => setCurrentVersion(normalizeVersion(v.version))).catch(() => {})
    api.checkUpdate().then((u) => setUpdateAvailable(Boolean(u.update_available))).catch(() => {})
  }, [])

  function handleLogout() {
    logout()
    navigate('/login')
  }

  const versionLabel = formatVersion(currentVersion)

  return (
    <div className="flex h-screen overflow-hidden bg-slate-100 dark:bg-slate-950">
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

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

        <nav className="flex-1 py-4 space-y-1 px-2">
          {mainNavItems.map(({ to, icon: Icon, label }) => (
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

        <div className="px-2 pb-3 border-t border-slate-200 dark:border-slate-800">
          <NavLink
            to={aboutNavItem.to}
            onClick={() => setMobileOpen(false)}
            className={({ isActive }) =>
              cn(
                'mt-3 relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                collapsed && 'justify-center',
                isActive
                  ? 'bg-amber-600/10 text-amber-600 dark:text-amber-500'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100',
              )
            }
          >
            <aboutNavItem.icon size={20} />
            {!collapsed && (
              <>
                <span>{aboutNavItem.label}</span>
                {updateAvailable && (
                  <span className="ml-auto inline-flex items-center rounded-full bg-amber-100 dark:bg-amber-900/40 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-300">
                    Update
                  </span>
                )}
              </>
            )}
            {collapsed && updateAvailable && (
              <span className="absolute right-2 top-2 h-2.5 w-2.5 rounded-full bg-amber-500 ring-2 ring-slate-900 lg:ring-slate-50 dark:lg:ring-slate-900" />
            )}
          </NavLink>
        </div>
      </aside>

      <div className="flex flex-col flex-1 min-w-0">
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
            <button
              onClick={toggle}
              className="flex items-center justify-center w-9 h-9 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 transition-colors"
              aria-label="Toggle theme"
            >
              {dark ? <Sun size={18} /> : <Moon size={18} />}
            </button>

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
                  <div className="absolute right-0 mt-1 w-52 bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 shadow-lg z-40 py-1">
                    <div className="px-3 py-2 text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                      Signed in as <span className="font-medium text-slate-700 dark:text-slate-200">{username}</span>
                    </div>
                    <div className="px-3 py-2 border-b border-slate-200 dark:border-slate-700">
                      <p className="text-xs font-medium text-slate-700 dark:text-slate-200">Labyrinth {versionLabel}</p>
                      <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">Pure Go Recursive DNS Resolver</p>
                      <button
                        onClick={() => {
                          setUserMenuOpen(false)
                          navigate('/about')
                        }}
                        className="mt-2 w-full px-2 py-1.5 rounded-md text-left text-xs text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
                      >
                        About and Updates
                      </button>
                      <div className="flex items-center gap-3 mt-2">
                        <a
                          href="https://labyrinthdns.com"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-[10px] text-slate-400 dark:text-slate-500 hover:text-amber-600 dark:hover:text-amber-400 transition-colors"
                        >
                          <ExternalLink size={8} />
                          Website
                        </a>
                        <a
                          href="https://github.com/labyrinthdns/labyrinth"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-[10px] text-slate-400 dark:text-slate-500 hover:text-amber-600 dark:hover:text-amber-400 transition-colors"
                        >
                          <ExternalLink size={8} />
                          GitHub
                        </a>
                      </div>
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

        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
