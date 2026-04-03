import { useState, useEffect } from 'react'
import { Routes, Route, Link, useLocation, Navigate } from 'react-router-dom'
import { ChevronRight, Menu, X } from 'lucide-react'
import Footer from '../../components/Footer'

import Overview from './Overview'
import Installation from './Installation'
import QuickStart from './QuickStart'
import Configuration from './Configuration'
import Resolution from './Resolution'
import WireProtocol from './WireProtocol'
import Caching from './Caching'
import Security from './Security'
import DashboardSetup from './DashboardSetup'
import Authentication from './Authentication'
import APIReference from './APIReference'
import WebSocketDoc from './WebSocketDoc'
import Monitoring from './Monitoring'
import ZabbixDoc from './ZabbixDoc'
import DaemonMode from './DaemonMode'
import SignalsDoc from './SignalsDoc'
import BenchmarkTool from './BenchmarkTool'
import PerformanceTuning from './PerformanceTuning'
import Troubleshooting from './Troubleshooting'

interface DocsLayoutProps {
  dark: boolean
}

interface SidebarSection {
  title: string
  links: { label: string; path: string }[]
}

const sidebarSections: SidebarSection[] = [
  {
    title: 'Getting Started',
    links: [
      { label: 'Overview', path: '/docs' },
      { label: 'Installation', path: '/docs/installation' },
      { label: 'Quick Start', path: '/docs/quick-start' },
      { label: 'Configuration', path: '/docs/configuration' },
    ],
  },
  {
    title: 'Core Concepts',
    links: [
      { label: 'Recursive Resolution', path: '/docs/resolution' },
      { label: 'DNS Wire Protocol', path: '/docs/wire-protocol' },
      { label: 'Caching', path: '/docs/caching' },
      { label: 'Security', path: '/docs/security' },
    ],
  },
  {
    title: 'Web Dashboard',
    links: [
      { label: 'Dashboard Setup', path: '/docs/dashboard-setup' },
      { label: 'Authentication', path: '/docs/authentication' },
      { label: 'API Reference', path: '/docs/api-reference' },
      { label: 'WebSocket', path: '/docs/websocket' },
    ],
  },
  {
    title: 'Operations',
    links: [
      { label: 'Monitoring', path: '/docs/monitoring' },
      { label: 'Zabbix Integration', path: '/docs/zabbix' },
      { label: 'Daemon Mode', path: '/docs/daemon-mode' },
      { label: 'Signals', path: '/docs/signals' },
    ],
  },
  {
    title: 'Advanced',
    links: [
      { label: 'Benchmark Tool', path: '/docs/benchmark' },
      { label: 'Performance Tuning', path: '/docs/performance-tuning' },
      { label: 'Troubleshooting', path: '/docs/troubleshooting' },
    ],
  },
]

// Build a flat map for breadcrumbs
const pathToLabel: Record<string, string> = {}
for (const section of sidebarSections) {
  for (const link of section.links) {
    pathToLabel[link.path] = link.label
  }
}

function Breadcrumb({ dark }: { dark: boolean }) {
  const location = useLocation()
  const current = pathToLabel[location.pathname] || 'Docs'

  return (
    <div className={`flex items-center gap-2 text-sm mb-8 ${dark ? 'text-gray-400' : 'text-navy-600'}`}>
      <Link to="/" className="hover:text-gold-500 transition-colors">Home</Link>
      <ChevronRight size={14} />
      <Link to="/docs" className="hover:text-gold-500 transition-colors">Docs</Link>
      {location.pathname !== '/docs' && (
        <>
          <ChevronRight size={14} />
          <span className="text-gold-500">{current}</span>
        </>
      )}
    </div>
  )
}

function Sidebar({ dark, onLinkClick }: { dark: boolean; onLinkClick?: () => void }) {
  const location = useLocation()

  return (
    <nav className="space-y-6">
      {sidebarSections.map(section => (
        <div key={section.title}>
          <h3
            className={`text-xs font-bold uppercase tracking-widest mb-3 ${
              dark ? 'text-gray-500' : 'text-navy-400'
            }`}
          >
            {section.title}
          </h3>
          <ul className="space-y-1">
            {section.links.map(link => {
              const isActive = location.pathname === link.path
              return (
                <li key={link.path}>
                  <Link
                    to={link.path}
                    onClick={onLinkClick}
                    className={`block px-3 py-2 rounded-lg text-sm transition-colors ${
                      isActive
                        ? dark
                          ? 'bg-gold-500/10 text-gold-500 font-medium border-l-2 border-gold-500'
                          : 'bg-gold-500/10 text-gold-600 font-medium border-l-2 border-gold-500'
                        : dark
                          ? 'text-gray-400 hover:text-white hover:bg-navy-800'
                          : 'text-navy-600 hover:text-navy-900 hover:bg-mist-100'
                    }`}
                  >
                    {link.label}
                  </Link>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </nav>
  )
}

export default function DocsLayout({ dark }: DocsLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const location = useLocation()

  // Close sidebar on route change (mobile)
  useEffect(() => {
    const closeSidebar = setTimeout(() => {
      setSidebarOpen(false)
    }, 0)
    return () => clearTimeout(closeSidebar)
  }, [location.pathname])

  // Scroll to top on navigation
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [location.pathname])

  return (
    <div className={`min-h-screen pt-16 ${dark ? 'bg-navy-900' : 'bg-mist-50'}`}>
      {/* Mobile sidebar toggle */}
      <button
        onClick={() => setSidebarOpen(v => !v)}
        className={`fixed bottom-6 right-6 z-50 lg:hidden p-3 rounded-full shadow-lg transition-colors ${
          dark
            ? 'bg-gold-500 text-navy-900 hover:bg-gold-400'
            : 'bg-gold-500 text-navy-900 hover:bg-gold-400'
        }`}
        aria-label="Toggle docs sidebar"
      >
        {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 lg:hidden bg-black/50"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <div className="max-w-[1400px] mx-auto flex">
        {/* Sidebar */}
        <aside
          className={`fixed top-16 left-0 z-40 h-[calc(100vh-4rem)] w-[280px] overflow-y-auto p-6 transition-transform duration-300 lg:sticky lg:translate-x-0 lg:block ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          } ${
            dark
              ? 'bg-navy-900 border-r border-navy-800 lg:bg-transparent lg:border-r lg:border-navy-800'
              : 'bg-white border-r border-mist-200 lg:bg-transparent lg:border-r lg:border-mist-200'
          }`}
        >
          <Sidebar dark={dark} onLinkClick={() => setSidebarOpen(false)} />
        </aside>

        {/* Main content */}
        <main className="flex-1 min-w-0">
          <div className="max-w-4xl mx-auto px-6 sm:px-8 py-10">
            <Breadcrumb dark={dark} />
            <Routes>
              <Route index element={<Overview dark={dark} />} />
              <Route path="installation" element={<Installation dark={dark} />} />
              <Route path="quick-start" element={<QuickStart dark={dark} />} />
              <Route path="configuration" element={<Configuration dark={dark} />} />
              <Route path="resolution" element={<Resolution dark={dark} />} />
              <Route path="wire-protocol" element={<WireProtocol dark={dark} />} />
              <Route path="caching" element={<Caching dark={dark} />} />
              <Route path="security" element={<Security dark={dark} />} />
              <Route path="dashboard-setup" element={<DashboardSetup dark={dark} />} />
              <Route path="authentication" element={<Authentication dark={dark} />} />
              <Route path="api-reference" element={<APIReference dark={dark} />} />
              <Route path="websocket" element={<WebSocketDoc dark={dark} />} />
              <Route path="monitoring" element={<Monitoring dark={dark} />} />
              <Route path="zabbix" element={<ZabbixDoc dark={dark} />} />
              <Route path="daemon-mode" element={<DaemonMode dark={dark} />} />
              <Route path="signals" element={<SignalsDoc dark={dark} />} />
              <Route path="benchmark" element={<BenchmarkTool dark={dark} />} />
              <Route path="performance-tuning" element={<PerformanceTuning dark={dark} />} />
              <Route path="troubleshooting" element={<Troubleshooting dark={dark} />} />
              <Route path="*" element={<Navigate to="/docs" replace />} />
            </Routes>
          </div>
          <Footer dark={dark} />
        </main>
      </div>
    </div>
  )
}
