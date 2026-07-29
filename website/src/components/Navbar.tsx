import { useState, useEffect } from 'react'
import { Sun, Moon, Menu, X } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'
import GithubIcon from './GithubIcon'

interface NavbarProps {
  dark: boolean
  toggleTheme: () => void
}

const navLinks = [
  { label: 'Features', href: '#features', internal: false },
  { label: 'Performance', href: '#performance', internal: false },
  { label: 'Install', href: '#install', internal: false },
  { label: 'Docs', href: '/docs', internal: true },
]

export default function Navbar({ dark, toggleTheme }: NavbarProps) {
  const [scrolled, setScrolled] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const location = useLocation()
  const isDocsPage = location.pathname.startsWith('/docs')

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  // Close mobile menu on resize
  useEffect(() => {
    const onResize = () => {
      if (window.innerWidth >= 768) setMobileOpen(false)
    }
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  const navBg = scrolled || isDocsPage
    ? dark
      ? 'bg-navy-900/80 border-b border-navy-700/50'
      : 'bg-white/80 border-b border-mist-200'
    : 'bg-transparent border-b border-transparent'

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 glass ${navBg}`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2 group">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-gold-500 to-gold-600 flex items-center justify-center">
              <span className="text-navy-900 font-bold text-sm font-serif">L</span>
            </div>
            <span
              className={`text-lg font-bold tracking-tight ${
                dark ? 'text-white' : 'text-navy-900'
              }`}
            >
              Labyrinth
            </span>
          </Link>

          {/* Center nav links - desktop */}
          <div className="hidden md:flex items-center gap-8">
            {navLinks.map(link => {
              const isActive = link.internal && isDocsPage

              if (link.internal) {
                return (
                  <Link
                    key={link.href}
                    to={link.href}
                    className={`text-sm font-medium transition-colors hover:text-gold-500 ${
                      isActive
                        ? 'text-gold-500'
                        : dark
                          ? 'text-gray-300'
                          : 'text-navy-700'
                    }`}
                  >
                    {link.label}
                  </Link>
                )
              }

              // Hash links: if on docs page, navigate to landing page first
              if (isDocsPage) {
                return (
                  <Link
                    key={link.href}
                    to={`/${link.href}`}
                    className={`text-sm font-medium transition-colors hover:text-gold-500 ${
                      dark ? 'text-gray-300' : 'text-navy-700'
                    }`}
                  >
                    {link.label}
                  </Link>
                )
              }

              return (
                <a
                  key={link.href}
                  href={link.href}
                  className={`text-sm font-medium transition-colors hover:text-gold-500 ${
                    dark ? 'text-gray-300' : 'text-navy-700'
                  }`}
                >
                  {link.label}
                </a>
              )
            })}
          </div>

          {/* Right side */}
          <div className="flex items-center gap-3">
            <button
              onClick={toggleTheme}
              className={`p-2 rounded-lg transition-colors ${
                dark
                  ? 'text-gray-400 hover:text-gold-500 hover:bg-navy-800'
                  : 'text-navy-600 hover:text-gold-600 hover:bg-mist-100'
              }`}
              aria-label="Toggle theme"
            >
              {dark ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <a
              href="https://github.com/labyrinthdns/labyrinth"
              target="_blank"
              rel="noopener noreferrer"
              className={`p-2 rounded-lg transition-colors ${
                dark
                  ? 'text-gray-400 hover:text-white hover:bg-navy-800'
                  : 'text-navy-600 hover:text-navy-900 hover:bg-mist-100'
              }`}
              aria-label="GitHub"
            >
              <GithubIcon size={18} />
            </a>

            {/* Mobile hamburger */}
            <button
              onClick={() => setMobileOpen(v => !v)}
              className={`md:hidden p-2 rounded-lg transition-colors ${
                dark
                  ? 'text-gray-400 hover:text-white hover:bg-navy-800'
                  : 'text-navy-600 hover:text-navy-900 hover:bg-mist-100'
              }`}
              aria-label="Menu"
            >
              {mobileOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div
          className={`md:hidden border-t ${
            dark ? 'bg-navy-900/95 border-navy-700/50' : 'bg-white/95 border-mist-200'
          } glass`}
        >
          <div className="px-4 py-4 space-y-3">
            {navLinks.map(link => {
              if (link.internal) {
                return (
                  <Link
                    key={link.href}
                    to={link.href}
                    onClick={() => setMobileOpen(false)}
                    className={`block text-sm font-medium py-2 transition-colors hover:text-gold-500 ${
                      isDocsPage
                        ? 'text-gold-500'
                        : dark
                          ? 'text-gray-300'
                          : 'text-navy-700'
                    }`}
                  >
                    {link.label}
                  </Link>
                )
              }

              if (isDocsPage) {
                return (
                  <Link
                    key={link.href}
                    to={`/${link.href}`}
                    onClick={() => setMobileOpen(false)}
                    className={`block text-sm font-medium py-2 transition-colors hover:text-gold-500 ${
                      dark ? 'text-gray-300' : 'text-navy-700'
                    }`}
                  >
                    {link.label}
                  </Link>
                )
              }

              return (
                <a
                  key={link.href}
                  href={link.href}
                  onClick={() => setMobileOpen(false)}
                  className={`block text-sm font-medium py-2 transition-colors hover:text-gold-500 ${
                    dark ? 'text-gray-300' : 'text-navy-700'
                  }`}
                >
                  {link.label}
                </a>
              )
            })}
          </div>
        </div>
      )}
    </nav>
  )
}
