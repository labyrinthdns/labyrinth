import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ArrowUpCircle,
  CheckCircle2,
  Check,
  Copy,
  ExternalLink,
  GitFork,
  Globe,
  Loader2,
  RefreshCw,
  Rocket,
  Search,
  Server,
  Shield,
  Sparkles,
} from 'lucide-react'
import { api } from '@/api/client'
import type { UpdateInfo } from '@/api/types'
import { copyTextToClipboard, formatVersion } from '@/lib/utils'
import { COMPLIANCE_ENTRIES, CATEGORY_LABELS, type ComplianceCategory } from '@/data/rfcCompliance'

type VersionInfo = {
  version: string
  build_time: string
  go_version: string
}

function formatBuildTime(value: string): string {
  if (!value) return 'N/A'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString()
}

// rfcDatatrackerURL returns the IETF datatracker link for an "RFC NNNN" string.
// The matrix entries spell the RFC out with a space ("RFC 8198") because that's
// the canonical citation form, but the datatracker URL needs the bare number.
function rfcDatatrackerURL(rfc: string): string {
  const m = rfc.match(/RFC\s+(\d+)/)
  if (!m) return ''
  return `https://datatracker.ietf.org/doc/html/rfc${m[1]}`
}

const CATEGORY_TINT: Record<ComplianceCategory, string> = {
  core: 'border-slate-400/40 bg-slate-500/10 text-slate-700 dark:text-slate-300',
  dnssec: 'border-emerald-400/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  'nsec-aggressive': 'border-teal-400/40 bg-teal-500/10 text-teal-700 dark:text-teal-300',
  edns: 'border-sky-400/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  'transport-security': 'border-indigo-400/40 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300',
  'special-use': 'border-violet-400/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  'error-signalling': 'border-rose-400/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  caching: 'border-amber-400/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  blocking: 'border-orange-400/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
}

function RFCComplianceMatrix() {
  const [query, setQuery] = useState('')
  const [activeCategory, setActiveCategory] = useState<ComplianceCategory | 'all'>('all')

  const categoriesPresent = useMemo(() => {
    const set = new Set<ComplianceCategory>()
    for (const e of COMPLIANCE_ENTRIES) set.add(e.category)
    return Array.from(set)
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return COMPLIANCE_ENTRIES.filter((e) => {
      if (activeCategory !== 'all' && e.category !== activeCategory) return false
      if (!q) return true
      const hay = `${e.rfc} ${e.section ?? ''} ${e.title} ${e.summary} ${e.since ?? ''}`.toLowerCase()
      return hay.includes(q)
    })
  }, [query, activeCategory])

  const categoryCounts = useMemo(() => {
    const counts: Partial<Record<ComplianceCategory, number>> = {}
    for (const e of COMPLIANCE_ENTRIES) counts[e.category] = (counts[e.category] ?? 0) + 1
    return counts
  }, [])

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm space-y-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">RFC Compliance Matrix</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            The standards Labyrinth implements, grouped by capability. Click any RFC to open the IETF datatracker.
          </p>
        </div>
        <span className="text-[11px] text-slate-500 dark:text-slate-400">
          {filtered.length} / {COMPLIANCE_ENTRIES.length} shown
        </span>
      </div>

      <div className="flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by RFC number, title, summary..."
            className="w-full h-9 pl-8 pr-3 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400"
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        <button
          type="button"
          onClick={() => setActiveCategory('all')}
          className={`px-2.5 py-1 rounded-full text-[11px] border transition ${
            activeCategory === 'all'
              ? 'border-slate-700 dark:border-slate-300 bg-slate-700 dark:bg-slate-300 text-white dark:text-slate-900'
              : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700'
          }`}
        >
          All ({COMPLIANCE_ENTRIES.length})
        </button>
        {categoriesPresent.map((cat) => (
          <button
            type="button"
            key={cat}
            onClick={() => setActiveCategory(cat)}
            className={`px-2.5 py-1 rounded-full text-[11px] border transition ${
              activeCategory === cat
                ? 'border-slate-700 dark:border-slate-300 bg-slate-700 dark:bg-slate-300 text-white dark:text-slate-900'
                : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700'
            }`}
          >
            {CATEGORY_LABELS[cat]} ({categoryCounts[cat]})
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <div className="text-center py-8 text-xs text-slate-500 dark:text-slate-400">
          No entries match the current filter.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2.5">
          {filtered.map((e) => {
            const tint = CATEGORY_TINT[e.category]
            const url = rfcDatatrackerURL(e.rfc)
            return (
              <div
                key={`${e.rfc}-${e.section ?? ''}-${e.title}`}
                className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-900/40 p-3 space-y-1.5"
              >
                <div className="flex items-baseline justify-between gap-2 flex-wrap">
                  <a
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-amber-700 dark:text-amber-300 hover:underline"
                  >
                    {e.rfc}{e.section ? ` ${e.section}` : ''}
                    <ExternalLink size={10} />
                  </a>
                  <span className={`inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-mono uppercase border ${tint}`}>
                    {CATEGORY_LABELS[e.category]}
                  </span>
                </div>
                <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 leading-snug">
                  {e.title}
                </div>
                <div className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                  {e.summary}
                </div>
                {e.since && (
                  <div className="text-[10px] text-slate-500 dark:text-slate-500 font-mono pt-1">
                    since {e.since}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default function AboutPage() {
  const [versionInfo, setVersionInfo] = useState<VersionInfo | null>(null)
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [checking, setChecking] = useState(false)
  const [applying, setApplying] = useState(false)
  const [confirmUpdate, setConfirmUpdate] = useState(false)
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [copiedCmd, setCopiedCmd] = useState('')
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const reloadTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  useEffect(() => {
    return () => {
      clearTimeout(copyTimerRef.current)
      clearTimeout(reloadTimerRef.current)
    }
  }, [])

  const loadAboutData = useCallback(async () => {
    setLoading(true)
    setError('')

    const [versionRes, updateRes] = await Promise.allSettled([
      api.version(),
      api.checkUpdate(),
    ])

    if (versionRes.status === 'fulfilled') {
      setVersionInfo(versionRes.value)
    }

    if (updateRes.status === 'fulfilled') {
      setUpdateInfo(updateRes.value)
    }

    if (versionRes.status === 'rejected' && updateRes.status === 'rejected') {
      setError('Failed to load About data')
    }

    setLoading(false)
  }, [])

  useEffect(() => {
    void loadAboutData()
  }, [loadAboutData])

  const checkUpdates = useCallback(async () => {
    setChecking(true)
    setError('')
    setStatus('')
    setConfirmUpdate(false)

    try {
      const info = await api.checkUpdate(true)
      setUpdateInfo(info)
      setStatus(info.update_available ? 'A new release is available.' : 'You are already on the latest version.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Update check failed')
    } finally {
      setChecking(false)
    }
  }, [])

  const applyUpdate = useCallback(async () => {
    setApplying(true)
    setError('')
    setStatus('Applying update. Service will restart and page will refresh...')

    try {
      await api.applyUpdate()
      reloadTimerRef.current = setTimeout(() => {
        window.location.reload()
      }, 5000)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Update failed'
      if (msg.includes('409') || msg.toLowerCase().includes('read-only')) {
        setUpdateInfo((prev) => prev ? { ...prev, read_only: true } : prev)
        setError('Install path is read-only. Use the update command below to upgrade manually.')
      } else {
        setError(msg)
      }
      setApplying(false)
      setConfirmUpdate(false)
      setStatus('')
    }
  }, [])

  const currentVersion = useMemo(() => {
    return formatVersion(updateInfo?.current_version || versionInfo?.version || '')
  }, [updateInfo, versionInfo])

  const latestVersion = useMemo(() => {
    return formatVersion(updateInfo?.latest_version || '')
  }, [updateInfo])

  const copyCommand = useCallback(async (id: string, command: string) => {
    const copied = await copyTextToClipboard(command)
    if (copied) {
      setError('')
      setCopiedCmd(id)
      clearTimeout(copyTimerRef.current)
      copyTimerRef.current = setTimeout(() => setCopiedCmd(''), 1200)
    } else {
      setError('Clipboard access is blocked in this browser. Copy the command manually.')
    }
  }, [])

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-6 shadow-sm relative overflow-hidden">
        <div className="absolute -top-20 -right-16 w-64 h-64 rounded-full bg-gradient-to-br from-amber-400/20 to-orange-500/15 blur-3xl" />
        <div className="absolute -bottom-16 -left-14 w-56 h-56 rounded-full bg-gradient-to-br from-sky-400/15 to-emerald-500/15 blur-3xl" />

        <div className="relative space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300">
            <Sparkles size={12} />
            About Labyrinth
          </div>

          <h1 className="text-3xl font-bold text-slate-900 dark:text-slate-100">
            Fast, secure and observable DNS resolver
          </h1>

          <p className="text-sm text-slate-600 dark:text-slate-300 max-w-3xl leading-relaxed">
            Labyrinth is a pure Go recursive DNS resolver with DNSSEC validation, caching, blocklist support,
            rate limiting and a modern Web UI for live operational visibility.
          </p>

          <div className="flex flex-wrap gap-2 pt-1">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200">
              <Server size={12} />
              {currentVersion || 'Version unavailable'}
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200">
              <Shield size={12} />
              DNSSEC + Blocklist + RRL
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200">
              <Rocket size={12} />
              Built with Go
            </span>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      {status && !error && (
        <div className="bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 text-sm rounded-lg px-4 py-3 inline-flex items-center gap-2">
          <CheckCircle2 size={16} />
          {status}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm space-y-4">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Project and Community</h2>
          <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
            Operate recursive DNS with confidence: inspect traffic patterns, tune cache behavior, enforce security policies,
            and keep your resolver instance healthy from a single control plane.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <a
              href="https://labyrinthdns.com"
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-lg border border-slate-200 dark:border-slate-700 p-4 hover:border-amber-400 dark:hover:border-amber-500 transition-colors"
            >
              <div className="inline-flex items-center gap-2 text-sm font-semibold text-slate-800 dark:text-slate-200">
                <Globe size={16} />
                Official Website
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Docs, announcements and release highlights.</p>
              <span className="inline-flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400 mt-2">
                Open website <ExternalLink size={12} />
              </span>
            </a>

            <a
              href="https://github.com/labyrinthdns/labyrinth"
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-lg border border-slate-200 dark:border-slate-700 p-4 hover:border-amber-400 dark:hover:border-amber-500 transition-colors"
            >
                <div className="inline-flex items-center gap-2 text-sm font-semibold text-slate-800 dark:text-slate-200">
                <GitFork size={16} />
                GitHub Repository
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Source code, issues, changelog and contribution flow.</p>
              <span className="inline-flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400 mt-2">
                Open GitHub <ExternalLink size={12} />
              </span>
            </a>
          </div>

          <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4 bg-slate-50/70 dark:bg-slate-900/40">
            <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400 mb-3">Build Info</h3>
            {loading ? (
              <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
                <Loader2 size={14} className="animate-spin" />
                Loading build metadata...
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
                <div>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Version</p>
                  <p className="font-semibold text-slate-900 dark:text-slate-100">{currentVersion || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Build Time</p>
                  <p className="font-semibold text-slate-900 dark:text-slate-100">{formatBuildTime(versionInfo?.build_time || '')}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Go Version</p>
                  <p className="font-semibold text-slate-900 dark:text-slate-100">{versionInfo?.go_version || 'N/A'}</p>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm space-y-4">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Update Center</h2>

          <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4 space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-500 dark:text-slate-400">Current</span>
              <span className="font-semibold text-slate-900 dark:text-slate-100">{currentVersion || 'N/A'}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-500 dark:text-slate-400">Latest</span>
              <span className="font-semibold text-slate-900 dark:text-slate-100">{latestVersion || 'Unknown'}</span>
            </div>
            <div className="pt-1 text-xs">
              {updateInfo?.update_available ? (
                <span className="inline-flex items-center gap-1 text-amber-600 dark:text-amber-400">
                  <ArrowUpCircle size={13} />
                  Update available
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                  <CheckCircle2 size={13} />
                  Up to date
                </span>
              )}
            </div>
            {updateInfo?.release_url && (
              <a
                href={updateInfo.release_url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400 hover:underline"
              >
                Release notes <ExternalLink size={11} />
              </a>
            )}
          </div>

          <div className="space-y-2">
            <button
              onClick={checkUpdates}
              disabled={checking || applying}
              className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 disabled:opacity-60"
            >
              {checking ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
              Check Updates
            </button>

            {updateInfo?.update_available && !updateInfo?.read_only && !confirmUpdate && (
              <button
                onClick={() => setConfirmUpdate(true)}
                disabled={checking || applying}
                className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-sm font-medium disabled:opacity-60"
              >
                <ArrowUpCircle size={14} />
                Update Now
              </button>
            )}

            {updateInfo?.update_available && updateInfo?.read_only && (
              <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50 dark:bg-slate-900/40">
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Self-update is not available because the install path is read-only. Use the update command below to upgrade manually.
                </p>
              </div>
            )}

            {updateInfo?.update_available && !updateInfo?.read_only && confirmUpdate && (
              <div className="space-y-2 rounded-lg border border-amber-200 dark:border-amber-800 p-3 bg-amber-50 dark:bg-amber-900/20">
                <p className="text-xs text-amber-700 dark:text-amber-400">Confirm update and restart service?</p>
                <button
                  onClick={applyUpdate}
                  disabled={applying}
                  className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-sm font-medium disabled:opacity-60"
                >
                  {applying ? <Loader2 size={14} className="animate-spin" /> : <ArrowUpCircle size={14} />}
                  Confirm and Apply
                </button>
                <button
                  onClick={() => setConfirmUpdate(false)}
                  disabled={applying}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>

          <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4 space-y-2">
            <p className="text-xs uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">Install & Upgrade Commands</p>
            <div className="space-y-2">
              <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/40 p-2">
                <p className="text-[10px] uppercase text-slate-400 mb-1">Install (Linux)</p>
                <code className="block text-[11px] text-slate-700 dark:text-slate-200 break-all">curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/install.sh | bash</code>
                <button
                  onClick={() => void copyCommand('install', 'curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/install.sh | bash')}
                  className="mt-2 inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700"
                >
                  {copiedCmd === 'install' ? <Check size={11} /> : <Copy size={11} />}
                  {copiedCmd === 'install' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/40 p-2">
                <p className="text-[10px] uppercase text-slate-400 mb-1">Update</p>
                <code className="block text-[11px] text-slate-700 dark:text-slate-200 break-all">curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/update.sh | sudo bash</code>
                <button
                  onClick={() => void copyCommand('update', 'curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/update.sh | sudo bash')}
                  className="mt-2 inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700"
                >
                  {copiedCmd === 'update' ? <Check size={11} /> : <Copy size={11} />}
                  {copiedCmd === 'update' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>
          </div>

          {updateInfo?.release_notes && (
            <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4">
              <p className="text-xs uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400 mb-2">Latest Release Notes</p>
              <p className="text-xs text-slate-600 dark:text-slate-300 whitespace-pre-line line-clamp-6">
                {updateInfo.release_notes}
              </p>
            </div>
          )}
        </div>
      </div>

      <RFCComplianceMatrix />
    </div>
  )
}
