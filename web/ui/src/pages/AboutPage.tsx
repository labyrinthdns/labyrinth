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
  Server,
  Shield,
  Sparkles,
} from 'lucide-react'
import { api } from '@/api/client'
import type { UpdateInfo } from '@/api/types'
import { copyTextToClipboard, formatVersion } from '@/lib/utils'

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
      setError(err instanceof Error ? err.message : 'Update failed')
      setApplying(false)
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

            {updateInfo?.update_available && !confirmUpdate && (
              <button
                onClick={() => setConfirmUpdate(true)}
                disabled={checking || applying}
                className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-sm font-medium disabled:opacity-60"
              >
                <ArrowUpCircle size={14} />
                Update Now
              </button>
            )}

            {updateInfo?.update_available && confirmUpdate && (
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
    </div>
  )
}
