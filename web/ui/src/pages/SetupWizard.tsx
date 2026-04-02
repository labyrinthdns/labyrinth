import { useState, useEffect, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronLeft, ChevronRight, Check, Loader2 } from 'lucide-react'
import { api } from '@/api/client'
import type { SetupStatus } from '@/api/types'

const TOTAL_STEPS = 5

export default function SetupWizard() {
  const navigate = useNavigate()
  const [step, setStep] = useState(1)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [setupInfo, setSetupInfo] = useState<SetupStatus | null>(null)

  // Form state
  const [adminUsername, setAdminUsername] = useState('admin')
  const [adminPassword, setAdminPassword] = useState('')
  const [adminPasswordConfirm, setAdminPasswordConfirm] = useState('')
  const [listenAddr, setListenAddr] = useState('0.0.0.0:53')
  const [metricsAddr, setMetricsAddr] = useState('0.0.0.0:9153')
  const [cacheMaxEntries, setCacheMaxEntries] = useState(10000)
  const [qnameMinimization, setQnameMinimization] = useState(true)

  useEffect(() => {
    api.setupStatus().then((res) => setSetupInfo(res as unknown as SetupStatus)).catch(() => {})
  }, [])

  function nextStep() {
    setError('')

    if (step === 2) {
      if (!adminUsername.trim()) {
        setError('Username is required')
        return
      }
      if (adminPassword.length < 8) {
        setError('Password must be at least 8 characters')
        return
      }
      if (adminPassword !== adminPasswordConfirm) {
        setError('Passwords do not match')
        return
      }
    }

    setStep((s) => Math.min(s + 1, TOTAL_STEPS))
  }

  function prevStep() {
    setError('')
    setStep((s) => Math.max(s - 1, 1))
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      await api.setupComplete({
        admin_username: adminUsername,
        admin_password: adminPassword,
        listen_addr: listenAddr,
        metrics_addr: metricsAddr,
        cache_max_entries: cacheMaxEntries,
        qname_minimization: qnameMinimization,
      })
      navigate('/login', { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed')
    } finally {
      setLoading(false)
    }
  }

  const inputClass =
    'bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg px-3 py-2 w-full text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-amber-600/50 focus:border-amber-600 transition-colors'

  const labelClass = 'block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5'

  return (
    <div className="flex items-center justify-center min-h-screen bg-slate-50 dark:bg-slate-950 px-4 py-8">
      <div className="w-full max-w-lg">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Labyrinth Setup
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Configure your DNS server
          </p>
        </div>

        {/* Step indicator */}
        <div className="flex items-center justify-center gap-2 mb-6">
          {Array.from({ length: TOTAL_STEPS }, (_, i) => i + 1).map((s) => (
            <div key={s} className="flex items-center">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${
                  s < step
                    ? 'bg-amber-600 text-white'
                    : s === step
                      ? 'bg-amber-600 text-white ring-2 ring-amber-600/30'
                      : 'bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400'
                }`}
              >
                {s < step ? <Check size={14} /> : s}
              </div>
              {s < TOTAL_STEPS && (
                <div
                  className={`w-8 h-0.5 mx-1 transition-colors ${
                    s < step ? 'bg-amber-600' : 'bg-slate-200 dark:bg-slate-700'
                  }`}
                />
              )}
            </div>
          ))}
        </div>

        {/* Card */}
        <form
          onSubmit={handleSubmit}
          className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 shadow-sm"
        >
          {error && (
            <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm rounded-lg px-3 py-2.5 mb-4">
              {error}
            </div>
          )}

          {/* Step 1: Welcome */}
          {step === 1 && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                Welcome
              </h2>
              <p className="text-slate-600 dark:text-slate-400 text-sm leading-relaxed">
                Welcome to Labyrinth DNS Server. This wizard will guide you through
                the initial configuration. You will set up an admin account, network
                settings, and DNS resolver options.
              </p>
              {setupInfo && (
                <div className="bg-slate-50 dark:bg-slate-900 rounded-lg p-4 space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-500 dark:text-slate-400">Version</span>
                    <span className="font-mono text-slate-700 dark:text-slate-300">
                      {setupInfo.version}
                    </span>
                  </div>
                  {setupInfo.os_arch && (
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-500 dark:text-slate-400">Platform</span>
                      <span className="font-mono text-slate-700 dark:text-slate-300">
                        {setupInfo.os_arch}
                      </span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Step 2: Admin Account */}
          {step === 2 && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                Admin Account
              </h2>
              <p className="text-slate-500 dark:text-slate-400 text-sm">
                Create the administrator account for the dashboard.
              </p>
              <div>
                <label htmlFor="setup-username" className={labelClass}>
                  Username
                </label>
                <input
                  id="setup-username"
                  type="text"
                  value={adminUsername}
                  onChange={(e) => setAdminUsername(e.target.value)}
                  className={inputClass}
                  placeholder="admin"
                  required
                />
              </div>
              <div>
                <label htmlFor="setup-password" className={labelClass}>
                  Password
                </label>
                <input
                  id="setup-password"
                  type="password"
                  value={adminPassword}
                  onChange={(e) => setAdminPassword(e.target.value)}
                  className={inputClass}
                  placeholder="Minimum 8 characters"
                  required
                  minLength={8}
                />
              </div>
              <div>
                <label htmlFor="setup-password-confirm" className={labelClass}>
                  Confirm Password
                </label>
                <input
                  id="setup-password-confirm"
                  type="password"
                  value={adminPasswordConfirm}
                  onChange={(e) => setAdminPasswordConfirm(e.target.value)}
                  className={inputClass}
                  placeholder="Repeat password"
                  required
                />
              </div>
            </div>
          )}

          {/* Step 3: Network Settings */}
          {step === 3 && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                Network Settings
              </h2>
              <p className="text-slate-500 dark:text-slate-400 text-sm">
                Configure the DNS listener and web dashboard addresses.
              </p>
              <div>
                <label htmlFor="listen-addr" className={labelClass}>
                  DNS Listen Address
                </label>
                <input
                  id="listen-addr"
                  type="text"
                  value={listenAddr}
                  onChange={(e) => setListenAddr(e.target.value)}
                  className={inputClass}
                  placeholder="0.0.0.0:53"
                />
                <p className="text-xs text-slate-400 mt-1">
                  The address and port the DNS server will listen on.
                </p>
              </div>
              <div>
                <label htmlFor="metrics-addr" className={labelClass}>
                  Web Dashboard Address
                </label>
                <input
                  id="metrics-addr"
                  type="text"
                  value={metricsAddr}
                  onChange={(e) => setMetricsAddr(e.target.value)}
                  className={inputClass}
                  placeholder="0.0.0.0:9153"
                />
                <p className="text-xs text-slate-400 mt-1">
                  The address and port for the web dashboard and API.
                </p>
              </div>
            </div>
          )}

          {/* Step 4: DNS Settings */}
          {step === 4 && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                DNS Settings
              </h2>
              <p className="text-slate-500 dark:text-slate-400 text-sm">
                Configure DNS resolver behavior.
              </p>
              <div>
                <label htmlFor="cache-size" className={labelClass}>
                  Cache Max Entries
                </label>
                <input
                  id="cache-size"
                  type="number"
                  value={cacheMaxEntries}
                  onChange={(e) => setCacheMaxEntries(Number(e.target.value))}
                  className={inputClass}
                  min={100}
                  max={1000000}
                />
                <p className="text-xs text-slate-400 mt-1">
                  Maximum number of DNS records to keep in cache.
                </p>
              </div>
              <div className="flex items-center justify-between py-2">
                <div>
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
                    QNAME Minimization
                  </p>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Reduces privacy leakage by sending minimal query names to upstream servers.
                  </p>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={qnameMinimization}
                  onClick={() => setQnameMinimization(!qnameMinimization)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors shrink-0 ${
                    qnameMinimization ? 'bg-amber-600' : 'bg-slate-300 dark:bg-slate-600'
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                      qnameMinimization ? 'translate-x-6' : 'translate-x-1'
                    }`}
                  />
                </button>
              </div>
            </div>
          )}

          {/* Step 5: Review */}
          {step === 5 && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                Review
              </h2>
              <p className="text-slate-500 dark:text-slate-400 text-sm">
                Please review your settings before completing setup.
              </p>
              <div className="bg-slate-50 dark:bg-slate-900 rounded-lg p-4 space-y-3 text-sm">
                <h3 className="font-semibold text-slate-700 dark:text-slate-300">
                  Admin Account
                </h3>
                <div className="flex justify-between">
                  <span className="text-slate-500 dark:text-slate-400">Username</span>
                  <span className="text-slate-700 dark:text-slate-300">{adminUsername}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500 dark:text-slate-400">Password</span>
                  <span className="text-slate-700 dark:text-slate-300">{'*'.repeat(adminPassword.length)}</span>
                </div>

                <hr className="border-slate-200 dark:border-slate-700" />

                <h3 className="font-semibold text-slate-700 dark:text-slate-300">
                  Network
                </h3>
                <div className="flex justify-between">
                  <span className="text-slate-500 dark:text-slate-400">DNS Listen</span>
                  <span className="font-mono text-slate-700 dark:text-slate-300">{listenAddr}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500 dark:text-slate-400">Dashboard</span>
                  <span className="font-mono text-slate-700 dark:text-slate-300">{metricsAddr}</span>
                </div>

                <hr className="border-slate-200 dark:border-slate-700" />

                <h3 className="font-semibold text-slate-700 dark:text-slate-300">
                  DNS
                </h3>
                <div className="flex justify-between">
                  <span className="text-slate-500 dark:text-slate-400">Cache Entries</span>
                  <span className="text-slate-700 dark:text-slate-300">{cacheMaxEntries.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500 dark:text-slate-400">QNAME Minimization</span>
                  <span className={qnameMinimization ? 'text-green-600' : 'text-slate-400'}>
                    {qnameMinimization ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Navigation */}
          <div className="flex items-center justify-between mt-6 pt-4 border-t border-slate-200 dark:border-slate-700">
            <button
              type="button"
              onClick={prevStep}
              disabled={step === 1}
              className="flex items-center gap-1 px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft size={16} />
              Back
            </button>

            {step < TOTAL_STEPS ? (
              <button
                type="button"
                onClick={nextStep}
                className="bg-amber-600 hover:bg-amber-700 text-white px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-1 transition-colors"
              >
                Next
                <ChevronRight size={16} />
              </button>
            ) : (
              <button
                type="submit"
                disabled={loading}
                className="bg-amber-600 hover:bg-amber-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-5 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition-colors"
              >
                {loading ? (
                  <Loader2 size={16} className="animate-spin" />
                ) : (
                  <Check size={16} />
                )}
                {loading ? 'Setting up...' : 'Complete Setup'}
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  )
}
