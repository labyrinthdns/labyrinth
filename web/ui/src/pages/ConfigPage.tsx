import { useEffect, useState } from 'react'
import { AlertCircle, CheckCircle2, Code2, Eye, FilePenLine, Loader2, PencilLine, Plus, Save, Trash2 } from 'lucide-react'
import { api } from '@/api/client'

type Mode = 'view' | 'edit'
type EditorMode = 'form' | 'raw'
type StatusType = 'success' | 'error' | 'info'
type BlocklistSource = { url: string; format: string }
type NamedCSV = { name: string; csv: string }
type FormState = {
  server: { listen: string; metrics: string; maxUDP: number; maxTCP: number; tcpTimeout: string; graceful: string }
  resolver: { maxDepth: number; maxCnameDepth: number; qmin: boolean; dnssec: boolean; upstreamTimeout: string; upstreamRetries: number }
  cache: { maxEntries: number; minTTL: number; maxTTL: number; negMaxTTL: number; sweep: string; serveStale: boolean; staleTTL: number; noCacheClients: string[] }
  security: { rateEnabled: boolean; rate: number; burst: number; rrlEnabled: boolean; rrlRPS: number; rrlSlip: number; rrlV4: number; rrlV6: number }
  web: { enabled: boolean; addr: string; doh: boolean; doh3: boolean; tls: boolean; authUser: string; authHash: string }
  logging: { level: string; format: string }
  daemon: { enabled: boolean; pidFile: string }
  zabbix: { enabled: boolean; addr: string }
  acl: { allow: string[]; deny: string[] }
  blocklist: { enabled: boolean; mode: string; refresh: string; whitelist: string[]; sources: BlocklistSource[] }
  cluster: { enabled: boolean; role: string; nodeID: string; sharedFields: string[]; fanoutCacheFlush: boolean; syncMode: string; pushOnSave: boolean; pullInterval: string; peers: string[] }
  localZones: NamedCSV[]
  forwardZones: NamedCSV[]
  stubZones: NamedCSV[]
}

const inputClass =
  'w-full rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-amber-500/50 disabled:opacity-60'
const keyClass = 'text-[11px] font-mono text-slate-500 dark:text-slate-400'

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {})
const str = (v: unknown, d = '') => (typeof v === 'string' ? v : d)
const num = (v: unknown, d = 0) => (typeof v === 'number' ? v : typeof v === 'string' ? Number(v || d) : d)
const boo = (v: unknown, d = false) => (typeof v === 'boolean' ? v : d)
const arr = (v: unknown) => (Array.isArray(v) ? v.map((x) => String(x).trim()).filter(Boolean) : []) as string[]
const csv = (values: string[]) => values.join(', ')
const y = (v: string) => (v === '' ? '""' : /[\s:#{},&*!|>'"%@`]/.test(v) ? JSON.stringify(v) : v)

function hashFromRaw(raw: string): string {
  const m = raw.match(/^\s*password_hash:\s*(.+?)\s*$/m)
  if (!m || !m[1]) return ''
  const v = m[1].trim()
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1)
  return v
}

function mapForm(cfg: Record<string, unknown>, authHash: string): FormState {
  const server = obj(cfg.server)
  const resolver = obj(cfg.resolver)
  const cache = obj(cfg.cache)
  const security = obj(cfg.security)
  const rl = obj(security.rate_limit)
  const rrl = obj(security.rrl)
  const web = obj(cfg.web)
  const auth = obj(web.auth)
  const acl = obj(cfg.acl)
  const blocklist = obj(cfg.blocklist)
  const cluster = obj(cfg.cluster)
  const clusterActions = obj(cluster.actions)
  const clusterSync = obj(cluster.sync)
  const mapNamed = (v: unknown, key = 'addrs'): NamedCSV[] =>
    Array.isArray(v)
      ? v.map((x) => obj(x)).map((x) => ({ name: str(x.name), csv: csv(arr(x[key])) })).filter((x) => x.name)
      : []

  return {
    server: { listen: str(server.listen_addr, ':53'), metrics: str(server.metrics_addr, '127.0.0.1:9153'), maxUDP: num(server.max_udp_size, 4096), maxTCP: num(server.max_tcp_conns, 256), tcpTimeout: str(server.tcp_timeout, '10s'), graceful: str(server.graceful_period, '5s') },
    resolver: { maxDepth: num(resolver.max_depth, 30), maxCnameDepth: num(resolver.max_cname_depth, 10), qmin: boo(resolver.qname_minimization, true), dnssec: boo(resolver.dnssec_enabled, true), upstreamTimeout: str(resolver.upstream_timeout, '2s'), upstreamRetries: num(resolver.upstream_retries, 3) },
    cache: { maxEntries: num(cache.max_entries, 100000), minTTL: num(cache.min_ttl, 5), maxTTL: num(cache.max_ttl, 86400), negMaxTTL: num(cache.negative_max_ttl, 3600), sweep: str(cache.sweep_interval, '60s'), serveStale: boo(cache.serve_stale, false), staleTTL: num(cache.stale_ttl, 30), noCacheClients: arr(cache.no_cache_clients) },
    security: { rateEnabled: boo(rl.enabled, true), rate: num(rl.rate, 50), burst: num(rl.burst, 100), rrlEnabled: boo(rrl.enabled, true), rrlRPS: num(rrl.responses_per_second, 5), rrlSlip: num(rrl.slip_ratio, 2), rrlV4: num(rrl.ipv4_prefix, 24), rrlV6: num(rrl.ipv6_prefix, 56) },
    web: {
      enabled: boo(web.enabled, true),
      addr: str(web.addr, '127.0.0.1:9153'),
      doh: boo(web.doh_enabled, false),
      doh3: boo(web.doh3_enabled, false),
      tls: boo(web.tls_enabled, false),
      authUser: str(auth.username, 'admin'),
      authHash,
    },
    logging: { level: str(obj(cfg.logging).level, 'info'), format: str(obj(cfg.logging).format, 'json') },
    daemon: { enabled: boo(obj(cfg.daemon).enabled, false), pidFile: str(obj(cfg.daemon).pid_file, '/var/run/labyrinth.pid') },
    zabbix: { enabled: boo(obj(cfg.zabbix).enabled, false), addr: str(obj(cfg.zabbix).addr) },
    acl: { allow: arr(acl.allow), deny: arr(acl.deny) },
    blocklist: {
      enabled: boo(blocklist.enabled, false),
      mode: str(blocklist.blocking_mode, 'nxdomain'),
      refresh: str(blocklist.refresh_interval, '24h'),
      whitelist: arr(blocklist.whitelist),
      sources: Array.isArray(blocklist.lists)
        ? blocklist.lists.map((x) => obj(x)).map((x) => ({ url: str(x.url), format: str(x.format) })).filter((x) => x.url)
        : [],
    },
    cluster: {
      enabled: boo(cluster.enabled, false),
      role: str(cluster.role, 'standalone'),
      nodeID: str(cluster.node_id, 'node-1'),
      sharedFields: arr(cluster.shared_fields),
      fanoutCacheFlush: boo(clusterActions.fanout_cache_flush, false),
      syncMode: str(clusterSync.mode, 'off'),
      pushOnSave: boo(clusterSync.push_on_save, false),
      pullInterval: str(clusterSync.pull_interval, '30s'),
      peers: Array.isArray(cluster.peers)
        ? cluster.peers
            .map((p) => obj(p))
            .map((p) => {
              const name = str(p.name)
              const enabled = boo(p.enabled, true)
              const apiBase = str(p.api_base)
              const token = str(p.api_token) && str(p.api_token) !== '***REDACTED***' ? str(p.api_token) : ''
              const syncFields = csv(arr(p.sync_fields))
              return `${name}|${enabled ? 'true' : 'false'}|${apiBase}|${token}|${syncFields}`
            })
            .filter(Boolean)
        : [],
    },
    localZones: mapNamed(cfg.local_zones, 'data'),
    forwardZones: mapNamed(cfg.forward_zones, 'addrs'),
    stubZones: mapNamed(cfg.stub_zones, 'addrs'),
  }
}

function buildYAML(f: FormState): string {
  const L: string[] = []
  L.push('server:')
  L.push(`  listen_addr: ${y(f.server.listen)}`)
  L.push(`  metrics_addr: ${y(f.server.metrics)}`)
  L.push(`  max_udp_size: ${f.server.maxUDP}`)
  L.push(`  tcp_timeout: ${y(f.server.tcpTimeout)}`)
  L.push(`  max_tcp_connections: ${f.server.maxTCP}`)
  L.push(`  graceful_shutdown: ${y(f.server.graceful)}`)
  L.push('')
  L.push('resolver:')
  L.push(`  max_depth: ${f.resolver.maxDepth}`)
  L.push(`  max_cname_depth: ${f.resolver.maxCnameDepth}`)
  L.push(`  upstream_timeout: ${y(f.resolver.upstreamTimeout)}`)
  L.push(`  upstream_retries: ${f.resolver.upstreamRetries}`)
  L.push(`  qname_minimization: ${f.resolver.qmin}`)
  L.push(`  dnssec_enabled: ${f.resolver.dnssec}`)
  L.push('')
  L.push('cache:')
  L.push(`  max_entries: ${f.cache.maxEntries}`)
  L.push(`  min_ttl: ${f.cache.minTTL}`)
  L.push(`  max_ttl: ${f.cache.maxTTL}`)
  L.push(`  negative_max_ttl: ${f.cache.negMaxTTL}`)
  L.push(`  sweep_interval: ${y(f.cache.sweep)}`)
  L.push(`  serve_stale: ${f.cache.serveStale}`)
  L.push(`  serve_stale_ttl: ${f.cache.staleTTL}`)
  if (f.cache.noCacheClients.length) L.push(`  no_cache_clients: ${y(csv(f.cache.noCacheClients))}`)
  L.push('')
  L.push('security:')
  L.push('  rate_limit:')
  L.push(`    enabled: ${f.security.rateEnabled}`)
  L.push(`    rate: ${f.security.rate}`)
  L.push(`    burst: ${f.security.burst}`)
  L.push('  rrl:')
  L.push(`    enabled: ${f.security.rrlEnabled}`)
  L.push(`    responses_per_second: ${f.security.rrlRPS}`)
  L.push(`    slip_ratio: ${f.security.rrlSlip}`)
  L.push(`    ipv4_prefix: ${f.security.rrlV4}`)
  L.push(`    ipv6_prefix: ${f.security.rrlV6}`)
  L.push('')
  L.push('logging:')
  L.push(`  level: ${y(f.logging.level)}`)
  L.push(`  format: ${y(f.logging.format)}`)
  L.push('')
  L.push('web:')
  L.push(`  enabled: ${f.web.enabled}`)
  L.push(`  addr: ${y(f.web.addr)}`)
  L.push(`  doh_enabled: ${f.web.doh}`)
  L.push(`  doh3_enabled: ${f.web.doh3}`)
  L.push(`  tls_enabled: ${f.web.tls}`)
  L.push('  auth:')
  L.push(`    username: ${y(f.web.authUser)}`)
  if (f.web.authHash) L.push(`    password_hash: ${y(f.web.authHash)}`)
  L.push('')
  L.push('daemon:')
  L.push(`  enabled: ${f.daemon.enabled}`)
  L.push(`  pid_file: ${y(f.daemon.pidFile)}`)
  L.push('')
  L.push('zabbix:')
  L.push(`  enabled: ${f.zabbix.enabled}`)
  L.push(`  addr: ${y(f.zabbix.addr)}`)
  L.push('')
  L.push('blocklist:')
  L.push(`  enabled: ${f.blocklist.enabled}`)
  L.push(`  refresh_interval: ${y(f.blocklist.refresh)}`)
  L.push(`  blocking_mode: ${y(f.blocklist.mode)}`)
  if (f.blocklist.whitelist.length) L.push(`  whitelist: ${y(csv(f.blocklist.whitelist))}`)
  if (f.blocklist.sources.length) {
    const packed = f.blocklist.sources.filter((x) => x.url && x.format).map((x) => `${x.url}|${x.format}`).join(', ')
    if (packed) L.push(`  lists: ${y(packed)}`)
  }
  L.push('')
  L.push('cluster:')
  L.push(`  enabled: ${f.cluster.enabled}`)
  L.push(`  role: ${y(f.cluster.role)}`)
  L.push(`  node_id: ${y(f.cluster.nodeID)}`)
  if (f.cluster.sharedFields.length) L.push(`  shared_fields: ${y(csv(f.cluster.sharedFields))}`)
  L.push('  actions:')
  L.push(`    fanout_cache_flush: ${f.cluster.fanoutCacheFlush}`)
  L.push('  sync:')
  L.push(`    mode: ${y(f.cluster.syncMode)}`)
  L.push(`    push_on_save: ${f.cluster.pushOnSave}`)
  L.push(`    pull_interval: ${y(f.cluster.pullInterval)}`)
  if (f.cluster.peers.length) {
    L.push('  peers:')
    f.cluster.peers.forEach((line) => {
      const [nameRaw, enabledRaw, apiBaseRaw, tokenRaw, syncFieldsRaw] = line.split('|')
      const name = (nameRaw || '').trim()
      if (!name) return
      const enabled = (enabledRaw || '').trim().toLowerCase() !== 'false'
      const apiBase = (apiBaseRaw || '').trim()
      const token = (tokenRaw || '').trim()
      const syncFields = (syncFieldsRaw || '').trim()
      L.push(`    ${y(name)}:`)
      L.push(`      enabled: ${enabled}`)
      if (apiBase) L.push(`      api_base: ${y(apiBase)}`)
      if (token) L.push(`      api_token: ${y(token)}`)
      if (syncFields) L.push(`      sync_fields: ${y(syncFields)}`)
    })
  }
  L.push('')
  L.push('access_control:')
  L.push(`  allow: ${y(csv(f.acl.allow))}`)
  L.push(`  deny: ${y(csv(f.acl.deny))}`)

  const pushNamed = (name: string, items: NamedCSV[]) => {
    if (!items.length) return
    L.push('')
    L.push(`${name}:`)
    items.filter((z) => z.name).forEach((z) => {
      L.push(`  ${y(z.name)}:`)
      L.push(`    addrs: ${y(z.csv)}`)
    })
  }
  pushNamed('forward_zones', f.forwardZones)
  pushNamed('stub_zones', f.stubZones)
  if (f.localZones.length) {
    L.push('')
    L.push('local_zones:')
    f.localZones.filter((z) => z.name).forEach((z) => {
      L.push(`  ${y(z.name)}:`)
      L.push('    type: static')
      if (z.csv) L.push(`    data: ${y(z.csv)}`)
    })
  }
  return `${L.join('\n').trim()}\n`
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm p-4 space-y-3">
      <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{title}</h2>
      {children}
    </div>
  )
}

function StringList({
  title, path, values, onChange, disabled, placeholder,
}: { title: string; path: string; values: string[]; onChange: (v: string[]) => void; disabled: boolean; placeholder: string }) {
  return (
    <div className="space-y-1.5">
      <div className="text-xs font-medium text-slate-700 dark:text-slate-200">{title}</div>
      <div className={keyClass}>{path}</div>
      {values.map((v, i) => (
        <div className="flex gap-2" key={`${title}-${i}`}>
          <input className={inputClass} value={v} placeholder={placeholder} disabled={disabled} onChange={(e) => { const n = [...values]; n[i] = e.target.value; onChange(n) }} />
          {!disabled && <button type="button" className="p-2 border rounded-lg" onClick={() => onChange(values.filter((_, idx) => idx !== i))}><Trash2 size={14} /></button>}
        </div>
      ))}
      {!disabled && <button type="button" className="text-xs inline-flex items-center gap-1 text-amber-700 dark:text-amber-300" onClick={() => onChange([...values, ''])}><Plus size={13} />Add</button>}
    </div>
  )
}

export default function ConfigPage() {
  const [mode, setMode] = useState<Mode>('view')
  const [editorMode, setEditorMode] = useState<EditorMode>('form')
  const [form, setForm] = useState<FormState | null>(null)
  const [rawPath, setRawPath] = useState('')
  const [rawContent, setRawContent] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('')
  const [statusType, setStatusType] = useState<StatusType>('info')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const [cfg, raw] = await Promise.all([api.config(), api.configRaw()])
      setForm(mapForm(cfg, hashFromRaw(raw.content)))
      setRawPath(raw.path)
      setRawContent(raw.content)
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to load config')
      setStatusType('error')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { void load() }, [])

  const patch = (fn: (v: FormState) => FormState) => setForm((v) => (v ? fn(v) : v))
  const readonly = mode === 'view'

  const validateConfig = async () => {
    if (!form) return
    setBusy(true)
    try {
      const res = await api.validateConfig(buildYAML(form))
      setStatus(res.valid ? 'Validation successful' : res.error || 'Validation failed')
      setStatusType(res.valid ? 'success' : 'error')
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Validation failed')
      setStatusType('error')
    } finally {
      setBusy(false)
    }
  }

  const saveConfig = async () => {
    if (!form) return
    setBusy(true)
    try {
      await api.saveConfig(buildYAML(form))
      setStatus('Config saved. Restart recommended.')
      setStatusType('success')
      setMode('view')
      await load()
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Save failed')
      setStatusType('error')
    } finally {
      setBusy(false)
    }
  }

  const validateRawConfig = async () => {
    setBusy(true)
    try {
      const res = await api.validateConfig(rawContent)
      setStatus(res.valid ? 'Raw YAML validation successful' : res.error || 'Raw YAML validation failed')
      setStatusType(res.valid ? 'success' : 'error')
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Raw YAML validation failed')
      setStatusType('error')
    } finally {
      setBusy(false)
    }
  }

  const saveRawConfig = async () => {
    setBusy(true)
    try {
      await api.saveConfig(rawContent)
      setStatus('Raw YAML saved. Restart recommended.')
      setStatusType('success')
      await load()
      setMode('view')
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Raw YAML save failed')
      setStatusType('error')
    } finally {
      setBusy(false)
    }
  }

  const changePassword = async () => {
    if (!currentPassword || !newPassword) return
    if (newPassword !== confirmPassword) {
      setStatus('New password and confirmation do not match')
      setStatusType('error')
      return
    }
    setBusy(true)
    try {
      await api.changePassword(currentPassword, newPassword)
      setStatus('Password changed successfully')
      setStatusType('success')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      await load()
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Password change failed')
      setStatusType('error')
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <div className="flex items-center justify-center h-64"><Loader2 size={24} className="animate-spin text-amber-600" /></div>
  if (!form) return <div className="text-sm text-red-600">Config unavailable</div>

  const statusClass =
    statusType === 'success'
      ? 'bg-green-50 dark:bg-green-900/30 border-green-200 dark:border-green-800 text-green-700 dark:text-green-400'
      : statusType === 'error'
        ? 'bg-red-50 dark:bg-red-900/30 border-red-200 dark:border-red-800 text-red-700 dark:text-red-400'
        : 'bg-amber-50 dark:bg-amber-900/30 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-400'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Configuration</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">{readonly ? 'View mode' : 'Edit mode'} - form mode for quick edits, raw mode for full YAML.</p>
        </div>
        <div className="flex items-center gap-2">
          <button type="button" className={`px-3 py-2 rounded-lg border text-sm inline-flex items-center gap-1 ${readonly ? 'border-amber-300 text-amber-700' : 'border-slate-300'}`} onClick={() => setMode('view')}><Eye size={14} />View</button>
          <button type="button" className={`px-3 py-2 rounded-lg border text-sm inline-flex items-center gap-1 ${!readonly ? 'border-amber-300 text-amber-700' : 'border-slate-300'}`} onClick={() => setMode('edit')}><PencilLine size={14} />Edit</button>
          <button
            type="button"
            className={`px-3 py-2 rounded-lg border text-sm inline-flex items-center gap-1 ${editorMode === 'form' ? 'border-amber-300 text-amber-700' : 'border-slate-300'}`}
            onClick={() => setEditorMode('form')}
          >
            <FilePenLine size={14} />
            Form
          </button>
          <button
            type="button"
            className={`px-3 py-2 rounded-lg border text-sm inline-flex items-center gap-1 ${editorMode === 'raw' ? 'border-amber-300 text-amber-700' : 'border-slate-300'}`}
            onClick={() => setEditorMode('raw')}
          >
            <Code2 size={14} />
            Raw YAML
          </button>
          {!readonly && editorMode === 'form' && <button type="button" className="px-3 py-2 rounded-lg border border-amber-300 text-amber-700 text-sm" onClick={validateConfig} disabled={busy}>Validate</button>}
          {!readonly && editorMode === 'form' && <button type="button" className="px-4 py-2 rounded-lg bg-amber-600 text-white text-sm inline-flex items-center gap-1" onClick={saveConfig} disabled={busy}>{busy ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}Save</button>}
          {!readonly && editorMode === 'raw' && <button type="button" className="px-3 py-2 rounded-lg border border-amber-300 text-amber-700 text-sm" onClick={validateRawConfig} disabled={busy}>Validate Raw</button>}
          {!readonly && editorMode === 'raw' && <button type="button" className="px-4 py-2 rounded-lg bg-amber-600 text-white text-sm inline-flex items-center gap-1" onClick={saveRawConfig} disabled={busy}>{busy ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}Save Raw</button>}
        </div>
      </div>

      {status && <div className={`text-sm rounded-lg border px-4 py-3 flex items-start gap-2 ${statusClass}`}>{statusType === 'success' ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}<span>{status}</span></div>}

      {editorMode === 'raw' && (
        <Section title="Full YAML Editor">
          <div className="space-y-2">
            <div className="text-xs text-slate-500 dark:text-slate-400">File: {rawPath || 'labyrinth.yaml'}</div>
            <div className={keyClass}>All keys from YAML are editable in this mode. `web.auth.password_hash` is locked and must be changed from Change Password.</div>
            <textarea
              className={`${inputClass} min-h-[520px] font-mono text-xs`}
              value={rawContent}
              disabled={readonly}
              onChange={(e) => setRawContent(e.target.value)}
            />
            {!readonly && (
              <div className="flex items-center gap-2">
                <button type="button" className="px-3 py-2 rounded-lg border border-slate-300 text-sm" onClick={validateRawConfig} disabled={busy}>Validate Raw</button>
                <button type="button" className="px-3 py-2 rounded-lg bg-amber-600 text-white text-sm" onClick={saveRawConfig} disabled={busy}>Save Raw</button>
                <button type="button" className="px-3 py-2 rounded-lg border border-slate-300 text-sm" onClick={() => { void load() }} disabled={busy}>Reload From Disk</button>
              </div>
            )}
          </div>
        </Section>
      )}

      {editorMode === 'form' && (
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <Section title="Core">
          <label className="text-xs font-medium">Listen Address<div className={keyClass}>server.listen_addr</div><input className={inputClass} disabled={readonly} value={form.server.listen} onChange={(e) => patch((p) => ({ ...p, server: { ...p.server, listen: e.target.value } }))} /></label>
          <label className="text-xs font-medium">Metrics Address<div className={keyClass}>server.metrics_addr</div><input className={inputClass} disabled={readonly} value={form.server.metrics} onChange={(e) => patch((p) => ({ ...p, server: { ...p.server, metrics: e.target.value } }))} /></label>
          <div className="grid grid-cols-2 gap-2">
            <label className="text-xs font-medium">Max Depth<div className={keyClass}>resolver.max_depth</div><input type="number" className={inputClass} disabled={readonly} value={form.resolver.maxDepth} onChange={(e) => patch((p) => ({ ...p, resolver: { ...p.resolver, maxDepth: Number(e.target.value || 0) } }))} /></label>
            <label className="text-xs font-medium">Cache Entries<div className={keyClass}>cache.max_entries</div><input type="number" className={inputClass} disabled={readonly} value={form.cache.maxEntries} onChange={(e) => patch((p) => ({ ...p, cache: { ...p.cache, maxEntries: Number(e.target.value || 0) } }))} /></label>
          </div>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={readonly} checked={form.resolver.qmin} onChange={(e) => patch((p) => ({ ...p, resolver: { ...p.resolver, qmin: e.target.checked } }))} />QNAME Minimization</label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={readonly} checked={form.resolver.dnssec} onChange={(e) => patch((p) => ({ ...p, resolver: { ...p.resolver, dnssec: e.target.checked } }))} />DNSSEC</label>
          <StringList title="No Cache Clients" path="cache.no_cache_clients" values={form.cache.noCacheClients} onChange={(next) => patch((p) => ({ ...p, cache: { ...p.cache, noCacheClients: next } }))} disabled={readonly} placeholder="192.168.1.0/24" />
        </Section>

        <Section title="Web + Auth">
          <label className="text-xs font-medium">Web Address<div className={keyClass}>web.addr</div><input className={inputClass} disabled={readonly} value={form.web.addr} onChange={(e) => patch((p) => ({ ...p, web: { ...p.web, addr: e.target.value } }))} /></label>
          <label className="text-xs font-medium">Admin Username<div className={keyClass}>web.auth.username</div><input className={inputClass} disabled={readonly} value={form.web.authUser} onChange={(e) => patch((p) => ({ ...p, web: { ...p.web, authUser: e.target.value } }))} /></label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={readonly} checked={form.web.enabled} onChange={(e) => patch((p) => ({ ...p, web: { ...p.web, enabled: e.target.checked } }))} />Web Enabled</label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={readonly} checked={form.web.doh} onChange={(e) => patch((p) => ({ ...p, web: { ...p.web, doh: e.target.checked } }))} />DoH Enabled (HTTP/1.1+2)</label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={readonly} checked={form.web.doh3} onChange={(e) => patch((p) => ({ ...p, web: { ...p.web, doh3: e.target.checked } }))} />DoH Enabled (HTTP/3)</label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={readonly} checked={form.web.tls} onChange={(e) => patch((p) => ({ ...p, web: { ...p.web, tls: e.target.checked } }))} />Web TLS Enabled</label>
          <div className="text-xs text-slate-500 dark:text-slate-400">
            HTTP/3 requires <code>web.tls_enabled</code> and valid <code>web.tls_cert_file</code>/<code>web.tls_key_file</code> in YAML.
          </div>
        </Section>

        <Section title="Security + ACL + Blocklist">
          <div className="grid grid-cols-3 gap-2">
            <label className="text-xs font-medium">Rate<div className={keyClass}>security.rate_limit.rate</div><input type="number" className={inputClass} disabled={readonly} value={form.security.rate} onChange={(e) => patch((p) => ({ ...p, security: { ...p.security, rate: Number(e.target.value || 0) } }))} /></label>
            <label className="text-xs font-medium">Burst<div className={keyClass}>security.rate_limit.burst</div><input type="number" className={inputClass} disabled={readonly} value={form.security.burst} onChange={(e) => patch((p) => ({ ...p, security: { ...p.security, burst: Number(e.target.value || 0) } }))} /></label>
            <label className="flex items-center gap-2 text-sm mt-5"><input type="checkbox" disabled={readonly} checked={form.security.rateEnabled} onChange={(e) => patch((p) => ({ ...p, security: { ...p.security, rateEnabled: e.target.checked } }))} />Enabled</label>
          </div>
          <StringList title="ACL Allow" path="access_control.allow" values={form.acl.allow} onChange={(next) => patch((p) => ({ ...p, acl: { ...p.acl, allow: next } }))} disabled={readonly} placeholder="10.0.0.0/8" />
          <StringList title="ACL Deny" path="access_control.deny" values={form.acl.deny} onChange={(next) => patch((p) => ({ ...p, acl: { ...p.acl, deny: next } }))} disabled={readonly} placeholder="0.0.0.0/0" />
          <StringList title="Blocklist Whitelist" path="blocklist.whitelist" values={form.blocklist.whitelist} onChange={(next) => patch((p) => ({ ...p, blocklist: { ...p.blocklist, whitelist: next } }))} disabled={readonly} placeholder="example.com" />
          <StringList
            title="Blocklist Sources"
            path="blocklist.lists (url|format)"
            values={form.blocklist.sources.map((s) => `${s.url}|${s.format}`)}
            onChange={(next) =>
              patch((p) => ({
                ...p,
                blocklist: {
                  ...p.blocklist,
                  sources: next
                    .map((line) => {
                      const [url, format] = line.split('|')
                      return { url: (url || '').trim(), format: (format || '').trim() || 'hosts' }
                    })
                    .filter((x) => x.url),
                },
              }))
            }
            disabled={readonly}
            placeholder="https://example.com/list.txt|hosts"
          />
        </Section>

        <Section title="Cluster Sync">
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={readonly} checked={form.cluster.enabled} onChange={(e) => patch((p) => ({ ...p, cluster: { ...p.cluster, enabled: e.target.checked } }))} />Cluster Enabled</label>
          <label className="text-xs font-medium">Role<div className={keyClass}>cluster.role</div><input className={inputClass} disabled={readonly} value={form.cluster.role} onChange={(e) => patch((p) => ({ ...p, cluster: { ...p.cluster, role: e.target.value } }))} /></label>
          <label className="text-xs font-medium">Node ID<div className={keyClass}>cluster.node_id</div><input className={inputClass} disabled={readonly} value={form.cluster.nodeID} onChange={(e) => patch((p) => ({ ...p, cluster: { ...p.cluster, nodeID: e.target.value } }))} /></label>
          <StringList title="Shared Fields (CSV entries)" path="cluster.shared_fields" values={form.cluster.sharedFields} onChange={(next) => patch((p) => ({ ...p, cluster: { ...p.cluster, sharedFields: next } }))} disabled={readonly} placeholder="access_control" />
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={readonly} checked={form.cluster.fanoutCacheFlush} onChange={(e) => patch((p) => ({ ...p, cluster: { ...p.cluster, fanoutCacheFlush: e.target.checked } }))} />Fanout Cache Flush</label>
          <label className="text-xs font-medium">Sync Mode<div className={keyClass}>cluster.sync.mode</div><input className={inputClass} disabled={readonly} value={form.cluster.syncMode} onChange={(e) => patch((p) => ({ ...p, cluster: { ...p.cluster, syncMode: e.target.value } }))} /></label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={readonly} checked={form.cluster.pushOnSave} onChange={(e) => patch((p) => ({ ...p, cluster: { ...p.cluster, pushOnSave: e.target.checked } }))} />Push On Save</label>
          <label className="text-xs font-medium">Pull Interval<div className={keyClass}>cluster.sync.pull_interval</div><input className={inputClass} disabled={readonly} value={form.cluster.pullInterval} onChange={(e) => patch((p) => ({ ...p, cluster: { ...p.cluster, pullInterval: e.target.value } }))} /></label>
          <StringList
            title="Peers (name|enabled|api_base|api_token|sync_fields_csv)"
            path="cluster.peers.*"
            values={form.cluster.peers}
            onChange={(next) => patch((p) => ({ ...p, cluster: { ...p.cluster, peers: next } }))}
            disabled={readonly}
            placeholder="dns-2|true|http://10.0.0.2:9153|TOKEN|access_control,blocklist"
          />
        </Section>

        <Section title="Zone Maps">
          <StringList title="Local Zones (name=records CSV)" path="local_zones" values={form.localZones.map((z) => `${z.name}=${z.csv}`)} onChange={(next) => patch((p) => ({ ...p, localZones: next.map((v) => { const [name, ...rest] = v.split('='); return { name: name.trim(), csv: rest.join('=').trim() } }) }))} disabled={readonly} placeholder="corp.local=host1 A 10.0.0.1" />
          <StringList title="Forward Zones (name=addr CSV)" path="forward_zones" values={form.forwardZones.map((z) => `${z.name}=${z.csv}`)} onChange={(next) => patch((p) => ({ ...p, forwardZones: next.map((v) => { const [name, ...rest] = v.split('='); return { name: name.trim(), csv: rest.join('=').trim() } }) }))} disabled={readonly} placeholder="example.com=1.1.1.1, 9.9.9.9" />
          <StringList title="Stub Zones (name=addr CSV)" path="stub_zones" values={form.stubZones.map((z) => `${z.name}=${z.csv}`)} onChange={(next) => patch((p) => ({ ...p, stubZones: next.map((v) => { const [name, ...rest] = v.split('='); return { name: name.trim(), csv: rest.join('=').trim() } }) }))} disabled={readonly} placeholder="internal=10.0.0.53" />
        </Section>

        <Section title="Password">
          <label className="text-xs font-medium">Current Password<input type="password" className={inputClass} value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} /></label>
          <label className="text-xs font-medium">New Password<input type="password" className={inputClass} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} /></label>
          <label className="text-xs font-medium">Confirm<input type="password" className={inputClass} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} /></label>
          <button type="button" className="px-4 py-2 rounded-lg border text-sm" onClick={changePassword} disabled={busy}>Change Password</button>
        </Section>
      </div>
      )}
    </div>
  )
}
