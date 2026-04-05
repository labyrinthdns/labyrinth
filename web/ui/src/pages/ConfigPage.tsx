import { useEffect, useState } from 'react'
import { AlertCircle, CheckCircle2, Code2, Eye, FilePenLine, Loader2, PencilLine, Plus, Save, Trash2 } from 'lucide-react'
import { api } from '@/api/client'

type Mode = 'view' | 'edit'
type EditorMode = 'form' | 'raw'
type StatusType = 'success' | 'error' | 'info'
type BlocklistSource = { url: string; format: string }
type NamedCSV = { name: string; csv: string }

type FormState = {
  server: {
    listen: string; metrics: string; maxUDP: number; tcpTimeout: string; maxTCP: number
    maxUDPWorkers: number; graceful: string; tcpPipelineMax: number; tcpIdleTimeout: string
    dotEnabled: boolean; dotListenAddr: string; tlsCertFile: string; tlsKeyFile: string
  }
  resolver: {
    maxDepth: number; maxCnameDepth: number; upstreamTimeout: string; upstreamRetries: number
    qmin: boolean; preferIPv4: boolean; dnssec: boolean; hardenBelowNX: boolean
    rootHintsRefresh: string; ecsEnabled: boolean; ecsMaxPrefix: number
    dns64Enabled: boolean; dns64Prefix: string; fallbackResolvers: string[]
  }
  cache: {
    maxEntries: number; minTTL: number; maxTTL: number; negMaxTTL: number
    sweep: string; serveStale: boolean; staleTTL: number; prefetch: boolean
    noCacheClients: string[]
  }
  security: {
    privateAddrFilter: boolean; dnsCookies: boolean
    rateEnabled: boolean; rate: number; burst: number
    rrlEnabled: boolean; rrlRPS: number; rrlSlip: number; rrlV4: number; rrlV6: number
  }
  web: {
    enabled: boolean; addr: string; doh: boolean; doh3: boolean
    tlsEnabled: boolean; tlsCertFile: string; tlsKeyFile: string
    autoTLS: boolean; autoTLSDomain: string; autoTLSEmail: string; autoTLSCacheDir: string; autoTLSStaging: boolean
    authUser: string; authHash: string
    dashPanelOrder: string[]; dashHiddenPanels: string[]
    queryLogBuffer: number; topClientsLimit: number; topDomainsLimit: number
    alertErrorThresholdPct: number; alertLatencyThresholdMs: number
    autoUpdate: boolean; updateCheckInterval: string
  }
  logging: { level: string; format: string }
  daemon: { enabled: boolean; pidFile: string }
  zabbix: { enabled: boolean; addr: string }
  acl: { allow: string[]; deny: string[] }
  blocklist: {
    enabled: boolean; mode: string; customIP: string; refresh: string
    whitelist: string[]; sources: BlocklistSource[]
  }
  cluster: {
    enabled: boolean; role: string; nodeID: string; sharedFields: string[]
    fanoutCacheFlush: boolean; fanoutBlocklistRefresh: boolean
    syncMode: string; pushOnSave: boolean; pullInterval: string; peers: string[]
  }
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
  const dash = obj(web.dashboard)
  const acl = obj(cfg.acl)
  const blocklist = obj(cfg.blocklist)
  const cluster = obj(cfg.cluster)
  const clusterActions = obj(cluster.actions)
  const clusterSync = obj(cluster.sync)
  const mapNamed = (v: unknown, key = 'addrs'): NamedCSV[] =>
    Array.isArray(v) ? v.map((x) => obj(x)).map((x) => ({ name: str(x.name), csv: csv(arr(x[key])) })).filter((x) => x.name) : []

  return {
    server: {
      listen: str(server.listen_addr, ':53'), metrics: str(server.metrics_addr, '127.0.0.1:9153'),
      maxUDP: num(server.max_udp_size, 4096), tcpTimeout: str(server.tcp_timeout, '10s'),
      maxTCP: num(server.max_tcp_conns, 256), maxUDPWorkers: num(server.max_udp_workers, 0),
      graceful: str(server.graceful_period, '5s'), tcpPipelineMax: num(server.tcp_pipeline_max, 0),
      tcpIdleTimeout: str(server.tcp_idle_timeout, '10s'),
      dotEnabled: boo(server.dot_enabled), dotListenAddr: str(server.dot_listen_addr),
      tlsCertFile: str(server.tls_cert_file), tlsKeyFile: str(server.tls_key_file),
    },
    resolver: {
      maxDepth: num(resolver.max_depth, 30), maxCnameDepth: num(resolver.max_cname_depth, 10),
      upstreamTimeout: str(resolver.upstream_timeout, '2s'), upstreamRetries: num(resolver.upstream_retries, 3),
      qmin: boo(resolver.qname_minimization, true), preferIPv4: boo(resolver.prefer_ipv4, true),
      dnssec: boo(resolver.dnssec_enabled, true), hardenBelowNX: boo(resolver.harden_below_nxdomain),
      rootHintsRefresh: str(resolver.root_hints_refresh, '168h'),
      ecsEnabled: boo(resolver.ecs_enabled), ecsMaxPrefix: num(resolver.ecs_max_prefix, 24),
      dns64Enabled: boo(resolver.dns64_enabled), dns64Prefix: str(resolver.dns64_prefix),
      fallbackResolvers: arr(resolver.fallback_resolvers),
    },
    cache: {
      maxEntries: num(cache.max_entries, 100000), minTTL: num(cache.min_ttl, 5),
      maxTTL: num(cache.max_ttl, 86400), negMaxTTL: num(cache.negative_max_ttl, 3600),
      sweep: str(cache.sweep_interval, '60s'), serveStale: boo(cache.serve_stale),
      staleTTL: num(cache.stale_ttl, 30), prefetch: boo(cache.prefetch),
      noCacheClients: arr(cache.no_cache_clients),
    },
    security: {
      privateAddrFilter: boo(security.private_address_filter), dnsCookies: boo(security.dns_cookies),
      rateEnabled: boo(rl.enabled, true), rate: num(rl.rate, 50), burst: num(rl.burst, 100),
      rrlEnabled: boo(rrl.enabled, true), rrlRPS: num(rrl.responses_per_second, 5),
      rrlSlip: num(rrl.slip_ratio, 2), rrlV4: num(rrl.ipv4_prefix, 24), rrlV6: num(rrl.ipv6_prefix, 56),
    },
    web: {
      enabled: boo(web.enabled, true), addr: str(web.addr, '127.0.0.1:9153'),
      doh: boo(web.doh_enabled), doh3: boo(web.doh3_enabled),
      tlsEnabled: boo(web.tls_enabled), tlsCertFile: str(web.tls_cert_file), tlsKeyFile: str(web.tls_key_file),
      autoTLS: boo(web.auto_tls), autoTLSDomain: str(web.auto_tls_domain), autoTLSEmail: str(web.auto_tls_email),
      autoTLSCacheDir: str(web.auto_tls_cache_dir, 'certs'), autoTLSStaging: boo(web.auto_tls_staging),
      authUser: str(auth.username, 'admin'), authHash,
      dashPanelOrder: arr(dash.panel_order), dashHiddenPanels: arr(dash.hidden_panels),
      queryLogBuffer: num(web.query_log_buffer, 300), topClientsLimit: num(web.top_clients_limit, 2000),
      topDomainsLimit: num(web.top_domains_limit, 2000),
      alertErrorThresholdPct: num(web.alert_error_threshold_pct, 5), alertLatencyThresholdMs: num(web.alert_latency_threshold_ms, 250),
      autoUpdate: boo(web.auto_update), updateCheckInterval: str(web.update_check_interval, '24h'),
    },
    logging: { level: str(obj(cfg.logging).level, 'info'), format: str(obj(cfg.logging).format, 'json') },
    daemon: { enabled: boo(obj(cfg.daemon).enabled), pidFile: str(obj(cfg.daemon).pid_file, '/var/run/labyrinth.pid') },
    zabbix: { enabled: boo(obj(cfg.zabbix).enabled), addr: str(obj(cfg.zabbix).addr) },
    acl: { allow: arr(acl.allow), deny: arr(acl.deny) },
    blocklist: {
      enabled: boo(blocklist.enabled), mode: str(blocklist.blocking_mode, 'nxdomain'),
      customIP: str(blocklist.custom_ip), refresh: str(blocklist.refresh_interval, '24h'),
      whitelist: arr(blocklist.whitelist),
      sources: Array.isArray(blocklist.lists)
        ? blocklist.lists.map((x) => obj(x)).map((x) => ({ url: str(x.url), format: str(x.format) })).filter((x) => x.url)
        : [],
    },
    cluster: {
      enabled: boo(cluster.enabled), role: str(cluster.role, 'standalone'), nodeID: str(cluster.node_id, 'node-1'),
      sharedFields: arr(cluster.shared_fields),
      fanoutCacheFlush: boo(clusterActions.fanout_cache_flush),
      fanoutBlocklistRefresh: boo(clusterActions.fanout_blocklist_refresh),
      syncMode: str(clusterSync.mode, 'off'), pushOnSave: boo(clusterSync.push_on_save),
      pullInterval: str(clusterSync.pull_interval, '30s'),
      peers: Array.isArray(cluster.peers)
        ? cluster.peers.map((p) => obj(p)).map((p) => {
            const name = str(p.name); const enabled = boo(p.enabled, true)
            const apiBase = str(p.api_base)
            const token = str(p.api_token) && str(p.api_token) !== '***REDACTED***' ? str(p.api_token) : ''
            const syncFields = csv(arr(p.sync_fields))
            return `${name}|${enabled ? 'true' : 'false'}|${apiBase}|${token}|${syncFields}`
          }).filter(Boolean)
        : [],
    },
    localZones: mapNamed(cfg.local_zones, 'data'),
    forwardZones: mapNamed(cfg.forward_zones, 'addrs'),
    stubZones: mapNamed(cfg.stub_zones, 'addrs'),
  }
}

function buildYAML(f: FormState): string {
  const L: string[] = []
  // Server
  L.push('server:')
  L.push(`  listen_addr: ${y(f.server.listen)}`)
  L.push(`  metrics_addr: ${y(f.server.metrics)}`)
  L.push(`  max_udp_size: ${f.server.maxUDP}`)
  L.push(`  tcp_timeout: ${y(f.server.tcpTimeout)}`)
  L.push(`  max_tcp_connections: ${f.server.maxTCP}`)
  if (f.server.maxUDPWorkers) L.push(`  max_udp_workers: ${f.server.maxUDPWorkers}`)
  L.push(`  graceful_shutdown: ${y(f.server.graceful)}`)
  if (f.server.tcpPipelineMax) L.push(`  tcp_pipeline_max: ${f.server.tcpPipelineMax}`)
  L.push(`  tcp_idle_timeout: ${y(f.server.tcpIdleTimeout)}`)
  L.push(`  dot_enabled: ${f.server.dotEnabled}`)
  if (f.server.dotEnabled || f.server.dotListenAddr) L.push(`  dot_listen_addr: ${y(f.server.dotListenAddr)}`)
  if (f.server.tlsCertFile) L.push(`  tls_cert_file: ${y(f.server.tlsCertFile)}`)
  if (f.server.tlsKeyFile) L.push(`  tls_key_file: ${y(f.server.tlsKeyFile)}`)
  L.push('')

  // Resolver
  L.push('resolver:')
  L.push(`  max_depth: ${f.resolver.maxDepth}`)
  L.push(`  max_cname_depth: ${f.resolver.maxCnameDepth}`)
  L.push(`  upstream_timeout: ${y(f.resolver.upstreamTimeout)}`)
  L.push(`  upstream_retries: ${f.resolver.upstreamRetries}`)
  L.push(`  qname_minimization: ${f.resolver.qmin}`)
  L.push(`  prefer_ipv4: ${f.resolver.preferIPv4}`)
  L.push(`  dnssec_enabled: ${f.resolver.dnssec}`)
  L.push(`  harden_below_nxdomain: ${f.resolver.hardenBelowNX}`)
  L.push(`  root_hints_refresh: ${y(f.resolver.rootHintsRefresh)}`)
  L.push(`  ecs_enabled: ${f.resolver.ecsEnabled}`)
  if (f.resolver.ecsEnabled) L.push(`  ecs_max_prefix: ${f.resolver.ecsMaxPrefix}`)
  L.push(`  dns64_enabled: ${f.resolver.dns64Enabled}`)
  if (f.resolver.dns64Enabled && f.resolver.dns64Prefix) L.push(`  dns64_prefix: ${y(f.resolver.dns64Prefix)}`)
  if (f.resolver.fallbackResolvers.length) L.push(`  fallback_resolvers: ${y(csv(f.resolver.fallbackResolvers))}`)
  L.push('')

  // Cache
  L.push('cache:')
  L.push(`  max_entries: ${f.cache.maxEntries}`)
  L.push(`  min_ttl: ${f.cache.minTTL}`)
  L.push(`  max_ttl: ${f.cache.maxTTL}`)
  L.push(`  negative_max_ttl: ${f.cache.negMaxTTL}`)
  L.push(`  sweep_interval: ${y(f.cache.sweep)}`)
  L.push(`  serve_stale: ${f.cache.serveStale}`)
  L.push(`  serve_stale_ttl: ${f.cache.staleTTL}`)
  L.push(`  prefetch: ${f.cache.prefetch}`)
  if (f.cache.noCacheClients.length) L.push(`  no_cache_clients: ${y(csv(f.cache.noCacheClients))}`)
  L.push('')

  // Security
  L.push('security:')
  L.push(`  private_address_filter: ${f.security.privateAddrFilter}`)
  L.push(`  dns_cookies: ${f.security.dnsCookies}`)
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

  // Logging
  L.push('logging:')
  L.push(`  level: ${y(f.logging.level)}`)
  L.push(`  format: ${y(f.logging.format)}`)
  L.push('')

  // Web
  L.push('web:')
  L.push(`  enabled: ${f.web.enabled}`)
  L.push(`  addr: ${y(f.web.addr)}`)
  L.push(`  query_log_buffer: ${f.web.queryLogBuffer}`)
  L.push(`  top_clients_limit: ${f.web.topClientsLimit}`)
  L.push(`  top_domains_limit: ${f.web.topDomainsLimit}`)
  L.push(`  doh_enabled: ${f.web.doh}`)
  L.push(`  doh3_enabled: ${f.web.doh3}`)
  L.push(`  tls_enabled: ${f.web.tlsEnabled}`)
  if (f.web.tlsCertFile) L.push(`  tls_cert_file: ${y(f.web.tlsCertFile)}`)
  if (f.web.tlsKeyFile) L.push(`  tls_key_file: ${y(f.web.tlsKeyFile)}`)
  L.push(`  auto_tls: ${f.web.autoTLS}`)
  if (f.web.autoTLSDomain) L.push(`  auto_tls_domain: ${y(f.web.autoTLSDomain)}`)
  if (f.web.autoTLSEmail) L.push(`  auto_tls_email: ${y(f.web.autoTLSEmail)}`)
  if (f.web.autoTLSCacheDir) L.push(`  auto_tls_cache_dir: ${y(f.web.autoTLSCacheDir)}`)
  if (f.web.autoTLSStaging) L.push(`  auto_tls_staging: true`)
  L.push(`  alert_error_threshold_pct: ${f.web.alertErrorThresholdPct}`)
  L.push(`  alert_latency_threshold_ms: ${f.web.alertLatencyThresholdMs}`)
  L.push(`  auto_update: ${f.web.autoUpdate}`)
  L.push(`  update_check_interval: ${y(f.web.updateCheckInterval)}`)
  L.push('  auth:')
  L.push(`    username: ${y(f.web.authUser)}`)
  if (f.web.authHash) L.push(`    password_hash: ${y(f.web.authHash)}`)
  L.push('  dashboard:')
  L.push(`    panel_order: ${f.web.dashPanelOrder.length ? y(csv(f.web.dashPanelOrder)) : '""'}`)
  L.push(`    hidden_panels: ${f.web.dashHiddenPanels.length ? y(csv(f.web.dashHiddenPanels)) : '""'}`)
  L.push('')

  // Daemon
  L.push('daemon:')
  L.push(`  enabled: ${f.daemon.enabled}`)
  L.push(`  pid_file: ${y(f.daemon.pidFile)}`)
  L.push('')

  // Zabbix
  L.push('zabbix:')
  L.push(`  enabled: ${f.zabbix.enabled}`)
  if (f.zabbix.addr) L.push(`  addr: ${y(f.zabbix.addr)}`)
  L.push('')

  // Blocklist
  L.push('blocklist:')
  L.push(`  enabled: ${f.blocklist.enabled}`)
  L.push(`  refresh_interval: ${y(f.blocklist.refresh)}`)
  L.push(`  blocking_mode: ${y(f.blocklist.mode)}`)
  if (f.blocklist.customIP) L.push(`  custom_ip: ${y(f.blocklist.customIP)}`)
  if (f.blocklist.whitelist.length) L.push(`  whitelist: ${y(csv(f.blocklist.whitelist))}`)
  if (f.blocklist.sources.length) {
    const packed = f.blocklist.sources.filter((x) => x.url && x.format).map((x) => `${x.url}|${x.format}`).join(', ')
    if (packed) L.push(`  lists: ${y(packed)}`)
  }
  L.push('')

  // Cluster
  L.push('cluster:')
  L.push(`  enabled: ${f.cluster.enabled}`)
  L.push(`  role: ${y(f.cluster.role)}`)
  L.push(`  node_id: ${y(f.cluster.nodeID)}`)
  if (f.cluster.sharedFields.length) L.push(`  shared_fields: ${y(csv(f.cluster.sharedFields))}`)
  L.push('  actions:')
  L.push(`    fanout_cache_flush: ${f.cluster.fanoutCacheFlush}`)
  L.push(`    fanout_blocklist_refresh: ${f.cluster.fanoutBlocklistRefresh}`)
  L.push('  sync:')
  L.push(`    mode: ${y(f.cluster.syncMode)}`)
  L.push(`    push_on_save: ${f.cluster.pushOnSave}`)
  L.push(`    pull_interval: ${y(f.cluster.pullInterval)}`)
  if (f.cluster.peers.length) {
    L.push('  peers:')
    f.cluster.peers.forEach((line) => {
      const [nameRaw, enabledRaw, apiBaseRaw, tokenRaw, syncFieldsRaw] = line.split('|')
      const name = (nameRaw || '').trim(); if (!name) return
      const enabled = (enabledRaw || '').trim().toLowerCase() !== 'false'
      const apiBase = (apiBaseRaw || '').trim(); const token = (tokenRaw || '').trim()
      const syncFields = (syncFieldsRaw || '').trim()
      L.push(`    ${y(name)}:`); L.push(`      enabled: ${enabled}`)
      if (apiBase) L.push(`      api_base: ${y(apiBase)}`)
      if (token) L.push(`      api_token: ${y(token)}`)
      if (syncFields) L.push(`      sync_fields: ${y(syncFields)}`)
    })
  }
  L.push('')

  // ACL
  L.push('access_control:')
  L.push(`  allow: ${y(csv(f.acl.allow))}`)
  L.push(`  deny: ${y(csv(f.acl.deny))}`)

  // Zones
  const pushNamed = (name: string, items: NamedCSV[]) => {
    if (!items.length) return
    L.push(''); L.push(`${name}:`)
    items.filter((z) => z.name).forEach((z) => { L.push(`  ${y(z.name)}:`); L.push(`    addrs: ${y(z.csv)}`) })
  }
  pushNamed('forward_zones', f.forwardZones)
  pushNamed('stub_zones', f.stubZones)
  if (f.localZones.length) {
    L.push(''); L.push('local_zones:')
    f.localZones.filter((z) => z.name).forEach((z) => {
      L.push(`  ${y(z.name)}:`); L.push('    type: static')
      if (z.csv) L.push(`    data: ${y(z.csv)}`)
    })
  }
  return `${L.join('\n').trim()}\n`
}

/* ── UI helpers ──────────────────────────────────────────────── */

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm p-4 space-y-3">
      <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{title}</h2>
      {children}
    </div>
  )
}

function Field({ label, path, children }: { label: string; path: string; children: React.ReactNode }) {
  return (
    <label className="text-xs font-medium text-slate-700 dark:text-slate-200 block">
      {label}
      <div className={keyClass}>{path}</div>
      {children}
    </label>
  )
}

function Toggle({ label, checked, disabled, onChange }: { label: string; checked: boolean; disabled: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200">
      <input type="checkbox" disabled={disabled} checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
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
          {!disabled && <button type="button" className="p-2 border rounded-lg border-slate-300 dark:border-slate-600 text-slate-500 hover:text-red-600" onClick={() => onChange(values.filter((_, idx) => idx !== i))}><Trash2 size={14} /></button>}
        </div>
      ))}
      {!disabled && <button type="button" className="text-xs inline-flex items-center gap-1 text-amber-700 dark:text-amber-300" onClick={() => onChange([...values, ''])}><Plus size={13} />Add</button>}
    </div>
  )
}

/* ── Main component ──────────────────────────────────────────── */

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
      setRawPath(raw.path); setRawContent(raw.content)
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to load config'); setStatusType('error')
    } finally { setLoading(false) }
  }
  useEffect(() => { void load() }, [])

  const patch = (fn: (v: FormState) => FormState) => setForm((v) => (v ? fn(v) : v))
  const readonly = mode === 'view'

  const validateConfig = async () => {
    if (!form) return; setBusy(true)
    try {
      const res = await api.validateConfig(buildYAML(form))
      setStatus(res.valid ? 'Validation successful' : res.error || 'Validation failed')
      setStatusType(res.valid ? 'success' : 'error')
    } catch (err) { setStatus(err instanceof Error ? err.message : 'Validation failed'); setStatusType('error') }
    finally { setBusy(false) }
  }
  const saveConfig = async () => {
    if (!form) return; setBusy(true)
    try {
      await api.saveConfig(buildYAML(form))
      setStatus('Config saved. Restart recommended.'); setStatusType('success'); setMode('view'); await load()
    } catch (err) { setStatus(err instanceof Error ? err.message : 'Save failed'); setStatusType('error') }
    finally { setBusy(false) }
  }
  const validateRawConfig = async () => {
    setBusy(true)
    try {
      const res = await api.validateConfig(rawContent)
      setStatus(res.valid ? 'Raw YAML valid' : res.error || 'Invalid'); setStatusType(res.valid ? 'success' : 'error')
    } catch (err) { setStatus(err instanceof Error ? err.message : 'Validation failed'); setStatusType('error') }
    finally { setBusy(false) }
  }
  const saveRawConfig = async () => {
    setBusy(true)
    try {
      await api.saveConfig(rawContent)
      setStatus('Raw YAML saved. Restart recommended.'); setStatusType('success'); await load(); setMode('view')
    } catch (err) { setStatus(err instanceof Error ? err.message : 'Save failed'); setStatusType('error') }
    finally { setBusy(false) }
  }
  const changePassword = async () => {
    if (!currentPassword || !newPassword) return
    if (newPassword !== confirmPassword) { setStatus('Passwords do not match'); setStatusType('error'); return }
    setBusy(true)
    try {
      await api.changePassword(currentPassword, newPassword)
      setStatus('Password changed'); setStatusType('success')
      setCurrentPassword(''); setNewPassword(''); setConfirmPassword(''); await load()
    } catch (err) { setStatus(err instanceof Error ? err.message : 'Failed'); setStatusType('error') }
    finally { setBusy(false) }
  }

  if (loading) return <div className="flex items-center justify-center h-64"><Loader2 size={24} className="animate-spin text-amber-600" /></div>
  if (!form) return <div className="text-sm text-red-600">Config unavailable</div>

  const statusClass =
    statusType === 'success' ? 'bg-green-50 dark:bg-green-900/30 border-green-200 dark:border-green-800 text-green-700 dark:text-green-400'
    : statusType === 'error' ? 'bg-red-50 dark:bg-red-900/30 border-red-200 dark:border-red-800 text-red-700 dark:text-red-400'
    : 'bg-amber-50 dark:bg-amber-900/30 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-400'

  const I = (props: { value: string | number; path: string; label: string; type?: string; min?: number; step?: number; onChange: (v: string) => void }) => (
    <Field label={props.label} path={props.path}>
      <input type={props.type || 'text'} className={inputClass} disabled={readonly} value={props.value} min={props.min} step={props.step}
        onChange={(e) => props.onChange(e.target.value)} />
    </Field>
  )

  return (
    <div className="space-y-6">
      {/* Header + actions */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Configuration</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">{readonly ? 'View mode' : 'Edit mode'}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className={`px-3 py-2 rounded-lg border text-sm inline-flex items-center gap-1 ${readonly ? 'border-amber-300 text-amber-700' : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-400'}`} onClick={() => setMode('view')}><Eye size={14} />View</button>
          <button type="button" className={`px-3 py-2 rounded-lg border text-sm inline-flex items-center gap-1 ${!readonly ? 'border-amber-300 text-amber-700' : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-400'}`} onClick={() => setMode('edit')}><PencilLine size={14} />Edit</button>
          <button type="button" className={`px-3 py-2 rounded-lg border text-sm inline-flex items-center gap-1 ${editorMode === 'form' ? 'border-amber-300 text-amber-700' : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-400'}`} onClick={() => setEditorMode('form')}><FilePenLine size={14} />Form</button>
          <button type="button" className={`px-3 py-2 rounded-lg border text-sm inline-flex items-center gap-1 ${editorMode === 'raw' ? 'border-amber-300 text-amber-700' : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-400'}`} onClick={() => setEditorMode('raw')}><Code2 size={14} />Raw</button>
          {!readonly && editorMode === 'form' && <button type="button" className="px-3 py-2 rounded-lg border border-amber-300 text-amber-700 text-sm" onClick={validateConfig} disabled={busy}>Validate</button>}
          {!readonly && editorMode === 'form' && <button type="button" className="px-4 py-2 rounded-lg bg-amber-600 text-white text-sm inline-flex items-center gap-1" onClick={saveConfig} disabled={busy}>{busy ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}Save</button>}
          {!readonly && editorMode === 'raw' && <button type="button" className="px-3 py-2 rounded-lg border border-amber-300 text-amber-700 text-sm" onClick={validateRawConfig} disabled={busy}>Validate</button>}
          {!readonly && editorMode === 'raw' && <button type="button" className="px-4 py-2 rounded-lg bg-amber-600 text-white text-sm inline-flex items-center gap-1" onClick={saveRawConfig} disabled={busy}>{busy ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}Save</button>}
        </div>
      </div>

      {status && <div className={`text-sm rounded-lg border px-4 py-3 flex items-start gap-2 ${statusClass}`}>{statusType === 'success' ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}<span>{status}</span></div>}

      {/* Raw editor */}
      {editorMode === 'raw' && (
        <Section title="Full YAML Editor">
          <div className={keyClass}>File: {rawPath || 'labyrinth.yaml'} &mdash; password_hash is locked, use Change Password.</div>
          <textarea className={`${inputClass} min-h-[520px] font-mono text-xs`} value={rawContent} disabled={readonly} onChange={(e) => setRawContent(e.target.value)} />
          {!readonly && (
            <div className="flex items-center gap-2">
              <button type="button" className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-600 dark:text-slate-400" onClick={validateRawConfig} disabled={busy}>Validate</button>
              <button type="button" className="px-3 py-2 rounded-lg bg-amber-600 text-white text-sm" onClick={saveRawConfig} disabled={busy}>Save</button>
              <button type="button" className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-600 dark:text-slate-400" onClick={() => { void load() }} disabled={busy}>Reload</button>
            </div>
          )}
        </Section>
      )}

      {/* Form editor */}
      {editorMode === 'form' && (
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">

        {/* ── Server ─────────────────────────────────────────── */}
        <Section title="Server">
          <div className="grid grid-cols-2 gap-2">
            <I label="Listen Address" path="server.listen_addr" value={form.server.listen} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, listen: v } }))} />
            <I label="Metrics Address" path="server.metrics_addr" value={form.server.metrics} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, metrics: v } }))} />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <I label="Max UDP Size" path="server.max_udp_size" type="number" value={form.server.maxUDP} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, maxUDP: Number(v) || 0 } }))} />
            <I label="Max TCP Conns" path="server.max_tcp_conns" type="number" value={form.server.maxTCP} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, maxTCP: Number(v) || 0 } }))} />
            <I label="Max UDP Workers" path="server.max_udp_workers" type="number" value={form.server.maxUDPWorkers} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, maxUDPWorkers: Number(v) || 0 } }))} />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <I label="TCP Timeout" path="server.tcp_timeout" value={form.server.tcpTimeout} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, tcpTimeout: v } }))} />
            <I label="TCP Idle Timeout" path="server.tcp_idle_timeout" value={form.server.tcpIdleTimeout} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, tcpIdleTimeout: v } }))} />
            <I label="Graceful Period" path="server.graceful_period" value={form.server.graceful} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, graceful: v } }))} />
          </div>
          <I label="TCP Pipeline Max" path="server.tcp_pipeline_max" type="number" value={form.server.tcpPipelineMax} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, tcpPipelineMax: Number(v) || 0 } }))} />
          <Toggle label="DNS-over-TLS (DoT)" checked={form.server.dotEnabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, dotEnabled: v } }))} />
          {form.server.dotEnabled && <I label="DoT Listen Address" path="server.dot_listen_addr" value={form.server.dotListenAddr} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, dotListenAddr: v } }))} />}
          <div className="grid grid-cols-2 gap-2">
            <I label="TLS Cert File" path="server.tls_cert_file" value={form.server.tlsCertFile} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, tlsCertFile: v } }))} />
            <I label="TLS Key File" path="server.tls_key_file" value={form.server.tlsKeyFile} onChange={(v) => patch((p) => ({ ...p, server: { ...p.server, tlsKeyFile: v } }))} />
          </div>
        </Section>

        {/* ── Resolver ───────────────────────────────────────── */}
        <Section title="Resolver">
          <div className="grid grid-cols-2 gap-2">
            <I label="Max Depth" path="resolver.max_depth" type="number" value={form.resolver.maxDepth} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, maxDepth: Number(v) || 0 } }))} />
            <I label="Max CNAME Depth" path="resolver.max_cname_depth" type="number" value={form.resolver.maxCnameDepth} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, maxCnameDepth: Number(v) || 0 } }))} />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <I label="Upstream Timeout" path="resolver.upstream_timeout" value={form.resolver.upstreamTimeout} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, upstreamTimeout: v } }))} />
            <I label="Upstream Retries" path="resolver.upstream_retries" type="number" value={form.resolver.upstreamRetries} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, upstreamRetries: Number(v) || 0 } }))} />
          </div>
          <I label="Root Hints Refresh" path="resolver.root_hints_refresh" value={form.resolver.rootHintsRefresh} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, rootHintsRefresh: v } }))} />
          <Toggle label="QNAME Minimization" checked={form.resolver.qmin} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, qmin: v } }))} />
          <Toggle label="Prefer IPv4" checked={form.resolver.preferIPv4} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, preferIPv4: v } }))} />
          <Toggle label="DNSSEC Validation" checked={form.resolver.dnssec} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, dnssec: v } }))} />
          <Toggle label="Harden Below NXDOMAIN" checked={form.resolver.hardenBelowNX} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, hardenBelowNX: v } }))} />
          <Toggle label="ECS (EDNS Client Subnet)" checked={form.resolver.ecsEnabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, ecsEnabled: v } }))} />
          {form.resolver.ecsEnabled && <I label="ECS Max Prefix" path="resolver.ecs_max_prefix" type="number" value={form.resolver.ecsMaxPrefix} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, ecsMaxPrefix: Number(v) || 0 } }))} />}
          <Toggle label="DNS64" checked={form.resolver.dns64Enabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, dns64Enabled: v } }))} />
          {form.resolver.dns64Enabled && <I label="DNS64 Prefix" path="resolver.dns64_prefix" value={form.resolver.dns64Prefix} onChange={(v) => patch((p) => ({ ...p, resolver: { ...p.resolver, dns64Prefix: v } }))} />}
          <StringList title="Fallback Resolvers" path="resolver.fallback_resolvers" values={form.resolver.fallbackResolvers} onChange={(n) => patch((p) => ({ ...p, resolver: { ...p.resolver, fallbackResolvers: n } }))} disabled={readonly} placeholder="8.8.8.8" />
        </Section>

        {/* ── Cache ──────────────────────────────────────────── */}
        <Section title="Cache">
          <I label="Max Entries" path="cache.max_entries" type="number" value={form.cache.maxEntries} onChange={(v) => patch((p) => ({ ...p, cache: { ...p.cache, maxEntries: Number(v) || 0 } }))} />
          <div className="grid grid-cols-3 gap-2">
            <I label="Min TTL" path="cache.min_ttl" type="number" min={0} value={form.cache.minTTL} onChange={(v) => patch((p) => ({ ...p, cache: { ...p.cache, minTTL: Number(v) || 0 } }))} />
            <I label="Max TTL" path="cache.max_ttl" type="number" min={0} value={form.cache.maxTTL} onChange={(v) => patch((p) => ({ ...p, cache: { ...p.cache, maxTTL: Number(v) || 0 } }))} />
            <I label="Negative Max TTL" path="cache.negative_max_ttl" type="number" min={0} value={form.cache.negMaxTTL} onChange={(v) => patch((p) => ({ ...p, cache: { ...p.cache, negMaxTTL: Number(v) || 0 } }))} />
          </div>
          <I label="Sweep Interval" path="cache.sweep_interval" value={form.cache.sweep} onChange={(v) => patch((p) => ({ ...p, cache: { ...p.cache, sweep: v } }))} />
          <Toggle label="Serve Stale" checked={form.cache.serveStale} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, cache: { ...p.cache, serveStale: v } }))} />
          {form.cache.serveStale && <I label="Stale TTL" path="cache.stale_ttl" type="number" value={form.cache.staleTTL} onChange={(v) => patch((p) => ({ ...p, cache: { ...p.cache, staleTTL: Number(v) || 0 } }))} />}
          <Toggle label="Prefetch" checked={form.cache.prefetch} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, cache: { ...p.cache, prefetch: v } }))} />
          <StringList title="No-Cache Clients" path="cache.no_cache_clients" values={form.cache.noCacheClients} onChange={(n) => patch((p) => ({ ...p, cache: { ...p.cache, noCacheClients: n } }))} disabled={readonly} placeholder="192.168.1.0/24" />
        </Section>

        {/* ── Security ───────────────────────────────────────── */}
        <Section title="Security">
          <Toggle label="Private Address Filter" checked={form.security.privateAddrFilter} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, security: { ...p.security, privateAddrFilter: v } }))} />
          <Toggle label="DNS Cookies" checked={form.security.dnsCookies} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, security: { ...p.security, dnsCookies: v } }))} />
          <div className="border-t border-slate-200 dark:border-slate-700 pt-3 mt-1">
            <Toggle label="Rate Limiting" checked={form.security.rateEnabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, security: { ...p.security, rateEnabled: v } }))} />
          </div>
          {form.security.rateEnabled && (
            <div className="grid grid-cols-2 gap-2">
              <I label="Rate (req/s)" path="security.rate_limit.rate" type="number" step={1} value={form.security.rate} onChange={(v) => patch((p) => ({ ...p, security: { ...p.security, rate: Number(v) || 0 } }))} />
              <I label="Burst" path="security.rate_limit.burst" type="number" value={form.security.burst} onChange={(v) => patch((p) => ({ ...p, security: { ...p.security, burst: Number(v) || 0 } }))} />
            </div>
          )}
          <div className="border-t border-slate-200 dark:border-slate-700 pt-3 mt-1">
            <Toggle label="Response Rate Limiting (RRL)" checked={form.security.rrlEnabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, security: { ...p.security, rrlEnabled: v } }))} />
          </div>
          {form.security.rrlEnabled && (
            <>
              <div className="grid grid-cols-2 gap-2">
                <I label="Responses/sec" path="security.rrl.responses_per_second" type="number" value={form.security.rrlRPS} onChange={(v) => patch((p) => ({ ...p, security: { ...p.security, rrlRPS: Number(v) || 0 } }))} />
                <I label="Slip Ratio" path="security.rrl.slip_ratio" type="number" value={form.security.rrlSlip} onChange={(v) => patch((p) => ({ ...p, security: { ...p.security, rrlSlip: Number(v) || 0 } }))} />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <I label="IPv4 Prefix" path="security.rrl.ipv4_prefix" type="number" value={form.security.rrlV4} onChange={(v) => patch((p) => ({ ...p, security: { ...p.security, rrlV4: Number(v) || 0 } }))} />
                <I label="IPv6 Prefix" path="security.rrl.ipv6_prefix" type="number" value={form.security.rrlV6} onChange={(v) => patch((p) => ({ ...p, security: { ...p.security, rrlV6: Number(v) || 0 } }))} />
              </div>
            </>
          )}
        </Section>

        {/* ── Web & Auth ─────────────────────────────────────── */}
        <Section title="Web & Auth">
          <Toggle label="Web Enabled" checked={form.web.enabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, enabled: v } }))} />
          <div className="grid grid-cols-2 gap-2">
            <I label="Web Address" path="web.addr" value={form.web.addr} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, addr: v } }))} />
            <I label="Admin Username" path="web.auth.username" value={form.web.authUser} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, authUser: v } }))} />
          </div>
          <Toggle label="DoH (HTTP/1.1+2)" checked={form.web.doh} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, doh: v } }))} />
          <Toggle label="DoH (HTTP/3)" checked={form.web.doh3} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, doh3: v } }))} />
          <Toggle label="Web TLS" checked={form.web.tlsEnabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, tlsEnabled: v } }))} />
          {(form.web.tlsEnabled || form.web.tlsCertFile) && !form.web.autoTLS && (
            <div className="grid grid-cols-2 gap-2">
              <I label="TLS Cert File" path="web.tls_cert_file" value={form.web.tlsCertFile} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, tlsCertFile: v } }))} />
              <I label="TLS Key File" path="web.tls_key_file" value={form.web.tlsKeyFile} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, tlsKeyFile: v } }))} />
            </div>
          )}
          <Toggle label="Auto-TLS (Let's Encrypt)" checked={form.web.autoTLS} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, autoTLS: v } }))} />
          {form.web.autoTLS && (
            <div className="grid grid-cols-2 gap-2">
              <I label="Domain" path="web.auto_tls_domain" value={form.web.autoTLSDomain} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, autoTLSDomain: v } }))} />
              <I label="Email" path="web.auto_tls_email" value={form.web.autoTLSEmail} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, autoTLSEmail: v } }))} />
              <I label="Cache Dir" path="web.auto_tls_cache_dir" value={form.web.autoTLSCacheDir} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, autoTLSCacheDir: v } }))} />
              <Toggle label="Staging (Test)" checked={form.web.autoTLSStaging} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, autoTLSStaging: v } }))} />
            </div>
          )}
          <div className="border-t border-slate-200 dark:border-slate-700 pt-3 mt-1 grid grid-cols-3 gap-2">
            <I label="Query Log Buffer" path="web.query_log_buffer" type="number" value={form.web.queryLogBuffer} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, queryLogBuffer: Number(v) || 0 } }))} />
            <I label="Top Clients Limit" path="web.top_clients_limit" type="number" value={form.web.topClientsLimit} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, topClientsLimit: Number(v) || 0 } }))} />
            <I label="Top Domains Limit" path="web.top_domains_limit" type="number" value={form.web.topDomainsLimit} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, topDomainsLimit: Number(v) || 0 } }))} />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <I label="Error Threshold %" path="web.alert_error_threshold_pct" type="number" min={0.1} step={0.1} value={form.web.alertErrorThresholdPct} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, alertErrorThresholdPct: Number(v) || 0 } }))} />
            <I label="Latency Threshold ms" path="web.alert_latency_threshold_ms" type="number" min={1} step={1} value={form.web.alertLatencyThresholdMs} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, alertLatencyThresholdMs: Number(v) || 0 } }))} />
          </div>
          <Toggle label="Auto Update" checked={form.web.autoUpdate} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, autoUpdate: v } }))} />
          {form.web.autoUpdate && <I label="Update Check Interval" path="web.update_check_interval" value={form.web.updateCheckInterval} onChange={(v) => patch((p) => ({ ...p, web: { ...p.web, updateCheckInterval: v } }))} />}
        </Section>

        {/* ── ACL & Blocklist ────────────────────────────────── */}
        <Section title="ACL & Blocklist">
          <StringList title="ACL Allow" path="access_control.allow" values={form.acl.allow} onChange={(n) => patch((p) => ({ ...p, acl: { ...p.acl, allow: n } }))} disabled={readonly} placeholder="10.0.0.0/8" />
          <StringList title="ACL Deny" path="access_control.deny" values={form.acl.deny} onChange={(n) => patch((p) => ({ ...p, acl: { ...p.acl, deny: n } }))} disabled={readonly} placeholder="0.0.0.0/0" />
          <div className="border-t border-slate-200 dark:border-slate-700 pt-3 mt-1">
            <Toggle label="Blocklist Enabled" checked={form.blocklist.enabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, blocklist: { ...p.blocklist, enabled: v } }))} />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <I label="Blocking Mode" path="blocklist.blocking_mode" value={form.blocklist.mode} onChange={(v) => patch((p) => ({ ...p, blocklist: { ...p.blocklist, mode: v } }))} />
            <I label="Custom IP" path="blocklist.custom_ip" value={form.blocklist.customIP} onChange={(v) => patch((p) => ({ ...p, blocklist: { ...p.blocklist, customIP: v } }))} />
            <I label="Refresh Interval" path="blocklist.refresh_interval" value={form.blocklist.refresh} onChange={(v) => patch((p) => ({ ...p, blocklist: { ...p.blocklist, refresh: v } }))} />
          </div>
          <StringList title="Whitelist" path="blocklist.whitelist" values={form.blocklist.whitelist} onChange={(n) => patch((p) => ({ ...p, blocklist: { ...p.blocklist, whitelist: n } }))} disabled={readonly} placeholder="example.com" />
          <StringList title="Blocklist Sources" path="blocklist.lists (url|format)"
            values={form.blocklist.sources.map((s) => `${s.url}|${s.format}`)}
            onChange={(n) => patch((p) => ({ ...p, blocklist: { ...p.blocklist, sources: n.map((l) => { const [url, format] = l.split('|'); return { url: (url || '').trim(), format: (format || '').trim() || 'hosts' } }).filter((x) => x.url) } }))}
            disabled={readonly} placeholder="https://example.com/list.txt|hosts" />
        </Section>

        {/* ── Cluster ────────────────────────────────────────── */}
        <Section title="Cluster">
          <Toggle label="Cluster Enabled" checked={form.cluster.enabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, cluster: { ...p.cluster, enabled: v } }))} />
          <div className="grid grid-cols-2 gap-2">
            <I label="Role" path="cluster.role" value={form.cluster.role} onChange={(v) => patch((p) => ({ ...p, cluster: { ...p.cluster, role: v } }))} />
            <I label="Node ID" path="cluster.node_id" value={form.cluster.nodeID} onChange={(v) => patch((p) => ({ ...p, cluster: { ...p.cluster, nodeID: v } }))} />
          </div>
          <StringList title="Shared Fields" path="cluster.shared_fields" values={form.cluster.sharedFields} onChange={(n) => patch((p) => ({ ...p, cluster: { ...p.cluster, sharedFields: n } }))} disabled={readonly} placeholder="access_control" />
          <Toggle label="Fanout Cache Flush" checked={form.cluster.fanoutCacheFlush} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, cluster: { ...p.cluster, fanoutCacheFlush: v } }))} />
          <Toggle label="Fanout Blocklist Refresh" checked={form.cluster.fanoutBlocklistRefresh} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, cluster: { ...p.cluster, fanoutBlocklistRefresh: v } }))} />
          <div className="grid grid-cols-2 gap-2">
            <I label="Sync Mode" path="cluster.sync.mode" value={form.cluster.syncMode} onChange={(v) => patch((p) => ({ ...p, cluster: { ...p.cluster, syncMode: v } }))} />
            <I label="Pull Interval" path="cluster.sync.pull_interval" value={form.cluster.pullInterval} onChange={(v) => patch((p) => ({ ...p, cluster: { ...p.cluster, pullInterval: v } }))} />
          </div>
          <Toggle label="Push On Save" checked={form.cluster.pushOnSave} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, cluster: { ...p.cluster, pushOnSave: v } }))} />
          <StringList title="Peers (name|enabled|api_base|api_token|sync_fields_csv)" path="cluster.peers.*"
            values={form.cluster.peers} onChange={(n) => patch((p) => ({ ...p, cluster: { ...p.cluster, peers: n } }))}
            disabled={readonly} placeholder="dns-2|true|http://10.0.0.2:9153|TOKEN|access_control,blocklist" />
        </Section>

        {/* ── Zones ──────────────────────────────────────────── */}
        <Section title="Zones">
          <StringList title="Local Zones (name=records CSV)" path="local_zones" values={form.localZones.map((z) => `${z.name}=${z.csv}`)} onChange={(n) => patch((p) => ({ ...p, localZones: n.map((v) => { const [name, ...rest] = v.split('='); return { name: name.trim(), csv: rest.join('=').trim() } }) }))} disabled={readonly} placeholder="corp.local=host1 A 10.0.0.1" />
          <StringList title="Forward Zones (name=addr CSV)" path="forward_zones" values={form.forwardZones.map((z) => `${z.name}=${z.csv}`)} onChange={(n) => patch((p) => ({ ...p, forwardZones: n.map((v) => { const [name, ...rest] = v.split('='); return { name: name.trim(), csv: rest.join('=').trim() } }) }))} disabled={readonly} placeholder="example.com=1.1.1.1, 9.9.9.9" />
          <StringList title="Stub Zones (name=addr CSV)" path="stub_zones" values={form.stubZones.map((z) => `${z.name}=${z.csv}`)} onChange={(n) => patch((p) => ({ ...p, stubZones: n.map((v) => { const [name, ...rest] = v.split('='); return { name: name.trim(), csv: rest.join('=').trim() } }) }))} disabled={readonly} placeholder="internal=10.0.0.53" />
        </Section>

        {/* ── System (Logging, Daemon, Zabbix) ───────────────── */}
        <Section title="System">
          <div className="grid grid-cols-2 gap-2">
            <I label="Log Level" path="logging.level" value={form.logging.level} onChange={(v) => patch((p) => ({ ...p, logging: { ...p.logging, level: v } }))} />
            <I label="Log Format" path="logging.format" value={form.logging.format} onChange={(v) => patch((p) => ({ ...p, logging: { ...p.logging, format: v } }))} />
          </div>
          <div className="border-t border-slate-200 dark:border-slate-700 pt-3 mt-1">
            <Toggle label="Daemon Mode" checked={form.daemon.enabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, daemon: { ...p.daemon, enabled: v } }))} />
          </div>
          {form.daemon.enabled && <I label="PID File" path="daemon.pid_file" value={form.daemon.pidFile} onChange={(v) => patch((p) => ({ ...p, daemon: { ...p.daemon, pidFile: v } }))} />}
          <div className="border-t border-slate-200 dark:border-slate-700 pt-3 mt-1">
            <Toggle label="Zabbix Integration" checked={form.zabbix.enabled} disabled={readonly} onChange={(v) => patch((p) => ({ ...p, zabbix: { ...p.zabbix, enabled: v } }))} />
          </div>
          {form.zabbix.enabled && <I label="Zabbix Address" path="zabbix.addr" value={form.zabbix.addr} onChange={(v) => patch((p) => ({ ...p, zabbix: { ...p.zabbix, addr: v } }))} />}
        </Section>

        {/* ── Password ───────────────────────────────────────── */}
        <Section title="Change Password">
          <Field label="Current Password" path="web.auth.password_hash"><input type="password" className={inputClass} value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} /></Field>
          <Field label="New Password" path=""><input type="password" className={inputClass} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} /></Field>
          <Field label="Confirm" path=""><input type="password" className={inputClass} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} /></Field>
          <button type="button" className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-300" onClick={changePassword} disabled={busy}>Change Password</button>
        </Section>

      </div>
      )}
    </div>
  )
}
