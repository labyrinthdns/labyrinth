import type {
  TopListResponse,
  NegativeCacheEntry,
  QueryEntry,
  TimeSeriesResponse,
  UpdateInfo,
  BlocklistStats,
  BlocklistListEntry,
  BlocklistDomainsResponse,
  ConfigRawResponse,
  ConfigValidateResponse,
  ConfigSaveResponse,
  SystemProfileResponse,
  DashboardLayoutResponse,
  StatsResponse,
  CacheStats,
  LoginResponse,
  TLSStatusResponse,
  DNSGuideResponse,
  FallbackEventsResponse,
  DNSSECStatusResponse,
  SecurityStatusResponse,
  TrustChainResponse,
} from '@/api/types'

const DEFAULT_REQUEST_TIMEOUT_MS = 15000

type CachedValue = {
  expiresAt: number
  value: unknown
}

const responseCache = new Map<string, CachedValue>()
const inflightCache = new Map<string, Promise<unknown>>()

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options.headers as Record<string, string>) || {}),
  }
  // Auth is handled by the labyrinth_token HttpOnly cookie, which
  // the browser sends automatically on same-origin requests. No
  // manual Bearer header is needed.

  const hasExternalSignal = Boolean(options.signal)
  const controller = hasExternalSignal ? null : new AbortController()
  const timeout = hasExternalSignal
    ? null
    : setTimeout(() => controller?.abort(), DEFAULT_REQUEST_TIMEOUT_MS)

  let resp: Response
  try {
    resp = await fetch(path, {
      ...options,
      headers,
      signal: options.signal ?? controller?.signal,
    })
  } catch (err) {
    if (!hasExternalSignal && (err instanceof DOMException) && err.name === 'AbortError') {
      throw new Error(`Request timeout after ${DEFAULT_REQUEST_TIMEOUT_MS}ms`)
    }
    throw err
  } finally {
    if (timeout) clearTimeout(timeout)
  }

  if (resp.status === 401) {
    if (!window.location.pathname.startsWith('/login')) {
      window.location.assign('/login')
    }
    throw new Error('Unauthorized')
  }

  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`${resp.status}: ${text}`)
  }

  return resp.json()
}

async function requestCached<T>(cacheKey: string, ttlMs: number, path: string, options: RequestInit = {}): Promise<T> {
  const now = Date.now()
  const cached = responseCache.get(cacheKey)
  if (cached && cached.expiresAt > now) {
    return cached.value as T
  }

  const inflight = inflightCache.get(cacheKey)
  if (inflight) {
    return inflight as Promise<T>
  }

  const promise = request<T>(path, options)
    .then((value) => {
      responseCache.set(cacheKey, { expiresAt: Date.now() + ttlMs, value })
      inflightCache.delete(cacheKey)
      return value
    })
    .catch((err) => {
      inflightCache.delete(cacheKey)
      throw err
    })

  inflightCache.set(cacheKey, promise as Promise<unknown>)
  return promise
}

function clearCached(...keys: string[]) {
  keys.forEach((key) => {
    responseCache.delete(key)
    inflightCache.delete(key)
  })
}

export const api = {
  login: (username: string, password: string) =>
    request<LoginResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  logout: () =>
    request<{ status: string }>('/api/auth/logout', { method: 'POST' }),

  me: () => request<{ username: string }>('/api/auth/me'),

  stats: () => request<StatsResponse>('/api/stats'),

  timeseries: (window = '5m') =>
    request<TimeSeriesResponse>(`/api/stats/timeseries?window=${encodeURIComponent(window)}`),

  recentQueries: (limit = 50) =>
    request<{ entries: QueryEntry[]; count: number }>(`/api/queries/recent?limit=${encodeURIComponent(String(limit))}`),

  cacheStats: () => request<CacheStats>('/api/cache/stats'),

  cacheLookup: (name: string, type: string) =>
    request<Record<string, unknown>>(`/api/cache/lookup?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`),

  cacheFlush: () =>
    request<{ status: string }>('/api/cache/flush', { method: 'POST' }),

  cacheDelete: (name: string, type: string) =>
    request<{ status: string }>(`/api/cache/entry?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, { method: 'DELETE' }),

  config: () => request<Record<string, unknown>>('/api/config'),
  configRaw: () => request<ConfigRawResponse>('/api/config/raw'),
  validateConfig: (content: string) =>
    request<ConfigValidateResponse>('/api/config/validate', {
      method: 'POST',
      body: JSON.stringify({ content }),
    }),
  saveConfig: (content: string) =>
    request<ConfigSaveResponse>('/api/config/raw', {
      method: 'PUT',
      body: JSON.stringify({ content }),
    }),

  setupStatus: () => request<{ setup_required: boolean; version: string }>('/api/setup/status'),

  setupComplete: (data: Record<string, unknown>) =>
    request<{ ok: boolean }>('/api/setup/complete', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  health: () => request<{ status: string; resolver_ready: boolean }>('/api/system/health'),

  version: () => requestCached<{ version: string; build_time: string; go_version: string }>(
    'system.version',
    60000,
    '/api/system/version',
  ),
  systemProfile: () => request<SystemProfileResponse>('/api/system/profile'),
  dashboardLayout: () => request<DashboardLayoutResponse>('/api/dashboard/layout'),
  saveDashboardLayout: (payload: { panel_order: string[]; hidden_panels: string[] }) =>
    request<DashboardLayoutResponse>('/api/dashboard/layout', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  topClients: (limit?: number, offset?: number) => {
    const params = new URLSearchParams()
    if (typeof limit === 'number' && limit > 0) params.set('limit', String(limit))
    if (typeof offset === 'number' && offset >= 0) params.set('offset', String(offset))
    const qs = params.toString()
    return request<TopListResponse>(`/api/stats/top-clients${qs ? `?${qs}` : ''}`)
  },

  topDomains: (limit?: number, offset?: number) => {
    const params = new URLSearchParams()
    if (typeof limit === 'number' && limit > 0) params.set('limit', String(limit))
    if (typeof offset === 'number' && offset >= 0) params.set('offset', String(offset))
    const qs = params.toString()
    return request<TopListResponse>(`/api/stats/top-domains${qs ? `?${qs}` : ''}`)
  },

  cacheNegative: (limit = 100) =>
    request<{ entries: NegativeCacheEntry[] }>(`/api/cache/negative?limit=${encodeURIComponent(String(limit))}`),

  fallbackEvents: () => request<FallbackEventsResponse>('/api/fallback-events'),

  dnssec: () => request<DNSSECStatusResponse>('/api/dnssec'),

  trustChain: (name: string) =>
    request<TrustChainResponse>(`/api/dnssec/trustchain?name=${encodeURIComponent(name)}`),

  addNTA: (zone: string, durationHours: number, reason: string) =>
    request<{ status: string; zone: string; expires_at: string }>(
      '/api/dnssec/nta',
      {
        method: 'POST',
        body: JSON.stringify({ zone, duration_hours: durationHours, reason }),
      },
    ),

  removeNTA: (zone: string) =>
    request<{ status: string; zone: string }>(
      `/api/dnssec/nta?zone=${encodeURIComponent(zone)}`,
      { method: 'DELETE' },
    ),

  security: () => request<SecurityStatusResponse>('/api/security'),

  checkUpdate: (force = false) => {
    if (force) {
      clearCached('system.update.check')
      return request<UpdateInfo>('/api/system/update/check?force=1')
    }
    return requestCached<UpdateInfo>('system.update.check', 30000, '/api/system/update/check')
  },

  applyUpdate: () => {
    clearCached('system.update.check')
    return request<{ status: string }>('/api/system/update/apply', { method: 'POST' })
  },

  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ status: string }>('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),

  blocklistStats: () => request<BlocklistStats>('/api/blocklist/stats'),
  blocklistLists: () => request<{ lists: BlocklistListEntry[] }>('/api/blocklist/lists'),
  blocklistRefresh: () => request<{ status: string }>('/api/blocklist/refresh', { method: 'POST' }),
  blocklistBlock: (domain: string) => request<{ status: string }>('/api/blocklist/block', { method: 'POST', body: JSON.stringify({ domain }) }),
  blocklistUnblock: (domain: string) => request<{ status: string }>('/api/blocklist/unblock', { method: 'POST', body: JSON.stringify({ domain }) }),
  blocklistCheck: (domain: string) => request<{ domain: string; blocked: boolean }>(`/api/blocklist/check?domain=${encodeURIComponent(domain)}`),
  blocklistDomains: () => request<BlocklistDomainsResponse>('/api/blocklist/domains'),

  tlsStatus: () => request<TLSStatusResponse>('/api/system/tls'),
  tlsRenew: () => request<{ status: string }>('/api/system/tls/renew', { method: 'POST' }),
  dnsGuide: () => request<DNSGuideResponse>('/api/dns-guide'),
}

function sameOriginWebSocketUrl(path: string): URL {
  const url = new URL(path, window.location.origin)
  url.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return url
}

export function createQueryWebSocket(): WebSocket {
  return new WebSocket(sameOriginWebSocketUrl('/api/queries/stream'))
}

export function createTimeSeriesWebSocket(mode: string, tsWindow: string, interval: string): WebSocket {
  const url = sameOriginWebSocketUrl('/api/stats/timeseries/ws')
  url.searchParams.set('mode', mode)
  if (mode === 'history') {
    url.searchParams.set('window', tsWindow)
    url.searchParams.set('interval', interval)
  }
  return new WebSocket(url)
}

export function createDiagnosticsTraceSocket(): WebSocket {
  return new WebSocket(sameOriginWebSocketUrl('/api/diagnostics/trace'))
}
