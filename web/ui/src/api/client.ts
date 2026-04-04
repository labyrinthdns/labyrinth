import type {
  TopEntry,
  NegativeCacheEntry,
  UpdateInfo,
  BlocklistStats,
  BlocklistListEntry,
  ConfigRawResponse,
  ConfigValidateResponse,
  ConfigSaveResponse,
  SystemProfileResponse,
} from '@/api/types'

const TOKEN_KEY = 'labyrinth_token'
const DEFAULT_REQUEST_TIMEOUT_MS = 15000

type CachedValue = {
  expiresAt: number
  value: unknown
}

const responseCache = new Map<string, CachedValue>()
const inflightCache = new Map<string, Promise<unknown>>()

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options.headers as Record<string, string>) || {}),
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

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
    clearToken()
    window.location.href = '/login'
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
    request<{ token: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  me: () => request<{ username: string }>('/api/auth/me'),

  stats: () => request<Record<string, unknown>>('/api/stats'),

  timeseries: (window = '5m') =>
    request<{ buckets: Record<string, unknown>[] }>(`/api/stats/timeseries?window=${window}`),

  recentQueries: (limit = 50) =>
    request<{ queries: Record<string, unknown>[] }>(`/api/queries/recent?limit=${limit}`),

  cacheStats: () => request<Record<string, unknown>>('/api/cache/stats'),

  cacheLookup: (name: string, type: string) =>
    request<Record<string, unknown>>(`/api/cache/lookup?name=${name}&type=${type}`),

  cacheFlush: () =>
    request<{ ok: boolean }>('/api/cache/flush', { method: 'POST' }),

  cacheDelete: (name: string, type: string) =>
    request<{ ok: boolean }>(`/api/cache/entry?name=${name}&type=${type}`, { method: 'DELETE' }),

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

  health: () => request<Record<string, unknown>>('/api/system/health'),

  version: () => requestCached<{ version: string; build_time: string; go_version: string }>(
    'system.version',
    60000,
    '/api/system/version',
  ),
  systemProfile: () => request<SystemProfileResponse>('/api/system/profile'),

  topClients: (limit?: number) =>
    request<{ entries: TopEntry[] }>(`/api/stats/top-clients${limit ? `?limit=${limit}` : ''}`),

  topDomains: (limit?: number) =>
    request<{ entries: TopEntry[] }>(`/api/stats/top-domains${limit ? `?limit=${limit}` : ''}`),

  cacheNegative: (limit = 100) =>
    request<{ entries: NegativeCacheEntry[] }>(`/api/cache/negative?limit=${limit}`),

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
  blocklistCheck: (domain: string) => request<{ domain: string; blocked: boolean }>(`/api/blocklist/check?domain=${domain}`),
}

export function createQueryWebSocket(): WebSocket {
  const token = getToken()
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const url = `${protocol}//${window.location.host}/api/queries/stream${token ? `?token=${token}` : ''}`
  return new WebSocket(url)
}
