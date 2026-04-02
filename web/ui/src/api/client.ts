const TOKEN_KEY = 'labyrinth_token'

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

  const resp = await fetch(path, { ...options, headers })

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

  setupStatus: () => request<{ setup_required: boolean; version: string }>('/api/setup/status'),

  setupComplete: (data: Record<string, unknown>) =>
    request<{ ok: boolean }>('/api/setup/complete', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  health: () => request<Record<string, unknown>>('/api/system/health'),

  version: () => request<{ version: string; build_time: string; go_version: string }>('/api/system/version'),
}

export function createQueryWebSocket(): WebSocket {
  const token = getToken()
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const url = `${protocol}//${window.location.host}/api/queries/stream${token ? `?token=${token}` : ''}`
  return new WebSocket(url)
}
