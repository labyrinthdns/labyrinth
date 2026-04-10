import { beforeEach, describe, expect, it, vi } from 'vitest'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('api/client', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.restoreAllMocks()
    localStorage.clear()
  })

  it('sets, reads, and clears auth token', async () => {
    const mod = await import('./client')
    expect(mod.getToken()).toBeNull()

    mod.setToken('abc')
    expect(mod.getToken()).toBe('abc')

    mod.clearToken()
    expect(mod.getToken()).toBeNull()
  })

  it('adds authorization header when token exists', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ username: 'alice' }))
    vi.stubGlobal('fetch', fetchMock)

    const mod = await import('./client')
    mod.setToken('token-123')
    await mod.api.me()

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    const headers = options.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer token-123')
  })

  it('caches version endpoint responses', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ version: '1.2.3', build_time: 'now', go_version: 'go1.26' }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const mod = await import('./client')
    await mod.api.version()
    await mod.api.version()

    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('force update bypasses update cache', async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(
        jsonResponse({ current_version: '1.0', latest_version: '1.1', update_available: true }),
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    const mod = await import('./client')
    await mod.api.checkUpdate()
    await mod.api.checkUpdate()
    await mod.api.checkUpdate(true)

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect((fetchMock.mock.calls[1] as [string])[0]).toContain('force=1')
  })

  it('clears token on unauthorized responses', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const fetchMock = vi.fn().mockResolvedValue(new Response('unauthorized', { status: 401 }))
    vi.stubGlobal('fetch', fetchMock)

    const mod = await import('./client')
    mod.setToken('will-be-cleared')

    await expect(mod.api.me()).rejects.toThrow('Unauthorized')
    expect(mod.getToken()).toBeNull()
  })

  it('builds websocket URLs with token and query parameters', async () => {
    const wsCtor = vi.fn().mockImplementation((url: string) => ({ url }))
    vi.stubGlobal('WebSocket', wsCtor as unknown as typeof WebSocket)

    const mod = await import('./client')
    mod.setToken('tok')
    mod.createQueryWebSocket()
    mod.createTimeSeriesWebSocket('history', '15m', '1m')

    const firstUrl = (wsCtor.mock.calls[0] as [string])[0]
    const secondUrl = (wsCtor.mock.calls[1] as [string])[0]
    expect(firstUrl).toContain('/api/queries/stream?token=tok')
    expect(secondUrl).toContain('/api/stats/timeseries/ws?')
    expect(secondUrl).toContain('token=tok')
    expect(secondUrl).toContain('mode=history')
    expect(secondUrl).toContain('window=15m')
    expect(secondUrl).toContain('interval=1m')
  })
})
