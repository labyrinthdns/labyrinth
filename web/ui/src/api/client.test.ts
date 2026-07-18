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

  it('does not send Bearer header (auth uses HttpOnly cookie)', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ username: 'alice' }))
    vi.stubGlobal('fetch', fetchMock)

    const mod = await import('./client')
    localStorage.setItem('labyrinth_token', 'legacy-token')
    await mod.api.me()

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    const headers = options.headers as Record<string, string>
    expect(headers.Authorization).toBeUndefined()
  })

  it('encodes user-controlled query parameters', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse({})))
    vi.stubGlobal('fetch', fetchMock)

    const mod = await import('./client')
    await mod.api.cacheLookup('example.test&type=AAAA', 'A&name=other')
    await mod.api.cacheDelete('example.test&type=AAAA', 'A&name=other')
    await mod.api.blocklistCheck('example.test&admin=true')
    await mod.api.timeseries('5m&token=leak')

    const paths = fetchMock.mock.calls.map(([path]) => String(path))
    expect(paths[0]).toBe('/api/cache/lookup?name=example.test%26type%3DAAAA&type=A%26name%3Dother')
    expect(paths[1]).toBe('/api/cache/entry?name=example.test%26type%3DAAAA&type=A%26name%3Dother')
    expect(paths[2]).toBe('/api/blocklist/check?domain=example.test%26admin%3Dtrue')
    expect(paths[3]).toBe('/api/stats/timeseries?window=5m%26token%3Dleak')
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

  it('keeps a login 401 on the login page for inline error handling', async () => {
    window.history.replaceState({}, '', '/login')
    const fetchMock = vi.fn().mockResolvedValue(new Response('unauthorized', { status: 401 }))
    vi.stubGlobal('fetch', fetchMock)

    const mod = await import('./client')

    await expect(mod.api.login('admin', 'wrong')).rejects.toThrow('Unauthorized')
    expect(window.location.pathname).toBe('/login')
  })

  it('builds cookie-authenticated websocket URLs without token query parameters', async () => {
    const wsCtor = vi.fn().mockImplementation((url: string) => ({ url }))
    vi.stubGlobal('WebSocket', wsCtor as unknown as typeof WebSocket)

    const mod = await import('./client')
    localStorage.setItem('labyrinth_token', 'legacy-token')
    mod.createQueryWebSocket()
    mod.createTimeSeriesWebSocket('history', '15m&token=leak', '1m')
    mod.createDiagnosticsTraceSocket()

    const urls = wsCtor.mock.calls.map(([url]) => String(url))
    expect(urls[0]).toMatch(/\/api\/queries\/stream$/)
    expect(urls[1]).toContain('/api/stats/timeseries/ws?')
    expect(urls[1]).toContain('mode=history')
    expect(urls[1]).toContain('window=15m%26token%3Dleak')
    expect(urls[1]).toContain('interval=1m')
    expect(urls[2]).toMatch(/\/api\/diagnostics\/trace$/)
    expect(urls.every((url) => !new URL(url).searchParams.has('token'))).toBe(true)
  })
})
