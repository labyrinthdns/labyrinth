import { afterEach, beforeEach, expect, it, vi } from 'vitest'

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

function jsonResponse(version: string) {
  return new Response(JSON.stringify({ latest_version: version, current_version: '1', update_available: true }), {
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeEach(() => { vi.resetModules() })
afterEach(() => { vi.unstubAllGlobals() })

it.each([
  { mutation: 'force', failOld: false, finishFreshFirst: false },
  { mutation: 'force', failOld: true, finishFreshFirst: false },
  { mutation: 'force', failOld: false, finishFreshFirst: true },
  { mutation: 'apply', failOld: false, finishFreshFirst: false },
])('preserves the replacement cache after $mutation (old error=$failOld, fresh first=$finishFreshFirst)', async ({ mutation, failOld, finishFreshFirst }) => {
  const oldGate = deferred<Response>()
  const newGate = deferred<Response>()
  const fetchMock = vi.fn()
    .mockImplementationOnce(() => oldGate.promise)
    .mockResolvedValueOnce(jsonResponse('mutation'))
    .mockImplementationOnce(() => newGate.promise)
  vi.stubGlobal('fetch', fetchMock)
  const { api } = await import('./client')

  const old = api.checkUpdate().catch((error: Error) => error)
  if (mutation === 'force') await api.checkUpdate(true)
  else await api.applyUpdate()
  const fresh = api.checkUpdate()
  if (finishFreshFirst) {
    newGate.resolve(jsonResponse('fresh'))
    await fresh
  }
  if (failOld) oldGate.reject(new Error('old request failed'))
  else oldGate.resolve(jsonResponse('stale'))
  await old

  const joined = api.checkUpdate()
  expect(fetchMock).toHaveBeenCalledTimes(3)
  if (!finishFreshFirst) newGate.resolve(jsonResponse('fresh'))
  const [freshValue, joinedValue] = await Promise.all([fresh, joined])
  expect(freshValue.latest_version).toBe('fresh')
  expect(joinedValue.latest_version).toBe('fresh')
  expect((await api.checkUpdate()).latest_version).toBe('fresh')
  expect(fetchMock).toHaveBeenCalledTimes(3)
})
