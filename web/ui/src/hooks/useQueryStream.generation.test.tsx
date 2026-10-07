import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createQueryWebSocket } from '@/api/client'
import { useQueryStream } from './useWebSocket'

vi.mock('@/api/client', () => ({ createQueryWebSocket: vi.fn() }))

describe('useQueryStream socket ownership', () => {
  let sockets: WebSocket[]

  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
    sockets = []
    vi.mocked(createQueryWebSocket).mockImplementation(() => {
      const socket = {
        onopen: null, onclose: null, onerror: null, onmessage: null, close: vi.fn(),
      } as unknown as WebSocket
      sockets.push(socket)
      return socket
    })
  })

  afterEach(() => {
    cleanup()
    vi.useRealTimers()
  })

  it.each(['replacement', 'pause and resume'] as const)('ignores gated old publication after %s', async (transition) => {
    const { result } = renderHook(() => useQueryStream(10, 10))
    const old = sockets[0]
    const stale = old.onmessage!
    let release!: () => void
    const gate = new Promise<void>((resolve) => { release = resolve })
    const completion = gate.then(() => stale.call(old, { data: '{"id":99}' } as MessageEvent))

    if (transition === 'replacement') {
      act(() => { window.dispatchEvent(new Event('focus')) })
    } else {
      act(() => { result.current.setPaused(true) })
      act(() => { result.current.setPaused(false) })
    }
    const current = sockets[1]
    act(() => {
      current.onmessage!.call(current, { data: '{"id":2}' } as MessageEvent)
      vi.advanceTimersByTime(10)
    })
    expect(result.current.queries.map((q) => q.id)).toEqual([2])
    await act(async () => { release(); await completion })
    act(() => { vi.advanceTimersByTime(10) })
    expect(result.current.queries.map((q) => q.id)).toEqual([2])
  })

  it('ignores a gated callback after unmount before parsing its data', async () => {
    const { unmount } = renderHook(() => useQueryStream(10, 10))
    const old = sockets[0]
    const stale = old.onmessage!
    const readData = vi.fn(() => '{"id":99}')
    const event = { get data() { return readData() } } as MessageEvent
    let release!: () => void
    const gate = new Promise<void>((resolve) => { release = resolve })
    const completion = gate.then(() => stale.call(old, event))
    unmount()
    await act(async () => { release(); await completion })
    expect(readData).not.toHaveBeenCalled()
  })
})
