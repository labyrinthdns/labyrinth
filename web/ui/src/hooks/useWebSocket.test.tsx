import { act, renderHook } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { QueryEntry } from '@/api/types'
import { createQueryWebSocket } from '@/api/client'
import { useQueryStream } from './useWebSocket'

vi.mock('@/api/client', () => ({
  createQueryWebSocket: vi.fn(),
}))

class MockWS {
  static readonly OPEN = 1
  static readonly CLOSED = 3

  public readyState = 0
  public onopen: ((event: Event) => void) | null = null
  public onclose: ((event: Event) => void) | null = null
  public onerror: ((event: Event) => void) | null = null
  public onmessage: ((event: MessageEvent) => void) | null = null

  open() {
    this.readyState = MockWS.OPEN
    this.onopen?.(new Event('open'))
  }

  close() {
    this.readyState = MockWS.CLOSED
    this.onclose?.(new Event('close'))
  }

  emitMessage(entry: QueryEntry) {
    const data = JSON.stringify(entry)
    this.onmessage?.({ data } as MessageEvent)
  }
}

function mkEntry(id: number): QueryEntry {
  return {
    id,
    ts: new Date(2026, 0, 1, 0, 0, id).toISOString(),
    client: '127.0.0.1',
    qname: `example-${id}.com`,
    qtype: 'A',
    rcode: 'NOERROR',
    cached: false,
    duration_ms: 1.2,
    global_num: id,
    client_num: id,
  }
}

describe('useQueryStream', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
  })

  it('flushes queued messages and enforces max entries', () => {
    const sockets: MockWS[] = []
    vi.mocked(createQueryWebSocket).mockImplementation(() => {
      const ws = new MockWS()
      sockets.push(ws)
      return ws as unknown as WebSocket
    })

    const { result, unmount } = renderHook(() => useQueryStream(2, 10))

    act(() => sockets[0].open())
    act(() => {
      sockets[0].emitMessage(mkEntry(1))
      sockets[0].emitMessage(mkEntry(2))
      sockets[0].emitMessage(mkEntry(3))
    })
    act(() => {
      vi.advanceTimersByTime(20)
    })

    expect(result.current.connected).toBe(true)
    expect(result.current.queries).toHaveLength(2)
    expect(result.current.queries.map((q) => q.id)).toEqual([3, 2])

    unmount()
    vi.useRealTimers()
  })

  it('ignores incoming messages while paused', () => {
    const sockets: MockWS[] = []
    vi.mocked(createQueryWebSocket).mockImplementation(() => {
      const ws = new MockWS()
      sockets.push(ws)
      return ws as unknown as WebSocket
    })

    const { result, unmount } = renderHook(() => useQueryStream(10, 10))
    act(() => sockets[0].open())

    act(() => {
      result.current.setPaused(true)
    })
    act(() => {
      sockets[0].emitMessage(mkEntry(1))
      vi.advanceTimersByTime(20)
    })

    expect(result.current.paused).toBe(true)
    expect(result.current.queries).toHaveLength(0)

    unmount()
    vi.useRealTimers()
  })

  it('reconnects with backoff when socket closes', () => {
    const sockets: MockWS[] = []
    vi.mocked(createQueryWebSocket).mockImplementation(() => {
      const ws = new MockWS()
      sockets.push(ws)
      return ws as unknown as WebSocket
    })

    const { unmount } = renderHook(() => useQueryStream(10, 10))
    expect(createQueryWebSocket).toHaveBeenCalledTimes(1)

    act(() => sockets[0].close())
    expect(createQueryWebSocket).toHaveBeenCalledTimes(1)

    act(() => {
      vi.advanceTimersByTime(3000)
    })
    expect(createQueryWebSocket).toHaveBeenCalledTimes(2)

    unmount()
    vi.useRealTimers()
  })
})
