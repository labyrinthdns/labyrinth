import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createTimeSeriesWebSocket } from '@/api/client'
import { useTimeSeriesStream, type TSStreamParams } from '@/hooks/useTimeSeriesStream'
vi.mock('@/api/client', () => ({ createTimeSeriesWebSocket: vi.fn() }))
class AuditSocket {
 readyState = 1
 onopen: ((event: Event) => void) | null = null
 onclose: ((event: Event) => void) | null = null
 onerror: ((event: Event) => void) | null = null
 onmessage: ((event: MessageEvent) => void) | null = null
 close() { this.readyState = 3 }
 message(queries: number) { return new MessageEvent('message', { data: JSON.stringify({buckets: [{timestamp:'2026-01-01T00:00:00Z',queries}]}) }) }
}
beforeEach(() => { vi.clearAllMocks(); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-01-01T00:00:00Z')) })
afterEach(() => { cleanup(); vi.useRealTimers() })
it('rejects stale time-series publication after parameters replace the socket', async () => {
 const sockets: AuditSocket[] = []
 vi.mocked(createTimeSeriesWebSocket).mockImplementation(() => { const ws = new AuditSocket(); sockets.push(ws); return ws as unknown as WebSocket })
 const initial: TSStreamParams = {mode:'history',window:'15m',interval:'1m'}
 const {result, rerender, unmount} = renderHook((params: TSStreamParams) => useTimeSeriesStream(params), {initialProps: initial})
 act(() => vi.advanceTimersByTime(50))
 const old = sockets[0]
 act(() => old.onmessage?.(old.message(1)))
 expect(result.current.buckets[0].queries).toBe(1) // unaffected active-socket control
 const lateHandler = old.onmessage
 let release!: () => void
 const gate = new Promise<void>((resolve) => { release = resolve })
 const completion = gate.then(() => lateHandler?.(old.message(99)))
 rerender({...initial, window:'1h'})
 act(() => lateHandler?.(old.message(77)))
 expect(result.current.buckets[0].queries).toBe(1) // disconnected gap edge
 act(() => vi.advanceTimersByTime(50))
 const current = sockets[1]
 act(() => current.onmessage?.(current.message(2)))
 expect(result.current.buckets[0].queries).toBe(2)
 act(() => current.onmessage?.(new MessageEvent('message', {data:'invalid JSON'})))
 expect(result.current.buckets[0].queries).toBe(2) // malformed active message edge
 await act(async () => { release(); await completion })
 console.log(`EXPECTED: current queries=2 ACTUAL: current queries=${result.current.buckets[0].queries}`)
 if (result.current.buckets[0].queries !== 2) throw new Error('PROBLEM CONFIRMED')
 const afterClose = current.onmessage
 unmount()
 const readData = vi.fn(() => '{}')
 const event = new MessageEvent('message')
 Object.defineProperty(event, 'data', {get:readData})
 act(() => afterClose?.(event))
 expect(readData).not.toHaveBeenCalled() // closed owner edge
 console.log('FIX VERIFIED')
})
