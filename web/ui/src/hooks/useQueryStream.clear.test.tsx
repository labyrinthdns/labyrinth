import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createQueryWebSocket } from '@/api/client'
import { useQueryStream } from '@/hooks/useWebSocket'
vi.mock('@/api/client', () => ({ createQueryWebSocket: vi.fn() }))
class AuditSocket {
 readyState=1
 onopen: ((event: Event) => void) | null = null
 onclose: ((event: Event) => void) | null = null
 onerror: ((event: Event) => void) | null = null
 onmessage: ((event: MessageEvent) => void) | null = null
 close() { this.readyState=3 }
 emit(id: number) { this.onmessage?.(new MessageEvent('message',{data:JSON.stringify({id,qname:`example-${id}.com`})})) }
}
beforeEach(() => {vi.clearAllMocks();vi.useFakeTimers()})
afterEach(() => {cleanup();vi.useRealTimers()})
it('clears queries that arrived before clear but have not been flushed', () => {
 const socket=new AuditSocket()
 vi.mocked(createQueryWebSocket).mockReturnValue(socket as unknown as WebSocket)
 const {result}=renderHook(()=>useQueryStream(10,10))
 act(()=>{socket.emit(1);vi.advanceTimersByTime(10)})
 expect(result.current.queries.map(q=>q.id)).toEqual([1])
 act(()=>result.current.clear())
 expect(result.current.queries).toEqual([]) // unaffected already-flushed control
 act(()=>socket.emit(2))
 act(()=>result.current.clear())
 act(()=>vi.advanceTimersByTime(10))
 console.log(`EXPECTED: ids=[] ACTUAL: ids=${JSON.stringify(result.current.queries.map(q=>q.id))}`)
 if(result.current.queries.length!==0)throw new Error('PROBLEM CONFIRMED')
 act(() => {result.current.clear();result.current.clear()})
 act(() => {socket.emit(3);vi.advanceTimersByTime(10)})
 expect(result.current.queries.map(q=>q.id)).toEqual([3]) // post-clear arrival edge
 act(() => result.current.clear())
 act(() => vi.advanceTimersByTime(20))
 expect(result.current.queries).toEqual([]) // repeated and empty clear edges
 console.log('FIX VERIFIED')
})
