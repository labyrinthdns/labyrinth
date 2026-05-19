import { useEffect, useRef, useState, useCallback } from 'react'
import { createQueryWebSocket } from '@/api/client'
import type { QueryEntry } from '@/api/types'

export function useQueryStream(maxEntries = 200, flushIntervalMs = 2000) {
  const [queries, setQueries] = useState<QueryEntry[]>([])
  const [connected, setConnected] = useState(false)
  const [paused, setPaused] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const pausedRef = useRef(false)
  const visibleRef = useRef<boolean>(typeof document === 'undefined' ? true : !document.hidden)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectAttemptRef = useRef(0)
  const queueRef = useRef<QueryEntry[]>([])
  const unmountedRef = useRef(false)

  pausedRef.current = paused

  const connect = useCallback(function connectImpl() {
    if (unmountedRef.current) return
    if (!visibleRef.current) return

    // Cancel any pending reconnect timer — a new connect supersedes it.
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }

    // Tear down any existing socket. Do NOT trust readyState === OPEN as a
    // signal that the connection is alive: after sleep/network drop the
    // browser may keep the socket in OPEN state for minutes before noticing
    // the peer is gone (zombie connection).
    const stale = wsRef.current
    if (stale) {
      stale.onopen = null
      stale.onclose = null
      stale.onerror = null
      stale.onmessage = null
      try { stale.close() } catch { /* noop */ }
    }

    const ws = createQueryWebSocket()
    wsRef.current = ws

    ws.onopen = () => {
      if (wsRef.current !== ws) return
      reconnectAttemptRef.current = 0
      if (!unmountedRef.current) setConnected(true)
    }
    ws.onclose = () => {
      // Ignore close events from sockets we've already discarded.
      if (wsRef.current !== ws) return
      wsRef.current = null
      if (unmountedRef.current) return
      setConnected(false)
      if (!visibleRef.current) return
      // Exponential backoff reconnect to avoid unnecessary load when backend is down.
      const attempt = reconnectAttemptRef.current
      const delay = Math.min(3000 * (2 ** attempt), 30000)
      reconnectAttemptRef.current = Math.min(attempt + 1, 6)
      reconnectTimerRef.current = setTimeout(() => {
        connectImpl()
      }, delay)
    }
    ws.onerror = () => {
      try { ws.close() } catch { /* noop */ }
    }
    ws.onmessage = (event) => {
      if (pausedRef.current) return
      try {
        const entry = JSON.parse(event.data) as QueryEntry
        queueRef.current.push(entry)
      } catch { /* ignore parse errors */ }
    }
  }, [])

  useEffect(() => {
    unmountedRef.current = false
    connect()
    const onVisibility = () => {
      visibleRef.current = !document.hidden
      if (visibleRef.current) {
        // Reset backoff so the user-visible reconnect happens immediately,
        // not after a 30s exponential wait carried over from while-hidden.
        reconnectAttemptRef.current = 0
        connect()
        return
      }
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
      wsRef.current?.close()
      wsRef.current = null
      setConnected(false)
    }
    const onOnline = () => {
      if (!visibleRef.current) return
      reconnectAttemptRef.current = 0
      connect()
    }
    document.addEventListener('visibilitychange', onVisibility)
    window.addEventListener('online', onOnline)
    window.addEventListener('focus', onOnline)
    return () => {
      unmountedRef.current = true
      document.removeEventListener('visibilitychange', onVisibility)
      window.removeEventListener('online', onOnline)
      window.removeEventListener('focus', onOnline)
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [connect])

  // Flush strategy:
  // - flushIntervalMs === 0  → real-time: RAF loop flushes every animation frame (~16ms)
  // - flushIntervalMs > 0    → batched: setInterval flushes at the given cadence
  useEffect(() => {
    const flush = () => {
      const batch = queueRef.current
      if (batch.length === 0) return
      queueRef.current = []
      setQueries((prev) => {
        const next = [...batch.reverse(), ...prev]
        return next.length > maxEntries ? next.slice(0, maxEntries) : next
      })
    }

    if (flushIntervalMs === 0) {
      let raf = 0
      const loop = () => {
        flush()
        raf = requestAnimationFrame(loop)
      }
      raf = requestAnimationFrame(loop)
      return () => cancelAnimationFrame(raf)
    }

    const timer = setInterval(flush, flushIntervalMs)
    return () => clearInterval(timer)
  }, [flushIntervalMs, maxEntries])

  const clear = useCallback(() => setQueries([]), [])

  return { queries, connected, paused, setPaused, clear }
}
