import { useEffect, useRef, useState, useCallback } from 'react'
import { createQueryWebSocket } from '@/api/client'
import type { QueryEntry } from '@/api/types'

export function useQueryStream(maxEntries = 200, flushIntervalMs = 200) {
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

  const teardown = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    const stale = wsRef.current
    if (stale) {
      stale.onopen = null
      stale.onclose = null
      stale.onerror = null
      stale.onmessage = null
      try { stale.close() } catch { /* noop */ }
    }
    wsRef.current = null
  }, [])

  const connect = useCallback(function connectImpl() {
    if (unmountedRef.current) return
    if (!visibleRef.current) return
    if (pausedRef.current) return

    teardown()

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
      if (!visibleRef.current || pausedRef.current) return
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
      if (wsRef.current !== ws || unmountedRef.current || pausedRef.current) return
      try {
        const entry = JSON.parse(event.data) as QueryEntry
        queueRef.current.push(entry)
      } catch { /* ignore parse errors */ }
    }
  }, [teardown])

  useEffect(() => {
    unmountedRef.current = false
    connect()
    const onVisibility = () => {
      visibleRef.current = !document.hidden
      if (visibleRef.current) {
        // Reset backoff so the user-visible reconnect happens immediately,
        // not after a 30s exponential wait carried over from while-hidden.
        reconnectAttemptRef.current = 0
        if (!pausedRef.current) connect()
        return
      }
      teardown()
      setConnected(false)
    }
    const onOnline = () => {
      if (!visibleRef.current || pausedRef.current) return
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
      teardown()
    }
  }, [connect, teardown])

  // Pause = unsubscribe: tear down the socket so the server stops fan-out.
  // Resume reconnects only when no socket is active (avoids double-connect on mount).
  useEffect(() => {
    if (paused) {
      queueRef.current = []
      teardown()
      setConnected(false)
      return
    }
    if (!wsRef.current && !unmountedRef.current && visibleRef.current) {
      reconnectAttemptRef.current = 0
      connect()
    }
  }, [paused, connect, teardown])

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

  const clear = useCallback(() => {
    queueRef.current = []
    setQueries([])
  }, [])

  return { queries, connected, paused, setPaused, clear }
}
