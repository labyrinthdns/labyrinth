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
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const ws = createQueryWebSocket()
    wsRef.current = ws

    ws.onopen = () => {
      reconnectAttemptRef.current = 0
      if (!unmountedRef.current) setConnected(true)
    }
    ws.onclose = () => {
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
    ws.onerror = () => ws.close()
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
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      unmountedRef.current = true
      document.removeEventListener('visibilitychange', onVisibility)
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
