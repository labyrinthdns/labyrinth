import { useEffect, useRef, useState, useCallback } from 'react'
import { createQueryWebSocket } from '@/api/client'
import type { QueryEntry } from '@/api/types'

export function useQueryStream(maxEntries = 200) {
  const [queries, setQueries] = useState<QueryEntry[]>([])
  const [connected, setConnected] = useState(false)
  const [paused, setPaused] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const pausedRef = useRef(false)
  const visibleRef = useRef<boolean>(typeof document === 'undefined' ? true : !document.hidden)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectAttemptRef = useRef(0)
  const flushRafRef = useRef<number | null>(null)
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
        if (flushRafRef.current != null) return
        flushRafRef.current = requestAnimationFrame(() => {
          flushRafRef.current = null
          const batch = queueRef.current
          queueRef.current = []
          if (batch.length === 0) return
          setQueries((prev) => {
            const next = [...batch.reverse(), ...prev]
            return next.length > maxEntries ? next.slice(0, maxEntries) : next
          })
        })
      } catch { /* ignore parse errors */ }
    }
  }, [maxEntries])

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
      if (flushRafRef.current != null) {
        cancelAnimationFrame(flushRafRef.current)
        flushRafRef.current = null
      }
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [connect])

  const clear = useCallback(() => setQueries([]), [])

  return { queries, connected, paused, setPaused, clear }
}
