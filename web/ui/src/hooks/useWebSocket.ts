import { useEffect, useRef, useState, useCallback } from 'react'
import { createQueryWebSocket } from '@/api/client'
import type { QueryEntry } from '@/api/types'

export function useQueryStream(maxEntries = 200) {
  const [queries, setQueries] = useState<QueryEntry[]>([])
  const [connected, setConnected] = useState(false)
  const [paused, setPaused] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const pausedRef = useRef(false)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const unmountedRef = useRef(false)

  pausedRef.current = paused

  const connect = useCallback(() => {
    if (unmountedRef.current) return
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const ws = createQueryWebSocket()
    wsRef.current = ws

    ws.onopen = () => {
      if (!unmountedRef.current) setConnected(true)
    }
    ws.onclose = () => {
      if (unmountedRef.current) return
      setConnected(false)
      // Auto-reconnect after 3 seconds
      reconnectTimerRef.current = setTimeout(connect, 3000)
    }
    ws.onerror = () => ws.close()
    ws.onmessage = (event) => {
      if (pausedRef.current) return
      try {
        const entry = JSON.parse(event.data) as QueryEntry
        setQueries((prev) => {
          const next = [entry, ...prev]
          return next.length > maxEntries ? next.slice(0, maxEntries) : next
        })
      } catch { /* ignore parse errors */ }
    }
  }, [maxEntries])

  useEffect(() => {
    unmountedRef.current = false
    connect()
    return () => {
      unmountedRef.current = true
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
      wsRef.current?.close()
    }
  }, [connect])

  const clear = useCallback(() => setQueries([]), [])

  return { queries, connected, paused, setPaused, clear }
}
