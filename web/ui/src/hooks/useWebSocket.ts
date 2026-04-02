import { useEffect, useRef, useState, useCallback } from 'react'
import { createQueryWebSocket } from '@/api/client'
import type { QueryEntry } from '@/api/types'

export function useQueryStream(maxEntries = 200) {
  const [queries, setQueries] = useState<QueryEntry[]>([])
  const [connected, setConnected] = useState(false)
  const [paused, setPaused] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const pausedRef = useRef(false)

  pausedRef.current = paused

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const ws = createQueryWebSocket()
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => {
      setConnected(false)
      // Auto-reconnect after 3 seconds
      setTimeout(connect, 3000)
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
    connect()
    return () => {
      wsRef.current?.close()
    }
  }, [connect])

  const clear = useCallback(() => setQueries([]), [])

  return { queries, connected, paused, setPaused, clear }
}
