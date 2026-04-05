import { useEffect, useRef, useState, useCallback } from 'react'
import { createTimeSeriesWebSocket } from '@/api/client'
import type { TimeSeriesBucket, TimeSeriesWSMessage } from '@/api/types'

export interface TSStreamParams {
  mode: 'live' | 'history'
  window: string   // "15m" | "1h" | "24h" (ignored for live)
  interval: string  // "1m" | "2m" | "5m" | "15m" | "30m" | "1h" (ignored for live)
}

export function useTimeSeriesStream(params: TSStreamParams) {
  const [buckets, setBuckets] = useState<TimeSeriesBucket[]>([])
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectAttemptRef = useRef(0)
  const unmountedRef = useRef(false)
  const visibleRef = useRef<boolean>(typeof document === 'undefined' ? true : !document.hidden)
  const paramsRef = useRef(params)
  paramsRef.current = params

  const connect = useCallback(function connectImpl() {
    if (unmountedRef.current) return
    if (!visibleRef.current) return
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const p = paramsRef.current
    const ws = createTimeSeriesWebSocket(p.mode, p.window, p.interval)
    wsRef.current = ws

    ws.onopen = () => {
      reconnectAttemptRef.current = 0
      if (!unmountedRef.current) setConnected(true)
    }

    ws.onclose = () => {
      if (unmountedRef.current) return
      setConnected(false)
      if (!visibleRef.current) return
      const attempt = reconnectAttemptRef.current
      const delay = Math.min(3000 * (2 ** attempt), 30000)
      reconnectAttemptRef.current = Math.min(attempt + 1, 6)
      reconnectTimerRef.current = setTimeout(() => {
        connectImpl()
      }, delay)
    }

    ws.onerror = () => ws.close()

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as TimeSeriesWSMessage
        if (msg.buckets) {
          setBuckets(msg.buckets)
        }
      } catch { /* ignore parse errors */ }
    }
  }, [])

  // Close and reconnect when params change.
  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    wsRef.current?.close()
    wsRef.current = null
    setConnected(false)
  }, [])

  // Reconnect on param change.
  useEffect(() => {
    unmountedRef.current = false
    disconnect()
    // Small delay to let previous WS close cleanly.
    const t = setTimeout(() => connect(), 50)
    return () => {
      clearTimeout(t)
    }
  }, [params.mode, params.window, params.interval, connect, disconnect])

  // Visibility handling.
  useEffect(() => {
    const onVisibility = () => {
      visibleRef.current = !document.hidden
      if (visibleRef.current) {
        connect()
      } else {
        disconnect()
      }
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [connect, disconnect])

  // Cleanup on unmount.
  useEffect(() => {
    return () => {
      unmountedRef.current = true
      disconnect()
    }
  }, [disconnect])

  return { buckets, connected }
}
