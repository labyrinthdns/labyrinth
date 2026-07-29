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
  const lastMsgAtRef = useRef<number>(0)
  const paramsRef = useRef(params)
  paramsRef.current = params

  const connect = useCallback(function connectImpl() {
    if (unmountedRef.current) return
    if (!visibleRef.current) return

    // Cancel any pending reconnect timer — a new connect supersedes it.
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }

    // Tear down any existing socket. Do NOT trust readyState === OPEN: after
    // sleep/network drop the browser keeps the socket OPEN for minutes before
    // noticing the peer is gone (zombie connection — root cause of the
    // dashboard freezing when returning to a backgrounded tab).
    const stale = wsRef.current
    if (stale) {
      stale.onopen = null
      stale.onclose = null
      stale.onerror = null
      stale.onmessage = null
      try { stale.close() } catch { /* noop */ }
    }

    const p = paramsRef.current
    const ws = createTimeSeriesWebSocket(p.mode, p.window, p.interval)
    wsRef.current = ws
    lastMsgAtRef.current = Date.now()

    ws.onopen = () => {
      if (wsRef.current !== ws) return
      reconnectAttemptRef.current = 0
      lastMsgAtRef.current = Date.now()
      if (!unmountedRef.current) setConnected(true)
    }

    ws.onclose = () => {
      if (wsRef.current !== ws) return
      wsRef.current = null
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

    ws.onerror = () => {
      try { ws.close() } catch { /* noop */ }
    }

    ws.onmessage = (event) => {
      lastMsgAtRef.current = Date.now()
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

  // Visibility / network handling.
  useEffect(() => {
    const onVisibility = () => {
      visibleRef.current = !document.hidden
      if (visibleRef.current) {
        // Reset backoff so the user-visible reconnect is immediate, not
        // delayed by any backoff that accumulated while hidden.
        reconnectAttemptRef.current = 0
        connect()
      } else {
        disconnect()
      }
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
      document.removeEventListener('visibilitychange', onVisibility)
      window.removeEventListener('online', onOnline)
      window.removeEventListener('focus', onOnline)
    }
  }, [connect, disconnect])

  // Watchdog: server pushes every 1s (live) / 10s (history). If we haven't
  // seen a message in 30s while visible, the connection is a zombie — force
  // reconnect. Covers laptop-wake and silent proxy idle timeouts.
  useEffect(() => {
    const id = setInterval(() => {
      if (unmountedRef.current || !visibleRef.current) return
      if (wsRef.current?.readyState !== WebSocket.OPEN) return
      if (lastMsgAtRef.current === 0) return
      if (Date.now() - lastMsgAtRef.current > 30000) {
        reconnectAttemptRef.current = 0
        connect()
      }
    }, 10000)
    return () => clearInterval(id)
  }, [connect])

  // Cleanup on unmount.
  useEffect(() => {
    return () => {
      unmountedRef.current = true
      disconnect()
    }
  }, [disconnect])

  return { buckets, connected }
}
