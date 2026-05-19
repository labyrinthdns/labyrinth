package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
)

// handleRecentQueries handles GET /api/queries/recent?limit=50.
func (s *AdminServer) handleRecentQueries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	entries := s.queryLog.Recent(limit)
	if entries == nil {
		entries = []QueryEntry{}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

// handleQueryStreamWS handles WebSocket upgrade for live query streaming.
// On connect, sends the last 50 entries as backfill, then streams new entries.
func (s *AdminServer) handleQueryStreamWS(w http.ResponseWriter, r *http.Request) {
	// H-2: enforce same-origin for WS upgrade. nhooyr/websocket compares
	// Origin to Host when InsecureSkipVerify is false; missing Origin
	// (non-browser clients) is allowed.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		s.logger.Error("websocket accept failed", "error", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "closing")

	ctx := r.Context()

	// Send backfill of recent entries
	backfill := s.queryLog.Recent(50)
	for _, entry := range backfill {
		data, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = conn.Write(writeCtx, websocket.MessageText, data)
		cancel()
		if err != nil {
			return
		}
	}

	// Subscribe to new entries
	subID, ch := s.queryLog.Subscribe()
	defer s.queryLog.Unsubscribe(subID)

	// Keepalive: send a websocket ping every 30s. This both surfaces dead
	// peers quickly (browser tab in background, laptop asleep, NAT/proxy
	// idle timeout) and keeps intermediaries from silently dropping the
	// connection. Without this, clients can sit on a zombie OPEN socket
	// until TCP RST eventually arrives — minutes later.
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pingTicker.C:
			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return
			}
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = conn.Write(writeCtx, websocket.MessageText, data)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
