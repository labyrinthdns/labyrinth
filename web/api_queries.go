package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"nhooyr.io/websocket"
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
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Allow connections from any origin for dashboard
	})
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

	for {
		select {
		case <-ctx.Done():
			return
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
