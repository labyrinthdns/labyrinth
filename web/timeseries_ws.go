package web

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// tsSubscription holds the current subscription parameters for a time-series WS client.
type tsSubscription struct {
	Mode      string        `json:"mode"`     // "live" or "history"
	Window    time.Duration `json:"-"`         // 60s for live; 15m/1h/24h for history
	Interval  time.Duration `json:"-"`         // 2s for live; 1m/2m/5m/15m/30m/1h for history
	PushEvery time.Duration `json:"-"`         // 2s for live; 10s for history
	WindowStr string        `json:"window"`    // original string
	InterStr  string        `json:"interval"`  // original string
}

// tsMessage is the JSON envelope pushed to the client.
type tsMessage struct {
	Mode     string   `json:"mode"`
	Window   string   `json:"window"`
	Interval string   `json:"interval"`
	Buckets  []Bucket `json:"buckets"`
}

// tsClientUpdate is sent by the client to change subscription on the fly.
type tsClientUpdate struct {
	Mode     string `json:"mode"`
	Window   string `json:"window"`
	Interval string `json:"interval"`
}

// validTSSubscriptions defines the allowed (window → interval[]) combos.
var validTSSubscriptions = map[string][]string{
	"live": {"1s"},
	"15m":  {"1m"},
	"1h":   {"2m", "5m"},
	"24h":  {"15m", "30m", "1h"},
}

// parseTSSubscription validates and builds a tsSubscription from string params.
func parseTSSubscription(mode, windowStr, intervalStr string) (*tsSubscription, bool) {
	if mode == "" {
		mode = "live"
	}

	// Normalise: for live mode, window and interval are fixed.
	if mode == "live" {
		return &tsSubscription{
			Mode:      "live",
			Window:    60 * time.Second,
			Interval:  1 * time.Second,
			PushEvery: 1 * time.Second,
			WindowStr: "1m",
			InterStr:  "1s",
		}, true
	}

	if mode != "history" {
		return nil, false
	}

	allowed, ok := validTSSubscriptions[windowStr]
	if !ok {
		return nil, false
	}

	found := false
	if intervalStr == "" {
		intervalStr = allowed[0] // default to first option
		found = true
	} else {
		for _, a := range allowed {
			if a == intervalStr {
				found = true
				break
			}
		}
	}
	if !found {
		return nil, false
	}

	window, err := time.ParseDuration(windowStr)
	if err != nil {
		// Handle "24h" etc.
		switch windowStr {
		case "15m":
			window = 15 * time.Minute
		case "1h":
			window = time.Hour
		case "24h":
			window = 24 * time.Hour
		default:
			return nil, false
		}
	}

	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		return nil, false
	}

	return &tsSubscription{
		Mode:      "history",
		Window:    window,
		Interval:  interval,
		PushEvery: 10 * time.Second,
		WindowStr: windowStr,
		InterStr:  intervalStr,
	}, true
}

// handleTimeSeriesWS handles WebSocket connections for time-series streaming.
// Query params: mode=live|history, window=15m|1h|24h, interval=1m|2m|5m|15m|30m|1h
func (s *AdminServer) handleTimeSeriesWS(w http.ResponseWriter, r *http.Request) {
	// H-2: enforce same-origin for WS upgrade.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		s.logger.Error("timeseries ws accept failed", "error", err)
		return
	}
	conn.SetReadLimit(MaxWebSocketMessageBytes)
	defer conn.Close(websocket.StatusNormalClosure, "closing")

	q := r.URL.Query()
	sub, ok := parseTSSubscription(q.Get("mode"), q.Get("window"), q.Get("interval"))
	if !ok {
		conn.Close(websocket.StatusPolicyViolation, "invalid subscription params")
		return
	}

	ctx := r.Context()

	// Channel for subscription updates from client messages.
	var subMu sync.Mutex

	// Read goroutine: listen for client subscription updates.
	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var update tsClientUpdate
			if err := json.Unmarshal(data, &update); err != nil {
				continue
			}
			newSub, ok := parseTSSubscription(update.Mode, update.Window, update.Interval)
			if !ok {
				continue
			}
			subMu.Lock()
			*sub = *newSub
			subMu.Unlock()
		}
	}()

	// Send initial snapshot. Hold subMu while reading the subscription
	// pointer: the read goroutine started above can be concurrently
	// rewriting *sub if a client races a subscription update against
	// the initial push. Without the lock, the data race is real even
	// though the loop's later ticker fires DO copy-under-lock. Pass a
	// copy so we don't hold the lock across the network write.
	subMu.Lock()
	initialSub := *sub
	subMu.Unlock()
	if err := s.pushTimeSeries(ctx, conn, &initialSub); err != nil {
		return
	}

	// Ticker loop. Use initialSub (copied under subMu above) rather
	// than dereferencing *sub here — the read goroutine spawned for
	// client subscription updates can be concurrently rewriting *sub,
	// so reading sub.PushEvery directly is a data race that the race
	// detector flags. lastPush is seeded from the same initial copy
	// so the comparison at the first tick is meaningful (otherwise
	// lastPush is zero and the first tick fires a redundant
	// ticker.Reset to the same interval).
	ticker := time.NewTicker(initialSub.PushEvery)
	defer ticker.Stop()

	// Keepalive ping — see handleQueryStreamWS for rationale.
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	lastPush := initialSub.PushEvery
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
		case <-ticker.C:
			subMu.Lock()
			currentSub := *sub
			subMu.Unlock()

			// Adjust ticker if push interval changed.
			if currentSub.PushEvery != lastPush {
				ticker.Reset(currentSub.PushEvery)
				lastPush = currentSub.PushEvery
			}

			if err := s.pushTimeSeries(ctx, conn, &currentSub); err != nil {
				return
			}
		}
	}
}

// pushTimeSeries sends a single time-series snapshot to the WebSocket client.
func (s *AdminServer) pushTimeSeries(ctx context.Context, conn *websocket.Conn, sub *tsSubscription) error {
	buckets := s.timeSeries.SnapshotAggregated(sub.Window, sub.Interval)
	if buckets == nil {
		buckets = []Bucket{}
	}

	msg := tsMessage{
		Mode:     sub.Mode,
		Window:   sub.WindowStr,
		Interval: sub.InterStr,
		Buckets:  buckets,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageText, data)
}
