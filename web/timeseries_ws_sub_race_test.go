package web

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestTimeSeriesWS_TickerInitRaceVsClientUpdate pins the v0.8.27 fix:
// handleTimeSeriesWS must seed its main-loop ticker from the
// `initialSub` snapshot copied under `subMu`, not from `sub.PushEvery`
// dereferenced off the shared subscription pointer.
//
// What was racy before v0.8.27:
//
//	ticker := time.NewTicker(sub.PushEvery)
//
// while the read goroutine spawned a few lines above was doing
// `*sub = *newSub` whenever a client posted a subscription update
// frame. Both lived in the same goroutine-spawn happens-before edge
// (the goroutine is launched before the ticker line), but the read
// goroutine could fire its mutation arbitrarily quickly — under the
// race detector, hammering the WS with rapid mode/window/interval
// updates while the server was still constructing the ticker
// reliably produced a flag.
//
// The fix copies the subscription to `initialSub` under `subMu`
// once, before any goroutines exist, and reads ticker/lastPush from
// that copy. The shared `*sub` is then only ever touched under the
// lock by the rest of the loop.
//
// The pin opens a WS connection in history mode, then immediately
// blasts client-side subscription updates at it. Under -race, the
// pre-fix code flags; after the fix, this passes silently.
func TestTimeSeriesWS_TickerInitRaceVsClientUpdate(t *testing.T) {
	srv := testAdminServer(t)
	// Seed some data so the initial snapshot does work (we want the
	// server goroutine to actually spend time in pushTimeSeries, not
	// return early on empty buckets).
	for i := 0; i < 25; i++ {
		srv.timeSeries.Record(true, 1.5, false)
	}

	base := startTestWSServer(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, base+"/api/stats/timeseries/ws?mode=history&window=15m&interval=1m", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Drain the initial snapshot so the server's main loop reaches
	// the ticker-init line.
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read initial: %v", err)
	}

	// Hammer subscription updates from the client side. Each accepted
	// update lands in the read goroutine and rewrites *sub. With the
	// pre-fix ticker line, a sufficiently fast client racing the loop
	// init flagged the detector.
	updates := []string{
		`{"mode":"history","window":"1h","interval":"2m"}`,
		`{"mode":"history","window":"1h","interval":"5m"}`,
		`{"mode":"history","window":"24h","interval":"15m"}`,
		`{"mode":"history","window":"24h","interval":"30m"}`,
		`{"mode":"history","window":"24h","interval":"1h"}`,
		`{"mode":"history","window":"15m","interval":"1m"}`,
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	i := 0
	for time.Now().Before(deadline) {
		writeCtx, wcancel := context.WithTimeout(ctx, 200*time.Millisecond)
		err := conn.Write(writeCtx, websocket.MessageText, []byte(updates[i%len(updates)]))
		wcancel()
		if err != nil {
			break
		}
		i++
	}

	// If we got here under -race with no data-race report, the fix
	// holds. The pin asserts absence-of-race, surfaced by the harness
	// auto-failing the test when -race is on.
}
