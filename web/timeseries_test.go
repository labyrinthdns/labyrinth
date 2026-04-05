package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/metrics"
	"nhooyr.io/websocket"
)

// ===========================================================================
// SnapshotAggregated tests
// ===========================================================================

func TestSnapshotAggregated_NoData(t *testing.T) {
	ts := NewTimeSeriesAggregator()
	result := ts.SnapshotAggregated(15*time.Minute, time.Minute)
	if len(result) != 0 {
		t.Fatalf("expected 0 buckets, got %d", len(result))
	}
}

func TestSnapshotAggregated_RawPassthrough(t *testing.T) {
	ts := NewTimeSeriesAggregator()
	ts.Record(true, 2.0, false)
	ts.Record(false, 4.0, false)

	// interval <= bucketInterval → should return raw buckets with cache_hit_ratio
	result := ts.SnapshotAggregated(time.Hour, time.Second)
	if len(result) == 0 {
		t.Fatal("expected at least 1 bucket")
	}
	found := false
	for _, b := range result {
		if b.Queries > 0 {
			found = true
			total := b.CacheHits + b.CacheMisses
			if total > 0 {
				expectedRatio := float64(b.CacheHits) / float64(total)
				if b.CacheHitRatio != expectedRatio {
					t.Fatalf("cache_hit_ratio mismatch: want %f, got %f", expectedRatio, b.CacheHitRatio)
				}
			}
		}
	}
	if !found {
		t.Fatal("no bucket with queries found")
	}
}

func TestSnapshotAggregated_Aggregation(t *testing.T) {
	ts := NewTimeSeriesAggregator()

	// Manually inject buckets spanning multiple minutes.
	now := time.Now().Truncate(time.Minute)
	ts.mu.Lock()
	for i := 0; i < 120; i++ {
		b := Bucket{
			Timestamp:    now.Add(-time.Duration(120-i) * time.Second).UTC().Format(time.RFC3339),
			Queries:      1,
			CacheHits:    1,
			CacheMisses:  0,
			Errors:       0,
			AvgLatencyMs: 2.0,
		}
		ts.buckets = append(ts.buckets, b)
	}
	ts.mu.Unlock()

	// Aggregate 120 1-second buckets into 1-minute super-buckets → ~2 groups.
	result := ts.SnapshotAggregated(5*time.Minute, time.Minute)
	if len(result) < 2 {
		t.Fatalf("expected at least 2 aggregated buckets, got %d", len(result))
	}

	// Each minute bucket should have ~60 queries.
	for _, b := range result {
		if b.Queries < 50 || b.Queries > 70 {
			t.Logf("bucket %s: queries=%d (expecting ~60)", b.Timestamp, b.Queries)
		}
		if b.CacheHitRatio < 0.9 {
			t.Fatalf("expected high cache_hit_ratio, got %f", b.CacheHitRatio)
		}
	}
}

func TestSnapshotAggregated_WeightedLatency(t *testing.T) {
	ts := NewTimeSeriesAggregator()

	now := time.Now().Truncate(time.Minute)
	ts.mu.Lock()
	// Two 1s buckets in the same minute:
	// bucket 1: 10 queries, avg 2ms → total latency 20ms
	// bucket 2: 5 queries, avg 10ms → total latency 50ms
	// Weighted average = 70ms / 15 queries = 4.666ms
	ts.buckets = append(ts.buckets, Bucket{
		Timestamp:    now.Add(-2 * time.Second).UTC().Format(time.RFC3339),
		Queries:      10,
		CacheHits:    5,
		CacheMisses:  5,
		AvgLatencyMs: 2.0,
	})
	ts.buckets = append(ts.buckets, Bucket{
		Timestamp:    now.Add(-1 * time.Second).UTC().Format(time.RFC3339),
		Queries:      5,
		CacheHits:    3,
		CacheMisses:  2,
		AvgLatencyMs: 10.0,
	})
	ts.mu.Unlock()

	result := ts.SnapshotAggregated(time.Minute, time.Minute)
	if len(result) != 1 {
		t.Fatalf("expected 1 aggregated bucket, got %d", len(result))
	}

	b := result[0]
	if b.Queries != 15 {
		t.Fatalf("expected 15 queries, got %d", b.Queries)
	}
	if b.CacheHits != 8 {
		t.Fatalf("expected 8 hits, got %d", b.CacheHits)
	}
	if b.CacheMisses != 7 {
		t.Fatalf("expected 7 misses, got %d", b.CacheMisses)
	}
	// Weighted avg: (10*2 + 5*10) / 15 = 70/15 ≈ 4.666
	expectedAvg := 70.0 / 15.0
	if b.AvgLatencyMs < expectedAvg-0.01 || b.AvgLatencyMs > expectedAvg+0.01 {
		t.Fatalf("expected weighted avg latency ~%.3f, got %.3f", expectedAvg, b.AvgLatencyMs)
	}
	// Ratio: 8 / (8+7) ≈ 0.533
	expectedRatio := 8.0 / 15.0
	if b.CacheHitRatio < expectedRatio-0.01 || b.CacheHitRatio > expectedRatio+0.01 {
		t.Fatalf("expected hit ratio ~%.3f, got %.3f", expectedRatio, b.CacheHitRatio)
	}
}

func TestSnapshotAggregated_EmptyBucketsIgnored(t *testing.T) {
	ts := NewTimeSeriesAggregator()
	now := time.Now().Truncate(time.Minute)
	ts.mu.Lock()
	// Add empty buckets (queries=0)
	for i := 0; i < 10; i++ {
		ts.buckets = append(ts.buckets, Bucket{
			Timestamp: now.Add(-time.Duration(10-i) * time.Second).UTC().Format(time.RFC3339),
		})
	}
	ts.mu.Unlock()

	result := ts.SnapshotAggregated(time.Minute, time.Minute)
	// Should still produce a bucket, just with 0 queries.
	for _, b := range result {
		if b.Queries != 0 {
			t.Fatalf("expected 0 queries in empty aggregated bucket, got %d", b.Queries)
		}
		if b.AvgLatencyMs != 0 {
			t.Fatalf("expected 0 avg latency in empty bucket, got %f", b.AvgLatencyMs)
		}
	}
}

func TestSnapshotAggregated_24hWindow(t *testing.T) {
	ts := NewTimeSeriesAggregator()
	now := time.Now().Truncate(time.Hour)
	ts.mu.Lock()
	// Add data at 3 different hours.
	for _, h := range []int{1, 12, 23} {
		ts.buckets = append(ts.buckets, Bucket{
			Timestamp:    now.Add(-time.Duration(24-h) * time.Hour).UTC().Format(time.RFC3339),
			Queries:      100,
			CacheHits:    80,
			CacheMisses:  20,
			AvgLatencyMs: 5.0,
		})
	}
	ts.mu.Unlock()

	result := ts.SnapshotAggregated(24*time.Hour, time.Hour)
	if len(result) < 3 {
		t.Fatalf("expected at least 3 hourly buckets, got %d", len(result))
	}
}

func TestSnapshotAggregated_CacheHitRatioZeroDiv(t *testing.T) {
	ts := NewTimeSeriesAggregator()
	now := time.Now()
	ts.mu.Lock()
	// Bucket with queries but no cache hits or misses (both 0).
	ts.buckets = append(ts.buckets, Bucket{
		Timestamp:    now.Add(-time.Second).UTC().Format(time.RFC3339),
		Queries:      5,
		CacheHits:    0,
		CacheMisses:  0,
		AvgLatencyMs: 1.0,
	})
	ts.mu.Unlock()

	result := ts.SnapshotAggregated(time.Minute, time.Minute)
	if len(result) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(result))
	}
	if result[0].CacheHitRatio != 0 {
		t.Fatalf("expected 0 cache_hit_ratio with no hits/misses, got %f", result[0].CacheHitRatio)
	}
}

// ===========================================================================
// parseTSSubscription tests
// ===========================================================================

func TestParseTSSubscription_LiveMode(t *testing.T) {
	sub, ok := parseTSSubscription("live", "", "")
	if !ok {
		t.Fatal("expected valid live subscription")
	}
	if sub.Mode != "live" {
		t.Fatalf("expected mode live, got %s", sub.Mode)
	}
	if sub.Window != 60*time.Second {
		t.Fatalf("expected 60s window, got %v", sub.Window)
	}
	if sub.Interval != 1*time.Second {
		t.Fatalf("expected 1s interval, got %v", sub.Interval)
	}
	if sub.PushEvery != 1*time.Second {
		t.Fatalf("expected 1s push rate, got %v", sub.PushEvery)
	}
}

func TestParseTSSubscription_DefaultMode(t *testing.T) {
	sub, ok := parseTSSubscription("", "", "")
	if !ok {
		t.Fatal("expected valid subscription for empty mode (defaults to live)")
	}
	if sub.Mode != "live" {
		t.Fatalf("expected live mode as default, got %s", sub.Mode)
	}
}

func TestParseTSSubscription_History15m(t *testing.T) {
	sub, ok := parseTSSubscription("history", "15m", "1m")
	if !ok {
		t.Fatal("expected valid 15m subscription")
	}
	if sub.Mode != "history" {
		t.Fatalf("expected history mode, got %s", sub.Mode)
	}
	if sub.Window != 15*time.Minute {
		t.Fatalf("expected 15m window, got %v", sub.Window)
	}
	if sub.Interval != time.Minute {
		t.Fatalf("expected 1m interval, got %v", sub.Interval)
	}
	if sub.PushEvery != 10*time.Second {
		t.Fatalf("expected 10s push rate, got %v", sub.PushEvery)
	}
}

func TestParseTSSubscription_History1h(t *testing.T) {
	for _, iv := range []string{"2m", "5m"} {
		sub, ok := parseTSSubscription("history", "1h", iv)
		if !ok {
			t.Fatalf("expected valid 1h/%s subscription", iv)
		}
		if sub.Window != time.Hour {
			t.Fatalf("expected 1h window, got %v", sub.Window)
		}
	}
}

func TestParseTSSubscription_History24h(t *testing.T) {
	for _, iv := range []string{"15m", "30m", "1h"} {
		sub, ok := parseTSSubscription("history", "24h", iv)
		if !ok {
			t.Fatalf("expected valid 24h/%s subscription", iv)
		}
		if sub.Window != 24*time.Hour {
			t.Fatalf("expected 24h window, got %v", sub.Window)
		}
	}
}

func TestParseTSSubscription_DefaultInterval(t *testing.T) {
	// Empty interval should default to the first option.
	sub, ok := parseTSSubscription("history", "1h", "")
	if !ok {
		t.Fatal("expected valid subscription with default interval")
	}
	if sub.Interval != 2*time.Minute {
		t.Fatalf("expected default interval 2m for 1h window, got %v", sub.Interval)
	}
}

func TestParseTSSubscription_InvalidMode(t *testing.T) {
	_, ok := parseTSSubscription("bogus", "", "")
	if ok {
		t.Fatal("expected rejection for unknown mode")
	}
}

func TestParseTSSubscription_InvalidWindow(t *testing.T) {
	_, ok := parseTSSubscription("history", "3h", "")
	if ok {
		t.Fatal("expected rejection for invalid window")
	}
}

func TestParseTSSubscription_InvalidInterval(t *testing.T) {
	_, ok := parseTSSubscription("history", "15m", "5m")
	if ok {
		t.Fatal("expected rejection for invalid interval/window combo")
	}
}

// ===========================================================================
// HTTP endpoint tests — interval param
// ===========================================================================

func TestHandleTimeSeries_WithInterval(t *testing.T) {
	srv := testAdminServer(t)
	// Record some data.
	for i := 0; i < 5; i++ {
		srv.timeSeries.Record(true, 1.0, false)
	}

	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=5m&interval=1m", nil)
	w := httptest.NewRecorder()
	srv.handleTimeSeries(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["bucket_seconds"] != float64(60) {
		t.Fatalf("expected bucket_seconds=60 with interval=1m, got %v", body["bucket_seconds"])
	}
}

func TestHandleTimeSeries_InvalidInterval(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=5m&interval=garbage", nil)
	w := httptest.NewRecorder()
	srv.handleTimeSeries(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestHandleTimeSeries_24hWindow(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=24h&interval=1h", nil)
	w := httptest.NewRecorder()
	srv.handleTimeSeries(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestHandleTimeSeries_CappedAt24h(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=48h", nil)
	w := httptest.NewRecorder()
	srv.handleTimeSeries(w, req)

	// Should succeed but be capped at 24h.
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

// ===========================================================================
// WebSocket handler tests
// ===========================================================================

func startTestWSServer(t *testing.T, srv *AdminServer) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats/timeseries/ws", srv.handleTimeSeriesWS)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return "ws" + ts.URL[4:] // http:// → ws://
}

func TestTimeSeriesWS_LiveMode(t *testing.T) {
	srv := testAdminServer(t)
	// Pre-populate some data.
	for i := 0; i < 10; i++ {
		srv.timeSeries.Record(true, 1.5, false)
	}

	base := startTestWSServer(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, base+"/api/stats/timeseries/ws?mode=live", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Should receive initial snapshot.
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read initial: %v", err)
	}

	var msg tsMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg.Mode != "live" {
		t.Fatalf("expected mode=live, got %s", msg.Mode)
	}
	if msg.Window != "1m" {
		t.Fatalf("expected window=1m, got %s", msg.Window)
	}
	if msg.Interval != "1s" {
		t.Fatalf("expected interval=1s, got %s", msg.Interval)
	}
}

func TestTimeSeriesWS_HistoryMode(t *testing.T) {
	srv := testAdminServer(t)
	srv.timeSeries.Record(false, 3.0, true)

	base := startTestWSServer(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, base+"/api/stats/timeseries/ws?mode=history&window=15m&interval=1m", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read initial: %v", err)
	}

	var msg tsMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg.Mode != "history" {
		t.Fatalf("expected mode=history, got %s", msg.Mode)
	}
	if msg.Window != "15m" {
		t.Fatalf("expected window=15m, got %s", msg.Window)
	}
	if msg.Interval != "1m" {
		t.Fatalf("expected interval=1m, got %s", msg.Interval)
	}
}

func TestTimeSeriesWS_InvalidParams(t *testing.T) {
	srv := testAdminServer(t)
	base := startTestWSServer(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, base+"/api/stats/timeseries/ws?mode=history&window=99h&interval=1m", nil)
	if err != nil {
		// Connection refused or handshake error — acceptable.
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Server should close with policy violation.
	_, _, err = conn.Read(ctx)
	if err == nil {
		t.Fatal("expected connection to be closed for invalid params")
	}
}

func TestTimeSeriesWS_ReceivesPeriodicUpdates(t *testing.T) {
	srv := testAdminServer(t)
	srv.timeSeries.Record(true, 1.0, false)

	base := startTestWSServer(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, base+"/api/stats/timeseries/ws?mode=live", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Read initial snapshot.
	_, _, err = conn.Read(ctx)
	if err != nil {
		t.Fatalf("read initial: %v", err)
	}

	// Record more data while connected.
	srv.timeSeries.Record(false, 5.0, true)

	// Read next periodic push (live mode pushes every 2s).
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read periodic: %v", err)
	}

	var msg tsMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg.Mode != "live" {
		t.Fatalf("expected live mode in periodic update")
	}
}

func TestTimeSeriesWS_ClientSubscriptionUpdate(t *testing.T) {
	srv := testAdminServer(t)
	srv.timeSeries.Record(true, 1.0, false)

	base := startTestWSServer(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Connect in live mode.
	conn, _, err := websocket.Dial(ctx, base+"/api/stats/timeseries/ws?mode=live", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Read initial.
	_, _, err = conn.Read(ctx)
	if err != nil {
		t.Fatalf("read initial: %v", err)
	}

	// Send subscription update to switch to history mode.
	update := tsClientUpdate{Mode: "history", Window: "1h", Interval: "5m"}
	updateData, _ := json.Marshal(update)
	writeCtx, writeCancel := context.WithTimeout(ctx, 2*time.Second)
	err = conn.Write(writeCtx, websocket.MessageText, updateData)
	writeCancel()
	if err != nil {
		t.Fatalf("write update: %v", err)
	}

	// Read next push — should reflect history mode eventually.
	// Note: there's a race between the ticker and the update, so we may
	// get one more live push first. Read up to 3 messages.
	gotHistory := false
	for i := 0; i < 3; i++ {
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		var msg tsMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.Mode == "history" && msg.Window == "1h" && msg.Interval == "5m" {
			gotHistory = true
			break
		}
	}
	if !gotHistory {
		t.Fatal("did not receive history mode update within 3 messages")
	}
}

// ===========================================================================
// Bucket struct CacheHitRatio field test
// ===========================================================================

func TestBucket_CacheHitRatioJSON(t *testing.T) {
	b := Bucket{
		Timestamp:     "2026-04-05T12:00:00Z",
		Queries:       100,
		CacheHits:     80,
		CacheMisses:   20,
		Errors:        2,
		AvgLatencyMs:  3.5,
		CacheHitRatio: 0.8,
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ratio, ok := decoded["cache_hit_ratio"]
	if !ok {
		t.Fatal("missing cache_hit_ratio in JSON output")
	}
	if ratio.(float64) != 0.8 {
		t.Fatalf("expected cache_hit_ratio=0.8, got %v", ratio)
	}
}

// ===========================================================================
// maxBuckets constant test
// ===========================================================================

func TestMaxBuckets_Is86400(t *testing.T) {
	if maxBuckets != 86400 {
		t.Fatalf("expected maxBuckets=86400 (24h), got %d", maxBuckets)
	}
}

// ===========================================================================
// Integration: pushTimeSeries helper
// ===========================================================================

func TestPushTimeSeries(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Web: config.WebConfig{
			Enabled:        true,
			Addr:           "127.0.0.1:0",
			QueryLogBuffer: 100,
		},
	}
	srv, err := NewAdminServer(cfg, c, m, nil, logger, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Record data.
	srv.timeSeries.Record(true, 1.0, false)
	srv.timeSeries.Record(false, 3.0, true)

	// Start a test WS server and connect.
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		sub := &tsSubscription{
			Mode:      "history",
			Window:    5 * time.Minute,
			Interval:  time.Minute,
			WindowStr: "5m",
			InterStr:  "1m",
		}
		_ = srv.pushTimeSeries(r.Context(), conn, sub)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsURL := "ws" + ts.URL[4:] + "/ws"
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var msg tsMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg.Mode != "history" {
		t.Fatalf("expected mode=history, got %s", msg.Mode)
	}
	if msg.Window != "5m" {
		t.Fatalf("expected window=5m, got %s", msg.Window)
	}
}
