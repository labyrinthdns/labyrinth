package web

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	bucketInterval = 1 * time.Second
	maxBuckets     = 86400 // 24 hours at 1s intervals
)

// Bucket represents an aggregated time-series data point.
type Bucket struct {
	Timestamp          string  `json:"timestamp"`
	Queries            int64   `json:"queries"`
	CacheHits          int64   `json:"cache_hits"`
	CacheMisses        int64   `json:"cache_misses"`
	Errors             int64   `json:"errors"`
	AvgLatencyMs       float64 `json:"avg_latency_ms"`
	CacheHitRatio      float64 `json:"cache_hit_ratio"`
	FallbackQueries    int64   `json:"fallback_queries"`
	FallbackRecoveries int64   `json:"fallback_recoveries"`
}

// activeBucket holds the mutable counters for the current time window.
// Kept for tests that inspect/manipulate the in-flight bucket; the hot
// path uses atomics and mirrors into this under mu on rotate/snapshot.
type activeBucket struct {
	ts                 time.Time
	queries            int64
	cacheHits          int64
	cacheMisses        int64
	errors             int64
	totalLatency       float64
	fallbackQueries    int64
	fallbackRecoveries int64
}

// TimeSeriesAggregator collects rolling bucketed counters at 1-second intervals.
// Record is lock-free on the steady-state path (same second); rotation and
// Snapshot take mu.
type TimeSeriesAggregator struct {
	mu      sync.Mutex
	buckets []Bucket
	current *activeBucket // mirror of hot counters; tests may poke this

	// Hot-path atomics for the in-flight second.
	curSec         atomic.Int64 // unix second; 0 = uninitialized
	queries        atomic.Int64
	cacheHits      atomic.Int64
	cacheMisses    atomic.Int64
	errors         atomic.Int64
	totalLatencyUs atomic.Int64 // sum of latency in microseconds
	fallbackQ      atomic.Int64
	fallbackR      atomic.Int64
}

// NewTimeSeriesAggregator creates a new time-series aggregator.
func NewTimeSeriesAggregator() *TimeSeriesAggregator {
	return &TimeSeriesAggregator{
		buckets: make([]Bucket, 0, maxBuckets),
	}
}

// Record records a single query into the current time bucket.
func (ts *TimeSeriesAggregator) Record(cached bool, latencyMs float64, isError bool) {
	sec := time.Now().Unix()
	if ts.curSec.Load() != sec {
		ts.rotateTo(sec)
	}

	ts.queries.Add(1)
	if cached {
		ts.cacheHits.Add(1)
	} else {
		ts.cacheMisses.Add(1)
	}
	if isError {
		ts.errors.Add(1)
	}
	if latencyMs > 0 && !math.IsNaN(latencyMs) && !math.IsInf(latencyMs, 0) {
		ts.totalLatencyUs.Add(int64(latencyMs * 1000))
	}
}

// RecordFallback records one fallback query attempt and optionally one recovery.
func (ts *TimeSeriesAggregator) RecordFallback(query, recovery int64) {
	sec := time.Now().Unix()
	if ts.curSec.Load() != sec {
		ts.rotateTo(sec)
	}
	if query != 0 {
		ts.fallbackQ.Add(query)
	}
	if recovery != 0 {
		ts.fallbackR.Add(recovery)
	}
}

// rotateTo flushes hot counters into buckets when the second boundary moves.
func (ts *TimeSeriesAggregator) rotateTo(sec int64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	cur := ts.curSec.Load()
	if cur == sec {
		return
	}
	if cur == 0 {
		// Tests may inject a stale current mirror before any Record.
		if ts.current != nil && ts.current.ts.Unix() < sec {
			ts.flushMirrorLocked()
		}
		ts.curSec.Store(sec)
		ts.current = &activeBucket{ts: time.Unix(sec, 0).UTC()}
		return
	}

	// Flush every elapsed second between cur and sec (usually just one).
	// The first flush carries real counters; later seconds are empty
	// continuity buckets (hot atomics already zeroed).
	for s := cur; s < sec; s++ {
		ts.flushHotLocked(s)
	}
	ts.curSec.Store(sec)
	ts.current = &activeBucket{ts: time.Unix(sec, 0).UTC()}
}

// flushHotLocked swaps out hot atomics into a sealed Bucket for sec.
// Must be called with ts.mu held. Leaves hot counters at zero.
func (ts *TimeSeriesAggregator) flushHotLocked(sec int64) {
	q := ts.queries.Swap(0)
	hits := ts.cacheHits.Swap(0)
	misses := ts.cacheMisses.Swap(0)
	errs := ts.errors.Swap(0)
	latUs := ts.totalLatencyUs.Swap(0)
	fbQ := ts.fallbackQ.Swap(0)
	fbR := ts.fallbackR.Swap(0)

	var avg float64
	if q > 0 {
		avg = float64(latUs) / 1000.0 / float64(q)
	}
	b := Bucket{
		Timestamp:          time.Unix(sec, 0).UTC().Format(time.RFC3339),
		Queries:            q,
		CacheHits:          hits,
		CacheMisses:        misses,
		Errors:             errs,
		AvgLatencyMs:       avg,
		FallbackQueries:    fbQ,
		FallbackRecoveries: fbR,
	}
	ts.buckets = append(ts.buckets, b)
	ts.trimLocked()

	// Keep current mirror in sync for tests that inspect it after rotate.
	ts.current = &activeBucket{ts: time.Unix(sec, 0).UTC()}
}

func (ts *TimeSeriesAggregator) trimLocked() {
	if len(ts.buckets) > maxBuckets {
		excess := len(ts.buckets) - maxBuckets
		copy(ts.buckets, ts.buckets[excess:])
		ts.buckets = ts.buckets[:maxBuckets]
	}
}

// flushCurrentLocked converts the active hot counters to a bucket.
// Kept for coverage/tests that call it directly under mu.
func (ts *TimeSeriesAggregator) flushCurrentLocked() {
	sec := ts.curSec.Load()
	if sec == 0 && ts.current == nil {
		return
	}
	if sec == 0 && ts.current != nil {
		// Test-injected current without hot atomics — flush the mirror.
		ts.flushMirrorLocked()
		return
	}
	ts.flushHotLocked(sec)
	// After an explicit flush, start a fresh second mirror at the same sec
	// so subsequent Records in this second accumulate again.
	ts.curSec.Store(sec)
	ts.current = &activeBucket{ts: time.Unix(sec, 0).UTC()}
}

// flushMirrorLocked seals ts.current (test-injected) into buckets.
func (ts *TimeSeriesAggregator) flushMirrorLocked() {
	if ts.current == nil {
		return
	}
	cur := ts.current
	var avg float64
	if cur.queries > 0 {
		avg = cur.totalLatency / float64(cur.queries)
	}
	b := Bucket{
		Timestamp:          cur.ts.UTC().Format(time.RFC3339),
		Queries:            cur.queries,
		CacheHits:          cur.cacheHits,
		CacheMisses:        cur.cacheMisses,
		Errors:             cur.errors,
		AvgLatencyMs:       avg,
		FallbackQueries:    cur.fallbackQueries,
		FallbackRecoveries: cur.fallbackRecoveries,
	}
	if cur.queries == 0 {
		b = Bucket{Timestamp: cur.ts.UTC().Format(time.RFC3339)}
	}
	ts.buckets = append(ts.buckets, b)
	ts.trimLocked()
	ts.current = nil
}

// syncMirrorLocked copies hot atomics into current for test inspection.
func (ts *TimeSeriesAggregator) syncMirrorLocked() {
	sec := ts.curSec.Load()
	if sec == 0 {
		return
	}
	q := ts.queries.Load()
	ts.current = &activeBucket{
		ts:                 time.Unix(sec, 0).UTC(),
		queries:            q,
		cacheHits:          ts.cacheHits.Load(),
		cacheMisses:        ts.cacheMisses.Load(),
		errors:             ts.errors.Load(),
		totalLatency:       float64(ts.totalLatencyUs.Load()) / 1000.0,
		fallbackQueries:    ts.fallbackQ.Load(),
		fallbackRecoveries: ts.fallbackR.Load(),
	}
}

// rotateLocked flushes when the interval has elapsed. Must hold ts.mu.
// Compatibility shim for older call sites/tests.
func (ts *TimeSeriesAggregator) rotateLocked(now time.Time) {
	sec := now.Unix()
	cur := ts.curSec.Load()
	if cur == 0 {
		// Prefer test-injected current with an old timestamp.
		if ts.current != nil {
			bucketStart := now.Truncate(bucketInterval)
			if !ts.current.ts.Equal(bucketStart) {
				ts.flushMirrorLocked()
				ts.curSec.Store(sec)
				ts.current = &activeBucket{ts: time.Unix(sec, 0).UTC()}
			}
			return
		}
		ts.curSec.Store(sec)
		ts.current = &activeBucket{ts: time.Unix(sec, 0).UTC()}
		return
	}
	if cur == sec {
		ts.syncMirrorLocked()
		return
	}
	// Release-and-reenter pattern avoided: rotateTo needs mu; we're already holding it.
	for s := cur; s < sec; s++ {
		ts.flushHotLocked(s)
	}
	ts.curSec.Store(sec)
	ts.current = &activeBucket{ts: time.Unix(sec, 0).UTC()}
}

// Snapshot returns all buckets within the given time window.
func (ts *TimeSeriesAggregator) Snapshot(window time.Duration) []Bucket {
	now := time.Now()
	cutoff := now.Add(-window)

	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.rotateLocked(now)
	ts.syncMirrorLocked()

	var result []Bucket
	for _, b := range ts.buckets {
		t, err := time.Parse(time.RFC3339, b.Timestamp)
		if err != nil {
			continue
		}
		if t.After(cutoff) || t.Equal(cutoff) {
			result = append(result, b)
		}
	}

	// Include current hot bucket
	if ts.current != nil && ts.current.queries > 0 {
		avgLatency := float64(0)
		if ts.current.queries > 0 {
			avgLatency = ts.current.totalLatency / float64(ts.current.queries)
		}
		cur := Bucket{
			Timestamp:          ts.current.ts.UTC().Format(time.RFC3339),
			Queries:            ts.current.queries,
			CacheHits:          ts.current.cacheHits,
			CacheMisses:        ts.current.cacheMisses,
			Errors:             ts.current.errors,
			AvgLatencyMs:       avgLatency,
			FallbackQueries:    ts.current.fallbackQueries,
			FallbackRecoveries: ts.current.fallbackRecoveries,
		}
		t := ts.current.ts
		if t.After(cutoff) || t.Equal(cutoff) {
			result = append(result, cur)
		}
	}

	return result
}

// LatestBuckets returns up to n most recent sealed+current buckets (for WS delta).
func (ts *TimeSeriesAggregator) LatestBuckets(n int) []Bucket {
	if n <= 0 {
		return nil
	}
	snap := ts.Snapshot(time.Duration(n+1) * bucketInterval)
	if len(snap) <= n {
		return snap
	}
	return snap[len(snap)-n:]
}

// ForceRotateForTest flushes hot counters into buckets without advancing the
// logical second. Used by unit tests that previously rewound current.ts.
func (ts *TimeSeriesAggregator) ForceRotateForTest() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	sec := ts.curSec.Load()
	if sec == 0 {
		if ts.current != nil {
			ts.flushMirrorLocked()
		}
		return
	}
	ts.flushHotLocked(sec)
	ts.curSec.Store(sec)
	ts.current = &activeBucket{ts: time.Unix(sec, 0).UTC()}
}

// SnapshotAggregated returns buckets within the given window, aggregated into
// super-buckets of the given interval. For example, window=15m and interval=1m
// produces ~15 data points. Each super-bucket sums queries/hits/misses/errors
// and computes a weighted-average latency plus cache-hit ratio.
func (ts *TimeSeriesAggregator) SnapshotAggregated(window, interval time.Duration) []Bucket {
	raw := ts.Snapshot(window)
	if len(raw) == 0 || interval <= bucketInterval {
		// No aggregation needed — add cache_hit_ratio to raw buckets.
		for i := range raw {
			total := raw[i].CacheHits + raw[i].CacheMisses
			if total > 0 {
				raw[i].CacheHitRatio = float64(raw[i].CacheHits) / float64(total)
			}
		}
		return raw
	}

	intervalSec := int64(interval.Seconds())
	type acc struct {
		bucketStart        int64
		queries            int64
		cacheHits          int64
		cacheMisses        int64
		errors             int64
		totalLatency       float64
		fallbackQueries    int64
		fallbackRecoveries int64
	}

	var groups []acc

	for _, b := range raw {
		t, err := time.Parse(time.RFC3339, b.Timestamp)
		if err != nil {
			continue
		}
		epoch := t.Unix()
		groupStart := epoch - (epoch % intervalSec)

		if len(groups) == 0 || groups[len(groups)-1].bucketStart != groupStart {
			groups = append(groups, acc{bucketStart: groupStart})
		}
		g := &groups[len(groups)-1]
		g.queries += b.Queries
		g.cacheHits += b.CacheHits
		g.cacheMisses += b.CacheMisses
		g.errors += b.Errors
		g.totalLatency += b.AvgLatencyMs * float64(b.Queries)
		g.fallbackQueries += b.FallbackQueries
		g.fallbackRecoveries += b.FallbackRecoveries
	}

	out := make([]Bucket, 0, len(groups))
	for _, g := range groups {
		var avgLat float64
		if g.queries > 0 {
			avgLat = g.totalLatency / float64(g.queries)
		}
		var hitRatio float64
		total := g.cacheHits + g.cacheMisses
		if total > 0 {
			hitRatio = float64(g.cacheHits) / float64(total)
		}
		out = append(out, Bucket{
			Timestamp:          time.Unix(g.bucketStart, 0).UTC().Format(time.RFC3339),
			Queries:            g.queries,
			CacheHits:          g.cacheHits,
			CacheMisses:        g.cacheMisses,
			Errors:             g.errors,
			AvgLatencyMs:       avgLat,
			CacheHitRatio:      hitRatio,
			FallbackQueries:    g.fallbackQueries,
			FallbackRecoveries: g.fallbackRecoveries,
		})
	}
	return out
}
