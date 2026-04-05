package web

import (
	"sync"
	"time"
)

const (
	bucketInterval = 1 * time.Second
	maxBuckets     = 86400 // 24 hours at 1s intervals
)

// Bucket represents an aggregated time-series data point.
type Bucket struct {
	Timestamp     string  `json:"timestamp"`
	Queries       int64   `json:"queries"`
	CacheHits     int64   `json:"cache_hits"`
	CacheMisses   int64   `json:"cache_misses"`
	Errors        int64   `json:"errors"`
	AvgLatencyMs  float64 `json:"avg_latency_ms"`
	CacheHitRatio float64 `json:"cache_hit_ratio"`
}

// activeBucket holds the mutable counters for the current time window.
type activeBucket struct {
	ts           time.Time
	queries      int64
	cacheHits    int64
	cacheMisses  int64
	errors       int64
	totalLatency float64
}

// TimeSeriesAggregator collects rolling 1-hour bucketed counters at 1-second intervals.
type TimeSeriesAggregator struct {
	mu      sync.Mutex
	buckets []Bucket
	current *activeBucket
}

// NewTimeSeriesAggregator creates a new time-series aggregator.
func NewTimeSeriesAggregator() *TimeSeriesAggregator {
	return &TimeSeriesAggregator{
		buckets: make([]Bucket, 0, maxBuckets),
	}
}

// Record records a single query into the current time bucket.
func (ts *TimeSeriesAggregator) Record(cached bool, latencyMs float64, isError bool) {
	now := time.Now()

	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.rotateLocked(now)

	ts.current.queries++
	ts.current.totalLatency += latencyMs
	if cached {
		ts.current.cacheHits++
	} else {
		ts.current.cacheMisses++
	}
	if isError {
		ts.current.errors++
	}
}

// rotateLocked flushes the current bucket and starts a new one if the interval has elapsed.
// Must be called with ts.mu held.
func (ts *TimeSeriesAggregator) rotateLocked(now time.Time) {
	bucketStart := now.Truncate(bucketInterval)

	if ts.current == nil {
		ts.current = &activeBucket{ts: bucketStart}
		return
	}

	if bucketStart.Equal(ts.current.ts) {
		return
	}

	// Flush current bucket
	ts.flushCurrentLocked()

	// Start new bucket
	ts.current = &activeBucket{ts: bucketStart}
}

// flushCurrentLocked converts the active bucket to an immutable Bucket and appends it.
// Must be called with ts.mu held.
func (ts *TimeSeriesAggregator) flushCurrentLocked() {
	if ts.current == nil || ts.current.queries == 0 {
		if ts.current != nil {
			// Even empty buckets get recorded for continuity
			b := Bucket{
				Timestamp: ts.current.ts.UTC().Format(time.RFC3339),
			}
			ts.buckets = append(ts.buckets, b)
		}
	} else {
		avgLatency := ts.current.totalLatency / float64(ts.current.queries)
		b := Bucket{
			Timestamp:    ts.current.ts.UTC().Format(time.RFC3339),
			Queries:      ts.current.queries,
			CacheHits:    ts.current.cacheHits,
			CacheMisses:  ts.current.cacheMisses,
			Errors:       ts.current.errors,
			AvgLatencyMs: avgLatency,
		}
		ts.buckets = append(ts.buckets, b)
	}

	// Trim to max buckets
	if len(ts.buckets) > maxBuckets {
		excess := len(ts.buckets) - maxBuckets
		copy(ts.buckets, ts.buckets[excess:])
		ts.buckets = ts.buckets[:maxBuckets]
	}
}

// Snapshot returns all buckets within the given time window.
func (ts *TimeSeriesAggregator) Snapshot(window time.Duration) []Bucket {
	now := time.Now()
	cutoff := now.Add(-window)

	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Rotate to flush current bucket if needed
	ts.rotateLocked(now)

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

	// Include current bucket
	if ts.current != nil && ts.current.queries > 0 {
		avgLatency := ts.current.totalLatency / float64(ts.current.queries)
		cur := Bucket{
			Timestamp:    ts.current.ts.UTC().Format(time.RFC3339),
			Queries:      ts.current.queries,
			CacheHits:    ts.current.cacheHits,
			CacheMisses:  ts.current.cacheMisses,
			Errors:       ts.current.errors,
			AvgLatencyMs: avgLatency,
		}
		t := ts.current.ts
		if t.After(cutoff) || t.Equal(cutoff) {
			result = append(result, cur)
		}
	}

	return result
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
		bucketStart  int64
		queries      int64
		cacheHits    int64
		cacheMisses  int64
		errors       int64
		totalLatency float64
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
			Timestamp:     time.Unix(g.bucketStart, 0).UTC().Format(time.RFC3339),
			Queries:       g.queries,
			CacheHits:     g.cacheHits,
			CacheMisses:   g.cacheMisses,
			Errors:        g.errors,
			AvgLatencyMs:  avgLat,
			CacheHitRatio: hitRatio,
		})
	}
	return out
}
