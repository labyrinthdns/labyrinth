package web

import (
	"sync"
	"time"
)

const (
	bucketInterval = 1 * time.Second
	maxBuckets     = 3600 // 1 hour at 1s intervals
)

// Bucket represents an aggregated time-series data point.
type Bucket struct {
	Timestamp    string  `json:"timestamp"`
	Queries      int64   `json:"queries"`
	CacheHits    int64   `json:"cache_hits"`
	CacheMisses  int64   `json:"cache_misses"`
	Errors       int64   `json:"errors"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
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
