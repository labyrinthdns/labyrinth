package web

import (
	"net/http"
	"time"
)

// handleStats handles GET /api/stats — returns metrics snapshot + cache stats as JSON.
func (s *AdminServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	snap := s.metrics.Snapshot()
	cacheStats := s.cache.DetailedStats()

	var hitRatio float64
	total := snap.CacheHits + snap.CacheMisses
	if total > 0 {
		hitRatio = float64(snap.CacheHits) / float64(total)
	}

	resolverReady := false
	if s.resolver != nil {
		resolverReady = s.resolver.IsReady()
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"queries_by_type":      snap.QueriesByType,
		"responses_by_rcode":   snap.ResponsesByRCode,
		"cache_hits":           snap.CacheHits,
		"cache_misses":         snap.CacheMisses,
		"cache_evictions":      snap.CacheEvictions,
		"cache_entries":        cacheStats.Entries,
		"cache_positive":       cacheStats.PositiveEntries,
		"cache_negative":       cacheStats.NegativeEntries,
		"cache_hit_ratio":      hitRatio,
		"upstream_queries":     snap.UpstreamQueries,
		"upstream_errors":      snap.UpstreamErrors,
		"rate_limited":         snap.RateLimited,
		"dnssec_secure":        snap.DNSSECSecure,
		"dnssec_insecure":      snap.DNSSECInsecure,
		"dnssec_bogus":         snap.DNSSECBogus,
		"blocked_queries":      snap.BlockedQueries,
		"fallback_queries":     snap.FallbackQueries,
		"fallback_recoveries":  snap.FallbackRecoveries,
		"uptime_seconds":       snap.UptimeSeconds,
		"goroutines":           snap.Goroutines,
		"query_duration_count": snap.QueryDurationCount,
		"resolver_ready":       resolverReady,
	})
}

// handleTimeSeries handles GET /api/stats/timeseries?window=5m&interval=1m — returns time-bucketed data.
// When interval is specified, raw 1s buckets are aggregated into larger intervals.
func (s *AdminServer) handleTimeSeries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	windowStr := r.URL.Query().Get("window")
	if windowStr == "" {
		windowStr = "5m"
	}

	window, err := time.ParseDuration(windowStr)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid window duration"})
		return
	}

	// Cap at 24 hours
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}

	intervalStr := r.URL.Query().Get("interval")
	resultBucketSec := int(bucketInterval.Seconds())

	var buckets []Bucket
	if intervalStr != "" {
		interval, err := time.ParseDuration(intervalStr)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid interval duration"})
			return
		}
		buckets = s.timeSeries.SnapshotAggregated(window, interval)
		resultBucketSec = int(interval.Seconds())
	} else {
		buckets = s.timeSeries.Snapshot(window)
	}

	if buckets == nil {
		buckets = []Bucket{}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"window":         windowStr,
		"bucket_seconds": resultBucketSec,
		"buckets":        buckets,
	})
}
