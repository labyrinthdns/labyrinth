package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// ServeHTTP implements http.Handler for the /metrics endpoint.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	m.mu.RLock()
	defer m.mu.RUnlock()

	for qtype, counter := range m.queriesTotal {
		fmt.Fprintf(w, "labyrinth_queries_total{type=%q} %d\n", qtype, counter.Load())
	}
	for rcode, counter := range m.responsesTotal {
		fmt.Fprintf(w, "labyrinth_responses_total{rcode=%q} %d\n", rcode, counter.Load())
	}
	fmt.Fprintf(w, "labyrinth_cache_hits_total %d\n", m.cacheHits.Load())
	fmt.Fprintf(w, "labyrinth_cache_misses_total %d\n", m.cacheMisses.Load())
	fmt.Fprintf(w, "labyrinth_cache_evictions_total %d\n", m.cacheEvictions.Load())
	fmt.Fprintf(w, "labyrinth_upstream_queries_total %d\n", m.upstreamQueries.Load())
	fmt.Fprintf(w, "labyrinth_upstream_errors_total %d\n", m.upstreamErrors.Load())
	fmt.Fprintf(w, "labyrinth_rate_limited_total %d\n", m.rateLimited.Load())
	fmt.Fprintf(w, "labyrinth_fallback_queries_total %d\n", m.fallbackQueries.Load())
	fmt.Fprintf(w, "labyrinth_fallback_recoveries_total %d\n", m.fallbackRecoveries.Load())
	fmt.Fprintf(w, "labyrinth_uptime_seconds %.0f\n", time.Since(m.startTime).Seconds())
	fmt.Fprintf(w, "labyrinth_goroutines %d\n", runtime.NumGoroutine())

	m.queryDurations.writeTo(w, "labyrinth_query_duration_seconds")
}
