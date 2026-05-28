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
	// Y34 — failure cache + server-cookie cache.
	fmt.Fprintf(w, "labyrinth_failure_cache_hits_total %d\n", m.failureCacheHits.Load())
	fmt.Fprintf(w, "labyrinth_failure_cache_misses_total %d\n", m.failureCacheMisses.Load())
	fmt.Fprintf(w, "labyrinth_server_cookie_cache_hits_total %d\n", m.serverCookieCacheHits.Load())
	fmt.Fprintf(w, "labyrinth_server_cookie_cache_misses_total %d\n", m.serverCookieCacheMisses.Load())
	// Y35 — RFC 8198 aggressive synthesis.
	fmt.Fprintf(w, "labyrinth_nsec_aggressive_synth_total{kind=\"nxdomain\"} %d\n", m.nsecAggressiveSynthNX.Load())
	fmt.Fprintf(w, "labyrinth_nsec_aggressive_synth_total{kind=\"nodata\"} %d\n", m.nsecAggressiveSynthNoData.Load())
	fmt.Fprintf(w, "labyrinth_nsec3_aggressive_synth_total{kind=\"nxdomain\"} %d\n", m.nsec3AggressiveSynthNX.Load())
	fmt.Fprintf(w, "labyrinth_nsec3_aggressive_synth_total{kind=\"nodata\"} %d\n", m.nsec3AggressiveSynthND.Load())
	// Y36 — cookie retry + stale-while-refresh.
	fmt.Fprintf(w, "labyrinth_outbound_badcookie_retries_total %d\n", m.outboundBadCookieRetries.Load())
	fmt.Fprintf(w, "labyrinth_stale_while_refresh_total %d\n", m.staleWhileRefreshTriggers.Load())
	// DNSSEC verdict breakdown — Prometheus operators want to alert
	// on "Bogus rate > 0.1%" across the resolver, not just the
	// dashboard. Exposed as a single metric with a `verdict` label.
	fmt.Fprintf(w, "labyrinth_dnssec_verdicts_total{verdict=\"secure\"} %d\n", m.dnssecSecure.Load())
	fmt.Fprintf(w, "labyrinth_dnssec_verdicts_total{verdict=\"insecure\"} %d\n", m.dnssecInsecure.Load())
	fmt.Fprintf(w, "labyrinth_dnssec_verdicts_total{verdict=\"bogus\"} %d\n", m.dnssecBogus.Load())
	fmt.Fprintf(w, "labyrinth_blocked_queries_total %d\n", m.blockedQueries.Load())
	// EDE emission breakdown — one series per info code observed.
	// Snapshot (lock dance handled by EDECounts) so we don't iterate
	// the map under m.mu (we're already holding it; calling EDECounts
	// would re-lock). Inline read instead.
	for code, counter := range m.edeCounts {
		fmt.Fprintf(w, "labyrinth_ede_emissions_total{code=\"%d\"} %d\n", code, counter.Load())
	}
	fmt.Fprintf(w, "labyrinth_uptime_seconds %.0f\n", time.Since(m.startTime).Seconds())
	fmt.Fprintf(w, "labyrinth_goroutines %d\n", runtime.NumGoroutine())

	m.queryDurations.writeTo(w, "labyrinth_query_duration_seconds")
}
