package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// ServeHTTP implements http.Handler for the /metrics endpoint.
//
// Format: Prometheus exposition v0.0.4 (the wire format every scraper
// understands; OpenMetrics is a superset and accepts this too). Every
// metric family is preceded by `# HELP` (one-line description used by
// Grafana auto-docs and `promtool check metrics`) and `# TYPE`
// (counter / gauge / histogram — required by `rate()` family
// semantics in PromQL). Skipping HELP/TYPE makes Labyrinth parse but
// silently downgrade the scraper's metadata, and `promtool check
// metrics` flags every series as missing metadata.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Prometheus scrapers use GET only. Refuse everything else with
	// 405 so a misbehaving probe (or a hostile POST flood at the
	// metrics endpoint, which is often exposed to the public internet
	// for scraping) doesn't hit the snapshot path needlessly.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Metrics are live state — never cache. An intermediate cache
	// serving a 30 s-old payload to a Prometheus scraper would create
	// fake-flat-line panic during an incident.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	m.mu.RLock()
	defer m.mu.RUnlock()

	fmt.Fprintln(w, "# HELP labyrinth_queries_total Total DNS queries received, partitioned by qtype.")
	fmt.Fprintln(w, "# TYPE labyrinth_queries_total counter")
	for qtype, counter := range m.queriesTotal {
		fmt.Fprintf(w, "labyrinth_queries_total{type=%q} %d\n", qtype, counter.Load())
	}

	fmt.Fprintln(w, "# HELP labyrinth_responses_total Total DNS responses sent, partitioned by rcode.")
	fmt.Fprintln(w, "# TYPE labyrinth_responses_total counter")
	for rcode, counter := range m.responsesTotal {
		fmt.Fprintf(w, "labyrinth_responses_total{rcode=%q} %d\n", rcode, counter.Load())
	}

	fmt.Fprintln(w, "# HELP labyrinth_cache_hits_total Cache hits across all caches.")
	fmt.Fprintln(w, "# TYPE labyrinth_cache_hits_total counter")
	fmt.Fprintf(w, "labyrinth_cache_hits_total %d\n", m.cacheHits.Load())

	fmt.Fprintln(w, "# HELP labyrinth_cache_misses_total Cache misses across all caches.")
	fmt.Fprintln(w, "# TYPE labyrinth_cache_misses_total counter")
	fmt.Fprintf(w, "labyrinth_cache_misses_total %d\n", m.cacheMisses.Load())

	fmt.Fprintln(w, "# HELP labyrinth_cache_evictions_total Cache entries evicted due to capacity or TTL.")
	fmt.Fprintln(w, "# TYPE labyrinth_cache_evictions_total counter")
	fmt.Fprintf(w, "labyrinth_cache_evictions_total %d\n", m.cacheEvictions.Load())

	fmt.Fprintln(w, "# HELP labyrinth_upstream_queries_total Queries sent to upstream authoritative servers.")
	fmt.Fprintln(w, "# TYPE labyrinth_upstream_queries_total counter")
	fmt.Fprintf(w, "labyrinth_upstream_queries_total %d\n", m.upstreamQueries.Load())

	fmt.Fprintln(w, "# HELP labyrinth_upstream_errors_total Upstream query errors (timeout, malformed, refused).")
	fmt.Fprintln(w, "# TYPE labyrinth_upstream_errors_total counter")
	fmt.Fprintf(w, "labyrinth_upstream_errors_total %d\n", m.upstreamErrors.Load())

	fmt.Fprintln(w, "# HELP labyrinth_rate_limited_total Queries refused by the rate limiter.")
	fmt.Fprintln(w, "# TYPE labyrinth_rate_limited_total counter")
	fmt.Fprintf(w, "labyrinth_rate_limited_total %d\n", m.rateLimited.Load())

	fmt.Fprintln(w, "# HELP labyrinth_fallback_queries_total Queries that engaged the failure-cache fallback.")
	fmt.Fprintln(w, "# TYPE labyrinth_fallback_queries_total counter")
	fmt.Fprintf(w, "labyrinth_fallback_queries_total %d\n", m.fallbackQueries.Load())

	fmt.Fprintln(w, "# HELP labyrinth_fallback_recoveries_total Failure-cache entries that subsequently recovered to a real answer.")
	fmt.Fprintln(w, "# TYPE labyrinth_fallback_recoveries_total counter")
	fmt.Fprintf(w, "labyrinth_fallback_recoveries_total %d\n", m.fallbackRecoveries.Load())

	fmt.Fprintln(w, "# HELP labyrinth_failure_cache_hits_total RFC 9520 failure cache short-circuits.")
	fmt.Fprintln(w, "# TYPE labyrinth_failure_cache_hits_total counter")
	fmt.Fprintf(w, "labyrinth_failure_cache_hits_total %d\n", m.failureCacheHits.Load())

	fmt.Fprintln(w, "# HELP labyrinth_failure_cache_misses_total RFC 9520 failure cache lookups that missed.")
	fmt.Fprintln(w, "# TYPE labyrinth_failure_cache_misses_total counter")
	fmt.Fprintf(w, "labyrinth_failure_cache_misses_total %d\n", m.failureCacheMisses.Load())

	fmt.Fprintln(w, "# HELP labyrinth_server_cookie_cache_hits_total RFC 7873 server-cookie cache hits.")
	fmt.Fprintln(w, "# TYPE labyrinth_server_cookie_cache_hits_total counter")
	fmt.Fprintf(w, "labyrinth_server_cookie_cache_hits_total %d\n", m.serverCookieCacheHits.Load())

	fmt.Fprintln(w, "# HELP labyrinth_server_cookie_cache_misses_total RFC 7873 server-cookie cache misses.")
	fmt.Fprintln(w, "# TYPE labyrinth_server_cookie_cache_misses_total counter")
	fmt.Fprintf(w, "labyrinth_server_cookie_cache_misses_total %d\n", m.serverCookieCacheMisses.Load())

	fmt.Fprintln(w, "# HELP labyrinth_nsec_aggressive_synth_total RFC 8198 aggressive NSEC synthesis, partitioned by negative kind.")
	fmt.Fprintln(w, "# TYPE labyrinth_nsec_aggressive_synth_total counter")
	fmt.Fprintf(w, "labyrinth_nsec_aggressive_synth_total{kind=\"nxdomain\"} %d\n", m.nsecAggressiveSynthNX.Load())
	fmt.Fprintf(w, "labyrinth_nsec_aggressive_synth_total{kind=\"nodata\"} %d\n", m.nsecAggressiveSynthNoData.Load())

	fmt.Fprintln(w, "# HELP labyrinth_nsec3_aggressive_synth_total RFC 8198 aggressive NSEC3 synthesis, partitioned by negative kind.")
	fmt.Fprintln(w, "# TYPE labyrinth_nsec3_aggressive_synth_total counter")
	fmt.Fprintf(w, "labyrinth_nsec3_aggressive_synth_total{kind=\"nxdomain\"} %d\n", m.nsec3AggressiveSynthNX.Load())
	fmt.Fprintf(w, "labyrinth_nsec3_aggressive_synth_total{kind=\"nodata\"} %d\n", m.nsec3AggressiveSynthND.Load())

	fmt.Fprintln(w, "# HELP labyrinth_outbound_badcookie_retries_total RFC 7873 BADCOOKIE retries with refreshed server cookie.")
	fmt.Fprintln(w, "# TYPE labyrinth_outbound_badcookie_retries_total counter")
	fmt.Fprintf(w, "labyrinth_outbound_badcookie_retries_total %d\n", m.outboundBadCookieRetries.Load())

	fmt.Fprintln(w, "# HELP labyrinth_stale_while_refresh_total RFC 8767 stale-while-refresh background refreshes triggered.")
	fmt.Fprintln(w, "# TYPE labyrinth_stale_while_refresh_total counter")
	fmt.Fprintf(w, "labyrinth_stale_while_refresh_total %d\n", m.staleWhileRefreshTriggers.Load())

	fmt.Fprintln(w, "# HELP labyrinth_dnssec_verdicts_total DNSSEC validator verdicts, partitioned by Secure/Insecure/Bogus.")
	fmt.Fprintln(w, "# TYPE labyrinth_dnssec_verdicts_total counter")
	fmt.Fprintf(w, "labyrinth_dnssec_verdicts_total{verdict=\"secure\"} %d\n", m.dnssecSecure.Load())
	fmt.Fprintf(w, "labyrinth_dnssec_verdicts_total{verdict=\"insecure\"} %d\n", m.dnssecInsecure.Load())
	fmt.Fprintf(w, "labyrinth_dnssec_verdicts_total{verdict=\"bogus\"} %d\n", m.dnssecBogus.Load())

	fmt.Fprintln(w, "# HELP labyrinth_blocked_queries_total Queries blocked by the blocklist surface.")
	fmt.Fprintln(w, "# TYPE labyrinth_blocked_queries_total counter")
	fmt.Fprintf(w, "labyrinth_blocked_queries_total %d\n", m.blockedQueries.Load())

	// EDE emission breakdown — one series per info code observed.
	// Snapshot (lock dance handled by EDECounts) so we don't iterate
	// the map under m.mu (we're already holding it; calling EDECounts
	// would re-lock). Inline read instead.
	if len(m.edeCounts) > 0 {
		fmt.Fprintln(w, "# HELP labyrinth_ede_emissions_total RFC 8914 Extended DNS Errors emitted, partitioned by info code.")
		fmt.Fprintln(w, "# TYPE labyrinth_ede_emissions_total counter")
		for code, counter := range m.edeCounts {
			fmt.Fprintf(w, "labyrinth_ede_emissions_total{code=\"%d\"} %d\n", code, counter.Load())
		}
	}

	fmt.Fprintln(w, "# HELP labyrinth_uptime_seconds Resolver uptime since process start.")
	fmt.Fprintln(w, "# TYPE labyrinth_uptime_seconds gauge")
	fmt.Fprintf(w, "labyrinth_uptime_seconds %.0f\n", time.Since(m.startTime).Seconds())

	fmt.Fprintln(w, "# HELP labyrinth_goroutines Live goroutine count.")
	fmt.Fprintln(w, "# TYPE labyrinth_goroutines gauge")
	fmt.Fprintf(w, "labyrinth_goroutines %d\n", runtime.NumGoroutine())

	fmt.Fprintln(w, "# HELP labyrinth_query_duration_seconds Query handling latency in seconds (handler entry to response build).")
	fmt.Fprintln(w, "# TYPE labyrinth_query_duration_seconds histogram")
	m.queryDurations.writeTo(w, "labyrinth_query_duration_seconds")
}
