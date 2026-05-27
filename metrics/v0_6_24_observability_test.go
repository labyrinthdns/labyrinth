package metrics

import (
	"bytes"
	"strings"
	"testing"
)

// TestObservability_FailureCacheCounters pins Y34: each new counter
// added in v0.6.24 must be (a) reachable via its Inc method and
// (b) surfaced on the /metrics endpoint so operators can scrape it.
// Without (b) the counter exists in memory but is invisible — a
// regression we have hit before when a new metric was added but the
// HTTP writer was forgotten.
func TestObservability_FailureCacheCounters(t *testing.T) {
	m := NewMetrics()
	m.IncFailureCacheHits()
	m.IncFailureCacheHits()
	m.IncFailureCacheMisses()

	body := writeMetricsBuffer(m)
	mustContain(t, body, "labyrinth_failure_cache_hits_total 2")
	mustContain(t, body, "labyrinth_failure_cache_misses_total 1")
}

// TestObservability_ServerCookieCacheCounters pins the Y34 server-
// cookie cache half. A high hit ratio in production means cookie-
// enforcing auths see us as the same client across queries; a low
// ratio means we're stuck in the BADCOOKIE round-trip per query.
func TestObservability_ServerCookieCacheCounters(t *testing.T) {
	m := NewMetrics()
	m.IncServerCookieCacheHits()
	m.IncServerCookieCacheMisses()
	m.IncServerCookieCacheMisses()

	body := writeMetricsBuffer(m)
	mustContain(t, body, "labyrinth_server_cookie_cache_hits_total 1")
	mustContain(t, body, "labyrinth_server_cookie_cache_misses_total 2")
}

// TestObservability_NSECAggressiveSynth pins Y35: NXDOMAIN and NODATA
// synthesis (RFC 8198 §5.2 and §5.4) tracked separately with
// "kind" label so the §5.2-vs-§5.4 split is visible to dashboards.
func TestObservability_NSECAggressiveSynth(t *testing.T) {
	m := NewMetrics()
	m.IncNSECAggressiveSynthNX()
	m.IncNSECAggressiveSynthNX()
	m.IncNSECAggressiveSynthNoData()

	body := writeMetricsBuffer(m)
	mustContain(t, body, `labyrinth_nsec_aggressive_synth_total{kind="nxdomain"} 2`)
	mustContain(t, body, `labyrinth_nsec_aggressive_synth_total{kind="nodata"} 1`)
}

// TestObservability_NSEC3AggressiveSynth — NSEC3 sibling, same labels.
func TestObservability_NSEC3AggressiveSynth(t *testing.T) {
	m := NewMetrics()
	m.IncNSEC3AggressiveSynthNX()
	m.IncNSEC3AggressiveSynthND()
	m.IncNSEC3AggressiveSynthND()

	body := writeMetricsBuffer(m)
	mustContain(t, body, `labyrinth_nsec3_aggressive_synth_total{kind="nxdomain"} 1`)
	mustContain(t, body, `labyrinth_nsec3_aggressive_synth_total{kind="nodata"} 2`)
}

// TestObservability_CookieRetryAndStaleRefresh pins Y36: a sustained
// non-zero BADCOOKIE retry rate signals the cookie cache is being
// evicted faster than it warms; a zero stale-refresh rate with high
// stale-serve traffic signals the prefetch hook is mis-wired.
func TestObservability_CookieRetryAndStaleRefresh(t *testing.T) {
	m := NewMetrics()
	m.IncOutboundBadCookieRetries()
	m.IncOutboundBadCookieRetries()
	m.IncOutboundBadCookieRetries()
	m.IncStaleWhileRefreshTriggers()

	body := writeMetricsBuffer(m)
	mustContain(t, body, "labyrinth_outbound_badcookie_retries_total 3")
	mustContain(t, body, "labyrinth_stale_while_refresh_total 1")
}

// writeMetricsBuffer drives WriteMetrics into a buffer for assertion.
func writeMetricsBuffer(m *Metrics) string {
	var buf bytes.Buffer
	m.WriteMetrics(&buf)
	return buf.String()
}

func mustContain(t *testing.T, body, needle string) {
	t.Helper()
	if !strings.Contains(body, needle) {
		t.Errorf("metrics output missing %q\nfull body:\n%s", needle, body)
	}
}
