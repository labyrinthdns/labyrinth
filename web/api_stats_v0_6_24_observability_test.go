package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleStats_SurfacesV0_6_24_ObservabilityCounters pins Y40: the
// /api/stats endpoint MUST expose the eight Y34/Y35/Y36 counters added
// in v0.6.24. Without these, the dashboard cannot see the new caches
// at all — they only live on /metrics, which is a Prometheus scrape
// target, not a UI data source.
//
// We don't need real traffic; the counters start at zero and the JSON
// must still carry the keys (so the dashboard can render "0" instead
// of "—"). The presence of the key, not its value, is what we pin.
func TestHandleStats_SurfacesV0_6_24_ObservabilityCounters(t *testing.T) {
	srv := testAdminServer(t)

	// Increment each counter once so the value is non-zero AND the key
	// is present in the JSON output — pins both "field exists" and
	// "field reflects the underlying counter".
	srv.metrics.IncFailureCacheHits()
	srv.metrics.IncFailureCacheMisses()
	srv.metrics.IncServerCookieCacheHits()
	srv.metrics.IncServerCookieCacheMisses()
	srv.metrics.IncNSECAggressiveSynthNX()
	srv.metrics.IncNSECAggressiveSynthNoData()
	srv.metrics.IncNSEC3AggressiveSynthNX()
	srv.metrics.IncNSEC3AggressiveSynthND()
	srv.metrics.IncOutboundBadCookieRetries()
	srv.metrics.IncStaleWhileRefreshTriggers()

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	got := decodeJSON(t, w)

	// Pin each key explicitly. A typo on either side surfaces here.
	for _, key := range []string{
		"failure_cache_hits",
		"failure_cache_misses",
		"server_cookie_cache_hits",
		"server_cookie_cache_misses",
		"nsec_aggressive_synth_nx",
		"nsec_aggressive_synth_nodata",
		"nsec3_aggressive_synth_nx",
		"nsec3_aggressive_synth_nodata",
		"outbound_badcookie_retries",
		"stale_while_refresh",
	} {
		v, ok := got[key]
		if !ok {
			t.Errorf("/api/stats missing field %q (dashboard cannot read v0.6.24 observability counter)", key)
			continue
		}
		// JSON numbers decode as float64; we incremented to 1.
		f, ok := v.(float64)
		if !ok {
			t.Errorf("%s: type = %T, want float64", key, v)
			continue
		}
		if f != 1 {
			t.Errorf("%s = %v, want 1 (single Inc call)", key, f)
		}
	}
}
