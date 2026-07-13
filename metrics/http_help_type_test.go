package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPrometheusExport_HasHelpAndTypeForEverySeries pins the
// well-formedness of the Prometheus exposition. Every metric family
// emitted by /metrics must carry both `# HELP <name> <description>`
// and `# TYPE <name> <type>` lines:
//
//   - `# TYPE` is required for `rate()` / `increase()` / `histogram_quantile()`
//     to produce correct results — a counter typed implicitly defaults
//     to "untyped", which silently disables many PromQL functions.
//   - `# HELP` populates Grafana's auto-doc and the result of
//     `promtool check metrics` which is part of every well-run
//     Prometheus operator's CI.
//
// Without this gate a future contributor adding a new
// `fmt.Fprintf(w, "labyrinth_foo_total %d\n", ...)` would silently
// land an under-specified series. The pin loops every metric family
// the exporter declares and asserts both metadata lines precede it.
func TestPrometheusExport_HasHelpAndTypeForEverySeries(t *testing.T) {
	m := NewMetrics()
	// Trigger at least one EDE counter so the conditional block fires.
	m.IncEDE(6)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.ServeHTTP(w, req)
	body := w.Body.String()

	families := []struct {
		name    string
		mtype   string // counter | gauge | histogram
	}{
		{"labyrinth_queries_total", "counter"},
		{"labyrinth_responses_total", "counter"},
		{"labyrinth_cache_hits_total", "counter"},
		{"labyrinth_cache_misses_total", "counter"},
		{"labyrinth_cache_evictions_total", "counter"},
		{"labyrinth_upstream_queries_total", "counter"},
		{"labyrinth_upstream_errors_total", "counter"},
		{"labyrinth_rate_limited_total", "counter"},
		{"labyrinth_fallback_queries_total", "counter"},
		{"labyrinth_fallback_recoveries_total", "counter"},
		{"labyrinth_failure_cache_hits_total", "counter"},
		{"labyrinth_failure_cache_misses_total", "counter"},
		{"labyrinth_server_cookie_cache_hits_total", "counter"},
		{"labyrinth_server_cookie_cache_misses_total", "counter"},
		{"labyrinth_nsec_aggressive_synth_total", "counter"},
		{"labyrinth_nsec3_aggressive_synth_total", "counter"},
		{"labyrinth_outbound_badcookie_retries_total", "counter"},
		{"labyrinth_stale_while_refresh_total", "counter"},
		{"labyrinth_dnssec_verdicts_total", "counter"},
		{"labyrinth_dnssec_rollover_validates_total", "counter"},
		{"labyrinth_blocked_queries_total", "counter"},
		{"labyrinth_ede_emissions_total", "counter"},
		{"labyrinth_uptime_seconds", "gauge"},
		{"labyrinth_goroutines", "gauge"},
		{"labyrinth_query_duration_seconds", "histogram"},
	}

	for _, f := range families {
		helpLine := "# HELP " + f.name + " "
		typeLine := "# TYPE " + f.name + " " + f.mtype
		if !strings.Contains(body, helpLine) {
			t.Errorf("missing HELP line for %s — every Prometheus series must carry one", f.name)
		}
		if !strings.Contains(body, typeLine) {
			t.Errorf("missing or wrong TYPE line for %s (want %q)", f.name, typeLine)
		}
	}
}

// TestPrometheusExport_ContentTypeIsExpositionFormat pins the
// content-type header so a scraper using strict format negotiation
// (the OpenMetrics-only mode of modern Prometheus) still accepts the
// payload. Version 0.0.4 is the original wire format; OpenMetrics
// scrapers accept it under the same content-type.
func TestPrometheusExport_ContentTypeIsExpositionFormat(t *testing.T) {
	m := NewMetrics()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") || !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("unexpected Content-Type %q — want text/plain; version=0.0.4", ct)
	}
}
