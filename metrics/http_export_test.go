package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPrometheusExport_IncludesEDEAndDNSSECVerdicts pins the
// Prometheus exposition surface so a monitoring stack scraping
// /metrics never silently loses the DNSSEC-verdict or EDE breakdown.
// Operators rely on per-code EDE alerting (e.g. "page when bogus
// rate spikes") and the absence of a series presents as a flat-line
// dashboard — the worst kind of monitoring lie.
func TestPrometheusExport_IncludesEDEAndDNSSECVerdicts(t *testing.T) {
	m := NewMetrics()

	// Move every counter we care about above zero so the export emits
	// a line and we can grep for it.
	m.IncDNSSECSecure()
	m.IncDNSSECInsecure()
	m.IncDNSSECBogus()
	m.SetDNSSECRolloverValidates(1)
	m.IncBlockedQueries()
	m.IncEDE(6)
	m.IncEDE(17)
	m.IncEDE(18)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.ServeHTTP(w, req)

	body := w.Body.String()

	mustContain := []string{
		`labyrinth_dnssec_verdicts_total{verdict="secure"} 1`,
		`labyrinth_dnssec_verdicts_total{verdict="insecure"} 1`,
		`labyrinth_dnssec_verdicts_total{verdict="bogus"} 1`,
		`labyrinth_dnssec_rollover_validates_total 1`,
		`labyrinth_blocked_queries_total 1`,
		`labyrinth_ede_emissions_total{code="6"} 1`,
		`labyrinth_ede_emissions_total{code="17"} 1`,
		`labyrinth_ede_emissions_total{code="18"} 1`,
	}
	for _, s := range mustContain {
		if !strings.Contains(body, s) {
			t.Errorf("Prometheus export missing line %q\n--- body ---\n%s", s, body)
		}
	}
}

// TestPrometheusExport_NoEDESeriesWhenNoneEmitted — negative control.
// Counters that never moved must NOT appear in the export (each line
// is a sample point in Prometheus; emitting zero-valued series
// inflates scrape size and creates phantom series for codes the
// resolver has never produced).
func TestPrometheusExport_NoEDESeriesWhenNoneEmitted(t *testing.T) {
	m := NewMetrics()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.ServeHTTP(w, req)

	if strings.Contains(w.Body.String(), "labyrinth_ede_emissions_total") {
		t.Errorf("EDE series present in export but no codes have been emitted:\n%s", w.Body.String())
	}
}
