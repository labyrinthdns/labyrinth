package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMetrics_RefusesNonGET pins the method gate on the Prometheus
// /metrics endpoint. Scrapers use GET only (HEAD is also allowed
// because Prometheus may issue a HEAD to test reachability before a
// scrape). Refusing POST/PUT/PATCH/DELETE with 405 prevents a
// misbehaving probe — or a hostile POST flood at the metrics
// endpoint, which is often deliberately exposed to the public
// internet for scraping — from running the snapshot path
// needlessly.
func TestMetrics_RefusesNonGET(t *testing.T) {
	m := NewMetrics()
	cases := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}
	for _, method := range cases {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/metrics", nil)
		m.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: got status %d, want 405", method, w.Code)
		}
		if allow := w.Header().Get("Allow"); !strings.Contains(allow, "GET") {
			t.Errorf("%s: Allow header missing GET (got %q)", method, allow)
		}
	}
}

// TestMetrics_AllowsGET — negative control: GET must still produce
// the exposition body.
func TestMetrics_AllowsGET(t *testing.T) {
	m := NewMetrics()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET: got status %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "labyrinth_") {
		t.Errorf("GET body missing labyrinth_ metric prefix:\n%s", w.Body.String())
	}
}

// TestMetrics_NoStoreHeader pins Cache-Control: no-store so an
// intermediate cache cannot serve a stale Prometheus payload during
// an incident — a fake flat-line dashboard is worse than no data.
func TestMetrics_NoStoreHeader(t *testing.T) {
	m := NewMetrics()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.ServeHTTP(w, req)

	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}
