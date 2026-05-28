package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDNSGuide_EmitsNoStoreCacheControl pins the Cache-Control:
// no-store contract on the unauthenticated /api/dns-guide endpoint.
// jsonResponse sets this on every other API path automatically, but
// handleDNSGuide writes the body directly via json.NewEncoder so the
// header had to be set by hand — and was missing. Without it an
// intermediate proxy could cache the live config payload and serve
// a stale snapshot to a downstream client after a TLS/DoH config
// change (the user opens the setup-guide page and sees the old
// endpoint URL).
func TestDNSGuide_EmitsNoStoreCacheControl(t *testing.T) {
	srv := testAdminServer(t)
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/api/dns-guide", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}
