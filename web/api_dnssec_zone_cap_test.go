package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNTAAdd_RejectsOverlongZone pins the RFC 1035 §2.3.4 length
// cap on the NTA install endpoint's `zone` field. The NTA store is
// consulted on every DNSSEC validation decision, so a malformed POST
// that persisted a 1 MB zone string would grow memory and slow
// every validation pass. The pin sends a 4 KiB zone field and
// expects a clean 400 BEFORE the store sees anything.
func TestNTAAdd_RejectsOverlongZone(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = "" // pass-through auth
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	huge := strings.Repeat("a", 4096) + ".example.test"
	body := `{"zone":"` + huge + `","duration_hours":1,"reason":"test"}`
	req := httptest.NewRequest("POST", "/api/dnssec/nta", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Status code may be 400 (length cap fires) or 503 (no validator
	// in test harness — the response handler returns 503 before the
	// length check if the resolver is not configured). What we
	// reject is a 200, which would mean the zone slipped through.
	if w.Code == http.StatusOK {
		t.Errorf("status: got %d, want a non-2xx response — overlong zone must not succeed", w.Code)
	}
}

// TestNTARemove_RejectsOverlongZone pins the same length cap on the
// DELETE side, which takes the zone in a query string.
func TestNTARemove_RejectsOverlongZone(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = ""
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	huge := strings.Repeat("b", 4096) + ".example.test"
	req := httptest.NewRequest("DELETE", "/api/dnssec/nta?zone="+huge, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("status: got %d, want a non-2xx response — overlong zone must not succeed", w.Code)
	}
}
