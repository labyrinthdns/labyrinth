package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBlocklistBlock_RejectsOverlongDomain pins RFC 1035 §2.3.4 on
// the /api/blocklist/block POST surface. Without the cap a malformed
// or hostile admin POST with a 1 MB "domain" field would be persisted
// into the in-memory blocklist set forever — balloons resolver
// memory while never matching a real query (since real queries
// cannot carry a 1 MB qname). The pin sends a 4 KiB domain and
// expects a clean 400.
func TestBlocklistBlock_RejectsOverlongDomain(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = "" // pass-through auth
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	huge := strings.Repeat("a", 4096) + ".example.test"
	body := `{"domain":"` + huge + `"}`
	req := httptest.NewRequest("POST", "/api/blocklist/block", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (overlong domain should be rejected)", w.Code)
	}
}

// TestBlocklistUnblock_RejectsOverlongDomain — companion pin on the
// unblock route. Same reasoning, same surface.
func TestBlocklistUnblock_RejectsOverlongDomain(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = ""
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	huge := strings.Repeat("a", 4096) + ".example.test"
	body := `{"domain":"` + huge + `"}`
	req := httptest.NewRequest("POST", "/api/blocklist/unblock", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (overlong domain should be rejected)", w.Code)
	}
}

// TestBlocklistCheck_RejectsOverlongDomain pins the same gate on the
// GET /api/blocklist/check route, which takes the domain in a query
// parameter rather than a JSON body. The check route hits a hash-set
// membership test on every request — a 1 MB key would cost time
// proportional to its length per call.
func TestBlocklistCheck_RejectsOverlongDomain(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = ""
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	huge := strings.Repeat("a", 4096) + ".example.test"
	req := httptest.NewRequest("GET", "/api/blocklist/check?domain="+huge, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (overlong domain should be rejected)", w.Code)
	}
}
