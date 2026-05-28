package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRobots_DisallowsAllCrawlers pins the /robots.txt response so an
// admin instance accidentally exposed to the public internet is not
// indexed by any major crawler. The contract: text/plain body with
// the universal disallow tuple. A regression that removed the route
// would 404 — and absent a robots.txt many crawlers default to
// indexing.
func TestRobots_DisallowsAllCrawlers(t *testing.T) {
	srv := testAdminServer(t)
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/robots.txt", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "User-agent: *") {
		t.Errorf("body missing universal user-agent rule:\n%s", body)
	}
	if !strings.Contains(body, "Disallow: /") {
		t.Errorf("body missing total Disallow:\n%s", body)
	}
}

// TestSecurityHeaders_XRobotsTagNoIndex pins the X-Robots-Tag header
// emitted by the securityHeaders middleware. This is the per-response
// equivalent of robots.txt: crawlers fetching API endpoints directly
// (without first checking /robots.txt) see this header on every
// response and must not index the URL. A regression that dropped the
// header would silently lose this defence.
func TestSecurityHeaders_XRobotsTagNoIndex(t *testing.T) {
	mw := securityHeaders(func() bool { return false })
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/anything", nil)
	mw(inner).ServeHTTP(w, req)

	tag := w.Header().Get("X-Robots-Tag")
	if tag == "" {
		t.Fatal("X-Robots-Tag header not set by security middleware")
	}
	if !strings.Contains(tag, "noindex") || !strings.Contains(tag, "nofollow") {
		t.Errorf("X-Robots-Tag = %q, want noindex+nofollow", tag)
	}
}
