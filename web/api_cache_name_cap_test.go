package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCacheLookup_RejectsOverlongName pins RFC 1035 §2.3.4 enforcement
// on the /api/cache/lookup admin endpoint. A name longer than 255
// octets is invalid by spec — refusing pre-empts wasted allocation
// and cache pollution from a bad admin query.
//
// The pin issues a 4096-octet name and asserts a clean 400 (rather
// than a 500 or hang). A regression that dropped the length gate
// would let the giant name flow into Cache.LookupAll/Lookup and cause
// allocation pressure proportional to the input size.
func TestCacheLookup_RejectsOverlongName(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = "" // pass-through auth

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	huge := strings.Repeat("a", 4096) + ".example.test"
	req := httptest.NewRequest("GET", "/api/cache/lookup?name="+huge, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (overlong name should be rejected)", w.Code)
	}
}

// TestCacheLookup_AcceptsNameAtCap — negative control: a name of
// exactly 255 octets must NOT be rejected by the length gate. The
// resolver and cache happily handle names at the spec limit; the gate
// is only there to filter clearly-bogus inputs.
func TestCacheLookup_AcceptsNameAtCap(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = "" // pass-through auth

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	// 255-char name: 250 "a"s + ".test"
	name := strings.Repeat("a", 250) + ".test"
	if len(name) != 255 {
		t.Fatalf("test setup: name length is %d not 255", len(name))
	}
	req := httptest.NewRequest("GET", "/api/cache/lookup?name="+name, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// We expect 404 (no such entry in an empty test cache), NOT 400.
	// The negative-control assertion is that the length gate did not
	// fire on a valid-length name.
	if w.Code == http.StatusBadRequest {
		t.Errorf("name at exactly the 255-octet cap was rejected by the length gate (status 400)")
	}
}

// TestCacheDelete_RejectsOverlongName pins the same length gate on
// the DELETE /api/cache/entry route, which also takes a name from
// the query string and has the same allocation-pressure surface.
func TestCacheDelete_RejectsOverlongName(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = ""

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	huge := strings.Repeat("b", 4096) + ".example.test"
	req := httptest.NewRequest("DELETE", "/api/cache/entry?name="+huge, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (overlong name should be rejected)", w.Code)
	}
}
