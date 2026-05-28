package web

import (
	"net/http/httptest"
	"testing"
)

// TestJSONResponse_NoStore pins the Cache-Control: no-store header on
// every JSON API reply. Live observability data must never be cached
// by intermediate proxies or the browser — without this header, a
// misconfigured Squid or a corporate proxy could serve a 30s-old
// /api/stats response and mask a failure during an incident.
//
// no-store (stricter than no-cache) is the right choice: we don't
// want even revalidation behaviour; we want every fetch to round-trip
// to the resolver.
func TestJSONResponse_NoStore(t *testing.T) {
	w := httptest.NewRecorder()
	jsonResponse(w, 200, map[string]string{"hello": "world"})

	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q (a regression here lets stale API responses leak through proxies)", got, "no-store")
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

// TestJSONResponse_NoStore_AlsoOnErrorPaths — error responses (400,
// 401, 500…) are equally observability-sensitive: a stale "401
// unauthorised" cached by a proxy after a successful re-auth would
// leave the operator locked out. Pin no-store on a representative
// error code.
func TestJSONResponse_NoStore_AlsoOnErrorPaths(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 500, 503} {
		w := httptest.NewRecorder()
		jsonResponse(w, status, map[string]string{"error": "test"})
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("status %d: Cache-Control = %q, want no-store", status, got)
		}
	}
}
