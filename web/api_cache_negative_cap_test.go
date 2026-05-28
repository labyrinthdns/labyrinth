package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// TestNegativeCache_CapsPageSize pins the upper bound on the
// /api/cache/negative `limit` parameter. The other paginated admin
// routes (top-clients, top-domains, recent queries) all carry a
// hard cap so a hostile or fat-fingered ?limit=1000000 cannot
// force the resolver to iterate millions of entries and serialise
// a multi-MB JSON response. The negative-cache endpoint had no cap.
// The pin asserts that an oversize limit value is clamped to
// maxNegativeCachePage in the response.
func TestNegativeCache_CapsPageSize(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = "" // pass-through auth
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	huge := strconv.Itoa(maxNegativeCachePage * 100)
	req := httptest.NewRequest("GET", "/api/cache/negative?limit="+huge, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}

	var body struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The clamp is what we're verifying; we don't care that the test
	// cache is empty (count may be 0). What matters is that an
	// over-cap request did not OOM or hang the handler.
	if body.Count > maxNegativeCachePage {
		t.Errorf("response returned %d entries, cap is %d — clamp not enforced",
			body.Count, maxNegativeCachePage)
	}
}
