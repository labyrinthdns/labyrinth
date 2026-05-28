package web

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDoH_EmitsVaryAccept pins RFC 8484 §5.1 / RFC 7234 §4.1:
// DoH responses must carry `Vary: Accept` so an intermediate cache
// keyed on URL+Accept does not serve a stored application/dns-message
// payload to a downstream client that asked for application/dns-json
// (or vice versa). The HTTP cache contract is "response varies on
// the headers named in Vary"; missing Vary lets a CDN reuse the same
// body for different Accept negotiations and the client rejects the
// payload as malformed.
//
// A regression that dropped the line would silently break cache
// correctness on every CDN or forward-proxy that fronts a Labyrinth
// DoH instance.
func TestDoH_EmitsVaryAccept(t *testing.T) {
	srv := testDoHServer(t)

	query := buildDNSQuery(0xABCD)
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	srv.handleDoH(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("DoH POST returned %d, want 200", w.Code)
	}
	if v := w.Header().Get("Vary"); !strings.Contains(v, "Accept") {
		t.Errorf("missing Vary: Accept header (got %q) — RFC 8484 §5.1 cache contract not held", v)
	}
}

// TestDoH_EmitsVaryAcceptOnGET — companion pin for the GET path.
// Both methods share the same response-writing block, but if a
// future refactor splits them this test catches the regression on
// the GET side independently.
func TestDoH_EmitsVaryAcceptOnGET(t *testing.T) {
	srv := testDoHServer(t)

	query := buildDNSQuery(0xCAFE)
	encoded := base64.RawURLEncoding.EncodeToString(query)
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	w := httptest.NewRecorder()

	srv.handleDoH(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("DoH GET returned %d, want 200", w.Code)
	}
	if v := w.Header().Get("Vary"); !strings.Contains(v, "Accept") {
		t.Errorf("missing Vary: Accept header on GET (got %q)", v)
	}
}
