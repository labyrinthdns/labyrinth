package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDoH_ErrorPathsCarryNoStore pins the v0.7.60 gate: every error
// response from /dns-query must carry Cache-Control: no-store.
// Without this header the Go default is empty, and an intermediate
// proxy / CDN / browser cache is free to store a 5xx response. A
// brief upstream failure (resolver hiccup, configuration reload mid-
// request) would then persist as a cached error well beyond its
// real duration, leaving the DoH endpoint silently broken for any
// client behind that intermediary.
//
// The pin covers four error paths chosen to exercise the distinct
// http.Error call sites in handleDoH: DoH disabled (404), method
// not allowed (405), invalid Content-Type (415), and DNS message
// too short (400).
func TestDoH_ErrorPathsCarryNoStore(t *testing.T) {
	mustNoStore := func(t *testing.T, h http.Header, label string) {
		t.Helper()
		cc := h.Get("Cache-Control")
		if !strings.Contains(cc, "no-store") {
			t.Errorf("[%s] Cache-Control = %q, want to contain 'no-store' — intermediate cache can store this error", label, cc)
		}
	}

	t.Run("DoH disabled (404)", func(t *testing.T) {
		srv := testDoHServer(t)
		srv.SetDoHEnabled(false)
		srv.SetDoHHandler(nil)
		req := httptest.NewRequest(http.MethodPost, "/dns-query", nil)
		req.Header.Set("Content-Type", "application/dns-message")
		w := httptest.NewRecorder()
		srv.handleDoH(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status %d, want 404", w.Code)
		}
		mustNoStore(t, w.Result().Header, "404 DoH disabled")
	})

	t.Run("method not allowed (405)", func(t *testing.T) {
		srv := testDoHServer(t)
		req := httptest.NewRequest(http.MethodPut, "/dns-query", nil)
		w := httptest.NewRecorder()
		srv.handleDoH(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status %d, want 405", w.Code)
		}
		mustNoStore(t, w.Result().Header, "405 method not allowed")
	})

	t.Run("invalid content-type (415)", func(t *testing.T) {
		srv := testDoHServer(t)
		req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte("not a dns message")))
		req.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()
		srv.handleDoH(w, req)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status %d, want 415", w.Code)
		}
		mustNoStore(t, w.Result().Header, "415 unsupported media type")
	})

	t.Run("dns message too short (400)", func(t *testing.T) {
		srv := testDoHServer(t)
		req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte{0x01, 0x02}))
		req.Header.Set("Content-Type", "application/dns-message")
		w := httptest.NewRecorder()
		srv.handleDoH(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", w.Code)
		}
		mustNoStore(t, w.Result().Header, "400 dns message too short")
	})
}

// TestDoH_SuccessPathOverridesNoStore is the counterpoint to the
// error-path test: a successful DoH response MUST carry
// Cache-Control: max-age=N (TTL-derived), NOT no-store. The default
// at the top of handleDoH is no-store, and the success branch
// overrides it with max-age before WriteHeader; a regression that
// dropped the override would tank DoH cacheability for every
// downstream resolver, multiplying upstream query load by 10–100x.
func TestDoH_SuccessPathOverridesNoStore(t *testing.T) {
	srv := testDoHServer(t)
	query := buildDNSQuery(0x4242)
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()
	srv.handleDoH(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	cc := w.Result().Header.Get("Cache-Control")
	if strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q — success path must NOT carry no-store; it kills DoH cacheability", cc)
	}
	if !strings.Contains(cc, "max-age=") {
		t.Errorf("Cache-Control = %q, want max-age=N", cc)
	}
}
