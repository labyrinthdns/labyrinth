package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTLSAndGuide_ErrorPathsCarryNoStore pins the v0.7.61 gate:
// /api/system/tls, /api/system/tls/renew, and /api/dns-guide must
// carry Cache-Control: no-store on every response, including the
// 405 method-not-allowed and 400 auto-tls-not-enabled http.Error
// branches that previously left the header unset.
//
// These endpoints surface live state (cert NotAfter, listen
// address, DoH URL, DoT host). A 405 cached by a CDN / browser is
// merely annoying; a stale 400 "auto-tls not enabled" cached
// across a config flip would mislead an operator who just enabled
// auto-TLS into thinking the toggle failed. Defence-in-depth says
// never cache any response that reflects live state.
func TestTLSAndGuide_ErrorPathsCarryNoStore(t *testing.T) {
	mustNoStore := func(t *testing.T, h http.Header, label string) {
		t.Helper()
		cc := h.Get("Cache-Control")
		if !strings.Contains(cc, "no-store") {
			t.Errorf("[%s] Cache-Control = %q, want to contain 'no-store'", label, cc)
		}
	}

	t.Run("tls/status method not allowed", func(t *testing.T) {
		srv := testAdminServer(t)
		req := httptest.NewRequest(http.MethodPost, "/api/system/tls", nil)
		w := httptest.NewRecorder()
		srv.handleTLSStatus(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status %d, want 405", w.Code)
		}
		mustNoStore(t, w.Result().Header, "tls/status 405")
	})

	t.Run("tls/renew method not allowed", func(t *testing.T) {
		srv := testAdminServer(t)
		req := httptest.NewRequest(http.MethodGet, "/api/system/tls/renew", nil)
		w := httptest.NewRecorder()
		srv.handleTLSRenew(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status %d, want 405", w.Code)
		}
		mustNoStore(t, w.Result().Header, "tls/renew 405")
	})

	t.Run("tls/renew auto-tls not enabled (400)", func(t *testing.T) {
		srv := testAdminServer(t)
		// certMgr is nil by default in testAdminServer — exercises the
		// "auto-tls not enabled" branch.
		req := httptest.NewRequest(http.MethodPost, "/api/system/tls/renew", nil)
		w := httptest.NewRecorder()
		srv.handleTLSRenew(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", w.Code)
		}
		mustNoStore(t, w.Result().Header, "tls/renew 400")
	})

	t.Run("dns-guide method not allowed", func(t *testing.T) {
		srv := testAdminServer(t)
		req := httptest.NewRequest(http.MethodPost, "/api/dns-guide", nil)
		w := httptest.NewRecorder()
		srv.handleDNSGuide(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status %d, want 405", w.Code)
		}
		mustNoStore(t, w.Result().Header, "dns-guide 405")
	})

	t.Run("dns-guide success still no-store", func(t *testing.T) {
		// The success path should still carry no-store — guide values
		// are live config readings, never appropriate to cache.
		srv := testAdminServer(t)
		req := httptest.NewRequest(http.MethodGet, "/api/dns-guide", nil)
		w := httptest.NewRecorder()
		srv.handleDNSGuide(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d, want 200", w.Code)
		}
		mustNoStore(t, w.Result().Header, "dns-guide 200")
	})

	t.Run("tls/status success still no-store", func(t *testing.T) {
		srv := testAdminServer(t)
		req := httptest.NewRequest(http.MethodGet, "/api/system/tls", nil)
		w := httptest.NewRecorder()
		srv.handleTLSStatus(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d, want 200", w.Code)
		}
		mustNoStore(t, w.Result().Header, "tls/status 200")
	})
}
