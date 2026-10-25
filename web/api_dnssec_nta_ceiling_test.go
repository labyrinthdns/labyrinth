package web

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNTAInstall_ExpiresAtClampedTo30Days pins the RFC 7646 §6 lifetime
// ceiling on the explicit expires_at path, not only on duration_hours: a
// far-future timestamp must not install a multi-year validation bypass.
func TestNTAInstall_ExpiresAtClampedTo30Days(t *testing.T) {
	srv := testAdminServerWithResolver(t)
	srv.resolver.EnableDNSSEC(slog.New(slog.NewTextHandler(io.Discard, nil)))

	raw, _ := json.Marshal(map[string]interface{}{
		"zone":       "example.test",
		"expires_at": time.Now().Add(10 * 365 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
	w := httptest.NewRecorder()
	srv.handleNTAAdd(w, httptest.NewRequest(http.MethodPost, "/api/dnssec/nta", bytes.NewReader(raw)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	ceiling := time.Now().Add(30*24*time.Hour + time.Minute)
	for _, nta := range srv.resolver.DNSSECValidator().NTAStore().List() {
		if nta.Zone == "example.test." {
			if nta.Expiry.After(ceiling) {
				t.Fatalf("NTA expiry %s exceeds the 30-day ceiling", nta.Expiry)
			}
			return
		}
	}
	t.Fatal("NTA for example.test not installed")
}
