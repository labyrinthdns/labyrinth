package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labyrinthdns/labyrinth/certmanager"
)

func TestHandleTLSStatus_Disabled(t *testing.T) {
	s := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/system/tls", nil)
	w := httptest.NewRecorder()
	s.handleTLSStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Enabled bool                  `json:"enabled"`
		AutoTLS bool                  `json:"auto_tls"`
		Cert    *certmanager.CertInfo `json:"cert"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Enabled {
		t.Fatal("expected TLS disabled")
	}
	if resp.AutoTLS {
		t.Fatal("expected auto-TLS disabled")
	}
}

func TestHandleTLSStatus_MethodNotAllowed(t *testing.T) {
	s := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/system/tls", nil)
	w := httptest.NewRecorder()
	s.handleTLSStatus(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleTLSRenew_NoAutoTLS(t *testing.T) {
	s := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/system/tls/renew", nil)
	w := httptest.NewRecorder()
	s.handleTLSRenew(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleTLSRenew_MethodNotAllowed(t *testing.T) {
	s := testAdminServer(t)
	req := httptest.NewRequest("GET", "/api/system/tls/renew", nil)
	w := httptest.NewRecorder()
	s.handleTLSRenew(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleDNSGuide(t *testing.T) {
	s := testAdminServer(t)
	s.config.Server.ListenAddr = ":53"
	req := httptest.NewRequest("GET", "/api/dns-guide", nil)
	w := httptest.NewRecorder()
	s.handleDNSGuide(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		ListenAddr string `json:"listen_addr"`
		DoHEnabled bool   `json:"doh_enabled"`
		DoTEnabled bool   `json:"dot_enabled"`
		Version    string `json:"version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ListenAddr != ":53" {
		t.Fatalf("expected :53, got %s", resp.ListenAddr)
	}
}

func TestHandleDNSGuide_WithDoH(t *testing.T) {
	s := testAdminServer(t)
	s.config.Web.DoHEnabled = true
	s.config.Web.TLSEnabled = true
	s.config.Web.AutoTLS = true
	s.config.Web.AutoTLSDomain = "dns.example.com"
	s.config.Web.Addr = "0.0.0.0:443"

	req := httptest.NewRequest("GET", "/api/dns-guide", nil)
	w := httptest.NewRecorder()
	s.handleDNSGuide(w, req)

	var resp struct {
		DoHEnabled bool   `json:"doh_enabled"`
		DoHURL     string `json:"doh_url"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.DoHEnabled {
		t.Fatal("expected DoH enabled")
	}
	if resp.DoHURL != "https://dns.example.com/dns-query" {
		t.Fatalf("expected DoH URL https://dns.example.com/dns-query, got %s", resp.DoHURL)
	}
}

func TestHandleDNSGuide_MethodNotAllowed(t *testing.T) {
	s := testAdminServer(t)
	req := httptest.NewRequest("POST", "/api/dns-guide", nil)
	w := httptest.NewRecorder()
	s.handleDNSGuide(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}
