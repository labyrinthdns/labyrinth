package web

import (
	"encoding/json"
	"net/http"

	"github.com/labyrinthdns/labyrinth/certmanager"
)

// handleTLSStatus returns the current TLS certificate status.
func (s *AdminServer) handleTLSStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type tlsResponse struct {
		Enabled bool                 `json:"enabled"`
		AutoTLS bool                 `json:"auto_tls"`
		Cert    *certmanager.CertInfo `json:"cert,omitempty"`
	}

	resp := tlsResponse{
		Enabled: s.config.Web.TLSEnabled,
		AutoTLS: s.config.Web.AutoTLS,
	}

	if s.certMgr != nil {
		resp.Cert = s.certMgr.Info()
	} else if s.config.Web.TLSEnabled && s.config.Web.TLSCertFile != "" {
		info, err := certmanager.InfoFromStatic(s.config.Web.TLSCertFile, s.config.Web.TLSKeyFile)
		if err == nil {
			resp.Cert = info
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleTLSRenew forces a certificate renewal (auto-TLS only).
func (s *AdminServer) handleTLSRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.certMgr == nil {
		http.Error(w, `{"error":"auto-tls not enabled"}`, http.StatusBadRequest)
		return
	}

	if err := s.certMgr.ForceRenew(r.Context()); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"certificate cache cleared, will renew on next handshake"}`))
}

// handleDNSGuide returns server configuration info for the public DNS setup guide.
// This endpoint does NOT require authentication.
func (s *AdminServer) handleDNSGuide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type guideResponse struct {
		ListenAddr string `json:"listen_addr"`
		DoHEnabled bool   `json:"doh_enabled"`
		DoHURL     string `json:"doh_url,omitempty"`
		DoTEnabled bool   `json:"dot_enabled"`
		DoTHost    string `json:"dot_host,omitempty"`
		TLSEnabled bool   `json:"tls_enabled"`
		Version    string `json:"version"`
	}

	resp := guideResponse{
		ListenAddr: s.config.Server.ListenAddr,
		DoHEnabled: s.config.Web.DoHEnabled || s.config.Web.DoH3Enabled,
		DoTEnabled: s.config.Server.DoTEnabled,
		TLSEnabled: s.config.Web.TLSEnabled,
		Version:    Version,
	}

	if resp.DoHEnabled {
		scheme := "http"
		if s.config.Web.TLSEnabled {
			scheme = "https"
		}
		host := s.config.Web.Addr
		if s.config.Web.AutoTLS && s.config.Web.AutoTLSDomain != "" {
			host = s.config.Web.AutoTLSDomain
		}
		resp.DoHURL = scheme + "://" + host + "/dns-query"
	}

	if resp.DoTEnabled {
		if s.config.Web.AutoTLS && s.config.Web.AutoTLSDomain != "" {
			resp.DoTHost = s.config.Web.AutoTLSDomain
		} else {
			resp.DoTHost = s.config.Server.DoTListenAddr
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
