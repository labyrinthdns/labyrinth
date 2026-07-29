package web

import (
	"encoding/json"
	"net/http"

	"github.com/labyrinthdns/labyrinth/certmanager"
)

// handleTLSStatus returns the current TLS certificate status.
func (s *AdminServer) handleTLSStatus(w http.ResponseWriter, r *http.Request) {
	// Default every response — including the 405 method-not-allowed
	// error path — to no-store. The endpoint surfaces live cert state
	// (issuer, NotAfter, ACME flag); a stale cached reading during a
	// renewal storm could mask a real expiry. http.Error preserves
	// previously-set headers, so setting this once at the top is
	// enough to cover the error branch.
	w.Header().Set("Cache-Control", "no-store")
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
		Enabled: s.config.Load().Web.TLSEnabled,
		AutoTLS: s.config.Load().Web.AutoTLS,
	}

	if s.certMgr != nil {
		resp.Cert = s.certMgr.Info()
	} else if s.config.Load().Web.TLSEnabled && s.config.Load().Web.TLSCertFile != "" {
		info, err := certmanager.InfoFromStatic(s.config.Load().Web.TLSCertFile, s.config.Load().Web.TLSKeyFile)
		if err == nil {
			resp.Cert = info
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleTLSRenew forces a certificate renewal (auto-TLS only).
func (s *AdminServer) handleTLSRenew(w http.ResponseWriter, r *http.Request) {
	// Cert renewal is a one-shot operator action; no response from this
	// endpoint is ever appropriate to cache. Default to no-store at
	// the top so the 400/405/500 error paths (which use http.Error)
	// inherit it. http.Error preserves previously-set headers.
	w.Header().Set("Cache-Control", "no-store")
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
	// Default Cache-Control: no-store at the top so the 405
	// method-not-allowed http.Error inherits it. The guide reflects
	// live config (listen addr, DoH URL, DoT host, TLS state) and
	// stale cached values would mislead an operator following the
	// setup instructions during a transitional moment (e.g. just
	// after TLS was enabled). The success path no longer needs to
	// re-set the header because it was already set here.
	w.Header().Set("Cache-Control", "no-store")
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
		ListenAddr: s.config.Load().Server.ListenAddr,
		DoHEnabled: s.config.Load().Web.DoHEnabled || s.config.Load().Web.DoH3Enabled,
		DoTEnabled: s.config.Load().Server.DoTEnabled,
		TLSEnabled: s.config.Load().Web.TLSEnabled,
		Version:    Version,
	}

	if resp.DoHEnabled {
		scheme := "http"
		if s.config.Load().Web.TLSEnabled {
			scheme = "https"
		}
		host := s.config.Load().Web.Addr
		if s.config.Load().Web.AutoTLS && s.config.Load().Web.AutoTLSDomain != "" {
			host = s.config.Load().Web.AutoTLSDomain
		}
		resp.DoHURL = scheme + "://" + host + "/dns-query"
	}

	if resp.DoTEnabled {
		if s.config.Load().Web.AutoTLS && s.config.Load().Web.AutoTLSDomain != "" {
			resp.DoTHost = s.config.Load().Web.AutoTLSDomain
		} else {
			resp.DoTHost = s.config.Load().Server.DoTListenAddr
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
