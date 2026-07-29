package web

import (
	"encoding/json"
	"net/http"
)

func (s *AdminServer) handleBlocklistStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.blocklist == nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"enabled": false, "total_rules": 0, "list_count": 0,
			"blocked_total": 0, "custom_blocks": 0, "custom_allows": 0,
			"blocking_mode": "nxdomain",
		})
		return
	}
	jsonResponse(w, http.StatusOK, s.blocklist.Stats())
}

func (s *AdminServer) handleBlocklistLists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.blocklist == nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"lists": []interface{}{}})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"lists": s.blocklist.Sources()})
}

func (s *AdminServer) handleBlocklistRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.blocklist == nil {
		jsonResponse(w, http.StatusOK, map[string]string{"status": "blocklist not enabled"})
		return
	}
	go s.blocklist.RefreshAll()
	jsonResponse(w, http.StatusOK, map[string]string{"status": "refresh started"})
}

func (s *AdminServer) handleBlocklistBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "missing or invalid domain"})
		return
	}
	// RFC 1035 §2.3.4 — domain name length cap. Validation runs BEFORE
	// the blocklist-nil check so a malformed POST is always rejected
	// with a 400 regardless of whether the blocklist subsystem is
	// configured (defence in depth: a future deployment that lazily
	// initialises the blocklist would otherwise silently swallow
	// 1 MB-of-junk POSTs as success).
	if len(req.Domain) > 255 {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "domain exceeds RFC 1035 §2.3.4 length cap"})
		return
	}

	if s.blocklist == nil {
		jsonResponse(w, http.StatusOK, map[string]string{"status": "blocklist not enabled"})
		return
	}
	if err := s.blocklist.BlockDomain(req.Domain); err != nil {
		// Capacity exhaustion: surface 507 Insufficient Storage so the
		// admin UI can show a clear "you've hit the cap" message
		// instead of a silent success. Other errors are not expected
		// from BlockDomain but get the same treatment defensively.
		jsonResponse(w, http.StatusInsufficientStorage, map[string]string{"error": err.Error()})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "blocked", "domain": req.Domain})
}

func (s *AdminServer) handleBlocklistUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "missing or invalid domain"})
		return
	}
	if len(req.Domain) > 255 {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "domain exceeds RFC 1035 §2.3.4 length cap"})
		return
	}

	if s.blocklist == nil {
		jsonResponse(w, http.StatusOK, map[string]string{"status": "blocklist not enabled"})
		return
	}
	if err := s.blocklist.UnblockDomain(req.Domain); err != nil {
		jsonResponse(w, http.StatusInsufficientStorage, map[string]string{"error": err.Error()})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "unblocked", "domain": req.Domain})
}

func (s *AdminServer) handleBlocklistCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "missing domain parameter"})
		return
	}
	if len(domain) > 255 {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "domain exceeds RFC 1035 §2.3.4 length cap"})
		return
	}

	if s.blocklist == nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"blocked": false, "domain": domain})
		return
	}
	blocked := s.blocklist.CheckDomain(domain)
	jsonResponse(w, http.StatusOK, map[string]interface{}{"blocked": blocked, "domain": domain})
}

func (s *AdminServer) handleBlocklistDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.blocklist == nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"blocked_domains":  []string{},
			"allowed_domains":  []string{},
		})
		return
	}

	blocks, allows := s.blocklist.BlockedDomains()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"blocked_domains": blocks,
		"allowed_domains": allows,
	})
}
