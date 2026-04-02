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
		jsonResponse(w, http.StatusOK, map[string]interface{}{"enabled": false})
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
		jsonResponse(w, http.StatusOK, []interface{}{})
		return
	}
	jsonResponse(w, http.StatusOK, s.blocklist.Sources())
}

func (s *AdminServer) handleBlocklistRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.blocklist == nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "blocklist not enabled"})
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
	if s.blocklist == nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "blocklist not enabled"})
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "missing or invalid domain"})
		return
	}

	s.blocklist.BlockDomain(req.Domain)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "blocked", "domain": req.Domain})
}

func (s *AdminServer) handleBlocklistUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.blocklist == nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "blocklist not enabled"})
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "missing or invalid domain"})
		return
	}

	s.blocklist.UnblockDomain(req.Domain)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "unblocked", "domain": req.Domain})
}

func (s *AdminServer) handleBlocklistCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.blocklist == nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"blocked": false, "domain": ""})
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "missing domain parameter"})
		return
	}

	blocked := s.blocklist.CheckDomain(domain)
	jsonResponse(w, http.StatusOK, map[string]interface{}{"blocked": blocked, "domain": domain})
}
