package web

import (
	"net/http"
	"strconv"
)

// handleTopClients handles GET /api/stats/top-clients — returns top querying clients.
func (s *AdminServer) handleTopClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit := s.config.Web.TopClientsLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	entries := s.topClients.Top(limit)
	jsonResponse(w, http.StatusOK, map[string]interface{}{"entries": entries})
}

// handleTopDomains handles GET /api/stats/top-domains — returns top queried domains.
func (s *AdminServer) handleTopDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit := s.config.Web.TopDomainsLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	entries := s.topDomains.Top(limit)
	jsonResponse(w, http.StatusOK, map[string]interface{}{"entries": entries})
}
