package web

import (
	"net/http"
	"strconv"
)

const maxTopPageLimit = 2000

func parseTopPagination(r *http.Request, defaultLimit int) (limit, offset int) {
	limit = defaultLimit
	offset = 0

	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxTopPageLimit {
		limit = maxTopPageLimit
	}

	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	return limit, offset
}

// handleTopClients handles GET /api/stats/top-clients and returns top querying clients.
func (s *AdminServer) handleTopClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit, offset := parseTopPagination(r, s.config.Web.TopClientsLimit)
	entries, total := s.topClients.TopPage(limit, offset)
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"entries":  entries,
		"limit":    limit,
		"offset":   offset,
		"total":    total,
		"has_more": offset+len(entries) < total,
	})
}

// handleTopDomains handles GET /api/stats/top-domains and returns top queried domains.
func (s *AdminServer) handleTopDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit, offset := parseTopPagination(r, s.config.Web.TopDomainsLimit)
	entries, total := s.topDomains.TopPage(limit, offset)
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"entries":  entries,
		"limit":    limit,
		"offset":   offset,
		"total":    total,
		"has_more": offset+len(entries) < total,
	})
}
