package web

import (
	"net/http"
	"runtime"
)

// handleHealth handles GET /api/system/health — JSON health check.
func (s *AdminServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	resolverReady := false
	if s.resolver != nil {
		resolverReady = s.resolver.IsReady()
	}

	status := "healthy"
	if !resolverReady {
		status = "degraded"
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":         status,
		"resolver_ready": resolverReady,
	})
}

// handleVersion handles GET /api/system/version — version info.
func (s *AdminServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"version":    Version,
		"build_time": BuildTime,
		"go_version": GoVersion,
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	})
}
