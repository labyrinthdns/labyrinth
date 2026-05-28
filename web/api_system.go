package web

import (
	"net/http"
	"runtime"
)

// handleHealth handles GET /api/system/health — JSON health check.
// Returns 200 when the resolver is ready, 503 Service Unavailable
// when it is not. The HTTP status code (not just the JSON body) is
// the load-bearing signal because Kubernetes-style readiness probes
// gate traffic on status code alone; a 200 with `status:"degraded"`
// would not pull the pod out of rotation during startup priming.
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
	httpStatus := http.StatusOK
	if !resolverReady {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	jsonResponse(w, httpStatus, map[string]interface{}{
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
