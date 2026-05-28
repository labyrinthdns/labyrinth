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

// handleReadyz handles GET /api/system/readyz — a status-code-only
// readiness probe. Unlike /api/system/health which returns a JSON
// body, this endpoint emits NO body at all so a Kubernetes-style
// probe scraping it costs zero allocations and the response fits in
// a single TCP segment. The body-less shape is the conventional
// k8s.io/component-base/healthz signal.
//
//   200 OK              — resolver primed and serving
//   503 Service Unavail — resolver not ready (still priming)
func (s *AdminServer) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.resolver == nil || !s.resolver.IsReady() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
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
