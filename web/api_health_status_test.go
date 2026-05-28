package web

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// TestHandleHealth_ReturnsServiceUnavailableWhenNoResolver pins the
// Kubernetes-style readiness contract: a degraded resolver MUST
// produce a 503 status code, not just a 200 with a JSON flag. Pod
// readiness probes gate traffic on status code alone — without 503
// during startup priming, the pod would receive client traffic
// before the resolver had primed the root NS cache.
func TestHandleHealth_ReturnsServiceUnavailableWhenNoResolver(t *testing.T) {
	s := &AdminServer{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/system/health", nil)

	s.handleHealth(w, req)

	if w.Code != 503 {
		t.Errorf("status = %d, want 503 (readiness contract)", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if body["status"] != "degraded" {
		t.Errorf("status field = %v, want degraded", body["status"])
	}
	if body["resolver_ready"] != false {
		t.Errorf("resolver_ready = %v, want false", body["resolver_ready"])
	}
}
