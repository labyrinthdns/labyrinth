package web

import (
	"net/http/httptest"
	"testing"
)

// TestHandleLivez_Always200 pins liveness semantics — the endpoint
// returns 200 regardless of whether the resolver is primed. Liveness
// asks "is the process alive at all"; the HTTP handler answering at
// all proves liveness. Tying livez to resolver-ready state would
// cause K8s to restart pods during slow root priming, which is the
// exact failure mode the liveness/readiness split is designed to
// prevent.
func TestHandleLivez_Always200(t *testing.T) {
	s := &AdminServer{} // no resolver wired — readiness would 503
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/system/livez", nil)

	s.handleLivez(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200 (liveness is process-level, not resolver-level)", w.Code)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("body = %q, want empty", body)
	}
}

func TestHandleLivez_MethodNotAllowed(t *testing.T) {
	s := &AdminServer{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/system/livez", nil)
	s.handleLivez(w, req)
	if w.Code != 405 {
		t.Errorf("status = %d, want 405", w.Code)
	}
}
