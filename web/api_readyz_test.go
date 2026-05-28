package web

import (
	"net/http/httptest"
	"testing"
)

// TestHandleReadyz_BodyLessAndStatusCoded pins the conventional
// k8s-readyz contract: status code only, no body. A regression that
// added a JSON body would still satisfy a simple status-code probe
// but would waste bytes per scrape (and at 1Hz × 1000 pods that adds
// up). The body-less shape also avoids the JSON encoder allocation
// on the hot probe path.
func TestHandleReadyz_BodyLessAndStatusCoded(t *testing.T) {
	s := &AdminServer{} // no resolver → degraded
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/system/readyz", nil)

	s.handleReadyz(w, req)

	if w.Code != 503 {
		t.Errorf("status = %d, want 503 (resolver not ready)", w.Code)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("body = %q, want empty (status-code-only probe contract)", body)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// TestHandleReadyz_MethodNotAllowed — only GET is meaningful.
func TestHandleReadyz_MethodNotAllowed(t *testing.T) {
	s := &AdminServer{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/system/readyz", nil)
	s.handleReadyz(w, req)
	if w.Code != 405 {
		t.Errorf("status = %d, want 405", w.Code)
	}
}
