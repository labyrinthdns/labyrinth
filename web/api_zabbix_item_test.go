package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestZabbixItem_RejectsOverlongKey pins the length cap on
// /api/zabbix/item?key=… A real Zabbix item key is a short
// identifier (labyrinth.queries.total, etc.); a multi-MB key only
// ever lands on the "unknown key" branch and would otherwise be
// reflected back into the error response. Refusing pre-empts both
// the wasted work and the reflection.
func TestZabbixItem_RejectsOverlongKey(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = "" // pass-through auth
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	huge := strings.Repeat("x", maxZabbixKeyLength+1)
	req := httptest.NewRequest("GET", "/api/zabbix/item?key="+huge, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (over-cap key must be rejected)", w.Code)
	}
}

// TestZabbixItem_DoesNotReflectUnknownKey pins that the error
// response for an unknown key does NOT echo the user-supplied key.
// Reflecting attacker-controlled bytes into a text/plain response
// body (which then gets piped into Zabbix log lines, etc.) is a
// poor habit even on an authenticated route.
func TestZabbixItem_DoesNotReflectUnknownKey(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = ""
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	// Use a key that doesn't match any real metric but is short
	// enough to pass the length cap. The sentinel string must NOT
	// appear in the response body.
	const sentinel = "zXz-sentinel-canary-zXz"
	req := httptest.NewRequest("GET", "/api/zabbix/item?key="+sentinel, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 for unknown key", w.Code)
	}
	if strings.Contains(w.Body.String(), sentinel) {
		t.Errorf("error body reflected the user-supplied key %q:\n%s",
			sentinel, w.Body.String())
	}
}

// TestZabbixItem_EmitsNoStoreOnSuccess — companion pin: live metric
// values must carry Cache-Control: no-store so a scraping pipeline
// (or intermediate proxy) cannot serve a stale value during an
// incident. A flat-line dashboard at the worst moment is worse than
// no data.
func TestZabbixItem_EmitsNoStoreOnSuccess(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = ""
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/api/zabbix/item?key=labyrinth.uptime", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 for a real metric", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}
