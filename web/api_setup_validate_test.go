package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSetupComplete_RejectsOverlongString pins the input-cap gate on
// /api/setup/complete. The setup endpoint can be hit before any
// authentication exists, so an attacker reaching it first could
// otherwise submit pathological values that round-trip into YAML
// on disk and crash on next startup or balloon resolver memory.
//
// The pin sends a 4 KiB username, which fits inside the v0.7.26
// 1 MiB body cap but exceeds the per-field 256-byte cap, and asserts
// a clean 400. Other string fields share the same gate; covering
// one is enough to prove the validator is wired.
func TestSetupComplete_RejectsOverlongString(t *testing.T) {
	srv := testAdminServer(t)
	srv.setupDone.Store(false)
	srv.config.Web.Auth.Username = "" // pass-through auth
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	huge := strings.Repeat("u", setupMaxStringLen+1)
	body := `{"username":"` + huge + `","password":"validpwd123"}`
	req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (over-cap username should be rejected)", w.Code)
	}
}

// TestSetupComplete_RejectsAbsurdMaxDepth pins the resolver-depth
// cap. A 1e9 depth would cause stack overflow + extreme query
// latency on every resolution; the cap stops it at config-write time.
func TestSetupComplete_RejectsAbsurdMaxDepth(t *testing.T) {
	srv := testAdminServer(t)
	srv.setupDone.Store(false)
	srv.config.Web.Auth.Username = ""
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	body := `{"username":"admin","password":"validpwd123","max_depth":1000000}`
	req := httptest.NewRequest("POST", "/api/setup/complete", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (max_depth over cap should be rejected)", w.Code)
	}
}

// TestValidateSetupRequest_AcceptsValid — negative control: every
// reasonable real-world value must pass the validator unchanged.
func TestValidateSetupRequest_AcceptsValid(t *testing.T) {
	req := &SetupRequest{
		ListenAddr:     ":53",
		WebAddr:        "127.0.0.1:8080",
		Username:       "admin",
		Password:       "validpwd123",
		MaxCacheSize:   100000,
		MaxDepth:       30,
		RateLimitRate:  100.0,
		RateLimitBurst: 200,
		LogLevel:       "info",
		LogFormat:      "json",
	}
	if err := validateSetupRequest(req); err != nil {
		t.Errorf("validateSetupRequest rejected a sane request: %v", err)
	}
}
