package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	srv.config.Load().Web.Auth.Username = "" // pass-through auth
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
	srv.config.Load().Web.Auth.Username = ""
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

func TestSetupComplete_RequiresValidCredentials(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing username", body: `{"password":"validpwd123"}`},
		{name: "blank username", body: `{"username":"  ","password":"validpwd123"}`},
		{name: "username with newline", body: `{"username":"admin\nother","password":"validpwd123"}`},
		{name: "missing password", body: `{"username":"admin"}`},
		{name: "short password", body: `{"username":"admin","password":"short"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := testAdminServer(t)
			srv.setupDone.Store(false)
			srv.SetConfigPath(filepath.Join(t.TempDir(), "labyrinth.yaml"))

			req := httptest.NewRequest(http.MethodPost, "/api/setup/complete", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			srv.handleSetupComplete(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			if srv.setupDone.Load() {
				t.Fatal("invalid credentials must not complete setup")
			}
		})
	}
}

func TestSetupComplete_PublishesCredentialsImmediately(t *testing.T) {
	srv := testAdminServer(t)
	srv.setupDone.Store(false)
	srv.SetConfigPath(filepath.Join(t.TempDir(), "labyrinth.yaml"))

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	setupBody := `{"username":"admin","password":"validpwd123"}`
	setupReq := httptest.NewRequest(http.MethodPost, "/api/setup/complete", strings.NewReader(setupBody))
	setupW := httptest.NewRecorder()
	mux.ServeHTTP(setupW, setupReq)
	if setupW.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want 200; body=%s", setupW.Code, setupW.Body.String())
	}

	// The already-registered middleware must see the newly published auth
	// snapshot immediately; no restart or route rebuild is allowed.
	protectedReq := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	protectedW := httptest.NewRecorder()
	mux.ServeHTTP(protectedW, protectedReq)
	if protectedW.Code != http.StatusUnauthorized {
		t.Fatalf("protected API status = %d, want 401 after setup", protectedW.Code)
	}

	loginBody, err := json.Marshal(map[string]string{"username": "admin", "password": "validpwd123"})
	if err != nil {
		t.Fatal(err)
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(loginBody)))
	loginW := httptest.NewRecorder()
	mux.ServeHTTP(loginW, loginReq)
	if loginW.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200 without restart; body=%s", loginW.Code, loginW.Body.String())
	}
}
