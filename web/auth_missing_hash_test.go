package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleLoginRejectsMissingPasswordHash(t *testing.T) {
	s := testAdminServer(t)
	cfg := *s.config.Load()
	cfg.Web.Auth.Username = "admin"
	s.config.Store(&cfg)
	failed := false
	for _, user := range []string{"unknown", "admin"} {
		body := `{"username":"` + user + `","password":"labyrinth-timing-absorber"}`
		w := httptest.NewRecorder()
		s.handleLogin(w, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body)))
		t.Logf("username=%s EXPECTED: login=401 ACTUAL: login=%d", user, w.Code)
		if w.Code != http.StatusUnauthorized {
			failed = true
		}
		if w.Code == http.StatusOK {
			var response map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			request.Header.Set("Authorization", "Bearer "+response["token"])
			protected := httptest.NewRecorder()
			s.requireAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })(protected, request)
			t.Logf("EXPECTED: no usable session ACTUAL: protected status=%d", protected.Code)
		}
	}
	if failed {
		t.Fatal("PROBLEM CONFIRMED")
	}
	// Nearby cases: malformed configured hash, and a real hash of the same password.
	for _, valid := range []bool{false, true} {
		next := *s.config.Load()
		next.Web.Auth.PasswordHash = "invalid-hash"
		want := http.StatusUnauthorized
		if valid {
			hash, err := HashPassword("labyrinth-timing-absorber")
			if err != nil {
				t.Fatal(err)
			}
			next.Web.Auth.PasswordHash = hash
			want = http.StatusOK
		}
		s.config.Store(&next)
		body := `{"username":"admin","password":"labyrinth-timing-absorber"}`
		w := httptest.NewRecorder()
		s.handleLogin(w, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body)))
		t.Logf("configured valid hash=%v EXPECTED: %d ACTUAL: %d", valid, want, w.Code)
		if w.Code != want {
			t.Fatal("nearby case failed")
		}
	}
	t.Log("FIX VERIFIED")
}
