package web

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRequireAuth_AppliesBodyCap pins the request-body size limit:
// an authenticated POST whose body exceeds MaxRequestBodyBytes must
// be cut off by http.MaxBytesReader before the handler can decode it.
// Without this gate an attacker (or a buggy script) POSTing a 1GB
// JSON blob would force the resolver to allocate 1GB of RAM before
// the decoder gave up — a trivial OOM DoS.
//
// The pin asserts the *behaviour* (read past the cap returns an
// error) rather than reading the cap from middleware constants — a
// regression that raised the cap to 1GB would still match if we
// pinned the value alone.
func TestRequireAuth_AppliesBodyCap(t *testing.T) {
	srv := testAdminServer(t)
	// pass-through auth so the body cap is the only gate
	srv.config.Web.Auth.Username = ""

	// Build a body that exceeds the cap.
	body := strings.NewReader(strings.Repeat("x", MaxRequestBodyBytes+1))
	req := httptest.NewRequest("POST", "/api/test", body)
	w := httptest.NewRecorder()

	srv.requireAuth(func(w2 http.ResponseWriter, r2 *http.Request) {
		// The handler tries to read everything; MaxBytesReader will
		// surface http.MaxBytesError once the limit is reached.
		_, err := io.ReadAll(r2.Body)
		if err == nil {
			t.Errorf("read past cap returned no error — MaxBytesReader not applied")
			return
		}
	})(w, req)
}

// TestRequireAuth_AllowsBodyUnderCap — negative control: a body
// well under the cap must pass through unmodified, so legitimate
// POST flows (NTA install, config update) aren't broken.
func TestRequireAuth_AllowsBodyUnderCap(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.Username = ""

	small := bytes.NewReader([]byte(`{"zone":"example.test"}`))
	req := httptest.NewRequest("POST", "/api/dnssec/nta", small)
	w := httptest.NewRecorder()

	var got []byte
	srv.requireAuth(func(_ http.ResponseWriter, r2 *http.Request) {
		got, _ = io.ReadAll(r2.Body)
	})(w, req)

	if string(got) != `{"zone":"example.test"}` {
		t.Errorf("body mangled by cap: got %q, want %q", got, `{"zone":"example.test"}`)
	}
}
