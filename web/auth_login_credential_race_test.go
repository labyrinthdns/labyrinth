package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestHandleLogin_CredentialReadIsRaceSafeVsPasswordChange pins the
// v0.8.24 gate: handleLogin must hold configFileMu when reading the
// credential fields from s.config so a concurrent password change can
// neither tear the in-memory PasswordHash string (16-byte Go header
// = ptr + len) nor leave the login handler comparing against a
// half-applied snapshot.
//
// Before the fix, handleLogin did:
//
//	cfgUser := s.config.Web.Auth.Username
//	cfgHash := s.config.Web.Auth.PasswordHash
//
// without any synchronisation, while handleChangePassword writes
// `s.config.Web.Auth.PasswordHash = newHash` under configFileMu. The
// 60+ second exposure is the visible-to-race-detector window during
// every routine credential rotation: every login that lands while
// the change-password handler is mid-rewrite races on the string
// header. The race detector flags it, and on a sufficiently
// adversarial scheduler the login handler can observe a torn header
// (old ptr + new len, or vice versa) — bcrypt against the resulting
// garbage bytes then rejects the operator's correct password during
// the rotation window.
//
// The pin fires N login goroutines against the auth endpoint while a
// single goroutine rotates the password via change-password. Without
// the configFileMu coverage on the reader side, `go test -race`
// reports a data race on s.config.Web.Auth.PasswordHash; with the fix
// the test passes cleanly.
func TestHandleLogin_CredentialReadIsRaceSafeVsPasswordChange(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)

	const loginGoroutines = 16
	const loginAttemptsEach = 50

	var stopRotator atomic.Bool

	var wg sync.WaitGroup
	wg.Add(loginGoroutines + 1)

	// One writer: rotate the password back and forth. Both rotations
	// land via the production handler, so configFileMu is held the way
	// the production path does.
	go func() {
		defer wg.Done()
		alt := "altPass!1234"
		current := password
		next := alt
		for i := 0; i < 20 && !stopRotator.Load(); i++ {
			body := `{"current_password":"` + current + `","new_password":"` + next + `"}`
			req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.handleChangePassword(w, req)
			// After a successful rotation, swap which password is
			// considered current — so the next login attempts see a
			// moving target. We don't assert on individual login
			// outcomes because the race window means some logins
			// land before, some after, the rotation.
			if w.Code == http.StatusOK {
				current, next = next, current
			}
		}
	}()

	// Many readers: hammer handleLogin in parallel. We don't care
	// about the success/failure split — only that the read of
	// s.config.Web.Auth.* is race-free.
	for g := 0; g < loginGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < loginAttemptsEach; i++ {
				body := `{"username":"admin","password":"` + password + `"}`
				req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				srv.handleLogin(w, req)
				// We deliberately do not check w.Code: under the
				// rotation race, some logins legitimately get 401
				// because the password is currently the alternate.
				// The point of the test is the race detector.
			}
		}()
	}

	stopRotator.Store(true)
	wg.Wait()

	// If we got here under -race without a data-race report, the
	// configFileMu coverage on the credential read holds. The test
	// itself does not assert on s.config because the rotator may
	// have left it on either password; what we assert is the absence
	// of a race report, which the harness surfaces by failing the
	// test automatically when -race is on.
}
