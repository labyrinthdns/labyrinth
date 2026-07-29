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
// invariant introduced by v0.8.24 and tightened by v0.8.26: a
// handleLogin reading credential fields off the runtime config must be
// race-free against a concurrent /api/auth/change-password rewriting
// them.
//
// History:
//   - v0.8.24 implemented this with a `configFileMu` extension on the
//     reader side. Login took the same mutex the writer was already
//     holding for the on-disk lost-update gate.
//   - v0.8.26 migrated `s.config` from `*config.Config` to
//     `atomic.Pointer[config.Config]`. Readers now do
//     `s.config.Load()` and use the returned snapshot. Writers do
//     copy-on-write `Load → shallow copy → mutate → Store`. The
//     reader-side `configFileMu` extension was retired (no longer
//     needed; reader pays no lock cost).
//
// What was racy before v0.8.24:
//
//	cfgUser := s.config.Web.Auth.Username       // plain field read
//	cfgHash := s.config.Web.Auth.PasswordHash   // plain field read
//
// while handleChangePassword did `s.config.Web.Auth.PasswordHash =
// newHash` under configFileMu — the writer was synchronised but the
// reader was not. The race detector flagged it on every routine
// credential rotation, and on a sufficiently adversarial scheduler
// the login handler could observe a torn Go string header (old ptr +
// new len, or vice versa) — bcrypt against the resulting garbage
// bytes then rejects the operator's correct password during the
// rotation window.
//
// The pin fires N login goroutines against the auth endpoint while a
// single goroutine rotates the password. Under the v0.8.26 atomic
// publication this passes silently; `go test -race` flags any future
// regression that drops the atomic publication AND fails to add an
// equivalent lock back.
func TestHandleLogin_CredentialReadIsRaceSafeVsPasswordChange(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)

	const loginGoroutines = 16
	const loginAttemptsEach = 50

	var stopRotator atomic.Bool

	var wg sync.WaitGroup
	wg.Add(loginGoroutines + 1)

	// One writer: rotate the password back and forth. Both rotations
	// land via the production handler, which still takes configFileMu
	// for the on-disk lost-update gate and Stores a new *Config via
	// atomic.Pointer.
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
	// about the success/failure split — only that the read of the
	// credential fields off the runtime config is race-free.
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
