package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginLimiter_AllowsUntilThreshold(t *testing.T) {
	l := newLoginLimiter()

	for i := 0; i < l.maxFailures-1; i++ {
		ok, _ := l.allow("10.0.0.1")
		if !ok {
			t.Fatalf("attempt %d should be allowed before lockout", i)
		}
		l.recordFailure("10.0.0.1")
	}
	// The maxFailures-th failure arms the lockout.
	if ok, _ := l.allow("10.0.0.1"); !ok {
		t.Fatalf("attempt %d (final pre-lockout) should still be allowed", l.maxFailures-1)
	}
	l.recordFailure("10.0.0.1")

	// Now we should be locked out.
	ok, retryAfter := l.allow("10.0.0.1")
	if ok {
		t.Fatal("expected lockout after max failures")
	}
	if retryAfter <= 0 || retryAfter > l.lockoutFor+time.Second {
		t.Fatalf("retryAfter %v outside expected window (0, %v]", retryAfter, l.lockoutFor+time.Second)
	}
}

func TestLoginLimiter_LockoutExpires(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }

	for i := 0; i < l.maxFailures; i++ {
		l.recordFailure("10.0.0.2")
	}
	if ok, _ := l.allow("10.0.0.2"); ok {
		t.Fatal("expected lockout immediately after threshold")
	}

	// Advance past lockout — should reset and allow again.
	now = now.Add(l.lockoutFor + time.Second)
	if ok, _ := l.allow("10.0.0.2"); !ok {
		t.Fatal("lockout should have expired")
	}
}

func TestLoginLimiter_FailuresAgeOutOfWindow(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }

	// 4 failures, then a long pause that should age them out.
	for i := 0; i < l.maxFailures-1; i++ {
		l.recordFailure("10.0.0.3")
	}
	now = now.Add(l.window + time.Second)

	// One more failure should NOT trigger lockout because the older 4 aged out.
	l.recordFailure("10.0.0.3")
	if ok, _ := l.allow("10.0.0.3"); !ok {
		t.Fatal("aged-out failures must not contribute to current lockout")
	}
}

func TestLoginLimiter_SuccessClearsCounter(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < l.maxFailures-1; i++ {
		l.recordFailure("10.0.0.4")
	}
	l.recordSuccess("10.0.0.4")

	// After success, a fresh streak of failures should not trip immediately.
	for i := 0; i < l.maxFailures-1; i++ {
		l.recordFailure("10.0.0.4")
	}
	if ok, _ := l.allow("10.0.0.4"); !ok {
		t.Fatal("counter should reset on success")
	}
}

func TestLoginLimiter_PerIPIsolation(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < l.maxFailures; i++ {
		l.recordFailure("10.0.0.5")
	}
	if ok, _ := l.allow("10.0.0.5"); ok {
		t.Fatal("offender should be locked out")
	}
	if ok, _ := l.allow("10.0.0.6"); !ok {
		t.Fatal("unrelated IP must not be affected by another IP's lockout")
	}
}

func TestLoginLimiter_EvictIdle(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }

	l.recordFailure("10.0.0.7")
	if _, ok := l.entries["10.0.0.7"]; !ok {
		t.Fatal("entry should exist after recording a failure")
	}

	// Advance time past the idle threshold and run cleanup.
	now = now.Add(loginIdleEvict + time.Minute)
	l.evictIdle()

	if _, ok := l.entries["10.0.0.7"]; ok {
		t.Fatal("idle entry should have been evicted")
	}
}

func TestLoginClientIP(t *testing.T) {
	cases := []struct {
		remote string
		want   string
	}{
		{"", "unknown"},
		{"10.0.0.8:5555", "10.0.0.8"},
		{"[2001:db8::1]:5555", "2001:db8::1"},
		{"[fe80::1%eth0]:5555", "fe80::1"},
		{"not-an-address", "not-an-address"},
		{"10.0.0.9", "10.0.0.9"}, // bare IP — SplitHostPort fails, fall through
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(""))
		req.RemoteAddr = tc.remote
		got := loginClientIP(req)
		if got != tc.want {
			t.Errorf("loginClientIP(%q) = %q; want %q", tc.remote, got, tc.want)
		}
	}
}

func TestRetryAfterDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{0, time.Second},
		{-1 * time.Second, time.Second},
		{500 * time.Millisecond, time.Second},
		{1 * time.Second, time.Second},
		{1500 * time.Millisecond, 2 * time.Second},
		{59 * time.Second, 59 * time.Second},
	}
	for _, tc := range cases {
		got := retryAfterDuration(tc.in)
		if got != tc.want {
			t.Errorf("retryAfterDuration(%v) = %v; want %v", tc.in, got, tc.want)
		}
	}
}

func TestHandleLogin_LockoutReturns429(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)

	body := `{"username":"admin","password":"wrong"}`
	for i := 0; i < loginMaxFailures; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.1:54321"
		w := httptest.NewRecorder()
		srv.handleLogin(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, w.Code)
		}
	}

	// The next attempt — even with the correct password — must be locked out
	// before bcrypt runs. We don't need to use the real password for this; the
	// limiter short-circuits the credential check.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.1:54322"
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked-out attempt: want 429, got %d (body: %s)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Error("expected Retry-After header on 429")
	}
}

func TestHandleLogin_SuccessClearsLockout(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)

	// Burn maxFailures-1 attempts (one short of the lockout).
	bodyWrong := `{"username":"admin","password":"wrong"}`
	for i := 0; i < loginMaxFailures-1; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(bodyWrong))
		req.RemoteAddr = "203.0.113.2:1000"
		w := httptest.NewRecorder()
		srv.handleLogin(w, req)
	}

	// Successful login must reset the failure counter.
	bodyOK := `{"username":"admin","password":"` + password + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(bodyOK))
	req.RemoteAddr = "203.0.113.2:1001"
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("legitimate login should succeed: got %d", w.Code)
	}

	// Now we should have a full quota again.
	for i := 0; i < loginMaxFailures-1; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(bodyWrong))
		req.RemoteAddr = "203.0.113.2:1002"
		w := httptest.NewRecorder()
		srv.handleLogin(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d: counter was not reset by prior success", i)
		}
	}
}
