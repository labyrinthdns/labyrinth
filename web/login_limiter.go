package web

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Defaults for the login limiter. Conservative on purpose: 5 wrong-password
// tries within a 60s rolling window arms a 60s lockout. Successful logins
// clear the counter.
const (
	loginMaxFailures   = 5
	loginFailureWindow = 60 * time.Second
	loginLockoutFor    = 60 * time.Second
	loginCleanupTick   = 5 * time.Minute
	loginIdleEvict     = 15 * time.Minute
)

// loginLimiter is a per-IP sliding-window failure counter for the admin login
// endpoint. It is intentionally tighter than the resolver's RateLimiter because
// /api/auth/login is the only externally reachable, unauthenticated, password-
// gated route — brute-force protection here is non-optional.
type loginLimiter struct {
	mu          sync.Mutex
	entries     map[string]*loginEntry
	maxFailures int
	window      time.Duration
	lockoutFor  time.Duration
	now         func() time.Time // injectable for tests
}

type loginEntry struct {
	failures    []time.Time
	lockedUntil time.Time
	lastSeen    time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		entries:     make(map[string]*loginEntry),
		maxFailures: loginMaxFailures,
		window:      loginFailureWindow,
		lockoutFor:  loginLockoutFor,
		now:         time.Now,
	}
}

// allow reports whether the given client IP may attempt a login right now.
// When false, retryAfter holds how long the caller should advise the client
// to wait (rounded up to the next second; minimum 1s).
func (l *loginLimiter) allow(ip string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.touchLocked(ip, now)
	if !e.lockedUntil.IsZero() {
		if now.Before(e.lockedUntil) {
			return false, retryAfterDuration(e.lockedUntil.Sub(now))
		}
		// Lockout elapsed — reset and allow.
		e.lockedUntil = time.Time{}
		e.failures = e.failures[:0]
	}
	return true, 0
}

// recordFailure registers a failed authentication for the given IP and arms a
// lockout if the threshold is reached within the rolling window.
func (l *loginLimiter) recordFailure(ip string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.touchLocked(ip, now)
	if !e.lockedUntil.IsZero() && now.Before(e.lockedUntil) {
		// Already locked; don't extend on each request.
		return
	}
	e.failures = append(e.failures, now)
	if len(e.failures) >= l.maxFailures {
		e.lockedUntil = now.Add(l.lockoutFor)
	}
}

// recordSuccess clears any recorded failures for the given IP. Successful
// authentication is a strong signal that the operator is back in control,
// so we drop the counter immediately rather than letting it age out.
func (l *loginLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// touchLocked returns (and lazily creates) the entry for ip while pruning
// failures that have aged out of the rolling window. Caller holds l.mu.
func (l *loginLimiter) touchLocked(ip string, now time.Time) *loginEntry {
	e, ok := l.entries[ip]
	if !ok {
		e = &loginEntry{}
		l.entries[ip] = e
	}
	e.lastSeen = now
	cutoff := now.Add(-l.window)
	keep := e.failures[:0]
	for _, t := range e.failures {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	e.failures = keep
	return e
}

// startCleanup periodically evicts entries that have been idle longer than
// loginIdleEvict to bound memory under sustained scanning. Returns when ctx
// is cancelled.
func (l *loginLimiter) startCleanup(ctx context.Context) {
	t := time.NewTicker(loginCleanupTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.evictIdle()
		}
	}
}

func (l *loginLimiter) evictIdle() {
	cutoff := l.now().Add(-loginIdleEvict)
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, e := range l.entries {
		if e.lastSeen.Before(cutoff) && (e.lockedUntil.IsZero() || e.lockedUntil.Before(cutoff)) {
			delete(l.entries, ip)
		}
	}
}

// loginClientIP extracts a stable bucket key from r.RemoteAddr. IPv6 zone
// IDs and ports are stripped. Unparseable inputs collapse to a single
// "unknown" bucket so anonymous traffic shares one quota — better than
// granting every malformed connection its own clean slate.
func loginClientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if addr == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "unknown"
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// retryAfterDuration rounds up to the next whole second with a 1s floor so
// the Retry-After header always advises a real wait.
func retryAfterDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	rounded := d.Truncate(time.Second)
	if rounded < d {
		rounded += time.Second
	}
	if rounded < time.Second {
		return time.Second
	}
	return rounded
}
