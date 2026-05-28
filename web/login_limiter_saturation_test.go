package web

import (
	"strconv"
	"testing"
	"time"
)

// TestLoginLimiter_RefusesNewIPsWhenSaturated pins the memory-DoS
// defence on the login limiter. Without a cap on the entries map a
// botnet hitting /api/auth/login from a million unique source IPs
// would grow the map until the resolver ran out of RAM — the
// existing 5-minute cleanup tick would not run nearly fast enough to
// keep up.
//
// The pin uses a small custom maxEntries (10) so the test is fast.
// Fills the limiter to capacity with known IPs, then asserts a new
// IP gets denied with the lockoutFor as retry-after. Known IPs
// already in the map continue to be processed normally — the
// saturation gate only fires for brand-new entries.
func TestLoginLimiter_RefusesNewIPsWhenSaturated(t *testing.T) {
	l := &loginLimiter{
		entries:     make(map[string]*loginEntry),
		maxFailures: loginMaxFailures,
		window:      loginFailureWindow,
		lockoutFor:  loginLockoutFor,
		now:         time.Now,
	}

	// Saturate up to (but not over) the production cap by inserting
	// loginMaxEntries distinct IPs. allow() should succeed for each.
	for i := 0; i < loginMaxEntries; i++ {
		ok, _ := l.allow("10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256))
		if !ok {
			t.Fatalf("filler IP #%d unexpectedly denied", i)
		}
	}

	// A brand-new IP must now be denied: the gate fired.
	ok, retry := l.allow("203.0.113.99")
	if ok {
		t.Errorf("new IP was allowed despite limiter being saturated")
	}
	if retry != loginLockoutFor {
		t.Errorf("retry-after = %v, want lockoutFor (%v)", retry, loginLockoutFor)
	}

	// And an IP that was already tracked (the first one) must still
	// be processed normally — the gate only refuses new entries.
	ok, _ = l.allow("10.0.0.0")
	if !ok {
		t.Error("known IP was denied — saturation gate must only refuse NEW entries")
	}
}

// TestLoginLimiter_RecoversAfterEviction — once the cleanup tick
// evicts idle entries, the saturation gate should re-open for new
// IPs. This locks the recovery half of the contract: the deny is a
// temporary back-pressure signal, not a permanent refusal.
func TestLoginLimiter_RecoversAfterEviction(t *testing.T) {
	// Time-mocked limiter so we can fast-forward past loginIdleEvict.
	fakeNow := time.Now()
	l := &loginLimiter{
		entries:     make(map[string]*loginEntry),
		maxFailures: loginMaxFailures,
		window:      loginFailureWindow,
		lockoutFor:  loginLockoutFor,
		now:         func() time.Time { return fakeNow },
	}

	// Fill to capacity.
	for i := 0; i < loginMaxEntries; i++ {
		l.allow("10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256))
	}

	// Confirm saturated.
	if ok, _ := l.allow("198.51.100.7"); ok {
		t.Fatal("setup: limiter should be saturated before recovery")
	}

	// Fast-forward past idle eviction window and run eviction.
	fakeNow = fakeNow.Add(loginIdleEvict + time.Minute)
	l.evictIdle()

	// New IPs should be accepted again.
	if ok, _ := l.allow("198.51.100.7"); !ok {
		t.Error("saturation gate did not recover after eviction tick")
	}
}
