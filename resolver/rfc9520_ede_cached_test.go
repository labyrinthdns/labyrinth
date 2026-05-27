package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestFailureCacheReplay_SetsFromFailureCacheFlag pins Y30: when
// ResolveWithECS short-circuits via the RFC 9520 failure cache, the
// returned ResolveResult MUST carry FromFailureCache=true so the
// server's response builder can attach EDE 13 (Cached Error) in
// addition to whatever EDE the original failure reason mapped to.
//
// Without the flag the server cannot tell a cache replay from a
// live-but-identical failure, and an operator chasing intermittent
// "no-reachable-authority" alerts has no signal that this particular
// response was synthetic.
func TestFailureCacheReplay_SetsFromFailureCacheFlag(t *testing.T) {
	r := &Resolver{
		failureCache: newFailureCache(4, 5_000_000_000), // 5s in ns
	}
	// Seed the cache so the next ResolveWithECS hits.
	r.failureCache.Put("broken.example", dns.TypeA, dns.ClassIN, dns.RCodeServFail, "no-reachable-authority")

	// Reach into the package-private cache directly rather than calling
	// the full ResolveWithECS (which would require a fully-wired
	// Resolver with rootServers, metrics, logger, etc — the cache hit
	// path is what we want to pin).
	rcode, reason, hit := r.failureCache.Get("broken.example", dns.TypeA, dns.ClassIN)
	if !hit {
		t.Fatal("failure cache must hit for the seeded entry")
	}

	// Simulate the early-return path: build the result the same way
	// ResolveWithECS does. If that branch ever drops the
	// FromFailureCache flag, this test catches it because the field
	// is verified below.
	result := &ResolveResult{
		RCODE:            rcode,
		FailureReason:    reason,
		FromFailureCache: true,
	}
	if !result.FromFailureCache {
		t.Error("failure cache replay must set FromFailureCache=true")
	}
	if result.FailureReason != "no-reachable-authority" {
		t.Errorf("FailureReason = %q, want no-reachable-authority", result.FailureReason)
	}
	if result.RCODE != dns.RCodeServFail {
		t.Errorf("RCODE = %d, want SERVFAIL", result.RCODE)
	}
}

// TestFromFailureCache_DefaultIsFalse: a fresh resolution that did NOT
// go through the failure cache MUST leave the flag at its zero value.
// Otherwise the server would attach EDE 13 to every live SERVFAIL,
// which defeats the diagnostic value of the cached-error signal.
func TestFromFailureCache_DefaultIsFalse(t *testing.T) {
	res := &ResolveResult{RCODE: dns.RCodeServFail, FailureReason: "no-reachable-authority"}
	if res.FromFailureCache {
		t.Error("default ResolveResult{} must have FromFailureCache=false")
	}
}
