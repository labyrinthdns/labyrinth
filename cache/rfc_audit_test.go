package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestStoreNegative_RejectsOutOfBailiwickSOA pins the R5 defense-in-depth
// guard (RFC 2308 §3): a negative-cache write whose authority section
// carries an SOA but the SOA owner does not cover the queried name is
// refused, regardless of what the upstream classifier decided. Without
// this guard, a caller could be tricked into caching a poisoned negative
// answer (attacker-attached SOA with attacker-controlled minimum-TTL)
// that pins the name into NXDOMAIN for as long as the SOA dictates.
func TestStoreNegative_RejectsOutOfBailiwickSOA(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// SOA owner = "attacker.example", qname = "victim.org" — completely
	// unrelated zones; the SOA has no authority over victim.org.
	soaRData := buildSOAWithMinimum(t, 3600)
	authority := []dns.ResourceRecord{{
		Name: "attacker.example", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 3600, RDLength: uint16(len(soaRData)), RData: soaRData,
	}}
	c.StoreNegative("victim.org", dns.TypeA, dns.ClassIN, NegNXDomain,
		dns.RCodeNXDomain, authority)

	if _, ok := c.Get("victim.org", dns.TypeA, dns.ClassIN); ok {
		t.Error("out-of-bailiwick SOA negative entry was cached " +
			"(RFC 2308 §3 violation)")
	}
}

// TestStoreNegative_AcceptsInBailiwickSOA is the positive counterpart:
// when the SOA owner IS an ancestor of qname the entry caches normally.
func TestStoreNegative_AcceptsInBailiwickSOA(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	soaRData := buildSOAWithMinimum(t, 3600)
	authority := []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 3600, RDLength: uint16(len(soaRData)), RData: soaRData,
	}}
	c.StoreNegative("missing.example.com", dns.TypeA, dns.ClassIN, NegNXDomain,
		dns.RCodeNXDomain, authority)

	if _, ok := c.Get("missing.example.com", dns.TypeA, dns.ClassIN); !ok {
		t.Error("ancestor SOA negative entry was not cached " +
			"(false-positive bailiwick rejection)")
	}
}

// TestStoreNegative_NoSOAStillCaches checks that a negative response with
// no SOA at all (RFC 2308 type-3 / pure-NXDOMAIN-no-SOA) still caches —
// the bailiwick check only applies when at least one SOA is present.
// Without an SOA there's nothing to forge.
func TestStoreNegative_NoSOAStillCaches(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// No SOA → falls back to the default negative TTL.
	c.StoreNegative("nothing.example.com", dns.TypeA, dns.ClassIN, NegNXDomain,
		dns.RCodeNXDomain, nil)

	if _, ok := c.Get("nothing.example.com", dns.TypeA, dns.ClassIN); !ok {
		t.Error("SOA-less negative entry must still cache")
	}
}

// TestStoreFailure_RFC9520Cap pins the R6 fix: resolution-failure cache
// entries have their TTL clamped to MaxFailureTTL (30s). A naive caller
// passing the auth-server-suggested 86400 cannot extend the negative
// window — RFC 9520 §4 caps it.
func TestStoreFailure_RFC9520Cap(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// Ask for a 1-day TTL — must be clamped to 30 s.
	c.StoreFailure("broken.example.com", dns.TypeA, dns.ClassIN, 86400)
	entry, ok := c.Get("broken.example.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("failure entry not stored")
	}
	if entry.OrigTTL > MaxFailureTTL {
		t.Errorf("failure TTL not clamped: got %d, max is %d", entry.OrigTTL, MaxFailureTTL)
	}
	if entry.NegType != NegServFail {
		t.Errorf("NegType: want NegServFail, got %d", entry.NegType)
	}
	if entry.RCODE != dns.RCodeServFail {
		t.Errorf("RCODE: want SERVFAIL, got %d", entry.RCODE)
	}
}

// TestStoreFailure_DefaultsWhenZero confirms the default-5s applies when
// the caller passes 0.
func TestStoreFailure_DefaultsWhenZero(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	c.StoreFailure("transient.example.com", dns.TypeA, dns.ClassIN, 0)
	entry, ok := c.Get("transient.example.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("failure entry not stored")
	}
	if entry.OrigTTL != DefaultFailureTTL {
		t.Errorf("zero TTL must adopt DefaultFailureTTL=%d, got %d",
			DefaultFailureTTL, entry.OrigTTL)
	}
}

// TestStoreFailure_PerTypeKeying checks that a failure on A doesn't poison
// AAAA — RFC 9520's caching is per-(name, type, class), not per-name.
func TestStoreFailure_PerTypeKeying(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	c.StoreFailure("dualstack.example.com", dns.TypeA, dns.ClassIN, 5)
	if _, ok := c.Get("dualstack.example.com", dns.TypeAAAA, dns.ClassIN); ok {
		t.Error("failure on A must not match AAAA lookup")
	}
	if _, ok := c.Get("dualstack.example.com", dns.TypeA, dns.ClassIN); !ok {
		t.Error("failure on A must match A lookup")
	}
}
