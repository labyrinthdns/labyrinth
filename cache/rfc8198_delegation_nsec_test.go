package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestLookupNSEC_DelegationNSECRejectedAsNODATA pins Y82 / the cache-
// side mirror of Y79's validator pin: a parent-side delegation NSEC
// (NS bit set, SOA bit clear) MUST NOT be used as authoritative NODATA
// proof for the child zone's records. The validator's NSEC denial path
// already rejects this (RFC 4035 §5.4, [dnssec/rfc4035_wildcard_proof_test.go]);
// the aggressive NSEC cache enforces the same guard so a delegation
// NSEC that slipped into a (NODATA-classified) response — perhaps via
// an upstream that misclassified a referral — cannot retroactively
// synthesise NODATA for arbitrary child-zone records.
//
// Why this matters: the delegation NSEC at the zone cut between
// `example.com` and `child.example.com` has NS + RRSIG + NSEC in its
// bitmap (the parent publishes these at the cut point) but NOT SOA
// (the SOA lives on the child side). Its bitmap therefore EXCLUDES
// every type the child zone serves (A, AAAA, MX, …). Without the
// guard, the aggressive cache would happily say "AAAA NODATA at
// child.example.com" for any query — hiding records the child zone
// actually publishes.
//
// We pin both polarities to lock the behaviour:
//
//   1. Delegation NSEC (NS, no SOA) at qname → MUST NOT synthesise.
//   2. Authoritative NSEC (NS + SOA OR no NS) at qname → MAY
//      synthesise normally.
func TestLookupNSEC_DelegationNSECRejectedAsNODATA(t *testing.T) {
	t.Run("delegation NSEC (NS, no SOA) → rejected", func(t *testing.T) {
		c := NewCache(1024, 60, 86400, 3600, nil)
		// Delegation point at child.example.com: parent publishes the
		// NS RRset, the NSEC bitmap declares NS+RRSIG+NSEC. SOA is
		// notably ABSENT — that's what makes this a delegation NSEC.
		authority := newFakeNSECAuthority(t,
			"child.example.com", "next.example.com",
			[]uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC})
		c.RegisterNSECInterval("example.com", 300, authority)

		// Query for AAAA at the delegation point. AAAA is NOT in the
		// bitmap; the naive synth path would treat that as NODATA.
		// Our gate must refuse.
		if _, ok := c.LookupNSECCoversTyped("child.example.com",
			dns.TypeAAAA, dns.ClassIN); ok {
			t.Errorf("aggressive cache synthesised NODATA from a delegation NSEC — RFC 4035 §5.4 / RFC 6840 §4.4 violation; child zone's AAAA records would be hidden")
		}
	})

	t.Run("authoritative NSEC (NS + SOA) → accepted", func(t *testing.T) {
		c := NewCache(1024, 60, 86400, 3600, nil)
		// The child-side apex NSEC: has SOA (child is authoritative
		// for itself) AND NS (it serves its own NS records). This
		// can authentically prove "no AAAA at the apex."
		authority := newFakeNSECAuthority(t,
			"child.example.com", "next.child.example.com",
			[]uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC})
		c.RegisterNSECInterval("child.example.com", 300, authority)

		if _, ok := c.LookupNSECCoversTyped("child.example.com",
			dns.TypeAAAA, dns.ClassIN); !ok {
			t.Errorf("authoritative apex NSEC (with both NS and SOA) was rejected — legitimate NODATA synth path broken")
		}
	})

	t.Run("non-delegation NSEC (no NS, no SOA — leaf with only A) → accepted", func(t *testing.T) {
		c := NewCache(1024, 60, 86400, 3600, nil)
		// A leaf name's NSEC: has only A (and RRSIG, NSEC for
		// validation). No NS at all — NOT a delegation point.
		authority := newFakeNSECAuthority(t,
			"host.example.com", "next.example.com",
			[]uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC})
		c.RegisterNSECInterval("example.com", 300, authority)

		if _, ok := c.LookupNSECCoversTyped("host.example.com",
			dns.TypeAAAA, dns.ClassIN); !ok {
			t.Errorf("leaf-host NSEC (no NS, no SOA) rejected — only NS+no-SOA pattern should trigger the delegation gate")
		}
	})
}
