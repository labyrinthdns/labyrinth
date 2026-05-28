package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestLookupNSEC3_DelegationNSEC3RejectedAsNODATA pins Y84: the
// NSEC3 counterpart of Y82. The fix in `cache/nsec3_aggressive.go`
// adds the same NS-without-SOA guard that the NSEC sibling has,
// closing the symmetric attack surface:
//
//   An attacker-injected parent-side delegation NSEC3 (whose bitmap
//   reflects only what the PARENT publishes at the zone cut: NS,
//   RRSIG, NSEC3 — but NOT SOA, A, AAAA, MX, …) would otherwise let
//   the aggressive cache synthesise NODATA for arbitrary child-zone
//   record types. Every type the child actually serves is absent
//   from the parent's bitmap, so the naive `typeBitmapHas(qtype) →
//   skip` check would never fire and synthesis would erroneously
//   succeed.
//
// The pin drives the three polarities:
//   1. Delegation NSEC3 (NS, no SOA) at qname-hash → MUST NOT synth.
//   2. Authoritative apex NSEC3 (NS + SOA) at qname-hash → synth OK.
//   3. Leaf NSEC3 (no NS, no SOA) at qname-hash → synth OK.
//
// Since NSEC3 indexes by HASH not name, the test uses
// `nsec3Hash(qname)` to align the cached owner-hash with the query's
// computed hash.
func TestLookupNSEC3_DelegationNSEC3RejectedAsNODATA(t *testing.T) {
	t.Run("delegation NSEC3 (NS, no SOA) → rejected", func(t *testing.T) {
		c := NewCache(1024, 60, 86400, 3600, nil)
		qname := "child.example.com"
		qHash := nsec3Hash(qname)

		// Delegation point bitmap — parent publishes NS+RRSIG+NSEC3
		// at the zone cut; no SOA (lives on child side).
		authority := newFakeNSEC3AuthorityWithBitmap(t,
			qHash, []byte{0xff, 0xff}, 0x00 /* no opt-out */,
			[]uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
		c.RegisterNSEC3Interval("example.com", 300, authority)

		if _, ok := c.LookupNSEC3CoversTyped(qname, dns.TypeAAAA, dns.ClassIN); ok {
			t.Errorf("aggressive NSEC3 cache synthesised NODATA from a delegation NSEC3 (NS without SOA) — RFC 4035 §5.4 / RFC 6840 §4.4 violation; child zone's AAAA records would be hidden")
		}
	})

	t.Run("authoritative apex NSEC3 (NS + SOA) → accepted", func(t *testing.T) {
		c := NewCache(1024, 60, 86400, 3600, nil)
		qname := "child.example.com"
		qHash := nsec3Hash(qname)

		authority := newFakeNSEC3AuthorityWithBitmap(t,
			qHash, []byte{0xff, 0xff}, 0x00,
			[]uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC3})
		c.RegisterNSEC3Interval("child.example.com", 300, authority)

		if _, ok := c.LookupNSEC3CoversTyped(qname, dns.TypeAAAA, dns.ClassIN); !ok {
			t.Errorf("authoritative apex NSEC3 (NS + SOA in bitmap) was rejected — legitimate NODATA synth path broken")
		}
	})

	t.Run("leaf NSEC3 (no NS, no SOA) → accepted", func(t *testing.T) {
		c := NewCache(1024, 60, 86400, 3600, nil)
		qname := "host.example.com"
		qHash := nsec3Hash(qname)

		authority := newFakeNSEC3AuthorityWithBitmap(t,
			qHash, []byte{0xff, 0xff}, 0x00,
			[]uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3})
		c.RegisterNSEC3Interval("example.com", 300, authority)

		if _, ok := c.LookupNSEC3CoversTyped(qname, dns.TypeAAAA, dns.ClassIN); !ok {
			t.Errorf("leaf-host NSEC3 (no NS, no SOA) rejected — only NS+no-SOA pattern should trigger the delegation gate")
		}
	})
}
