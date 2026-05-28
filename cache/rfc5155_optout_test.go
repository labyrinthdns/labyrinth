package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestRegisterNSEC3Interval_OptOutDropped pins Y85: RFC 5155 §6 +
// RFC 8198 §6 + RFC 9276 §3 require aggressive synthesis to SKIP
// opt-out NSEC3 records entirely. An opt-out NSEC3 (Flags LSB = 1)
// is authoritative ONLY for the existence/non-existence of SIGNED
// delegations — it makes NO claim about unsigned names in its gap.
// Using such a record for aggressive NXDOMAIN synthesis would
// fabricate "name doesn't exist" answers for names the zone never
// proved nonexistent, which is the canonical RFC 8198 §6 pitfall.
//
// The cache enforces this at `RegisterNSEC3Interval` line 120 by
// dropping opt-out intervals before they're indexed — they never
// enter the byZone map, so no subsequent lookup can find them.
//
// We pin BOTH sides of the gate to make the regression target
// unambiguous:
//
//   1. Opt-out flag SET (0x01) → interval NOT cached → no synth.
//   2. Opt-out flag CLEAR (0x00) → interval IS cached → synth fires.
//
// A regression that flipped the conditional (`!= 0` → `== 0`, or
// the entire guard removed) would either drop all NSEC3s and break
// aggressive use entirely, OR enable forgery via opt-out intervals.
func TestRegisterNSEC3Interval_OptOutDropped(t *testing.T) {
	t.Run("opt-out flag SET → interval dropped → no NXDOMAIN synth", func(t *testing.T) {
		c := NewCache(1024, 60, 86400, 3600, nil)
		// Owner hash before qname's hash; next-hash all-ones — qname
		// would fall inside (owner, next) IF the interval were live.
		ownerHash := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00}
		nextHash := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff}
		authority := newFakeNSEC3AuthorityWithBitmap(t,
			ownerHash, nextHash,
			0x01, /* opt-out flag set — RFC 5155 §6 */
			[]uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
		c.RegisterNSEC3Interval("example.com", 300, authority)

		// Any qname in the (owner, next) gap would normally synth NXDOMAIN.
		if _, ok := c.LookupNSEC3Covers("nonexistent.example.com", dns.ClassIN); ok {
			t.Errorf("opt-out NSEC3 used for NXDOMAIN synthesis — RFC 5155 §6 / RFC 8198 §6: opt-out has no authority over unsigned names in its gap; aggressive synth here would manufacture NXDOMAIN for names the zone never denied")
		}
	})

	t.Run("opt-out flag CLEAR → interval cached → NXDOMAIN synth fires", func(t *testing.T) {
		c := NewCache(1024, 60, 86400, 3600, nil)
		// Cover the entire hash space so any qname falls inside.
		ownerHash := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00}
		nextHash := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff}
		authority := newFakeNSEC3AuthorityWithBitmap(t,
			ownerHash, nextHash,
			0x00, /* opt-out CLEAR */
			[]uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
		c.RegisterNSEC3Interval("example.com", 300, authority)

		if _, ok := c.LookupNSEC3Covers("nonexistent.example.com", dns.ClassIN); !ok {
			t.Errorf("non-opt-out NSEC3 was not used for NXDOMAIN synthesis — regression broke the aggressive cache; the gate must apply ONLY when the opt-out flag is set")
		}
	})
}
