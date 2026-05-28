package dnssec

import (
	"bytes"
	"testing"
	"testing/quick"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestCanonicalRData_IsIdempotent — property-based pin for RFC 4034
// §6.2 canonical RDATA: applying canonicalRData TWICE must produce
// the same output as applying it once. Idempotence is the load-
// bearing invariant of any canonicaliser — if it's not idempotent,
// the canonical form depends on call count rather than input alone,
// and downstream signature verification becomes order-dependent.
//
// testing/quick.Check generates random RDATA bytes and a random type
// drawn from the set canonicalRData actually handles. A regression
// that introduced an asymmetric transformation (e.g. only lowercasing
// on the FIRST byte, or off-by-one in the embedded-name length-walk)
// would surface here as a counterexample.
func TestCanonicalRData_IsIdempotent(t *testing.T) {
	property := func(rdata []byte, rtype uint8) bool {
		// Pick a type the canonicaliser handles. The canonical-RDATA
		// transform only touches RR types with embedded names; for
		// pure-binary types it's a no-op which is still a valid
		// idempotent transform.
		types := []uint16{
			dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeCNAME,
			dns.TypePTR, dns.TypeMX, dns.TypeSOA, dns.TypeTXT,
			dns.TypeDNAME, dns.TypeRRSIG, dns.TypeSRV, dns.TypeNSEC,
		}
		ty := types[int(rtype)%len(types)]
		once := canonicalRData(rdata, ty)
		twice := canonicalRData(once, ty)
		// Idempotence: f(f(x)) == f(x). If not, the transform is
		// order-dependent and signatures will go nondeterministic.
		return bytes.Equal(once, twice)
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 200}); err != nil {
		t.Errorf("canonicalRData is NOT idempotent — found counterexample: %v", err)
	}
}

// TestCanonicalRData_PreservesLength — property: the canonical form
// of any RDATA is the same byte length as the input. The transforms
// canonicalRData performs (lowercasing embedded names) NEVER change
// length: ASCII lowercasing is a 1:1 byte substitution, and the
// length-prefixed name encoding doesn't move bytes around. A
// regression that re-encoded names (e.g. decompressing pointers, or
// inserting a trailing dot byte) would change the length and break
// the RRSIG length-field arithmetic on the signing-side too.
//
// Note: lowercaseWireName falls back to returning the original rdata
// when the wire-format name is malformed, so length is preserved on
// both the happy path AND the parser-rejection path.
func TestCanonicalRData_PreservesLength(t *testing.T) {
	property := func(rdata []byte) bool {
		// Test against the RR types that DO get canonicalised.
		types := []uint16{
			dns.TypeNS, dns.TypeCNAME, dns.TypeMX, dns.TypePTR,
			dns.TypeSOA, dns.TypeDNAME, dns.TypeRRSIG, dns.TypeSRV,
			dns.TypeNSEC,
		}
		for _, ty := range types {
			out := canonicalRData(rdata, ty)
			if len(out) != len(rdata) {
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 200}); err != nil {
		t.Errorf("canonicalRData changed RDATA length — broken RFC 4034 §6.2 invariant: %v", err)
	}
}
