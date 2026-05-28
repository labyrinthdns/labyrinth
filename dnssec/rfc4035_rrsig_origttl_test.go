package dnssec

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestCanonicalRRSetWire_UsesRRSIGOrigTTL pins RFC 4035 §5.3.2 /
// §5.3.3: when building the canonical RRset wire form for RRSIG
// verification, the RRset header TTL field MUST come from the
// RRSIG's `OrigTTL` field, NOT from the RR's `TTL` field. The
// distinction matters because:
//
//   - The RR's TTL decays over its lifetime as it propagates through
//     caches (resolvers count down toward zero).
//   - The OrigTTL embedded in the RRSIG is the FIXED original TTL
//     the auth server signed.
//
// If verification used the decayed RR.TTL, every cached RRset would
// fail signature verification a second after the auth handed it
// out — every signed zone would come back Bogus, every time.
// Conversely, an attacker could not poison the cache by replaying
// an old RRset with a tampered TTL: the signature is bound to
// OrigTTL, not the live TTL.
//
// The pin builds an RRset where rr.TTL=10 (decayed) but
// rrsig.OrigTTL=3600 (signed value), runs it through the canonical
// wire builder, and asserts the TTL bytes at the canonical header
// position equal 3600. A regression that grabbed rr.TTL would
// produce 10 there and the bytes would differ.
func TestCanonicalRRSetWire_UsesRRSIGOrigTTL(t *testing.T) {
	const decayedTTL = uint32(10)
	const signedOrigTTL = uint32(3600)

	rrset := []dns.ResourceRecord{{
		Name:     "example.com",
		Type:     dns.TypeA,
		Class:    dns.ClassIN,
		TTL:      decayedTTL, // cache decayed this — must not bleed into canonical form
		RDLength: 4,
		RData:    []byte{192, 0, 2, 1},
	}}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgRSASHA256,
		Labels:      2,
		OrigTTL:     signedOrigTTL, // what the auth signed — must be used
		Expiration:  0x60000000,
		Inception:   0x50000000,
		KeyTag:      12345,
		SignerName:  "example.com",
	}

	wire := canonicalRRSetWire(rrset, rrsig)

	// The canonical RR layout is:
	//   owner-wire (variable length, lowercase-encoded)
	//   type (2)
	//   class (2)
	//   ttl (4)             ← MUST be signedOrigTTL
	//   rdlength (2)
	//   rdata
	//
	// Find the TTL bytes by parsing through the owner name. The
	// owner "example.com" encodes as [7] "example" [3] "com" [0]
	// = 13 bytes.
	const ownerWireLen = 13
	const ttlOffset = ownerWireLen + 2 + 2 // skip type + class
	if len(wire) < ttlOffset+4 {
		t.Fatalf("canonical wire too short to contain TTL field: len=%d", len(wire))
	}
	got := binary.BigEndian.Uint32(wire[ttlOffset : ttlOffset+4])
	if got != signedOrigTTL {
		t.Errorf("canonical TTL = %d, want %d — RFC 4035 §5.3.2 violation: a regression that used rr.TTL (%d) would Bogus every cached signed RRset within seconds of insertion",
			got, signedOrigTTL, decayedTTL)
	}
	if got == decayedTTL {
		t.Errorf("canonical TTL leaked the decayed rr.TTL into the signature input — every cache decay would invalidate the signature")
	}
}
