package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestVerifyRRSIG_RejectsDNSKEYWithoutZoneBit pins Y53: RFC 4034 §2.1.1
// makes the Zone Key flag (bit 7, value 0x0100) a structural requirement
// for any DNSKEY used to verify RRSIGs over RRsets:
//
//   "If bit 7 has value 0, then the DNSKEY record holds some other type
//    of DNS public key and MUST NOT be used to verify RRSIGs that cover
//    RRsets."
//
// Real-world threat model: a host's SIG(0) public key shares the DNSKEY
// resource-record encoding but has Zone Key bit clear. A validator that
// ignored the bit could be tricked into accepting forged zone signatures
// from any party that controls a SIG(0) key — the parent zone's DS
// would still cover that key's tag, and the chain would appear intact.
//
// The gate is intentionally cheap (single bit test) and runs BEFORE any
// algorithm switch, so an attacker can't sidestep it by picking an
// unusual algorithm.
func TestVerifyRRSIG_RejectsDNSKEYWithoutZoneBit(t *testing.T) {
	// SEP-only KSK shape (Flags=0x0001) — has the SEP bit but NOT the
	// Zone Key bit. This represents the malicious case the RFC §2.1.1
	// rule defends against.
	nonZoneKey := &dns.DNSKEYRecord{
		Flags:     0x0001, // SEP set, Zone Key (0x0100) clear
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03}, // shape only — crypto never runs
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgRSASHA256,
		Labels:      2,
		OrigTTL:     300,
		SignerName:  "example.com",
		Signature:   []byte{0x42}, // non-empty to skip the empty-sig guard
	}
	rrset := []dns.ResourceRecord{{Name: "example.com", Type: dns.TypeA}}

	err := VerifyRRSIG(rrset, rrsig, nonZoneKey)
	if err == nil {
		t.Fatalf("VerifyRRSIG accepted DNSKEY with Zone Key bit clear (RFC 4034 §2.1.1 violation)")
	}
	if err != errZoneKeyBitClear {
		t.Errorf("err = %v, want errZoneKeyBitClear (so the failure reason is clearly RFC §2.1.1 and not generic crypto failure)", err)
	}
}

// TestVerifyRRSIG_AcceptsZoneKeyButFailsCrypto pins the inverse: a key
// WITH Zone Key bit set is allowed past the structural gate, even if the
// subsequent crypto verification fails. Without this pin a future
// refactor that tightened the gate to require both ZONE AND SEP (KSK
// only) would silently break ZSK-only validation (the common case).
func TestVerifyRRSIG_AcceptsZoneKeyButFailsCrypto(t *testing.T) {
	// ZSK: Zone Key bit set, SEP clear (Flags=0x0100 = 256).
	zsk := &dns.DNSKEYRecord{
		Flags:     0x0100,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03}, // bogus — crypto will fail
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgRSASHA256,
		Labels:      2,
		OrigTTL:     300,
		SignerName:  "example.com",
		Signature:   []byte{0x42},
	}
	rrset := []dns.ResourceRecord{{Name: "example.com", Type: dns.TypeA}}

	err := VerifyRRSIG(rrset, rrsig, zsk)
	if err == nil {
		t.Errorf("expected crypto failure on bogus key material, got nil — gate is letting through too much")
	}
	if err == errZoneKeyBitClear {
		t.Errorf("ZSK rejected as non-zone-key — the gate is wrongly excluding valid ZSKs")
	}
}

// TestDNSKEYRecord_IsZoneKey pins the helper's truth table so a refactor
// of the bit constant cannot silently invert the predicate.
func TestDNSKEYRecord_IsZoneKey(t *testing.T) {
	for _, c := range []struct {
		flags uint16
		want  bool
	}{
		{0x0000, false},                // bare key, no flags
		{0x0001, false},                // SEP only — host key shape
		{0x0080, false},                // REVOKE only
		{0x0100, true},                 // ZONE only (canonical ZSK)
		{0x0101, true},                 // ZONE + SEP (canonical KSK)
		{0x0181, true},                 // ZONE + REVOKE + SEP (revoked KSK)
	} {
		k := &dns.DNSKEYRecord{Flags: c.flags}
		if got := k.IsZoneKey(); got != c.want {
			t.Errorf("Flags=0x%04x IsZoneKey()=%v, want %v", c.flags, got, c.want)
		}
	}
}
