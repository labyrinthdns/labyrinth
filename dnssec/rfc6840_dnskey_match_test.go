package dnssec

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestFindMatchingDNSKEY_RequiresAlgAndKeyTag pins RFC 6840 §5.4 /
// RFC 4034 §3.1.6: the DNSKEY that verifies an RRSIG must match BOTH
// the RRSIG's key_tag AND its algorithm. A regression that dropped
// the algorithm check would let an attacker who finds a key_tag
// collision (the tag is only 16 bits — birthday-paradox collisions
// at ~2^8 keys) substitute a DNSKEY of a DIFFERENT (potentially
// weaker or unsupported) algorithm. The attacker's substituted key
// would never decrypt the real signature, but they could combine
// this with a same-tag-different-algorithm RRSIG of their own choice
// — bypassing the algorithm strength expectation of the zone's
// publisher.
//
// We pin a four-case truth table:
//
//  1. Matching tag + matching algorithm → returns the key.
//  2. Matching tag, DIFFERENT algorithm → "no DNSKEY" error.
//  3. Matching algorithm, DIFFERENT tag → "no DNSKEY" error.
//  4. Revoked DNSKEY (flag 0x0080 set, RFC 5011 §2) even with matching
//     tag+algorithm → skipped, "no DNSKEY" error.
//
// All four behaviours must hold simultaneously for the validator to
// be safe against the algorithm-substitution and revocation-flag
// attacks. A regression in any of them is silent in normal operation
// — only an active attacker probes for these conditions.
func TestFindMatchingDNSKEY_RequiresAlgAndKeyTag(t *testing.T) {
	// Build a DNSKEY with deterministic key tag. Use a tiny key
	// (4-byte PublicKey) so we can compute the tag and reproduce it
	// here without external tooling.
	mkDNSKEY := func(flags uint16, alg uint8, pubKey []byte) (dns.ResourceRecord, uint16) {
		rdata := make([]byte, 4+len(pubKey))
		binary.BigEndian.PutUint16(rdata[0:2], flags)
		rdata[2] = 3 // Protocol = 3 always
		rdata[3] = alg
		copy(rdata[4:], pubKey)
		parsed, _ := dns.ParseDNSKEY(rdata)
		tag := parsed.KeyTag()
		return dns.ResourceRecord{
			Name: "example.com", Type: dns.TypeDNSKEY, Class: dns.ClassIN,
			TTL: 3600, RDLength: uint16(len(rdata)), RData: rdata,
		}, tag
	}

	pubKeyA := []byte{0x01, 0x02, 0x03, 0x04}
	dnskeyZSK, tagZSK := mkDNSKEY(256 /* zone key, not SEP */, dns.AlgRSASHA256, pubKeyA)

	// A different DNSKEY with same algorithm but DIFFERENT key.
	dnskeyOther, _ := mkDNSKEY(256, dns.AlgRSASHA256, []byte{0xFF, 0xEE, 0xDD, 0xCC})

	dnskeys := []dns.ResourceRecord{dnskeyZSK, dnskeyOther}

	t.Run("matching tag + matching algorithm → found", func(t *testing.T) {
		got, err := findMatchingDNSKEY(dnskeys, tagZSK, dns.AlgRSASHA256)
		if err != nil {
			t.Fatalf("expected match, got error: %v", err)
		}
		if got.KeyTag() != tagZSK {
			t.Errorf("returned key has tag %d, want %d", got.KeyTag(), tagZSK)
		}
	})

	t.Run("matching tag, DIFFERENT algorithm → rejected", func(t *testing.T) {
		_, err := findMatchingDNSKEY(dnskeys, tagZSK, dns.AlgECDSAP256)
		if err == nil {
			t.Error("RFC 6840 §5.4 violation: a DNSKEY with the right tag but WRONG algorithm was accepted — algorithm substitution attack surface")
		}
	})

	t.Run("matching algorithm, DIFFERENT tag → rejected", func(t *testing.T) {
		_, err := findMatchingDNSKEY(dnskeys, tagZSK+9999, dns.AlgRSASHA256)
		if err == nil {
			t.Error("findMatchingDNSKEY ignored key_tag — every RRSIG would now bind to the first DNSKEY of the right algorithm regardless of which key actually signed it")
		}
	})

	t.Run("revoked DNSKEY (RFC 5011 §2 flag 0x0080) → skipped", func(t *testing.T) {
		// Flag 0x0080 = REVOKE bit per RFC 5011. A revoked key MUST
		// be skipped even if everything else matches.
		// 256 (ZONE) | 0x0080 (REVOKE) = 384.
		revoked, revTag := mkDNSKEY(384, dns.AlgRSASHA256, pubKeyA)
		_, err := findMatchingDNSKEY([]dns.ResourceRecord{revoked}, revTag, dns.AlgRSASHA256)
		if err == nil {
			t.Error("revoked DNSKEY (REVOKE bit set) was accepted — RFC 5011 §2 requires revoked keys to be ignored for validation; an attacker who stole an old key could keep using it past revocation")
		}
	})
}
