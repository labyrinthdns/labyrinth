package dnssec

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestSEPBit_DoesNotGateValidation pins RFC 4034 §2.1.2: the SEP
// (Secure Entry Point) flag, bit 15 of DNSKEY Flags (value 0x0001),
// is ADVISORY — it tells operators which keys to publish DS records
// for, but it does NOT gate validation. A DNSKEY with SEP=0 (a ZSK,
// flag=256) MUST be usable to validate signatures over zone data
// just like a DNSKEY with SEP=1 (a KSK, flag=257).
//
// Why pin this: a well-intentioned hardening that "only KSKs can
// validate" would silently break every zone that follows the
// recommended KSK/ZSK split. KSKs typically sign only the DNSKEY
// RRset; the bulk of zone data (A, MX, NS, etc.) is signed by ZSKs.
// Rejecting ZSK signatures would force every signed zone to come
// back Bogus despite the cryptography being correct.
//
// We pin: findMatchingDNSKEY returns BOTH a KSK (flag=257, SEP set)
// AND a ZSK (flag=256, SEP clear) when each is independently looked
// up by its key_tag + algorithm. RFC 4034 §2.1.1 Zone Key bit
// (value 0x0100) IS gating — both fixtures have it set; the test
// targets the SEP bit specifically.
func TestSEPBit_DoesNotGateValidation(t *testing.T) {
	mkDNSKEY := func(flags uint16, pubKey []byte) (dns.ResourceRecord, uint16) {
		rdata := make([]byte, 4+len(pubKey))
		binary.BigEndian.PutUint16(rdata[0:2], flags)
		rdata[2] = 3 // Protocol
		rdata[3] = dns.AlgRSASHA256
		copy(rdata[4:], pubKey)
		parsed, _ := dns.ParseDNSKEY(rdata)
		return dns.ResourceRecord{
			Name: "example.com", Type: dns.TypeDNSKEY, Class: dns.ClassIN,
			TTL: 3600, RDLength: uint16(len(rdata)), RData: rdata,
		}, parsed.KeyTag()
	}

	// 256 = ZONE bit only (ZSK — SEP=0).
	// 257 = ZONE bit + SEP bit (KSK).
	ksk, kskTag := mkDNSKEY(257, []byte{0x01, 0x02, 0x03, 0x04})
	zsk, zskTag := mkDNSKEY(256, []byte{0xAA, 0xBB, 0xCC, 0xDD})
	dnskeys := []dns.ResourceRecord{ksk, zsk}

	t.Run("KSK (SEP=1) findable", func(t *testing.T) {
		got, err := findMatchingDNSKEY(dnskeys, kskTag, dns.AlgRSASHA256)
		if err != nil {
			t.Fatalf("KSK lookup failed: %v", err)
		}
		if !got.IsKSK() {
			t.Errorf("returned key SEP bit clear, want set")
		}
	})

	t.Run("ZSK (SEP=0) findable — RFC 4034 §2.1.2 advisory", func(t *testing.T) {
		got, err := findMatchingDNSKEY(dnskeys, zskTag, dns.AlgRSASHA256)
		if err != nil {
			t.Fatalf("ZSK lookup failed: %v — a regression that gated validation on SEP=1 would break every RFC-recommended KSK/ZSK zone, since ZSK signs the bulk of zone data", err)
		}
		if got.IsKSK() {
			t.Errorf("returned key SEP bit set on ZSK lookup — wrong key returned")
		}
		// The structural assertion: the returned DNSKEY parses with
		// IsZoneKey() == true (RFC 4034 §2.1.1 — required) AND
		// IsKSK() == false (RFC 4034 §2.1.2 SEP — not required).
		if !got.IsZoneKey() {
			t.Errorf("ZSK returned without Zone Key bit set — RFC 4034 §2.1.1 violation; this fixture was built with flag=256 which IS Zone Key")
		}
	})
}
