package dns

import (
	"encoding/binary"
	"testing"
)

// TestDNSKEYKeyTag_FixtureValues pins RFC 4034 Appendix B.1 key-tag
// computation against INDEPENDENTLY-computed fixtures. The pre-existing
// TestDNSKEYKeyTag computes its expected value with the same algorithm
// as the code under test — a tautology that would still pass if both
// the code and the test were broken in the same way. This pin uses
// values computed step-by-step from RFC 4034 Appendix B.1 reference
// pseudocode and locked in as constants. A regression in the
// bit-twiddling (off-by-one in the high-low byte split, missing the
// `ac += ac >> 16` fold-back, wrong final mask) is caught immediately.
//
// Key tag drives delegation-chain validation: the validator finds
// "the DNSKEY in the zone whose KeyTag() matches the RRSIG's KeyTag
// field." Wrong tag math means the validator looks for the wrong
// DNSKEY and every signed response in the zone fails verification
// despite the cryptography being intact.
func TestDNSKEYKeyTag_FixtureValues(t *testing.T) {
	cases := []struct {
		name    string
		flags   uint16
		proto   uint8
		alg     uint8
		pubKey  []byte
		wantTag uint16
	}{
		{
			name:   "all-zero key — only header bytes contribute",
			flags:  0, proto: 0, alg: 0,
			pubKey:  []byte{},
			wantTag: 0,
		},
		{
			// Step-by-step from RFC 4034 App B.1:
			// wire = [0x01, 0x01, 0x03, 0x08, 0x01, 0x02, 0x03, 0x04]
			// Even bytes (i=0,2,4,6): 0x01<<8 + 0x03<<8 + 0x01<<8 + 0x03<<8 = (1+3+1+3)*256 = 2048
			// Odd bytes  (i=1,3,5,7): 0x01     + 0x08     + 0x02     + 0x04     = 15
			// ac = 2063
			// ac >> 16 = 0
			// ac & 0xFFFF = 2063
			name:   "KSK alg=8 PublicKey=[01,02,03,04] → 2063 (manual)",
			flags:  257, proto: 3, alg: 8,
			pubKey:  []byte{0x01, 0x02, 0x03, 0x04},
			wantTag: 2063,
		},
		{
			// Force a fold-back (ac >> 16 > 0). Step-by-step:
			// wire = [0x01, 0x01, 0x03, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
			// Even bytes (i=0,2,4,6,8,10) high-half:
			//   0x0100 + 0x0300 + 0xFF00 + 0xFF00 + 0xFF00 + 0xFF00
			//   = 256 + 768 + 65280×4 = 1024 + 261120 = 262144 = 0x40000
			// Odd bytes (i=1,3,5,7,9,11) low-half:
			//   1 + 8 + 255 + 255 + 255 + 255 = 1029 = 0x405
			// ac = 262144 + 1029 = 263173 = 0x40405
			// ac >> 16 = 4
			// ac += 4 = 263177 = 0x40409
			// ac & 0xFFFF = 0x0409 = 1033
			name:   "fold-back forces overflow handling",
			flags:  257, proto: 3, alg: 8,
			pubKey:  []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			wantTag: 1033,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &DNSKEYRecord{
				Flags:     c.flags,
				Protocol:  c.proto,
				Algorithm: c.alg,
				PublicKey: c.pubKey,
			}
			got := rec.KeyTag()
			if got != c.wantTag {
				t.Errorf("KeyTag = %d, want %d — RFC 4034 App B.1 bit-twiddle regression", got, c.wantTag)
			}
		})
	}
}

// TestDNSKEYKeyTag_StableAcrossParseRoundtrip pins that the KeyTag
// value is identical whether computed from a struct-built DNSKEY or
// from one parsed from on-wire RDATA bytes. A regression in the wire
// parser that flipped Flags byte order would silently shift every
// key tag and orphan every RRSIG in the zone (RRSIGs reference the
// tag the AUTH server computed, which is on-wire).
func TestDNSKEYKeyTag_StableAcrossParseRoundtrip(t *testing.T) {
	pubKey := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

	// Build via struct.
	direct := &DNSKEYRecord{
		Flags: 257, Protocol: 3, Algorithm: 8,
		PublicKey: pubKey,
	}
	tagDirect := direct.KeyTag()

	// Build via RDATA and parse.
	rdata := make([]byte, 4+len(pubKey))
	binary.BigEndian.PutUint16(rdata[0:2], 257)
	rdata[2] = 3
	rdata[3] = 8
	copy(rdata[4:], pubKey)
	parsed, err := ParseDNSKEY(rdata)
	if err != nil {
		t.Fatalf("ParseDNSKEY: %v", err)
	}
	tagParsed := parsed.KeyTag()

	if tagDirect != tagParsed {
		t.Errorf("KeyTag differs across struct/parse build: direct=%d parsed=%d — wire format and struct must agree on byte order", tagDirect, tagParsed)
	}
}
