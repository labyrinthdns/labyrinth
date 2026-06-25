package dns

import "testing"

// TestPackRData_NamesNotCompressed pins RFC 3597 §4: domain names inside the
// RDATA of types NOT on the RFC 1035 §4.1.4 well-known list must be written
// uncompressed, because a conforming receiver does not decompress them and
// would read a pointer (0xC0…) as literal name bytes. RRSIG Signer's Name
// (RFC 4034 §3.1.7), NSEC Next Domain Name (RFC 4034 §4.1.3/§6.2), DNAME target
// (RFC 6672 §2.1) and SRV target (RFC 2782) all require this. The risk is real
// because compression is keyed case-insensitively (for 0x20), so the embedded
// name frequently matches an earlier owner.
//
// Each case seeds the compression dictionary with the embedded name (as if it
// were an earlier owner), then packs the RR and asserts the first byte of the
// embedded name in the RDATA is a label-length byte, not a 0xC0 pointer.
func TestPackRData_NamesNotCompressed(t *testing.T) {
	const shared = "apex.example.com"

	cases := []struct {
		name      string
		rr        ResourceRecord
		nameStart int // offset of the embedded name within RDATA (after rdlen)
	}{
		{
			name:      "DNAME target",
			rr:        ResourceRecord{Type: TypeDNAME, RData: encodePlainName(shared)},
			nameStart: 0,
		},
		{
			name:      "SRV target",
			rr:        ResourceRecord{Type: TypeSRV, RData: append([]byte{0, 10, 0, 5, 0x1f, 0x90}, encodePlainName(shared)...)},
			nameStart: 6,
		},
		{
			name:      "RRSIG signer",
			rr:        ResourceRecord{Type: TypeRRSIG, RData: append(append(make([]byte, 18), encodePlainName(shared)...), 0xAA, 0xBB)},
			nameStart: 18,
		},
		{
			name:      "NSEC next domain",
			rr:        ResourceRecord{Type: TypeNSEC, RData: append(encodePlainName(shared), 0x00, 0x01, 0x40)},
			nameStart: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWireWriter(make([]byte, 4096))
			// Seed the dictionary: write the shared name as an "owner" first, so
			// a compressing encoder would be tempted to point back to it.
			if err := EncodeName(w, shared); err != nil {
				t.Fatalf("seed EncodeName: %v", err)
			}

			rdStart := w.offset // where packRData writes the 2-byte RDLENGTH
			if err := packRData(w, tc.rr); err != nil {
				t.Fatalf("packRData: %v", err)
			}

			nameByte := w.buf[rdStart+2+tc.nameStart]
			if nameByte&0xC0 == 0xC0 {
				t.Errorf("%s: embedded name was compressed (first byte 0x%02x is a pointer); RFC 3597 §4 forbids this",
					tc.name, nameByte)
			}
			if int(nameByte) != len("apex") {
				t.Errorf("%s: expected first label-length byte %d, got 0x%02x", tc.name, len("apex"), nameByte)
			}
		})
	}
}
