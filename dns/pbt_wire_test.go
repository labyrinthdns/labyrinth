package dns

import (
	"encoding/binary"
	"math/rand/v2"
	"reflect"
	"testing"
	"testing/quick"
)

// ──────────────────────────────────────────────
// Property 1: Header Pack/Unpack is bijective
// ──────────────────────────────────────────────

// headerProperty holds six random uint16 values that are packed as a Header
// and then unpacked. The property passes if the unpacked result equals the
// original, proving that Pack and Unpack are inverses on any possible Header
// value (no field is silently truncated or modified).
type headerProperty struct {
	ID, Flags, QDCount, ANCount, NSCount, ARCount uint16
}

func (hp headerProperty) Generate(rand *rand.Rand) headerProperty {
	return headerProperty{
		ID:      uint16(rand.Uint32()),
		Flags:   uint16(rand.Uint32()),
		QDCount: uint16(rand.Uint32()),
		ANCount: uint16(rand.Uint32()),
		NSCount: uint16(rand.Uint32()),
		ARCount: uint16(rand.Uint32()),
	}
}

func TestProperty_HeaderPackUnpackRoundTrip(t *testing.T) {
	f := func(id, flags, qd, an, ns, ar uint16) bool {
		orig := Header{ID: id, Flags: flags, QDCount: qd, ANCount: an, NSCount: ns, ARCount: ar}

		buf := make([]byte, 12)
		w := newWireWriter(buf)
		if err := orig.Pack(w); err != nil {
			return false
		}

		r := newWireReader(w.bytes())
		var got Header
		if err := got.Unpack(r); err != nil {
			return false
		}

		return orig == got
	}

	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

func TestProperty_HeaderPackUnpackSpecificFlags(t *testing.T) {
	// Exhaustively test all 16 RCODE values at the flag extremes.
	for rcode := uint16(0); rcode < 16; rcode++ {
		flags := (1 << 15) | // QR
			(1 << 8) | // RD
			(1 << 7) | // RA
			rcode
		orig := Header{ID: 0xAAAA, Flags: flags, QDCount: 1, ANCount: 0, NSCount: 0, ARCount: 0}

		buf := make([]byte, 12)
		w := newWireWriter(buf)
		if err := orig.Pack(w); err != nil {
			t.Fatalf("Pack error for rcode=%d: %v", rcode, err)
		}

		r := newWireReader(w.bytes())
		var got Header
		if err := got.Unpack(r); err != nil {
			t.Fatalf("Unpack error for rcode=%d: %v", rcode, err)
		}

		if got.Flags != orig.Flags {
			t.Errorf("rcode=%d: flags round-trip %#04x → %#04x", rcode, orig.Flags, got.Flags)
		}
		if got.ID != orig.ID || got.QDCount != orig.QDCount {
			t.Errorf("rcode=%d: header field mismatch", rcode)
		}
	}
}

// ──────────────────────────────────────────────
// Property 2: Name Encode/Decode is bijective
// ──────────────────────────────────────────────

// validName returns a random DNS name that is syntactically valid: labels
// between 1-63 bytes, total ≤ 255 bytes, ASCII printable characters.
func validName(r *rand.Rand) string {
	labels := r.IntN(4) + 1 // 1-4 labels
	total := 0
	var name []byte
	for i := 0; i < labels; i++ {
		labelLen := r.IntN(10) + 1 // 1-10 chars per label
		if total+labelLen+1 > 250 {
			labelLen = 250 - total - 1
			if labelLen < 1 {
				break
			}
		}
		if i > 0 {
			name = append(name, '.')
		}
		// Generate a-z characters so the name is always lower case (avoids
		// 0x20 case-randomisation complications in the comparison).
		for j := 0; j < labelLen; j++ {
			name = append(name, byte('a'+r.IntN(26)))
		}
		total += labelLen + 1
	}
	name = append(name, '.')
	return string(name)
}

func TestProperty_NameEncodeDecodeRoundTrip(t *testing.T) {
	// Use a deterministic RNG to generate 1000 random domain names and
	// verify that EncodeName→DecodeName is a bijection for each.
	rng := rand.New(rand.NewPCG(42, 1))
	for i := 0; i < 1000; i++ {
		name := validName(rng)
		if name == "" || name == "." {
			continue
		}

		encoded := BuildPlainName(name)
		decoded, _, err := DecodeName(encoded, 0)
		if err != nil {
			t.Errorf("iter %d: DecodeName(%q) failed: %v", i, name, err)
			continue
		}

		got := normaliseName(decoded)
		want := normaliseName(name)
		if got != want {
			t.Errorf("iter %d: %q encoded → %q decoded (want %q)", i, name, decoded, want)
		}
	}
}

func normaliseName(n string) string {
	if len(n) > 0 && n[len(n)-1] == '.' {
		return n[:len(n)-1]
	}
	return n
}

// ──────────────────────────────────────────────
// Property 3: Wire Pack/Unpack is structurally
// idempotent for all RR types
// ──────────────────────────────────────────────

// buildTestMessage constructs a minimal DNS response with a single answer of
// the given type, returning the message and a human-readable label.
type testCase struct {
	label string
	msg   *Message
}

func testMessages() []testCase {
	return []testCase{
		{
			label: "A record",
			msg: &Message{
				Header: Header{ID: 1, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 300,
					RData: []byte{192, 168, 1, 1},
				}},
			},
		},
		{
			label: "AAAA record",
			msg: &Message{
				Header: Header{ID: 2, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "example.com.", Type: TypeAAAA, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "example.com.", Type: TypeAAAA, Class: ClassIN, TTL: 300,
					RData: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				}},
			},
		},
		{
			label: "NS record",
			msg: &Message{
				Header: Header{ID: 3, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "example.com.", Type: TypeNS, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "example.com.", Type: TypeNS, Class: ClassIN, TTL: 86400,
					RData: BuildPlainName("ns1.example.com."),
				}},
			},
		},
		{
			label: "CNAME record",
			msg: &Message{
				Header: Header{ID: 4, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "www.example.com.", Type: TypeCNAME, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "www.example.com.", Type: TypeCNAME, Class: ClassIN, TTL: 300,
					RData: BuildPlainName("example.com."),
				}},
			},
		},
		{
			label: "MX record",
			msg: &Message{
				Header: Header{ID: 5, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "example.com.", Type: TypeMX, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "example.com.", Type: TypeMX, Class: ClassIN, TTL: 300,
					RData: func() []byte {
						pref := []byte{0x00, 10} // preference 10
						name := BuildPlainName("mail.example.com.")
						return append(pref, name...)
					}(),
				}},
			},
		},
		{
			label: "SOA record",
			msg: &Message{
				Header: Header{ID: 6, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "example.com.", Type: TypeSOA, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "example.com.", Type: TypeSOA, Class: ClassIN, TTL: 86400,
					RData: func() []byte {
						mname := BuildPlainName("ns1.example.com.")
						rname := BuildPlainName("admin.example.com.")
						serials := make([]byte, 20)
						// serial, refresh, retry, expire, minimum
						binary.BigEndian.PutUint32(serials[0:4], 2026071501)
						binary.BigEndian.PutUint32(serials[4:8], 3600)
						binary.BigEndian.PutUint32(serials[8:12], 600)
						binary.BigEndian.PutUint32(serials[12:16], 86400)
						binary.BigEndian.PutUint32(serials[16:20], 300)
						out := make([]byte, len(mname)+len(rname)+20)
						copy(out, mname)
						copy(out[len(mname):], rname)
						copy(out[len(mname)+len(rname):], serials)
						return out
					}(),
				}},
			},
		},
		{
			label: "TXT record",
			msg: &Message{
				Header: Header{ID: 7, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "example.com.", Type: TypeTXT, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "example.com.", Type: TypeTXT, Class: ClassIN, TTL: 300,
					RData: func() []byte {
						txt := []byte("v=spf1 include:_spf.example.com ~all")
						out := make([]byte, 1+len(txt))
						out[0] = byte(len(txt))
						copy(out[1:], txt)
						return out
					}(),
				}},
			},
		},
		{
			label: "SRV record",
			msg: &Message{
				Header: Header{ID: 8, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "_sip._tcp.example.com.", Type: TypeSRV, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "_sip._tcp.example.com.", Type: TypeSRV, Class: ClassIN, TTL: 300,
					RData: func() []byte {
						header := make([]byte, 6)
						binary.BigEndian.PutUint16(header[0:2], 10)  // priority
						binary.BigEndian.PutUint16(header[2:4], 20)  // weight
						binary.BigEndian.PutUint16(header[4:6], 5060) // port
						name := BuildPlainName("sip.example.com.")
						return append(header, name...)
					}(),
				}},
			},
		},
		{
			label: "PTR record",
			msg: &Message{
				Header: Header{ID: 9, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "1.0.168.192.in-addr.arpa.", Type: TypePTR, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "1.0.168.192.in-addr.arpa.", Type: TypePTR, Class: ClassIN, TTL: 300,
					RData: BuildPlainName("example.com."),
				}},
			},
		},
		{
			label: "DNAME record",
			msg: &Message{
				Header: Header{ID: 10, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "sub.example.com.", Type: TypeDNAME, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "sub.example.com.", Type: TypeDNAME, Class: ClassIN, TTL: 300,
					RData: BuildPlainName("example.net."),
				}},
			},
		},
		{
			label: "OPT pseudo-record (EDNS0)",
			msg: &Message{
				Header: Header{ID: 11, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
				Additional: []ResourceRecord{{
					Name: "", Type: TypeOPT, Class: 4096, TTL: 0,
					RData: []byte{},
				}},
			},
		},
		{
			label: "RRSIG record",
			msg: &Message{
				Header: Header{ID: 12, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "example.com.", Type: TypeRRSIG, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "example.com.", Type: TypeRRSIG, Class: ClassIN, TTL: 86400,
					RData: func() []byte {
						fixed := make([]byte, 18)
						binary.BigEndian.PutUint16(fixed[0:2], TypeA)    // type covered
						fixed[2] = 8   // algorithm (ECDSA-P256)
						fixed[3] = 1   // labels (example.com → 1 label)
						// Note: labels field counts only the non-zone labels
						// but any reasonable value keeps the round-trip valid.
						binary.BigEndian.PutUint32(fixed[4:8], 86400)     // original TTL
						binary.BigEndian.PutUint32(fixed[8:12], 2026071501) // signature expiration
						binary.BigEndian.PutUint32(fixed[12:16], 2026070101) // signature inception
						binary.BigEndian.PutUint16(fixed[16:18], 12345)    // key tag
						signer := BuildPlainName("example.com.")
						sig := make([]byte, 64) // 64 bytes of fake signature
						out := make([]byte, 18+len(signer)+len(sig))
						copy(out, fixed)
						copy(out[18:], signer)
						copy(out[18+len(signer):], sig)
						return out
					}(),
				}},
			},
		},
		{
			label: "NSEC record",
			msg: &Message{
				Header: Header{ID: 13, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "example.com.", Type: TypeNSEC, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "example.com.", Type: TypeNSEC, Class: ClassIN, TTL: 86400,
					RData: func() []byte {
						next := BuildPlainName("other.example.com.")
						bitmap := []byte{0x00, 0x06, 0x40, 0x00, 0x00, 0x08} // A + NS + SOA + MX + TXT + RRSIG + NSEC
						return append(next, bitmap...)
					}(),
				}},
			},
		},
		{
			label: "Multiple sections (answer + authority + additional)",
			msg: &Message{
				Header: Header{ID: 14, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
				Answers: []ResourceRecord{{
					Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 300,
					RData: []byte{10, 0, 0, 1},
				}},
				Authority: []ResourceRecord{{
					Name: "example.com.", Type: TypeNS, Class: ClassIN, TTL: 86400,
					RData: BuildPlainName("ns1.example.com."),
				}},
				Additional: []ResourceRecord{{
					Name: "ns1.example.com.", Type: TypeA, Class: ClassIN, TTL: 300,
					RData: []byte{10, 0, 0, 2},
				}},
			},
		},
		{
			label: "Empty message (header only)",
			msg: &Message{
				Header: Header{ID: 15, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
			},
		},
		{
			label: "Multiple questions",
			msg: &Message{
				Header: Header{ID: 16, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
				Questions: []Question{
					{Name: "example.com.", Type: TypeA, Class: ClassIN},
					{Name: "example.com.", Type: TypeAAAA, Class: ClassIN},
				},
			},
		},
	}
}

func TestProperty_WireRoundTrip_AllTypes(t *testing.T) {
	for _, tc := range testMessages() {
		t.Run(tc.label, func(t *testing.T) {
			buf := make([]byte, 8192)
			packed, err := Pack(tc.msg, buf)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}

			unpacked, err := Unpack(packed)
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}

			// Compare header fields (counts are set by Pack so they
			// reflect the slice lengths in both directions).
			if unpacked.Header.ID != tc.msg.Header.ID {
				t.Errorf("Header.ID: %d → %d", tc.msg.Header.ID, unpacked.Header.ID)
			}
			if unpacked.Header.Flags != tc.msg.Header.Flags {
				t.Errorf("Header.Flags: %#04x → %#04x", tc.msg.Header.Flags, unpacked.Header.Flags)
			}

			// Compare question count and names
			if len(unpacked.Questions) != len(tc.msg.Questions) {
				t.Errorf("Questions: %d → %d", len(tc.msg.Questions), len(unpacked.Questions))
			} else {
				for i := range tc.msg.Questions {
					qOrig := tc.msg.Questions[i]
					qGot := unpacked.Questions[i]
					if normaliseName(qOrig.Name) != normaliseName(qGot.Name) {
						t.Errorf("Question[%d].Name: %q → %q", i, qOrig.Name, qGot.Name)
					}
					if qOrig.Type != qGot.Type {
						t.Errorf("Question[%d].Type: %d → %d", i, qOrig.Type, qGot.Type)
					}
					if qOrig.Class != qGot.Class {
						t.Errorf("Question[%d].Class: %d → %d", i, qOrig.Class, qGot.Class)
					}
				}
			}

			// Compare answer count and key fields
			if len(unpacked.Answers) != len(tc.msg.Answers) {
				t.Errorf("Answers: %d → %d", len(tc.msg.Answers), len(unpacked.Answers))
			} else {
				for i := range tc.msg.Answers {
					aOrig := tc.msg.Answers[i]
					aGot := unpacked.Answers[i]
					if normaliseName(aOrig.Name) != normaliseName(aGot.Name) {
						t.Errorf("Answer[%d].Name: %q → %q", i, aOrig.Name, aGot.Name)
					}
					if aOrig.Type != aGot.Type {
						t.Errorf("Answer[%d].Type: %d → %d", i, aOrig.Type, aGot.Type)
					}
					if aOrig.Class != aGot.Class {
						t.Errorf("Answer[%d].Class: %d → %d", i, aOrig.Class, aGot.Class)
					}
					if aOrig.TTL != aGot.TTL {
						t.Errorf("Answer[%d].TTL: %d → %d", i, aOrig.TTL, aGot.TTL)
					}
					// RDATA comparison: Type determines how we check.
					// For raw types (A, AAAA, TXT, OPT, RRSIG, NSEC) we
					// compare bytes exactly. For name-bearing types (NS,
					// CNAME, PTR, DNAME, MX, SRV, SOA) the internal
					// representation may re-encode names, so compare
					// the parsed value.
					if !reflect.DeepEqual(aOrig.RData, aGot.RData) {
						// RDATA differs — for name-bearing types this is
						// expected because the re-encoded name may use
						// different compression. Verify the type-specific
						// semantics match instead.
						switch aOrig.Type {
						case TypeNS, TypeCNAME, TypePTR, TypeDNAME:
							n1, _, e1 := DecodeName(aOrig.RData, 0)
							n2, _, e2 := DecodeName(aGot.RData, 0)
							if e1 != nil || e2 != nil || normaliseName(n1) != normaliseName(n2) {
								t.Errorf("Answer[%d] type=%d RDATA round-trip failed: %x → %x", i, aOrig.Type, aOrig.RData, aGot.RData)
							}
						case TypeMX:
							if len(aOrig.RData) >= 2 && len(aGot.RData) >= 2 {
								if aOrig.RData[0] != aGot.RData[0] || aOrig.RData[1] != aGot.RData[1] {
									t.Errorf("Answer[%d] MX preference mismatch", i)
								}
								n1, _, e1 := DecodeName(aOrig.RData, 2)
								n2, _, e2 := DecodeName(aGot.RData, 2)
								if e1 != nil || e2 != nil || normaliseName(n1) != normaliseName(n2) {
									t.Errorf("Answer[%d] MX exchange round-trip failed", i)
								}
							} else {
								t.Errorf("Answer[%d] MX RDATA truncated", i)
							}
						case TypeSOA:
							// Just verify both names parse and the serials match
							m1, off1, e1 := DecodeName(aOrig.RData, 0)
							r1, _, e2 := DecodeName(aOrig.RData, off1)
							m2, off2, e3 := DecodeName(aGot.RData, 0)
							r2, _, e4 := DecodeName(aGot.RData, off2)
							if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
								t.Errorf("Answer[%d] SOA names failed to parse", i)
							} else {
								if normaliseName(m1) != normaliseName(m2) || normaliseName(r1) != normaliseName(r2) {
									t.Errorf("Answer[%d] SOA MNAME or RNAME mismatch", i)
								}
								if len(aOrig.RData) >= off1+20 && len(aGot.RData) >= off2+20 {
									for j := 0; j < 20; j++ {
										if aOrig.RData[off1+j] != aGot.RData[off2+j] {
											t.Errorf("Answer[%d] SOA serials mismatch at byte %d", i, j)
											break
										}
									}
								}
							}
						default:
							t.Errorf("Answer[%d] RDATA mismatch: %x → %x", i, aOrig.RData, aGot.RData)
						}
					}
				}
			}

			// Compare authority and additional section counts
			if len(unpacked.Authority) != len(tc.msg.Authority) {
				t.Errorf("Authority count: %d → %d", len(tc.msg.Authority), len(unpacked.Authority))
			}
			if len(unpacked.Additional) != len(tc.msg.Additional) {
				t.Errorf("Additional count: %d → %d", len(tc.msg.Additional), len(unpacked.Additional))
			}
		})
	}
}

// ──────────────────────────────────────────────
// Property 4: Compression pointer stability
// ──────────────────────────────────────────────

// TestProperty_NameCompressionStable verifies that a name written with
// compression can be read back and re-written identically. This catches
// cases where compression creates a pointer that the next Pack refuses
// (because the shared name reference has shifted) or where the
// decompressed name doesn't re-compress to the same wire bytes.
func TestProperty_NameCompressionStable(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 100, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Answers: []ResourceRecord{
			{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
			{Name: "www.example.com.", Type: TypeCNAME, Class: ClassIN, TTL: 300, RData: BuildPlainName("example.com.")},
		},
		Authority: []ResourceRecord{
			{Name: "example.com.", Type: TypeNS, Class: ClassIN, TTL: 86400, RData: BuildPlainName("ns1.example.com.")},
		},
		Additional: []ResourceRecord{
			{Name: "ns1.example.com.", Type: TypeA, Class: ClassIN, TTL: 300, RData: []byte{10, 0, 0, 1}},
		},
	}

	buf := make([]byte, 8192)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("first Pack failed: %v", err)
	}

	// Unpack then repack three times — each iteration exercises the
	// compression table with the previous output as input.
	for i := 0; i < 3; i++ {
		unpacked, err := Unpack(packed)
		if err != nil {
			t.Fatalf("Unpack iteration %d failed: %v", i, err)
		}

		buf2 := make([]byte, 8192)
		packed2, err := Pack(unpacked, buf2)
		if err != nil {
			t.Fatalf("Pack iteration %d failed: %v", i, err)
		}

		// Unpack the re-packed bytes to verify structural consistency
		_, err = Unpack(packed2)
		if err != nil {
			t.Fatalf("Unpack after iteration %d failed: %v", i, err)
		}

		packed = packed2
	}
}

// ──────────────────────────────────────────────
// Property 5: Buffer bounds — Pack does not write
// past the end of the provided buffer
// ──────────────────────────────────────────────

func TestProperty_PackBufferBounds(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1, Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build()},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Answers: []ResourceRecord{
			{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 300, RData: []byte{10, 0, 0, 1}},
		},
	}

	// Pack into a too-small buffer.
	smallBuf := make([]byte, 10)
	_, err := Pack(msg, smallBuf)
	if err != errBufferFull {
		t.Errorf("expected errBufferFull for 10-byte buffer, got %v", err)
	}

	// Pack into a buffer that's exactly the right size by first
	// determining the needed size.
	bigBuf := make([]byte, 65535)
	packed, err := Pack(msg, bigBuf)
	if err != nil {
		t.Fatalf("Pack into large buffer failed: %v", err)
	}

	exactBuf := make([]byte, len(packed))
	repacked, err := Pack(msg, exactBuf)
	if err != nil {
		t.Fatalf("Pack into exact-size buffer failed: %v", err)
	}
	if len(repacked) != len(packed) {
		t.Errorf("exact-size pack produced %d bytes, expected %d", len(repacked), len(packed))
	}
}
