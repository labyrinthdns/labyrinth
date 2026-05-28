package dns

import (
	"bytes"
	"testing"
)

// TestUnknownRRType_OpaqueRoundtrip pins RFC 3597 §3: "An implementation
// of the DNS protocol MUST handle all RR types that it does not
// implement at least by treating the RDATA as a generic opaque block."
// The parser sees an RR type the resolver has no special-case logic
// for (TypeSPF=99 — once defined, now deprecated, perfectly suited as
// a "known-but-unhandled" specimen) and MUST:
//
//   1. Preserve the RDATA bytes verbatim on pack→unpack→pack roundtrip.
//   2. Preserve Type, Class, TTL, and Name across the same cycle.
//   3. NOT attempt to interpret the bytes as a domain name and
//      recompress them — a buggy parser that fell through to the NS/
//      CNAME/PTR handler would corrupt the RDATA on any byte sequence
//      that happened to start with a valid label-length prefix.
//
// Without this invariant, the cache could not safely store RR types
// the resolver does not natively understand — and the entire RFC 3597
// promise of "forward compatibility with future RR types" silently
// breaks. A resolver that fails this test cannot be trusted with
// signed zones that carry future types in the answer section.
//
// The specimen RDATA is deliberately chosen to start with a byte that
// LOOKS like a label-length (0x07) — a buggy "interpret as name"
// fallback would mangle it.
func TestUnknownRRType_OpaqueRoundtrip(t *testing.T) {
	const customType uint16 = 99 // TypeSPF — IANA-assigned, no special-case parser
	rdata := []byte{
		0x07, // first byte resembles label-length — bait for a "treat as name" bug
		'r', 'f', 'c', '3', '5', '9', '7',
		0x00, // pseudo-NUL terminator — second decoy
		0xDE, 0xAD, 0xBE, 0xEF, // arbitrary binary
	}

	orig := &Message{
		Header:    Header{ID: 0x3597, Flags: NewFlagBuilder().SetQR(true).Build()},
		Questions: []Question{{Name: "y70.example.com", Type: customType, Class: ClassIN}},
		Answers: []ResourceRecord{{
			Name:     "y70.example.com",
			Type:     customType,
			Class:    ClassIN,
			TTL:      3600,
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		}},
	}

	// Round 1: pack → unpack.
	buf := make([]byte, 4096)
	packed, err := Pack(orig, buf)
	if err != nil {
		t.Fatalf("pack #1: %v", err)
	}
	round1, err := Unpack(packed)
	if err != nil {
		t.Fatalf("unpack #1: %v", err)
	}
	if len(round1.Answers) != 1 {
		t.Fatalf("answers after round 1 = %d, want 1", len(round1.Answers))
	}
	assertRRPreserved(t, "round 1", round1.Answers[0], customType, rdata)

	// Round 2: pack the unpacked message and unpack again — proves the
	// pack side also writes back the bytes verbatim, not just that
	// unpack reads them correctly.
	repacked, err := Pack(round1, make([]byte, 4096))
	if err != nil {
		t.Fatalf("pack #2: %v", err)
	}
	round2, err := Unpack(repacked)
	if err != nil {
		t.Fatalf("unpack #2: %v", err)
	}
	if len(round2.Answers) != 1 {
		t.Fatalf("answers after round 2 = %d, want 1", len(round2.Answers))
	}
	assertRRPreserved(t, "round 2", round2.Answers[0], customType, rdata)
}

func assertRRPreserved(t *testing.T, label string, got ResourceRecord, wantType uint16, wantRData []byte) {
	t.Helper()
	if got.Type != wantType {
		t.Errorf("%s: Type = %d, want %d (RFC 3597 §3: opaque types preserve type)", label, got.Type, wantType)
	}
	if got.Class != ClassIN {
		t.Errorf("%s: Class = %d, want IN (%d)", label, got.Class, ClassIN)
	}
	if got.TTL != 3600 {
		t.Errorf("%s: TTL = %d, want 3600", label, got.TTL)
	}
	if got.Name != "y70.example.com" {
		t.Errorf("%s: Name = %q, want y70.example.com", label, got.Name)
	}
	if !bytes.Equal(got.RData, wantRData) {
		t.Errorf("%s: RDATA = %v, want %v — RFC 3597 §3 requires unknown RR types to roundtrip opaque RDATA; a 'fall through to name decoder' bug would mangle the label-length-looking first byte (0x07)", label, got.RData, wantRData)
	}
	if int(got.RDLength) != len(wantRData) {
		t.Errorf("%s: RDLength = %d, want %d", label, got.RDLength, len(wantRData))
	}
}
