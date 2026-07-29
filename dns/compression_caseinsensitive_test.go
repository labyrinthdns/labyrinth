package dns

import (
	"strings"
	"testing"
)

// TestEncodeName_CaseInsensitiveCompression pins the fix for the multi-hop
// CNAME truncation bug: name compression must fold case (RFC 1035 §2.3.3,
// §3.1) so that 0x20-randomized (RFC 5452 §9.2) variants of the same name
// still compress. A CNAME chain resolved with 0x20 comes back with each owner
// and target in independent random case; keyed by exact case, none of them
// match and the whole chain is written out in full, bloating the response past
// the 512-byte UDP limit.
//
// The test packs the same logical CNAME chain twice — once all-lowercase, once
// with the upstream-style mixed casing — and asserts the wire encodings are
// byte-for-byte identical in length. Before the fix the mixed-case message was
// materially larger because compression silently failed.
func TestEncodeName_CaseInsensitiveCompression(t *testing.T) {
	// chain: owner -> target across a shared "amazon.com" suffix.
	chain := func(c func(string) string) *Message {
		mk := func(owner, target string) ResourceRecord {
			rd, err := EncodeNameToBytes(c(target))
			if err != nil {
				t.Fatalf("encode target %q: %v", target, err)
			}
			return ResourceRecord{
				Name: c(owner), Type: TypeCNAME, Class: ClassIN, TTL: 300,
				RDLength: uint16(len(rd)), RData: rd,
			}
		}
		return &Message{
			Header:    Header{ID: 0x1234, Flags: 0x8180},
			Questions: []Question{{Name: c("a.lightsail.amazon.com"), Type: TypeCNAME, Class: ClassIN}},
			Answers: []ResourceRecord{
				mk("a.lightsail.amazon.com", "b.console.amazon.com"),
				mk("b.console.amazon.com", "c.geo.amazon.com"),
				mk("c.geo.amazon.com", "d.accel.amazon.com"),
			},
		}
	}

	lower := chain(strings.ToLower)
	// Mimic 0x20: each name comes back in its own random-ish casing.
	mixed := chain(func(s string) string {
		out := []byte(s)
		for i := range out {
			if i%2 == 0 && out[i] >= 'a' && out[i] <= 'z' {
				out[i] -= 32
			}
		}
		return string(out)
	})

	bufL := make([]byte, 4096)
	bufM := make([]byte, 4096)
	packedLower, err := Pack(lower, bufL)
	if err != nil {
		t.Fatalf("pack lower: %v", err)
	}
	packedMixed, err := Pack(mixed, bufM)
	if err != nil {
		t.Fatalf("pack mixed: %v", err)
	}

	if len(packedMixed) != len(packedLower) {
		t.Fatalf("case randomization defeated compression: mixed=%d bytes, lower=%d bytes (must be equal)",
			len(packedMixed), len(packedLower))
	}

	// Sanity: the chain must still round-trip to the same names case-folded.
	out, err := Unpack(packedMixed)
	if err != nil {
		t.Fatalf("unpack mixed: %v", err)
	}
	if len(out.Answers) != 3 {
		t.Fatalf("expected 3 answers, got %d", len(out.Answers))
	}
	if got := strings.ToLower(out.Answers[0].Name); got != "a.lightsail.amazon.com" {
		t.Errorf("answer[0] owner = %q, want a.lightsail.amazon.com", got)
	}
}
