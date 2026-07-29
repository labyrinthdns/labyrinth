package dns

import (
	"testing"
)

// TestPadRawResponse_PadsToBlock pins the Y22 happy path: when called
// with the RFC 8467 §4.1 recommended block of 468, the wire length of
// the returned response MUST be an exact multiple of 468. Without this,
// passive observers on the encrypted channel can fingerprint queries
// from response length alone — small NXDOMAIN, medium A answer, large
// DNSSEC-signed AAAA all sit in distinct buckets.
func TestPadRawResponse_PadsToBlock(t *testing.T) {
	// Build a tiny response: header + 1 question + 1 A answer + OPT.
	msg := &Message{
		Header: Header{ID: 0x1234, Flags: 0x8180, QDCount: 1, ANCount: 1, ARCount: 1},
		Questions: []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}},
		Answers: []ResourceRecord{{
			Name: "example.com", Type: TypeA, Class: ClassIN, TTL: 300,
			RData: []byte{93, 184, 216, 34}, RDLength: 4,
		}},
		Additional: []ResourceRecord{BuildOPT(1232, false)},
	}
	raw, err := Pack(msg, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	rawCopy := append([]byte(nil), raw...)

	padded := PadRawResponse(rawCopy, PaddingBlockSize)
	if len(padded)%PaddingBlockSize != 0 {
		t.Errorf("padded length %d is not a multiple of %d", len(padded), PaddingBlockSize)
	}
	if len(padded) < len(rawCopy) {
		t.Errorf("padded length %d shorter than original %d", len(padded), len(rawCopy))
	}
	// Sanity: padded message still parses.
	if _, err := Unpack(padded); err != nil {
		t.Errorf("padded response no longer parses: %v", err)
	}
}

// TestPadRawResponse_AlreadyAlignedNoGrow: if the message happens to
// already sit on a block boundary, we still add an empty PADDING option
// (option header = 4 bytes) — which means the new length is original+4
// not original. That's fine; the spec only requires the FINAL length
// is a multiple of block. This test pins that "no-grow" path returns a
// length that is still a clean multiple.
func TestPadRawResponse_AlreadyAlignedNoGrow(t *testing.T) {
	// Tiny query so we can pad to small block for easy checking.
	msg := &Message{Header: Header{ID: 1, QDCount: 1}, Questions: []Question{{Name: ".", Type: TypeA, Class: ClassIN}}}
	raw, err := Pack(msg, make([]byte, 256))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	padded := PadRawResponse(raw, 64)
	if len(padded)%64 != 0 {
		t.Errorf("padded length %d not aligned to 64", len(padded))
	}
}

// TestPadRawResponse_InvalidWireReturnsOriginal: a corrupt wire payload
// must not crash the helper; the original bytes are returned unchanged
// so the caller can still ship the response (the auth's choice, not
// ours, to send malformed bytes).
func TestPadRawResponse_InvalidWireReturnsOriginal(t *testing.T) {
	bogus := []byte{0xff, 0xff} // way too short to be DNS
	out := PadRawResponse(bogus, PaddingBlockSize)
	if len(out) != len(bogus) {
		t.Errorf("expected pass-through on unpackable input, got len %d (input %d)", len(out), len(bogus))
	}
}

// TestPadRawResponse_ZeroBlockNoop: block <= 0 disables padding — the
// guard against operator misconfiguration. Otherwise dividing by zero
// or producing astronomically large messages.
func TestPadRawResponse_ZeroBlockNoop(t *testing.T) {
	msg := &Message{Header: Header{ID: 1, QDCount: 1}, Questions: []Question{{Name: ".", Type: TypeA, Class: ClassIN}}}
	raw, _ := Pack(msg, make([]byte, 256))
	if got := PadRawResponse(raw, 0); len(got) != len(raw) {
		t.Error("block=0 must return original bytes unchanged")
	}
}

// TestHasPaddingOption_DetectsClientSignal pins that the helper used
// by the DoT/DoH dispatch path correctly recognises the client-side
// PADDING signal (zero-length option data is the canonical client form
// per RFC 8467 §4.3).
func TestHasPaddingOption_DetectsClientSignal(t *testing.T) {
	edns := &EDNS0{Options: []EDNSOption{{Code: EDNSOptionCodePadding, Data: nil}}}
	if !HasPaddingOption(edns) {
		t.Error("padding option with zero-length data must be detected")
	}
	edns2 := &EDNS0{Options: []EDNSOption{{Code: EDNSOptionCodeECS, Data: []byte{0}}}}
	if HasPaddingOption(edns2) {
		t.Error("non-padding option must not be detected as padding")
	}
	if HasPaddingOption(nil) {
		t.Error("nil EDNS0 must report no padding")
	}
}
