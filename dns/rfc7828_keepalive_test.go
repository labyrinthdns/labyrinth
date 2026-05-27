package dns

import (
	"encoding/binary"
	"testing"
)

// TestAddTCPKeepaliveToRawResponse_AppendsOption pins the Y23 happy
// path: after AddTCPKeepaliveToRawResponse the resulting wire format
// must parse, must carry an OPT, and the OPT must include a KEEPALIVE
// option whose 2-byte payload equals the timeout we passed in 100ms
// units (RFC 7828 §3.1).
func TestAddTCPKeepaliveToRawResponse_AppendsOption(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 0xabcd, Flags: 0x8180, QDCount: 1, ANCount: 1},
		Questions: []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}},
		Answers: []ResourceRecord{{
			Name: "example.com", Type: TypeA, Class: ClassIN, TTL: 60,
			RData: []byte{1, 2, 3, 4}, RDLength: 4,
		}},
	}
	raw, err := Pack(msg, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	withKA := AddTCPKeepaliveToRawResponse(raw, 100) // 100 * 100ms = 10s
	parsed, err := Unpack(withKA)
	if err != nil {
		t.Fatalf("repacked response no longer parses: %v", err)
	}
	if parsed.EDNS0 == nil {
		t.Fatal("OPT was not added by helper")
	}
	found := false
	for _, opt := range parsed.EDNS0.Options {
		if opt.Code == EDNSOptionCodeTCPKeepalive {
			found = true
			if len(opt.Data) != 2 {
				t.Errorf("keepalive option payload length = %d, want 2 (RFC 7828 §3.1)", len(opt.Data))
			}
			if binary.BigEndian.Uint16(opt.Data) != 100 {
				t.Errorf("keepalive timeout = %d, want 100 (units of 100ms)", binary.BigEndian.Uint16(opt.Data))
			}
		}
	}
	if !found {
		t.Error("KEEPALIVE option not present in repacked response")
	}
}

// TestAddTCPKeepaliveToRawResponse_IdempotentOnExisting: if the response
// already carries a KEEPALIVE option (because some inner layer already
// added one), the helper MUST NOT append a second copy. RFC 7828 §3.4
// requires "no more than one option" per response. The helper is the
// only writer in this codebase, but the idempotency check protects us
// against a future code path that might add it independently.
func TestAddTCPKeepaliveToRawResponse_IdempotentOnExisting(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1, QDCount: 1},
		Questions: []Question{{Name: ".", Type: TypeA, Class: ClassIN}},
		Additional: []ResourceRecord{BuildOPTWithOptions(1232, false, []EDNSOption{
			BuildTCPKeepaliveOption(50),
		})},
	}
	raw, err := Pack(msg, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	out := AddTCPKeepaliveToRawResponse(raw, 999) // should NOT overwrite
	parsed, err := Unpack(out)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	count := 0
	for _, opt := range parsed.EDNS0.Options {
		if opt.Code == EDNSOptionCodeTCPKeepalive {
			count++
			if binary.BigEndian.Uint16(opt.Data) != 50 {
				t.Errorf("existing keepalive timeout overwritten: got %d, want 50", binary.BigEndian.Uint16(opt.Data))
			}
		}
	}
	if count != 1 {
		t.Errorf("KEEPALIVE option count = %d, want 1 (RFC 7828 §3.4 — at most one)", count)
	}
}

// TestHasTCPKeepaliveOption_DetectsClientSignal pins the helper used
// to detect a client's RFC 7828 §3.2 keepalive signal. The client
// form is the option with zero-length data; the server form carries
// 2 bytes. We accept either as "client wants keepalive."
func TestHasTCPKeepaliveOption_DetectsClientSignal(t *testing.T) {
	edns := &EDNS0{Options: []EDNSOption{{Code: EDNSOptionCodeTCPKeepalive, Data: nil}}}
	if !HasTCPKeepaliveOption(edns) {
		t.Error("zero-length keepalive (client form) must be detected")
	}
	if HasTCPKeepaliveOption(&EDNS0{Options: []EDNSOption{{Code: EDNSOptionCodeECS, Data: []byte{0}}}}) {
		t.Error("non-keepalive option must not be detected as keepalive")
	}
	if HasTCPKeepaliveOption(nil) {
		t.Error("nil EDNS0 must report no keepalive")
	}
}
