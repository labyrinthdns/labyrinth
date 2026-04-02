package dns

import "testing"

func TestHeaderOpcode(t *testing.T) {
	// Opcode is bits 11-14 of Flags. Opcode=2 (Status) → bits 11-14 = 0010 → 0x1000
	h := Header{Flags: uint16(OpcodeStatus) << 11}
	if got := h.Opcode(); got != OpcodeStatus {
		t.Errorf("Opcode: expected %d, got %d", OpcodeStatus, got)
	}

	// All opcode bits set → opcode = 15
	h.Flags = 0xF << 11
	if got := h.Opcode(); got != 15 {
		t.Errorf("Opcode: expected 15, got %d", got)
	}
}

func TestHeaderTC(t *testing.T) {
	// TC is bit 9
	h := Header{Flags: 1 << 9}
	if !h.TC() {
		t.Error("TC should be true")
	}
	h.Flags = 0
	if h.TC() {
		t.Error("TC should be false")
	}
}

func TestHeaderAD(t *testing.T) {
	// AD is bit 5
	h := Header{Flags: 1 << 5}
	if !h.AD() {
		t.Error("AD should be true")
	}
	h.Flags = 0
	if h.AD() {
		t.Error("AD should be false")
	}
}

func TestHeaderCD(t *testing.T) {
	// CD is bit 4
	h := Header{Flags: 1 << 4}
	if !h.CD() {
		t.Error("CD should be true")
	}
	h.Flags = 0
	if h.CD() {
		t.Error("CD should be false")
	}
}

func TestFlagBuilderSetOpcode(t *testing.T) {
	flags := NewFlagBuilder().SetOpcode(OpcodeStatus).Build()
	h := Header{Flags: flags}
	if got := h.Opcode(); got != OpcodeStatus {
		t.Errorf("SetOpcode: expected opcode %d, got %d", OpcodeStatus, got)
	}
}

func TestFlagBuilderSetAA(t *testing.T) {
	flags := NewFlagBuilder().SetAA(true).Build()
	h := Header{Flags: flags}
	if !h.AA() {
		t.Error("SetAA(true) should set AA flag")
	}

	flags = NewFlagBuilder().SetAA(false).Build()
	h = Header{Flags: flags}
	if h.AA() {
		t.Error("SetAA(false) should not set AA flag")
	}
}

func TestFlagBuilderSetTC(t *testing.T) {
	flags := NewFlagBuilder().SetTC(true).Build()
	h := Header{Flags: flags}
	if !h.TC() {
		t.Error("SetTC(true) should set TC flag")
	}

	flags = NewFlagBuilder().SetTC(false).Build()
	h = Header{Flags: flags}
	if h.TC() {
		t.Error("SetTC(false) should not set TC flag")
	}
}

func TestFlagBuilderSetAD(t *testing.T) {
	flags := NewFlagBuilder().SetAD(true).Build()
	h := Header{Flags: flags}
	if !h.AD() {
		t.Error("SetAD(true) should set AD flag")
	}

	flags = NewFlagBuilder().SetAD(false).Build()
	h = Header{Flags: flags}
	if h.AD() {
		t.Error("SetAD(false) should not set AD flag")
	}
}

func TestFlagBuilderSetCD(t *testing.T) {
	flags := NewFlagBuilder().SetCD(true).Build()
	h := Header{Flags: flags}
	if !h.CD() {
		t.Error("SetCD(true) should set CD flag")
	}

	flags = NewFlagBuilder().SetCD(false).Build()
	h = Header{Flags: flags}
	if h.CD() {
		t.Error("SetCD(false) should not set CD flag")
	}
}

func TestFlagBuilderAllFlags(t *testing.T) {
	flags := NewFlagBuilder().
		SetQR(true).
		SetOpcode(OpcodeIQuery).
		SetAA(true).
		SetTC(true).
		SetRD(true).
		SetRA(true).
		SetAD(true).
		SetCD(true).
		SetRCODE(RCodeRefused).
		Build()

	h := Header{Flags: flags}

	if !h.QR() {
		t.Error("QR should be true")
	}
	if h.Opcode() != OpcodeIQuery {
		t.Errorf("Opcode: expected %d, got %d", OpcodeIQuery, h.Opcode())
	}
	if !h.AA() {
		t.Error("AA should be true")
	}
	if !h.TC() {
		t.Error("TC should be true")
	}
	if !h.RD() {
		t.Error("RD should be true")
	}
	if !h.RA() {
		t.Error("RA should be true")
	}
	if !h.AD() {
		t.Error("AD should be true")
	}
	if !h.CD() {
		t.Error("CD should be true")
	}
	if h.RCODE() != RCodeRefused {
		t.Errorf("RCODE: expected %d, got %d", RCodeRefused, h.RCODE())
	}
}

func TestHeaderUnpackTruncated(t *testing.T) {
	// Only 10 bytes, need 12
	buf := make([]byte, 10)
	r := newWireReader(buf)
	var h Header
	if err := h.Unpack(r); err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestHeaderPackBufferFull(t *testing.T) {
	buf := make([]byte, 4) // need 12
	w := newWireWriter(buf)
	h := Header{ID: 1}
	if err := h.Pack(w); err != errBufferFull {
		t.Fatalf("expected errBufferFull, got %v", err)
	}
}

// Cover each readUint16 error path in Header.Unpack by truncating at different points.
func TestHeaderUnpackTruncatedAtEachField(t *testing.T) {
	// A valid 12-byte header
	full := []byte{0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}

	// Truncation sizes that fail at each readUint16 call:
	// 0-1 bytes: fails at ID
	// 2-3 bytes: fails at Flags
	// 4-5 bytes: fails at QDCount
	// 6-7 bytes: fails at ANCount
	// 8-9 bytes: fails at NSCount
	// 10-11 bytes: fails at ARCount
	for _, size := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} {
		r := newWireReader(full[:size])
		var h Header
		err := h.Unpack(r)
		if err != errTruncated {
			t.Errorf("size=%d: expected errTruncated, got %v", size, err)
		}
	}
}
