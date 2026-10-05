package dns

import "testing"

func TestFlagBuilder_ReplacesFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*FlagBuilder, bool) *FlagBuilder
		bit  uint16
	}{
		{"QR", (*FlagBuilder).SetQR, 1 << 15},
		{"AA", (*FlagBuilder).SetAA, 1 << 10},
		{"TC", (*FlagBuilder).SetTC, 1 << 9},
		{"RD", (*FlagBuilder).SetRD, 1 << 8},
		{"RA", (*FlagBuilder).SetRA, 1 << 7},
		{"AD", (*FlagBuilder).SetAD, 1 << 5},
		{"CD", (*FlagBuilder).SetCD, 1 << 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &FlagBuilder{flags: 0xffff}
			tc.set(b, false)
			if b.Build() != 0xffff&^tc.bit {
				t.Errorf("clear: flags = %#x, want %#x", b.Build(), 0xffff&^tc.bit)
			}
			tc.set(b, true)
			if b.Build() != 0xffff {
				t.Errorf("restore: flags = %#x, want 0xffff", b.Build())
			}
		})
	}
	for _, value := range []uint8{0, 1, 2, 15, 255} {
		b := &FlagBuilder{flags: 0xffff}
		b.SetOpcode(value)
		want := uint16(0xffff&^(0xf<<11)) | uint16(value&0xf)<<11
		if b.Build() != want {
			t.Errorf("opcode %d: flags = %#x, want %#x", value, b.Build(), want)
		}
		b.flags = 0xffff
		b.SetRCODE(value)
		want = uint16(0xfff0) | uint16(value&0xf)
		if b.Build() != want {
			t.Errorf("rcode %d: flags = %#x, want %#x", value, b.Build(), want)
		}
	}
}
