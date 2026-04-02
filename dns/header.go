package dns

// Flag accessor methods

func (h *Header) QR() bool      { return h.Flags>>15&1 == 1 }
func (h *Header) Opcode() uint8 { return uint8(h.Flags >> 11 & 0xF) }
func (h *Header) AA() bool      { return h.Flags>>10&1 == 1 }
func (h *Header) TC() bool      { return h.Flags>>9&1 == 1 }
func (h *Header) RD() bool      { return h.Flags>>8&1 == 1 }
func (h *Header) RA() bool      { return h.Flags>>7&1 == 1 }
func (h *Header) AD() bool      { return h.Flags>>5&1 == 1 }
func (h *Header) CD() bool      { return h.Flags>>4&1 == 1 }
func (h *Header) RCODE() uint8  { return uint8(h.Flags & 0xF) }

// Unpack reads the header from a wireReader.
func (h *Header) Unpack(r *wireReader) error {
	var err error
	if h.ID, err = r.readUint16(); err != nil {
		return err
	}
	if h.Flags, err = r.readUint16(); err != nil {
		return err
	}
	if h.QDCount, err = r.readUint16(); err != nil {
		return err
	}
	if h.ANCount, err = r.readUint16(); err != nil {
		return err
	}
	if h.NSCount, err = r.readUint16(); err != nil {
		return err
	}
	if h.ARCount, err = r.readUint16(); err != nil {
		return err
	}
	return nil
}

// Pack writes the header to a wireWriter.
func (h *Header) Pack(w *wireWriter) error {
	for _, v := range []uint16{h.ID, h.Flags, h.QDCount, h.ANCount, h.NSCount, h.ARCount} {
		if err := w.writeUint16(v); err != nil {
			return err
		}
	}
	return nil
}

// FlagBuilder provides a builder pattern for constructing DNS header flags.
type FlagBuilder struct {
	flags uint16
}

func NewFlagBuilder() *FlagBuilder {
	return &FlagBuilder{}
}

func (fb *FlagBuilder) SetQR(v bool) *FlagBuilder {
	if v {
		fb.flags |= 1 << 15
	}
	return fb
}

func (fb *FlagBuilder) SetOpcode(v uint8) *FlagBuilder {
	fb.flags |= uint16(v&0xF) << 11
	return fb
}

func (fb *FlagBuilder) SetAA(v bool) *FlagBuilder {
	if v {
		fb.flags |= 1 << 10
	}
	return fb
}

func (fb *FlagBuilder) SetTC(v bool) *FlagBuilder {
	if v {
		fb.flags |= 1 << 9
	}
	return fb
}

func (fb *FlagBuilder) SetRD(v bool) *FlagBuilder {
	if v {
		fb.flags |= 1 << 8
	}
	return fb
}

func (fb *FlagBuilder) SetRA(v bool) *FlagBuilder {
	if v {
		fb.flags |= 1 << 7
	}
	return fb
}

func (fb *FlagBuilder) SetAD(v bool) *FlagBuilder {
	if v {
		fb.flags |= 1 << 5
	}
	return fb
}

func (fb *FlagBuilder) SetCD(v bool) *FlagBuilder {
	if v {
		fb.flags |= 1 << 4
	}
	return fb
}

func (fb *FlagBuilder) SetRCODE(v uint8) *FlagBuilder {
	fb.flags |= uint16(v & 0xF)
	return fb
}

func (fb *FlagBuilder) Build() uint16 {
	return fb.flags
}
