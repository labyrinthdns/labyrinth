package dns

import (
	"encoding/binary"
	"testing"
)

func TestWireReaderReadUint16(t *testing.T) {
	buf := []byte{0xAB, 0xCD, 0x12, 0x34}
	r := newWireReader(buf)

	v, err := r.readUint16()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 0xABCD {
		t.Fatalf("expected 0xABCD, got 0x%04X", v)
	}

	v, err = r.readUint16()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 0x1234 {
		t.Fatalf("expected 0x1234, got 0x%04X", v)
	}

	_, err = r.readUint16()
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestWireReaderReadUint32(t *testing.T) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, 0xDEADBEEF)
	r := newWireReader(buf)

	v, err := r.readUint32()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 0xDEADBEEF {
		t.Fatalf("expected 0xDEADBEEF, got 0x%08X", v)
	}
}

func TestWireReaderBoundsViolation(t *testing.T) {
	r := newWireReader([]byte{0x01})

	_, err := r.readUint16()
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestHeaderUnpack(t *testing.T) {
	// ID=0xABCD, Flags=0x8180 (QR=1, RD=1, RA=1), QD=1, AN=1, NS=0, AR=0
	buf := []byte{0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	r := newWireReader(buf)

	var h Header
	if err := h.Unpack(r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.ID != 0xABCD {
		t.Errorf("ID: expected 0xABCD, got 0x%04X", h.ID)
	}
	if !h.QR() {
		t.Error("QR should be true")
	}
	if !h.RD() {
		t.Error("RD should be true")
	}
	if !h.RA() {
		t.Error("RA should be true")
	}
	if h.RCODE() != 0 {
		t.Errorf("RCODE: expected 0, got %d", h.RCODE())
	}
	if h.QDCount != 1 {
		t.Errorf("QDCount: expected 1, got %d", h.QDCount)
	}
	if h.ANCount != 1 {
		t.Errorf("ANCount: expected 1, got %d", h.ANCount)
	}
}

func TestHeaderFlags(t *testing.T) {
	// Flags=0x8583: QR=1, AA=1, RCODE=3 (NXDOMAIN)
	h := Header{Flags: 0x8583}
	if !h.QR() {
		t.Error("QR should be true")
	}
	if !h.AA() {
		t.Error("AA should be true")
	}
	if h.RCODE() != 3 {
		t.Errorf("RCODE: expected 3, got %d", h.RCODE())
	}
}

func TestFlagBuilder(t *testing.T) {
	flags := NewFlagBuilder().SetQR(true).SetRA(true).SetRCODE(0).Build()
	if flags != 0x8080 {
		t.Errorf("expected 0x8080, got 0x%04X", flags)
	}

	flags = NewFlagBuilder().SetQR(true).SetRA(true).SetRCODE(3).Build()
	if flags != 0x8083 {
		t.Errorf("expected 0x8083, got 0x%04X", flags)
	}
}

func TestHeaderPackUnpackRoundTrip(t *testing.T) {
	orig := Header{ID: 0x1234, Flags: 0x8180, QDCount: 1, ANCount: 2, NSCount: 3, ARCount: 4}

	buf := make([]byte, 12)
	w := newWireWriter(buf)
	if err := orig.Pack(w); err != nil {
		t.Fatalf("pack error: %v", err)
	}

	r := newWireReader(w.bytes())
	var h Header
	if err := h.Unpack(r); err != nil {
		t.Fatalf("unpack error: %v", err)
	}

	if h != orig {
		t.Errorf("round-trip mismatch: %+v != %+v", h, orig)
	}
}

func TestUnpackTruncated(t *testing.T) {
	_, err := Unpack([]byte{0x00, 0x01, 0x02})
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestPackUnpackRoundTrip(t *testing.T) {
	msg := &Message{
		Header: Header{
			ID:    0x1234,
			Flags: NewFlagBuilder().SetQR(true).SetRA(true).Build(),
		},
		Questions: []Question{{
			Name:  "google.com",
			Type:  TypeA,
			Class: ClassIN,
		}},
		Answers: []ResourceRecord{{
			Name:     "google.com",
			Type:     TypeA,
			Class:    ClassIN,
			TTL:      300,
			RDLength: 4,
			RData:    []byte{142, 250, 80, 46},
		}},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("unpack error: %v", err)
	}

	if unpacked.Header.ID != 0x1234 {
		t.Errorf("ID mismatch")
	}
	if len(unpacked.Questions) != 1 {
		t.Fatalf("expected 1 question, got %d", len(unpacked.Questions))
	}
	if unpacked.Questions[0].Name != "google.com" {
		t.Errorf("question name: %s", unpacked.Questions[0].Name)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(unpacked.Answers))
	}
	if unpacked.Answers[0].TTL != 300 {
		t.Errorf("TTL: expected 300, got %d", unpacked.Answers[0].TTL)
	}
}

func TestWireWriterBasic(t *testing.T) {
	buf := make([]byte, 10)
	w := newWireWriter(buf)

	if err := w.writeUint16(0xABCD); err != nil {
		t.Fatalf("writeUint16 error: %v", err)
	}
	if err := w.writeUint32(0x12345678); err != nil {
		t.Fatalf("writeUint32 error: %v", err)
	}
	if err := w.writeBytes([]byte{0xFF}); err != nil {
		t.Fatalf("writeBytes error: %v", err)
	}

	result := w.bytes()
	if len(result) != 7 {
		t.Fatalf("expected 7 bytes, got %d", len(result))
	}
	if binary.BigEndian.Uint16(result[0:2]) != 0xABCD {
		t.Error("uint16 mismatch")
	}
	if binary.BigEndian.Uint32(result[2:6]) != 0x12345678 {
		t.Error("uint32 mismatch")
	}
}

func TestWireWriterBufferFull(t *testing.T) {
	buf := make([]byte, 2)
	w := newWireWriter(buf)

	if err := w.writeUint16(0x0001); err != nil {
		t.Fatalf("first write should succeed: %v", err)
	}
	if err := w.writeUint16(0x0002); err != errBufferFull {
		t.Fatalf("expected errBufferFull, got %v", err)
	}
}

// --- wireReader: readBytes ---

func TestWireReaderReadBytes(t *testing.T) {
	buf := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	r := newWireReader(buf)

	b, err := r.readBytes(3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 3 || b[0] != 0x01 || b[1] != 0x02 || b[2] != 0x03 {
		t.Errorf("readBytes(3): got %v, want [01 02 03]", b)
	}

	// Read remaining 2 bytes
	b, err = r.readBytes(2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 2 || b[0] != 0x04 || b[1] != 0x05 {
		t.Errorf("readBytes(2): got %v, want [04 05]", b)
	}

	// Read beyond remaining
	_, err = r.readBytes(1)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestWireReaderReadBytesEmpty(t *testing.T) {
	r := newWireReader([]byte{})
	_, err := r.readBytes(1)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

// --- wireReader: peek ---

func TestWireReaderPeek(t *testing.T) {
	buf := []byte{0xAB, 0xCD}
	r := newWireReader(buf)

	b, err := r.peek()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b != 0xAB {
		t.Errorf("peek: expected 0xAB, got 0x%02X", b)
	}
	// peek should not advance offset
	if r.offset != 0 {
		t.Errorf("peek advanced offset to %d", r.offset)
	}
}

func TestWireReaderPeekEmpty(t *testing.T) {
	r := newWireReader([]byte{})
	_, err := r.peek()
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

// --- wireWriter: writeUint32 error path ---

func TestWireWriterWriteUint32BufferFull(t *testing.T) {
	buf := make([]byte, 3) // need 4
	w := newWireWriter(buf)

	if err := w.writeUint32(0x12345678); err != errBufferFull {
		t.Fatalf("expected errBufferFull, got %v", err)
	}
}

// --- wireWriter: writeBytes error path ---

func TestWireWriterWriteBytesBufferFull(t *testing.T) {
	buf := make([]byte, 2)
	w := newWireWriter(buf)

	if err := w.writeBytes([]byte{0x01, 0x02, 0x03}); err != errBufferFull {
		t.Fatalf("expected errBufferFull, got %v", err)
	}
}

// --- packRData tests for NS, CNAME, PTR ---

func TestPackRData_NS(t *testing.T) {
	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeNS,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(encodePlainName("ns1.example.com"))),
		RData:    encodePlainName("ns1.example.com"),
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(unpacked.Answers))
	}
	// The decompressed RDATA should contain "ns1.example.com"
	name, _, err := DecodeName(unpacked.Answers[0].RData, 0)
	if err != nil {
		t.Fatalf("DecodeName error: %v", err)
	}
	if name != "ns1.example.com" {
		t.Errorf("expected ns1.example.com, got %s", name)
	}
}

func TestPackRData_CNAME(t *testing.T) {
	rr := ResourceRecord{
		Name:     "www.example.com",
		Type:     TypeCNAME,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(encodePlainName("example.com"))),
		RData:    encodePlainName("example.com"),
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(unpacked.Answers))
	}
	name, _, err := DecodeName(unpacked.Answers[0].RData, 0)
	if err != nil {
		t.Fatalf("DecodeName error: %v", err)
	}
	if name != "example.com" {
		t.Errorf("expected example.com, got %s", name)
	}
}

// --- packRData: MX ---

func TestPackRData_MX(t *testing.T) {
	nameBytes := encodePlainName("mail.example.com")
	rdata := make([]byte, 2+len(nameBytes))
	binary.BigEndian.PutUint16(rdata, 10) // preference
	copy(rdata[2:], nameBytes)

	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeMX,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(unpacked.Answers))
	}

	ans := unpacked.Answers[0]
	pref := binary.BigEndian.Uint16(ans.RData[0:2])
	if pref != 10 {
		t.Errorf("MX preference: expected 10, got %d", pref)
	}
	name, _, err := DecodeName(ans.RData, 2)
	if err != nil {
		t.Fatalf("DecodeName MX exchange: %v", err)
	}
	if name != "mail.example.com" {
		t.Errorf("MX exchange: expected mail.example.com, got %s", name)
	}
}

// --- packRData: SOA ---

func TestPackRData_SOA(t *testing.T) {
	mnameBytes := encodePlainName("ns1.example.com")
	rnameBytes := encodePlainName("admin.example.com")
	serials := make([]byte, 20)
	binary.BigEndian.PutUint32(serials[0:], 2024010101)
	binary.BigEndian.PutUint32(serials[4:], 3600)
	binary.BigEndian.PutUint32(serials[8:], 900)
	binary.BigEndian.PutUint32(serials[12:], 604800)
	binary.BigEndian.PutUint32(serials[16:], 86400)

	rdata := make([]byte, 0, len(mnameBytes)+len(rnameBytes)+20)
	rdata = append(rdata, mnameBytes...)
	rdata = append(rdata, rnameBytes...)
	rdata = append(rdata, serials...)

	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeSOA,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:    Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Authority: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Authority) != 1 {
		t.Fatalf("expected 1 authority, got %d", len(unpacked.Authority))
	}

	// Parse the SOA from the decompressed RDATA
	soa := unpacked.Authority[0]
	mname, off1, err := DecodeName(soa.RData, 0)
	if err != nil {
		t.Fatalf("DecodeName SOA mname: %v", err)
	}
	if mname != "ns1.example.com" {
		t.Errorf("SOA mname: expected ns1.example.com, got %s", mname)
	}
	rname, off2, err := DecodeName(soa.RData, off1)
	if err != nil {
		t.Fatalf("DecodeName SOA rname: %v", err)
	}
	if rname != "admin.example.com" {
		t.Errorf("SOA rname: expected admin.example.com, got %s", rname)
	}
	// Check serial
	serial := binary.BigEndian.Uint32(soa.RData[off2:])
	if serial != 2024010101 {
		t.Errorf("SOA serial: expected 2024010101, got %d", serial)
	}
}

// --- packRData: SRV ---

func TestPackRData_SRV(t *testing.T) {
	nameBytes := encodePlainName("server.example.com")
	rdata := make([]byte, 6+len(nameBytes))
	binary.BigEndian.PutUint16(rdata[0:], 10) // priority
	binary.BigEndian.PutUint16(rdata[2:], 20) // weight
	binary.BigEndian.PutUint16(rdata[4:], 80) // port
	copy(rdata[6:], nameBytes)

	rr := ResourceRecord{
		Name:     "_http._tcp.example.com",
		Type:     TypeSRV,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(unpacked.Answers))
	}

	ans := unpacked.Answers[0]
	if binary.BigEndian.Uint16(ans.RData[0:2]) != 10 {
		t.Errorf("SRV priority mismatch")
	}
	if binary.BigEndian.Uint16(ans.RData[2:4]) != 20 {
		t.Errorf("SRV weight mismatch")
	}
	if binary.BigEndian.Uint16(ans.RData[4:6]) != 80 {
		t.Errorf("SRV port mismatch")
	}
	name, _, err := DecodeName(ans.RData, 6)
	if err != nil {
		t.Fatalf("DecodeName SRV target: %v", err)
	}
	if name != "server.example.com" {
		t.Errorf("SRV target: expected server.example.com, got %s", name)
	}
}

// --- packRData: empty RDATA ---

func TestPackRData_EmptyRData(t *testing.T) {
	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeA,
		Class:    ClassIN,
		TTL:      0,
		RDLength: 0,
		RData:    nil,
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(unpacked.Answers))
	}
	if len(unpacked.Answers[0].RData) != 0 {
		t.Errorf("expected empty RDATA, got %v", unpacked.Answers[0].RData)
	}
}

// --- packRData: default type (raw bytes, e.g. TXT) ---

func TestPackRData_DefaultRaw(t *testing.T) {
	txtRData := []byte{5, 'h', 'e', 'l', 'l', 'o'}
	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeTXT,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(txtRData)),
		RData:    txtRData,
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(unpacked.Answers))
	}
	strs, err := ParseTXT(unpacked.Answers[0].RData)
	if err != nil {
		t.Fatalf("ParseTXT error: %v", err)
	}
	if len(strs) != 1 || strs[0] != "hello" {
		t.Errorf("TXT: expected [hello], got %v", strs)
	}
}

// --- packRData: MX with short RDATA (< 2 bytes, fallback) ---

func TestPackRData_MX_Short(t *testing.T) {
	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeMX,
		Class:    ClassIN,
		TTL:      300,
		RDLength: 1,
		RData:    []byte{0x42},
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(unpacked.Answers))
	}
}

// --- packRData: SRV with short RDATA (< 6 bytes, fallback) ---

func TestPackRData_SRV_Short(t *testing.T) {
	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeSRV,
		Class:    ClassIN,
		TTL:      300,
		RDLength: 4,
		RData:    []byte{0x00, 0x01, 0x00, 0x02},
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(unpacked.Answers))
	}
}

// --- Pack: buffer too small ---

func TestPackBufferTooSmall(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1},
		Questions: []Question{{
			Name:  "example.com",
			Type:  TypeA,
			Class: ClassIN,
		}},
	}

	buf := make([]byte, 5) // too small for header
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull, got %v", err)
	}
}

// --- wireReader: readUint32 truncated ---

func TestWireReaderReadUint32Truncated(t *testing.T) {
	r := newWireReader([]byte{0x01, 0x02, 0x03}) // 3 bytes, need 4
	_, err := r.readUint32()
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

// --- newWireReader / newWireWriter constructors ---

func TestNewWireReaderConstructor(t *testing.T) {
	buf := []byte{0x01, 0x02}
	r := newWireReader(buf)
	if r.offset != 0 {
		t.Errorf("initial offset should be 0, got %d", r.offset)
	}
	if r.remaining() != 2 {
		t.Errorf("remaining should be 2, got %d", r.remaining())
	}
}

func TestNewWireWriterConstructor(t *testing.T) {
	buf := make([]byte, 100)
	w := newWireWriter(buf)
	if w.offset != 0 {
		t.Errorf("initial offset should be 0, got %d", w.offset)
	}
	if w.compressed == nil {
		t.Error("compressed map should be initialized")
	}
}

// Cover Pack error paths: buffer too small to pack questions and each RR section.
func TestPackBufferTooSmallForQuestion(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1},
		Questions: []Question{{
			Name:  "example.com",
			Type:  TypeA,
			Class: ClassIN,
		}},
	}
	// 12 bytes is exactly enough for the header, but not for the question name
	buf := make([]byte, 12)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for question name, got %v", err)
	}
}

func TestPackBufferTooSmallForAnswers(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1},
		Answers: []ResourceRecord{{
			Name:     "a.com",
			Type:     TypeA,
			Class:    ClassIN,
			TTL:      300,
			RDLength: 4,
			RData:    []byte{1, 2, 3, 4},
		}},
	}
	// Just barely enough for the header but not the answer RR
	buf := make([]byte, 13)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for answer section, got %v", err)
	}
}

func TestPackBufferTooSmallForAuthority(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1},
		Authority: []ResourceRecord{{
			Name:     "a.com",
			Type:     TypeNS,
			Class:    ClassIN,
			TTL:      300,
			RDLength: 4,
			RData:    encodePlainName("ns.a.com"),
		}},
	}
	buf := make([]byte, 13)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for authority section, got %v", err)
	}
}

func TestPackBufferTooSmallForAdditional(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1},
		Additional: []ResourceRecord{{
			Name:     "a.com",
			Type:     TypeA,
			Class:    ClassIN,
			TTL:      300,
			RDLength: 4,
			RData:    []byte{1, 2, 3, 4},
		}},
	}
	buf := make([]byte, 13)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for additional section, got %v", err)
	}
}

// Cover packRData: SOA with broken mname (DecodeName fails, fallback to writeBytes)
func TestPackRData_SOA_BrokenMName(t *testing.T) {
	// RData with a label that says length 63 but actual data is short
	rdata := []byte{0x3F, 'a', 'b', 'c'}
	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeSOA,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:    Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Authority: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Authority) != 1 {
		t.Fatalf("expected 1 authority, got %d", len(unpacked.Authority))
	}
}

// Cover packRData: SOA with broken rname (mname decodes OK, rname fails)
func TestPackRData_SOA_BrokenRName(t *testing.T) {
	var rdata []byte
	rdata = append(rdata, 0x02, 'n', 's', 0x00)  // valid mname "ns"
	rdata = append(rdata, 0x3F, 'x', 'y')         // broken rname: label says 63 but only 2 bytes
	rdata = append(rdata, make([]byte, 20)...)     // pad

	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeSOA,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:    Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Authority: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Authority) != 1 {
		t.Fatalf("expected 1 authority, got %d", len(unpacked.Authority))
	}
}

// Cover the EDNS0 extraction loop in Unpack with an OPT record containing options
func TestUnpackMessageWithEDNSOptions(t *testing.T) {
	// Build an OPT record with RDATA options
	var rdata []byte
	// Option: code=10, length=3, data=[0xAA, 0xBB, 0xCC]
	rdata = append(rdata, 0x00, 0x0A) // code=10
	rdata = append(rdata, 0x00, 0x03) // length=3
	rdata = append(rdata, 0xAA, 0xBB, 0xCC)

	opt := ResourceRecord{
		Name:     "",
		Type:     TypeOPT,
		Class:    4096,
		TTL:      1 << 15, // DO flag set
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}

	msg := &Message{
		Header: Header{
			ID:    0xBEEF,
			Flags: NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []Question{{
			Name:  "test.com",
			Type:  TypeA,
			Class: ClassIN,
		}},
		Additional: []ResourceRecord{opt},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}

	if unpacked.EDNS0 == nil {
		t.Fatal("EDNS0 should be extracted")
	}
	if !unpacked.EDNS0.DOFlag {
		t.Error("DO flag should be true")
	}
	if unpacked.EDNS0.UDPSize != 4096 {
		t.Errorf("UDPSize: expected 4096, got %d", unpacked.EDNS0.UDPSize)
	}
	if len(unpacked.EDNS0.Options) != 1 {
		t.Fatalf("expected 1 EDNS option, got %d", len(unpacked.EDNS0.Options))
	}
	if unpacked.EDNS0.Options[0].Code != 10 {
		t.Errorf("option code: expected 10, got %d", unpacked.EDNS0.Options[0].Code)
	}
	if len(unpacked.EDNS0.Options[0].Data) != 3 {
		t.Errorf("option data length: expected 3, got %d", len(unpacked.EDNS0.Options[0].Data))
	}
}

// --- Unpack error paths ---

func TestUnpackBadHeader(t *testing.T) {
	// 11 bytes: too short for 12-byte header
	buf := make([]byte, 11)
	_, err := Unpack(buf)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestUnpackBadQuestion(t *testing.T) {
	// Valid header saying 1 question, but question name is truncated
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:], 1) // QDCount=1
	buf = append(buf, header...)
	buf = append(buf, 0x03, 'a', 'b') // truncated name
	_, err := Unpack(buf)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for bad question, got %v", err)
	}
}

func TestUnpackBadAnswer(t *testing.T) {
	// Valid header + valid question, but answer section is truncated
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:], 1) // QDCount=1
	binary.BigEndian.PutUint16(header[6:], 1) // ANCount=1
	buf = append(buf, header...)
	// Question: root name, Type A, Class IN
	buf = append(buf, 0x00)           // root name
	buf = append(buf, 0x00, 0x01)     // Type A
	buf = append(buf, 0x00, 0x01)     // Class IN
	// No answer data (but header says ANCount=1)
	_, err := Unpack(buf)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for bad answer, got %v", err)
	}
}

func TestUnpackBadAuthority(t *testing.T) {
	// Valid header + 0 questions + 0 answers + 1 authority (truncated)
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[8:], 1) // NSCount=1
	buf = append(buf, header...)
	// No authority data
	_, err := Unpack(buf)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for bad authority, got %v", err)
	}
}

func TestUnpackBadAdditional(t *testing.T) {
	// Valid header + 0 questions + 0 answers + 0 authority + 1 additional (truncated)
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[10:], 1) // ARCount=1
	buf = append(buf, header...)
	// No additional data
	_, err := Unpack(buf)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for bad additional, got %v", err)
	}
}

// --- Pack error paths for question type/class ---

func TestPackBufferTooSmallForQuestionType(t *testing.T) {
	// Buffer: 12 (header) + 16 ("example.com" encoded) = 28. Need 2 more for type.
	// "example.com" = \x07 example \x03 com \x00 = 13 bytes
	msg := &Message{
		Header: Header{ID: 1},
		Questions: []Question{{
			Name:  "example.com",
			Type:  TypeA,
			Class: ClassIN,
		}},
	}
	// 12 header + 13 name = 25. Type needs 2 more → buf of 25 fails at type
	buf := make([]byte, 25)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for question type, got %v", err)
	}
}

func TestPackBufferTooSmallForQuestionClass(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1},
		Questions: []Question{{
			Name:  "example.com",
			Type:  TypeA,
			Class: ClassIN,
		}},
	}
	// 12 header + 13 name + 2 type = 27. Class needs 2 more → buf of 27 fails at class
	buf := make([]byte, 27)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for question class, got %v", err)
	}
}

// --- Pack error paths for RR fields (type/class/TTL/packRData) ---

func TestPackBufferTooSmallForRRType(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1},
		Answers: []ResourceRecord{{
			Name:     "a",
			Type:     TypeA,
			Class:    ClassIN,
			TTL:      300,
			RDLength: 4,
			RData:    []byte{1, 2, 3, 4},
		}},
	}
	// 12 header + 3 name ("a" = \x01 a \x00) = 15. Type needs 2 more → 15 fails at type
	buf := make([]byte, 15)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for RR type, got %v", err)
	}
}

func TestPackBufferTooSmallForRRClass(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1},
		Answers: []ResourceRecord{{
			Name:     "a",
			Type:     TypeA,
			Class:    ClassIN,
			TTL:      300,
			RDLength: 4,
			RData:    []byte{1, 2, 3, 4},
		}},
	}
	// 12 header + 3 name + 2 type = 17. Class needs 2 → 17 fails at class
	buf := make([]byte, 17)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for RR class, got %v", err)
	}
}

func TestPackBufferTooSmallForRRTTL(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1},
		Answers: []ResourceRecord{{
			Name:     "a",
			Type:     TypeA,
			Class:    ClassIN,
			TTL:      300,
			RDLength: 4,
			RData:    []byte{1, 2, 3, 4},
		}},
	}
	// 12 header + 3 name + 2 type + 2 class = 19. TTL needs 4 → 19 fails at TTL
	buf := make([]byte, 19)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for RR TTL, got %v", err)
	}
}

func TestPackBufferTooSmallForRRRData(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 1},
		Answers: []ResourceRecord{{
			Name:     "a",
			Type:     TypeA,
			Class:    ClassIN,
			TTL:      300,
			RDLength: 4,
			RData:    []byte{1, 2, 3, 4},
		}},
	}
	// 12 header + 3 name + 2 type + 2 class + 4 TTL = 23.
	// packRData needs 2 for rdlength placeholder → 23 fails at rdlength
	buf := make([]byte, 23)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for RR RDATA, got %v", err)
	}
}

// --- packRData error paths ---

func TestPackRData_NS_DecodeFailWriteBytesFallback(t *testing.T) {
	// Give NS record RDATA that doesn't decode as a valid name,
	// so it falls through to w.writeBytes(rr.RData)
	rdata := []byte{0x3F, 'x', 'y'} // label says 63, but only 2 bytes
	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeNS,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	packed, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("expected 1 answer")
	}
}

func TestPackRData_MX_DecodeFailWriteBytesFallback(t *testing.T) {
	// MX with valid preference but invalid exchange name
	rdata := []byte{0x00, 0x0A, 0x3F, 'x', 'y'} // pref=10, bad name
	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeMX,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	_, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}
}

func TestPackRData_SRV_DecodeFailWriteBytesFallback(t *testing.T) {
	// SRV with valid header but invalid target name
	var rdata []byte
	rdata = append(rdata, 0x00, 0x01) // priority
	rdata = append(rdata, 0x00, 0x02) // weight
	rdata = append(rdata, 0x00, 0x50) // port
	rdata = append(rdata, 0x3F, 'x')  // bad name: label says 63 but only 1 byte
	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeSRV,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	buf := make([]byte, 4096)
	_, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}
}

// Test packRData buffer overflow on MX preference writeBytes
func TestPackRData_MX_BufferOverflowPref(t *testing.T) {
	nameBytes := encodePlainName("mail.com")
	rdata := make([]byte, 2+len(nameBytes))
	binary.BigEndian.PutUint16(rdata, 10)
	copy(rdata[2:], nameBytes)

	rr := ResourceRecord{
		Name:     "a",
		Type:     TypeMX,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	// 12 header + 3 name + 2 type + 2 class + 4 TTL + 2 rdlength = 25
	// Then MX pref writeBytes needs 2 more → 25 fails
	buf := make([]byte, 25)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for MX pref, got %v", err)
	}
}

// Test packRData buffer overflow on SOA encode mname
func TestPackRData_SOA_BufferOverflowMName(t *testing.T) {
	mnameBytes := encodePlainName("ns.a.com")
	rnameBytes := encodePlainName("admin.a.com")
	serials := make([]byte, 20)
	rdata := make([]byte, 0, len(mnameBytes)+len(rnameBytes)+20)
	rdata = append(rdata, mnameBytes...)
	rdata = append(rdata, rnameBytes...)
	rdata = append(rdata, serials...)

	rr := ResourceRecord{
		Name:     "a",
		Type:     TypeSOA,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:    Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Authority: []ResourceRecord{rr},
	}

	// 12 header + 3 name + 2 type + 2 class + 4 TTL + 2 rdlength = 25
	// SOA mname encoding starts here but buffer is too small
	buf := make([]byte, 25)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for SOA mname encode, got %v", err)
	}
}

// Test packRData buffer overflow on SOA encode rname
func TestPackRData_SOA_BufferOverflowRName(t *testing.T) {
	mnameBytes := encodePlainName("n")
	rnameBytes := encodePlainName("admin.example.com")
	serials := make([]byte, 20)
	rdata := make([]byte, 0, len(mnameBytes)+len(rnameBytes)+20)
	rdata = append(rdata, mnameBytes...)
	rdata = append(rdata, rnameBytes...)
	rdata = append(rdata, serials...)

	rr := ResourceRecord{
		Name:     "a",
		Type:     TypeSOA,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:    Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Authority: []ResourceRecord{rr},
	}

	// 12 header + 3 name("a") + 2 type + 2 class + 4 TTL + 2 rdlength = 25
	// mname "n" = \x01 n \x00 = 3 bytes → offset 28
	// rname needs "admin.example.com" = 19 bytes but we only have ~2 bytes left
	buf := make([]byte, 29)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for SOA rname encode, got %v", err)
	}
}

// Test packRData buffer overflow on SRV header writeBytes
func TestPackRData_SRV_BufferOverflowHeader(t *testing.T) {
	nameBytes := encodePlainName("srv.com")
	rdata := make([]byte, 6+len(nameBytes))
	binary.BigEndian.PutUint16(rdata[0:], 1)
	binary.BigEndian.PutUint16(rdata[2:], 2)
	binary.BigEndian.PutUint16(rdata[4:], 80)
	copy(rdata[6:], nameBytes)

	rr := ResourceRecord{
		Name:     "a",
		Type:     TypeSRV,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	// 12 header + 3 name + 2 type + 2 class + 4 TTL + 2 rdlength = 25
	// SRV header writeBytes needs 6 → buffer of 25 fails
	buf := make([]byte, 25)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for SRV header, got %v", err)
	}
}

// Test packRData: default type (raw bytes) buffer overflow
func TestPackRData_Default_BufferOverflow(t *testing.T) {
	rr := ResourceRecord{
		Name:     "a",
		Type:     TypeA,
		Class:    ClassIN,
		TTL:      300,
		RDLength: 4,
		RData:    []byte{1, 2, 3, 4},
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	// 12 header + 3 name + 2 type + 2 class + 4 TTL + 2 rdlength = 25
	// Then 4 bytes of A record RDATA → needs 29. Give 26 to fail on raw writeBytes
	buf := make([]byte, 26)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for default RDATA, got %v", err)
	}
}
