package dns

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// --- Helper: build a minimal DNS message with one question + one answer RR ---
// The question is for "example.com" so the answer can use a compressed pointer.
// Returns (fullMsg, answerOffset).
func buildMsgWithAnswer(rrType uint16, rdataBytes []byte) ([]byte, int) {
	var buf []byte

	// -- Header (12 bytes) --
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:], 0x1234)  // ID
	binary.BigEndian.PutUint16(header[2:], 0x8180)  // Flags: QR=1, RD=1, RA=1
	binary.BigEndian.PutUint16(header[4:], 1)        // QDCount
	binary.BigEndian.PutUint16(header[6:], 1)        // ANCount
	binary.BigEndian.PutUint16(header[8:], 0)        // NSCount
	binary.BigEndian.PutUint16(header[10:], 0)       // ARCount
	buf = append(buf, header...)

	// -- Question: "example.com" A IN --
	// "example.com" starts at offset 12
	qname := []byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}
	buf = append(buf, qname...)
	buf = append(buf, 0x00, 0x01) // Type A
	buf = append(buf, 0x00, 0x01) // Class IN

	answerOffset := len(buf)

	// -- Answer RR --
	// Name: pointer to offset 12 ("example.com")
	buf = append(buf, 0xC0, 0x0C)
	// Type
	t := make([]byte, 2)
	binary.BigEndian.PutUint16(t, rrType)
	buf = append(buf, t...)
	// Class IN
	buf = append(buf, 0x00, 0x01)
	// TTL
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 300)
	buf = append(buf, ttl...)
	// RDLength
	rdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlen, uint16(len(rdataBytes)))
	buf = append(buf, rdlen...)
	// RData
	buf = append(buf, rdataBytes...)

	return buf, answerOffset
}

// --- encodePlainName tests ---

func TestEncodePlainNameSimple(t *testing.T) {
	got := encodePlainName("www.example.com")
	want := []byte{
		0x03, 'w', 'w', 'w',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("encodePlainName(www.example.com) = %v, want %v", got, want)
	}
}

func TestEncodePlainNameTrailingDot(t *testing.T) {
	got := encodePlainName("example.com.")
	want := []byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("encodePlainName(example.com.) = %v, want %v", got, want)
	}
}

func TestEncodePlainNameRoot(t *testing.T) {
	for _, input := range []string{"", "."} {
		got := encodePlainName(input)
		want := []byte{0x00}
		if !bytes.Equal(got, want) {
			t.Errorf("encodePlainName(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestEncodePlainNameSingleLabel(t *testing.T) {
	got := encodePlainName("localhost")
	want := []byte{0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("encodePlainName(localhost) = %v, want %v", got, want)
	}
}

// --- UnpackRR: NS with compressed RDATA ---

func TestUnpackRR_NS_Compressed(t *testing.T) {
	// RDATA contains a compressed name pointing back to "example.com" at offset 12
	rdata := []byte{0xC0, 0x0C} // pointer to offset 12
	msg, off := buildMsgWithAnswer(TypeNS, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Type != TypeNS {
		t.Fatalf("Type: expected %d, got %d", TypeNS, rr.Type)
	}
	// RDATA should be decompressed: "example.com" in plain label format
	want := encodePlainName("example.com")
	if !bytes.Equal(rr.RData, want) {
		t.Errorf("NS RDATA: got %v, want %v", rr.RData, want)
	}
}

// --- UnpackRR: CNAME with compressed RDATA ---

func TestUnpackRR_CNAME_Compressed(t *testing.T) {
	rdata := []byte{0xC0, 0x0C}
	msg, off := buildMsgWithAnswer(TypeCNAME, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Type != TypeCNAME {
		t.Fatalf("Type: expected %d, got %d", TypeCNAME, rr.Type)
	}
	want := encodePlainName("example.com")
	if !bytes.Equal(rr.RData, want) {
		t.Errorf("CNAME RDATA: got %v, want %v", rr.RData, want)
	}
}

// --- UnpackRR: PTR with compressed RDATA ---

func TestUnpackRR_PTR_Compressed(t *testing.T) {
	rdata := []byte{0xC0, 0x0C}
	msg, off := buildMsgWithAnswer(TypePTR, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Type != TypePTR {
		t.Fatalf("Type: expected %d, got %d", TypePTR, rr.Type)
	}
	want := encodePlainName("example.com")
	if !bytes.Equal(rr.RData, want) {
		t.Errorf("PTR RDATA: got %v, want %v", rr.RData, want)
	}
}

// --- UnpackRR: MX with compressed exchange name ---

func TestUnpackRR_MX_Compressed(t *testing.T) {
	// MX RDATA: 2-byte preference + compressed name
	rdata := []byte{0x00, 0x0A, 0xC0, 0x0C} // pref=10, name=pointer to offset 12
	msg, off := buildMsgWithAnswer(TypeMX, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Type != TypeMX {
		t.Fatalf("Type: expected %d, got %d", TypeMX, rr.Type)
	}
	// Check preference
	pref := binary.BigEndian.Uint16(rr.RData[0:2])
	if pref != 10 {
		t.Errorf("MX preference: expected 10, got %d", pref)
	}
	// Check decompressed name
	nameBytes := encodePlainName("example.com")
	if !bytes.Equal(rr.RData[2:], nameBytes) {
		t.Errorf("MX exchange RDATA: got %v, want %v", rr.RData[2:], nameBytes)
	}
}

// --- UnpackRR: MX with rdlength < 2 (fallback) ---

func TestUnpackRR_MX_TooShort(t *testing.T) {
	rdata := []byte{0x0A} // only 1 byte
	msg, off := buildMsgWithAnswer(TypeMX, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(rr.RData, []byte{0x0A}) {
		t.Errorf("MX short RDATA: got %v, want [0x0A]", rr.RData)
	}
}

// --- UnpackRR: SOA with compressed names ---

func TestUnpackRR_SOA_Compressed(t *testing.T) {
	// SOA RDATA: mname (ptr) + rname (ptr) + 20 bytes of serials
	// Build rdata with two compressed pointers + 20 bytes
	var rdata []byte
	rdata = append(rdata, 0xC0, 0x0C) // mname -> "example.com"
	rdata = append(rdata, 0xC0, 0x0C) // rname -> "example.com"
	// 5 x uint32 = 20 bytes: serial, refresh, retry, expire, minimum
	serials := make([]byte, 20)
	binary.BigEndian.PutUint32(serials[0:], 2024010101)
	binary.BigEndian.PutUint32(serials[4:], 3600)
	binary.BigEndian.PutUint32(serials[8:], 900)
	binary.BigEndian.PutUint32(serials[12:], 604800)
	binary.BigEndian.PutUint32(serials[16:], 86400)
	rdata = append(rdata, serials...)

	msg, off := buildMsgWithAnswer(TypeSOA, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Type != TypeSOA {
		t.Fatalf("Type: expected %d, got %d", TypeSOA, rr.Type)
	}

	// Verify decompressed SOA RDATA: mname(plain) + rname(plain) + 20 bytes
	examplePlain := encodePlainName("example.com")
	expectedLen := len(examplePlain)*2 + 20
	if len(rr.RData) != expectedLen {
		t.Fatalf("SOA RDATA length: expected %d, got %d", expectedLen, len(rr.RData))
	}
	// Check mname
	if !bytes.Equal(rr.RData[:len(examplePlain)], examplePlain) {
		t.Errorf("SOA mname mismatch")
	}
	// Check rname
	if !bytes.Equal(rr.RData[len(examplePlain):len(examplePlain)*2], examplePlain) {
		t.Errorf("SOA rname mismatch")
	}
	// Check serials
	if !bytes.Equal(rr.RData[len(examplePlain)*2:], serials) {
		t.Errorf("SOA serials mismatch")
	}
}

// --- UnpackRR: SOA with invalid mname (fallback) ---

func TestUnpackRR_SOA_BadMName(t *testing.T) {
	// RDATA with a broken name (label length says 63 but data is short)
	rdata := []byte{0x3F, 'a', 'b'} // label length 63 but only 2 data bytes
	// Pad to at least the declared length so rdlength check passes
	rdata = append(rdata, make([]byte, 30)...)
	msg, off := buildMsgWithAnswer(TypeSOA, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fall back to raw copy
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("SOA fallback RDATA mismatch")
	}
}

// --- UnpackRR: SOA with invalid rname (fallback) ---

func TestUnpackRR_SOA_BadRName(t *testing.T) {
	// Valid mname, but rname is broken
	var rdata []byte
	// Valid mname: "ns" as a plain name
	rdata = append(rdata, 0x02, 'n', 's', 0x00)
	// Invalid rname: label says 63 but truncated
	rdata = append(rdata, 0x3F, 'x')
	rdata = append(rdata, make([]byte, 30)...)
	msg, off := buildMsgWithAnswer(TypeSOA, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fallback to raw copy
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("SOA fallback (bad rname) RDATA mismatch")
	}
}

// --- UnpackRR: SOA with serials truncated (fallback) ---

func TestUnpackRR_SOA_SerialsTruncated(t *testing.T) {
	// Valid mname and rname, but not enough bytes for 20 serial bytes
	var rdata []byte
	rdata = append(rdata, 0x02, 'n', 's', 0x00)       // mname "ns"
	rdata = append(rdata, 0x05, 'a', 'd', 'm', 'i', 'n', 0x00) // rname "admin"
	rdata = append(rdata, make([]byte, 10)...)          // only 10 bytes, need 20
	msg, off := buildMsgWithAnswer(TypeSOA, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fallback to raw copy
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("SOA fallback (truncated serials) RDATA mismatch")
	}
}

// --- UnpackRR: SRV with compressed target ---

func TestUnpackRR_SRV_Compressed(t *testing.T) {
	// SRV RDATA: priority(2) + weight(2) + port(2) + compressed name
	var rdata []byte
	rdata = append(rdata, 0x00, 0x0A) // priority=10
	rdata = append(rdata, 0x00, 0x14) // weight=20
	rdata = append(rdata, 0x00, 0x50) // port=80
	rdata = append(rdata, 0xC0, 0x0C) // target -> "example.com"
	msg, off := buildMsgWithAnswer(TypeSRV, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Type != TypeSRV {
		t.Fatalf("Type: expected %d, got %d", TypeSRV, rr.Type)
	}

	// Check header fields
	if binary.BigEndian.Uint16(rr.RData[0:2]) != 10 {
		t.Errorf("SRV priority mismatch")
	}
	if binary.BigEndian.Uint16(rr.RData[2:4]) != 20 {
		t.Errorf("SRV weight mismatch")
	}
	if binary.BigEndian.Uint16(rr.RData[4:6]) != 80 {
		t.Errorf("SRV port mismatch")
	}
	// Check decompressed target
	nameBytes := encodePlainName("example.com")
	if !bytes.Equal(rr.RData[6:], nameBytes) {
		t.Errorf("SRV target RDATA: got %v, want %v", rr.RData[6:], nameBytes)
	}
}

// --- UnpackRR: SRV with rdlength < 6 (fallback) ---

func TestUnpackRR_SRV_TooShort(t *testing.T) {
	rdata := []byte{0x00, 0x01, 0x00, 0x02} // only 4 bytes
	msg, off := buildMsgWithAnswer(TypeSRV, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("SRV short RDATA: got %v, want %v", rr.RData, rdata)
	}
}

// --- UnpackRR: default type (e.g. A record) ---

func TestUnpackRR_Default_ARecord(t *testing.T) {
	rdata := []byte{192, 168, 1, 1}
	msg, off := buildMsgWithAnswer(TypeA, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Type != TypeA {
		t.Fatalf("Type: expected %d, got %d", TypeA, rr.Type)
	}
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("A RDATA: got %v, want %v", rr.RData, rdata)
	}
}

// --- UnpackRR: error paths ---

func TestUnpackRR_TruncatedName(t *testing.T) {
	// Message too short for even the name
	buf := []byte{0x03, 'a', 'b'} // label says 3 bytes, only 2 available
	_, _, err := UnpackRR(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestUnpackRR_TruncatedFixedFields(t *testing.T) {
	// Valid name but truncated after it (missing type/class/ttl/rdlen)
	buf := []byte{0x03, 'c', 'o', 'm', 0x00}
	_, _, err := UnpackRR(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for missing fixed fields, got %v", err)
	}
}

func TestUnpackRR_TruncatedAtClass(t *testing.T) {
	// Valid name + type, but missing class
	var buf []byte
	buf = append(buf, 0x03, 'c', 'o', 'm', 0x00) // name "com"
	buf = append(buf, 0x00, 0x01)                   // type A
	// no class
	_, _, err := UnpackRR(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated at class, got %v", err)
	}
}

func TestUnpackRR_TruncatedAtTTL(t *testing.T) {
	// Valid name + type + class, but missing TTL
	var buf []byte
	buf = append(buf, 0x03, 'c', 'o', 'm', 0x00) // name
	buf = append(buf, 0x00, 0x01)                   // type A
	buf = append(buf, 0x00, 0x01)                   // class IN
	// no TTL
	_, _, err := UnpackRR(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated at TTL, got %v", err)
	}
}

func TestUnpackRR_TruncatedAtRDLength(t *testing.T) {
	// Valid name + type + class + TTL, but missing RDLength
	var buf []byte
	buf = append(buf, 0x03, 'c', 'o', 'm', 0x00) // name
	buf = append(buf, 0x00, 0x01)                   // type A
	buf = append(buf, 0x00, 0x01)                   // class IN
	buf = append(buf, 0x00, 0x00, 0x01, 0x2C)       // TTL 300
	// no RDLength
	_, _, err := UnpackRR(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated at RDLength, got %v", err)
	}
}

func TestUnpackRR_RDataBeyondMessage(t *testing.T) {
	// Valid name + type + class + ttl + rdlength that exceeds remaining bytes
	var buf []byte
	buf = append(buf, 0x03, 'c', 'o', 'm', 0x00) // name
	buf = append(buf, 0x00, 0x01)                   // type A
	buf = append(buf, 0x00, 0x01)                   // class IN
	buf = append(buf, 0x00, 0x00, 0x01, 0x2C)       // TTL 300
	buf = append(buf, 0x00, 0x10)                   // rdlength=16, but no data follows
	_, _, err := UnpackRR(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for RData overflow, got %v", err)
	}
}

// --- UnpackRR: NS/CNAME/PTR with bad compressed name in RDATA (fallback to raw copy) ---

func TestUnpackRR_NS_BadCompressedName(t *testing.T) {
	// RDATA with a forward pointer (invalid) so DecodeName fails
	// Forward pointer: points to offset 0xFF which is beyond the RDATA start
	rdata := []byte{0xC0, 0xFF}
	msg, off := buildMsgWithAnswer(TypeNS, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fallback to raw copy of the RDATA
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("NS fallback RDATA: got %v, want %v", rr.RData, rdata)
	}
}

// --- UnpackRR: MX with bad exchange name (fallback) ---

func TestUnpackRR_MX_BadExchangeName(t *testing.T) {
	// Preference bytes + forward pointer
	rdata := []byte{0x00, 0x0A, 0xC0, 0xFF}
	msg, off := buildMsgWithAnswer(TypeMX, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fallback to raw copy
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("MX fallback RDATA: got %v, want %v", rr.RData, rdata)
	}
}

// --- UnpackRR: SRV with bad target name (fallback) ---

func TestUnpackRR_SRV_BadTargetName(t *testing.T) {
	var rdata []byte
	rdata = append(rdata, 0x00, 0x01) // priority
	rdata = append(rdata, 0x00, 0x02) // weight
	rdata = append(rdata, 0x00, 0x50) // port
	rdata = append(rdata, 0xC0, 0xFF) // bad pointer
	msg, off := buildMsgWithAnswer(TypeSRV, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("SRV fallback RDATA: got %v, want %v", rr.RData, rdata)
	}
}

// --- UnpackRR via full Unpack: verify all record types in a response ---

func TestUnpackFullMessage_WithNS(t *testing.T) {
	// Build NS answer with uncompressed name in RDATA
	nsName := encodePlainName("ns1.example.com")
	msg, _ := buildMsgWithAnswer(TypeNS, nsName)

	parsed, err := Unpack(msg)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answers))
	}
	if parsed.Answers[0].Type != TypeNS {
		t.Errorf("expected TypeNS, got %d", parsed.Answers[0].Type)
	}
	// Verify the RDATA was decoded as the plain name
	name, _, err := DecodeName(parsed.Answers[0].RData, 0)
	if err != nil {
		t.Fatalf("failed to decode NS RDATA: %v", err)
	}
	if name != "ns1.example.com" {
		t.Errorf("NS name: expected 'ns1.example.com', got '%s'", name)
	}
}
