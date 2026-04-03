package dns

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// =============================================================================
// rdata.go coverage: ParseRRSIG error paths
// =============================================================================

func TestParseRRSIG_VeryShort(t *testing.T) {
	// Even shorter than the existing TooShort test (only 2 bytes)
	_, err := ParseRRSIG([]byte{0x00, 0x01}, 0)
	if err == nil {
		t.Fatal("expected error for short RRSIG RDATA")
	}
}

func TestParseRRSIG_NoSignature(t *testing.T) {
	// 18 bytes fixed + signer name but no signature after name
	var rdata []byte
	rdata = append(rdata, make([]byte, 18)...)
	rdata = append(rdata, encodePlainName("example.com")...)

	rec, err := ParseRRSIG(rdata, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Signature != nil {
		t.Errorf("expected nil signature, got %v", rec.Signature)
	}
}

func TestParseRRSIG_BadSignerName(t *testing.T) {
	// 18 fixed bytes + truncated signer name
	var rdata []byte
	rdata = append(rdata, make([]byte, 18)...)
	rdata = append(rdata, 0x3F, 'x') // label says 63, only 1 byte follows

	_, err := ParseRRSIG(rdata, 0)
	if err == nil {
		t.Fatal("expected error for bad signer name in RRSIG")
	}
}

// =============================================================================
// rdata.go coverage: ParseNSEC error and edge paths
// =============================================================================

func TestParseNSEC_Empty(t *testing.T) {
	_, err := ParseNSEC([]byte{}, 0)
	if err == nil {
		t.Fatal("expected error for empty NSEC RDATA")
	}
}

func TestParseNSEC_BadName(t *testing.T) {
	// Truncated name: label says 63 but only 1 byte of data
	rdata := []byte{0x3F, 'x'}
	_, err := ParseNSEC(rdata, 0)
	if err == nil {
		t.Fatal("expected error for bad NSEC next domain name")
	}
}

func TestParseNSEC_ValidWithBitmap(t *testing.T) {
	// Valid next domain name + type bitmap for types A(1) and AAAA(28)
	var rdata []byte
	rdata = append(rdata, encodePlainName("next.example.com")...)
	// Type bitmap: window=0, bitmap length=4
	// Type A=1 => byte 0, bit 6 => 0x40
	// Type AAAA=28 => byte 3, bit 4 => 0x08
	rdata = append(rdata, 0x00, 0x04, 0x40, 0x00, 0x00, 0x08)

	rec, err := ParseNSEC(rdata, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.NextDomainName != "next.example.com" {
		t.Errorf("NextDomainName: expected 'next.example.com', got '%s'", rec.NextDomainName)
	}
	// Should have types A(1) and AAAA(28)
	found := make(map[uint16]bool)
	for _, tp := range rec.TypeBitMaps {
		found[tp] = true
	}
	if !found[TypeA] {
		t.Error("expected TypeA in TypeBitMaps")
	}
	if !found[TypeAAAA] {
		t.Error("expected TypeAAAA in TypeBitMaps")
	}
}

// =============================================================================
// rdata.go coverage: ParseNSEC3 error paths
// =============================================================================

func TestParseNSEC3_VeryShort(t *testing.T) {
	_, err := ParseNSEC3([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for short NSEC3 RDATA")
	}
}

func TestParseNSEC3_SaltOverflow(t *testing.T) {
	// salt length says 200 but only a few bytes follow
	rdata := []byte{
		0x01,       // HashAlgorithm
		0x00,       // Flags
		0x00, 0x0A, // Iterations=10
		0xC8,       // SaltLength=200 (overflows)
		0x01, 0x02, // only 2 bytes of data
	}
	_, err := ParseNSEC3(rdata)
	if err == nil {
		t.Fatal("expected error for salt overflow")
	}
}

func TestParseNSEC3_TruncatedAtHashLength(t *testing.T) {
	// Valid header + 0-length salt, then truncated before hash length byte
	rdata := []byte{
		0x01,       // HashAlgorithm
		0x00,       // Flags
		0x00, 0x0A, // Iterations=10
		0x00,       // SaltLength=0
		// no hash length byte follows
	}
	_, err := ParseNSEC3(rdata)
	if err == nil {
		t.Fatal("expected error for truncated NSEC3 at hash length")
	}
}

func TestParseNSEC3_NextHashOverflow(t *testing.T) {
	// Valid header + 0-length salt + hash length says 200 but only 2 bytes follow
	rdata := []byte{
		0x01,       // HashAlgorithm
		0x00,       // Flags
		0x00, 0x0A, // Iterations=10
		0x00,       // SaltLength=0
		0xC8,       // HashLength=200 (overflows)
		0x01, 0x02, // only 2 bytes
	}
	_, err := ParseNSEC3(rdata)
	if err == nil {
		t.Fatal("expected error for next hash overflow")
	}
}

func TestParseNSEC3_ValidWithSaltAndHash(t *testing.T) {
	var rdata []byte
	rdata = append(rdata, 0x01)       // HashAlgorithm
	rdata = append(rdata, 0x01)       // Flags (opt-out)
	rdata = append(rdata, 0x00, 0x0A) // Iterations=10
	rdata = append(rdata, 0x04)       // SaltLength=4
	rdata = append(rdata, 0xAA, 0xBB, 0xCC, 0xDD) // Salt
	rdata = append(rdata, 0x03)       // HashLength=3
	rdata = append(rdata, 0x11, 0x22, 0x33)        // NextHash
	// Type bitmap: window=0, length=1, bitmap=0x40 (type A=1)
	rdata = append(rdata, 0x00, 0x01, 0x40)

	rec, err := ParseNSEC3(rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.HashAlgorithm != 1 {
		t.Errorf("HashAlgorithm: expected 1, got %d", rec.HashAlgorithm)
	}
	if rec.Flags != 1 {
		t.Errorf("Flags: expected 1, got %d", rec.Flags)
	}
	if rec.Iterations != 10 {
		t.Errorf("Iterations: expected 10, got %d", rec.Iterations)
	}
	if !bytes.Equal(rec.Salt, []byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Errorf("Salt mismatch: %v", rec.Salt)
	}
	if !bytes.Equal(rec.NextHash, []byte{0x11, 0x22, 0x33}) {
		t.Errorf("NextHash mismatch: %v", rec.NextHash)
	}
	if len(rec.TypeBitMaps) == 0 {
		t.Error("expected non-empty TypeBitMaps")
	}
}

// =============================================================================
// rdata.go coverage: parseTypeBitMaps bitmap overflow (break path)
// =============================================================================

func TestParseTypeBitMaps_BitmapOverflow(t *testing.T) {
	// Window header says bitmap length=10, but only 2 bytes of data follow
	data := []byte{0x00, 0x0A, 0x40, 0x01}
	types := parseTypeBitMaps(data)
	// Should parse what's available and break when overflow detected
	// The two bytes that ARE there: 0x40 => type 1 (A), 0x01 => type 15 (MX)
	// But since bitmapLen=10 > remaining 2 bytes, the loop breaks
	if len(types) != 0 {
		t.Errorf("expected empty result due to overflow, got %v", types)
	}
}

func TestParseTypeBitMaps_SingleByteTruncated(t *testing.T) {
	// Only 1 byte, need at least 2 for window + bitmap length
	data := []byte{0x00}
	types := parseTypeBitMaps(data)
	if len(types) != 0 {
		t.Errorf("expected empty, got %v", types)
	}
}

// =============================================================================
// record.go coverage: UnpackRR for RRSIG type
// =============================================================================

func TestUnpackRR_RRSIG_Compressed(t *testing.T) {
	// Build RRSIG RDATA with a compressed signer name pointing to "example.com" at offset 12
	var rdata []byte
	fixed := make([]byte, 18)
	binary.BigEndian.PutUint16(fixed[0:], TypeA) // TypeCovered
	fixed[2] = 8                                  // Algorithm
	fixed[3] = 2                                  // Labels
	binary.BigEndian.PutUint32(fixed[4:], 300)    // OrigTTL
	binary.BigEndian.PutUint32(fixed[8:], 1700000000)
	binary.BigEndian.PutUint32(fixed[12:], 1699000000)
	binary.BigEndian.PutUint16(fixed[16:], 54321) // KeyTag
	rdata = append(rdata, fixed...)
	rdata = append(rdata, 0xC0, 0x0C) // compressed pointer to "example.com" at offset 12
	rdata = append(rdata, 0xAA, 0xBB, 0xCC) // signature bytes

	msg, off := buildMsgWithAnswer(TypeRRSIG, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Type != TypeRRSIG {
		t.Fatalf("Type: expected %d, got %d", TypeRRSIG, rr.Type)
	}

	// Verify decompressed RDATA: 18 fixed bytes + plain "example.com" + signature
	nameBytes := encodePlainName("example.com")
	expectedLen := 18 + len(nameBytes) + 3
	if len(rr.RData) != expectedLen {
		t.Fatalf("RRSIG RDATA length: expected %d, got %d", expectedLen, len(rr.RData))
	}
	// Verify signer name was decompressed
	signerName, nameEnd, err := DecodeName(rr.RData, 18)
	if err != nil {
		t.Fatalf("failed to decode signer name: %v", err)
	}
	if signerName != "example.com" {
		t.Errorf("signer name: expected 'example.com', got '%s'", signerName)
	}
	// Verify signature
	if !bytes.Equal(rr.RData[nameEnd:], []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("signature mismatch: got %v", rr.RData[nameEnd:])
	}
}

func TestUnpackRR_RRSIG_NoSignature(t *testing.T) {
	// RRSIG with compressed signer name but no signature bytes after it
	var rdata []byte
	rdata = append(rdata, make([]byte, 18)...)
	rdata = append(rdata, 0xC0, 0x0C) // compressed pointer to "example.com"

	msg, off := buildMsgWithAnswer(TypeRRSIG, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have 18 fixed bytes + plain "example.com" + no signature
	nameBytes := encodePlainName("example.com")
	expectedLen := 18 + len(nameBytes)
	if len(rr.RData) != expectedLen {
		t.Fatalf("RRSIG RDATA length: expected %d, got %d", expectedLen, len(rr.RData))
	}
}

func TestUnpackRR_RRSIG_BadSignerName(t *testing.T) {
	// RRSIG with bad compressed signer name → fallback to raw copy
	var rdata []byte
	rdata = append(rdata, make([]byte, 18)...)
	rdata = append(rdata, 0xC0, 0xFF) // bad pointer
	rdata = append(rdata, 0xAA)       // some trailing byte

	msg, off := buildMsgWithAnswer(TypeRRSIG, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fallback to raw copy
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("RRSIG fallback RDATA mismatch")
	}
}

func TestUnpackRR_RRSIG_TooShort(t *testing.T) {
	// RRSIG with < 18 bytes RDATA → fallback to raw copy
	rdata := make([]byte, 10)
	msg, off := buildMsgWithAnswer(TypeRRSIG, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("RRSIG short RDATA should be raw copy")
	}
}

// =============================================================================
// record.go coverage: UnpackRR for NSEC type
// =============================================================================

func TestUnpackRR_NSEC_Compressed(t *testing.T) {
	// NSEC RDATA: compressed next domain name + type bitmaps
	var rdata []byte
	rdata = append(rdata, 0xC0, 0x0C) // compressed pointer to "example.com"
	// Type bitmap: window=0, length=1, bitmap=0x40 (type A=1)
	rdata = append(rdata, 0x00, 0x01, 0x40)

	msg, off := buildMsgWithAnswer(TypeNSEC, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Type != TypeNSEC {
		t.Fatalf("Type: expected %d, got %d", TypeNSEC, rr.Type)
	}

	// Verify decompressed RDATA: plain "example.com" + type bitmap
	nameBytes := encodePlainName("example.com")
	expectedLen := len(nameBytes) + 3
	if len(rr.RData) != expectedLen {
		t.Fatalf("NSEC RDATA length: expected %d, got %d", expectedLen, len(rr.RData))
	}
	name, nameEnd, err := DecodeName(rr.RData, 0)
	if err != nil {
		t.Fatalf("failed to decode next domain name: %v", err)
	}
	if name != "example.com" {
		t.Errorf("next domain name: expected 'example.com', got '%s'", name)
	}
	// Verify bitmap is preserved
	if !bytes.Equal(rr.RData[nameEnd:], []byte{0x00, 0x01, 0x40}) {
		t.Errorf("NSEC bitmap mismatch: got %v", rr.RData[nameEnd:])
	}
}

func TestUnpackRR_NSEC_NoBitmap(t *testing.T) {
	// NSEC RDATA: compressed name only, no type bitmap after
	rdata := []byte{0xC0, 0x0C} // compressed pointer to "example.com"

	msg, off := buildMsgWithAnswer(TypeNSEC, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should be just the plain name
	nameBytes := encodePlainName("example.com")
	if len(rr.RData) != len(nameBytes) {
		t.Fatalf("NSEC RDATA length: expected %d, got %d", len(nameBytes), len(rr.RData))
	}
}

func TestUnpackRR_NSEC_BadName(t *testing.T) {
	// NSEC with bad compressed pointer → fallback to raw copy
	rdata := []byte{0xC0, 0xFF} // bad pointer

	msg, off := buildMsgWithAnswer(TypeNSEC, rdata)

	rr, _, err := UnpackRR(msg, off)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(rr.RData, rdata) {
		t.Errorf("NSEC fallback RDATA mismatch")
	}
}

// =============================================================================
// wire.go coverage: packRData for RRSIG type
// =============================================================================

func TestPackRData_RRSIG(t *testing.T) {
	// Build RRSIG RDATA with plain signer name + signature
	var rdata []byte
	fixed := make([]byte, 18)
	binary.BigEndian.PutUint16(fixed[0:], TypeA) // TypeCovered
	fixed[2] = 8                                  // Algorithm
	fixed[3] = 2                                  // Labels
	binary.BigEndian.PutUint32(fixed[4:], 300)
	binary.BigEndian.PutUint32(fixed[8:], 1700000000)
	binary.BigEndian.PutUint32(fixed[12:], 1699000000)
	binary.BigEndian.PutUint16(fixed[16:], 12345)
	rdata = append(rdata, fixed...)
	rdata = append(rdata, encodePlainName("signer.example.com")...)
	rdata = append(rdata, 0xDE, 0xAD) // signature

	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeRRSIG,
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

	// Parse the RRSIG from the decompressed answer
	ans := unpacked.Answers[0]
	rec, err := ParseRRSIG(ans.RData, 0)
	if err != nil {
		t.Fatalf("ParseRRSIG error: %v", err)
	}
	if rec.SignerName != "signer.example.com" {
		t.Errorf("signer name: expected 'signer.example.com', got '%s'", rec.SignerName)
	}
	if !bytes.Equal(rec.Signature, []byte{0xDE, 0xAD}) {
		t.Errorf("signature mismatch: got %v", rec.Signature)
	}
}

func TestPackRData_RRSIG_NoSignature(t *testing.T) {
	// RRSIG with signer name but no trailing signature
	var rdata []byte
	rdata = append(rdata, make([]byte, 18)...)
	rdata = append(rdata, encodePlainName("signer.com")...)

	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeRRSIG,
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
}

func TestPackRData_RRSIG_BadSignerName(t *testing.T) {
	// RRSIG with bad signer name → fallback to raw writeBytes
	var rdata []byte
	rdata = append(rdata, make([]byte, 18)...)
	rdata = append(rdata, 0x3F, 'x', 'y') // label says 63, only 2 bytes
	rdata = append(rdata, make([]byte, 5)...)

	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeRRSIG,
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

func TestPackRData_RRSIG_Short(t *testing.T) {
	// RRSIG with < 18 bytes → fallback to raw writeBytes
	rdata := make([]byte, 10)
	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeRRSIG,
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

func TestPackRData_RRSIG_BufferOverflowFixed(t *testing.T) {
	// Buffer overflow when writing the 18 fixed bytes of RRSIG
	var rdata []byte
	rdata = append(rdata, make([]byte, 18)...)
	rdata = append(rdata, encodePlainName("s.com")...)
	rdata = append(rdata, 0xAA)

	rr := ResourceRecord{
		Name:     "a",
		Type:     TypeRRSIG,
		Class:    ClassIN,
		TTL:      300,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	msg := &Message{
		Header:  Header{Flags: NewFlagBuilder().SetQR(true).Build()},
		Answers: []ResourceRecord{rr},
	}

	// 12 header + 3 name("a") + 2 type + 2 class + 4 TTL + 2 rdlength = 25
	// 18 fixed RRSIG bytes don't fit
	buf := make([]byte, 26)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull, got %v", err)
	}
}

func TestPackRData_RRSIG_BufferOverflowSignerName(t *testing.T) {
	// Buffer large enough for 18 fixed bytes but not the signer name
	var rdata []byte
	rdata = append(rdata, make([]byte, 18)...)
	rdata = append(rdata, encodePlainName("very.long.signer.name.example.com")...)
	rdata = append(rdata, 0xAA)

	rr := ResourceRecord{
		Name:     "a",
		Type:     TypeRRSIG,
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
	// + 18 fixed = 43, signer name needs more
	buf := make([]byte, 44)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for signer name, got %v", err)
	}
}

// =============================================================================
// wire.go coverage: packRData for NSEC type
// =============================================================================

func TestPackRData_NSEC(t *testing.T) {
	// Build NSEC RDATA: plain next domain name + type bitmap
	var rdata []byte
	rdata = append(rdata, encodePlainName("next.example.com")...)
	// Type bitmap: window=0, length=1, bitmap=0x40 (type A=1)
	rdata = append(rdata, 0x00, 0x01, 0x40)

	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeNSEC,
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

	// Parse the NSEC
	nsec, err := ParseNSEC(unpacked.Authority[0].RData, 0)
	if err != nil {
		t.Fatalf("ParseNSEC error: %v", err)
	}
	if nsec.NextDomainName != "next.example.com" {
		t.Errorf("next domain name: expected 'next.example.com', got '%s'", nsec.NextDomainName)
	}
}

func TestPackRData_NSEC_NoBitmap(t *testing.T) {
	// NSEC with just a name, no bitmap
	rdata := encodePlainName("next.com")

	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeNSEC,
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

func TestPackRData_NSEC_BadName(t *testing.T) {
	// NSEC with bad domain name → fallback to raw writeBytes
	rdata := []byte{0x3F, 'x', 'y'} // label says 63, only 2 bytes

	rr := ResourceRecord{
		Name:     "example.com",
		Type:     TypeNSEC,
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
	_, err := Pack(msg, buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}
}

func TestPackRData_NSEC_BufferOverflowName(t *testing.T) {
	// Buffer overflow when encoding the next domain name
	var rdata []byte
	rdata = append(rdata, encodePlainName("next.example.com")...)
	rdata = append(rdata, 0x00, 0x01, 0x40) // bitmap

	rr := ResourceRecord{
		Name:     "a",
		Type:     TypeNSEC,
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
	// Name encoding starts here, but buffer is too small
	buf := make([]byte, 26)
	_, err := Pack(msg, buf)
	if err != errBufferFull {
		t.Fatalf("expected errBufferFull for NSEC name encoding, got %v", err)
	}
}

// =============================================================================
// Full round-trip: Pack/Unpack message with RRSIG and NSEC records
// =============================================================================

func TestPackUnpackRoundTrip_RRSIG_NSEC(t *testing.T) {
	// Build a message with RRSIG answer + NSEC authority
	var rrsigRData []byte
	fixed := make([]byte, 18)
	binary.BigEndian.PutUint16(fixed[0:], TypeA)
	fixed[2] = 8
	fixed[3] = 2
	binary.BigEndian.PutUint32(fixed[4:], 300)
	binary.BigEndian.PutUint32(fixed[8:], 1700000000)
	binary.BigEndian.PutUint32(fixed[12:], 1699000000)
	binary.BigEndian.PutUint16(fixed[16:], 11111)
	rrsigRData = append(rrsigRData, fixed...)
	rrsigRData = append(rrsigRData, encodePlainName("example.com")...)
	rrsigRData = append(rrsigRData, 0x01, 0x02, 0x03, 0x04)

	var nsecRData []byte
	nsecRData = append(nsecRData, encodePlainName("z.example.com")...)
	nsecRData = append(nsecRData, 0x00, 0x01, 0x40) // type A

	msg := &Message{
		Header: Header{
			ID:    0xBEEF,
			Flags: NewFlagBuilder().SetQR(true).SetAA(true).Build(),
		},
		Questions: []Question{{
			Name:  "example.com",
			Type:  TypeA,
			Class: ClassIN,
		}},
		Answers: []ResourceRecord{{
			Name:     "example.com",
			Type:     TypeRRSIG,
			Class:    ClassIN,
			TTL:      300,
			RDLength: uint16(len(rrsigRData)),
			RData:    rrsigRData,
		}},
		Authority: []ResourceRecord{{
			Name:     "example.com",
			Type:     TypeNSEC,
			Class:    ClassIN,
			TTL:      300,
			RDLength: uint16(len(nsecRData)),
			RData:    nsecRData,
		}},
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
	if unpacked.Answers[0].Type != TypeRRSIG {
		t.Errorf("answer type: expected RRSIG, got %d", unpacked.Answers[0].Type)
	}
	if len(unpacked.Authority) != 1 {
		t.Fatalf("expected 1 authority, got %d", len(unpacked.Authority))
	}
	if unpacked.Authority[0].Type != TypeNSEC {
		t.Errorf("authority type: expected NSEC, got %d", unpacked.Authority[0].Type)
	}
}
