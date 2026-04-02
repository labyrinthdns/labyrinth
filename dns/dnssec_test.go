package dns

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// ParseDNSKEY
// ---------------------------------------------------------------------------

func TestParseDNSKEY_Valid(t *testing.T) {
	pubkey := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	rdata := make([]byte, 4+len(pubkey))
	binary.BigEndian.PutUint16(rdata[0:2], 257) // flags (KSK)
	rdata[2] = 3                                 // protocol
	rdata[3] = 8                                 // algorithm (RSASHA256)
	copy(rdata[4:], pubkey)

	rec, err := ParseDNSKEY(rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Flags != 257 {
		t.Errorf("Flags: expected 257, got %d", rec.Flags)
	}
	if rec.Protocol != 3 {
		t.Errorf("Protocol: expected 3, got %d", rec.Protocol)
	}
	if rec.Algorithm != 8 {
		t.Errorf("Algorithm: expected 8, got %d", rec.Algorithm)
	}
	if !bytes.Equal(rec.PublicKey, pubkey) {
		t.Errorf("PublicKey: expected %x, got %x", pubkey, rec.PublicKey)
	}
}

func TestParseDNSKEY_KSK(t *testing.T) {
	// flags=257 has the SEP bit (bit 0) set -> KSK
	rdata := make([]byte, 4)
	binary.BigEndian.PutUint16(rdata[0:2], 257)
	rdata[2] = 3
	rdata[3] = 8

	rec, err := ParseDNSKEY(rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rec.IsKSK() {
		t.Error("IsKSK() should be true for flags=257")
	}
}

func TestParseDNSKEY_ZSK(t *testing.T) {
	// flags=256 has the Zone Key flag set but NOT the SEP bit -> ZSK
	rdata := make([]byte, 4)
	binary.BigEndian.PutUint16(rdata[0:2], 256)
	rdata[2] = 3
	rdata[3] = 8

	rec, err := ParseDNSKEY(rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.IsKSK() {
		t.Error("IsKSK() should be false for flags=256")
	}
}

func TestParseDNSKEY_TooShort(t *testing.T) {
	// Only 3 bytes; minimum is 4.
	_, err := ParseDNSKEY([]byte{0x01, 0x01, 0x03})
	if err == nil {
		t.Fatal("expected error for RDATA shorter than 4 bytes")
	}
}

func TestDNSKEYKeyTag(t *testing.T) {
	// Construct a known DNSKEY and verify the key tag computation.
	// Using flags=257, protocol=3, algorithm=8 with a fixed public key.
	pubkey := []byte{
		0x03, 0x01, 0x00, 0x01, 0xA0, 0xB1, 0xC2, 0xD3,
		0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B,
	}
	rec := &DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: pubkey,
	}

	// Manually compute the expected key tag per RFC 4034 Appendix B.
	wire := make([]byte, 4+len(pubkey))
	binary.BigEndian.PutUint16(wire[0:2], 257)
	wire[2] = 3
	wire[3] = 8
	copy(wire[4:], pubkey)

	var ac uint32
	for i, b := range wire {
		if i&1 == 1 {
			ac += uint32(b)
		} else {
			ac += uint32(b) << 8
		}
	}
	ac += ac >> 16 & 0xFFFF
	expected := uint16(ac & 0xFFFF)

	got := rec.KeyTag()
	if got != expected {
		t.Errorf("KeyTag: expected %d, got %d", expected, got)
	}

	// Sanity: tag should be nonzero with this input.
	if got == 0 {
		t.Error("KeyTag returned 0, which is unexpected for this input")
	}
}

// ---------------------------------------------------------------------------
// ParseDS
// ---------------------------------------------------------------------------

func TestParseDS_Valid(t *testing.T) {
	digest := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	rdata := make([]byte, 4+len(digest))
	binary.BigEndian.PutUint16(rdata[0:2], 12345) // key tag
	rdata[2] = 8                                   // algorithm
	rdata[3] = 2                                   // digest type (SHA-256)
	copy(rdata[4:], digest)

	rec, err := ParseDS(rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.KeyTag != 12345 {
		t.Errorf("KeyTag: expected 12345, got %d", rec.KeyTag)
	}
	if rec.Algorithm != 8 {
		t.Errorf("Algorithm: expected 8, got %d", rec.Algorithm)
	}
	if rec.DigestType != 2 {
		t.Errorf("DigestType: expected 2, got %d", rec.DigestType)
	}
	if !bytes.Equal(rec.Digest, digest) {
		t.Errorf("Digest: expected %x, got %x", digest, rec.Digest)
	}
}

func TestParseDS_TooShort(t *testing.T) {
	_, err := ParseDS([]byte{0x30, 0x39, 0x08})
	if err == nil {
		t.Fatal("expected error for RDATA shorter than 4 bytes")
	}
}

// ---------------------------------------------------------------------------
// ParseRRSIG
// ---------------------------------------------------------------------------

func TestParseRRSIG_Valid(t *testing.T) {
	signerName := BuildPlainName("example.com")
	sigBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	rdata := make([]byte, 18+len(signerName)+len(sigBytes))
	binary.BigEndian.PutUint16(rdata[0:2], TypeA)       // type covered
	rdata[2] = 8                                         // algorithm
	rdata[3] = 2                                         // labels
	binary.BigEndian.PutUint32(rdata[4:8], 3600)         // original TTL
	binary.BigEndian.PutUint32(rdata[8:12], 1700000000)  // expiration
	binary.BigEndian.PutUint32(rdata[12:16], 1690000000) // inception
	binary.BigEndian.PutUint16(rdata[16:18], 54321)      // key tag
	copy(rdata[18:], signerName)
	copy(rdata[18+len(signerName):], sigBytes)

	rec, err := ParseRRSIG(rdata, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.TypeCovered != TypeA {
		t.Errorf("TypeCovered: expected %d, got %d", TypeA, rec.TypeCovered)
	}
	if rec.Algorithm != 8 {
		t.Errorf("Algorithm: expected 8, got %d", rec.Algorithm)
	}
	if rec.Labels != 2 {
		t.Errorf("Labels: expected 2, got %d", rec.Labels)
	}
	if rec.OrigTTL != 3600 {
		t.Errorf("OrigTTL: expected 3600, got %d", rec.OrigTTL)
	}
	if rec.Expiration != 1700000000 {
		t.Errorf("Expiration: expected 1700000000, got %d", rec.Expiration)
	}
	if rec.Inception != 1690000000 {
		t.Errorf("Inception: expected 1690000000, got %d", rec.Inception)
	}
	if rec.KeyTag != 54321 {
		t.Errorf("KeyTag: expected 54321, got %d", rec.KeyTag)
	}
	if rec.SignerName != "example.com" {
		t.Errorf("SignerName: expected 'example.com', got '%s'", rec.SignerName)
	}
	if !bytes.Equal(rec.Signature, sigBytes) {
		t.Errorf("Signature: expected %x, got %x", sigBytes, rec.Signature)
	}
}

func TestParseRRSIG_TooShort(t *testing.T) {
	// 17 bytes is less than the required 18 byte fixed header.
	rdata := make([]byte, 17)
	_, err := ParseRRSIG(rdata, 0)
	if err == nil {
		t.Fatal("expected error for RDATA shorter than 18 bytes")
	}
}

// ---------------------------------------------------------------------------
// ParseNSEC
// ---------------------------------------------------------------------------

func TestParseNSEC_Valid(t *testing.T) {
	nextName := BuildPlainName("z.example.com")

	// Type bitmap: window 0 with A (1) and AAAA (28) set.
	// A=1:  byte_index=0, bit=7-1%8=6 -> 0x40
	// AAAA=28: byte_index=3, bit=7-28%8=7-4=3 -> 0x08
	bitmap := []byte{
		0x00, // window number 0
		0x04, // bitmap length = 4 bytes
		0x40, // byte 0: type 1 (A)
		0x00, // byte 1
		0x00, // byte 2
		0x08, // byte 3: type 28 (AAAA)
	}

	rdata := make([]byte, 0, len(nextName)+len(bitmap))
	rdata = append(rdata, nextName...)
	rdata = append(rdata, bitmap...)

	rec, err := ParseNSEC(rdata, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.NextDomainName != "z.example.com" {
		t.Errorf("NextDomainName: expected 'z.example.com', got '%s'", rec.NextDomainName)
	}
	if len(rec.TypeBitMaps) != 2 {
		t.Fatalf("TypeBitMaps: expected 2 types, got %d", len(rec.TypeBitMaps))
	}
	if rec.TypeBitMaps[0] != TypeA {
		t.Errorf("TypeBitMaps[0]: expected %d (A), got %d", TypeA, rec.TypeBitMaps[0])
	}
	if rec.TypeBitMaps[1] != TypeAAAA {
		t.Errorf("TypeBitMaps[1]: expected %d (AAAA), got %d", TypeAAAA, rec.TypeBitMaps[1])
	}
}

// ---------------------------------------------------------------------------
// ParseNSEC3
// ---------------------------------------------------------------------------

func TestParseNSEC3_Valid(t *testing.T) {
	salt := []byte{0xAB, 0xCD}
	nextHash := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	// Type bitmap: window 0 with A (1) and NS (2)
	// A=1:  byte 0, bit 6 -> 0x40
	// NS=2: byte 0, bit 5 -> 0x20
	// Combined byte 0: 0x60
	bitmap := []byte{
		0x00, // window 0
		0x01, // bitmap length = 1 byte
		0x60, // A + NS
	}

	rdata := make([]byte, 0, 5+len(salt)+1+len(nextHash)+len(bitmap))
	rdata = append(rdata, 1)    // hash algorithm (SHA-1)
	rdata = append(rdata, 0)    // flags
	rdata = append(rdata, 0, 10) // iterations = 10
	rdata = append(rdata, byte(len(salt)))
	rdata = append(rdata, salt...)
	rdata = append(rdata, byte(len(nextHash)))
	rdata = append(rdata, nextHash...)
	rdata = append(rdata, bitmap...)

	rec, err := ParseNSEC3(rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.HashAlgorithm != 1 {
		t.Errorf("HashAlgorithm: expected 1, got %d", rec.HashAlgorithm)
	}
	if rec.Flags != 0 {
		t.Errorf("Flags: expected 0, got %d", rec.Flags)
	}
	if rec.Iterations != 10 {
		t.Errorf("Iterations: expected 10, got %d", rec.Iterations)
	}
	if !bytes.Equal(rec.Salt, salt) {
		t.Errorf("Salt: expected %x, got %x", salt, rec.Salt)
	}
	if !bytes.Equal(rec.NextHash, nextHash) {
		t.Errorf("NextHash: expected %x, got %x", nextHash, rec.NextHash)
	}
	if len(rec.TypeBitMaps) != 2 {
		t.Fatalf("TypeBitMaps: expected 2 types, got %d", len(rec.TypeBitMaps))
	}
	if rec.TypeBitMaps[0] != TypeA {
		t.Errorf("TypeBitMaps[0]: expected %d (A), got %d", TypeA, rec.TypeBitMaps[0])
	}
	if rec.TypeBitMaps[1] != TypeNS {
		t.Errorf("TypeBitMaps[1]: expected %d (NS), got %d", TypeNS, rec.TypeBitMaps[1])
	}
}

func TestParseNSEC3_TooShort(t *testing.T) {
	// 4 bytes is less than the required 5 byte minimum.
	_, err := ParseNSEC3([]byte{1, 0, 0, 10})
	if err == nil {
		t.Fatal("expected error for RDATA shorter than 5 bytes")
	}
}

// ---------------------------------------------------------------------------
// parseTypeBitMaps
// ---------------------------------------------------------------------------

func TestParseTypeBitMaps_Basic(t *testing.T) {
	// Window 0 with A (1) and AAAA (28).
	// A=1:   byte_index=0, bit=7-(1%8)=6  -> 0x40
	// AAAA=28: byte_index=3, bit=7-(28%8)=3 -> 0x08
	data := []byte{
		0x00, // window 0
		0x04, // bitmap length 4
		0x40, // byte 0: type 1 (A)
		0x00, // byte 1
		0x00, // byte 2
		0x08, // byte 3: type 28 (AAAA)
	}

	types := parseTypeBitMaps(data)
	if len(types) != 2 {
		t.Fatalf("expected 2 types, got %d: %v", len(types), types)
	}
	if types[0] != 1 {
		t.Errorf("types[0]: expected 1 (A), got %d", types[0])
	}
	if types[1] != 28 {
		t.Errorf("types[1]: expected 28 (AAAA), got %d", types[1])
	}
}

func TestParseTypeBitMaps_MultipleWindows(t *testing.T) {
	// Window 0: type A (1)
	//   byte_index=0, bit=6 -> 0x40
	// Window 1: type 256 (window 1, offset 0)
	//   type 256: window=1, bit_position=0, byte_index=0, bit=7 -> 0x80
	data := []byte{
		// Window 0
		0x00, // window number
		0x01, // bitmap length 1
		0x40, // type 1 (A)
		// Window 1
		0x01, // window number
		0x01, // bitmap length 1
		0x80, // type 256 (window 1, bit 0)
	}

	types := parseTypeBitMaps(data)
	if len(types) != 2 {
		t.Fatalf("expected 2 types, got %d: %v", len(types), types)
	}
	if types[0] != 1 {
		t.Errorf("types[0]: expected 1 (A), got %d", types[0])
	}
	if types[1] != 256 {
		t.Errorf("types[1]: expected 256, got %d", types[1])
	}
}

func TestParseTypeBitMaps_Empty(t *testing.T) {
	types := parseTypeBitMaps(nil)
	if len(types) != 0 {
		t.Errorf("expected empty result, got %v", types)
	}

	types = parseTypeBitMaps([]byte{})
	if len(types) != 0 {
		t.Errorf("expected empty result for empty slice, got %v", types)
	}
}
