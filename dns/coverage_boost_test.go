package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

// =============================================================================
// rdata.go: ParseDNAME (0% coverage — never called in tests)
// =============================================================================

func TestParseDNAME(t *testing.T) {
	// Encode "alias.example.com" as a plain DNS name
	buf := []byte{
		0x05, 'a', 'l', 'i', 'a', 's',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}

	name, err := ParseDNAME(buf, 0)
	if err != nil {
		t.Fatalf("ParseDNAME error: %v", err)
	}
	if name != "alias.example.com" {
		t.Errorf("expected 'alias.example.com', got '%s'", name)
	}
}

func TestParseDNAME_Truncated(t *testing.T) {
	// Label says 10 but only 2 bytes of data
	buf := []byte{0x0A, 'a', 'b'}
	_, err := ParseDNAME(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParseDNAME_Root(t *testing.T) {
	buf := []byte{0x00}
	name, err := ParseDNAME(buf, 0)
	if err != nil {
		t.Fatalf("ParseDNAME error: %v", err)
	}
	if name != "" && name != "." {
		t.Errorf("expected root or empty, got '%s'", name)
	}
}

// =============================================================================
// ecs.go: TruncateIP non-byte-aligned prefix for IPv6 (lines 109-113)
// =============================================================================

func TestTruncateIP_IPv6_NonByteAligned(t *testing.T) {
	// Use a prefix like 50 bits which is not byte-aligned (50/8 = 6 remainder 2)
	// This exercises the bitIndex > 0 branch in TruncateIP for IPv6.
	ip := net.ParseIP("2001:db8:1234:5678:9abc:def0:1234:5678")
	truncated := TruncateIP(ip, 50)
	v6 := truncated.To16()
	if v6 == nil {
		t.Fatal("expected IPv6 result")
	}
	// 50 bits = 6 full bytes + 2 bits
	// Byte 6 (index 6) should have only top 2 bits of original preserved
	// Original byte 6: 0x56 = 01010110, with mask 0xC0 (top 2 bits) => 0x40
	if v6[6]&0x3F != 0 {
		t.Errorf("byte 6 should have lower 6 bits zeroed, got %08b", v6[6])
	}
	// Bytes 7-15 should be zero
	for i := 7; i < 16; i++ {
		if v6[i] != 0 {
			t.Errorf("byte %d should be 0, got %d", i, v6[i])
		}
	}
}

func TestTruncateIP_IPv4_NonByteAligned(t *testing.T) {
	// 20 bits = 2 full bytes + 4 bits, exercises bitIndex > 0 for IPv4
	ip := net.ParseIP("192.168.255.255")
	truncated := TruncateIP(ip, 20)
	v4 := truncated.To4()
	if v4 == nil {
		t.Fatal("expected IPv4 result")
	}
	// Byte 2 (3rd byte) original 0xFF, with 4 bit mask (0xF0) => 0xF0
	if v4[2] != 0xF0 {
		t.Errorf("byte 2: expected 0xF0, got 0x%02X", v4[2])
	}
	if v4[3] != 0 {
		t.Errorf("byte 3: expected 0, got %d", v4[3])
	}
}

func TestTruncateIP_IPv6_ByteAligned(t *testing.T) {
	// 64 bits = exactly 8 bytes, no partial byte masking needed
	ip := net.ParseIP("2001:db8:1234:5678:9abc:def0:1234:5678")
	truncated := TruncateIP(ip, 64)
	v6 := truncated.To16()
	if v6 == nil {
		t.Fatal("expected IPv6 result")
	}
	// Bytes 8-15 should be zero
	for i := 8; i < 16; i++ {
		if v6[i] != 0 {
			t.Errorf("byte %d should be 0, got %d", i, v6[i])
		}
	}
	// First 8 bytes should be preserved
	if v6[0] != 0x20 || v6[1] != 0x01 {
		t.Errorf("first bytes should be preserved")
	}
}

func TestTruncateIP_FullPrefix(t *testing.T) {
	// prefixLen == 128 for IPv6 (byteIndex >= len(addr), so no truncation)
	ip := net.ParseIP("2001:db8::1")
	truncated := TruncateIP(ip, 128)
	if !truncated.Equal(ip) {
		t.Errorf("full prefix should preserve IP: got %v, want %v", truncated, ip)
	}
}

// =============================================================================
// wire.go: Unpack — UnpackQuestion error path (line 111-113)
// =============================================================================

func TestUnpack_BadQuestion(t *testing.T) {
	// Build a header claiming 1 question, but the question section is truncated.
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:], 0x1234) // ID
	binary.BigEndian.PutUint16(header[2:], 0x0100) // Flags: RD=1
	binary.BigEndian.PutUint16(header[4:], 1)       // QDCount = 1
	// No question data follows the header

	_, err := Unpack(header)
	if err == nil {
		t.Fatal("expected error when question section is truncated")
	}
}

func TestUnpack_BadQuestionPartialName(t *testing.T) {
	// Header says 1 question, question name label is truncated
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:], 0xABCD)
	binary.BigEndian.PutUint16(header[2:], 0x0100)
	binary.BigEndian.PutUint16(header[4:], 1) // QDCount = 1
	buf = append(buf, header...)
	// Add a label that claims 10 bytes but only has 2
	buf = append(buf, 0x0A, 'a', 'b')

	_, err := Unpack(buf)
	if err == nil {
		t.Fatal("expected error for truncated question name")
	}
}
