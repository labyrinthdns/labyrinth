package dns

import (
	"net"
	"testing"
)

func TestBuildAndParseECS_IPv4(t *testing.T) {
	ecs := &ECSOption{
		Family:          1,
		SourcePrefixLen: 24,
		ScopePrefixLen:  0,
		Address:         net.ParseIP("192.168.1.0").To4(),
	}

	opt := BuildECS(ecs)
	if opt.Code != EDNSOptionCodeECS {
		t.Fatalf("expected option code %d, got %d", EDNSOptionCodeECS, opt.Code)
	}

	parsed, err := ParseECS(opt.Data)
	if err != nil {
		t.Fatalf("ParseECS error: %v", err)
	}

	if parsed.Family != 1 {
		t.Errorf("Family: expected 1, got %d", parsed.Family)
	}
	if parsed.SourcePrefixLen != 24 {
		t.Errorf("SourcePrefixLen: expected 24, got %d", parsed.SourcePrefixLen)
	}
	if parsed.ScopePrefixLen != 0 {
		t.Errorf("ScopePrefixLen: expected 0, got %d", parsed.ScopePrefixLen)
	}

	// First 3 bytes should match
	v4 := parsed.Address.To4()
	if v4 == nil {
		t.Fatal("expected IPv4 address")
	}
	if v4[0] != 192 || v4[1] != 168 || v4[2] != 1 {
		t.Errorf("Address mismatch: got %v", v4)
	}
}

func TestBuildAndParseECS_IPv6(t *testing.T) {
	ecs := &ECSOption{
		Family:          2,
		SourcePrefixLen: 48,
		ScopePrefixLen:  0,
		Address:         net.ParseIP("2001:db8:1234::").To16(),
	}

	opt := BuildECS(ecs)
	parsed, err := ParseECS(opt.Data)
	if err != nil {
		t.Fatalf("ParseECS error: %v", err)
	}

	if parsed.Family != 2 {
		t.Errorf("Family: expected 2, got %d", parsed.Family)
	}
	if parsed.SourcePrefixLen != 48 {
		t.Errorf("SourcePrefixLen: expected 48, got %d", parsed.SourcePrefixLen)
	}
}

func TestParseECS_TooShort(t *testing.T) {
	_, err := ParseECS([]byte{0, 1})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestParseECS_UnsupportedFamily(t *testing.T) {
	data := []byte{0, 3, 24, 0} // family=3
	_, err := ParseECS(data)
	if err == nil {
		t.Fatal("expected error for unsupported family")
	}
}

func TestParseECS_IPv4PrefixTooLong(t *testing.T) {
	data := []byte{0, 1, 33, 0} // family=1, source=33
	_, err := ParseECS(data)
	if err == nil {
		t.Fatal("expected error for prefix > 32")
	}
}

func TestParseECS_IPv6PrefixTooLong(t *testing.T) {
	data := []byte{0, 2, 129, 0} // family=2, source=129
	_, err := ParseECS(data)
	if err == nil {
		t.Fatal("expected error for prefix > 128")
	}
}

func TestBuildECS_TrailingBitsZeroed(t *testing.T) {
	// Address with bits beyond prefix that should be zeroed
	ecs := &ECSOption{
		Family:          1,
		SourcePrefixLen: 20,
		ScopePrefixLen:  0,
		Address:         net.ParseIP("192.168.255.255").To4(),
	}

	opt := BuildECS(ecs)
	// 20 bits = 3 bytes, but last nibble should be zeroed
	// byte[6] (3rd addr byte) should have lower 4 bits zeroed
	if len(opt.Data) < 7 {
		t.Fatalf("expected at least 7 bytes, got %d", len(opt.Data))
	}
	lastAddrByte := opt.Data[6]
	if lastAddrByte&0x0F != 0 {
		t.Errorf("trailing bits not zeroed: %08b", lastAddrByte)
	}
}

func TestTruncateIP_IPv4(t *testing.T) {
	ip := net.ParseIP("192.168.1.100")
	truncated := TruncateIP(ip, 24)
	v4 := truncated.To4()
	if v4 == nil {
		t.Fatal("expected IPv4")
	}
	if v4[3] != 0 {
		t.Errorf("expected last octet to be 0, got %d", v4[3])
	}
	if v4[0] != 192 || v4[1] != 168 || v4[2] != 1 {
		t.Errorf("first 3 octets changed: %v", v4)
	}
}

func TestTruncateIP_IPv4_16(t *testing.T) {
	ip := net.ParseIP("10.20.30.40")
	truncated := TruncateIP(ip, 16)
	v4 := truncated.To4()
	if v4 == nil {
		t.Fatal("expected IPv4")
	}
	if v4[2] != 0 || v4[3] != 0 {
		t.Errorf("expected last 2 octets to be 0, got %v", v4)
	}
}

func TestTruncateIP_IPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8:1234:5678:9abc:def0:1234:5678")
	truncated := TruncateIP(ip, 48)
	v6 := truncated.To16()
	if v6 == nil {
		t.Fatal("expected IPv6")
	}
	// Bytes 6-15 should be zero
	for i := 6; i < 16; i++ {
		if v6[i] != 0 {
			t.Errorf("byte %d should be 0, got %d", i, v6[i])
		}
	}
}

func TestBuildECS_ZeroPrefixLen(t *testing.T) {
	ecs := &ECSOption{
		Family:          1,
		SourcePrefixLen: 0,
		ScopePrefixLen:  0,
		Address:         net.ParseIP("0.0.0.0").To4(),
	}

	opt := BuildECS(ecs)
	if len(opt.Data) != 4 {
		t.Errorf("expected 4 bytes (header only), got %d", len(opt.Data))
	}
}
