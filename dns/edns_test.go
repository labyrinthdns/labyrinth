package dns

import (
	"encoding/binary"
	"testing"
)

func TestParseOPTWithOptions(t *testing.T) {
	// Build OPT RR with EDNS0 options in RDATA
	// Option: Code=10 (COOKIE), Data=[0x01, 0x02, 0x03, 0x04]
	var rdata []byte
	// Option 1
	opt1Code := make([]byte, 2)
	binary.BigEndian.PutUint16(opt1Code, 10) // code=10
	rdata = append(rdata, opt1Code...)
	opt1Len := make([]byte, 2)
	binary.BigEndian.PutUint16(opt1Len, 4) // length=4
	rdata = append(rdata, opt1Len...)
	rdata = append(rdata, 0x01, 0x02, 0x03, 0x04) // data

	// Option 2
	opt2Code := make([]byte, 2)
	binary.BigEndian.PutUint16(opt2Code, 15) // code=15
	rdata = append(rdata, opt2Code...)
	opt2Len := make([]byte, 2)
	binary.BigEndian.PutUint16(opt2Len, 2) // length=2
	rdata = append(rdata, opt2Len...)
	rdata = append(rdata, 0xAB, 0xCD) // data

	rr := &ResourceRecord{
		Name:     "",
		Type:     TypeOPT,
		Class:    4096,
		TTL:      0,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}

	edns, err := ParseOPT(rr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if edns.UDPSize != 4096 {
		t.Errorf("UDPSize: expected 4096, got %d", edns.UDPSize)
	}
	if len(edns.Options) != 2 {
		t.Fatalf("expected 2 options, got %d", len(edns.Options))
	}
	if edns.Options[0].Code != 10 {
		t.Errorf("option 0 code: expected 10, got %d", edns.Options[0].Code)
	}
	if len(edns.Options[0].Data) != 4 {
		t.Errorf("option 0 data length: expected 4, got %d", len(edns.Options[0].Data))
	}
	if edns.Options[0].Data[0] != 0x01 || edns.Options[0].Data[3] != 0x04 {
		t.Errorf("option 0 data mismatch")
	}
	if edns.Options[1].Code != 15 {
		t.Errorf("option 1 code: expected 15, got %d", edns.Options[1].Code)
	}
	if len(edns.Options[1].Data) != 2 {
		t.Errorf("option 1 data length: expected 2, got %d", len(edns.Options[1].Data))
	}
}

func TestParseOPTWithDOFlag(t *testing.T) {
	// DO flag is bit 15 of the TTL field
	rr := &ResourceRecord{
		Name:     "",
		Type:     TypeOPT,
		Class:    4096,
		TTL:      1 << 15, // DO=1
		RDLength: 0,
		RData:    nil,
	}

	edns, err := ParseOPT(rr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !edns.DOFlag {
		t.Error("DOFlag should be true")
	}
}

func TestParseOPTExtRCODEAndVersion(t *testing.T) {
	// ExtRCODE in top byte of TTL, Version in second byte
	// TTL = (ExtRCODE=3)<<24 | (Version=1)<<16
	ttl := uint32(3)<<24 | uint32(1)<<16
	rr := &ResourceRecord{
		Name:     "",
		Type:     TypeOPT,
		Class:    4096,
		TTL:      ttl,
		RDLength: 0,
		RData:    nil,
	}

	edns, err := ParseOPT(rr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if edns.ExtRCODE != 3 {
		t.Errorf("ExtRCODE: expected 3, got %d", edns.ExtRCODE)
	}
	if edns.Version != 1 {
		t.Errorf("Version: expected 1, got %d", edns.Version)
	}
}

func TestParseOPTNotOPTRecord(t *testing.T) {
	rr := &ResourceRecord{
		Name: "example.com",
		Type: TypeA,
	}

	_, err := ParseOPT(rr)
	if err == nil {
		t.Fatal("expected error for non-OPT record")
	}
}

func TestParseOPTTruncatedOption(t *testing.T) {
	// Option header says length=10 but RDATA only has 2 bytes of data
	var rdata []byte
	code := make([]byte, 2)
	binary.BigEndian.PutUint16(code, 10)
	rdata = append(rdata, code...)
	optLen := make([]byte, 2)
	binary.BigEndian.PutUint16(optLen, 10) // says 10 bytes
	rdata = append(rdata, optLen...)
	rdata = append(rdata, 0x01, 0x02) // only 2 bytes

	rr := &ResourceRecord{
		Type:     TypeOPT,
		Class:    4096,
		TTL:      0,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}

	edns, err := ParseOPT(rr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should skip the truncated option
	if len(edns.Options) != 0 {
		t.Errorf("expected 0 options for truncated data, got %d", len(edns.Options))
	}
}

func TestBuildOPTWithDOFlag(t *testing.T) {
	rr := BuildOPT(4096, true)
	if rr.Type != TypeOPT {
		t.Errorf("Type: expected %d, got %d", TypeOPT, rr.Type)
	}
	if rr.Class != 4096 {
		t.Errorf("Class (UDP size): expected 4096, got %d", rr.Class)
	}
	// DO flag should be set in TTL
	if rr.TTL&(1<<15) == 0 {
		t.Error("DO flag should be set in TTL")
	}

	// Round-trip: parse the built OPT
	edns, err := ParseOPT(&rr)
	if err != nil {
		t.Fatalf("ParseOPT error: %v", err)
	}
	if !edns.DOFlag {
		t.Error("DOFlag should be true after round-trip")
	}
	if edns.UDPSize != 4096 {
		t.Errorf("UDPSize: expected 4096, got %d", edns.UDPSize)
	}
}

func TestBuildOPTNoDOFlag(t *testing.T) {
	rr := BuildOPT(1232, false)
	if rr.TTL != 0 {
		t.Errorf("TTL should be 0 when DO=false, got %d", rr.TTL)
	}
	if rr.Class != 1232 {
		t.Errorf("Class: expected 1232, got %d", rr.Class)
	}
}

// Test that EDNS0 is extracted when unpacking a message with an OPT additional record
func TestUnpackMessageWithEDNS(t *testing.T) {
	// Build a message with an OPT record in additional section
	opt := BuildOPT(4096, true)
	msg := &Message{
		Header: Header{
			ID:    0x5678,
			Flags: NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []Question{{
			Name:  "example.com",
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
		t.Fatal("EDNS0 should be extracted from additional section")
	}
	if !unpacked.EDNS0.DOFlag {
		t.Error("EDNS0 DOFlag should be true")
	}
	if unpacked.EDNS0.UDPSize != 4096 {
		t.Errorf("EDNS0 UDPSize: expected 4096, got %d", unpacked.EDNS0.UDPSize)
	}
}

func TestBuildEDEOption(t *testing.T) {
	opt := BuildEDEOption(6, "DNSSEC validation failure")
	if opt.Code != EDNSOptionCodeEDE {
		t.Errorf("expected option code %d, got %d", EDNSOptionCodeEDE, opt.Code)
	}
	if len(opt.Data) < 2 {
		t.Fatal("EDE data too short")
	}

	code, text, err := ParseEDEOption(opt.Data)
	if err != nil {
		t.Fatalf("ParseEDEOption error: %v", err)
	}
	if code != 6 {
		t.Errorf("info code: expected 6, got %d", code)
	}
	if text != "DNSSEC validation failure" {
		t.Errorf("extra text: expected 'DNSSEC validation failure', got %q", text)
	}
}

func TestBuildEDEOption_NoText(t *testing.T) {
	opt := BuildEDEOption(EDECodeStaleAnswer, "")
	code, text, err := ParseEDEOption(opt.Data)
	if err != nil {
		t.Fatalf("ParseEDEOption error: %v", err)
	}
	if code != EDECodeStaleAnswer {
		t.Errorf("info code: expected %d, got %d", EDECodeStaleAnswer, code)
	}
	if text != "" {
		t.Errorf("extra text: expected empty, got %q", text)
	}
}

func TestParseEDEOption_TooShort(t *testing.T) {
	_, _, err := ParseEDEOption([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestBuildEDEOption_AllCodes(t *testing.T) {
	codes := []uint16{
		EDECodeOtherError, EDECodeUnsupportedDNSKEYAlgo, EDECodeUnsupportedDSDigestType,
		EDECodeStaleAnswer, EDECodeForgedAnswer, EDECodeDNSSECIndeterminate,
		EDECodeDNSSECBogus, EDECodeSignatureExpired, EDECodeSignatureNotYetValid,
		EDECodeDNSKEYMissing, EDECodeRRSIGsMissing, EDECodeNoZoneKeyBitSet,
		EDECodeNSECMissing, EDECodeCachedError, EDECodeNotReady,
		EDECodeBlocked, EDECodeCensored, EDECodeFiltered,
		EDECodeProhibited, EDECodeStaleNXDOMAINAnswer, EDECodeNotAuthoritative,
		EDECodeNotSupported, EDECodeNoReachableAuthority, EDECodeNetworkError,
		EDECodeInvalidData,
	}
	for _, code := range codes {
		opt := BuildEDEOption(code, "test")
		parsed, _, err := ParseEDEOption(opt.Data)
		if err != nil {
			t.Fatalf("code %d: %v", code, err)
		}
		if parsed != code {
			t.Errorf("expected code %d, got %d", code, parsed)
		}
	}
	// Verify we covered all 25 codes (0..24)
	if len(codes) != 25 {
		t.Errorf("expected 25 EDE codes, got %d", len(codes))
	}
}

func TestParseCookieOption_Valid(t *testing.T) {
	data := make([]byte, 16)
	for i := range data {
		data[i] = byte(i + 1)
	}

	client, server := ParseCookieOption(data)
	if len(client) != 8 {
		t.Fatalf("client cookie length: expected 8, got %d", len(client))
	}
	if len(server) != 8 {
		t.Fatalf("server cookie length: expected 8, got %d", len(server))
	}

	for i := 0; i < 8; i++ {
		if client[i] != byte(i+1) {
			t.Errorf("client[%d]: expected %d, got %d", i, i+1, client[i])
		}
	}
	for i := 0; i < 8; i++ {
		if server[i] != byte(i+9) {
			t.Errorf("server[%d]: expected %d, got %d", i, i+9, server[i])
		}
	}
}

func TestParseCookieOption_ClientOnly(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	client, server := ParseCookieOption(data)
	if len(client) != 8 {
		t.Fatalf("client cookie length: expected 8, got %d", len(client))
	}
	if server != nil {
		t.Errorf("expected nil server cookie, got %v", server)
	}
}

func TestParseCookieOption_TooShort(t *testing.T) {
	data := []byte{1, 2, 3}
	client, server := ParseCookieOption(data)
	if client != nil {
		t.Errorf("expected nil client cookie for short data")
	}
	if server != nil {
		t.Errorf("expected nil server cookie for short data")
	}
}

func TestBuildOPTWithOptions(t *testing.T) {
	opts := []EDNSOption{
		BuildEDEOption(6, "bogus"),
		{Code: 10, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
	}

	rr := BuildOPTWithOptions(4096, true, opts)
	if rr.Type != TypeOPT {
		t.Errorf("Type: expected OPT, got %d", rr.Type)
	}
	if rr.RDLength == 0 {
		t.Error("expected non-zero RDLength")
	}

	// Parse back
	edns, err := ParseOPT(&rr)
	if err != nil {
		t.Fatalf("ParseOPT error: %v", err)
	}
	if len(edns.Options) != 2 {
		t.Fatalf("expected 2 options, got %d", len(edns.Options))
	}
	if edns.Options[0].Code != EDNSOptionCodeEDE {
		t.Errorf("option 0 code: expected %d, got %d", EDNSOptionCodeEDE, edns.Options[0].Code)
	}
	if edns.Options[1].Code != 10 {
		t.Errorf("option 1 code: expected 10, got %d", edns.Options[1].Code)
	}
}

func TestBuildOPTWithOptions_Empty(t *testing.T) {
	rr := BuildOPTWithOptions(4096, false, nil)
	if rr.RDLength != 0 {
		t.Errorf("expected 0 RDLength for empty options, got %d", rr.RDLength)
	}
	if len(rr.RData) != 0 {
		t.Errorf("expected nil RData for empty options")
	}
}
