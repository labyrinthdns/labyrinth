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
