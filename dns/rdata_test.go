package dns

import "testing"

func TestParseA(t *testing.T) {
	ip, err := ParseA([]byte{192, 168, 1, 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip.String() != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", ip)
	}
}

func TestParseAWrongLength(t *testing.T) {
	_, err := ParseA([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}

func TestParseAAAA(t *testing.T) {
	rdata := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	ip, err := ParseAAAA(rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip.String() != "2001:db8::1" {
		t.Errorf("expected 2001:db8::1, got %s", ip)
	}
}

func TestParseAAAAWrongLength(t *testing.T) {
	_, err := ParseAAAA([]byte{1, 2, 3, 4})
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}

func TestParseNS(t *testing.T) {
	// Build a message buffer with "ns1.google.com" encoded
	buf := []byte{
		0x03, 'n', 's', '1',
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}

	name, err := ParseNS(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "ns1.google.com" {
		t.Errorf("expected 'ns1.google.com', got '%s'", name)
	}
}

func TestParseCNAME(t *testing.T) {
	buf := []byte{
		0x03, 'w', 'w', 'w',
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}

	name, err := ParseCNAME(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "www.google.com" {
		t.Errorf("expected 'www.google.com', got '%s'", name)
	}
}

func TestParseTXT(t *testing.T) {
	// Single string "hello"
	rdata := []byte{5, 'h', 'e', 'l', 'l', 'o'}
	strs, err := ParseTXT(rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(strs) != 1 || strs[0] != "hello" {
		t.Errorf("expected [\"hello\"], got %v", strs)
	}
}

func TestParseTXTMultiple(t *testing.T) {
	rdata := []byte{2, 'a', 'b', 3, 'c', 'd', 'e'}
	strs, err := ParseTXT(rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(strs) != 2 || strs[0] != "ab" || strs[1] != "cde" {
		t.Errorf("expected [\"ab\",\"cde\"], got %v", strs)
	}
}

func TestParseTXTEmpty(t *testing.T) {
	rdata := []byte{0}
	strs, err := ParseTXT(rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(strs) != 1 || strs[0] != "" {
		t.Errorf("expected [\"\"], got %v", strs)
	}
}

func TestParsePTR(t *testing.T) {
	buf := []byte{
		0x01, '4',
		0x01, '3',
		0x01, '2',
		0x01, '1',
		0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r',
		0x04, 'a', 'r', 'p', 'a',
		0x00,
	}

	name, err := ParsePTR(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "4.3.2.1.in-addr.arpa" {
		t.Errorf("expected '4.3.2.1.in-addr.arpa', got '%s'", name)
	}
}

func TestParseMX(t *testing.T) {
	// Preference=10, Exchange="mail.google.com"
	buf := make([]byte, 0, 64)
	buf = append(buf, 0x00, 0x0A) // preference=10
	buf = append(buf,
		0x04, 'm', 'a', 'i', 'l',
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	)

	mx, err := ParseMX(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mx.Preference != 10 {
		t.Errorf("preference: expected 10, got %d", mx.Preference)
	}
	if mx.Exchange != "mail.google.com" {
		t.Errorf("exchange: expected 'mail.google.com', got '%s'", mx.Exchange)
	}
}

func TestParseSOA(t *testing.T) {
	buf := make([]byte, 0, 128)
	// MNAME: "ns1.example.com"
	buf = append(buf,
		0x03, 'n', 's', '1',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	)
	// RNAME: "admin.example.com"
	buf = append(buf,
		0x05, 'a', 'd', 'm', 'i', 'n',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	)
	// Serial=2024010101, Refresh=3600, Retry=900, Expire=604800, Minimum=86400
	serial := make([]byte, 4)
	serial[0] = 0x78
	serial[1] = 0xA0
	serial[2] = 0xA9
	serial[3] = 0x15
	buf = append(buf, serial...)
	refresh := make([]byte, 4)
	refresh[3] = 0x10
	refresh[2] = 0x0E
	buf = append(buf, refresh...)
	retry := make([]byte, 4)
	retry[3] = 0x84
	retry[2] = 0x03
	buf = append(buf, retry...)
	expire := make([]byte, 4)
	expire[2] = 0x3B
	expire[1] = 0x09
	buf = append(buf, expire...)
	minimum := make([]byte, 4)
	minimum[2] = 0x51
	minimum[1] = 0x01
	buf = append(buf, minimum...)

	soa, err := ParseSOA(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if soa.MName != "ns1.example.com" {
		t.Errorf("MNAME: expected 'ns1.example.com', got '%s'", soa.MName)
	}
	if soa.RName != "admin.example.com" {
		t.Errorf("RNAME: expected 'admin.example.com', got '%s'", soa.RName)
	}
}

func TestParseSRV(t *testing.T) {
	buf := make([]byte, 0, 64)
	buf = append(buf, 0x00, 0x0A) // priority=10
	buf = append(buf, 0x00, 0x14) // weight=20
	buf = append(buf, 0x00, 0x50) // port=80
	buf = append(buf,
		0x03, 'w', 'w', 'w',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	)

	srv, err := ParseSRV(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if srv.Priority != 10 || srv.Weight != 20 || srv.Port != 80 {
		t.Errorf("SRV fields: priority=%d weight=%d port=%d", srv.Priority, srv.Weight, srv.Port)
	}
	if srv.Target != "www.example.com" {
		t.Errorf("target: expected 'www.example.com', got '%s'", srv.Target)
	}
}

func TestParseNSTruncated(t *testing.T) {
	// Label says 3 but only 2 data bytes
	buf := []byte{0x03, 'a', 'b'}
	_, err := ParseNS(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParseCNAMETruncated(t *testing.T) {
	buf := []byte{0x05, 'a', 'b'}
	_, err := ParseCNAME(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParsePTRTruncated(t *testing.T) {
	buf := []byte{0x04, 'a'}
	_, err := ParsePTR(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParseSOATruncatedMName(t *testing.T) {
	// mname label says 10 but data is too short
	buf := []byte{0x0A, 'a', 'b', 'c'}
	_, err := ParseSOA(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParseSOATruncatedRName(t *testing.T) {
	// Valid mname, then truncated rname
	buf := []byte{
		0x02, 'n', 's', 0x00, // mname "ns"
		0x0A, 'x', 'y', // rname truncated
	}
	_, err := ParseSOA(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParseSOATruncatedSerials(t *testing.T) {
	// Valid mname and rname, but missing serial fields
	buf := []byte{
		0x02, 'n', 's', 0x00,                         // mname
		0x05, 'a', 'd', 'm', 'i', 'n', 0x00,          // rname
		0x00, 0x00, 0x00, 0x01,                         // serial (only 1 of 5 uint32s)
	}
	_, err := ParseSOA(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for missing serial fields, got %v", err)
	}
}

func TestParseSOATruncatedSerial(t *testing.T) {
	// Valid mname and rname, but NO serial bytes at all
	var buf []byte
	buf = append(buf, 0x02, 'n', 's', 0x00)                         // mname
	buf = append(buf, 0x05, 'a', 'd', 'm', 'i', 'n', 0x00)          // rname
	// No serial bytes
	_, err := ParseSOA(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for Serial, got %v", err)
	}
}

func TestParseSOATruncatedRefresh(t *testing.T) {
	// Valid mname, rname, and serial, but Refresh truncated
	var buf []byte
	buf = append(buf, 0x02, 'n', 's', 0x00)                         // mname
	buf = append(buf, 0x05, 'a', 'd', 'm', 'i', 'n', 0x00)          // rname
	buf = append(buf, 0x00, 0x00, 0x00, 0x01)                         // serial (4 bytes)
	buf = append(buf, 0x00, 0x00)                                      // only 2 bytes for refresh, need 4
	_, err := ParseSOA(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for Refresh, got %v", err)
	}
}

func TestParseSOATruncatedRetry(t *testing.T) {
	var buf []byte
	buf = append(buf, 0x02, 'n', 's', 0x00)
	buf = append(buf, 0x05, 'a', 'd', 'm', 'i', 'n', 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // serial
	buf = append(buf, 0x00, 0x00, 0x00, 0x02) // refresh
	buf = append(buf, 0x00, 0x00)              // only 2 bytes for retry
	_, err := ParseSOA(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for Retry, got %v", err)
	}
}

func TestParseSOATruncatedExpire(t *testing.T) {
	var buf []byte
	buf = append(buf, 0x02, 'n', 's', 0x00)
	buf = append(buf, 0x05, 'a', 'd', 'm', 'i', 'n', 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // serial
	buf = append(buf, 0x00, 0x00, 0x00, 0x02) // refresh
	buf = append(buf, 0x00, 0x00, 0x00, 0x03) // retry
	buf = append(buf, 0x00, 0x00)              // only 2 bytes for expire
	_, err := ParseSOA(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for Expire, got %v", err)
	}
}

func TestParseSOATruncatedMinimum(t *testing.T) {
	var buf []byte
	buf = append(buf, 0x02, 'n', 's', 0x00)
	buf = append(buf, 0x05, 'a', 'd', 'm', 'i', 'n', 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // serial
	buf = append(buf, 0x00, 0x00, 0x00, 0x02) // refresh
	buf = append(buf, 0x00, 0x00, 0x00, 0x03) // retry
	buf = append(buf, 0x00, 0x00, 0x00, 0x04) // expire
	buf = append(buf, 0x00, 0x00)              // only 2 bytes for minimum
	_, err := ParseSOA(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for Minimum, got %v", err)
	}
}

func TestParseSRVTruncatedPriority(t *testing.T) {
	// Only 1 byte, not enough for priority (need 2)
	buf := []byte{0x00}
	_, err := ParseSRV(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for Priority, got %v", err)
	}
}

func TestParseSRVTruncatedWeight(t *testing.T) {
	// Only priority (2 bytes), not enough for weight
	buf := []byte{0x00, 0x0A, 0x00} // 3 bytes
	_, err := ParseSRV(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for Weight, got %v", err)
	}
}

func TestParseSRVTruncatedPort(t *testing.T) {
	// Priority + weight (4 bytes), not enough for port
	buf := []byte{0x00, 0x0A, 0x00, 0x14, 0x00} // 5 bytes
	_, err := ParseSRV(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated for Port, got %v", err)
	}
}

func TestParseMXTruncated(t *testing.T) {
	// Only 1 byte, need at least 2 for preference
	buf := []byte{0x00}
	_, err := ParseMX(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParseMXTruncatedExchange(t *testing.T) {
	// Preference OK but exchange name is truncated
	buf := []byte{0x00, 0x0A, 0x05, 'a', 'b'} // label says 5, only 2 data bytes
	_, err := ParseMX(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParseSRVTruncated(t *testing.T) {
	// Only 4 bytes, need at least 6 for priority+weight+port
	buf := []byte{0x00, 0x0A, 0x00, 0x14}
	_, err := ParseSRV(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParseSRVTruncatedTarget(t *testing.T) {
	// priority+weight+port OK, but target name truncated
	buf := []byte{
		0x00, 0x0A, // priority
		0x00, 0x14, // weight
		0x00, 0x50, // port
		0x05, 'a',  // label says 5, only 1 data byte
	}
	_, err := ParseSRV(buf, 0)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParseTXTTruncated(t *testing.T) {
	// String says length 10, but only 3 bytes available
	rdata := []byte{10, 'a', 'b', 'c'}
	_, err := ParseTXT(rdata)
	if err != errTruncated {
		t.Fatalf("expected errTruncated, got %v", err)
	}
}

func TestParseOPT(t *testing.T) {
	rr := &ResourceRecord{
		Name:     "",
		Type:     TypeOPT,
		Class:    4096, // UDP payload size
		TTL:      0,
		RDLength: 0,
		RData:    nil,
	}

	edns, err := ParseOPT(rr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if edns.UDPSize != 4096 {
		t.Errorf("UDPSize: expected 4096, got %d", edns.UDPSize)
	}
	if edns.DOFlag {
		t.Error("DOFlag should be false")
	}
}

func TestBuildOPT(t *testing.T) {
	rr := BuildOPT(4096, false)
	if rr.Type != TypeOPT {
		t.Errorf("Type: expected %d (OPT), got %d", TypeOPT, rr.Type)
	}
	if rr.Class != 4096 {
		t.Errorf("Class (UDP size): expected 4096, got %d", rr.Class)
	}
	if rr.TTL != 0 {
		t.Errorf("TTL: expected 0, got %d", rr.TTL)
	}
}
