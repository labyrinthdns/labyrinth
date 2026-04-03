package resolver

import (
	"net"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// --- ParseLocalRecord tests ---

func TestParseLocalRecord_A(t *testing.T) {
	rec, err := ParseLocalRecord("localhost. A 127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Name != "localhost" {
		t.Errorf("name = %q, want %q", rec.Name, "localhost")
	}
	if rec.Type != dns.TypeA {
		t.Errorf("type = %d, want %d", rec.Type, dns.TypeA)
	}
	ip := net.IP(rec.RData).To4()
	if ip == nil || ip.String() != "127.0.0.1" {
		t.Errorf("rdata IP = %v, want 127.0.0.1", ip)
	}
	if rec.TTL != 3600 {
		t.Errorf("ttl = %d, want 3600", rec.TTL)
	}
}

func TestParseLocalRecord_AAAA(t *testing.T) {
	rec, err := ParseLocalRecord("localhost. AAAA ::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Type != dns.TypeAAAA {
		t.Errorf("type = %d, want %d", rec.Type, dns.TypeAAAA)
	}
	ip := net.IP(rec.RData)
	if ip == nil || ip.String() != "::1" {
		t.Errorf("rdata IP = %v, want ::1", ip)
	}
}

func TestParseLocalRecord_CNAME(t *testing.T) {
	rec, err := ParseLocalRecord("www.example.com. CNAME example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Name != "www.example.com" {
		t.Errorf("name = %q, want %q", rec.Name, "www.example.com")
	}
	if rec.Type != dns.TypeCNAME {
		t.Errorf("type = %d, want %d", rec.Type, dns.TypeCNAME)
	}
	// Verify wire-format encoding: \x07example\x03com\x00
	expected := encodeNameWire("example.com")
	if len(rec.RData) != len(expected) {
		t.Fatalf("rdata length = %d, want %d", len(rec.RData), len(expected))
	}
	for i := range expected {
		if rec.RData[i] != expected[i] {
			t.Errorf("rdata[%d] = %02x, want %02x", i, rec.RData[i], expected[i])
		}
	}
}

func TestParseLocalRecord_TXT(t *testing.T) {
	rec, err := ParseLocalRecord(`example.com. TXT "hello world"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Type != dns.TypeTXT {
		t.Errorf("type = %d, want %d", rec.Type, dns.TypeTXT)
	}
	// Wire format: length byte + text
	text := "hello world"
	if len(rec.RData) != 1+len(text) {
		t.Fatalf("rdata length = %d, want %d", len(rec.RData), 1+len(text))
	}
	if int(rec.RData[0]) != len(text) {
		t.Errorf("txt length byte = %d, want %d", rec.RData[0], len(text))
	}
	if string(rec.RData[1:]) != text {
		t.Errorf("txt content = %q, want %q", string(rec.RData[1:]), text)
	}
}

func TestParseLocalRecord_PTR(t *testing.T) {
	rec, err := ParseLocalRecord("1.0.0.127.in-addr.arpa. PTR localhost.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Type != dns.TypePTR {
		t.Errorf("type = %d, want %d", rec.Type, dns.TypePTR)
	}
	expected := encodeNameWire("localhost")
	if len(rec.RData) != len(expected) {
		t.Fatalf("rdata length = %d, want %d", len(rec.RData), len(expected))
	}
}

func TestParseLocalRecord_MX(t *testing.T) {
	rec, err := ParseLocalRecord("example.com. MX 10 mail.example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Type != dns.TypeMX {
		t.Errorf("type = %d, want %d", rec.Type, dns.TypeMX)
	}
	// First 2 bytes = preference (10), rest = wire name
	if len(rec.RData) < 2 {
		t.Fatalf("rdata too short: %d", len(rec.RData))
	}
	pref := int(rec.RData[0])<<8 | int(rec.RData[1])
	if pref != 10 {
		t.Errorf("MX preference = %d, want 10", pref)
	}
}

func TestParseLocalRecord_Invalid(t *testing.T) {
	tests := []struct {
		input string
		desc  string
	}{
		{"localhost.", "too few fields"},
		{"localhost. UNKNOWN 1.2.3.4", "unsupported type"},
		{"localhost. A not-an-ip", "invalid A rdata"},
		{"localhost. AAAA not-ipv6", "invalid AAAA rdata"},
	}
	for _, tc := range tests {
		_, err := ParseLocalRecord(tc.input)
		if err == nil {
			t.Errorf("ParseLocalRecord(%q): expected error for %s", tc.input, tc.desc)
		}
	}
}

// --- LocalZone behavior tests ---

func TestLocalZoneStatic_Found(t *testing.T) {
	zone := LocalZone{
		Name: "example.local",
		Type: LocalStatic,
		Records: []LocalRecord{
			{Name: "host.example.local", Type: dns.TypeA, RData: net.ParseIP("10.0.0.1").To4(), TTL: 300},
		},
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	result := table.Lookup("host.example.local", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("RCODE = %d, want NoError (%d)", result.RCODE, dns.RCodeNoError)
	}
	if len(result.Answers) != 1 {
		t.Fatalf("answers count = %d, want 1", len(result.Answers))
	}
	if result.Answers[0].Name != "host.example.local" {
		t.Errorf("answer name = %q, want %q", result.Answers[0].Name, "host.example.local")
	}
}

func TestLocalZoneStatic_NotFound_NXDOMAIN(t *testing.T) {
	zone := LocalZone{
		Name: "example.local",
		Type: LocalStatic,
		Records: []LocalRecord{
			{Name: "host.example.local", Type: dns.TypeA, RData: net.ParseIP("10.0.0.1").To4(), TTL: 300},
		},
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	result := table.Lookup("unknown.example.local", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected NXDOMAIN result, got nil")
	}
	if result.RCODE != dns.RCodeNXDomain {
		t.Errorf("RCODE = %d, want NXDomain (%d)", result.RCODE, dns.RCodeNXDomain)
	}
	if len(result.Answers) != 0 {
		t.Errorf("answers count = %d, want 0", len(result.Answers))
	}
}

func TestLocalZoneStatic_NameExists_WrongType(t *testing.T) {
	zone := LocalZone{
		Name: "example.local",
		Type: LocalStatic,
		Records: []LocalRecord{
			{Name: "host.example.local", Type: dns.TypeA, RData: net.ParseIP("10.0.0.1").To4(), TTL: 300},
		},
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	// Query AAAA for a name that has an A record → NODATA (NoError, no answers)
	result := table.Lookup("host.example.local", dns.TypeAAAA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected NODATA result, got nil")
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("RCODE = %d, want NoError (%d)", result.RCODE, dns.RCodeNoError)
	}
	if len(result.Answers) != 0 {
		t.Errorf("answers count = %d, want 0", len(result.Answers))
	}
}

func TestLocalZoneDeny(t *testing.T) {
	zone := LocalZone{
		Name: "blocked.local",
		Type: LocalDeny,
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	result := table.Lookup("anything.blocked.local", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	// Deny returns a sentinel result with DNSSECStatus = "local-deny"
	if result.DNSSECStatus != "local-deny" {
		t.Errorf("DNSSECStatus = %q, want %q", result.DNSSECStatus, "local-deny")
	}
}

func TestLocalZoneRefuse(t *testing.T) {
	zone := LocalZone{
		Name: "private.local",
		Type: LocalRefuse,
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	result := table.Lookup("any.private.local", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected REFUSED result, got nil")
	}
	if result.RCODE != dns.RCodeRefused {
		t.Errorf("RCODE = %d, want Refused (%d)", result.RCODE, dns.RCodeRefused)
	}
}

func TestLocalZoneTransparent_Found(t *testing.T) {
	zone := LocalZone{
		Name: "internal.local",
		Type: LocalTransparent,
		Records: []LocalRecord{
			{Name: "myhost.internal.local", Type: dns.TypeA, RData: net.ParseIP("192.168.1.1").To4(), TTL: 60},
		},
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	result := table.Lookup("myhost.internal.local", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("RCODE = %d, want NoError", result.RCODE)
	}
	if len(result.Answers) != 1 {
		t.Fatalf("answers count = %d, want 1", len(result.Answers))
	}
}

func TestLocalZoneTransparent_NotFound_Nil(t *testing.T) {
	zone := LocalZone{
		Name: "internal.local",
		Type: LocalTransparent,
		Records: []LocalRecord{
			{Name: "myhost.internal.local", Type: dns.TypeA, RData: net.ParseIP("192.168.1.1").To4(), TTL: 60},
		},
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	// Query for a name not in the zone → nil (falls through to recursive)
	result := table.Lookup("other.internal.local", dns.TypeA, dns.ClassIN)
	if result != nil {
		t.Errorf("expected nil for transparent miss, got RCODE=%d", result.RCODE)
	}
}

func TestLocalZoneRedirect(t *testing.T) {
	zone := LocalZone{
		Name: "redirect.local",
		Type: LocalRedirect,
		Records: []LocalRecord{
			{Name: "redirect.local", Type: dns.TypeA, RData: net.ParseIP("10.10.10.10").To4(), TTL: 300},
		},
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	// Any name under the zone gets the redirect answer, rewritten to query name
	result := table.Lookup("anything.redirect.local", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected redirect result, got nil")
	}
	if result.RCODE != dns.RCodeNoError {
		t.Errorf("RCODE = %d, want NoError", result.RCODE)
	}
	if len(result.Answers) != 1 {
		t.Fatalf("answers count = %d, want 1", len(result.Answers))
	}
	if result.Answers[0].Name != "anything.redirect.local" {
		t.Errorf("answer name = %q, want %q", result.Answers[0].Name, "anything.redirect.local")
	}
}

// --- Longest match tests ---

func TestLocalZoneTableLongestMatch(t *testing.T) {
	// More specific zone should win over less specific one.
	broadZone := LocalZone{
		Name: "example.com",
		Type: LocalStatic,
		Records: []LocalRecord{
			{Name: "host.sub.example.com", Type: dns.TypeA, RData: net.ParseIP("1.1.1.1").To4(), TTL: 300},
		},
	}
	specificZone := LocalZone{
		Name: "sub.example.com",
		Type: LocalStatic,
		Records: []LocalRecord{
			{Name: "host.sub.example.com", Type: dns.TypeA, RData: net.ParseIP("2.2.2.2").To4(), TTL: 300},
		},
	}

	// Order should not matter — constructor sorts by specificity.
	table := NewLocalZoneTable([]LocalZone{broadZone, specificZone})

	result := table.Lookup("host.sub.example.com", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if len(result.Answers) != 1 {
		t.Fatalf("answers count = %d, want 1", len(result.Answers))
	}
	// Should match the specific zone's record (2.2.2.2)
	ip := net.IP(result.Answers[0].RData).To4()
	if ip.String() != "2.2.2.2" {
		t.Errorf("answer IP = %s, want 2.2.2.2 (from specific zone)", ip)
	}
}

func TestLocalZoneTableNoMatch(t *testing.T) {
	zone := LocalZone{
		Name: "example.local",
		Type: LocalStatic,
		Records: []LocalRecord{
			{Name: "host.example.local", Type: dns.TypeA, RData: net.ParseIP("10.0.0.1").To4(), TTL: 300},
		},
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	// Query for a name outside any local zone → nil
	result := table.Lookup("google.com", dns.TypeA, dns.ClassIN)
	if result != nil {
		t.Errorf("expected nil for unmatched zone, got RCODE=%d", result.RCODE)
	}
}

func TestLocalZoneTableNormalization(t *testing.T) {
	// Names should be case-insensitive and trailing dots stripped.
	zone := LocalZone{
		Name: "Example.LOCAL.",
		Type: LocalStatic,
		Records: []LocalRecord{
			{Name: "HOST.Example.LOCAL.", Type: dns.TypeA, RData: net.ParseIP("10.0.0.1").To4(), TTL: 300},
		},
	}
	table := NewLocalZoneTable([]LocalZone{zone})

	result := table.Lookup("host.example.local", dns.TypeA, dns.ClassIN)
	if result == nil {
		t.Fatal("expected result after normalization, got nil")
	}
	if len(result.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(result.Answers))
	}
}
