package dns

import (
	"bytes"
	"strings"
	"testing"
)

// TestParseZone_SOAOnly is the round-trip oracle for the simplest zone:
// one SOA, no records. The parser must produce a slice with the same
// RDATA bytes the writer emitted. The parser is built against the writer
// on purpose so that the assertion is "the round-trip is identity".
func TestParseZone_SOAOnly(t *testing.T) {
	apex := "example.com."
	soaRData := buildSOA(t, "ns.example.com.", "hostmaster.example.com.",
		2024010101, 7200, 3600, 1209600, 3600)

	src := []ResourceRecord{
		{Name: apex, Type: TypeSOA, Class: ClassIN, TTL: 86400, RData: soaRData},
	}
	formatted, err := FormatZone(apex, src)
	if err != nil {
		t.Fatalf("FormatZone: %v", err)
	}

	got, err := ParseZone(apex, formatted)
	if err != nil {
		t.Fatalf("ParseZone: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	r := got[0]
	if r.Name != apex {
		t.Errorf("Name = %q, want %q", r.Name, apex)
	}
	if r.Type != TypeSOA {
		t.Errorf("Type = %d, want %d", r.Type, TypeSOA)
	}
	if !bytes.Equal(r.RData, soaRData) {
		t.Errorf("RData mismatch:\n got  %x\n want %x", r.RData, soaRData)
	}
}

// TestParseZone_BasicRoundTrip is the strongest single test: write a
// zone with the supported types, parse it back, expect the record slice
// to match modulo the trivially equivalent differences (Name == apex is
// kept absolute with a trailing dot, not relative to $ORIGIN). The
// writer groups records by owner (NS first, then SOA, then DNSSEC, then
// everything else), so the comparison is keyed by (Name, Type) rather
// than by index.
func TestParseZone_BasicRoundTrip(t *testing.T) {
	apex := "example.com."
	soaRData := buildSOA(t, "ns.example.com.", "hostmaster.example.com.",
		2024010101, 7200, 3600, 1209600, 3600)
	src := []ResourceRecord{
		{Name: apex, Type: TypeSOA, Class: ClassIN, TTL: 86400, RData: soaRData},
		{Name: apex, Type: TypeNS, Class: ClassIN, TTL: 86400, RData: buildName(t, "ns.example.com.")},
		{Name: apex, Type: TypeMX, Class: ClassIN, TTL: 86400, RData: buildMX(t, 10, "mail.example.com.")},
		{Name: "www.example.com.", Type: TypeA, Class: ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
		{Name: "api.example.com.", Type: TypeAAAA, Class: ClassIN, TTL: 300, RData: []byte{
			0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
			0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
		}},
		{Name: "ftp.example.com.", Type: TypeCNAME, Class: ClassIN, TTL: 600, RData: buildName(t, "www.example.com.")},
		{Name: "1.2.3.4.in-addr.arpa.", Type: TypePTR, Class: ClassIN, TTL: 600, RData: buildName(t, "host.example.com.")},
		{Name: "_sip._tcp.example.com.", Type: TypeSRV, Class: ClassIN, TTL: 60, RData: append(
			[]byte{0x00, 0x05, 0x00, 0x00, 0x13, 0xC4},
			buildName(t, "sip.example.com.")...,
		)},
		{Name: "example.com.", Type: TypeCAA, Class: ClassIN, TTL: 3600, RData: []byte{
			0, 5, 'i', 's', 's', 'u', 'e', 'l', 'e', 't', 's', 'e', 'n', 'c', 'r', 'y', 'p', 't', '.',
			'o', 'r', 'g',
		}},
		{Name: "txt.example.com.", Type: TypeTXT, Class: ClassIN, TTL: 60, RData: []byte{
			5, '"', 'a', '"', 'b', 'X',
			4, 't', 'e', 'x', 't',
		}},
	}

	formatted, err := FormatZone(apex, src)
	if err != nil {
		t.Fatalf("FormatZone: %v", err)
	}
	got, err := ParseZone(apex, formatted)
	if err != nil {
		t.Fatalf("ParseZone: %v\nformatted:\n%s", err, formatted)
	}

	if len(got) != len(src) {
		t.Fatalf("record count: want %d, got %d", len(src), len(got))
	}
	// Index by (Name, Type) so the writer's per-owner reordering does
	// not move the goalposts.
	want := make(map[string]ResourceRecord)
	for _, r := range src {
		key := r.Name + "|" + TypeName(r.Type)
		if _, ok := want[key]; ok {
			t.Fatalf("duplicate input record %q", key)
		}
		want[key] = r
	}
	for _, r := range got {
		key := r.Name + "|" + TypeName(r.Type)
		w, ok := want[key]
		if !ok {
			t.Errorf("unexpected record %q of type %d", r.Name, r.Type)
			continue
		}
		if !bytes.Equal(r.RData, w.RData) {
			t.Errorf("record %q RDATA mismatch:\n got  %x\n want %x", r.Name, r.RData, w.RData)
		}
	}
}

// TestParseZone_GenericUnknown verifies that the RFC 3597 §5 generic
// form is parsed back to the same wire bytes. The writer emits this
// form for any type the dns package does not model as a struct (TLSA,
// NAPTR, …); the parser must round-trip it byte-for-byte.
func TestParseZone_GenericUnknown(t *testing.T) {
	apex := "example.com."
	soaRData := buildSOA(t, "ns.example.com.", "hostmaster.example.com.",
		2024010101, 7200, 3600, 1209600, 3600)
	unknownRData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	src := []ResourceRecord{
		{Name: apex, Type: TypeSOA, Class: ClassIN, TTL: 86400, RData: soaRData},
		{Name: "unknown.example.com.", Type: 999, Class: ClassIN, TTL: 60, RData: unknownRData},
	}
	formatted, err := FormatZone(apex, src)
	if err != nil {
		t.Fatalf("FormatZone: %v", err)
	}
	got, err := ParseZone(apex, formatted)
	if err != nil {
		t.Fatalf("ParseZone: %v\nformatted:\n%s", err, formatted)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[1].Type != 999 {
		t.Errorf("Type = %d, want 999", got[1].Type)
	}
	if !bytes.Equal(got[1].RData, unknownRData) {
		t.Errorf("RData mismatch:\n got  %x\n want %x", got[1].RData, unknownRData)
	}
}

// TestParseZone_TTLDirective demonstrates that a $TTL directive at the
// top of the file applies to records without an explicit TTL column.
// The writer does not emit a $TTL directive when every record carries
// its own TTL, so a hand-written file that omits per-record TTLs is the
// only way to exercise this path through the round-trip.
func TestParseZone_TTLDirective(t *testing.T) {
	apex := "example.com."
	text := `$TTL 1800
@	IN	SOA	ns.example.com. hostmaster.example.com. (
		2024010101	; serial
		7200	; refresh
		3600	; retry
		1209600	; expire
		3600	; minimum
		)
	IN	NS	ns.example.com.
www	IN	A	1.2.3.4
`
	got, err := ParseZone(apex, []byte(text))
	if err != nil {
		t.Fatalf("ParseZone: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3", len(got))
	}
	for _, r := range got {
		if r.TTL != 1800 {
			t.Errorf("record %q TTL = %d, want 1800 (from $TTL)", r.Name, r.TTL)
		}
	}
}

// TestParseZone_NoSOA returns an error for a file with no SOA — a
// parser that silently accepted such a file would let a misconfigured
// zone load through.
func TestParseZone_NoSOA(t *testing.T) {
	text := "@	IN	NS	ns.example.com.\n"
	_, err := ParseZone("example.com.", []byte(text))
	if err == nil {
		t.Fatalf("expected error for zone with no SOA, got nil")
	}
	if !strings.Contains(err.Error(), "no SOA") {
		t.Errorf("error = %q, want it to mention 'no SOA'", err)
	}
}

// TestParseZone_RejectInclude asserts that $INCLUDE is rejected. The
// parser is round-trip-only; allowing $INCLUDE would broaden the trust
// boundary past what the writer can produce.
func TestParseZone_RejectInclude(t *testing.T) {
	text := "$INCLUDE /etc/bind/some-other-zone\n@	IN	SOA	ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600\n"
	_, err := ParseZone("example.com.", []byte(text))
	if err == nil {
		t.Fatalf("expected error for $INCLUDE, got nil")
	}
	if !strings.Contains(err.Error(), "$INCLUDE") {
		t.Errorf("error = %q, want it to mention $INCLUDE", err)
	}
}
