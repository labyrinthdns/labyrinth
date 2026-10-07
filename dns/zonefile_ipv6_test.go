package dns

import (
	"bytes"
	"testing"
)

// RFC 4291 §2.2 allows an IPv6 address to end with an embedded IPv4
// dotted-quad, which stands for the final 32 bits. BIND and dig accept these
// forms and operators write them, but this parser used to discard them:
// splitIPv6Groups parses each field with strconv.ParseUint(f, 16, 16), a
// dotted field fails, and the function returns nil for the ENTIRE half — so
// parseIPv6 zero-padded past the garbage and returned a *different address*
// with no error. "::ffff:192.0.2.1" silently became "::".
//
// Note the failure mode is silent corruption, not rejection: nothing errored,
// the record just held the wrong 16 bytes.

const ipv6ShorthandHdr = `@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300
@ IN NS ns1.example.com.
`

// parseAAAA parses a one-record zone and returns the AAAA RDATA.
func parseAAAA(t *testing.T, addr string) []byte {
	t.Helper()
	records, err := ParseZone("example.com.", []byte(ipv6ShorthandHdr+"v6 IN AAAA "+addr+"\n"))
	if err != nil {
		t.Fatalf("ParseZone with AAAA %q: unexpected error: %v", addr, err)
	}
	for _, r := range records {
		if r.Type == TypeAAAA {
			return r.RData
		}
	}
	t.Fatalf("AAAA %q produced no record", addr)
	return nil
}

// Embedded IPv4 forms must keep their final 32 bits.
func TestParseZone_AAAAEmbeddedIPv4(t *testing.T) {
	tests := []struct {
		label string
		addr  string
		want  []byte
	}{
		// 192.0.2.1 == c0.00.02.01
		{"IPv4-mapped", "::ffff:192.0.2.1",
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x01}},
		// RFC 6052 NAT64 well-known prefix
		{"NAT64 prefix", "64:ff9b::192.0.2.1",
			[]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0x00, 0x02, 0x01}},
		// IPv4-compatible
		{"IPv4-compatible", "::192.0.2.1",
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0x00, 0x02, 0x01}},
		// An embedded quad after an explicit prefix
		{"after a prefix", "2001:db8::1.2.3.4",
			[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04}},
	}
	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			got := parseAAAA(t, tc.addr)
			if !bytes.Equal(got, tc.want) {
				t.Errorf("AAAA %q parsed to %x, want %x; the embedded IPv4 address "+
					"was discarded and the zone stored a different address",
					tc.addr, got, tc.want)
			}
		})
	}
}

// CONTROL: the forms without an embedded quad must be unchanged. A fix that
// mangled ordinary shorthand would break these.
func TestParseZone_AAAAWithoutEmbeddedIPv4(t *testing.T) {
	tests := []struct {
		addr string
		want []byte
	}{
		{"2001:db8::1", []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"::1", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"::", make([]byte, 16)},
		// The writer's own hex form for an IPv4-mapped address
		// (dns/zonefile_rdata.go emits "::ffff:%x:%x").
		{"::ffff:c0a8:0101", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01}},
		{"2001:db8:1:2:3:4:5:6", []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06}},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			got := parseAAAA(t, tc.addr)
			if !bytes.Equal(got, tc.want) {
				t.Errorf("AAAA %q parsed to %x, want %x", tc.addr, got, tc.want)
			}
		})
	}
}

// expandIPv4Suffix is the boundary that decides whether a dotted tail is
// rewritten or rejected, so it is pinned directly: a bad literal must be
// refused outright rather than quietly zero-filled.
func TestExpandIPv4Suffix(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"::ffff:192.0.2.1", "::ffff:c000:201", true},
		{"64:ff9b::192.0.2.1", "64:ff9b::c000:201", true},
		{"2001:db8::1.2.3.4", "2001:db8::102:304", true},
		{"::0.0.0.0", "::0:0", true},
		{"::255.255.255.255", "::ffff:ffff", true},
		// No dotted tail: passed through untouched.
		{"2001:db8::1", "2001:db8::1", true},
		{"::ffff:c0a8:0101", "::ffff:c0a8:0101", true},
		{"", "", true},
		// A dotted tail that is not a valid IPv4 literal is refused, so the
		// caller errors instead of storing a truncated address.
		{"::192.0.2", "::192.0.2", false},
		{"::192.0.2.1.5", "::192.0.2.1.5", false},
		{"::192.0.2.300", "::192.0.2.300", false},
		{"::1.2.3.x", "::1.2.3.x", false},
	}
	for _, tc := range tests {
		got, ok := expandIPv4Suffix(tc.in)
		if ok != tc.wantOK {
			t.Errorf("expandIPv4Suffix(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
		}
		if got != tc.want {
			t.Errorf("expandIPv4Suffix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A malformed embedded quad must be reported, never silently zero-filled.
func TestParseZone_AAAARejectsMalformedEmbeddedIPv4(t *testing.T) {
	for _, addr := range []string{"::192.0.2", "::192.0.2.1.5", "::192.0.2.300"} {
		if _, err := ParseZone("example.com.",
			[]byte(ipv6ShorthandHdr+"v6 IN AAAA "+addr+"\n")); err == nil {
			t.Errorf("AAAA %q was accepted; a malformed embedded IPv4 address must be an error", addr)
		}
	}
}

// The round-trip contract still holds for the writer's hex form: the writer
// never emits a dotted-quad, so its output must parse back unchanged.
func TestParseZone_AAAAWriterFormRoundTrips(t *testing.T) {
	seed := ipv6ShorthandHdr + "v6 IN AAAA ::ffff:c000:201\n"
	first, err := ParseZone("example.com.", []byte(seed))
	if err != nil {
		t.Fatalf("seed parse failed: %v", err)
	}
	out, err := FormatZone("example.com.", first)
	if err != nil {
		t.Fatalf("FormatZone failed: %v", err)
	}
	second, err := ParseZone("example.com.", out)
	if err != nil {
		t.Fatalf("parse of writer output failed: %v", err)
	}
	if len(second) != len(first) {
		t.Fatalf("round trip changed the record count: %d -> %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Type == TypeAAAA && !bytes.Equal(first[i].RData, second[i].RData) {
			t.Errorf("AAAA round trip changed %x to %x", first[i].RData, second[i].RData)
		}
	}
}

// splitIPv6Groups must not conflate "empty input" with "unparseable group".
// Returning a bare nil for both let parseIPv6 zero-pad past the unreadable text
// and return a DIFFERENT address with no error: "::zzz" silently became "::"
// and "2001:db8::zzz" became "2001:db8::". Garbage in an address has to be an
// error, not a silent truncation.
func TestSplitIPv6Groups(t *testing.T) {
	tests := []struct {
		in     string
		want   []uint16
		wantOK bool
	}{
		{"", nil, true},
		{"2001", []uint16{0x2001}, true},
		{"db8:1", []uint16{0x0db8, 1}, true},
		{"ffff", []uint16{0xffff}, true},
		// Garbage is refused rather than dropped.
		{"zzz", nil, false},
		{"2001:zzz", nil, false},
		// Ten valid groups are split fine here; parseIPv6 is what enforces
		// the eight-group limit, so this is not a split-level failure.
		{"db8:1:2:3:4:5:6:7:8:9", []uint16{0x0db8, 1, 2, 3, 4, 5, 6, 7, 8, 9}, true},
		{"1:2:3:4:5:6:7:8:", nil, false},
		{"1.", nil, false},
	}
	for _, tc := range tests {
		got, ok := splitIPv6Groups(tc.in)
		if ok != tc.wantOK {
			t.Errorf("splitIPv6Groups(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
		}
		if len(got) != len(tc.want) {
			t.Errorf("splitIPv6Groups(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitIPv6Groups(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}

// An address containing an unparseable group must be reported, never silently
// zero-filled or truncated to a shorter prefix.
func TestParseZone_AAAARejectsUnparseableGroups(t *testing.T) {
	for _, addr := range []string{"::zzz", "2001:db8::zzz", "2001:db8:zzz::1"} {
		if _, err := ParseZone("example.com.",
			[]byte(ipv6ShorthandHdr+"v6 IN AAAA "+addr+"\n")); err == nil {
			t.Errorf("AAAA %q was accepted; an unparseable group must be an error "+
				"rather than a silently truncated address", addr)
		}
	}
}
