package dns

import (
	"strings"
	"testing"
)

// TestFormatZone_Basic checks that a small zone with an SOA, NS, MX, A
// record set serialises to a recognisable BIND file. The shapes are
// the ones a RFC 1035 reader would produce; the actual TTL numbers
// are not part of the assertion because the writer picks the smallest
// TTL in the zone for the $TTL directive by design (see FormatZone).
//
func TestFormatZone_Basic(t *testing.T) {
	apex := "example.com."

	// Build RDATA bytes for the records we want to round-trip.
	soaRData := buildSOA(t, "ns.example.com.", "hostmaster.example.com.",
		2024010101, 7200, 3600, 1209600, 3600)
	nsRData := buildName(t, "ns.example.com.")
	mxRData := buildMX(t, 10, "mail.example.com.")
	aRData := []byte{1, 2, 3, 4}

	records := []ResourceRecord{
		{Name: apex, Type: TypeSOA, Class: ClassIN, TTL: 86400, RData: soaRData},
		{Name: apex, Type: TypeNS, Class: ClassIN, TTL: 86400, RData: nsRData},
		{Name: apex, Type: TypeMX, Class: ClassIN, TTL: 86400, RData: mxRData},
		{Name: "www.example.com.", Type: TypeA, Class: ClassIN, TTL: 300, RData: aRData},
	}

	out, err := FormatZone(apex, records)
	if err != nil {
		t.Fatalf("FormatZone: %v", err)
	}
	got := string(out)

	// Hard checks: the file must contain the $TTL, the SOA header, the
	// NS, the MX, and the A record. The exact ordering of the lines
	// after the SOA header is hard to pin down without overfitting the
	// test, so we check substring presence rather than byte equality.
	mustContain(t, got, "$TTL")
	mustContain(t, got, "IN\tSOA\tns.example.com.")
	mustContain(t, got, "hostmaster.example.com.")
	mustContain(t, got, "2024010101")
	mustContain(t, got, "IN\tNS\tns.example.com.")
	mustContain(t, got, "IN\tMX\t10 mail.example.com.")
	mustContain(t, got, "www\t300\tIN\tA\t1.2.3.4")
}

// TestFormatZone_GenericUnknown confirms that an RR type the writer
// does not decode is emitted in RFC 3597 §5 generic form. This is the
// round-trip path for unknown types: same wire bytes in, same wire
// bytes out, no information loss.
//
func TestFormatZone_GenericUnknown(t *testing.T) {
	// TYPE999 with a 4-byte RDATA payload.
	rdata := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	records := []ResourceRecord{
		{Name: "example.com.", Type: TypeSOA, Class: ClassIN, TTL: 86400, RData: []byte{}},
		{Name: "example.com.", Type: 999, Class: ClassIN, TTL: 60, RData: rdata},
	}
	out, err := FormatZone("example.com.", records)
	if err != nil {
		t.Fatalf("FormatZone: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "TYPE999 \\# 4 deadbeef") {
		t.Errorf("expected RFC 3597 generic form `TYPE999 \\# 4 deadbeef`, got:\n%s", got)
	}
}

// TestFormatZone_EmptyRData confirms that an empty-RDATA record emits
// `TYPE<n> \# 0` rather than omitting the RDATA, so a parser reading
// the file back produces the same zero-length opaque block.
//
func TestFormatZone_EmptyRData(t *testing.T) {
	records := []ResourceRecord{
		{Name: "example.com.", Type: TypeSOA, Class: ClassIN, TTL: 86400, RData: []byte{}},
		{Name: "example.com.", Type: 999, Class: ClassIN, TTL: 60, RData: []byte{}},
	}
	out, err := FormatZone("example.com.", records)
	if err != nil {
		t.Fatalf("FormatZone: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "TYPE999 \\# 0") {
		t.Errorf("expected `TYPE999 \\# 0`, got:\n%s", got)
	}
}

// TestFormatZone_NoSOA confirms that emitting a zone without an SOA
// still produces a usable file (the $TTL directive is still set from
// the smallest TTL in the records, and records are written without
// the parenthesised header). This is the path for a partial zone
// dump — uncommon but useful for round-tripping a single RRset.
//
func TestFormatZone_NoSOA(t *testing.T) {
	records := []ResourceRecord{
		{Name: "example.com.", Type: TypeNS, Class: ClassIN, TTL: 86400, RData: buildName(t, "ns.example.com.")},
	}
	out, err := FormatZone("example.com.", records)
	if err != nil {
		t.Fatalf("FormatZone: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "$TTL 86400") {
		t.Errorf("expected $TTL 86400 from the only record's TTL, got:\n%s", got)
	}
	if !strings.Contains(got, "IN\tNS\tns.example.com.") {
		t.Errorf("expected NS line, got:\n%s", got)
	}
}

// TestFormatZone_TXTStringEscape confirms TXT records round-trip with
// backslash-escaped quotes intact. The wire form stores an embedded
// quote as a literal 0x22 byte, and the master-file form must escape
// it so the parser does not terminate the quoted string early.
//
func TestFormatZone_TXTStringEscape(t *testing.T) {
	// Two character-strings: one with an embedded quote, one normal.
	// Wire form: 1-byte length prefix, then that many bytes of content.
	rdata := []byte{
		5, '"', 'a', '"', 'b', 'X',  // 5-byte string: "a"bX
		4, 't', 'e', 'x', 't',       // 4-byte string: text
	}
	records := []ResourceRecord{
		{Name: "example.com.", Type: TypeSOA, Class: ClassIN, TTL: 86400, RData: []byte{}},
		{Name: "example.com.", Type: TypeTXT, Class: ClassIN, TTL: 60, RData: rdata},
	}
	out, err := FormatZone("example.com.", records)
	if err != nil {
		t.Fatalf("FormatZone: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, `"\"a\"bX" "text"`) {
		t.Errorf("expected escaped-quote TXT, got:\n%s", got)
	}
}

// TestEscapeName covers the backslash-decimal escape for non-printable
// characters and the literal pass-through for the safe set. The empty
// string and the all-dot edge cases are included because a caller
// might pass "" or "." in error and the writer must not panic.
//
func TestEscapeName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"normal", "normal"},
		{"with space", `with\ space`},
		{"with\nnewline", `with\010newline`},
		{"", ""},
		{".", "."},
		{"a.b.c", "a.b.c"},
		{`back\slash`, `back\\slash`},
		// The writer emits the RFC 1035 §5.1 `\DDD` decimal form for
		// non-printable characters and the master-file delimiters (`, `;`,
		// `(`, `)`); either decimal or symbolic form is valid and BIND
		// parsers accept both, so an exact `\059` is the documented
		// output here.
		{"semi;colon", `semi\059colon`},
	}
	for _, c := range cases {
		got := escapeName(c.in)
		if got != c.want {
			t.Errorf("escapeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFormatZone_TTLDefaultZero confirms that a record with TTL=0 gets
// the default 86400 (one day) rather than emitting a literal 0. The
// RFC 1035 master-file grammar permits a literal 0, but downstream
// tools (and the resolver's negative-cache TTL clamp) treat 0 as "no
// TTL", which is not what an operator exporting a zone expects. So
// the writer substitutes the BIND default.
//
func TestFormatZone_TTLDefaultZero(t *testing.T) {
	records := []ResourceRecord{
		{Name: "example.com.", Type: TypeSOA, Class: ClassIN, TTL: 86400, RData: []byte{}},
		{Name: "example.com.", Type: TypeNS, Class: ClassIN, TTL: 0, RData: buildName(t, "ns.example.com.")},
	}
	out, err := FormatZone("example.com.", records)
	if err != nil {
		t.Fatalf("FormatZone: %v", err)
	}
	if !strings.Contains(string(out), "86400\tIN\tNS") {
		t.Errorf("expected TTL 86400 substitution for zero-TTL record, got:\n%s", string(out))
	}
}

// --- helpers ---

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("output missing %q\n---\n%s\n---", needle, haystack)
	}
}

// buildSOA packs an SOA's RDATA in wire format. The five timers MUST be
// in the order serial, refresh, retry, expire, minimum (RFC 1035 §3.3.13).
//
func buildSOA(t *testing.T, mname, rname string, serial, refresh, retry, expire, minimum uint32) []byte {
	t.Helper()
	out := []byte{}
	out = appendName(out, mname)
	out = appendName(out, rname)
	for _, v := range []uint32{serial, refresh, retry, expire, minimum} {
		out = append(out, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return out
}

// buildName packs a single domain-name in wire format (no compression).
//
func buildName(t *testing.T, name string) []byte {
	t.Helper()
	out, err := EncodeNameToBytes(name)
	if err != nil {
		t.Fatalf("EncodeNameToBytes(%q): %v", name, err)
	}
	return out
}

// buildMX packs a 16-bit preference plus a single name. The caller
// supplies the preference and the exchange name; the helper is a
// thin wrapper that does the byte layout.
//
func buildMX(t *testing.T, pref uint16, exchange string) []byte {
	t.Helper()
	out := []byte{byte(pref >> 8), byte(pref)}
	out = append(out, buildName(t, exchange)...)
	return out
}

// appendName concatenates a wire-format name to an existing byte slice.
// (EncodeNameToBytes already returns a complete name; appendName is
// provided for symmetry with the build* helpers.)
//
func appendName(dst []byte, name string) []byte {
	encoded, err := EncodeNameToBytes(name)
	if err != nil {
		// Tests should not trigger this; the EncodeNameToBytes call
		// already panics on bad input.
		panic(err)
	}
	return append(dst, encoded...)
}
