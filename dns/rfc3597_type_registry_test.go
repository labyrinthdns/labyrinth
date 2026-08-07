package dns

import "testing"

// The RR type registry had drifted into four partial copies: dns.TypeToString,
// a ten-entry map in the cache API, an eleven-case switch in the trace API,
// and a twenty-case switch in the resolver's trace formatter. Each covered a
// different subset, so which record types you could see — or query — depended
// on which page of the dashboard you happened to be on. TLSA, CAA, SVCB and
// HTTPS were resolvable and cacheable but invisible and unqueryable.
//
// These tests pin the single registry those four now share, and the two
// properties that make the consolidation safe: the inverse map cannot drift
// from the forward map, and every type has a displayable name.

// TestTypeRegistryRoundTrip pins that StringToType is a true inverse of
// TypeToString. It is derived at init rather than hand-written precisely so
// this cannot fail — the test guards against someone "optimising" it back
// into a literal.
func TestTypeRegistryRoundTrip(t *testing.T) {
	for code, name := range TypeToString {
		got, ok := StringToType[name]
		if !ok {
			t.Errorf("type %d (%s) is in TypeToString but missing from StringToType", code, name)
			continue
		}
		if got != code {
			t.Errorf("StringToType[%q] = %d, want %d", name, got, code)
		}
	}
	if len(StringToType) != len(TypeToString) {
		t.Errorf("registry size mismatch: %d names for %d types — two types share a name",
			len(StringToType), len(TypeToString))
	}
}

// TestTypeNameAlwaysDisplayable pins RFC 3597 §5: an implementation that
// meets a type it has no mnemonic for presents it as TYPE<n>. Returning ""
// (the old behaviour of indexing the map directly) renders as a blank column
// in the cache viewer, which reads as "no data" rather than "unusual type".
func TestTypeNameAlwaysDisplayable(t *testing.T) {
	if got := TypeName(TypeTLSA); got != "TLSA" {
		t.Errorf("TypeName(52) = %q, want %q", got, "TLSA")
	}
	if got := TypeName(999); got != "TYPE999" {
		t.Errorf("TypeName(999) = %q, want %q (RFC 3597 §5 generic form)", got, "TYPE999")
	}
	if got := TypeName(0); got != "TYPE0" {
		t.Errorf("TypeName(0) = %q, want %q", got, "TYPE0")
	}
}

// TestParseTypeAcceptsGenericForm pins the other half of RFC 3597 §5. The
// resolver already caches types this build has never heard of — correctly,
// as opaque RDATA. Accepting TYPE<n> on input is what lets an operator
// actually look at them.
func TestParseTypeAcceptsGenericForm(t *testing.T) {
	cases := []struct {
		in   string
		want uint16
		ok   bool
	}{
		{"TLSA", TypeTLSA, true},
		{"tlsa", TypeTLSA, true},     // case-insensitive
		{"  TLSA  ", TypeTLSA, true}, // trimmed
		{"TYPE52", TypeTLSA, true},   // generic form of a known type
		{"TYPE999", 999, true},       // generic form of an unknown type
		{"TYPE65535", 65535, true},   // top of the range
		{"TYPE65536", 0, false},      // out of range for uint16
		{"TYPE", 0, false},           // prefix with no number
		{"TYPEABC", 0, false},        // prefix with a non-number
		{"", 0, false},
		{"NOTAREALTYPE", 0, false},
	}
	for _, tc := range cases {
		got, ok := ParseType(tc.in)
		if ok != tc.ok {
			t.Errorf("ParseType(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("ParseType(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestTypeConstantsMatchIANA pins the wire values of the types added in this
// pass. These are the numbers that decide how a record is interpreted, and a
// transposed digit would make the resolver label one type as another —
// silently, since RFC 3597 passthrough means the RDATA still round-trips.
func TestTypeConstantsMatchIANA(t *testing.T) {
	iana := map[string]uint16{
		"LOC": 29, "NAPTR": 35, "CERT": 37, "SSHFP": 44, "IPSECKEY": 45,
		"DHCID": 49, "TLSA": 52, "SMIMEA": 53, "HIP": 55, "OPENPGPKEY": 61,
		"CSYNC": 62, "ZONEMD": 63, "SVCB": 64, "HTTPS": 65, "SPF": 99,
		"NID": 104, "L32": 105, "L64": 106, "LP": 107, "EUI48": 108,
		"EUI64": 109, "TKEY": 249, "TSIG": 250, "IXFR": 251, "AXFR": 252,
		"URI": 256, "CAA": 257, "RESINFO": 261, "TA": 32768, "DLV": 32769,
	}
	for name, want := range iana {
		got, ok := StringToType[name]
		if !ok {
			t.Errorf("%s is not registered", name)
			continue
		}
		if got != want {
			t.Errorf("%s = %d, want %d (IANA DNS Parameters registry)", name, got, want)
		}
	}
}

// TestOpcodeConstantsMatchIANA pins the opcodes. NOTIFY and UPDATE are
// refused with NOTIMP rather than served, but naming them is what turns an
// opaque rejection into a diagnosable one for an operator who pointed a
// primary at this resolver by mistake.
func TestOpcodeConstantsMatchIANA(t *testing.T) {
	cases := map[string]uint8{
		"QUERY": OpcodeQuery, "IQUERY": OpcodeIQuery, "STATUS": OpcodeStatus,
		"NOTIFY": OpcodeNotify, "UPDATE": OpcodeUpdate, "DSO": OpcodeDSO,
	}
	want := map[string]uint8{
		"QUERY": 0, "IQUERY": 1, "STATUS": 2, "NOTIFY": 4, "UPDATE": 5, "DSO": 6,
	}
	for name, got := range cases {
		if got != want[name] {
			t.Errorf("Opcode %s = %d, want %d", name, got, want[name])
		}
	}
}
