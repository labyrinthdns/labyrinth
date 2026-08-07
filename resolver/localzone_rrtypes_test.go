package resolver

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// Local zones could previously express only A, AAAA, CNAME, PTR, TXT and MX.
// That covers overriding an address, and nothing else an operator actually
// needs to override internally: an internal service-discovery SRV record, a
// delegation NS, or a CAA record — where getting it wrong blocks certificate
// issuance for the whole name.
//
// The encoders are where the risk sits. Each of these RDATA layouts has a
// detail that is easy to get wrong and produces a record that packs fine and
// means something different on the wire.

func mustParseLocal(t *testing.T, s string) *LocalRecord {
	t.Helper()
	rec, err := ParseLocalRecord(s)
	if err != nil {
		t.Fatalf("ParseLocalRecord(%q): %v", s, err)
	}
	return rec
}

// TestLocalZone_SRVEncoding pins RFC 2782's field order. Priority, weight and
// port are three consecutive uint16s, and transposing any two produces a
// record that parses cleanly and directs traffic to the wrong place.
func TestLocalZone_SRVEncoding(t *testing.T) {
	rec := mustParseLocal(t, "_sip._tcp.example.com. SRV 10 60 5060 sipserver.example.com.")

	if rec.Type != dns.TypeSRV {
		t.Fatalf("type = %d, want SRV", rec.Type)
	}
	if got := binary.BigEndian.Uint16(rec.RData[0:2]); got != 10 {
		t.Errorf("priority = %d, want 10", got)
	}
	if got := binary.BigEndian.Uint16(rec.RData[2:4]); got != 60 {
		t.Errorf("weight = %d, want 60", got)
	}
	if got := binary.BigEndian.Uint16(rec.RData[4:6]); got != 5060 {
		t.Errorf("port = %d, want 5060", got)
	}
	target, _, err := dns.DecodeName(rec.RData, 6)
	if err != nil {
		t.Fatalf("decode target: %v", err)
	}
	if target != "sipserver.example.com" {
		t.Errorf("target = %q, want sipserver.example.com", target)
	}
}

// TestLocalZone_CAAEncoding pins RFC 8659 §4.1. The tag is length-prefixed
// and the value is NOT — it runs to the end of the RDATA. Length-prefixing
// the value (the obvious symmetry) would put a stray octet at the front of
// the CA's domain name and silently authorise nobody.
func TestLocalZone_CAAEncoding(t *testing.T) {
	rec := mustParseLocal(t, `example.com. CAA 0 issue "letsencrypt.org"`)

	if rec.Type != dns.TypeCAA {
		t.Fatalf("type = %d, want CAA", rec.Type)
	}
	if rec.RData[0] != 0 {
		t.Errorf("flags = %d, want 0", rec.RData[0])
	}
	tagLen := int(rec.RData[1])
	if tagLen != len("issue") {
		t.Fatalf("tag length = %d, want %d", tagLen, len("issue"))
	}
	if got := string(rec.RData[2 : 2+tagLen]); got != "issue" {
		t.Errorf("tag = %q, want %q", got, "issue")
	}
	if got := string(rec.RData[2+tagLen:]); got != "letsencrypt.org" {
		t.Errorf("value = %q, want %q — the value is unprefixed and runs to the "+
			"end of the RDATA (RFC 8659 §4.1)", got, "letsencrypt.org")
	}
}

// TestLocalZone_CAATagLowercased pins RFC 8659 §4.1: the property tag is
// lowercase. A CA matching "ISSUE" against its expected "issue" finds no
// authorisation and refuses to issue.
func TestLocalZone_CAATagLowercased(t *testing.T) {
	rec := mustParseLocal(t, `example.com. CAA 0 ISSUE "letsencrypt.org"`)
	tagLen := int(rec.RData[1])
	if got := string(rec.RData[2 : 2+tagLen]); got != "issue" {
		t.Errorf("tag = %q, want it lowercased to %q", got, "issue")
	}
}

// TestLocalZone_NSEncoding pins that NS carries a bare uncompressed name,
// the same shape as CNAME and PTR.
func TestLocalZone_NSEncoding(t *testing.T) {
	rec := mustParseLocal(t, "internal.example. NS ns1.internal.example.")
	if rec.Type != dns.TypeNS {
		t.Fatalf("type = %d, want NS", rec.Type)
	}
	name, _, err := dns.DecodeName(rec.RData, 0)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if name != "ns1.internal.example" {
		t.Errorf("NS target = %q", name)
	}
}

// TestLocalZone_MalformedRecordsRejected pins that a bad record is an error at
// config-load time rather than a record that serves nonsense. A local zone is
// authoritative for its names, so a malformed entry is not merely ignored —
// it would be answered with.
func TestLocalZone_MalformedRecordsRejected(t *testing.T) {
	cases := []string{
		"x.example. SRV 10 60 sipserver.example.",      // missing port
		"x.example. SRV 10 60 99999 target.example.",   // port out of range
		"x.example. SRV a b c target.example.",         // non-numeric
		"x.example. CAA 0 issue",                       // missing value
		"x.example. CAA 999 issue \"letsencrypt.org\"", // flags out of range
		"x.example. MX mail.example.",                  // missing preference
		"x.example. ZONEMD 1 2 3",                      // type the encoder cannot build
	}
	for _, s := range cases {
		if _, err := ParseLocalRecord(s); err == nil {
			t.Errorf("ParseLocalRecord(%q) succeeded; malformed local records must "+
				"be rejected at load rather than served", s)
		}
	}
}

// TestLocalZone_TypeAllowlistIsDeliberate pins that the accepted type names
// are an allowlist matched to what the encoder can actually build, not the
// resolver's full type registry. Accepting a name the encoder then rejects
// would turn a clear "unsupported type" into a confusing per-record failure.
func TestLocalZone_TypeAllowlistIsDeliberate(t *testing.T) {
	for name, qtype := range localZoneTypes {
		// Every listed type must round-trip through the encoder for at
		// least one well-formed input, or the allowlist is lying.
		if _, err := encodeRData(qtype, sampleRData(name)); err != nil {
			t.Errorf("type %s is in the allowlist but encodeRData rejects a "+
				"well-formed value: %v", name, err)
		}
	}
}

func sampleRData(typeName string) string {
	switch typeName {
	case "A":
		return "192.0.2.1"
	case "AAAA":
		return "2001:db8::1"
	case "CNAME", "PTR", "NS":
		return "target.example.com."
	case "TXT":
		return `"hello"`
	case "MX":
		return "10 mail.example.com."
	case "SRV":
		return "10 60 5060 sip.example.com."
	case "CAA":
		return `0 issue "letsencrypt.org"`
	}
	return ""
}
