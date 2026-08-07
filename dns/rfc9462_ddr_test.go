package dns

import (
	"bytes"
	"testing"
)

// RFC 9462 Discovery of Designated Resolvers, and the RFC 9461 SvcParams it
// rides on.
//
// DDR exists because a client that learned this resolver's address from DHCP
// has an IP and nothing else. It cannot know DoT, DoH or DoQ are available,
// so it uses plaintext port 53 and the encrypted listeners sit idle. The
// SVCB answer to `_dns.resolver.arpa` is the bootstrap out of that.
//
// The encoding rules are unusually easy to get subtly wrong — ALPN is
// length-prefixed per protocol rather than as a list, parameters must be in
// increasing key order, and a wrong port silently becomes "use the default".
// Each of those produces a record that looks plausible in a hex dump and is
// rejected or misread by real clients, so they are pinned individually.

// TestRFC9462_QueryNameRecognition pins which questions trigger a
// designation. The name is special-use with no delegation in the global DNS:
// treating it as ordinary would forward the client's discovery attempt
// upstream and return NXDOMAIN.
func TestRFC9462_QueryNameRecognition(t *testing.T) {
	cases := []struct {
		name  string
		qtype uint16
		want  bool
	}{
		{"_dns.resolver.arpa", TypeSVCB, true},
		{"_dns.resolver.arpa.", TypeSVCB, true},  // trailing dot
		{"_DNS.RESOLVER.ARPA", TypeSVCB, true},   // RFC 4343 case-insensitive
		{"_dns.resolver.arpa", TypeA, false},     // only SVCB designates
		{"_dns.resolver.arpa", TypeHTTPS, false}, // HTTPS is a different type
		{"resolver.arpa", TypeSVCB, false},
		{"_dns.resolver.arpa.evil.example", TypeSVCB, false}, // not a suffix match
		{"", TypeSVCB, false},
	}
	for _, tc := range cases {
		if got := IsDDRQuery(tc.name, tc.qtype); got != tc.want {
			t.Errorf("IsDDRQuery(%q, %d) = %v, want %v", tc.name, tc.qtype, got, tc.want)
		}
	}
}

// TestRFC9462_DisabledWithoutTargetName pins the opt-in. Without a name whose
// certificate covers this resolver's address, every designation we publish
// fails the client's RFC 9462 §4.2 verification — so we would be spending a
// round trip to hand out something guaranteed not to work.
func TestRFC9462_DisabledWithoutTargetName(t *testing.T) {
	cfg := DDRConfig{DoTEnabled: true, DoHEnabled: true, DoQEnabled: true}
	if cfg.Enabled() {
		t.Error("DDR reported enabled with no target name")
	}
	records, err := BuildDDRAnswer(cfg)
	if err != nil {
		t.Fatalf("BuildDDRAnswer: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("built %d designations with no target name, want 0", len(records))
	}
}

// TestRFC9462_DisabledWithoutTransports pins the other half: a target name
// but nothing encrypted to designate.
func TestRFC9462_DisabledWithoutTransports(t *testing.T) {
	cfg := DDRConfig{TargetName: "dns.example.net"}
	if cfg.Enabled() {
		t.Error("DDR reported enabled with no encrypted transport")
	}
}

// TestRFC9462_OnlyEnabledTransportsAdvertised pins that the designation
// tracks what is actually running. Advertising a listener that is switched
// off sends the client to a closed port, and a client that cannot reach a
// designated resolver falls back to plaintext — so an over-eager designation
// is worse than none.
func TestRFC9462_OnlyEnabledTransportsAdvertised(t *testing.T) {
	cfg := DDRConfig{
		TargetName: "dns.example.net",
		DoTEnabled: true,
		DoTPort:    853,
		// DoH and DoQ deliberately off.
	}
	designations := cfg.Designations()
	if len(designations) != 1 {
		t.Fatalf("got %d designations, want 1 (DoT only)", len(designations))
	}
	if len(designations[0].ALPNs) != 1 || designations[0].ALPNs[0] != ALPNDoT {
		t.Errorf("ALPNs = %v, want [%s]", designations[0].ALPNs, ALPNDoT)
	}
}

// TestRFC9462_PriorityOrdering pins the preference order and its reasoning:
// DoH first because 443 traverses middleboxes that drop 853 outright, so the
// client is least likely to end up back on plaintext.
func TestRFC9462_PriorityOrdering(t *testing.T) {
	cfg := DDRConfig{
		TargetName: "dns.example.net",
		DoTEnabled: true, DoTPort: 853,
		DoQEnabled: true, DoQPort: 853,
		DoHEnabled: true, DoHPort: 443,
	}
	designations := cfg.Designations()
	if len(designations) != 3 {
		t.Fatalf("got %d designations, want 3", len(designations))
	}

	wantALPN := []string{ALPNDoH2, ALPNDoT, ALPNDoQ}
	for i, want := range wantALPN {
		if designations[i].ALPNs[0] != want {
			t.Errorf("designation %d ALPN = %s, want %s", i, designations[i].ALPNs[0], want)
		}
		if designations[i].Priority != uint16(i+1) {
			t.Errorf("designation %d priority = %d, want %d", i, designations[i].Priority, i+1)
		}
	}
}

// TestRFC9461_ALPNEncoding pins RFC 9460 §7.1.1. The one-octet length prefix
// is per protocol identifier, not for the list as a whole. A concatenation
// without prefixes decodes as one long garbage protocol name, which a client
// silently fails to match rather than reporting.
func TestRFC9461_ALPNEncoding(t *testing.T) {
	p := SvcParamALPNValue("h2", "h3")
	want := []byte{2, 'h', '2', 2, 'h', '3'}
	if !bytes.Equal(p.Value, want) {
		t.Fatalf("alpn value = %v, want %v", p.Value, want)
	}
	if p.Key != SvcParamALPN {
		t.Errorf("alpn key = %d, want %d", p.Key, SvcParamALPN)
	}
}

// TestRFC9461_DoHPathIsRawTemplate pins RFC 9461 §5: dohpath carries the URI
// template verbatim, delimited by the parameter's own length field. Adding a
// length prefix (as ALPN needs) would put a stray byte at the front of the
// path and every DoH request would 404.
func TestRFC9461_DoHPathIsRawTemplate(t *testing.T) {
	const template = "/dns-query{?dns}"
	p := SvcParamDoHPathValue(template)
	if string(p.Value) != template {
		t.Fatalf("dohpath value = %q, want %q", p.Value, template)
	}
	if p.Key != SvcParamDoHPath {
		t.Errorf("dohpath key = %d, want 7 (RFC 9461 §5)", p.Key)
	}
}

// TestRFC9460_ParamsSortedByKey pins §2.2's strictly-increasing-key rule.
// A caller listing parameters in reading order (alpn, dohpath, port) would
// otherwise emit key order 1, 7, 3 — which a conforming receiver may reject
// outright, producing an interop failure that only shows up against some
// client implementations.
func TestRFC9460_ParamsSortedByKey(t *testing.T) {
	rdata, err := BuildSVCBRData(1, "dns.example.net", []SvcParam{
		SvcParamDoHPathValue("/dns-query{?dns}"), // key 7
		SvcParamALPNValue("h2"),                  // key 1
		SvcParamPortValue(443),                   // key 3
	})
	if err != nil {
		t.Fatalf("BuildSVCBRData: %v", err)
	}

	params, err := ParseSVCBParams(rdata)
	if err != nil {
		t.Fatalf("ParseSVCBParams: %v", err)
	}
	if len(params) != 3 {
		t.Fatalf("parsed %d params, want 3", len(params))
	}
	wantKeys := []uint16{SvcParamALPN, SvcParamPort, SvcParamDoHPath}
	for i, want := range wantKeys {
		if params[i].Key != want {
			t.Errorf("param %d key = %d, want %d (RFC 9460 §2.2 requires increasing order)",
				i, params[i].Key, want)
		}
	}
}

// TestRFC9460_DuplicateParamRejected pins that a repeated key is an error
// rather than two encoded entries. RFC 9460 §2.2 forbids repetition, and
// emitting both would produce a record some clients accept and others reject.
func TestRFC9460_DuplicateParamRejected(t *testing.T) {
	_, err := BuildSVCBRData(1, "dns.example.net", []SvcParam{
		SvcParamALPNValue("h2"),
		SvcParamALPNValue("h3"),
	})
	if err == nil {
		t.Fatal("duplicate SvcParam key accepted")
	}
}

// TestRFC9462_AnswerShape pins the full record: owner name, type, class and
// TTL, plus a round-trip through the parameter parser.
func TestRFC9462_AnswerShape(t *testing.T) {
	cfg := DDRConfig{
		TargetName: "dns.example.net",
		DoHEnabled: true, DoHPort: 443, DoHPath: "/dns-query{?dns}",
	}
	records, err := BuildDDRAnswer(cfg)
	if err != nil {
		t.Fatalf("BuildDDRAnswer: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	rr := records[0]

	if rr.Name != DDRQueryName {
		t.Errorf("owner = %q, want %q", rr.Name, DDRQueryName)
	}
	if rr.Type != TypeSVCB {
		t.Errorf("type = %d, want SVCB (64)", rr.Type)
	}
	if rr.Class != ClassIN {
		t.Errorf("class = %d, want IN", rr.Class)
	}
	if rr.TTL != DDRTTL {
		t.Errorf("ttl = %d, want %d", rr.TTL, DDRTTL)
	}
	if int(rr.RDLength) != len(rr.RData) {
		t.Errorf("RDLength = %d but RData is %d octets", rr.RDLength, len(rr.RData))
	}

	// Priority must be ServiceMode: RFC 9460 §2.4.2 reserves 0 for
	// AliasMode, which forbids the parameters a designation depends on.
	priority := uint16(rr.RData[0])<<8 | uint16(rr.RData[1])
	if priority == 0 {
		t.Error("priority 0 is AliasMode, which cannot carry SvcParams")
	}

	params, err := ParseSVCBParams(rr.RData)
	if err != nil {
		t.Fatalf("ParseSVCBParams: %v", err)
	}
	found := map[uint16][]byte{}
	for _, p := range params {
		found[p.Key] = p.Value
	}
	if string(found[SvcParamDoHPath]) != "/dns-query{?dns}" {
		t.Errorf("dohpath = %q", found[SvcParamDoHPath])
	}
	if !bytes.Equal(found[SvcParamALPN], []byte{2, 'h', '2'}) {
		t.Errorf("alpn = %v", found[SvcParamALPN])
	}
	if !bytes.Equal(found[SvcParamPort], []byte{0x01, 0xBB}) { // 443
		t.Errorf("port = %v, want 443", found[SvcParamPort])
	}
}

// TestRFC9462_ZeroPortOmitsParam pins that port 0 means "omit", not
// "advertise port zero". SVCB has no way to express port 0, and a client
// reading it would connect somewhere unintended.
func TestRFC9462_ZeroPortOmitsParam(t *testing.T) {
	cfg := DDRConfig{TargetName: "dns.example.net", DoTEnabled: true, DoTPort: 0}
	records, err := BuildDDRAnswer(cfg)
	if err != nil {
		t.Fatalf("BuildDDRAnswer: %v", err)
	}
	params, err := ParseSVCBParams(records[0].RData)
	if err != nil {
		t.Fatalf("ParseSVCBParams: %v", err)
	}
	for _, p := range params {
		if p.Key == SvcParamPort {
			t.Error("a port parameter was emitted for port 0; it must be omitted " +
				"so the client uses the ALPN default")
		}
	}
}

// TestRFC9462_DoH3AddsALPN pins that enabling HTTP/3 extends the DoH
// designation rather than creating a second one — same endpoint, two
// protocols, which is what the ALPN list is for.
func TestRFC9462_DoH3AddsALPN(t *testing.T) {
	cfg := DDRConfig{
		TargetName: "dns.example.net",
		DoHEnabled: true, DoH3Enabled: true, DoHPort: 443,
	}
	designations := cfg.Designations()
	if len(designations) != 1 {
		t.Fatalf("got %d designations, want 1", len(designations))
	}
	if len(designations[0].ALPNs) != 2 {
		t.Fatalf("ALPNs = %v, want both h2 and h3", designations[0].ALPNs)
	}
}

// TestRFC9462_DefaultDoHPath pins the fallback template. RFC 9461 §5 defines
// no default, but a DoH designation without a dohpath is unusable — the
// client has a host and port and no idea what to GET.
func TestRFC9462_DefaultDoHPath(t *testing.T) {
	cfg := DDRConfig{TargetName: "dns.example.net", DoHEnabled: true}
	designations := cfg.Designations()
	if len(designations) != 1 {
		t.Fatalf("got %d designations, want 1", len(designations))
	}
	if designations[0].DoHPath != "/dns-query{?dns}" {
		t.Errorf("default dohpath = %q, want %q", designations[0].DoHPath, "/dns-query{?dns}")
	}
}

// TestRFC9606_RESINFOEncoding pins the RESINFO payload (RFC 9606 §6): TXT
// wire format, with "qnamemin" as a bare presence flag rather than a
// key=value pair.
func TestRFC9606_RESINFOEncoding(t *testing.T) {
	rdata := BuildRESINFORData(ResolverInfo{
		QnameMinimisation: true,
		ExtendedErrors:    []uint16{15, 16, 17},
		InfoURL:           "https://resolver.example/policy",
	})

	strs, err := ParseTXT(rdata)
	if err != nil {
		t.Fatalf("ParseTXT: %v", err)
	}
	want := []string{
		"qnamemin",
		"exterr=15,16,17",
		"infourl=https://resolver.example/policy",
	}
	if len(strs) != len(want) {
		t.Fatalf("got %d strings %v, want %d", len(strs), strs, len(want))
	}
	for i := range want {
		if strs[i] != want[i] {
			t.Errorf("string %d = %q, want %q", i, strs[i], want[i])
		}
	}
}

// TestRFC9606_EmptyInfoProducesNoRecord pins that a resolver with nothing to
// declare publishes nothing, rather than an empty record that claims to have
// declared nothing.
func TestRFC9606_EmptyInfoProducesNoRecord(t *testing.T) {
	if rdata := BuildRESINFORData(ResolverInfo{}); rdata != nil {
		t.Errorf("empty ResolverInfo produced %d octets of RDATA, want none", len(rdata))
	}
}
