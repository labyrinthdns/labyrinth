package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestClassifyResponseNXDomain(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
		},
	}

	rtype := classifyResponse(msg, "test.com", dns.TypeA)
	if rtype != responseNXDomain {
		t.Errorf("expected responseNXDomain, got %d", rtype)
	}
}

func TestClassifyResponseServFail(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build(),
		},
	}

	rtype := classifyResponse(msg, "test.com", dns.TypeA)
	if rtype != responseServFail {
		t.Errorf("expected responseServFail, got %d", rtype)
	}
}

func TestClassifyResponseAnswer(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
			ANCount: 1,
		},
		Answers: []dns.ResourceRecord{{
			Name: "test.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}},
	}

	rtype := classifyResponse(msg, "test.com", dns.TypeA)
	if rtype != responseAnswer {
		t.Errorf("expected responseAnswer, got %d", rtype)
	}
}

func TestClassifyResponseCNAME(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
			ANCount: 1,
		},
		Answers: []dns.ResourceRecord{{
			Name: "test.com", Type: dns.TypeCNAME, Class: dns.ClassIN,
			TTL: 300, RDLength: 0, RData: nil,
		}},
	}

	rtype := classifyResponse(msg, "test.com", dns.TypeA)
	if rtype != responseCNAME {
		t.Errorf("expected responseCNAME, got %d", rtype)
	}
}

func TestClassifyResponseReferral(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
			NSCount: 1,
		},
		Authority: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN,
			TTL: 3600, RDLength: 0, RData: nil,
		}},
	}

	rtype := classifyResponse(msg, "test.example.com", dns.TypeA)
	if rtype != responseReferral {
		t.Errorf("expected responseReferral, got %d", rtype)
	}
}

func TestClassifyResponseNoData(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
			NSCount: 1,
		},
		Authority: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
			TTL: 3600, RDLength: 0, RData: nil,
		}},
	}

	rtype := classifyResponse(msg, "test.example.com", dns.TypeAAAA)
	if rtype != responseNoData {
		t.Errorf("expected responseNoData, got %d", rtype)
	}
}

func TestMinimizeQName(t *testing.T) {
	r := &Resolver{config: ResolverConfig{QMinEnabled: true}}

	// At root: extract TLD
	name, qtype := r.minimizeQName("www.secret.example.com", dns.TypeA, "")
	if name != "com" || qtype != dns.TypeNS {
		t.Errorf("at root: expected ('com', NS), got ('%s', %d)", name, qtype)
	}

	// At "com": next label
	name, qtype = r.minimizeQName("www.secret.example.com", dns.TypeA, "com")
	if name != "example.com" || qtype != dns.TypeNS {
		t.Errorf("at 'com': expected ('example.com', NS), got ('%s', %d)", name, qtype)
	}

	// At "example.com": final query
	name, qtype = r.minimizeQName("www.secret.example.com", dns.TypeA, "example.com")
	if name != "secret.example.com" || qtype != dns.TypeNS {
		t.Errorf("at 'example.com': expected ('secret.example.com', NS), got ('%s', %d)", name, qtype)
	}

	// At "secret.example.com": one label left = final
	name, qtype = r.minimizeQName("www.secret.example.com", dns.TypeA, "secret.example.com")
	if name != "www.secret.example.com" || qtype != dns.TypeA {
		t.Errorf("at 'secret.example.com': expected ('www.secret.example.com', A), got ('%s', %d)", name, qtype)
	}
}

func TestVisitedSet(t *testing.T) {
	v := newVisitedSet()

	v.Add("1.2.3.4|test.com")
	if !v.Has("1.2.3.4|test.com") {
		t.Error("expected key to be present")
	}
	if v.Has("5.6.7.8|test.com") {
		t.Error("expected key to be absent")
	}

	v.AddCNAME("target.com")
	if !v.HasCNAME("target.com") {
		t.Error("expected CNAME to be present")
	}
	if !v.HasCNAME("TARGET.COM") {
		t.Error("CNAME check should be case-insensitive")
	}
}

func TestClassifyResponseRefused(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeRefused).Build(),
		},
	}

	rtype := classifyResponse(msg, "test.com", dns.TypeA)
	if rtype != responseServFail {
		t.Errorf("REFUSED should classify as responseServFail, got %d", rtype)
	}
}

func TestClassifyResponseEmptyFallback(t *testing.T) {
	// No answers, no authority, RCODE=0 → SERVFAIL fallback
	msg := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).Build(),
		},
	}

	rtype := classifyResponse(msg, "test.com", dns.TypeA)
	if rtype != responseServFail {
		t.Errorf("empty response should classify as responseServFail, got %d", rtype)
	}
}

func TestExtractDelegation(t *testing.T) {
	// Build NS RDATA for "ns1.example.com" (uncompressed, as produced by our Unpack)
	nsRData := buildPlainNameRData("ns1.example.com")
	ns2RData := buildPlainNameRData("ns2.example.com")

	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600,
				RDLength: uint16(len(nsRData)), RData: nsRData},
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600,
				RDLength: uint16(len(ns2RData)), RData: ns2RData},
		},
		Additional: []dns.ResourceRecord{
			{Name: "ns1.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600,
				RDLength: 4, RData: []byte{93, 184, 216, 34}},
			{Name: "ns2.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600,
				RDLength: 4, RData: []byte{93, 184, 216, 35}},
		},
	}

	delegation, zone := extractDelegation(msg)
	if zone != "example.com" {
		t.Errorf("zone: expected 'example.com', got %q", zone)
	}
	if len(delegation) != 2 {
		t.Fatalf("expected 2 NS, got %d", len(delegation))
	}

	foundNS1, foundNS2 := false, false
	for _, ns := range delegation {
		if ns.Hostname == "ns1.example.com" {
			foundNS1 = true
			if ns.IPv4 != "93.184.216.34" {
				t.Errorf("ns1 ipv4: got %q", ns.IPv4)
			}
		}
		if ns.Hostname == "ns2.example.com" {
			foundNS2 = true
			if ns.IPv4 != "93.184.216.35" {
				t.Errorf("ns2 ipv4: got %q", ns.IPv4)
			}
		}
	}
	if !foundNS1 || !foundNS2 {
		t.Errorf("missing NS: ns1=%v ns2=%v", foundNS1, foundNS2)
	}
}

func TestExtractDelegationGlueless(t *testing.T) {
	nsRData := buildPlainNameRData("ns1.otherdomain.net")

	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600,
				RDLength: uint16(len(nsRData)), RData: nsRData},
		},
		Additional: []dns.ResourceRecord{}, // no glue
	}

	delegation, zone := extractDelegation(msg)
	if zone != "example.com" {
		t.Errorf("zone: expected 'example.com', got %q", zone)
	}
	if len(delegation) != 1 {
		t.Fatalf("expected 1 NS, got %d", len(delegation))
	}
	if delegation[0].IPv4 != "" {
		t.Error("glueless NS should have no IPv4")
	}
}

func TestExtractDelegationSkipsOPT(t *testing.T) {
	nsRData := buildPlainNameRData("ns1.example.com")

	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600,
				RDLength: uint16(len(nsRData)), RData: nsRData},
		},
		Additional: []dns.ResourceRecord{
			dns.BuildOPT(4096, false), // should be skipped
			{Name: "ns1.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600,
				RDLength: 4, RData: []byte{1, 2, 3, 4}},
		},
	}

	delegation, _ := extractDelegation(msg)
	if len(delegation) != 1 {
		t.Fatalf("expected 1 NS, got %d", len(delegation))
	}
	if delegation[0].IPv4 != "1.2.3.4" {
		t.Errorf("expected glue 1.2.3.4, got %q", delegation[0].IPv4)
	}
}

func TestExtractCNAMETarget(t *testing.T) {
	cnameRData := buildPlainNameRData("cdn.example.com")

	msg := &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "www.example.com", Type: dns.TypeCNAME, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(cnameRData)), RData: cnameRData},
		},
	}

	target := extractCNAMETarget(msg, "www.example.com")
	if target != "cdn.example.com" {
		t.Errorf("expected 'cdn.example.com', got %q", target)
	}
}

func TestExtractCNAMETargetMissing(t *testing.T) {
	msg := &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "other.com", Type: dns.TypeCNAME, Class: dns.ClassIN,
				TTL: 300, RDLength: 0, RData: nil},
		},
	}

	target := extractCNAMETarget(msg, "www.example.com")
	if target != "" {
		t.Errorf("expected empty, got %q", target)
	}
}

func TestVisitedSetCNAMELoop(t *testing.T) {
	v := newVisitedSet()

	v.AddCNAME("a.com")
	v.AddCNAME("b.com")
	v.AddCNAME("c.com")

	if !v.HasCNAME("a.com") {
		t.Error("a.com should be visited")
	}
	if !v.HasCNAME("b.com") {
		t.Error("b.com should be visited")
	}
	if v.HasCNAME("d.com") {
		t.Error("d.com should not be visited")
	}
}

func TestNSEntryHelpers(t *testing.T) {
	servers := []NameServer{
		{Name: "ns1.test.com", IPv4: "1.1.1.1", IPv6: "::1"},
		{Name: "ns2.test.com", IPv4: "2.2.2.2", IPv6: "::2"},
	}

	entries := toNameServerList(servers)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].hostname != "ns1.test.com" || entries[0].ipv4 != "1.1.1.1" {
		t.Errorf("entry 0: %+v", entries[0])
	}

	remaining := removeNSByIP(entries, "1.1.1.1")
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining, got %d", len(remaining))
	}
	if remaining[0].ipv4 != "2.2.2.2" {
		t.Errorf("wrong NS remaining: %+v", remaining[0])
	}
}

func TestDelegationToNSList(t *testing.T) {
	delegation := []DelegationNS{
		{Hostname: "ns1.example.com", IPv4: "10.0.0.1"},
		{Hostname: "ns2.example.com", IPv6: "::1"},
	}

	entries := delegationToNSList(delegation)
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
	if entries[0].ipv4 != "10.0.0.1" {
		t.Errorf("entry 0 ipv4: %q", entries[0].ipv4)
	}
	if entries[1].ipv6 != "::1" {
		t.Errorf("entry 1 ipv6: %q", entries[1].ipv6)
	}
}

// buildPlainNameRData creates uncompressed wire-format bytes for a domain name.
func buildPlainNameRData(name string) []byte {
	var buf []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
			start = i + 1
		}
	}
	buf = append(buf, 0)
	return buf
}

func TestRootServersComplete(t *testing.T) {
	if len(RootServers) != 13 {
		t.Errorf("expected 13 root servers, got %d", len(RootServers))
	}

	for _, rs := range RootServers {
		if rs.Name == "" {
			t.Error("root server name is empty")
		}
		if rs.IPv4 == "" {
			t.Errorf("root server %s has no IPv4", rs.Name)
		}
		if rs.IPv6 == "" {
			t.Errorf("root server %s has no IPv6", rs.Name)
		}
	}
}
