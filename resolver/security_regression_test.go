package resolver

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestResolveWithECS_DoesNotCacheNegativeGlobally(t *testing.T) {
	soa := buildSOARData()
	tests := []struct {
		name      string
		qtype     uint16
		rcode     uint8
		cacheType uint16
	}{
		{name: "NXDOMAIN", qtype: dns.TypeA, rcode: dns.RCodeNXDomain, cacheType: 0},
		{name: "NODATA", qtype: dns.TypeAAAA, rcode: dns.RCodeNoError, cacheType: dns.TypeAAAA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// An ECS-aware authoritative scoping its answer to the client's
			// /24 (RFC 7871 §7.2.1).
			mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
				return &dns.Message{
					Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(tt.rcode).Build()},
					Questions: q.Questions,
					Authority: []dns.ResourceRecord{{
						Name: "ecstest.net", Type: dns.TypeSOA, Class: dns.ClassIN,
						TTL: 300, RDLength: uint16(len(soa)), RData: soa,
					}},
					Additional: []dns.ResourceRecord{dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{dns.BuildECS(&dns.ECSOption{
						Family: 1, SourcePrefixLen: 24, ScopePrefixLen: 24, Address: []byte{192, 0, 2, 0},
					})})},
				}
			})
			defer mock.close()

			r := testResolver(t, mock)
			r.config.ECSEnabled = true
			ecs := &dns.ECSOption{
				Family: 1, SourcePrefixLen: 24,
				Address: []byte{192, 0, 2, 0},
			}
			result, err := r.ResolveWithECS("missing.ecstest.net", tt.qtype, dns.ClassIN, ecs)
			if err != nil {
				t.Fatalf("ResolveWithECS: %v", err)
			}
			if result == nil || result.RCODE != tt.rcode {
				t.Fatalf("result = %#v, want RCODE %d", result, tt.rcode)
			}
			if _, ok := r.cache.Lookup("missing.ecstest.net", tt.cacheType, dns.ClassIN); ok {
				t.Fatal("ECS-scoped negative response poisoned the global cache")
			}
		})
	}
}

// TestResolveWithECS_GlobalScopeNegativeCachedGlobally: RFC 7871 §7.3.1
// — a negative reply without ECS (an ECS-unaware authoritative) answers
// every client, so it is cached under the global key.
func TestResolveWithECS_GlobalScopeNegativeCachedGlobally(t *testing.T) {
	soa := buildSOARData()
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build()},
			Questions: q.Questions,
			Authority: []dns.ResourceRecord{{
				Name: "ecstest.net", Type: dns.TypeSOA, Class: dns.ClassIN,
				TTL: 300, RDLength: uint16(len(soa)), RData: soa,
			}},
		}
	})
	defer mock.close()
	r := testResolver(t, mock)
	r.config.ECSEnabled = true
	ecs := &dns.ECSOption{Family: 1, SourcePrefixLen: 24, Address: []byte{192, 0, 2, 0}}
	res, err := r.ResolveWithECS("missing.ecstest.net", dns.TypeA, dns.ClassIN, ecs)
	if err != nil || res == nil || res.RCODE != dns.RCodeNXDomain {
		t.Fatalf("res=%+v err=%v, want NXDOMAIN", res, err)
	}
	if _, ok := r.cache.Lookup("missing.ecstest.net", 0, dns.ClassIN); !ok {
		t.Error("unscoped NXDOMAIN learned for an ECS client was not cached globally")
	}
}

func TestExtractDelegationForQName_ClosestOwnerAndBailiwickGlue(t *testing.T) {
	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			{Name: "example", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RData: dns.BuildPlainName("ns.parent.example")},
			{Name: "child.example", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RData: dns.BuildPlainName("ns.good.child.example")},
			{Name: "sibling.example", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RData: dns.BuildPlainName("ns.sibling.example")},
			{Name: "child.example", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RData: dns.BuildPlainName("ns.external.test")},
		},
		Additional: []dns.ResourceRecord{
			{Name: "ns.parent.example", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{1, 1, 1, 1}},
			{Name: "ns.good.child.example", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{2, 2, 2, 2}},
			{Name: "ns.sibling.example", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{3, 3, 3, 3}},
			{Name: "ns.external.test", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{4, 4, 4, 4}},
		},
	}

	delegation, zone := extractDelegationForQName(msg, "www.child.example", "example", 0)
	if zone != "child.example" {
		t.Fatalf("zone = %q, want closest ancestor child.example", zone)
	}
	if len(delegation) != 2 {
		t.Fatalf("delegation length = %d, want only the two child.example NS names", len(delegation))
	}
	for _, ns := range delegation {
		switch ns.Hostname {
		case "ns.good.child.example":
			if ns.IPv4 != "2.2.2.2" {
				t.Fatalf("in-bailiwick glue = %q, want 2.2.2.2", ns.IPv4)
			}
		case "ns.external.test":
			if ns.IPv4 != "" {
				t.Fatalf("out-of-delegation glue accepted: %q", ns.IPv4)
			}
		default:
			t.Fatalf("selected NS from sibling/ancestor owner: %q", ns.Hostname)
		}
	}
}

func TestExtractDelegationForQName_RejectsNonAncestorOwners(t *testing.T) {
	msg := &dns.Message{
		Authority: []dns.ResourceRecord{{
			Name: "sibling.example", Type: dns.TypeNS, Class: dns.ClassIN,
			TTL: 300, RData: dns.BuildPlainName("ns.sibling.example"),
		}},
		Additional: []dns.ResourceRecord{{
			Name: "ns.sibling.example", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{3, 3, 3, 3},
		}},
	}
	delegation, zone := extractDelegationForQName(msg, "www.child.example", "example", 0)
	if zone != "" || len(delegation) != 0 {
		t.Fatalf("accepted sibling-only referral: zone=%q delegation=%#v", zone, delegation)
	}
}

// TestExtractDelegationForQName_SiblingGlue pins the live sivas.gov.tr shape:
// gov.tr delegates sivas.gov.tr to ns1/ns2.isay.gov.tr with glue for both.
// The names sit outside the delegated zone but inside the referring server's
// zone, so the glue is usable; dropping it left only a lookup that hit the
// dead ns1 and pushed every query to the public fallback. Glue outside the
// server's zone stays rejected.
func TestExtractDelegationForQName_SiblingGlue(t *testing.T) {
	ns := func(name string) dns.ResourceRecord {
		rd := dns.BuildPlainName(name)
		return dns.ResourceRecord{Name: "sivas.gov.tr", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd}
	}
	a := func(name string, last byte) dns.ResourceRecord {
		return dns.ResourceRecord{Name: name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{192, 0, 2, last}}
	}
	msg := &dns.Message{
		Authority:  []dns.ResourceRecord{ns("ns1.isay.gov.tr"), ns("ns2.isay.gov.tr"), ns("ns.external.test")},
		Additional: []dns.ResourceRecord{a("ns1.isay.gov.tr", 1), a("ns2.isay.gov.tr", 2), a("ns.external.test", 3)},
	}

	delegation, zone := extractDelegationForQName(msg, "www.sivas.gov.tr", "tr", 0)
	if zone != "sivas.gov.tr" || len(delegation) != 3 {
		t.Fatalf("zone=%q len=%d, want sivas.gov.tr with three NS", zone, len(delegation))
	}
	want := map[string]string{"ns1.isay.gov.tr": "192.0.2.1", "ns2.isay.gov.tr": "192.0.2.2", "ns.external.test": ""}
	for _, d := range delegation {
		if d.IPv4 != want[d.Hostname] {
			t.Errorf("%s glue = %q, want %q", d.Hostname, d.IPv4, want[d.Hostname])
		}
	}

	// From a server for sivas.gov.tr's own zone only, the sibling glue is
	// out of bailiwick and must be dropped.
	delegation, _ = extractDelegationForQName(msg, "www.sivas.gov.tr", "sivas.gov.tr", 0)
	for _, d := range delegation {
		if d.IPv4 != "" {
			t.Errorf("%s: glue %q accepted outside the server's zone", d.Hostname, d.IPv4)
		}
	}
}

func TestReqBudget_ConcurrentChargeHonorsCap(t *testing.T) {
	const (
		workers = 64
		cap     = 17
	)
	b := &reqBudget{maxQueries: cap}
	var successes atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			if b.charge() == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != cap {
		t.Fatalf("successful concurrent charges = %d, want exactly %d", got, cap)
	}
}

func TestResolveNSHappyEyeballs_CancelsDelayedLoser(t *testing.T) {
	var queries atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queries.Add(1)
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{8, 8, 8, 8},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	r.config.PreferIPv4 = true
	_, ip, err := r.resolveNSHappyEyeballs("ns.example", 500*time.Millisecond, newVisitedSet())
	if err != nil {
		t.Fatalf("resolveNSHappyEyeballs: %v", err)
	}
	if ip != "8.8.8.8" {
		t.Fatalf("IP = %q, want 8.8.8.8", ip)
	}
	// Wait past the stagger: a leaked loser would start an AAAA resolution now.
	time.Sleep(600 * time.Millisecond)
	if got := queries.Load(); got != 1 {
		t.Fatalf("upstream queries = %d, want 1; delayed loser was not canceled", got)
	}
}

// TestReferralDescends pins the two live loops: pool.telefonica.de answering
// a minimised "12.pool.telefonica.de NS" with a referral back to itself, and
// the Comcast NS of 99.236.71.in-addr.arpa referring the zone's own NS query
// to the zone. Neither makes progress; only a strictly deeper zone does.
func TestReferralDescends(t *testing.T) {
	ref := func(owner string) *dns.Message {
		rd := dns.BuildPlainName("ns1.telefonica.de")
		return &dns.Message{Authority: []dns.ResourceRecord{
			{Name: owner, Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd},
		}}
	}
	cases := []struct {
		owner, qname, current string
		want                  bool
	}{
		{"pool.telefonica.de", "12.pool.telefonica.de", "pool.telefonica.de", false},
		{"telefonica.de", "12.pool.telefonica.de", "pool.telefonica.de", false},
		{"12.pool.telefonica.de", "12.pool.telefonica.de", "pool.telefonica.de", true},
		{"de", "telefonica.de", "", true},
	}
	for _, c := range cases {
		if got := referralDescends(ref(c.owner), c.qname, c.current); got != c.want {
			t.Errorf("referral to %q for %q from %q: descends=%v, want %v", c.owner, c.qname, c.current, got, c.want)
		}
	}
}
