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
			mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
				return &dns.Message{
					Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(tt.rcode).Build()},
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

	delegation, zone := extractDelegationForQName(msg, "www.child.example", 0)
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
	delegation, zone := extractDelegationForQName(msg, "www.child.example", 0)
	if zone != "" || len(delegation) != 0 {
		t.Fatalf("accepted sibling-only referral: zone=%q delegation=%#v", zone, delegation)
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
