package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestFreshCacheHit_NoStaleEDE pins Y58: RFC 8914 §4.3 / §4.19 EDE
// codes (3 Stale Answer / 19 Stale NXDOMAIN Answer) are reserved for
// the serve-stale path only. A fresh cache hit (RFC 1035 §3.2.1 normal
// TTL window) MUST NOT carry either code, because a client reading EDE
// 3 on a non-stale answer would treat the data as suspect and
// potentially re-query — exactly the loop RFC 8767 §6 sought to
// terminate. The pin guards against a refactor that hoists the EDE
// attachment too high (e.g. into a shared cache-response builder) and
// starts spraying stale-EDE on every cached hit.
//
// We seed a positive cache entry with a healthy TTL, immediately query
// for it with an EDNS-bearing OPT, and verify the response either has
// no OPT at all (legal under RFC 6891 §6.2.5 when nothing to add) or
// has an OPT whose options do NOT include EDE 3 or 19.
func TestFreshCacheHit_NoStaleEDE(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 60, 86400, 3600, true, 30, cacheMetrics)

	qname := "y58-fresh.example.com"
	ca.Store(qname, dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}, nil)

	// Resolver is intentionally broken so any cache-miss path would
	// blow up — proves the test is reading the hot cache hit path.
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	query := buildTestQueryWithEDNS(qname, dns.TypeA, 1232)
	resp, err := h.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	for _, rr := range parsed.Additional {
		if rr.Type != dns.TypeOPT {
			continue
		}
		edns, perr := dns.ParseOPT(&rr)
		if perr != nil {
			t.Fatalf("ParseOPT: %v", perr)
		}
		for _, o := range edns.Options {
			if o.Code != dns.EDNSOptionCodeEDE {
				continue
			}
			code, _, perr := dns.ParseEDEOption(o.Data)
			if perr != nil {
				t.Errorf("ParseEDEOption: %v", perr)
				continue
			}
			if code == dns.EDECodeStaleAnswer || code == dns.EDECodeStaleNXDOMAINAnswer {
				t.Errorf("fresh cache hit carried stale EDE code %d — RFC 8914 §4.3/§4.19 reserve these for the serve-stale path", code)
			}
		}
	}
}

// TestFreshNXDomainCacheHit_NoStaleNXDOMAINEDE pins the negative-side
// mirror of Y58: a fresh cached NXDOMAIN (RFC 2308 negative caching
// inside the negative TTL window) MUST NOT carry EDE 19. A client that
// sees EDE 19 on a non-stale denial would (correctly under §4.19's
// semantics) doubt the answer and retry against another resolver —
// turning a working negative cache into a high-QPS amplifier of upstream
// load.
func TestFreshNXDomainCacheHit_NoStaleNXDOMAINEDE(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 60, 86400, 3600, true, 30, cacheMetrics)

	qname := "y58-fresh-nx.example.com"
	soa := dns.ResourceRecord{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 300, RData: buildSOAForStaleTest(t),
	}
	soa.RDLength = uint16(len(soa.RData))
	ca.StoreNegative(qname, dns.TypeA, dns.ClassIN,
		cache.NegNXDomain, dns.RCodeNXDomain, []dns.ResourceRecord{soa})

	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	query := buildTestQueryWithEDNS(qname, dns.TypeA, 1232)
	resp, err := h.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	for _, rr := range parsed.Additional {
		if rr.Type != dns.TypeOPT {
			continue
		}
		edns, _ := dns.ParseOPT(&rr)
		for _, o := range edns.Options {
			if o.Code != dns.EDNSOptionCodeEDE {
				continue
			}
			code, _, _ := dns.ParseEDEOption(o.Data)
			if code == dns.EDECodeStaleAnswer || code == dns.EDECodeStaleNXDOMAINAnswer {
				t.Errorf("fresh NXDOMAIN cache hit carried stale EDE code %d (RFC 8914 §4.19 violation)", code)
			}
		}
	}
}
