package resolver

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// serveUDPOn answers every query arriving at addr with fn's response.
func serveUDPOn(t *testing.T, addr string, fn func(q *dns.Message) *dns.Message) {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Skipf("cannot bind %s: %v", addr, err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := dns.Unpack(buf[:n])
			if err != nil || len(q.Questions) == 0 {
				continue
			}
			resp := fn(q)
			resp.Header.ID = q.Header.ID
			resp.Questions = q.Questions
			resp.Header.QDCount = 1
			if packed, err := dns.Pack(resp, make([]byte, 4096)); err == nil {
				_, _ = pc.WriteTo(packed, from)
			}
		}
	}()
}

// TestResolve_GluelessAlternateNSAfterServFail pins the alternate-NS rule:
// when the NS whose address is known returns SERVFAIL, a glueless NS of the
// same delegation that has not been tried yet must be resolved and asked.
// Live, 78.181.in-addr.arpa has four glueless NS and only ns1.ifxnetworks.co
// answers; the resolver gave up with EDE 22 while 1.1.1.1 got the PTR.
func TestResolve_GluelessAlternateNSAfterServFail(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
	probe.Close()

	aRR := func(name string, ip net.IP) dns.ResourceRecord {
		return dns.ResourceRecord{Name: name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: ip.To4()}
	}
	nsRR := func(host string) dns.ResourceRecord {
		rd := dns.BuildPlainName(host)
		return dns.ResourceRecord{Name: "glueless.lab", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd}
	}
	flags := func(aa bool, rcode uint8) uint16 {
		return dns.NewFlagBuilder().SetQR(true).SetAA(aa).SetRCODE(rcode).Build()
	}

	// Root: referral for glueless.lab without glue; answers NS addresses.
	serveUDPOn(t, "127.0.0.1:"+port, func(q *dns.Message) *dns.Message {
		qq := q.Questions[0]
		resp := &dns.Message{Header: dns.Header{Flags: flags(true, dns.RCodeNoError)}}
		switch {
		case qq.Name == "nsgood.other.lab" && qq.Type == dns.TypeA:
			resp.Answers = []dns.ResourceRecord{aRR(qq.Name, net.IPv4(127, 0, 0, 3))}
		case qq.Name == "nsbad.other.lab" && qq.Type == dns.TypeA:
			resp.Answers = []dns.ResourceRecord{aRR(qq.Name, net.IPv4(127, 0, 0, 2))}
		case qq.Name == "host.glueless.lab":
			resp.Header.Flags = flags(false, dns.RCodeNoError)
			resp.Authority = []dns.ResourceRecord{nsRR("nsbad.other.lab"), nsRR("nsgood.other.lab")}
		}
		return resp
	})
	var badQueries atomic.Int32
	serveUDPOn(t, "127.0.0.2:"+port, func(*dns.Message) *dns.Message {
		badQueries.Add(1)
		return &dns.Message{Header: dns.Header{Flags: flags(false, dns.RCodeServFail)}}
	})
	serveUDPOn(t, "127.0.0.3:"+port, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:  dns.Header{Flags: flags(true, dns.RCodeNoError)},
			Answers: []dns.ResourceRecord{aRR(q.Questions[0].Name, net.IPv4(192, 0, 2, 7))},
		}
	})

	r := testResolver(t, &mockDNSServer{ip: "127.0.0.1", port: port})
	// The broken NS's address is already cached, so it is picked first.
	r.cache.Store("nsbad.other.lab", dns.TypeA, dns.ClassIN,
		[]dns.ResourceRecord{aRR("nsbad.other.lab", net.IPv4(127, 0, 0, 2))}, nil)

	result, err := r.Resolve("host.glueless.lab", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.RCODE != dns.RCodeNoError || len(result.Answers) != 1 {
		t.Fatalf("rcode=%d answers=%d reason=%q, want NOERROR with the answer from the untried glueless NS",
			result.RCODE, len(result.Answers), result.FailureReason)
	}
	if n := badQueries.Load(); n != 1 {
		t.Errorf("broken NS asked %d times, want 1", n)
	}
}

// TestResolve_GluelessAllNSServFailBounded pins the bound on the rule above:
// with every glueless NS returning SERVFAIL, each hostname is resolved and
// asked once per delegation, then the resolver gives up with EDE 22.
func TestResolve_GluelessAllNSServFailBounded(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
	probe.Close()

	hosts := []string{"ns1.other.lab", "ns2.other.lab", "ns3.other.lab", "ns4.other.lab"}
	var addrQueries atomic.Int32
	serveUDPOn(t, "127.0.0.1:"+port, func(q *dns.Message) *dns.Message {
		qq := q.Questions[0]
		resp := &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()}}
		if qq.Name == "host.glueless.lab" {
			resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).Build()
			for _, h := range hosts {
				rd := dns.BuildPlainName(h)
				resp.Authority = append(resp.Authority, dns.ResourceRecord{Name: "glueless.lab", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd})
			}
		} else if qq.Type == dns.TypeA && strings.HasSuffix(qq.Name, ".other.lab") {
			addrQueries.Add(1)
			resp.Answers = []dns.ResourceRecord{{Name: qq.Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{127, 0, 0, 2}}}
		} else {
			resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).SetAA(true).SetRCODE(dns.RCodeNXDomain).Build()
		}
		return resp
	})
	var badQueries atomic.Int32
	serveUDPOn(t, "127.0.0.2:"+port, func(*dns.Message) *dns.Message {
		badQueries.Add(1)
		return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build()}}
	})

	r := testResolver(t, &mockDNSServer{ip: "127.0.0.1", port: port})
	result, err := r.Resolve("host.glueless.lab", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.RCODE != dns.RCodeServFail || result.FailureReason != "no-reachable-authority" {
		t.Errorf("rcode=%d reason=%q, want SERVFAIL no-reachable-authority", result.RCODE, result.FailureReason)
	}
	// All four hosts share one address, so after the first SERVFAIL marks
	// it failed the others resolve to nothing usable: one ask in total, and
	// at most one A lookup per hostname.
	if n := badQueries.Load(); n != 1 {
		t.Errorf("broken address asked %d times, want 1", n)
	}
	if n := addrQueries.Load(); n > int32(len(hosts)) {
		t.Errorf("%d NS address lookups for %d hostnames, want at most one each", n, len(hosts))
	}
}

// TestResolveNSAddr_FailureCached pins RFC 9520 §3 for NS-address lookups: a
// dead NS name is resolved once per failure window, not once per query into
// its zone. A spent request budget is not the name's failure and must not be
// cached.
func TestResolveNSAddr_FailureCached(t *testing.T) {
	var queries atomic.Int32
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		queries.Add(1)
		return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build()}, Questions: q.Questions}
	})
	defer mock.close()
	r := testResolver(t, mock)

	spent := newVisitedSet()
	spent.budget.maxQueries = 1
	_ = spent.budget.charge()
	if res, _ := r.resolveNSAddr("dead.ns.lab", dns.TypeA, spent); res == nil || res.FailureReason != "query-budget-exceeded" {
		t.Fatalf("budget control: got %+v", res)
	}
	if _, _, hit := r.failureCache.Get("dead.ns.lab", dns.TypeA, dns.ClassIN); hit {
		t.Fatal("a spent request budget was cached as the NS name's failure")
	}

	first, _ := r.resolveNSAddr("dead.ns.lab", dns.TypeA, newVisitedSet())
	if first == nil || first.RCODE != dns.RCodeServFail {
		t.Fatalf("first lookup: got %+v, want SERVFAIL", first)
	}
	sent := queries.Load()
	second, _ := r.resolveNSAddr("dead.ns.lab", dns.TypeA, newVisitedSet())
	if second == nil || second.RCODE != dns.RCodeServFail || !second.FromFailureCache {
		t.Errorf("second lookup: got %+v, want SERVFAIL from the failure cache", second)
	}
	if n := queries.Load() - sent; n != 0 {
		t.Errorf("second lookup sent %d queries, want 0", n)
	}
}

// TestResolve_StaleGlueNSResolvedOnce pins the stale-glue half of the rule:
// glue is the parent's copy of an NS address and can be wrong. Live, .co
// publishes three A glue records for ns1.ifxnetworks.co, but its own zone
// serves only the one that answers. When the glue address SERVFAILs, the NS
// name must be resolved once from its own zone and that address tried.
func TestResolve_StaleGlueNSResolvedOnce(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
	probe.Close()

	aRR := func(name string, ip net.IP) dns.ResourceRecord {
		return dns.ResourceRecord{Name: name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: ip.To4()}
	}
	var addrQueries atomic.Int32
	serveUDPOn(t, "127.0.0.1:"+port, func(q *dns.Message) *dns.Message {
		qq := q.Questions[0]
		resp := &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()}}
		switch {
		case qq.Name == "ns1.other.lab" && qq.Type == dns.TypeA:
			addrQueries.Add(1)
			resp.Answers = []dns.ResourceRecord{aRR(qq.Name, net.IPv4(127, 0, 0, 3))}
		case qq.Name == "host.glueless.lab":
			resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).Build()
			rd := dns.BuildPlainName("ns1.other.lab")
			resp.Authority = []dns.ResourceRecord{{Name: "glueless.lab", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd}}
		}
		return resp
	})
	serveUDPOn(t, "127.0.0.2:"+port, func(*dns.Message) *dns.Message {
		return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build()}}
	})
	serveUDPOn(t, "127.0.0.3:"+port, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:  dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()},
			Answers: []dns.ResourceRecord{aRR(q.Questions[0].Name, net.IPv4(192, 0, 2, 7))},
		}
	})

	r := testResolver(t, &mockDNSServer{ip: "127.0.0.1", port: port})
	// Stale parent glue for the only NS.
	r.cache.StoreGlue("ns1.other.lab", dns.TypeA, dns.ClassIN,
		[]dns.ResourceRecord{aRR("ns1.other.lab", net.IPv4(127, 0, 0, 2))})

	result, err := r.Resolve("host.glueless.lab", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.RCODE != dns.RCodeNoError || len(result.Answers) != 1 {
		t.Fatalf("rcode=%d answers=%d reason=%q, want NOERROR via the NS's authoritative address",
			result.RCODE, len(result.Answers), result.FailureReason)
	}
	if n := addrQueries.Load(); n != 1 {
		t.Errorf("NS address resolved %d times, want 1", n)
	}
}

// TestResolveFromClosest_RetryKeepsFailedIPs pins the retry-from-root path:
// when the cached delegation is unreachable, the walk from the root is the
// same client request, so it keeps the request budget and the NS addresses
// and names already proven dead. With a fresh budget the retry re-asked every dead
// address (live: 225.129.203.in-addr.arpa SERVFAIL after 21 s, past the 20 s
// RequestTimeout).
func TestResolveFromClosest_RetryKeepsFailedIPs(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
	probe.Close()

	aRR := func(name string, ip net.IP) dns.ResourceRecord {
		return dns.ResourceRecord{Name: name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: ip.To4()}
	}
	var addrQueries atomic.Int32
	nsRD := dns.BuildPlainName("ns1.other.lab")
	nsRR := dns.ResourceRecord{Name: "deadzone.lab", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(nsRD)), RData: nsRD}
	serveUDPOn(t, "127.0.0.1:"+port, func(q *dns.Message) *dns.Message {
		qq := q.Questions[0]
		resp := &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()}}
		switch {
		case qq.Name == "host.deadzone.lab":
			resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).Build()
			resp.Authority = []dns.ResourceRecord{nsRR}
		case qq.Name == "ns1.other.lab" && qq.Type == dns.TypeA:
			addrQueries.Add(1)
			resp.Answers = []dns.ResourceRecord{aRR(qq.Name, net.IPv4(127, 0, 0, 2))}
		default:
			resp.Header.Flags = dns.NewFlagBuilder().SetQR(true).SetAA(true).SetRCODE(dns.RCodeNXDomain).Build()
		}
		return resp
	})
	var badQueries atomic.Int32
	serveUDPOn(t, "127.0.0.2:"+port, func(*dns.Message) *dns.Message {
		badQueries.Add(1)
		return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build()}}
	})

	r := testResolver(t, &mockDNSServer{ip: "127.0.0.1", port: port})
	// A cached delegation, so resolution starts there and then retries
	// from the root.
	r.cache.Store("deadzone.lab", dns.TypeNS, dns.ClassIN, []dns.ResourceRecord{nsRR}, nil)
	r.cache.Store("ns1.other.lab", dns.TypeA, dns.ClassIN,
		[]dns.ResourceRecord{aRR("ns1.other.lab", net.IPv4(127, 0, 0, 2))}, nil)

	result, err := r.Resolve("host.deadzone.lab", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.RCODE != dns.RCodeServFail || result.FailureReason != "no-reachable-authority" {
		t.Errorf("rcode=%d reason=%q, want SERVFAIL no-reachable-authority", result.RCODE, result.FailureReason)
	}
	if n := badQueries.Load(); n != 1 {
		t.Errorf("dead NS address asked %d times across the retry, want 1", n)
	}
	if n := addrQueries.Load(); n != 1 {
		t.Errorf("dead NS name resolved %d times across the retry, want 1", n)
	}
}

// TestVisitedSet_UnreachableSharedAcrossRequest pins that an NS address that
// timed out in one sub-resolution is skipped by the rest of the request. Live,
// stpa.soft.net's address 203.129.225.116 timed out while resolving the NS
// name, then cost another 4.5 s timeout when the retry from the root picked
// it as cached glue. A SERVFAIL stays local: it is specific to the query.
func TestVisitedSet_UnreachableSharedAcrossRequest(t *testing.T) {
	parent := newVisitedSet()
	child := newVisitedSetForNSAddr(parent, "ns1.other.lab")
	child.MarkFailedIP("192.0.2.1") // SERVFAIL for the NS-address query
	child.budget.markUnreachable("192.0.2.2")

	if parent.IsFailedIP("192.0.2.1") {
		t.Error("a SERVFAIL in a sub-resolution leaked into the parent")
	}
	if !parent.IsFailedIP("192.0.2.2") {
		t.Error("an address unreachable in a sub-resolution is not skipped by the parent")
	}
	retry := newVisitedSetWithBudget(parent.budget)
	if !retry.IsFailedIP("192.0.2.2") {
		t.Error("an unreachable address is not skipped by the retry from the root")
	}
	if newVisitedSet().IsFailedIP("192.0.2.2") {
		t.Error("an unreachable address leaked into another request")
	}
}
