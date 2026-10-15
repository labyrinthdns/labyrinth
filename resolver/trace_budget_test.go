package resolver

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestTrace_CyclicGluelessDelegationHonoursBudget pins the trace's request
// budget. Live shape (marcatel.net.mx / marcatel.com.mx): the registry glue
// of each zone points at a stale address that is now a recursion-lame cache
// (RA=1, empty answers), and each zone's other NS lives in the other zone
// without glue. Resolving those NS names alternates between the two zones;
// the trace did that with no budget and never finished, while production
// stopped at its query cap / deadline. The trace now shares the request's
// budget like production resolution does.
func TestTrace_CyclicGluelessDelegationHonoursBudget(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
	probe.Close()

	nsRR := func(zone, host string) dns.ResourceRecord {
		rd := dns.BuildPlainName(host)
		return dns.ResourceRecord{Name: zone, Type: dns.TypeNS, Class: dns.ClassIN, TTL: 60, RDLength: uint16(len(rd)), RData: rd}
	}
	glue := func(host string) dns.ResourceRecord {
		return dns.ResourceRecord{Name: host, Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RDLength: 4, RData: []byte{127, 0, 0, 2}}
	}
	// Root (acting for "lab" too): loop-a.lab is served by ns.loop-a.lab
	// (glue → the lame cache) and ns.loop-b.lab (no glue); loop-b.lab the
	// other way round.
	serveUDPOn(t, "127.0.0.1:"+port, func(q *dns.Message) *dns.Message {
		self, other := "loop-a.lab", "loop-b.lab"
		if strings.HasSuffix(strings.ToLower(q.Questions[0].Name), "loop-b.lab") {
			self, other = other, self
		}
		return &dns.Message{
			Header:     dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Authority:  []dns.ResourceRecord{nsRR(self, "ns."+self), nsRR(self, "ns."+other)},
			Additional: []dns.ResourceRecord{glue("ns." + self)},
		}
	})
	// The stale glue address: a recursive cache answering RA=1, empty.
	serveUDPOn(t, "127.0.0.2:"+port, func(*dns.Message) *dns.Message {
		return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRA(true).Build()}}
	})

	r := testResolver(t, &mockDNSServer{ip: "127.0.0.1", port: port})
	r.config.RequestTimeout = 2 * time.Second

	ev := make(chan TraceEvent)
	go func() {
		for range ev {
		}
	}()
	done := make(chan *ResolveResult, 1)
	go func() {
		res, _ := r.Trace(context.Background(), "www.loop-a.lab", dns.TypeA, dns.ClassIN, TraceOptions{BypassCache: true}, ev)
		done <- res
	}()
	select {
	case res := <-done:
		// The point is that the trace ends within the budget. Every server
		// answers an empty NOERROR, which (as in Unbound) ends as NODATA
		// once the delegation is exhausted; SERVFAIL would be fine too.
		if res == nil || len(res.Answers) != 0 || (res.RCODE != dns.RCodeNoError && res.RCODE != dns.RCodeServFail) {
			t.Fatalf("trace result = %+v, want NODATA or SERVFAIL", res)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("trace of a cyclic glueless delegation did not finish within 15s (RequestTimeout 2s)")
	}
}
