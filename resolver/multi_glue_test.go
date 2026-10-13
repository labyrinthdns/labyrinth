package resolver

import (
	"net"
	"sync/atomic"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestExtractDelegation_KeepsEveryGlueAddress pins that a referral with
// several A glue records for one NS name keeps all of them, in order.
// Before, each A overwrote the last, so only the final address survived.
func TestExtractDelegation_KeepsEveryGlueAddress(t *testing.T) {
	rd := dns.BuildPlainName("ns.multi.lab")
	a := func(ip byte) dns.ResourceRecord {
		return dns.ResourceRecord{Name: "ns.multi.lab", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{192, 0, 2, ip}}
	}
	msg := &dns.Message{
		Authority: []dns.ResourceRecord{
			{Name: "multi.lab", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd},
		},
		Additional: []dns.ResourceRecord{a(1), a(2), a(3), a(2)},
	}

	del, zone := extractDelegation(msg, 0)
	if zone != "multi.lab" || len(del) != 1 {
		t.Fatalf("zone=%q len=%d, want multi.lab with one NS", zone, len(del))
	}
	want := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if got := del[0].IPv4s; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("IPv4s=%v, want %v", got, want)
	}
	if del[0].IPv4 != "192.0.2.1" {
		t.Errorf("IPv4=%q, want the first glue address", del[0].IPv4)
	}
	if n := len(delegationToNSList(del)); n != 3 {
		t.Errorf("delegationToNSList gave %d candidates, want one per address (3)", n)
	}
}

// TestResolve_MultiGlueSkipsRefusingAddress pins the live failure: the zone
// freemailbl-s.snb.it is served by one NS name with three A glue records, the
// last of which answers REFUSED. Keeping only that address made every query
// fall back to 1.1.1.1/8.8.8.8; the other two addresses must be tried.
func TestResolve_MultiGlueSkipsRefusingAddress(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
	probe.Close()

	flags := func(aa bool, rcode uint8) uint16 {
		return dns.NewFlagBuilder().SetQR(true).SetAA(aa).SetRCODE(rcode).Build()
	}
	aRR := func(name string, ip net.IP) dns.ResourceRecord {
		return dns.ResourceRecord{Name: name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: ip.To4()}
	}

	// Root: referral to multi.lab, NS ns.multi.lab with glue .2, .3, .4 —
	// the refusing address last, as in the live referral.
	serveUDPOn(t, "127.0.0.1:"+port, func(q *dns.Message) *dns.Message {
		rd := dns.BuildPlainName("ns.multi.lab")
		return &dns.Message{
			Header: dns.Header{Flags: flags(false, dns.RCodeNoError)},
			Authority: []dns.ResourceRecord{
				{Name: "multi.lab", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd},
			},
			Additional: []dns.ResourceRecord{
				aRR("ns.multi.lab", net.IPv4(127, 0, 0, 2)),
				aRR("ns.multi.lab", net.IPv4(127, 0, 0, 3)),
				aRR("ns.multi.lab", net.IPv4(127, 0, 0, 4)),
			},
		}
	})
	var good atomic.Int32
	answer := func(q *dns.Message) *dns.Message {
		good.Add(1)
		return &dns.Message{
			Header:  dns.Header{Flags: flags(true, dns.RCodeNoError)},
			Answers: []dns.ResourceRecord{aRR(q.Questions[0].Name, net.IPv4(192, 0, 2, 9))},
		}
	}
	serveUDPOn(t, "127.0.0.2:"+port, answer)
	serveUDPOn(t, "127.0.0.3:"+port, answer)
	serveUDPOn(t, "127.0.0.4:"+port, func(*dns.Message) *dns.Message {
		return &dns.Message{Header: dns.Header{Flags: flags(false, dns.RCodeRefused)}}
	})

	r := testResolver(t, &mockDNSServer{ip: "127.0.0.1", port: port})
	// Make the refusing address the RTT-preferred one so it is asked first.
	r.infraCache.RecordRTT("127.0.0.4", 1)

	result, err := r.Resolve("host.multi.lab", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.RCODE != dns.RCodeNoError || len(result.Answers) != 1 {
		t.Fatalf("rcode=%d answers=%d reason=%q, want NOERROR from a non-refusing glue address",
			result.RCODE, len(result.Answers), result.FailureReason)
	}
	if good.Load() == 0 {
		t.Error("no healthy glue address was asked")
	}

	// The glue cache must hold the full address set for later lookups.
	entry, ok := r.cache.Get("ns.multi.lab", dns.TypeA, dns.ClassIN)
	if !ok || len(entry.Records) != 3 {
		n := 0
		if ok {
			n = len(entry.Records)
		}
		t.Errorf("cached glue for ns.multi.lab has %d A records, want 3", n)
	}
}
