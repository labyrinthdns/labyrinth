package resolver

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestResolve_EmptyNoErrorFromEveryNSIsNoData pins the Unbound-compatible
// empty-NODATA rule. The GSLB servers of pims.turktelekom.com.tr answer AAAA
// with NOERROR and empty answer and authority sections, without AA (flags
// qr ad). That was a lame reply, so every AAAA query was SERVFAIL and went
// to the public fallback, where 8.8.8.8 and 1.1.1.1 answer NODATA. Unbound
// tries the other servers first and then takes the empty reply as NODATA;
// so do we. The NODATA has no SOA and is not cached.
func TestResolve_EmptyNoErrorFromEveryNSIsNoData(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
	probe.Close()

	nsRR := func(host string) dns.ResourceRecord {
		rd := dns.BuildPlainName(host)
		return dns.ResourceRecord{Name: "gslb.lab", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd}
	}
	glue := func(host string, last byte) dns.ResourceRecord {
		return dns.ResourceRecord{Name: host, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{127, 0, 0, last}}
	}
	serveUDPOn(t, "127.0.0.1:"+port, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:     dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Authority:  []dns.ResourceRecord{nsRR("ns1.gslb.lab"), nsRR("ns2.gslb.lab")},
			Additional: []dns.ResourceRecord{glue("ns1.gslb.lab", 2), glue("ns2.gslb.lab", 3)},
		}
	})
	var asked atomic.Int32
	gslb := func(q *dns.Message) *dns.Message {
		asked.Add(1)
		if q.Questions[0].Type == dns.TypeA && q.Questions[0].Name == "pims.gslb.lab" {
			return &dns.Message{
				Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()},
				Answers: []dns.ResourceRecord{{
					Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 30, RDLength: 4, RData: []byte{192, 0, 2, 17},
				}},
			}
		}
		// AAAA: NOERROR, empty, no AA — as live.
		return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()}}
	}
	serveUDPOn(t, "127.0.0.2:"+port, gslb)
	serveUDPOn(t, "127.0.0.3:"+port, gslb)

	r := testResolver(t, &mockDNSServer{ip: "127.0.0.1", port: port})
	// Production-like budget: the glueless NS-address lookups this mock
	// invites would otherwise recurse without limit.
	r.config.MaxQueriesPerRequest = 200
	r.config.RequestTimeout = 5 * time.Second

	res, err := r.Resolve("pims.gslb.lab", dns.TypeAAAA, dns.ClassIN)
	if err != nil || res == nil || res.RCODE != dns.RCodeNoError || len(res.Answers) != 0 {
		t.Fatalf("AAAA: res=%+v err=%v, want NODATA", res, err)
	}
	if n := asked.Load(); n < 2 {
		t.Errorf("GSLB servers asked %d times, want both tried before NODATA", n)
	}

	res, err = r.Resolve("pims.gslb.lab", dns.TypeA, dns.ClassIN)
	if err != nil || res == nil || res.RCODE != dns.RCodeNoError || len(res.Answers) != 1 {
		t.Fatalf("A: res=%+v err=%v, want the address", res, err)
	}
}

// TestResolve_EmptyNoErrorThenAnswerUsesAnswer: an empty NOERROR from one NS
// must not win over a real answer from another.
func TestResolve_EmptyNoErrorThenAnswerUsesAnswer(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
	probe.Close()

	nsRR := func(host string) dns.ResourceRecord {
		rd := dns.BuildPlainName(host)
		return dns.ResourceRecord{Name: "mixed.lab", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd}
	}
	glue := func(host string, last byte) dns.ResourceRecord {
		return dns.ResourceRecord{Name: host, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{127, 0, 0, last}}
	}
	serveUDPOn(t, "127.0.0.1:"+port, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:     dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Authority:  []dns.ResourceRecord{nsRR("ns1.mixed.lab"), nsRR("ns2.mixed.lab")},
			Additional: []dns.ResourceRecord{glue("ns1.mixed.lab", 2), glue("ns2.mixed.lab", 3)},
		}
	})
	serveUDPOn(t, "127.0.0.2:"+port, func(*dns.Message) *dns.Message {
		return &dns.Message{Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()}}
	})
	serveUDPOn(t, "127.0.0.3:"+port, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header: dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()},
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 30, RDLength: 4, RData: []byte{192, 0, 2, 33},
			}},
		}
	})

	r := testResolver(t, &mockDNSServer{ip: "127.0.0.1", port: port})
	r.config.MaxQueriesPerRequest = 200
	r.config.RequestTimeout = 5 * time.Second
	res, err := r.Resolve("www.mixed.lab", dns.TypeA, dns.ClassIN)
	if err != nil || res == nil || res.RCODE != dns.RCodeNoError || len(res.Answers) != 1 {
		t.Fatalf("res=%+v err=%v, want the answer from the NS that has it", res, err)
	}
}
