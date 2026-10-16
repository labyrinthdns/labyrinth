package resolver

import (
	"net"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestResolve_AuthoritativeApexNSWithoutAnswerIsNoData pins the Unbound rule
// for a reply with no answers and the zone's own NS RRset in authority: with
// AA it is NODATA (RESPONSE_TYPE_ANSWER), without AA a lame server. Live, the
// delta1/delta2.rdrhost.com servers of ip-109-238-212-091.aim-net.cz answer
// AAAA with AA, no SOA and the apex NS, which the non-descending-referral
// guard turned into SERVFAIL and a public fallback.
func TestResolve_AuthoritativeApexNSWithoutAnswerIsNoData(t *testing.T) {
	for _, tc := range []struct {
		name  string
		aa    bool
		rcode uint8
	}{
		{"AA=1 is NODATA", true, dns.RCodeNoError},
		{"AA=0 is lame", false, dns.RCodeServFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			_, port, _ := net.SplitHostPort(probe.LocalAddr().String())
			probe.Close()

			rd := dns.BuildPlainName("ns.apex.lab")
			apexNS := dns.ResourceRecord{Name: "host.apex.lab", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd}
			serveUDPOn(t, "127.0.0.1:"+port, func(q *dns.Message) *dns.Message {
				return &dns.Message{
					Header:     dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
					Authority:  []dns.ResourceRecord{apexNS},
					Additional: []dns.ResourceRecord{{Name: "ns.apex.lab", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{127, 0, 0, 2}}},
				}
			})
			serveUDPOn(t, "127.0.0.2:"+port, func(q *dns.Message) *dns.Message {
				return &dns.Message{
					Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(tc.aa).Build()},
					Authority: []dns.ResourceRecord{apexNS},
				}
			})

			r := testResolver(t, &mockDNSServer{ip: "127.0.0.1", port: port})
			r.config.MaxQueriesPerRequest = 200
			r.config.RequestTimeout = 5 * time.Second
			res, err := r.Resolve("host.apex.lab", dns.TypeAAAA, dns.ClassIN)
			if err != nil || res == nil || res.RCODE != tc.rcode || len(res.Answers) != 0 {
				t.Fatalf("res=%+v err=%v, want rcode %d and no answers", res, err, tc.rcode)
			}
		})
	}
}

func TestNonDescendingReferralType(t *testing.T) {
	ref := func(owner string, aa bool) *dns.Message {
		rd := dns.BuildPlainName("ns.example.net")
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(aa).Build()},
			Authority: []dns.ResourceRecord{{Name: owner, Type: dns.TypeNS, Class: dns.ClassIN, TTL: 300, RDLength: uint16(len(rd)), RData: rd}},
		}
	}
	cases := []struct {
		owner, current string
		aa             bool
		want           responseType
	}{
		{"zone.lab", "zone.lab", true, responseNoData},
		{"zone.lab", "zone.lab", false, responseServFail},
		{"lab", "zone.lab", true, responseServFail}, // upward, even with AA
	}
	for _, c := range cases {
		if got := nonDescendingReferralType(ref(c.owner, c.aa), "www.zone.lab", c.current); got != c.want {
			t.Errorf("owner %q current %q AA=%v: got %d, want %d", c.owner, c.current, c.aa, got, c.want)
		}
	}
}
