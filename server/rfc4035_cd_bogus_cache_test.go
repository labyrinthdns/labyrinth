package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestHandler_BogusCacheEntryServedOnlyUnderCD pins RFC 4035 §3.2.2: a Bogus
// entry is cached only because a CD=1 client asked for the data unvalidated.
// Live, `dig +cd dnssec-failed.org` cached the answer and every later CD=0
// client got it as NOERROR, bypassing DNSSEC. CD=0 must now resolve (the
// fail-fast resolver yields SERVFAIL) while CD=1 is still served from cache.
func TestHandler_BogusCacheEntryServedOnlyUnderCD(t *testing.T) {
	rr := dns.ResourceRecord{
		Name: "bogus.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{192, 0, 2, 1},
	}
	for _, tc := range []struct {
		cd        bool
		wantRCode uint8
	}{{false, dns.RCodeServFail}, {true, dns.RCodeNoError}} {
		m := metrics.NewMetrics()
		c := cache.NewCache(1000, 5, 86400, 3600, m)
		c.StoreWithStatus("bogus.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{rr}, nil, "bogus")

		res := newFailFastResolver(c, m)
		res.EnableDNSSEC(discardLogger())
		h := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

		query := buildTestQueryWithEDNS("bogus.example.com", dns.TypeA, 4096)
		if tc.cd {
			flags := binary.BigEndian.Uint16(query[2:4])
			binary.BigEndian.PutUint16(query[2:4], flags|1<<4)
		}
		resp, err := h.Handle(query, nil)
		if err != nil {
			t.Fatalf("CD=%v: Handle: %v", tc.cd, err)
		}
		msg, err := dns.Unpack(resp)
		if err != nil {
			t.Fatalf("CD=%v: Unpack: %v", tc.cd, err)
		}
		if msg.Header.RCODE() != tc.wantRCode {
			t.Errorf("CD=%v: rcode=%d, want %d", tc.cd, msg.Header.RCODE(), tc.wantRCode)
		}
		if msg.Header.AD() {
			t.Errorf("CD=%v: AD set on a Bogus entry", tc.cd)
		}
	}
}
