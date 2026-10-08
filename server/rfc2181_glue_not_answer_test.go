package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestHandler_GlueCacheEntryNotServedAsAnswer pins RFC 2181 §5.4.1: referral
// glue cached for nameserver lookups must not answer a client query. Live
// shape: the root's .istanbul referral seeds a2.nic.istanbul A/AAAA glue,
// and a later client query got that unvalidated glue back with AD=0 even
// though nic.istanbul is signed.
//
// The fail-fast resolver SERVFAILs on any real resolution, so NOERROR here
// would mean the glue was served from cache.
func TestHandler_GlueCacheEntryNotServedAsAnswer(t *testing.T) {
	for _, dnssecOn := range []bool{true, false} {
		name := "dnssec-off"
		if dnssecOn {
			name = "dnssec-on"
		}
		t.Run(name, func(t *testing.T) {
			m := metrics.NewMetrics()
			c := cache.NewCache(1000, 5, 86400, 3600, m)
			c.StoreGlue("ns1.zone.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
				Name: "ns1.zone.example.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{192, 0, 2, 1},
			}})

			res := newFailFastResolver(c, m)
			if dnssecOn {
				res.EnableDNSSEC(discardLogger())
			}
			h := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

			resp, err := h.Handle(buildTestQueryWithEDNS("ns1.zone.example.com", dns.TypeA, 4096), nil)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			msg, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("Unpack: %v", err)
			}
			if msg.Header.RCODE() != dns.RCodeServFail {
				t.Errorf("glue entry served as answer (rcode=%d); want resolution (SERVFAIL from fail-fast resolver)",
					msg.Header.RCODE())
			}
		})
	}
}
