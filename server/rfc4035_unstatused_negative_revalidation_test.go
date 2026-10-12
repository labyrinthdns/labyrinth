package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestHandler_UnstatusedNegativeCacheHitRevalidates pins that an NXDOMAIN or
// NODATA cached with no DNSSEC status is not served to a client while a
// validator is active. NS-address lookups resolve with validation skipped and
// cache their denials; live, the AAAA NODATA of ns2.private-domain.com (a
// signed zone's nameserver) was then served to clients without AD.
//
// The fail-fast resolver tells the paths apart: a served entry gives the
// cached rcode, revalidation gives SERVFAIL. A secure negative is still
// served with AD, and an RFC 9520 failure entry is still served from cache.
func TestHandler_UnstatusedNegativeCacheHitRevalidates(t *testing.T) {
	soaRD := append(dns.BuildPlainName("ns.zone.example.com"), dns.BuildPlainName("hostmaster.zone.example.com")...)
	soaRD = append(soaRD, 0, 0, 0, 1, 0, 0, 0, 60, 0, 0, 0, 60, 0, 0, 1, 0, 0, 0, 1, 0)
	soa := []dns.ResourceRecord{{
		Name: "zone.example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 300, RDLength: uint16(len(soaRD)), RData: soaRD,
	}}

	for _, tc := range []struct {
		name      string
		store     func(c *cache.Cache)
		wantRCode uint8
		wantAD    bool
	}{
		{"nodata/unstatused-is-revalidated", func(c *cache.Cache) {
			c.StoreNegative("ns2.zone.example.com", dns.TypeAAAA, dns.ClassIN, cache.NegNoData, dns.RCodeNoError, soa)
		}, dns.RCodeServFail, false},
		{"nxdomain/unstatused-is-revalidated", func(c *cache.Cache) {
			c.StoreNegative("ns2.zone.example.com", dns.TypeAAAA, dns.ClassIN, cache.NegNXDomain, dns.RCodeNXDomain, soa)
		}, dns.RCodeServFail, false},
		{"nodata/secure-still-served", func(c *cache.Cache) {
			c.StoreNegativeWithStatus("ns2.zone.example.com", dns.TypeAAAA, dns.ClassIN, cache.NegNoData, dns.RCodeNoError, soa, "secure")
		}, dns.RCodeNoError, true},
		{"failure-entry-still-served", func(c *cache.Cache) {
			c.StoreFailure("ns2.zone.example.com", dns.TypeAAAA, dns.ClassIN, cache.DefaultFailureTTL)
		}, dns.RCodeServFail, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := metrics.NewMetrics()
			c := cache.NewCache(1000, 5, 86400, 3600, m)
			tc.store(c)
			res := newFailFastResolver(c, m)
			res.EnableDNSSEC(discardLogger())
			h := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

			hitsBefore := m.Snapshot().CacheHits
			resp, err := h.Handle(buildTestQueryWithEDNS("ns2.zone.example.com", dns.TypeAAAA, 4096), nil)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			msg, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("Unpack: %v", err)
			}
			if msg.Header.RCODE() != tc.wantRCode {
				t.Errorf("rcode=%d, want %d", msg.Header.RCODE(), tc.wantRCode)
			}
			if msg.Header.AD() != tc.wantAD {
				t.Errorf("AD=%v, want %v", msg.Header.AD(), tc.wantAD)
			}
			if tc.name == "failure-entry-still-served" && m.Snapshot().CacheHits == hitsBefore {
				t.Error("RFC 9520 failure entry was not served from cache")
			}
		})
	}
}
