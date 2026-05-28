package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestRFC6303_PrivateReverseZones_HandlerIntegration pins RFC 6303 §3
// at the HANDLER level. The unit-level matcher in
// [resolver/rfc6303_locally_served_test.go] already covers the address
// arithmetic; this test pins the INTEGRATION — that a PTR query for
// an RFC 1918 / link-local / loopback / ULA reverse name actually
// produces an NXDOMAIN response through the full pipeline and is NOT
// forwarded to the public root.
//
// Why this matters: leaking 192.168.0.1 / 10.x.x.x reverse PTR queries
// to the public DNS root is both a privacy/topology disclosure (the
// pattern of queries tells external observers about the internal
// network layout) AND an unnecessary load on the root operators —
// which is exactly why RFC 6303 §3 mandates local short-circuit.
//
// We drive a handful of canonical private reverses and assert NXDOMAIN
// comes back cleanly (the broken resolver would surface as SERVFAIL if
// the short-circuit failed to catch them).
func TestRFC6303_PrivateReverseZones_HandlerIntegration(t *testing.T) {
	cases := []struct {
		name  string
		qname string
		why   string
	}{
		{"RFC 1918 10/8", "1.0.0.10.in-addr.arpa", "RFC 1918 private — must not leak"},
		{"RFC 1918 172.16/12", "1.0.16.172.in-addr.arpa", "RFC 1918 private"},
		{"RFC 1918 192.168/16", "1.1.168.192.in-addr.arpa", "RFC 1918 private"},
		{"Loopback 127/8", "1.0.0.127.in-addr.arpa", "RFC 6303 §4.2 — loopback"},
		{"Link-local 169.254/16", "1.1.254.169.in-addr.arpa", "RFC 6303 §4.3 — IPv4 link-local"},
		{"TEST-NET-1 192.0.2/24", "1.2.0.192.in-addr.arpa", "RFC 6303 §4.4 — documentation range"},
		{"IPv6 ULA fd00::/8", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa", "RFC 6303 §4.5 — IPv6 ULA"},
		{"IPv6 link-local fe80::/10", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa", "RFC 6303 §4.6 — IPv6 link-local"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handlerMetrics := metrics.NewMetrics()
			cacheMetrics := metrics.NewMetrics()
			ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
			res := newPanickingResolver(ca)
			h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

			query := buildTestQuery(c.qname, dns.TypePTR)
			resp, err := h.Handle(query, nil)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			parsed, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}
			if parsed.Header.RCODE() != dns.RCodeNXDomain {
				t.Errorf("RCODE = %d, want NXDOMAIN — %s. A non-NXDOMAIN here means the reverse query reached upstream and leaked internal topology to the root operators (RFC 6303 §3 violation)", parsed.Header.RCODE(), c.why)
			}
		})
	}
}

// TestRFC6303_PublicReverseNotShortCircuited pins the negation —
// a real public-address reverse query (8.8.8.8) MUST reach normal
// resolution. A regression that broadened the matcher to all
// in-addr.arpa names would silently NXDOMAIN every PTR lookup,
// blinding monitoring/logging tools to all reverse-DNS data.
func TestRFC6303_PublicReverseNotShortCircuited(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	// Public Google DNS reverse: 8.8.8.8 → 8.8.8.8.in-addr.arpa
	query := buildTestQuery("8.8.8.8.in-addr.arpa", dns.TypePTR)
	resp, err := h.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	// Broken resolver returns SERVFAIL through normal path; clean
	// NXDOMAIN here would mean the matcher mistakenly caught a
	// public address.
	if parsed.Header.RCODE() == dns.RCodeNXDomain {
		t.Errorf("public 8.8.8.8 reverse caught by RFC 6303 short-circuit — matcher must reject only the RFC-listed private ranges")
	}
}
