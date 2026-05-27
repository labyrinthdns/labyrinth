package server

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// buildSOAForStaleTest builds a wire-format SOA RDATA with Minimum=1
// so StoreNegative caches the entry with a 1-second negative TTL — the
// 1.2s sleep in the test then crosses expiry and the GetStale path
// fires. Without this the StoreNegative default-minute fallback would
// leave the entry live at the regular cache lookup.
func buildSOAForStaleTest(t *testing.T) []byte {
	t.Helper()
	mname, err := dns.EncodeNameToBytes("ns1.example.com")
	if err != nil {
		t.Fatalf("encode mname: %v", err)
	}
	rname, err := dns.EncodeNameToBytes("admin.example.com")
	if err != nil {
		t.Fatalf("encode rname: %v", err)
	}
	var buf []byte
	buf = append(buf, mname...)
	buf = append(buf, rname...)
	for _, v := range []uint32{2024010101, 3600, 900, 604800, 1 /* Minimum */} {
		buf = append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return buf
}

// TestServeStale_EmitsEDEByRCODE pins Y57: RFC 8914 §4.3 defines EDE 3
// "Stale Answer" for a serve-stale positive response and §4.19 defines
// EDE 19 "Stale NXDOMAIN Answer" specifically for a stale NXDOMAIN. The
// handler picks between them based on the cached entry's RCODE so a
// client can distinguish "expired positive answer" from "expired denial
// of existence" — useful for retry logic (a stale NXDOMAIN is more
// likely to be a real "still doesn't exist" than a positive answer
// going stale, but the client may want to retry against a different
// resolver to confirm).
//
// We drive the handler with an expired cache entry, a deliberately
// broken resolver that can't refresh, and an EDNS-bearing query (RFC
// 8914 §3 — EDE only emits to EDNS-aware clients per Y52). The pin
// verifies BOTH the §4.3 and §4.19 code paths.
func TestServeStale_EmitsEDEByRCODE(t *testing.T) {
	for _, c := range []struct {
		name      string
		cacheRCODE uint8
		wantEDE   uint16
		wantText  string
	}{
		{"positive stale => EDE 3 Stale Answer", dns.RCodeNoError, dns.EDECodeStaleAnswer, "serve-stale"},
		{"stale NXDOMAIN => EDE 19 Stale NXDOMAIN Answer", dns.RCodeNXDomain, dns.EDECodeStaleNXDOMAINAnswer, "serve-stale-nxdomain"},
	} {
		t.Run(c.name, func(t *testing.T) {
			handlerMetrics := metrics.NewMetrics()
			cacheMetrics := metrics.NewMetrics()
			ca := cache.NewCacheWithStale(1000, 1, 86400, 3600, true, 30, cacheMetrics)

			// Seed an entry with TTL=1s so it expires fast.
			// NOTE: .test would hit RFC 6761 special-use synthesis
			// (NXDOMAIN without error) and skip the stale fallback;
			// example.com falls through to real iterative resolution
			// where the panicking resolver returns err and the serve-
			// stale branch fires.
			qname := "y57-stale.example.com"
			if c.cacheRCODE == dns.RCodeNXDomain {
				// RFC 2308 §5: negative TTL = min(SOA RR TTL, SOA.Minimum).
				// Without an SOA in authority, StoreNegative falls back
				// to a 1-minute default — the entry would still be live
				// at the regular cache lookup and never reach GetStale.
				// We attach an SOA with TTL=1 / Minimum=1 so the entry
				// expires before the test sleep and the stale path fires.
				soa := dns.ResourceRecord{
					Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
					TTL: 1, RData: buildSOAForStaleTest(t),
				}
				soa.RDLength = uint16(len(soa.RData))
				ca.StoreNegative(qname, dns.TypeA, dns.ClassIN,
					cache.NegNXDomain, dns.RCodeNXDomain, []dns.ResourceRecord{soa})
			} else {
				ca.Store(qname, dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
					Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 1, RDLength: 4, RData: []byte{10, 0, 0, 1},
				}}, nil)
			}
			// Sleep past TTL so the lookup hits the GetStale path.
			time.Sleep(1200 * time.Millisecond)

			// Broken resolver: triggers the err != nil → GetStale fallback.
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

			// Find the OPT and any EDE option inside it.
			var sawCode uint16
			var sawText string
			var sawEDE bool
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
					code, text, perr := dns.ParseEDEOption(o.Data)
					if perr != nil {
						t.Errorf("ParseEDEOption: %v", perr)
						continue
					}
					sawCode = code
					sawText = text
					sawEDE = true
				}
			}
			if !sawEDE {
				t.Fatalf("no EDE option attached to serve-stale response (RFC 8914 §4.3/§4.19)")
			}
			if sawCode != c.wantEDE {
				t.Errorf("EDE code = %d, want %d", sawCode, c.wantEDE)
			}
			if sawText != c.wantText {
				t.Errorf("EDE text = %q, want %q", sawText, c.wantText)
			}
		})
	}
}

// TestServeStale_NoEDEForNonEDNSClient pins Y57/b: the same serve-stale
// path MUST NOT attach an OPT/EDE to a non-EDNS client's response (RFC
// 8914 §3 + handler's existing `msg.EDNS0 != nil` gate at handler.go).
// A regression that dropped the gate would start spraying EDE OPTs at
// legacy stubs on every serve-stale event — exactly the noise level §3
// forbids. We use the same expired-entry + broken-resolver fixture but
// the query carries no OPT.
func TestServeStale_NoEDEForNonEDNSClient(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 1, 86400, 3600, true, 30, cacheMetrics)

	qname := "y57-stale-nognds.example.com"
	ca.Store(qname, dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}, nil)
	time.Sleep(1200 * time.Millisecond)

	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	query := buildTestQuery(qname, dns.TypeA) // no OPT
	resp, err := h.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	parsed, _ := dns.Unpack(resp)
	for _, rr := range parsed.Additional {
		if rr.Type == dns.TypeOPT {
			t.Errorf("serve-stale response to non-EDNS client carried an OPT (RFC 8914 §3 violation)")
		}
	}
}
