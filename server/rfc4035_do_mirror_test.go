package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestResponseOPT_DOFlagMirrorsQuery pins RFC 4035 §3.1.3 + RFC 6891
// §6.1.4: the DO (DNSSEC OK) bit in the response OPT record MUST
// reflect the resolver's commitment regarding DNSSEC records in the
// answer. Because our resolver strips DNSSEC RRs for non-DO clients
// (Y51) and includes them for DO clients, the response OPT DO bit
// effectively mirrors the query OPT DO bit.
//
// Why this matters: a downstream stub uses the response DO bit to
// know whether to expect DNSSEC RRs and to set its AD-bit expectation.
// A regression that hard-coded DO=1 in every response would make
// non-DO stubs see DNSSEC bytes (which they ignore but still pay
// transport cost for); a regression that hard-coded DO=0 would
// make DO-aware stubs lose the validator-feedback signal.
//
// We drive both polarities through the handler and assert the
// response OPT carries the same DO flag as the query OPT.
func TestResponseOPT_DOFlagMirrorsQuery(t *testing.T) {
	cases := []struct {
		name        string
		queryDOFlag bool
	}{
		{"DO=0 (legacy stub) → DO=0 in response", false},
		{"DO=1 (DNSSEC-aware stub) → DO=1 in response", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handlerMetrics := metrics.NewMetrics()
			cacheMetrics := metrics.NewMetrics()
			ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
			// Pre-seed an entry so the response goes through buildCacheResponse
			// (the cache-hit path) — this exercises the OPT-build site at
			// handler.go:1160 which is the canonical DO-mirror call.
			qname := "y86-domirror.example.com"
			ca.Store(qname, dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 7},
			}}, nil)

			res := newPanickingResolver(ca)
			h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

			msg := &dns.Message{
				Header: dns.Header{
					ID:    0xD0DF,
					Flags: dns.NewFlagBuilder().SetRD(true).Build(),
				},
				Questions: []dns.Question{{Name: qname, Type: dns.TypeA, Class: dns.ClassIN}},
				Additional: []dns.ResourceRecord{
					dns.BuildOPT(1232, c.queryDOFlag),
				},
			}
			buf := make([]byte, 512)
			packed, err := dns.Pack(msg, buf)
			if err != nil {
				t.Fatalf("pack: %v", err)
			}

			resp, err := h.Handle(packed, nil)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			parsed, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}

			// Find the response OPT and check DO bit.
			foundOPT := false
			for _, rr := range parsed.Additional {
				if rr.Type != dns.TypeOPT {
					continue
				}
				foundOPT = true
				edns, perr := dns.ParseOPT(&rr)
				if perr != nil {
					t.Fatalf("ParseOPT: %v", perr)
				}
				if edns.DOFlag != c.queryDOFlag {
					t.Errorf("response OPT DOFlag = %v, want %v (mirror of query)\nRFC 4035 §3.1.3: response DO bit signals whether DNSSEC RRs are included; mismatch confuses DNSSEC-aware stubs", edns.DOFlag, c.queryDOFlag)
				}
			}
			if !foundOPT {
				t.Errorf("EDNS-bearing query received a response without OPT — RFC 6891 §6.1 requires OPT echo when client speaks EDNS")
			}
		})
	}
}
