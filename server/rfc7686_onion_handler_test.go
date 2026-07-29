package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestSpecialUseNames_HandlerIntegration_NeverLeaveResolver pins
// RFC 7686 §2 + RFC 6761 §6.4 + RFC 6762 §3 + RFC 8375 §3 at the
// HANDLER level — `resolver/specialuse.go` is unit-tested in
// [resolver/specialuse_test.go], but the integration through the full
// request pipeline (cache lookup → resolve → response build) is what
// matters: a refactor that hooked the short-circuit too late in the
// chain (after a real iterative query had already left the wire) would
// pass the unit test and leak .onion names to upstream resolvers — a
// Tor de-anonymisation hazard explicitly called out in RFC 7686 §2:
//
//   "Name resolution requests for .onion names MUST NOT be performed
//    by recursive resolvers, to avoid privacy leaks."
//
// The pin drives one query per special-use name through the handler
// pipeline and asserts NXDOMAIN comes back. The resolver passed in is
// a `newPanickingResolver` whose metrics are nil — if the short-circuit
// fails and the query reaches real iterative resolution, the panic
// recovery inside `inflight.do` would surface a SERVFAIL+EDE 23 rather
// than the silent NXDOMAIN we expect. So a clean NXDOMAIN is positive
// proof that the short-circuit caught the name before any wire attempt.
func TestSpecialUseNames_HandlerIntegration_NeverLeaveResolver(t *testing.T) {
	cases := []struct {
		name  string
		qname string
		rfc   string
	}{
		{"facebookcorewwwi.onion (Tor)", "facebookcorewwwi.onion", "RFC 7686 §2 — privacy leak risk"},
		{"deep .onion subname", "service.www.facebookcorewwwi.onion", "RFC 7686 §2"},
		{"foo.invalid", "foo.invalid", "RFC 6761 §6.4"},
		{"foo.test", "foo.test", "RFC 6761 §6.2"},
		{"foo.example (bare TLD)", "foo.example", "RFC 6761 §6.5"},
		{"printer.local (mDNS)", "printer.local", "RFC 6762 §3 / RFC 6761 §6.3"},
		{"home.arpa (homenet)", "router.home.arpa", "RFC 8375 §3"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handlerMetrics := metrics.NewMetrics()
			cacheMetrics := metrics.NewMetrics()
			ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
			res := newPanickingResolver(ca)
			h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

			query := buildTestQuery(c.qname, dns.TypeA)
			resp, err := h.Handle(query, nil)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			parsed, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}
			if parsed.Header.RCODE() != dns.RCodeNXDomain {
				t.Errorf("RCODE = %d, want NXDOMAIN — %s requires short-circuit before any upstream attempt", parsed.Header.RCODE(), c.rfc)
			}
		})
	}
}

// TestSpecialUseNames_DoNotShortCircuitPublicNames pins the negation:
// public-DNS names whose label-suffix incidentally contains a
// special-use substring (e.g. "myonion.example.com" — has "onion"
// inside but is NOT a .onion name) MUST reach the regular resolution
// path. A regression that loosened the suffix matcher to a substring
// matcher would NXDOMAIN every domain with "onion" or "test" or
// "local" in its labels — a sweeping silent outage for many real
// names. We use the broken resolver: if the public-name path is
// reached, the result is SERVFAIL (from the panic recovery), not the
// clean NXDOMAIN that the short-circuit produces. SERVFAIL here is
// positive proof that the short-circuit correctly declined the name.
func TestSpecialUseNames_DoNotShortCircuitPublicNames(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	cases := []string{
		"myonion.example.com",    // "onion" inside a label
		"protest.example.com",    // "test" as substring
		"vocally.example.com",    // "local" as substring
		"home.arpa.example.com",  // home.arpa as INTERIOR labels, not suffix
	}
	for _, qname := range cases {
		t.Run(qname, func(t *testing.T) {
			query := buildTestQuery(qname, dns.TypeA)
			resp, err := h.Handle(query, nil)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			parsed, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}
			if parsed.Header.RCODE() == dns.RCodeNXDomain {
				t.Errorf("public name %q matched special-use short-circuit — RFC 7686 / RFC 6761 matchers must be SUFFIX-based, not SUBSTRING-based", qname)
			}
		})
	}
}
