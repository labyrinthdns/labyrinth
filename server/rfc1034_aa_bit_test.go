package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// TestBuildCacheResponse_AABitAlwaysClear pins Y50/a: RFC 1034 §3.7
// defines the AA (Authoritative Answer) bit as a property of "responses
// returned by an authoritative server for the queried name." A recursive
// resolver is by definition NOT authoritative for cached data — even if
// the cached records originally came from an auth's AA=1 response, the
// fact that they're now being served from OUR cache means we ARE the
// intermediary, and AA on our outbound response would be a lie.
//
// Real-world consequence of getting this wrong: monitoring tools and
// stub resolvers treat AA=1 as a strong signal of "fresh, direct from
// origin." A cache hit returning AA=1 silently misleads them into
// trusting stale data as live, and breaks split-horizon detection
// (where the same name has different answers from different auth views).
//
// We assert AA=0 across every DNSSECStatus value and both CD modes —
// AA must NEVER be set on a cache response, regardless of validation
// state or client cookie / CD preference.
func TestBuildCacheResponse_AABitAlwaysClear(t *testing.T) {
	for _, c := range []struct {
		status  string
		queryCD bool
	}{
		{"secure", false},
		{"secure", true},
		{"insecure", false},
		{"bogus", false},
		{"", false},
	} {
		t.Run(c.status+"-cd="+map[bool]string{true: "1", false: "0"}[c.queryCD], func(t *testing.T) {
			h := testHandler()
			query := &dns.Message{
				Header: dns.Header{
					ID: 0x9090,
					Flags: dns.NewFlagBuilder().
						SetRD(true).
						SetCD(c.queryCD).
						Build(),
				},
				Questions: []dns.Question{{Name: "aa.test", Type: dns.TypeA, Class: dns.ClassIN}},
			}
			entry := &cache.Entry{
				DNSSECStatus: c.status,
				Records: []dns.ResourceRecord{{
					Name: "aa.test", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
				}},
			}
			resp, err := h.buildCacheResponse(query, entry)
			if err != nil {
				t.Fatalf("buildCacheResponse: %v", err)
			}
			parsed, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}
			if parsed.Header.AA() {
				t.Errorf("AA bit set on cache response (RFC 1034 §3.7 — recursive resolver is NOT authoritative)")
			}
		})
	}
}

// TestBuildResponse_AABitAlwaysClear pins Y50/b: the same invariant on
// the live-result path. The resolver fetched the answer through the
// iterative chain and is forwarding it to the client — it is still NOT
// the authoritative server for that name, regardless of RCODE outcome.
func TestBuildResponse_AABitAlwaysClear(t *testing.T) {
	for _, c := range []struct {
		name  string
		rcode uint8
	}{
		{"NOERROR", dns.RCodeNoError},
		{"NXDOMAIN", dns.RCodeNXDomain},
		{"SERVFAIL", dns.RCodeServFail},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := testHandler()
			query := &dns.Message{
				Header: dns.Header{
					ID:    0xa0a0,
					Flags: dns.NewFlagBuilder().SetRD(true).Build(),
				},
				Questions: []dns.Question{{Name: "aa-result.test", Type: dns.TypeA, Class: dns.ClassIN}},
			}
			result := &resolver.ResolveResult{
				RCODE: c.rcode,
				Answers: []dns.ResourceRecord{{
					Name: "aa-result.test", Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 60, RDLength: 4, RData: []byte{192, 0, 2, 1},
				}},
			}
			resp, err := h.buildResponse(query, result)
			if err != nil {
				t.Fatalf("buildResponse: %v", err)
			}
			parsed, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}
			if parsed.Header.AA() {
				t.Errorf("AA bit set on live response (RFC 1034 §3.7 — RCODE=%s)", c.name)
			}
		})
	}
}
