package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// TestBuildCacheResponse_StripsDNSSECForNonDOClient pins Y51/a: RFC 4035
// §3.2.1 — "the server MUST NOT include DNSSEC RR types in the response
// unless the originating query indicated support for DNSSEC." The
// stripDNSSECRRs helper has its own unit tests; this pin guards the
// INTEGRATION — that buildCacheResponse actually calls the strip helper
// on the right paths. A refactor that moved the strip elsewhere (or
// dropped it entirely) would silently ship RRSIGs/NSEC3/DNSKEY records
// to a legacy stub, both wasting bandwidth (DDoS amplification surface)
// and confusing strict stubs that reject unknown RR types in answers.
//
// We seed a cache entry with mixed A + RRSIG records and check that:
//  - non-DO client (no EDNS, or EDNS without DO) gets ONLY the A
//  - DO=1 client gets BOTH
func TestBuildCacheResponse_StripsDNSSECForNonDOClient(t *testing.T) {
	for _, c := range []struct {
		name          string
		clientHasDO   bool
		wantRRSIGKept bool
	}{
		{"no EDNS => RRSIG stripped", false, false},
		{"EDNS DO=1 => RRSIG passed through", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := testHandler()

			query := &dns.Message{
				Header: dns.Header{
					ID:    0xb0b0,
					Flags: dns.NewFlagBuilder().SetRD(true).Build(),
				},
				Questions: []dns.Question{{Name: "strip.test", Type: dns.TypeA, Class: dns.ClassIN}},
			}
			if c.clientHasDO {
				query.EDNS0 = &dns.EDNS0{UDPSize: 4096, DOFlag: true}
			}

			entry := &cache.Entry{
				DNSSECStatus: "secure",
				Records: []dns.ResourceRecord{
					{
						Name: "strip.test", Type: dns.TypeA, Class: dns.ClassIN,
						TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
					},
					{
						Name: "strip.test", Type: dns.TypeRRSIG, Class: dns.ClassIN,
						TTL: 300, RDLength: 1, RData: []byte{0x00}, // placeholder
					},
				},
			}

			resp, err := h.buildCacheResponse(query, entry)
			if err != nil {
				t.Fatalf("buildCacheResponse: %v", err)
			}
			parsed, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}

			rrsigSeen := false
			aSeen := false
			for _, rr := range parsed.Answers {
				switch rr.Type {
				case dns.TypeRRSIG:
					rrsigSeen = true
				case dns.TypeA:
					aSeen = true
				}
			}
			if !aSeen {
				t.Errorf("A record was stripped along with DNSSEC RRs (regression)")
			}
			if rrsigSeen != c.wantRRSIGKept {
				t.Errorf("RRSIG in answers = %v, want %v (RFC 4035 §3.2.1)", rrsigSeen, c.wantRRSIGKept)
			}
		})
	}
}

// TestBuildResponse_StripsDNSSECForNonDOClient pins Y51/b: same RFC
// 4035 §3.2.1 invariant on the live-result path. The fresh-from-upstream
// response carries RRSIG/DNSKEY/NSEC if the resolver validated, and
// those records MUST NOT leak to a non-DO client.
func TestBuildResponse_StripsDNSSECForNonDOClient(t *testing.T) {
	for _, c := range []struct {
		name          string
		clientHasDO   bool
		wantRRSIGKept bool
	}{
		{"no EDNS => RRSIG stripped", false, false},
		{"EDNS DO=1 => RRSIG passed through", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := testHandler()

			query := &dns.Message{
				Header: dns.Header{
					ID:    0xc0c0,
					Flags: dns.NewFlagBuilder().SetRD(true).Build(),
				},
				Questions: []dns.Question{{Name: "strip-live.test", Type: dns.TypeA, Class: dns.ClassIN}},
			}
			if c.clientHasDO {
				query.EDNS0 = &dns.EDNS0{UDPSize: 4096, DOFlag: true}
			}

			result := &resolver.ResolveResult{
				RCODE:        dns.RCodeNoError,
				DNSSECStatus: "secure",
				Answers: []dns.ResourceRecord{
					{
						Name: "strip-live.test", Type: dns.TypeA, Class: dns.ClassIN,
						TTL: 60, RDLength: 4, RData: []byte{192, 0, 2, 1},
					},
					{
						Name: "strip-live.test", Type: dns.TypeRRSIG, Class: dns.ClassIN,
						TTL: 60, RDLength: 1, RData: []byte{0x00},
					},
				},
			}

			resp, err := h.buildResponse(query, result)
			if err != nil {
				t.Fatalf("buildResponse: %v", err)
			}
			parsed, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}

			rrsigSeen := false
			for _, rr := range parsed.Answers {
				if rr.Type == dns.TypeRRSIG {
					rrsigSeen = true
				}
			}
			if rrsigSeen != c.wantRRSIGKept {
				t.Errorf("RRSIG in answers = %v, want %v (RFC 4035 §3.2.1)", rrsigSeen, c.wantRRSIGKept)
			}
		})
	}
}

// TestBuildResponse_KeepsDNSSECWhenClientQueriedForIt pins Y51/c: the
// stripper has a deliberate exception — an explicit `RRSIG name` or
// `DNSKEY name` query MUST receive its DNSSEC records even without DO
// (RFC 4035 §3.2.1: "the only DNSSEC RR types that should be returned
// in response to non-DO queries are those that the originating query
// requested by qtype"). Without this exception a DNS audit tool that
// asks for `DNSKEY .` over a plain UDP query would get an empty answer.
func TestBuildResponse_KeepsDNSSECWhenClientQueriedForIt(t *testing.T) {
	h := testHandler()

	query := &dns.Message{
		Header: dns.Header{
			ID:    0xd0d0,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		// No EDNS — but qtype is DNSKEY, so the strip MUST keep DNSKEY.
		Questions: []dns.Question{{Name: "explicit.test", Type: dns.TypeDNSKEY, Class: dns.ClassIN}},
	}

	result := &resolver.ResolveResult{
		RCODE: dns.RCodeNoError,
		Answers: []dns.ResourceRecord{
			{
				Name: "explicit.test", Type: dns.TypeDNSKEY, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{0, 0, 0, 0},
			},
		},
	}

	resp, err := h.buildResponse(query, result)
	if err != nil {
		t.Fatalf("buildResponse: %v", err)
	}
	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	dnskeySeen := false
	for _, rr := range parsed.Answers {
		if rr.Type == dns.TypeDNSKEY {
			dnskeySeen = true
		}
	}
	if !dnskeySeen {
		t.Errorf("explicit DNSKEY query lost its DNSKEY answer (RFC 4035 §3.2.1 exception)")
	}
}
