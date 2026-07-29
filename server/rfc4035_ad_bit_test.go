package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
)

// TestBuildCacheResponse_ADBitGating pins Y45: RFC 4035 §3.2.2 — a
// recursive resolver MUST clear the AD bit on responses to clients
// unless the data was validated AND the client did not ask to skip
// validation (CD bit clear).
//
// Three cases pin the truth table:
//  1. status=secure  + client CD=0 → AD=1 (the canonical "validated" path)
//  2. status=secure  + client CD=1 → AD=0 (client opted out, RFC 6840 §5.7)
//  3. status=insecure/bogus/unset + CD=0 → AD=0 (no validation = no AD)
//
// A regression here is a silent security downgrade: stub resolvers /
// downstream forwarders use AD to decide whether to trust the answer.
// If we set AD=1 without validating, we are LYING; if we clear AD=1
// after validating, we mark a clean answer as untrusted.
func TestBuildCacheResponse_ADBitGating(t *testing.T) {
	for _, c := range []struct {
		name     string
		status   string
		queryCD  bool
		wantAD   bool
	}{
		{"secure + CD=0 => AD=1", "secure", false, true},
		{"secure + CD=1 => AD=0 (client opted out)", "secure", true, false},
		{"insecure + CD=0 => AD=0", "insecure", false, false},
		{"bogus + CD=0 => AD=0", "bogus", false, false},
		{"unset + CD=0 => AD=0", "", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := testHandler()

			query := &dns.Message{
				Header: dns.Header{
					ID: 0x1234,
					Flags: dns.NewFlagBuilder().
						SetRD(true).
						SetCD(c.queryCD).
						Build(),
				},
				Questions: []dns.Question{{Name: "ad.test", Type: dns.TypeA, Class: dns.ClassIN}},
			}

			entry := &cache.Entry{
				DNSSECStatus: c.status,
				Records: []dns.ResourceRecord{{
					Name:     "ad.test",
					Type:     dns.TypeA,
					Class:    dns.ClassIN,
					TTL:      300,
					RDLength: 4,
					RData:    []byte{10, 0, 0, 1},
				}},
			}

			resp, err := h.buildCacheResponse(query, entry)
			if err != nil {
				t.Fatalf("buildCacheResponse: %v", err)
			}
			parsed, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("unpack response: %v", err)
			}
			gotAD := parsed.Header.AD()
			if gotAD != c.wantAD {
				t.Errorf("AD bit = %v, want %v (status=%q, queryCD=%v)", gotAD, c.wantAD, c.status, c.queryCD)
			}
		})
	}
}
