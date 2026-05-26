package resolver

import (
	"strings"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestResolveIterativeDNAME_SynthesizesCNAMEWhenUpstreamOmitsIt pins the
// Y10 fix to RFC 6672 §5.3: "If the resolver does not find a CNAME [in
// the response] associated with the DNAME, it MUST synthesize one." Many
// stub resolvers and applications only know how to follow CNAME chains;
// without the synthesized CNAME the redirection is invisible to them and
// the lookup appears to fail. The auth is supposed to include the
// synthesized CNAME per RFC 6672 §3.2 but historical and
// non-conformant servers omit it — the iterative resolver is the last
// line of defence.
//
// Mock returns ONLY a DNAME at example.com → target.com (no companion
// CNAME), then resolves target.com normally. After resolution, the answer
// the resolver returns to its caller must contain BOTH the DNAME and a
// CNAME synthesised by the resolver itself, mapping sub.example.com →
// sub.target.com. The TTL of the synthesised CNAME equals the DNAME TTL
// (RFC 6672 §5.3.3).
func TestResolveIterativeDNAME_SynthesizesCNAMEWhenUpstreamOmitsIt(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		qname := q.Questions[0].Name

		// example.com tree: respond DNAME-only (NO companion CNAME).
		if strings.HasSuffix(qname, ".example.com") || qname == "example.com" {
			dnameRData := dns.BuildPlainName("target.com")
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: "example.com", Type: dns.TypeDNAME, Class: dns.ClassIN,
					TTL: 7777, RDLength: uint16(len(dnameRData)), RData: dnameRData,
				}},
			}
		}

		// target.com tree: ordinary A answer.
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).Build()},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: qname, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 99},
			}},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("sub.example.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Fatalf("resolve error: %v", err)
	}
	if result.RCODE != dns.RCodeNoError {
		t.Fatalf("expected NOERROR, got %d", result.RCODE)
	}

	var sawDNAME, sawSynthCNAME bool
	for _, rr := range result.Answers {
		switch rr.Type {
		case dns.TypeDNAME:
			sawDNAME = true
		case dns.TypeCNAME:
			if strings.EqualFold(strings.TrimSuffix(rr.Name, "."), "sub.example.com") {
				if rr.TTL != 7777 {
					t.Errorf("synthesised CNAME TTL: want 7777 (inherited from DNAME), got %d", rr.TTL)
				}
				target, perr := dns.ParseCNAME(rr.RData, 0)
				if perr != nil {
					t.Fatalf("synthesised CNAME RData unparsable: %v", perr)
				}
				if !strings.EqualFold(strings.TrimSuffix(target, "."), "sub.target.com") {
					t.Errorf("synthesised CNAME target: want sub.target.com, got %s", target)
				}
				sawSynthCNAME = true
			}
		}
	}
	if !sawDNAME {
		t.Error("DNAME RR missing from answer (must be preserved alongside synth CNAME)")
	}
	if !sawSynthCNAME {
		t.Error("synthesised CNAME for sub.example.com missing — RFC 6672 §5.3 says the " +
			"resolver MUST synthesise one when upstream omits it")
	}
}

// TestEncodeNameToBytes pins the new helper's encoding shape — the
// synthesised CNAME's RData round-trips through ParseCNAME. A drift here
// (e.g. accidentally adding a trailing label length byte or omitting the
// root terminator) breaks every downstream CNAME parser.
func TestEncodeNameToBytes_RoundTripWithParseCNAME(t *testing.T) {
	cases := []string{
		".",
		"example.com",
		"example.com.",
		"a.b.c.d.example.com",
	}
	for _, in := range cases {
		raw, err := dns.EncodeNameToBytes(in)
		if err != nil {
			t.Fatalf("EncodeNameToBytes(%q): %v", in, err)
		}
		got, err := dns.ParseCNAME(raw, 0)
		if err != nil {
			t.Fatalf("ParseCNAME after encoding %q: %v", in, err)
		}
		want := strings.TrimSuffix(in, ".")
		if got2 := strings.TrimSuffix(got, "."); got2 != want {
			t.Errorf("round-trip %q → encode → parse = %q, want %q", in, got, want)
		}
	}
}
