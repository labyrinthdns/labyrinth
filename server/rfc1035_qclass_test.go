package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestNonINQClass_Refused pins the policy that the resolver REFUSES
// queries with QCLASS != IN (RFC 1035 §3.2.4). CHAOS class queries
// like `version.bind. CH TXT` are deliberately not honoured here:
// echoing software identification is a passive recon gift to anyone
// scanning the internet for resolver versions. Refusing with EDE 21
// (Not Supported) tells legitimate operators why their misrouted
// query got rejected.
//
// Pin three values: RCODE = REFUSED, ARCount > 0 with an OPT carrying
// EDE 21 (when the client speaks EDNS), and no panic/error from the
// handler — a regression that let CH through to the resolver could
// crash the iterative path which assumes IN-class delegations.
func TestNonINQClass_Refused(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	h := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	client := &mockAddr{network: "udp", addr: "10.0.0.1:12345"}

	// Build a CH-class query manually — buildTestQueryWithEDNS hardcodes
	// IN. We patch the QCLASS byte directly so the test stays in this
	// file rather than reaching into the helper.
	q := buildTestQueryWithEDNS("version.bind", dns.TypeTXT, 1232)
	// The QCLASS for the question lives 2 bytes after QTYPE; for our
	// canonical wire shape that's just before the OPT pseudo-RR.
	// Easier: re-pack via dns.Pack with explicit Class=3 (CHAOS).
	msg, err := dns.Unpack(q)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	msg.Questions[0].Class = 3 // CHAOS
	buf := make([]byte, 4096)
	q2, err := dns.Pack(msg, buf)
	if err != nil {
		t.Fatalf("repack: %v", err)
	}

	resp, err := h.Handle(q2, client)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	// RCODE == REFUSED.
	if len(resp) < 4 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeRefused {
		t.Errorf("RCODE = %d, want REFUSED(5)", rcode)
	}

	// EDE 21 in the response (EDNS client).
	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	var opt *dns.ResourceRecord
	for i := range parsed.Additional {
		if parsed.Additional[i].Type == dns.TypeOPT {
			opt = &parsed.Additional[i]
			break
		}
	}
	if opt == nil {
		t.Fatalf("OPT missing from EDNS-client refusal response")
	}
	edns, err := dns.ParseOPT(opt)
	if err != nil {
		t.Fatalf("ParseOPT: %v", err)
	}
	var sawEDE bool
	for _, o := range edns.Options {
		if o.Code != dns.EDNSOptionCodeEDE {
			continue
		}
		code, _, err := dns.ParseEDEOption(o.Data)
		if err != nil {
			continue
		}
		if code == dns.EDECodeNotSupported {
			sawEDE = true
		}
	}
	if !sawEDE {
		t.Errorf("EDE %d (Not Supported) not present on CH-class refusal", dns.EDECodeNotSupported)
	}

	// Per-EDE counter wiring (M4.6) — exactly one EDE 21 emission.
	counts := m.EDECounts()
	if got := counts[dns.EDECodeNotSupported]; got != 1 {
		t.Errorf("EDE %d count = %d after 1 refusal, want 1", dns.EDECodeNotSupported, got)
	}
}

// TestINQClass_NotRejected — negative control: an IN-class query is
// NOT rejected by the QCLASS gate. Without this check a regression
// that flipped the comparison would break every query.
func TestINQClass_NotRejected(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	h := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	client := &mockAddr{network: "udp", addr: "10.0.0.1:12345"}
	q := buildTestQuery("example.test", dns.TypeA)

	resp, err := h.Handle(q, client)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	// Resolver test mock may answer NOERROR or SERVFAIL depending on
	// data. The key invariant: NOT REFUSED-by-QCLASS-gate. NOTIMP and
	// FORMERR would indicate other regression classes.
	if rcode == dns.RCodeRefused {
		t.Errorf("RCODE = REFUSED for IN-class query; QCLASS gate over-applied")
	}
}
