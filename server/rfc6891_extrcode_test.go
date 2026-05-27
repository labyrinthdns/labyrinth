package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestExtRCODE_RoundTrip_BADCOOKIE pins Y46/a: RFC 6891 §6.1.3 splits
// the 12-bit Extended RCODE across two fields — the low 4 bits live in
// the DNS header's RCODE nibble, the high 8 bits live in the OPT
// pseudo-record's TTL byte 0. A BADCOOKIE (23 = 0x017) response
// therefore has header RCODE=0x07 and OPT ExtRCODE byte=0x01, recombined
// at the client as (0x01<<4)|0x07 = 23.
//
// The risk this pin guards against: a refactor that "simplifies" the
// error builder to write 23 into the header RCODE nibble alone would
// silently truncate to RCODE 7 (NXRRSET — meaningless here), and a
// validating client would never see BADCOOKIE. Round-trip pins both
// pack (server writes split form) and unpack (client recombines).
func TestExtRCODE_RoundTrip_BADCOOKIE(t *testing.T) {
	h := testHandler()
	h.cookiesEnabled = true

	// Synthesize a minimal client query for the BADCOOKIE handler.
	query := buildBadCookieTestQuery(t, 0x4242)

	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	resp, err := h.buildBadCookieResponse(query, clientCookie, "192.0.2.1:12345")
	if err != nil {
		t.Fatalf("buildBadCookieResponse: %v", err)
	}

	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack BADCOOKIE response: %v", err)
	}

	// Pack-side: header low4 carries BADCOOKIE & 0x0F = 7.
	if got := parsed.Header.RCODE(); got != dns.RCodeBadCookie&0x0F {
		t.Errorf("header RCODE = %d, want %d (BADCOOKIE low 4 bits)", got, dns.RCodeBadCookie&0x0F)
	}

	// Find the OPT pseudo-record and confirm ExtRCODE byte = 1.
	var opt *dns.ResourceRecord
	for i := range parsed.Additional {
		if parsed.Additional[i].Type == dns.TypeOPT {
			opt = &parsed.Additional[i]
			break
		}
	}
	if opt == nil {
		t.Fatalf("BADCOOKIE response MUST carry an OPT pseudo-record (RFC 6891 §6.1.3 — no OPT = no place for ExtRCODE bits)")
	}
	extRCODE := uint8(opt.TTL >> 24)
	if extRCODE != 1 {
		t.Errorf("OPT ExtRCODE byte = %d, want 1 (BADCOOKIE high 8 bits)", extRCODE)
	}

	// Unpack-side: ParseOPT recomposes the value the client will read.
	edns, err := dns.ParseOPT(opt)
	if err != nil {
		t.Fatalf("ParseOPT: %v", err)
	}
	composed := uint16(edns.ExtRCODE)<<4 | uint16(parsed.Header.RCODE())
	if composed != uint16(dns.RCodeBadCookie) {
		t.Errorf("composed Extended RCODE = %d, want %d (BADCOOKIE)", composed, dns.RCodeBadCookie)
	}
}

// TestExtRCODE_RoundTrip_BADVERS pins Y46/b: BADVERS (16 = 0x010) has
// header RCODE=0 and OPT ExtRCODE byte=1. A response that omitted the
// OPT (and thus had no place for the high bits) would arrive at the
// client as plain NOERROR with no signal that the requester's EDNS
// version is unsupported — silent breakage.
func TestExtRCODE_RoundTrip_BADVERS(t *testing.T) {
	h := testHandler()

	query := buildBadCookieTestQuery(t, 0x5252)
	resp, err := h.buildBadVersResponse(query)
	if err != nil {
		t.Fatalf("buildBadVersResponse: %v", err)
	}

	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack BADVERS response: %v", err)
	}

	if got := parsed.Header.RCODE(); got != 0 {
		t.Errorf("header RCODE = %d, want 0 (BADVERS low 4 bits)", got)
	}

	var opt *dns.ResourceRecord
	for i := range parsed.Additional {
		if parsed.Additional[i].Type == dns.TypeOPT {
			opt = &parsed.Additional[i]
			break
		}
	}
	if opt == nil {
		t.Fatalf("BADVERS response MUST carry an OPT pseudo-record (RFC 6891 §6.1.3)")
	}
	extRCODE := uint8(opt.TTL >> 24)
	if extRCODE != 1 {
		t.Errorf("OPT ExtRCODE byte = %d, want 1 (BADVERS high 8 bits)", extRCODE)
	}

	edns, err := dns.ParseOPT(opt)
	if err != nil {
		t.Fatalf("ParseOPT: %v", err)
	}
	composed := uint16(edns.ExtRCODE)<<4 | uint16(parsed.Header.RCODE())
	if composed != 16 { // BADVERS
		t.Errorf("composed Extended RCODE = %d, want 16 (BADVERS)", composed)
	}

	// RFC 6891 §6.1.3 also requires that the responder reports its
	// highest supported EDNS version (0 — we don't support higher) so
	// the requester can downgrade. Pin this so a future bump to
	// version 1 doesn't accidentally still report 0.
	if edns.Version != 0 {
		t.Errorf("OPT Version = %d, want 0 (highest supported)", edns.Version)
	}
}

// buildBadCookieTestQuery returns a minimal wire-format query suitable
// for feeding into the bad-cookie / bad-vers builders. The handlers care
// only about the ID + a parseable question; OPT contents are reconstructed
// by the response builder.
func buildBadCookieTestQuery(t *testing.T, id uint16) []byte {
	t.Helper()
	q := &dns.Message{
		Header: dns.Header{
			ID:      id,
			Flags:   dns.NewFlagBuilder().SetRD(true).Build(),
			QDCount: 1,
		},
		Questions: []dns.Question{{Name: "ext-rcode.test", Type: dns.TypeA, Class: dns.ClassIN}},
	}
	buf := make([]byte, 512)
	packed, err := dns.Pack(q, buf)
	if err != nil {
		t.Fatalf("pack test query: %v", err)
	}
	return packed
}
