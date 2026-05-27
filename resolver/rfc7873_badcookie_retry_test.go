package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestExtendedRCODE_ComposesEDNSAndHeader pins the bit-stitching
// required by RFC 6891 §6.1.3: the 12-bit extended RCODE is built by
// concatenating the OPT TTL's high byte (parsed as EDNS0.ExtRCODE) with
// the header's low 4 RCODE bits. A resolver that consults only the
// header sees BADCOOKIE (23 = 0x17) as plain "7" (a reserved value)
// and never triggers the retry path.
func TestExtendedRCODE_ComposesEDNSAndHeader(t *testing.T) {
	// Construct a header carrying low 4 bits = 7 (BADCOOKIE low nibble)
	// and an EDNS0 ExtRCODE = 1 (BADCOOKIE high nibble).
	h := dns.Header{Flags: 0x0007}
	msg := &dns.Message{Header: h, EDNS0: &dns.EDNS0{ExtRCODE: 1}}
	if got := extendedRCODE(msg); got != dns.RCodeBadCookie {
		t.Errorf("extendedRCODE = %d, want %d (BADCOOKIE)", got, dns.RCodeBadCookie)
	}
}

// TestExtendedRCODE_PlainHeaderRcode: when ExtRCODE is zero (the common
// case), the result is just the header's low 4 bits — no extension.
func TestExtendedRCODE_PlainHeaderRcode(t *testing.T) {
	msg := &dns.Message{Header: dns.Header{Flags: 0x0003}} // NXDOMAIN
	if got := extendedRCODE(msg); got != dns.RCodeNXDomain {
		t.Errorf("extendedRCODE = %d, want %d (NXDOMAIN)", got, dns.RCodeNXDomain)
	}
}

// TestExtendedRCODE_NilMessage is the defensive guard — extendedRCODE
// must not panic on a nil pointer (it is called on freshly-unpacked
// responses, but a future path might pass a nil after an upstream
// error path).
func TestExtendedRCODE_NilMessage(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil message must not panic: %v", r)
		}
	}()
	if got := extendedRCODE(nil); got != 0 {
		t.Errorf("nil message must return 0, got %d", got)
	}
}

// TestExtractServerCookie_ReturnsServerPortion pins the helper that
// pulls the server cookie out of a BADCOOKIE response so we can append
// it to the retry query (RFC 7873 §5.4). Bytes 0..7 are the client
// cookie we sent (echoed back); bytes 8..end are the server cookie.
func TestExtractServerCookie_ReturnsServerPortion(t *testing.T) {
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	serverCookie := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22}
	payload := append(append([]byte(nil), clientCookie...), serverCookie...)

	msg := &dns.Message{EDNS0: &dns.EDNS0{
		Options: []dns.EDNSOption{{Code: dns.EDNSOptionCodeCookie, Data: payload}},
	}}
	got := extractServerCookie(msg)
	if len(got) != len(serverCookie) {
		t.Fatalf("extractServerCookie length = %d, want %d", len(got), len(serverCookie))
	}
	for i := range serverCookie {
		if got[i] != serverCookie[i] {
			t.Errorf("server cookie byte %d = %#x, want %#x", i, got[i], serverCookie[i])
		}
	}
}

// TestExtractServerCookie_NoServerPortion: a cookie option with only
// the 8-byte client cookie and no server portion must return nil so
// the BADCOOKIE retry path does NOT fire (an auth that issues
// BADCOOKIE without a server cookie is buggy; nothing useful to
// retry with).
func TestExtractServerCookie_NoServerPortion(t *testing.T) {
	msg := &dns.Message{EDNS0: &dns.EDNS0{
		Options: []dns.EDNSOption{{Code: dns.EDNSOptionCodeCookie, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}},
	}}
	if got := extractServerCookie(msg); got != nil {
		t.Errorf("missing server cookie must return nil, got %v", got)
	}
}

// TestExtractServerCookie_NoCookieOption: a response without any
// COOKIE option at all returns nil. Same outcome as above — no retry.
func TestExtractServerCookie_NoCookieOption(t *testing.T) {
	msg := &dns.Message{EDNS0: &dns.EDNS0{}}
	if got := extractServerCookie(msg); got != nil {
		t.Errorf("no cookie option must return nil, got %v", got)
	}
	// Also check nil EDNS0 path.
	if got := extractServerCookie(&dns.Message{}); got != nil {
		t.Errorf("nil EDNS0 must return nil, got %v", got)
	}
}
