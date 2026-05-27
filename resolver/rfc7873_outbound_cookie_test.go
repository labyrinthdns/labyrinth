package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateResponseCookie_MatchAccepted pins the Y21 happy path: a
// response whose COOKIE option's first 8 bytes equal our outbound client
// cookie must be accepted (RFC 7873 §5.4 — compliant auth correctly
// echoed our cookie back).
func TestValidateResponseCookie_MatchAccepted(t *testing.T) {
	r := &Resolver{outboundClientCookie: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	resp := &dns.Message{
		EDNS0: &dns.EDNS0{
			Options: []dns.EDNSOption{{
				Code: dns.EDNSOptionCodeCookie,
				// 8-byte client + 8-byte server echo
				Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02},
			}},
		},
	}
	if !r.validateResponseCookie(resp) {
		t.Error("response echoing our client cookie must be accepted")
	}
}

// TestValidateResponseCookie_MismatchRejected pins the security-critical
// path: a response whose COOKIE first 8 bytes do NOT match our client
// cookie is positive evidence of off-path forgery (the spoofer could
// not have observed our random cookie). Must be rejected even though
// TXID + 0x20 caps + port matched (those are the layers cookies are
// designed to backstop).
func TestValidateResponseCookie_MismatchRejected(t *testing.T) {
	r := &Resolver{outboundClientCookie: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	resp := &dns.Message{
		EDNS0: &dns.EDNS0{
			Options: []dns.EDNSOption{{
				Code: dns.EDNSOptionCodeCookie,
				// Wrong first 8 bytes — the spoofer guessed.
				Data: []byte{9, 9, 9, 9, 9, 9, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0},
			}},
		},
	}
	if r.validateResponseCookie(resp) {
		t.Error("response with mismatched client cookie must be rejected (off-path forgery signal)")
	}
}

// TestValidateResponseCookie_NoCookieOptionAccepted pins the back-compat
// path: auths that do not implement RFC 7873 simply omit the option.
// We MUST accept those responses (§5.4 "the resolver MUST NOT discard
// responses that do not include a COOKIE option").
func TestValidateResponseCookie_NoCookieOptionAccepted(t *testing.T) {
	r := &Resolver{outboundClientCookie: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	// Response with EDNS0 but no COOKIE option.
	resp := &dns.Message{EDNS0: &dns.EDNS0{Options: nil}}
	if !r.validateResponseCookie(resp) {
		t.Error("response without COOKIE option must be accepted (RFC 7873 §5.4)")
	}
	// Response without EDNS0 at all.
	resp2 := &dns.Message{}
	if !r.validateResponseCookie(resp2) {
		t.Error("response without EDNS0 at all must be accepted")
	}
}

// TestValidateResponseCookie_DisabledWhenNoOutboundCookie: when the
// resolver was started without a usable outbound cookie (RNG failed at
// init), the check is a no-op. Otherwise an inopportune RNG failure
// would silently break every outbound query.
func TestValidateResponseCookie_DisabledWhenNoOutboundCookie(t *testing.T) {
	r := &Resolver{outboundClientCookie: nil}
	resp := &dns.Message{
		EDNS0: &dns.EDNS0{
			Options: []dns.EDNSOption{{
				Code: dns.EDNSOptionCodeCookie,
				// Any payload — we should accept since the check is disabled.
				Data: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			}},
		},
	}
	if !r.validateResponseCookie(resp) {
		t.Error("when outboundClientCookie is unset the check must accept (no comparison possible)")
	}
}

// TestValidateResponseCookie_MalformedCookieIgnored: a COOKIE option
// shorter than 8 bytes is malformed (RFC 7873 §4 requires 8-byte client
// cookie minimum). Treat as no-cookie rather than as a forgery — a
// buggy implementation should not look like an attacker.
func TestValidateResponseCookie_MalformedCookieIgnored(t *testing.T) {
	r := &Resolver{outboundClientCookie: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	resp := &dns.Message{
		EDNS0: &dns.EDNS0{
			Options: []dns.EDNSOption{{
				Code: dns.EDNSOptionCodeCookie,
				Data: []byte{0xaa, 0xbb, 0xcc}, // 3 bytes — malformed
			}},
		},
	}
	if !r.validateResponseCookie(resp) {
		t.Error("malformed COOKIE option should be ignored, not treated as forgery")
	}
}
