package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestCookieDisabledServer_IgnoresClientCookies pins RFC 7873 §5.4 +
// the general DNS extension policy: when the server has DNS Cookies
// DISABLED, a query carrying a Cookie option in its OPT record MUST
// be answered normally — no FORMERR for the unrecognised option, no
// BADCOOKIE for unvalidatable contents. The operator opted out of
// cookies; the option simply has no semantic effect from the server's
// perspective and the query proceeds as if it carried no cookie at all.
//
// Why this matters: a cookie-aware stub (BIND ≥ 9.10, Knot stub,
// systemd-resolved with the right config) ALWAYS attaches a cookie
// option when it has one. If the server we point that stub at happens
// to have cookies disabled — common in tightly-locked-down deployments
// where the operator doesn't want cookies — the server MUST gracefully
// ignore the cookie and answer the underlying question. Rejecting the
// cookie would break the stub for every query, not just one.
//
// We drive a 24-byte (8 client + 16 server) cookie at a handler whose
// cookies are NOT enabled and assert: (a) no FORMERR, (b) no extended
// BADCOOKIE — any other RCODE (typically SERVFAIL from the broken
// resolver, but NXDOMAIN, NOERROR are also fine) is acceptable.
func TestCookieDisabledServer_IgnoresClientCookies(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())
	// Note: NO EnableCookies / EnableCookiesWithSecret — cookies stay disabled.

	// Full 24-byte cookie (8 client + 16 server) — looks plausible
	// but the server has no way to validate it (no secret).
	cookieData := []byte{
		0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, // client
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // server (16)
	}

	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x7873,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "y83.example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{
				{Code: dns.EDNSOptionCodeCookie, Data: cookieData},
			}),
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

	if parsed.Header.RCODE() == dns.RCodeFormErr {
		t.Errorf("FORMERR returned for cookie option on cookie-disabled server — RFC 7873 §5.4: a disabled-cookie server MUST treat unrecognised cookie options as no-ops, not malformations")
	}

	// Compose 12-bit extended RCODE: BADCOOKIE = 23.
	var extRCODE uint16
	headerLow := uint16(parsed.Header.RCODE())
	for _, rr := range parsed.Additional {
		if rr.Type != dns.TypeOPT {
			continue
		}
		extHigh := uint16((rr.TTL >> 24) & 0xff)
		extRCODE = (extHigh << 4) | headerLow
	}
	if extRCODE == uint16(dns.RCodeBadCookie) {
		t.Errorf("BADCOOKIE returned by cookie-disabled server — the server cannot ASK for cookie validation it doesn't perform; cookie-aware stubs would loop forever retrying")
	}
}
