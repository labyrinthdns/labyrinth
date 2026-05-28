package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestCookie_BootstrapPermissiveness pins RFC 7873 §5.2 + §5.4 cookie
// state-machine semantics. The handler MUST be permissive about the
// SHAPE of the cookie option in two distinct cases that look superficially
// like errors but are actually valid protocol states:
//
//   1. **Bootstrap query** — client sends only an 8-byte client cookie
//      and no server cookie. This is the very first query in a new
//      client/server session before the client has been issued one.
//      The handler MUST NOT FORMERR; it should proceed with resolution
//      and (in a separate code path, server/handler.go:1012) attach a
//      fresh server-cookie to the success response so the client can
//      use it on the next query. A FORMERR here would prevent every
//      cookie-aware client from EVER exchanging a first cookie.
//
//   2. **Non-16-byte server cookie** — some legacy clients (and the
//      original RFC 7873 spec before RFC 9018 fixed the length at 16)
//      issue server cookies of 8 bytes. RFC 9018 §4 allows 8–32 byte
//      server cookies; only 16 is current spec. The validation gate
//      at server/handler.go:649 only triggers BADCOOKIE when client
//      cookie is 8 AND server cookie is 16. Lengths outside [16] fall
//      through silently — must not FORMERR.
//
// A regression that tightened either gate would silently break interop
// with millions of cookie-aware stubs (Knot resolver < 5.3, BIND
// pre-9.18). The pin drives both shapes through a cookie-enabled
// handler and asserts neither produces FORMERR.
func TestCookie_BootstrapPermissiveness(t *testing.T) {
	mkHandler := func() *MainHandler {
		handlerMetrics := metrics.NewMetrics()
		cacheMetrics := metrics.NewMetrics()
		ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
		res := newPanickingResolver(ca)
		h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())
		h.EnableCookiesWithSecret(make([]byte, 16))
		return h
	}

	mkQuery := func(t *testing.T, cookieData []byte) []byte {
		t.Helper()
		msg := &dns.Message{
			Header: dns.Header{
				ID:    0x7873,
				Flags: dns.NewFlagBuilder().SetRD(true).Build(),
			},
			Questions: []dns.Question{{Name: "y71.example.com", Type: dns.TypeA, Class: dns.ClassIN}},
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
		return packed
	}

	t.Run("client-only 8-byte cookie (bootstrap)", func(t *testing.T) {
		h := mkHandler()
		// 8 bytes: just the client cookie, no server cookie yet.
		cookie := []byte{0xCC, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
		resp, err := h.Handle(mkQuery(t, cookie), nil)
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		parsed, err := dns.Unpack(resp)
		if err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if parsed.Header.RCODE() == dns.RCodeFormErr {
			t.Errorf("bootstrap query (8-byte client cookie, no server cookie) returned FORMERR — RFC 7873 §5.4 requires the server to proceed and ISSUE a cookie on this state, not reject it")
		}
	})

	t.Run("8-byte server cookie (legacy / RFC 9018 8-32 byte range)", func(t *testing.T) {
		h := mkHandler()
		// 16 bytes: 8 client + 8 server (RFC 7873 original 8-byte server
		// cookie, valid per RFC 9018 §4's 8–32 range though not our default).
		legacyCookie := []byte{
			0xCC, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		}
		resp, err := h.Handle(mkQuery(t, legacyCookie), nil)
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		parsed, err := dns.Unpack(resp)
		if err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if parsed.Header.RCODE() == dns.RCodeFormErr {
			t.Errorf("legacy 8-byte server cookie produced FORMERR — RFC 9018 §4 allows 8–32 byte server cookies and the gate must not reject other lengths")
		}
	})
}
