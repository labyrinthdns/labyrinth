package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestBADCOOKIE_EchoesFreshServerCookie pins RFC 7873 §5.2.3: when the
// server returns BADCOOKIE because the client's server-cookie failed
// validation, the response MUST carry a freshly issued server-cookie
// so the client can adopt it on retry. Without this echo, after a
// routine server-secret rotation (RFC 9018 §4.3) every active client
// would be permanently locked out: their stored server-cookie hashes
// against the old secret and fails forever, with no in-band path to
// learn a new one. The fix is to issue the new cookie with BADCOOKIE
// — the client retries with the fresh pair and resumes service.
//
// The pin sends a query carrying a (well-formed-by-length but
// hash-mismatched) cookie-pair to a cookie-enabled handler, asserts
// the response is BADCOOKIE (composed Extended RCODE 23), and that
// the response OPT carries a Cookie option with the original 8-byte
// client cookie + a fresh 16-byte server cookie issued for THIS
// client IP.
func TestBADCOOKIE_EchoesFreshServerCookie(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())
	h.EnableCookiesWithSecret(make([]byte, 16)) // deterministic test secret

	// Build a query with a deliberately mismatched server cookie.
	clientCookie := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	bogusServerCookie := make([]byte, 16) // all-zero, will not validate
	cookieData := append([]byte{}, clientCookie...)
	cookieData = append(cookieData, bogusServerCookie...)

	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x9999,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "y64.example.com", Type: dns.TypeA, Class: dns.ClassIN}},
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

	// Compose 12-bit extended RCODE: high 8 bits from OPT TTL byte 0
	// + low 4 bits from header.
	headerLow := uint16(parsed.Header.RCODE())
	var extHigh uint16
	var foundCookie bool
	var gotClient, gotServer []byte
	for _, rr := range parsed.Additional {
		if rr.Type != dns.TypeOPT {
			continue
		}
		extHigh = uint16((rr.TTL >> 24) & 0xff)
		edns, perr := dns.ParseOPT(&rr)
		if perr != nil {
			t.Fatalf("ParseOPT: %v", perr)
		}
		for _, o := range edns.Options {
			if o.Code != dns.EDNSOptionCodeCookie {
				continue
			}
			gotClient, gotServer = dns.ParseCookieOption(o.Data)
			foundCookie = true
		}
	}

	extRCODE := (extHigh << 4) | headerLow
	if extRCODE != uint16(dns.RCodeBadCookie) {
		t.Errorf("extended RCODE = %d, want BADCOOKIE (23) — RFC 7873 §5.2.3", extRCODE)
	}

	if !foundCookie {
		t.Fatalf("BADCOOKIE response carried no Cookie option — RFC 7873 §5.2.3 requires the server to echo a fresh server-cookie so the client can recover after secret rotation")
	}
	if string(gotClient) != string(clientCookie) {
		t.Errorf("echoed client cookie = %x, want %x — must be the exact 8 bytes the client sent", gotClient, clientCookie)
	}
	if len(gotServer) != 16 {
		t.Errorf("fresh server cookie length = %d, want 16 — RFC 9018 §4 fixed-size", len(gotServer))
	}
	// The fresh cookie MUST be different from the bogus one we sent —
	// otherwise we'd just be echoing the rejected token back.
	if string(gotServer) == string(bogusServerCookie) {
		t.Errorf("server echoed the same (rejected) cookie back instead of issuing a fresh one — the client would loop forever")
	}
}
