package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestHandle_BadCookie pins the R7+R8 fix: a client that presents BOTH a
// client cookie and a server cookie MUST be validated, and an invalid
// server cookie MUST cause the server to respond with extended-RCODE 23
// (BADCOOKIE). The wire encoding splits the 12-bit RCODE: low 4 bits
// (= 0x07) into the header, high 8 bits (= 0x01) into the OPT TTL byte 0.
// Without the fix, a stale or forged cookie was silently accepted and
// the server returned normal results — defeating the cookie's purpose
// as proof-of-IP-ownership for bypassing rate-limit/RRL.
func TestHandle_BadCookie(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.EnableCookiesWithSecret(make([]byte, 16))

	clientCookie := []byte("ABCDEFGH")
	// 16-byte server cookie that won't validate against the secret —
	// version byte 1, zero hash. This is what an attacker replaying a
	// stale cookie would send.
	forgedServerCookie := make([]byte, 16)
	forgedServerCookie[0] = 1

	cookieData := append([]byte{}, clientCookie...)
	cookieData = append(cookieData, forgedServerCookie...)

	q := &dns.Message{
		Header:    dns.Header{ID: 0xC0FE, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
		Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{{
				Code: dns.EDNSOptionCodeCookie,
				Data: cookieData,
			}}),
		},
	}
	packed, _ := dns.Pack(q, make([]byte, 1232))

	resp, err := handler.Handle(packed, &mockAddr{network: "udp", addr: "1.2.3.4:54321"})
	if err != nil || resp == nil {
		t.Fatalf("Handle: err=%v resp=%v", err, resp)
	}

	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	// Header RCODE must be 7 (low 4 bits of BADCOOKIE=23).
	if rc := msg.Header.RCODE(); rc != 0x07 {
		t.Errorf("header RCODE: want 7 (low nibble of BADCOOKIE), got %d", rc)
	}

	// Find OPT and verify ExtRCODE high byte = 1.
	var optRR *dns.ResourceRecord
	for i := range msg.Additional {
		if msg.Additional[i].Type == dns.TypeOPT {
			optRR = &msg.Additional[i]
			break
		}
	}
	if optRR == nil {
		t.Fatal("BADCOOKIE response carried no OPT — extended RCODE has " +
			"nowhere to live (RFC 6604 §3)")
	}
	extRCODE := uint8(optRR.TTL >> 24)
	if extRCODE != 1 {
		t.Errorf("OPT ExtRCODE: want 1 (BADCOOKIE high byte), got %d", extRCODE)
	}

	// BADCOOKIE response must echo a freshly-issued server cookie so the
	// client can adopt it (RFC 7873 §5.2.3).
	if msg.EDNS0 == nil {
		t.Fatal("response missing EDNS0")
	}
	cookieFound := false
	for _, opt := range msg.EDNS0.Options {
		if opt.Code == dns.EDNSOptionCodeCookie {
			cookieFound = true
			cc, sc := dns.ParseCookieOption(opt.Data)
			if len(cc) != 8 {
				t.Errorf("echoed client cookie length: want 8, got %d", len(cc))
			}
			if len(sc) != 16 {
				t.Errorf("issued server cookie length: want 16, got %d", len(sc))
			}
		}
	}
	if !cookieFound {
		t.Error("BADCOOKIE response did not echo a cookie option " +
			"(RFC 7873 §5.2.3 — client cannot adopt fresh cookie)")
	}
}

// TestHandle_ValidCookieDoesNotTriggerBadCookie is the positive control:
// when a client presents a properly computed server cookie the handler
// processes the query normally (no BADCOOKIE).
func TestHandle_ValidCookieDoesNotTriggerBadCookie(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.EnableCookiesWithSecret(make([]byte, 16))

	clientCookie := []byte("ABCDEFGH")
	clientIP := "1.2.3.4"
	// Use the same handler to compute the expected server cookie so it
	// validates against the very same secret.
	serverCookie := handler.generateServerCookie(clientCookie, clientIP)

	cookieData := append([]byte{}, clientCookie...)
	cookieData = append(cookieData, serverCookie...)

	q := &dns.Message{
		Header:    dns.Header{ID: 0xD00D, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
		Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{{
				Code: dns.EDNSOptionCodeCookie,
				Data: cookieData,
			}}),
		},
	}
	packed, _ := dns.Pack(q, make([]byte, 1232))

	resp, err := handler.Handle(packed, &mockAddr{network: "udp", addr: clientIP + ":1234"})
	if err != nil || resp == nil {
		t.Fatalf("Handle: err=%v resp=%v", err, resp)
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode == 0x07 {
		t.Error("valid cookie must not trigger BADCOOKIE")
	}
}

// TestHandle_RFC9520_CachesResolutionFailure pins the R6 fix: a SERVFAIL
// returned by the resolver causes the handler to write a short-lived
// failure entry to the cache (RFC 9520 §3) so an aggressive client cannot
// amplify upstream load by retrying the same broken name.
func TestHandle_RFC9520_CachesResolutionFailure(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	// newFailFastResolver points at an unreachable upstream so resolution
	// returns SERVFAIL quickly, exercising the failure-caching branch.
	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	q := buildTestQuery("broken.example.com", dns.TypeA)
	resp, err := handler.Handle(q, &mockAddr{network: "udp", addr: "1.2.3.4:54321"})
	if err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	msg, _ := dns.Unpack(resp)
	if msg.Header.RCODE() != dns.RCodeServFail {
		t.Fatalf("first response RCODE: want SERVFAIL, got %d", msg.Header.RCODE())
	}

	// Verify the cache now has a failure entry capped at MaxFailureTTL.
	entry, ok := c.Get("broken.example.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("RFC 9520 §3: SERVFAIL was not cached")
	}
	if entry.OrigTTL > cache.MaxFailureTTL {
		t.Errorf("RFC 9520 §4: failure TTL exceeded cap %d, got %d",
			cache.MaxFailureTTL, entry.OrigTTL)
	}
	if entry.NegType != cache.NegServFail {
		t.Errorf("cached entry has wrong NegType: %d", entry.NegType)
	}
}
