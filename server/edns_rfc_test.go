package server

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestHandle_BadVers pins RFC 6891 §6.1.3: a query whose EDNS version is
// greater than what the responder supports MUST get RCODE=BADVERS (16),
// not FORMERR/NOTIMP/NOERROR. BADVERS is composed as:
//
//	header RCODE  = low 4 bits  = 0
//	OPT ExtRCODE  = high 8 bits = 1
//	→ effective RCODE = (1 << 4) | 0 = 16
//
// The OPT in the reply MUST carry our highest supported version (0) so
// the client can downgrade.
func TestHandle_BadVers(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	// Build a query with EDNS version = 1 (we only support 0).
	q := &dns.Message{
		Header:    dns.Header{ID: 0xBEEF, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
		Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
	}
	opt := dns.BuildOPT(1232, false)
	// Version = 1 → set bits 16-23 of TTL.
	opt.TTL = uint32(1) << 16
	q.Additional = []dns.ResourceRecord{opt}
	packed, _ := dns.Pack(q, make([]byte, 1232))

	resp, err := handler.Handle(packed, &mockAddr{network: "udp", addr: "1.2.3.4:54321"})
	if err != nil || resp == nil {
		t.Fatalf("Handle: err=%v resp=%v", err, resp)
	}

	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	// Header RCODE must be 0 (low 4 bits of 16).
	if rc := msg.Header.RCODE(); rc != 0 {
		t.Errorf("header RCODE: want 0 (low nibble of BADVERS), got %d", rc)
	}

	// Find OPT in Additional and check ExtRCODE byte.
	var optRR *dns.ResourceRecord
	for i := range msg.Additional {
		if msg.Additional[i].Type == dns.TypeOPT {
			optRR = &msg.Additional[i]
			break
		}
	}
	if optRR == nil {
		t.Fatal("response carried no OPT record (RFC 6891 §6.1.3 violation — BADVERS requires OPT to convey ExtRCODE)")
	}
	extRCODE := uint8(optRR.TTL >> 24)
	if extRCODE != 1 {
		t.Errorf("OPT ExtRCODE: want 1 (BADVERS high byte), got %d", extRCODE)
	}
	version := uint8(optRR.TTL >> 16)
	if version != 0 {
		t.Errorf("OPT Version in reply: want 0 (our highest), got %d", version)
	}
}

// TestHandle_MultipleOPTs pins RFC 6891 §6.1.1: "If a query message with
// more than one OPT RR is received, a FORMERR (RCODE=1) MUST be returned."
func TestHandle_MultipleOPTs(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	q := &dns.Message{
		Header:    dns.Header{ID: 0xBEEF, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
		Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPT(1232, false),
			dns.BuildOPT(1232, true), // second OPT — illegal
		},
	}
	packed, _ := dns.Pack(q, make([]byte, 1232))

	resp, err := handler.Handle(packed, &mockAddr{network: "udp", addr: "1.2.3.4:54321"})
	if err != nil || resp == nil {
		t.Fatalf("Handle: err=%v resp=%v", err, resp)
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeFormErr {
		t.Errorf("expected FORMERR(1), got rcode=%d", rcode)
	}
}

// TestCookie_FutureTimestampRejected pins RFC 9018 §4.3: server cookies
// with timestamps in the future (beyond a small NTP skew tolerance) MUST
// be rejected. Otherwise an attacker probing the validation window has
// the same 1-hour tolerance in both directions, doubling the attack
// surface for cookie forgery against a low-entropy hash space.
func TestCookie_FutureTimestampRejected(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())
	handler.EnableCookiesWithSecret(make([]byte, 16))

	clientCookie := []byte("ABCDEFGH")
	clientIP := "192.0.2.1"

	// Freeze "now" so timestamp math is predictable.
	const baseNow uint32 = 1_700_000_000
	prev := nowFunc
	defer func() { nowFunc = prev }()
	nowFunc = func() uint32 { return baseNow }

	// 1. Cookie issued AT the current time → must validate.
	cookie := handler.generateServerCookieAt(clientCookie, clientIP, baseNow)
	if !handler.validateServerCookie(clientCookie, cookie, clientIP) {
		t.Error("freshly-issued cookie should validate")
	}

	// 2. Cookie issued 30 minutes ago → still valid (within 1h window).
	cookie = handler.generateServerCookieAt(clientCookie, clientIP, baseNow-1800)
	if !handler.validateServerCookie(clientCookie, cookie, clientIP) {
		t.Error("30-min-old cookie should validate (1h validity window)")
	}

	// 3. Cookie issued 2 hours ago → expired (>1h).
	cookie = handler.generateServerCookieAt(clientCookie, clientIP, baseNow-7200)
	if handler.validateServerCookie(clientCookie, cookie, clientIP) {
		t.Error("2-hour-old cookie should be rejected (expired)")
	}

	// 4. Cookie within the 5-minute future-skew tolerance → accept.
	cookie = handler.generateServerCookieAt(clientCookie, clientIP, baseNow+60)
	if !handler.validateServerCookie(clientCookie, cookie, clientIP) {
		t.Error("cookie 60s in future should validate (NTP skew tolerance)")
	}

	// 5. Cookie far in the future → reject (RFC 9018 §4.3).
	cookie = handler.generateServerCookieAt(clientCookie, clientIP, baseNow+3600)
	if handler.validateServerCookie(clientCookie, cookie, clientIP) {
		t.Error("cookie 1h in future MUST be rejected per RFC 9018 §4.3")
	}
}

// silence unused-import sweeper
var _ = time.Now
var _ net.IP
