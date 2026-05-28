package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// buildPlainQuery constructs a wire-format DNS query for example.com A,
// optionally carrying an EDNS OPT pseudo-RR with a client COOKIE
// option. Returns the raw bytes ready to feed to handler.Handle.
func buildPlainQuery(t *testing.T, withClientCookie bool) []byte {
	t.Helper()
	q := &dns.Message{
		Header:    dns.Header{ID: 0x4321, Flags: 0x0100, QDCount: 1, ARCount: 1},
		Questions: []dns.Question{{Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN}},
	}
	if withClientCookie {
		q.Additional = []dns.ResourceRecord{dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{
			{Code: dns.EDNSOptionCodeCookie, Data: []byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8}},
		})}
	} else {
		// Plain EDNS OPT, no COOKIE option.
		q.Additional = []dns.ResourceRecord{dns.BuildOPT(1232, false)}
	}
	raw, err := dns.Pack(q, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return raw
}

// rcodeOf returns the DNS header RCODE from a wire-format response.
// Helper for asserting the response class without re-decoding the full
// message. The low 4 bits of byte 3 of the header are the base RCODE;
// for BADCOOKIE the full RCODE is split between the header low nibble
// (7) and the OPT extended-RCODE byte (1), but for the gate-firing
// check we only need the low nibble.
func rcodeOf(t *testing.T, raw []byte) uint8 {
	t.Helper()
	if len(raw) < 4 {
		t.Fatalf("response too short to read RCODE: %d bytes", len(raw))
	}
	return raw[3] & 0x0F
}

// TestCookiesEnforce_UDPOnly_TruthTable pins the RFC 7873 §5.4 strict
// mode gate. The four-corner truth table:
//
//   enforce=false, any transport, no cookie  → answered (default behaviour)
//   enforce=true,  UDP,            no cookie → BADCOOKIE (the whole point)
//   enforce=true,  UDP,            cookie    → answered (client proved itself)
//   enforce=true,  TCP,            no cookie → answered (TCP already passes
//                                              source-validation; forcing
//                                              another round-trip is overhead)
//
// The 3rd and 4th rows are the critical "no false positives" cells. A
// regression that gated on transport=UDP only without checking the
// presence of a cookie would lock out legitimate UDP clients forever;
// a regression that gated regardless of transport would punish every
// TCP/DoT/DoH client with a useless BADCOOKIE bounce.
func TestCookiesEnforce_UDPOnly_TruthTable(t *testing.T) {
	cases := []struct {
		name        string
		enforce     bool
		transport   string
		withCookie  bool
		wantRCode   uint8 // RCode low nibble; BADCOOKIE = 7 (extended)
		wantOK      bool  // true if response should NOT be BADCOOKIE
		why         string
	}{
		{
			name:       "enforce off, UDP, no cookie — answered (default)",
			enforce:    false,
			transport:  "udp",
			withCookie: false,
			wantOK:     true,
			why:        "default config must not break clients that don't speak cookies",
		},
		{
			name:       "enforce on, UDP, no cookie — BADCOOKIE",
			enforce:    true,
			transport:  "udp",
			withCookie: false,
			wantRCode:  dns.RCodeBadCookie & 0x0F,
			wantOK:     false,
			why:        "the entire point of §5.4 strict mode — spoofed source cannot get answers",
		},
		{
			name:       "enforce on, UDP, with cookie — answered",
			enforce:    true,
			transport:  "udp",
			withCookie: true,
			wantOK:     true,
			why:        "client proved itself with a cookie; gate must let it through",
		},
		{
			name:       "enforce on, TCP, no cookie — answered",
			enforce:    true,
			transport:  "tcp",
			withCookie: false,
			wantOK:     true,
			why:        "TCP handshake already provides source validation; gate must be UDP-only",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handlerMetrics := metrics.NewMetrics()
			ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, metrics.NewMetrics())
			res := newPanickingResolver(ca)
			h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())
			h.EnableCookiesWithSecret(make([]byte, 16))
			h.SetCookiesEnforce(c.enforce)

			query := buildPlainQuery(t, c.withCookie)
			addr := &mockAddr{network: c.transport, addr: "192.0.2.10:1234"}

			resp, err := h.Handle(query, addr)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			gotRcode := rcodeOf(t, resp)
			isBadCookie := gotRcode == (dns.RCodeBadCookie & 0x0F)

			if c.wantOK {
				// We don't care about the exact RCODE for the "answered"
				// row — the cookie gate is downstream of resolution and
				// the panickingResolver will surface its own errors. The
				// invariant we lock is "NOT BADCOOKIE".
				if isBadCookie {
					t.Errorf("got BADCOOKIE but expected gate to pass; %s", c.why)
				}
			} else {
				if !isBadCookie {
					t.Errorf("got rcode %d, want BADCOOKIE (7); %s", gotRcode, c.why)
				}
			}
		})
	}
}

// TestIsUDPAddr_NetworkStringPrefixes pins the gating helper so a
// regression that swapped the prefix to "TCP" (or that switched to
// type assertion on *net.UDPAddr — fragile under DoH plumbing that
// wraps addrs through HTTP) is caught.
func TestIsUDPAddr_NetworkStringPrefixes(t *testing.T) {
	cases := []struct {
		network string
		want    bool
	}{
		{"udp", true},
		{"udp4", true},
		{"udp6", true},
		{"tcp", false},
		{"tcp4", false},
		{"tcp6", false},
		{"unix", false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.network, func(t *testing.T) {
			got := isUDPAddr(&mockAddr{network: c.network, addr: "127.0.0.1:1"})
			if got != c.want {
				t.Errorf("isUDPAddr(network=%q) = %v, want %v", c.network, got, c.want)
			}
		})
	}
	// Nil sentinel must NOT panic and MUST report false.
	if isUDPAddr(nil) {
		t.Errorf("isUDPAddr(nil) returned true — would fire enforce gate on impossible addresses")
	}
}
