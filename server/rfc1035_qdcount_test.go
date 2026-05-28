package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestQDCount_NotOne_ReturnsFORMERR pins RFC 1035 §4.1.2: although the
// DNS header structure allows multiple questions in a single message
// (QDCOUNT is a uint16), the standard has only ever defined the
// behaviour for QDCOUNT==1. Every operational resolver treats other
// counts as malformed. A multi-question query is the classic AXFR
// look-alike that some authoritatives crash on (CVE-2002-2213 era), and
// QDCOUNT==0 is occasionally seen in stateful TCP probes — neither
// should ever reach the recursion pipeline.
//
// The handler enforces this at handler.go:591. Two cases: QDCOUNT=0
// (empty question section) and QDCOUNT=2 (two stuffed questions). Both
// MUST return FORMERR (RCODE=1) with the header otherwise sane.
func TestQDCount_NotOne_ReturnsFORMERR(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	t.Run("QDCOUNT=0 empty question section", func(t *testing.T) {
		// 12-byte header, QDCOUNT=0, no body.
		q := make([]byte, 12)
		binary.BigEndian.PutUint16(q[0:2], 0x1234) // ID
		binary.BigEndian.PutUint16(q[2:4], 0x0100) // RD=1
		// QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT already zero.

		resp, err := h.Handle(q, nil)
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		assertFORMERR(t, resp)
	})

	t.Run("QDCOUNT=2 two questions packed", func(t *testing.T) {
		// Build a real two-question query through Pack (Pack
		// derives QDCount from len(Questions), so this lands on
		// the wire with QDCOUNT=2).
		msg := &dns.Message{
			Header: dns.Header{
				ID:    0x5678,
				Flags: dns.NewFlagBuilder().SetRD(true).Build(),
			},
			Questions: []dns.Question{
				{Name: "y63-a.example.com", Type: dns.TypeA, Class: dns.ClassIN},
				{Name: "y63-b.example.com", Type: dns.TypeA, Class: dns.ClassIN},
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
		assertFORMERR(t, resp)
	})
}

func assertFORMERR(t *testing.T, resp []byte) {
	t.Helper()
	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if parsed.Header.RCODE() != dns.RCodeFormErr {
		t.Errorf("RCODE = %d, want FORMERR (1) — RFC 1035 §4.1.2 requires single-question per message", parsed.Header.RCODE())
	}
	if !parsed.Header.QR() {
		t.Errorf("QR bit clear on error response — RFC 1035 §4.1.1 requires QR=1 on responses")
	}
}
