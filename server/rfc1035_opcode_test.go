package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestOpcodeNotQuery_ReturnsNOTIMP pins RFC 1035 §4.1.1 / RFC 6895 §2.2:
// a recursive resolver implements only OPCODE QUERY (0). Other opcodes
// have completely different message semantics — UPDATE (5, RFC 2136)
// expects pre-requisite + update sections, NOTIFY (4, RFC 1996) expects
// a zone-change announcement, IQUERY (1, obsoleted by RFC 3425) and
// STATUS (2) are not implemented anywhere meaningful. A regression
// that let any non-QUERY opcode through the recursion pipeline would
// treat update RRs as answers, corrupting the cache (CVE class:
// "DNS UPDATE injection via misclassified opcode").
//
// The handler MUST return NOTIMP (4) for every non-QUERY opcode, with
// QR=1 so clients can pair the response with their request.
func TestOpcodeNotQuery_ReturnsNOTIMP(t *testing.T) {
	cases := []struct {
		name   string
		opcode uint8
	}{
		{"IQUERY (1)", dns.OpcodeIQuery},
		{"STATUS (2)", dns.OpcodeStatus},
		{"NOTIFY (4)", 4},
		{"UPDATE (5)", 5},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handlerMetrics := metrics.NewMetrics()
			cacheMetrics := metrics.NewMetrics()
			ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
			res := newPanickingResolver(ca)
			h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

			msg := &dns.Message{
				Header: dns.Header{
					ID:    0xBEEF,
					Flags: dns.NewFlagBuilder().SetOpcode(c.opcode).SetRD(true).Build(),
				},
				Questions: []dns.Question{{Name: "y65.example.com", Type: dns.TypeA, Class: dns.ClassIN}},
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
			if parsed.Header.RCODE() != dns.RCodeNotImp {
				t.Errorf("RCODE = %d, want NOTIMP (4) for opcode %d — RFC 1035 §4.1.1", parsed.Header.RCODE(), c.opcode)
			}
			if !parsed.Header.QR() {
				t.Errorf("QR bit clear on error response — must be 1 per RFC 1035 §4.1.1")
			}
		})
	}
}
