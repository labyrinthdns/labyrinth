package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/security"
)

// TestACLDenyRefused_EDEOnlyForEDNSClient pins Y52: RFC 8914 §3 makes
// Extended DNS Errors meaningful ONLY for clients that speak EDNS — the
// OPT pseudo-record is where the EDE option lives, and a non-EDNS
// client has no OPT in its query to indicate it can parse one in the
// response. Sending an OPT-bearing response to a non-EDNS client both:
//  1. wastes bytes (legacy clients ignore it but pay the parsing cost), and
//  2. may trip strict RFC 1035-only implementations that count
//     "additional with unknown type" as malformed.
//
// `queryHasEDNS` gates emission on the global ACL deny / rate-limit /
// per-zone ACL refuse paths. A refactor that dropped the gate would
// start spraying EDE OPTs at every legacy stub forwarding through us.
// We pin both shapes by sending the same ACL-denied query twice, once
// without OPT and once with OPT, and asserting the response ARCount.
func TestACLDenyRefused_EDEOnlyForEDNSClient(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	// ACL allows 10.0.0.0/8 only; the test client comes from 192.168.x.x.
	acl, err := security.NewACL([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewMainHandler(res, c, nil, nil, acl, m, discardLogger())

	denied := &mockAddr{network: "udp", addr: "192.168.1.1:12345"}

	t.Run("no EDNS => no OPT/EDE in REFUSED", func(t *testing.T) {
		q := buildTestQuery("aclblock.test", dns.TypeA)
		resp, err := h.Handle(q, denied)
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		assertRefused(t, resp)
		if arCount := binary.BigEndian.Uint16(resp[10:12]); arCount != 0 {
			t.Errorf("ARCount = %d, want 0 (RFC 8914 §3 — no OPT allowed for non-EDNS client)", arCount)
		}
	})

	t.Run("EDNS=>OPT+EDE in REFUSED", func(t *testing.T) {
		q := buildTestQueryWithEDNS("aclblock.test", dns.TypeA, 1232)
		resp, err := h.Handle(q, denied)
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		assertRefused(t, resp)
		if arCount := binary.BigEndian.Uint16(resp[10:12]); arCount == 0 {
			t.Errorf("ARCount = 0, want >0 (RFC 8914 §3 — EDNS client should receive EDE)")
		}
		parsed, err := dns.Unpack(resp)
		if err != nil {
			t.Fatalf("unpack: %v", err)
		}
		var opt *dns.ResourceRecord
		for i := range parsed.Additional {
			if parsed.Additional[i].Type == dns.TypeOPT {
				opt = &parsed.Additional[i]
				break
			}
		}
		if opt == nil {
			t.Fatalf("OPT pseudo-record missing from EDNS-client REFUSED response")
		}
		edns, err := dns.ParseOPT(opt)
		if err != nil {
			t.Fatalf("ParseOPT: %v", err)
		}
		// EDE 18 "Prohibited" is the §4.18 code for ACL refusal.
		var sawEDE bool
		for _, o := range edns.Options {
			if o.Code != dns.EDNSOptionCodeEDE {
				continue
			}
			code, _, err := dns.ParseEDEOption(o.Data)
			if err != nil {
				t.Errorf("ParseEDEOption: %v", err)
				continue
			}
			if code == dns.EDECodeProhibited {
				sawEDE = true
			}
		}
		if !sawEDE {
			t.Errorf("EDE %d (Prohibited) not present on ACL-denied EDNS response", dns.EDECodeProhibited)
		}
	})
}

func assertRefused(t *testing.T, resp []byte) {
	t.Helper()
	if len(resp) < 4 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeRefused {
		t.Errorf("RCODE = %d, want REFUSED(5)", rcode)
	}
}
