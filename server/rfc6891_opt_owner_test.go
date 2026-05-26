package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestHandle_NonRootOPTOwnerIsFormErr pins the Y14 fix to RFC 6891 §6.1.2:
// "The fixed part of an OPT RR is structured as follows: NAME — domain
// name — MUST be 0 (root domain)." A non-root owner is a structural
// malformation; accepting it would let a buggy or hostile client smuggle
// arbitrary names through the pseudo-RR (potentially confusing log
// pipelines, ACL paths keyed on name, or downstream EDNS option parsers
// that assume owner == root).
func TestHandle_NonRootOPTOwnerIsFormErr(t *testing.T) {
	h := testHandler()

	// Build a query whose OPT record has owner "evil.example.com." —
	// every other field is valid so the FORMERR must be triggered
	// specifically by the non-root owner check.
	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x1234,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{
			Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN,
		}},
		Additional: []dns.ResourceRecord{{
			Name:     "evil.example.com.", // RFC 6891 violation
			Type:     dns.TypeOPT,
			Class:    1232, // UDP payload size
			TTL:      0,
			RDLength: 0,
			RData:    nil,
		}},
	}
	buf := make([]byte, 512)
	packed, err := dns.Pack(msg, buf)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	query := make([]byte, len(packed))
	copy(query, packed)

	resp, err := h.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp == nil {
		t.Fatal("expected FORMERR response, got nil")
	}
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	if rcode != dns.RCodeFormErr {
		t.Errorf("rcode: want FORMERR(%d), got %d", dns.RCodeFormErr, rcode)
	}
}

