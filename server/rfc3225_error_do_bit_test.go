package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestBuildErrorWithEDE_EchoesDO pins RFC 3225 §3: the DO bit of the query
// MUST be copied in the response. buildError carries no OPT, so the OPT that
// addEDEToResponse created had DO clear and every Bogus SERVFAIL went out
// with `flags:` to a validating stub.
func TestBuildErrorWithEDE_EchoesDO(t *testing.T) {
	h := testHandler()
	for _, do := range []bool{true, false} {
		q := &dns.Message{
			Header:     dns.Header{ID: 0x1234, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
			Questions:  []dns.Question{{Name: "bogus.example", Type: dns.TypeA, Class: dns.ClassIN}},
			Additional: []dns.ResourceRecord{dns.BuildOPT(1232, do)},
		}
		packed, err := dns.Pack(q, make([]byte, 512))
		if err != nil {
			t.Fatalf("Pack: %v", err)
		}
		query := append([]byte(nil), packed...)

		resp, err := h.buildErrorWithEDE(query, dns.RCodeServFail, dns.EDECodeDNSSECBogus, "bogus")
		if err != nil {
			t.Fatalf("DO=%v: buildErrorWithEDE: %v", do, err)
		}
		msg, err := dns.Unpack(resp)
		if err != nil {
			t.Fatalf("DO=%v: Unpack: %v", do, err)
		}
		if msg.EDNS0 == nil {
			t.Fatalf("DO=%v: response has no OPT", do)
		}
		if msg.EDNS0.DOFlag != do {
			t.Errorf("DO=%v: response DO=%v", do, msg.EDNS0.DOFlag)
		}
	}
}
