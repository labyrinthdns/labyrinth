package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestClassify_MultipleCNAMEsRejected pins the Y15 fix to RFC 2181 §10.1:
// "There may be only one such [CNAME] record per domain name." A response
// carrying multiple distinct CNAMEs at a single owner is structurally
// illegal — either the authoritative is misconfigured or someone is
// injecting a forged second CNAME to redirect the chain (extractCNAMETarget
// would otherwise take whichever appeared first). The resolver must refuse
// the response and try a sibling NS.
func TestClassify_MultipleCNAMEsRejected(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			ANCount: 2,
			Flags:   dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(),
		},
		Answers: []dns.ResourceRecord{
			// Real CNAME pointing to the legit target.
			{Name: "alias.example.com", Type: dns.TypeCNAME, Class: dns.ClassIN, TTL: 300, RData: []byte("real-target")},
			// Forged second CNAME at the SAME owner pointing somewhere else.
			{Name: "alias.example.com", Type: dns.TypeCNAME, Class: dns.ClassIN, TTL: 300, RData: []byte("evil-target")},
		},
	}
	got := classifyResponse(msg, "alias.example.com", dns.TypeA)
	if got != responseServFail {
		t.Errorf("multi-CNAME at one owner must classify as ServFail (RFC 2181 §10.1); got %d", got)
	}
}

// TestClassify_SingleCNAMEStillAccepted is the positive control: the
// normal one-CNAME shape must still flow through as responseCNAME so
// the chase logic continues.
func TestClassify_SingleCNAMEStillAccepted(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			ANCount: 1,
			Flags:   dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(),
		},
		Answers: []dns.ResourceRecord{
			{Name: "alias.example.com", Type: dns.TypeCNAME, Class: dns.ClassIN, TTL: 300, RData: []byte("target")},
		},
	}
	got := classifyResponse(msg, "alias.example.com", dns.TypeA)
	if got != responseCNAME {
		t.Errorf("single CNAME should classify as CNAME; got %d", got)
	}
}

// TestClassify_CNAMEsAtDifferentOwnersAccepted: multiple CNAME RRs at
// DIFFERENT owners (a CNAME chain in one response) is allowed — RFC 2181
// §10.1's constraint is per-owner. Make sure the new count is per owner,
// not message-global.
func TestClassify_CNAMEsAtDifferentOwnersAccepted(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			ANCount: 2,
			Flags:   dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(),
		},
		Answers: []dns.ResourceRecord{
			// CNAME at qname.
			{Name: "alias.example.com", Type: dns.TypeCNAME, Class: dns.ClassIN, TTL: 300, RData: []byte("hop1")},
			// CNAME at a DIFFERENT name (intermediate hop served in same answer).
			{Name: "hop1.example.com", Type: dns.TypeCNAME, Class: dns.ClassIN, TTL: 300, RData: []byte("hop2")},
		},
	}
	got := classifyResponse(msg, "alias.example.com", dns.TypeA)
	if got != responseCNAME {
		t.Errorf("two CNAMEs at distinct owners must still classify as CNAME; got %d", got)
	}
}
