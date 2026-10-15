package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestClassify_FORMERRTreatedAsServFail pins the R1 fix: a FORMERR rcode
// is treated as a generic server failure by classifyResponse, so the
// resolver moves to a sibling NS instead of silently retrying with EDNS
// disabled. Without the fix, an attacker who wins the TXID/0x20 race for
// a single forged packet could strip DNSSEC OK / ECS / 1232-buffer off
// the immediate retry — a one-packet DNSSEC-validation downgrade.
func TestClassify_FORMERRTreatedAsServFail(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeFormErr).Build(),
		},
	}
	if got := classifyResponse(msg, "example.com", dns.TypeA); got != responseServFail {
		t.Errorf("FORMERR must classify as responseServFail (no auto-EDNS-downgrade), got %d", got)
	}
}

// TestClassify_NonAuthoritativeAnswer pins the Unbound-compatible AA rule:
// an iterative answer with AA=0 is accepted unless RA=1, which marks a
// recursive resolver echoing its cache (Unbound's REC_LAME). Live, the
// Huawei OBS and probe.performance.dropbox.com authoritatives answer with
// only QR set and were SERVFAIL here while public resolvers answered.
func TestClassify_NonAuthoritativeAnswer(t *testing.T) {
	answer := func(flags uint16) *dns.Message {
		return &dns.Message{
			Header: dns.Header{Flags: flags, ANCount: 1},
			Answers: []dns.ResourceRecord{{
				Name: "test.example.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
			}},
		}
	}
	if got := classifyResponse(answer(dns.NewFlagBuilder().SetQR(true).Build()), "test.example.com", dns.TypeA); got != responseAnswer {
		t.Errorf("AA=0 RA=0 answer: got %d, want responseAnswer", got)
	}
	if got := classifyResponse(answer(dns.NewFlagBuilder().SetQR(true).SetRA(true).Build()), "test.example.com", dns.TypeA); got != responseServFail {
		t.Errorf("AA=0 RA=1 answer (recursive-lame): got %d, want responseServFail", got)
	}
}

// TestClassify_AuthoritativeAnswerAccepted is the positive counterpart to
// the R2 fix — when AA=1 the same response classifies as responseAnswer.
func TestClassify_AuthoritativeAnswerAccepted(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags:   dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(),
			ANCount: 1,
		},
		Answers: []dns.ResourceRecord{{
			Name: "test.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}},
	}
	if got := classifyResponse(msg, "test.example.com", dns.TypeA); got != responseAnswer {
		t.Errorf("authoritative answer must classify as responseAnswer, got %d", got)
	}
}

// TestClassify_NonAuthoritativeCNAME mirrors the AA rule for the CNAME
// chase path: followed without AA (live: Huawei OBS), lame with RA=1.
func TestClassify_NonAuthoritativeCNAME(t *testing.T) {
	cname := func(flags uint16) *dns.Message {
		return &dns.Message{
			Header: dns.Header{Flags: flags, ANCount: 1},
			Answers: []dns.ResourceRecord{{
				Name: "alias.example.com", Type: dns.TypeCNAME, Class: dns.ClassIN,
				TTL: 300, RDLength: 0, RData: nil,
			}},
		}
	}
	if got := classifyResponse(cname(dns.NewFlagBuilder().SetQR(true).Build()), "alias.example.com", dns.TypeA); got != responseCNAME {
		t.Errorf("AA=0 RA=0 CNAME: got %d, want responseCNAME", got)
	}
	if got := classifyResponse(cname(dns.NewFlagBuilder().SetQR(true).SetRA(true).Build()), "alias.example.com", dns.TypeA); got != responseServFail {
		t.Errorf("AA=0 RA=1 CNAME (recursive-lame): got %d, want responseServFail", got)
	}
}

// TestClassify_OutOfBailiwickSOANotNODATA pins the R5 fix (RFC 2308 §3):
// an SOA whose owner is not an ancestor of the queried name has no
// authority over the name and must not contribute to negative-response
// classification. Before the fix, a hostile authoritative could attach
// an unrelated SOA (with attacker-controlled minimum TTL) to forge a
// NODATA result whose negative cache lifetime is dictated by the
// attacker.
func TestClassify_OutOfBailiwickSOANotNODATA(t *testing.T) {
	// qname = victim.org, authority section carries SOA for attacker.example
	// — a zone that is in no way an ancestor of victim.org.
	msg := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).Build(),
		},
		Authority: []dns.ResourceRecord{{
			Name: "attacker.example", Type: dns.TypeSOA, Class: dns.ClassIN,
			TTL: 3600, RDLength: 0, RData: nil,
		}},
	}
	got := classifyResponse(msg, "victim.org", dns.TypeA)
	if got == responseNoData {
		t.Errorf("out-of-bailiwick SOA must not produce NODATA classification "+
			"(RFC 2308 §3); got %d", got)
	}
}

// TestClassify_InBailiwickSOAIsNODATA is the positive counterpart: an SOA
// whose owner IS an ancestor of the qname properly proves NODATA.
func TestClassify_InBailiwickSOAIsNODATA(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).Build(),
		},
		Authority: []dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
			TTL: 3600, RDLength: 0, RData: nil,
		}},
	}
	if got := classifyResponse(msg, "missing.example.com", dns.TypeA); got != responseNoData {
		t.Errorf("ancestor SOA must produce NODATA, got %d", got)
	}
}

// TestSOACoversName_RootCoversAll covers the edge case where the SOA owner
// is the root zone (".") — the root SOA implicitly covers every name.
func TestSOACoversName_RootCoversAll(t *testing.T) {
	if !soaCoversName(".", "example.com") {
		t.Error("root SOA must cover any name")
	}
	if !soaCoversName("", "example.com") {
		t.Error("empty SOA owner (root) must cover any name")
	}
}
