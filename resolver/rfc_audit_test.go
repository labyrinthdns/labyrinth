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

// TestClassify_NonAuthoritativeAnswerRejected pins the R2 fix
// (RFC 1034 §3.7 / RFC 2181 §6.1): an iterative response carrying an
// answer but with AA=0 is not trusted as authoritative and must not be
// promoted to responseAnswer. The fix classifies such a response as
// responseServFail so the resolver loop tries a sibling NS rather than
// caching a lame/forged answer.
func TestClassify_NonAuthoritativeAnswerRejected(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			// QR=1, AA=0 (deliberately omitted) — a lame answer.
			Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
			ANCount: 1,
		},
		Answers: []dns.ResourceRecord{{
			Name: "test.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}},
	}
	if got := classifyResponse(msg, "test.example.com", dns.TypeA); got != responseServFail {
		t.Errorf("answer without AA=1 must classify as responseServFail, got %d", got)
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

// TestClassify_NonAuthoritativeCNAMERejected mirrors the AA check for the
// CNAME chase path — a CNAME answer without AA=1 is equally untrusted and
// must not be followed.
func TestClassify_NonAuthoritativeCNAMERejected(t *testing.T) {
	msg := &dns.Message{
		Header: dns.Header{
			Flags:   dns.NewFlagBuilder().SetQR(true).Build(),
			ANCount: 1,
		},
		Answers: []dns.ResourceRecord{{
			Name: "alias.example.com", Type: dns.TypeCNAME, Class: dns.ClassIN,
			TTL: 300, RDLength: 0, RData: nil,
		}},
	}
	if got := classifyResponse(msg, "alias.example.com", dns.TypeA); got != responseServFail {
		t.Errorf("CNAME without AA=1 must classify as responseServFail, got %d", got)
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
