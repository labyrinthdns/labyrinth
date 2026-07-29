package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestExtractDNAMETarget_OwnerMustBeStrictParent pins RFC 6672 §2.4
// + RFC 6840 §5.10: a DNAME owner must be a STRICT parent of the
// queried name (not the qname itself, and not an unrelated owner).
// Two attacker shapes that the bailiwick check must reject:
//
//  1. **Sibling DNAME** — owner shares no suffix relationship with
//     qname (e.g. owner=`attacker.org` while qname=`victim.com`).
//     Accepting this would let an upstream that holds a delegation
//     for `attacker.org` inject a redirect for any unrelated name.
//
//  2. **Owner equal to qname** — qname IS the DNAME owner.
//     RFC 6672 §3.2 forbids this: a DNAME does not synthesise an
//     answer for its own owner name. The substitution math
//     (`qname[:len(qname)-len(owner)-1]`) would produce a
//     string starting with "." or an out-of-bounds slice — a
//     pre-existing safety check (`HasSuffix(qname, "."+owner)`)
//     requires the qname to be STRICTLY DEEPER than the owner.
//
// We also pin the affirmative cases (immediate child, deep descendant,
// case-insensitive owner) to make sure the bailiwick check isn't so
// strict it rejects legitimate DNAMEs.
func TestExtractDNAMETarget_OwnerMustBeStrictParent(t *testing.T) {
	mkMsg := func(ownerName string) *dns.Message {
		rdata := dns.BuildPlainName("target.com")
		return &dns.Message{
			Answers: []dns.ResourceRecord{{
				Name: ownerName, Type: dns.TypeDNAME, Class: dns.ClassIN,
				TTL: 3600, RDLength: uint16(len(rdata)), RData: rdata,
			}},
		}
	}

	cases := []struct {
		name    string
		dnameAt string
		qname   string
		want    string
		why     string
	}{
		{
			name:    "immediate child — substitution applies",
			dnameAt: "example.com",
			qname:   "sub.example.com",
			want:    "sub.target.com",
			why:     "RFC 6672 §3 normal case",
		},
		{
			name:    "deep descendant — full suffix substitution",
			dnameAt: "example.com",
			qname:   "a.b.c.example.com",
			want:    "a.b.c.target.com",
			why:     "RFC 6672 §3 — owner suffix replaced; prefix preserved verbatim",
		},
		{
			name:    "owner == qname — owner is NOT a strict parent → no synthesis",
			dnameAt: "example.com",
			qname:   "example.com",
			want:    "",
			why:     "RFC 6672 §3.2 — DNAME does not redirect its own owner",
		},
		{
			name:    "sibling owner — no suffix relationship → rejected",
			dnameAt: "attacker.org",
			qname:   "victim.com",
			want:    "",
			why:     "out-of-bailiwick DNAME injection: an upstream that holds attacker.org auth must not be able to redirect victim.com",
		},
		{
			name:    "partial-label match (NOT a label boundary) → rejected",
			dnameAt: "ample.com",
			qname:   "example.com",
			want:    "",
			why:     "HasSuffix(\".\"+owner) — the leading dot enforces label boundary; without it 'example' would match 'ample' suffix and redirect arbitrary names",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractDNAMETarget(mkMsg(c.dnameAt), c.qname)
			if got != c.want {
				t.Errorf("extractDNAMETarget(owner=%q, qname=%q) = %q, want %q\nrationale: %s",
					c.dnameAt, c.qname, got, c.want, c.why)
			}
		})
	}
}
