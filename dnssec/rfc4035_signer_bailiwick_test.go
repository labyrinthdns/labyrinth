package dnssec

import (
	"testing"
)

// TestIsInBailiwick_RRSIGSignerNameTruthTable pins RFC 4035 §5.3.1
// signer-name bailiwick: an RRSIG's SignerName field MUST be an
// ancestor (or equal) to the qname being verified. The signer is the
// zone whose DNSKEY-set was used to sign the RRset; for the signature
// to be authoritative, that zone must actually contain the qname in
// its delegation hierarchy.
//
// Without the bailiwick check, an attacker who controls ANY signed
// zone could inject an RRSIG into a victim-zone response and the
// validator would dutifully fetch the attacker's zone DNSKEYs (via
// fetchDNSKEYs(signerZone)) and verify against the attacker-key. The
// attacker's signature would verify cryptographically; the only
// thing standing between forgery and acceptance is "did the attacker's
// zone have authority over the queried name?" — which is the
// bailiwick check.
//
// Truth table:
//
//   - signer="." (root)              → always in-bailiwick (root signs everything)
//   - signer == qname                → in-bailiwick (zone signs its own apex)
//   - signer ancestor of qname       → in-bailiwick (signer.com signs www.signer.com)
//   - signer == sibling of qname     → NOT in-bailiwick (attacker.com cannot sign victim.com)
//   - signer descendant of qname     → NOT in-bailiwick (sub.victim.com cannot sign victim.com)
//   - signer with partial-label match → NOT in-bailiwick (mple.com cannot sign example.com)
//
// The "partial-label" case is the security-critical regression target:
// the bailiwick check uses `strings.HasSuffix(qname, "." + signer)` —
// the LEADING DOT enforces label boundary. A regression that dropped
// it would let `mple.com` redirect every `*ample.com` query.
func TestIsInBailiwick_RRSIGSignerNameTruthTable(t *testing.T) {
	cases := []struct {
		name   string
		qname  string
		signer string
		want   bool
	}{
		{"root signer always in-bailiwick", "victim.com", ".", true},
		{"signer == qname", "victim.com", "victim.com", true},
		{"signer is strict ancestor", "www.victim.com", "victim.com", true},
		{"signer is deep ancestor", "a.b.c.victim.com", "victim.com", true},
		{"signer is TLD of qname", "victim.com", "com", true},
		{"sibling signer rejected", "victim.com", "attacker.com", false},
		{"descendant cannot sign ancestor", "victim.com", "sub.victim.com", false},
		{"partial-label signer rejected (label-boundary)", "example.com", "mple.com", false},
		{"unrelated TLD rejected", "victim.com", "attacker.org", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isInBailiwick(c.qname, c.signer)
			if got != c.want {
				if c.want {
					t.Errorf("legitimate signer %q for qname %q rejected — chain-of-trust broken; would mark valid signed responses Bogus",
						c.signer, c.qname)
				} else {
					t.Errorf("attacker-controlled signer %q accepted for qname %q — RFC 4035 §5.3.1 violation; an attacker who controls signer's zone could forge RRSIGs for victim's records",
						c.signer, c.qname)
				}
			}
		})
	}
}
