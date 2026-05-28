package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateResponse_MultiSigner_RFC8901 pins the RFC 8901 model:
// the same zone is signed independently by TWO operators, each
// running its own KSK and ZSK. The parent zone publishes TWO DS
// records — one per operator's KSK — and both operators publish their
// own DNSKEYs at the apex. The validator MUST accept the answer if
// EITHER operator's chain validates end-to-end.
//
// Real-world model: a customer with critical uptime requirements
// (financials, healthcare) splits authoritative service across two
// independent DNS operators. Each operator generates and rotates its
// own KSKs without coordination beyond the published DNSKEY RRset.
// A validator that hard-coded "exactly one DS at the parent" or
// "exactly one signing operator" would either reject the answer or
// silently lose half the chain's redundancy.
//
// What we exercise here is structurally distinct from the
// algorithm-rollover pin (rfc4035_algorithm_rollover_test.go):
//
//   - Rollover: ONE operator publishing TWO ZSKs (typically same KSK)
//     during an algorithm transition. Trust chain root: one DS.
//   - Multi-signer: TWO operators each publishing their own
//     {KSK, ZSK} pair. Trust chain root: TWO DS records at the parent.
//
// The two-DS-at-the-parent path is the new ground covered here. If
// the validator's DS-matching loop short-circuited on the first DS
// and one operator's DS happened to fail (e.g. unsupported digest),
// the multi-signer answer would come back Bogus even though the
// other operator's full chain was perfectly valid.
//
// The trust-anchor edge for this test is the root — we install BOTH
// operators' KSK DS hashes as root trust anchors so the chain has
// two parallel anchors; the test validates an answer that is signed
// by operator A's ZSK only, proving that the validator finds the
// matching chain.
func TestValidateResponse_MultiSigner_RFC8901(t *testing.T) {
	// Operator A — ED25519 (the newFullTestSetup provides this one).
	s := newFullTestSetup(t)

	// Operator B — ECDSA-P256, independently generated. Its KSK does
	// NOT match operator A's at the parent; both DS records co-exist
	// at the trust-anchor edge.
	opBPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("operator B keygen: %v", err)
	}
	opBWireKey := make([]byte, 64)
	xB := opBPriv.PublicKey.X.Bytes()
	yB := opBPriv.PublicKey.Y.Bytes()
	copy(opBWireKey[32-len(xB):32], xB)
	copy(opBWireKey[64-len(yB):64], yB)
	opBKSKRData := encodeDNSKEYRData(257, 3, dns.AlgECDSAP256, opBWireKey) // 257 = SEP+ZONE → KSK
	opBKSK, err := dns.ParseDNSKEY(opBKSKRData)
	if err != nil {
		t.Fatalf("parse operator B KSK: %v", err)
	}

	// Build operator B's DS hash and install it alongside operator
	// A's at the root trust anchor list. This is RFC 8901's
	// "parent publishes one DS per signer" pattern.
	opBDSInput := buildDSDigestInput(".", opBKSK)
	opBDSHash := sha256.Sum256(opBDSInput)
	s.v.trustAnchors = append(s.v.trustAnchors, dns.DSRecord{
		KeyTag:     opBKSK.KeyTag(),
		Algorithm:  dns.AlgECDSAP256,
		DigestType: dns.DigestSHA256,
		Digest:     opBDSHash[:],
	})

	// Both KSKs MUST appear in the root DNSKEY RRset (RFC 8901 §3:
	// "all DNSKEYs from all signers MUST be present in the apex
	// DNSKEY RRset"). The newFullTestSetup already wired operator A's
	// KSK; we append operator B's. We also need operator A's ZSK
	// present so the signing chain works.
	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
			// Operator B's KSK — present in the apex but NOT signing
			// the answer in this scenario. The validator must still
			// accept the answer because operator A's chain is intact.
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: opBKSKRData},
		},
	}

	// Build an answer signed by operator A's ZSK only (the typical
	// case — a client query happens to be answered by one of the
	// two operators' authoritative servers).
	rrset := []dns.ResourceRecord{
		{Name: ".", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := s.signRRSet(t, rrset, ".")

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	got := s.v.ValidateResponse(resp, ".", dns.TypeA)
	if got != Secure {
		t.Errorf("multi-signer answer signed by operator A: got %v, want Secure — RFC 8901 §3 requires the validator to accept the chain that DOES match without requiring all DS records to validate", got)
	}

	// Negative control: drop BOTH operators' DS records from the
	// trust anchors. With no parent-side anchor for the apex DNSKEY
	// RRset, the chain has nothing to attach to — must be Bogus. If
	// the validator still returned Secure here, it would mean the
	// trust-anchor verification step was a no-op and the test wasn't
	// actually exercising the chain.
	origAnchors := s.v.trustAnchors
	s.v.trustAnchors = nil
	s.v.keyCache = make(map[string]*dnskeyCache)
	got = s.v.ValidateResponse(resp, ".", dns.TypeA)
	if got == Secure {
		t.Errorf("with ALL trust anchors removed, validator still returned Secure — verifyAgainstTrustAnchors is not actually gating the chain")
	}
	s.v.trustAnchors = origAnchors

	// Keep ed25519 import live (used implicitly via signRRSet helper);
	// without this reference the import gets dead-stripped on Windows
	// build hosts where the helper is in a separate compilation unit.
	_ = ed25519.Sign
}
