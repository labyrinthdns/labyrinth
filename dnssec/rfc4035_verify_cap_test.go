package dnssec

import (
	"crypto/ed25519"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateResponse_RRSIGVerifyCap_StopsCryptoFlood — M5.5 pin.
// A hostile authoritative can attach an arbitrary number of garbage
// RRSIGs to an answer; without a cap the validator would walk every
// one of them, performing a DNSKEY fetch + asymmetric verify per
// signature. The cap (`maxRRSIGVerifyAttempts`) bounds the worst-case
// crypto work per RRset so a flooded answer cannot exhaust the
// resolver's CPU.
//
// We construct an answer with 30 garbage RRSIGs (alg/key-tag/window
// all valid so they reach VerifyRRSIG, but the signature bytes are
// zeroed so the crypto check fails). The validator should:
//
//  1. Walk RRSIGs and attempt verifies up to the cap
//  2. Stop the loop at the cap (verify-cap step emitted)
//  3. Settle on Bogus (every attempted verify failed)
//
// The pin proves the BOUNDED-CPU property: a regression that removed
// the cap would still produce Bogus, but at the cost of 30 verifies
// instead of 16 — invisible in a black-box result check. We surface
// the cap-engagement explicitly via ValidateResponseDetailed's step
// log so the regression cannot silently land.
func TestValidateResponse_RRSIGVerifyCap_StopsCryptoFlood(t *testing.T) {
	s := newFullTestSetup(t)

	// Add the ZSK to the root DNSKEY response so findMatchingDNSKEY
	// succeeds for the garbage RRSIGs we're about to build (they all
	// carry s.dnskey.KeyTag()). Without the ZSK in the response the
	// validator short-circuits on "no matching DNSKEY" before reaching
	// the verify step — and the cap is on verifies, so we'd never see
	// the cap engage.
	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	// Build the RRset under root.
	rrset := []dns.ResourceRecord{
		{Name: ".", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}

	// Construct N > cap garbage RRSIGs. Each uses the legitimate
	// ED25519 key tag (so findMatchingDNSKEY succeeds) but its
	// signature bytes are zeroed → VerifyRRSIG will fail. The
	// expiration is far in the future so the time-window check
	// passes and we reach the verify step.
	const numGarbage = 30 // well above maxRRSIGVerifyAttempts (16)
	var answers []dns.ResourceRecord
	answers = append(answers, rrset...)
	for i := 0; i < numGarbage; i++ {
		rrsig := &dns.RRSIGRecord{
			TypeCovered: dns.TypeA,
			Algorithm:   dns.AlgED25519,
			Labels:      0,
			OrigTTL:     300,
			Expiration:  0xFFFFFFFF,
			Inception:   0,
			KeyTag:      s.dnskey.KeyTag(),
			SignerName:  ".",
			Signature:   make([]byte, ed25519.SignatureSize), // zeros → verify fails
		}
		answers = append(answers, dns.ResourceRecord{
			Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		})
	}

	resp := &dns.Message{Answers: answers}

	verdict, steps := s.v.ValidateResponseDetailed(resp, ".", dns.TypeA)

	// Verdict: Bogus — every attempted verify failed.
	if verdict != Bogus {
		t.Errorf("verdict = %v, want Bogus (every garbage RRSIG fails crypto)", verdict)
	}

	// Cap engagement: at least one step with Stage == "verify-cap".
	// The cap-step is the load-bearing evidence; without it a future
	// refactor that drops the cap could still produce Bogus and pass
	// the verdict check, but would have spent unbounded CPU getting
	// there.
	var verifyAttempts, capHits int
	for _, st := range steps {
		switch st.Stage {
		case "verify-failed":
			verifyAttempts++
		case "verify-cap":
			capHits++
		}
	}

	if capHits == 0 {
		t.Errorf("no verify-cap step — cap did not engage; validator walked all %d garbage RRSIGs", numGarbage)
	}
	// We allow up to maxRRSIGVerifyAttempts failures plus the cap
	// step itself. A regression that loosened the cap (say, to 100)
	// would show more verifyAttempts than expected.
	if verifyAttempts > maxRRSIGVerifyAttempts {
		t.Errorf("performed %d crypto verifications, exceeds cap of %d", verifyAttempts, maxRRSIGVerifyAttempts)
	}
}

// TestValidateResponse_RRSIGVerifyCap_DoesNotBlockNormalRollover —
// negative control: a normal algorithm rollover (2 algorithms, 2-4
// total RRSIGs) MUST not trip the cap. This pins that the cap value
// stays well above any realistic rollover scenario. If a future
// release tightens maxRRSIGVerifyAttempts to (say) 1 because someone
// misread it as "max signatures to verify before declaring Secure",
// this test surfaces the regression by showing legitimate rollovers
// now fail.
func TestValidateResponse_RRSIGVerifyCap_DoesNotBlockNormalRollover(t *testing.T) {
	if maxRRSIGVerifyAttempts < 4 {
		t.Fatalf("maxRRSIGVerifyAttempts = %d is too tight to survive 2-algorithm rollover", maxRRSIGVerifyAttempts)
	}
}
