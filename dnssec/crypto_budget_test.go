package dnssec

import "testing"

// TestCryptoBudget pins the per-response signature-verification backstop that
// completes the KeyTrap (CVE-2023-50387) mitigation: the per-RRset cap bounds
// one RRset, but an attacker can spread crypto cost across the answer RRset,
// the trust chain, and the uncapped authority-RRSIG loops of a denial proof.
// cryptoBudget bounds the TOTAL across all of those within one validation.
func TestCryptoBudget(t *testing.T) {
	// A budget with max N allows exactly N charges, then refuses.
	b := &cryptoBudget{max: maxCryptoVerifyPerResponse}
	for i := 0; i < maxCryptoVerifyPerResponse; i++ {
		if !b.allow() {
			t.Fatalf("charge %d should be allowed under cap %d", i+1, maxCryptoVerifyPerResponse)
		}
	}
	if b.allow() {
		t.Fatalf("charge %d should be refused past cap %d", maxCryptoVerifyPerResponse+1, maxCryptoVerifyPerResponse)
	}

	// nil budget and max <= 0 are unlimited (the direct-test / forwarder path).
	var nilB *cryptoBudget
	for i := 0; i < 1000; i++ {
		if !nilB.allow() {
			t.Fatal("nil budget must be unlimited")
		}
	}
	unlimited := &cryptoBudget{max: 0}
	for i := 0; i < 1000; i++ {
		if !unlimited.allow() {
			t.Fatal("max<=0 budget must be unlimited")
		}
	}

	// budgetFrom unpacks the variadic threading helper.
	if budgetFrom(nil) != nil {
		t.Error("budgetFrom(nil) must be nil (unlimited)")
	}
	want := &cryptoBudget{max: 5}
	if budgetFrom([]*cryptoBudget{want}) != want {
		t.Error("budgetFrom must return the passed budget")
	}
}

// TestCryptoBudget_DeepReverseFloor pins the seznam.cz IPv6 reverse failure
// mode: the signer trust chain alone (0.0.a.8.4.6…ip6.arpa) burns ~36
// signature verifies across NSEC-covered RIPE intermediates + NSEC3 ENTs
// under 8.9.5.0.2.0.a.2.ip6.arpa. Cap 32 collapsed that chain to Bogus and
// engaged public-resolver fallback even though Cloudflare/Google Secure the
// PTR. Leave headroom for the answer RRSIG and a mid-rollover extra sig.
func TestCryptoBudget_DeepReverseFloor(t *testing.T) {
	const seznamSignerChainVerifies = 36
	const answerAndRolloverHeadroom = 4
	floor := seznamSignerChainVerifies + answerAndRolloverHeadroom
	if maxCryptoVerifyPerResponse < floor {
		t.Fatalf("maxCryptoVerifyPerResponse=%d is below deep-reverse floor %d (seznam IPv6 PTR)",
			maxCryptoVerifyPerResponse, floor)
	}
}
