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
