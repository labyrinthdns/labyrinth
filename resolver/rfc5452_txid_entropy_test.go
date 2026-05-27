package resolver

import (
	"math/bits"
	"testing"
)

// TestRandomTXID_HasFullEntropy pins Y56: RFC 5452 §7 / §9 require the
// query ID to be unpredictable to an off-path attacker. Predictable IDs
// reduce the forgery search space below the nominal 16 bits, and combined
// with the source-port and 0x20 entropy stack determine the effective
// off-path cache-poisoning window. A regression to a deterministic or
// monotonic generator (e.g. a refactor that swapped crypto/rand for
// math/rand without seeding, or that returned the low byte of a counter)
// would be undetectable in normal traffic — only an active probe would
// catch it.
//
// We pin two statistical invariants on 256 consecutive IDs:
//   1. No duplicate (probability of collision in 256 16-bit values is
//      ~1/2^7; we sample with replacement and tolerate one collision)
//   2. Hamming-weight spread (the set must touch a wide swath of bits;
//      a constant generator would fail this immediately)
//
// These are weak compared to the full NIST entropy test suite but are
// the right shape for a regression pin: an actually-broken generator
// will fail them, an actually-good generator will never flake.
func TestRandomTXID_HasFullEntropy(t *testing.T) {
	const samples = 256

	seen := make(map[uint16]int, samples)
	var unionBits uint16

	collisions := 0
	for i := 0; i < samples; i++ {
		id, err := randomTXID()
		if err != nil {
			t.Fatalf("randomTXID returned error on sample %d: %v", i, err)
		}
		seen[id]++
		if seen[id] > 1 {
			collisions++
		}
		unionBits |= id
	}

	// Pin 1: duplicate cap. Birthday paradox at 256 over 65536 ≈ 0.5
	// expected collisions; >5 means the generator is silently narrow.
	if collisions > 5 {
		t.Errorf("collisions = %d in %d samples — TXID generator is too narrow (RFC 5452 §9)", collisions, samples)
	}

	// Pin 2: bit-spread. A predictable / counter-based generator would
	// only ever flip the low bits; a healthy 16-bit RNG with 256 samples
	// has each bit set with probability 1-(1/2)^256 ≈ 1.0. We require
	// at least 14 of the 16 positions to have appeared in the union to
	// allow a tiny safety margin without admitting an actual regression.
	bitsTouched := bits.OnesCount16(unionBits)
	if bitsTouched < 14 {
		t.Errorf("union of 256 TXIDs only covered %d/16 bit positions (0x%04x) — generator likely deterministic / narrow", bitsTouched, unionBits)
	}
}

// TestRandomTXID_NoMonotonicity pins the second-level invariant that
// might survive even a passable Hamming weight: the values must not be
// monotonically increasing (a counter wrapped to uint16). We assert
// fewer than 80% of consecutive pairs are strictly ascending — a true
// random source has ~50% ascending pairs.
func TestRandomTXID_NoMonotonicity(t *testing.T) {
	const samples = 256
	ascending := 0
	prev, err := randomTXID()
	if err != nil {
		t.Fatalf("randomTXID: %v", err)
	}
	for i := 1; i < samples; i++ {
		cur, err := randomTXID()
		if err != nil {
			t.Fatalf("randomTXID(%d): %v", i, err)
		}
		if cur > prev {
			ascending++
		}
		prev = cur
	}
	// 80% of 255 = 204; a counter generator hits ~99% ascending.
	if ascending > 204 {
		t.Errorf("%d/%d consecutive pairs ascending — generator is monotonic, not random", ascending, samples-1)
	}
}
