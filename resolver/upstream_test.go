package resolver

import "testing"

func TestRandomTXID(t *testing.T) {
	const count = 10000
	seen := make(map[uint16]struct{}, count)

	for i := 0; i < count; i++ {
		id, err := randomTXID()
		if err != nil {
			t.Fatalf("randomTXID error: %v", err)
		}
		seen[id] = struct{}{}
	}

	// With 65536 possible values and 10000 samples,
	// collisions are expected but unique count should be high (>9900)
	if len(seen) < 9000 {
		t.Errorf("expected >9000 unique IDs out of %d, got %d (possible weak randomness)", count, len(seen))
	}
}

func TestRandomTXIDNotZero(t *testing.T) {
	// Generate many IDs — none should all be zero (basic sanity)
	allZero := true
	for i := 0; i < 100; i++ {
		id, err := randomTXID()
		if err != nil {
			t.Fatalf("randomTXID error: %v", err)
		}
		if id != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("all 100 IDs were zero — randomness is broken")
	}
}
