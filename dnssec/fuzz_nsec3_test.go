package dnssec

import (
	"testing"
)

// seedNSEC3Query is a realistic NSEC3 hash input for fuzzing.
var seedNSEC3Query = []byte("example.com")

func FuzzComputeNSEC3Hash(f *testing.F) {
	// Seed with realistic parameter combinations.
	// Note: seed values must match the fuzz function parameter types:
	// (string, uint8, uint16, []byte).
	f.Add("example.com", uint8(1), uint16(0), []byte("abcdef"))
	f.Add("example.com", uint8(1), uint16(10), []byte(nil))
	f.Add("test.example.com", uint8(1), uint16(0), []byte(""))
	f.Add(".", uint8(1), uint16(0), []byte("salt"))
	f.Add("", uint8(1), uint16(0), []byte(nil))
	f.Add("example.com", uint8(255), uint16(0), []byte(nil))  // unsupported algorithm
	f.Add("example.com", uint8(1), uint16(200), []byte(nil))   // over max iterations

	f.Fuzz(func(t *testing.T, name string, algorithm uint8, iterations uint16, salt []byte) {
		// ComputeNSEC3Hash must never panic, even on pathological inputs.
		// Errors are expected for:
		//   - algorithm != 1
		//   - iterations > MaxNSEC3Iterations (100)
		//   - name that cannot be encoded to wire format
		//   - empty/nil name
		hash, err := ComputeNSEC3Hash(name, algorithm, iterations, salt)
		if err != nil {
			return
		}
		// When successful, the hash must be:
		//   - non-nil (SHA-1 produces 20 bytes)
		//   - exactly 20 bytes
		if len(hash) != 20 {
			t.Errorf("expected 20-byte SHA-1 hash, got %d bytes", len(hash))
		}
	})
}

func FuzzNSEC3HashToString(f *testing.F) {
	f.Add([]byte("abcdefghijabcdefghij")) // 20 bytes = valid SHA-1 hash
	f.Add([]byte(""))
	f.Add([]byte{0x00, 0x01, 0x02})

	f.Fuzz(func(t *testing.T, hash []byte) {
		// NSEC3HashToString must never panic.
		result := NSEC3HashToString(hash)
		if result == "" && len(hash) > 0 {
			// An empty result for non-empty input is suspicious
			// but not a panic, so just note it.
			t.Log("empty result for non-empty hash")
		}
	})
}
