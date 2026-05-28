package dnssec

import (
	"errors"
	"testing"
)

// TestComputeNSEC3Hash_AlgorithmSupport pins RFC 5155 §8.2 + IANA
// "DNSSEC NSEC3 Parameters" registry: only algorithm number 1 (SHA-1)
// is defined for NSEC3. Algorithm 0 is permanently Reserved. Future
// numbers (2..255) are unassigned and MUST be rejected — accepting
// an unknown NSEC3 hash algorithm would either crash inside an
// unimplemented hash routine or, worse, return a meaningless hash
// that an attacker could synthesise NSEC3 records to match.
//
// The cap on the SUPPORT set is also the practical hardening against
// a future Reserved → Allocated change: if IANA ever assigns
// algorithm 2, we want the validator to fail conservatively (treat
// as Indeterminate / Insecure) rather than silently produce wrong
// hashes. RFC 9276 reinforces this: "NSEC3 algorithm 1 is the only
// algorithm specified in any RFC at this time."
//
// We pin: alg 0 rejected, alg 1 accepted, alg 2/3/255 rejected.
func TestComputeNSEC3Hash_AlgorithmSupport(t *testing.T) {
	cases := []struct {
		name        string
		alg         uint8
		expectError bool
	}{
		{"Reserved (0) rejected", 0, true},
		{"SHA-1 (1) accepted — only defined algorithm", 1, false},
		{"Unassigned (2) rejected", 2, true},
		{"Unassigned (3) rejected", 3, true},
		{"Future (100) rejected", 100, true},
		{"Last unassigned (255) rejected", 255, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ComputeNSEC3Hash("example.com", c.alg, 0, nil)
			if c.expectError {
				if err == nil {
					t.Errorf("alg %d unexpectedly accepted — RFC 5155 §8.2 defines only alg=1; accepting other numbers risks attacker-controlled hash collisions on undefined algorithms", c.alg)
				} else if !errors.Is(err, errUnsupportedHashAlg) {
					t.Errorf("alg %d rejected with unexpected error %v — want errUnsupportedHashAlg so a future IANA allocation lands on the correct guard rail", c.alg, err)
				}
			} else if err != nil {
				t.Errorf("alg %d (SHA-1, the only defined NSEC3 algorithm) rejected: %v", c.alg, err)
			}
		})
	}
}
