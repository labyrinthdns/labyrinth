package dnssec

import (
	"crypto"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestHashForAlgorithm_RFC6605Pairing pins the strict algorithm/hash
// pairing defined by RFC 6605 §2 and the broader IANA DNSSEC Algorithm
// Numbers registry. The pairings are NOT free choices — each algorithm
// is bound to one specific hash:
//
//   - Algorithm 5 (RSASHA1)            → SHA-1
//   - Algorithm 8 (RSASHA256)          → SHA-256
//   - Algorithm 10 (RSASHA512)         → SHA-512
//   - Algorithm 13 (ECDSAP256SHA256)   → SHA-256 (RFC 6605 §2.1)
//   - Algorithm 14 (ECDSAP384SHA384)   → SHA-384 (RFC 6605 §2.1, NOT SHA-512!)
//   - Algorithm 15 (ED25519)           → internal (returns 0/no-hash)
//
// The history of this function carries a real production bug it once
// had: algorithm 14 (ECDSAP384) was grouped with RSASHA512 under
// SHA-512, which made every zone signed with alg 14 (e.g.
// `fedoraproject.org`) come back Bogus. The fix is a dedicated case
// that maps alg 14 → SHA-384. A regression that re-grouped them
// would silently break a long tail of real signed zones.
//
// We pin the FULL truth table including the no-hash ED25519 case and
// the unsupported-algorithm path (alg 99 reserved / undefined).
func TestHashForAlgorithm_RFC6605Pairing(t *testing.T) {
	cases := []struct {
		name string
		alg  uint8
		want crypto.Hash
		err  bool
	}{
		{"RSASHA1 → SHA-1", dns.AlgRSASHA1, crypto.SHA1, false},
		{"RSASHA256 → SHA-256", dns.AlgRSASHA256, crypto.SHA256, false},
		{"RSASHA512 → SHA-512", dns.AlgRSASHA512, crypto.SHA512, false},
		{"ECDSAP256 → SHA-256 (RFC 6605 §2.1)", dns.AlgECDSAP256, crypto.SHA256, false},
		{"ECDSAP384 → SHA-384 (NOT SHA-512 — fedoraproject.org regression target)", dns.AlgECDSAP384, crypto.SHA384, false},
		{"ED25519 → no external hash (alg does it internally)", dns.AlgED25519, crypto.Hash(0), false},
		{"unsupported alg 99 → error", 99, 0, true},
		{"unsupported alg 0 (Reserved) → error", 0, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := hashForAlgorithm(c.alg)
			if c.err {
				if err == nil {
					t.Errorf("alg %d: expected error, got hash %v", c.alg, got)
				}
				return
			}
			if err != nil {
				t.Errorf("alg %d: unexpected error %v", c.alg, err)
			}
			if got != c.want {
				t.Errorf("alg %d: hashForAlgorithm = %v, want %v — RFC 6605 §2.1 binds algorithm/hash one-to-one", c.alg, got, c.want)
			}
		})
	}
}
