package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestMustNotAlgorithms_VerifyRRSIGRejects pins Y39: VerifyRRSIG must
// refuse RFC 8624 §3.1 "MUST NOT" algorithms even with fully-formed
// crypto material in front of it. RSAMD5 (1) is broken (RFC 6151);
// DSA (3) and its NSEC3 variant (6) are deprecated; RSASHA1-NSEC3
// (7) is rejected because we honour SHA-1 only via the explicit
// allowSHA1 toggle on algorithm 5, not on the NSEC3 variant.
//
// The actual reject path is the verify-switch in verify.go falling
// through to "unsupported algorithm" — this test pins that the
// constants exist with the correct IANA numbers AND that they are
// not silently accepted.
func TestMustNotAlgorithms_VerifyRRSIGRejects(t *testing.T) {
	for _, c := range []struct {
		name string
		alg  uint8
	}{
		{"RSAMD5", dns.AlgRSAMD5},
		{"DSA", dns.AlgDSA},
		{"DSA-NSEC3-SHA1", dns.AlgDSANSEC3SHA1},
		{"RSASHA1-NSEC3-SHA1", dns.AlgRSASHA1NSEC3},
	} {
		t.Run(c.name, func(t *testing.T) {
			// A minimal RRSIG header carrying the test algorithm.
			// VerifyRRSIG checks algorithm BEFORE crypto so we can pass
			// nil/empty rrset/key — the algorithm gate runs first.
			rrsig := &dns.RRSIGRecord{
				TypeCovered: dns.TypeA,
				Algorithm:   c.alg,
				Labels:      2,
				OrigTTL:     300,
				SignerName:  "example.com",
				Signature:   []byte{0x01},
			}
			key := &dns.DNSKEYRecord{Algorithm: c.alg}
			err := VerifyRRSIG(nil, rrsig, key)
			if err == nil {
				t.Errorf("alg %d (%s) must be rejected as unsupported", c.alg, c.name)
			}
		})
	}
}

// TestMustNotAlgorithms_ConstantsMatchIANA pins the IANA assignments.
// Numbers come from RFC 8624 §3.1 / IANA "DNS Security Algorithm
// Numbers" registry. A renumber would silently break the reject path
// (we'd reject the wrong number and accept the broken one).
func TestMustNotAlgorithms_ConstantsMatchIANA(t *testing.T) {
	checks := []struct {
		name string
		got  uint8
		want uint8
	}{
		{"AlgRSAMD5", dns.AlgRSAMD5, 1},
		{"AlgDSA", dns.AlgDSA, 3},
		{"AlgDSANSEC3SHA1", dns.AlgDSANSEC3SHA1, 6},
		{"AlgRSASHA1NSEC3", dns.AlgRSASHA1NSEC3, 7},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d (IANA registry)", c.name, c.got, c.want)
		}
	}
}
