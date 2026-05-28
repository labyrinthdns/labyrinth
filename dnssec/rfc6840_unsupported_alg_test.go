package dnssec

import (
	"log/slog"
	"io"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestIsUnsupportedRRSIGAlg_TruthTable pins RFC 6840 §5.2: "a validator
// that does not recognize a [DNSSEC] algorithm MUST treat the RRSIG
// as if it had not been signed." The downstream effect is that the
// validator returns Insecure (not Bogus) for a zone signed exclusively
// with an algorithm we cannot verify — which is the correct outcome
// per §5.2 (we cannot speak about a zone's authenticity if we cannot
// read its signatures).
//
// The supported set is fixed by what Go's standard library offers
// without external crypto dependencies. A regression that "added"
// an unsupported algorithm to the supported list (or vice-versa)
// would either:
//
//   - Falsely claim Insecure for fully-validatable zones (false
//     negative — security loss), OR
//   - Attempt to verify with the wrong crypto routine and crash /
//     return Bogus despite the signature being correct (operational
//     loss against modern-algo zones).
//
// We pin the exhaustive truth table: every IANA-assigned DNSSEC
// algorithm number is either "supported" (Go stdlib can verify) or
// "unsupported" (we treat as if unsigned). Reserved/private numbers
// fall in the unsupported set.
func TestIsUnsupportedRRSIGAlg_TruthTable(t *testing.T) {
	v := NewValidator(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	cases := []struct {
		name string
		alg  uint8
		want bool // true = unsupported
	}{
		// Supported algorithms — Go stdlib can verify these.
		{"RSASHA1 (5) — needs explicit allowSHA1 but is reachable", dns.AlgRSASHA1, false},
		{"RSASHA256 (8)", dns.AlgRSASHA256, false},
		{"RSASHA512 (10)", dns.AlgRSASHA512, false},
		{"ECDSAP256 (13)", dns.AlgECDSAP256, false},
		{"ECDSAP384 (14)", dns.AlgECDSAP384, false},
		{"ED25519 (15)", dns.AlgED25519, false},

		// Unsupported algorithms — MUST treat as unsigned (RFC 6840 §5.2).
		{"Reserved (0)", 0, true},
		{"RSAMD5 (1) — broken hash, MUST NOT (RFC 6151)", dns.AlgRSAMD5, true},
		{"DSA (3) — RFC 8624 MUST NOT", dns.AlgDSA, true},
		{"DSA-NSEC3-SHA1 (6) — RFC 8624 MUST NOT", dns.AlgDSANSEC3SHA1, true},
		{"RSASHA1-NSEC3 (7) — RFC 8624 MUST NOT", dns.AlgRSASHA1NSEC3, true},
		{"ED448 (16) — well-formed DNSSEC but no Go stdlib verifier", 16, true},
		{"GOST (12) — withdrawn algorithm, no implementation", 12, true},
		{"PRIVATEDNS (253)", 253, true},
		{"PRIVATEOID (254)", 254, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := v.isUnsupportedRRSIGAlg(c.alg)
			if got != c.want {
				if c.want {
					t.Errorf("alg %d (%s) reported as SUPPORTED — would trigger an attempt to call a non-existent verifier; RFC 6840 §5.2 requires treating as unsigned (Insecure)", c.alg, c.name)
				} else {
					t.Errorf("alg %d (%s) reported as UNSUPPORTED — fully-validatable zones would degrade to Insecure; security loss", c.alg, c.name)
				}
			}
		})
	}
}
