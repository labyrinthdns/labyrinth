package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateResponse_AlgorithmRollover_DualSig pins RFC 4035 §4.6
// (and the iteration strategy comment in validator.go:296-305):
// during an algorithm rollover, a zone publishes BOTH the old and the
// new DNSKEY/RRSIG simultaneously. The validator MUST accept the
// answer if AT LEAST ONE RRSIG validates against AT LEAST ONE matching
// DNSKEY — not give up after the first failure.
//
// Real-world failure mode this defends against:
//
//   A zone is mid-rollover from ED25519 to ECDSA-P256. The ED25519
//   RRSIG has just expired (clock skew, slow signer). The ECDSA RRSIG
//   is fresh. A "first failure short-circuits" validator would emit
//   Bogus → SERVFAIL for every query against the zone until the
//   operator notices, even though a perfectly valid signature was
//   right there in the same answer.
//
// We pin four corners of the truth table:
//
//   1. Old expired, new valid           → Secure (rollover survival)
//   2. Old valid, new expired           → Secure (reverse, order matters not)
//   3. Both valid                       → Secure (steady-state)
//   4. Both expired                     → Bogus  (negative control:
//                                                 the iteration does
//                                                 not silently downgrade
//                                                 to Insecure when every
//                                                 candidate fails)
//
// We sign with two different algorithms (ED25519 + ECDSA-P256) so the
// pin also catches a refactor that accidentally hard-codes a single
// algorithm path. The validator's findMatchingDNSKEY/VerifyRRSIG pair
// must dispatch on rrsig.Algorithm correctly to traverse both.
func TestValidateResponse_AlgorithmRollover_DualSig(t *testing.T) {
	cases := []struct {
		name        string
		ed25519Exp  uint32 // ED25519 RRSIG expiration
		ecdsaExp    uint32 // ECDSA   RRSIG expiration
		want        ValidationResult
		wantComment string
	}{
		{
			name: "old expired, new valid — survives rollover",
			// Make ED25519 (the "old" key in this scenario) expired by
			// using a timestamp well before any plausible Unix now.
			ed25519Exp:  100,
			ecdsaExp:    0xFFFFFFFF,
			want:        Secure,
			wantComment: "ED25519 expired but ECDSA fresh — validator must traverse to ECDSA",
		},
		{
			name:        "old valid, new expired — reverse order also survives",
			ed25519Exp:  0xFFFFFFFF,
			ecdsaExp:    100,
			want:        Secure,
			wantComment: "ECDSA expired but ED25519 fresh — iteration order does not affect outcome",
		},
		{
			name:        "both valid — steady state secure",
			ed25519Exp:  0xFFFFFFFF,
			ecdsaExp:    0xFFFFFFFF,
			want:        Secure,
			wantComment: "either signature alone would prove it; both fresh is the dual-sign norm during rollover",
		},
		{
			name:        "both expired — bogus (every candidate failed)",
			ed25519Exp:  100,
			ecdsaExp:    100,
			want:        Bogus,
			wantComment: "no usable signature; must surface as Bogus per validator.go:524, never silently Insecure",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newFullTestSetup(t)

			// Generate a second key in a different algorithm (ECDSA-P256).
			// The first key (ED25519) is already wired by newFullTestSetup
			// as the root ZSK with KeyTag = s.dnskey.KeyTag().
			ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("generate ECDSA-P256 key: %v", err)
			}
			ecdsaWireKey := encodeECDSAWireKey(&ecdsaPriv.PublicKey, 32)
			ecdsaZSKRData := encodeDNSKEYRData(256, 3, dns.AlgECDSAP256, ecdsaWireKey)
			ecdsaZSK, err := dns.ParseDNSKEY(ecdsaZSKRData)
			if err != nil {
				t.Fatalf("parse ECDSA DNSKEY: %v", err)
			}

			// Augment the root DNSKEY RRset to include both ZSKs alongside
			// the root KSK. This is the wire-realistic "two-algorithm
			// rollover" shape.
			rootKSKR := s.mq.responses[".|48"].Answers[0].RData
			s.mq.responses[".|48"] = &dns.Message{
				Answers: []dns.ResourceRecord{
					{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
					{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
					{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: ecdsaZSKRData},
				},
			}

			// Build the RRset under root.
			rrset := []dns.ResourceRecord{
				{Name: ".", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
			}

			// ED25519 RRSIG with caller-specified expiration.
			edRRSIG := &dns.RRSIGRecord{
				TypeCovered: dns.TypeA,
				Algorithm:   dns.AlgED25519,
				Labels:      0, // root has zero labels excluding root
				OrigTTL:     300,
				Expiration:  c.ed25519Exp,
				Inception:   0,
				KeyTag:      s.dnskey.KeyTag(),
				SignerName:  ".",
			}
			edSignedData := buildSignedData(rrset, edRRSIG)
			edRRSIG.Signature = ed25519.Sign(s.privKey, edSignedData)

			// ECDSA RRSIG with caller-specified expiration.
			ecRRSIG := &dns.RRSIGRecord{
				TypeCovered: dns.TypeA,
				Algorithm:   dns.AlgECDSAP256,
				Labels:      0,
				OrigTTL:     300,
				Expiration:  c.ecdsaExp,
				Inception:   0,
				KeyTag:      ecdsaZSK.KeyTag(),
				SignerName:  ".",
			}
			ecSignedData := buildSignedData(rrset, ecRRSIG)
			ecHash := sha256.Sum256(ecSignedData)
			r, sVal, err := ecdsa.Sign(rand.Reader, ecdsaPriv, ecHash[:])
			if err != nil {
				t.Fatalf("ECDSA sign: %v", err)
			}
			ecSig := make([]byte, 64)
			rBytes := r.Bytes()
			sBytes := sVal.Bytes()
			copy(ecSig[32-len(rBytes):32], rBytes)
			copy(ecSig[64-len(sBytes):64], sBytes)
			ecRRSIG.Signature = ecSig

			// Build the response with BOTH RRSIGs alongside the answer.
			// Order matters for the iteration test — ED25519 first means
			// the validator hits ED25519 first; if that one is the
			// expired one, the validator MUST continue to ECDSA.
			resp := &dns.Message{
				Answers: append(rrset,
					dns.ResourceRecord{
						Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
						RData: buildRRSIGRData(edRRSIG),
					},
					dns.ResourceRecord{
						Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
						RData: buildRRSIGRData(ecRRSIG),
					},
				),
			}

			got := s.v.ValidateResponse(resp, ".", dns.TypeA)
			if got != c.want {
				t.Errorf("got %v, want %v — %s", got, c.want, c.wantComment)
			}
		})
	}
}

// encodeECDSAWireKey returns the wire encoding of an ECDSA public key
// (raw X || Y, each coordLen bytes). Kept local so the test does not
// depend on the test-only helper in coverage_test.go (which uses a
// different signature shape).
func encodeECDSAWireKey(pub *ecdsa.PublicKey, coordLen int) []byte {
	wire := make([]byte, coordLen*2)
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	copy(wire[coordLen-len(x):coordLen], x)
	copy(wire[2*coordLen-len(y):2*coordLen], y)
	return wire
}
