package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateResponseWithReason_DSMatchesNoDNSKEY pins the EDE for a broken
// key rollover: the parent publishes an authenticated DS, but no DNSKEY of
// the child matches it. That must surface ReasonNoMatchingDNSKEY, so the
// server emits EDE 9 (DNSKEY Missing) as 1.1.1.1 and 8.8.8.8 do, not the
// generic EDE 6. Live: 231.196.91.in-addr.arpa. A DS the parent did not sign
// is a different failure and stays ReasonOther.
func TestValidateResponseWithReason_DSMatchesNoDNSKEY(t *testing.T) {
	for _, tc := range []struct {
		name    string
		signDS  bool
		want    FailureReason
		wantEDE uint16
	}{
		{"authenticated DS, no matching DNSKEY", true, ReasonNoMatchingDNSKEY, dns.EDECodeDNSKEYMissing},
		{"DS not signed by the parent", false, ReasonOther, dns.EDECodeDNSSECBogus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ti := newTestInfra()
			ti.setRootDNSKEYs()

			zonePub, zonePriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			zoneKeyR := encodeDNSKEYRData(257, 3, dns.AlgED25519, zonePub)
			zoneKey, _ := dns.ParseDNSKEY(zoneKeyR)

			// The DS describes a retired key, not the one the zone publishes.
			oldPub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			oldKey, _ := dns.ParseDNSKEY(encodeDNSKEYRData(257, 3, dns.AlgED25519, oldPub))
			h := sha256.Sum256(buildDSDigestInput("example.", oldKey))
			dsRR := dns.ResourceRecord{Name: "example.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600,
				RData: encodeDSRData(oldKey.KeyTag(), dns.AlgED25519, dns.DigestSHA256, h[:])}
			dsAnswer := []dns.ResourceRecord{dsRR}
			if tc.signDS {
				dsSig := &dns.RRSIGRecord{TypeCovered: dns.TypeDS, Algorithm: dns.AlgED25519, Labels: 1,
					OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: ti.rootKSK.KeyTag(), SignerName: "."}
				dsSig.Signature = ed25519.Sign(ti.rootPrivKey, buildSignedData([]dns.ResourceRecord{dsRR}, dsSig))
				dsAnswer = append(dsAnswer, dns.ResourceRecord{Name: "example.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(dsSig)})
			}
			ti.mq.responses["example.|43"] = &dns.Message{Answers: dsAnswer}

			// Self-signed DNSKEY RRset.
			keyRR := dns.ResourceRecord{Name: "example.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: zoneKeyR}
			keySig := &dns.RRSIGRecord{TypeCovered: dns.TypeDNSKEY, Algorithm: dns.AlgED25519, Labels: 1,
				OrigTTL: 3600, Expiration: 0xFFFFFFFF, KeyTag: zoneKey.KeyTag(), SignerName: "example."}
			keySig.Signature = ed25519.Sign(zonePriv, buildSignedData([]dns.ResourceRecord{keyRR}, keySig))
			ti.mq.responses["example.|48"] = &dns.Message{Answers: []dns.ResourceRecord{
				keyRR,
				{Name: "example.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: buildRRSIGRData(keySig)},
			}}

			// A correctly signed answer, so only the DS link can fail.
			a := []dns.ResourceRecord{{Name: "www.example.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{192, 0, 2, 1}}}
			aSig := &dns.RRSIGRecord{TypeCovered: dns.TypeA, Algorithm: dns.AlgED25519, Labels: 2,
				OrigTTL: 300, Expiration: 0xFFFFFFFF, KeyTag: zoneKey.KeyTag(), SignerName: "example."}
			aSig.Signature = ed25519.Sign(zonePriv, buildSignedData(a, aSig))
			resp := &dns.Message{Answers: append(a, dns.ResourceRecord{
				Name: "www.example.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(aSig)})}

			verdict, reason := ti.v.ValidateResponseWithReason(resp, "www.example.", dns.TypeA)
			if verdict != Bogus {
				t.Fatalf("verdict: got %v, want Bogus", verdict)
			}
			if reason != tc.want {
				t.Errorf("reason: got %v, want %v", reason, tc.want)
			}
			if code, _ := dns.BogusReasonToEDE(reason.String()); code != tc.wantEDE {
				t.Errorf("EDE: got %d, want %d", code, tc.wantEDE)
			}
		})
	}
}
