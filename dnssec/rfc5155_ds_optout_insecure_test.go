package dnssec

import (
	"crypto/ed25519"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidateDenialResponse_DSOptOutIsInsecureNotBogus pins RFC 5155 §7.2.4:
// a DS query answered with NODATA at a delegation that sits inside an opt-out
// NSEC3 span is an authenticated *insecure delegation* signal, NOT a forgery.
//
// The generic NSEC3 NODATA proof (VerifyNSEC3Denial5155) requires an NSEC3 that
// MATCHES the qname hash with the DS bit clear. An opt-out delegation — the norm
// for the millions of unsigned zones under .com / .net — has no matching NSEC3;
// the name is only covered by an opt-out span. Without a DS-specific fallback the
// validator falls through to Bogus and the resolver returns SERVFAIL for e.g.
// `google.com DS`, `amazon.com DS`, `microsoft.com DS`, whereas Unbound, BIND,
// and the public 1.1.1.1 / 8.8.8.8 validators return NOERROR with AD=0 (Insecure).
//
// The companion sub-test guards the security boundary: a covering NSEC3 WITHOUT
// the opt-out flag must NOT be accepted as proof of DS absence (that is the
// empty-DS spoofing vector), so it stays Bogus.
func TestValidateDenialResponse_DSOptOutIsInsecureNotBogus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		optOut bool
		want   ValidationResult
	}{
		{"opt-out cover proves insecure delegation", true, Insecure},
		{"non-opt-out cover must not downgrade (stays bogus)", false, Bogus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newFullTestSetup(t)

			// The NSEC3 is signed by root in this fixture; wire the root
			// DNSKEY response to include the Ed25519 ZSK so fetchDNSKEYs(".")
			// returns a key whose tag matches the RRSIG below.
			rootKSKR := s.mq.responses[".|48"].Answers[0].RData
			s.mq.responses[".|48"] = &dns.Message{
				Answers: []dns.ResourceRecord{
					{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
					{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
				},
			}

			const qname = "unsigned-delegation.test."
			salt := []byte{0xAB}
			childHash, err := ComputeNSEC3Hash(qname, 1, 0, salt)
			if err != nil {
				t.Fatal(err)
			}
			// Bracket H(qname) with an all-zero owner and all-FF next hash so
			// the NSEC3 unconditionally COVERS (but does not MATCH) the qname.
			ownerHash := make([]byte, len(childHash))
			nextHash := make([]byte, len(childHash))
			for i := range nextHash {
				nextHash[i] = 0xFF
			}

			var flags uint8
			if tc.optOut {
				flags = 0x01 // RFC 5155 §3.1.2.1 opt-out
			}
			// Delegation NSEC3: NS present, DS absent. (For a matching NSEC3 the
			// DS-clear bitmap would itself prove insecurity, so we deliberately
			// use a COVER, not a match, to isolate the opt-out semantics.)
			nsec3RData := buildNSEC3RData(1, flags, 0, salt, nextHash, []uint16{dns.TypeNS})
			nsec3RR := dns.ResourceRecord{
				Name:  NSEC3HashToString(ownerHash) + ".",
				Type:  dns.TypeNSEC3,
				Class: dns.ClassIN,
				TTL:   300,
				RData: nsec3RData,
			}

			rrsig := &dns.RRSIGRecord{
				TypeCovered: dns.TypeNSEC3,
				Algorithm:   dns.AlgED25519,
				Labels:      0,
				OrigTTL:     300,
				Expiration:  0xFFFFFFFF,
				Inception:   0,
				KeyTag:      s.dnskey.KeyTag(),
				SignerName:  ".",
			}
			signedData := buildSignedData([]dns.ResourceRecord{nsec3RR}, rrsig)
			rrsig.Signature = ed25519.Sign(s.privKey, signedData)

			// DS NODATA is RCODE=NoError with an empty answer section.
			resp := &dns.Message{
				Header: dns.Header{
					Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNoError).Build(),
				},
				Authority: []dns.ResourceRecord{
					nsec3RR,
					{Name: ".", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(rrsig)},
				},
			}

			got := s.v.ValidateResponse(resp, qname, dns.TypeDS)
			if got != tc.want {
				t.Errorf("ValidateResponse(DS NODATA, opt-out=%v) = %v, want %v", tc.optOut, got, tc.want)
			}
		})
	}
}
