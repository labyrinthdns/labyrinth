package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestVerifyRRSIG_NSECNextDomainMixedCase pins RFC 6840 §5.1: the Next Domain
// Name in an NSEC RR's RDATA MUST NOT be downcased when forming the canonical
// form for signature verification (RFC 4034 §6.2 erroneously listed NSEC among
// the downcased types).
//
// A signer emits the NSEC Next Domain Name in the ORIGINAL case of the next
// owner name — mixed-case labels like the ubiquitous `_DMARC` TXT-policy record
// are common. A validator that downcases the Next Domain Name reconstructs a
// different canonical RRset than the signer used, so the RRSIG over the NSEC
// fails to verify and the denial cannot be authenticated — a false Bogus /
// SERVFAIL for the affected NODATA/NXDOMAIN response (observed live against
// `fedoraproject.org SRV`, whose apex NSEC points to `_DMARC.fedoraproject.org.`).
//
// The NSEC is signed over its Next Domain Name in original case, computed
// independently of the validator's own canonicalisation (manualSignedData uses
// the RR's RDATA verbatim). A validator that downcases the name fails to verify;
// the fixed validator, which leaves it untouched, verifies.
func TestVerifyRRSIG_NSECNextDomainMixedCase(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dnskey := &dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.AlgED25519,
		PublicKey: []byte(pubKey),
	}

	// NSEC RDATA: mixed-case Next Domain Name "_DMARC.example.com." followed by
	// a minimal type bitmap (window 0, one octet, bit for type A set).
	nextDomain := dns.BuildPlainName("_DMARC.example.com")
	typeBitmap := []byte{0x00, 0x01, 0x40} // window 0, len 1, bit for TypeA(1)
	nsecRData := append(append([]byte{}, nextDomain...), typeBitmap...)

	nsecRR := dns.ResourceRecord{
		Name: "example.com.", Type: dns.TypeNSEC, Class: dns.ClassIN,
		TTL: 300, RDLength: uint16(len(nsecRData)), RData: nsecRData,
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeNSEC,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  "example.com.",
	}

	// Sign over the NSEC with its Next Domain Name in ORIGINAL case, the way a
	// real signer does — independent of the validator's canonicalisation.
	signedData := manualSignedData(rrsig, []dns.ResourceRecord{nsecRR})
	rrsig.Signature = ed25519.Sign(privKey, signedData)

	if err := VerifyRRSIG([]dns.ResourceRecord{nsecRR}, rrsig, dnskey); err != nil {
		t.Fatalf("VerifyRRSIG rejected a validly-signed NSEC — the NSEC Next Domain "+
			"Name must NOT be downcased in canonical form (RFC 6840 §5.1): %v", err)
	}
}
