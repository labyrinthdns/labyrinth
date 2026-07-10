package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestVerifyRRSIG_RFC4034_Section6_3_RDATAOnlyOrdering pins RFC 4034 §6.3:
// within an RRset the RRs are ordered "by treating the RDATA portion of the
// canonical form of each RR as a left-justified unsigned octet sequence." The
// ordering key is the RDATA ALONE — the 2-byte RDLENGTH is NOT part of RDATA.
//
// A prior implementation sorted by the full RR wire form (owner+type+class+
// ttl+RDLENGTH+RDATA). Owner/type/class/ttl are constant across an RRset, but
// prefixing the per-record RDLENGTH makes every shorter RDATA sort before a
// longer one regardless of content. Real signers (which sort by RDATA only)
// then produce a different canonical RRset than the resolver reconstructs, so
// the hash mismatches and a perfectly valid signed RRset is declared Bogus —
// observed in the wild as SERVFAIL for e.g. `cloudflare.com CAA` and
// `cloudflare.com MX`.
//
// This test signs an RRset using the CORRECT RFC 4034 §6.3 order computed
// independently of the resolver's own sort, then asks VerifyRRSIG to accept
// it. Under the buggy RDLENGTH-prefixed sort the resolver reconstructs the
// wrong order and verification fails, catching any regression. The two RDATAs
// are chosen so the two orderings genuinely differ:
//
//	rdataLong  = {0x00, 0x00}  (len 2)  sorts FIRST  by RDATA (0x00 < 0xFF)
//	rdataShort = {0xFF}        (len 1)  sorts SECOND by RDATA
//
// but under RDLENGTH-prefixed sorting rdataShort (len 1) would sort first.
func TestVerifyRRSIG_RFC4034_Section6_3_RDATAOnlyOrdering(t *testing.T) {
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

	rdataLong := []byte{0x00, 0x00}
	rdataShort := []byte{0xFF}

	// CAA is treated as opaque RDATA by canonicalRData (no embedded names),
	// so these synthetic byte values exercise pure ordering.
	rrLong := dns.ResourceRecord{
		Name: "example.com.", Type: dns.TypeCAA, Class: dns.ClassIN,
		TTL: 300, RDLength: uint16(len(rdataLong)), RData: rdataLong,
	}
	rrShort := dns.ResourceRecord{
		Name: "example.com.", Type: dns.TypeCAA, Class: dns.ClassIN,
		TTL: 300, RDLength: uint16(len(rdataShort)), RData: rdataShort,
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeCAA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  "example.com.",
	}

	// Build the signed data in the CORRECT RFC 4034 §6.3 order (RDATA-only),
	// independent of the resolver's canonicalRRSetWire, and sign it.
	correctOrder := []dns.ResourceRecord{rrLong, rrShort} // rdataLong (0x00 0x00) before rdataShort (0xFF)
	signedData := manualSignedData(rrsig, correctOrder)
	rrsig.Signature = ed25519.Sign(privKey, signedData)

	// Present the RRset to the verifier in the OPPOSITE order; a correct
	// verifier re-sorts by RDATA and accepts. A verifier that sorts by the
	// RDLENGTH-prefixed key reconstructs {rrShort, rrLong} and rejects.
	if err := VerifyRRSIG([]dns.ResourceRecord{rrShort, rrLong}, rrsig, dnskey); err != nil {
		t.Fatalf("VerifyRRSIG rejected a validly-signed RRset — RRset ordering "+
			"must key on RDATA only, not RDLENGTH+RDATA (RFC 4034 §6.3): %v", err)
	}
}

// manualSignedData rebuilds the RRSIG signing input the way buildSignedData
// does, but with the RRset taken in the exact order supplied (no internal
// re-sort), so a test can control the canonical ordering independently of the
// code under test.
func manualSignedData(rrsig *dns.RRSIGRecord, ordered []dns.ResourceRecord) []byte {
	var buf []byte
	fixed := make([]byte, 18)
	binary.BigEndian.PutUint16(fixed[0:2], rrsig.TypeCovered)
	fixed[2] = rrsig.Algorithm
	fixed[3] = rrsig.Labels
	binary.BigEndian.PutUint32(fixed[4:8], rrsig.OrigTTL)
	binary.BigEndian.PutUint32(fixed[8:12], rrsig.Expiration)
	binary.BigEndian.PutUint32(fixed[12:16], rrsig.Inception)
	binary.BigEndian.PutUint16(fixed[16:18], rrsig.KeyTag)
	buf = append(buf, fixed...)
	buf = append(buf, canonicalNameWire(rrsig.SignerName)...)

	for _, rr := range ordered {
		buf = append(buf, canonicalNameWire(rr.Name)...)
		hdr := make([]byte, 10)
		binary.BigEndian.PutUint16(hdr[0:2], rr.Type)
		binary.BigEndian.PutUint16(hdr[2:4], rr.Class)
		binary.BigEndian.PutUint32(hdr[4:8], rrsig.OrigTTL)
		binary.BigEndian.PutUint16(hdr[8:10], uint16(len(rr.RData)))
		buf = append(buf, hdr...)
		buf = append(buf, rr.RData...)
	}
	return buf
}
