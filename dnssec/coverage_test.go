package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// --- helpers ---

// encodeDNSKEYRData builds a DNSKEY RDATA from the given fields.
func encodeDNSKEYRData(flags uint16, protocol, algorithm uint8, pubKey []byte) []byte {
	rdata := make([]byte, 4+len(pubKey))
	binary.BigEndian.PutUint16(rdata[0:2], flags)
	rdata[2] = protocol
	rdata[3] = algorithm
	copy(rdata[4:], pubKey)
	return rdata
}

// encodeDSRData builds a DS RDATA from the given fields.
func encodeDSRData(keyTag uint16, algorithm, digestType uint8, digest []byte) []byte {
	rdata := make([]byte, 4+len(digest))
	binary.BigEndian.PutUint16(rdata[0:2], keyTag)
	rdata[2] = algorithm
	rdata[3] = digestType
	copy(rdata[4:], digest)
	return rdata
}

// encodeNameWire encodes a domain name in DNS wire format (for use inside RRSIG RDATA).
// The name must end with ".".
func encodeNameWire(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0x00}
	}
	labels := strings.Split(name, ".")
	var buf []byte
	for _, l := range labels {
		buf = append(buf, byte(len(l)))
		buf = append(buf, []byte(l)...)
	}
	buf = append(buf, 0x00)
	return buf
}

// buildRRSIGRData builds RRSIG RDATA from the given RRSIG fields + signature.
func buildRRSIGRData(rrsig *dns.RRSIGRecord) []byte {
	fixed := make([]byte, 18)
	binary.BigEndian.PutUint16(fixed[0:2], rrsig.TypeCovered)
	fixed[2] = rrsig.Algorithm
	fixed[3] = rrsig.Labels
	binary.BigEndian.PutUint32(fixed[4:8], rrsig.OrigTTL)
	binary.BigEndian.PutUint32(fixed[8:12], rrsig.Expiration)
	binary.BigEndian.PutUint32(fixed[12:16], rrsig.Inception)
	binary.BigEndian.PutUint16(fixed[16:18], rrsig.KeyTag)

	nameWire := encodeNameWire(rrsig.SignerName)
	rdata := append(fixed, nameWire...)
	rdata = append(rdata, rrsig.Signature...)
	return rdata
}

// rsaWireKey encodes an RSA public key in DNSKEY wire format.
func rsaWireKey(pubKey *rsa.PublicKey) []byte {
	expBytes := big.NewInt(int64(pubKey.E)).Bytes()
	modBytes := pubKey.N.Bytes()
	var wireKey []byte
	if len(expBytes) <= 255 {
		wireKey = append(wireKey, byte(len(expBytes)))
	} else {
		wireKey = append(wireKey, 0)
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(expBytes)))
		wireKey = append(wireKey, lenBuf...)
	}
	wireKey = append(wireKey, expBytes...)
	wireKey = append(wireKey, modBytes...)
	return wireKey
}

// ecdsaWireKey encodes an ECDSA public key in DNSKEY wire format.
func ecdsaWireKey(pubKey *ecdsa.PublicKey, coordLen int) []byte {
	wireKey := make([]byte, coordLen*2)
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	copy(wireKey[coordLen-len(xBytes):coordLen], xBytes)
	copy(wireKey[2*coordLen-len(yBytes):2*coordLen], yBytes)
	return wireKey
}

// --- DS tests ---

func TestVerifyDS_SHA384(t *testing.T) {
	dnskey := &dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("test-public-key-data-for-sha384-verification"),
	}
	ownerName := "example.com."
	digestInput := buildDSDigestInput(ownerName, dnskey)
	h := sha512.Sum384(digestInput)

	ds := &dns.DSRecord{
		KeyTag:     dnskey.KeyTag(),
		Algorithm:  dns.AlgRSASHA256,
		DigestType: dns.DigestSHA384,
		Digest:     h[:],
	}

	if !VerifyDS(dnskey, ds, ownerName) {
		t.Error("VerifyDS with correct SHA-384 digest should return true")
	}
}

// --- parseRSAPublicKey tests ---

func TestParseRSAPublicKey_LongExponentFormat(t *testing.T) {
	// Build a key with the 3-byte exponent length prefix (first byte = 0).
	// We need an exponent that fits in >255 bytes, but let's just use the 3-byte
	// header format with a small exponent to test the parsing branch.
	expBytes := []byte{0x01, 0x00, 0x01} // 65537
	modBytes := make([]byte, 128)
	modBytes[0] = 0x01 // non-zero modulus

	var wireKey []byte
	wireKey = append(wireKey, 0) // signals 3-byte header
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(expBytes)))
	wireKey = append(wireKey, lenBuf...)
	wireKey = append(wireKey, expBytes...)
	wireKey = append(wireKey, modBytes...)

	parsed, err := parseRSAPublicKey(wireKey)
	if err != nil {
		t.Fatalf("parseRSAPublicKey (long exponent) failed: %v", err)
	}
	if parsed.E != 65537 {
		t.Errorf("exponent: got %d, want 65537", parsed.E)
	}
}

func TestParseRSAPublicKey_ExponentTooLarge(t *testing.T) {
	// Build a key where the exponent value exceeds 2^31-1.
	// Use a 5-byte exponent = 0x0100000000 = 4294967296 which is > maxInt32.
	expBytes := []byte{0x01, 0x00, 0x00, 0x00, 0x00}
	modBytes := []byte{0x01}

	var wireKey []byte
	wireKey = append(wireKey, byte(len(expBytes))) // expLen = 5
	wireKey = append(wireKey, expBytes...)
	wireKey = append(wireKey, modBytes...)

	_, err := parseRSAPublicKey(wireKey)
	if err == nil {
		t.Error("expected error for exponent too large")
	}
	if err != errInvalidRSAKey {
		t.Errorf("expected errInvalidRSAKey, got %v", err)
	}
}

func TestParseRSAPublicKey_EmptyModulusLongHeader(t *testing.T) {
	// 3-byte header format where exponent consumes all remaining bytes.
	expBytes := []byte{0x01, 0x00, 0x01}
	var wireKey []byte
	wireKey = append(wireKey, 0) // 3-byte header
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(expBytes)))
	wireKey = append(wireKey, lenBuf...)
	wireKey = append(wireKey, expBytes...) // no modulus bytes after

	_, err := parseRSAPublicKey(wireKey)
	if err == nil {
		t.Error("expected error for empty modulus with long exponent header")
	}
}

func TestParseRSAPublicKey_ZeroPrefixTooShort(t *testing.T) {
	// First byte is 0 but only 3 bytes total (need at least 4).
	_, err := parseRSAPublicKey([]byte{0, 0, 3})
	if err != errInvalidRSAKey {
		t.Errorf("expected errInvalidRSAKey, got %v", err)
	}
}

// --- verifyRSA error branches ---

func TestVerifyRSA_BadKey(t *testing.T) {
	err := verifyRSA([]byte("data"), []byte("sig"), []byte{1, 2}, dns.AlgRSASHA256)
	if err == nil {
		t.Error("expected error for invalid RSA key data")
	}
}

func TestVerifyRSA_WrongSignature(t *testing.T) {
	// Generate a real RSA key, then supply a bogus signature.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	wireKey := rsaWireKey(&privKey.PublicKey)

	err = verifyRSA([]byte("some data"), []byte("bad-signature-that-is-wrong"), wireKey, dns.AlgRSASHA256)
	if err == nil {
		t.Error("expected error for wrong RSA signature")
	}
	if err != errVerifyFailed {
		t.Errorf("expected errVerifyFailed, got %v", err)
	}
}

// --- verifyECDSA error branches ---

func TestVerifyECDSA_BadKey(t *testing.T) {
	// Invalid key data length for P-256.
	err := verifyECDSA([]byte("data"), make([]byte, 64), []byte{1, 2, 3}, dns.AlgECDSAP256)
	if err == nil {
		t.Error("expected error for invalid ECDSA key data")
	}
}

func TestVerifyECDSA_WrongSignatureLength(t *testing.T) {
	// Generate a valid P-256 key.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	wireKey := ecdsaWireKey(&privKey.PublicKey, 32)

	// Signature of wrong length.
	err = verifyECDSA([]byte("data"), []byte("short"), wireKey, dns.AlgECDSAP256)
	if err == nil {
		t.Error("expected error for wrong ECDSA signature length")
	}
	if err != errVerifyFailed {
		t.Errorf("expected errVerifyFailed, got %v", err)
	}
}

func TestVerifyECDSA_WrongSignature(t *testing.T) {
	// Generate a valid P-256 key, use correct-length but bogus signature.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	wireKey := ecdsaWireKey(&privKey.PublicKey, 32)

	err = verifyECDSA([]byte("data"), make([]byte, 64), wireKey, dns.AlgECDSAP256)
	if err == nil {
		t.Error("expected error for wrong ECDSA signature")
	}
	if err != errVerifyFailed {
		t.Errorf("expected errVerifyFailed, got %v", err)
	}
}

func TestVerifyECDSA_P384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA P-384 key: %v", err)
	}
	wireKey := ecdsaWireKey(&privKey.PublicKey, 48)

	data := []byte("test data for P-384 ECDSA")
	// hashForAlgorithm returns crypto.SHA512 for AlgECDSAP384.
	h := crypto.SHA512.New()
	h.Write(data)
	hashed := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashed)
	if err != nil {
		t.Fatalf("ECDSA sign failed: %v", err)
	}

	sigBytes := make([]byte, 96)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[48-len(rBytes):48], rBytes)
	copy(sigBytes[96-len(sBytes):96], sBytes)

	err = verifyECDSA(data, sigBytes, wireKey, dns.AlgECDSAP384)
	if err != nil {
		t.Fatalf("verifyECDSA P-384 failed: %v", err)
	}
}

func TestVerifyECDSA_P384_WrongSig(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA P-384 key: %v", err)
	}
	wireKey := ecdsaWireKey(&privKey.PublicKey, 48)

	err = verifyECDSA([]byte("data"), make([]byte, 96), wireKey, dns.AlgECDSAP384)
	if err != errVerifyFailed {
		t.Errorf("expected errVerifyFailed, got %v", err)
	}
}

func TestVerifyECDSA_UnsupportedAlgInSwitch(t *testing.T) {
	// Call verifyECDSA with an algorithm that parseECDSAPublicKey doesn't support.
	// This hits the parseECDSAPublicKey error return.
	err := verifyECDSA([]byte("data"), make([]byte, 64), make([]byte, 64), dns.AlgRSASHA256)
	if err == nil {
		t.Error("expected error for unsupported algorithm in verifyECDSA")
	}
}

// --- verifyED25519 error branches ---

func TestVerifyED25519_WrongSignatureSize(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Correct key size, wrong signature size.
	err = verifyED25519([]byte("data"), []byte("short"), []byte(pubKey))
	if err == nil {
		t.Error("expected error for wrong signature size")
	}
	if err != errVerifyFailed {
		t.Errorf("expected errVerifyFailed, got %v", err)
	}
}

// --- findMatchingDNSKEY tests ---

func TestFindMatchingDNSKEY_Found(t *testing.T) {
	// Build a DNSKEY record.
	pubKeyBytes := []byte("test-key-for-matching")
	dnskeyRData := encodeDNSKEYRData(256, 3, dns.AlgED25519, pubKeyBytes)
	dnskey, _ := dns.ParseDNSKEY(dnskeyRData)

	rrs := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeDNSKEY,
			Class: dns.ClassIN,
			TTL:   3600,
			RData: dnskeyRData,
		},
	}

	found, err := findMatchingDNSKEY(rrs, dnskey.KeyTag(), dns.AlgED25519)
	if err != nil {
		t.Fatalf("findMatchingDNSKEY failed: %v", err)
	}
	if found.KeyTag() != dnskey.KeyTag() {
		t.Errorf("key tag mismatch: got %d, want %d", found.KeyTag(), dnskey.KeyTag())
	}
}

func TestFindMatchingDNSKEY_NotFound(t *testing.T) {
	dnskeyRData := encodeDNSKEYRData(256, 3, dns.AlgED25519, []byte("test-key"))

	rrs := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeDNSKEY,
			Class: dns.ClassIN,
			TTL:   3600,
			RData: dnskeyRData,
		},
	}

	_, err := findMatchingDNSKEY(rrs, 9999, dns.AlgED25519)
	if err == nil {
		t.Error("expected error when no matching DNSKEY found")
	}
}

func TestFindMatchingDNSKEY_BadRData(t *testing.T) {
	rrs := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeDNSKEY,
			Class: dns.ClassIN,
			TTL:   3600,
			RData: []byte{0, 1}, // too short to parse
		},
	}

	_, err := findMatchingDNSKEY(rrs, 12345, dns.AlgED25519)
	if err == nil {
		t.Error("expected error when DNSKEY RData is malformed")
	}
}

func TestFindMatchingDNSKEY_WrongAlgorithm(t *testing.T) {
	pubKeyBytes := []byte("test-key-for-wrong-alg")
	dnskeyRData := encodeDNSKEYRData(256, 3, dns.AlgED25519, pubKeyBytes)
	dnskey, _ := dns.ParseDNSKEY(dnskeyRData)

	rrs := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeDNSKEY,
			Class: dns.ClassIN,
			TTL:   3600,
			RData: dnskeyRData,
		},
	}

	// Same key tag but different algorithm.
	_, err := findMatchingDNSKEY(rrs, dnskey.KeyTag(), dns.AlgRSASHA256)
	if err == nil {
		t.Error("expected error for wrong algorithm")
	}
}

// --- fetchDS tests ---

func TestFetchDS_Success(t *testing.T) {
	dsRData := encodeDSRData(12345, dns.AlgRSASHA256, dns.DigestSHA256, make([]byte, 32))
	mq := &mockQuerier{
		responses: map[string]*dns.Message{
			"example.com.|43": { // TypeDS = 43
				Answers: []dns.ResourceRecord{
					{
						Name:  "example.com.",
						Type:  dns.TypeDS,
						Class: dns.ClassIN,
						TTL:   3600,
						RData: dsRData,
					},
				},
			},
		},
	}
	v := NewValidator(mq, nil)
	dsRecords, err := v.fetchDS("example.com.", "com.")
	if err != nil {
		t.Fatalf("fetchDS failed: %v", err)
	}
	if len(dsRecords) != 1 {
		t.Errorf("expected 1 DS record, got %d", len(dsRecords))
	}
}

func TestFetchDS_QueryError(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)
	_, err := v.fetchDS("example.com.", "com.")
	if err == nil {
		t.Error("expected error when querier has no response for DS")
	}
}

func TestFetchDS_BadDSRData(t *testing.T) {
	mq := &mockQuerier{
		responses: map[string]*dns.Message{
			"example.com.|43": {
				Answers: []dns.ResourceRecord{
					{
						Name:  "example.com.",
						Type:  dns.TypeDS,
						Class: dns.ClassIN,
						TTL:   3600,
						RData: []byte{0, 1}, // too short
					},
				},
			},
		},
	}
	v := NewValidator(mq, nil)
	dsRecords, err := v.fetchDS("example.com.", "com.")
	if err != nil {
		t.Fatalf("fetchDS should not error on bad DS RData: %v", err)
	}
	if len(dsRecords) != 0 {
		t.Errorf("expected 0 DS records (bad RData skipped), got %d", len(dsRecords))
	}
}

func TestFetchDS_MixedRecords(t *testing.T) {
	dsRData := encodeDSRData(12345, dns.AlgRSASHA256, dns.DigestSHA256, make([]byte, 32))
	mq := &mockQuerier{
		responses: map[string]*dns.Message{
			"example.com.|43": {
				Answers: []dns.ResourceRecord{
					{
						Name:  "example.com.",
						Type:  dns.TypeDS,
						Class: dns.ClassIN,
						TTL:   3600,
						RData: dsRData,
					},
					{
						Name:  "example.com.",
						Type:  dns.TypeRRSIG, // not DS, should be skipped
						Class: dns.ClassIN,
						TTL:   3600,
						RData: make([]byte, 50),
					},
				},
			},
		},
	}
	v := NewValidator(mq, nil)
	dsRecords, err := v.fetchDS("example.com.", "com.")
	if err != nil {
		t.Fatalf("fetchDS failed: %v", err)
	}
	if len(dsRecords) != 1 {
		t.Errorf("expected 1 DS record, got %d", len(dsRecords))
	}
}

// --- verifyAgainstTrustAnchors tests ---

func TestVerifyAgainstTrustAnchors_Match(t *testing.T) {
	// Build a KSK DNSKEY that matches a trust anchor.
	kskPubKey := []byte("root-ksk-public-key-data-for-trust-anchor-test")
	kskRData := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, kskPubKey)
	ksk, _ := dns.ParseDNSKEY(kskRData)

	// Compute the digest for the trust anchor.
	digestInput := buildDSDigestInput(".", ksk)
	h := sha256.Sum256(digestInput)

	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)
	v.trustAnchors = []dns.DSRecord{
		{
			KeyTag:     ksk.KeyTag(),
			Algorithm:  dns.AlgRSASHA256,
			DigestType: dns.DigestSHA256,
			Digest:     h[:],
		},
	}

	dnskeys := []dns.ResourceRecord{
		{
			Name:  ".",
			Type:  dns.TypeDNSKEY,
			Class: dns.ClassIN,
			TTL:   3600,
			RData: kskRData,
		},
	}

	if !v.verifyAgainstTrustAnchors(".", dnskeys) {
		t.Error("verifyAgainstTrustAnchors should return true for matching KSK")
	}
}

func TestVerifyAgainstTrustAnchors_NoMatch(t *testing.T) {
	kskRData := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, []byte("some-key"))
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)
	v.trustAnchors = []dns.DSRecord{
		{
			KeyTag:     9999,
			Algorithm:  dns.AlgRSASHA256,
			DigestType: dns.DigestSHA256,
			Digest:     make([]byte, 32),
		},
	}

	dnskeys := []dns.ResourceRecord{
		{
			Name:  ".",
			Type:  dns.TypeDNSKEY,
			Class: dns.ClassIN,
			TTL:   3600,
			RData: kskRData,
		},
	}

	if v.verifyAgainstTrustAnchors(".", dnskeys) {
		t.Error("verifyAgainstTrustAnchors should return false when no anchor matches")
	}
}

func TestVerifyAgainstTrustAnchors_BadRData(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	dnskeys := []dns.ResourceRecord{
		{Name: ".", Type: dns.TypeDNSKEY, RData: []byte{0}}, // too short
	}

	if v.verifyAgainstTrustAnchors(".", dnskeys) {
		t.Error("verifyAgainstTrustAnchors should return false with bad RData")
	}
}

func TestVerifyAgainstTrustAnchors_ZSKIgnored(t *testing.T) {
	// ZSK (flags=256, not KSK) should be skipped.
	zskRData := encodeDNSKEYRData(256, 3, dns.AlgRSASHA256, []byte("zsk-key"))

	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	dnskeys := []dns.ResourceRecord{
		{Name: ".", Type: dns.TypeDNSKEY, RData: zskRData},
	}

	if v.verifyAgainstTrustAnchors(".", dnskeys) {
		t.Error("verifyAgainstTrustAnchors should skip ZSKs")
	}
}

// --- verifyDNSKEYWithDS tests ---

func TestVerifyDNSKEYWithDS_Match(t *testing.T) {
	kskPubKey := []byte("ksk-public-key-for-ds-verification")
	kskRData := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, kskPubKey)
	ksk, _ := dns.ParseDNSKEY(kskRData)

	digestInput := buildDSDigestInput("example.com.", ksk)
	h := sha256.Sum256(digestInput)

	dsRecords := []*dns.DSRecord{
		{
			KeyTag:     ksk.KeyTag(),
			Algorithm:  dns.AlgRSASHA256,
			DigestType: dns.DigestSHA256,
			Digest:     h[:],
		},
	}

	dnskeys := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeDNSKEY, RData: kskRData},
	}

	if !verifyDNSKEYWithDS(dnskeys, dsRecords, "example.com.") {
		t.Error("verifyDNSKEYWithDS should return true for matching KSK + DS")
	}
}

func TestVerifyDNSKEYWithDS_NoMatch(t *testing.T) {
	kskRData := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, []byte("ksk-key"))
	dsRecords := []*dns.DSRecord{
		{
			KeyTag:     9999,
			Algorithm:  dns.AlgRSASHA256,
			DigestType: dns.DigestSHA256,
			Digest:     make([]byte, 32),
		},
	}

	dnskeys := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeDNSKEY, RData: kskRData},
	}

	if verifyDNSKEYWithDS(dnskeys, dsRecords, "example.com.") {
		t.Error("verifyDNSKEYWithDS should return false when no KSK matches DS")
	}
}

func TestVerifyDNSKEYWithDS_BadRData(t *testing.T) {
	dsRecords := []*dns.DSRecord{
		{KeyTag: 1, Algorithm: dns.AlgRSASHA256, DigestType: dns.DigestSHA256, Digest: make([]byte, 32)},
	}
	dnskeys := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeDNSKEY, RData: []byte{0}}, // too short
	}

	if verifyDNSKEYWithDS(dnskeys, dsRecords, "example.com.") {
		t.Error("verifyDNSKEYWithDS should return false with bad RData")
	}
}

func TestVerifyDNSKEYWithDS_ZSKIgnored(t *testing.T) {
	zskRData := encodeDNSKEYRData(256, 3, dns.AlgRSASHA256, []byte("zsk-key"))
	dsRecords := []*dns.DSRecord{
		{KeyTag: 1, Algorithm: dns.AlgRSASHA256, DigestType: dns.DigestSHA256, Digest: make([]byte, 32)},
	}
	dnskeys := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeDNSKEY, RData: zskRData},
	}

	if verifyDNSKEYWithDS(dnskeys, dsRecords, "example.com.") {
		t.Error("verifyDNSKEYWithDS should skip ZSKs")
	}
}

// --- fetchDNSKEYs TTL zero branch ---

func TestFetchDNSKEYs_ZeroTTL(t *testing.T) {
	dnskeyRData := encodeDNSKEYRData(256, 3, dns.AlgED25519, make([]byte, 32))
	mq := &mockQuerier{
		responses: map[string]*dns.Message{
			"example.com.|48": {
				Answers: []dns.ResourceRecord{
					{
						Name:  "example.com.",
						Type:  dns.TypeDNSKEY,
						Class: dns.ClassIN,
						TTL:   0, // zero TTL - should use default
						RData: dnskeyRData,
					},
				},
			},
		},
	}
	v := NewValidator(mq, nil)
	keys, err := v.fetchDNSKEYs("example.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYs failed: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 DNSKEY, got %d", len(keys))
	}
}

// --- validateTrustChain tests ---

// buildTestInfrastructure creates a full mock DNS infrastructure with a root KSK,
// and returns the validator and relevant structures for testing the trust chain.
type testInfra struct {
	mq       *mockQuerier
	v        *Validator
	rootKSK  *dns.DNSKEYRecord
	rootKSKR []byte // RDATA
}

func newTestInfra() *testInfra {
	ti := &testInfra{}
	ti.mq = &mockQuerier{responses: make(map[string]*dns.Message)}

	// Build root KSK.
	rootKSKPub := []byte("root-ksk-key-for-trust-chain-tests!!")
	ti.rootKSKR = encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, rootKSKPub)
	ti.rootKSK, _ = dns.ParseDNSKEY(ti.rootKSKR)

	// Compute trust anchor digest.
	digestInput := buildDSDigestInput(".", ti.rootKSK)
	h := sha256.Sum256(digestInput)

	ti.v = NewValidator(ti.mq, nil)
	ti.v.trustAnchors = []dns.DSRecord{
		{
			KeyTag:     ti.rootKSK.KeyTag(),
			Algorithm:  dns.AlgRSASHA256,
			DigestType: dns.DigestSHA256,
			Digest:     h[:],
		},
	}

	return ti
}

// setRootDNSKEYs sets the root DNSKEY response in the mock.
func (ti *testInfra) setRootDNSKEYs() {
	ti.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: ti.rootKSKR},
		},
	}
}

func TestValidateTrustChain_RootOnly(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	result := ti.v.validateTrustChain(".", []dns.ResourceRecord{
		{Name: ".", Type: dns.TypeDNSKEY, RData: ti.rootKSKR},
	})
	if result != Secure {
		t.Errorf("validateTrustChain for root: got %v, want Secure", result)
	}
}

func TestValidateTrustChain_RootMismatch(t *testing.T) {
	ti := newTestInfra()
	// Set root DNSKEY to something different from the trust anchor.
	wrongKSKR := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, []byte("wrong-root-key"))
	ti.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: wrongKSKR},
		},
	}

	result := ti.v.validateTrustChain(".", nil)
	if result != Bogus {
		t.Errorf("validateTrustChain with wrong root KSK: got %v, want Bogus", result)
	}
}

func TestValidateTrustChain_FetchError(t *testing.T) {
	ti := newTestInfra()
	// No mock responses set, so fetching root DNSKEY will fail.

	result := ti.v.validateTrustChain(".", nil)
	if result != Indeterminate {
		t.Errorf("validateTrustChain with fetch error: got %v, want Indeterminate", result)
	}
}

func TestValidateTrustChain_TLDWithDS(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	// Build a KSK for "com." zone.
	comKSKPub := []byte("com-ksk-public-key-data-for-chain")
	comKSKR := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, comKSKPub)
	comKSK, _ := dns.ParseDNSKEY(comKSKR)

	// Set DNSKEY response for com.
	ti.mq.responses["com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: comKSKR},
		},
	}

	// Build DS record for com. that matches comKSK.
	digestInput := buildDSDigestInput("com.", comKSK)
	h := sha256.Sum256(digestInput)
	dsRData := encodeDSRData(comKSK.KeyTag(), dns.AlgRSASHA256, dns.DigestSHA256, h[:])

	// Set DS response for com. (queried from parent = root).
	ti.mq.responses["com.|43"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "com.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600, RData: dsRData},
		},
	}

	result := ti.v.validateTrustChain("com.", nil)
	if result != Secure {
		t.Errorf("validateTrustChain for com.: got %v, want Secure", result)
	}
}

func TestValidateTrustChain_TLDNoDSInsecure(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	comKSKR := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, []byte("com-key"))
	ti.mq.responses["com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: comKSKR},
		},
	}

	// DS response with no DS records -> insecure delegation.
	ti.mq.responses["com.|43"] = &dns.Message{
		Answers: []dns.ResourceRecord{},
	}

	result := ti.v.validateTrustChain("com.", nil)
	if result != Insecure {
		t.Errorf("validateTrustChain with no DS: got %v, want Insecure", result)
	}
}

func TestValidateTrustChain_DSFetchError(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	comKSKR := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, []byte("com-key"))
	ti.mq.responses["com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: comKSKR},
		},
	}
	// No DS response set -> fetch error.

	result := ti.v.validateTrustChain("com.", nil)
	if result != Indeterminate {
		t.Errorf("validateTrustChain with DS fetch error: got %v, want Indeterminate", result)
	}
}

func TestValidateTrustChain_DSMismatch(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	comKSKR := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, []byte("com-key"))
	ti.mq.responses["com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: comKSKR},
		},
	}

	// DS record that doesn't match the com. KSK.
	bogusDS := encodeDSRData(9999, dns.AlgRSASHA256, dns.DigestSHA256, make([]byte, 32))
	ti.mq.responses["com.|43"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "com.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600, RData: bogusDS},
		},
	}

	result := ti.v.validateTrustChain("com.", nil)
	if result != Bogus {
		t.Errorf("validateTrustChain with DS mismatch: got %v, want Bogus", result)
	}
}

func TestValidateTrustChain_ChainFetchDNSKEYError(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()
	// No DNSKEY response for com. -> will fail in the for loop at i=1.

	// DS response for com. is set, but DNSKEY fetch for com. will fail.
	// Actually the fetch happens first. The code fetches DNSKEY for each chain zone.
	// Since there's no "com.|48" response, it will return Indeterminate.

	result := ti.v.validateTrustChain("com.", nil)
	if result != Indeterminate {
		t.Errorf("validateTrustChain with DNSKEY fetch error at com.: got %v, want Indeterminate", result)
	}
}

// --- ValidateResponse full path tests ---

// validatorTestSetup builds a complete test infrastructure for ValidateResponse
// using Ed25519 for simplicity.
type fullTestSetup struct {
	mq       *mockQuerier
	v        *Validator
	privKey  ed25519.PrivateKey
	pubKey   ed25519.PublicKey
	dnskey   *dns.DNSKEYRecord
	wireKey  []byte
	zskRData []byte
}

func newFullTestSetup(t *testing.T) *fullTestSetup {
	t.Helper()
	s := &fullTestSetup{}
	s.mq = &mockQuerier{responses: make(map[string]*dns.Message)}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	s.privKey = priv
	s.pubKey = pub
	s.wireKey = []byte(pub)
	s.zskRData = encodeDNSKEYRData(256, 3, dns.AlgED25519, s.wireKey)
	s.dnskey, _ = dns.ParseDNSKEY(s.zskRData)

	// Build root KSK matching the trust anchor.
	rootKSKPub := []byte("root-ksk-key-for-full-validate-test!!")
	rootKSKR := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, rootKSKPub)
	rootKSK, _ := dns.ParseDNSKEY(rootKSKR)
	digestInput := buildDSDigestInput(".", rootKSK)
	h := sha256.Sum256(digestInput)

	s.v = NewValidator(s.mq, nil)
	s.v.trustAnchors = []dns.DSRecord{
		{
			KeyTag:     rootKSK.KeyTag(),
			Algorithm:  dns.AlgRSASHA256,
			DigestType: dns.DigestSHA256,
			Digest:     h[:],
		},
	}

	// Set root DNSKEY response.
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
		},
	}

	return s
}

// signRRSet signs an RRset and returns the RRSIG with valid time bounds.
func (s *fullTestSetup) signRRSet(t *testing.T, rrset []dns.ResourceRecord, signerName string) *dns.RRSIGRecord {
	t.Helper()
	rrsig := &dns.RRSIGRecord{
		TypeCovered: rrset[0].Type,
		Algorithm:   dns.AlgED25519,
		Labels:      uint8(strings.Count(strings.TrimSuffix(signerName, "."), ".") + 1),
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  signerName,
	}
	signedData := buildSignedData(rrset, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)
	return rrsig
}

func TestValidateResponse_SecureRootZone(t *testing.T) {
	s := newFullTestSetup(t)

	// The signer zone is ".". We need the DNSKEY for "." to include our ZSK.
	// We already have root KSK; we need to add the ZSK to the root DNSKEY response.
	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	rrset := []dns.ResourceRecord{
		{Name: ".", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := s.signRRSet(t, rrset, ".")

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name:  ".",
			Type:  dns.TypeRRSIG,
			Class: dns.ClassIN,
			TTL:   300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	result := s.v.ValidateResponse(resp, ".", dns.TypeA)
	if result != Secure {
		t.Errorf("ValidateResponse for root zone: got %v, want Secure", result)
	}
}

func TestValidateResponse_RRSIGNotYetValid(t *testing.T) {
	s := newFullTestSetup(t)

	s.mq.responses["example.com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0xFFFFFFFE, // Far in the future.
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
	}
	signedData := buildSignedData(rrset, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	result := s.v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Bogus {
		t.Errorf("ValidateResponse with not-yet-valid RRSIG: got %v, want Bogus", result)
	}
}

func TestValidateResponse_RRSIGExpired(t *testing.T) {
	s := newFullTestSetup(t)

	s.mq.responses["example.com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  1, // Already expired.
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
	}
	signedData := buildSignedData(rrset, rrsig)
	rrsig.Signature = ed25519.Sign(s.privKey, signedData)

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	result := s.v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Bogus {
		t.Errorf("ValidateResponse with expired RRSIG: got %v, want Bogus", result)
	}
}

func TestValidateResponse_FetchDNSKEYError(t *testing.T) {
	s := newFullTestSetup(t)
	// No DNSKEY response for example.com. -> fetch error.

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := s.signRRSet(t, rrset, "example.com.")

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	result := s.v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Indeterminate {
		t.Errorf("ValidateResponse with DNSKEY fetch error: got %v, want Indeterminate", result)
	}
}

func TestValidateResponse_NoMatchingDNSKEY(t *testing.T) {
	s := newFullTestSetup(t)

	// Set a DNSKEY with a different key tag.
	otherRData := encodeDNSKEYRData(256, 3, dns.AlgED25519, make([]byte, 32))
	s.mq.responses["example.com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: otherRData},
		},
	}

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := s.signRRSet(t, rrset, "example.com.")

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	result := s.v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Indeterminate {
		t.Errorf("ValidateResponse with no matching DNSKEY: got %v, want Indeterminate", result)
	}
}

func TestValidateResponse_SignatureVerificationFails(t *testing.T) {
	s := newFullTestSetup(t)

	s.mq.responses["example.com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
		Signature:   make([]byte, ed25519.SignatureSize), // bogus
	}

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	result := s.v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Bogus {
		t.Errorf("ValidateResponse with bad signature: got %v, want Bogus", result)
	}
}

func TestValidateResponse_TrustChainFailure(t *testing.T) {
	s := newFullTestSetup(t)

	s.mq.responses["example.com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := s.signRRSet(t, rrset, "example.com.")

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	// Trust chain will fail at com. level (no DNSKEY for com.)
	// First it validates root (OK), then tries com. DNSKEY -> error.
	// Actually: the trust chain starts at root, validates root KSK against trust anchors.
	// Then for "com.", it needs to fetchDNSKEYs("com.") which will fail -> Indeterminate.
	result := s.v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Indeterminate {
		t.Errorf("ValidateResponse with trust chain failure: got %v, want Indeterminate", result)
	}
}

func TestValidateResponse_NoMatchingRRsForRRSIG(t *testing.T) {
	s := newFullTestSetup(t)

	// RRSIG covers TypeAAAA but answer only has TypeA.
	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeAAAA, // No AAAA in answers.
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	result := s.v.ValidateResponse(resp, "example.com.", dns.TypeA)
	// The RRSIG covers AAAA but there are no AAAA RRs, so it's skipped -> no valid RRSIG -> Indeterminate.
	if result != Indeterminate {
		t.Errorf("ValidateResponse with no matching RRs: got %v, want Indeterminate", result)
	}
}

func TestValidateResponse_OnlyRRSIG(t *testing.T) {
	s := newFullTestSetup(t)

	// Response with only RRSIG records (all parsed OK), but the RRSIG covers TypeA
	// and there are no TypeA answer records.
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	resp := &dns.Message{
		Answers: []dns.ResourceRecord{
			{
				Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
				RData: buildRRSIGRData(rrsig),
			},
		},
	}

	result := s.v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Indeterminate {
		t.Errorf("ValidateResponse with only RRSIG, no actual RRs: got %v, want Indeterminate", result)
	}
}

func TestValidateResponse_ValidParsedRRSIGAppended(t *testing.T) {
	// Test that successfully parsed RRSIG records are appended to the rrsigs list.
	// Response with both a valid and an invalid RRSIG. The valid one covers AAAA
	// (no actual AAAA records), so it gets skipped. The invalid one is also skipped.
	// Net result: Indeterminate because the valid RRSIG has no matching RRs.
	s := newFullTestSetup(t)

	validRRSIG := &dns.RRSIGRecord{
		TypeCovered: dns.TypeAAAA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      s.dnskey.KeyTag(),
		SignerName:  "example.com.",
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	resp := &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
			{Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: []byte{0, 1, 2}}, // malformed
			{Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300, RData: buildRRSIGRData(validRRSIG)},
		},
	}

	result := s.v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Indeterminate {
		t.Errorf("got %v, want Indeterminate", result)
	}
}

// --- ValidateResponse secure with full trust chain (example.com.) ---

func TestValidateResponse_FullTrustChainSecure(t *testing.T) {
	s := newFullTestSetup(t)

	// Build KSK for "com." zone.
	comKSKPub := []byte("com-ksk-public-key-data-for-full-chain!")
	comKSKR := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, comKSKPub)
	comKSK, _ := dns.ParseDNSKEY(comKSKR)

	// DS for com. at root.
	comDSInput := buildDSDigestInput("com.", comKSK)
	comDSHash := sha256.Sum256(comDSInput)
	comDSRData := encodeDSRData(comKSK.KeyTag(), dns.AlgRSASHA256, dns.DigestSHA256, comDSHash[:])

	// Build KSK for "example.com." zone.
	exKSKPub := []byte("example-com-ksk-public-key-data!!")
	exKSKR := encodeDNSKEYRData(257, 3, dns.AlgRSASHA256, exKSKPub)
	exKSK, _ := dns.ParseDNSKEY(exKSKR)

	// DS for example.com. at com.
	exDSInput := buildDSDigestInput("example.com.", exKSK)
	exDSHash := sha256.Sum256(exDSInput)
	exDSRData := encodeDSRData(exKSK.KeyTag(), dns.AlgRSASHA256, dns.DigestSHA256, exDSHash[:])

	// Set up mock responses.
	rootKSKR := s.mq.responses[".|48"].Answers[0].RData
	s.mq.responses[".|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: ".", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: rootKSKR},
		},
	}
	s.mq.responses["com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: comKSKR},
		},
	}
	s.mq.responses["com.|43"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "com.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600, RData: comDSRData},
		},
	}
	s.mq.responses["example.com.|48"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: exKSKR},
			{Name: "example.com.", Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: s.zskRData},
		},
	}
	s.mq.responses["example.com.|43"] = &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "example.com.", Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600, RData: exDSRData},
		},
	}

	// Build the response to validate.
	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{93, 184, 216, 34}},
	}
	rrsig := s.signRRSet(t, rrset, "example.com.")

	resp := &dns.Message{
		Answers: append(rrset, dns.ResourceRecord{
			Name: "example.com.", Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 300,
			RData: buildRRSIGRData(rrsig),
		}),
	}

	result := s.v.ValidateResponse(resp, "example.com.", dns.TypeA)
	if result != Secure {
		t.Errorf("ValidateResponse full trust chain: got %v, want Secure", result)
	}
}

// --- verifyRSA with RSASHA1 and RSASHA512 ---

func TestVerifyRSA_SHA1(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	wireKey := rsaWireKey(&privKey.PublicKey)

	data := []byte("test data for RSA-SHA1")
	h := crypto.SHA1.New()
	h.Write(data)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA1, hashed)
	if err != nil {
		t.Fatalf("RSA sign failed: %v", err)
	}

	err = verifyRSA(data, signature, wireKey, dns.AlgRSASHA1)
	if err != nil {
		t.Fatalf("verifyRSA with SHA1 failed: %v", err)
	}
}

func TestVerifyRSA_SHA512(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	wireKey := rsaWireKey(&privKey.PublicKey)

	data := []byte("test data for RSA-SHA512")
	h := crypto.SHA512.New()
	h.Write(data)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, hashed)
	if err != nil {
		t.Fatalf("RSA sign failed: %v", err)
	}

	err = verifyRSA(data, signature, wireKey, dns.AlgRSASHA512)
	if err != nil {
		t.Fatalf("verifyRSA with SHA512 failed: %v", err)
	}
}

// --- VerifyRRSIG with ECDSA P-384 ---

func TestVerifyRRSIG_ECDSA_P384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA P-384 key: %v", err)
	}
	wireKey := ecdsaWireKey(&privKey.PublicKey, 48)

	dnskey := &dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.AlgECDSAP384,
		PublicKey: wireKey,
	}

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{93, 184, 216, 34}},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgECDSAP384,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  "example.com.",
	}

	signedData := buildSignedData(rrset, rrsig)
	// hashForAlgorithm returns crypto.SHA512 for AlgECDSAP384.
	hasher := crypto.SHA512.New()
	hasher.Write(signedData)
	hashed := hasher.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashed)
	if err != nil {
		t.Fatalf("ECDSA P-384 sign failed: %v", err)
	}

	sigBytes := make([]byte, 96)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[48-len(rBytes):48], rBytes)
	copy(sigBytes[96-len(sBytes):96], sBytes)
	rrsig.Signature = sigBytes

	err = VerifyRRSIG(rrset, rrsig, dnskey)
	if err != nil {
		t.Fatalf("VerifyRRSIG (ECDSA P-384) failed: %v", err)
	}
}

// --- VerifyRRSIG with RSA-SHA1 ---

func TestVerifyRRSIG_RSA_SHA1(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	wireKey := rsaWireKey(&privKey.PublicKey)

	dnskey := &dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA1,
		PublicKey: wireKey,
	}

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgRSASHA1,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  "example.com.",
	}

	signedData := buildSignedData(rrset, rrsig)
	h := crypto.SHA1.New()
	h.Write(signedData)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA1, hashed)
	if err != nil {
		t.Fatalf("RSA-SHA1 sign failed: %v", err)
	}
	rrsig.Signature = signature

	err = VerifyRRSIG(rrset, rrsig, dnskey)
	if err != nil {
		t.Fatalf("VerifyRRSIG (RSA-SHA1) failed: %v", err)
	}
}

// --- VerifyRRSIG with RSA-SHA512 ---

func TestVerifyRRSIG_RSA_SHA512(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	wireKey := rsaWireKey(&privKey.PublicKey)

	dnskey := &dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA512,
		PublicKey: wireKey,
	}

	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgRSASHA512,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  "example.com.",
	}

	signedData := buildSignedData(rrset, rrsig)
	h := crypto.SHA512.New()
	h.Write(signedData)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, hashed)
	if err != nil {
		t.Fatalf("RSA-SHA512 sign failed: %v", err)
	}
	rrsig.Signature = signature

	err = VerifyRRSIG(rrset, rrsig, dnskey)
	if err != nil {
		t.Fatalf("VerifyRRSIG (RSA-SHA512) failed: %v", err)
	}
}

// --- mockQuerier that returns errors for specific queries ---

type errorQuerier struct {
	responses map[string]*dns.Message
	errors    map[string]error
}

func (eq *errorQuerier) QueryDNSSEC(name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	key := fmt.Sprintf("%s|%d", name, qtype)
	if err, ok := eq.errors[key]; ok {
		return nil, err
	}
	if resp, ok := eq.responses[key]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("no mock response for %s type %d", name, qtype)
}

func TestFetchDNSKEYs_NoMatchingRecordsInResponse(t *testing.T) {
	// Response has records but none are DNSKEY.
	mq := &mockQuerier{
		responses: map[string]*dns.Message{
			"example.com.|48": {
				Answers: []dns.ResourceRecord{
					{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
				},
			},
		},
	}
	v := NewValidator(mq, nil)
	keys, err := v.fetchDNSKEYs("example.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYs should not error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 DNSKEY records, got %d", len(keys))
	}
}

func TestFetchDNSKEYs_LowTTL(t *testing.T) {
	// Test the branch where rr.TTL > 0 && rr.TTL < minTTL (3600 default).
	dnskeyRData := encodeDNSKEYRData(256, 3, dns.AlgED25519, make([]byte, 32))
	mq := &mockQuerier{
		responses: map[string]*dns.Message{
			"lowttl.com.|48": {
				Answers: []dns.ResourceRecord{
					{
						Name:  "lowttl.com.",
						Type:  dns.TypeDNSKEY,
						Class: dns.ClassIN,
						TTL:   60, // TTL > 0 and < 3600 (default minTTL)
						RData: dnskeyRData,
					},
				},
			},
		},
	}
	v := NewValidator(mq, nil)
	keys, err := v.fetchDNSKEYs("lowttl.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYs failed: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 DNSKEY, got %d", len(keys))
	}
}

func TestVerifyRSA_UnsupportedHashAlgorithm(t *testing.T) {
	// Call verifyRSA with a valid RSA key but an algorithm that hashForAlgorithm
	// does not support. This covers the hashForAlgorithm error branch in verifyRSA.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	wireKey := rsaWireKey(&privKey.PublicKey)

	err = verifyRSA([]byte("data"), []byte("sig"), wireKey, 99) // unsupported algorithm
	if err == nil {
		t.Error("expected error for unsupported algorithm in verifyRSA")
	}
	if err != errUnsupportedAlg {
		t.Errorf("expected errUnsupportedAlg, got %v", err)
	}
}
