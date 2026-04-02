package dnssec

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// buildDSDigestInput builds the digest input for a DS record:
// canonical owner name wire form + DNSKEY RDATA (flags + protocol + algorithm + public key).
func buildDSDigestInput(ownerName string, dnskey *dns.DNSKEYRecord) []byte {
	nameWire := canonicalNameWire(ownerName)
	dnskeyRData := make([]byte, 4+len(dnskey.PublicKey))
	binary.BigEndian.PutUint16(dnskeyRData[0:2], dnskey.Flags)
	dnskeyRData[2] = dnskey.Protocol
	dnskeyRData[3] = dnskey.Algorithm
	copy(dnskeyRData[4:], dnskey.PublicKey)

	input := make([]byte, len(nameWire)+len(dnskeyRData))
	copy(input, nameWire)
	copy(input[len(nameWire):], dnskeyRData)
	return input
}

func TestVerifyDS_SHA256(t *testing.T) {
	dnskey := &dns.DNSKEYRecord{
		Flags:     257, // KSK
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("test-public-key-data-for-sha256-verification"),
	}

	ownerName := "example.com."

	// Compute the expected SHA-256 digest.
	digestInput := buildDSDigestInput(ownerName, dnskey)
	h := sha256.Sum256(digestInput)

	ds := &dns.DSRecord{
		KeyTag:     dnskey.KeyTag(),
		Algorithm:  dns.AlgRSASHA256,
		DigestType: dns.DigestSHA256,
		Digest:     h[:],
	}

	if !VerifyDS(dnskey, ds, ownerName) {
		t.Error("VerifyDS with correct SHA-256 digest should return true")
	}
}

func TestVerifyDS_SHA1(t *testing.T) {
	dnskey := &dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("test-public-key-data-for-sha1-verification"),
	}

	ownerName := "example.com."

	digestInput := buildDSDigestInput(ownerName, dnskey)
	h := sha1.Sum(digestInput)

	ds := &dns.DSRecord{
		KeyTag:     dnskey.KeyTag(),
		Algorithm:  dns.AlgRSASHA256,
		DigestType: dns.DigestSHA1,
		Digest:     h[:],
	}

	if !VerifyDS(dnskey, ds, ownerName) {
		t.Error("VerifyDS with correct SHA-1 digest should return true")
	}
}

func TestVerifyDS_WrongDigest(t *testing.T) {
	dnskey := &dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("test-public-key-data"),
	}

	ownerName := "example.com."

	// Use a wrong digest (all zeros).
	ds := &dns.DSRecord{
		KeyTag:     dnskey.KeyTag(),
		Algorithm:  dns.AlgRSASHA256,
		DigestType: dns.DigestSHA256,
		Digest:     make([]byte, 32),
	}

	if VerifyDS(dnskey, ds, ownerName) {
		t.Error("VerifyDS with wrong digest should return false")
	}
}

func TestVerifyDS_WrongKeyTag(t *testing.T) {
	dnskey := &dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("test-public-key-data"),
	}

	ownerName := "example.com."

	digestInput := buildDSDigestInput(ownerName, dnskey)
	h := sha256.Sum256(digestInput)

	ds := &dns.DSRecord{
		KeyTag:     dnskey.KeyTag() + 1, // wrong key tag
		Algorithm:  dns.AlgRSASHA256,
		DigestType: dns.DigestSHA256,
		Digest:     h[:],
	}

	if VerifyDS(dnskey, ds, ownerName) {
		t.Error("VerifyDS with wrong key tag should return false")
	}
}

func TestVerifyDS_WrongAlgorithm(t *testing.T) {
	dnskey := &dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("test-public-key-data"),
	}

	ownerName := "example.com."

	digestInput := buildDSDigestInput(ownerName, dnskey)
	h := sha256.Sum256(digestInput)

	ds := &dns.DSRecord{
		KeyTag:     dnskey.KeyTag(),
		Algorithm:  dns.AlgED25519, // wrong algorithm
		DigestType: dns.DigestSHA256,
		Digest:     h[:],
	}

	if VerifyDS(dnskey, ds, ownerName) {
		t.Error("VerifyDS with wrong algorithm should return false")
	}
}

func TestVerifyDS_UnknownDigestType(t *testing.T) {
	dnskey := &dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("test-public-key-data"),
	}

	ownerName := "example.com."

	ds := &dns.DSRecord{
		KeyTag:     dnskey.KeyTag(),
		Algorithm:  dns.AlgRSASHA256,
		DigestType: 99, // unknown digest type
		Digest:     make([]byte, 32),
	}

	if VerifyDS(dnskey, ds, ownerName) {
		t.Error("VerifyDS with unknown digest type should return false")
	}
}

func TestVerifyDS_DifferentOwnerNames(t *testing.T) {
	dnskey := &dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("test-public-key-data-owner-name-test"),
	}

	ownerName := "example.com."

	// Compute correct digest for example.com.
	digestInput := buildDSDigestInput(ownerName, dnskey)
	h := sha256.Sum256(digestInput)

	ds := &dns.DSRecord{
		KeyTag:     dnskey.KeyTag(),
		Algorithm:  dns.AlgRSASHA256,
		DigestType: dns.DigestSHA256,
		Digest:     h[:],
	}

	// Should pass with the correct owner name.
	if !VerifyDS(dnskey, ds, ownerName) {
		t.Error("VerifyDS should succeed with correct owner name")
	}

	// Should fail with a different owner name (different digest input).
	if VerifyDS(dnskey, ds, "other.com.") {
		t.Error("VerifyDS should fail with wrong owner name")
	}
}

func TestVerifyDS_CaseInsensitiveOwnerName(t *testing.T) {
	dnskey := &dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: []byte("test-public-key-data-case-test"),
	}

	// Compute digest with lowercase name.
	digestInput := buildDSDigestInput("example.com.", dnskey)
	h := sha256.Sum256(digestInput)

	ds := &dns.DSRecord{
		KeyTag:     dnskey.KeyTag(),
		Algorithm:  dns.AlgRSASHA256,
		DigestType: dns.DigestSHA256,
		Digest:     h[:],
	}

	// Should work with different cases because canonicalNameWire lowercases.
	if !VerifyDS(dnskey, ds, "Example.COM.") {
		t.Error("VerifyDS should be case-insensitive for owner name")
	}

	if !VerifyDS(dnskey, ds, "EXAMPLE.COM.") {
		t.Error("VerifyDS should be case-insensitive for owner name (all caps)")
	}
}
