package dnssec

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestCanonicalNameWire(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "root domain",
			input:    ".",
			expected: []byte{0x00},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []byte{0x00},
		},
		{
			name:  "simple domain with trailing dot",
			input: "example.com.",
			expected: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				3, 'c', 'o', 'm',
				0x00,
			},
		},
		{
			name:  "simple domain without trailing dot",
			input: "example.com",
			expected: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				3, 'c', 'o', 'm',
				0x00,
			},
		},
		{
			name:  "mixed case is lowercased",
			input: "Example.COM.",
			expected: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				3, 'c', 'o', 'm',
				0x00,
			},
		},
		{
			name:  "subdomain",
			input: "www.Example.COM.",
			expected: []byte{
				3, 'w', 'w', 'w',
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				3, 'c', 'o', 'm',
				0x00,
			},
		},
		{
			name:  "single label",
			input: "com.",
			expected: []byte{
				3, 'c', 'o', 'm',
				0x00,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canonicalNameWire(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("canonicalNameWire(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	// Generate a test RSA key pair.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubKey := &privKey.PublicKey

	// Encode the public key in DNSKEY wire format (RFC 3110):
	// exponent_length(1 or 3 bytes) + exponent + modulus
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

	parsed, err := parseRSAPublicKey(wireKey)
	if err != nil {
		t.Fatalf("parseRSAPublicKey failed: %v", err)
	}

	if parsed.E != pubKey.E {
		t.Errorf("exponent mismatch: got %d, want %d", parsed.E, pubKey.E)
	}
	if parsed.N.Cmp(pubKey.N) != 0 {
		t.Error("modulus mismatch")
	}
}

func TestParseRSAPublicKey_Errors(t *testing.T) {
	tests := []struct {
		name    string
		keyData []byte
	}{
		{"too short", []byte{1, 2}},
		{"zero prefix too short", []byte{0, 0, 3}},
		{"exponent exceeds data", []byte{10, 1, 2, 3}},
		{"empty modulus", []byte{1, 65}}, // expLen=1, exp=65, mod=empty
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRSAPublicKey(tt.keyData)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestParseECDSAPublicKey_P256(t *testing.T) {
	// Generate a P-256 key pair.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	pubKey := &privKey.PublicKey

	// Encode as DNSKEY wire format: raw x || y coordinates, 32 bytes each for P-256.
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	// Pad to 32 bytes each.
	wireKey := make([]byte, 64)
	copy(wireKey[32-len(xBytes):32], xBytes)
	copy(wireKey[64-len(yBytes):64], yBytes)

	parsed, err := parseECDSAPublicKey(wireKey, dns.AlgECDSAP256)
	if err != nil {
		t.Fatalf("parseECDSAPublicKey failed: %v", err)
	}

	if parsed.X.Cmp(pubKey.X) != 0 {
		t.Error("X coordinate mismatch")
	}
	if parsed.Y.Cmp(pubKey.Y) != 0 {
		t.Error("Y coordinate mismatch")
	}
	if parsed.Curve != elliptic.P256() {
		t.Error("curve mismatch")
	}
}

func TestParseECDSAPublicKey_P384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	pubKey := &privKey.PublicKey

	// 48 bytes each for P-384.
	wireKey := make([]byte, 96)
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	copy(wireKey[48-len(xBytes):48], xBytes)
	copy(wireKey[96-len(yBytes):96], yBytes)

	parsed, err := parseECDSAPublicKey(wireKey, dns.AlgECDSAP384)
	if err != nil {
		t.Fatalf("parseECDSAPublicKey failed: %v", err)
	}

	if parsed.X.Cmp(pubKey.X) != 0 {
		t.Error("X coordinate mismatch")
	}
	if parsed.Y.Cmp(pubKey.Y) != 0 {
		t.Error("Y coordinate mismatch")
	}
	if parsed.Curve != elliptic.P384() {
		t.Error("curve mismatch")
	}
}

func TestParseECDSAPublicKey_Errors(t *testing.T) {
	tests := []struct {
		name      string
		keyData   []byte
		algorithm uint8
	}{
		{"wrong length for P-256", make([]byte, 63), dns.AlgECDSAP256},
		{"wrong length for P-384", make([]byte, 95), dns.AlgECDSAP384},
		{"unsupported algorithm", make([]byte, 64), dns.AlgRSASHA256},
		{"invalid point on P-256", make([]byte, 64), dns.AlgECDSAP256}, // all zeros is not on curve
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseECDSAPublicKey(tt.keyData, tt.algorithm)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestHashForAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm uint8
		expected  crypto.Hash
		wantErr   bool
	}{
		{"RSASHA1", dns.AlgRSASHA1, crypto.SHA1, false},
		{"RSASHA256", dns.AlgRSASHA256, crypto.SHA256, false},
		{"RSASHA512", dns.AlgRSASHA512, crypto.SHA512, false},
		{"ECDSAP256", dns.AlgECDSAP256, crypto.SHA256, false},
		// RFC 6605 §2.1: algorithm 14 (ECDSA P-384) MUST use SHA-384.
		// The earlier table here mistakenly expected SHA-512, which locked in
		// the bug that made every fedoraproject.org-style algorithm-14 zone
		// validate Bogus.
		{"ECDSAP384", dns.AlgECDSAP384, crypto.SHA384, false},
		{"ED25519", dns.AlgED25519, 0, false},
		{"unknown algorithm 99", 99, 0, true},
		{"unknown algorithm 0", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := hashForAlgorithm(tt.algorithm)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h != tt.expected {
				t.Errorf("got %v, want %v", h, tt.expected)
			}
		})
	}
}

func TestVerifyRRSIG_InvalidAlgorithm(t *testing.T) {
	rrset := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{93, 184, 216, 34}, // 93.184.216.34
		},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   99, // unsupported
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   []byte{1, 2, 3, 4},
	}

	dnskey := &dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: 99,
		PublicKey: []byte{1, 2, 3, 4},
	}

	err := VerifyRRSIG(rrset, rrsig, dnskey)
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
	if err != errUnsupportedAlg {
		t.Errorf("expected errUnsupportedAlg, got %v", err)
	}
}

func TestVerifyRRSIG_EmptyRRSet(t *testing.T) {
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Signature:   []byte{1, 2, 3},
	}
	dnskey := &dns.DNSKEYRecord{}

	err := VerifyRRSIG(nil, rrsig, dnskey)
	if err != errEmptyRRSet {
		t.Errorf("expected errEmptyRRSet, got %v", err)
	}
}

func TestVerifyRRSIG_NoSignature(t *testing.T) {
	rrset := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassIN, RData: []byte{1, 2, 3, 4}},
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Signature:   nil, // no signature
	}
	dnskey := &dns.DNSKEYRecord{}

	err := VerifyRRSIG(rrset, rrsig, dnskey)
	if err != errNoSignature {
		t.Errorf("expected errNoSignature, got %v", err)
	}
}

func TestVerifyRRSIG_ED25519(t *testing.T) {
	// 1. Generate Ed25519 key pair.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	// 2. Create a DNSKEY record with the public key.
	dnskey := &dns.DNSKEYRecord{
		Flags:     256, // ZSK
		Protocol:  3,
		Algorithm: dns.AlgED25519,
		PublicKey: []byte(pubKey),
	}

	// 3. Create a simple A record RRset.
	rrset := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{93, 184, 216, 34},
		},
	}

	// 4. Build RRSIG fields (we'll compute the signature manually).
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  "example.com.",
	}

	// 5. Build the signed data (same as buildSignedData does internally).
	signedData := buildSignedData(rrset, rrsig)

	// 6. Sign with the private key.
	signature := ed25519.Sign(privKey, signedData)
	rrsig.Signature = signature

	// 7. Verify.
	err = VerifyRRSIG(rrset, rrsig, dnskey)
	if err != nil {
		t.Fatalf("VerifyRRSIG failed: %v", err)
	}
}

func TestVerifyRRSIG_ED25519_WrongSignature(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	dnskey := &dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.AlgED25519,
		PublicKey: []byte(pubKey),
	}

	rrset := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{93, 184, 216, 34},
		},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  "example.com.",
		Signature:   make([]byte, ed25519.SignatureSize), // bogus signature (all zeros)
	}

	err = VerifyRRSIG(rrset, rrsig, dnskey)
	if err == nil {
		t.Error("expected verification failure with wrong signature")
	}
	if err != errVerifyFailed {
		t.Errorf("expected errVerifyFailed, got %v", err)
	}
}

func TestVerifyRRSIG_ED25519_WrongKeyLength(t *testing.T) {
	dnskey := &dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.AlgED25519,
		PublicKey: []byte{1, 2, 3}, // wrong length
	}

	rrset := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{93, 184, 216, 34},
		},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  "example.com.",
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	err := VerifyRRSIG(rrset, rrsig, dnskey)
	if err == nil {
		t.Error("expected error for wrong key length")
	}
	if err != errInvalidKeyLength {
		t.Errorf("expected errInvalidKeyLength, got %v", err)
	}
}

func TestVerifyRRSIG_RSA(t *testing.T) {
	// Generate a test RSA key pair.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubKey := &privKey.PublicKey

	// Encode public key in DNSKEY wire format.
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

	dnskey := &dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.AlgRSASHA256,
		PublicKey: wireKey,
	}

	rrset := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{93, 184, 216, 34},
		},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgRSASHA256,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  "example.com.",
	}

	// Build signed data and sign with RSA.
	signedData := buildSignedData(rrset, rrsig)
	h := sha256.Sum256(signedData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("RSA sign failed: %v", err)
	}
	rrsig.Signature = signature

	err = VerifyRRSIG(rrset, rrsig, dnskey)
	if err != nil {
		t.Fatalf("VerifyRRSIG (RSA) failed: %v", err)
	}
}

func TestVerifyRRSIG_ECDSA_P256(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	pubKey := &privKey.PublicKey

	// Encode public key in DNSKEY wire format: raw x || y, each 32 bytes for P-256.
	wireKey := make([]byte, 64)
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	copy(wireKey[32-len(xBytes):32], xBytes)
	copy(wireKey[64-len(yBytes):64], yBytes)

	dnskey := &dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.AlgECDSAP256,
		PublicKey: wireKey,
	}

	rrset := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{93, 184, 216, 34},
		},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgECDSAP256,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  0xFFFFFFFF,
		Inception:   0,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  "example.com.",
	}

	signedData := buildSignedData(rrset, rrsig)
	h := sha256.Sum256(signedData)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, h[:])
	if err != nil {
		t.Fatalf("ECDSA sign failed: %v", err)
	}

	// Encode signature as fixed-size r || s (32 bytes each for P-256).
	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	rrsig.Signature = sigBytes

	err = VerifyRRSIG(rrset, rrsig, dnskey)
	if err != nil {
		t.Fatalf("VerifyRRSIG (ECDSA P-256) failed: %v", err)
	}
}

func TestBuildSignedData(t *testing.T) {
	// Verify that buildSignedData produces the expected format:
	// 18 bytes fixed fields + signer name wire + canonical rrset wire.
	rrset := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{1, 2, 3, 4},
		},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		Algorithm:   dns.AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  1000000,
		Inception:   999000,
		KeyTag:      12345,
		SignerName:  "example.com.",
	}

	data := buildSignedData(rrset, rrsig)

	// Check the fixed header (18 bytes).
	if len(data) < 18 {
		t.Fatalf("signed data too short: %d bytes", len(data))
	}

	// TypeCovered
	if got := binary.BigEndian.Uint16(data[0:2]); got != dns.TypeA {
		t.Errorf("TypeCovered: got %d, want %d", got, dns.TypeA)
	}
	// Algorithm
	if data[2] != dns.AlgED25519 {
		t.Errorf("Algorithm: got %d, want %d", data[2], dns.AlgED25519)
	}
	// Labels
	if data[3] != 2 {
		t.Errorf("Labels: got %d, want 2", data[3])
	}
	// OrigTTL
	if got := binary.BigEndian.Uint32(data[4:8]); got != 300 {
		t.Errorf("OrigTTL: got %d, want 300", got)
	}
	// Expiration
	if got := binary.BigEndian.Uint32(data[8:12]); got != 1000000 {
		t.Errorf("Expiration: got %d, want 1000000", got)
	}
	// Inception
	if got := binary.BigEndian.Uint32(data[12:16]); got != 999000 {
		t.Errorf("Inception: got %d, want 999000", got)
	}
	// KeyTag
	if got := binary.BigEndian.Uint16(data[16:18]); got != 12345 {
		t.Errorf("KeyTag: got %d, want 12345", got)
	}

	// After fixed header: signer name wire form.
	signerWire := canonicalNameWire("example.com.")
	if !bytes.Equal(data[18:18+len(signerWire)], signerWire) {
		t.Error("signer name wire mismatch in signed data")
	}
}

func TestCanonicalRRSetWire_SortOrder(t *testing.T) {
	// Two A records with different RDATA should be sorted.
	rrset := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{10, 0, 0, 2},
		},
		{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{10, 0, 0, 1},
		},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		OrigTTL:     300,
	}

	wire := canonicalRRSetWire(rrset, rrsig)

	// The record with 10.0.0.1 should come before 10.0.0.2 in canonical order.
	// Both records have the same name wire, type, class, TTL, so the sort is by the
	// full wire form which includes RDATA.
	if len(wire) == 0 {
		t.Fatal("canonical RRset wire is empty")
	}

	// Verify there are two records' worth of data.
	nameWire := canonicalNameWire("example.com.")
	singleRecordLen := len(nameWire) + 10 + 4 // name + header(10) + rdata(4)
	expectedLen := singleRecordLen * 2
	if len(wire) != expectedLen {
		t.Errorf("wire length: got %d, want %d", len(wire), expectedLen)
	}

	// Extract the RDATA from the first record (should be 10.0.0.1).
	firstRDataOffset := len(nameWire) + 10
	firstRData := wire[firstRDataOffset : firstRDataOffset+4]
	if !bytes.Equal(firstRData, []byte{10, 0, 0, 1}) {
		t.Errorf("first record RDATA: got %v, want [10 0 0 1]", firstRData)
	}
}

func TestCanonicalRRSetWire_FiltersByType(t *testing.T) {
	// RRset with mixed types: only TypeA records should be included
	// when RRSIG covers TypeA.
	rrset := []dns.ResourceRecord{
		{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{1, 2, 3, 4},
		},
		{
			Name:  "example.com.",
			Type:  dns.TypeAAAA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: make([]byte, 16),
		},
	}

	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		OrigTTL:     300,
	}

	wire := canonicalRRSetWire(rrset, rrsig)

	// Only 1 record should be present.
	nameWire := canonicalNameWire("example.com.")
	singleRecordLen := len(nameWire) + 10 + 4
	if len(wire) != singleRecordLen {
		t.Errorf("wire length: got %d, want %d (expected only 1 A record)", len(wire), singleRecordLen)
	}
}

// canonicalWildcardOwner: regression test for the wildcard expansion fix.
// When the queried name has strictly more labels than RRSIG.Labels, the
// canonical owner used for signature verification must be
// "*.<closest_encloser>", not the queried name (RFC 4035 §5.3.2). This
// codepath was previously broken and caused every wildcard-served zone
// (e.g. *.fedoraproject.org → wildcard.fedoraproject.org) to validate Bogus.
func TestCanonicalWildcardOwner(t *testing.T) {
	cases := []struct {
		name         string
		signedLabels uint8
		want         string
	}{
		// Non-wildcard: rr.Name labels equal signedLabels — used as-is.
		{"example.com.", 2, "example.com."},
		{"example.com.", 2, "example.com."},
		// Wildcard expansion: 3 labels in rr.Name vs 2 in signature.
		// Trailing dot is stripped during reconstruction; canonicalNameWire
		// re-strips before encoding so the wire form is identical either way.
		{"wildcard.example.com.", 2, "*.example.com"},
		// Deeper wildcard expansion: 4 labels vs 2.
		{"a.b.example.com.", 2, "*.example.com"},
		// Root-zone signature: Labels=0 means no wildcard semantics.
		{".", 0, "."},
		// Already at signed depth without trailing dot.
		{"example.com", 2, "example.com"},
		// Pathological: signedLabels > actual labels — keep as-is.
		{"example.com.", 5, "example.com."},
	}
	for _, c := range cases {
		got := canonicalWildcardOwner(c.name, c.signedLabels)
		if got != c.want {
			t.Errorf("canonicalWildcardOwner(%q, %d) = %q; want %q",
				c.name, c.signedLabels, got, c.want)
		}
	}
}

// TestCanonicalRRSetWire_WildcardExpansion verifies that a wildcard-expanded
// answer reconstructs the "*.<closest_encloser>" owner in the canonical wire
// form. Without this, the signed-data bytes diverge from what the auth
// server signed and every wildcard answer becomes a false Bogus.
func TestCanonicalRRSetWire_WildcardExpansion(t *testing.T) {
	rrset := []dns.ResourceRecord{
		{
			// Queried name returned by the resolver — looks like a concrete
			// child of example.com but was synthesised from "*.example.com".
			Name:  "wildcard.example.com.",
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: []byte{10, 0, 0, 1},
		},
	}
	rrsig := &dns.RRSIGRecord{
		TypeCovered: dns.TypeA,
		OrigTTL:     300,
		Labels:      2, // signed under *.example.com (2 labels excluding wildcard label)
	}

	wire := canonicalRRSetWire(rrset, rrsig)

	wantOwner := canonicalNameWire("*.example.com.")
	if !bytes.HasPrefix(wire, wantOwner) {
		t.Fatalf("canonical wire should start with *.example.com wire form; got %v", wire)
	}
	// Reject the broken-before-fix encoding under the queried name.
	badOwner := canonicalNameWire("wildcard.example.com.")
	if bytes.HasPrefix(wire, badOwner) {
		t.Fatalf("canonical wire still encodes the queried name instead of the wildcard owner")
	}
}

// canonicalRData: regression test for RFC 4034 §6.2 item 3 — domain names
// embedded in RDATA for specific RR types must be lowercased before signing
// or verifying. The previous code appended rr.RData verbatim, so any auth
// server emitting uppercase characters in wire (e.g. fedoraproject.org's
// path that produced verify-failed for the mirrormanager CNAME hop) made
// signature verification fail for a perfectly legitimate response.
func TestCanonicalRData_CNAMELowercased(t *testing.T) {
	// Wire format of "Wildcard.FedoraProject.ORG" (mixed case).
	rdata := dns.BuildPlainName("Wildcard.FedoraProject.ORG")
	got := canonicalRData(rdata, dns.TypeCNAME)
	want := dns.BuildPlainName("wildcard.fedoraproject.org")
	if !bytes.Equal(got, want) {
		t.Errorf("CNAME RDATA not lowercased.\n got:  %v\n want: %v", got, want)
	}
	// Length must be preserved (ASCII lowercase preserves byte length).
	if len(got) != len(rdata) {
		t.Errorf("canonicalRData changed length: got %d want %d", len(got), len(rdata))
	}
}

func TestCanonicalRData_LeavesNonNameTypesAlone(t *testing.T) {
	// A record RDATA is a 4-byte IP; lowercasing has no meaning. Must be
	// returned untouched (even with byte values that overlap ASCII letters).
	rdata := []byte{'A', 'B', 'C', 'D'}
	got := canonicalRData(rdata, dns.TypeA)
	if !bytes.Equal(got, rdata) {
		t.Errorf("non-name-bearing type was modified: got %v want %v", got, rdata)
	}
}

func TestCanonicalRData_MXLowercased(t *testing.T) {
	// MX RDATA: 2-byte preference + name. Preference bytes must NOT be
	// touched even if they happen to contain ASCII-letter byte values.
	pref := []byte{0x00, 0x0A}
	name := dns.BuildPlainName("Mail.EXAMPLE.com")
	rdata := append(append([]byte{}, pref...), name...)

	got := canonicalRData(rdata, dns.TypeMX)
	wantName := dns.BuildPlainName("mail.example.com")
	want := append(append([]byte{}, pref...), wantName...)
	if !bytes.Equal(got, want) {
		t.Errorf("MX RDATA not canonicalised correctly.\n got:  %v\n want: %v", got, want)
	}
}

// TestHashForAlgorithm_ECDSAP384UsesSHA384 regression-locks the algorithm 14
// (ECDSA P-384) → SHA-384 pairing fixed by RFC 6605 §2.1. The previous code
// mapped this algorithm to SHA-512 (because it was grouped in the same case
// arm as RSASHA512), which silently broke validation for every zone published
// with algorithm 14 — including fedoraproject.org, where the mirrormanager
// CNAME chain came out Bogus despite valid signatures.
func TestHashForAlgorithm_ECDSAP384UsesSHA384(t *testing.T) {
	h, err := hashForAlgorithm(dns.AlgECDSAP384)
	if err != nil {
		t.Fatalf("hashForAlgorithm(ECDSAP384) returned error: %v", err)
	}
	if h != crypto.SHA384 {
		t.Errorf("hashForAlgorithm(ECDSAP384) = %v; want SHA-384 (per RFC 6605 §2.1)", h)
	}
}

func TestHashForAlgorithm_RFC6605Pairings(t *testing.T) {
	cases := []struct {
		alg  uint8
		want crypto.Hash
	}{
		{dns.AlgRSASHA1, crypto.SHA1},
		{dns.AlgRSASHA256, crypto.SHA256},
		{dns.AlgRSASHA512, crypto.SHA512},
		{dns.AlgECDSAP256, crypto.SHA256},
		{dns.AlgECDSAP384, crypto.SHA384},
	}
	for _, c := range cases {
		got, err := hashForAlgorithm(c.alg)
		if err != nil {
			t.Errorf("hashForAlgorithm(%d) error: %v", c.alg, err)
			continue
		}
		if got != c.want {
			t.Errorf("hashForAlgorithm(%d) = %v; want %v", c.alg, got, c.want)
		}
	}
}

func TestCanonicalRData_RRSIGLowercasesSignerOnly(t *testing.T) {
	// RRSIG RDATA: 18 fixed bytes + signer name + signature blob. Only the
	// signer name is a domain name — the fixed header and signature must
	// remain byte-identical, including any byte values overlapping ASCII letters.
	header := make([]byte, 18)
	for i := range header {
		header[i] = byte('A' + i%26) // letter values, MUST stay uppercase
	}
	signer := dns.BuildPlainName("Fedoraproject.ORG")
	sig := []byte{'A', 'B', 'C', 'D', 'E', 'F'} // signature bytes — leave alone
	rdata := append(append(append([]byte{}, header...), signer...), sig...)

	got := canonicalRData(rdata, dns.TypeRRSIG)

	// First 18 bytes untouched.
	if !bytes.Equal(got[:18], header) {
		t.Errorf("RRSIG fixed header was modified: got %v want %v", got[:18], header)
	}
	// Signer lowercased.
	wantSigner := dns.BuildPlainName("fedoraproject.org")
	if !bytes.Equal(got[18:18+len(wantSigner)], wantSigner) {
		t.Errorf("RRSIG signer not lowercased: got %v want %v",
			got[18:18+len(wantSigner)], wantSigner)
	}
	// Signature bytes untouched.
	gotSig := got[18+len(wantSigner):]
	if !bytes.Equal(gotSig, sig) {
		t.Errorf("RRSIG signature bytes modified: got %v want %v", gotSig, sig)
	}
}
