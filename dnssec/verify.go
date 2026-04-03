package dnssec

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"
	"sort"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

var (
	errInvalidRSAKey    = errors.New("dnssec: invalid RSA public key data")
	errInvalidECDSAKey  = errors.New("dnssec: invalid ECDSA public key data")
	errUnsupportedAlg   = errors.New("dnssec: unsupported algorithm")
	errVerifyFailed     = errors.New("dnssec: signature verification failed")
	errEmptyRRSet       = errors.New("dnssec: empty RRset")
	errNoSignature      = errors.New("dnssec: RRSIG has no signature data")
	errInvalidKeyLength = errors.New("dnssec: invalid key length")
)

// VerifyRRSIG verifies an RRSIG signature over an RRset using a DNSKEY.
// It builds the signed data (RRSIG RDATA without signature + canonical RRset)
// and verifies the cryptographic signature according to the algorithm.
func VerifyRRSIG(rrset []dns.ResourceRecord, rrsig *dns.RRSIGRecord, dnskey *dns.DNSKEYRecord) error {
	if len(rrset) == 0 {
		return errEmptyRRSet
	}
	if len(rrsig.Signature) == 0 {
		return errNoSignature
	}

	// Build the signature input: RRSIG RDATA (without signature) + canonical RRset wire form.
	signedData := buildSignedData(rrset, rrsig)

	// Verify based on algorithm.
	switch rrsig.Algorithm {
	case dns.AlgRSASHA1, dns.AlgRSASHA256, dns.AlgRSASHA512:
		return verifyRSA(signedData, rrsig.Signature, dnskey.PublicKey, rrsig.Algorithm)
	case dns.AlgECDSAP256, dns.AlgECDSAP384:
		return verifyECDSA(signedData, rrsig.Signature, dnskey.PublicKey, rrsig.Algorithm)
	case dns.AlgED25519:
		return verifyED25519(signedData, rrsig.Signature, dnskey.PublicKey)
	default:
		return errUnsupportedAlg
	}
}

// buildSignedData constructs the data that is signed by an RRSIG:
// RRSIG RDATA fields (without the signature) followed by the canonical RRset wire form.
func buildSignedData(rrset []dns.ResourceRecord, rrsig *dns.RRSIGRecord) []byte {
	var buf []byte

	// RRSIG fixed fields: type_covered(2) + algorithm(1) + labels(1) + orig_ttl(4) +
	// expiration(4) + inception(4) + key_tag(2) = 18 bytes
	fixed := make([]byte, 18)
	binary.BigEndian.PutUint16(fixed[0:2], rrsig.TypeCovered)
	fixed[2] = rrsig.Algorithm
	fixed[3] = rrsig.Labels
	binary.BigEndian.PutUint32(fixed[4:8], rrsig.OrigTTL)
	binary.BigEndian.PutUint32(fixed[8:12], rrsig.Expiration)
	binary.BigEndian.PutUint32(fixed[12:16], rrsig.Inception)
	binary.BigEndian.PutUint16(fixed[16:18], rrsig.KeyTag)
	buf = append(buf, fixed...)

	// Signer name in canonical (lowercase) wire format.
	buf = append(buf, canonicalNameWire(rrsig.SignerName)...)

	// Canonical RRset wire form.
	buf = append(buf, canonicalRRSetWire(rrset, rrsig)...)

	return buf
}

// canonicalRRSetWire builds the canonical wire form of an RRset for RRSIG verification.
// Each RR is encoded as: name(wire, lowercase) + type(2) + class(2) + origTTL(4) + rdlength(2) + rdata.
// RRs are sorted by their RDATA in canonical order.
func canonicalRRSetWire(rrset []dns.ResourceRecord, rrsig *dns.RRSIGRecord) []byte {
	type rrWire struct {
		data []byte
	}

	wires := make([]rrWire, 0, len(rrset))

	for _, rr := range rrset {
		// Skip records that do not match the type covered by the RRSIG.
		if rr.Type != rrsig.TypeCovered {
			continue
		}

		var buf []byte

		// Owner name in canonical (lowercase) wire format.
		buf = append(buf, canonicalNameWire(rr.Name)...)

		// Type, class, original TTL (from RRSIG, not the RR), and RDATA length.
		header := make([]byte, 10)
		binary.BigEndian.PutUint16(header[0:2], rr.Type)
		binary.BigEndian.PutUint16(header[2:4], rr.Class)
		binary.BigEndian.PutUint32(header[4:8], rrsig.OrigTTL)
		binary.BigEndian.PutUint16(header[8:10], uint16(len(rr.RData)))
		buf = append(buf, header...)

		// RDATA as-is.
		buf = append(buf, rr.RData...)

		wires = append(wires, rrWire{data: buf})
	}

	// Sort RRs by their wire-format representation for canonical ordering.
	sort.Slice(wires, func(i, j int) bool {
		return bytes.Compare(wires[i].data, wires[j].data) < 0
	})

	var result []byte
	for _, w := range wires {
		result = append(result, w.data...)
	}
	return result
}

// canonicalNameWire encodes a domain name as lowercase uncompressed DNS wire format.
// For example, "Example.COM." becomes [7]example[3]com[0].
func canonicalNameWire(name string) []byte {
	// Normalize: remove trailing dot, lowercase.
	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)

	if name == "" {
		return []byte{0x00}
	}

	labels := strings.Split(name, ".")
	var buf []byte
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00)
	return buf
}

// hashForAlgorithm returns the crypto.Hash to use for a given DNSSEC algorithm.
func hashForAlgorithm(algorithm uint8) (crypto.Hash, error) {
	switch algorithm {
	case dns.AlgRSASHA1:
		return crypto.SHA1, nil
	case dns.AlgRSASHA256, dns.AlgECDSAP256:
		return crypto.SHA256, nil
	case dns.AlgRSASHA512, dns.AlgECDSAP384:
		return crypto.SHA512, nil
	case dns.AlgED25519:
		// ED25519 does its own hashing internally.
		return 0, nil
	default:
		return 0, errUnsupportedAlg
	}
}

// parseRSAPublicKey parses an RSA public key from DNSKEY wire format (RFC 3110).
// Format: exponent length (1 or 3 bytes) + exponent + modulus.
func parseRSAPublicKey(keyData []byte) (*rsa.PublicKey, error) {
	if len(keyData) < 3 {
		return nil, errInvalidRSAKey
	}

	var expLen int
	var offset int

	// If the first byte is zero, the next two bytes contain the exponent length.
	if keyData[0] == 0 {
		if len(keyData) < 4 {
			return nil, errInvalidRSAKey
		}
		expLen = int(binary.BigEndian.Uint16(keyData[1:3]))
		offset = 3
	} else {
		expLen = int(keyData[0])
		offset = 1
	}

	if offset+expLen >= len(keyData) {
		return nil, errInvalidRSAKey
	}

	expBytes := keyData[offset : offset+expLen]
	modBytes := keyData[offset+expLen:] // guaranteed non-empty by check above

	// Parse exponent as big-endian integer.
	exp := new(big.Int).SetBytes(expBytes)
	if !exp.IsInt64() || exp.Int64() > 1<<31-1 {
		return nil, errInvalidRSAKey
	}

	modulus := new(big.Int).SetBytes(modBytes)

	return &rsa.PublicKey{
		N: modulus,
		E: int(exp.Int64()),
	}, nil
}

// parseECDSAPublicKey parses an ECDSA public key from DNSKEY wire format.
// The key data contains raw x and y coordinates concatenated (no 0x04 prefix).
func parseECDSAPublicKey(keyData []byte, algorithm uint8) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	var coordLen int

	switch algorithm {
	case dns.AlgECDSAP256:
		curve = elliptic.P256()
		coordLen = 32
	case dns.AlgECDSAP384:
		curve = elliptic.P384()
		coordLen = 48
	default:
		return nil, errUnsupportedAlg
	}

	if len(keyData) != coordLen*2 {
		return nil, errInvalidECDSAKey
	}

	x := new(big.Int).SetBytes(keyData[:coordLen])
	y := new(big.Int).SetBytes(keyData[coordLen:])

	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Validate the point is on the curve.
	if !curve.IsOnCurve(x, y) {
		return nil, errInvalidECDSAKey
	}

	return key, nil
}

// verifyRSA verifies an RSA-based DNSSEC signature (algorithms 5, 8, 10).
func verifyRSA(signedData, signature, keyData []byte, algorithm uint8) error {
	pubKey, err := parseRSAPublicKey(keyData)
	if err != nil {
		return err
	}

	hashAlg, err := hashForAlgorithm(algorithm)
	if err != nil {
		return err
	}

	hasher := hashAlg.New()
	hasher.Write(signedData)
	hashed := hasher.Sum(nil)

	if err := rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed, signature); err != nil {
		return errVerifyFailed
	}
	return nil
}

// verifyECDSA verifies an ECDSA-based DNSSEC signature (algorithms 13, 14).
// The signature format is r || s, each encoded as a fixed-size big-endian integer.
func verifyECDSA(signedData, signature, keyData []byte, algorithm uint8) error {
	pubKey, err := parseECDSAPublicKey(keyData, algorithm)
	if err != nil {
		return err
	}

	// hashForAlgorithm is guaranteed to succeed here because
	// parseECDSAPublicKey already rejected unsupported algorithms.
	hashAlg, _ := hashForAlgorithm(algorithm)

	var coordLen int
	if algorithm == dns.AlgECDSAP384 {
		coordLen = 48
	} else {
		coordLen = 32 // AlgECDSAP256
	}

	if len(signature) != coordLen*2 {
		return errVerifyFailed
	}

	r := new(big.Int).SetBytes(signature[:coordLen])
	s := new(big.Int).SetBytes(signature[coordLen:])

	hasher := hashAlg.New()
	hasher.Write(signedData)
	hashed := hasher.Sum(nil)

	if !ecdsa.Verify(pubKey, hashed, r, s) {
		return errVerifyFailed
	}
	return nil
}

// verifyED25519 verifies an Ed25519 DNSSEC signature (algorithm 15).
// The public key is the raw 32-byte key; the signature is 64 bytes.
func verifyED25519(signedData, signature, keyData []byte) error {
	if len(keyData) != ed25519.PublicKeySize {
		return errInvalidKeyLength
	}
	if len(signature) != ed25519.SignatureSize {
		return errVerifyFailed
	}

	pubKey := ed25519.PublicKey(keyData)
	if !ed25519.Verify(pubKey, signedData, signature) {
		return errVerifyFailed
	}
	return nil
}
