package dnssec

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-1 and SHA-256 with the crypto package
	_ "crypto/sha512" // registers SHA-384 and SHA-512 (RFC 6605 §2.1 needs SHA-384 for ECDSAP384)
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
		//
		// RFC 4035 §5.3.2 wildcard reconstruction: if the RR was synthesized
		// from a wildcard, the RDATA was signed under the wildcard owner
		// "*.<closest_encloser>", not the queried name appearing in `rr.Name`.
		// We detect this by comparing the number of labels in rr.Name (root
		// excluded) against rrsig.Labels — the count of labels that were in
		// the originally-signed owner. A larger rr.Name means wildcard
		// expansion; we must reconstruct "*." + (the last rrsig.Labels labels)
		// before encoding, or every wildcard-served answer comes out Bogus.
		ownerForCanonical := canonicalWildcardOwner(rr.Name, rrsig.Labels)
		buf = append(buf, canonicalNameWire(ownerForCanonical)...)

		// RDATA in canonical form. For RR types listed in RFC 4034 §6.2 item 3
		// (CNAME, NS, PTR, DNAME, MX, SOA, SRV, RRSIG, NSEC), any embedded
		// domain names in RDATA must be lowercased before signing/verifying.
		// Auth servers that emit uppercase in wire responses (or upstreams
		// that don't normalize) would otherwise turn every CNAME hop into a
		// false Bogus. ASCII lowercasing preserves byte length, so the
		// signed RDLENGTH does not change.
		canonRData := canonicalRData(rr.RData, rrsig.TypeCovered)

		// Type, class, original TTL (from RRSIG, not the RR), and RDATA length.
		header := make([]byte, 10)
		binary.BigEndian.PutUint16(header[0:2], rr.Type)
		binary.BigEndian.PutUint16(header[2:4], rr.Class)
		binary.BigEndian.PutUint32(header[4:8], rrsig.OrigTTL)
		binary.BigEndian.PutUint16(header[8:10], uint16(len(canonRData)))
		buf = append(buf, header...)

		buf = append(buf, canonRData...)

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

// canonicalRData returns the RDATA bytes a signer would have used as input
// to the signature, applying RFC 4034 §6.2 item 3: domain names embedded in
// the RDATA of certain RR types are lowercased. For types not in that list
// the RDATA is returned unchanged.
//
// The transformation only touches the bytes that constitute label payload —
// label length octets, numeric fields, signatures, and bitmaps are left
// alone. Length is preserved so the surrounding RDLENGTH stays correct.
func canonicalRData(rdata []byte, rrtype uint16) []byte {
	switch rrtype {
	case dns.TypeCNAME, dns.TypeNS, dns.TypePTR, dns.TypeDNAME:
		out, ok := lowercaseWireName(rdata, 0)
		if !ok {
			return rdata
		}
		return out
	case dns.TypeMX:
		// 2-byte preference then a name.
		if len(rdata) < 3 {
			return rdata
		}
		out, ok := lowercaseWireName(rdata, 2)
		if !ok {
			return rdata
		}
		return out
	case dns.TypeSRV:
		// 6-byte fixed header (priority, weight, port) then target name.
		if len(rdata) < 7 {
			return rdata
		}
		out, ok := lowercaseWireName(rdata, 6)
		if !ok {
			return rdata
		}
		return out
	case dns.TypeSOA:
		// MNAME then RNAME then 20 bytes of serial/refresh/retry/expire/minimum.
		out, ok := lowercaseWireName(rdata, 0)
		if !ok {
			return rdata
		}
		// Find the end of MNAME to know where RNAME starts.
		mnameEnd, ok := scanWireNameEnd(out, 0)
		if !ok {
			return rdata
		}
		out2, ok := lowercaseWireName(out, mnameEnd)
		if !ok {
			return out
		}
		return out2
	case dns.TypeRRSIG:
		// 18 fixed bytes, then signer name, then signature. Lowercase signer.
		if len(rdata) < 19 {
			return rdata
		}
		out, ok := lowercaseWireName(rdata, 18)
		if !ok {
			return rdata
		}
		return out
	case dns.TypeNSEC:
		// Next domain name followed by type bitmaps.
		out, ok := lowercaseWireName(rdata, 0)
		if !ok {
			return rdata
		}
		return out
	}
	return rdata
}

// lowercaseWireName returns a copy of rdata in which the wire-format domain
// name starting at `start` has its label payload bytes lowercased. Length
// octets, root terminator, and all bytes outside the name are left untouched.
// Returns (out, false) if the bytes do not look like a valid wire name —
// the caller falls back to the original RDATA in that case rather than
// risking a corrupt canonical form.
func lowercaseWireName(rdata []byte, start int) ([]byte, bool) {
	if start < 0 || start > len(rdata) {
		return nil, false
	}
	out := make([]byte, len(rdata))
	copy(out, rdata)

	i := start
	for {
		if i >= len(out) {
			return nil, false
		}
		l := int(out[i])
		// Compression pointers must not appear in canonical (uncompressed)
		// form. If we see one, refuse — the caller falls back.
		if l&0xC0 != 0 {
			return nil, false
		}
		if l == 0 {
			return out, true
		}
		if l > 63 || i+1+l > len(out) {
			return nil, false
		}
		for j := i + 1; j < i+1+l; j++ {
			c := out[j]
			if c >= 'A' && c <= 'Z' {
				out[j] = c + ('a' - 'A')
			}
		}
		i += 1 + l
	}
}

// scanWireNameEnd returns the byte offset immediately after the root
// terminator of the wire name that starts at `start`. (out, false) on
// malformed input.
func scanWireNameEnd(rdata []byte, start int) (int, bool) {
	i := start
	for {
		if i >= len(rdata) {
			return 0, false
		}
		l := int(rdata[i])
		if l&0xC0 != 0 {
			return 0, false
		}
		if l == 0 {
			return i + 1, true
		}
		if l > 63 || i+1+l > len(rdata) {
			return 0, false
		}
		i += 1 + l
	}
}

// canonicalWildcardOwner returns the owner name to use when canonicalising
// an RRset for RRSIG verification. Per RFC 4035 §5.3.2, when an answer was
// synthesised from a wildcard the signed owner is "*.<closest_encloser>",
// not the queried name. The RRSIG's Labels field records how many labels
// the originally-signed owner contained (root excluded, wildcard label not
// counted). If the RR's owner has strictly more labels than that, the RR
// is a wildcard expansion and must be canonicalised under "*." + last
// signedLabels labels of the owner. Otherwise the RR's owner is used as-is.
func canonicalWildcardOwner(rrName string, signedLabels uint8) string {
	// Labels == 0 means the RRSIG was made over the root zone apex; the
	// concept of "wildcard expansion" does not apply and the RR is used
	// verbatim. This also keeps tests that leave RRSIG.Labels zero-valued
	// behaving as before the fix.
	if signedLabels == 0 {
		return rrName
	}
	trimmed := strings.TrimSuffix(rrName, ".")
	if trimmed == "" {
		return rrName
	}
	labels := strings.Split(trimmed, ".")
	// labels excludes the empty root label, matching RRSIG.Labels semantics.
	if uint8(len(labels)) <= signedLabels {
		return rrName
	}
	tail := labels[len(labels)-int(signedLabels):]
	return "*." + strings.Join(tail, ".")
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
//
// RFC 6605 §2 fixes the algorithm/hash pairing strictly:
//   - Algorithm 13 (ECDSA P-256) MUST use SHA-256.
//   - Algorithm 14 (ECDSA P-384) MUST use SHA-384 — NOT SHA-512.
//
// Previously this function grouped ECDSAP384 with RSASHA512 under SHA-512,
// which made every signed zone published with algorithm 14 (e.g. fedoraproject.org)
// fail crypto verification and come back Bogus. The fix gives ECDSAP384 its
// own case mapped to SHA-384.
func hashForAlgorithm(algorithm uint8) (crypto.Hash, error) {
	switch algorithm {
	case dns.AlgRSASHA1:
		return crypto.SHA1, nil
	case dns.AlgRSASHA256, dns.AlgECDSAP256:
		return crypto.SHA256, nil
	case dns.AlgECDSAP384:
		return crypto.SHA384, nil
	case dns.AlgRSASHA512:
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
