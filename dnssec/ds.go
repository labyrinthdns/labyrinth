package dnssec

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"

	"github.com/labyrinthdns/labyrinth/dns"
)

// VerifyDS checks if a DNSKEY matches a DS record by computing the DS digest
// over the canonical owner name + DNSKEY RDATA and comparing it to the DS digest.
// The ownerName is the domain name that owns the DNSKEY (e.g., "example.com.").
func VerifyDS(dnskey *dns.DNSKEYRecord, ds *dns.DSRecord, ownerName string) bool {
	// Quick check: key tag must match.
	if dnskey.KeyTag() != ds.KeyTag {
		return false
	}
	// Algorithm must match.
	if dnskey.Algorithm != ds.Algorithm {
		return false
	}

	// Build the digest input: canonical owner name wire form + DNSKEY RDATA.
	// DNSKEY RDATA = flags(2) + protocol(1) + algorithm(1) + public key.
	nameWire := canonicalNameWire(ownerName)
	dnskeyRData := make([]byte, 4+len(dnskey.PublicKey))
	binary.BigEndian.PutUint16(dnskeyRData[0:2], dnskey.Flags)
	dnskeyRData[2] = dnskey.Protocol
	dnskeyRData[3] = dnskey.Algorithm
	copy(dnskeyRData[4:], dnskey.PublicKey)

	digestInput := make([]byte, len(nameWire)+len(dnskeyRData))
	copy(digestInput, nameWire)
	copy(digestInput[len(nameWire):], dnskeyRData)

	// Hash with the appropriate digest algorithm.
	var computed []byte
	switch ds.DigestType {
	case dns.DigestSHA1:
		h := sha1.Sum(digestInput)
		computed = h[:]
	case dns.DigestSHA256:
		h := sha256.Sum256(digestInput)
		computed = h[:]
	case dns.DigestSHA384:
		h := sha512.Sum384(digestInput)
		computed = h[:]
	default:
		// Unsupported digest type.
		return false
	}

	return bytes.Equal(computed, ds.Digest)
}
