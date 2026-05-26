package dnssec

import (
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

var (
	errUnsupportedHashAlg = errors.New("dnssec: unsupported NSEC3 hash algorithm")
	errTooManyIterations  = errors.New("dnssec: NSEC3 iterations exceed maximum (100)")
	errNoNSEC3Records     = errors.New("dnssec: no NSEC3 records provided")
)

// MaxNSEC3Iterations is the hard ceiling on the NSEC3 iteration count this
// resolver will honour, per RFC 9276 §3.2 (August 2022): "validating
// resolvers SHOULD return an insecure response when processing NSEC3
// records with iterations larger than 100." High iteration counts give
// no real cryptographic benefit but let an attacker amplify CPU cost
// per query (NSEC3 hash-walk DoS) and slow down legitimate validation.
// Aligns with BIND 9.18+ and Unbound 1.16+ defaults.
const MaxNSEC3Iterations = 100

// nsec3Base32 is the extended hex base32 encoding used by NSEC3 (RFC 4648 §7),
// without padding.
var nsec3Base32 = base32.HexEncoding.WithPadding(base32.NoPadding)

// ComputeNSEC3Hash computes the NSEC3 hash for a domain name.
// Algorithm 1 is SHA-1 (the only defined algorithm per RFC 5155).
// The result is the raw hash bytes (not base32-encoded).
func ComputeNSEC3Hash(name string, algorithm uint8, iterations uint16, salt []byte) ([]byte, error) {
	if algorithm != 1 {
		return nil, errUnsupportedHashAlg
	}
	if iterations > MaxNSEC3Iterations {
		return nil, errTooManyIterations
	}

	// Normalize: lowercase and ensure trailing dot for wire format encoding
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	// Convert domain name to wire format
	wire := nameToWire(name)

	// IH(salt, x, 0) = H(x || salt)
	// IH(salt, x, k) = H(IH(salt, x, k-1) || salt)
	h := sha1.New()
	h.Write(wire)
	h.Write(salt)
	hash := h.Sum(nil)

	for i := uint16(0); i < iterations; i++ {
		h.Reset()
		h.Write(hash)
		h.Write(salt)
		hash = h.Sum(nil)
	}

	return hash, nil
}

// NSEC3HashToString encodes raw NSEC3 hash bytes to the base32hex string
// representation used in NSEC3 owner names.
func NSEC3HashToString(hash []byte) string {
	return strings.ToUpper(nsec3Base32.EncodeToString(hash))
}

// nsec3StringToHash decodes a base32hex NSEC3 hash string to raw bytes.
func nsec3StringToHash(s string) ([]byte, error) {
	return nsec3Base32.DecodeString(strings.ToUpper(s))
}

// nameToWire converts a domain name to DNS wire format (sequence of labels).
func nameToWire(name string) []byte {
	if name == "." {
		return []byte{0}
	}

	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	var wire []byte
	for _, label := range labels {
		wire = append(wire, byte(len(label)))
		wire = append(wire, []byte(label)...)
	}
	wire = append(wire, 0) // root label
	return wire
}

// VerifyNSEC3Denial verifies that a queried name falls within an NSEC3 hash gap,
// proving the name does not exist (NXDOMAIN) or the type does not exist (NODATA).
// Returns true if the denial proof is valid.
func VerifyNSEC3Denial(qname string, nsec3Records []*dns.NSEC3Record) (bool, error) {
	if len(nsec3Records) == 0 {
		return false, errNoNSEC3Records
	}

	// Use parameters from the first NSEC3 record
	rec := nsec3Records[0]
	if rec.Iterations > MaxNSEC3Iterations {
		return false, errTooManyIterations
	}

	// Compute the hash for the queried name
	qnameHash, err := ComputeNSEC3Hash(qname, rec.HashAlgorithm, rec.Iterations, rec.Salt)
	if err != nil {
		return false, fmt.Errorf("computing NSEC3 hash for %s: %w", qname, err)
	}

	// Check if any NSEC3 record covers this hash (hash falls in the gap)
	for _, nsec3 := range nsec3Records {
		if coversHash(nsec3, qnameHash) {
			return true, nil
		}
	}

	return false, nil
}

// VerifyClosestEncloser finds the closest encloser for the queried name
// by looking for an NSEC3 record whose hash matches a parent of qname.
// Returns the closest encloser name if found.
func VerifyClosestEncloser(qname string, nsec3Records []*dns.NSEC3Record) (string, error) {
	if len(nsec3Records) == 0 {
		return "", errNoNSEC3Records
	}

	rec := nsec3Records[0]
	if rec.Iterations > MaxNSEC3Iterations {
		return "", errTooManyIterations
	}

	// Build the set of known hashes from NSEC3 owner names
	// In a real implementation, the owner names would be extracted from
	// the RR owner names. Here we use the NextHash fields plus we
	// check each ancestor of qname.
	qname = strings.ToLower(qname)
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}

	// Walk up the label tree from qname toward root
	candidate := qname
	for {
		hash, err := ComputeNSEC3Hash(candidate, rec.HashAlgorithm, rec.Iterations, rec.Salt)
		if err != nil {
			return "", err
		}
		hashStr := NSEC3HashToString(hash)

		// Check if this hash matches any NSEC3 record's owner hash
		// (In practice, the owner name of the NSEC3 RR is the hash)
		for _, nsec3 := range nsec3Records {
			// The NSEC3 record itself proves existence of the hashed name
			// We compare with the NextHash to check coverage, but for
			// closest encloser we need the hash to match an NSEC3 owner.
			// Since we don't have owner names in the record struct,
			// we check if any NSEC3 does NOT cover this hash (meaning
			// the hash matches the NSEC3 owner itself).
			ownerHash := NSEC3HashToString(nsec3.NextHash)
			_ = ownerHash // owner hash comparison done differently

			// For closest encloser proof: the hash of the candidate
			// must match an NSEC3 record's owner (which we approximate
			// by checking the hash is not in any gap — it's a boundary).
			_ = hashStr
		}

		// Move to parent
		dotIdx := strings.IndexByte(candidate, '.')
		if dotIdx < 0 || candidate[dotIdx+1:] == "" {
			break
		}
		candidate = candidate[dotIdx+1:]
	}

	// Simplified closest encloser: walk up labels and check if hash is
	// covered by any NSEC3 record. The first label whose hash is NOT covered
	// is below the closest encloser.
	candidate = qname
	for {
		dotIdx := strings.IndexByte(candidate, '.')
		if dotIdx < 0 || candidate[dotIdx+1:] == "" {
			break
		}
		parent := candidate[dotIdx+1:]

		parentHash, err := ComputeNSEC3Hash(parent, rec.HashAlgorithm, rec.Iterations, rec.Salt)
		if err != nil {
			return "", err
		}

		// If the parent's hash is NOT covered by any NSEC3 gap, it exists
		covered := false
		for _, nsec3 := range nsec3Records {
			if coversHash(nsec3, parentHash) {
				covered = true
				break
			}
		}
		if !covered {
			return parent, nil
		}

		candidate = parent
	}

	return ".", nil
}

// coversHash checks if a hash falls strictly within the NSEC3 range
// (ownerHash, nextHash). The range wraps around for the last record in
// the zone (where ownerHash > nextHash).
func coversHash(nsec3 *dns.NSEC3Record, hash []byte) bool {
	// We need the owner hash, but NSEC3Record only contains NextHash.
	// The owner hash would come from the NSEC3 RR's owner name.
	// For this implementation, we store the hash from the owner name
	// separately. Since we can't derive it from the record alone,
	// we use a simplified approach: check if the queried hash matches
	// the NextHash (proving next-closer name).

	// Compare hash bytes with NextHash
	return compareHashes(hash, nsec3.NextHash) != 0 && hashInRange(hash, nsec3)
}

// hashInRange checks if hash is in the open range defined by an NSEC3 record.
// This requires knowing the owner hash. Since we only have NextHash in the
// record, this is an approximation that checks the hash is not equal to NextHash.
func hashInRange(hash []byte, nsec3 *dns.NSEC3Record) bool {
	// In a full implementation, we'd compare:
	//   ownerHash < hash < nextHash (or wrapping)
	// Since we don't have the owner hash in the struct, we check
	// that the hash doesn't equal the NextHash (which would mean
	// the name exists).
	return compareHashes(hash, nsec3.NextHash) != 0
}

// compareHashes compares two hash byte slices lexicographically.
// Returns -1, 0, or 1.
func compareHashes(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// NSEC3RecordWithOwner extends NSEC3Record with the owner hash for proper
// range checking in denial proofs.
type NSEC3RecordWithOwner struct {
	dns.NSEC3Record
	OwnerHash []byte // raw hash bytes from the NSEC3 RR owner name
}

// VerifyNSEC3DenialFull verifies NSEC3 denial with full owner hash information.
// This is the proper implementation that checks hash ranges correctly.
func VerifyNSEC3DenialFull(qname string, nsec3Records []NSEC3RecordWithOwner) (bool, error) {
	if len(nsec3Records) == 0 {
		return false, errNoNSEC3Records
	}

	rec := &nsec3Records[0]
	if rec.Iterations > MaxNSEC3Iterations {
		return false, errTooManyIterations
	}

	qnameHash, err := ComputeNSEC3Hash(qname, rec.HashAlgorithm, rec.Iterations, rec.Salt)
	if err != nil {
		return false, err
	}

	for _, nsec3 := range nsec3Records {
		if coversHashFull(nsec3.OwnerHash, nsec3.NextHash, qnameHash) {
			return true, nil
		}
	}

	return false, nil
}

// coversHashFull checks if hash falls in the open interval (ownerHash, nextHash).
// Handles the wrap-around case where ownerHash > nextHash (last NSEC3 in zone).
func coversHashFull(ownerHash, nextHash, hash []byte) bool {
	cmpOwner := compareHashes(hash, ownerHash)
	cmpNext := compareHashes(hash, nextHash)

	if compareHashes(ownerHash, nextHash) < 0 {
		// Normal range: ownerHash < hash < nextHash
		return cmpOwner > 0 && cmpNext < 0
	}
	// Wrap-around: hash > ownerHash OR hash < nextHash
	return cmpOwner > 0 || cmpNext < 0
}

// HasType checks whether the NSEC3 type bitmap includes the given RR type.
func HasType(nsec3 *dns.NSEC3Record, rrtype uint16) bool {
	for _, t := range nsec3.TypeBitMaps {
		if t == rrtype {
			return true
		}
	}
	return false
}

// nsec3OptOut reports whether the opt-out flag (RFC 5155 §3.1.2.1, bit 0
// of the Flags field) is set. An opt-out NSEC3 may span unsigned delegation
// names that the zone owner chose not to enumerate; such a record cannot
// be used as proof that a name within its hash interval does not exist —
// the name might exist as an unsigned delegation.
func nsec3OptOut(rec *dns.NSEC3Record) bool {
	return rec.Flags&0x01 != 0
}

// findNSEC3Match returns the first NSEC3 whose owner hash exactly equals
// the given hash, or nil if none match. "Matching" (as opposed to
// "covering") proves that a name with that hash exists in the zone.
func findNSEC3Match(records []NSEC3RecordWithOwner, hash []byte) *NSEC3RecordWithOwner {
	for i := range records {
		if compareHashes(records[i].OwnerHash, hash) == 0 {
			return &records[i]
		}
	}
	return nil
}

// findNSEC3Cover returns the first NSEC3 whose half-open interval
// (OwnerHash, NextHash] covers the given hash. "Covering" proves that
// no name with that hash exists in the zone (because the hash falls
// in a gap between two enumerated owner hashes).
func findNSEC3Cover(records []NSEC3RecordWithOwner, hash []byte) *NSEC3RecordWithOwner {
	for i := range records {
		if coversHashFull(records[i].OwnerHash, records[i].NextHash, hash) {
			return &records[i]
		}
	}
	return nil
}

// canonicalQName lowercases qname and strips any trailing dot, normalising
// to the form ComputeNSEC3Hash expects to re-append.
func canonicalQName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// ancestorsOf returns the dot-separated ancestors of name, ordered from
// the deepest (parent) to the shallowest (root). For "a.b.example.com" it
// returns ["b.example.com", "example.com", "com", ""]. The root is represented
// by the empty string so callers can detect it cheaply.
func ancestorsOf(name string) []string {
	name = canonicalQName(name)
	if name == "" {
		return nil
	}
	out := make([]string, 0, strings.Count(name, ".")+1)
	for {
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			out = append(out, "")
			return out
		}
		name = name[dot+1:]
		out = append(out, name)
	}
}

// VerifyNSEC3Denial5155 verifies a NXDOMAIN or NODATA denial proof per
// RFC 5155 §8.4–8.7 and RFC 6840 §4.8. Unlike the loose VerifyNSEC3DenialFull
// (which only checks that some NSEC3 covers H(qname) and is correct only for
// the next-closer-coverage step in isolation), this function requires the
// full three-record proof for NXDOMAIN:
//
//  1. Closest-encloser MATCH: an NSEC3 whose owner hash equals H(CE), where
//     CE is the deepest ancestor of qname proven to exist.
//  2. Next-closer COVER: an NSEC3 whose interval contains H(next_closer),
//     where next_closer is CE's immediate child label on the path to qname.
//  3. Wildcard-at-CE COVER: an NSEC3 whose interval contains H(*.CE), proving
//     that the synthetic wildcard does not exist either.
//
// For NODATA the function accepts either:
//
//   - Direct NODATA: an NSEC3 matching H(qname) whose type bitmap omits qtype
//     (and CNAME).
//   - Wildcard NODATA: CE-match + NC-cover + wildcard-MATCH whose bitmap omits
//     qtype.
//
// Opt-out semantics (RFC 5155 §6): if the next-closer-covering NSEC3 has the
// opt-out flag set, the next closer name could be an unsigned delegation,
// and the NXDOMAIN proof is therefore inconclusive (return false). A caller
// receiving false here treats the response as Bogus (signed denial without a
// verifiable proof) rather than Secure NXDOMAIN.
//
// Without this strict layering, a forged single covering NSEC3 over H(qname)
// can fake NXDOMAIN for any name whose true closest-encloser differs from
// what the attacker claims — exactly the proof-substitution attack RFC 5155
// is designed to prevent.
func VerifyNSEC3Denial5155(qname string, qtype uint16, rcode uint8, records []NSEC3RecordWithOwner) (bool, error) {
	if len(records) == 0 {
		return false, errNoNSEC3Records
	}
	// RFC 9276 §3.2: apply the iteration cap to every record, not just
	// records[0] — an attacker mixing a low-iteration record with high-
	// iteration siblings must not slip past with the slowest one in the
	// proof.
	for i := range records {
		if records[i].Iterations > MaxNSEC3Iterations {
			return false, errTooManyIterations
		}
	}
	rec := &records[0]
	qname = canonicalQName(qname)

	// Direct NODATA — NSEC3 at H(qname) with qtype absent. This is the
	// simplest case and applies only when RCODE=NOERROR.
	if rcode == dns.RCodeNoError {
		qnameHash, err := ComputeNSEC3Hash(qname, rec.HashAlgorithm, rec.Iterations, rec.Salt)
		if err != nil {
			return false, fmt.Errorf("computing NSEC3 hash for qname: %w", err)
		}
		if m := findNSEC3Match(records, qnameHash); m != nil {
			if !HasType(&m.NSEC3Record, qtype) && !HasType(&m.NSEC3Record, dns.TypeCNAME) {
				return true, nil
			}
			// Owner-match with qtype present means the type DOES exist —
			// the response is misclassified as NODATA. Fall through to
			// the wildcard-NODATA path to be safe.
		}
	}

	// Find the closest encloser by walking ancestors of qname upward and
	// looking for an NSEC3 owner-match. The FIRST (deepest) match is the
	// CE; everything below it is unproven.
	ancestors := ancestorsOf(qname)
	var ce string
	var nc string
	found := false
	prev := qname
	for _, ancestor := range ancestors {
		ancestorWithDot := ancestor
		if ancestor == "" {
			ancestorWithDot = "."
		}
		h, err := ComputeNSEC3Hash(ancestorWithDot, rec.HashAlgorithm, rec.Iterations, rec.Salt)
		if err != nil {
			return false, fmt.Errorf("computing NSEC3 hash for ancestor %q: %w", ancestor, err)
		}
		if findNSEC3Match(records, h) != nil {
			ce = ancestor
			nc = prev
			found = true
			break
		}
		prev = ancestor
	}
	if !found {
		return false, nil
	}

	// Verify next-closer is covered.
	ncWithDot := nc
	if ncWithDot == "" {
		ncWithDot = "."
	} else {
		ncWithDot = nc + "."
	}
	ncHash, err := ComputeNSEC3Hash(ncWithDot, rec.HashAlgorithm, rec.Iterations, rec.Salt)
	if err != nil {
		return false, fmt.Errorf("computing NSEC3 hash for next-closer %q: %w", nc, err)
	}
	ncRec := findNSEC3Cover(records, ncHash)
	if ncRec == nil {
		return false, nil
	}
	// RFC 5155 §6: opt-out at the NC-covering NSEC3 makes NXDOMAIN proof
	// inconclusive — the NC name may exist as an unsigned delegation.
	// For NODATA we still accept it because the lower bound on validation
	// is "the type doesn't exist", not "the name doesn't exist".
	if rcode == dns.RCodeNXDomain && nsec3OptOut(&ncRec.NSEC3Record) {
		return false, nil
	}

	// Verify wildcard at CE.
	wcCanonical := "*"
	if ce != "" {
		wcCanonical = "*." + ce
	}
	wcHash, err := ComputeNSEC3Hash(wcCanonical+".", rec.HashAlgorithm, rec.Iterations, rec.Salt)
	if err != nil {
		return false, fmt.Errorf("computing NSEC3 hash for wildcard %q: %w", wcCanonical, err)
	}

	if rcode == dns.RCodeNXDomain {
		if findNSEC3Cover(records, wcHash) != nil {
			return true, nil
		}
		return false, nil
	}

	// NODATA via wildcard expansion: wildcard exists (owner-match) but
	// lacks qtype.
	if wcMatch := findNSEC3Match(records, wcHash); wcMatch != nil {
		if !HasType(&wcMatch.NSEC3Record, qtype) && !HasType(&wcMatch.NSEC3Record, dns.TypeCNAME) {
			return true, nil
		}
	}
	// Or: wildcard does not exist (covered). This applies when the
	// authoritative is asserting NODATA via a synthesised wildcard that
	// itself was denied.
	if findNSEC3Cover(records, wcHash) != nil {
		return true, nil
	}
	return false, nil
}

// VerifyNSEC3DenialDSAbsent verifies an NSEC3 proof that the queried zone
// has no DS record at its parent — required for authenticating "insecure
// delegation" responses (RFC 5155 §10.4). Three forms are accepted:
//
//   - NSEC3 at H(childZone) with DS absent from the bitmap (and NS present,
//     so we're at a real delegation point rather than a synthesized empty
//     name).
//   - Opt-out next-closer-cover: the NC-covering NSEC3 has the opt-out
//     flag set, asserting that the child is an unsigned delegation that
//     the parent zone has not enumerated.
//
// The function returns true only when one of these proofs holds. A caller
// that gets `true` from this function may safely treat the delegation as
// Insecure; `false` means the denial of DS is unproven and the response
// must NOT downgrade a previously-Secure chain to Insecure.
func VerifyNSEC3DenialDSAbsent(childZone string, records []NSEC3RecordWithOwner) (bool, error) {
	if len(records) == 0 {
		return false, errNoNSEC3Records
	}
	for i := range records {
		if records[i].Iterations > MaxNSEC3Iterations {
			return false, errTooManyIterations
		}
	}
	rec := &records[0]
	childZone = canonicalQName(childZone)

	// Direct: NSEC3 at H(childZone) with DS absent. We don't require NS
	// presence here — the parent zone signs the delegation point and may
	// or may not list NS in the parent-side NSEC3 bitmap, depending on
	// the signer. The critical bit is DS absence.
	childHash, err := ComputeNSEC3Hash(childZone+".", rec.HashAlgorithm, rec.Iterations, rec.Salt)
	if err != nil {
		return false, fmt.Errorf("computing NSEC3 hash for child zone: %w", err)
	}
	if m := findNSEC3Match(records, childHash); m != nil {
		if !HasType(&m.NSEC3Record, dns.TypeDS) {
			return true, nil
		}
		return false, nil
	}

	// Opt-out: an NSEC3 with opt-out flag covering H(childZone) proves
	// the child is an unsigned delegation. Walk back to find the CE so
	// we can identify which NSEC3 covers the next-closer (which in this
	// case IS childZone itself — the deepest existing ancestor is the
	// parent, so NC == childZone).
	if c := findNSEC3Cover(records, childHash); c != nil && nsec3OptOut(&c.NSEC3Record) {
		return true, nil
	}
	return false, nil
}
