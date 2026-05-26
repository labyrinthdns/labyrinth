package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// buildNSEC3RecordWithOwner is a small helper that hashes `owner` under the
// given NSEC3 parameters and returns a NSEC3RecordWithOwner whose OwnerHash
// equals H(owner), with the supplied NextHash and type bitmap. It exists so
// proof-construction in tests reads as "an NSEC3 matching <name>" rather
// than a wall of byte manipulation.
func buildNSEC3RecordWithOwner(t *testing.T, owner string, salt []byte, iter uint16, nextHash []byte, types []uint16, flags uint8) NSEC3RecordWithOwner {
	t.Helper()
	hash, err := ComputeNSEC3Hash(owner, 1, iter, salt)
	if err != nil {
		t.Fatalf("hashing %q: %v", owner, err)
	}
	return NSEC3RecordWithOwner{
		NSEC3Record: dns.NSEC3Record{
			HashAlgorithm: 1,
			Flags:         flags,
			Iterations:    iter,
			Salt:          salt,
			NextHash:      nextHash,
			TypeBitMaps:   types,
		},
		OwnerHash: hash,
	}
}

// TestVerifyNSEC3Denial5155_RejectsLooseProof pins the R3 fix: a single
// covering NSEC3 over H(qname) — the legacy "any covering record proves
// nonexistence" shape — must NOT be accepted as proof of NXDOMAIN. Without
// this rejection an attacker who lifts any one valid signed NSEC3 from a
// zone can replay it to forge NXDOMAIN for unrelated names in that zone
// (proof-substitution attack, RFC 5155 §8.4–8.7).
func TestVerifyNSEC3Denial5155_RejectsLooseProof(t *testing.T) {
	salt := []byte{0xAA}
	// Build an NSEC3 with a wide-open interval (owner=0x00…, next=0xFF…)
	// that covers H(qname) for any qname. This is the legacy "loose"
	// proof shape; pre-fix it was accepted.
	ownerHash := make([]byte, 20)
	nextHash := make([]byte, 20)
	for i := range nextHash {
		nextHash[i] = 0xFF
	}
	records := []NSEC3RecordWithOwner{
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1, Flags: 0, Iterations: 0, Salt: salt,
				NextHash: nextHash, TypeBitMaps: []uint16{dns.TypeA},
			},
			OwnerHash: ownerHash,
		},
	}
	denied, err := VerifyNSEC3Denial5155("nonexist.example.com", dns.TypeA,
		dns.RCodeNXDomain, records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Error("loose single-NSEC3 proof must NOT be accepted (RFC 5155 §8.4–8.7)")
	}
}

// TestVerifyNSEC3Denial5155_NXDOMAIN_ProperProof is the positive
// counterpart: a correctly-constructed (CE-match, NC-cover, WC-cover)
// triplet for the zone example.com authoritatively proves that the
// queried name does not exist.
func TestVerifyNSEC3Denial5155_NXDOMAIN_ProperProof(t *testing.T) {
	salt := []byte{0xCC}
	const iter uint16 = 0

	// Place the next-closer hash strictly between the (synthetic) owner
	// hash and next hash of one NSEC3, and the wildcard hash strictly
	// between the owner/next of another. The CE-match NSEC3 is built
	// directly via buildNSEC3RecordWithOwner.

	// Compute the actual hashes for the three names we need to prove
	// statements about.
	ncHash, _ := ComputeNSEC3Hash("nonexist.example.com.", 1, iter, salt)
	wcHash, _ := ComputeNSEC3Hash("*.example.com.", 1, iter, salt)

	// Construct NC-covering NSEC3: owner hash = ncHash - 1, next = ncHash + 1.
	ncOwner := make([]byte, len(ncHash))
	ncNext := make([]byte, len(ncHash))
	copy(ncOwner, ncHash)
	copy(ncNext, ncHash)
	ncOwner[len(ncOwner)-1]--
	ncNext[len(ncNext)-1]++

	wcOwner := make([]byte, len(wcHash))
	wcNext := make([]byte, len(wcHash))
	copy(wcOwner, wcHash)
	copy(wcNext, wcHash)
	wcOwner[len(wcOwner)-1]--
	wcNext[len(wcNext)-1]++

	records := []NSEC3RecordWithOwner{
		// 1) CE-match for example.com
		buildNSEC3RecordWithOwner(t, "example.com.", salt, iter,
			[]byte{0xFF}, []uint16{dns.TypeNS, dns.TypeSOA}, 0),
		// 2) NC-cover for nonexist.example.com
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1, Iterations: iter, Salt: salt,
				NextHash: ncNext, TypeBitMaps: []uint16{dns.TypeA},
			},
			OwnerHash: ncOwner,
		},
		// 3) WC-cover for *.example.com
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1, Iterations: iter, Salt: salt,
				NextHash: wcNext, TypeBitMaps: []uint16{dns.TypeA},
			},
			OwnerHash: wcOwner,
		},
	}

	denied, err := VerifyNSEC3Denial5155("nonexist.example.com", dns.TypeA,
		dns.RCodeNXDomain, records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Error("proper three-NSEC3 NXDOMAIN proof was rejected")
	}
}

// TestVerifyNSEC3Denial5155_OptOutCoveredNCIsNotProof pins RFC 5155 §6:
// when the next-closer-covering NSEC3 has the opt-out flag set, the next
// closer name may exist as an unsigned delegation, so the proof is
// inconclusive and must NOT be accepted as NXDOMAIN.
func TestVerifyNSEC3Denial5155_OptOutCoveredNCIsNotProof(t *testing.T) {
	salt := []byte{0xCC}
	const iter uint16 = 0

	ncHash, _ := ComputeNSEC3Hash("nonexist.example.com.", 1, iter, salt)
	wcHash, _ := ComputeNSEC3Hash("*.example.com.", 1, iter, salt)

	ncOwner := make([]byte, len(ncHash))
	ncNext := make([]byte, len(ncHash))
	copy(ncOwner, ncHash)
	copy(ncNext, ncHash)
	ncOwner[len(ncOwner)-1]--
	ncNext[len(ncNext)-1]++

	wcOwner := make([]byte, len(wcHash))
	wcNext := make([]byte, len(wcHash))
	copy(wcOwner, wcHash)
	copy(wcNext, wcHash)
	wcOwner[len(wcOwner)-1]--
	wcNext[len(wcNext)-1]++

	records := []NSEC3RecordWithOwner{
		buildNSEC3RecordWithOwner(t, "example.com.", salt, iter,
			[]byte{0xFF}, []uint16{dns.TypeNS, dns.TypeSOA}, 0),
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1, Iterations: iter, Salt: salt,
				Flags:    0x01, // opt-out
				NextHash: ncNext, TypeBitMaps: []uint16{dns.TypeA},
			},
			OwnerHash: ncOwner,
		},
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1, Iterations: iter, Salt: salt,
				NextHash: wcNext, TypeBitMaps: []uint16{dns.TypeA},
			},
			OwnerHash: wcOwner,
		},
	}

	denied, err := VerifyNSEC3Denial5155("nonexist.example.com", dns.TypeA,
		dns.RCodeNXDomain, records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Error("opt-out NC-cover must invalidate NXDOMAIN proof (RFC 5155 §6)")
	}
}

// TestVerifyNSEC3Denial5155_NODATA_DirectMatch pins the simpler NODATA
// case: an NSEC3 owner-matching H(qname) whose type bitmap excludes qtype
// directly proves NODATA.
func TestVerifyNSEC3Denial5155_NODATA_DirectMatch(t *testing.T) {
	salt := []byte{0xDD}
	const iter uint16 = 0

	// qname matches owner; bitmap has AAAA but not A → NODATA for A.
	records := []NSEC3RecordWithOwner{
		buildNSEC3RecordWithOwner(t, "exists.example.com.", salt, iter,
			[]byte{0xFF}, []uint16{dns.TypeAAAA}, 0),
	}
	denied, err := VerifyNSEC3Denial5155("exists.example.com", dns.TypeA,
		dns.RCodeNoError, records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Error("NODATA proof (NSEC3 at qname, type absent) was rejected")
	}
}

// TestVerifyNSEC3Denial5155_PerRecordIterationCap pins the RFC 9276 §3.2
// refinement: the 100-iteration ceiling applies to EVERY NSEC3 record in
// the proof, not just records[0]. Without this, an attacker could mix a
// low-iteration leader record with high-iteration siblings to slip past
// validation while still imposing the CPU cost of high iterations on
// follow-up hash computations.
func TestVerifyNSEC3Denial5155_PerRecordIterationCap(t *testing.T) {
	salt := []byte{0xEE}
	records := []NSEC3RecordWithOwner{
		// First record: iterations within cap (passes the old single-record check).
		buildNSEC3RecordWithOwner(t, "example.com.", salt, 0,
			[]byte{0xFF}, []uint16{dns.TypeNS}, 0),
		// Second record: iterations OVER the cap. With the old check
		// (records[0] only) this would have been silently accepted.
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1, Iterations: MaxNSEC3Iterations + 1,
				Salt: salt, NextHash: []byte{0xFF},
			},
			OwnerHash: []byte{0x00},
		},
	}
	_, err := VerifyNSEC3Denial5155("nonexist.example.com", dns.TypeA,
		dns.RCodeNXDomain, records)
	if err != errTooManyIterations {
		t.Errorf("per-record iteration cap not enforced: got err=%v, want %v",
			err, errTooManyIterations)
	}
}

// TestVerifyNSEC3DenialDSAbsent_DirectMatch pins the R4 NSEC3 helper: an
// NSEC3 at H(childZone) whose bitmap omits DS authenticates the parent's
// claim that the child is an unsigned delegation.
func TestVerifyNSEC3DenialDSAbsent_DirectMatch(t *testing.T) {
	salt := []byte{0xAA}
	records := []NSEC3RecordWithOwner{
		buildNSEC3RecordWithOwner(t, "insecure.example.", salt, 0,
			[]byte{0xFF}, []uint16{dns.TypeNS}, 0),
	}
	ok, err := VerifyNSEC3DenialDSAbsent("insecure.example", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("DS-absent proof (NSEC3 at child, DS bit clear) was rejected")
	}
}

// TestVerifyNSEC3DenialDSAbsent_DSPresentRejected: if the child's NSEC3
// bitmap actually advertises DS, the parent is *not* claiming insecure
// delegation. The function must return false.
func TestVerifyNSEC3DenialDSAbsent_DSPresentRejected(t *testing.T) {
	salt := []byte{0xBB}
	records := []NSEC3RecordWithOwner{
		buildNSEC3RecordWithOwner(t, "secure.example.", salt, 0,
			[]byte{0xFF}, []uint16{dns.TypeNS, dns.TypeDS}, 0),
	}
	ok, err := VerifyNSEC3DenialDSAbsent("secure.example", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("NSEC3 advertising DS must not authenticate DS-absent claim")
	}
}

// TestVerifyNSEC3DenialDSAbsent_OptOutCoverProves: when no NSEC3 owner-
// matches the child but an opt-out NSEC3 covers H(child), the parent has
// asserted that the child is an unsigned delegation under the opt-out
// span. This is the canonical RFC 5155 §6 insecure-delegation pattern
// used by TLDs that publish opt-out (com, net, …).
func TestVerifyNSEC3DenialDSAbsent_OptOutCoverProves(t *testing.T) {
	salt := []byte{0xCC}
	childHash, _ := ComputeNSEC3Hash("opt.example.", 1, 0, salt)
	owner := make([]byte, len(childHash))
	next := make([]byte, len(childHash))
	copy(owner, childHash)
	copy(next, childHash)
	owner[len(owner)-1]--
	next[len(next)-1]++

	records := []NSEC3RecordWithOwner{
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1, Flags: 0x01 /* opt-out */, Iterations: 0,
				Salt: salt, NextHash: next, TypeBitMaps: []uint16{dns.TypeNS},
			},
			OwnerHash: owner,
		},
	}
	ok, err := VerifyNSEC3DenialDSAbsent("opt.example", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("opt-out NSEC3 covering child hash must authenticate insecure delegation")
	}
}

// TestVerifyNSEC3DenialDSAbsent_NonOptOutCoverDoesNotProve: a covering
// NSEC3 *without* opt-out doesn't authorise downgrade — that would be
// the original empty-DS spoofing attack the R4 fix is built around.
func TestVerifyNSEC3DenialDSAbsent_NonOptOutCoverDoesNotProve(t *testing.T) {
	salt := []byte{0xDD}
	childHash, _ := ComputeNSEC3Hash("forge.example.", 1, 0, salt)
	owner := make([]byte, len(childHash))
	next := make([]byte, len(childHash))
	copy(owner, childHash)
	copy(next, childHash)
	owner[len(owner)-1]--
	next[len(next)-1]++

	records := []NSEC3RecordWithOwner{
		{
			NSEC3Record: dns.NSEC3Record{
				HashAlgorithm: 1, Flags: 0, /* NO opt-out */
				Iterations: 0, Salt: salt, NextHash: next,
			},
			OwnerHash: owner,
		},
	}
	ok, err := VerifyNSEC3DenialDSAbsent("forge.example", records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("non-opt-out covering NSEC3 must NOT authenticate insecure delegation")
	}
}

// TestVerifyDSDenial_UnsignedEmptyResponseRejected pins the R4 fix at
// the validator layer: an empty-DS authority section with no RRSIG must
// be rejected, regardless of what NSEC/NSEC3 records it carries. The
// pre-0.6.12 code treated empty-DS as Insecure automatically — this is
// the off-path downgrade vector RFC 4035 §5.2 closes.
func TestVerifyDSDenial_UnsignedEmptyResponseRejected(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	// The parent (root) DNSKEYs are set; the authority section carries
	// only an NSEC3 — no RRSIG. Without a signature, the proof cannot
	// authenticate.
	parentKeys := ti.mq.responses[".|48"].Answers
	authority := []dns.ResourceRecord{
		{
			Name:  "abc123.",
			Type:  dns.TypeNSEC3,
			Class: dns.ClassIN,
			TTL:   3600,
			RData: nil, // contents irrelevant — there's no RRSIG to validate
		},
	}
	ok := ti.v.verifyDSDenial("child.", ".", parentKeys, authority)
	if ok {
		t.Error("unsigned empty-DS authority must NOT authenticate insecure delegation")
	}
}

// TestVerifyDSDenial_NoParentKeysRejected pins the defense-in-depth
// guard: if the caller has no parent keys (e.g. an unusual chain-walker
// state) we MUST refuse rather than fall back to a permissive verdict.
func TestVerifyDSDenial_NoParentKeysRejected(t *testing.T) {
	ti := newTestInfra()
	ti.setRootDNSKEYs()

	authority := []dns.ResourceRecord{
		{Name: "x.", Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: 60, RData: nil},
	}
	ok := ti.v.verifyDSDenial("child.", ".", nil, authority)
	if ok {
		t.Error("verifyDSDenial without parent keys must refuse the denial")
	}
}
