package dnssec

import (
	"errors"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

var errNoNSECRecords = errors.New("dnssec: no NSEC records provided")

// NSECRecordWithOwner pairs a parsed NSEC RDATA with the owner name from
// the resource record. The owner is required for both canonical range
// coverage checks and NODATA proofs (which compare owner against qname).
type NSECRecordWithOwner struct {
	dns.NSECRecord
	OwnerName string
}

// VerifyNSECDenial verifies an NSEC denial proof for a NODATA or NXDOMAIN
// response. Returns true if the records authenticate the negative answer.
//
// Three forms are accepted:
//
//  1. NODATA (RFC 4035 §5.4) — an NSEC at owner == qname whose type bitmap
//     does not include qtype or CNAME. A delegation-style NSEC (NS bit set
//     without SOA) is rejected: it belongs to the parent zone and proves
//     nothing about types served at the child.
//
//  2. NXDOMAIN — covering NSEC for qname plus covering NSEC for the wildcard
//     `*.closest_encloser` derived from the qname-covering NSEC. This is the
//     standard two-NSEC name-error proof.
//
//  3. Compact denial of existence (draft-ietf-dnsop-compact-denial-of-existence,
//     widely deployed by Cloudflare as "black lies"). For an NXDOMAIN response
//     the auth server returns an NSEC at owner == qname whose bitmap excludes
//     CNAME and DNAME, asserting the name has no useful records. Treated as a
//     valid NXDOMAIN proof: the RCODE is signer-authenticated via the SOA
//     RRSIG and the NSEC bitmap denies every type the client could have wanted.
func VerifyNSECDenial(qname string, qtype uint16, rcode uint8, records []NSECRecordWithOwner) (bool, error) {
	if len(records) == 0 {
		return false, errNoNSECRecords
	}
	qname = canonicalName(qname)

	// 1) NODATA — NSEC at qname denying qtype.
	for _, n := range records {
		owner := canonicalName(n.OwnerName)
		if owner != qname {
			continue
		}
		if nsecHasType(&n.NSECRecord, qtype) {
			continue
		}
		if nsecHasType(&n.NSECRecord, dns.TypeCNAME) {
			continue
		}
		// A parent-side NSEC at a delegation point has NS set and SOA clear.
		// It cannot prove NODATA for the child zone's own data.
		if nsecHasType(&n.NSECRecord, dns.TypeNS) && !nsecHasType(&n.NSECRecord, dns.TypeSOA) {
			continue
		}
		return true, nil
	}

	if rcode != dns.RCodeNXDomain {
		return false, nil
	}

	// 2) Compact denial — NSEC at qname with no CNAME/DNAME, paired with an
	//    NXDOMAIN RCODE. Cloudflare and other online signers emit this rather
	//    than a real two-NSEC closest-encloser proof.
	for _, n := range records {
		owner := canonicalName(n.OwnerName)
		if owner != qname {
			continue
		}
		if nsecHasType(&n.NSECRecord, dns.TypeCNAME) {
			continue
		}
		if nsecHasType(&n.NSECRecord, dns.TypeDNAME) {
			continue
		}
		if nsecHasType(&n.NSECRecord, dns.TypeNS) && !nsecHasType(&n.NSECRecord, dns.TypeSOA) {
			continue
		}
		return true, nil
	}

	// 3) Standard RFC 4035 §5.4 — covering NSEC for qname AND wildcard NSEC.
	var coveringOwner, coveringNext string
	covered := false
	for _, n := range records {
		owner := canonicalName(n.OwnerName)
		next := canonicalName(n.NextDomainName)
		if nsecCoversName(owner, next, qname) {
			coveringOwner = owner
			coveringNext = next
			covered = true
			break
		}
	}
	if !covered {
		return false, nil
	}

	ce := closestEncloser(qname, coveringOwner, coveringNext)
	if ce == "" {
		// Closest encloser is the root.
		ce = ""
	}

	wildcard := "*"
	if ce != "" {
		wildcard = "*." + ce
	}

	for _, n := range records {
		owner := canonicalName(n.OwnerName)
		next := canonicalName(n.NextDomainName)
		// Wildcard does not exist: covering NSEC over *.<ce>.
		if nsecCoversName(owner, next, wildcard) {
			return true, nil
		}
		// Wildcard exists but lacks qtype (wildcard NODATA after expansion).
		if owner == wildcard && !nsecHasType(&n.NSECRecord, qtype) &&
			!nsecHasType(&n.NSECRecord, dns.TypeCNAME) {
			return true, nil
		}
	}

	return false, nil
}

// nsecCoversName reports whether qname falls in the open canonical interval
// (owner, next). Handles wrap-around for the zone's last NSEC where the
// owner sorts after next.
func nsecCoversName(owner, next, qname string) bool {
	cmpOwner := canonicalCompareName(qname, owner)
	cmpNext := canonicalCompareName(qname, next)
	if canonicalCompareName(owner, next) < 0 {
		return cmpOwner > 0 && cmpNext < 0
	}
	// Wrap: qname > owner OR qname < next.
	return cmpOwner > 0 || cmpNext < 0
}

// closestEncloser derives the closest existing ancestor of qname from a
// covering NSEC. Per RFC 4035 §5.4 the closest encloser is the longest
// ancestor of qname that is also an ancestor of either the NSEC owner or
// the NSEC next-domain. We pick whichever side yields the longer ancestor.
func closestEncloser(qname, owner, next string) string {
	a := commonAncestor(qname, owner)
	b := commonAncestor(qname, next)
	if labelCount(a) >= labelCount(b) {
		return a
	}
	return b
}

// commonAncestor returns the longest suffix shared by a and b, comparing
// labels from the rightmost (TLD) toward the left.
func commonAncestor(a, b string) string {
	aLabels := canonicalLabels(a)
	bLabels := canonicalLabels(b)
	aIdx := len(aLabels) - 1
	bIdx := len(bLabels) - 1
	matched := 0
	for aIdx >= 0 && bIdx >= 0 && aLabels[aIdx] == bLabels[bIdx] {
		matched++
		aIdx--
		bIdx--
	}
	if matched == 0 {
		return ""
	}
	return strings.Join(aLabels[len(aLabels)-matched:], ".")
}

// labelCount returns the number of labels in a canonical (dot-separated) name.
func labelCount(name string) int {
	if name == "" {
		return 0
	}
	return strings.Count(name, ".") + 1
}

// canonicalName lowercases the name and strips the trailing root dot, the
// form used for canonical comparison throughout this file.
func canonicalName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// canonicalLabels returns the canonical labels of name in left-to-right
// order. Empty name (root) returns nil.
func canonicalLabels(name string) []string {
	name = canonicalName(name)
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// canonicalCompareName returns -1, 0, or 1 per RFC 4034 §6.1 canonical
// DNS name ordering: compare labels from the rightmost (TLD) toward the
// left, each label compared as a byte string with shorter sorting first.
func canonicalCompareName(a, b string) int {
	aLabels := canonicalLabels(a)
	bLabels := canonicalLabels(b)
	aIdx := len(aLabels) - 1
	bIdx := len(bLabels) - 1
	for aIdx >= 0 && bIdx >= 0 {
		if c := compareLabelBytes(aLabels[aIdx], bLabels[bIdx]); c != 0 {
			return c
		}
		aIdx--
		bIdx--
	}
	switch {
	case aIdx < 0 && bIdx < 0:
		return 0
	case aIdx < 0:
		return -1
	default:
		return 1
	}
}

// compareLabelBytes does an octet-wise comparison of two labels (already
// lowercased). Per RFC 4034 §6.1 the shorter label sorts before the longer
// one when they share a common prefix.
func compareLabelBytes(a, b string) int {
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
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// nsecHasType reports whether the NSEC type bitmap includes rrtype.
func nsecHasType(rec *dns.NSECRecord, rrtype uint16) bool {
	for _, t := range rec.TypeBitMaps {
		if t == rrtype {
			return true
		}
	}
	return false
}
