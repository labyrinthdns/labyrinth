package resolver

import (
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

type responseType int

const (
	responseAnswer responseType = iota
	responseCNAME
	responseDNAME
	responseReferral
	responseNXDomain
	responseNoData
	responseServFail
)

// soaCoversName reports whether soaOwner is qname or an ancestor of qname.
// Used to enforce the RFC 2308 §3 rule that the SOA in the authority section
// of a negative response must come from a zone that covers the queried name.
// Comparison is case-insensitive and trailing dots are normalised away.
func soaCoversName(soaOwner, qname string) bool {
	soaOwner = strings.ToLower(strings.TrimSuffix(soaOwner, "."))
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	if soaOwner == "" {
		return true // root SOA covers everything
	}
	if soaOwner == qname {
		return true
	}
	return strings.HasSuffix(qname, "."+soaOwner)
}

func classifyResponse(msg *dns.Message, qname string, qtype uint16) responseType {
	rcode := msg.Header.RCODE()

	// 1. NXDOMAIN
	if rcode == dns.RCodeNXDomain {
		return responseNXDomain
	}

	// 2. Server error. FORMERR is grouped here so that a single forged
	// FORMERR (RFC 5452 §6.1 spoofing window) cannot silently downgrade
	// the query — see resolver/upstream.go for the rationale. Treating it
	// as a server failure lets the resolver loop move to a sibling NS
	// rather than retry the same query with EDNS disabled.
	if rcode == dns.RCodeServFail || rcode == dns.RCodeRefused || rcode == dns.RCodeFormErr {
		return responseServFail
	}

	// 3. Has answers
	if msg.Header.ANCount > 0 {
		hasRequestedType := false
		hasCNAME := false
		hasDNAME := false

		for _, rr := range msg.Answers {
			rrName := strings.ToLower(rr.Name)
			if rrName == qname && rr.Type == qtype {
				hasRequestedType = true
			}
			if rrName == qname && rr.Type == dns.TypeCNAME {
				hasCNAME = true
			}
			// DNAME: owner is a parent of qname (RFC 6672)
			if rr.Type == dns.TypeDNAME && strings.HasSuffix(qname, "."+rrName) {
				hasDNAME = true
			}
		}

		// RFC 1034 §3.7 / RFC 2181 §6.1: an authoritative server MUST set
		// AA=1 on responses for names in its zone. The resolver issues
		// iterative queries (RD=0) and addresses them at servers it
		// believes are authoritative for the relevant zone. A response
		// that carries an answer but has AA=0 is either a lame server
		// echoing its cache or an off-path forgery race-winner. Either
		// way the answer is not safe to cache as authoritative — skip
		// the NS and let the resolver try a sibling. (Forwarding mode
		// uses a different code path and never calls classifyResponse,
		// so RD=1 recursive answers without AA are not affected here.)
		if !msg.Header.AA() {
			if hasRequestedType || hasCNAME || hasDNAME {
				return responseServFail
			}
		}
		if hasRequestedType {
			return responseAnswer
		}
		if hasCNAME {
			return responseCNAME
		}
		if hasDNAME {
			return responseDNAME
		}

		// Answer section has records that don't match the question.
		// Check authority section — this may actually be a referral
		// (some servers include unrelated records in the answer section).
		// Fall through to authority section checks below.
	}

	// 4. No answers — check authority
	hasNS := false
	hasSOA := false
	for _, rr := range msg.Authority {
		if rr.Type == dns.TypeNS {
			hasNS = true
		}
		if rr.Type == dns.TypeSOA {
			// RFC 2308 §3: the SOA in the authority section of a negative
			// response identifies the zone of authority. An SOA whose owner
			// is not an ancestor of (or equal to) the queried name has no
			// authority over the name and MUST NOT be used as proof of
			// NXDOMAIN/NODATA — accepting one lets a hostile or buggy
			// authoritative attach an unrelated SOA to forge a negative
			// answer with attacker-controlled minimum-TTL, pinning the
			// name into the negative cache for as long as the SOA dictates.
			if soaCoversName(rr.Name, qname) {
				hasSOA = true
			}
		}
	}

	// 5. Referral
	if hasNS && !hasSOA {
		return responseReferral
	}

	// 6. NODATA
	if hasSOA {
		return responseNoData
	}

	// 7. Fallback
	return responseServFail
}
