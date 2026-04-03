package resolver

import (
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

type responseType int

const (
	responseAnswer responseType = iota
	responseCNAME
	responseReferral
	responseNXDomain
	responseNoData
	responseServFail
)

func classifyResponse(msg *dns.Message, qname string, qtype uint16) responseType {
	rcode := msg.Header.RCODE()

	// 1. NXDOMAIN
	if rcode == dns.RCodeNXDomain {
		return responseNXDomain
	}

	// 2. Server error
	if rcode == dns.RCodeServFail || rcode == dns.RCodeRefused {
		return responseServFail
	}

	// 3. Has answers
	if msg.Header.ANCount > 0 {
		hasRequestedType := false
		hasCNAME := false

		for _, rr := range msg.Answers {
			rrName := strings.ToLower(rr.Name)
			if rrName == qname && rr.Type == qtype {
				hasRequestedType = true
			}
			if rrName == qname && rr.Type == dns.TypeCNAME {
				hasCNAME = true
			}
		}

		if hasRequestedType {
			return responseAnswer
		}
		if hasCNAME {
			return responseCNAME
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
			hasSOA = true
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
