package resolver

import (
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// extractCNAMETarget finds the CNAME target for qname in the message.
// RDATA is decompressed during Unpack, so we parse directly from rr.RData.
func extractCNAMETarget(msg *dns.Message, qname string) string {
	for _, rr := range msg.Answers {
		if rr.Type == dns.TypeCNAME && strings.ToLower(rr.Name) == qname {
			target, err := dns.ParseCNAME(rr.RData, 0)
			if err == nil && target != "" {
				return strings.ToLower(target)
			}
		}
	}
	return ""
}

// extractDNAMETarget finds the DNAME target for qname in the message (RFC 6672).
// DNAME owner is a parent of qname; the target substitutes the owner suffix.
// Example: qname="a.b.example.com", DNAME owner="example.com", target="target.com"
// → synthesized name = "a.b.target.com"
func extractDNAMETarget(msg *dns.Message, qname string) string {
	for _, rr := range msg.Answers {
		if rr.Type != dns.TypeDNAME {
			continue
		}
		owner := strings.ToLower(rr.Name)
		if !strings.HasSuffix(qname, "."+owner) {
			continue
		}
		target, err := dns.ParseDNAME(rr.RData, 0)
		if err != nil || target == "" {
			continue
		}
		target = strings.ToLower(target)
		// Substitute: strip owner suffix from qname, append target
		prefix := qname[:len(qname)-len(owner)-1] // "a.b" from "a.b.example.com"
		return prefix + "." + target                // "a.b.target.com"
	}
	return ""
}

// extractCNAMERecords returns all CNAME records matching qname from the
// message, together with any RRSIG records that cover the CNAME RRset at the
// same owner. Dropping the covering RRSIG breaks downstream DNSSEC validation
// in clients (e.g. systemd-resolved) chasing CNAME chains, because the chain
// ends up partially signed (signature for the final answer only) — which is
// indistinguishable from a forgery and makes the whole response unverifiable.
func extractCNAMERecords(msg *dns.Message, qname string) []dns.ResourceRecord {
	var result []dns.ResourceRecord
	for _, rr := range msg.Answers {
		if strings.ToLower(rr.Name) != qname {
			continue
		}
		switch rr.Type {
		case dns.TypeCNAME:
			result = append(result, rr)
		case dns.TypeRRSIG:
			parsed, err := dns.ParseRRSIG(rr.RData, 0)
			if err == nil && parsed.TypeCovered == dns.TypeCNAME {
				result = append(result, rr)
			}
		}
	}
	return result
}

// extractRRsForOwnerWithRRSIG returns every record matching qname whose type
// is in the keep set, plus RRSIG records at qname whose TypeCovered is in the
// keep set. Used when forwarding parts of an upstream response that must
// remain independently verifiable by a downstream validator.
func extractRRsForOwnerWithRRSIG(msg *dns.Message, qname string, keep map[uint16]struct{}) []dns.ResourceRecord {
	var result []dns.ResourceRecord
	for _, rr := range msg.Answers {
		if strings.ToLower(rr.Name) != qname {
			continue
		}
		if _, ok := keep[rr.Type]; ok {
			result = append(result, rr)
			continue
		}
		if rr.Type == dns.TypeRRSIG {
			parsed, err := dns.ParseRRSIG(rr.RData, 0)
			if err == nil {
				if _, ok := keep[parsed.TypeCovered]; ok {
					result = append(result, rr)
				}
			}
		}
	}
	return result
}
