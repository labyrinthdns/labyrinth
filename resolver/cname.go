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

// extractCNAMERecords returns all CNAME records matching qname from the message.
func extractCNAMERecords(msg *dns.Message, qname string) []dns.ResourceRecord {
	var result []dns.ResourceRecord
	for _, rr := range msg.Answers {
		if rr.Type == dns.TypeCNAME && strings.ToLower(rr.Name) == qname {
			result = append(result, rr)
		}
	}
	return result
}
