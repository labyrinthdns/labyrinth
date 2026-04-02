package resolver

import (
	"strings"

	"github.com/labyrinth-dns/labyrinth/dns"
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
