package security

import (
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// SanitizeBailiwick removes records from a DNS response that are
// outside the authority of the responding nameserver's zone.
//
// Out-of-bailiwick glue (e.g. a `.com` server returning glue for
// `ns.evil.org` to back an example.com delegation) is dropped: an
// out-of-zone responder has no authority to bind a hostname to an
// address. Such records must be re-resolved through the proper
// chain of authority. RFC 8499 §7 / RFC 1034 §4.2.1.
//
// When zone is empty (the priming/root case), the filter is
// permissive: the root server is allowed to publish glue for any
// TLD nameserver, since that is exactly its job.
func SanitizeBailiwick(msg *dns.Message, zone string) {
	zone = strings.ToLower(zone)

	msg.Answers = filterInZone(msg.Answers, zone)
	msg.Authority = filterInZone(msg.Authority, zone)

	// Additional: keep glue only for NS names in Authority + always keep OPT.
	// Since RDATA is decompressed during Unpack, parse directly from rr.RData.
	nsNames := make(map[string]struct{})
	for _, rr := range msg.Authority {
		if rr.Type == dns.TypeNS {
			nsName, err := dns.ParseNS(rr.RData, 0)
			if err == nil {
				nsNames[strings.ToLower(nsName)] = struct{}{}
			}
		}
	}

	filtered := msg.Additional[:0]
	for _, rr := range msg.Additional {
		if rr.Type == dns.TypeOPT {
			filtered = append(filtered, rr)
			continue
		}
		rrName := strings.ToLower(rr.Name)
		if _, isGlue := nsNames[rrName]; !isGlue {
			continue
		}
		// Reject out-of-bailiwick glue. A server authoritative for
		// "com." has no business asserting addresses for "ns.evil.org" —
		// that's a classic cache-poisoning vector. The resolver must
		// chase such glue through the proper authority chain.
		if !InZone(rrName, zone) {
			continue
		}
		filtered = append(filtered, rr)
	}
	msg.Additional = filtered
}

func filterInZone(records []dns.ResourceRecord, zone string) []dns.ResourceRecord {
	if zone == "" {
		return records
	}

	filtered := records[:0]
	for _, rr := range records {
		rrName := strings.ToLower(rr.Name)
		if InZone(rrName, zone) {
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

// InZone checks if name is at or below zone.
func InZone(name string, zone string) bool {
	if zone == "" {
		return true
	}
	if name == zone {
		return true
	}
	return strings.HasSuffix(name, "."+zone)
}
