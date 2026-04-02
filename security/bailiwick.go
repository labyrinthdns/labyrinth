package security

import (
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// SanitizeBailiwick removes records from a DNS response that are
// outside the authority of the responding nameserver's zone.
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
		if _, isGlue := nsNames[rrName]; isGlue {
			filtered = append(filtered, rr)
		}
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
