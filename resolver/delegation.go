package resolver

import (
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// DelegationNS represents a delegated nameserver with optional glue.
type DelegationNS struct {
	Hostname string
	IPv4     string
	IPv6     string
}

func extractDelegation(msg *dns.Message) ([]DelegationNS, string) {
	var zone string
	nsMap := make(map[string]*DelegationNS)

	// Collect NS hostnames from Authority section.
	// Since RDATA is decompressed during Unpack, we can parse directly from rr.RData.
	for _, rr := range msg.Authority {
		if rr.Type != dns.TypeNS {
			continue
		}
		zone = strings.ToLower(rr.Name)

		nsName, err := dns.ParseNS(rr.RData, 0)
		if err != nil || nsName == "" {
			continue
		}
		nsName = strings.ToLower(nsName)

		if _, exists := nsMap[nsName]; !exists {
			nsMap[nsName] = &DelegationNS{Hostname: nsName}
		}
	}

	// Collect glue records from Additional
	for _, rr := range msg.Additional {
		if rr.Type == dns.TypeOPT {
			continue
		}

		rrName := strings.ToLower(rr.Name)
		ns, exists := nsMap[rrName]
		if !exists {
			continue
		}

		switch rr.Type {
		case dns.TypeA:
			ip, err := dns.ParseA(rr.RData)
			if err == nil {
				ns.IPv4 = ip.String()
			}
		case dns.TypeAAAA:
			ip, err := dns.ParseAAAA(rr.RData)
			if err == nil {
				ns.IPv6 = ip.String()
			}
		}
	}

	result := make([]DelegationNS, 0, len(nsMap))
	for _, ns := range nsMap {
		result = append(result, *ns)
	}

	return result, zone
}
