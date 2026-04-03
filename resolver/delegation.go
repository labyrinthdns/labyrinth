package resolver

import (
	"log/slog"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// DelegationNS represents a delegated nameserver with optional glue.
type DelegationNS struct {
	Hostname string
	IPv4     string
	IPv6     string
	IPv4TTL  uint32
	IPv6TTL  uint32
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
				ns.IPv4TTL = rr.TTL
			}
		case dns.TypeAAAA:
			ip, err := dns.ParseAAAA(rr.RData)
			if err == nil {
				ns.IPv6 = ip.String()
				ns.IPv6TTL = rr.TTL
			}
		}
	}

	result := make([]DelegationNS, 0, len(nsMap))
	for _, ns := range nsMap {
		result = append(result, *ns)
	}

	return result, zone
}

// validateReferralNS checks whether NS hostnames are plausibly related to
// the delegated zone. This is a harden-referral-path soft check: suspicious
// NS names are logged but not rejected, since some legitimate setups use
// external nameservers.
func validateReferralNS(delegations []DelegationNS, zone string, logger *slog.Logger) {
	if logger == nil || zone == "" {
		return
	}

	zone = strings.ToLower(strings.TrimSuffix(zone, "."))

	// Build the parent hierarchy for the zone.
	// For "example.com", hierarchy is ["example.com", "com", ""]
	var hierarchy []string
	parts := strings.Split(zone, ".")
	for i := 0; i < len(parts); i++ {
		hierarchy = append(hierarchy, strings.Join(parts[i:], "."))
	}

	for _, ns := range delegations {
		hostname := strings.ToLower(strings.TrimSuffix(ns.Hostname, "."))
		if hostname == "" {
			continue
		}

		related := false

		// Check if NS hostname is within the delegated zone
		if hostname == zone || strings.HasSuffix(hostname, "."+zone) {
			related = true
		}

		// Check if NS hostname is within any parent of the zone
		if !related {
			for _, parent := range hierarchy {
				if parent == "" {
					continue
				}
				if hostname == parent || strings.HasSuffix(hostname, "."+parent) {
					related = true
					break
				}
			}
		}

		if !related {
			logger.Warn("suspicious NS in referral: NS hostname unrelated to delegated zone",
				"zone", zone,
				"ns_hostname", ns.Hostname,
			)
		}
	}
}
