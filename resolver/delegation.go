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

// extractDelegation retains the package helper used by older callers that do
// not have the upstream QNAME. Production resolution uses
// extractDelegationForQName so owner selection is bound to the actual query.
func extractDelegation(msg *dns.Message, maxNames int) ([]DelegationNS, string) {
	return extractDelegationForQName(msg, "", maxNames)
}

func extractDelegationForQName(msg *dns.Message, qname string, maxNames int) ([]DelegationNS, string) {
	qname = canonicalDNSName(qname)

	// A referral may contain multiple NS owners. Only one can be the next
	// delegation point: the closest (longest) ancestor of the name that was
	// actually queried upstream. Mixing owners lets a sibling RRset replace the
	// intended delegation, and also lets its Additional records become glue.
	zone := ""
	foundZone := false
	for _, rr := range msg.Authority {
		if rr.Type != dns.TypeNS {
			continue
		}
		owner := canonicalDNSName(rr.Name)
		if qname != "" && !nameAtOrBelow(qname, owner) {
			continue
		}
		if !foundZone || (qname != "" && len(owner) > len(zone)) {
			zone = owner
			foundZone = true
		}
	}
	if !foundZone {
		return nil, ""
	}

	nsMap := make(map[string]*DelegationNS)
	// Collect only the NS RRset at the selected delegation owner. Since RDATA
	// is decompressed during Unpack, it can be parsed directly.
	for _, rr := range msg.Authority {
		if rr.Type != dns.TypeNS || canonicalDNSName(rr.Name) != zone {
			continue
		}

		nsName, err := dns.ParseNS(rr.RData, 0)
		if err != nil || nsName == "" {
			continue
		}
		nsName = canonicalDNSName(nsName)

		// Apply the cap to distinct names in this RRset only. An unrelated
		// owner cannot consume the budget before the real delegation is read.
		if _, exists := nsMap[nsName]; !exists {
			if maxNames > 0 && len(nsMap) >= maxNames {
				continue
			}
			nsMap[nsName] = &DelegationNS{Hostname: nsName}
		}
	}

	// Glue is usable only for an NS name at or below the selected delegation
	// owner. Out-of-bailiwick NS names remain valid delegation targets, but
	// their addresses must be resolved through their own authority chain.
	for _, rr := range msg.Additional {
		if rr.Type == dns.TypeOPT || rr.Class != dns.ClassIN {
			continue
		}

		rrName := canonicalDNSName(rr.Name)
		ns, exists := nsMap[rrName]
		if !exists || !nameAtOrBelow(rrName, zone) {
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

func canonicalDNSName(name string) string {
	return strings.ToLower(strings.TrimRight(name, "."))
}

// nameAtOrBelow performs a label-boundary-aware ancestor check. The empty
// canonical name represents the root and therefore covers every name.
func nameAtOrBelow(name, zone string) bool {
	if zone == "" {
		return true
	}
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// validateReferralNS checks whether NS hostnames are plausibly related to
// the delegated zone. This is a harden-referral-path soft check: suspicious
// NS names are logged but not rejected, since some legitimate setups use
// external nameservers.
//
// Two whole classes of zones are skipped because their NS-naming conventions
// guarantee a false positive otherwise:
//
//   - **TLDs (1-label zones like "com", "net", "tr").** gTLDs are served by
//     Verisign/IANA infrastructure (`*.gtld-servers.net`, `*.nic.it` etc.)
//     and ccTLDs by registry-operator domains — all structurally out of
//     bailiwick of the TLD label itself.
//   - **The `arpa` tree (in-addr.arpa, ip6.arpa, and any subzone).** Reverse
//     DNS delegations are issued by IANA / the five RIRs from their own
//     domains (`*.lacnic.net`, `*.ripe.net`, `*.arin.net`, `*.apnic.net`,
//     `*.afrinic.net`, `*.in-addr-servers.arpa`). Out-of-bailiwick is the
//     normal case here, not an anomaly.
//
// Without these skips a single PTR lookup produced ~10 WARN events on every
// resolution — drowning real "suspicious NS" findings in noise.
func validateReferralNS(delegations []DelegationNS, zone string, logger *slog.Logger) {
	if logger == nil || zone == "" {
		return
	}

	zone = strings.ToLower(strings.TrimSuffix(zone, "."))

	// Skip TLD referrals (single-label zone): registry infrastructure is
	// structurally out of bailiwick of the TLD label.
	if !strings.Contains(zone, ".") {
		return
	}
	// Skip the entire arpa hierarchy: RIR-served reverse delegations are
	// always out of bailiwick of *.arpa, by IANA convention.
	if zone == "arpa" || strings.HasSuffix(zone, ".arpa") {
		return
	}

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
