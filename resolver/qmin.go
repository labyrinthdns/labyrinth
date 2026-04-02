package resolver

import (
	"strings"

	"github.com/labyrinth-dns/labyrinth/dns"
)

// minimizeQName returns a minimized query name and type for the current
// delegation level, implementing RFC 9156 QNAME minimization.
func (r *Resolver) minimizeQName(fullName string, qtype uint16, currentZone string) (string, uint16) {
	if currentZone == "" {
		// At root: extract TLD
		labels := strings.Split(fullName, ".")
		return labels[len(labels)-1], dns.TypeNS
	}

	// Strip current zone suffix to get remaining labels
	remaining := strings.TrimSuffix(fullName, "."+currentZone)
	if remaining == fullName {
		// fullName doesn't end with currentZone — fallback
		return fullName, qtype
	}

	labels := strings.Split(remaining, ".")

	if len(labels) <= 1 {
		// One label left — final query, use real type
		return fullName, qtype
	}

	// Reveal one more label
	nextLabel := labels[len(labels)-1]
	minimized := nextLabel + "." + currentZone
	return minimized, dns.TypeNS
}
