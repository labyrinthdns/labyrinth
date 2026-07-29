package resolver

import (
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// minimizeQName returns a minimized query name and type for the current
// delegation level, implementing RFC 9156 QNAME minimization.
func (r *Resolver) minimizeQName(fullName string, qtype uint16, currentZone string) (string, uint16) {
	// Root-zone query (qname is root itself) — never minimize, ask the
	// real qtype directly. Without this guard, asking for "." DNSKEY at
	// the root would be rewritten into an NS query and the chain-of-trust
	// walker would never see the root DNSKEY RRset, breaking every
	// DNSSEC validation downstream.
	if fullName == "" {
		return fullName, qtype
	}
	// DS records are published by the PARENT zone, not the child. Qmin's
	// rewrite-to-NS step takes the resolver one delegation step too far —
	// it ends up at the child's authoritative server, which has no DS for
	// itself, and the response is NODATA. The natural iterative descent
	// without minimization stops at the parent exactly where the DS lives,
	// so skip qmin for TypeDS. Without this, every chain-of-trust walk
	// fails at the first non-root level (RFC 9156 §3 / §4.1).
	if qtype == dns.TypeDS {
		return fullName, qtype
	}
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
