package resolver

import (
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// specialUseResponse returns a synthesized ResolveResult for queries that
// fall under an RFC 6761 / RFC 7686 / RFC 8375 special-use domain name, or
// nil if the name is not special-use.
//
// These names MUST NOT be resolved via the public DNS hierarchy:
//
//   - **.onion** (RFC 7686 §2): "Name resolution requests for .onion names
//     MUST NOT be performed [by recursive resolvers], to avoid privacy
//     leaks." Tor de-anonymization risk.
//   - **.invalid** (RFC 6761 §6.4): "Caching DNS servers SHOULD recognize
//     .invalid names as special and SHOULD, as a performance optimization,
//     generate immediate negative responses."
//   - **.test** (RFC 6761 §6.2): same SHOULD-immediate-NXDOMAIN guidance.
//   - **.example** (RFC 6761 §6.5): reserved for documentation; recursive
//     resolvers SHOULD NOT forward to the public DNS root.
//   - **.local** (RFC 6762 §3 / RFC 6761 §6.3): mDNS namespace; "DNS
//     servers SHOULD NOT attempt to look up names ending in .local."
//   - **home.arpa** (RFC 8375 §3): residential homenet namespace; "must be
//     locally served and never forwarded to the public DNS root."
//
// `localhost` is intentionally NOT covered here — that is handled via the
// `localhost.` local zone bootstrap (RFC 6761 §6.3 mandates 127.0.0.1/::1
// answers, which is structurally a zone, not a synthesized NXDOMAIN).
//
// The function returns NXDOMAIN with an empty authority section. The caller
// short-circuits the recursive pipeline so the name never appears on the
// wire to upstreams.
func specialUseResponse(name string, qtype uint16, qclass uint16) *ResolveResult {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if n == "" {
		return nil
	}

	switch {
	case n == "onion" || strings.HasSuffix(n, ".onion"):
	case n == "invalid" || strings.HasSuffix(n, ".invalid"):
	case n == "test" || strings.HasSuffix(n, ".test"):
	case n == "example" || strings.HasSuffix(n, ".example") ||
		n == "example.com" || strings.HasSuffix(n, ".example.com") ||
		n == "example.net" || strings.HasSuffix(n, ".example.net") ||
		n == "example.org" || strings.HasSuffix(n, ".example.org"):
		// RFC 6761 §6.5: example, example.com, example.net, example.org
		// are all reserved. example.{com,net,org} are real authoritative
		// names with public delegations, but per the RFC resolvers
		// SHOULD treat them as locally served. Returning NXDOMAIN here
		// would break documentation/test workflows that point at the
		// real authoritative example.com; we therefore fall through to
		// upstream resolution for those three. Only the bare TLDs
		// .example, .test, .invalid, .onion get the NXDOMAIN short-
		// circuit per the RFC's privacy/correctness intent.
		if n == "example.com" || strings.HasSuffix(n, ".example.com") ||
			n == "example.net" || strings.HasSuffix(n, ".example.net") ||
			n == "example.org" || strings.HasSuffix(n, ".example.org") {
			return nil
		}
	case n == "local" || strings.HasSuffix(n, ".local"):
	case n == "home.arpa" || strings.HasSuffix(n, ".home.arpa"):
	default:
		return nil
	}

	// All matched cases land here with NXDOMAIN.
	_ = qtype
	_ = qclass
	return &ResolveResult{
		RCODE: dns.RCodeNXDomain,
	}
}
