package dns

import (
	"sort"
	"strings"
)

// RFC 9462 (Discovery of Designated Resolvers) and RFC 9606 (RESINFO).
//
// # The problem DDR solves
//
// Labyrinth speaks DoT, DoH and DoQ, and an operator can turn all three on.
// A client that got this resolver's address from DHCP has no way to find out
// — it has an IP address and nothing else, so it uses plaintext port 53 and
// the encrypted listeners sit idle. DDR is the bootstrap: the client sends a
// SVCB query for the special name `_dns.resolver.arpa.` over the plaintext
// channel it already has, and the resolver answers with a description of its
// own encrypted endpoints.
//
// # Why the answer is not itself a security claim
//
// The DDR answer arrives unauthenticated over plaintext, so an attacker on
// the path can forge one. RFC 9462 §4.2 handles this by making the *client*
// verify: it must check that the TLS certificate presented by the designated
// endpoint covers the IP address of the resolver it was originally configured
// with. A forged designation pointing at an attacker's server fails that
// check. That is why this code can serve a designation without the resolver
// having to prove anything in-band — and why the target name we advertise
// must be one whose certificate actually covers our address, which is an
// operator responsibility the config documents.
//
// # RESINFO
//
// RFC 9606 is the smaller sibling: a TXT-shaped record at the resolver's own
// name listing what it does — whether it minimises QNAMEs, which extended
// error codes it emits, where to read its policy. It answers "what is this
// resolver going to do to my queries?" without requiring the client to probe
// for each behaviour.

// DDRQueryName is the special-use name a client queries to discover
// designated resolvers by IP address (RFC 9462 §4). It is served locally and
// must never be forwarded — resolver.arpa has no delegation in the global
// DNS, so a forwarded query would leak the client's discovery attempt and
// return NXDOMAIN.
const DDRQueryName = "_dns.resolver.arpa"

// DDRTTL is the TTL on designation records. RFC 9462 §4.1 uses 7200 in its
// examples; the value trades off how fast an endpoint change propagates
// against how often clients re-query for something that rarely changes.
const DDRTTL uint32 = 7200

// ALPN identifiers for the encrypted DNS transports, from the IANA TLS
// Application-Layer Protocol Negotiation registry. RFC 9461 §4 specifies
// which one designates which transport.
const (
	ALPNDoT  = "dot" // RFC 7858, via RFC 9461 §4
	ALPNDoH2 = "h2"  // RFC 8484 over HTTP/2
	ALPNDoH3 = "h3"  // RFC 8484 over HTTP/3
	ALPNDoQ  = "doq" // RFC 9250
)

// DesignatedResolver describes one encrypted endpoint to advertise.
type DesignatedResolver struct {
	// Priority is the SVCB priority. Lower is preferred; RFC 9460 §2.4.2
	// reserves 0 for AliasMode, so a designation is always >= 1.
	Priority uint16
	// Target is the DNS name of the endpoint. Its certificate must cover
	// the address the client already has for this resolver, or the client
	// will reject the designation per RFC 9462 §4.2.
	Target string
	// ALPNs are the protocols this endpoint speaks.
	ALPNs []string
	// Port is the endpoint port. Zero omits the parameter, which tells the
	// client to use the default for the ALPN (853 for dot/doq, 443 for
	// h2/h3).
	Port uint16
	// DoHPath is the RFC 9461 §5 URI template, required for h2/h3
	// designations and meaningless otherwise.
	DoHPath string
}

// DDRConfig describes which transports to advertise.
type DDRConfig struct {
	// TargetName is the DNS name clients should connect to. Empty disables
	// DDR entirely: without a name whose certificate covers this resolver's
	// address, every designation we published would fail the client's
	// RFC 9462 §4.2 verification, and we would be spending a round trip to
	// hand out something guaranteed not to work.
	TargetName string

	DoTEnabled bool
	DoTPort    uint16

	DoQEnabled bool
	DoQPort    uint16

	DoHEnabled bool
	DoHPort    uint16
	DoHPath    string
	// DoH3Enabled adds "h3" to the DoH designation's ALPN list.
	DoH3Enabled bool
}

// Enabled reports whether there is anything to advertise. A DDR query gets
// NODATA rather than a designation when this is false — which is the honest
// answer, and distinct from NXDOMAIN, since the name does exist.
func (c DDRConfig) Enabled() bool {
	return c.TargetName != "" && (c.DoTEnabled || c.DoQEnabled || c.DoHEnabled)
}

// Designations turns the config into the endpoint list to publish, ordered by
// SVCB priority.
//
// The priority ordering encodes a preference, and the one chosen here is DoH
// first, then DoT, then DoQ. The reasoning is reachability rather than
// merit: DoH on 443 traverses restrictive middleboxes that drop 853
// outright, so a client that tries it first is least likely to fall back to
// plaintext. DoQ is last only because it is the least widely deployed.
func (c DDRConfig) Designations() []DesignatedResolver {
	if !c.Enabled() {
		return nil
	}

	var out []DesignatedResolver
	if c.DoHEnabled {
		alpns := []string{ALPNDoH2}
		if c.DoH3Enabled {
			alpns = append(alpns, ALPNDoH3)
		}
		path := c.DoHPath
		if path == "" {
			// RFC 9461 §5 gives no default, but this template is what
			// RFC 8484 §4.1 uses and what every DoH client expects.
			path = "/dns-query{?dns}"
		}
		out = append(out, DesignatedResolver{
			Priority: 1,
			Target:   c.TargetName,
			ALPNs:    alpns,
			Port:     c.DoHPort,
			DoHPath:  path,
		})
	}
	if c.DoTEnabled {
		out = append(out, DesignatedResolver{
			Priority: 2,
			Target:   c.TargetName,
			ALPNs:    []string{ALPNDoT},
			Port:     c.DoTPort,
		})
	}
	if c.DoQEnabled {
		out = append(out, DesignatedResolver{
			Priority: 3,
			Target:   c.TargetName,
			ALPNs:    []string{ALPNDoQ},
			Port:     c.DoQPort,
		})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// BuildDDRAnswer returns the SVCB records answering a `_dns.resolver.arpa`
// query. An empty slice means NODATA.
func BuildDDRAnswer(cfg DDRConfig) ([]ResourceRecord, error) {
	designations := cfg.Designations()
	if len(designations) == 0 {
		return nil, nil
	}

	records := make([]ResourceRecord, 0, len(designations))
	for _, d := range designations {
		params := []SvcParam{SvcParamALPNValue(d.ALPNs...)}
		if d.Port != 0 {
			params = append(params, SvcParamPortValue(d.Port))
		}
		if d.DoHPath != "" {
			params = append(params, SvcParamDoHPathValue(d.DoHPath))
		}

		rdata, err := BuildSVCBRData(d.Priority, d.Target, params)
		if err != nil {
			return nil, err
		}
		records = append(records, ResourceRecord{
			Name:     DDRQueryName,
			Type:     TypeSVCB,
			Class:    ClassIN,
			TTL:      DDRTTL,
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		})
	}
	return records, nil
}

// IsDDRQuery reports whether a question is the RFC 9462 §4 discovery query.
// Matching is case-insensitive per RFC 4343 and tolerates a trailing dot.
func IsDDRQuery(name string, qtype uint16) bool {
	if qtype != TypeSVCB {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(name, "."), DDRQueryName)
}

// ResolverInfoKey/Value pairs describe resolver behaviour for RFC 9606
// RESINFO. The record shares TXT's wire format: a sequence of
// length-prefixed character-strings.
type ResolverInfo struct {
	// QnameMinimisation reports RFC 9156 QNAME minimisation, published as
	// the bare key "qnamemin" (RFC 9606 §6.1). It is a presence flag, not
	// a key=value pair.
	QnameMinimisation bool
	// ExtendedErrors lists the RFC 8914 EDE codes this resolver may emit
	// for filtered answers, published as "exterr=15,16,17" (§6.2). It tells
	// a client which codes carry a policy meaning here, so a filtered
	// answer can be surfaced to the user as a block rather than a failure.
	ExtendedErrors []uint16
	// InfoURL is a human-readable policy page, published as "infourl=..."
	// (§6.3).
	InfoURL string
}

// RESINFOName is the owner name under which a resolver publishes RESINFO:
// its own name, queried directly (RFC 9606 §4).
//
// Empty ResolverInfo produces no record at all rather than an empty one — a
// resolver that has nothing to declare should not claim to have declared
// nothing.
func BuildRESINFORData(info ResolverInfo) []byte {
	var strs []string
	if info.QnameMinimisation {
		strs = append(strs, "qnamemin")
	}
	if len(info.ExtendedErrors) > 0 {
		var b strings.Builder
		b.WriteString("exterr=")
		for i, code := range info.ExtendedErrors {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(itoa(code))
		}
		strs = append(strs, b.String())
	}
	if info.InfoURL != "" {
		strs = append(strs, "infourl="+info.InfoURL)
	}
	if len(strs) == 0 {
		return nil
	}
	return encodeTXTStrings(strs)
}

// encodeTXTStrings packs character-strings in TXT wire format (RFC 1035
// §3.3.14): each preceded by a one-octet length. Strings longer than 255
// octets are split, since the length field cannot express more.
func encodeTXTStrings(strs []string) []byte {
	var out []byte
	for _, s := range strs {
		for len(s) > 255 {
			out = append(out, 255)
			out = append(out, s[:255]...)
			s = s[255:]
		}
		out = append(out, byte(len(s)))
		out = append(out, s...)
	}
	return out
}

// itoa is a small unsigned formatter, kept local so this file does not pull
// strconv in for one call.
func itoa(n uint16) string {
	if n == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
