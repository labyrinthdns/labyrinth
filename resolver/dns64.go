package resolver

import (
	"net"

	"github.com/labyrinthdns/labyrinth/dns"
)

// DefaultDNS64Prefix is the well-known prefix for DNS64 (RFC 6052).
var DefaultDNS64Prefix = net.IPNet{
	IP:   net.ParseIP("64:ff9b::"),
	Mask: net.CIDRMask(96, 128),
}

// SynthesizeAAAA embeds an IPv4 address into a DNS64 prefix to produce a
// synthesized IPv6 address. The prefix must be a /96 network. For the
// well-known prefix 64:ff9b::/96, the result is 64:ff9b::<ipv4 bytes>.
func SynthesizeAAAA(ipv4 net.IP, prefix net.IPNet) net.IP {
	v4 := ipv4.To4()
	if v4 == nil {
		return nil
	}

	ones, bits := prefix.Mask.Size()
	if bits != 128 || ones != 96 {
		return nil // only /96 prefixes are supported
	}

	// Build the synthesized IPv6 address: prefix (96 bits) + IPv4 (32 bits).
	synth := make(net.IP, 16)
	copy(synth, prefix.IP.To16()[:12]) // first 96 bits from prefix
	copy(synth[12:], v4)               // last 32 bits from IPv4
	return synth
}

// ParseDNS64Prefix parses a CIDR string into a net.IPNet suitable for DNS64.
// It returns an error if the prefix is not a valid IPv6 /96 network.
func ParseDNS64Prefix(cidr string) (net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.IPNet{}, err
	}
	return *ipNet, nil
}

// dns64Synthesize performs DNS64 synthesis: queries the same name for A
// records and, if found, creates synthesized AAAA records by embedding
// the IPv4 addresses into the configured prefix.
func (r *Resolver) dns64Synthesize(name string, qclass uint16, original *ResolveResult, prefix net.IPNet) (*ResolveResult, error) {
	// Query for A record.
	aResult, err := r.resolveIterative(name, dns.TypeA, qclass, 0, newVisitedSet())
	if err != nil {
		return original, nil // fall back to original NODATA
	}
	if aResult.RCODE != dns.RCodeNoError || len(aResult.Answers) == 0 {
		return original, nil // no A records, return original NODATA
	}

	// Synthesize AAAA records from A records.
	var synthAnswers []dns.ResourceRecord
	for _, rr := range aResult.Answers {
		if rr.Type != dns.TypeA {
			continue
		}
		ipv4, parseErr := dns.ParseA(rr.RData)
		if parseErr != nil {
			continue
		}
		synth := SynthesizeAAAA(ipv4, prefix)
		if synth == nil {
			continue
		}
		synthAnswers = append(synthAnswers, dns.ResourceRecord{
			Name:     rr.Name,
			Type:     dns.TypeAAAA,
			Class:    rr.Class,
			TTL:      rr.TTL,
			RDLength: 16,
			RData:    synth,
		})
	}

	if len(synthAnswers) == 0 {
		return original, nil
	}

	return &ResolveResult{
		Answers:   synthAnswers,
		Authority: aResult.Authority,
		RCODE:     dns.RCodeNoError,
	}, nil
}
