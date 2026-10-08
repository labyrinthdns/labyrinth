package resolver

import (
	"errors"
	"net"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// dsDenialSignedByChild reports whether a negative DS response's authority
// is signed by the child zone itself (SignerName == qname). Parent-side
// denials are signed by the parent (e.g. com.); child-signed NODATA is the
// Cloudflare island shape and must not be used as a DS proof.
func dsDenialSignedByChild(qname string, authority []dns.ResourceRecord) bool {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	if qname == "" || len(authority) == 0 {
		return false
	}
	for _, rr := range authority {
		if rr.Type != dns.TypeRRSIG {
			continue
		}
		sig, err := dns.ParseRRSIG(rr.RData, 0)
		if err != nil || sig == nil {
			continue
		}
		signer := strings.ToLower(strings.TrimSuffix(sig.SignerName, "."))
		if signer == qname {
			return true
		}
	}
	return false
}

var errNoDelegation = errors.New("no NS delegation in response")

// commonPrimeZones are high-traffic parents primed after root hints so the
// first client query for a name under them can skip the root RTT.
var commonPrimeZones = []string{"com", "net", "org", "arpa"}

// closestCachedDelegation returns the most specific ancestor of name that
// has a cached NS RRset, plus those nameservers with any cached glue.
// When nothing is cached it falls back to the configured root hints with
// an empty zone (same as the historical always-start-at-root behavior).
//
// Skipping already-known parents is the dominant cold-path win for names
// like deneme.com once .com NS (and glue) are in cache: root→TLD RTT gone.
func (r *Resolver) closestCachedDelegation(name string) ([]nsEntry, string) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || name == "." {
		return toNameServerList(r.rootServers), ""
	}

	labels := strings.Split(name, ".")
	for i := 0; i < len(labels); i++ {
		zone := strings.Join(labels[i:], ".")
		entry, ok := r.cache.Get(zone, dns.TypeNS, dns.ClassIN)
		if !ok || len(entry.Records) == 0 {
			continue
		}
		nss := nsEntriesFromCachedNS(r, entry.Records)
		if len(nss) == 0 {
			continue
		}
		// Only jump to a cached parent when at least one NS already has
		// an address. Priming / thin NS caches without glue would otherwise
		// force a nested glue lookup under query budget and collapse into
		// EDE 22 (seen live: every .com name SERVFAIL ~1.4s after TLD prime).
		if !nsListHasAddress(nss) {
			continue
		}
		return nss, zone
	}

	return toNameServerList(r.rootServers), ""
}

func nsListHasAddress(nss []nsEntry) bool {
	for _, ns := range nss {
		if ns.ipv4 != "" || ns.ipv6 != "" {
			return true
		}
	}
	return false
}

func nsEntriesFromCachedNS(r *Resolver, records []dns.ResourceRecord) []nsEntry {
	out := make([]nsEntry, 0, len(records))
	for _, rr := range records {
		if rr.Type != dns.TypeNS {
			continue
		}
		host, err := dns.ParseNS(rr.RData, 0)
		if err != nil || host == "" {
			continue
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		ns := nsEntry{hostname: host}
		if a, ok := r.cache.Get(host, dns.TypeA, dns.ClassIN); ok {
			for _, arr := range a.Records {
				if ip, err := dns.ParseA(arr.RData); err == nil {
					ns.ipv4 = ip.String()
					break
				}
			}
		}
		if aaaa, ok := r.cache.Get(host, dns.TypeAAAA, dns.ClassIN); ok {
			for _, arr := range aaaa.Records {
				if ip, err := dns.ParseAAAA(arr.RData); err == nil {
					ns.ipv6 = ip.String()
					break
				}
			}
		}
		out = append(out, ns)
	}
	return out
}

// seedIterativeStart picks nameservers + currentZone for a top-level
// iterative walk. Prefer the closest cached delegation; otherwise roots.
//
// TypeDS is excluded: DS is published at the parent (RFC 4035 §2.4 /
// RFC 9156 §4.1). Starting at a cached child NS asks the child for its
// own DS; Cloudflare-style islands answer with a self-signed NSEC NODATA
// that then poisons the DS cache. validateTrustChain sees that denial,
// cannot authenticate it with parent keys, returns Bogus, and the A/AAAA
// query falls to public-resolver fallback (live: turkmmo.com,
// yesilbeyazhosting.com).
func (r *Resolver) seedIterativeStart(name string, qtype uint16) ([]nsEntry, string) {
	if qtype == dns.TypeDS {
		return toNameServerList(r.rootServers), ""
	}
	return r.closestCachedDelegation(name)
}

// PrimeCommonTLDs asks a root server for NS (+glue) of busy parent zones
// and caches them. Best-effort: individual zone failures are logged and
// skipped so a single unreachable TLD never blocks readiness.
func (r *Resolver) PrimeCommonTLDs() {
	for _, zone := range commonPrimeZones {
		if err := r.primeZoneNS(zone); err != nil {
			r.logger.Debug("TLD prime skipped", "zone", zone, "error", err)
			continue
		}
		r.logger.Info("TLD hints primed", "zone", zone)
	}
}

// primeZoneNS fetches a referral for zone from a root server and caches
// the NS RRset plus glue, mirroring the hot-path referral cache logic.
func (r *Resolver) primeZoneNS(zone string) error {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if zone == "" {
		return nil
	}

	var lastErr error
	for _, ns := range toNameServerList(r.rootServers) {
		if ns.ipv4 == "" {
			continue
		}
		resp, err := r.queryUpstream(ns.ipv4, zone, dns.TypeNS, dns.ClassIN)
		if err != nil {
			lastErr = err
			continue
		}
		// Prefer Authority referrals (normal root response). Fall back to
		// synthesizing a referral view from ANSWER+ADDITIONAL when a root
		// returns the NS RRset as an answer.
		del, z := extractDelegationForQName(resp, zone, r.config.MaxNSNamesPerDelegation)
		if len(del) == 0 && len(resp.Answers) > 0 {
			synth := &dns.Message{
				Authority:  resp.Answers,
				Additional: resp.Additional,
			}
			del, z = extractDelegationForQName(synth, zone, r.config.MaxNSNamesPerDelegation)
			if len(del) > 0 {
				resp = synth
			}
		}
		if len(del) == 0 {
			lastErr = errNoDelegation
			continue
		}
		if z == "" {
			z = zone
		}
		r.cacheDelegation(resp, z)
		// extractDelegation strips out-of-bailiwick glue (e.g. com NS →
		// *.gtld-servers.net). For a parent-sourced referral that glue is
		// the intended bootstrap addresses — cache A/AAAA from Additional
		// that match the NS hostnames so closest-delegation can jump
		// without a nested glue lookup.
		r.cacheDelegationGlue(del)
		r.cacheOutOfBailiwickNSGlue(resp, del)
		return nil
	}
	if lastErr == nil {
		lastErr = errNoDelegation
	}
	return lastErr
}

func (r *Resolver) cacheDelegationGlue(del []DelegationNS) {
	for _, delNS := range del {
		if delNS.IPv4 != "" {
			ip := parseIPv4Bytes(delNS.IPv4)
			if ip != nil {
				ttl := delNS.IPv4TTL
				if ttl == 0 {
					ttl = 3600
				}
				r.cache.StoreGlue(delNS.Hostname, dns.TypeA, dns.ClassIN,
					[]dns.ResourceRecord{{
						Name: delNS.Hostname, Type: dns.TypeA, Class: dns.ClassIN,
						TTL: ttl, RDLength: 4, RData: ip,
					}})
			}
		}
		if delNS.IPv6 != "" {
			ip := net.ParseIP(delNS.IPv6)
			if ip != nil {
				ipBytes := ip.To16()
				ttl := delNS.IPv6TTL
				if ttl == 0 {
					ttl = 3600
				}
				r.cache.StoreGlue(delNS.Hostname, dns.TypeAAAA, dns.ClassIN,
					[]dns.ResourceRecord{{
						Name: delNS.Hostname, Type: dns.TypeAAAA, Class: dns.ClassIN,
						TTL: ttl, RDLength: 16, RData: ipBytes,
					}})
			}
		}
	}
}

// cacheOutOfBailiwickNSGlue stores A/AAAA from Additional whose owner matches
// an NS hostname in del. Used when the parent (root) publishes glue outside
// the child zone — the common .com → *.gtld-servers.net shape.
func (r *Resolver) cacheOutOfBailiwickNSGlue(resp *dns.Message, del []DelegationNS) {
	if resp == nil || len(del) == 0 {
		return
	}
	want := make(map[string]struct{}, len(del))
	for _, d := range del {
		h := strings.ToLower(strings.TrimSuffix(d.Hostname, "."))
		if h != "" {
			want[h] = struct{}{}
		}
	}
	for _, rr := range resp.Additional {
		if rr.Class != dns.ClassIN {
			continue
		}
		owner := strings.ToLower(strings.TrimSuffix(rr.Name, "."))
		if _, ok := want[owner]; !ok {
			continue
		}
		switch rr.Type {
		case dns.TypeA:
			if len(rr.RData) == 4 {
				ttl := rr.TTL
				if ttl == 0 {
					ttl = 172800
				}
				r.cache.StoreGlue(owner, dns.TypeA, dns.ClassIN,
					[]dns.ResourceRecord{{
						Name: owner, Type: dns.TypeA, Class: dns.ClassIN,
						TTL: ttl, RDLength: 4, RData: append([]byte(nil), rr.RData...),
					}})
			}
		case dns.TypeAAAA:
			if len(rr.RData) == 16 {
				ttl := rr.TTL
				if ttl == 0 {
					ttl = 172800
				}
				r.cache.StoreGlue(owner, dns.TypeAAAA, dns.ClassIN,
					[]dns.ResourceRecord{{
						Name: owner, Type: dns.TypeAAAA, Class: dns.ClassIN,
						TTL: ttl, RDLength: 16, RData: append([]byte(nil), rr.RData...),
					}})
			}
		}
	}
}
