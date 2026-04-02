package resolver

import (
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/dnssec"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/security"
)

// ResolverConfig holds configuration for the recursive resolver.
type ResolverConfig struct {
	MaxDepth        int
	MaxCNAMEDepth   int
	UpstreamTimeout time.Duration
	UpstreamRetries int
	QMinEnabled     bool
	PreferIPv4      bool
	DNSSECEnabled   bool
	// UpstreamPort overrides the DNS port for upstream queries (default "53").
	// Used for testing with mock DNS servers.
	UpstreamPort string
}

// ResolveResult holds the outcome of a recursive resolution.
type ResolveResult struct {
	Answers      []dns.ResourceRecord
	Authority    []dns.ResourceRecord
	Additional   []dns.ResourceRecord
	RCODE        uint8
	DNSSECStatus string // "secure", "insecure", "bogus", ""
}

// Resolver implements recursive DNS resolution.
type Resolver struct {
	cache           *cache.Cache
	rootServers     []NameServer
	config          ResolverConfig
	metrics         *metrics.Metrics
	logger          *slog.Logger
	ready           bool
	inflight        *inflight
	dnssecValidator *dnssec.Validator
}

// NewResolver creates a new recursive resolver.
func NewResolver(c *cache.Cache, cfg ResolverConfig, m *metrics.Metrics, logger *slog.Logger) *Resolver {
	return &Resolver{
		cache:       c,
		rootServers: RootServers,
		config:      cfg,
		metrics:     m,
		logger:      logger,
		inflight:    newInflight(),
	}
}

// IsReady returns whether the resolver has completed root hint priming.
func (r *Resolver) IsReady() bool {
	return r.ready
}

// PrimeRootHints queries a root server for . NS to refresh root data.
func (r *Resolver) PrimeRootHints() error {
	for attempt := 0; attempt < 3; attempt++ {
		idx := rand.IntN(len(r.rootServers))
		ns := r.rootServers[idx]

		response, err := r.queryUpstream(ns.IPv4, ".", dns.TypeNS, dns.ClassIN)
		if err != nil {
			r.logger.Warn("root priming attempt failed", "ns", ns.Name, "error", err, "attempt", attempt+1)
			retryDelay := 5 * time.Second
			if r.config.UpstreamTimeout < time.Second {
				retryDelay = r.config.UpstreamTimeout // use short delay in tests
			}
			time.Sleep(retryDelay)
			continue
		}

		// Cache the root NS records
		if len(response.Answers) > 0 {
			r.cache.Store(".", dns.TypeNS, dns.ClassIN, response.Answers, response.Authority)
		}
		r.ready = true
		r.logger.Info("root hints primed", "ns", ns.Name)
		return nil
	}

	// Even if priming fails, mark as ready so the resolver can still function
	r.ready = true
	return errors.New("root hint priming failed after 3 attempts")
}

// EnableDNSSEC creates the DNSSEC validator, allowing the resolver to
// validate signed responses. Call this after PrimeRootHints.
func (r *Resolver) EnableDNSSEC(logger *slog.Logger) {
	r.dnssecValidator = dnssec.NewValidator(r, logger)
}

// QueryDNSSEC sends a DNS query with the DO bit set. It satisfies the
// dnssec.Querier interface so the validator can fetch DNSKEY/DS records.
func (r *Resolver) QueryDNSSEC(name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	idx := rand.IntN(len(r.rootServers))
	return r.queryUpstream(r.rootServers[idx].IPv4, name, qtype, qclass)
}

// Resolve performs recursive resolution for the given query.
// Concurrent requests for the same name+type are coalesced.
func (r *Resolver) Resolve(name string, qtype uint16, qclass uint16) (*ResolveResult, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	key := name + "|" + strconv.Itoa(int(qtype)) + "|" + strconv.Itoa(int(qclass))
	return r.inflight.do(key, func() (*ResolveResult, error) {
		return r.resolveIterative(name, qtype, qclass, 0, newVisitedSet())
	})
}

func (r *Resolver) resolveIterative(
	name string,
	qtype uint16,
	qclass uint16,
	cnameDepth int,
	visited *visitedSet,
) (*ResolveResult, error) {

	if cnameDepth > r.config.MaxCNAMEDepth {
		return nil, errors.New("CNAME chain too long")
	}

	// Start with root servers
	nameservers := toNameServerList(r.rootServers)
	var currentZone string

	for depth := 0; depth < r.config.MaxDepth; depth++ {
		// Pick a nameserver
		_, nsIP, err := r.selectAndResolveNS(nameservers, visited, currentZone)
		if err != nil {
			return &ResolveResult{RCODE: dns.RCodeServFail}, nil
		}

		// Loop detection
		queryKey := nsIP + "|" + name
		if visited.Has(queryKey) {
			r.logger.Warn("loop detected", "ns", nsIP, "name", name)
			return &ResolveResult{RCODE: dns.RCodeServFail}, nil
		}
		visited.Add(queryKey)

		// Determine query name (QNAME minimization)
		queryName := name
		queryType := qtype
		if r.config.QMinEnabled {
			queryName, queryType = r.minimizeQName(name, qtype, currentZone)
		}

		// Send upstream query
		response, err := r.queryUpstream(nsIP, queryName, queryType, qclass)
		if err != nil {
			r.logger.Debug("upstream error", "ns", nsIP, "error", err)
			nameservers = removeNSByIP(nameservers, nsIP)
			if len(nameservers) == 0 {
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			continue
		}

		// Bailiwick filter
		security.SanitizeBailiwick(response, currentZone)

		// Classify response
		rtype := classifyResponse(response, name, qtype)

		// If using QNAME minimization and we got NODATA for NS query,
		// it might mean the name exists but has no NS — try full query
		if r.config.QMinEnabled && queryName != name && rtype == responseNoData {
			response2, err2 := r.queryUpstream(nsIP, name, qtype, qclass)
			if err2 == nil {
				security.SanitizeBailiwick(response2, currentZone)
				rtype = classifyResponse(response2, name, qtype)
				response = response2
			}
		}

		switch rtype {
		case responseAnswer:
			result := &ResolveResult{
				Answers:    response.Answers,
				Authority:  response.Authority,
				Additional: response.Additional,
				RCODE:      dns.RCodeNoError,
			}
			if r.dnssecValidator != nil {
				vr := r.dnssecValidator.ValidateResponse(response, name, qtype)
				switch vr {
				case dnssec.Secure:
					r.metrics.IncDNSSECSecure()
					result.DNSSECStatus = "secure"
				case dnssec.Insecure:
					r.metrics.IncDNSSECInsecure()
					result.DNSSECStatus = "insecure"
				case dnssec.Bogus:
					r.metrics.IncDNSSECBogus()
					return &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}, nil
				default:
					result.DNSSECStatus = "insecure"
				}
			}
			return result, nil

		case responseCNAME:
			target := extractCNAMETarget(response, name)
			if target == "" {
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}

			if visited.HasCNAME(target) {
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			visited.AddCNAME(target)

			// Cache CNAME
			for _, rr := range response.Answers {
				if rr.Type == dns.TypeCNAME && strings.ToLower(rr.Name) == name {
					r.cache.Store(name, dns.TypeCNAME, qclass, []dns.ResourceRecord{rr}, nil)
					break
				}
			}

			result, err := r.resolveIterative(target, qtype, qclass, cnameDepth+1, visited)
			if err != nil {
				return nil, err
			}

			cnameRRs := extractCNAMERecords(response, name)
			result.Answers = append(cnameRRs, result.Answers...)
			return result, nil

		case responseReferral:
			newNS, zone := extractDelegation(response)
			if len(newNS) == 0 {
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			nameservers = delegationToNSList(newNS)
			currentZone = zone

			// Cache NS delegation records
			r.cacheDelegation(response, zone)

			// Cache glue records (A and AAAA)
			for _, delNS := range newNS {
				if delNS.IPv4 != "" {
					ip := parseIPv4Bytes(delNS.IPv4)
					if ip != nil {
						r.cache.Store(delNS.Hostname, dns.TypeA, dns.ClassIN,
							[]dns.ResourceRecord{{
								Name: delNS.Hostname, Type: dns.TypeA, Class: dns.ClassIN,
								TTL: 3600, RDLength: 4, RData: ip,
							}}, nil)
					}
				}
				if delNS.IPv6 != "" {
					ip := net.ParseIP(delNS.IPv6)
					if ip != nil {
						ipBytes := ip.To16()
						r.cache.Store(delNS.Hostname, dns.TypeAAAA, dns.ClassIN,
							[]dns.ResourceRecord{{
								Name: delNS.Hostname, Type: dns.TypeAAAA, Class: dns.ClassIN,
								TTL: 3600, RDLength: 16, RData: ipBytes,
							}}, nil)
					}
				}
			}
			continue

		case responseNXDomain:
			r.cache.StoreNegative(name, qtype, qclass, cache.NegNXDomain, dns.RCodeNXDomain, response.Authority)
			return &ResolveResult{
				Authority: response.Authority,
				RCODE:     dns.RCodeNXDomain,
			}, nil

		case responseNoData:
			r.cache.StoreNegative(name, qtype, qclass, cache.NegNoData, dns.RCodeNoError, response.Authority)
			return &ResolveResult{
				Authority: response.Authority,
				RCODE:     dns.RCodeNoError,
			}, nil

		case responseServFail:
			nameservers = removeNSByIP(nameservers, nsIP)
			if len(nameservers) == 0 {
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			continue
		}
	}

	return &ResolveResult{RCODE: dns.RCodeServFail}, nil
}

func (r *Resolver) selectAndResolveNS(nameservers []nsEntry, visited *visitedSet, currentZone string) (string, string, error) {
	// Shuffle for load distribution
	shuffled := make([]nsEntry, len(nameservers))
	copy(shuffled, nameservers)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	// Prefer NS with IPv4 glue
	for _, ns := range shuffled {
		if ns.ipv4 != "" {
			return ns.hostname, ns.ipv4, nil
		}
	}

	// Try IPv6 glue
	if !r.config.PreferIPv4 {
		for _, ns := range shuffled {
			if ns.ipv6 != "" {
				return ns.hostname, ns.ipv6, nil
			}
		}
	}

	// Try cache lookup for NS IP (A first, then AAAA)
	for _, ns := range shuffled {
		if entry, ok := r.cache.Get(ns.hostname, dns.TypeA, dns.ClassIN); ok && len(entry.Records) > 0 {
			ip, err := dns.ParseA(entry.Records[0].RData)
			if err == nil {
				return ns.hostname, ip.String(), nil
			}
		}
	}
	for _, ns := range shuffled {
		if entry, ok := r.cache.Get(ns.hostname, dns.TypeAAAA, dns.ClassIN); ok && len(entry.Records) > 0 {
			ip, err := dns.ParseAAAA(entry.Records[0].RData)
			if err == nil {
				return ns.hostname, ip.String(), nil
			}
		}
	}

	// Recursive resolve for NS hostname — try A then AAAA.
	// First pass: out-of-bailiwick NS (safe, no loop risk).
	// Second pass: in-bailiwick NS (needed for TLDs like .tr where NS is *.ns.tr).
	for pass := 0; pass < 2; pass++ {
		for _, ns := range shuffled {
			inZone := security.InZone(ns.hostname, currentZone)
			if pass == 0 && inZone {
				continue // first pass: skip in-bailiwick
			}
			if pass == 1 && !inZone {
				continue // second pass: skip out-of-bailiwick (already tried)
			}

			result, err := r.Resolve(ns.hostname, dns.TypeA, dns.ClassIN)
			if err == nil && len(result.Answers) > 0 {
				ip, err := dns.ParseA(result.Answers[0].RData)
				if err == nil {
					return ns.hostname, ip.String(), nil
				}
			}
			// Fallback to AAAA (always try, even with PreferIPv4 — it's a last resort)
			result, err = r.Resolve(ns.hostname, dns.TypeAAAA, dns.ClassIN)
			if err == nil && len(result.Answers) > 0 {
				ip, err := dns.ParseAAAA(result.Answers[0].RData)
				if err == nil {
					return ns.hostname, ip.String(), nil
				}
			}
		}
	}

	return "", "", errors.New("no reachable nameserver")
}

// visitedSet tracks visited nameservers and CNAME targets for loop detection.
type visitedSet struct {
	ns    map[string]struct{}
	cname map[string]struct{}
}

func newVisitedSet() *visitedSet {
	return &visitedSet{
		ns:    make(map[string]struct{}, 32),
		cname: make(map[string]struct{}, 10),
	}
}

func (v *visitedSet) Has(key string) bool {
	_, ok := v.ns[key]
	return ok
}

func (v *visitedSet) Add(key string) {
	v.ns[key] = struct{}{}
}

func (v *visitedSet) HasCNAME(name string) bool {
	_, ok := v.cname[strings.ToLower(name)]
	return ok
}

func (v *visitedSet) AddCNAME(name string) {
	v.cname[strings.ToLower(name)] = struct{}{}
}

// nsEntry is an internal representation of a nameserver candidate.
type nsEntry struct {
	hostname string
	ipv4     string
	ipv6     string
}

func toNameServerList(servers []NameServer) []nsEntry {
	result := make([]nsEntry, len(servers))
	for i, s := range servers {
		result[i] = nsEntry{hostname: s.Name, ipv4: s.IPv4, ipv6: s.IPv6}
	}
	return result
}

func delegationToNSList(delegation []DelegationNS) []nsEntry {
	result := make([]nsEntry, len(delegation))
	for i, d := range delegation {
		result[i] = nsEntry{hostname: d.Hostname, ipv4: d.IPv4, ipv6: d.IPv6}
	}
	return result
}

func removeNSByIP(nameservers []nsEntry, ip string) []nsEntry {
	result := make([]nsEntry, 0, len(nameservers))
	for _, ns := range nameservers {
		if ns.ipv4 != ip && ns.ipv6 != ip {
			result = append(result, ns)
		}
	}
	return result
}

func parseIPv4Bytes(ipStr string) []byte {
	parts := strings.Split(ipStr, ".")
	if len(parts) != 4 {
		return nil
	}
	result := make([]byte, 4)
	for i, p := range parts {
		var val int
		for _, c := range p {
			val = val*10 + int(c-'0')
		}
		if val > 255 {
			return nil
		}
		result[i] = byte(val)
	}
	return result
}

func (r *Resolver) dnsPort() string {
	if r.config.UpstreamPort != "" {
		return r.config.UpstreamPort
	}
	return "53"
}

// cacheDelegation stores NS records from a referral response.
func (r *Resolver) cacheDelegation(response *dns.Message, zone string) {
	var nsRecords []dns.ResourceRecord
	for _, rr := range response.Authority {
		if rr.Type == dns.TypeNS {
			nsRecords = append(nsRecords, rr)
		}
	}
	if len(nsRecords) > 0 {
		r.cache.Store(zone, dns.TypeNS, dns.ClassIN, nsRecords, nil)
	}
}
