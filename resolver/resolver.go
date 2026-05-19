package resolver

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
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
	Caps0x20Enabled bool // DNS 0x20 case randomization (RFC 5452)
	PreferIPv4      bool
	DNSSECEnabled   bool
	// UpstreamPort overrides the DNS port for upstream queries (default "53").
	// Used for testing with mock DNS servers.
	UpstreamPort string
	// DNS64Enabled enables DNS64 synthesis (RFC 6147).
	DNS64Enabled bool
	// DNS64Prefix is the IPv6 prefix used for DNS64 synthesis (must be /96).
	DNS64Prefix net.IPNet
	// ECSEnabled enables forwarding of EDNS Client Subnet options.
	ECSEnabled bool
	// ECSMaxPrefix is the maximum source prefix length for ECS (default 24).
	ECSMaxPrefix int
	// FallbackResolvers is a list of backup recursive DNS servers (e.g. 8.8.8.8, 1.1.1.1).
	// When primary resolution returns SERVFAIL, one randomly-picked fallback is tried once.
	FallbackResolvers []string
	// UpstreamUDPBufferSize is the EDNS0 UDP payload size advertised in
	// outgoing OPT records. RFC 9018 / DNS Flag Day 2020 recommends 1232
	// to avoid IP fragmentation, which closes the off-path fragment-
	// injection cache-poisoning vector. 0 means "use the safe default".
	UpstreamUDPBufferSize int
}

// ResolveResult holds the outcome of a recursive resolution.
type ResolveResult struct {
	Answers      []dns.ResourceRecord
	Authority    []dns.ResourceRecord
	Additional   []dns.ResourceRecord
	RCODE        uint8
	DNSSECStatus string // "secure", "insecure", "bogus", ""
	Error        error  // underlying error if resolution failed
}

// Resolver implements recursive DNS resolution.
type Resolver struct {
	cache           *cache.Cache
	rootServers     []NameServer
	config          ResolverConfig
	metrics         *metrics.Metrics
	logger          *slog.Logger
	ready           atomic.Bool
	inflight        *inflight
	dnssecValidator *dnssec.Validator
	localZones      *LocalZoneTable
	forwardTable    *ForwardTable
	infraCache      *InfraCache

	// activeECS holds the ECS option to include in upstream queries.
	// Set per-query when ECS forwarding is enabled; nil otherwise.
	//
	// Stored via atomic.Pointer to keep concurrent Set/read safe — the
	// underlying field is process-global on the Resolver (one slot
	// across N concurrent client queries). The current shape of the
	// API does not support per-query ECS, so racy callers would otherwise
	// leak one client's subnet onto another's outbound query. Once the
	// ECS path is plumbed through context this whole field should go
	// away; until then atomic prevents the data race.
	activeECS atomic.Pointer[dns.ECSOption]
}

// SetActiveECS sets the EDNS Client Subnet option for the next query.
// Pass nil to clear.
func (r *Resolver) SetActiveECS(ecs *dns.ECSOption) {
	r.activeECS.Store(ecs)
}

// SetForwardTable configures forward and stub zones for the resolver.
func (r *Resolver) SetForwardTable(ft *ForwardTable) {
	r.forwardTable = ft
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
		infraCache:  NewInfraCache(),
	}
}

// InfraCache returns the resolver's infrastructure cache for external use.
func (r *Resolver) InfraCache() *InfraCache {
	return r.infraCache
}

// IsReady returns whether the resolver has completed root hint priming.
func (r *Resolver) IsReady() bool {
	return r.ready.Load()
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
		r.ready.Store(true)
		r.logger.Info("root hints primed", "ns", ns.Name)
		return nil
	}

	// Even if priming fails, mark as ready so the resolver can still function
	r.ready.Store(true)
	return errors.New("root hint priming failed after 3 attempts")
}

// StartRootRefresh runs a background goroutine that re-primes root hints
// at the given interval (RFC 8109). Call this after the initial PrimeRootHints.
func (r *Resolver) StartRootRefresh(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.PrimeRootHints(); err != nil {
				r.logger.Warn("root hints refresh failed", "error", err)
			} else {
				r.logger.Debug("root hints refreshed")
			}
		}
	}
}

// EnableDNSSEC creates the DNSSEC validator, allowing the resolver to
// validate signed responses. Call this after PrimeRootHints.
func (r *Resolver) EnableDNSSEC(logger *slog.Logger) {
	r.dnssecValidator = dnssec.NewValidator(r, logger)
}

// SetDNSSECAllowSHA1 toggles acceptance of weak SHA1-based DNSSEC primitives
// (RSASHA1 RRSIGs and SHA1 DS digests) on the active validator. Default is
// false, matching modern resolver behavior. No-op if DNSSEC is not enabled.
func (r *Resolver) SetDNSSECAllowSHA1(allow bool) {
	if r.dnssecValidator == nil {
		return
	}
	r.dnssecValidator.AllowSHA1(allow)
}

// QueryDNSSEC fetches a DNS record for DNSSEC chain validation. It satisfies
// the dnssec.Querier interface used by the validator to fetch DNSKEY and DS
// records.
//
// The previous implementation only sent a single query to a random root
// server, which works only for ".", root-zone DNSKEY, and TLD DS records.
// For any deeper zone the root server returns a referral, not the requested
// records, so the validator could never assemble a chain past the TLD and
// fell back to Indeterminate for almost every signed zone.
//
// This implementation does proper iterative resolution from the roots,
// reusing the standard resolver pipeline but bypassing the resolver's own
// DNSSEC validator on the result. The validator is bypassed because this
// method is called from within the validator itself — running it again
// would recurse infinitely. The validator performs its own signature
// verification on the records this method returns, which is the only
// correctness guarantee that matters.
func (r *Resolver) QueryDNSSEC(name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	normalized := strings.ToLower(strings.TrimSuffix(name, "."))

	// Cache check first. DNSKEY/DS records are large; chain validation
	// otherwise re-fetches them for every signed answer.
	if entry, ok := r.cache.Get(normalized, qtype, qclass); ok {
		return &dns.Message{
			Header: dns.Header{
				Flags: dns.NewFlagBuilder().SetQR(true).SetRA(true).
					SetRCODE(entry.RCODE).Build(),
			},
			Questions: []dns.Question{{Name: normalized, Type: qtype, Class: qclass}},
			Answers:   entry.Records,
			Authority: entry.Authority,
		}, nil
	}

	result, err := r.resolveIterativeFromInner(
		normalized, qtype, qclass, 0, newVisitedSet(),
		toNameServerList(r.rootServers), "",
		true, // skipValidation: validator is calling us, prevent recursion
	)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("dnssec query: empty result")
	}

	// Cache positive answers so repeated chain walks reuse them.
	if result.RCODE == dns.RCodeNoError && len(result.Answers) > 0 {
		r.cache.Store(normalized, qtype, qclass, result.Answers, result.Authority)
	}

	return &dns.Message{
		Header: dns.Header{
			Flags: dns.NewFlagBuilder().SetQR(true).SetRA(true).
				SetRCODE(result.RCODE).Build(),
		},
		Questions:  []dns.Question{{Name: normalized, Type: qtype, Class: qclass}},
		Answers:    result.Answers,
		Authority:  result.Authority,
		Additional: result.Additional,
	}, nil
}

// SetLocalZones configures the resolver's local zone table. Queries
// matching a local zone are answered immediately without recursion.
func (r *Resolver) SetLocalZones(lz *LocalZoneTable) {
	r.localZones = lz
}

// Resolve performs recursive resolution for the given query.
// Concurrent requests for the same name+type are coalesced.
func (r *Resolver) Resolve(name string, qtype uint16, qclass uint16) (*ResolveResult, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	// Check local zones before going recursive.
	if r.localZones != nil {
		if result := r.localZones.Lookup(name, qtype, qclass); result != nil {
			return result, nil
		}
	}

	// Check forward/stub zones before normal recursive resolution.
	var result *ResolveResult
	var err error

	if fz := r.forwardTable.Match(name); fz != nil {
		if !fz.IsStub {
			// Forward zone: send directly to configured upstreams with RD=1.
			r.logger.Debug("forward zone match", "name", name, "zone", fz.Name)
			result, err = r.queryForward(fz.Addrs, name, qtype, qclass)
		} else {
			// Stub zone: start iterative resolution using configured addrs as initial NS.
			r.logger.Debug("stub zone match", "name", name, "zone", fz.Name)
			key := name + "|" + strconv.Itoa(int(qtype)) + "|" + strconv.Itoa(int(qclass))
			result, err = r.inflight.do(key, func() (*ResolveResult, error) {
				return r.resolveStub(name, qtype, qclass, fz)
			})
		}
	} else {
		key := name + "|" + strconv.Itoa(int(qtype)) + "|" + strconv.Itoa(int(qclass))
		result, err = r.inflight.do(key, func() (*ResolveResult, error) {
			return r.resolveIterative(name, qtype, qclass, 0, newVisitedSet())
		})
	}

	// DNS64 synthesis (RFC 6147): if an AAAA query returned NODATA (no
	// AAAA records), synthesize AAAA records from A records.
	if err == nil && result != nil &&
		qtype == dns.TypeAAAA &&
		result.RCODE == dns.RCodeNoError &&
		len(result.Answers) == 0 &&
		r.config.DNS64Enabled {
		return r.dns64Synthesize(name, qclass, result, r.config.DNS64Prefix)
	}

	// Fallback resolver: on SERVFAIL (not DNSSEC bogus), try one backup resolver.
	if fb := shouldFallback(result, err); fb.triggered {
		r.logger.Info("primary resolver failed, trying fallback",
			"name", name, "qtype", qtype, "reason", fb.reason)
		if fbResult := r.queryFallback(name, qtype, qclass, fb.reason); fbResult != nil {
			return fbResult, nil
		}
	}

	return result, err
}

func (r *Resolver) resolveIterative(
	name string,
	qtype uint16,
	qclass uint16,
	cnameDepth int,
	visited *visitedSet,
) (*ResolveResult, error) {
	return r.resolveIterativeFromInner(name, qtype, qclass, cnameDepth, visited, toNameServerList(r.rootServers), "", false)
}

// resolveIterativeFrom keeps the public-ish signature stable for callers like
// the forward/stub paths and tests; it always runs DNSSEC validation on the
// terminal answer.
func (r *Resolver) resolveIterativeFrom(
	name string,
	qtype uint16,
	qclass uint16,
	cnameDepth int,
	visited *visitedSet,
	initialNS []nsEntry,
	initialZone string,
) (*ResolveResult, error) {
	return r.resolveIterativeFromInner(name, qtype, qclass, cnameDepth, visited, initialNS, initialZone, false)
}

// resolveIterativeFromInner drives the iterative resolution loop. When
// skipValidation is true the validator call on the terminal answer is bypassed
// — used by QueryDNSSEC to fetch DNSKEY/DS records without recursing back into
// the validator that called it.
func (r *Resolver) resolveIterativeFromInner(
	name string,
	qtype uint16,
	qclass uint16,
	cnameDepth int,
	visited *visitedSet,
	initialNS []nsEntry,
	initialZone string,
	skipValidation bool,
) (*ResolveResult, error) {

	if cnameDepth > r.config.MaxCNAMEDepth {
		return nil, errors.New("CNAME chain too long")
	}

	nameservers := initialNS
	currentZone := initialZone
	var lastErr error

	for depth := 0; depth < r.config.MaxDepth; depth++ {
		// Pick a nameserver
		_, nsIP, err := r.selectAndResolveNS(nameservers, visited, currentZone)
		if err != nil {
			lastErr = err
			return &ResolveResult{RCODE: dns.RCodeServFail, Error: lastErr}, nil
		}

		// Loop detection: include currentZone so that querying the same NS IP
		// for the same name at different delegation levels (common for TLDs like
		// .tr where ns1.nic.tr serves .tr, com.tr, net.tr, etc.) is not
		// mistakenly flagged as a loop.
		queryKey := nsIP + "|" + name + "|" + currentZone
		if visited.Has(queryKey) {
			r.logger.Warn("loop detected", "ns", nsIP, "name", name, "zone", currentZone)
			lastErr = errors.New("loop detected")
			return &ResolveResult{RCODE: dns.RCodeServFail, Error: lastErr}, nil
		}
		visited.Add(queryKey)

		// Determine query name (QNAME minimization)
		queryName := name
		queryType := qtype
		if r.config.QMinEnabled {
			queryName, queryType = r.minimizeQName(name, qtype, currentZone)
		}

		// Send upstream query
		queryStart := time.Now()
		response, err := r.queryUpstream(nsIP, queryName, queryType, qclass)
		if err != nil {
			r.infraCache.RecordFailure(nsIP)
			r.logger.Debug("upstream error", "ns", nsIP, "error", err)
			lastErr = err
			nameservers = removeNSByIP(nameservers, nsIP)
			if len(nameservers) == 0 {
				return &ResolveResult{RCODE: dns.RCodeServFail, Error: lastErr}, nil
			}
			continue
		}
		r.infraCache.RecordRTT(nsIP, time.Since(queryStart))

		// Bailiwick filter
		security.SanitizeBailiwick(response, currentZone)

		// Classify response using the actual query parameters (which may
		// differ from the original name/qtype when QMIN is active).
		rtype := classifyResponse(response, queryName, queryType)

		// If using QNAME minimization and the minimized query did not
		// produce a useful referral, retry with the full query name
		// (RFC 9156 §3). A referral means the NS delegated to a child
		// zone — we follow that. Anything else (answer for the minimized
		// name, NXDOMAIN, NODATA, ServFail) means we should ask the
		// full question to get the real delegation or answer.
		//
		// Type change matters too: if qmin rewrote the qtype (e.g. into NS
		// for an intermediate step), an "answer" classified against the
		// rewritten type would carry the wrong RRset back to the caller
		// (root NS records instead of root DNSKEY, breaking DNSSEC).
		minimized := queryName != name || queryType != qtype
		if r.config.QMinEnabled && minimized && rtype != responseReferral {
			response, err = r.queryUpstream(nsIP, name, qtype, qclass)
			if err != nil {
				r.logger.Debug("qmin fallback upstream error", "ns", nsIP, "error", err)
				lastErr = err
				nameservers = removeNSByIP(nameservers, nsIP)
				if len(nameservers) == 0 {
					return &ResolveResult{RCODE: dns.RCodeServFail, Error: lastErr}, nil
				}
				continue
			}
			security.SanitizeBailiwick(response, currentZone)
			rtype = classifyResponse(response, name, qtype)
		}

		switch rtype {
		case responseAnswer:
			result := &ResolveResult{
				Answers:    response.Answers,
				Authority:  response.Authority,
				Additional: response.Additional,
				RCODE:      dns.RCodeNoError,
			}
			if r.dnssecValidator != nil && !skipValidation {
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

			// Validate the CNAME RRset BEFORE descending so a forged CNAME
			// cannot redirect the chain off-zone undetected. The full chain's
			// verdict is the AND of every hop's verdict (RFC 4035 §3.2.3:
			// AD set only if every RRset in the answer is Authentic).
			cnameVerdict := dnssec.Insecure
			if r.dnssecValidator != nil && !skipValidation {
				cnameVerdict = r.dnssecValidator.ValidateResponse(response, name, dns.TypeCNAME)
				if cnameVerdict == dnssec.Bogus {
					r.metrics.IncDNSSECBogus()
					return &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}, nil
				}
			}

			// Cache the CNAME together with its covering RRSIG so a cache hit
			// later returns a verifiable record set to downstream validators.
			cnameWithSig := extractCNAMERecords(response, name)
			if len(cnameWithSig) > 0 {
				r.cache.Store(name, dns.TypeCNAME, qclass, cnameWithSig, nil)
			}

			result, err := r.resolveIterativeFromInner(
				target, qtype, qclass, cnameDepth+1, visited,
				toNameServerList(r.rootServers), "", skipValidation,
			)
			if err != nil {
				return nil, err
			}

			cnameRRs := extractCNAMERecords(response, name)
			result.Answers = append(cnameRRs, result.Answers...)
			result.DNSSECStatus = combineDNSSECStatus(verdictToStatus(cnameVerdict), result.DNSSECStatus)
			return result, nil

		case responseDNAME:
			// RFC 6672: DNAME redirection — substitute the DNAME owner with target
			target := extractDNAMETarget(response, name)
			if target == "" {
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}

			if visited.HasCNAME(target) {
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			visited.AddCNAME(target)

			// Same chain-validation logic as for CNAME: a forged DNAME would
			// redirect the entire subtree below the owner.
			dnameVerdict := dnssec.Insecure
			if r.dnssecValidator != nil && !skipValidation {
				dnameVerdict = r.dnssecValidator.ValidateResponse(response, name, dns.TypeDNAME)
				if dnameVerdict == dnssec.Bogus {
					r.metrics.IncDNSSECBogus()
					return &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}, nil
				}
			}

			result, err := r.resolveIterativeFromInner(
				target, qtype, qclass, cnameDepth+1, visited,
				toNameServerList(r.rootServers), "", skipValidation,
			)
			if err != nil {
				return nil, err
			}
			result.DNSSECStatus = combineDNSSECStatus(verdictToStatus(dnameVerdict), result.DNSSECStatus)

			// Prepend DNAME + synthesized CNAME records together with any
			// RRSIGs covering DNAME or CNAME. RRSIG(DNAME) is required for
			// downstream validators; RRSIG(CNAME) on a synthesized CNAME is
			// not produced by signers (RFC 6672 §5.3) but if the upstream
			// included one we preserve it.
			var dnameRRs []dns.ResourceRecord
			for _, rr := range response.Answers {
				if rr.Type == dns.TypeDNAME || rr.Type == dns.TypeCNAME {
					dnameRRs = append(dnameRRs, rr)
					continue
				}
				if rr.Type == dns.TypeRRSIG {
					parsed, perr := dns.ParseRRSIG(rr.RData, 0)
					if perr == nil && (parsed.TypeCovered == dns.TypeDNAME ||
						parsed.TypeCovered == dns.TypeCNAME) {
						dnameRRs = append(dnameRRs, rr)
					}
				}
			}
			result.Answers = append(dnameRRs, result.Answers...)
			return result, nil

		case responseReferral:
			newNS, zone := extractDelegation(response)
			if len(newNS) == 0 {
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			// Harden-referral-path: log suspicious NS hostnames
			validateReferralNS(newNS, zone, r.logger)
			nameservers = delegationToNSList(newNS)
			currentZone = zone

			// Cache NS delegation records
			r.cacheDelegation(response, zone)

			// Cache glue records (A and AAAA) with their wire TTL (RFC 2181 §5.4.1)
			for _, delNS := range newNS {
				if delNS.IPv4 != "" {
					ip := parseIPv4Bytes(delNS.IPv4)
					if ip != nil {
						r.cache.Store(delNS.Hostname, dns.TypeA, dns.ClassIN,
							[]dns.ResourceRecord{{
								Name: delNS.Hostname, Type: dns.TypeA, Class: dns.ClassIN,
								TTL: delNS.IPv4TTL, RDLength: 4, RData: ip,
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
								TTL: delNS.IPv6TTL, RDLength: 16, RData: ipBytes,
							}}, nil)
					}
				}
			}
			continue

		case responseNXDomain:
			result := &ResolveResult{
				Authority: response.Authority,
				RCODE:     dns.RCodeNXDomain,
			}
			result.DNSSECStatus = r.validateDenialIfEnabled(response, name, qtype, skipValidation)
			if result.DNSSECStatus == "bogus" {
				return &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}, nil
			}
			r.cache.StoreNegative(name, qtype, qclass, cache.NegNXDomain, dns.RCodeNXDomain, response.Authority)
			return result, nil

		case responseNoData:
			result := &ResolveResult{
				Authority: response.Authority,
				RCODE:     dns.RCodeNoError,
			}
			result.DNSSECStatus = r.validateDenialIfEnabled(response, name, qtype, skipValidation)
			if result.DNSSECStatus == "bogus" {
				return &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}, nil
			}
			r.cache.StoreNegative(name, qtype, qclass, cache.NegNoData, dns.RCodeNoError, response.Authority)
			return result, nil

		case responseServFail:
			nameservers = removeNSByIP(nameservers, nsIP)
			if len(nameservers) == 0 {
				return &ResolveResult{RCODE: dns.RCodeServFail}, nil
			}
			continue
		}
	}

	return &ResolveResult{RCODE: dns.RCodeServFail, Error: lastErr}, nil
}

func (r *Resolver) selectAndResolveNS(nameservers []nsEntry, visited *visitedSet, currentZone string) (string, string, error) {
	// Sort by RTT (fastest first) instead of random shuffle
	shuffled := r.infraCache.SortByRTT(nameservers)

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

	// Try cache lookup for NS IP (A first, then AAAA).
	// Scan all cached records — the first one may have corrupt RDATA.
	for _, ns := range shuffled {
		if entry, ok := r.cache.Get(ns.hostname, dns.TypeA, dns.ClassIN); ok {
			for _, rr := range entry.Records {
				if ip, err := dns.ParseA(rr.RData); err == nil {
					return ns.hostname, ip.String(), nil
				}
			}
		}
	}
	for _, ns := range shuffled {
		if entry, ok := r.cache.Get(ns.hostname, dns.TypeAAAA, dns.ClassIN); ok {
			for _, rr := range entry.Records {
				if ip, err := dns.ParseAAAA(rr.RData); err == nil {
					return ns.hostname, ip.String(), nil
				}
			}
		}
	}

	// Recursive resolve for NS hostname — try A then AAAA.
	// Use resolveNSAddr (bypasses inflight) to avoid deadlock when the NS
	// hostname itself requires resolution through the same inflight key.
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

			result, err := r.resolveNSAddr(ns.hostname, dns.TypeA)
			if err == nil {
				// Scan all answers for an A record (answers may include
				// CNAME records before the final A record).
				for _, rr := range result.Answers {
					if rr.Type == dns.TypeA {
						ip, parseErr := dns.ParseA(rr.RData)
						if parseErr == nil {
							return ns.hostname, ip.String(), nil
						}
					}
				}
			}
			// Fallback to AAAA (always try, even with PreferIPv4 — it's a last resort)
			result, err = r.resolveNSAddr(ns.hostname, dns.TypeAAAA)
			if err == nil {
				for _, rr := range result.Answers {
					if rr.Type == dns.TypeAAAA {
						ip, parseErr := dns.ParseAAAA(rr.RData)
						if parseErr == nil {
							return ns.hostname, ip.String(), nil
						}
					}
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

// resolveNSAddr resolves a nameserver hostname bypassing the inflight
// coalescer. This prevents deadlock when the NS hostname resolution would
// hit the same inflight key as the caller (e.g., ns1.example.tr while
// already resolving something under example.tr).
func (r *Resolver) resolveNSAddr(name string, qtype uint16) (*ResolveResult, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return r.resolveIterative(name, qtype, dns.ClassIN, 0, newVisitedSet())
}

func (r *Resolver) dnsPort() string {
	if r.config.UpstreamPort != "" {
		return r.config.UpstreamPort
	}
	return "53"
}

// verdictToStatus maps the validator's enum verdict onto the string
// representation stored on ResolveResult. Indeterminate is collapsed onto
// "insecure" because the resolver-side switch treats it as non-failing but
// non-Authentic — the same semantics as "insecure" for AD-bit decisions.
func verdictToStatus(v dnssec.ValidationResult) string {
	switch v {
	case dnssec.Secure:
		return "secure"
	case dnssec.Bogus:
		return "bogus"
	default:
		return "insecure"
	}
}

// validateDenialIfEnabled runs the DNSSEC validator over an NXDOMAIN or
// NODATA upstream response and returns the corresponding DNSSECStatus
// string ("secure", "insecure", "bogus", or "" when validation is off).
// Empty string keeps the result unsigned, leaving the caller free to
// classify it as "insecure" by default.
func (r *Resolver) validateDenialIfEnabled(response *dns.Message, name string, qtype uint16, skipValidation bool) string {
	if r.dnssecValidator == nil || skipValidation {
		return ""
	}
	switch r.dnssecValidator.ValidateResponse(response, name, qtype) {
	case dnssec.Secure:
		r.metrics.IncDNSSECSecure()
		return "secure"
	case dnssec.Insecure:
		r.metrics.IncDNSSECInsecure()
		return "insecure"
	case dnssec.Bogus:
		r.metrics.IncDNSSECBogus()
		return "bogus"
	default:
		return "insecure"
	}
}

// combineDNSSECStatus returns the AND of two DNSSEC verdicts along a chain.
// Per RFC 4035 §3.2.3 the AD bit may only be set when every RRset in the
// Answer/Authority sections is Authentic; a chain is therefore only Secure
// when each hop is Secure. Any "bogus" link poisons the whole result.
func combineDNSSECStatus(a, b string) string {
	if a == "bogus" || b == "bogus" {
		return "bogus"
	}
	if a == "secure" && b == "secure" {
		return "secure"
	}
	// Either side is "insecure" (or unknown empty); the chain is not
	// fully Authentic, so report Insecure. Empty stays empty only when
	// validator is disabled on both sides — caller treats empty as
	// insecure for AD purposes anyway.
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return "insecure"
}

// cacheDelegation stores NS records from a referral response, together with
// any RRSIG records that cover the NS RRset at the same owner. The covering
// RRSIG is signed by the parent zone; it lets a downstream validator (or a
// later direct `NS <zone>` query served from cache) confirm the delegation
// without re-querying the parent.
func (r *Resolver) cacheDelegation(response *dns.Message, zone string) {
	zoneLower := strings.ToLower(zone)
	var nsAndSigs []dns.ResourceRecord
	for _, rr := range response.Authority {
		rrNameLower := strings.ToLower(rr.Name)
		if rrNameLower != zoneLower {
			continue
		}
		switch rr.Type {
		case dns.TypeNS:
			nsAndSigs = append(nsAndSigs, rr)
		case dns.TypeRRSIG:
			parsed, err := dns.ParseRRSIG(rr.RData, 0)
			if err == nil && parsed.TypeCovered == dns.TypeNS {
				nsAndSigs = append(nsAndSigs, rr)
			}
		}
	}
	// Only cache if we actually saw NS records (we may have collected only
	// stray RRSIGs otherwise — useless without their covered rrset).
	hasNS := false
	for _, rr := range nsAndSigs {
		if rr.Type == dns.TypeNS {
			hasNS = true
			break
		}
	}
	if hasNS {
		r.cache.Store(zone, dns.TypeNS, dns.ClassIN, nsAndSigs, nil)
	}
}
