package resolver

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
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
	// MaxQueriesPerRequest caps total outbound queries per client request
	// (NXNS / runaway-referral backstop). <= 0 means unlimited.
	MaxQueriesPerRequest int
	// RequestTimeout is the wall-clock deadline for one client request.
	// <= 0 means no deadline.
	RequestTimeout  time.Duration
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
	// DNSSECReason carries a stable token classifying the cause when
	// DNSSECStatus is "bogus" or "insecure" due to a specific RFC condition.
	// The server uses it to pick a granular RFC 8914 EDE info code
	// (signature-expired → 7, dnskey-missing → 9, etc.) instead of always
	// emitting the generic EDE 6. Empty string when no specific cause is
	// recorded. See dnssec.FailureReason.
	DNSSECReason string
	// Synthesized marks a result that was locally constructed from cached
	// DNSSEC proofs (DNS64 AAAA synthesis) rather than fetched from an
	// authoritative server. The server uses this flag to attach RFC 8914
	// §4.29 EDE code 29 ("Synthesized") so downstream clients know the
	// answer was materialised locally, not an authoritative response.
	Synthesized bool

	// FailureReason carries a stable token classifying a NON-DNSSEC
	// failure (RCODE=SERVFAIL paths that have nothing to do with crypto).
	// Currently used to surface "no-reachable-authority" when every NS in
	// the delegation refused or was unreachable — the server maps it to
	// EDE info code 22 (RFC 8914 §4.22) so clients and operators can tell
	// "your resolver is broken" from "the auth chain itself is broken
	// upstream of us, retry won't help". Empty when no specific cause.
	FailureReason string
	// FromFailureCache marks this result as a replay from the RFC 9520
	// resolution-failure cache rather than a fresh upstream attempt.
	// The server uses the flag to attach RFC 8914 §4.13 EDE info code
	// 13 ("Cached Error") alongside whatever EDE the original failure
	// reason mapped to, so downstream operators can tell a cache replay
	// from a live fresh failure without having to track query timing.
	FromFailureCache bool
	Error            error // underlying error if resolution failed

	// UpstreamECS is the EDNS Client Subnet option that the authoritative
	// (or forward) server included in its response, if any. The SCOPE
	// PREFIX-LENGTH field (RFC 7871 §6) determines the cache key shape: a
	// scope of 0 means the answer is global and can be shared across all
	// clients; a non-zero scope means the answer is subnet-specific and
	// must be cached under the matching ECS-keyed entry. Nil when the
	// upstream did not include ECS in its response.
	UpstreamECS *dns.ECSOption
}

// Resolver implements recursive DNS resolution.
type Resolver struct {
	cache       *cache.Cache
	rootServers []NameServer
	config      ResolverConfig
	metrics     *metrics.Metrics
	logger      *slog.Logger
	ready       atomic.Bool
	inflight    *inflight
	// dnssecValidator is set lazily by EnableDNSSEC from a startup
	// goroutine that runs in parallel with the DNS server's request
	// handlers. A plain *dnssec.Validator publish would be a data race
	// on every query path that does `r.dnssecValidator != nil` followed
	// by `r.dnssecValidator.X()` — the two reads could observe a torn
	// half-published pointer on weak-ordering architectures. atomic.Pointer
	// publishes the validator atomically; readers Load() once and use
	// the snapshot, never re-reading the field mid-use.
	dnssecValidator atomic.Pointer[dnssec.Validator]
	localZones      *LocalZoneTable
	forwardTable    *ForwardTable
	infraCache      *InfraCache
	// outboundClientCookie is the 8-byte stable client cookie this
	// resolver presents to every authoritative we query (RFC 7873 §5.4).
	// Sent in the EDNS COOKIE option; auths that support cookies echo it
	// back as the first 8 bytes of their reply's COOKIE option. We refuse
	// any response whose echoed client cookie does not match — that
	// mismatch is a positive signal of off-path forgery (the spoofer
	// could not have guessed the random cookie). Randomised once at
	// startup so the value is unpredictable to off-path attackers while
	// stable enough across queries for auths to recognise us as the same
	// originator (the SHOULD in §5.4 around RTT- and identity-stable
	// cookies for friendly upstream behaviour). Length 0 disables.
	outboundClientCookie []byte
	// serverCookieCache stores the most recent server cookie observed
	// per upstream IP (RFC 7873 §5.3). Pre-emptively included on
	// subsequent queries so the BADCOOKIE round-trip — already handled
	// by the §5.4 retry path in queryUpstreamOnceECS — is paid at most
	// once per server rather than once per query. nil-safe; callers
	// that have no cache (test paths, RNG-disabled resolver) still
	// behave correctly via the cache's nil receivers.
	serverCookieCache *serverCookieCache
	// failureCache stores recent resolution failures (RFC 9520) so a
	// downstream client retry storm against a broken auth chain is
	// absorbed by the resolver instead of being forwarded to the
	// already-broken upstream. The 5-second default TTL matches the
	// upper bound the RFC sets, balancing "long enough to absorb a
	// retry burst" against "short enough that transient failures
	// recover quickly". Only no-answer outcomes (SERVFAIL with no
	// authority/answer to cache positively) land here; DNSSEC bogus
	// and authoritative NXDOMAIN/NODATA stay in the normal answer
	// cache because they carry their own authenticated denial proof.
	failureCache *failureCache
}

// SetForwardTable configures forward and stub zones for the resolver.
func (r *Resolver) SetForwardTable(ft *ForwardTable) {
	r.forwardTable = ft
}

// NewResolver creates a new recursive resolver.
func NewResolver(c *cache.Cache, cfg ResolverConfig, m *metrics.Metrics, logger *slog.Logger) *Resolver {
	r := &Resolver{
		cache:       c,
		rootServers: RootServers,
		config:      cfg,
		metrics:     m,
		logger:      logger,
		inflight:    newInflight(),
		infraCache:  NewInfraCache(),
	}
	// Stable per-resolver outbound client cookie (RFC 7873 §5.4). We
	// generate 8 random bytes from the OS RNG; on rare RNG failure we
	// silently disable the option rather than fall back to a constant
	// (a constant cookie defeats the off-path-spoofing protection).
	cookie := make([]byte, 8)
	if _, err := cryptorand.Read(cookie); err == nil {
		r.outboundClientCookie = cookie
	} else if logger != nil {
		logger.Warn("outbound DNS cookie disabled: RNG failure", "error", err)
	}
	// Per-upstream server-cookie cache (RFC 7873 §5.3). Capacity 1024
	// is the typical authoritative-IP footprint a recursive resolver
	// touches in a busy hour; ttl 1h matches the cookie validity window
	// in RFC 9018 §4.3 so cached entries cannot survive a server-secret
	// rotation indefinitely.
	r.serverCookieCache = newServerCookieCache(1024, time.Hour)
	// RFC 9520 resolution-failure cache. Capacity 4096 covers the
	// usual long-tail of broken delegations a busy resolver
	// encounters in a given hour; ttl 5s is the RFC §4 upper bound.
	r.failureCache = newFailureCache(4096, 5*time.Second)
	return r
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

// MinRootRefreshInterval is the floor StartRootRefresh applies. The
// loop calls time.NewTicker(interval) which panics on a non-positive
// value; a YAML resolver.root_hints_refresh: 0 (or a misconfigured
// /api/config/raw PUT) would crash the resolver at boot. RFC 8109
// recommends ~25 hours (just over a day); 1 minute is well below any
// legitimate operator setting and just above the panic threshold.
const MinRootRefreshInterval = time.Minute

// StartRootRefresh runs a background goroutine that re-primes root hints
// at the given interval (RFC 8109). Call this after the initial PrimeRootHints.
// Floors interval at MinRootRefreshInterval so a bad config never crashes the
// refresher.
func (r *Resolver) StartRootRefresh(ctx context.Context, interval time.Duration) {
	if interval < MinRootRefreshInterval {
		interval = MinRootRefreshInterval
	}
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
	r.dnssecValidator.Store(dnssec.NewValidator(r, logger))
}

// SetDNSSECAllowSHA1 toggles acceptance of weak SHA1-based DNSSEC primitives
// (RSASHA1 RRSIGs and SHA1 DS digests) on the active validator. Default is
// false, matching modern resolver behavior. No-op if DNSSEC is not enabled.
func (r *Resolver) SetDNSSECAllowSHA1(allow bool) {
	v := r.dnssecValidator.Load()
	if v == nil {
		return
	}
	v.AllowSHA1(allow)
}

// SetDNSSECNegativeTrustAnchors installs the operator-configured
// RFC 7646 NTA list onto the active validator. Each entry is
// "<zone>|<RFC3339-expiry>|<reason>". Returns the list of entries that
// failed to parse (caller logs them); the validator still receives the
// entries that did parse. No-op if DNSSEC is not enabled.
func (r *Resolver) SetDNSSECNegativeTrustAnchors(entries []string) []string {
	v := r.dnssecValidator.Load()
	if v == nil {
		return nil
	}
	store, failed := dnssec.LoadNTAStoreFromStrings(entries)
	v.SetNTAStore(store)
	return failed
}

// DNSSECValidator exposes the active DNSSEC validator (or nil if DNSSEC
// is disabled). Used by the observability layer to surface validator
// counters (e.g. NTAMatches) through the metrics endpoint.
func (r *Resolver) DNSSECValidator() *dnssec.Validator {
	return r.dnssecValidator.Load()
}

// supportedDNSSECAlgorithms returns the list of DNSKEY/RRSIG algorithm
// numbers this resolver advertises in the RFC 6975 DAU option. The list
// reflects what the validator will actually accept — RSASHA1 is omitted
// unless the operator has explicitly opted into SHA-1 acceptance, and
// ED448 (alg 16) is omitted because Go's stdlib has no verifier and we
// don't carry an external crypto dep.
func (r *Resolver) supportedDNSSECAlgorithms() []uint8 {
	algs := []uint8{
		dns.AlgRSASHA256,
		dns.AlgRSASHA512,
		dns.AlgECDSAP256,
		dns.AlgECDSAP384,
		dns.AlgED25519,
	}
	if v := r.dnssecValidator.Load(); v != nil && v.SHA1Allowed() {
		algs = append(algs, dns.AlgRSASHA1)
	}
	return algs
}

// supportedDSDigests returns the DS digest type numbers this resolver
// accepts (RFC 6975 DHU option payload). SHA-1 is conditionally included
// per the same allowSHA1 gate used by the validator.
func (r *Resolver) supportedDSDigests() []uint8 {
	digests := []uint8{
		dns.DigestSHA256,
		dns.DigestSHA384,
	}
	if v := r.dnssecValidator.Load(); v != nil && v.SHA1Allowed() {
		digests = append(digests, dns.DigestSHA1)
	}
	return digests
}

// supportedNSEC3Hashes returns the NSEC3 hash algorithm numbers this
// resolver accepts (RFC 6975 N3U option payload). Only SHA-1 (algorithm
// 1) is currently defined for NSEC3 (RFC 5155 §8) so the list is fixed.
func (r *Resolver) supportedNSEC3Hashes() []uint8 {
	return []uint8{1}
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
		normalized, qtype, qclass, 0, r.newRequestVisited(),
		toNameServerList(r.rootServers), "",
		true, // skipValidation: validator is calling us, prevent recursion
		nil,  // DNSSEC chain fetches never carry client subnet
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
// Concurrent requests for the same name+type are coalesced. This wrapper
// retains the legacy signature for callers (and the broad test suite) that
// do not carry client subnet context.
func (r *Resolver) Resolve(name string, qtype uint16, qclass uint16) (*ResolveResult, error) {
	return r.ResolveWithECS(name, qtype, qclass, nil)
}

// ResolveWithECS performs recursive resolution while carrying the client's
// EDNS Client Subnet option (RFC 7871) end-to-end. clientECS is propagated
// to every authoritative or forward upstream query so the upstream may
// geo-tailor its response, and the upstream's returned scope is surfaced
// in ResolveResult.UpstreamECS so the caller can pick the appropriate
// cache key. Pass nil for clientECS to disable ECS for this resolution
// (equivalent to Resolve).
//
// Note: ECS is intentionally NOT propagated through the in-flight coalescer
// key. A coalescer that mixes subnets would serve client A's geo-tailored
// answer to client B; the coalescer therefore only fires for the no-ECS
// path. ECS-bearing queries always run independently — correctness over
// dedup throughput.
func (r *Resolver) ResolveWithECS(name string, qtype uint16, qclass uint16, clientECS *dns.ECSOption) (*ResolveResult, error) {
	return r.ResolveWithECSAndCD(name, qtype, qclass, clientECS, false)
}

// ResolveWithECSAndCD is the CD-bit-aware entry point used by the
// server when the client's query carried CD=1 (RFC 4035 §3.2.2,
// RFC 6840 §5.9 — "Checking Disabled"). On the iterative path CD is
// irrelevant (authoritative servers ignore it), but on the forward
// path we MUST propagate it so a downstream-validating client does
// not get its verdict silently rewritten by an intermediate cache
// that chose to validate on its own. Existing ResolveWithECS callers
// keep cd=false.
func (r *Resolver) ResolveWithECSAndCD(name string, qtype uint16, qclass uint16, clientECS *dns.ECSOption, cd bool) (*ResolveResult, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	// RFC 9520 resolution-failure cache hit — short-circuit when a
	// recent attempt already failed for the same (name, type, class).
	// Skipped when ECS is in play because failures are not portable
	// across client subnets: an auth that REFUSED our subnet may
	// happily answer another.
	if clientECS == nil {
		if rcode, reason, hit := r.failureCache.Get(name, qtype, qclass); hit {
			if r.metrics != nil {
				r.metrics.IncFailureCacheHits()
			}
			return &ResolveResult{
				RCODE:            rcode,
				FailureReason:    reason,
				FromFailureCache: true,
			}, nil
		}
		if r.metrics != nil {
			r.metrics.IncFailureCacheMisses()
		}
	}

	// Operator-configured local zones win over the RFC 6761 short-circuit:
	// an admin who configured `myzone.local` or `something.test` knows what
	// they want, and the special-use rule says "if no other local data
	// authoritatively answers." Order matters.
	if r.localZones != nil {
		if result := r.localZones.Lookup(name, qtype, qclass); result != nil {
			return result, nil
		}
	}

	// RFC 6761 / RFC 7686 / RFC 8375 special-use names (.onion, .invalid,
	// .test, .example TLD, .local, home.arpa) must never leave the
	// resolver. .onion in particular is a Tor privacy hazard if leaked.
	if result := specialUseResponse(name, qtype, qclass); result != nil {
		return result, nil
	}

	// RFC 6303 §3 locally-served reverse zones — RFC 1918 private
	// space, link-local, TEST-NET-1/2/3, loopback, IPv6 ULA, IPv6
	// link-local. Returned as NXDOMAIN without leaving the resolver
	// so the public root never sees private-LAN reverse traffic.
	if result := rfc6303LocallyServed(name, qtype, qclass); result != nil {
		return result, nil
	}

	// Check forward/stub zones before normal recursive resolution.
	var result *ResolveResult
	var err error

	if fz := r.forwardTable.Match(name); fz != nil {
		if !fz.IsStub {
			// Forward zone: send directly to configured upstreams with RD=1.
			// RFC 6840 §5.9 — propagate the client's CD bit so the
			// downstream upstream does not validate on behalf of a
			// client that asked us to skip validation.
			r.logger.Debug("forward zone match", "name", name, "zone", fz.Name)
			result, err = r.queryForwardECSCD(fz.Addrs, name, qtype, qclass, clientECS, cd)
		} else {
			// Stub zone: start iterative resolution using configured addrs as initial NS.
			r.logger.Debug("stub zone match", "name", name, "zone", fz.Name)
			if clientECS != nil {
				// Skip the coalescer when carrying client subnet — see comment above.
				result, err = r.resolveStubECS(name, qtype, qclass, fz, clientECS)
			} else {
				key := name + "|" + strconv.Itoa(int(qtype)) + "|" + strconv.Itoa(int(qclass))
				result, err = r.inflight.do(key, func() (*ResolveResult, error) {
					return r.resolveStub(name, qtype, qclass, fz)
				})
			}
		}
	} else {
		if clientECS != nil {
			result, err = r.resolveIterativeECS(name, qtype, qclass, 0, r.newRequestVisited(), clientECS)
		} else {
			key := name + "|" + strconv.Itoa(int(qtype)) + "|" + strconv.Itoa(int(qclass))
			result, err = r.inflight.do(key, func() (*ResolveResult, error) {
				return r.resolveIterative(name, qtype, qclass, 0, r.newRequestVisited())
			})
		}
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

	// RFC 9520 — record the failure so the next identical query in the
	// next few seconds is served from cache. Only when we ended up with
	// SERVFAIL AND we are not carrying ECS (subnet-specific failures
	// would poison cross-subnet queries). DNSSEC-bogus outcomes are
	// excluded because the answer cache will keep their SERVFAIL with
	// the bogus marker on its own schedule.
	if clientECS == nil && result != nil && result.RCODE == dns.RCodeServFail && result.DNSSECStatus != "bogus" {
		r.failureCache.Put(name, qtype, qclass, result.RCODE, result.FailureReason)
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
	return r.resolveIterativeFromInner(name, qtype, qclass, cnameDepth, visited, toNameServerList(r.rootServers), "", false, nil)
}

func (r *Resolver) resolveIterativeECS(
	name string,
	qtype uint16,
	qclass uint16,
	cnameDepth int,
	visited *visitedSet,
	clientECS *dns.ECSOption,
) (*ResolveResult, error) {
	return r.resolveIterativeFromInner(name, qtype, qclass, cnameDepth, visited, toNameServerList(r.rootServers), "", false, clientECS)
}

// resolveIterativeFromInner drives the iterative resolution loop. When
// skipValidation is true the validator call on the terminal answer is bypassed
// — used by QueryDNSSEC to fetch DNSKEY/DS records without recursing back into
// the validator that called it. clientECS, when non-nil, is forwarded as an
// EDNS Client Subnet option to each upstream query and the authoritative
// scope is captured on the terminal result for downstream cache keying.
func (r *Resolver) resolveIterativeFromInner(
	name string,
	qtype uint16,
	qclass uint16,
	cnameDepth int,
	visited *visitedSet,
	initialNS []nsEntry,
	initialZone string,
	skipValidation bool,
	clientECS *dns.ECSOption,
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
			// selectAndResolveNS exhausted every glue IP and every NS
			// hostname it could recursively resolve — same upstream
			// failure mode as the "all NS REFUSED" path below. Tag the
			// reason so the server emits EDE 22.
			lastErr = err
			return &ResolveResult{
				RCODE:         dns.RCodeServFail,
				FailureReason: "no-reachable-authority",
				Error:         lastErr,
			}, nil
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

		// Charge this outbound query against the per-request budget — the
		// global NXNS / runaway-referral backstop plus the wall-clock
		// deadline. Shared across CNAME hops and NS-address sub-resolutions
		// via the visitedSet's budget pointer.
		if err := visited.budget.charge(); err != nil {
			return &ResolveResult{
				RCODE:         dns.RCodeServFail,
				FailureReason: "query-budget-exceeded",
				Error:         err,
			}, nil
		}

		// Send upstream query
		queryStart := time.Now()
		response, err := r.queryUpstreamECS(nsIP, queryName, queryType, qclass, clientECS)
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
			if err := visited.budget.charge(); err != nil {
				return &ResolveResult{
					RCODE:         dns.RCodeServFail,
					FailureReason: "query-budget-exceeded",
					Error:         err,
				}, nil
			}
			response, err = r.queryUpstreamECS(nsIP, name, qtype, qclass, clientECS)
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
				// Capture the authoritative ECS scope so the caller can pick
				// the correct cache key shape (RFC 7871 §7.3): scope=0 means
				// share globally, scope>0 means store under the truncated
				// client subnet.
				UpstreamECS: extractResponseECS(response),
			}
			if v := r.dnssecValidator.Load(); v != nil && !skipValidation {
				r.metrics.SetDNSSECRolloverValidates(v.RolloverValidates())
				vr, reason := v.ValidateResponseWithReason(response, name, qtype)
				switch vr {
				case dnssec.Secure:
					r.metrics.IncDNSSECSecure()
					result.DNSSECStatus = "secure"
				case dnssec.Insecure:
					r.metrics.IncDNSSECInsecure()
					result.DNSSECStatus = "insecure"
					result.DNSSECReason = reason.String()
				case dnssec.Bogus:
					r.metrics.IncDNSSECBogus()
					return &ResolveResult{
						RCODE:        dns.RCodeServFail,
						DNSSECStatus: "bogus",
						DNSSECReason: reason.String(),
					}, nil
				default:
					result.DNSSECStatus = "insecure"
					result.DNSSECReason = reason.String()
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
			if v := r.dnssecValidator.Load(); v != nil && !skipValidation {
				var cnameReason dnssec.FailureReason
				cnameVerdict, cnameReason = v.ValidateResponseWithReason(response, name, dns.TypeCNAME)
				if cnameVerdict == dnssec.Bogus {
					r.metrics.IncDNSSECBogus()
					return &ResolveResult{
						RCODE:        dns.RCodeServFail,
						DNSSECStatus: "bogus",
						DNSSECReason: cnameReason.String(),
					}, nil
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
				clientECS, // carry the client's subnet across the CNAME hop
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
			if v := r.dnssecValidator.Load(); v != nil && !skipValidation {
				var dnameReason dnssec.FailureReason
				dnameVerdict, dnameReason = v.ValidateResponseWithReason(response, name, dns.TypeDNAME)
				if dnameVerdict == dnssec.Bogus {
					r.metrics.IncDNSSECBogus()
					return &ResolveResult{
						RCODE:        dns.RCodeServFail,
						DNSSECStatus: "bogus",
						DNSSECReason: dnameReason.String(),
					}, nil
				}
			}

			result, err := r.resolveIterativeFromInner(
				target, qtype, qclass, cnameDepth+1, visited,
				toNameServerList(r.rootServers), "", skipValidation,
				clientECS, // carry the client's subnet across the DNAME hop
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
			var sawCNAMEForQname bool
			var dnameTTL uint32
			lowerName := strings.ToLower(name)
			for _, rr := range response.Answers {
				if rr.Type == dns.TypeDNAME {
					dnameRRs = append(dnameRRs, rr)
					if dnameTTL == 0 {
						dnameTTL = rr.TTL
					}
					continue
				}
				if rr.Type == dns.TypeCNAME {
					dnameRRs = append(dnameRRs, rr)
					if strings.ToLower(rr.Name) == lowerName {
						sawCNAMEForQname = true
					}
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
			// RFC 6672 §5.3: when the upstream answers with a DNAME but
			// omits the companion synthesized CNAME, the resolver must
			// synthesize one before passing the chain to the client.
			// Without this, stub resolvers and downstream applications that
			// only know how to follow CNAME aliases (the common case) cannot
			// finish the redirection and the lookup fails. The TTL is
			// inherited from the DNAME RR (RFC 6672 §5.3.3); the synthesized
			// CNAME is intentionally NOT signed — RFC 6672 §3.2 forbids
			// signing it because the DNAME RRSIG already authenticates the
			// substitution rule.
			if !sawCNAMEForQname && dnameTTL > 0 {
				if rdata, err := dns.EncodeNameToBytes(target); err == nil {
					dnameRRs = append(dnameRRs, dns.ResourceRecord{
						Name:     name,
						Type:     dns.TypeCNAME,
						Class:    qclass,
						TTL:      dnameTTL,
						RDLength: uint16(len(rdata)),
						RData:    rdata,
					})
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
				Authority:   response.Authority,
				RCODE:       dns.RCodeNXDomain,
				UpstreamECS: extractResponseECS(response),
			}
			result.DNSSECStatus = r.validateDenialIfEnabled(response, name, qtype, skipValidation)
			if result.DNSSECStatus == "bogus" {
				return &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}, nil
			}
			r.cache.StoreNegativeWithStatus(name, qtype, qclass, cache.NegNXDomain, dns.RCodeNXDomain, response.Authority, result.DNSSECStatus)
			// RFC 8198 aggressive NSEC caching: when the denial is Secure
			// the NSEC intervals in the authority section are themselves
			// authenticated proof that every name in the gap is non-
			// existent. Register them so future queries for *other* names
			// covered by the same gap can be answered from cache, dropping
			// the upstream auth-server load for popular signed zones (.com,
			// .org, ccTLDs).
			if result.DNSSECStatus == "secure" {
				zone := nsecZoneFromAuthority(response.Authority)
				negTTL := minNegativeTTL(response.Authority)
				if zone != "" && negTTL > 0 {
					r.cache.RegisterNSECInterval(zone, negTTL, response.Authority)
					// RFC 8198 §5.3 — same idea for NSEC3-signed zones,
					// which is most of the modern signed Internet (.com,
					// .net, the majority of ccTLDs). Opt-out NSEC3s are
					// filtered inside RegisterNSEC3Interval; if there
					// are no usable NSEC3s the call is a no-op.
					r.cache.RegisterNSEC3Interval(zone, negTTL, response.Authority)
				}
			}
			return result, nil

		case responseNoData:
			result := &ResolveResult{
				Authority:   response.Authority,
				RCODE:       dns.RCodeNoError,
				UpstreamECS: extractResponseECS(response),
			}
			result.DNSSECStatus = r.validateDenialIfEnabled(response, name, qtype, skipValidation)
			if result.DNSSECStatus == "bogus" {
				return &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus"}, nil
			}
			r.cache.StoreNegativeWithStatus(name, qtype, qclass, cache.NegNoData, dns.RCodeNoError, response.Authority, result.DNSSECStatus)
			return result, nil

		case responseServFail:
			nameservers = removeNSByIP(nameservers, nsIP)
			if len(nameservers) == 0 {
				// Every authoritative NS in the delegation refused or
				// errored out (typical broken-reverse-zone shape: parent
				// publishes NS records for a /24 whose actual operators
				// never set up real auth). Tag the cause so the server
				// emits EDE 22 (No Reachable Authority) — clients then
				// know retry won't help and the failure is upstream.
				return &ResolveResult{
					RCODE:         dns.RCodeServFail,
					FailureReason: "no-reachable-authority",
				}, nil
			}
			continue
		}
	}

	return &ResolveResult{
		RCODE:         dns.RCodeServFail,
		FailureReason: "no-reachable-authority",
		Error:         lastErr,
	}, nil
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

	// Recursive resolve for NS hostname — Happy Eyeballs v2 (RFC 8305):
	// fire A and AAAA queries concurrently with a 300ms IPv6-first stagger
	// and use whichever responds first. This avoids paying the latency of
	// an A timeout before trying AAAA (or vice-versa).
	// First pass: out-of-bailiwick NS (safe, no loop risk).
	// Second pass: in-bailiwick NS (needed for TLDs like .tr where NS is *.ns.tr).
	happyEyeballsDelay := 300 * time.Millisecond
	for pass := 0; pass < 2; pass++ {
		for _, ns := range shuffled {
			inZone := security.InZone(ns.hostname, currentZone)
			if pass == 0 && inZone {
				continue
			}
			if pass == 1 && !inZone {
				continue
			}

			hostname, ip, err := r.resolveNSHappyEyeballs(ns.hostname, happyEyeballsDelay, visited)
			if err == nil {
				return hostname, ip, nil
			}
		}
	}

	return "", "", errors.New("no reachable nameserver")
}

// resolveNSHappyEyeballs resolves an NS hostname using Happy Eyeballs v2
// (RFC 8305): fire A and AAAA queries concurrently with an IPv6-first
// stagger, returning the first successful result. Prefers IPv4 when the
// resolver config sets PreferIPv4.
func (r *Resolver) resolveNSHappyEyeballs(hostname string, delay time.Duration, visited *visitedSet) (string, string, error) {
	type nsResult struct {
		ip  string
		err error
	}

	// Determine which family to start first.
	firstType, secondType := dns.TypeAAAA, dns.TypeA
	firstLabel, secondLabel := "AAAA", "A"
	if r.config.PreferIPv4 {
		firstType, secondType = dns.TypeA, dns.TypeAAAA
		firstLabel, secondLabel = "A", "AAAA"
	}

	results := make(chan nsResult, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Launch the first address family immediately.
	go func() {
		result, err := r.resolveNSAddr(hostname, firstType, visited.budget)
		if err == nil && !nsHasCNAMERedirect(hostname, result.Answers) {
			for _, rr := range result.Answers {
				if rr.Type == firstType {
					ip, parseErr := dnsParseByType(rr.RData, firstType)
					if parseErr == nil {
						results <- nsResult{ip: ip.String()}
						return
					}
				}
			}
		}
		results <- nsResult{err: fmt.Errorf("%s resolution failed: %w", firstLabel, err)}
	}()

	// Launch the second address family after the staggered delay,
	// unless the first has already succeeded.
	timer := time.NewTimer(delay)
	defer timer.Stop()

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		result, err := r.resolveNSAddr(hostname, secondType, visited.budget)
		if err == nil && !nsHasCNAMERedirect(hostname, result.Answers) {
			for _, rr := range result.Answers {
				if rr.Type == secondType {
					ip, parseErr := dnsParseByType(rr.RData, secondType)
					if parseErr == nil {
						results <- nsResult{ip: ip.String()}
						return
					}
				}
			}
		}
		results <- nsResult{err: fmt.Errorf("%s resolution failed: %w", secondLabel, err)}
	}()

	// Collect results — return the first success, or the last error if all fail.
	var lastErr error
	for i := 0; i < 2; i++ {
		res := <-results
		if res.err == nil {
			return hostname, res.ip, nil
		}
		lastErr = res.err
	}
	return "", "", lastErr
}

// dnsParseByType parses an IP address from RDATA, dispatching on A vs AAAA.
func dnsParseByType(rdata []byte, qtype uint16) (net.IP, error) {
	if qtype == dns.TypeA {
		return dns.ParseA(rdata)
	}
	return dns.ParseAAAA(rdata)
}

// nsHasCNAMERedirect reports whether the answer set for an NS-hostname
// A/AAAA lookup contains a CNAME whose owner matches the NS hostname.
// RFC 2181 §10.3: "The domain name used as the value of a NS resource
// record [...] must not be an alias. Not only is the specification
// clear on this point, but using an alias in one of these positions
// neither works as well as might be hoped, nor well fulfills the ambition
// that may have led to this approach."
//
// An attacker who controls a zone could otherwise publish
// `ns1.example.com CNAME evil.attacker.com` and have us silently follow
// the alias to attacker-controlled glue. We refuse to use any NS whose
// hostname resolves through a CNAME and let the caller try the next NS
// in the delegation set.
func nsHasCNAMERedirect(nsHostname string, answers []dns.ResourceRecord) bool {
	owner := strings.ToLower(strings.TrimSuffix(nsHostname, "."))
	for _, rr := range answers {
		if rr.Type != dns.TypeCNAME {
			continue
		}
		if strings.ToLower(strings.TrimSuffix(rr.Name, ".")) == owner {
			return true
		}
	}
	return false
}

// visitedSet tracks visited nameservers and CNAME targets for loop detection.
// reqBudget is the per-client-request work budget, shared across the entire
// resolution tree — every CNAME hop, QNAME-minimisation step, and nameserver-
// address sub-resolution. It bounds the total outbound queries (the global
// NXNS / runaway-referral backstop that MaxDepth, a per-iteration *depth*
// limit, does not provide) and the wall-clock time. Resolution within one
// request is sequential (NS targets and CNAME hops are chased one at a time),
// and the budget pointer is never shared across goroutines — only across the
// nested calls of a single request — so a plain counter needs no atomics.
type reqBudget struct {
	queries    int
	maxQueries int       // <= 0 means unlimited (tests / internal helpers)
	deadline   time.Time // zero means no deadline
}

var (
	errQueryBudgetExceeded = errors.New("resolver: per-request query budget exceeded")
	errRequestDeadline     = errors.New("resolver: per-request deadline exceeded")
)

// charge records one outbound query against the budget and reports whether the
// request has exhausted its query allowance or wall-clock deadline. A nil
// budget (or one with maxQueries <= 0 and no deadline) is unlimited.
func (b *reqBudget) charge() error {
	if b == nil {
		return nil
	}
	if !b.deadline.IsZero() && time.Now().After(b.deadline) {
		return errRequestDeadline
	}
	if b.maxQueries > 0 {
		b.queries++
		if b.queries > b.maxQueries {
			return errQueryBudgetExceeded
		}
	}
	return nil
}

type visitedSet struct {
	ns     map[string]struct{}
	cname  map[string]struct{}
	budget *reqBudget
}

func newVisitedSet() *visitedSet {
	return &visitedSet{
		ns:     make(map[string]struct{}, 32),
		cname:  make(map[string]struct{}, 10),
		budget: &reqBudget{}, // unlimited; top-level entries attach a configured budget
	}
}

// newVisitedSetWithBudget returns a fresh loop-detection set that shares an
// existing request budget. Used to start a nameserver-address sub-resolution:
// its loop-detection state must be independent (a different query subtree) but
// its query/time budget must keep counting against the same client request.
func newVisitedSetWithBudget(b *reqBudget) *visitedSet {
	v := newVisitedSet()
	if b != nil {
		v.budget = b
	}
	return v
}

// newRequestVisited builds the per-request loop-detection + work-budget object
// for a fresh client request, seeding the budget from config (the global
// query-count backstop and the wall-clock deadline).
func (r *Resolver) newRequestVisited() *visitedSet {
	v := newVisitedSet()
	v.budget.maxQueries = r.config.MaxQueriesPerRequest
	if r.config.RequestTimeout > 0 {
		v.budget.deadline = time.Now().Add(r.config.RequestTimeout)
	}
	return v
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
func (r *Resolver) resolveNSAddr(name string, qtype uint16, budget *reqBudget) (*ResolveResult, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	// Fresh loop-detection state (a distinct query subtree) but the SAME
	// request budget, so NXNS-style NS-address fan-out counts against the
	// originating client request's global query/time allowance.
	return r.resolveIterative(name, qtype, dns.ClassIN, 0, newVisitedSetWithBudget(budget))
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
	v := r.dnssecValidator.Load()
	if v == nil || skipValidation {
		return ""
	}
	switch v.ValidateResponse(response, name, qtype) {
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
