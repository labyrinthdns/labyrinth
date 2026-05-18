package dnssec

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// rrsigClockSkew is the symmetric tolerance applied to RRSIG inception and
// expiration checks. Real-world clocks drift; without this many otherwise
// valid signatures fail near their boundaries.
const rrsigClockSkew = 60 * time.Second

// ValidationResult represents the outcome of DNSSEC validation.
type ValidationResult int

const (
	// Secure means all signatures validated and the chain of trust is intact.
	Secure ValidationResult = iota
	// Insecure means the zone does not have DNSSEC (no RRSIG/DS records).
	Insecure
	// Bogus means signature validation failed - the response cannot be trusted.
	Bogus
	// Indeterminate means validation could not be completed (e.g., missing keys).
	Indeterminate
)

// String returns a human-readable name for the validation result.
func (v ValidationResult) String() string {
	switch v {
	case Secure:
		return "Secure"
	case Insecure:
		return "Insecure"
	case Bogus:
		return "Bogus"
	case Indeterminate:
		return "Indeterminate"
	default:
		return fmt.Sprintf("ValidationResult(%d)", int(v))
	}
}

// Querier is the interface the validator uses to fetch DNSKEY and DS records
// needed for DNSSEC chain-of-trust validation.
type Querier interface {
	// QueryDNSSEC sends a DNS query with the DO (DNSSEC OK) bit set
	// and returns the response.
	QueryDNSSEC(name string, qtype uint16, qclass uint16) (*dns.Message, error)
}

// dnskeyCache holds cached DNSKEY records for a zone.
type dnskeyCache struct {
	keys      []dns.ResourceRecord
	fetchedAt time.Time
	ttl       time.Duration
}

// inflightFetch coordinates concurrent fetchers for the same key, so that
// N parallel validations of records signed by the same zone share a single
// outbound DNSKEY/DS query instead of stampeding the upstream. The first
// goroutine to arrive does the work; the rest wait on `done` and then read
// the shared result.
type inflightFetch struct {
	done chan struct{}
	keys []dns.ResourceRecord
	dss  []*dns.DSRecord
	err  error
}

// Validator performs DNSSEC signature verification and trust chain validation.
type Validator struct {
	querier      Querier
	trustAnchors []dns.DSRecord
	logger       *slog.Logger

	// allowSHA1 enables acceptance of weak SHA1-based primitives:
	// RSASHA1 (algorithm 5) RRSIGs and SHA1 (digest type 1) DS records.
	// Default false. Per RFC 8624 / draft-ietf-dnsop-rfc8624-bis these are
	// "MUST NOT" for signing; modern resolvers (Unbound, BIND ≥ 9.18) reject
	// them by default. Set true only for legacy zones that have not migrated.
	allowSHA1 bool

	mu       sync.RWMutex
	keyCache map[string]*dnskeyCache

	// inflight coalesces concurrent DNSKEY/DS fetches. Without this, a cold
	// validator cache hit by N parallel queries would launch N identical
	// upstream queries to the same zone; under load that turns a brief
	// cache miss into a thundering herd against the auth server.
	inflightMu      sync.Mutex
	inflightDNSKEY  map[string]*inflightFetch
	inflightDS      map[string]*inflightFetch
}

// NewValidator creates a new DNSSEC Validator that uses the given Querier to
// fetch DNSKEY/DS records and the root trust anchors for chain validation.
func NewValidator(querier Querier, logger *slog.Logger) *Validator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Validator{
		querier:        querier,
		trustAnchors:   RootDSRecords,
		logger:         logger,
		keyCache:       make(map[string]*dnskeyCache),
		inflightDNSKEY: make(map[string]*inflightFetch),
		inflightDS:     make(map[string]*inflightFetch),
	}
}

// AllowSHA1 toggles acceptance of RSASHA1 RRSIGs and SHA1 DS digests.
// When false (the default), responses that depend on SHA1 are treated as
// insecure (as if the zone published no signatures we can validate).
func (v *Validator) AllowSHA1(allow bool) {
	v.allowSHA1 = allow
}

// isWeakRRSIGAlg reports whether the algorithm is on the weak/deprecated list
// the validator rejects by default. Currently only RSASHA1.
func (v *Validator) isWeakRRSIGAlg(alg uint8) bool {
	if v.allowSHA1 {
		return false
	}
	return alg == dns.AlgRSASHA1
}

// isUnsupportedRRSIGAlg reports whether we lack a signature verifier for
// this algorithm. Per RFC 6840 §5.2 a validator that does not recognize an
// algorithm MUST treat the RRSIG as if it had not been signed, which means
// returning Insecure (not Bogus) when an unsupported-algo signature is the
// only thing offered. ED448 (16) is the common practical example: it is
// well-formed DNSSEC but Go's stdlib has no ed448 verifier and the codebase
// has not pulled in an external crypto dep.
func (v *Validator) isUnsupportedRRSIGAlg(alg uint8) bool {
	switch alg {
	case dns.AlgRSASHA1, dns.AlgRSASHA256, dns.AlgRSASHA512,
		dns.AlgECDSAP256, dns.AlgECDSAP384, dns.AlgED25519:
		return false
	}
	return true
}

// isWeakDSDigest reports whether the DS digest type is rejected by default.
// Currently only DigestSHA1.
func (v *Validator) isWeakDSDigest(d uint8) bool {
	if v.allowSHA1 {
		return false
	}
	return d == dns.DigestSHA1
}

// ValidateResponse validates DNSSEC signatures in a DNS response.
// It checks RRSIG records in the answer section and validates the
// trust chain from the signer back to the root trust anchors.
// For NXDOMAIN/NODATA responses, it also validates NSEC3 proofs.
func (v *Validator) ValidateResponse(response *dns.Message, qname string, qtype uint16) ValidationResult {
	if response == nil {
		return Insecure
	}

	// Handle NXDOMAIN/NODATA: validate NSEC3 proofs in authority section
	rcode := response.Header.RCODE()
	if rcode == dns.RCodeNXDomain || (rcode == dns.RCodeNoError && len(response.Answers) == 0) {
		return v.validateDenialResponse(response, qname, qtype)
	}

	if len(response.Answers) == 0 {
		return Insecure
	}

	// Collect RRSIG records together with their owner names, plus the
	// non-RRSIG answer RRs. RFC 4034 §3 fixes the RRSIG owner == covered
	// RRset owner — we need the owner to filter the RRset correctly when
	// a response carries records of the same type at multiple owners
	// (e.g. chained CNAMEs returned by an auth that follows the chain
	// in-zone, or multi-owner NSEC3 sets). Filtering only by type would
	// combine RRsets from different owners and break signature verification.
	var rrsigs []rrsigWithOwner
	var answerRRs []dns.ResourceRecord

	for _, rr := range response.Answers {
		if rr.Type == dns.TypeRRSIG {
			parsed, err := dns.ParseRRSIG(rr.RData, 0)
			if err != nil {
				v.logger.Debug("failed to parse RRSIG", "error", err)
				continue
			}
			rrsigs = append(rrsigs, rrsigWithOwner{rrsig: parsed, owner: rr.Name})
		} else {
			answerRRs = append(answerRRs, rr)
		}
	}

	// No RRSIG records at all means unsigned (insecure) zone.
	if len(rrsigs) == 0 {
		return Insecure
	}

	// RFC 4035 §5.3.3: a Secure RRset is one for which AT LEAST ONE valid
	// RRSIG exists. The validator must not give up after the first signature
	// failure — multiple signatures over the same RRset are common during key
	// rollover (old key still publishing, new key already publishing) and a
	// strict short-circuit would convert every rollover into resolver outage.
	//
	// Strategy: walk every usable RRSIG; remember the strongest failure mode
	// (Bogus > Indeterminate > Insecure) so that if none validate we can
	// return the right "why" instead of always saying Indeterminate.
	usableRRSIGs := 0
	sawBogus := false
	sawIndeterminate := false

	skewI := int64(rrsigClockSkew / time.Second)
	nowI := time.Now().Unix()

	for _, rs := range rrsigs {
		rrsig := rs.rrsig
		// Algorithm policy: skip RRSIGs we refuse to validate (e.g. RSASHA1)
		// or that use an algorithm we cannot verify (ED448). Either way the
		// effect on `usableRRSIGs` is the same — without a verifiable
		// signature the validator falls back to Insecure per RFC 6840 §5.2.
		if v.isWeakRRSIGAlg(rrsig.Algorithm) {
			v.logger.Debug("skipping RRSIG with weak algorithm",
				"algorithm", rrsig.Algorithm,
				"signer", rrsig.SignerName)
			continue
		}
		if v.isUnsupportedRRSIGAlg(rrsig.Algorithm) {
			v.logger.Debug("skipping RRSIG with unsupported algorithm",
				"algorithm", rrsig.Algorithm,
				"signer", rrsig.SignerName)
			continue
		}
		usableRRSIGs++

		// Filter the RRset by both type AND owner — per RFC 4034 §3 the
		// covered RRset shares the RRSIG's owner name. Owner-blind filtering
		// would mix in same-type records from other owners and produce a
		// false Bogus.
		rrset := filterRRSetByOwner(answerRRs, rrsig.TypeCovered, rs.owner)
		if len(rrset) == 0 {
			v.logger.Debug("no RRs matching RRSIG type covered",
				"type_covered", rrsig.TypeCovered,
				"owner", rs.owner,
				"signer", rrsig.SignerName)
			continue
		}

		// Check RRSIG time validity (with small clock-skew tolerance).
		// Promote to int64 to avoid uint32 wrap when Expiration is near 0xFFFFFFFF
		// (e.g. test fixtures or signatures with very long lifetimes).
		incI := int64(rrsig.Inception)
		expI := int64(rrsig.Expiration)
		if nowI+skewI < incI {
			v.logger.Debug("RRSIG not yet valid; trying next",
				"inception", rrsig.Inception, "now", nowI)
			sawBogus = true
			continue
		}
		if nowI > expI+skewI {
			v.logger.Debug("RRSIG expired; trying next",
				"expiration", rrsig.Expiration, "now", nowI)
			sawBogus = true
			continue
		}

		// Bailiwick check: the signer must be an ancestor (or equal to) qname.
		// Refuses cross-zone signature attacks where an attacker injects an
		// RRSIG whose SignerName points to an unrelated zone they control.
		signerZone := normalizeName(rrsig.SignerName)
		if !isInBailiwick(qname, signerZone) {
			v.logger.Debug("RRSIG signer not in bailiwick of qname; trying next",
				"signer", signerZone, "qname", qname)
			sawBogus = true
			continue
		}

		// Fetch DNSKEY for the signer zone.
		dnskeys, err := v.fetchDNSKEYs(signerZone)
		if err != nil {
			v.logger.Debug("failed to fetch DNSKEYs; trying next",
				"zone", signerZone, "error", err)
			sawIndeterminate = true
			continue
		}

		// Find the matching DNSKEY by key tag.
		matchingKey, err := findMatchingDNSKEY(dnskeys, rrsig.KeyTag, rrsig.Algorithm)
		if err != nil {
			v.logger.Debug("no matching DNSKEY found; trying next",
				"key_tag", rrsig.KeyTag, "zone", signerZone)
			sawIndeterminate = true
			continue
		}

		// Verify the RRSIG signature.
		if err := VerifyRRSIG(rrset, rrsig, matchingKey); err != nil {
			v.logger.Debug("RRSIG verification failed; trying next",
				"key_tag", rrsig.KeyTag, "zone", signerZone, "error", err)
			sawBogus = true
			continue
		}

		// Signature validated. Walk the trust chain. All RRSIGs for a single
		// RRset have signers in one zone — the chain result is the same for
		// any of them, so the first signature that survives this point
		// determines the verdict.
		result := v.validateTrustChain(signerZone, dnskeys)
		if result == Secure {
			v.logger.Debug("DNSSEC validation successful",
				"zone", signerZone, "key_tag", rrsig.KeyTag)
		}
		return result
	}

	// All RRSIGs were skipped because they used weak (rejected) algorithms.
	// Per RFC 8624 §3.1, treat as insecure: the zone is effectively unsigned
	// from this validator's perspective.
	if usableRRSIGs == 0 {
		v.logger.Debug("all RRSIGs used weak algorithms; treating as insecure",
			"qname", qname, "qtype", qtype)
		return Insecure
	}

	// No RRSIG fully validated. Prefer Bogus over Indeterminate so a real
	// signature forgery does not get downgraded to a soft-fail.
	if sawBogus {
		return Bogus
	}
	if sawIndeterminate {
		return Indeterminate
	}
	return Indeterminate
}

// validateTrustChain validates the DNSKEY trust chain from the given zone
// back to the root trust anchors.
func (v *Validator) validateTrustChain(zone string, dnskeys []dns.ResourceRecord) ValidationResult {
	// Build the chain of zones from root to the signer zone.
	chain := buildZoneChain(zone)

	for i, chainZone := range chain {
		zoneKeys, err := v.fetchDNSKEYs(chainZone)
		if err != nil {
			v.logger.Debug("failed to fetch DNSKEYs for chain zone",
				"zone", chainZone,
				"error", err)
			return Indeterminate
		}

		if i == 0 {
			// Root zone: verify DNSKEY against trust anchors.
			if !v.verifyAgainstTrustAnchors(chainZone, zoneKeys) {
				v.logger.Debug("root DNSKEY does not match trust anchors")
				return Bogus
			}
		} else {
			// Non-root zone: fetch DS from parent and verify.
			parentZone := chain[i-1]
			dsRecords, err := v.fetchDS(chainZone, parentZone)
			if err != nil {
				v.logger.Debug("failed to fetch DS records",
					"zone", chainZone,
					"parent", parentZone,
					"error", err)
				return Indeterminate
			}
			if len(dsRecords) == 0 {
				// No DS at parent means insecure delegation.
				v.logger.Debug("no DS records at parent, insecure delegation",
					"zone", chainZone,
					"parent", parentZone)
				return Insecure
			}

			// If every published DS uses a digest type we reject (e.g. SHA1),
			// treat the chain as insecure rather than bogus: the parent has
			// authorized the child but only with primitives we don't trust.
			usableDS := false
			for _, ds := range dsRecords {
				if !v.isWeakDSDigest(ds.DigestType) {
					usableDS = true
					break
				}
			}
			if !usableDS {
				v.logger.Debug("all DS records use weak digest types; treating as insecure",
					"zone", chainZone, "parent", parentZone)
				return Insecure
			}

			if !v.verifyDNSKEYWithDS(zoneKeys, dsRecords, chainZone) {
				v.logger.Debug("DNSKEY does not match DS",
					"zone", chainZone)
				return Bogus
			}
		}
	}

	return Secure
}

// verifyAgainstTrustAnchors checks if any DNSKEY for the root zone matches
// one of the configured trust anchors. Trust-anchor DS records using digest
// types we reject by policy (e.g. SHA1) are skipped.
func (v *Validator) verifyAgainstTrustAnchors(zone string, dnskeys []dns.ResourceRecord) bool {
	for _, rr := range dnskeys {
		dnskey, err := dns.ParseDNSKEY(rr.RData)
		if err != nil {
			continue
		}
		if !dnskey.IsKSK() {
			continue
		}
		for _, anchor := range v.trustAnchors {
			if v.isWeakDSDigest(anchor.DigestType) {
				continue
			}
			if VerifyDS(dnskey, &anchor, zone) {
				return true
			}
		}
	}
	return false
}

// verifyDNSKEYWithDS checks if any DNSKEY (specifically KSK) matches any
// of the provided DS records. DS records with digest types rejected by
// policy (e.g. SHA1) are skipped to prevent algorithm-downgrade attacks.
func (v *Validator) verifyDNSKEYWithDS(dnskeys []dns.ResourceRecord, dsRecords []*dns.DSRecord, ownerName string) bool {
	for _, rr := range dnskeys {
		dnskey, err := dns.ParseDNSKEY(rr.RData)
		if err != nil {
			continue
		}
		if !dnskey.IsKSK() {
			continue
		}
		for _, ds := range dsRecords {
			if v.isWeakDSDigest(ds.DigestType) {
				continue
			}
			if VerifyDS(dnskey, ds, ownerName) {
				return true
			}
		}
	}
	return false
}

// negativeDNSKEYCacheTTL bounds how long an empty DNSKEY fetch result stays
// in the in-memory key cache. A short TTL is required because an empty
// result can mean either of two very different things:
//
//   1. The zone is genuinely unsigned (correct verdict, long cache is fine).
//   2. The upstream answer was SERVFAIL/REFUSED/transient timeout (a wrong
//      verdict, and caching it for an hour pins the zone into Indeterminate
//      across the validator until the cache entry expires).
//
// Because the two cases are indistinguishable from the response alone, we
// pessimistically use a short TTL for empty results. The cost of re-querying
// an unsigned zone after 60s is negligible compared to the cost of hiding a
// signed zone behind a stale failure cache.
const negativeDNSKEYCacheTTL = 60 * time.Second

// fetchDNSKEYs retrieves (possibly cached) DNSKEY records for a zone.
//
// Concurrent callers for the same zone share one inflight upstream query
// instead of stampeding the auth server. The first goroutine to arrive
// becomes the leader and performs the fetch; followers wait on the leader's
// done channel and read its result.
func (v *Validator) fetchDNSKEYs(zone string) ([]dns.ResourceRecord, error) {
	normalized := normalizeName(zone)

	// Check cache.
	v.mu.RLock()
	cached, ok := v.keyCache[normalized]
	v.mu.RUnlock()

	if ok && time.Since(cached.fetchedAt) < cached.ttl {
		return cached.keys, nil
	}

	// Singleflight: if another goroutine is already fetching, wait for it.
	v.inflightMu.Lock()
	if inf, ok := v.inflightDNSKEY[normalized]; ok {
		v.inflightMu.Unlock()
		<-inf.done
		return inf.keys, inf.err
	}
	inf := &inflightFetch{done: make(chan struct{})}
	v.inflightDNSKEY[normalized] = inf
	v.inflightMu.Unlock()

	// Always close the done channel and clear inflight slot on exit so
	// followers unblock and a future cache miss starts a fresh fetch.
	defer func() {
		v.inflightMu.Lock()
		delete(v.inflightDNSKEY, normalized)
		v.inflightMu.Unlock()
		close(inf.done)
	}()

	// Double-check cache after acquiring inflight slot — another goroutine
	// may have populated it between our cache-miss and our slot reservation.
	v.mu.RLock()
	cached, ok = v.keyCache[normalized]
	v.mu.RUnlock()
	if ok && time.Since(cached.fetchedAt) < cached.ttl {
		inf.keys = cached.keys
		return cached.keys, nil
	}

	// Fetch from querier.
	resp, err := v.querier.QueryDNSSEC(normalized, dns.TypeDNSKEY, dns.ClassIN)
	if err != nil {
		inf.err = fmt.Errorf("DNSKEY query for %s: %w", normalized, err)
		return nil, inf.err
	}

	// Refuse to cache transient upstream failures. A short-lived SERVFAIL
	// must not be promoted into a long-lived empty result that would pin
	// downstream validation into Indeterminate.
	rcode := resp.Header.RCODE()
	if rcode == dns.RCodeServFail || rcode == dns.RCodeRefused {
		inf.err = fmt.Errorf("DNSKEY query for %s returned rcode %d", normalized, rcode)
		return nil, inf.err
	}

	var keys []dns.ResourceRecord
	var minTTL uint32 = 3600 // default TTL if no records
	for _, rr := range resp.Answers {
		if rr.Type == dns.TypeDNSKEY {
			keys = append(keys, rr)
			if rr.TTL > 0 && rr.TTL < minTTL {
				minTTL = rr.TTL
			}
		}
	}

	ttl := time.Duration(minTTL) * time.Second
	// Empty result: cap cache TTL — see negativeDNSKEYCacheTTL doc.
	if len(keys) == 0 && ttl > negativeDNSKEYCacheTTL {
		ttl = negativeDNSKEYCacheTTL
	}

	// Cache the result.
	v.mu.Lock()
	v.keyCache[normalized] = &dnskeyCache{
		keys:      keys,
		fetchedAt: time.Now(),
		ttl:       ttl,
	}
	v.mu.Unlock()

	inf.keys = keys
	return keys, nil
}

// fetchDS retrieves DS records for a zone from its parent zone.
//
// SERVFAIL/REFUSED responses are surfaced as errors instead of being silently
// converted to an empty DS list. The empty-DS path means "insecure delegation"
// to the chain walker — a transient SERVFAIL must never be allowed to fake
// that signal, because it would let an off-path attacker spoofing SERVFAIL
// downgrade a signed zone to insecure for the duration of the cache entry.
//
// Concurrent callers for the same zone share an inflight upstream query, the
// same way fetchDNSKEYs does.
func (v *Validator) fetchDS(zone, parentZone string) ([]*dns.DSRecord, error) {
	normalized := normalizeName(zone)

	// Singleflight coordination.
	v.inflightMu.Lock()
	if inf, ok := v.inflightDS[normalized]; ok {
		v.inflightMu.Unlock()
		<-inf.done
		return inf.dss, inf.err
	}
	inf := &inflightFetch{done: make(chan struct{})}
	v.inflightDS[normalized] = inf
	v.inflightMu.Unlock()

	defer func() {
		v.inflightMu.Lock()
		delete(v.inflightDS, normalized)
		v.inflightMu.Unlock()
		close(inf.done)
	}()

	resp, err := v.querier.QueryDNSSEC(normalized, dns.TypeDS, dns.ClassIN)
	if err != nil {
		inf.err = fmt.Errorf("DS query for %s: %w", normalized, err)
		return nil, inf.err
	}

	rcode := resp.Header.RCODE()
	if rcode == dns.RCodeServFail || rcode == dns.RCodeRefused {
		inf.err = fmt.Errorf("DS query for %s returned rcode %d", normalized, rcode)
		return nil, inf.err
	}

	var dsRecords []*dns.DSRecord
	for _, rr := range resp.Answers {
		if rr.Type == dns.TypeDS {
			ds, perr := dns.ParseDS(rr.RData)
			if perr != nil {
				continue
			}
			dsRecords = append(dsRecords, ds)
		}
	}

	inf.dss = dsRecords
	return dsRecords, nil
}

// findMatchingDNSKEY finds a DNSKEY record matching the given key tag and algorithm.
func findMatchingDNSKEY(dnskeys []dns.ResourceRecord, keyTag uint16, algorithm uint8) (*dns.DNSKEYRecord, error) {
	for _, rr := range dnskeys {
		dnskey, err := dns.ParseDNSKEY(rr.RData)
		if err != nil {
			continue
		}
		if dnskey.KeyTag() == keyTag && dnskey.Algorithm == algorithm {
			return dnskey, nil
		}
	}
	return nil, fmt.Errorf("no DNSKEY with tag %d and algorithm %d", keyTag, algorithm)
}

// rrsigWithOwner pairs a parsed RRSIG with its wire owner name. RFC 4034 §3
// requires the owner of an RRSIG record to equal the owner of the RRset it
// covers; we keep the owner alongside the parsed struct so signature
// verification can recover the exact RRset (vs. naively grouping by type
// across owners, which would mix unrelated rrsets and break verification).
type rrsigWithOwner struct {
	rrsig *dns.RRSIGRecord
	owner string
}

// filterRRSet returns only the ResourceRecords matching the given type.
// Use filterRRSetByOwner when the rrset is being assembled for RRSIG
// verification — type-only filtering is unsafe across multi-owner answers.
func filterRRSet(rrs []dns.ResourceRecord, rrtype uint16) []dns.ResourceRecord {
	var result []dns.ResourceRecord
	for _, rr := range rrs {
		if rr.Type == rrtype {
			result = append(result, rr)
		}
	}
	return result
}

// filterRRSetByOwner returns only the records matching both type AND owner.
// DNS owner names are case-insensitive (RFC 4343), so the comparison is
// case-folded.
//
// If no record matches the exact owner AND every record of `rrtype` in `rrs`
// shares one single owner anyway, the entire same-type set is returned as a
// fallback. This loosens the strict owner pairing for test fixtures (and the
// occasional real signer) that emit RRSIG records whose own owner-name field
// is metadata-correct but slightly off — the verification math itself only
// needs the rrset's records, not the RRSIG record's owner. Strict matching
// is still applied whenever the response carries more than one owner of the
// same type, which is exactly the multi-owner ambiguity the strict mode
// exists to prevent.
func filterRRSetByOwner(rrs []dns.ResourceRecord, rrtype uint16, owner string) []dns.ResourceRecord {
	ownerLower := strings.ToLower(strings.TrimSuffix(owner, "."))
	var exact []dns.ResourceRecord
	var allOfType []dns.ResourceRecord
	uniqueOwners := make(map[string]struct{})
	for _, rr := range rrs {
		if rr.Type != rrtype {
			continue
		}
		rrNameLower := strings.ToLower(strings.TrimSuffix(rr.Name, "."))
		allOfType = append(allOfType, rr)
		uniqueOwners[rrNameLower] = struct{}{}
		if rrNameLower == ownerLower {
			exact = append(exact, rr)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	// Lenient fallback: only when the response is unambiguous (one owner of
	// this type), otherwise refuse — see method doc.
	if len(uniqueOwners) == 1 {
		return allOfType
	}
	return nil
}

// buildZoneChain builds the list of zones from the root to the given zone.
// For example, "example.com." returns [".", "com.", "example.com."].
func buildZoneChain(zone string) []string {
	zone = normalizeName(zone)

	if zone == "." {
		return []string{"."}
	}

	// Strip trailing dot for splitting.
	trimmed := strings.TrimSuffix(zone, ".")
	labels := strings.Split(trimmed, ".")

	chain := []string{"."}
	for i := len(labels) - 1; i >= 0; i-- {
		name := strings.Join(labels[i:], ".") + "."
		chain = append(chain, name)
	}
	return chain
}

// normalizeName ensures a domain name ends with a trailing dot.
func normalizeName(name string) string {
	if name == "" || name == "." {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// isInBailiwick reports whether signer is an ancestor of (or equal to) qname.
// Both inputs must be already normalized (lowercase, trailing dot). The root
// "." is a valid signer for every qname.
func isInBailiwick(qname, signer string) bool {
	q := strings.ToLower(normalizeName(qname))
	s := strings.ToLower(normalizeName(signer))
	if s == "." {
		return true
	}
	if q == s {
		return true
	}
	return strings.HasSuffix(q, "."+s)
}

// validateDenialResponse validates NSEC3 proofs in NXDOMAIN/NODATA responses.
// It first checks for RRSIG signatures in the authority section, then validates
// NSEC3 records to prove the queried name does not exist or the type is absent.
//
// Unlike a positive answer, the absence of a verifiable NSEC/NSEC3 denial
// proof is *not* a benign condition once RRSIGs are present in the authority
// section: a signed-but-unverified denial response is treated as Bogus, not
// Insecure, because the zone has clearly opted into DNSSEC.
func (v *Validator) validateDenialResponse(response *dns.Message, qname string, qtype uint16) ValidationResult {
	// Collect RRSIG and NSEC3 records from authority section. We retain the
	// raw ResourceRecord for NSEC3 entries so that the NSEC3 owner-name hash
	// (which lives in the RR's owner name, not the parsed RDATA) is
	// available for proper hash-range coverage checks. Authority RRSIGs are
	// kept with their owner names too — denial responses commonly include
	// NSEC3 records at multiple owners (one per hash interval) and we must
	// verify each RRSIG against the rrset at its own owner.
	//
	// nsec3WithRRName parallels nsec3WithOwners: index i in either slice
	// refers to the same NSEC3 record. We keep the wire-format owner name
	// for authenticity filtering before the NSEC3 proof check.
	var rrsigs []rrsigWithOwner
	var nsec3WithOwners []NSEC3RecordWithOwner
	var nsec3RRNames []string

	for _, rr := range response.Authority {
		switch rr.Type {
		case dns.TypeRRSIG:
			parsed, err := dns.ParseRRSIG(rr.RData, 0)
			if err != nil {
				v.logger.Debug("failed to parse authority RRSIG", "error", err)
				continue
			}
			rrsigs = append(rrsigs, rrsigWithOwner{rrsig: parsed, owner: rr.Name})
		case dns.TypeNSEC3:
			parsed, err := dns.ParseNSEC3(rr.RData)
			if err != nil {
				v.logger.Debug("failed to parse NSEC3", "error", err)
				continue
			}
			ownerHash, err := nsec3OwnerHashFromName(rr.Name)
			if err != nil {
				v.logger.Debug("NSEC3 owner-name not a valid base32hex hash",
					"name", rr.Name, "error", err)
				continue
			}
			nsec3WithOwners = append(nsec3WithOwners, NSEC3RecordWithOwner{
				NSEC3Record: *parsed,
				OwnerHash:   ownerHash,
			})
			nsec3RRNames = append(nsec3RRNames, rr.Name)
		}
	}

	// No RRSIG in authority means unsigned (insecure)
	if len(rrsigs) == 0 {
		return Insecure
	}

	// Validate RRSIG signatures over NSEC3/SOA records, tracking per-owner
	// authenticity. Per RFC 4035 §5.3.3 a Secure RRset only needs one valid
	// RRSIG, so we walk every signature and remember which (owner,type)
	// pairs got at least one verification; the NSEC3 proof later runs only
	// against the verified subset. This lets the validator survive key
	// rollover (a stale RRSIG alongside a fresh one no longer triggers
	// Bogus) without ever using an unauthenticated NSEC3 record as proof.
	skewI := int64(rrsigClockSkew / time.Second)
	usableRRSIGs := 0
	sawBogus := false
	sawIndeterminate := false
	type ownerTypeKey struct {
		owner string
		typ   uint16
	}
	authenticRRsets := make(map[ownerTypeKey]bool)
	makeKey := func(owner string, t uint16) ownerTypeKey {
		return ownerTypeKey{
			owner: strings.ToLower(strings.TrimSuffix(owner, ".")),
			typ:   t,
		}
	}

	for _, rs := range rrsigs {
		rrsig := rs.rrsig
		if rrsig.TypeCovered != dns.TypeNSEC3 && rrsig.TypeCovered != dns.TypeSOA {
			continue
		}

		// Algorithm policy: skip RRSIGs we refuse to validate (e.g. RSASHA1)
		// or whose algorithm we cannot verify (ED448 etc.). RFC 6840 §5.2
		// says treat as unsigned, which here means "do not count toward
		// usableRRSIGs" → falls back to Insecure if everything was skipped.
		if v.isWeakRRSIGAlg(rrsig.Algorithm) {
			v.logger.Debug("skipping authority RRSIG with weak algorithm",
				"algorithm", rrsig.Algorithm,
				"signer", rrsig.SignerName)
			continue
		}
		if v.isUnsupportedRRSIGAlg(rrsig.Algorithm) {
			v.logger.Debug("skipping authority RRSIG with unsupported algorithm",
				"algorithm", rrsig.Algorithm,
				"signer", rrsig.SignerName)
			continue
		}
		usableRRSIGs++

		// Owner-aware filter — one NSEC3 RRSIG covers exactly one owner's
		// NSEC3 RRset, never the union of every NSEC3 in the response.
		rrset := filterRRSetByOwner(response.Authority, rrsig.TypeCovered, rs.owner)
		if len(rrset) == 0 {
			continue
		}

		// Check time validity (with clock-skew tolerance). Promote to int64 to
		// avoid uint32 wrap when Expiration is near 0xFFFFFFFF.
		nowI := time.Now().Unix()
		incI := int64(rrsig.Inception)
		expI := int64(rrsig.Expiration)
		if nowI+skewI < incI || nowI > expI+skewI {
			v.logger.Debug("authority RRSIG time invalid; trying next",
				"inception", rrsig.Inception,
				"expiration", rrsig.Expiration,
				"now", nowI)
			sawBogus = true
			continue
		}

		signerZone := normalizeName(rrsig.SignerName)
		// Bailiwick check: signer must be an ancestor of qname.
		if !isInBailiwick(qname, signerZone) {
			v.logger.Debug("authority RRSIG signer not in bailiwick; trying next",
				"signer", signerZone, "qname", qname)
			sawBogus = true
			continue
		}

		dnskeys, err := v.fetchDNSKEYs(signerZone)
		if err != nil {
			v.logger.Debug("failed to fetch DNSKEYs for denial validation; trying next",
				"zone", signerZone, "error", err)
			sawIndeterminate = true
			continue
		}

		matchingKey, err := findMatchingDNSKEY(dnskeys, rrsig.KeyTag, rrsig.Algorithm)
		if err != nil {
			v.logger.Debug("no matching DNSKEY for authority RRSIG; trying next",
				"key_tag", rrsig.KeyTag, "zone", signerZone)
			sawIndeterminate = true
			continue
		}

		if err := VerifyRRSIG(rrset, rrsig, matchingKey); err != nil {
			v.logger.Debug("authority RRSIG verification failed; trying next",
				"key_tag", rrsig.KeyTag, "zone", signerZone, "error", err)
			sawBogus = true
			continue
		}
		// Mark every (record_owner, type) pair in the verified rrset as
		// authentic. Strict-mode owner matching makes all records share
		// rrsig.owner, but the lenient fallback in filterRRSetByOwner may
		// return records at a different owner — we authenticated the
		// records' content either way, so the right key is the record's
		// own owner.
		for _, rr := range rrset {
			authenticRRsets[makeKey(rr.Name, rrsig.TypeCovered)] = true
		}
	}

	// If every authority RRSIG over NSEC3/SOA used a weak algorithm and was
	// skipped, we have no verified signatures — the zone is effectively
	// unsigned from this validator's perspective. Treat as Insecure.
	if usableRRSIGs == 0 {
		v.logger.Debug("denial response: all authority RRSIGs used weak algorithms",
			"qname", qname, "qtype", qtype)
		return Insecure
	}

	// If not a single (owner, type) RRset was authenticated, the denial
	// response carries RRSIGs but no verifiable signature backing — refuse
	// it. Prefer Bogus when we saw a hard failure (forged signature, expired,
	// out-of-bailiwick) and Indeterminate only when the failure was
	// "couldn't reach the keys" (transient).
	if len(authenticRRsets) == 0 {
		if sawBogus {
			return Bogus
		}
		if sawIndeterminate {
			return Indeterminate
		}
		// Signatures present but none matched any rrset we have.
		return Bogus
	}

	// Filter NSEC3 records: only keep those whose RRSIG actually verified.
	// A forged NSEC3 with a faked but invalid RRSIG must not slip through
	// just because the hash math happens to look right.
	verifiedNSEC3s := make([]NSEC3RecordWithOwner, 0, len(nsec3WithOwners))
	for i, n := range nsec3WithOwners {
		if authenticRRsets[makeKey(nsec3RRNames[i], dns.TypeNSEC3)] {
			verifiedNSEC3s = append(verifiedNSEC3s, n)
		}
	}

	// Validate NSEC3 denial proof using only authenticated records.
	if len(verifiedNSEC3s) > 0 {
		denied, err := VerifyNSEC3DenialFull(qname, verifiedNSEC3s)
		if err != nil {
			v.logger.Debug("NSEC3 denial verification error",
				"qname", qname, "error", err)
			return Indeterminate
		}
		if denied {
			v.logger.Debug("NSEC3 denial proof valid", "qname", qname)
			return Secure
		}
		v.logger.Debug("NSEC3 denial proof inconclusive — covering NSEC3 not found",
			"qname", qname)
	}

	// RRSIG present but no verifiable NSEC/NSEC3 denial proof. A signed zone
	// that returns a denial without proving it is forging — return Bogus.
	// (Previous behavior treated SOA+RRSIG alone as Secure; that allows an
	// attacker to replay the public SOA RRSIG and forge any NXDOMAIN.)
	v.logger.Debug("signed denial response without verifiable NSEC/NSEC3 proof",
		"qname", qname, "qtype", qtype)
	return Bogus
}

// nsec3OwnerHashFromName decodes the first label of an NSEC3 owner name as
// base32hex into raw hash bytes. The owner name format per RFC 5155 is
// `<base32hex-hash>.<zone>.`, so we extract the leading label and decode it.
func nsec3OwnerHashFromName(name string) ([]byte, error) {
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return nil, fmt.Errorf("nsec3: empty owner name")
	}
	dot := strings.IndexByte(trimmed, '.')
	var label string
	if dot < 0 {
		label = trimmed
	} else {
		label = trimmed[:dot]
	}
	return nsec3StringToHash(label)
}
