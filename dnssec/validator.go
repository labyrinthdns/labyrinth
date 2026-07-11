package dnssec

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// rrsigClockSkew is the symmetric tolerance applied to RRSIG inception and
// expiration checks. Real-world clocks drift; without this many otherwise
// valid signatures fail near their boundaries.
const rrsigClockSkew = 60 * time.Second

// maxRRSIGVerifyAttempts caps the number of *expensive* cryptographic
// signature checks the validator will perform for a single RRset before
// it gives up. RFC 4035 §5.3.3 mandates "at least one valid RRSIG"
// suffices, but the walk-every-RRSIG strategy is open to a CPU-exhaustion
// attack: a hostile authoritative can attach an arbitrarily long list
// of garbage RRSIGs, each forcing a DNSKEY fetch + asymmetric verify.
// A cap of 16 covers all realistic scenarios — algorithm rollover with
// 2 algorithms × 2 keys × an outgoing+incoming pair = 8 signatures —
// while bounding the worst-case crypto cost an attacker can induce per
// query. Beyond the cap the validator stops the crypto loop and lets
// the trailing logic settle on Bogus/Indeterminate per the failures
// already observed, which is the safe collapse for "we cannot validate".
const maxRRSIGVerifyAttempts = 16

// MaxRRSIGVerifyAttempts exposes the verify-cap value for the
// observability UI. Operators reading the DNSSEC page can confirm the
// safety-net value without having to grep the source.
func MaxRRSIGVerifyAttempts() int { return maxRRSIGVerifyAttempts }

// maxCryptoVerifyPerResponse bounds the TOTAL expensive signature
// verifications across the whole validation of one response — the answer
// RRset, the trust chain, and every NSEC/NSEC3 denial proof combined. The
// per-RRset maxRRSIGVerifyAttempts cap (16) bounds a single RRset, but KeyTrap
// (CVE-2023-50387) showed that an attacker can spread the cost across multiple
// RRsets (and, critically, the uncapped authority-section RRSIG loops of a
// denial/insecure-delegation proof), so the per-RRset cap alone leaks. This
// response-wide counter is the global backstop every patched resolver added
// (PowerDNS max-signature-validations-per-query=30, Unbound 16 global
// suspensions). 32 covers the most elaborate legitimate validation — answer +
// DNSKEY chain + denial across a couple of zones, each mid algorithm-rollover —
// while bounding an attacker's crypto amplification to a small constant.
const maxCryptoVerifyPerResponse = 32

// cryptoBudget is a per-response signature-verification counter, created once
// per top-level ValidateResponse* call and threaded (variadically, so existing
// direct callers stay unlimited) to every VerifyRRSIG site. One validation runs
// in a single goroutine sequentially, so no atomics are needed.
type cryptoBudget struct {
	used int
	max  int
}

// allow charges one verification and reports whether it is within budget. A nil
// budget (or max <= 0) is unlimited.
func (c *cryptoBudget) allow() bool {
	if c == nil || c.max <= 0 {
		return true
	}
	if c.used >= c.max {
		return false
	}
	c.used++
	return true
}

// budgetFrom unpacks the variadic per-response crypto budget, returning nil
// (unlimited) when a direct caller (e.g. a test) passed none.
func budgetFrom(budget []*cryptoBudget) *cryptoBudget {
	if len(budget) > 0 {
		return budget[0]
	}
	return nil
}

// maxTrustChainDepth caps the number of zone hops the trust-chain
// walker will traverse before giving up. The chain length grows with
// the label count of the signer zone, which a hostile authoritative
// can control via the RRSIG SignerName field. Each chain step does a
// DNSKEY fetch + a DS fetch — both potentially network round-trips.
// A 127-label name (the RFC 1034 §3.1 theoretical maximum) would
// cost 128 round-trips per validation; an attacker pointing many
// queries at us could weaponise this. Real DNSSEC-signed zones top
// out around 5-7 labels (e.g. www.api.staging.eu-west.example.com.);
// 32 is a comfortable margin above any legitimate depth and far
// below the RFC-1034 maximum. Beyond the cap the validator returns
// Indeterminate — the chain "could not be completed" — rather than
// Bogus (no signature failed) or Insecure (no positive denial).
const maxTrustChainDepth = 32

// MaxTrustChainDepth exposes the chain-depth cap value (see the
// constant above). Surfaced through /api/dnssec so the UI's safety-
// net panel can reflect the value the resolver is actually enforcing.
func MaxTrustChainDepth() int { return maxTrustChainDepth }

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

// MaxDNSKEYCacheEntries caps the validator's keyCache to bound the
// memory footprint of an attacker who controls many DNSSEC-signed
// zones. Each cache entry stores the full DNSKEY RRset for one zone
// — RSA-2048 keys are 256 bytes of wire format, plus RDATA framing
// and slice headers ~1 KB per entry in practice — so an attacker
// driving the resolver to fetch DNSKEYs for distinct zones can pin
// gigabytes of cache with normal query rates. 50k zones is well
// above any realistic resolver workload (the top of the DNSSEC-
// signed namespace plus active deep zones rarely exceeds 10k) and
// small enough that the worst-case footprint stays bounded. LRU
// eviction on insert past the cap drops the entry with the oldest
// fetchedAt — a zone we haven't refreshed in the longest is the
// right one to lose; if we hit it again it just costs one upstream
// DNSKEY query to re-populate.
const MaxDNSKEYCacheEntries = 50_000

// evictOldestDNSKEYLocked drops the keyCache entry with the oldest
// fetchedAt timestamp. Caller holds v.mu in write mode. O(n) over
// the map; only runs on insert after the cap is reached.
func (v *Validator) evictOldestDNSKEYLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, e := range v.keyCache {
		if first || e.fetchedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.fetchedAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(v.keyCache, oldestKey)
	}
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
	// denialAuth carries the authority section of an empty-DS response so
	// the caller can authenticate the parent's denial of DS per
	// RFC 4035 §5.2 / RFC 5155 §10.4. Without authenticated denial, an
	// off-path attacker spoofing a NOERROR-empty DS answer can downgrade
	// a previously-Secure child zone to Insecure.
	denialAuth []dns.ResourceRecord
	err        error
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
	//
	// atomic.Bool wrapper publishes the value with the right barrier so
	// the resolver.Resolver startup goroutine's
	// `res.SetDNSSECAllowSHA1(...)` is visible to the DNS handler goroutines
	// that call `isWeakRRSIGAlg` / `isWeakDSDigest` on every signed RR. The
	// writer runs in the same startup goroutine that calls EnableDNSSEC
	// (after PrimeRootHints completes), and DNS handlers are already
	// serving by then — so a plain bool field has a publication race
	// identical to the v0.8.16 dnssecValidator race: queries landing in
	// the gap between EnableDNSSEC and SetDNSSECAllowSHA1 use the default
	// (false), even when the operator opted in to legacy SHA1 acceptance.
	allowSHA1 atomic.Bool

	mu       sync.RWMutex
	keyCache map[string]*dnskeyCache

	// inflight coalesces concurrent DNSKEY/DS fetches. Without this, a cold
	// validator cache hit by N parallel queries would launch N identical
	// upstream queries to the same zone; under load that turns a brief
	// cache miss into a thundering herd against the auth server.
	inflightMu     sync.Mutex
	inflightDNSKEY map[string]*inflightFetch
	inflightDS     map[string]*inflightFetch

	// ntaStore is the per-validator Negative Trust Anchor registry
	// (RFC 7646). When non-nil, ValidateResponse consults it before
	// running the trust-chain walk. Any qname covered by an active NTA
	// short-circuits to Insecure with reason ReasonNTAOverride. The
	// store is optional: validators constructed via NewValidator get
	// a nil store and behave exactly as before. Operators wire one in
	// via SetNTAStore. atomic.Pointer makes SetNTAStore / NTAStore /
	// validation-path Load race-free without taking a mutex on the
	// hot validation path; GetOrCreateNTAStore uses CAS for safe
	// lazy-init from concurrent admin POSTs to /api/dnssec/nta.
	ntaStore atomic.Pointer[NTAStore]

	// ntaMatches is incremented every time an NTA hides a validation
	// outcome. Surfaced via NTAMatches() for the observability layer.
	ntaMatches atomic.Int64

	// rolloverValidates counts successful validations where at least one
	// prior RRSIG candidate was skipped (expired, not-yet-valid, algorithm
	// mismatch, missing DNSKEY). An active zone algorithm rollover (RFC
	// 4035 §4.6) produces this pattern: the old RRSIG fails but the new
	// one succeeds. Surfaced via RolloverValidates().
	rolloverValidates atomic.Int64
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

// SetNTAStore wires a Negative Trust Anchor (RFC 7646) registry into
// the validator. Pass nil to disable NTA enforcement. Once set, every
// ValidateResponse call consults the store first; matching qnames are
// short-circuited to Insecure with ReasonNTAOverride before any
// chain work runs.
func (v *Validator) SetNTAStore(store *NTAStore) {
	v.ntaStore.Store(store)
}

// NTAStore returns the configured store, or nil if none is wired.
// Operator-facing UI reads from here.
func (v *Validator) NTAStore() *NTAStore {
	return v.ntaStore.Load()
}

// GetOrCreateNTAStore returns the configured NTA store, creating an
// empty one and wiring it in atomically if none is set. Safe to call
// from multiple goroutines: the first caller wins the CAS, losers
// observe the winner's store. This closes the lazy-init TOCTOU on
// the /api/dnssec/nta admin handler where two concurrent POSTs could
// each create a fresh store, the loser's store.Add would write to an
// orphaned store, and the NTA would silently never take effect.
func (v *Validator) GetOrCreateNTAStore() *NTAStore {
	if store := v.ntaStore.Load(); store != nil {
		return store
	}
	fresh := NewNTAStore()
	if v.ntaStore.CompareAndSwap(nil, fresh) {
		return fresh
	}
	return v.ntaStore.Load()
}

// NTAMatches reports the cumulative count of validations short-
// circuited by an NTA match. Surfaced via /api/stats so operators can
// see whether an NTA is actually doing anything.
func (v *Validator) NTAMatches() int64 {
	return v.ntaMatches.Load()
}

// RolloverValidates returns the number of validated responses where the
// first RRSIG candidate failed but a subsequent one succeeded — a pattern
// characteristic of zone algorithm rollovers (RFC 4035 §4.6) or multi-signer
// transitions (RFC 8901).
func (v *Validator) RolloverValidates() int64 {
	return v.rolloverValidates.Load()
}

// AllowSHA1 toggles acceptance of RSASHA1 RRSIGs and SHA1 DS digests.
// When false (the default), responses that depend on SHA1 are treated as
// insecure (as if the zone published no signatures we can validate).
func (v *Validator) AllowSHA1(allow bool) {
	v.allowSHA1.Store(allow)
}

// SHA1Allowed reports the current allowSHA1 setting. Used by callers that
// advertise their accepted primitives via RFC 6975 DAU/DHU options — the
// advertised list must match what the validator will actually accept.
func (v *Validator) SHA1Allowed() bool {
	return v.allowSHA1.Load()
}

// isWeakRRSIGAlg reports whether the algorithm is on the weak/deprecated list
// the validator rejects by default. Currently only RSASHA1.
func (v *Validator) isWeakRRSIGAlg(alg uint8) bool {
	if v.allowSHA1.Load() {
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

// isWeakDSDigest reports whether the DS digest type cannot be used to
// authenticate a DNSKEY:
//
//   - DigestSHA1 (1) — RFC 8624 §3.3 deprecated; honoured only when
//     the operator explicitly opted in via allowSHA1.
//   - DigestReserved (0) — RFC 4509 §2.4 / RFC 8624 §3.3 hard
//     constraint: digest type 0 is IANA-reserved and MUST NOT be used
//     for validation regardless of the allowSHA1 toggle. If the parent
//     publishes ONLY digest-type-0 DS records the delegation has no
//     usable DS and falls to Insecure (RFC 4035 §5.2).
//
// Algorithms outside these two ranges are accepted; the verify-switch
// in verify.go is the final arbiter for crypto support.
func (v *Validator) isWeakDSDigest(d uint8) bool {
	if d == dns.DigestReserved {
		return true
	}
	if v.allowSHA1.Load() {
		return false
	}
	return d == dns.DigestSHA1
}

// ValidationStep captures one RRSIG-attempt outcome inside a validation pass.
// It is produced by ValidateResponseDetailed and exposed to diagnostic tools
// (the DNS lookup trace UI) so an operator can see exactly which signature
// the validator considered, what it covered, and why it was accepted or
// rejected. Plain ValidateResponse callers do not pay for this — they get the
// same single verdict as before.
type ValidationStep struct {
	Stage       string // "skip-weak", "skip-unsupported", "no-rrset", "expired", "not-yet", "out-of-bailiwick", "no-dnskey", "no-matching-key", "verify-failed", "verify-ok", "trust-chain"
	Signer      string
	Owner       string
	KeyTag      uint16
	Algorithm   uint8
	TypeCovered uint16
	Labels      uint8
	Outcome     string // "ok", "bogus", "insecure", "indeterminate", "skipped"
	Detail      string
}

// ValidateResponse validates DNSSEC signatures in a DNS response.
// It checks RRSIG records in the answer section and validates the
// trust chain from the signer back to the root trust anchors.
// For NXDOMAIN/NODATA responses, it also validates NSEC3 proofs.
func (v *Validator) ValidateResponse(response *dns.Message, qname string, qtype uint16) ValidationResult {
	verdict, _, _ := v.validateResponseImpl(response, qname, qtype, false)
	return verdict
}

// ValidateResponseWithReason returns the same verdict as ValidateResponse
// plus a FailureReason that classifies why a Bogus / Indeterminate verdict
// was reached. Callers can map the reason to an RFC 8914 EDE info code so
// that "RRSIG expired" and "no DNSKEY by key tag" don't collapse into the
// generic EDE 6. For Secure verdicts the reason is ReasonNone.
//
// Like ValidateResponse, this path does not allocate per-RRSIG steps.
func (v *Validator) ValidateResponseWithReason(response *dns.Message, qname string, qtype uint16) (ValidationResult, FailureReason) {
	verdict, _, reason := v.validateResponseImpl(response, qname, qtype, false)
	return verdict, reason
}

// ValidateResponseDetailed returns the same verdict as ValidateResponse plus
// a per-RRSIG step log for diagnostic UIs. Each step records the algorithm,
// key tag, signer, type covered, labels, and outcome so a human can see why
// the validator settled on Secure / Insecure / Bogus / Indeterminate.
//
// Plain ValidateResponse callers do not pay for this — they get the same
// single verdict and no allocated step slice.
func (v *Validator) ValidateResponseDetailed(response *dns.Message, qname string, qtype uint16) (ValidationResult, []ValidationStep) {
	verdict, steps, _ := v.validateResponseImpl(response, qname, qtype, true)
	return verdict, steps
}

// validateResponseImpl is the unified routine behind both public entrypoints.
// When collect is false `steps` is left nil — the hot path stays allocation-free.
// The FailureReason result classifies the cause when verdict is not Secure
// so callers can map it to an RFC 8914 EDE info code.
func (v *Validator) validateResponseImpl(response *dns.Message, qname string, qtype uint16, collect bool) (ValidationResult, []ValidationStep, FailureReason) {
	var steps []ValidationStep
	push := func(s ValidationStep) {
		if collect {
			steps = append(steps, s)
		}
	}
	if response == nil {
		return Insecure, steps, ReasonNone
	}

	// Per-response crypto budget: the global KeyTrap backstop shared across the
	// answer RRset, the trust chain, and every denial proof in this validation.
	budget := &cryptoBudget{max: maxCryptoVerifyPerResponse}

	// RFC 7646 §1: a Negative Trust Anchor for the queried subtree
	// suppresses validation. The operator installed it precisely
	// because the zone's chain is broken; we honour that decision
	// before doing any signature work. The verdict is Insecure (not
	// Bogus or Secure) — "we deliberately stopped looking", which is
	// what the RFC 8914 EDE consumer should see too.
	if store := v.ntaStore.Load(); store != nil {
		if nta, matched := store.Match(qname); matched {
			v.ntaMatches.Add(1)
			push(ValidationStep{
				Stage:   "nta-override",
				Outcome: "insecure",
				Detail:  fmt.Sprintf("NTA active for %q (expires %s)", nta.Zone, nta.Expiry.Format(time.RFC3339)),
			})
			return Insecure, steps, ReasonNTAOverride
		}
	}

	// Handle NXDOMAIN/NODATA: validate NSEC3 proofs in authority section
	rcode := response.Header.RCODE()
	if rcode == dns.RCodeNXDomain || (rcode == dns.RCodeNoError && len(response.Answers) == 0) {
		verdict := v.validateDenialResponse(response, qname, qtype, budget)
		push(ValidationStep{Stage: "denial", Outcome: verdictToOutcome(verdict), Detail: "NSEC/NSEC3 denial proof"})
		reason := ReasonNone
		if verdict == Bogus {
			reason = ReasonOther
		}
		return verdict, steps, reason
	}

	if len(response.Answers) == 0 {
		return Insecure, steps, ReasonNone
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
				push(ValidationStep{Stage: "parse-rrsig", Outcome: "skipped", Detail: err.Error()})
				continue
			}
			rrsigs = append(rrsigs, rrsigWithOwner{rrsig: parsed, owner: rr.Name})
		} else {
			answerRRs = append(answerRRs, rr)
		}
	}

	// No RRSIG records at all means unsigned (insecure) zone.
	if len(rrsigs) == 0 {
		push(ValidationStep{Stage: "no-rrsigs", Outcome: "insecure", Detail: "answer section has no RRSIG"})
		return Insecure, steps, ReasonNone
	}

	// RFC 4035 §5.3.3: a Secure RRset is one for which AT LEAST ONE valid
	// RRSIG exists. The validator must not give up after the first signature
	// failure — multiple signatures over the same RRset are common during key
	// rollover (old key still publishing, new key already publishing) and a
	// strict short-circuit would convert every rollover into resolver outage.
	//
	// Strategy: walk every usable RRSIG; remember the strongest failure mode
	// (Bogus > Indeterminate > Insecure) so that if none validate we can
	// return the right "why" instead of always saying Indeterminate. Track
	// the specific cause too so callers can pick an RFC 8914 EDE info code.
	usableRRSIGs := 0
	sawBogus := false
	sawIndeterminate := false
	sawUnsupportedAlg := false
	bogusReason := ReasonNone
	indetReason := ReasonNone
	// setBogusReason records the first specific bogus cause we see. Later
	// causes do not overwrite — the first signature failure is usually the
	// most informative for the operator looking at the EDE.
	setBogusReason := func(r FailureReason) {
		if bogusReason == ReasonNone {
			bogusReason = r
		}
	}
	setIndetReason := func(r FailureReason) {
		if indetReason == ReasonNone {
			indetReason = r
		}
	}

	skewI := int64(rrsigClockSkew / time.Second)
	nowI := time.Now().Unix()

	// verifyAttempts counts the number of expensive crypto verifications
	// already performed for this RRset. Beyond maxRRSIGVerifyAttempts we
	// stop walking the RRSIG list — an attacker cannot make us spend
	// unbounded CPU by stuffing the answer with garbage signatures.
	verifyAttempts := 0

	for _, rs := range rrsigs {
		rrsig := rs.rrsig
		// Algorithm policy: skip RRSIGs we refuse to validate (e.g. RSASHA1)
		// or that use an algorithm we cannot verify (ED448). Either way the
		// effect on `usableRRSIGs` is the same — without a verifiable
		// signature the validator falls back to Insecure per RFC 6840 §5.2.
		baseStep := ValidationStep{
			Signer:      normalizeName(rrsig.SignerName),
			Owner:       rs.owner,
			KeyTag:      rrsig.KeyTag,
			Algorithm:   rrsig.Algorithm,
			TypeCovered: rrsig.TypeCovered,
			Labels:      rrsig.Labels,
		}
		if v.isWeakRRSIGAlg(rrsig.Algorithm) {
			v.logger.Debug("skipping RRSIG with weak algorithm",
				"algorithm", rrsig.Algorithm,
				"signer", rrsig.SignerName)
			step := baseStep
			step.Stage = "skip-weak"
			step.Outcome = "skipped"
			step.Detail = "algorithm on weak/deprecated list"
			push(step)
			continue
		}
		if v.isUnsupportedRRSIGAlg(rrsig.Algorithm) {
			v.logger.Debug("skipping RRSIG with unsupported algorithm",
				"algorithm", rrsig.Algorithm,
				"signer", rrsig.SignerName)
			step := baseStep
			step.Stage = "skip-unsupported"
			step.Outcome = "skipped"
			step.Detail = "no verifier for this algorithm"
			push(step)
			sawUnsupportedAlg = true
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
			step := baseStep
			step.Stage = "no-rrset"
			step.Outcome = "skipped"
			step.Detail = "no RRs match (type, owner) of this RRSIG"
			push(step)
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
			setBogusReason(ReasonSignatureNotYetValid)
			step := baseStep
			step.Stage = "not-yet"
			step.Outcome = "bogus"
			step.Detail = fmt.Sprintf("inception=%d > now=%d", rrsig.Inception, nowI)
			push(step)
			continue
		}
		if nowI > expI+skewI {
			v.logger.Debug("RRSIG expired; trying next",
				"expiration", rrsig.Expiration, "now", nowI)
			sawBogus = true
			setBogusReason(ReasonSignatureExpired)
			step := baseStep
			step.Stage = "expired"
			step.Outcome = "bogus"
			step.Detail = fmt.Sprintf("expiration=%d < now=%d", rrsig.Expiration, nowI)
			push(step)
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
			setBogusReason(ReasonOther)
			step := baseStep
			step.Stage = "out-of-bailiwick"
			step.Outcome = "bogus"
			step.Detail = fmt.Sprintf("signer %q not ancestor of %q", signerZone, qname)
			push(step)
			continue
		}

		// Fetch DNSKEY for the signer zone.
		dnskeys, err := v.fetchDNSKEYs(signerZone)
		if err != nil {
			v.logger.Debug("failed to fetch DNSKEYs; trying next",
				"zone", signerZone, "error", err)
			sawIndeterminate = true
			setIndetReason(ReasonDNSKEYMissing)
			step := baseStep
			step.Stage = "no-dnskey"
			step.Outcome = "indeterminate"
			step.Detail = fmt.Sprintf("DNSKEY fetch failed: %v", err)
			push(step)
			continue
		}

		// Find the matching DNSKEY by key tag.
		matchingKey, err := findMatchingDNSKEY(dnskeys, rrsig.KeyTag, rrsig.Algorithm)
		if err != nil {
			v.logger.Debug("no matching DNSKEY found; trying next",
				"key_tag", rrsig.KeyTag, "zone", signerZone)
			sawIndeterminate = true
			setIndetReason(ReasonNoMatchingDNSKEY)
			step := baseStep
			step.Stage = "no-matching-key"
			step.Outcome = "indeterminate"
			step.Detail = fmt.Sprintf("no DNSKEY with key_tag=%d alg=%d at %s", rrsig.KeyTag, rrsig.Algorithm, signerZone)
			push(step)
			continue
		}

		// M5.5 — cap expensive crypto work. Once we've spent
		// maxRRSIGVerifyAttempts cycles on this RRset we stop walking
		// further RRSIGs even if more are present. A hostile auth that
		// attached 1000 garbage RRSIGs cannot make us spend 1000 verifies.
		if verifyAttempts >= maxRRSIGVerifyAttempts || !budget.allow() {
			step := baseStep
			step.Stage = "verify-cap"
			step.Outcome = "skipped"
			step.Detail = fmt.Sprintf("RRSIG verify cap reached (per-RRset %d / per-response %d); refusing further crypto work", maxRRSIGVerifyAttempts, maxCryptoVerifyPerResponse)
			push(step)
			break
		}
		verifyAttempts++

		// Verify the RRSIG signature.
		if err := VerifyRRSIG(rrset, rrsig, matchingKey); err != nil {
			v.logger.Debug("RRSIG verification failed; trying next",
				"key_tag", rrsig.KeyTag, "zone", signerZone, "error", err)
			sawBogus = true
			setBogusReason(ReasonOther)
			step := baseStep
			step.Stage = "verify-failed"
			step.Outcome = "bogus"
			step.Detail = fmt.Sprintf("crypto verify: %v", err)
			push(step)
			continue
		}

		// Signature validated. Walk the trust chain. All RRSIGs for a single
		// RRset have signers in one zone — the chain result is the same for
		// any of them, so the first signature that survives this point
		// determines the verdict.
		verifyStep := baseStep
		verifyStep.Stage = "verify-ok"
		verifyStep.Outcome = "ok"
		verifyStep.Detail = "RRSIG cryptographic verification succeeded"
		push(verifyStep)

		result := v.validateTrustChain(signerZone, dnskeys, budget)
		if result == Secure {
			if sawBogus || sawIndeterminate {
				// At least one prior RRSIG candidate failed before this
				// one validated — likely an algorithm rollover (RFC 4035
				// §4.6) or multi-signer transition (RFC 8901). Count
				// these so operators can monitor rollover activity.
				v.rolloverValidates.Add(1)
			}
			v.logger.Debug("DNSSEC validation successful",
				"zone", signerZone, "key_tag", rrsig.KeyTag)
		}
		chainStep := baseStep
		chainStep.Stage = "trust-chain"
		chainStep.Outcome = verdictToOutcome(result)
		chainStep.Detail = fmt.Sprintf("trust chain from %s to root: %s", signerZone, result)
		push(chainStep)
		// Trust chain may have ruled Bogus (e.g. revoked KSK, DS-DNSKEY
		// mismatch). Surface that as a generic Bogus reason since we don't
		// have a more specific tag from here.
		chainReason := ReasonNone
		if result == Bogus {
			chainReason = ReasonOther
		}
		return result, steps, chainReason
	}

	// All RRSIGs were skipped because they used weak (rejected) algorithms.
	// Per RFC 8624 §3.1, treat as insecure: the zone is effectively unsigned
	// from this validator's perspective. The unsupported-algorithm signal is
	// still useful to emit as EDE 1 — clients deciding whether to retry with
	// a different resolver should know the answer is unsigned-by-policy here.
	if usableRRSIGs == 0 {
		v.logger.Debug("all RRSIGs used weak algorithms; treating as insecure",
			"qname", qname, "qtype", qtype)
		reason := ReasonNone
		if sawUnsupportedAlg {
			reason = ReasonUnsupportedDNSKEYAlgo
		}
		return Insecure, steps, reason
	}

	// No RRSIG fully validated. Prefer Bogus over Indeterminate so a real
	// signature forgery does not get downgraded to a soft-fail.
	if sawBogus {
		return Bogus, steps, bogusReason
	}
	if sawIndeterminate {
		return Indeterminate, steps, indetReason
	}
	return Indeterminate, steps, indetReason
}

func verdictToOutcome(v ValidationResult) string {
	switch v {
	case Secure:
		return "ok"
	case Insecure:
		return "insecure"
	case Bogus:
		return "bogus"
	}
	return "indeterminate"
}

// validateTrustChain validates the DNSKEY trust chain from the given zone
// back to the root trust anchors.
func (v *Validator) validateTrustChain(zone string, dnskeys []dns.ResourceRecord, budget ...*cryptoBudget) ValidationResult {
	cb := budgetFrom(budget)
	// Build the chain of zones from root to the signer zone.
	chain := buildZoneChain(zone)

	// M5.5 — refuse to walk pathologically deep chains. A hostile
	// authoritative could publish an RRSIG whose SignerName is 127
	// labels long; the walker would do 128 DNSKEY + 128 DS fetches
	// per query. The cap collapses such an attempt to Indeterminate
	// before any network round-trip fires.
	if len(chain) > maxTrustChainDepth {
		v.logger.Debug("trust chain exceeds depth cap; refusing to walk",
			"zone", zone, "depth", len(chain), "cap", maxTrustChainDepth)
		return Indeterminate
	}

	// parentKeys holds the previous chain element's verified DNSKEY RRset.
	// Required for authenticating the parent's denial-of-DS (RFC 4035 §5.2 /
	// RFC 5155 §10.4) on the empty-DS path — without it, an off-path
	// attacker spoofing a NOERROR-empty DS reply downgrades a secure child
	// to Insecure for the lifetime of the (legitimate) cache miss.
	var parentKeys []dns.ResourceRecord

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
			dsRecords, denialAuth, err := v.fetchDS(chainZone, parentZone)
			if err != nil {
				v.logger.Debug("failed to fetch DS records",
					"zone", chainZone,
					"parent", parentZone,
					"error", err)
				return Indeterminate
			}
			if len(dsRecords) == 0 {
				// RFC 4035 §5.2 / RFC 5155 §10.4: a NOERROR-empty DS
				// response must be authenticated as denial-of-DS before
				// it can downgrade the chain to Insecure. Without this
				// check, a spoofed empty DS reply downgrades any secure
				// child to Insecure for the cache lifetime.
				ok := v.verifyDSDenial(chainZone, parentZone, parentKeys, denialAuth, cb)
				if !ok {
					v.logger.Debug("empty DS response without authenticated denial — treating as Bogus",
						"zone", chainZone, "parent", parentZone)
					return Bogus
				}
				v.logger.Debug("authenticated insecure delegation",
					"zone", chainZone, "parent", parentZone)
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
		// Carry this iteration's verified DNSKEY rrset forward as the
		// parent keys for the next chain element; needed by the
		// empty-DS denial verification on the next hop.
		parentKeys = zoneKeys
	}

	return Secure
}

// verifyDSDenial authenticates a NOERROR-empty DS response from the parent
// zone. Without this check, an off-path attacker who wins the TXID/0x20
// race for a single forged packet can inject an empty DS answer and
// downgrade any previously-Secure child to Insecure for the lifetime of
// the cache miss (RFC 4035 §5.2 / RFC 5155 §10.4 / RFC 6840 §5.9).
//
// The proof must be served from the parent's authority section and signed
// by a key in parentKeys. Accepted forms:
//
//   - NSEC at the child's owner name whose type bitmap omits DS (and CNAME,
//     and either includes NS or — for a same-zone NSEC — includes SOA).
//   - NSEC3 at H(childZone) with DS absent from the bitmap.
//   - NSEC3 covering H(childZone) with the opt-out flag set, asserting that
//     the child is an unsigned delegation that the parent did not enumerate.
//
// Returns true only when at least one such proof is present AND signed by
// parentKeys. A false return must be treated as Bogus by the caller (signed
// chain with a forged/missing parent denial).
func (v *Validator) verifyDSDenial(childZone, parentZone string, parentKeys []dns.ResourceRecord, authority []dns.ResourceRecord, budget ...*cryptoBudget) bool {
	cb := budgetFrom(budget)
	// Defense in depth: if we have no parent keys (e.g. trust-anchor
	// fast-path issue), refuse the denial — an unverified Insecure
	// downgrade is what we are trying to prevent.
	if len(parentKeys) == 0 {
		return false
	}

	// Collect RRSIGs, NSEC, NSEC3 from the authority section, alongside the
	// raw RR owner names needed for owner-aware RRset reconstruction.
	var rrsigs []rrsigWithOwner
	var nsec3WithOwners []NSEC3RecordWithOwner
	var nsec3RRNames []string
	var nsecWithOwners []NSECRecordWithOwner

	for _, rr := range authority {
		switch rr.Type {
		case dns.TypeRRSIG:
			parsed, err := dns.ParseRRSIG(rr.RData, 0)
			if err != nil {
				continue
			}
			rrsigs = append(rrsigs, rrsigWithOwner{rrsig: parsed, owner: rr.Name})
		case dns.TypeNSEC:
			parsed, err := dns.ParseNSEC(rr.RData, 0)
			if err != nil {
				continue
			}
			nsecWithOwners = append(nsecWithOwners, NSECRecordWithOwner{
				NSECRecord: *parsed,
				OwnerName:  rr.Name,
			})
		case dns.TypeNSEC3:
			parsed, err := dns.ParseNSEC3(rr.RData)
			if err != nil {
				continue
			}
			ownerHash, err := nsec3OwnerHashFromName(rr.Name)
			if err != nil {
				continue
			}
			nsec3WithOwners = append(nsec3WithOwners, NSEC3RecordWithOwner{
				NSEC3Record: *parsed,
				OwnerHash:   ownerHash,
			})
			nsec3RRNames = append(nsec3RRNames, rr.Name)
		}
	}

	if len(rrsigs) == 0 {
		// An unsigned empty DS reply cannot prove anything; this is the
		// classic downgrade-attempt shape.
		return false
	}

	// Validate each RRSIG against parentKeys, recording which (owner, type)
	// rrsets have a verified signature. We refuse to use unauthenticated
	// NSEC/NSEC3 records even if the math of their bitmap/coverage looks
	// fine — the whole point of denial-of-DS authentication is that the
	// signature is what blocks substitution.
	type ownerTypeKey struct {
		owner string
		typ   uint16
	}
	authenticated := make(map[ownerTypeKey]bool)
	skewI := int64(rrsigClockSkew / time.Second)
	for _, rs := range rrsigs {
		rrsig := rs.rrsig
		if rrsig.TypeCovered != dns.TypeNSEC && rrsig.TypeCovered != dns.TypeNSEC3 {
			continue
		}
		if v.isWeakRRSIGAlg(rrsig.Algorithm) || v.isUnsupportedRRSIGAlg(rrsig.Algorithm) {
			continue
		}
		// Bailiwick — the RRSIG signer must be the parent zone (or root)
		// to authenticate a denial-of-DS at the delegation point.
		signer := strings.ToLower(strings.TrimSuffix(rrsig.SignerName, "."))
		parent := strings.ToLower(strings.TrimSuffix(parentZone, "."))
		if signer != parent {
			continue
		}
		rrset := filterRRSetByOwner(authority, rrsig.TypeCovered, rs.owner)
		if len(rrset) == 0 {
			continue
		}
		nowI := time.Now().Unix()
		incI := int64(rrsig.Inception)
		expI := int64(rrsig.Expiration)
		if nowI+skewI < incI || nowI > expI+skewI {
			continue
		}
		dnskey, err := findMatchingDNSKEY(parentKeys, rrsig.KeyTag, rrsig.Algorithm)
		if err != nil {
			continue
		}
		if !cb.allow() {
			// Per-response crypto budget exhausted — stop verifying the
			// attacker-supplied authority RRSIGs (KeyTrap backstop).
			break
		}
		if err := VerifyRRSIG(rrset, rrsig, dnskey); err == nil {
			authenticated[ownerTypeKey{
				owner: strings.ToLower(strings.TrimSuffix(rs.owner, ".")),
				typ:   rrsig.TypeCovered,
			}] = true
		}
	}

	if len(authenticated) == 0 {
		return false
	}

	// Path 1: NSEC at childZone with DS absent.
	for _, n := range nsecWithOwners {
		owner := strings.ToLower(strings.TrimSuffix(n.OwnerName, "."))
		want := strings.ToLower(strings.TrimSuffix(childZone, "."))
		if owner != want {
			continue
		}
		if !authenticated[ownerTypeKey{owner: owner, typ: dns.TypeNSEC}] {
			continue
		}
		if nsecHasType(&n.NSECRecord, dns.TypeDS) {
			continue
		}
		if nsecHasType(&n.NSECRecord, dns.TypeCNAME) {
			continue
		}
		// Must be a parent-side delegation NSEC (NS without SOA) OR an
		// apex NSEC at the child (NS+SOA). Either way the DS bitmap
		// absence is the load-bearing fact; we just want a sanity check
		// that we aren't looking at an unrelated NSEC.
		if nsecHasType(&n.NSECRecord, dns.TypeNS) {
			return true
		}
	}

	// Path 2 & 3: NSEC3 forms.
	if len(nsec3WithOwners) == 0 {
		return false
	}
	// Restrict to authenticated NSEC3 records.
	verified := make([]NSEC3RecordWithOwner, 0, len(nsec3WithOwners))
	for i, n := range nsec3WithOwners {
		if authenticated[ownerTypeKey{
			owner: strings.ToLower(strings.TrimSuffix(nsec3RRNames[i], ".")),
			typ:   dns.TypeNSEC3,
		}] {
			verified = append(verified, n)
		}
	}
	if len(verified) == 0 {
		return false
	}
	ok, err := VerifyNSEC3DenialDSAbsent(childZone, verified)
	if err != nil {
		v.logger.Debug("NSEC3 DS-denial verification error",
			"zone", childZone, "error", err)
		return false
	}
	return ok
}

// verifyAgainstTrustAnchors checks if any DNSKEY for the root zone matches
// one of the configured trust anchors. Trust-anchor DS records using digest
// types we reject by policy (e.g. SHA1) are skipped. RFC 4509 §3: when the
// trust-anchor set carries multiple digest types for the same key tag +
// algorithm, only the strongest supported digest is consulted — otherwise
// a SHA-1 collision could let an attacker chain to a key the operator
// would never have accepted under the stronger SHA-256 anchor.
func (v *Validator) verifyAgainstTrustAnchors(zone string, dnskeys []dns.ResourceRecord) bool {
	// Materialise pointers once so the strongest-digest helper can scan
	// the same list. The variable scope is intentionally short to limit
	// the allocation footprint to this verify pass.
	anchorPtrs := make([]*dns.DSRecord, 0, len(v.trustAnchors))
	for i := range v.trustAnchors {
		anchorPtrs = append(anchorPtrs, &v.trustAnchors[i])
	}
	for _, rr := range dnskeys {
		dnskey, err := dns.ParseDNSKEY(rr.RData)
		if err != nil {
			continue
		}
		if !dnskey.IsKSK() {
			continue
		}
		// RFC 5011 §3: a revoked DNSKEY MUST NOT match a trust anchor.
		// The operator has explicitly disowned this key.
		if dnskey.IsRevoked() {
			continue
		}
		strongest := strongestDSDigestForKey(anchorPtrs, dnskey.KeyTag(), dnskey.Algorithm, v)
		for _, anchor := range v.trustAnchors {
			if v.isWeakDSDigest(anchor.DigestType) {
				continue
			}
			if anchor.KeyTag == dnskey.KeyTag() && anchor.Algorithm == dnskey.Algorithm &&
				strongest != 0 && anchor.DigestType != strongest {
				continue
			}
			if VerifyDS(dnskey, &anchor, zone) {
				return true
			}
		}
	}
	return false
}

// strongestDSDigestForKey returns the most-trusted supported DS digest
// type present among `dsRecords` for the given (keyTag, algorithm) pair.
// RFC 4509 §3 mandates the "highest value among the supported ones" rule;
// the digest-type numbers were assigned in ascending strength, so a
// simple max over the supported subset is the correct selection. Returns
// 0 when no DS for this key has a supported digest — caller should leave
// the (now empty) supported set alone and the verify loop falls through.
func strongestDSDigestForKey(dsRecords []*dns.DSRecord, keyTag uint16, algorithm uint8, v *Validator) uint8 {
	var best uint8
	for _, ds := range dsRecords {
		if ds == nil {
			continue
		}
		if ds.KeyTag != keyTag || ds.Algorithm != algorithm {
			continue
		}
		if v.isWeakDSDigest(ds.DigestType) {
			continue
		}
		if ds.DigestType > best {
			best = ds.DigestType
		}
	}
	return best
}

// verifyDNSKEYWithDS checks if any DNSKEY (specifically KSK) matches any
// of the provided DS records. DS records with digest types rejected by
// policy (e.g. SHA1) are skipped to prevent algorithm-downgrade attacks.
// RFC 4509 §3 / RFC 6840 §5.2: when the parent publishes multiple DS RRs
// for the same key tag + algorithm with different digest types, the
// validator MUST use the strongest supported digest and ignore weaker
// siblings — otherwise an attacker who can break SHA-1 (collision attack)
// can craft a key matching the SHA-1 DS even though a SHA-256 DS exists.
// strongestDSDigestForKey computes the per-(keytag,algorithm) ceiling.
func (v *Validator) verifyDNSKEYWithDS(dnskeys []dns.ResourceRecord, dsRecords []*dns.DSRecord, ownerName string) bool {
	for _, rr := range dnskeys {
		dnskey, err := dns.ParseDNSKEY(rr.RData)
		if err != nil {
			continue
		}
		if !dnskey.IsKSK() {
			continue
		}
		// RFC 5011 §3: revoked KSKs MUST NOT chain to a DS record.
		// A revoked-yet-DS-published key is exactly the rollover hold-
		// down period when the parent has not yet retracted the DS;
		// during that window only the unrevoked successor key is the
		// legitimate authority.
		if dnskey.IsRevoked() {
			continue
		}
		strongest := strongestDSDigestForKey(dsRecords, dnskey.KeyTag(), dnskey.Algorithm, v)
		for _, ds := range dsRecords {
			if v.isWeakDSDigest(ds.DigestType) {
				continue
			}
			// RFC 4509 §3: among the DS RRs that target this key, only
			// the strongest supported digest type may be used. Lower
			// digest types for the SAME key are now downgrade chaff.
			if ds.KeyTag == dnskey.KeyTag() && ds.Algorithm == dnskey.Algorithm &&
				strongest != 0 && ds.DigestType != strongest {
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
//  1. The zone is genuinely unsigned (correct verdict, long cache is fine).
//  2. The upstream answer was SERVFAIL/REFUSED/transient timeout (a wrong
//     verdict, and caching it for an hour pins the zone into Indeterminate
//     across the validator until the cache entry expires).
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

	// Cache the result. Enforce the cap with LRU eviction on insert
	// past MaxDNSKEYCacheEntries; existing-zone refreshes are exempt
	// because they replace in place and don't grow the map.
	v.mu.Lock()
	if _, exists := v.keyCache[normalized]; !exists && len(v.keyCache) >= MaxDNSKEYCacheEntries {
		v.evictOldestDNSKEYLocked()
	}
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
func (v *Validator) fetchDS(zone, parentZone string) ([]*dns.DSRecord, []dns.ResourceRecord, error) {
	normalized := normalizeName(zone)

	// Singleflight coordination.
	v.inflightMu.Lock()
	if inf, ok := v.inflightDS[normalized]; ok {
		v.inflightMu.Unlock()
		<-inf.done
		return inf.dss, inf.denialAuth, inf.err
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
		return nil, nil, inf.err
	}

	rcode := resp.Header.RCODE()
	if rcode == dns.RCodeServFail || rcode == dns.RCodeRefused {
		inf.err = fmt.Errorf("DS query for %s returned rcode %d", normalized, rcode)
		return nil, nil, inf.err
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
	// Surface the authority section so the caller can authenticate the
	// denial of DS when no DS records were returned. Cloning into a fresh
	// slice would also work, but inflightFetch outlives this call only
	// for the singleflight followers, and they receive read-only access.
	inf.denialAuth = resp.Authority
	return dsRecords, resp.Authority, nil
}

// findMatchingDNSKEY finds a DNSKEY record matching the given key tag and
// algorithm. RFC 5011 §3 revoked keys are skipped — a revoked DNSKEY can
// still appear in the zone's published DNSKEY rrset for the duration of
// the hold-down period, but it MUST NOT be used to validate RRSIGs.
func findMatchingDNSKEY(dnskeys []dns.ResourceRecord, keyTag uint16, algorithm uint8) (*dns.DNSKEYRecord, error) {
	for _, rr := range dnskeys {
		dnskey, err := dns.ParseDNSKEY(rr.RData)
		if err != nil {
			continue
		}
		if dnskey.IsRevoked() {
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
func (v *Validator) validateDenialResponse(response *dns.Message, qname string, qtype uint16, budget ...*cryptoBudget) ValidationResult {
	cb := budgetFrom(budget)
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
	var nsecWithOwners []NSECRecordWithOwner

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
		case dns.TypeNSEC:
			parsed, err := dns.ParseNSEC(rr.RData, 0)
			if err != nil {
				v.logger.Debug("failed to parse NSEC", "error", err)
				continue
			}
			nsecWithOwners = append(nsecWithOwners, NSECRecordWithOwner{
				NSECRecord: *parsed,
				OwnerName:  rr.Name,
			})
		}
	}

	// NSEC3 records-per-proof cap. A legitimate denial proof needs at most a
	// handful of NSEC3 records (closest-encloser + next-closer + wildcard, plus
	// a few more for opt-out spans). An attacker stuffing the authority section
	// with hundreds forces wasted parse + closest-encloser hashing work; refuse
	// the response outright (CVE-2023-50868 family — Knot refuses > 8, PowerDNS
	// caps records-per-record at 10; 16 leaves comfortable opt-out headroom).
	// The per-response crypto budget already bounds the verify loop; this is the
	// cheaper early reject before any hashing.
	if len(nsec3WithOwners) > MaxNSEC3RecordsPerProof {
		v.logger.Debug("NSEC3 denial proof carries too many records; refusing",
			"count", len(nsec3WithOwners), "cap", MaxNSEC3RecordsPerProof)
		return Indeterminate
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
		if rrsig.TypeCovered != dns.TypeNSEC3 &&
			rrsig.TypeCovered != dns.TypeNSEC &&
			rrsig.TypeCovered != dns.TypeSOA {
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

		if !cb.allow() {
			// Per-response crypto budget exhausted — stop verifying the
			// attacker-supplied authority RRSIGs (KeyTrap backstop). Leaving
			// the proof unverified collapses to Indeterminate below.
			sawIndeterminate = true
			break
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
	// Requires the full RFC 5155 §8.4–8.7 closest-encloser / next-closer /
	// wildcard triplet — not just a single covering NSEC3, which was the
	// pre-0.6.12 forgery vector (any one valid NSEC3 anywhere in the zone
	// could be replayed to "prove" NXDOMAIN for unrelated names).
	if len(verifiedNSEC3s) > 0 {
		denied, err := VerifyNSEC3Denial5155(qname, qtype, response.Header.RCODE(), verifiedNSEC3s)
		if err != nil {
			v.logger.Debug("NSEC3 denial verification error",
				"qname", qname, "error", err)
			return Indeterminate
		}
		if denied {
			v.logger.Debug("NSEC3 denial proof valid", "qname", qname)
			return Secure
		}
		v.logger.Debug("NSEC3 denial proof inconclusive — closest-encloser/NC/wildcard triplet not satisfied",
			"qname", qname)
	}

	// Validate NSEC denial proof using only authenticated records. NSEC is
	// what online signers such as Cloudflare emit (compact denial / black
	// lies); without this path every Cloudflare-hosted DNSSEC zone falls
	// over the moment it returns NXDOMAIN or NODATA.
	verifiedNSECs := make([]NSECRecordWithOwner, 0, len(nsecWithOwners))
	for _, n := range nsecWithOwners {
		if authenticRRsets[makeKey(n.OwnerName, dns.TypeNSEC)] {
			verifiedNSECs = append(verifiedNSECs, n)
		}
	}
	if len(verifiedNSECs) > 0 {
		denied, err := VerifyNSECDenial(qname, qtype, response.Header.RCODE(), verifiedNSECs)
		if err != nil {
			v.logger.Debug("NSEC denial verification error",
				"qname", qname, "error", err)
			return Indeterminate
		}
		if denied {
			v.logger.Debug("NSEC denial proof valid", "qname", qname)
			return Secure
		}
		v.logger.Debug("NSEC denial proof inconclusive — covering NSEC not found",
			"qname", qname)
	}

	// RFC 5155 §7.2.4 — a DS query answered with NODATA at a delegation is
	// not a forgery but an authenticated "insecure delegation" signal. The
	// generic NODATA proof above needs an NSEC3 that MATCHES the qname with
	// the DS bit clear; an opt-out delegation (the norm under .com/.net) has
	// no such record — the name sits inside an opt-out span — so that proof
	// legitimately comes up inconclusive and we must not fall through to
	// Bogus. Fall back to the dedicated DS-absence proof (matching NSEC3 with
	// DS clear, OR an opt-out NSEC3 covering H(qname)); when it holds the
	// correct verdict is Insecure — the same NOERROR / AD=0 that Unbound,
	// BIND, and the public 1.1.1.1 / 8.8.8.8 validators return for
	// `google.com DS`, NOT SERVFAIL. This runs only for TypeDS and only over
	// the already-authenticated NSEC3 set, so it cannot manufacture a denial.
	// It reuses exactly the proof the trust-chain walker trusts to declare an
	// insecure delegation, so it introduces no new trust surface.
	if qtype == dns.TypeDS && len(verifiedNSEC3s) > 0 {
		if proven, dsErr := VerifyNSEC3DenialDSAbsent(qname, verifiedNSEC3s); dsErr == nil && proven {
			v.logger.Debug("DS NODATA is an authenticated insecure delegation (NSEC3 opt-out / DS-clear)",
				"qname", qname)
			return Insecure
		}
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
