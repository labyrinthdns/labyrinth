package dnssec

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// MaxNTAEntries caps the size of an NTAStore. /api/dnssec/nta POST is
// authenticated, but a runaway operator script or a malicious admin
// with valid credentials could otherwise blow up the in-memory store
// (consulted on every DNSSEC-validated query through Match) by
// spamming distinct zone names. Real operator NTA lists are tiny
// (handful — RFC 7646 §6 explicitly warns NTAs are an exceptional
// measure, not a normal operating mode). 10k is well above any
// plausible legitimate workload and tiny enough that the entire map
// fits in CPU cache.
const MaxNTAEntries = 10_000

// ErrNTAStoreFull is returned by Add when the store has reached
// MaxNTAEntries. The /api/dnssec/nta admin handler surfaces this as
// 507 Insufficient Storage so the operator sees the cap rather than
// a silent no-op.
var ErrNTAStoreFull = errors.New("NTA store is full")

// NegativeTrustAnchor (NTA, RFC 7646) is an operator-installed override
// that suppresses DNSSEC validation for a specific zone subtree for a
// bounded time window.
//
// Motivation: a major TLD or a frequently-used domain misconfigures its
// signatures (expired RRSIG, broken DS rollover, KSK lost). Every
// validating resolver in front of that zone goes SERVFAIL. The operator
// — who knows the zone is broken but the operator of the broken zone
// has not yet fixed it — wants to keep their users working without
// disabling DNSSEC globally. RFC 7646 §1 defines an NTA as exactly
// that: a per-zone, time-bounded local override that downgrades
// validation to Insecure for matching qnames.
//
// Safety design:
//
//   - NTAs are bounded by expiry. RFC 7646 §6 stresses that NTAs MUST
//     NOT be open-ended; an entry past its expiry is treated as
//     removed. The store enforces this on every Match call.
//   - The expiry is operator-set (no implicit duration), so the
//     operational team takes the explicit decision of how long to
//     tolerate the broken zone.
//   - Match uses strict suffix semantics: an NTA at `example.test`
//     covers `example.test` itself and any descendant
//     (`foo.example.test`, `bar.foo.example.test`), but NOT sibling
//     zones like `other.test`. This matches the bailiwick rule used
//     everywhere else in the validator.
//
// Match is read-side hot path (every DNSSEC-validated query passes
// through it), so the store uses RWMutex with the read path under
// RLock only.
type NegativeTrustAnchor struct {
	// Zone is the apex name of the zone for which validation is
	// suppressed. Always stored normalized (lowercase, trailing dot).
	Zone string

	// Expiry is the wall-clock time after which this NTA is treated
	// as removed. RFC 7646 §6 requires a bounded lifetime.
	Expiry time.Time

	// Reason is an operator-supplied free-text note. Surfaced via the
	// observability API so the operator can later answer "why did I
	// add this NTA". Not used by the matcher.
	Reason string
}

// NTAStore is a thread-safe collection of negative trust anchors.
// Construct via NewNTAStore. The zero value is NOT ready for use —
// callers must use the constructor so the internal map is allocated.
type NTAStore struct {
	mu      sync.RWMutex
	entries map[string]NegativeTrustAnchor // keyed by normalized zone

	// nowFunc is the clock used for expiry comparison. Defaults to
	// time.Now but tests inject a mocked clock to exercise expiry
	// transitions deterministically.
	nowFunc func() time.Time
}

// NewNTAStore returns an empty store backed by the wall clock.
func NewNTAStore() *NTAStore {
	return &NTAStore{
		entries: make(map[string]NegativeTrustAnchor),
		nowFunc: time.Now,
	}
}

// SetClock replaces the store's clock for tests. Not safe to call
// concurrently with Match — wire it before publishing the store.
func (s *NTAStore) SetClock(fn func() time.Time) {
	s.nowFunc = fn
}

// Add installs an NTA for the given zone. If an NTA already exists for
// the same zone it is replaced (typical "extend or shorten the window"
// operator action). Expiry MUST be in the future at the moment of the
// call; an Expiry already in the past is silently ignored — the caller
// should detect this and surface an error if it matters.
//
// Returns ErrNTAStoreFull when the store is at MaxNTAEntries capacity
// and the call would create a NEW entry (replacements of existing
// zones continue to succeed at the cap because they do not grow the
// map). nil on success, including the silent no-ops for empty zone
// names and past-expiry entries (those are not error states).
func (s *NTAStore) Add(zone string, expiry time.Time, reason string) error {
	normalized := normalizeNTAName(zone)
	if normalized == "" {
		return nil
	}
	if !expiry.After(s.nowFunc()) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[normalized]; !exists && len(s.entries) >= MaxNTAEntries {
		return ErrNTAStoreFull
	}
	s.entries[normalized] = NegativeTrustAnchor{
		Zone:   normalized,
		Expiry: expiry,
		Reason: reason,
	}
	return nil
}

// Remove deletes the NTA for the given zone. No-op if the zone is not
// covered. Returns true iff an entry was actually removed.
func (s *NTAStore) Remove(zone string) bool {
	normalized := normalizeNTAName(zone)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[normalized]; ok {
		delete(s.entries, normalized)
		return true
	}
	return false
}

// Match reports whether the given qname is covered by any active
// (unexpired) NTA. The walk is suffix-based: the NTA at `example.test`
// matches `example.test`, `foo.example.test`, and so on, but NOT
// `other.test`. Cousins outside the NTA subtree always fall through
// to normal validation.
//
// Expired entries are treated as absent; they are not eagerly evicted
// here (that would require a write lock on the hot path). Use
// Cleanup() periodically to reclaim memory.
func (s *NTAStore) Match(qname string) (NegativeTrustAnchor, bool) {
	normalized := normalizeNTAName(qname)
	if normalized == "" {
		return NegativeTrustAnchor{}, false
	}
	now := s.nowFunc()

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Walk from longest suffix to shortest: foo.bar.example.test →
	// bar.example.test → example.test → test → "."
	// First active match wins. We iterate by progressively dropping
	// labels rather than scanning all entries — typical operator NTA
	// list is small (handful), but a label-walk is bounded by name
	// depth (~10 max in practice) regardless of store size.
	candidate := normalized
	for {
		if nta, ok := s.entries[candidate]; ok {
			if nta.Expiry.After(now) {
				return nta, true
			}
		}
		// Drop the leftmost label.
		idx := strings.IndexByte(candidate, '.')
		if idx < 0 || idx == len(candidate)-1 {
			// Reached the root or a single-label name; stop.
			break
		}
		candidate = candidate[idx+1:]
	}
	return NegativeTrustAnchor{}, false
}

// Cleanup removes expired NTAs from the store. Returns the number of
// entries removed. Safe to call on a schedule (e.g. once per minute)
// from a background goroutine.
func (s *NTAStore) Cleanup() int {
	now := s.nowFunc()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for zone, nta := range s.entries {
		if !nta.Expiry.After(now) {
			delete(s.entries, zone)
			removed++
		}
	}
	return removed
}

// List returns a snapshot of all currently-stored NTAs (active OR
// expired — for operator-facing UI it is useful to surface expired
// entries until Cleanup runs). Order is not specified.
func (s *NTAStore) List() []NegativeTrustAnchor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NegativeTrustAnchor, 0, len(s.entries))
	for _, nta := range s.entries {
		out = append(out, nta)
	}
	return out
}

// LoadNTAStoreFromStrings builds a store from operator config lines of
// the form "<zone>|<RFC3339-expiry>|<reason>". Empty lines are skipped.
// Lines that fail to parse (bad format, unparseable timestamp, expiry
// already past) are returned in the second result so the caller can
// log them but the store remains usable with the entries that did
// parse. Returns a non-nil store even on total parse failure.
func LoadNTAStoreFromStrings(entries []string) (*NTAStore, []string) {
	store := NewNTAStore()
	var failed []string
	for _, raw := range entries {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// zone | expiry | reason  — reason may itself contain spaces
		// but no pipes (the grammar is fixed-arity-3).
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 2 {
			failed = append(failed, raw+" (need at least zone|expiry)")
			continue
		}
		zone := strings.TrimSpace(parts[0])
		expiryStr := strings.TrimSpace(parts[1])
		reason := ""
		if len(parts) == 3 {
			reason = strings.TrimSpace(parts[2])
		}
		expiry, err := time.Parse(time.RFC3339, expiryStr)
		if err != nil {
			failed = append(failed, raw+" (bad expiry: "+err.Error()+")")
			continue
		}
		if addErr := store.Add(zone, expiry, reason); addErr != nil {
			failed = append(failed, raw+" ("+addErr.Error()+")")
			continue
		}
		// Add silently drops past-expiry entries; surface that as a
		// soft failure so the operator notices in logs.
		if _, ok := store.entries[normalizeNTAName(zone)]; !ok {
			failed = append(failed, raw+" (expiry already past)")
		}
	}
	return store, failed
}

// normalizeNTAName lowercases the name and ensures a trailing dot, so
// the store's keys are canonical. Returns "" for empty input.
func normalizeNTAName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}
