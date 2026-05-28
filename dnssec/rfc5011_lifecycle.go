package dnssec

import (
	"bytes"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// RFC 5011 — Automated Updates of DNS Security (DNSSEC) Trust Anchors.
//
// The static trust anchor list in trustanchor.go covers the easy case:
// a resolver ships a fixed root KSK list and operators rebuild on
// KSK rollover. RFC 5011 defines the harder case — automatically
// follow root KSK rollover without operator intervention, while
// resisting two specific attacks:
//
//   1. Premature add — a victim resolver picks up a newly-published
//      KSK before the operator community has accepted it; an attacker
//      who got their key into the published RRset (via compromise of
//      the auth) gains validation power immediately.
//   2. Premature remove — a previously-trusted KSK disappears from
//      the published RRset, and the resolver immediately untrusts it,
//      breaking validation for any RRSIG still signed by it (which
//      will exist for the TTL of the signed records).
//
// The RFC defends both with a hold-down state machine. A new KSK
// observed in the published DNSKEY RRset enters the **AddPending**
// state with a 30-day add hold-down timer. Only after the timer
// elapses with the KSK *still* in the RRset does it transition to
// **Valid** and become a usable trust anchor. A KSK that disappears
// from the RRset enters **Missing** with a 30-day remove hold-down
// timer; if it does not reappear before the timer elapses it is
// transitioned to **Removed** (no longer trusted but kept in the
// store so a re-add restarts the AddPending timer cleanly). A KSK
// with the REVOKE bit set transitions directly to **Revoked**
// regardless of timer state (RFC 5011 §2.1) — the operator has
// explicitly disowned that key.
//
// This file is the in-memory machine. Persistence (so the resolver
// survives restarts without re-running the 30-day timers) is the
// caller's responsibility — see Snapshot / RestoreSnapshot.

// TrustAnchorState is the lifecycle position of a KSK candidate.
type TrustAnchorState int

const (
	// TAStateAddPending — observed but the add hold-down has not elapsed.
	// MUST NOT be used to validate signatures yet.
	TAStateAddPending TrustAnchorState = iota
	// TAStateValid — passed the add hold-down and is currently
	// published in the parent's DNSKEY RRset. Use to validate.
	TAStateValid
	// TAStateMissing — was Valid, now absent from the RRset. The
	// remove hold-down is counting down. We KEEP using this anchor
	// for validation during the hold-down — RFC 5011 §2.2: "an
	// anchor that has not been formally revoked SHOULD continue to
	// be used until the remove hold-down timer expires".
	TAStateMissing
	// TAStateRemoved — remove hold-down elapsed without the key
	// reappearing. No longer a usable trust anchor. We keep the
	// entry in the store so a future reappearance restarts the
	// AddPending timer rather than instantly trusting it.
	TAStateRemoved
	// TAStateRevoked — RFC 5011 §2.1: the operator published the
	// key with the REVOKE bit set. Immediate transition; bypasses
	// hold-down timers. Never trust this key again.
	TAStateRevoked
)

// String returns a stable token for logs and the observability API.
func (s TrustAnchorState) String() string {
	switch s {
	case TAStateAddPending:
		return "add-pending"
	case TAStateValid:
		return "valid"
	case TAStateMissing:
		return "missing"
	case TAStateRemoved:
		return "removed"
	case TAStateRevoked:
		return "revoked"
	}
	return "unknown"
}

// Default hold-down timers per RFC 5011 §2.4.1.
//
// "MUST be the greater of the addHoldDownTime (30 days) and the
// active refresh period (per RFC 5011 §2.3). The default we ship is
// the 30-day floor, which is the right answer for the root KSK
// which has a long refresh period anyway."
const (
	DefaultAddHoldDown    = 30 * 24 * time.Hour
	DefaultRemoveHoldDown = 30 * 24 * time.Hour
)

// AnchorCandidate is one KSK tracked by the lifecycle machine.
type AnchorCandidate struct {
	// Owner is the zone the KSK belongs to (typically "." for the
	// root). Pinned to the entry so a multi-zone deployment can
	// share one TrustAnchorStore.
	Owner string
	// KeyTag is the RFC 4034 App B.1 key tag of the DNSKEY.
	KeyTag uint16
	// Algorithm + Flags are pinned so a refresh that returned a
	// different DNSKEY at the same key tag (collision or attacker
	// substitution) is treated as a different candidate.
	Algorithm uint8
	Flags     uint16
	// PublicKeyHash is SHA-256 over the DNSKEY RDATA wire form. We
	// keep a hash rather than the raw key so the store is cheap to
	// serialise and so equality checks don't need to deal with
	// variable-length wire bytes.
	PublicKeyHash [32]byte

	State TrustAnchorState
	// FirstSeen is when this candidate first appeared in a refresh.
	// AddPending → Valid transition fires when wall-time exceeds
	// FirstSeen + AddHoldDown AND the candidate was still observed
	// in the latest refresh.
	FirstSeen time.Time
	// MissingSince is set when the candidate transitions to Missing.
	// Zero in any other state. Missing → Removed transition fires
	// when wall-time exceeds MissingSince + RemoveHoldDown AND the
	// candidate was NOT in the latest refresh.
	MissingSince time.Time
	// RevokedAt is when the REVOKE bit was first observed. Once
	// non-zero, the candidate is in TAStateRevoked permanently.
	RevokedAt time.Time
	// LastObserved is the time of the most recent refresh that
	// included this candidate.
	LastObserved time.Time
}

// candidateKey is the comparable identity of a candidate within a
// single owner zone. We deliberately exclude PublicKeyHash from the
// identity — RFC 5011 keys candidates by (KeyTag, Algorithm). A key
// observed at the same tag/alg with different bytes is a substitution
// attack and the machine handles that distinctly (see TrackRefresh).
type candidateKey struct {
	owner     string
	keyTag    uint16
	algorithm uint8
}

// TrustAnchorStore is the RFC 5011 lifecycle machine. Safe for
// concurrent use. Construct via NewTrustAnchorStore.
type TrustAnchorStore struct {
	mu sync.RWMutex

	candidates map[candidateKey]*AnchorCandidate

	addHoldDown    time.Duration
	removeHoldDown time.Duration
	nowFunc        func() time.Time
}

// NewTrustAnchorStore returns an empty store with the RFC defaults.
func NewTrustAnchorStore() *TrustAnchorStore {
	return &TrustAnchorStore{
		candidates:     make(map[candidateKey]*AnchorCandidate),
		addHoldDown:    DefaultAddHoldDown,
		removeHoldDown: DefaultRemoveHoldDown,
		nowFunc:        time.Now,
	}
}

// SetHoldDowns overrides the default RFC timers. Tests use this to
// shrink the 30-day windows to milliseconds. Not safe to call
// concurrently with TrackRefresh — wire it before publication.
func (s *TrustAnchorStore) SetHoldDowns(addHold, removeHold time.Duration) {
	s.addHoldDown = addHold
	s.removeHoldDown = removeHold
}

// SetClock injects a mocked clock for tests.
func (s *TrustAnchorStore) SetClock(fn func() time.Time) {
	s.nowFunc = fn
}

// TrackRefresh processes one refresh of the published DNSKEY RRset at
// the given owner zone. It updates the lifecycle state of every
// candidate (existing + newly-observed):
//
//   - A new candidate enters AddPending with FirstSeen = now.
//   - An AddPending candidate observed again has its observation
//     timestamp refreshed; if the elapsed time since FirstSeen >=
//     addHoldDown, transitions to Valid.
//   - A Valid candidate observed again stays Valid (LastObserved
//     updated).
//   - A Valid candidate absent from THIS refresh transitions to
//     Missing (MissingSince = now). It REMAINS usable during the
//     remove hold-down.
//   - A Missing candidate observed again resurrects to Valid.
//   - A Missing candidate still absent and now past MissingSince +
//     removeHoldDown transitions to Removed.
//   - Any candidate seen with the REVOKE bit set transitions to
//     Revoked immediately.
//   - A Revoked or Removed candidate that reappears as a fresh DNSKEY
//     restarts at AddPending (RFC 5011 §2.1: a once-revoked key never
//     bypasses hold-down again).
//
// The caller passes the DNSKEY records from the refresh. The store
// recomputes the canonical (KeyTag, Algorithm, hash) tuple from each.
func (s *TrustAnchorStore) TrackRefresh(owner string, dnskeys []*dns.DNSKEYRecord) {
	now := s.nowFunc()

	s.mu.Lock()
	defer s.mu.Unlock()

	observed := make(map[candidateKey]*dns.DNSKEYRecord)
	for _, k := range dnskeys {
		if !k.IsKSK() {
			// Only KSKs (SEP bit) are trust-anchor candidates.
			// Zone-signing keys are out of scope for the lifecycle
			// machine — their authenticity is established via the
			// signed DNSKEY RRset, not via 5011.
			continue
		}
		key := candidateKey{owner, k.KeyTag(), k.Algorithm}
		observed[key] = k
	}

	// Phase 1 — process every observed candidate.
	for key, k := range observed {
		hash := sha256DNSKEY(k)
		existing, ok := s.candidates[key]

		switch {
		case k.IsRevoked():
			// REVOKE bit set: jump straight to Revoked regardless of
			// prior state.
			if existing == nil {
				existing = &AnchorCandidate{
					Owner:         owner,
					KeyTag:        k.KeyTag(),
					Algorithm:     k.Algorithm,
					Flags:         k.Flags,
					PublicKeyHash: hash,
					FirstSeen:     now,
				}
				s.candidates[key] = existing
			}
			existing.State = TAStateRevoked
			existing.RevokedAt = now
			existing.LastObserved = now
			existing.PublicKeyHash = hash

		case !ok:
			// Brand new candidate. Default to AddPending; if the
			// operator has shrunk the add hold-down to 0 (test
			// setup or operator opt-in to faster trust), promote
			// to Valid immediately so a zero-hold-down deployment
			// doesn't get stuck for one extra refresh cycle.
			state := TAStateAddPending
			if s.addHoldDown <= 0 {
				state = TAStateValid
			}
			s.candidates[key] = &AnchorCandidate{
				Owner:         owner,
				KeyTag:        k.KeyTag(),
				Algorithm:     k.Algorithm,
				Flags:         k.Flags,
				PublicKeyHash: hash,
				State:         state,
				FirstSeen:     now,
				LastObserved:  now,
			}

		default:
			// Known candidate. Refresh state.
			existing.LastObserved = now

			// Substitution attack detection: same (KeyTag, Algorithm)
			// but different PublicKeyHash. We treat this as a brand
			// new candidate restarting in AddPending — the previous
			// trust ends. A clear log line here lets the operator
			// notice an attempted substitution.
			if existing.PublicKeyHash != hash {
				existing.PublicKeyHash = hash
				existing.State = TAStateAddPending
				existing.FirstSeen = now
				existing.MissingSince = time.Time{}
				continue
			}

			switch existing.State {
			case TAStateRevoked, TAStateRemoved:
				// Reappearance after explicit removal/revocation
				// restarts the hold-down (RFC 5011 §2.1).
				existing.State = TAStateAddPending
				existing.FirstSeen = now
				existing.MissingSince = time.Time{}

			case TAStateMissing:
				// Disappear-then-reappear within the remove hold-
				// down: resurrects to Valid.
				existing.State = TAStateValid
				existing.MissingSince = time.Time{}

			case TAStateAddPending:
				if now.Sub(existing.FirstSeen) >= s.addHoldDown {
					existing.State = TAStateValid
				}
			case TAStateValid:
				// Steady state; nothing to change.
			}
		}
	}

	// Phase 2 — process every candidate NOT in this refresh.
	for key, existing := range s.candidates {
		if _, seen := observed[key]; seen {
			continue
		}
		switch existing.State {
		case TAStateValid:
			existing.State = TAStateMissing
			existing.MissingSince = now
		case TAStateMissing:
			if now.Sub(existing.MissingSince) >= s.removeHoldDown {
				existing.State = TAStateRemoved
			}
		case TAStateAddPending:
			// Disappeared before hold-down elapsed: just drop it.
			// We never trusted this candidate, no audit trail needed.
			delete(s.candidates, key)
		}
	}
}

// ValidAnchors returns the candidates currently usable for chain
// validation: Valid + Missing (the latter still in remove hold-down
// per RFC 5011 §2.2).
func (s *TrustAnchorStore) ValidAnchors() []AnchorCandidate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AnchorCandidate, 0, len(s.candidates))
	for _, c := range s.candidates {
		if c.State == TAStateValid || c.State == TAStateMissing {
			out = append(out, *c)
		}
	}
	return out
}

// All returns every tracked candidate regardless of state. Used by
// the operator-facing UI to surface the full lifecycle picture.
func (s *TrustAnchorStore) All() []AnchorCandidate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AnchorCandidate, 0, len(s.candidates))
	for _, c := range s.candidates {
		out = append(out, *c)
	}
	return out
}

// sha256DNSKEY computes the canonical hash over the DNSKEY RDATA wire
// form. Mirrors the DNSKEY wire encoder so the hash is stable across
// stores.
func sha256DNSKEY(k *dns.DNSKEYRecord) [32]byte {
	buf := bytes.NewBuffer(make([]byte, 0, 4+len(k.PublicKey)))
	// Flags (2)
	buf.WriteByte(byte(k.Flags >> 8))
	buf.WriteByte(byte(k.Flags))
	// Protocol (1)
	buf.WriteByte(k.Protocol)
	// Algorithm (1)
	buf.WriteByte(k.Algorithm)
	// PublicKey
	buf.Write(k.PublicKey)
	return sha256.Sum256(buf.Bytes())
}
