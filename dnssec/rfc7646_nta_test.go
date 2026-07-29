package dnssec

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestNTAStore_Match_SubtreeAndSiblings pins RFC 7646's matching
// semantics: an NTA at zone X covers X itself and every descendant
// of X, but NEVER a sibling. A sloppy implementation that did string
// substring matching (instead of label-suffix walking) would let an
// NTA at `example.test` accidentally hide `evil-example.test` —
// which is not a descendant and must continue to validate normally.
func TestNTAStore_Match_SubtreeAndSiblings(t *testing.T) {
	store := NewNTAStore()
	expiry := time.Now().Add(1 * time.Hour)
	store.Add("example.test", expiry, "broken DNSSEC during incident")

	cases := []struct {
		qname     string
		wantMatch bool
		why       string
	}{
		{"example.test.", true, "the NTA zone itself"},
		{"foo.example.test.", true, "direct child"},
		{"bar.foo.example.test.", true, "grand-descendant"},
		{"EVIL.EXAMPLE.TEST.", true, "case-insensitive match (DNS names are case-insensitive)"},
		{"other.test.", false, "sibling zone — must NOT be covered"},
		{"evil-example.test.", false, "string-substring trap — `evil-example.test` shares letters but is a different label, must NOT match"},
		{"test.", false, "parent zone — NTA only covers descendants, not ancestors"},
		{"example.com.", false, "unrelated zone"},
		{".", false, "the root — never accidentally covered"},
	}

	for _, c := range cases {
		t.Run(c.qname, func(t *testing.T) {
			_, got := store.Match(c.qname)
			if got != c.wantMatch {
				t.Errorf("Match(%q) = %v, want %v — %s", c.qname, got, c.wantMatch, c.why)
			}
		})
	}
}

// TestNTAStore_Match_Expiry pins RFC 7646 §6: an NTA past its expiry
// MUST behave as if removed. The store must not eagerly accept a stale
// override just because the operator forgot to remove it — the bounded
// lifetime is the entire safety story of the mechanism.
func TestNTAStore_Match_Expiry(t *testing.T) {
	store := NewNTAStore()
	fakeNow := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return fakeNow })

	store.Add("example.test", fakeNow.Add(1*time.Hour), "scheduled")

	// At t=now: NTA is active.
	if _, ok := store.Match("example.test."); !ok {
		t.Errorf("active NTA did not match at t=now — store rejected a future-expiry entry")
	}

	// Advance past expiry.
	fakeNow = fakeNow.Add(2 * time.Hour)
	if _, ok := store.Match("example.test."); ok {
		t.Errorf("expired NTA still matched — RFC 7646 §6 violation (NTAs MUST NOT be open-ended)")
	}
}

// TestNTAStore_Add_RejectsPastExpiry pins the safety guard: adding an
// NTA whose expiry is already in the past is silently ignored, so a
// misconfigured operator script can't accidentally install a permanent
// override by mistyping the timestamp.
func TestNTAStore_Add_RejectsPastExpiry(t *testing.T) {
	store := NewNTAStore()
	past := time.Now().Add(-1 * time.Hour)
	store.Add("example.test", past, "operator typo")

	if _, ok := store.Match("example.test."); ok {
		t.Errorf("NTA with already-past expiry was accepted — would create de facto permanent override")
	}
	if got := len(store.List()); got != 0 {
		t.Errorf("List() size = %d, want 0 — rejected NTA must not pollute the store", got)
	}
}

// TestNTAStore_Cleanup pins the cleanup contract: expired entries are
// reclaimed without disturbing active ones. UI-side display may want
// to show "recently-expired" too, but the in-memory store is the hot
// path and should not bloat.
func TestNTAStore_Cleanup(t *testing.T) {
	store := NewNTAStore()
	fakeNow := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return fakeNow })

	store.Add("active.test", fakeNow.Add(1*time.Hour), "active")
	store.Add("soon.test", fakeNow.Add(30*time.Minute), "active short-window")

	// Advance to a time where soon.test has expired but active.test is still live.
	fakeNow = fakeNow.Add(45 * time.Minute)

	removed := store.Cleanup()
	if removed != 1 {
		t.Errorf("Cleanup() removed %d, want 1 (only soon.test should be reaped)", removed)
	}
	if _, ok := store.Match("active.test."); !ok {
		t.Errorf("Cleanup reaped the still-active NTA — cleanup must be strictly past-expiry-only")
	}
}

// TestValidateResponse_NTAOverridesBogus pins the integration: when an
// NTA covers the qname, the validator returns Insecure with
// ReasonNTAOverride EVEN IF the response would otherwise be Bogus
// (e.g. forged signature, expired RRSIG, missing DNSKEY). The whole
// point of an NTA is operator-controlled override of a broken chain;
// a validator that still emitted Bogus would defeat it.
//
// We use a response with no RRSIG at all — without NTA the verdict
// would be Insecure already, so we lean on the *reason* code to prove
// the NTA path fired. ReasonNone (no NTA) vs ReasonNTAOverride (NTA
// applied) is the discriminator the metrics/EDE layer cares about.
func TestValidateResponse_NTAOverridesBogus(t *testing.T) {
	mq := &mockQuerier{responses: make(map[string]*dns.Message)}
	v := NewValidator(mq, nil)

	// Without an NTA, an unsigned answer returns Insecure with ReasonNone.
	resp := &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "broken.example.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
		},
	}
	verdict, reason := v.ValidateResponseWithReason(resp, "broken.example.", dns.TypeA)
	if verdict != Insecure {
		t.Fatalf("baseline: verdict = %v, want Insecure", verdict)
	}
	if reason == ReasonNTAOverride {
		t.Fatalf("baseline: reason = NTAOverride, want NOT-NTA (no store wired yet)")
	}

	// Install NTA. The exact same response now must come back tagged
	// ReasonNTAOverride so callers (EDE emitter, metrics, log) can
	// distinguish "we suppressed" from "happened to be Insecure anyway".
	store := NewNTAStore()
	store.Add("example", time.Now().Add(1*time.Hour), "incident response")
	v.SetNTAStore(store)

	verdict, reason = v.ValidateResponseWithReason(resp, "broken.example.", dns.TypeA)
	if verdict != Insecure {
		t.Errorf("with NTA: verdict = %v, want Insecure", verdict)
	}
	if reason != ReasonNTAOverride {
		t.Errorf("with NTA: reason = %v, want ReasonNTAOverride — without this tag the operator cannot tell the validator stopped vs. the zone was unsigned", reason)
	}
	if got := v.NTAMatches(); got != 1 {
		t.Errorf("NTAMatches() = %d, want 1 (one validation was overridden)", got)
	}

	// Sibling zone outside NTA scope: behavior reverts to baseline.
	sibResp := &dns.Message{
		Answers: []dns.ResourceRecord{
			{Name: "other.zone.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
		},
	}
	_, reason = v.ValidateResponseWithReason(sibResp, "other.zone.", dns.TypeA)
	if reason == ReasonNTAOverride {
		t.Errorf("sibling zone tagged NTAOverride — NTA matched outside its subtree (RFC 7646 §1 scope violation)")
	}
	if got := v.NTAMatches(); got != 1 {
		t.Errorf("NTAMatches() = %d, want 1 still (sibling did not trigger NTA path)", got)
	}
}

// TestFailureReason_NTAOverride_RoundTrips pins the string ↔ enum
// roundtrip for ReasonNTAOverride. The EDE layer serialises the
// reason as a string and clients deserialise it back; a typo here
// would silently drop the NTA signal at the network boundary.
func TestFailureReason_NTAOverride_RoundTrips(t *testing.T) {
	const want = "nta-override"
	if got := ReasonNTAOverride.String(); got != want {
		t.Errorf("ReasonNTAOverride.String() = %q, want %q", got, want)
	}
	if got := FailureReasonFromString(want); got != ReasonNTAOverride {
		t.Errorf("FailureReasonFromString(%q) = %v, want ReasonNTAOverride", want, got)
	}
}
