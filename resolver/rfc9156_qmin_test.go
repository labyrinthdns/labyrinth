package resolver

import (
	"log/slog"
	"os"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestMinimizeQName_RFC9156Invariants pins the four behavioural
// invariants of QNAME minimisation that materially affect security and
// chain-of-trust correctness:
//
//  1. Root-zone qname ("") never rewritten — keep the original qtype.
//     Otherwise the root DNSKEY walk turns into a root-NS query and
//     every DNSSEC validation downstream breaks (RFC 9156 §3 implicit:
//     the root has no parent to minimise toward).
//  2. TypeDS never minimised — DS lives at the parent zone, qmin's
//     rewrite-to-NS would step one delegation too far and land at the
//     child auth which has no DS for itself (RFC 9156 §4.1).
//  3. At root (currentZone=""), the minimised query is TLD-only with
//     TypeNS — the §3 "one extra label per iteration" rule.
//  4. With one label remaining inside currentZone, the resolver MUST
//     ask the FULL qtype (the final query is not rewritten to NS).
//
// A regression on any of these breaks something silently: #1 and #2
// break DNSSEC for every query through the resolver; #3 leaks too much
// of the QNAME to the root servers (the whole privacy point of RFC
// 9156); #4 turns every leaf query into an unanswerable NS lookup.
func TestMinimizeQName_RFC9156Invariants(t *testing.T) {
	r := newQMinTestResolver(t)

	cases := []struct {
		name        string
		fullName    string
		qtype       uint16
		currentZone string
		wantQName   string
		wantQType   uint16
		rationale   string
	}{
		{
			name:        "root-qname stays root",
			fullName:    "",
			qtype:       dns.TypeDNSKEY,
			currentZone: "",
			wantQName:   "",
			wantQType:   dns.TypeDNSKEY,
			rationale:   "RFC 9156 §3 — root has no parent to minimise toward; rewriting kills the root DNSKEY walk",
		},
		{
			name:        "DS query never minimised",
			fullName:    "www.example.com",
			qtype:       dns.TypeDS,
			currentZone: "com",
			wantQName:   "www.example.com",
			wantQType:   dns.TypeDS,
			rationale:   "RFC 9156 §4.1 — DS lives at parent; qmin would land at the child auth which has no DS for itself",
		},
		{
			name:        "at root → TLD-only NS query",
			fullName:    "www.example.com",
			qtype:       dns.TypeA,
			currentZone: "",
			wantQName:   "com",
			wantQType:   dns.TypeNS,
			rationale:   "RFC 9156 §3 — one extra label per iteration; root servers see only the TLD",
		},
		{
			name:        "one-label-remaining: full qtype, not NS",
			fullName:    "www.example.com",
			qtype:       dns.TypeAAAA,
			currentZone: "example.com",
			wantQName:   "www.example.com",
			wantQType:   dns.TypeAAAA,
			rationale:   "RFC 9156 §3 — final leaf query uses the real qtype, never collapses to NS",
		},
		{
			name:        "intermediate: peel one more label, rewrite to NS",
			fullName:    "deep.path.example.com",
			qtype:       dns.TypeA,
			currentZone: "com",
			wantQName:   "example.com",
			wantQType:   dns.TypeNS,
			rationale:   "RFC 9156 §3 — one-label-at-a-time peel; intermediate hops use NS as the probe",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotName, gotType := r.minimizeQName(c.fullName, c.qtype, c.currentZone)
			if gotName != c.wantQName {
				t.Errorf("qname = %q, want %q\nrationale: %s", gotName, c.wantQName, c.rationale)
			}
			if gotType != c.wantQType {
				t.Errorf("qtype = %d, want %d\nrationale: %s", gotType, c.wantQType, c.rationale)
			}
		})
	}
}

// newQMinTestResolver builds a minimal Resolver whose only dependency
// is on the receiver method (minimizeQName has no field reads beyond
// the receiver type), so we don't need mocks or a running upstream.
func newQMinTestResolver(t *testing.T) *Resolver {
	t.Helper()
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewResolver(c, ResolverConfig{
		MaxDepth:      10,
		MaxCNAMEDepth: 5,
		QMinEnabled:   true,
		PreferIPv4:    true,
	}, m, logger)
}
