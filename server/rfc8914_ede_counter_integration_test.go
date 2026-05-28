package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/security"
)

// TestEDECounter_IntegratedAtACLRefusal pins M4.6 + UI-M6.3 at the
// integration layer: when an ACL-deny path emits EDE 18 (Prohibited),
// the per-code emission counter in metrics MUST go up by exactly one.
// A regression that dropped the IncEDE call from buildErrorWithEDE
// would leave the unit test in metrics/ green while breaking the
// observability surface the Security page reads from.
//
// Two assertions, both important:
//   - Counter goes up exactly once per emission (not zero, not twice).
//   - Other EDE codes stay at zero — the regression class where one
//     code's increment leaks into a sibling counter would surface here.
func TestEDECounter_IntegratedAtACLRefusal(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	res := newTestResolver(c, m)
	acl, err := security.NewACL([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewMainHandler(res, c, nil, nil, acl, m, discardLogger())

	denied := &mockAddr{network: "udp", addr: "192.168.1.1:12345"}
	q := buildTestQueryWithEDNS("aclblock.test", dns.TypeA, 1232)

	// Baseline.
	baseline := m.EDECounts()
	if baseline[dns.EDECodeProhibited] != 0 {
		t.Fatalf("test setup contaminated: EDE 18 = %d before any handle", baseline[dns.EDECodeProhibited])
	}

	// One refusal.
	if _, err := h.Handle(q, denied); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	after := m.EDECounts()
	if got := after[dns.EDECodeProhibited]; got != 1 {
		t.Errorf("EDE %d (Prohibited) count = %d after 1 refusal, want 1", dns.EDECodeProhibited, got)
	}

	// Negative control: no leakage into other codes.
	for code, n := range after {
		if code == dns.EDECodeProhibited {
			continue
		}
		if n != 0 {
			t.Errorf("EDE %d count leaked to %d, want 0 (cross-counter contamination)", code, n)
		}
	}

	// Idempotence: a second refusal increments by exactly 1 more (not
	// zero — which would mean the call site is gated incorrectly; not
	// 2+ — which would mean the call is duplicated somewhere).
	if _, err := h.Handle(q, denied); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	after2 := m.EDECounts()
	if got := after2[dns.EDECodeProhibited]; got != 2 {
		t.Errorf("EDE %d count = %d after 2 refusals, want 2", dns.EDECodeProhibited, got)
	}
}
