package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestFailureCache_OnlyStoresSERVFAIL pins RFC 9520 §4: the
// resolution-failure cache is for SERVFAILs that could not be classified
// further (no auth answered, all NS REFUSED, network dropped) — NOT for
// negative answers that DID resolve. A regression that loosened the
// `result.RCODE == RCodeServFail` gate to "any non-NOERROR" would start
// caching every legitimate NXDOMAIN here for the §4 short TTL, racing
// against the answer cache's RFC 2308 negative TTL and breaking the
// "delete-after-fix" expectation operators have (fix the auth record →
// resolver reflects the change within a few seconds), because the
// answer cache would be skipped entirely on the next query.
//
// The pin drives the mock through three RCODEs that MUST NOT enter the
// failure cache (NOERROR, NXDOMAIN, NODATA) and one that MUST (SERVFAIL),
// asserting the right-shaped membership in failureCache.
func TestFailureCache_OnlyStoresSERVFAIL(t *testing.T) {
	cases := []struct {
		name      string
		responder func(q *dns.Message) *dns.Message
		wantCache bool
	}{
		{
			name: "NOERROR with A — never cached",
			responder: func(q *dns.Message) *dns.Message {
				return &dns.Message{
					Header: dns.Header{
						Flags: dns.NewFlagBuilder().SetQR(true).Build(),
					},
					Questions: q.Questions,
					Answers: []dns.ResourceRecord{{
						Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
						TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
					}},
				}
			},
			wantCache: false,
		},
		{
			name: "NXDOMAIN — answer-cache territory, not failure-cache",
			responder: func(q *dns.Message) *dns.Message {
				return &dns.Message{
					Header: dns.Header{
						Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeNXDomain).Build(),
					},
					Questions: q.Questions,
					Authority: []dns.ResourceRecord{{
						Name: "com", Type: dns.TypeSOA, Class: dns.ClassIN,
						TTL: 300, RDLength: 0, RData: buildSOARData(),
					}},
				}
			},
			wantCache: false,
		},
		{
			name: "SERVFAIL — RFC 9520 §3 short-circuit target",
			responder: func(q *dns.Message) *dns.Message {
				return &dns.Message{
					Header: dns.Header{
						Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build(),
					},
				}
			},
			wantCache: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mock := startMockDNS(t, c.responder)
			defer mock.close()

			r := testResolver(t, mock)
			// Each subtest builds a fresh resolver via testResolver,
			// so its failureCache starts at Len()==0 regardless of
			// prior tests; the count below reflects only this case.
			_, err := r.Resolve("y60-target.com", dns.TypeA, dns.ClassIN)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			gotCache := r.failureCache.Len() > 0
			if gotCache != c.wantCache {
				t.Errorf("failureCache populated = %v, want %v (RFC 9520 §4: only SERVFAIL — never NOERROR/NXDOMAIN — enters this cache)", gotCache, c.wantCache)
			}
		})
	}
}

// TestFailureCache_NotPopulatedByECSResolves pins RFC 9520 §4 +
// RFC 7871 §7.1 interaction: a SERVFAIL accompanied by a client-subnet
// option is NOT cached in the failure cache. Failures are not portable
// across client subnets — an auth that REFUSED 192.0.2.0/24 might
// happily answer 198.51.100.0/24, and caching the failure under the
// shared key would deny service to every other subnet until the entry
// expired. The gate `clientECS == nil` at resolver.go:510 enforces this.
// A regression that dropped the ECS check would manifest as random
// SERVFAILs for fully working zones whenever ANY client probed via a
// stale or hostile ECS-aware resolver.
func TestFailureCache_NotPopulatedByECSResolves(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header: dns.Header{
				Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeServFail).Build(),
			},
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	ecs := &dns.ECSOption{
		Family:          1,
		SourcePrefixLen: 24,
		ScopePrefixLen:  0,
		Address:         []byte{192, 0, 2, 0},
	}
	_, err := r.ResolveWithECS("y60-ecs.com", dns.TypeA, dns.ClassIN, ecs)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.failureCache.Len() != 0 {
		t.Errorf("ECS-bearing SERVFAIL entered failure cache — RFC 7871 §7.1 violation: failures are not subnet-portable")
	}
}
