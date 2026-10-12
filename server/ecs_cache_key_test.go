package server

import (
	"net"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestChooseCacheECSKey_MatchesLookupKey pins the invariant that the cache
// STORE key and the cache LOOKUP key are the same string, for every scope an
// authoritative server may legally return.
//
// The lookup path in Handle can only know the client's SOURCE prefix — it
// runs before any upstream reply exists — so it keys on
// outboundECS.CacheKey(). If chooseCacheECSKey instead derived the key from
// the echoed SCOPE prefix, the two would disagree whenever the
// authoritative narrowed the scope below the source prefix we sent. RFC 7871
// §7.2.1 explicitly permits scope <= source (a client asking /24 that gets a
// /16 answer is the ordinary "this answer is not client-specific" shape), and
// the resulting entry was stored under an unreachable key: a permanent cache
// miss that also re-resolved the same names upstream forever.
//
// The echoed scope must still reach the client, so ECSScope is asserted
// alongside the key.
func TestChooseCacheECSKey_MatchesLookupKey(t *testing.T) {
	tests := []struct {
		name     string
		family   uint16
		src      uint8
		scope    uint8
		addr     string
		wantKey  string
		wantGlob bool
	}{
		{
			name:   "upstream echoes the source prefix",
			family: 1, src: 24, scope: 24, addr: "1.2.3.4",
			wantKey: "1.2.3.0/24",
		},
		{
			// The regression: scope narrower than source.
			name:   "upstream narrows scope below source",
			family: 1, src: 24, scope: 16, addr: "1.2.3.4",
			wantKey: "1.2.3.0/24",
		},
		{
			// RFC 7871 §7.2.1 requires scope <= source, so a /32 scope for a
			// /24 query is out of spec. The key must still agree with the
			// lookup so a misbehaving upstream cannot orphan the entry.
			name:   "out-of-spec scope above source still agrees",
			family: 1, src: 24, scope: 32, addr: "1.2.3.4",
			wantKey: "1.2.3.0/24",
		},
		{
			name:   "IPv6 narrows scope below source",
			family: 2, src: 56, scope: 48, addr: "2001:db8::1",
			wantKey: "2001:db8::/56",
		},
		{
			// scope=0 routes to the shared global entry, which Handle finds via
			// cache.Lookup — not via the GetWithECS fallback — so the
			// store/lookup string invariant does not apply; "" is what matters.
			name:   "scope zero caches globally",
			family: 1, src: 24, scope: 0, addr: "1.2.3.4",
			wantKey:  "",
			wantGlob: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.addr)
			if tt.family == 1 {
				ip = ip.To4()
			} else {
				ip = ip.To16()
			}
			outbound := &dns.ECSOption{
				Family: tt.family, SourcePrefixLen: tt.src,
				ScopePrefixLen: 0, Address: ip,
			}
			// What the authoritative echoed back (RFC 7871 §7.2.1).
			upstream := &dns.ECSOption{
				Family: tt.family, SourcePrefixLen: tt.src,
				ScopePrefixLen: tt.scope, Address: ip,
			}

			storeKey := chooseCacheECSKey(outbound, upstream)
			lookupKey := outbound.CacheKey()

			if storeKey != tt.wantKey {
				t.Errorf("store key = %q, want %q", storeKey, tt.wantKey)
			}
			if tt.wantGlob {
				// Global entries are written and found under the "" key, which
				// Handle reaches through cache.Lookup, not the ECS fallback.
				// The store/lookup string invariant is scoped to real ECS keys.
				if storeKey != "" {
					t.Errorf("scope=0 must cache globally, got key %q", storeKey)
				}
				return
			}
			// The invariant under test: a scoped entry is only reachable if the
			// string it was stored under is the string a lookup will ask for.
			if storeKey != lookupKey {
				t.Errorf("store key %q != lookup key %q: entry would be unreachable", storeKey, lookupKey)
			}
		})
	}
}

// TestChooseCacheECSKey_NoOutboundOrUpstream covers the two nil/zero guards
// that route to the shared global cache entry.
func TestChooseCacheECSKey_NoOutboundOrUpstream(t *testing.T) {
	addr := net.ParseIP("1.2.3.4").To4()

	if got := chooseCacheECSKey(nil, &dns.ECSOption{Family: 1, SourcePrefixLen: 24, ScopePrefixLen: 24, Address: addr}); got != "" {
		t.Errorf("nil outbound must cache globally, got %q", got)
	}
	outbound := &dns.ECSOption{Family: 1, SourcePrefixLen: 24, Address: addr}
	if got := chooseCacheECSKey(outbound, nil); got != "" {
		t.Errorf("nil upstream (ECS-unaware) must cache globally, got %q", got)
	}
}
