package resolver

import (
	"testing"
	"time"
)

// TestServerCookieCache_PutThenGetRoundTrip pins the Y25 happy path:
// after Put, a Get for the same IP returns a copy of the cookie that
// equals the stored bytes. RFC 7873 §5.3 motivates this cache —
// without it, every cold query to a cookie-enforcing auth pays a
// BADCOOKIE round-trip even after we already learned the cookie.
func TestServerCookieCache_PutThenGetRoundTrip(t *testing.T) {
	c := newServerCookieCache(8, time.Hour)
	c.Put("198.51.100.7", []byte{1, 2, 3, 4, 5, 6, 7, 8})
	got := c.Get("198.51.100.7")
	if len(got) != 8 {
		t.Fatalf("cookie length = %d, want 8", len(got))
	}
	for i, b := range []byte{1, 2, 3, 4, 5, 6, 7, 8} {
		if got[i] != b {
			t.Errorf("byte %d = %#x, want %#x", i, got[i], b)
		}
	}
}

// TestServerCookieCache_GetReturnsCopyNotAlias prevents a class of
// subtle bugs: if Get returned the underlying slice directly, a
// caller mutating the result (or appending past its cap) would
// silently corrupt every future lookup for the same IP. The cache
// must hand out a defensive copy.
func TestServerCookieCache_GetReturnsCopyNotAlias(t *testing.T) {
	c := newServerCookieCache(8, time.Hour)
	original := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	c.Put("203.0.113.1", original)

	first := c.Get("203.0.113.1")
	first[0] = 0xff // mutate caller's copy

	second := c.Get("203.0.113.1")
	if second[0] != 1 {
		t.Errorf("cached cookie mutated by caller: byte 0 = %#x, want 1", second[0])
	}
}

// TestServerCookieCache_EvictsOldestWhenFull pins the bounded-growth
// invariant: a resolver hammering thousands of distinct auths must
// not grow its cookie cache unboundedly. We use a tiny capacity and
// verify the oldest entry by seenAt is the one dropped.
func TestServerCookieCache_EvictsOldestWhenFull(t *testing.T) {
	c := newServerCookieCache(2, time.Hour)
	c.Put("a", []byte("AAAAAAAA"))
	time.Sleep(2 * time.Millisecond)
	c.Put("b", []byte("BBBBBBBB"))
	time.Sleep(2 * time.Millisecond)
	c.Put("c", []byte("CCCCCCCC")) // should evict "a"

	if c.Get("a") != nil {
		t.Error("oldest entry 'a' should have been evicted")
	}
	if c.Get("b") == nil || c.Get("c") == nil {
		t.Error("'b' and 'c' should still be present")
	}
	if got := c.Len(); got != 2 {
		t.Errorf("cache size = %d, want 2", got)
	}
}

// TestServerCookieCache_ExpiredEntryEvictedOnLookup pins the TTL
// guard — RFC 9018 §4.3 sets one hour as the cookie validity window,
// so we MUST treat older entries as gone. Otherwise a server-secret
// rotation upstream silently breaks every cached cookie.
func TestServerCookieCache_ExpiredEntryEvictedOnLookup(t *testing.T) {
	c := newServerCookieCache(8, 1*time.Millisecond)
	c.Put("198.51.100.99", []byte("ABCDEFGH"))
	time.Sleep(5 * time.Millisecond)
	if got := c.Get("198.51.100.99"); got != nil {
		t.Errorf("expired entry must return nil, got %v", got)
	}
}

// TestServerCookieCache_DisabledByZeroCapacity: capacity <= 0 means
// the operator opted out (or the resolver was constructed with the
// cookie cache disabled). Put is a no-op, Get always misses, Len
// stays at zero — no allocations on the hot path.
func TestServerCookieCache_DisabledByZeroCapacity(t *testing.T) {
	c := newServerCookieCache(0, time.Hour)
	c.Put("any", []byte("12345678"))
	if c.Get("any") != nil {
		t.Error("disabled cache must miss")
	}
	if c.Len() != 0 {
		t.Errorf("disabled cache length = %d, want 0", c.Len())
	}
}

// TestServerCookieCache_NilReceiverSafe: a Resolver constructed in a
// minimal test path may have a nil cache. The methods must be
// nil-safe so we do not have to scatter nil checks at call sites.
func TestServerCookieCache_NilReceiverSafe(t *testing.T) {
	var c *serverCookieCache
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil cache must not panic: %v", r)
		}
	}()
	c.Put("any", []byte("12345678"))
	if got := c.Get("any"); got != nil {
		t.Error("nil cache must miss")
	}
}
