package web

import (
	"testing"
)

// TestNewQueryLog_CapsOversizedCapacity pins the v0.7.69 gate:
// NewQueryLog must clamp `capacity` to MaxQueryLogCapacity. Without
// the clamp, a typo in YAML (`web.query_log_buffer: 1000000000`
// instead of `1000000`) or a hostile config-raw PUT that planted a
// gigabyte-scale value would `make([]QueryEntry, 1e9)` upfront and
// instant-OOM the resolver at startup. QueryEntry is ~80 bytes per
// entry, so 1B entries = 80 GB allocation.
//
// The pin requests a 10×-over-cap capacity and asserts the resulting
// ring buffer is exactly MaxQueryLogCapacity entries — the clamp
// must trim oversized requests rather than fail-stop the resolver.
func TestNewQueryLog_CapsOversizedCapacity(t *testing.T) {
	const requested = MaxQueryLogCapacity * 10
	ql := NewQueryLog(requested)

	if got := ql.capacity; got != MaxQueryLogCapacity {
		t.Errorf("capacity = %d, want %d (clamp to MaxQueryLogCapacity)", got, MaxQueryLogCapacity)
	}
	if got := len(ql.entries); got != MaxQueryLogCapacity {
		t.Errorf("len(entries) = %d, want %d", got, MaxQueryLogCapacity)
	}
}

// TestNewQueryLog_HonoursNonNegativeUnderCap pins that requests
// below the cap are honoured unchanged. The clamp must not lower
// reasonable operator values; it only protects against the OOM
// pathology at the very top end.
func TestNewQueryLog_HonoursNonNegativeUnderCap(t *testing.T) {
	cases := []int{1, 100, 10000, 500_000, MaxQueryLogCapacity}
	for _, c := range cases {
		ql := NewQueryLog(c)
		if ql.capacity != c {
			t.Errorf("NewQueryLog(%d).capacity = %d, want %d", c, ql.capacity, c)
		}
		if len(ql.entries) != c {
			t.Errorf("NewQueryLog(%d) len(entries) = %d, want %d", c, len(ql.entries), c)
		}
	}
}

// TestNewQueryLog_NonPositiveFallsBackToDefault pins the existing
// fallback behaviour for zero / negative capacities (default = 1000).
// The new cap logic must not break this branch.
func TestNewQueryLog_NonPositiveFallsBackToDefault(t *testing.T) {
	for _, c := range []int{0, -1, -1000} {
		ql := NewQueryLog(c)
		if ql.capacity != 1000 {
			t.Errorf("NewQueryLog(%d).capacity = %d, want 1000", c, ql.capacity)
		}
	}
}

// TestMaxQueryLogCapacityIsSane is a tripwire on the constant.
func TestMaxQueryLogCapacityIsSane(t *testing.T) {
	if MaxQueryLogCapacity < 10000 {
		t.Errorf("MaxQueryLogCapacity = %d, too small — busy resolver fills the buffer in seconds", MaxQueryLogCapacity)
	}
	if MaxQueryLogCapacity > 100_000_000 {
		t.Errorf("MaxQueryLogCapacity = %d, too large — defeats OOM protection (per-entry ~80 bytes)", MaxQueryLogCapacity)
	}
}
