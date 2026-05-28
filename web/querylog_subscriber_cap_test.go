package web

import (
	"testing"
)

// TestQueryLog_SubscribeCapEnforced pins the v0.8.12 gate: the
// fan-out subscribers map must refuse new subscribers past
// MaxQueryLogSubscribers rather than growing without bound. The
// /api/queries/stream endpoint is behind requireAuth, but a buggy
// dashboard or an authenticated attacker that loops open-and-leak
// WebSocket connections could pile up subscribers and pin memory
// (each entry is a buffered chan QueryEntry of ~10 KiB).
//
// The pin opens MaxQueryLogSubscribers subscriptions, then asserts:
//   - subscription # cap+1 returns id=0 and an already-closed channel,
//   - the underlying map size does NOT grow past the cap,
//   - the closed channel makes the would-be caller's read loop exit
//     immediately (read from closed channel returns zero value + ok=false).
func TestQueryLog_SubscribeCapEnforced(t *testing.T) {
	ql := NewQueryLog(100)

	// Fill to the cap.
	ids := make([]uint64, 0, MaxQueryLogSubscribers)
	for i := 0; i < MaxQueryLogSubscribers; i++ {
		id, _ := ql.Subscribe()
		if id == 0 {
			t.Fatalf("Subscribe #%d returned id=0 before cap reached", i)
		}
		ids = append(ids, id)
	}

	// One over the cap → id=0 + closed channel.
	id, ch := ql.Subscribe()
	if id != 0 {
		t.Errorf("Subscribe past cap returned id=%d, want 0", id)
	}
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("over-cap subscriber received a value; expected channel to be closed")
		}
	default:
		t.Error("over-cap subscriber channel is not closed — read would block")
	}

	// Map size never grew past the cap.
	ql.subMu.Lock()
	got := len(ql.subs)
	ql.subMu.Unlock()
	if got != MaxQueryLogSubscribers {
		t.Errorf("len(ql.subs) = %d, want %d", got, MaxQueryLogSubscribers)
	}

	// Cleanup: unsubscribe everyone.
	for _, id := range ids {
		ql.Unsubscribe(id)
	}
	ql.Unsubscribe(0) // sentinel must be a no-op (does not panic)
}

// TestQueryLog_SubscribeCapConstantStable pins the constant against
// regressions that would either reopen the unbounded-fanout gap or
// drop it to a thrash-level value that would deny legitimate dashboards.
func TestQueryLog_SubscribeCapConstantStable(t *testing.T) {
	if MaxQueryLogSubscribers < 8 {
		t.Fatalf("MaxQueryLogSubscribers = %d denies legitimate dashboards", MaxQueryLogSubscribers)
	}
	if MaxQueryLogSubscribers > 1<<20 {
		t.Fatalf("MaxQueryLogSubscribers = %d reopens the unbounded-fanout gap", MaxQueryLogSubscribers)
	}
}
