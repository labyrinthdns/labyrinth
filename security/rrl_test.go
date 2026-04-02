package security

import (
	"context"
	"testing"
	"time"
)

func TestRRLAllow(t *testing.T) {
	rrl := NewRRL(5, 2, 24, 56)

	// First 5 responses should be allowed
	for i := 0; i < 5; i++ {
		action := rrl.AllowResponse("192.168.1.1", "example.com", "NOERROR")
		if action != RRLAllow {
			t.Errorf("response %d should be allowed, got %d", i+1, action)
		}
	}
}

func TestRRLDropAndSlip(t *testing.T) {
	rrl := NewRRL(2, 2, 24, 56)

	// Allow first 2
	rrl.AllowResponse("10.0.0.1", "test.com", "NOERROR")
	rrl.AllowResponse("10.0.0.1", "test.com", "NOERROR")

	// 3rd and beyond should be Drop or Slip
	action := rrl.AllowResponse("10.0.0.1", "test.com", "NOERROR")
	if action == RRLAllow {
		t.Error("3rd response should be rate limited")
	}
}

func TestRRLSlipRatio(t *testing.T) {
	rrl := NewRRL(1, 2, 24, 56) // slip every 2nd limited response

	// Allow first one
	rrl.AllowResponse("10.0.0.1", "test.com", "NOERROR")

	// Subsequent should alternate Drop/Slip with slipRatio=2
	var drops, slips int
	for i := 0; i < 10; i++ {
		action := rrl.AllowResponse("10.0.0.1", "test.com", "NOERROR")
		switch action {
		case RRLDrop:
			drops++
		case RRLSlip:
			slips++
		}
	}

	if slips == 0 {
		t.Error("expected at least one slip response")
	}
	if drops == 0 {
		t.Error("expected at least one drop")
	}
}

func TestRRLDifferentSourcesIndependent(t *testing.T) {
	rrl := NewRRL(2, 2, 24, 56)

	// Exhaust rate for source 1
	rrl.AllowResponse("10.0.0.1", "test.com", "NOERROR")
	rrl.AllowResponse("10.0.0.1", "test.com", "NOERROR")

	// Different source should still be allowed
	action := rrl.AllowResponse("10.0.1.1", "test.com", "NOERROR")
	if action != RRLAllow {
		t.Error("different source IP should not be rate limited")
	}
}

func TestRRLSourcePrefix(t *testing.T) {
	rrl := NewRRL(2, 2, 24, 56)

	// Same /24 prefix — should share rate limit
	rrl.AllowResponse("10.0.0.1", "test.com", "NOERROR")
	rrl.AllowResponse("10.0.0.2", "test.com", "NOERROR")

	// 10.0.0.3 is same /24 as 10.0.0.1 — should be limited
	action := rrl.AllowResponse("10.0.0.3", "test.com", "NOERROR")
	if action == RRLAllow {
		t.Error("same /24 source should share rate limit")
	}
}

func TestRRLSourcePrefixIPv6(t *testing.T) {
	// Cover the IPv6 path in sourcePrefix
	rrl := NewRRL(2, 2, 24, 56)

	prefix := rrl.sourcePrefix("2001:db8:abcd:0012::1")
	if prefix == "2001:db8:abcd:0012::1" {
		t.Error("IPv6 should be masked to /56 prefix, not returned as-is")
	}
	if prefix == "" {
		t.Error("sourcePrefix returned empty string for valid IPv6")
	}

	// Two IPs in the same /56 should produce the same prefix
	p1 := rrl.sourcePrefix("2001:db8:abcd:00ff::1")
	p2 := rrl.sourcePrefix("2001:db8:abcd:00ff::2")
	if p1 != p2 {
		t.Errorf("same /56 IPs should have same prefix: %q vs %q", p1, p2)
	}

	// Two IPs in different /56 blocks should produce different prefixes
	p3 := rrl.sourcePrefix("2001:db8:abcd:0100::1")
	if p1 == p3 {
		t.Errorf("different /56 IPs should have different prefix: %q vs %q", p1, p3)
	}
}

func TestRRLSourcePrefixInvalid(t *testing.T) {
	// Cover the ip == nil path in sourcePrefix
	rrl := NewRRL(2, 2, 24, 56)

	prefix := rrl.sourcePrefix("not-an-ip")
	if prefix != "not-an-ip" {
		t.Errorf("invalid IP should be returned as-is, got %q", prefix)
	}
}

func TestRRLStartCleanup(t *testing.T) {
	// Cover StartCleanup including the ticker.C body that removes stale entries
	rrl := NewRRL(5, 2, 24, 56)
	rrl.cleanupInterval = 100 * time.Millisecond // short interval for testing

	// Add a stale entry with lastTime far in the past (well beyond cleanup interval)
	rrl.mu.Lock()
	rrl.entries["stale|test.com|NOERROR"] = &rrlEntry{
		tokens:   5,
		lastTime: time.Now().Add(-10 * time.Minute),
	}
	rrl.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rrl.StartCleanup(ctx)
		close(done)
	}()

	// Wait for at least one cleanup tick
	time.Sleep(300 * time.Millisecond)

	rrl.mu.Lock()
	count := len(rrl.entries)
	rrl.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 entries after cleanup (stale removed), got %d", count)
	}

	cancel()

	select {
	case <-done:
		// OK - cleanup goroutine exited
	case <-time.After(2 * time.Second):
		t.Error("StartCleanup did not stop after context cancel")
	}
}

func TestRRLTokenCap(t *testing.T) {
	// Cover the entry.tokens > r.responsesPerSecond cap branch in AllowResponse
	rrl := NewRRL(1000, 2, 24, 56) // high rate so tokens refill quickly

	rrl.AllowResponse("10.0.0.1", "test.com", "NOERROR") // create entry

	// Wait so tokens refill well beyond responsesPerSecond
	time.Sleep(100 * time.Millisecond)

	// This call triggers the cap (tokens > responsesPerSecond -> cap)
	action := rrl.AllowResponse("10.0.0.1", "test.com", "NOERROR")
	if action != RRLAllow {
		t.Errorf("should be allowed after token refill, got %d", action)
	}
}

func TestRRLStartCleanupContextCancel(t *testing.T) {
	// Cover the ctx.Done() path of StartCleanup
	rrl := NewRRL(5, 2, 24, 56)
	rrl.cleanupInterval = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rrl.StartCleanup(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("StartCleanup did not stop after context cancel")
	}
}

func TestRRLStartCleanupDefaultInterval(t *testing.T) {
	// Cover the interval <= 0 fallback to 5 * time.Minute
	rrl := NewRRL(5, 2, 24, 56)
	rrl.cleanupInterval = 0 // triggers the default fallback

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rrl.StartCleanup(ctx)
		close(done)
	}()

	// Cancel immediately — we just need the function to start and hit the fallback
	cancel()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("StartCleanup did not stop after context cancel")
	}
}
