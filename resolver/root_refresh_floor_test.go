package resolver

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// TestStartRootRefresh_ZeroIntervalDoesNotPanic pins the v0.8.11 gate:
// time.NewTicker(0) panics with "non-positive interval for NewTicker".
// StartRootRefresh, launched from main.go on a background goroutine
// when DNSSEC is enabled, would panic-and-die silently — the resolver
// kept resolving with whatever root hints it had at startup, never
// re-priming, and stale hints would only surface as resolution
// failures months later when an IANA root server moved.
//
// The pin fires the panic-prone path with interval=0 and asserts the
// goroutine exits cleanly via context cancellation, not via panic.
func TestStartRootRefresh_ZeroIntervalDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("StartRootRefresh panicked with zero interval: %v — MinRootRefreshInterval floor not applied", r)
		}
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := &Resolver{logger: logger}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		r.StartRootRefresh(ctx, 0)
		close(done)
	}()

	select {
	case <-done:
		// Goroutine exited cleanly via ctx cancellation — what we want.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("StartRootRefresh goroutine did not exit after ctx cancellation")
	}
}

// TestStartRootRefresh_NegativeIntervalDoesNotPanic covers the
// symmetric branch — time.NewTicker treats negative the same as zero.
func TestStartRootRefresh_NegativeIntervalDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("StartRootRefresh panicked with negative interval: %v", r)
		}
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := &Resolver{logger: logger}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		r.StartRootRefresh(ctx, -1*time.Hour)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("StartRootRefresh did not exit after ctx cancellation")
	}
}

// TestMinRootRefreshInterval_StableConstant pins the floor against
// thrash-level and impossibly-high regressions.
func TestMinRootRefreshInterval_StableConstant(t *testing.T) {
	if MinRootRefreshInterval <= 0 {
		t.Fatalf("MinRootRefreshInterval = %v is non-positive — would re-introduce the panic", MinRootRefreshInterval)
	}
	if MinRootRefreshInterval > 24*time.Hour {
		t.Fatalf("MinRootRefreshInterval = %v is too high — RFC 8109 recommends ~25h, floor must allow legitimate operator settings", MinRootRefreshInterval)
	}
}
