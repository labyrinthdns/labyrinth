package xfr

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// stallingPrimary accepts one connection, reads the query and never answers.
// `queried` closes once the query has been consumed, i.e. the client is in its
// read loop. release unblocks and tears the server down.
func stallingPrimary(t *testing.T) (addr string, queried <-chan struct{}, release func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gate := make(chan struct{})
	q := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		close(q)
		<-gate
		c.Close()
	}()
	return ln.Addr().String(), q, func() { close(gate); ln.Close() }
}

// TestTransfer_ContextCancelUnblocksStalledPrimary pins that cancelling ctx
// ends an in-flight transfer even when the per-message timeout is very long.
func TestTransfer_ContextCancelUnblocksStalledPrimary(t *testing.T) {
	run := map[string]func(context.Context, ClientConfig) error{
		"AXFR": func(ctx context.Context, cfg ClientConfig) error { _, err := AXFR(ctx, cfg); return err },
		"IXFR": func(ctx context.Context, cfg ClientConfig) error { _, err := IXFR(ctx, cfg, 1); return err },
	}
	for name, fn := range run {
		t.Run(name, func(t *testing.T) {
			addr, queried, release := stallingPrimary(t)
			defer release()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- fn(ctx, ClientConfig{PrimaryAddr: addr, Zone: "example.test", Timeout: time.Hour})
			}()
			<-queried
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("want context.Canceled, got %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("transfer still blocked after ctx cancel")
			}
		})
	}

	t.Run("already cancelled ctx fails fast", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := AXFR(ctx, ClientConfig{PrimaryAddr: "127.0.0.1:1", Zone: "example.test", Timeout: time.Hour}); err == nil {
			t.Fatal("expected error")
		}
	})
}
