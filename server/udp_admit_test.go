package server

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/metrics"
)

// blockingHandler holds the first Handle call until release is closed,
// so the UDP worker semaphore can be saturated for the admit test.
type blockingHandler struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func (h *blockingHandler) Handle(query []byte, _ net.Addr) ([]byte, error) {
	h.calls.Add(1)
	select {
	case h.started <- struct{}{}:
	default:
	}
	<-h.release
	return nil, nil
}

func TestUDPServer_DropsWhenWorkersSaturated(t *testing.T) {
	h := &blockingHandler{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := metrics.NewMetrics()

	srv, err := NewUDPServer("127.0.0.1:0", h, 1, logger)
	if err != nil {
		t.Fatalf("NewUDPServer: %v", err)
	}
	srv.SetMetrics(m)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(ctx)
	}()

	addr := srv.conn.LocalAddr().String()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write1: %v", err)
	}
	select {
	case <-h.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first query never entered handler")
	}

	// Semafor dolu — sonraki paketler drop edilmeli, read loop donmamalı.
	for i := 0; i < 20; i++ {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write burst: %v", err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.UDPWorkerDrops() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := m.UDPWorkerDrops(); got == 0 {
		t.Fatal("expected udp worker drops while semaphore saturated")
	}
	if got := h.calls.Load(); got != 1 {
		t.Fatalf("handler calls = %d, want 1 (only the admitted worker)", got)
	}

	close(h.release)
	cancel()
	wg.Wait()
}
