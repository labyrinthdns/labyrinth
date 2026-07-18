package web

import (
	"context"
	"testing"
	"time"
)

func TestDiagnosticTraceLimiterGlobalCap(t *testing.T) {
	limiter := newDiagnosticTraceLimiter(2)
	if !limiter.tryAcquire() || !limiter.tryAcquire() {
		t.Fatal("expected both configured diagnostic trace slots to be available")
	}
	if limiter.tryAcquire() {
		t.Fatal("limiter admitted a trace above its global cap")
	}
	limiter.release()
	if !limiter.tryAcquire() {
		t.Fatal("released diagnostic trace slot was not reusable")
	}
	limiter.release()
	limiter.release()
}

func TestDiagnosticTraceSessionCancelJoinsGeneration(t *testing.T) {
	session := &diagnosticTraceSession{}
	ctx, cancel := context.WithCancel(context.Background())
	run := session.start(cancel)

	returned := make(chan struct{})
	go func() {
		session.cancelAndWait()
		close(returned)
	}()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancelAndWait did not cancel the active generation")
	}
	select {
	case <-returned:
		t.Fatal("cancelAndWait returned before the generation finished")
	case <-time.After(20 * time.Millisecond):
	}

	session.finish(run)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("cancelAndWait did not join the finished generation")
	}
}

func TestDiagnosticTraceSessionOldGenerationCannotClearNew(t *testing.T) {
	session := &diagnosticTraceSession{}
	first := session.start(func() {})
	second := session.start(func() {})

	session.finish(first)
	session.mu.Lock()
	current := session.current
	session.mu.Unlock()
	if current != second {
		t.Fatal("an old generation cleared or replaced the current generation")
	}

	session.finish(second)
	session.mu.Lock()
	current = session.current
	session.mu.Unlock()
	if current != nil {
		t.Fatal("current generation did not clear itself on completion")
	}
}
