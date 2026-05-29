package web

import (
	"bytes"
	"sync"
	"testing"
)

// TestJWTSecret_ConcurrentRotationIsRaceFree pins the v0.8.13 gate:
// jwtSecret was a plain []byte field that handleChangePassword wrote
// to under configFileMu while every authenticated HTTP request read
// it (via validateJWT inside requireAuth) WITHOUT that mutex. The
// slice header is 24 bytes on 64-bit Go, so concurrent read+write
// could observe a torn header — a new pointer with the old length —
// and crash on out-of-bounds access during password rotation.
//
// The fix migrated the field to atomic.Pointer[[]byte] so each read
// sees a complete, consistent header. This pin spawns N readers and
// M rotators against the gate and asserts every read returns a
// well-formed 32-byte secret.
func TestJWTSecret_ConcurrentRotationIsRaceFree(t *testing.T) {
	srv := testAdminServer(t)
	initial := make([]byte, 32)
	for i := range initial {
		initial[i] = byte(i)
	}
	srv.jwtSecret.Store(&initial)

	const (
		readers = 8
		rotates = 8
		ops     = 500
	)

	var wg sync.WaitGroup

	// Readers — mirror what requireAuth does on the hot path.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < ops; j++ {
				got := *srv.jwtSecret.Load()
				if len(got) != 32 {
					t.Errorf("torn read: len=%d, want 32", len(got))
					return
				}
			}
		}()
	}

	// Rotators — mirror handleChangePassword: build a fresh 32-byte
	// secret, publish atomically.
	for i := 0; i < rotates; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for j := 0; j < ops; j++ {
				next := bytes.Repeat([]byte{byte(seed)}, 32)
				srv.jwtSecret.Store(&next)
			}
		}(i + 1)
	}

	wg.Wait()

	// Final secret must still be a complete 32-byte slice — sanity guard
	// against the rotators somehow installing a torn or zero-length value.
	if final := *srv.jwtSecret.Load(); len(final) != 32 {
		t.Fatalf("after the storm: len=%d, want 32", len(final))
	}
}
