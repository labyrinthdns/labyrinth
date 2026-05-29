package resolver

import (
	"io"
	"log/slog"
	"sync"
	"testing"
)

// TestDNSSECValidator_ConcurrentEnableIsRaceFree pins the v0.8.16 gate:
// EnableDNSSEC publishes r.dnssecValidator from a startup goroutine that
// runs in parallel with the DNS server's query handlers. Before v0.8.16
// the field was a plain *dnssec.Validator pointer; every hot-path read
// (every validated query and every trace) did
//
//	if r.dnssecValidator != nil { r.dnssecValidator.X(...) }
//
// — two unsynchronised reads. On weak-ordering architectures a reader
// could see the new pointer with a half-published Validator struct, or
// keep observing nil indefinitely after publication. The fix migrated
// the field to atomic.Pointer[dnssec.Validator]: all reads are now
// Load() once at the top of each call site, and EnableDNSSEC does
// Store(NewValidator(...)).
//
// The pin spawns N readers (DNSSECValidator() — the public accessor
// that mirrors the hot path) and one writer (EnableDNSSEC) and asserts
// every observed non-nil pointer is a complete, dereferenceable
// validator. Failing this test under data-race UB would surface as a
// nil-deref panic or a torn struct read.
func TestDNSSECValidator_ConcurrentEnableIsRaceFree(t *testing.T) {
	r := &Resolver{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	const (
		readers = 8
		ops     = 500
	)

	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < ops; j++ {
				if v := r.DNSSECValidator(); v != nil {
					// Touch a real method so a half-published struct
					// would deref bad memory rather than silently pass.
					_ = v.SHA1Allowed()
				}
			}
		}()
	}

	// Writer publishes the validator once partway through.
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.EnableDNSSEC(logger)
	}()

	wg.Wait()

	// After the storm, the validator must be the one EnableDNSSEC
	// published. Re-publishing would race the readers; we just assert
	// the published pointer is non-nil and usable.
	v := r.DNSSECValidator()
	if v == nil {
		t.Fatal("after EnableDNSSEC, DNSSECValidator() returned nil")
	}
	_ = v.SHA1Allowed()
}
