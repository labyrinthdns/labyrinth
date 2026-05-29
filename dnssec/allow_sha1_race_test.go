package dnssec

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestValidator_AllowSHA1IsRaceFree pins the v0.8.25 gate:
// Validator.allowSHA1 must be atomic.Bool, not a plain bool. The
// resolver wires the value via a startup goroutine that runs in
// parallel with the DNS handler goroutines:
//
//	main.go:340 → go func() {
//	    PrimeRootHints()
//	    res.EnableDNSSEC(logger)             // creates the validator
//	    res.SetDNSSECAllowSHA1(cfg...)       // writes allowSHA1
//	    res.SetDNSSECNegativeTrustAnchors(...)
//	}
//
// By the time SetDNSSECAllowSHA1 fires, the UDP/TCP/DoT listeners are
// already accepting queries (they were started before the priming
// goroutine). Every DNS validation that lands BEFORE the writer
// completes calls `isWeakRRSIGAlg` / `isWeakDSDigest`, both of which
// read v.allowSHA1. Before this fix, the read was unsynchronised: the
// race detector flagged it, and on a weak-ordering CPU a reader could
// keep observing the default (false) indefinitely after the writer
// landed — every legacy SHA1-signed zone would intermittently fail
// with Bogus even though the operator opted in via
// `dnssec_allow_sha1: true`. The fix migrates allowSHA1 to atomic.Bool
// (mirroring the v0.8.16 dnssecValidator atomic.Pointer migration);
// AllowSHA1/SHA1Allowed and the two hot-path checks now Store/Load.
//
// The pin runs N readers calling isWeakRRSIGAlg / isWeakDSDigest in
// parallel with a writer toggling AllowSHA1. Without the atomic
// migration `go test -race` reports a data race on Validator.allowSHA1;
// with the fix the test passes under both race and non-race builds.
func TestValidator_AllowSHA1IsRaceFree(t *testing.T) {
	v := &Validator{}

	const readers = 8
	const opsPerReader = 500

	var stopWriter atomic.Bool
	var wg sync.WaitGroup
	wg.Add(readers + 1)

	// Writer: flip the bit back and forth as fast as the scheduler will
	// let it. This emulates the production case where the startup
	// goroutine lands SetDNSSECAllowSHA1 a few nanoseconds after the
	// handlers start.
	go func() {
		defer wg.Done()
		toggle := true
		for !stopWriter.Load() {
			v.AllowSHA1(toggle)
			toggle = !toggle
		}
	}()

	// Readers: hammer the hot-path checks. The exact return value does
	// not matter — what matters is that the field read is race-free.
	// On a successful run the race detector reports no race; on a
	// regression that drops atomic publication the detector fires.
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerReader; j++ {
				_ = v.isWeakRRSIGAlg(dns.AlgRSASHA1)
				_ = v.isWeakDSDigest(dns.DigestSHA1)
				_ = v.SHA1Allowed()
			}
		}()
	}

	stopWriter.Store(true)
	wg.Wait()
}
