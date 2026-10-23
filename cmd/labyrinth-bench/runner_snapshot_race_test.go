package main

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestRunBenchmark_SnapshotReadsLatenciesUnderLock exercises the per-second
// snapshot path while the collector appends latencies. Under -race (make
// test-race) the detector flags any unlocked read of the shared slice.
func TestRunBenchmark_SnapshotReadsLatenciesUnderLock(t *testing.T) {
	addr, stop := startUDPResponder(t, func(m *dns.Message) []byte { return buildDNSResponse(t, m, dns.RCodeNoError) })
	defer stop()

	snaps := 0
	res := RunBenchmark(RunConfig{
		Target:   addr,
		QPS:      500,
		Duration: 1500 * time.Millisecond,
		Workers:  2,
		Domains:  []string{"a.test"},
		Types:    []uint16{dns.TypeA},
		Name:     "snapshot-race",
	}, func(RunResult) { snaps++ })

	if res.TotalQueries == 0 || snaps == 0 {
		t.Fatalf("expected traffic and at least one snapshot, got total=%d snapshots=%d", res.TotalQueries, snaps)
	}
}
