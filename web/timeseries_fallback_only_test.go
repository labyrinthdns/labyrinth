package web

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestTimeSeriesFallbackOnlySnapshot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		if got := NewTimeSeriesAggregator().Snapshot(time.Minute); len(got) != 0 {
			t.Fatalf("empty aggregator: %v", got)
		}
		for _, counts := range [][2]int64{{1, 0}, {0, 1}, {1, 1}} {
			ts := NewTimeSeriesAggregator()
			ts.RecordFallback(counts[0], counts[1])
			assertCounts := func(b []Bucket) {
				t.Helper()
				if len(b) != 1 || b[0].Queries != 0 || b[0].FallbackQueries != counts[0] || b[0].FallbackRecoveries != counts[1] || b[0].AvgLatencyMs != 0 {
					t.Fatalf("fallback %v: %+v", counts, b)
				}
			}
			assertCounts(ts.Snapshot(time.Minute))
			assertCounts(ts.LatestBuckets(1))
			assertCounts(ts.SnapshotAggregated(time.Minute, time.Minute))
			time.Sleep(time.Second) // Advances only synctest's virtual clock.
			assertCounts(ts.Snapshot(time.Minute))
		}
	})
}
