package main

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestCoordinator_AllRunnersExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := NewCoordinator()
		c.runners["runner"] = &RunnerState{LastSeen: time.Now(), LastResult: RunResult{QPS: 10}}
		if got := c.buildAggregatedSnapshotLocked(); got.RunnerCount != 1 || got.TotalQPS != 10 {
			t.Fatalf("active snapshot=%+v", got)
		}
		time.Sleep(11 * time.Second) // virtual time, no wall-clock wait
		if got := c.buildAggregatedSnapshotLocked(); got.RunnerCount != 0 || got.TotalQPS != 0 {
			t.Fatalf("expired snapshot=%+v, want zero active runners and QPS", got)
		}
	})
}
