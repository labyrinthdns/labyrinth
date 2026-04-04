//go:build windows

package web

import (
	"strings"
	"testing"
)

func TestSystemProfileWindowsZeroMetrics(t *testing.T) {
	if got := readSystemTotalMemoryBytes(); got != 0 {
		t.Fatalf("expected total memory 0 on windows stub, got %d", got)
	}
	if got := readSystemFreeMemoryBytes(); got != 0 {
		t.Fatalf("expected free memory 0 on windows stub, got %d", got)
	}
	one, five, fifteen := readSystemLoadAverages()
	if one != 0 || five != 0 || fifteen != 0 {
		t.Fatalf("expected load averages to be zero, got %f %f %f", one, five, fifteen)
	}
	rxB, txB, rxP, txP := readNetworkIOCounters()
	if rxB != 0 || txB != 0 || rxP != 0 || txP != 0 {
		t.Fatalf("expected network counters zero, got %d %d %d %d", rxB, txB, rxP, txP)
	}
}

func TestReadDiskUsageBytes_Windows(t *testing.T) {
	total, free, target, err := readDiskUsageBytes("")
	if err != nil {
		t.Fatalf("readDiskUsageBytes empty path failed: %v", err)
	}
	if !strings.HasSuffix(target, "\\") {
		t.Fatalf("expected target path to be drive root, got %q", target)
	}
	if total == 0 {
		t.Fatalf("expected non-zero total disk bytes")
	}
	if free > total {
		t.Fatalf("free bytes should be <= total bytes")
	}
}

func TestReadDiskUsageBytes_WindowsInvalidVolume(t *testing.T) {
	total, free, target, err := readDiskUsageBytes("?:\\not-a-real-volume")
	if err == nil {
		t.Fatalf("expected error for invalid volume, got total=%d free=%d target=%q", total, free, target)
	}
}
