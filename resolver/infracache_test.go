package resolver

import (
	"context"
	"testing"
	"time"
)

func TestInfraCacheRecordRTT(t *testing.T) {
	ic := NewInfraCache()

	// First sample sets the RTT directly
	ic.RecordRTT("1.2.3.4", 100*time.Millisecond)
	rtt := ic.GetRTT("1.2.3.4")
	if rtt != 100*time.Millisecond {
		t.Errorf("expected 100ms, got %v", rtt)
	}

	// Second sample uses EWMA: 0.7*100 + 0.3*200 = 70+60 = 130ms
	ic.RecordRTT("1.2.3.4", 200*time.Millisecond)
	rtt = ic.GetRTT("1.2.3.4")
	expected := time.Duration(float64(100*time.Millisecond)*0.7 + float64(200*time.Millisecond)*0.3)
	if rtt != expected {
		t.Errorf("expected %v, got %v", expected, rtt)
	}
}

func TestInfraCacheRecordFailure(t *testing.T) {
	ic := NewInfraCache()

	ic.RecordFailure("1.2.3.4")
	ic.RecordFailure("1.2.3.4")

	ic.mu.RLock()
	info := ic.entries["1.2.3.4"]
	ic.mu.RUnlock()

	if info.FailCount != 2 {
		t.Errorf("expected fail count 2, got %d", info.FailCount)
	}
}

func TestInfraCacheLameness(t *testing.T) {
	ic := NewInfraCache()

	ic.RecordLame("1.2.3.4", "example.com")

	if !ic.IsLame("1.2.3.4", "example.com") {
		t.Error("expected NS to be lame for example.com")
	}
	if ic.IsLame("1.2.3.4", "other.com") {
		t.Error("NS should not be lame for other.com")
	}
	if ic.IsLame("5.6.7.8", "example.com") {
		t.Error("unknown NS should not be lame")
	}
}

func TestInfraCacheSortByRTT(t *testing.T) {
	ic := NewInfraCache()

	ic.RecordRTT("1.1.1.1", 50*time.Millisecond)
	ic.RecordRTT("8.8.8.8", 10*time.Millisecond)
	ic.RecordRTT("9.9.9.9", 200*time.Millisecond)

	entries := []nsEntry{
		{hostname: "ns1", ipv4: "9.9.9.9"},
		{hostname: "ns2", ipv4: "1.1.1.1"},
		{hostname: "ns3", ipv4: "8.8.8.8"},
	}

	sorted := ic.SortByRTT(entries)

	if sorted[0].ipv4 != "8.8.8.8" {
		t.Errorf("expected fastest first (8.8.8.8), got %s", sorted[0].ipv4)
	}
	if sorted[1].ipv4 != "1.1.1.1" {
		t.Errorf("expected second (1.1.1.1), got %s", sorted[1].ipv4)
	}
	if sorted[2].ipv4 != "9.9.9.9" {
		t.Errorf("expected slowest last (9.9.9.9), got %s", sorted[2].ipv4)
	}
}

func TestInfraCacheSortByRTTWithFailures(t *testing.T) {
	ic := NewInfraCache()

	ic.RecordRTT("1.1.1.1", 10*time.Millisecond) // fast but failing
	ic.RecordFailure("1.1.1.1")
	ic.RecordFailure("1.1.1.1")

	ic.RecordRTT("8.8.8.8", 50*time.Millisecond) // moderate, reliable

	entries := []nsEntry{
		{hostname: "ns1", ipv4: "1.1.1.1"},
		{hostname: "ns2", ipv4: "8.8.8.8"},
	}

	sorted := ic.SortByRTT(entries)

	// 1.1.1.1: 10ms + 2*500ms = 1010ms
	// 8.8.8.8: 50ms + 0 = 50ms
	if sorted[0].ipv4 != "8.8.8.8" {
		t.Errorf("expected reliable server first (8.8.8.8), got %s", sorted[0].ipv4)
	}
}

func TestInfraCacheSortByRTTUnknown(t *testing.T) {
	ic := NewInfraCache()

	ic.RecordRTT("8.8.8.8", 10*time.Millisecond)

	entries := []nsEntry{
		{hostname: "ns1", ipv4: "1.1.1.1"}, // unknown → 100ms default
		{hostname: "ns2", ipv4: "8.8.8.8"}, // 10ms known
	}

	sorted := ic.SortByRTT(entries)
	if sorted[0].ipv4 != "8.8.8.8" {
		t.Errorf("expected known fast server first, got %s", sorted[0].ipv4)
	}
}

func TestInfraCacheSortByRTTIPv6(t *testing.T) {
	ic := NewInfraCache()

	ic.RecordRTT("2001:db8::1", 20*time.Millisecond)
	ic.RecordRTT("2001:db8::2", 80*time.Millisecond)

	entries := []nsEntry{
		{hostname: "ns1", ipv6: "2001:db8::2"},
		{hostname: "ns2", ipv6: "2001:db8::1"},
	}

	sorted := ic.SortByRTT(entries)
	if sorted[0].ipv6 != "2001:db8::1" {
		t.Errorf("expected fastest IPv6 first, got %s", sorted[0].ipv6)
	}
}

func TestInfraCacheCleanStale(t *testing.T) {
	ic := NewInfraCache()

	ic.RecordRTT("1.1.1.1", 10*time.Millisecond)
	ic.RecordRTT("8.8.8.8", 10*time.Millisecond)

	// Manually set LastUsed to the past for one entry
	ic.mu.Lock()
	ic.entries["1.1.1.1"].LastUsed = time.Now().Add(-2 * time.Hour)
	ic.mu.Unlock()

	ic.CleanStale(1 * time.Hour)

	if ic.Len() != 1 {
		t.Errorf("expected 1 entry after cleanup, got %d", ic.Len())
	}
	if ic.GetRTT("8.8.8.8") == 0 {
		t.Error("active entry should not be cleaned")
	}
}

func TestInfraCacheStartCleanup(t *testing.T) {
	ic := NewInfraCache()

	ic.RecordRTT("1.1.1.1", 10*time.Millisecond)
	ic.mu.Lock()
	ic.entries["1.1.1.1"].LastUsed = time.Now().Add(-2 * time.Hour)
	ic.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ic.StartCleanup(ctx, 50*time.Millisecond, 1*time.Hour)
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	if ic.Len() != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", ic.Len())
	}
}
