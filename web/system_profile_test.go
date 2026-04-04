package web

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestHandleSystemProfile_MethodNotAllowed(t *testing.T) {
	srv := testAdminServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/system/profile", nil)
	w := httptest.NewRecorder()

	srv.handleSystemProfile(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestHandleSystemProfile_OK(t *testing.T) {
	srv := testAdminServer(t)

	srv.metrics.IncQueries("A")
	srv.metrics.IncUpstreamQueries()
	srv.metrics.IncBlockedQueries()
	srv.metrics.IncRateLimited()
	srv.timeSeries.Record(true, 2.5, false)
	srv.timeSeries.Record(false, 5.0, true)

	req := httptest.NewRequest(http.MethodGet, "/api/system/profile", nil)
	w := httptest.NewRecorder()

	srv.handleSystemProfile(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	runtimeObj, ok := body["runtime"].(map[string]interface{})
	if !ok {
		t.Fatalf("runtime object missing")
	}
	if runtimeObj["os"] != runtime.GOOS {
		t.Fatalf("want runtime os %q, got %v", runtime.GOOS, runtimeObj["os"])
	}

	networkObj, ok := body["network"].(map[string]interface{})
	if !ok {
		t.Fatalf("network object missing")
	}
	if _, ok := networkObj["interfaces"].([]interface{}); !ok {
		t.Fatalf("network.interfaces should be array")
	}
	if _, ok := networkObj["dns_listen_addresses"].([]interface{}); !ok {
		t.Fatalf("network.dns_listen_addresses should be array")
	}

	trafficObj, ok := body["traffic"].(map[string]interface{})
	if !ok {
		t.Fatalf("traffic object missing")
	}
	if trafficObj["last_minute_qps_peak"].(float64) <= 0 {
		t.Fatalf("expected qps peak > 0, got %v", trafficObj["last_minute_qps_peak"])
	}
}

func TestCollectSystemInterfaces_SortedAndUnique(t *testing.T) {
	ifaces, ips := collectSystemInterfaces()

	for i := 1; i < len(ifaces); i++ {
		if ifaces[i-1].Name > ifaces[i].Name {
			t.Fatalf("interfaces not sorted by name")
		}
	}
	for i := 1; i < len(ips); i++ {
		if ips[i-1] > ips[i] {
			t.Fatalf("ips not sorted")
		}
		if ips[i-1] == ips[i] {
			t.Fatalf("ips not unique")
		}
	}
}

func TestFormatInterfaceFlags(t *testing.T) {
	flags := net.FlagUp | net.FlagBroadcast | net.FlagLoopback | net.FlagPointToPoint | net.FlagMulticast
	got := formatInterfaceFlags(flags)
	want := []string{"up", "broadcast", "loopback", "pointtopoint", "multicast"}
	if len(got) != len(want) {
		t.Fatalf("want %d flags, got %d (%v)", len(want), len(got), got)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing flag %q in %v", w, got)
		}
	}
}

func TestReadMemoryAndCPUAndDisk(t *testing.T) {
	mem := readMemoryStats()
	if _, ok := mem["process_alloc_bytes"]; !ok {
		t.Fatalf("process_alloc_bytes missing")
	}
	if _, ok := mem["gc_cycles"]; !ok {
		t.Fatalf("gc_cycles missing")
	}

	cpuSec := readProcessCPUSeconds()
	if cpuSec < 0 {
		t.Fatalf("cpu seconds should be non-negative, got %f", cpuSec)
	}

	disk := readDiskUsage()
	if _, ok := disk["path"]; !ok {
		t.Fatalf("disk path missing")
	}
}

func TestReadTrafficSummary_EmptyAndWithBuckets(t *testing.T) {
	srv := testAdminServer(t)
	srv.metrics.IncQueries("A")
	srv.metrics.IncUpstreamQueries()
	srv.metrics.IncBlockedQueries()
	srv.metrics.IncRateLimited()

	empty := readTrafficSummary(srv)
	if empty.totalQueries < 1 {
		t.Fatalf("expected at least 1 total query, got %d", empty.totalQueries)
	}
	if empty.lastMinuteQPSAvg != 0 {
		t.Fatalf("expected empty qps avg 0, got %f", empty.lastMinuteQPSAvg)
	}

	srv.timeSeries.Record(true, 2.0, false)
	srv.timeSeries.Record(false, 3.0, true)
	withBuckets := readTrafficSummary(srv)
	if withBuckets.lastMinuteQPSAvg <= 0 {
		t.Fatalf("expected qps avg > 0, got %f", withBuckets.lastMinuteQPSAvg)
	}
	if withBuckets.lastMinuteQPSPeak <= 0 {
		t.Fatalf("expected qps peak > 0, got %f", withBuckets.lastMinuteQPSPeak)
	}
	if withBuckets.lastMinuteErrors < 1 {
		t.Fatalf("expected at least 1 error, got %d", withBuckets.lastMinuteErrors)
	}
}

func TestResolveListenIPs(t *testing.T) {
	discovered := []string{"10.0.0.2", "2001:db8::2"}

	tests := []struct {
		name     string
		listen   string
		expected []string
	}{
		{name: "empty listen address", listen: "", expected: []string{}},
		{name: "wildcard empty host", listen: ":53", expected: discovered},
		{name: "wildcard ipv4", listen: "0.0.0.0:53", expected: discovered},
		{name: "wildcard ipv6", listen: "[::]:53", expected: discovered},
		{name: "wildcard star", listen: "*:53", expected: discovered},
		{name: "specific ipv4", listen: "127.0.0.1:53", expected: []string{"127.0.0.1"}},
		{name: "specific ipv6", listen: "[2001:db8::10]:53", expected: []string{"2001:db8::10"}},
		{name: "specific without port", listen: "127.0.0.1", expected: []string{"127.0.0.1"}},
		{name: "hostname", listen: "localhost:53", expected: []string{"localhost"}},
		{name: "hostname trimmed brackets", listen: "[localhost]:53", expected: []string{"localhost"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveListenIPs(tt.listen, discovered)
			if len(got) != len(tt.expected) {
				t.Fatalf("expected %d listen IPs, got %d (%v)", len(tt.expected), len(got), got)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Fatalf("expected[%d]=%q, got=%q", i, tt.expected[i], got[i])
				}
			}
		})
	}

	t.Run("wildcard deduplicates discovered addresses", func(t *testing.T) {
		got := resolveListenIPs("0.0.0.0:53", []string{"10.0.0.2", "10.0.0.2", "2001:db8::2"})
		expected := []string{"10.0.0.2", "2001:db8::2"}
		if len(got) != len(expected) {
			t.Fatalf("expected %d deduplicated entries, got %d (%v)", len(expected), len(got), got)
		}
		for i := range got {
			if got[i] != expected[i] {
				t.Fatalf("expected[%d]=%q, got=%q", i, expected[i], got[i])
			}
		}
	})
}

func TestSetConfigPath_EmptyIgnored(t *testing.T) {
	srv := testAdminServer(t)
	before := srv.configPath
	srv.SetConfigPath("")
	if srv.configPath != before {
		t.Fatalf("empty path should not override configPath")
	}
}

func TestDefaultAltSvc(t *testing.T) {
	h3WithPort := &http3.Server{Port: 9443}
	if got := defaultAltSvc(h3WithPort); !strings.Contains(got, ":9443") {
		t.Fatalf("expected alt-svc with :9443, got %q", got)
	}

	h3WithAddr := &http3.Server{Addr: "127.0.0.1:4443"}
	if got := defaultAltSvc(h3WithAddr); !strings.Contains(got, ":4443") {
		t.Fatalf("expected alt-svc with :4443, got %q", got)
	}

	h3Invalid := &http3.Server{Addr: "invalid"}
	if got := defaultAltSvc(h3Invalid); got != "" {
		t.Fatalf("expected empty alt-svc for invalid address, got %q", got)
	}
}

func TestCleanupStaleClients(t *testing.T) {
	srv := testAdminServer(t)
	srv.clientCleanupInterval = 10 * time.Millisecond
	old := &clientQueryEntry{lastAccess: time.Now().Add(-time.Second)}
	newEntry := &clientQueryEntry{lastAccess: time.Now()}
	srv.clientQueryNum = map[string]*clientQueryEntry{
		"old": old,
		"new": newEntry,
	}

	srv.cleanupStaleClients()
	if _, ok := srv.clientQueryNum["old"]; ok {
		t.Fatalf("old entry should be removed")
	}
	if _, ok := srv.clientQueryNum["new"]; !ok {
		t.Fatalf("new entry should stay")
	}
}

func TestStartClientCleanup(t *testing.T) {
	srv := testAdminServer(t)
	srv.clientCleanupInterval = 10 * time.Millisecond
	srv.clientQueryNum = map[string]*clientQueryEntry{
		"old": {lastAccess: time.Now().Add(-time.Second)},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		srv.startClientCleanup(ctx)
		close(done)
	}()

	time.Sleep(35 * time.Millisecond)
	cancel()
	<-done

	if len(srv.clientQueryNum) != 0 {
		t.Fatalf("expected stale entries to be cleaned by background cleanup")
	}
}
