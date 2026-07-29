package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMetricsCounters(t *testing.T) {
	m := NewMetrics()

	m.IncQueries("A")
	m.IncQueries("A")
	m.IncQueries("AAAA")
	m.IncResponses("NOERROR")
	m.IncResponses("NXDOMAIN")
	m.IncCacheHits()
	m.IncCacheHits()
	m.IncCacheHits()
	m.IncCacheMisses()
	m.IncUpstreamQueries()
	m.IncUpstreamErrors()
	m.IncRateLimited()
	m.IncCacheEvictions("expired")

	var buf bytes.Buffer
	m.WriteMetrics(&buf)
	output := buf.String()

	checks := []string{
		`labyrinth_queries_total{type="A"} 2`,
		`labyrinth_queries_total{type="AAAA"} 1`,
		`labyrinth_responses_total{rcode="NOERROR"} 1`,
		`labyrinth_responses_total{rcode="NXDOMAIN"} 1`,
		"labyrinth_cache_hits_total 3",
		"labyrinth_cache_misses_total 1",
		"labyrinth_upstream_queries_total 1",
		"labyrinth_upstream_errors_total 1",
		"labyrinth_rate_limited_total 1",
		"labyrinth_cache_evictions_total 1",
		"labyrinth_uptime_seconds",
		"labyrinth_goroutines",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("metrics output missing %q", check)
		}
	}
}

func TestMetricsConcurrent(t *testing.T) {
	m := NewMetrics()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.IncQueries("A")
				m.IncCacheHits()
				m.IncResponses("NOERROR")
			}
		}()
	}
	wg.Wait()

	var buf bytes.Buffer
	m.WriteMetrics(&buf)
	output := buf.String()

	if !strings.Contains(output, `labyrinth_queries_total{type="A"} 10000`) {
		t.Errorf("expected 10000 queries, got output:\n%s", output)
	}
	if !strings.Contains(output, "labyrinth_cache_hits_total 10000") {
		t.Errorf("expected 10000 cache hits")
	}
}

func TestHistogramObserve(t *testing.T) {
	h := newHistogram([]float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0})

	// Observe values in different buckets
	h.observe(0.0005) // ≤ 0.001
	h.observe(0.003)  // ≤ 0.005
	h.observe(0.008)  // ≤ 0.01
	h.observe(0.03)   // ≤ 0.05
	h.observe(0.07)   // ≤ 0.1
	h.observe(0.3)    // ≤ 0.5
	h.observe(0.8)    // ≤ 1.0
	h.observe(3.0)    // ≤ 5.0
	h.observe(10.0)   // +Inf

	var buf bytes.Buffer
	h.writeTo(&buf, "test_duration")
	output := buf.String()

	// Verify cumulative buckets
	if !strings.Contains(output, `test_duration_bucket{le="0.001"} 1`) {
		t.Errorf("bucket 0.001 wrong")
	}
	if !strings.Contains(output, `test_duration_bucket{le="0.005"} 2`) {
		t.Errorf("bucket 0.005 wrong")
	}
	if !strings.Contains(output, `test_duration_bucket{le="+Inf"} 9`) {
		t.Errorf("+Inf bucket should be 9")
	}
	if !strings.Contains(output, "test_duration_count 9") {
		t.Errorf("count should be 9")
	}
}

func TestObserveQueryDuration(t *testing.T) {
	m := NewMetrics()
	m.ObserveQueryDuration(50 * time.Millisecond)
	m.ObserveQueryDuration(200 * time.Millisecond)

	var buf bytes.Buffer
	m.WriteMetrics(&buf)
	output := buf.String()

	if !strings.Contains(output, "labyrinth_query_duration_seconds_count 2") {
		t.Errorf("expected 2 observations in histogram")
	}
}

func TestStartTime(t *testing.T) {
	before := time.Now()
	m := NewMetrics()
	after := time.Now()

	st := m.StartTime()
	if st.Before(before) || st.After(after) {
		t.Error("StartTime should be around now")
	}
}

func TestServeHTTP(t *testing.T) {
	m := NewMetrics()
	m.IncQueries("A")
	m.IncResponses("NOERROR")
	m.IncCacheHits()
	m.IncCacheMisses()
	m.IncCacheEvictions("expired")
	m.IncUpstreamQueries()
	m.IncUpstreamErrors()
	m.IncRateLimited()
	m.ObserveQueryDuration(10 * time.Millisecond)

	req, err := http.NewRequest("GET", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()

	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", ct)
	}

	body := rr.Body.String()
	checks := []string{
		`labyrinth_queries_total{type="A"} 1`,
		`labyrinth_responses_total{rcode="NOERROR"} 1`,
		"labyrinth_cache_hits_total 1",
		"labyrinth_cache_misses_total 1",
		"labyrinth_cache_evictions_total 1",
		"labyrinth_upstream_queries_total 1",
		"labyrinth_upstream_errors_total 1",
		"labyrinth_rate_limited_total 1",
		"labyrinth_uptime_seconds",
		"labyrinth_goroutines",
		"labyrinth_query_duration_seconds_count 1",
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Errorf("ServeHTTP output missing %q", check)
		}
	}
}

func TestDNSSECAndBlockedCounters(t *testing.T) {
	m := NewMetrics()

	m.IncDNSSECSecure()
	m.IncDNSSECSecure()
	m.IncDNSSECInsecure()
	m.IncDNSSECBogus()
	m.IncBlockedQueries()
	m.IncBlockedQueries()
	m.IncBlockedQueries()

	var buf bytes.Buffer
	m.WriteMetrics(&buf)
	output := buf.String()

	checks := []string{
		"labyrinth_dnssec_secure_total 2",
		"labyrinth_dnssec_insecure_total 1",
		"labyrinth_dnssec_bogus_total 1",
		"labyrinth_blocked_queries_total 3",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("metrics output missing %q", check)
		}
	}
}

func TestFallbackCounters_WriteMetrics(t *testing.T) {
	m := NewMetrics()

	m.IncFallbackQueries()
	m.IncFallbackQueries()
	m.IncFallbackRecoveries()

	var buf bytes.Buffer
	m.WriteMetrics(&buf)
	output := buf.String()

	checks := []string{
		"labyrinth_fallback_queries_total 2",
		"labyrinth_fallback_recoveries_total 1",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("WriteMetrics output missing %q", check)
		}
	}
}

func TestFallbackCounters_ServeHTTP(t *testing.T) {
	m := NewMetrics()

	m.IncFallbackQueries()
	m.IncFallbackQueries()
	m.IncFallbackQueries()
	m.IncFallbackRecoveries()
	m.IncFallbackRecoveries()

	req, err := http.NewRequest("GET", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	body := rr.Body.String()
	checks := []string{
		"labyrinth_fallback_queries_total 3",
		"labyrinth_fallback_recoveries_total 2",
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Errorf("ServeHTTP output missing %q", check)
		}
	}
}

func TestAddCacheEvictions(t *testing.T) {
	m := NewMetrics()

	m.AddCacheEvictions("sweep", 5)
	m.AddCacheEvictions("sweep", 3)

	var buf bytes.Buffer
	m.WriteMetrics(&buf)
	output := buf.String()

	if !strings.Contains(output, "labyrinth_cache_evictions_total 8") {
		t.Errorf("expected 8 cache evictions, got output:\n%s", output)
	}
}

func TestGetOrCreateConcurrentRace(t *testing.T) {
	// Cover the double-check locking branch in getOrCreate
	// where a key is created between RUnlock and Lock
	m := NewMetrics()

	var wg sync.WaitGroup
	// Many goroutines all creating the same key simultaneously
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.IncQueries("RACE")
		}()
	}
	wg.Wait()

	var buf bytes.Buffer
	m.WriteMetrics(&buf)
	output := buf.String()

	if !strings.Contains(output, `labyrinth_queries_total{type="RACE"} 50`) {
		t.Errorf("expected 50 RACE queries, got output:\n%s", output)
	}
}

func TestGetOrCreateDoubleCheck(t *testing.T) {
	// Directly exercise the double-check locking path in getOrCreate.
	// The double-check (line 80) fires when the key was created by another
	// goroutine between the RUnlock (line 73) and the Lock (line 78).
	// We use many goroutines racing on the same new key to trigger this.
	for attempt := 0; attempt < 20; attempt++ {
		m := NewMetrics()
		var wg sync.WaitGroup
		start := make(chan struct{})
		key := "RACE_KEY"
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				m.getOrCreate(m.queriesTotal, key)
			}()
		}
		close(start)
		wg.Wait()
	}
	// If the double-check path isn't hit, coverage will show it.
	// We can't guarantee it deterministically, but high concurrency makes it likely.
}
