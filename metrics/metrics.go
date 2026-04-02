package metrics

import (
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds all application metrics using lock-free atomic counters.
type Metrics struct {
	queriesTotal   map[string]*atomic.Int64
	responsesTotal map[string]*atomic.Int64
	cacheHits      atomic.Int64
	cacheMisses    atomic.Int64
	cacheEvictions atomic.Int64
	upstreamQueries atomic.Int64
	upstreamErrors  atomic.Int64
	rateLimited    atomic.Int64

	queryDurations *histogram

	startTime time.Time

	mu sync.RWMutex
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		queriesTotal:   make(map[string]*atomic.Int64),
		responsesTotal: make(map[string]*atomic.Int64),
		startTime:      time.Now(),
		queryDurations: newHistogram([]float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0}),
	}
}

func (m *Metrics) IncQueries(qtype string) {
	m.getOrCreate(m.queriesTotal, qtype).Add(1)
}

func (m *Metrics) IncResponses(rcode string) {
	m.getOrCreate(m.responsesTotal, rcode).Add(1)
}

func (m *Metrics) IncCacheHits()    { m.cacheHits.Add(1) }
func (m *Metrics) IncCacheMisses()  { m.cacheMisses.Add(1) }
func (m *Metrics) IncUpstreamQueries() { m.upstreamQueries.Add(1) }
func (m *Metrics) IncUpstreamErrors()  { m.upstreamErrors.Add(1) }
func (m *Metrics) IncRateLimited()     { m.rateLimited.Add(1) }

func (m *Metrics) IncCacheEvictions(reason string) {
	m.cacheEvictions.Add(1)
}

func (m *Metrics) AddCacheEvictions(reason string, count int) {
	m.cacheEvictions.Add(int64(count))
}

func (m *Metrics) ObserveQueryDuration(d time.Duration) {
	m.queryDurations.observe(d.Seconds())
}

func (m *Metrics) StartTime() time.Time {
	return m.startTime
}

func (m *Metrics) getOrCreate(mp map[string]*atomic.Int64, key string) *atomic.Int64 {
	m.mu.RLock()
	v, ok := mp[key]
	m.mu.RUnlock()
	if ok {
		return v
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok = mp[key]; ok {
		return v
	}
	v = &atomic.Int64{}
	mp[key] = v
	return v
}

// histogram is a simple bucketed histogram using atomic counters.
type histogram struct {
	boundaries []float64
	counts     []atomic.Int64
	sum        atomic.Int64
	count      atomic.Int64
}

func newHistogram(boundaries []float64) *histogram {
	return &histogram{
		boundaries: boundaries,
		counts:     make([]atomic.Int64, len(boundaries)+1), // +1 for +Inf bucket
	}
}

func (h *histogram) observe(value float64) {
	for i, b := range h.boundaries {
		if value <= b {
			h.counts[i].Add(1)
			h.count.Add(1)
			h.sum.Add(int64(value * 1e9)) // store as nanoseconds for precision
			return
		}
	}
	h.counts[len(h.boundaries)].Add(1)
	h.count.Add(1)
	h.sum.Add(int64(value * 1e9))
}

func (h *histogram) writeTo(w io.Writer, name string) {
	var cumulative int64
	for i, b := range h.boundaries {
		cumulative += h.counts[i].Load()
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, b, cumulative)
	}
	cumulative += h.counts[len(h.boundaries)].Load()
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, cumulative)
	fmt.Fprintf(w, "%s_sum %g\n", name, float64(h.sum.Load())/1e9)
	fmt.Fprintf(w, "%s_count %d\n", name, h.count.Load())
}

// MetricsSnapshot holds a point-in-time snapshot of all metrics.
type MetricsSnapshot struct {
	QueriesByType      map[string]int64
	ResponsesByRCode   map[string]int64
	CacheHits          int64
	CacheMisses        int64
	CacheEvictions     int64
	UpstreamQueries    int64
	UpstreamErrors     int64
	RateLimited        int64
	UptimeSeconds      float64
	Goroutines         int
	QueryDurationCount int64
}

// Snapshot returns a point-in-time snapshot of all metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	qbt := make(map[string]int64, len(m.queriesTotal))
	for k, v := range m.queriesTotal {
		qbt[k] = v.Load()
	}

	rbr := make(map[string]int64, len(m.responsesTotal))
	for k, v := range m.responsesTotal {
		rbr[k] = v.Load()
	}

	return MetricsSnapshot{
		QueriesByType:      qbt,
		ResponsesByRCode:   rbr,
		CacheHits:          m.cacheHits.Load(),
		CacheMisses:        m.cacheMisses.Load(),
		CacheEvictions:     m.cacheEvictions.Load(),
		UpstreamQueries:    m.upstreamQueries.Load(),
		UpstreamErrors:     m.upstreamErrors.Load(),
		RateLimited:        m.rateLimited.Load(),
		UptimeSeconds:      time.Since(m.startTime).Seconds(),
		Goroutines:         runtime.NumGoroutine(),
		QueryDurationCount: m.queryDurations.count.Load(),
	}
}

// WriteMetrics writes all metrics in Prometheus text format.
func (m *Metrics) WriteMetrics(w io.Writer) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for qtype, counter := range m.queriesTotal {
		fmt.Fprintf(w, "labyrinth_queries_total{type=%q} %d\n", qtype, counter.Load())
	}
	for rcode, counter := range m.responsesTotal {
		fmt.Fprintf(w, "labyrinth_responses_total{rcode=%q} %d\n", rcode, counter.Load())
	}
	fmt.Fprintf(w, "labyrinth_cache_hits_total %d\n", m.cacheHits.Load())
	fmt.Fprintf(w, "labyrinth_cache_misses_total %d\n", m.cacheMisses.Load())
	fmt.Fprintf(w, "labyrinth_cache_evictions_total %d\n", m.cacheEvictions.Load())
	fmt.Fprintf(w, "labyrinth_upstream_queries_total %d\n", m.upstreamQueries.Load())
	fmt.Fprintf(w, "labyrinth_upstream_errors_total %d\n", m.upstreamErrors.Load())
	fmt.Fprintf(w, "labyrinth_rate_limited_total %d\n", m.rateLimited.Load())
	fmt.Fprintf(w, "labyrinth_uptime_seconds %.0f\n", time.Since(m.startTime).Seconds())
	fmt.Fprintf(w, "labyrinth_goroutines %d\n", runtime.NumGoroutine())

	m.queryDurations.writeTo(w, "labyrinth_query_duration_seconds")
}
