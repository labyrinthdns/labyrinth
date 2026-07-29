package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// RunnerState holds the current state and history for a single runner.
type RunnerState struct {
	Name       string      `json:"name"`
	LastSeen   time.Time   `json:"last_seen"`
	LastResult RunResult   `json:"last_result"`
	Snapshots  []RunResult `json:"snapshots"`
}

// AggregatedSnapshot is a time-series data point aggregating all runners.
type AggregatedSnapshot struct {
	Timestamp    int64   `json:"timestamp"`
	TotalQPS     float64 `json:"total_qps"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	P50LatencyMs float64 `json:"p50_latency_ms"`
	P95LatencyMs float64 `json:"p95_latency_ms"`
	P99LatencyMs float64 `json:"p99_latency_ms"`
	SuccessRate  float64 `json:"success_rate"`
	RunnerCount  int     `json:"runner_count"`
}

// Coordinator aggregates results from multiple runners and serves the dashboard.
type Coordinator struct {
	mu      sync.RWMutex
	runners map[string]*RunnerState
	history []AggregatedSnapshot
}

// NewCoordinator creates a new Coordinator instance.
func NewCoordinator() *Coordinator {
	return &Coordinator{
		runners: make(map[string]*RunnerState),
	}
}

// Serve starts the coordinator HTTP server.
func (c *Coordinator) Serve(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/report", c.handleReport)
	mux.HandleFunc("/api/status", c.handleStatus)
	mux.HandleFunc("/api/timeseries", c.handleTimeseries)
	mux.HandleFunc("/", c.handleDashboard)

	fmt.Printf("Labyrinth DNS Benchmark Coordinator\n")
	fmt.Printf("Dashboard: http://%s\n", resolveAddr(addr))
	fmt.Printf("Waiting for runners to connect...\n\n")

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
}

func resolveAddr(addr string) string {
	if addr[0] == ':' {
		return "localhost" + addr
	}
	return addr
}

func (c *Coordinator) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var result RunResult
	if err := json.Unmarshal(body, &result); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	name := result.RunnerName
	if name == "" {
		name = r.RemoteAddr
	}

	c.mu.Lock()
	state, ok := c.runners[name]
	if !ok {
		state = &RunnerState{Name: name}
		c.runners[name] = state
		fmt.Printf("Runner connected: %s\n", name)
	}
	state.LastSeen = time.Now()
	state.LastResult = result
	// Keep last 300 snapshots per runner (5 minutes at 1/s).
	if len(state.Snapshots) >= 300 {
		state.Snapshots = state.Snapshots[1:]
	}
	state.Snapshots = append(state.Snapshots, result)

	// Build aggregated snapshot.
	snap := c.buildAggregatedSnapshotLocked()
	if len(c.history) >= 600 {
		c.history = c.history[1:]
	}
	c.history = append(c.history, snap)
	c.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok":true}`))
}

func (c *Coordinator) buildAggregatedSnapshotLocked() AggregatedSnapshot {
	snap := AggregatedSnapshot{
		Timestamp:   time.Now().Unix(),
		RunnerCount: len(c.runners),
	}

	if len(c.runners) == 0 {
		return snap
	}

	var totalLatency, totalP50, totalP95, totalP99 float64
	var totalQueries, totalSuccess int64
	activeCount := 0

	for _, rs := range c.runners {
		// Only include runners seen in the last 10 seconds.
		if time.Since(rs.LastSeen) > 10*time.Second {
			continue
		}
		activeCount++
		snap.TotalQPS += rs.LastResult.QPS
		totalLatency += rs.LastResult.AvgLatencyMs
		totalP50 += rs.LastResult.P50LatencyMs
		totalP95 += rs.LastResult.P95LatencyMs
		totalP99 += rs.LastResult.P99LatencyMs
		totalQueries += rs.LastResult.TotalQueries
		totalSuccess += rs.LastResult.SuccessCount
	}

	if activeCount > 0 {
		snap.AvgLatencyMs = totalLatency / float64(activeCount)
		snap.P50LatencyMs = totalP50 / float64(activeCount)
		snap.P95LatencyMs = totalP95 / float64(activeCount)
		snap.P99LatencyMs = totalP99 / float64(activeCount)
		snap.RunnerCount = activeCount
	}
	if totalQueries > 0 {
		snap.SuccessRate = float64(totalSuccess) / float64(totalQueries) * 100
	}

	return snap
}

func (c *Coordinator) handleStatus(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	type statusResponse struct {
		Runners map[string]*RunnerState `json:"runners"`
	}

	resp := statusResponse{Runners: c.runners}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (c *Coordinator) handleTimeseries(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c.history)
}

func (c *Coordinator) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}
