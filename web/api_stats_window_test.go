package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTimeSeries_RejectsNegativeWindow pins the input gate added in
// v0.7.39 on the /api/stats/timeseries endpoint. time.ParseDuration
// happily returns negative or zero durations from inputs like
// "-5m" or "0s"; the downstream snapshot path treats those as
// "no data" or produces empty buckets — leaking the impression
// that the resolver has no traffic. A clean 400 is better than a
// misleading empty 200.
func TestTimeSeries_RejectsNegativeWindow(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Load().Web.Auth.Username = ""
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=-5m", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (negative window must be rejected)", w.Code)
	}
}

// TestTimeSeries_RejectsZeroWindow — companion negative input.
func TestTimeSeries_RejectsZeroWindow(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Load().Web.Auth.Username = ""
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=0s", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (zero window must be rejected)", w.Code)
	}
}

// TestTimeSeries_RejectsNegativeInterval pins the same gate on the
// `interval` parameter. A negative interval passes through to the
// aggregator where the int64 seconds value goes negative; downstream
// math (modular arithmetic for bucket alignment) misbehaves on
// negative values.
func TestTimeSeries_RejectsNegativeInterval(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Load().Web.Auth.Username = ""
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=5m&interval=-1m", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400 (negative interval must be rejected)", w.Code)
	}
}

// TestTimeSeries_AcceptsValidWindow — negative control: a sane
// `5m` window must still succeed. The gate must reject ONLY
// non-positive inputs.
func TestTimeSeries_AcceptsValidWindow(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Load().Web.Auth.Username = ""
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/api/stats/timeseries?window=5m", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d want 200 for a valid 5m window", w.Code)
	}
}
