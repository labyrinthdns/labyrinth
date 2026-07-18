package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHTTP3ServerDisables0RTT(t *testing.T) {
	h3 := newHTTP3Server("127.0.0.1:8443", http.NotFoundHandler())
	if h3.QUICConfig == nil {
		t.Fatal("HTTP/3 server has no explicit QUIC configuration")
	}
	if h3.QUICConfig.Allow0RTT {
		t.Fatal("HTTP/3 server must reject replayable 0-RTT application data")
	}
}

func TestRejectCrossOriginCookieMutations(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := srv.rejectCrossOriginCookieMutations(next)

	tests := []struct {
		name       string
		method     string
		path       string
		origin     string
		fetchSite  string
		bearer     bool
		cookie     bool
		tls        bool
		wantStatus int
	}{
		{
			name:       "cross-origin cookie mutation rejected",
			method:     http.MethodPost,
			path:       "/api/cache/flush",
			origin:     "https://attacker.example",
			cookie:     true,
			tls:        true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing origin rejected even with same-origin fetch metadata",
			method:     http.MethodDelete,
			path:       "/api/cache/entry",
			fetchSite:  "same-origin",
			cookie:     true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "same origin accepted",
			method:     http.MethodPut,
			path:       "/api/config/raw",
			origin:     "https://admin.example",
			cookie:     true,
			tls:        true,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "cross-site fetch metadata overrides matching origin",
			method:     http.MethodPost,
			path:       "/api/cache/flush",
			origin:     "http://admin.example",
			fetchSite:  "cross-site",
			cookie:     true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cookie takes precedence over bearer and is rejected",
			method:     http.MethodPost,
			path:       "/api/cache/flush",
			origin:     "https://attacker.example",
			bearer:     true,
			cookie:     true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "bearer-only client exempt",
			method:     http.MethodPost,
			path:       "/api/cache/flush",
			origin:     "https://attacker.example",
			bearer:     true,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "safe cookie request accepted",
			method:     http.MethodGet,
			path:       "/api/stats",
			origin:     "https://attacker.example",
			cookie:     true,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "non API mutation unaffected",
			method:     http.MethodPost,
			path:       "/dns-query",
			origin:     "https://attacker.example",
			cookie:     true,
			wantStatus: http.StatusNoContent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://admin.example"+tc.path, nil)
			req.Host = "admin.example"
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tc.cookie {
				req.AddCookie(&http.Cookie{Name: authCookieName, Value: "token"})
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			if tc.bearer {
				req.Header.Set("Authorization", "Bearer api-token")
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestRejectCrossOriginCookieMutationsNoAuthPassesThrough(t *testing.T) {
	srv := testAdminServer(t)
	handler := srv.rejectCrossOriginCookieMutations(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://admin.example/api/cache/flush", nil)
	req.AddCookie(&http.Cookie{Name: authCookieName, Value: "irrelevant"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want pass-through 204 when authentication is disabled", rec.Code)
	}
}
