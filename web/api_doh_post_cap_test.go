package web

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoHPostRejectsOversizedBody(t *testing.T) {
	srv := testDoHServer(t)

	tests := []struct {
		name          string
		body          io.Reader
		contentLength int64
	}{
		{
			name:          "declared length",
			body:          bytes.NewReader(make([]byte, dohMaxPostBodyBytes+1)),
			contentLength: dohMaxPostBodyBytes + 1,
		},
		{
			name:          "chunked unknown length",
			body:          io.LimitReader(&endlessZeroReader{}, dohMaxPostBodyBytes+1),
			contentLength: -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/dns-query", tc.body)
			req.Header.Set("Content-Type", "application/dns-message")
			req.ContentLength = tc.contentLength
			rec := httptest.NewRecorder()

			srv.handleDoH(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413; body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

func TestDoHPostAcceptsBodyAtCap(t *testing.T) {
	srv := testDoHServer(t)
	body := make([]byte, dohMaxPostBodyBytes)
	copy(body, buildDNSQuery(0x1234))
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()

	srv.handleDoH(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

type endlessZeroReader struct{}

func (*endlessZeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
