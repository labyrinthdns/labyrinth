package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := New("example.com", "admin@example.com", dir, false, logger)
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.Domain() != "example.com" {
		t.Fatalf("expected domain example.com, got %s", m.Domain())
	}
}

func TestNew_Staging(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := New("test.example.com", "", dir, true, logger)
	if m.acm.Client == nil {
		t.Fatal("expected staging ACME client to be set")
	}
}

func TestInfo_NoCert(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := New("example.com", "", dir, false, logger)
	info := m.Info()
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if info.Domain != "example.com" {
		t.Fatalf("expected domain example.com, got %s", info.Domain)
	}
	if !info.AutoTLS || !info.ACME {
		t.Fatal("expected AutoTLS and ACME to be true")
	}
	if info.Issuer != "" {
		t.Fatalf("expected empty issuer before handshake, got %s", info.Issuer)
	}
}

func TestInfo_WithCert(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := New("example.com", "", dir, false, logger)

	// Inject a fake certificate
	leaf := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "example.com"},
		Issuer:   pkix.Name{CommonName: "Fake CA", Organization: []string{"FakeOrg"}},
		DNSNames: []string{"example.com", "*.example.com"},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
	}
	m.mu.Lock()
	m.lastCert = leaf
	m.mu.Unlock()

	info := m.Info()
	if info.Issuer != "Fake CA" {
		t.Fatalf("expected issuer Fake CA, got %s", info.Issuer)
	}
	if info.Subject != "example.com" {
		t.Fatalf("expected subject example.com, got %s", info.Subject)
	}
	if len(info.DNSNames) != 2 {
		t.Fatalf("expected 2 DNS names, got %d", len(info.DNSNames))
	}
}

func TestForceRenew(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := New("example.com", "", dir, false, logger)

	// Inject a cert
	m.mu.Lock()
	m.lastCert = &x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}
	m.mu.Unlock()

	if err := m.ForceRenew(context.Background()); err != nil {
		t.Fatalf("ForceRenew error: %v", err)
	}

	info := m.Info()
	if info.Issuer != "" {
		t.Fatal("expected cert cleared after ForceRenew")
	}
}

func TestTLSConfig(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := New("example.com", "", dir, false, logger)
	tlsCfg := m.TLSConfig()
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatal("expected MinVersion TLS 1.2")
	}
	if tlsCfg.GetCertificate == nil {
		t.Fatal("expected GetCertificate to be set")
	}
}

func TestHTTPHandler(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := New("example.com", "", dir, false, logger)
	h := m.HTTPHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil HTTP handler")
	}
}

func TestInfoFromStatic(t *testing.T) {
	// Generate a self-signed cert
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "static.example.com", Organization: []string{"Test Corp"}},
		DNSNames:     []string{"static.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certFile := filepath.Join(t.TempDir(), "cert.pem")
	keyFile := filepath.Join(t.TempDir(), "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(certFile, certPEM, 0644)
	os.WriteFile(keyFile, keyPEM, 0644)

	info, err := InfoFromStatic(certFile, keyFile)
	if err != nil {
		t.Fatalf("InfoFromStatic error: %v", err)
	}
	if info.Domain != "static.example.com" {
		t.Fatalf("expected domain static.example.com, got %s", info.Domain)
	}
	if info.AutoTLS || info.ACME {
		t.Fatal("expected AutoTLS and ACME to be false for static cert")
	}
	if info.Issuer != "static.example.com" {
		t.Fatalf("expected self-signed issuer, got %s", info.Issuer)
	}
}

func TestInfoFromStatic_InvalidFile(t *testing.T) {
	_, err := InfoFromStatic("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestCertIssuer(t *testing.T) {
	tests := []struct {
		name   string
		leaf   *x509.Certificate
		expect string
	}{
		{"common name", &x509.Certificate{Issuer: pkix.Name{CommonName: "CA"}}, "CA"},
		{"org only", &x509.Certificate{Issuer: pkix.Name{Organization: []string{"Org"}}}, "Org"},
		{"empty", &x509.Certificate{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certIssuer(tt.leaf)
			if got != tt.expect {
				t.Fatalf("expected %q, got %q", tt.expect, got)
			}
		})
	}
}
