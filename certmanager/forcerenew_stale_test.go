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
	"io"
	"log/slog"
	"math/big"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// gatedCertCache serves one cached cert; the first Get for gateKey blocks until
// released, so a handshake can be held in flight across ForceRenew.
type gatedCertCache struct {
	mu      sync.Mutex
	data    map[string][]byte
	gateKey string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *gatedCertCache) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	b, ok := c.data[key]
	c.mu.Unlock()
	if !ok {
		return nil, autocert.ErrCacheMiss
	}
	if key == c.gateKey && c.entered != nil {
		c.once.Do(func() { close(c.entered); <-c.release })
	}
	return b, nil
}
func (c *gatedCertCache) Put(_ context.Context, key string, d []byte) error {
	c.mu.Lock()
	c.data[key] = d
	c.mu.Unlock()
	return nil
}
func (c *gatedCertCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	delete(c.data, key)
	c.mu.Unlock()
	return nil
}

func frEntry(t *testing.T, domain string) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(400 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

func frHello(domain string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: domain, SupportedVersions: []uint16{tls.VersionTLS12},
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, SupportedCurves: []tls.CurveID{tls.CurveP256},
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}
}

func frManager(t *testing.T, cache *gatedCertCache, domain string) *Manager {
	m := New(domain, "a@example.test", t.TempDir(), false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.acm.Cache = cache
	return m
}

// TestForceRenew_StaleHandshakeDoesNotRepublish pins that a handshake started
// against the pre-renewal autocert manager cannot restore lastCert after
// ForceRenew cleared it.
func TestForceRenew_StaleHandshakeDoesNotRepublish(t *testing.T) {
	const domain = "example.test"
	entry := frEntry(t, domain)

	t.Run("control: un-raced handshake publishes", func(t *testing.T) {
		c := &gatedCertCache{data: map[string][]byte{domain: entry}, gateKey: domain}
		m := frManager(t, c, domain)
		if _, err := m.TLSConfig().GetCertificate(frHello(domain)); err != nil {
			t.Fatal(err)
		}
		if m.lastCert == nil {
			t.Fatal("lastCert not set by handshake")
		}
	})

	t.Run("stale handshake dropped, later handshake publishes", func(t *testing.T) {
		c := &gatedCertCache{data: map[string][]byte{domain: entry}, gateKey: domain, entered: make(chan struct{}), release: make(chan struct{})}
		m := frManager(t, c, domain)
		cfg := m.TLSConfig()
		done := make(chan error, 1)
		go func() { _, err := cfg.GetCertificate(frHello(domain)); done <- err }()
		<-c.entered
		if err := m.ForceRenew(context.Background()); err != nil {
			t.Fatal(err)
		}
		close(c.release)
		if err := <-done; err != nil {
			t.Fatalf("stale handshake: %v", err)
		}
		m.mu.RLock()
		stale := m.lastCert != nil
		m.mu.RUnlock()
		if stale {
			t.Fatal("stale handshake republished the pre-renewal leaf")
		}
		if info := m.Info(); info.Issuer != "" {
			t.Fatalf("Info reports a certificate after ForceRenew: %+v", info)
		}

		// A handshake on the renewed manager still publishes.
		c.mu.Lock()
		c.data[domain] = entry
		c.mu.Unlock()
		if _, err := cfg.GetCertificate(frHello(domain)); err != nil {
			t.Fatal(err)
		}
		if m.Info().Issuer == "" {
			t.Fatal("post-renewal handshake did not publish")
		}
	})
}
