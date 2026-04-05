// Package certmanager provides automatic TLS certificate provisioning via
// Let's Encrypt (ACME). It wraps golang.org/x/crypto/acme/autocert and
// exposes helpers for the web server and DoT server to share certificates.
package certmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// CertInfo describes the currently active certificate.
type CertInfo struct {
	Domain    string    `json:"domain"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names"`
	AutoTLS   bool      `json:"auto_tls"`
	ACME      bool      `json:"acme"`
}

// Manager wraps autocert.Manager and provides certificate status inspection.
type Manager struct {
	acm    *autocert.Manager
	domain string
	email  string
	logger *slog.Logger

	mu       sync.RWMutex
	lastCert *x509.Certificate
}

// New creates a new certificate manager.
// cacheDir is the directory where certs are stored on disk.
// If staging is true, the Let's Encrypt staging endpoint is used (for testing).
func New(domain, email, cacheDir string, staging bool, logger *slog.Logger) *Manager {
	acm := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(domain),
		Email:      email,
	}

	if staging {
		acm.Client = &acme.Client{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		}
	}

	return &Manager{
		acm:    acm,
		domain: domain,
		email:  email,
		logger: logger,
	}
}

// TLSConfig returns a *tls.Config that automatically provisions certificates.
// Use this for both the web server and DoT server.
func (m *Manager) TLSConfig() *tls.Config {
	tlsCfg := m.acm.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12

	// Wrap GetCertificate to capture cert info for status reporting.
	origGetCert := tlsCfg.GetCertificate
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := origGetCert(hello)
		if err != nil {
			return nil, err
		}
		if cert != nil && cert.Leaf != nil {
			m.mu.Lock()
			m.lastCert = cert.Leaf
			m.mu.Unlock()
		} else if cert != nil && len(cert.Certificate) > 0 {
			if parsed, parseErr := x509.ParseCertificate(cert.Certificate[0]); parseErr == nil {
				m.mu.Lock()
				m.lastCert = parsed
				m.mu.Unlock()
			}
		}
		return cert, nil
	}

	return tlsCfg
}

// HTTPHandler returns an http.Handler that serves ACME HTTP-01 challenges
// and redirects all other traffic to HTTPS. Use this on port 80.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.acm.HTTPHandler(fallback)
}

// Info returns information about the currently active certificate.
func (m *Manager) Info() *CertInfo {
	m.mu.RLock()
	leaf := m.lastCert
	m.mu.RUnlock()

	if leaf == nil {
		return &CertInfo{
			Domain:  m.domain,
			AutoTLS: true,
			ACME:    true,
		}
	}

	return &CertInfo{
		Domain:    m.domain,
		Issuer:    certIssuer(leaf),
		Subject:   leaf.Subject.CommonName,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		DNSNames:  leaf.DNSNames,
		AutoTLS:   true,
		ACME:      true,
	}
}

// Domain returns the managed domain name.
func (m *Manager) Domain() string {
	return m.domain
}

// ForceRenew removes the cached certificate so autocert provisions a new one
// on the next TLS handshake.
func (m *Manager) ForceRenew(ctx context.Context) error {
	cache := m.acm.Cache

	// autocert caches certs under the domain name and domain+rsa keys.
	_ = cache.Delete(ctx, m.domain)
	_ = cache.Delete(ctx, m.domain+"+rsa")
	_ = cache.Delete(ctx, m.domain+"+token")

	m.mu.Lock()
	m.lastCert = nil
	m.mu.Unlock()

	m.logger.Info("auto-tls: cached certificate removed, will re-provision on next handshake", "domain", m.domain)
	return nil
}

// InfoFromStatic returns CertInfo by reading a static cert+key file pair.
func InfoFromStatic(certFile, keyFile string) (*CertInfo, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", certFile)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return &CertInfo{
		Domain:    leaf.Subject.CommonName,
		Issuer:    certIssuer(leaf),
		Subject:   leaf.Subject.CommonName,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		DNSNames:  leaf.DNSNames,
		AutoTLS:   false,
		ACME:      false,
	}, nil
}

func certIssuer(leaf *x509.Certificate) string {
	if leaf.Issuer.CommonName != "" {
		return leaf.Issuer.CommonName
	}
	if len(leaf.Issuer.Organization) > 0 {
		return leaf.Issuer.Organization[0]
	}
	return "unknown"
}
