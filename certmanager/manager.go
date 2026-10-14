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
	"slices"
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
	// acm is replaced by ForceRenew (under mu): autocert keeps issued
	// certificates in an in-memory map with no eviction API, so a fresh
	// manager is the only way to stop serving the old certificate.
	acm    *autocert.Manager
	domain string
	email  string
	logger *slog.Logger

	mu       sync.RWMutex
	lastCert *x509.Certificate
}

// current returns the autocert manager in use.
func (m *Manager) current() *autocert.Manager {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.acm
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
	tlsCfg := m.current().TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12

	// Wrap GetCertificate to capture cert info for status reporting. It
	// resolves the autocert manager per handshake so a ForceRenew takes
	// effect on listeners that were configured before it.
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := m.current().GetCertificate(hello)
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
	// Resolved per request, like GetCertificate: HTTP-01 tokens live in the
	// autocert manager that placed the order, which is the current one.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.current().HTTPHandler(fallback).ServeHTTP(w, r)
	})
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
		DNSNames:  slices.Clone(leaf.DNSNames),
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
	cache := m.current().Cache

	// autocert caches certs under the domain name and domain+rsa keys.
	for _, key := range []string{m.domain, m.domain + "+rsa", m.domain + "+token"} {
		if err := cache.Delete(ctx, key); err != nil {
			return fmt.Errorf("delete cached certificate %q: %w", key, err)
		}
	}

	// Deleting the disk cache alone changes nothing: autocert serves the
	// certificate from its in-memory state until renewal is due. A manager
	// with the same configuration and empty state provisions anew on the
	// next handshake.
	m.mu.Lock()
	m.acm = freshAutocert(m.acm)
	m.lastCert = nil
	m.mu.Unlock()

	m.logger.Info("auto-tls: cached certificate removed, will re-provision on next handshake", "domain", m.domain)
	return nil
}

// freshAutocert returns an autocert manager with old's configuration and no
// in-memory certificates. The ACME client is recreated rather than shared so
// the two managers never contend over one client's account state.
func freshAutocert(old *autocert.Manager) *autocert.Manager {
	acm := &autocert.Manager{
		Prompt:                 old.Prompt,
		Cache:                  old.Cache,
		HostPolicy:             old.HostPolicy,
		RenewBefore:            old.RenewBefore,
		Email:                  old.Email,
		ExtraExtensions:        old.ExtraExtensions,
		ExternalAccountBinding: old.ExternalAccountBinding,
	}
	if old.Client != nil {
		acm.Client = &acme.Client{DirectoryURL: old.Client.DirectoryURL}
	}
	return acm
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
