package certmanager

import (
	"context"
	"crypto/x509"
	"errors"
	"golang.org/x/crypto/acme/autocert"
	"log/slog"
	"testing"
)

type renewFailureCache struct {
	err     error
	failKey string
	deleted []string
}

func (c *renewFailureCache) Get(context.Context, string) ([]byte, error) {
	return nil, autocert.ErrCacheMiss
}
func (c *renewFailureCache) Put(context.Context, string, []byte) error { return nil }
func (c *renewFailureCache) Delete(ctx context.Context, key string) error {
	c.deleted = append(c.deleted, key)
	if key == c.failKey {
		return c.err
	}
	return nil
}
func TestForceRenewPropagatesCacheErrors(t *testing.T) {
	failed := false
	for _, bad := range []bool{false, true} {
		cache := &renewFailureCache{}
		sentinel := errors.New("injected delete error")
		if bad {
			cache.err = sentinel
			cache.failKey = "example.com"
		}
		leaf := &x509.Certificate{DNSNames: []string{"example.com"}}
		m := &Manager{acm: &autocert.Manager{Cache: cache}, domain: "example.com", logger: slog.Default(), lastCert: leaf}
		err := m.ForceRenew(context.Background())
		t.Logf("delete failure=%v EXPECTED: error=%v status preserved=%v ACTUAL: error=%v status preserved=%v", bad, bad, bad, err != nil, m.lastCert == leaf)
		if bad {
			if !errors.Is(err, sentinel) || m.lastCert != leaf {
				failed = true
			}
		} else if err != nil || m.lastCert != nil {
			t.Fatal("unaffected successful-delete control failed")
		}
	}
	if failed {
		t.Fatal("PROBLEM CONFIRMED")
	}
	for _, key := range []string{"example.com+rsa", "example.com+token"} {
		cache := &renewFailureCache{err: context.Canceled, failKey: key}
		leaf := &x509.Certificate{DNSNames: []string{"example.com"}}
		m := &Manager{acm: &autocert.Manager{Cache: cache}, domain: "example.com", logger: slog.Default(), lastCert: leaf}
		if err := m.ForceRenew(context.Background()); !errors.Is(err, context.Canceled) || m.lastCert != leaf {
			t.Fatalf("failure at %s not propagated / state lost", key)
		}
	}
	m := New("example.com", "", t.TempDir(), false, slog.Default())
	if err := m.ForceRenew(context.Background()); err != nil {
		t.Fatalf("empty-cache edge: %v", err)
	}
	t.Log("FIX VERIFIED")
}
