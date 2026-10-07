package certmanager

import (
	"crypto/x509"
	"testing"
)

func TestInfoSnapshotsOwnDNSNames(t *testing.T) {
	leaf := &x509.Certificate{DNSNames: []string{"original.example"}}
	m := &Manager{domain: "original.example", lastCert: leaf}
	snapshot := m.Info()
	sibling := m.Info()
	snapshot.Domain = "caller-edit"
	if m.Info().Domain != "original.example" {
		t.Fatal("struct-copy control failed")
	}
	gate, done := make(chan struct{}), make(chan struct{})
	go func() { <-gate; snapshot.DNSNames[0] = "caller-edit"; close(done) }()
	m.mu.Lock()
	m.lastCert = &x509.Certificate{DNSNames: []string{"replacement.example"}}
	m.mu.Unlock()
	close(gate)
	<-done
	t.Logf("EXPECTED: old leaf/sibling=original.example current=replacement.example ACTUAL: old leaf=%s sibling=%s current=%s", leaf.DNSNames[0], sibling.DNSNames[0], m.Info().DNSNames[0])
	if leaf.DNSNames[0] != "original.example" || sibling.DNSNames[0] != "original.example" {
		t.Fatal("PROBLEM CONFIRMED")
	}
	for _, names := range [][]string{nil, {}, {"a.example", "b.example"}} {
		m.lastCert = &x509.Certificate{DNSNames: names}
		first, second := m.Info(), m.Info()
		if (first.DNSNames == nil) != (names == nil) || len(first.DNSNames) != len(names) {
			t.Fatal("empty/nil edge failed")
		}
		if len(first.DNSNames) > 0 {
			first.DNSNames[0] = "mutated"
			if second.DNSNames[0] != names[0] || names[0] != "a.example" {
				t.Fatal("repeated info edge failed")
			}
		}
	}
	m.lastCert = nil
	if m.Info().DNSNames != nil {
		t.Fatal("no-cert edge failed")
	}
	t.Log("FIX VERIFIED")
}
