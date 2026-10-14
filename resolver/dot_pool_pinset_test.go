package resolver

import (
	"errors"
	"testing"
)

// TestRFC8310_PoolKeyedByPinset pins that two forward zones pointing at the
// same DoT upstream with different SPKI pinsets never share a session. The
// pool key used to carry only the auth name, so a session authenticated under
// one zone's pins was handed to a zone whose pins never matched the server,
// and that zone's strict policy was silently skipped.
func TestRFC8310_PoolKeyedByPinset(t *testing.T) {
	ca := newTestCA(t)
	cert, pin := ca.issue(t, "dns.internal.example")
	srv := startDoTTestServer(t, cert)
	otherCA := newTestCA(t)
	_, otherPin := otherCA.issue(t, "dns.internal.example")
	r := dotTestResolver(t)

	matching := DoTPolicy{Pins: []string{pin}}
	if _, err := r.queryDoT(srv.addr(), matching, buildTCPQuery(t, 0xC001, "a.example.com")); err != nil {
		t.Fatalf("matching-pin query: %v", err)
	}

	mismatched := DoTPolicy{Pins: []string{otherPin}}
	_, err := r.queryDoT(srv.addr(), mismatched, buildTCPQuery(t, 0xC002, "b.example.com"))
	if !errors.Is(err, errDoTPinMatch) {
		t.Fatalf("zone with a non-matching pin reused another zone's session: err=%v, want %v", err, errDoTPinMatch)
	}
}

// TestRFC8310_PoolKeyIgnoresPinOrder pins that listing the same pinset in a
// different order is the same policy and keeps reusing the session.
func TestRFC8310_PoolKeyIgnoresPinOrder(t *testing.T) {
	ca := newTestCA(t)
	cert, pin := ca.issue(t, "dns.internal.example")
	_, backupPin := ca.issue(t, "backup.internal.example")
	srv := startDoTTestServer(t, cert)
	r := dotTestResolver(t)

	for i, pins := range [][]string{{pin, backupPin}, {backupPin, pin}} {
		if _, err := r.queryDoT(srv.addr(), DoTPolicy{Pins: pins}, buildTCPQuery(t, uint16(0xC100+i), "a.example.com")); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	if got := srv.handshakes.Load(); got != 1 {
		t.Errorf("server performed %d handshakes, want 1: a reordered pinset is the same policy", got)
	}
}
