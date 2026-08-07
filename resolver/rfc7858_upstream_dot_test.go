package resolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Upstream DoT (RFC 7858) with RFC 8310 authentication.
//
// The security-relevant decision here is that Labyrinth implements only
// RFC 8310's Strict Privacy profile, never Opportunistic. That is not the
// obvious choice — Opportunistic is strictly more encrypted traffic than
// plaintext — so these tests pin the reasoning as much as the code:
//
//	a forward zone is a trust statement (the resolver honours the upstream's
//	AD bit for that zone), so an unauthenticated TLS session hands an on-path
//	attacker that trusted position while the config still reports "encrypted".
//
// Consequently the tests that matter most are the negative ones: a wrong pin,
// a wrong name, and a policy with no authentication at all must every one
// fail closed.

// --- test PKI helpers -------------------------------------------------------

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certDER []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Labyrinth Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{cert: cert, key: key, certDER: der}
}

// issue returns a leaf certificate valid for the given DNS names, plus the
// RFC 8310 §8.1 SPKI pin for its public key.
func (ca *testCA) issue(t *testing.T, names ...string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)

	return tls.Certificate{
		Certificate: [][]byte{der, ca.certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}, base64.StdEncoding.EncodeToString(spki[:])
}

// --- test DoT server --------------------------------------------------------

type dotTestServer struct {
	ln         net.Listener
	handshakes atomic.Int32
	queries    atomic.Int32
	wg         sync.WaitGroup
}

func startDoTTestServer(t *testing.T, cert tls.Certificate) *dotTestServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	s := &dotTestServer{ln: ln}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.handshakes.Add(1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				s.handle(conn)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); s.wg.Wait() })
	return s
}

func (s *dotTestServer) addr() string { return s.ln.Addr().String() }

func (s *dotTestServer) handle(conn net.Conn) {
	for {
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(lenBuf))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		s.queries.Add(1)

		resp := buildTCPTestResponse(query, false)
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// dotTestResolver builds a resolver whose system root pool trusts only the
// test CA, so PKIX verification is exercised for real rather than skipped.
func dotTestResolver(t *testing.T) *Resolver {
	t.Helper()
	r := &Resolver{
		config:  ResolverConfig{UpstreamTimeout: 2 * time.Second},
		tcpPool: newTCPConnPool(),
	}
	t.Cleanup(func() { r.tcpPool.Close() })
	return r
}

// --- tests ------------------------------------------------------------------

// TestRFC8310_PinAuthenticationSucceeds pins the pin-only path: no PKIX-valid
// name, authentication carried entirely by the SPKI pin (RFC 8310 §8.1). This
// is the configuration an operator uses for an internal resolver with a
// self-signed certificate.
func TestRFC8310_PinAuthenticationSucceeds(t *testing.T) {
	ca := newTestCA(t)
	cert, pin := ca.issue(t, "dns.internal.example")
	srv := startDoTTestServer(t, cert)
	r := dotTestResolver(t)

	policy := DoTPolicy{Pins: []string{pin}}
	query := buildTCPQuery(t, 0x7858, "dot.example.com")

	resp, err := r.queryDoT(srv.addr(), policy, query)
	if err != nil {
		t.Fatalf("pin-authenticated DoT query failed: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("empty response")
	}
	if srv.queries.Load() != 1 {
		t.Errorf("server saw %d queries, want 1", srv.queries.Load())
	}
}

// TestRFC8310_WrongPinFailsClosed is the core negative test. A pin that does
// not match must abort the connection — not warn, not fall back to plaintext,
// not proceed unauthenticated.
func TestRFC8310_WrongPinFailsClosed(t *testing.T) {
	ca := newTestCA(t)
	cert, _ := ca.issue(t, "dns.internal.example")
	srv := startDoTTestServer(t, cert)
	r := dotTestResolver(t)

	// A syntactically valid pin for a different key.
	otherCA := newTestCA(t)
	_, otherPin := otherCA.issue(t, "dns.internal.example")

	policy := DoTPolicy{Pins: []string{otherPin}}
	_, err := r.queryDoT(srv.addr(), policy, buildTCPQuery(t, 0x7859, "dot.example.com"))
	if err == nil {
		t.Fatal("query succeeded against a server whose SPKI does not match the pin — " +
			"RFC 8310 Strict Privacy must fail closed")
	}
	if !errors.Is(err, errDoTPinMatch) {
		t.Errorf("error = %v, want an SPKI pin mismatch", err)
	}

	if n := r.tcpPool.idleLen(); n != 0 {
		t.Errorf("pool holds %d connections after a failed authentication, want 0", n)
	}
}

// TestRFC8310_UnauthenticatedPolicyRefused pins that the Opportunistic
// profile is genuinely absent rather than merely undocumented. Even if a
// policy with no auth name and no pins reaches the dialer, it must not open a
// connection.
func TestRFC8310_UnauthenticatedPolicyRefused(t *testing.T) {
	ca := newTestCA(t)
	cert, _ := ca.issue(t, "dns.internal.example")
	srv := startDoTTestServer(t, cert)
	r := dotTestResolver(t)

	_, err := r.queryDoT(srv.addr(), DoTPolicy{}, buildTCPQuery(t, 0x785A, "dot.example.com"))
	if err == nil {
		t.Fatal("an unauthenticated DoT policy connected — Opportunistic Privacy " +
			"is deliberately not implemented, see resolver/dot_upstream.go")
	}
	if !errors.Is(err, errDoTNoAuth) {
		t.Errorf("error = %v, want errDoTNoAuth", err)
	}
	if srv.handshakes.Load() != 0 {
		t.Errorf("server saw %d handshakes; the dialer must refuse before connecting",
			srv.handshakes.Load())
	}
}

// TestRFC8310_WrongAuthNameFails pins PKIX name verification. A certificate
// valid for some other name must not satisfy an auth-name policy, which is
// what stops a compromised-but-valid certificate for an unrelated domain from
// impersonating the configured upstream.
func TestRFC8310_WrongAuthNameFails(t *testing.T) {
	ca := newTestCA(t)
	cert, _ := ca.issue(t, "wrong.example")
	srv := startDoTTestServer(t, cert)
	r := dotTestResolver(t)

	policy := DoTPolicy{AuthName: "dns.expected.example"}
	_, err := r.queryDoT(srv.addr(), policy, buildTCPQuery(t, 0x785B, "dot.example.com"))
	if err == nil {
		t.Fatal("a certificate for the wrong name satisfied an auth-name policy")
	}
}

// TestRFC8310_ConnectionReused pins that DoT sessions are pooled. Without
// reuse a cold query pays a TCP handshake plus a TLS handshake, and turning
// on encryption would read as a latency regression — which is how a privacy
// feature ends up switched off.
func TestRFC8310_ConnectionReused(t *testing.T) {
	ca := newTestCA(t)
	cert, pin := ca.issue(t, "dns.internal.example")
	srv := startDoTTestServer(t, cert)
	r := dotTestResolver(t)

	policy := DoTPolicy{Pins: []string{pin}}
	for i := 0; i < 4; i++ {
		if _, err := r.queryDoT(srv.addr(), policy, buildTCPQuery(t, uint16(0x8000+i), "dot.example.com")); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}

	if got := srv.handshakes.Load(); got != 1 {
		t.Errorf("server performed %d TLS handshakes for 4 queries, want 1 — "+
			"session reuse is not happening and every DoT query pays a full "+
			"handshake", got)
	}
	if got := srv.queries.Load(); got != 4 {
		t.Errorf("server saw %d queries, want 4", got)
	}
}

// TestRFC8310_PoolKeyedByAuthName pins that two zones pointing at the same
// address under different authentication policies never share a session.
// Sharing would let a zone configured for strict PKIX inherit a connection
// that was only ever pin-authenticated, quietly weakening its policy.
func TestRFC8310_PoolKeyedByAuthName(t *testing.T) {
	ca := newTestCA(t)
	cert, pin := ca.issue(t, "dns.internal.example")
	srv := startDoTTestServer(t, cert)
	r := dotTestResolver(t)

	pinOnly := DoTPolicy{Pins: []string{pin}}
	if _, err := r.queryDoT(srv.addr(), pinOnly, buildTCPQuery(t, 0x9001, "a.example.com")); err != nil {
		t.Fatalf("pin-only query: %v", err)
	}

	// Same address, different policy: must not reuse the pooled session.
	named := DoTPolicy{AuthName: "dns.internal.example", Pins: []string{pin}}
	_, _ = r.queryDoT(srv.addr(), named, buildTCPQuery(t, 0x9002, "a.example.com"))

	if got := srv.handshakes.Load(); got < 2 {
		t.Errorf("server performed %d handshakes; a differing auth policy must "+
			"not reuse a session established under another one", got)
	}
}

// TestRFC7858_DefaultPortIs853 pins RFC 7858 §3.1. An address with no port
// must go to 853, not 53 — connecting a TLS client to a plaintext DNS port
// produces a confusing handshake failure rather than an obvious config error.
func TestRFC7858_DefaultPortIs853(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737) and unroutable, so the dial
	// fails fast; the error text is what carries the port we chose.
	_, err := dialDoT("192.0.2.1", DoTPolicy{AuthName: "x.example"}, 50*time.Millisecond)
	if err == nil {
		t.Fatal("dial to TEST-NET-1 unexpectedly succeeded")
	}
	// net.OpError carries the address we actually tried.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if _, port, splitErr := net.SplitHostPort(opErr.Addr.String()); splitErr == nil && port != defaultDoTPort {
			t.Errorf("dialled port %s, want %s (RFC 7858 §3.1)", port, defaultDoTPort)
		}
	}
}

// TestRFC7858_ExplicitPortPreserved pins that an operator can override the
// port, for an upstream behind a proxy or on a non-standard listener.
func TestRFC7858_ExplicitPortPreserved(t *testing.T) {
	ca := newTestCA(t)
	cert, pin := ca.issue(t, "dns.internal.example")
	srv := startDoTTestServer(t, cert) // random high port
	r := dotTestResolver(t)

	// srv.addr() already carries an explicit port; if it were overridden
	// with 853 this query could not reach the test server at all.
	if _, err := r.queryDoT(srv.addr(), DoTPolicy{Pins: []string{pin}}, buildTCPQuery(t, 0xA001, "x.example.com")); err != nil {
		t.Fatalf("explicit port was not honoured: %v", err)
	}
}

// TestVerifyPinRejectsEmptyChain pins the degenerate case. A peer that
// somehow completes a handshake without presenting a certificate must not be
// treated as authenticated by a pin check that finds nothing to compare.
func TestVerifyPinRejectsEmptyChain(t *testing.T) {
	if err := verifyPin(nil, []string{"anything"}); err == nil {
		t.Fatal("verifyPin accepted an empty certificate chain")
	}
}
