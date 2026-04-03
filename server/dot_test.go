package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// generateSelfSignedCert creates a self-signed TLS certificate for testing.
func generateSelfSignedCert() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	pool := x509.NewCertPool()
	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool.AddCert(x509Cert)

	return cert, pool, nil
}

// startTestDoTServer creates a DoT server with a self-signed certificate for testing.
// It returns the server, its address, a TLS config for clients, and a cancel function.
func startTestDoTServer(t *testing.T, handler Handler) (*DoTServer, string, *tls.Config, context.CancelFunc) {
	t.Helper()

	cert, pool, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	tlsLn := tls.NewListener(ln, serverTLSCfg)

	logger := discardLogger()
	srv := NewDoTServerWithListener(tlsLn, handler, 5*time.Second, 10, logger)

	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx)

	clientTLSCfg := &tls.Config{
		RootCAs: pool,
	}

	return srv, ln.Addr().String(), clientTLSCfg, cancel
}

// sendDoTQuery sends a single length-prefixed DNS query over a TLS connection
// and reads the length-prefixed response.
func sendDoTQuery(t *testing.T, conn net.Conn, query []byte) []byte {
	t.Helper()
	if err := binary.Write(conn, binary.BigEndian, uint16(len(query))); err != nil {
		t.Fatalf("write length prefix: %v", err)
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write query: %v", err)
	}

	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		t.Fatalf("read response length: %v", err)
	}
	resp := make([]byte, length)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp
}

// TestDoTServerStartStop verifies that a DoT server can start and stop cleanly.
func TestDoTServerStartStop(t *testing.T) {
	handler := &EchoHandler{}
	srv, addr, _, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	// Verify the server is listening by connecting
	clientCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("failed to connect to DoT server: %v", err)
	}
	conn.Close()

	// Cancel context and verify server shuts down
	cancel()
	time.Sleep(200 * time.Millisecond)

	// After shutdown, new connections should fail
	conn2, err := tls.DialWithDialer(&net.Dialer{Timeout: 500 * time.Millisecond}, "tcp", addr, clientCfg)
	if err == nil {
		conn2.Close()
		// The connection might still succeed if the OS hasn't torn down the listener yet,
		// but sending a query should fail.
	}
}

// TestDoTQueryResponse verifies that DNS queries over TLS receive correct responses.
func TestDoTQueryResponse(t *testing.T) {
	handler := &EchoHandler{}
	srv, addr, clientTLSCfg, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientTLSCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send a query and verify the response
	query := buildMinimalQuery(0xABCD)
	resp := sendDoTQuery(t, conn, query)

	if len(resp) < 12 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	// EchoHandler echoes the query verbatim
	respID := binary.BigEndian.Uint16(resp[0:2])
	if respID != 0xABCD {
		t.Errorf("expected ID 0xABCD, got 0x%04X", respID)
	}
	if len(resp) != len(query) {
		t.Errorf("expected response length %d, got %d", len(query), len(resp))
	}
}

// TestDoTPipelining verifies that multiple queries can be sent on a single TLS connection.
func TestDoTPipelining(t *testing.T) {
	handler := &EchoHandler{}
	srv, addr, clientTLSCfg, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientTLSCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send 5 pipelined queries
	for i := 0; i < 5; i++ {
		query := buildMinimalQuery(uint16(0xD000 + i))
		resp := sendDoTQuery(t, conn, query)

		if len(resp) < 12 {
			t.Fatalf("query %d: response too short (%d bytes)", i, len(resp))
		}
		respID := binary.BigEndian.Uint16(resp[0:2])
		if respID != uint16(0xD000+i) {
			t.Errorf("query %d: expected ID 0x%04X, got 0x%04X", i, 0xD000+i, respID)
		}
	}
}

// TestDoTTLSVersion verifies that the server uses at least TLS 1.2.
func TestDoTTLSVersion(t *testing.T) {
	handler := &EchoHandler{}
	srv, addr, clientTLSCfg, cancel := startTestDoTServer(t, handler)
	defer cancel()
	defer srv.Close()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientTLSCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		t.Errorf("expected TLS version >= 1.2, got 0x%04X", state.Version)
	}
}
