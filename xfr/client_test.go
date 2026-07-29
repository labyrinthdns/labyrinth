package xfr

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// startXFRMock starts a mock XFR server that serves a simple zone.
// It returns the server address and a close function.
func startXFRMock(t *testing.T, zone string, records []dns.ResourceRecord, useTLS bool) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Build the AXFR response stream — two messages:
	// 1. First message: SOA in answer (opening marker)
	// 2. Second message: all records (with SOA closing marker)
	soa := dns.ResourceRecord{
		Name:  zone,
		Type:  dns.TypeSOA,
		Class: dns.ClassIN,
		TTL:   86400,
		RData: buildSOARDATA("ns1."+zone, "admin."+zone, 2026071301, 3600, 900, 604800, 86400),
	}

	openMsg := &dns.Message{
		Header:  dns.Header{ID: 0, Flags: 0x8580, QDCount: 1, ANCount: 1},
		Answers: []dns.ResourceRecord{soa},
	}
	closeMsg := &dns.Message{
		Header:  dns.Header{ID: 0, Flags: 0x8580, QDCount: 1, ANCount: uint16(len(records) + 1)},
		Answers: append([]dns.ResourceRecord{soa}, records...),
	}

	var tlsCfg *tls.Config
	if useTLS {
		cert, err := generateTestCert()
		if err != nil {
			t.Fatalf("generate test cert: %v", err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))

				var rwc net.Conn
				if useTLS {
					tlsConn := tls.Server(c, tlsCfg)
					if err := tlsConn.Handshake(); err != nil {
						return
					}
					rwc = tlsConn
				} else {
					rwc = c
				}

				// Read query
				var length uint16
				if err := binary.Read(rwc, binary.BigEndian, &length); err != nil {
					return
				}
				query := make([]byte, length)
				if _, err := io.ReadFull(rwc, query); err != nil {
					return
				}

				// Send response messages
				for _, msg := range []*dns.Message{openMsg, closeMsg} {
					wire, err := dns.Pack(msg, make([]byte, 512))
					if err != nil {
						return
					}
					if err := binary.Write(rwc, binary.BigEndian, uint16(len(wire))); err != nil {
						return
					}
					if _, err := rwc.Write(wire); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// buildSOARDATA constructs the RDATA for an SOA record using the dns encoder.
func buildSOARDATA(mname, rname string, serial, refresh, retry, expire, minimum uint32) []byte {
	mnameEnc, err := dns.EncodeNameToBytes(mname)
	if err != nil {
		return nil
	}
	rnameEnc, err := dns.EncodeNameToBytes(rname)
	if err != nil {
		return nil
	}
	data := make([]byte, 0, len(mnameEnc)+len(rnameEnc)+20)
	data = append(data, mnameEnc...)
	data = append(data, rnameEnc...)
	data = append(data, byte(serial>>24), byte(serial>>16), byte(serial>>8), byte(serial))
	data = append(data, byte(refresh>>24), byte(refresh>>16), byte(refresh>>8), byte(refresh))
	data = append(data, byte(retry>>24), byte(retry>>16), byte(retry>>8), byte(retry))
	data = append(data, byte(expire>>24), byte(expire>>16), byte(expire>>8), byte(expire))
	data = append(data, byte(minimum>>24), byte(minimum>>16), byte(minimum>>8), byte(minimum))
	return data
}

// TestAXFR_BasicTransferFullZone verifies a complete AXFR round-trip:
// connect, send query, receive two-message response stream, collect records.
func TestAXFR_BasicTransferFullZone(t *testing.T) {
	zone := "example.com"
	records := []dns.ResourceRecord{
		{Name: zone, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{93, 184, 216, 34}, RDLength: 4},
		{Name: "www." + zone, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{93, 184, 216, 35}, RDLength: 4},
	}

	addr, close := startXFRMock(t, zone, records, false)
	defer close()

	cfg := ClientConfig{
		PrimaryAddr: addr,
		Zone:        zone,
		Timeout:     5 * time.Second,
		UseTLS:      false,
	}

	result, err := AXFR(context.Background(), cfg)
	if err != nil {
		t.Fatalf("AXFR failed: %v", err)
	}

	// Should have: SOA (open) + records + SOA (close) + records again from close msg
	// The close message carries SOA + all records
	if len(result) == 0 {
		t.Fatal("AXFR returned no records")
	}

	// Verify SOA was found
	var soaCount int
	for _, rr := range result {
		if rr.Type == dns.TypeSOA {
			soaCount++
		}
	}
	if soaCount < 2 {
		t.Errorf("expected at least 2 SOA records (open + close), got %d", soaCount)
	}

	// Verify A records found
	var aCount int
	for _, rr := range result {
		if rr.Type == dns.TypeA {
			aCount++
		}
	}
	if aCount == 0 {
		t.Error("expected A records in AXFR result, got none")
	}
}

// TestAXFR_OverTLS verifies AXFR works over TLS 1.3 (RFC 9103).
func TestAXFR_OverTLS(t *testing.T) {
	zone := "example.com"
	records := []dns.ResourceRecord{
		{Name: zone, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{10, 0, 0, 1}, RDLength: 4},
	}

	addr, close := startXFRMock(t, zone, records, true)
	defer close()

	cfg := ClientConfig{
		PrimaryAddr:        addr,
		Zone:               zone,
		Timeout:            5 * time.Second,
		UseTLS:             true,
		InsecureSkipVerify: true,
	}

	result, err := AXFR(context.Background(), cfg)
	if err != nil {
		t.Fatalf("AXFR over TLS failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("AXFR over TLS returned no records")
	}
}

func TestAXFR_OverTLSRejectsTLS12OnlyPrimary(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		})
		_ = tlsConn.Handshake()
	}()

	_, err = AXFR(context.Background(), ClientConfig{
		PrimaryAddr:        ln.Addr().String(),
		Zone:               "example.com",
		Timeout:            time.Second,
		UseTLS:             true,
		InsecureSkipVerify: true,
	})
	if err == nil {
		t.Fatal("AXFR over TLS succeeded against a TLS 1.2-only primary; RFC 9103 requires TLS 1.3")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("TLS 1.2-only primary was not contacted")
	}
}

// TestAXFR_EmptyZone verifies AXFR handles a zone with no records
// (only the opening and closing SOA).
func TestAXFR_EmptyZone(t *testing.T) {
	zone := "empty.zone.test."
	records := []dns.ResourceRecord{}

	addr, close := startXFRMock(t, zone, records, false)
	defer close()

	cfg := ClientConfig{
		PrimaryAddr: addr,
		Zone:        zone,
		Timeout:     5 * time.Second,
		UseTLS:      false,
	}

	result, err := AXFR(context.Background(), cfg)
	if err != nil {
		t.Fatalf("AXFR failed for empty zone: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("AXFR for empty zone should still return SOA records")
	}
}

// TestAXFR_Timeout verifies AXFR returns an error on timeout.
func TestAXFR_Timeout(t *testing.T) {
	// Connect to an address that accepts but never responds
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			// Accept but never respond
			time.Sleep(10 * time.Second)
			conn.Close()
		}
	}()

	cfg := ClientConfig{
		PrimaryAddr: ln.Addr().String(),
		Zone:        "timeout.test.",
		Timeout:     100 * time.Millisecond,
		UseTLS:      false,
	}

	_, err = AXFR(context.Background(), cfg)
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

// TestBuildAXFRQuery verifies the query message is well-formed.
func TestBuildAXFRQuery(t *testing.T) {
	zone := "example.com"
	msg := buildAXFRQuery(zone)

	if len(msg.Questions) != 1 {
		t.Fatalf("expected 1 question, got %d", len(msg.Questions))
	}
	if msg.Questions[0].Type != dns.TypeAXFR {
		t.Errorf("expected TypeAXFR (%d), got %d", dns.TypeAXFR, msg.Questions[0].Type)
	}
	if msg.Questions[0].Name != zone {
		t.Errorf("expected zone %q, got %q", zone, msg.Questions[0].Name)
	}
	if !msg.Header.RD() {
		t.Error("expected RD=1 on AXFR query")
	}
}

// TestMissingPrimaryAddr verifies that an empty primary address returns an error.
func TestMissingPrimaryAddr(t *testing.T) {
	_, err := AXFR(context.Background(), ClientConfig{Zone: "test."})
	if err == nil {
		t.Error("expected error for missing primary address")
	}
}

// generateTestCert creates a self-signed TLS certificate for testing XFR over TLS.
func generateTestCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
