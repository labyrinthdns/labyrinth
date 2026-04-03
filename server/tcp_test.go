package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// buildMinimalQuery creates a minimal valid DNS query for testing.
// It produces a query with ID=id, RD=1, one question for "example.com" A.
func buildMinimalQuery(id uint16) []byte {
	// Header: 12 bytes
	// Question: \x07example\x03com\x00 (13 bytes) + QTYPE(2) + QCLASS(2) = 17 bytes
	// Total: 29 bytes
	buf := make([]byte, 29)
	binary.BigEndian.PutUint16(buf[0:2], id)       // ID
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)    // Flags: RD=1
	binary.BigEndian.PutUint16(buf[4:6], 1)          // QDCOUNT=1
	binary.BigEndian.PutUint16(buf[6:8], 0)          // ANCOUNT=0
	binary.BigEndian.PutUint16(buf[8:10], 0)         // NSCOUNT=0
	binary.BigEndian.PutUint16(buf[10:12], 0)        // ARCOUNT=0
	// QNAME: \x07example\x03com\x00
	copy(buf[12:], []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0})
	binary.BigEndian.PutUint16(buf[25:27], 1) // QTYPE=A
	binary.BigEndian.PutUint16(buf[27:29], 1) // QCLASS=IN
	return buf
}

// sendTCPQuery writes a single length-prefixed query on an existing connection
// and reads the length-prefixed response.
func sendTCPQuery(t *testing.T, conn net.Conn, query []byte) []byte {
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

// TestTCPPipelining verifies that multiple queries can be sent on a single
// TCP connection and each receives a valid response (RFC 7766).
func TestTCPPipelining(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}

	srv, err := NewTCPServer(":0", handler, 5*time.Second, 10, logger,
		WithPipelineMax(100),
		WithIdleTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Close()

	addr := srv.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send 3 queries on the same connection
	for i := 0; i < 3; i++ {
		query := buildMinimalQuery(uint16(0x1000 + i))
		resp := sendTCPQuery(t, conn, query)

		if len(resp) < 12 {
			t.Fatalf("query %d: response too short (%d bytes)", i, len(resp))
		}
		// EchoHandler echoes the query back verbatim, so verify ID matches
		respID := binary.BigEndian.Uint16(resp[0:2])
		if respID != uint16(0x1000+i) {
			t.Errorf("query %d: expected ID 0x%04x, got 0x%04x", i, 0x1000+i, respID)
		}
		// Verify the response length matches the query (echo)
		if len(resp) != len(query) {
			t.Errorf("query %d: expected response length %d, got %d", i, len(query), len(resp))
		}
	}
}

// TestTCPPipelineMaxReached verifies that the server closes the connection
// after pipelineMax queries have been served.
func TestTCPPipelineMaxReached(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}

	pipelineMax := 3
	srv, err := NewTCPServer(":0", handler, 5*time.Second, 10, logger,
		WithPipelineMax(pipelineMax),
		WithIdleTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Close()

	addr := srv.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send exactly pipelineMax queries -- all should succeed
	for i := 0; i < pipelineMax; i++ {
		query := buildMinimalQuery(uint16(0x2000 + i))
		resp := sendTCPQuery(t, conn, query)
		if len(resp) < 12 {
			t.Fatalf("query %d: response too short (%d bytes)", i, len(resp))
		}
	}

	// The next query should fail because the server closes the connection
	// after pipelineMax queries.
	extra := buildMinimalQuery(0x2FFF)
	if err := binary.Write(conn, binary.BigEndian, uint16(len(extra))); err != nil {
		// Write may succeed if the TCP send buffer hasn't been drained yet,
		// but reading the response should fail.
		return
	}
	conn.Write(extra)

	// Try to read -- should get EOF or error
	var length uint16
	err = binary.Read(conn, binary.BigEndian, &length)
	if err == nil {
		t.Error("expected error (EOF) after pipelineMax queries, but read succeeded")
	}
}

// TestTCPPipelineIdleTimeout verifies that the server closes the connection
// if the client is idle longer than the idle timeout between queries.
func TestTCPPipelineIdleTimeout(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}

	idleTimeout := 200 * time.Millisecond
	srv, err := NewTCPServer(":0", handler, 5*time.Second, 10, logger,
		WithPipelineMax(100),
		WithIdleTimeout(idleTimeout),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Close()

	addr := srv.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send one query successfully
	query := buildMinimalQuery(0x3000)
	resp := sendTCPQuery(t, conn, query)
	if len(resp) < 12 {
		t.Fatalf("first response too short (%d bytes)", len(resp))
	}

	// Wait longer than the idle timeout
	time.Sleep(idleTimeout + 200*time.Millisecond)

	// Try to send another query -- the server should have closed the connection
	query2 := buildMinimalQuery(0x3001)
	_ = binary.Write(conn, binary.BigEndian, uint16(len(query2)))
	conn.Write(query2)

	var length uint16
	err = binary.Read(conn, binary.BigEndian, &length)
	if err == nil {
		t.Error("expected error after idle timeout, but read succeeded")
	}
}

// TestTCPPipelineDefaults verifies that creating a TCPServer without options
// uses the default pipelineMax and idleTimeout values.
func TestTCPPipelineDefaults(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}

	srv, err := NewTCPServer(":0", handler, 5*time.Second, 10, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if srv.pipelineMax != 100 {
		t.Errorf("expected default pipelineMax=100, got %d", srv.pipelineMax)
	}
	if srv.idleTimeout != 5*time.Second {
		t.Errorf("expected default idleTimeout=5s, got %v", srv.idleTimeout)
	}
}

// TestTCPPipelineOptionOverride verifies that WithPipelineMax and
// WithIdleTimeout correctly override default values.
func TestTCPPipelineOptionOverride(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}

	srv, err := NewTCPServer(":0", handler, 5*time.Second, 10, logger,
		WithPipelineMax(50),
		WithIdleTimeout(10*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if srv.pipelineMax != 50 {
		t.Errorf("expected pipelineMax=50, got %d", srv.pipelineMax)
	}
	if srv.idleTimeout != 10*time.Second {
		t.Errorf("expected idleTimeout=10s, got %v", srv.idleTimeout)
	}
}

// TestTCPPipelineInvalidOptions verifies that zero/negative options are ignored.
func TestTCPPipelineInvalidOptions(t *testing.T) {
	logger := discardLogger()
	handler := &EchoHandler{}

	srv, err := NewTCPServer(":0", handler, 5*time.Second, 10, logger,
		WithPipelineMax(0),
		WithIdleTimeout(0),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Should keep defaults since 0 is not valid
	if srv.pipelineMax != 100 {
		t.Errorf("expected pipelineMax=100 (default), got %d", srv.pipelineMax)
	}
	if srv.idleTimeout != 5*time.Second {
		t.Errorf("expected idleTimeout=5s (default), got %v", srv.idleTimeout)
	}
}
