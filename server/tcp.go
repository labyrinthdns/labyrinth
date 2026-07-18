package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// TCPServer handles DNS queries over TCP.
type TCPServer struct {
	listener    net.Listener
	handler     Handler
	timeout     time.Duration
	maxConns    int
	sem         chan struct{}
	logger      *slog.Logger
	pipelineMax int
	idleTimeout time.Duration
	// per-source connection cap
	maxConnsPerClient int
	clientConns       map[string]int
	clientMu          sync.Mutex
}

// NewTCPServer creates a new TCP DNS server.
func NewTCPServer(addr string, handler Handler, timeout time.Duration, maxConns int, logger *slog.Logger, opts ...TCPOption) (*TCPServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	s := &TCPServer{
		listener:          ln,
		handler:           handler,
		timeout:           timeout,
		maxConns:          maxConns,
		maxConnsPerClient: 16, // default; overridden via WithMaxConnsPerClient
		sem:               make(chan struct{}, maxConns),
		logger:            logger,
		pipelineMax:       100,
		idleTimeout:       5 * time.Second,
		clientConns:       make(map[string]int),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// WithMaxConnsPerClient sets the per-source-IP connection cap for the TCP server.
func WithMaxConnsPerClient(n int) TCPOption {
	return func(s *TCPServer) {
		if n > 0 {
			s.maxConnsPerClient = n
		}
	}
}

// TCPOption configures optional TCPServer parameters.
type TCPOption func(*TCPServer)

// WithPipelineMax sets the maximum number of queries per TCP connection.
func WithPipelineMax(n int) TCPOption {
	return func(s *TCPServer) {
		if n > 0 {
			s.pipelineMax = n
		}
	}
}

// WithIdleTimeout sets the idle timeout between pipelined queries.
func WithIdleTimeout(d time.Duration) TCPOption {
	return func(s *TCPServer) {
		if d > 0 {
			s.idleTimeout = d
		}
	}
}

// Serve starts the TCP server loop.
func (s *TCPServer) Serve(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Set accept deadline so we can check context
		if dl, ok := s.listener.(*net.TCPListener); ok {
			dl.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.logger.Error("tcp accept error", "error", err)
			continue
		}

		// Per-source connection cap check.
		clientIP := sourceIP(conn.RemoteAddr())
		if s.maxConnsPerClient > 0 {
			s.clientMu.Lock()
			count := s.clientConns[clientIP]
			if count >= s.maxConnsPerClient {
				s.clientMu.Unlock()
				conn.Close()
				continue
			}
			s.clientConns[clientIP] = count + 1
			s.clientMu.Unlock()
		}

		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			s.releaseClientConn(clientIP)
			_ = conn.Close()
			return nil
		}
		go func(c net.Conn, ip string) {
			defer func() { <-s.sem }()
			defer s.releaseClientConn(ip)
			s.handleTCP(c)
			c.Close()
		}(conn, clientIP)
	}
}

func (s *TCPServer) releaseClientConn(ip string) {
	if s.maxConnsPerClient <= 0 {
		return
	}
	s.clientMu.Lock()
	s.clientConns[ip]--
	if s.clientConns[ip] <= 0 {
		delete(s.clientConns, ip)
	}
	s.clientMu.Unlock()
}

func (s *TCPServer) handleTCP(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("panic in TCP handler", "client", conn.RemoteAddr(), "panic", r)
		}
		conn.Close()
	}()

	// Set initial deadline for the first query
	conn.SetDeadline(time.Now().Add(s.timeout))

	for i := 0; i < s.pipelineMax; i++ {
		// Read 2-byte length prefix
		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return // EOF or error = done
		}

		if length < 12 {
			return
		}

		// Read query
		query := make([]byte, length)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}

		// Handle
		response, err := s.handler.Handle(query, conn.RemoteAddr())
		if err != nil || response == nil {
			return
		}

		// RFC 7828 — advertise edns-tcp-keepalive when the client asked.
		// Plaintext TCP, so padding is intentionally NOT applied
		// (RFC 8467 §6 forbids it on unencrypted transports).
		response = applyTCPTransportPolicies(query, response, s.idleTimeout, false)

		// Write 2-byte length prefix + response
		if err := binary.Write(conn, binary.BigEndian, uint16(len(response))); err != nil {
			return
		}
		if _, err := conn.Write(response); err != nil {
			return
		}

		// Reset deadline for next query (idle timeout)
		conn.SetDeadline(time.Now().Add(s.idleTimeout))
	}
}

// Close closes the TCP server.
func (s *TCPServer) Close() error {
	return s.listener.Close()
}

// sourceIP extracts the source IP string from a remote address, stripping
// the port. Used for per-client connection caps.
func sourceIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	}
	// Fallback: SplitHostPort for string-form addresses (e.g. from
	// unix-domain sockets or custom transports).
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
