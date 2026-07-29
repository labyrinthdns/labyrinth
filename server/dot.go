package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// DoTServer handles DNS queries over TLS (RFC 7858).
type DoTServer struct {
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

// NewDoTServer creates a new DNS-over-TLS server.
// It loads the TLS certificate/key pair and wraps a TCP listener with TLS.
func NewDoTServer(addr string, handler Handler, certFile, keyFile string, timeout time.Duration, maxConns int, maxConnsPerClient int, logger *slog.Logger) (*DoTServer, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsLn := tls.NewListener(ln, tlsCfg)

	return &DoTServer{
		listener:          tlsLn,
		handler:           handler,
		timeout:           timeout,
		maxConns:          maxConns,
		sem:               make(chan struct{}, maxConns),
		logger:            logger,
		pipelineMax:       100,
		idleTimeout:       5 * time.Second,
		maxConnsPerClient: maxConnsPerClient,
		clientConns:       make(map[string]int),
	}, nil
}

// NewDoTServerWithTLSConfig creates a DoT server using a pre-built tls.Config.
// This is used when auto-TLS provides the certificate dynamically.
func NewDoTServerWithTLSConfig(addr string, handler Handler, tlsCfg *tls.Config, timeout time.Duration, maxConns int, maxConnsPerClient int, logger *slog.Logger) (*DoTServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsLn := tls.NewListener(ln, tlsCfg)

	return &DoTServer{
		listener:          tlsLn,
		handler:           handler,
		timeout:           timeout,
		maxConns:          maxConns,
		sem:               make(chan struct{}, maxConns),
		logger:            logger,
		pipelineMax:       100,
		idleTimeout:       5 * time.Second,
		maxConnsPerClient: maxConnsPerClient,
		clientConns:       make(map[string]int),
	}, nil
}

// NewDoTServerWithListener creates a DoT server using an existing TLS listener.
// This is primarily useful for testing.
func NewDoTServerWithListener(ln net.Listener, handler Handler, timeout time.Duration, maxConns int, maxConnsPerClient int, logger *slog.Logger) *DoTServer {
	return &DoTServer{
		listener:          ln,
		handler:           handler,
		timeout:           timeout,
		maxConns:          maxConns,
		sem:               make(chan struct{}, maxConns),
		logger:            logger,
		pipelineMax:       100,
		idleTimeout:       5 * time.Second,
		maxConnsPerClient: maxConnsPerClient,
		clientConns:       make(map[string]int),
	}
}

// Serve starts the DoT server loop. It uses the same semaphore-based
// concurrency limiting pattern as TCPServer.
func (s *DoTServer) Serve(ctx context.Context) error {
	// Ensure Accept unblocks promptly on shutdown.
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

		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Error("dot accept error", "error", err)
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
			s.handleDoT(c)
			c.Close()
		}(conn, clientIP)
	}
}

// handleDoT processes DNS queries on a single TLS connection.
// It uses the same length-prefixed DNS message framing as TCP (RFC 1035 / RFC 7858).
func (s *DoTServer) releaseClientConn(ip string) {
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

func (s *DoTServer) handleDoT(conn net.Conn) {
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

		// RFC 7828 + RFC 7830/8467 — apply keepalive + padding on
		// encrypted transport when the client signalled the options.
		response = applyTCPTransportPolicies(query, response, s.idleTimeout, true)

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

// Close closes the DoT server listener.
func (s *DoTServer) Close() error {
	return s.listener.Close()
}

// Addr returns the listener's network address.
func (s *DoTServer) Addr() net.Addr {
	return s.listener.Addr()
}
