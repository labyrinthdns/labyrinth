package server

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
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
}

// NewTCPServer creates a new TCP DNS server.
func NewTCPServer(addr string, handler Handler, timeout time.Duration, maxConns int, logger *slog.Logger, opts ...TCPOption) (*TCPServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	s := &TCPServer{
		listener:    ln,
		handler:     handler,
		timeout:     timeout,
		maxConns:    maxConns,
		sem:         make(chan struct{}, maxConns),
		logger:      logger,
		pipelineMax: 100,
		idleTimeout: 5 * time.Second,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
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
	for {
		select {
		case <-ctx.Done():
			return s.listener.Close()
		default:
		}

		// Set accept deadline so we can check context
		if dl, ok := s.listener.(*net.TCPListener); ok {
			dl.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.logger.Error("tcp accept error", "error", err)
			continue
		}

		s.sem <- struct{}{}
		go func(c net.Conn) {
			defer func() { <-s.sem }()
			defer c.Close()
			s.handleTCP(c)
		}(conn)
	}
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

		if length < 12 || length > 65535 {
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
