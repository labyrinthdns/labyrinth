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
	listener net.Listener
	handler  Handler
	timeout  time.Duration
	maxConns int
	sem      chan struct{}
	logger   *slog.Logger
}

// NewTCPServer creates a new TCP DNS server.
func NewTCPServer(addr string, handler Handler, timeout time.Duration, maxConns int, logger *slog.Logger) (*TCPServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &TCPServer{
		listener: ln,
		handler:  handler,
		timeout:  timeout,
		maxConns: maxConns,
		sem:      make(chan struct{}, maxConns),
		logger:   logger,
	}, nil
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
	conn.SetDeadline(time.Now().Add(s.timeout))

	// Read 2-byte length prefix
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return
	}

	if length < 12 || length > 65535 {
		return
	}

	query := make([]byte, length)
	if _, err := io.ReadFull(conn, query); err != nil {
		return
	}

	response, err := s.handler.Handle(query, conn.RemoteAddr())
	if err != nil || response == nil {
		return
	}

	// Write 2-byte length prefix + response
	binary.Write(conn, binary.BigEndian, uint16(len(response)))
	conn.Write(response)
}

// Close closes the TCP server.
func (s *TCPServer) Close() error {
	return s.listener.Close()
}
