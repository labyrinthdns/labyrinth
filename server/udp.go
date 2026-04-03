package server

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/labyrinthdns/labyrinth/internal/pool"
)

// UDPServer handles DNS queries over UDP.
type UDPServer struct {
	conn       net.PacketConn
	handler    Handler
	maxWorkers int
	sem        chan struct{}
	logger     *slog.Logger
}

// NewUDPServer creates a new UDP DNS server.
func NewUDPServer(addr string, handler Handler, maxWorkers int, logger *slog.Logger) (*UDPServer, error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	return &UDPServer{
		conn:       conn,
		handler:    handler,
		maxWorkers: maxWorkers,
		sem:        make(chan struct{}, maxWorkers),
		logger:     logger,
	}, nil
}

// Serve starts the UDP server loop.
func (s *UDPServer) Serve(ctx context.Context) error {
	readBuf := pool.GetBuffer()
	defer pool.PutBuffer(readBuf)
	buf := *readBuf

	for {
		select {
		case <-ctx.Done():
			return s.conn.Close()
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, clientAddr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return s.conn.Close()
			}
			s.logger.Error("udp read error", "error", err)
			continue
		}

		// Copy buffer before dispatching
		query := make([]byte, n)
		copy(query, buf[:n])

		s.sem <- struct{}{}
		go func(data []byte, addr net.Addr) {
			defer func() { <-s.sem }()
			s.handleUDP(data, addr)
		}(query, clientAddr)
	}
}

func (s *UDPServer) handleUDP(query []byte, clientAddr net.Addr) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("panic in UDP handler", "client", clientAddr, "panic", r)
		}
	}()

	response, err := s.handler.Handle(query, clientAddr)
	if err != nil {
		s.logger.Debug("handler error", "client", clientAddr, "error", err)
		return
	}
	if response == nil {
		return
	}

	if _, err := s.conn.WriteTo(response, clientAddr); err != nil {
		s.logger.Error("udp write error", "client", clientAddr, "error", err)
	}
}

// Close closes the UDP server.
func (s *UDPServer) Close() error {
	return s.conn.Close()
}
