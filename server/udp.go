package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/labyrinthdns/labyrinth/internal/pool"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// UDPServer handles DNS queries over UDP.
type UDPServer struct {
	conn       net.PacketConn
	handler    Handler
	maxWorkers int
	sem        chan struct{}
	logger     *slog.Logger
	metrics    *metrics.Metrics
}

// udpSocketBufferBytes is the SO_RCVBUF/SO_SNDBUF target for the
// client-facing UDP listener. The kernel doubles the requested value
// for bookkeeping, so 4 MiB ≈ 8 MiB of actual socket memory — enough
// to absorb short query bursts without Recv-Q saturation (which we
// observed dropping answers under load when the default ~212 KiB
// rmem was in effect).
const udpSocketBufferBytes = 4 << 20

// NewUDPServer creates a new UDP DNS server.
func NewUDPServer(addr string, handler Handler, maxWorkers int, logger *slog.Logger) (*UDPServer, error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	if uc, ok := conn.(*net.UDPConn); ok {
		if err := uc.SetReadBuffer(udpSocketBufferBytes); err != nil {
			logger.Warn("udp SetReadBuffer failed", "size", udpSocketBufferBytes, "error", err)
		}
		if err := uc.SetWriteBuffer(udpSocketBufferBytes); err != nil {
			logger.Warn("udp SetWriteBuffer failed", "size", udpSocketBufferBytes, "error", err)
		}
	}

	if maxWorkers <= 0 {
		maxWorkers = 1
	}

	return &UDPServer{
		conn:       conn,
		handler:    handler,
		maxWorkers: maxWorkers,
		sem:        make(chan struct{}, maxWorkers),
		logger:     logger,
	}, nil
}

// SetMetrics wires optional metrics for UDP admission drops.
func (s *UDPServer) SetMetrics(m *metrics.Metrics) {
	s.metrics = m
}

// Serve starts the UDP server loop.
func (s *UDPServer) Serve(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	readBuf := pool.GetBuffer()
	defer pool.PutBuffer(readBuf)
	buf := *readBuf

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, clientAddr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Error("udp read error", "error", err)
			continue
		}

		// Non-blocking admit: if all workers are busy, drop this
		// datagram and keep reading. Blocking here would stall
		// ReadFrom, fill the kernel Recv-Q, and drop *older* packets
		// invisibly — worse than shedding the newest query.
		select {
		case s.sem <- struct{}{}:
		default:
			if s.metrics != nil {
				s.metrics.IncUDPWorkerDrops()
			}
			s.logger.Debug("udp worker saturated; dropping query",
				"client", clientAddr, "size", n)
			continue
		}

		// Copy buffer only after admission — avoid alloc on drops.
		query := make([]byte, n)
		copy(query, buf[:n])

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
