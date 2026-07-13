package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// doqALPN is the ALPN token registered for DNS over QUIC (RFC 9250 §4.2).
const doqALPN = "doq"

// DoQServer handles DNS queries over QUIC (RFC 9250).
type DoQServer struct {
	listener    *quic.Listener
	handler     Handler
	timeout     time.Duration
	maxConns    int
	sem         chan struct{}
	logger      *slog.Logger
	pipelineMax int
	idleTimeout time.Duration
	tlsCfg      *tls.Config
}

// DoQOption configures optional DoQServer parameters.
type DoQOption func(*DoQServer)

// WithDoQIdleTimeout sets the idle timeout for QUIC connections.
func WithDoQIdleTimeout(d time.Duration) DoQOption {
	return func(s *DoQServer) {
		if d > 0 {
			s.idleTimeout = d
		}
	}
}

// WithDoQPipelineMax sets the maximum number of concurrent streams per connection.
func WithDoQPipelineMax(n int) DoQOption {
	return func(s *DoQServer) {
		if n > 0 {
			s.pipelineMax = n
		}
	}
}

// NewDoQServer creates a new DNS-over-QUIC server.
// It loads TLS certificate/key and creates a QUIC listener.
func NewDoQServer(addr string, handler Handler, certFile, keyFile string, timeout time.Duration, maxConns int, logger *slog.Logger, opts ...DoQOption) (*DoQServer, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // QUIC requires TLS 1.3
		NextProtos:   []string{doqALPN},
	}

	return newDoQServer(addr, handler, tlsCfg, timeout, maxConns, logger, opts...)
}

// NewDoQServerWithTLSConfig creates a DoQ server using a pre-built tls.Config.
// The caller must set NextProtos to include "doq" and MinVersion to TLS 1.3.
// Used when auto-TLS provides the certificate dynamically.
func NewDoQServerWithTLSConfig(addr string, handler Handler, tlsCfg *tls.Config, timeout time.Duration, maxConns int, logger *slog.Logger, opts ...DoQOption) (*DoQServer, error) {
	// Ensure QUIC-required TLS settings
	cfg := tlsCfg.Clone()
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	hasALPN := false
	for _, proto := range cfg.NextProtos {
		if proto == doqALPN {
			hasALPN = true
			break
		}
	}
	if !hasALPN {
		cfg.NextProtos = append(cfg.NextProtos, doqALPN)
	}

	return newDoQServer(addr, handler, cfg, timeout, maxConns, logger, opts...)
}

func newDoQServer(addr string, handler Handler, tlsCfg *tls.Config, timeout time.Duration, maxConns int, logger *slog.Logger, opts ...DoQOption) (*DoQServer, error) {
	if maxConns <= 0 {
		maxConns = 256
	}

	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{
		MaxIncomingStreams: int64(maxConns),
	})
	if err != nil {
		return nil, err
	}

	s := &DoQServer{
		listener:    ln,
		handler:     handler,
		timeout:     timeout,
		maxConns:    maxConns,
		sem:         make(chan struct{}, maxConns),
		logger:      logger,
		pipelineMax: 100,
		idleTimeout: 30 * time.Second, // RFC 9250 recommends 30s idle
		tlsCfg:      tlsCfg,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// Serve starts the DoQ server loop.
func (s *DoQServer) Serve(ctx context.Context) error {
	for {
		conn, err := s.listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logger.Error("doq accept error", "error", err)
			continue
		}

		s.sem <- struct{}{}
		go func(c *quic.Conn) {
			defer func() { <-s.sem }()
			s.handleConnection(ctx, c)
		}(conn)
	}
}

// handleConnection processes incoming streams on a single QUIC connection.
func (s *DoQServer) handleConnection(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "server shutdown")
	clientAddr := conn.RemoteAddr()

	for i := 0; i < s.pipelineMax; i++ {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return // EOF or error = done
		}

		// Handle each stream concurrently so one slow query does not
		// block subsequent queries on the same connection (RFC 9250 §4.3).
		go func(str *quic.Stream) {
			defer str.Close()
			s.handleStream(str, clientAddr)
		}(stream)
	}
}

// handleStream processes a single DNS query on a QUIC stream.
// The DNS message is length-prefixed (2-byte big-endian length, then message),
// matching the same wire format as DNS over TCP (RFC 1035 §4.2.2 / RFC 9250 §4.3).
func (s *DoQServer) handleStream(stream *quic.Stream, clientAddr net.Addr) {
	// Set read deadline for the initial query
	stream.SetReadDeadline(time.Now().Add(s.timeout))

	// Read 2-byte length prefix
	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		return
	}

	if length < 12 {
		return
	}

	// Read query
	query := make([]byte, length)
	if _, err := io.ReadFull(stream, query); err != nil {
		return
	}

	// Handle via the shared handler
	response, err := s.handler.Handle(query, clientAddr)
	if err != nil || response == nil {
		return
	}

	// Apply transport policies: padding on encrypted transport, keepalive
	// Use nil query since we don't have the raw query anymore for keepalive detection.
	response = applyTCPTransportPolicies(nil, response, s.idleTimeout, true)

	// Write 2-byte length prefix + response
	stream.SetWriteDeadline(time.Now().Add(s.timeout))
	if err := binary.Write(stream, binary.BigEndian, uint16(len(response))); err != nil {
		return
	}
	if _, err := stream.Write(response); err != nil {
		return
	}
}

// Close closes the DoQ server listener.
func (s *DoQServer) Close() error {
	return s.listener.Close()
}

// Addr returns the listener's network address.
func (s *DoQServer) Addr() net.Addr {
	return s.listener.Addr()
}
