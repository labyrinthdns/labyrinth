package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/quic-go/quic-go"
)

type captureTransportHandler struct {
	addrCh chan net.Addr
}

func (h *captureTransportHandler) Handle(query []byte, addr net.Addr) ([]byte, error) {
	h.addrCh <- addr
	msg, err := dns.Unpack(query)
	if err != nil {
		return nil, err
	}
	resp := &dns.Message{
		Header:    dns.Header{ID: msg.Header.ID, Flags: dns.NewFlagBuilder().SetQR(true).SetRA(true).Build()},
		Questions: msg.Questions,
		Additional: []dns.ResourceRecord{
			dns.BuildOPT(1232, false),
		},
	}
	return dns.Pack(resp, make([]byte, 512))
}

func startTestDoQServer(t *testing.T, handler Handler) (*DoQServer, *tls.Config, context.CancelFunc, <-chan error) {
	t.Helper()
	cert, pool, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{doqALPN},
	}
	srv, err := newDoQServer("127.0.0.1:0", handler, serverTLS, 2*time.Second, 4, discardLogger())
	if err != nil {
		t.Fatalf("newDoQServer: %v", err)
	}
	clientTLS := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{doqALPN},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
	})
	return srv, clientTLS, cancel, done
}

func TestDoQStreamTransportAndPadding(t *testing.T) {
	handler := &captureTransportHandler{addrCh: make(chan net.Addr, 1)}
	srv, clientTLS, _, _ := startTestDoQServer(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, srv.Addr().String(), clientTLS, nil)
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	defer conn.CloseWithError(0, "test complete")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	query := buildQueryWithPadding(t)
	if err := binary.Write(stream, binary.BigEndian, uint16(len(query))); err != nil {
		t.Fatalf("write length: %v", err)
	}
	if _, err := stream.Write(query); err != nil {
		t.Fatalf("write query: %v", err)
	}

	var responseLen uint16
	if err := binary.Read(stream, binary.BigEndian, &responseLen); err != nil {
		t.Fatalf("read response length: %v", err)
	}
	response := make([]byte, responseLen)
	if _, err := io.ReadFull(stream, response); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(response)%dns.PaddingBlockSize != 0 {
		t.Fatalf("DoQ response length = %d, want multiple of %d; raw query was not passed to padding policy", len(response), dns.PaddingBlockSize)
	}

	select {
	case addr := <-handler.addrCh:
		if got := addr.Network(); got != "doq" {
			t.Fatalf("handler transport = %q, want doq", got)
		}
		if !isStreamTransport(addr) {
			t.Fatal("DoQ handler address was not classified as stateful stream")
		}
	case <-ctx.Done():
		t.Fatal("handler did not receive DoQ query")
	}
}

func TestDoQCloseStopsServeWithoutContextCancel(t *testing.T) {
	srv, _, _, done := startTestDoQServer(t, &EchoHandler{})
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve after Close = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not exit after listener Close")
	}
}
