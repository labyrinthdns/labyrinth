package resolver

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestQueryUpstream_TCPFallback_RejectsTCResponseLoop pins RFC 7766 §4:
// "The TC flag SHOULD NOT be set ... for responses arriving over TCP."
// A confused authoritative might still set TC=1 on the TCP retry; if
// the resolver naively chains a second TCP retry on TC=1 we'd loop
// forever. The contract we want to lock is: a TC=1 response over TCP
// is rejected as a structural error rather than re-recursed.
//
// We stand up a mock auth that:
//
//   - Returns TC=1 over UDP (legitimate truncation signal — too big to fit)
//   - Returns TC=1 over TCP too (the BUG case we're pinning against)
//
// Expected: queryUpstreamOnce returns an error mentioning RFC 7766. A
// regression that removed the guard would manifest as either an
// infinite loop or a silent stall on the upstream timeout.
func TestQueryUpstream_TCPFallback_RejectsTCResponseLoop(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer udp.Close()
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())

	var tcp net.Listener
	for attempt := 0; attempt < 10; attempt++ {
		tcp, err = net.Listen("tcp", "127.0.0.1:"+portStr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Skipf("could not bind matching TCP port: %v", err)
	}
	defer tcp.Close()

	// Tracks how many TCP retries the resolver attempted. If the guard
	// works there should be exactly 1: the resolver hits TC=1, refuses
	// to recurse, and bails.
	var tcpRetries atomic.Int32

	respond := func(query *dns.Message) *dns.Message {
		resp := &dns.Message{
			Header:    dns.Header{ID: query.Header.ID},
			Questions: query.Questions,
			Answers: []dns.ResourceRecord{
				{Name: "x.example.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RData: []byte{1, 2, 3, 4}},
			},
		}
		// QR=1, AA=1, TC=1 — truncated authoritative answer.
		resp.Header.Flags = 0x8400 | 0x0200
		return resp
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			resp := respond(query)
			out := make([]byte, 4096)
			packed, err := dns.Pack(resp, out)
			if err != nil {
				continue
			}
			udp.WriteTo(packed, addr)
		}
	}()

	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			tcpRetries.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, lenBuf); err != nil {
					return
				}
				qLen := binary.BigEndian.Uint16(lenBuf)
				qBuf := make([]byte, qLen)
				if _, err := io.ReadFull(c, qBuf); err != nil {
					return
				}
				query, err := dns.Unpack(qBuf)
				if err != nil {
					return
				}
				resp := respond(query) // STILL TC=1 over TCP — the bug we pin against
				out := make([]byte, 4096)
				packed, err := dns.Pack(resp, out)
				if err != nil {
					return
				}
				binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
				c.Write(lenBuf)
				c.Write(packed)
			}(conn)
		}
	}()

	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	r := NewResolver(c, ResolverConfig{
		MaxDepth:        10,
		UpstreamTimeout: 2 * time.Second,
		UpstreamRetries: 1,
		UpstreamPort:    portStr,
	}, m, logger)

	_, err = r.queryUpstreamOnce("127.0.0.1", "x.example.", dns.TypeA, dns.ClassIN)
	if err == nil {
		t.Fatalf("expected error on TC=1 TCP response, got nil")
	}

	// Exactly one TCP attempt — the guard refused to recurse.
	if got := tcpRetries.Load(); got != 1 {
		t.Errorf("TCP attempts = %d, want 1 (guard should have stopped after first TC=1 TCP response)", got)
	}
}
