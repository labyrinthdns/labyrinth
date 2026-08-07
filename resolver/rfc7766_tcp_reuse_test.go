package resolver

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// RFC 7766 §6.2.1: "In order to achieve performance on par with UDP, DNS
// clients SHOULD support connection reuse."
//
// The reason this matters for a *validating* resolver specifically: DNSKEY
// RRsets and large signed answers routinely exceed the 1232-byte EDNS buffer,
// so TC=1 fallback to TCP is a normal step in a DNSSEC chain walk, not an
// exceptional one. Dialling per query adds a full three-way handshake to the
// critical path of every signed lookup.
//
// The interesting cases are not the happy path but the ways reuse can go
// wrong, and those are what these tests concentrate on: a peer that closed
// the connection while it sat idle, and a stream that desynchronised.

// tcpTestServer is a minimal length-prefixed DNS-over-TCP server that counts
// accepted connections, so a test can distinguish "reused" from "redialled".
type tcpTestServer struct {
	ln         net.Listener
	conns      atomic.Int32
	queries    atomic.Int32
	closeAfter int32 // close the connection after N queries; 0 = never
	corruptID  bool  // reply with a mismatched transaction ID
	wg         sync.WaitGroup
}

func startTCPTestServer(t *testing.T) *tcpTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &tcpTestServer{ln: ln}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *tcpTestServer) addr() string { return s.ln.Addr().String() }

func (s *tcpTestServer) port() string {
	_, p, _ := net.SplitHostPort(s.ln.Addr().String())
	return p
}

func (s *tcpTestServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.conns.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.handle(conn)
		}()
	}
}

func (s *tcpTestServer) handle(conn net.Conn) {
	served := int32(0)
	for {
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(lenBuf))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		s.queries.Add(1)
		served++

		resp := buildTCPTestResponse(query, s.corruptID)
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}

		if s.closeAfter > 0 && served >= s.closeAfter {
			return // emulate an idle-timeout close by the peer
		}
	}
}

// buildTCPTestResponse echoes the query as a minimal NOERROR answer.
func buildTCPTestResponse(query []byte, corruptID bool) []byte {
	msg, err := dns.Unpack(query)
	if err != nil || len(msg.Questions) == 0 {
		return query
	}
	q := msg.Questions[0]
	resp := &dns.Message{
		Header:    dns.Header{ID: msg.Header.ID, Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()},
		Questions: msg.Questions,
		Answers: []dns.ResourceRecord{{
			Name: q.Name, Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RData: []byte{192, 0, 2, 1},
		}},
	}
	if corruptID {
		resp.Header.ID = msg.Header.ID ^ 0xFFFF
	}
	packed, err := dns.Pack(resp, make([]byte, 512))
	if err != nil {
		return query
	}
	out := make([]byte, len(packed))
	copy(out, packed)
	return out
}

func tcpReuseResolver(t *testing.T, port string) *Resolver {
	t.Helper()
	r := &Resolver{
		config: ResolverConfig{
			UpstreamTimeout: 2 * time.Second,
			UpstreamPort:    port,
		},
		tcpPool: newTCPConnPool(),
	}
	t.Cleanup(func() { r.tcpPool.Close() })
	return r
}

// buildTCPQuery packs a query with a caller-chosen transaction ID.
func buildTCPQuery(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	msg := &dns.Message{
		Header:    dns.Header{ID: id, Flags: dns.NewFlagBuilder().SetRD(true).Build()},
		Questions: []dns.Question{{Name: name, Type: dns.TypeA, Class: dns.ClassIN}},
	}
	packed, err := dns.Pack(msg, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	out := make([]byte, len(packed))
	copy(out, packed)
	return out
}

// TestRFC7766_ConnectionReused is the core pin: N queries to the same
// authoritative must cost one TCP handshake, not N.
func TestRFC7766_ConnectionReused(t *testing.T) {
	srv := startTCPTestServer(t)
	r := tcpReuseResolver(t, srv.port())
	host, _, _ := net.SplitHostPort(srv.addr())

	const queries = 5
	for i := 0; i < queries; i++ {
		q := buildTCPQuery(t, uint16(0x1000+i), "reuse.example.com")
		if _, err := r.queryTCP(host, q); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}

	if got := srv.queries.Load(); got != queries {
		t.Fatalf("server saw %d queries, want %d", got, queries)
	}
	if got := srv.conns.Load(); got != 1 {
		t.Fatalf("server accepted %d connections for %d queries — RFC 7766 §6.2.1 "+
			"connection reuse is not happening", got, queries)
	}
	if r.tcpPool.idleLen() != 1 {
		t.Errorf("pool holds %d idle connections after the run, want 1", r.tcpPool.idleLen())
	}
}

// TestRFC7766_StaleConnectionRetried pins the failure mode that makes naive
// reuse worse than no reuse. RFC 7766 §6.2.3 lets a server close an idle
// connection whenever it wants, and the client only discovers this by trying
// to use it. If that discovery surfaced as an error, enabling reuse would
// turn a harmless server-side timeout into a SERVFAIL for whichever client
// drew the stale connection.
func TestRFC7766_StaleConnectionRetried(t *testing.T) {
	srv := startTCPTestServer(t)
	srv.closeAfter = 1 // peer hangs up after answering once
	r := tcpReuseResolver(t, srv.port())
	host, _, _ := net.SplitHostPort(srv.addr())

	// First query: fresh dial, answered, connection pooled — then the
	// server closes its end.
	if _, err := r.queryTCP(host, buildTCPQuery(t, 0x2001, "stale.example.com")); err != nil {
		t.Fatalf("first query: %v", err)
	}

	// Give the close time to land on our side.
	time.Sleep(50 * time.Millisecond)

	// Second query draws the dead pooled connection. It MUST still succeed,
	// via a transparent redial.
	if _, err := r.queryTCP(host, buildTCPQuery(t, 0x2002, "stale.example.com")); err != nil {
		t.Fatalf("second query failed on a stale pooled connection — the redial "+
			"path is missing, so a routine server-side idle close becomes a "+
			"client-visible failure: %v", err)
	}

	if got := srv.conns.Load(); got < 2 {
		t.Errorf("server accepted %d connections, expected a redial after the close", got)
	}
}

// TestRFC7766_TXIDMismatchNotPooled pins the safety property that makes reuse
// sound. A desynchronised stream — one where the previous exchange left
// unread bytes — hands the next caller someone else's answer. The mismatch
// must be detected AND the connection must not go back in the pool, or every
// subsequent query on it inherits the same desynchronisation.
func TestRFC7766_TXIDMismatchNotPooled(t *testing.T) {
	srv := startTCPTestServer(t)
	srv.corruptID = true
	r := tcpReuseResolver(t, srv.port())
	host, _, _ := net.SplitHostPort(srv.addr())

	_, err := r.queryTCP(host, buildTCPQuery(t, 0x3001, "mismatch.example.com"))
	if err == nil {
		t.Fatal("a response with the wrong transaction ID was accepted — on a " +
			"reused connection this is how one query gets another's answer")
	}

	if n := r.tcpPool.idleLen(); n != 0 {
		t.Errorf("pool holds %d connections after a TXID mismatch, want 0 — "+
			"a poisoned stream must never be reused", n)
	}
}

// TestRFC7766_PoolCapPerHost pins the per-host idle bound. Concurrent
// resolutions against one authoritative each need their own connection
// (reuse here is sequential, not pipelined), but the surplus must be closed
// rather than parked.
func TestRFC7766_PoolCapPerHost(t *testing.T) {
	p := newTCPConnPool()
	defer p.Close()

	const addr = "192.0.2.1:53"
	var made []net.Conn
	for i := 0; i < tcpPoolMaxIdlePerHost+3; i++ {
		c1, c2 := net.Pipe()
		made = append(made, c1, c2)
		p.put(addr, c1)
	}
	t.Cleanup(func() {
		for _, c := range made {
			c.Close()
		}
	})

	if got := p.idleLen(); got != tcpPoolMaxIdlePerHost {
		t.Fatalf("pool holds %d idle connections for one host, cap is %d",
			got, tcpPoolMaxIdlePerHost)
	}
}

// TestRFC7766_IdleConnectionsExpire pins that a connection idle past the
// timeout is not handed out. The peer has very likely reaped it already, and
// discovering that costs a failed write plus a redial on the critical path.
func TestRFC7766_IdleConnectionsExpire(t *testing.T) {
	p := newTCPConnPool()
	defer p.Close()

	const addr = "192.0.2.2:53"
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	p.put(addr, c1)
	// Backdate the idle stamp past the timeout.
	p.mu.Lock()
	p.idle[addr][0].idleFrom = time.Now().Add(-2 * tcpPoolIdleTimeout)
	p.mu.Unlock()

	if got := p.get(addr); got != nil {
		t.Error("pool returned a connection that was idle past the timeout")
	}
	if n := p.idleLen(); n != 0 {
		t.Errorf("expired connection still counted: idleLen = %d, want 0", n)
	}
}

// TestRFC7766_SweepClosesIdle pins the background sweeper. get() alone is
// enough for correctness; the sweeper is what stops a resolver that went
// quiet from parking sockets on an authoritative indefinitely (RFC 7766
// §6.2.3 puts that obligation on the client).
func TestRFC7766_SweepClosesIdle(t *testing.T) {
	p := newTCPConnPool()
	defer p.Close()

	const addr = "192.0.2.3:53"
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	p.put(addr, c1)
	p.mu.Lock()
	p.idle[addr][0].idleFrom = time.Now().Add(-2 * tcpPoolIdleTimeout)
	p.mu.Unlock()

	p.sweep()

	if n := p.idleLen(); n != 0 {
		t.Errorf("sweep left %d idle connections, want 0", n)
	}
}

// TestRFC7766_NilPoolFallsBackToDialPerQuery pins that a resolver built
// without a pool still works. Several test constructors build a bare
// &Resolver{}, and the pool must be an optimisation rather than a
// prerequisite.
func TestRFC7766_NilPoolFallsBackToDialPerQuery(t *testing.T) {
	srv := startTCPTestServer(t)
	r := &Resolver{config: ResolverConfig{
		UpstreamTimeout: 2 * time.Second,
		UpstreamPort:    srv.port(),
	}} // tcpPool deliberately nil
	host, _, _ := net.SplitHostPort(srv.addr())

	for i := 0; i < 3; i++ {
		if _, err := r.queryTCP(host, buildTCPQuery(t, uint16(0x4000+i), "nilpool.example.com")); err != nil {
			t.Fatalf("query %d with a nil pool: %v", i, err)
		}
	}
	if got := srv.conns.Load(); got != 3 {
		t.Errorf("nil pool accepted %d connections for 3 queries, want 3 "+
			"(dial-per-query fallback)", got)
	}
}
