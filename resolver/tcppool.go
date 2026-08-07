package resolver

import (
	"context"
	"net"
	"sync"
	"time"
)

// RFC 7766 §6.2.1: "In order to achieve performance on par with UDP, DNS
// clients SHOULD support connection reuse." Labyrinth did not — every TCP
// query dialled a fresh connection and closed it on the way out.
//
// That is a real cost, and it lands exactly where it hurts. TCP is not a rare
// path for a validating resolver: DNSKEY and large signed RRsets routinely
// exceed the 1232-byte EDNS buffer, so a TC=1 retry over TCP is part of the
// normal DNSSEC chain walk. Paying a three-way handshake for each one adds a
// full round trip to the critical path of resolving a signed name, and on the
// authoritative side it turns a steady query stream into a steady stream of
// connection setups and TIME_WAIT sockets.
//
// This pool reuses idle connections sequentially — one outstanding query per
// connection at a time. It deliberately does NOT pipeline. RFC 7766 §6.2.1.1
// permits multiple outstanding queries with out-of-order responses, which
// requires demultiplexing replies by message ID and handling the case where a
// server answers query 3 before query 1. That machinery buys throughput on a
// busy forwarder; the handshake elimination is where nearly all the latency
// win is, and sequential reuse gets it without the complexity of a
// multiplexer that could mismatch a response to the wrong query.
//
// The safety-critical property is that a connection is returned to the pool
// only after a *clean* exchange. Any error — timeout mid-read, short write,
// transaction-ID mismatch — leaves the stream in an unknown state with
// possibly-unread bytes still in flight, so the connection is closed rather
// than handed to the next caller who would read the tail of someone else's
// answer as the head of their own.

const (
	// tcpPoolMaxIdlePerHost bounds idle connections kept per authoritative
	// address. A resolver talks to one authoritative from many concurrent
	// resolutions, but idle connections beyond a handful just consume file
	// descriptors on both ends.
	tcpPoolMaxIdlePerHost = 4

	// tcpPoolMaxIdleTotal bounds the whole pool. A resolver walking the
	// long tail of the DNS touches thousands of authoritative IPs in an
	// hour; without a global cap the idle set would track that tail and
	// exhaust the process file-descriptor limit.
	tcpPoolMaxIdleTotal = 256

	// tcpPoolIdleTimeout is how long an unused connection is kept. RFC 7766
	// §6.2.3 tells clients to close idle connections and notes servers may
	// close them unilaterally at any time, so this is a local hygiene bound
	// rather than a negotiated one — kept well under the ~10s that common
	// authoritative implementations use, so we usually close first instead
	// of discovering a half-closed socket on the next query.
	tcpPoolIdleTimeout = 8 * time.Second
)

// pooledTCPConn is an idle connection plus the time it went idle.
type pooledTCPConn struct {
	conn     net.Conn
	idleFrom time.Time
}

// tcpConnPool holds idle upstream TCP connections keyed by "ip:port".
//
// A zero value is not usable; construct with newTCPConnPool. All methods are
// nil-safe so a resolver built without a pool (test paths) transparently
// falls back to dial-per-query.
type tcpConnPool struct {
	mu        sync.Mutex
	idle      map[string][]pooledTCPConn
	idleCount int
	closed    bool
}

func newTCPConnPool() *tcpConnPool {
	return &tcpConnPool{idle: make(map[string][]pooledTCPConn)}
}

// get returns an idle connection for addr, or nil when none is available.
//
// Connections that have been idle past tcpPoolIdleTimeout are closed rather
// than returned: the peer has very likely closed its end already, and
// discovering that costs a failed write plus a retry on the query's critical
// path. Closing them here moves that cost off the hot path.
func (p *tcpConnPool) get(addr string) net.Conn {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}

	conns := p.idle[addr]
	now := time.Now()
	// Walk from the most recently returned end: those are the least likely
	// to have been reaped by the peer.
	for len(conns) > 0 {
		last := len(conns) - 1
		c := conns[last]
		conns = conns[:last]
		p.idleCount--

		if now.Sub(c.idleFrom) > tcpPoolIdleTimeout {
			c.conn.Close()
			continue
		}
		if len(conns) == 0 {
			delete(p.idle, addr)
		} else {
			p.idle[addr] = conns
		}
		return c.conn
	}
	delete(p.idle, addr)
	return nil
}

// put returns a connection to the pool after a clean exchange. The connection
// is closed instead when the pool is full or shut down — dropping a reusable
// connection is always safe, whereas exceeding the cap is not.
//
// Callers MUST NOT put back a connection whose exchange errored. See the
// package comment: a poisoned stream handed to the next caller returns the
// wrong answer rather than an error, which is far worse than a reconnect.
func (p *tcpConnPool) put(addr string, conn net.Conn) {
	if p == nil || conn == nil {
		if conn != nil {
			conn.Close()
		}
		return
	}

	p.mu.Lock()
	if p.closed || p.idleCount >= tcpPoolMaxIdleTotal || len(p.idle[addr]) >= tcpPoolMaxIdlePerHost {
		p.mu.Unlock()
		conn.Close()
		return
	}
	// Clear any deadline left over from the exchange. A pooled connection
	// carrying a past deadline would fail instantly for the next caller,
	// who would then blame the peer for a timeout we set ourselves.
	_ = conn.SetDeadline(time.Time{})
	p.idle[addr] = append(p.idle[addr], pooledTCPConn{conn: conn, idleFrom: time.Now()})
	p.idleCount++
	p.mu.Unlock()
}

// StartTCPPoolCleanup runs the idle-connection sweeper until ctx is done,
// then closes the pool.
//
// get() already discards connections that went idle too long, so the sweeper
// is not needed for correctness — it is needed for manners. Without it, a
// resolver that queried an authoritative over TCP once and then went quiet
// would hold that socket open on the authoritative's side until the peer
// timed it out. RFC 7766 §6.2.3 puts the onus on the client to close idle
// connections, and a busy authoritative serving thousands of resolvers
// notices when they do not.
func (r *Resolver) StartTCPPoolCleanup(ctx context.Context) {
	if r.tcpPool == nil {
		return
	}
	defer r.tcpPool.Close()

	ticker := time.NewTicker(tcpPoolIdleTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tcpPool.sweep()
		}
	}
}

// sweep closes connections that have been idle past the timeout. Called
// periodically so a pool that stops seeing traffic does not hold sockets open
// against an authoritative indefinitely.
func (p *tcpConnPool) sweep() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for addr, conns := range p.idle {
		kept := conns[:0]
		for _, c := range conns {
			if now.Sub(c.idleFrom) > tcpPoolIdleTimeout {
				c.conn.Close()
				p.idleCount--
				continue
			}
			kept = append(kept, c)
		}
		if len(kept) == 0 {
			delete(p.idle, addr)
		} else {
			p.idle[addr] = kept
		}
	}
}

// Close shuts the pool down and closes every idle connection. Subsequent
// get calls return nil and put calls close immediately, so an in-flight query
// holding a connection still completes — it just does not get pooled.
func (p *tcpConnPool) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true
	for addr, conns := range p.idle {
		for _, c := range conns {
			c.conn.Close()
		}
		delete(p.idle, addr)
	}
	p.idleCount = 0
}

// idleLen reports the number of pooled connections. Test helper.
func (p *tcpConnPool) idleLen() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.idleCount
}
