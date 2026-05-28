package resolver

import (
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestPrimeRootHints_QueryShape_RFC8109 pins the exact on-wire shape
// of the priming query. RFC 8109 §3 says the priming MUST be a query
// for the root zone's NS RRset:
//
//   QNAME  = "."  (root, encoded as a single zero byte on the wire)
//   QTYPE  = NS   (type 2)
//   QCLASS = IN   (class 1)
//
// A regression that asked for "." A (treating root like any other
// name) would still get a NOERROR-empty response from a real root
// server — the resolver would then mark itself ready with NO root NS
// records cached, and every subsequent iterative resolution would
// have to walk priming-from-scratch every query, defeating the
// entire RFC 8109 point.
//
// We instrument a mock root server that captures the first inbound
// query, then assert it on each of the three fields.
func TestPrimeRootHints_QueryShape_RFC8109(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock root: %v", err)
	}
	defer conn.Close()

	var (
		mu       sync.Mutex
		gotQName string
		gotType  uint16
		gotClass uint16
		captured bool
	)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := dns.Unpack(buf[:n])
			if err == nil && len(q.Questions) > 0 {
				mu.Lock()
				if !captured {
					gotQName = q.Questions[0].Name
					gotType = q.Questions[0].Type
					gotClass = q.Questions[0].Class
					captured = true
				}
				mu.Unlock()

				// Respond with an empty NOERROR so PrimeRootHints
				// believes the priming succeeded and returns. We
				// don't need real root NS data to validate the
				// query shape — we only need the goroutine to exit.
				resp := &dns.Message{
					Header:    dns.Header{ID: q.Header.ID, Flags: 0x8400, QDCount: 1},
					Questions: q.Questions,
				}
				out := make([]byte, 4096)
				packed, _ := dns.Pack(resp, out)
				conn.WriteTo(packed, addr)
			}
		}
	}()

	host, port, _ := net.SplitHostPort(conn.LocalAddr().String())

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		UpstreamTimeout: 1 * time.Second,
		UpstreamRetries: 1,
		UpstreamPort:    port,
	}, m, logger)

	// Override NameServers to ONLY our mock so the random pick is
	// deterministic.
	r.rootServers = []NameServer{{Name: "mock.root", IPv4: host}}

	if err := r.PrimeRootHints(); err != nil {
		t.Fatalf("PrimeRootHints: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !captured {
		t.Fatalf("mock root never received a query — PrimeRootHints did not actually dial")
	}
	// QNAME "." can be represented as "" (root encoded as nothing
	// after the trailing dot is stripped) or "." literally — both
	// represent the same root label. Accept either.
	if gotQName != "" && gotQName != "." {
		t.Errorf("priming QNAME = %q, want root (\"\" or \".\") — a regression that asked for a literal label would defeat RFC 8109", gotQName)
	}
	if gotType != dns.TypeNS {
		t.Errorf("priming QTYPE = %d, want NS (%d) — a regression to A or ANY would fetch wrong RRset and root NS cache would stay empty", gotType, dns.TypeNS)
	}
	if gotClass != dns.ClassIN {
		t.Errorf("priming QCLASS = %d, want IN (%d) — non-IN class is nonsensical for root NS", gotClass, dns.ClassIN)
	}
}

// TestPrimeRootHints_SetsReadyFlag pins the post-priming side effect:
// regardless of whether the priming itself succeeds in caching answers,
// the resolver MUST mark itself Ready so the rest of the daemon can
// proceed. A regression that gated ready=true on cache.Store actually
// succeeding would deadlock a resolver started during a root NS outage —
// even though normal queries against cached zones could still work.
func TestPrimeRootHints_SetsReadyFlag(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock: %v", err)
	}
	// Don't bother spawning a responder — every priming attempt times
	// out. PrimeRootHints MUST still mark ready (returns error but
	// sets r.ready.Store(true) before returning).
	defer conn.Close()

	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		UpstreamTimeout: 100 * time.Millisecond,
		UpstreamRetries: 1,
		UpstreamPort:    port,
	}, m, logger)
	r.rootServers = []NameServer{{Name: "dead.root", IPv4: "127.0.0.1"}}

	if r.IsReady() {
		t.Fatalf("resolver reported Ready before priming — gate is broken")
	}
	_ = r.PrimeRootHints() // expected to error
	if !r.IsReady() {
		t.Errorf("resolver did NOT mark Ready after priming attempt — a regression that ties Ready to success would deadlock under root outage")
	}
}
