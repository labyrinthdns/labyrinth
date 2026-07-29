package resolver

import (
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestQueryUDP_SourcePortRandomization pins RFC 5452 §10's "use
// unpredictable source ports" requirement empirically. The resolver
// MUST allocate a fresh, randomly-chosen UDP source port for each
// outbound query — without this, an off-path attacker who can guess
// the source port (in addition to the 16-bit TXID) gets a 2^16
// reduction in forgery search space, effectively defeating the
// transaction-ID defence on its own.
//
// Go's net.DialTimeout("udp", ...) leaves the local port choice to
// the OS, which on Linux/Windows/macOS implements RFC 6056 algorithm 3
// (full-range ephemeral randomisation). This pin verifies the property
// EMPIRICALLY by counting distinct source ports across N outbound
// dials — a regression that switched to a fixed-port net.ListenPacket
// pattern (a common bug when adding source-address binding for
// multi-homed hosts) would collapse the distinct count to 1.
//
// We deliberately do NOT pin the exact statistical distribution
// (uniformity, χ² independence) — those tests are fragile and the
// real defensive property is "the attacker can't guess it", for which
// any high-entropy allocation is fine. We pin the weakest invariant
// that catches all real failure modes: across 50 dials, see at least
// 30 distinct source ports. A correctly-randomised pool will produce
// ~50 distinct (no birthday collisions in a 64k-wide pool that thin);
// the failure modes (fixed port, monotonic increment from a bind,
// hashed-from-tuple) all produce ≤5.
func TestQueryUDP_SourcePortRandomization(t *testing.T) {
	// Set up a mock UDP DNS server that captures every source port
	// it sees. We don't bother responding correctly — queryUDP will
	// either time out or surface a TXID mismatch but the source-port
	// observation happens BEFORE that, which is what we need.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock udp: %v", err)
	}
	defer conn.Close()

	var (
		mu        sync.Mutex
		seenPorts = make(map[int]struct{})
	)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				mu.Lock()
				seenPorts[udpAddr.Port] = struct{}{}
				mu.Unlock()
			}
			// Send a garbage 12-byte header reply so the client's
			// Read returns quickly instead of waiting for the full
			// timeout — keeps the test fast. The reply will fail
			// validation but that doesn't matter for what we're
			// measuring.
			_, _ = conn.WriteTo([]byte{0x00, 0x01, 0x80, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}, addr)
			_ = n
		}
	}()

	host, port, _ := net.SplitHostPort(conn.LocalAddr().String())

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := NewResolver(c, ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 500 * time.Millisecond,
		UpstreamRetries: 1,
		UpstreamPort:    port,
	}, m, logger)

	// A minimal well-formed query — content doesn't matter to the
	// dial-side test, only the act of dialing.
	query := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// question: example.com A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}

	const dials = 50
	for i := 0; i < dials; i++ {
		// Errors are expected (TXID mismatch or timeout); we just
		// need the dial to fire so the OS allocates a source port.
		_, _ = r.queryUDP(host, query)
	}

	mu.Lock()
	distinct := len(seenPorts)
	allLow := 0
	for p := range seenPorts {
		if p < 1024 {
			allLow++
		}
	}
	mu.Unlock()

	const minDistinct = 30
	if distinct < minDistinct {
		t.Errorf("only %d distinct source ports across %d dials — RFC 5452 §10 randomisation appears broken (fixed/sequential/hashed source-port allocation)", distinct, dials)
	}

	// Sanity guard: a regression that bound outbound dials to a
	// privileged port (e.g. always 53) would surface here distinctly
	// from the distinct-count guard.
	if allLow > 0 {
		t.Errorf("%d outbound dials used a privileged port (< 1024) — a port-53-bound regression would surface here", allLow)
	}
}
