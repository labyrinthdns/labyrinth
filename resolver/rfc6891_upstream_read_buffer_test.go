package resolver

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestQueryUDP_ReadBufferMatchesAdvertisedSize pins the fix for the
// silent UDP truncation gap (v0.7.44): if we advertise an EDNS UDP
// buffer size larger than the read buffer, the kernel delivers only
// the first `len(buf)` bytes from a single datagram and discards the
// rest. The next `dns.Unpack` mis-parses the truncated message —
// either returning a parse error or, worse, a structurally-valid
// but content-truncated message that the validator then trusts.
//
// The pin sets up a fake authoritative that replies with a 6000-byte
// payload on UDP, configures the resolver to advertise an 8 KiB EDNS
// UDP buffer, and asserts the full 6000-byte response makes it back
// to queryUDP — proving the read buffer scaled with the advertised
// size and did not silently truncate at the legacy 4096 cap.
func TestQueryUDP_ReadBufferMatchesAdvertisedSize(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	const payloadSize = 6000
	go func() {
		buf := make([]byte, 4096)
		for {
			_, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, payloadSize)
			resp[0] = 0xAA // sentinel byte so the test can identify the response
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	host, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}

	r := NewResolver(
		cache.NewCache(100, 5, 60, 10, metrics.NewMetrics()),
		ResolverConfig{
			MaxDepth:              30,
			MaxCNAMEDepth:         10,
			UpstreamTimeout:       2 * time.Second,
			UpstreamRetries:       1,
			UpstreamPort:          port, // route queryUDP to the fake auth
			UpstreamUDPBufferSize: 8192, // advertise > 4096 legacy floor
		},
		metrics.NewMetrics(),
		slog.Default(),
	)

	resp, err := r.queryUDP(host, []byte("test"))
	if err != nil {
		t.Fatalf("queryUDP: %v", err)
	}
	if len(resp) != payloadSize {
		t.Errorf("response length: got %d, want %d (read buffer silently truncated?)",
			len(resp), payloadSize)
	}
	if len(resp) > 0 && resp[0] != 0xAA {
		t.Errorf("response[0]: got %#02x, want 0xAA (corrupted bytes)", resp[0])
	}
}
