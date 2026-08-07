package secondary

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testResolver returns a real resolver rather than nil.
//
// The manager republishes the local zone table through it on every change, so
// a nil resolver would mean either a panic in the tests or a nil check in
// production code that exists only to serve them. A real resolver is cheap
// here and keeps the production path free of test-shaped conditionals.
func testResolver(t *testing.T) *resolver.Resolver {
	t.Helper()
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	return resolver.NewResolver(c, resolver.ResolverConfig{MaxDepth: 5}, m, discardLogger())
}

// cancelledContext returns an already-cancelled context, so a zone loop
// started during a reconcile test exits immediately instead of trying to
// reach a primary that does not exist.
func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// buildSOARDATA constructs SOA RDATA for tests.
func buildSOARDATA(mname, rname string, serial, refresh, retry, expire, minimum uint32) []byte {
	out := append([]byte{}, dns.BuildPlainName(mname)...)
	out = append(out, dns.BuildPlainName(rname)...)
	timers := make([]byte, 20)
	binary.BigEndian.PutUint32(timers[0:4], serial)
	binary.BigEndian.PutUint32(timers[4:8], refresh)
	binary.BigEndian.PutUint32(timers[8:12], retry)
	binary.BigEndian.PutUint32(timers[12:16], expire)
	binary.BigEndian.PutUint32(timers[16:20], minimum)
	return append(out, timers...)
}

func testSOA(t *testing.T, zone string, serial uint32) dns.ResourceRecord {
	t.Helper()
	rdata := buildSOARDATA("ns1."+zone, "admin."+zone, serial, 3600, 900, 604800, 86400)
	return dns.ResourceRecord{
		Name: zone, Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 3600,
		RData: rdata, RDLength: uint16(len(rdata)),
	}
}
