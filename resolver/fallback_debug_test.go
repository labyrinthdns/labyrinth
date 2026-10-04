package resolver

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

func TestQueryFallback_WritesDebugLog(t *testing.T) {
	fallbackMock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(),
				QDCount: 1,
				ANCount: 1,
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
			}},
		}
	})
	defer fallbackMock.close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "fallback.jsonl")
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		UpstreamPort:      fallbackMock.port,
		FallbackResolvers: []string{fallbackMock.ip},
		FallbackDebug:     true,
		FallbackLogPath:   logPath,
	}, m, logger)

	primary := &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus", DNSSECReason: "other"}
	got := r.queryFallbackWithPrimary("example.com", dns.TypeA, dns.ClassIN, "DNSSEC bogus", primary)
	if got == nil {
		t.Fatal("expected recovery")
	}

	deadline := time.Now().Add(2 * time.Second)
	var rec fallbackLogRecord
	for time.Now().Before(deadline) {
		f, err := os.Open(logPath)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		sc := bufio.NewScanner(f)
		if sc.Scan() {
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				f.Close()
				t.Fatal(err)
			}
			f.Close()
			break
		}
		f.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if rec.Name != "example.com" {
		t.Fatalf("log name=%q", rec.Name)
	}
	if rec.Reason != "DNSSEC bogus" {
		t.Fatalf("reason=%q", rec.Reason)
	}
	if rec.DNSSECStatus != "bogus" {
		t.Fatalf("dnssec_status=%q", rec.DNSSECStatus)
	}
	if !rec.Recovered {
		t.Fatal("expected recovered=true")
	}
	if rec.QTypeName != "A" {
		t.Fatalf("qtype_name=%q", rec.QTypeName)
	}
}

func TestQueryFallback_DebugOff_NoLog(t *testing.T) {
	fallbackMock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if len(q.Questions) == 0 {
			return nil
		}
		return &dns.Message{
			Header: dns.Header{
				Flags:   dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(),
				QDCount: 1,
				ANCount: 1,
			},
			Questions: q.Questions,
			Answers: []dns.ResourceRecord{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
			}},
		}
	})
	defer fallbackMock.close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "fallback.jsonl")
	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 86400, 3600, m)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := NewResolver(c, ResolverConfig{
		MaxDepth:          30,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		UpstreamPort:      fallbackMock.port,
		FallbackResolvers: []string{fallbackMock.ip},
		FallbackDebug:     false,
		FallbackLogPath:   logPath,
	}, m, logger)

	primary := &ResolveResult{RCODE: dns.RCodeServFail, DNSSECStatus: "bogus", DNSSECReason: "other"}
	got := r.queryFallbackWithPrimary("example.com", dns.TypeA, dns.ClassIN, "DNSSEC bogus", primary)
	if got == nil {
		t.Fatal("expected recovery")
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("fallback debug off should not write log: err=%v", err)
	}
}
