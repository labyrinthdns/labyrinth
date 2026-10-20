package resolver

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// refusingAuthMock refuses every iterative (RD=0) query and answers every
// recursive (RD=1) one, so the primary resolution fails at the root and the
// same mock, used as the fallback resolver, recovers the name.
func refusingAuthMock(t *testing.T) *mockDNSServer {
	return startMockDNS(t, func(q *dns.Message) *dns.Message {
		if q.Header.RD() {
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(), QDCount: 1, ANCount: 1},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{127, 0, 0, 2},
				}},
			}
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeRefused).Build(), QDCount: 1},
			Questions: q.Questions,
		}
	})
}

func fallbackLogResolver(t *testing.T, mock *mockDNSServer) (*Resolver, string) {
	logPath := filepath.Join(t.TempDir(), "fallback.jsonl")
	m := metrics.NewMetrics()
	r := NewResolver(cache.NewCache(100, 5, 86400, 3600, m), ResolverConfig{
		MaxDepth:          30,
		MaxCNAMEDepth:     10,
		UpstreamTimeout:   2 * time.Second,
		UpstreamRetries:   1,
		UpstreamPort:      mock.port,
		FallbackResolvers: []string{mock.ip},
		FallbackDebug:     true,
		FallbackLogPath:   logPath,
	}, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	r.rootServers = []NameServer{{Name: "mock.root", IPv4: mock.ip}}
	return r, logPath
}

func readFallbackLog(t *testing.T, path string) []fallbackLogRecord {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var recs []fallbackLogRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec fallbackLogRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
	}
	return recs
}

// TestFallbackLog_RecordsPrimaryAttempts: the fallback log names each
// failed authoritative exchange of the primary resolution, so a burst of
// recovered queries (live: hourly DNSBL bursts, all "no reachable
// nameserver") shows whether the servers timed out, refused or were lame.
func TestFallbackLog_RecordsPrimaryAttempts(t *testing.T) {
	mock := refusingAuthMock(t)
	defer mock.close()
	r, logPath := fallbackLogResolver(t, mock)

	res, err := r.Resolve("www.example.com", dns.TypeA, dns.ClassIN)
	if err != nil || res == nil || res.RCODE != dns.RCodeNoError {
		t.Fatalf("res=%+v err=%v, want the fallback's answer", res, err)
	}
	recs := readFallbackLog(t, logPath)
	if len(recs) != 1 || !recs[0].Recovered {
		t.Fatalf("fallback log = %+v, want one recovered record", recs)
	}
	want := ".@" + mock.ip + ": REFUSED"
	found := false
	for _, a := range recs[0].PrimaryAttempts {
		if a == want {
			found = true
		}
	}
	if !found {
		t.Errorf("primary_attempts = %q, want an entry %q", recs[0].PrimaryAttempts, want)
	}
}

// TestFallback_SkipsPublicResolverBlockedDNSBLs: Spamhaus, URIBL and SURBL
// answer queries from large public resolvers with a policy code (Spamhaus
// 127.255.255.254, URIBL 127.0.0.1) instead of the listing. Such an answer
// would reach a mail server as a listing, so these names never use the
// fallback; other DNSBLs (Barracuda, SpamCop) answer public resolvers
// correctly and keep it.
func TestFallback_SkipsPublicResolverBlockedDNSBLs(t *testing.T) {
	mock := refusingAuthMock(t)
	defer mock.close()
	r, logPath := fallbackLogResolver(t, mock)

	for _, name := range []string{
		"2.0.0.127.zen.spamhaus.org",
		"dbltest.com.dbl.spamhaus.org",
		"key.zen.dq.spamhaus.net",
		"test.uribl.com.multi.uribl.com",
		"test.surbl.org.multi.surbl.org",
	} {
		res, _ := r.Resolve(name, dns.TypeA, dns.ClassIN)
		if res == nil || res.RCODE != dns.RCodeServFail {
			t.Errorf("%s: rcode=%v, want SERVFAIL without fallback", name, res)
		}
	}
	if recs := readFallbackLog(t, logPath); len(recs) != 0 {
		t.Errorf("blocked DNSBL names reached the fallback: %+v", recs)
	}

	res, _ := r.Resolve("2.0.0.127.b.barracudacentral.org", dns.TypeA, dns.ClassIN)
	if res == nil || res.RCODE != dns.RCodeNoError {
		t.Errorf("barracudacentral: res=%+v, want the fallback's answer", res)
	}
	for _, n := range []string{"spamhaus.org", "x.spamhaus.org", "ZEN.SPAMHAUS.ORG."} {
		if !publicResolverBlockedZone(n) {
			t.Errorf("publicResolverBlockedZone(%q) = false", n)
		}
	}
	for _, n := range []string{"notspamhaus.org", "spamhaus.org.example.com", "b.barracudacentral.org"} {
		if publicResolverBlockedZone(n) {
			t.Errorf("publicResolverBlockedZone(%q) = true", n)
		}
	}
}

// TestFallback_ConcurrentFailuresShareOneExchange: the primary resolution
// of concurrent identical queries is coalesced, and so is the fallback
// that follows. Live: buddhaonline.art asked by three clients in the same
// second produced three fallback exchanges and three log lines.
func TestFallback_ConcurrentFailuresShareOneExchange(t *testing.T) {
	var recursive atomic.Int32
	release := make(chan struct{})
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		if q.Header.RD() {
			recursive.Add(1)
			<-release
			return &dns.Message{
				Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).Build(), QDCount: 1, ANCount: 1},
				Questions: q.Questions,
				Answers: []dns.ResourceRecord{{
					Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN,
					TTL: 300, RDLength: 4, RData: []byte{127, 0, 0, 2},
				}},
			}
		}
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetRCODE(dns.RCodeRefused).Build(), QDCount: 1},
			Questions: q.Questions,
		}
	})
	defer mock.close()
	r, logPath := fallbackLogResolver(t, mock)

	const n = 3
	var wg sync.WaitGroup
	results := make([]*ResolveResult, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = r.Resolve("www.coalesce.com", dns.TypeA, dns.ClassIN)
		}(i)
	}
	deadline := time.Now().Add(5 * time.Second)
	for recursive.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // let the other waiters join
	close(release)
	wg.Wait()

	for i, res := range results {
		if res == nil || res.RCODE != dns.RCodeNoError || len(res.Answers) != 1 {
			t.Errorf("client %d: res=%+v, want the fallback's answer", i, res)
		}
	}
	if got := recursive.Load(); got != 1 {
		t.Errorf("fallback asked %d times, want 1", got)
	}
	if recs := readFallbackLog(t, logPath); len(recs) != 1 {
		t.Errorf("fallback log has %d records, want 1", len(recs))
	}
}
