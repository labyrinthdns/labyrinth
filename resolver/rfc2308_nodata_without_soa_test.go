package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestClassify_AuthoritativeNoDataWithoutSOA pins RFC 2308 §2.2 "NODATA
// type 3": AA=1, NOERROR, empty answer and authority sections. Live, the
// merlincdn.net and bplslb.com servers answer AAAA this way (behind
// www.hurriyet.com.tr and www.tgrthaber.com) and the names were SERVFAIL
// here while public resolvers returned NODATA. The same empty reply
// without AA is a lame server and stays a failure.
func TestClassify_AuthoritativeNoDataWithoutSOA(t *testing.T) {
	for _, tc := range []struct {
		aa    bool
		rcode uint8
		want  responseType
	}{
		{true, dns.RCodeNoError, responseNoData},
		{false, dns.RCodeNoError, responseServFail},
		// Any other RCODE (here BADCOOKIE's low bits, 7) is not a NODATA.
		{true, 7, responseServFail},
	} {
		msg := &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(tc.aa).SetRCODE(tc.rcode).Build(), QDCount: 1},
			Questions: []dns.Question{{Name: "cdn.example.net", Type: dns.TypeAAAA, Class: dns.ClassIN}},
		}
		if got := classifyResponse(msg, "cdn.example.net", dns.TypeAAAA); got != tc.want {
			t.Errorf("AA=%v rcode=%d: got %d, want %d", tc.aa, tc.rcode, got, tc.want)
		}
	}
}

// TestResolve_NoDataWithoutSOAIsNotCached: the SOA-less NODATA reaches the
// client as NOERROR with no answers, and is not negatively cached (RFC 2308
// §5) because there is no SOA to take a negative TTL from.
func TestResolve_NoDataWithoutSOAIsNotCached(t *testing.T) {
	mock := startMockDNS(t, func(q *dns.Message) *dns.Message {
		return &dns.Message{
			Header:    dns.Header{Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()},
			Questions: q.Questions,
		}
	})
	defer mock.close()

	r := testResolver(t, mock)
	result, err := r.Resolve("cdn.example.net", dns.TypeAAAA, dns.ClassIN)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCODE != dns.RCodeNoError || len(result.Answers) != 0 {
		t.Fatalf("rcode=%d answers=%d, want NOERROR with no answers", result.RCODE, len(result.Answers))
	}
	if entry, ok := r.cache.Get("cdn.example.net", dns.TypeAAAA, dns.ClassIN); ok && entry != nil {
		t.Errorf("SOA-less NODATA was cached: %+v", entry)
	}
}
