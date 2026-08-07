package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// RFC 7873 §5.2.3: a server that supports cookies and receives a query with a
// client cookie "SHALL" return a response containing a server cookie. The
// wording admits no exception for where the answer came from.
//
// Labyrinth had one anyway. The single attach site sat below the cache-hit
// return in Handle, so the rule held only for queries that went all the way
// through recursive resolution. On a warm resolver — which is to say, in
// production — most queries are cache hits, so most cookie-carrying clients
// got no server cookie back.
//
// The failure is quiet, which is why it survived: the client keeps using the
// server cookie it was issued on some earlier cache miss. It only surfaces
// after a server-secret rotation, when that stored cookie stops validating,
// and every such client eats an extra BADCOOKIE round trip before it can be
// re-issued one. Under strict mode (§5.4) the same gap makes the cold-start
// path depend on hitting a cache miss first.
//
// These tests pin the rule at the two response shapes that skip resolution.

func cookieCacheTestHandler(t *testing.T) (*MainHandler, *cache.Cache) {
	t.Helper()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, metrics.NewMetrics())
	h := NewMainHandler(newPanickingResolver(ca), ca, nil, nil, nil, metrics.NewMetrics(), discardLogger())
	h.EnableCookiesWithSecret(make([]byte, 16))
	return h, ca
}

// cookieQuery builds a query carrying an 8-byte client cookie and no server
// cookie — the RFC 7873 §5.2.2 "bootstrap" shape a client uses before it has
// been issued one.
func cookieQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x7873,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: name, Type: qtype, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{
				{Code: dns.EDNSOptionCodeCookie, Data: []byte{0xC0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
			}),
		},
	}
	packed, err := dns.Pack(msg, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return packed
}

// responseCookie returns the COOKIE option payload from a response, and how
// many COOKIE options were present — the count matters because RFC 6891
// §6.1.1 permits each option code at most once.
func responseCookie(t *testing.T, resp []byte) ([]byte, int) {
	t.Helper()
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	var data []byte
	count := 0
	for i := range msg.Additional {
		if msg.Additional[i].Type != dns.TypeOPT {
			continue
		}
		edns, perr := dns.ParseOPT(&msg.Additional[i])
		if perr != nil {
			t.Fatalf("parse OPT: %v", perr)
		}
		for _, o := range edns.Options {
			if o.Code == dns.EDNSOptionCodeCookie {
				data = o.Data
				count++
			}
		}
	}
	return data, count
}

// TestRFC7873_ServerCookieOnCacheHit is the regression pin. Prime the cache,
// then query with a client cookie and require a server cookie back.
func TestRFC7873_ServerCookieOnCacheHit(t *testing.T) {
	h, ca := cookieCacheTestHandler(t)

	const name = "cached.example.com"
	ca.Store(name, dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name:  name,
		Type:  dns.TypeA,
		Class: dns.ClassIN,
		TTL:   300,
		RData: []byte{192, 0, 2, 1},
	}}, nil)

	resp, err := h.Handle(cookieQuery(t, name, dns.TypeA), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	// Confirm the answer really came from cache — if resolution ran, the
	// panicking resolver would have produced SERVFAIL and this test would
	// be pinning the wrong path.
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if msg.Header.RCODE() != dns.RCodeNoError || len(msg.Answers) == 0 {
		t.Fatalf("expected a cache hit with an answer, got rcode=%d answers=%d",
			msg.Header.RCODE(), len(msg.Answers))
	}

	cookie, count := responseCookie(t, resp)
	if count == 0 {
		t.Fatal("cache-hit response carries no COOKIE option — RFC 7873 §5.2.3 " +
			"requires a server cookie in reply to any query bearing a client cookie, " +
			"regardless of whether the answer came from cache")
	}
	if count > 1 {
		t.Fatalf("response carries %d COOKIE options — RFC 6891 §6.1.1 allows one", count)
	}
	// Client cookie (8) + server cookie (16) per RFC 9018 §4.
	if len(cookie) != 24 {
		t.Fatalf("cookie length = %d, want 24 (8-byte client + 16-byte server)", len(cookie))
	}
}

// TestRFC7873_ServerCookieOnErrorResponse pins the same rule for a response
// that never reaches the resolver at all. A client debugging why it is being
// refused still needs a usable cookie for its retry.
func TestRFC7873_ServerCookieOnErrorResponse(t *testing.T) {
	h, _ := cookieCacheTestHandler(t)

	// The panicking resolver drives this to SERVFAIL without a cache entry.
	resp, err := h.Handle(cookieQuery(t, "servfail.example.com", dns.TypeA), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	_, count := responseCookie(t, resp)
	if count == 0 {
		t.Error("error response carries no COOKIE option — the client cannot " +
			"refresh its pair on the very path where it most needs to retry")
	}
	if count > 1 {
		t.Errorf("response carries %d COOKIE options — RFC 6891 §6.1.1 allows one", count)
	}
}

// TestRFC7873_BadCookieResponseNotDoubled pins the idempotence guard.
// buildBadCookieResponse issues its own fresh server cookie, and that
// response then passes through the same decorator that attaches cookies to
// everything else. Without the guard the client would receive two COOKIE
// options and, per RFC 6891 §6.1.1, be entitled to treat the response as
// malformed.
func TestRFC7873_BadCookieResponseNotDoubled(t *testing.T) {
	h, _ := cookieCacheTestHandler(t)
	h.SetCookiesEnforce(true) // §5.4 strict mode: cookie-less UDP gets BADCOOKIE

	// A query with a client cookie but a *wrong* server cookie triggers the
	// BADCOOKIE path.
	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x7873,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "bad.example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{{
				Code: dns.EDNSOptionCodeCookie,
				Data: []byte{
					0xC0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // client
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // bogus server
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				},
			}}),
		},
	}
	query, err := dns.Pack(msg, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	resp, err := h.Handle(query, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if _, count := responseCookie(t, resp); count > 1 {
		t.Errorf("BADCOOKIE response carries %d COOKIE options — the decorator "+
			"must not append on top of the one buildBadCookieResponse already "+
			"issued (RFC 6891 §6.1.1)", count)
	}
}
