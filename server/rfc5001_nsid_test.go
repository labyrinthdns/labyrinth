package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// RFC 5001 (Name Server Identifier) exists for one operational reason: on an
// anycast deployment, every node answers on the same address, so when one
// node in a cluster starts returning wrong answers there is no in-band way to
// tell which one you reached. NSID is that way — the client asks with an
// empty NSID option, the server names itself in the reply.
//
// Two properties make or break it, and both are pinned here:
//
//   - It must work on UDP. The failure mode operators chase (a single
//     misrouted anycast node) is a UDP-path phenomenon; an NSID that only
//     appeared on TCP would be absent exactly when it is needed.
//   - It must be off unless configured. RFC 5001 §3.1 warns the identifier
//     is disclosed to anyone who asks, so a server that defaulted to its
//     hostname would leak internal topology to the open Internet.

func nsidTestHandler(t *testing.T, id string) *MainHandler {
	t.Helper()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, metrics.NewMetrics())
	h := NewMainHandler(newPanickingResolver(ca), ca, nil, nil, nil, metrics.NewMetrics(), discardLogger())
	if id != "" {
		h.SetNSID(id)
	}
	return h
}

// nsidQuery builds a query carrying an NSID request. RFC 5001 §2.1 specifies
// the request form as the option code with zero-length data.
func nsidQuery(t *testing.T, withNSID bool) []byte {
	t.Helper()
	var opts []dns.EDNSOption
	if withNSID {
		opts = append(opts, dns.EDNSOption{Code: dns.EDNSOptionCodeNSID, Data: nil})
	}
	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x5001,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions:  []dns.Question{{Name: "nsid.example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{dns.BuildOPTWithOptions(1232, false, opts)},
	}
	packed, err := dns.Pack(msg, make([]byte, 512))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return packed
}

// responseNSID returns the NSID payload from a wire response, and whether the
// option was present at all.
func responseNSID(t *testing.T, resp []byte) ([]byte, bool) {
	t.Helper()
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	for i := range msg.Additional {
		if msg.Additional[i].Type != dns.TypeOPT {
			continue
		}
		edns, err := dns.ParseOPT(&msg.Additional[i])
		if err != nil {
			t.Fatalf("parse OPT: %v", err)
		}
		for _, o := range edns.Options {
			if o.Code == dns.EDNSOptionCodeNSID {
				return o.Data, true
			}
		}
	}
	return nil, false
}

// TestRFC5001_NSIDEchoedWhenRequested pins the core exchange: configured
// identifier + client request → identifier in the response.
func TestRFC5001_NSIDEchoedWhenRequested(t *testing.T) {
	h := nsidTestHandler(t, "ams-01")

	resp, err := h.Handle(nsidQuery(t, true), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	got, ok := responseNSID(t, resp)
	if !ok {
		t.Fatal("response carries no NSID option — RFC 5001 §2.3 requires a " +
			"configured server to answer an NSID request with its identifier")
	}
	if string(got) != "ams-01" {
		t.Fatalf("NSID = %q, want %q", got, "ams-01")
	}
}

// TestRFC5001_NoNSIDUnlessRequested pins that the identifier is not
// volunteered. RFC 5001 §2.3 makes the response conditional on the request;
// attaching it unconditionally would put the node name in every packet on the
// wire, including to clients that never asked.
func TestRFC5001_NoNSIDUnlessRequested(t *testing.T) {
	h := nsidTestHandler(t, "ams-01")

	resp, err := h.Handle(nsidQuery(t, false), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if got, ok := responseNSID(t, resp); ok {
		t.Fatalf("response carries NSID %q for a query that did not request it — "+
			"RFC 5001 §2.3 makes the response conditional on the request", got)
	}
}

// TestRFC5001_DisabledByDefault pins the privacy default. An operator who has
// not set server.nsid must not have their node identified, even to a client
// that explicitly asks — the absence of an answer is itself the correct
// answer (RFC 5001 §3.1).
func TestRFC5001_DisabledByDefault(t *testing.T) {
	h := nsidTestHandler(t, "") // no SetNSID call at all

	resp, err := h.Handle(nsidQuery(t, true), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if got, ok := responseNSID(t, resp); ok {
		t.Fatalf("unconfigured server disclosed NSID %q — RFC 5001 §3.1 warns "+
			"the identifier is visible to any client, so emitting one the "+
			"operator never set leaks topology", got)
	}
}

// TestRFC5001_EmptyStringDisables pins that explicitly clearing the setting
// (config hot-reload sets it to "") turns NSID back off rather than emitting
// a zero-length option, which a client would read as "I am nobody" instead of
// "I do not participate".
func TestRFC5001_EmptyStringDisables(t *testing.T) {
	h := nsidTestHandler(t, "ams-01")
	h.SetNSID("") // operator removed server.nsid and reloaded

	resp, err := h.Handle(nsidQuery(t, true), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if _, ok := responseNSID(t, resp); ok {
		t.Fatal("NSID still emitted after being cleared — SetNSID(\"\") must disable")
	}
}

// TestRFC5001_IdentifierTruncated pins the MaxNSIDLength ceiling. RFC 5001
// sets no limit, so the bound is ours: the option rides in every response to
// a requesting client, and an operator pasting something long into the config
// should not quietly push responses past the UDP buffer into TCP fallback.
func TestRFC5001_IdentifierTruncated(t *testing.T) {
	long := strings.Repeat("x", dns.MaxNSIDLength*2)
	h := nsidTestHandler(t, long)

	resp, err := h.Handle(nsidQuery(t, true), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	got, ok := responseNSID(t, resp)
	if !ok {
		t.Fatal("no NSID option in response")
	}
	if len(got) != dns.MaxNSIDLength {
		t.Fatalf("NSID length = %d, want %d (truncated at MaxNSIDLength)", len(got), dns.MaxNSIDLength)
	}
}

// TestRFC5001_OpaqueBytesPreserved pins RFC 5001 §2.3: the payload is an
// opaque byte string. A well-meaning implementation that hex-encoded it, or
// null-terminated it, or rejected non-UTF-8, would break operators who encode
// structured data (a packed site+instance id) in the field.
func TestRFC5001_OpaqueBytesPreserved(t *testing.T) {
	raw := string([]byte{0x00, 0xFF, 0x41, 0x7F, 0x80})
	h := nsidTestHandler(t, raw)

	resp, err := h.Handle(nsidQuery(t, true), nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	got, ok := responseNSID(t, resp)
	if !ok {
		t.Fatal("no NSID option in response")
	}
	if !bytes.Equal(got, []byte(raw)) {
		t.Fatalf("NSID = %v, want %v — RFC 5001 §2.3 payload is opaque and must "+
			"survive verbatim", got, []byte(raw))
	}
}

// TestRFC5001_CoexistsWithCookie pins that NSID does not displace options
// attached earlier in the response pipeline. Cookies (RFC 7873) are appended
// to the same OPT RR just before NSID; a rebuild-instead-of-append bug in
// either path would silently drop the other option.
func TestRFC5001_CoexistsWithCookie(t *testing.T) {
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, metrics.NewMetrics())
	h := NewMainHandler(newPanickingResolver(ca), ca, nil, nil, nil, metrics.NewMetrics(), discardLogger())
	h.EnableCookiesWithSecret(make([]byte, 16))
	h.SetNSID("ams-01")

	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x5001,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: "nsid.example.com", Type: dns.TypeA, Class: dns.ClassIN}},
		Additional: []dns.ResourceRecord{
			dns.BuildOPTWithOptions(1232, false, []dns.EDNSOption{
				{Code: dns.EDNSOptionCodeCookie, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
				{Code: dns.EDNSOptionCodeNSID, Data: nil},
			}),
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

	parsed, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	var sawCookie, sawNSID bool
	for i := range parsed.Additional {
		if parsed.Additional[i].Type != dns.TypeOPT {
			continue
		}
		edns, perr := dns.ParseOPT(&parsed.Additional[i])
		if perr != nil {
			t.Fatalf("parse OPT: %v", perr)
		}
		for _, o := range edns.Options {
			switch o.Code {
			case dns.EDNSOptionCodeCookie:
				sawCookie = true
			case dns.EDNSOptionCodeNSID:
				sawNSID = true
			}
		}
	}
	if !sawCookie {
		t.Error("cookie option lost after NSID was attached")
	}
	if !sawNSID {
		t.Error("NSID option missing when a cookie was also attached")
	}
}
