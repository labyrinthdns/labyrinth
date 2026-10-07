package web

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// TestZoneExport_RoundTrip is the strongest test for the export
// endpoint: build a local-zone table with a small zone, call the
// handler, parse the body as a BIND zone file with the parser
// shipped in `dns/zonefile_parser.go`, and verify the records come
// back identically. This is the same round-trip oracle used for the
// writer and parser, applied end-to-end through the HTTP handler.
func TestZoneExport_RoundTrip(t *testing.T) {
	srv := testAdminServerWithResolver(t)

	// Build a small zone with mixed record types.
	lz := resolver.NewLocalZoneTable([]resolver.LocalZone{
		{
			Name: "example.com",
			Type: resolver.LocalStatic,
			Records: []resolver.LocalRecord{
				{Name: "example.com", Type: dns.TypeSOA, TTL: 86400, RData: buildSOA(t,
					"ns.example.com.", "hostmaster.example.com.",
					2024010101, 7200, 3600, 1209600, 3600)},
				{Name: "example.com", Type: dns.TypeNS, TTL: 86400, RData: buildName(t, "ns.example.com.")},
				{Name: "www.example.com", Type: dns.TypeA, TTL: 300, RData: []byte{1, 2, 3, 4}},
			},
		},
	})
	srv.resolver.SetLocalZones(lz)

	req := httptest.NewRequest(http.MethodGet, "/api/zones/example.com/export", nil)
	rr := httptest.NewRecorder()
	srv.handleZoneExport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}

	// Parse the response back through the parser to verify the
	// round-trip is identity.
	body := rr.Body.String()
	got, err := dns.ParseZone("example.com.", []byte(body))
	if err != nil {
		t.Fatalf("ParseZone on response body: %v\nbody:\n%s", err, body)
	}
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3", len(got))
	}

	// Write a small zone and verify the response body matches the
	// writer's output for the same input. The endpoint is a thin
	// wrapper around dns.FormatZone, so this is the contract.
	src := []dns.ResourceRecord{
		{Name: "example.com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 86400, RData: buildSOA(t,
			"ns.example.com.", "hostmaster.example.com.",
			2024010101, 7200, 3600, 1209600, 3600)},
		{Name: "example.com.", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 86400, RData: buildName(t, "ns.example.com.")},
		{Name: "www.example.com.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: []byte{1, 2, 3, 4}},
	}
	expected, err := dns.FormatZone("example.com.", src)
	if err != nil {
		t.Fatalf("FormatZone: %v", err)
	}
	if body != string(expected) {
		t.Errorf("response body != FormatZone output\n got:\n%s\n want:\n%s", body, expected)
	}
}

// TestZoneExport_SOALessZoneRoundTrips pins the placeholder-SOA path at the
// HTTP layer.
//
// TestZoneExport_RoundTrip builds its zone with a hand-assembled SOA, which is
// the one shape a real local zone cannot have: resolver.ParseLocalRecord
// rejects the SOA type, so an operator can neither inline one via `data:` nor
// supply one via `zone_file:`. Every real local zone is therefore SOA-less, and
// dns.FormatZone substitutes a placeholder SOA for the missing record.
//
// That placeholder must itself be valid BIND: two names, the five timers, and
// the closing paren. When it was only the opener (`@ IN SOA <apex> invalid.
// invalid. (`) the endpoint happily served 200 with a body the project's own
// parser rejected, so an operator's exported zone could not be re-imported.
// Asserting on the HTTP response is what makes that visible at the layer the
// operator actually uses.
func TestZoneExport_SOALessZoneRoundTrips(t *testing.T) {
	srv := testAdminServerWithResolver(t)

	lz := resolver.NewLocalZoneTable([]resolver.LocalZone{
		{
			Name: "no-soa.test",
			Type: resolver.LocalStatic,
			Records: []resolver.LocalRecord{
				{Name: "no-soa.test", Type: dns.TypeNS, TTL: 86400, RData: buildName(t, "ns.no-soa.test.")},
				{Name: "www.no-soa.test", Type: dns.TypeA, TTL: 300, RData: []byte{1, 2, 3, 4}},
				{Name: "v6.no-soa.test", Type: dns.TypeAAAA, TTL: 300, RData: net.ParseIP("2001:db8::1").To16()},
			},
		},
	})
	srv.resolver.SetLocalZones(lz)

	req := httptest.NewRequest(http.MethodGet, "/api/zones/no-soa.test/export", nil)
	rr := httptest.NewRecorder()
	srv.handleZoneExport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()

	// The contract: the exported body must parse with the project's own parser.
	got, err := dns.ParseZone("no-soa.test.", []byte(body))
	if err != nil {
		t.Fatalf("ParseZone on an SOA-less zone export failed: %v\nbody:\n%s", err, body)
	}

	// The placeholder SOA must be present, and carry exactly two names plus the
	// five timers — a third name would make the parser read it as timer 0.
	var sawSOA, sawA, sawNS bool
	for i := range got {
		rec := &got[i]
		switch rec.Type {
		case dns.TypeSOA:
			sawSOA = true
		case dns.TypeA:
			if rec.Name == "www.no-soa.test." && len(rec.RData) == 4 &&
				rec.RData[0] == 1 && rec.RData[1] == 2 && rec.RData[2] == 3 && rec.RData[3] == 4 {
				sawA = true
			}
		case dns.TypeNS:
			if rec.Name == "no-soa.test." {
				sawNS = true
			}
		}
	}

	if !sawSOA {
		t.Errorf("no SOA in the export; a zone file without an SOA is not loadable\nbody:\n%s", body)
	}
	if !sawA {
		t.Error("the A record did not survive the export")
	}
	if !sawNS {
		t.Error("the NS record did not survive the export")
	}
}

// TestZoneExport_NotFound returns 404 for a zone that does not exist
// in the local-zone table. The handler must not 500 or return an empty
// body that the operator might mistake for a valid zone.
func TestZoneExport_NotFound(t *testing.T) {
	srv := testAdminServerWithResolver(t)
	srv.resolver.SetLocalZones(resolver.NewLocalZoneTable(nil))

	req := httptest.NewRequest(http.MethodGet, "/api/zones/does-not-exist.example/export", nil)
	rr := httptest.NewRecorder()
	srv.handleZoneExport(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "does-not-exist.example") {
		t.Errorf("body should name the missing zone, got %q", rr.Body.String())
	}
}

// TestZoneExport_BadMethod rejects POST, PUT, DELETE on the export
// endpoint — it is a read-only view. The handler must not accept
// mutating methods silently.
func TestZoneExport_BadMethod(t *testing.T) {
	srv := testAdminServerWithResolver(t)
	srv.resolver.SetLocalZones(resolver.NewLocalZoneTable([]resolver.LocalZone{
		{Name: "example.com", Type: resolver.LocalStatic, Records: []resolver.LocalRecord{
			{Name: "example.com", Type: dns.TypeSOA, TTL: 86400, RData: buildSOA(t,
				"ns.example.com.", "hostmaster.example.com.",
				2024010101, 7200, 3600, 1209600, 3600)},
		}},
	}))

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/api/zones/example.com/export", nil)
		rr := httptest.NewRecorder()
		srv.handleZoneExport(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want 405", m, rr.Code)
		}
	}
}

// TestZoneList_HappyPath returns the local zones in the table with
// the metadata the operator expects to see in the dashboard. The
// "kind" field is "local" for everything this endpoint emits; a
// future iteration can include forward/stub zones from config.
func TestZoneList_HappyPath(t *testing.T) {
	srv := testAdminServerWithResolver(t)
	srv.resolver.SetLocalZones(resolver.NewLocalZoneTable([]resolver.LocalZone{
		{
			Name: "example.com",
			Type: resolver.LocalStatic,
			Records: []resolver.LocalRecord{
				{Name: "example.com", Type: dns.TypeSOA, TTL: 86400, RData: buildSOA(t,
					"ns.example.com.", "hostmaster.example.com.",
					2024010101, 7200, 3600, 1209600, 3600)},
			},
		},
		{Name: "static-zone.test", Type: resolver.LocalStatic, Records: nil},
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	rr := httptest.NewRecorder()
	srv.handleZoneList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "example.com") {
		t.Errorf("body missing example.com: %s", body)
	}
	if !strings.Contains(body, "static-zone.test") {
		t.Errorf("body missing static-zone.test: %s", body)
	}
}

// --- helpers ---

func buildSOA(t *testing.T, mname, rname string, serial, refresh, retry, expire, minimum uint32) []byte {
	t.Helper()
	out := []byte{}
	out = appendName(out, mname)
	out = appendName(out, rname)
	for _, v := range []uint32{serial, refresh, retry, expire, minimum} {
		out = append(out, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return out
}

func buildName(t *testing.T, name string) []byte {
	t.Helper()
	out, err := dns.EncodeNameToBytes(name)
	if err != nil {
		t.Fatalf("EncodeNameToBytes(%q): %v", name, err)
	}
	return out
}

func appendName(dst []byte, name string) []byte {
	encoded, err := dns.EncodeNameToBytes(name)
	if err != nil {
		panic(err)
	}
	return append(dst, encoded...)
}
