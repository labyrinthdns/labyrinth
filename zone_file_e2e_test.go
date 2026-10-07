package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/dns"
)

// zoneFileZone writes a minimal but complete BIND master-file and returns its
// path. The parser is the round-trip partner of the export endpoint, so the
// file is exactly what `GET /api/zones/<name>/export` serves.
func zoneFileZone(t *testing.T, dir, origin string) string {
	t.Helper()
	body := `$ORIGIN ` + origin + `.
$TTL 3600
@	IN	SOA	ns1.` + origin + `. hostmaster.` + origin + `. (
		2024010101 ; serial
		7200       ; refresh
		3600       ; retry
		1209600    ; expire
		3600 )     ; minimum
@	IN	NS	ns1.` + origin + `.
ns1	IN	A	192.0.2.1
www	IN	A	192.0.2.10
`
	path := filepath.Join(dir, origin+".zone")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	return path
}

func zoneFileLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The headline case: a zone named by `zone_file:` is loaded at startup and
// answers a query through the same LocalZoneTable the server uses.
func TestZoneFile_ConfiguredZoneIsQueryableEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := zoneFileZone(t, dir, "corp.test")

	cfg := &config.Config{}
	cfg.LocalZones = []config.LocalZoneConfig{
		{Name: "corp.test", Type: "static", ZoneFile: path},
	}

	table := buildLocalZones(cfg, zoneFileLogger())

	got := table.Lookup("www.corp.test.", dns.TypeA, dns.ClassIN)
	if got == nil {
		t.Fatal("query for www.corp.test. A returned nil; the zone file was not loaded")
	}
	if len(got.Answers) != 1 {
		t.Fatalf("got %d answers, want 1", len(got.Answers))
	}

	want := []byte{192, 0, 2, 10}
	if !equalBytes(got.Answers[0].RData, want) {
		t.Errorf("www.corp.test. A = %v, want %v", got.Answers[0].RData, want)
	}

	// The apex NS from the same file must be present too — this proves the
	// whole file was parsed, not just the one record asserted above.
	if ns := table.Lookup("corp.test.", dns.TypeNS, dns.ClassIN); ns == nil || len(ns.Answers) == 0 {
		t.Error("apex NS from the zone file is missing")
	}

	// A name that is not in the file must NOT resolve from this zone.
	if extra := table.Lookup("absent.corp.test.", dns.TypeA, dns.ClassIN); extra != nil {
		if extra.RCODE == dns.RCodeNoError {
			t.Error("a name absent from the zone file resolved with NOERROR")
		}
	}
}

// CONTROL: inline `data:` records still load, proving the zone_file branch did
// not swallow the pre-existing path.
func TestZoneFile_InlineDataStillWorks(t *testing.T) {
	cfg := &config.Config{}
	cfg.LocalZones = []config.LocalZoneConfig{
		{Name: "inline.test", Type: "static", Data: []string{"host.inline.test. A 198.51.100.7"}},
	}

	table := buildLocalZones(cfg, zoneFileLogger())
	got := table.Lookup("host.inline.test.", dns.TypeA, dns.ClassIN)
	if got == nil || len(got.Answers) == 0 {
		t.Fatal("inline data zone is not queryable")
	}
	if r := got.Answers[0].RData; !equalBytes(r, []byte{198, 51, 100, 7}) {
		t.Errorf("inline data A = %v, want 198.51.100.7", r)
	}
}

// LocalZoneConfig documents "If both are set, ZoneFile wins and Data is
// ignored." Pin that precedence so it cannot silently regress.
func TestZoneFile_TakesPrecedenceOverInlineData(t *testing.T) {
	dir := t.TempDir()
	path := zoneFileZone(t, dir, "both.test")

	cfg := &config.Config{}
	cfg.LocalZones = []config.LocalZoneConfig{{
		Name:     "both.test",
		Type:     "static",
		ZoneFile: path,
		// Would answer 203.0.113.99 if data were consulted.
		Data: []string{"www.both.test. A 203.0.113.99"},
	}}

	table := buildLocalZones(cfg, zoneFileLogger())
	got := table.Lookup("www.both.test.", dns.TypeA, dns.ClassIN)
	if got == nil || len(got.Answers) != 1 {
		t.Fatalf("want exactly 1 answer, got %#v", got)
	}
	if equalBytes(got.Answers[0].RData, []byte{203, 0, 113, 99}) {
		t.Error("inline data was consulted even though zone_file is set")
	}
	if !equalBytes(got.Answers[0].RData, []byte{192, 0, 2, 10}) {
		t.Errorf("want the zone_file record 192.0.2.10, got %v", got.Answers[0].RData)
	}
}

// A bad zone file must skip only that zone. The default localhost zone and the
// operator's other zones must still load — a resolver that refuses to serve
// because one internal zone file has a typo is worse than one that logs it.
func TestZoneFile_BadFileSkipsOnlyThatZone(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.zone")

	cfg := &config.Config{}
	cfg.LocalZones = []config.LocalZoneConfig{
		{Name: "broken.test", Type: "static", ZoneFile: missing},
		{Name: "ok.test", Type: "static", Data: []string{"host.ok.test. A 198.51.100.8"}},
	}

	table := buildLocalZones(cfg, zoneFileLogger())

	if bad := table.Lookup("anything.broken.test.", dns.TypeA, dns.ClassIN); bad != nil {
		t.Error("a zone whose file failed to load is still being served")
	}
	if lh := table.Lookup("localhost.", dns.TypeA, dns.ClassIN); lh == nil || len(lh.Answers) == 0 {
		t.Error("the default localhost zone was lost when another zone file failed")
	}
	if ok := table.Lookup("host.ok.test.", dns.TypeA, dns.ClassIN); ok == nil || len(ok.Answers) == 0 {
		t.Error("an unrelated configured zone was lost when another zone file failed")
	}
}

// A zone file that parses to nothing would answer NXDOMAIN for everything
// under the zone, which is far more confusing than a startup error.
func TestZoneFile_EmptyFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.zone")
	if err := os.WriteFile(empty, []byte("$ORIGIN empty.test.\n$TTL 3600\n"), 0o600); err != nil {
		t.Fatalf("write empty zone file: %v", err)
	}

	if _, err := loadZoneFileRecords("empty.test", empty); err == nil {
		t.Error("a zone file with no records was accepted; it would NXDOMAIN everything")
	}

	cfg := &config.Config{}
	cfg.LocalZones = []config.LocalZoneConfig{{Name: "empty.test", Type: "static", ZoneFile: empty}}
	table := buildLocalZones(cfg, zoneFileLogger())
	if got := table.Lookup("anything.empty.test.", dns.TypeA, dns.ClassIN); got != nil {
		t.Error("the empty zone was still installed")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
