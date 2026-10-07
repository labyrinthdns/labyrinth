package dns

import (
	"bytes"
	"strings"
	"testing"
)

// FormatZone and ParseZone are documented inverses, so whatever the writer
// emits has to be readable by the project's own parser. That did not hold for
// the placeholder SOA: when the record set carries no SOA, the writer emitted
// only the opener — "<apex> invalid. invalid. (" — with no timers and no
// closing paren. The output was not a BIND master file at all.
//
// This is not a corner case. resolver.ParseLocalRecord rejects the SOA type
// ("unsupported type \"SOA\""), so a resolver.LocalZone can never contain one,
// which means web/api_zone.go's GET /api/zones/:name/export took this branch
// for EVERY local zone it served — the operator downloaded a file that could
// not be loaded back.

// localZoneStyleRecords mirrors what web/api_zone.go's localZoneToRecords
// produces for a local zone: no SOA can ever be among them.
func localZoneStyleRecords() []ResourceRecord {
	return []ResourceRecord{
		{Name: "localhost", Type: TypeA, Class: ClassIN, TTL: 3600, RData: []byte{127, 0, 0, 1}},
		{Name: "localhost", Type: TypeAAAA, Class: ClassIN, TTL: 3600, RData: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}
}

// The exported file must parse. This is the whole defect: the writer's
// placeholder branch produced text the parser rejected.
func TestFormatZone_PlaceholderSOAProducesParseableZone(t *testing.T) {
	out, err := FormatZone("localhost.", localZoneStyleRecords())
	if err != nil {
		t.Fatalf("FormatZone failed: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, "SOA") {
		t.Fatalf("expected a placeholder SOA in the output, got:\n%s", text)
	}

	if _, perr := ParseZone("localhost.", out); perr != nil {
		t.Fatalf("the exported zone file does not parse: %v\nexported text:\n%s", perr, text)
	}

	// The placeholder record must be structurally complete: balanced parens,
	// two names, and five timers. A truncated opener is what broke this.
	if !strings.Contains(text, ")") {
		t.Errorf("placeholder SOA block is not closed; exported text:\n%s", text)
	}
	for _, timer := range []string{"; serial", "; refresh", "; retry", "; expire", "; minimum"} {
		if !strings.Contains(text, timer) {
			t.Errorf("placeholder SOA is missing the %q line; exported text:\n%s", timer, text)
		}
	}
}

// The placeholder must not leak a third name. An SOA takes exactly two (mname,
// rname) before the timers; a third one is read as timer 0 and fails to parse.
func TestFormatZone_PlaceholderSOAHasExactlyTwoNames(t *testing.T) {
	out, err := FormatZone("corp.", []ResourceRecord{
		{Name: "corp", Type: TypeA, Class: ClassIN, TTL: 3600, RData: []byte{192, 0, 2, 1}},
	})
	if err != nil {
		t.Fatalf("FormatZone failed: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "SOA") {
			continue
		}
		fields := strings.Fields(line)
		// $TTL line excluded; an SOA header is: @ IN SOA <mname> <rname> (
		if len(fields) != 6 {
			t.Errorf("SOA header %q has %d fields, want 6 (@ IN SOA mname rname \"(\")", line, len(fields))
		}
		if _, perr := ParseZone("corp.", out); perr != nil {
			t.Errorf("exported zone does not parse: %v", perr)
		}
	}
}

// CONTROL: a zone that does carry an SOA exercises the other branch and must
// keep working. Fails before or after the fix only if the harness is wrong.
func TestFormatZone_RealSOAUnaffected(t *testing.T) {
	const seed = `@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300
@ IN NS ns1.example.com.
www IN A 192.0.2.1
`
	recs, err := ParseZone("example.com.", []byte(seed))
	if err != nil {
		t.Fatalf("seed parse failed: %v", err)
	}
	out, err := FormatZone("example.com.", recs)
	if err != nil {
		t.Fatalf("FormatZone failed: %v", err)
	}
	back, perr := ParseZone("example.com.", out)
	if perr != nil {
		t.Fatalf("zone with a real SOA failed to round-trip: %v", perr)
	}
	if len(back) != len(recs) {
		t.Errorf("round trip changed the record count: %d -> %d", len(recs), len(back))
	}
	if strings.Contains(string(out), "invalid") {
		t.Errorf("a zone carrying a real SOA should not get a placeholder; got:\n%s", string(out))
	}
	for i := range recs {
		if recs[i].Type == TypeSOA && !bytes.Equal(recs[i].RData, back[i].RData) {
			t.Errorf("SOA round trip changed %x to %x", recs[i].RData, back[i].RData)
		}
	}
}

// CONTROL: an SOA record that exists but has empty RDATA also takes the
// placeholder branch; it must still produce a loadable file.
func TestFormatZone_EmptyRDATASOATakesPlaceholderAndParses(t *testing.T) {
	out, err := FormatZone("empty.example.com.", []ResourceRecord{
		{Name: "empty.example.com", Type: TypeSOA, Class: ClassIN, TTL: 3600, RData: nil},
		{Name: "empty.example.com", Type: TypeA, Class: ClassIN, TTL: 3600, RData: []byte{192, 0, 2, 9}},
	})
	if err != nil {
		t.Fatalf("FormatZone failed: %v", err)
	}
	if _, perr := ParseZone("empty.example.com.", out); perr != nil {
		t.Fatalf("placeholder branch emitted an unparseable zone: %v\nexported text:\n%s", perr, string(out))
	}
}
