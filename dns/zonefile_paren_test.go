package dns

import "testing"

// parenDelta decides how many parenthesised-continuation blocks are open after
// reading a line. BIND master-file grammar lexes a quoted string as a unit, so
// a "(" or ")" between quotes is character data and must not open or close a
// block.
//
// Counting them with strings.Count let a TXT value such as "note ) here" drive
// the depth negative. isContinuation then read "depth != 0" as "block still
// open" and glued every following indented line into that TXT record, silently
// dropping those records with no error reported.
//
// The discriminator used here: an indented line beginning with a class column
// ("\tIN A x") is a valid owner-inheriting record when the depth is zero
// (zonefile_parser.go:26-27) and a continuation when it is not. So "did the A
// record survive?" measures the depth directly.

const zoneParenHdr = `$ORIGIN example.com.
$TTL 300
@	IN SOA ns1.example.com. hostmaster.example.com. ( 1 3600 600 86400 300 )
@	IN NS ns1.example.com.
`

// hasARecord reports whether an A record for 192.0.2.<last> was parsed.
func hasARecord(records []ResourceRecord, last byte) bool {
	for _, r := range records {
		if r.Type == TypeA && len(r.RData) == 4 &&
			r.RData[0] == 192 && r.RData[1] == 0 && r.RData[2] == 2 && r.RData[3] == last {
			return true
		}
	}
	return false
}

// parseQuotedThenA parses a TXT record whose quoted string is `content`,
// followed by an indented owner-inheriting A record for 192.0.2.<last>.
func parseQuotedThenA(t *testing.T, content string, last byte) []ResourceRecord {
	t.Helper()
	body := "txt\tIN TXT \"" + content + "\"\n\tIN A 192.0.2." + itoa(uint16(last)) + "\n"
	records, err := ParseZone("example.com.", []byte(zoneParenHdr+body))
	if err != nil {
		t.Fatalf("ParseZone with quoted %q: unexpected error: %v", content, err)
	}
	return records
}

// A ")" inside a quoted string is character data, not the close of a block.
func TestParseZone_ClosingParenInsideQuotedString(t *testing.T) {
	records := parseQuotedThenA(t, "note ) here", 62)
	if !hasARecord(records, 62) {
		t.Errorf("A record 192.0.2.62 was swallowed by the preceding TXT record; " +
			"a ')' inside a quoted string was counted as a continuation delimiter")
	}
}

// Once the depth went negative, every following indented line was treated as a
// continuation, so one stray paren could drop a run of records rather than one.
func TestParseZone_NegativeDepthDoesNotSwallowFollowingRecords(t *testing.T) {
	body := "txt\tIN TXT \"close ) here\"\n\tIN A 192.0.2.71\n\tIN A 192.0.2.72\n"
	records, err := ParseZone("example.com.", []byte(zoneParenHdr+body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, last := range []byte{71, 72} {
		if !hasARecord(records, last) {
			t.Errorf("A record 192.0.2.%d was swallowed; a negative continuation "+
				"depth was misread as an open block", last)
		}
	}
}

// A "(" inside a quoted string must not open a block either.
func TestParseZone_OpeningParenInsideQuotedString(t *testing.T) {
	records := parseQuotedThenA(t, "note (see RFC 1035)", 61)
	if !hasARecord(records, 61) {
		t.Error("A record 192.0.2.61 was swallowed; a '(' inside a quoted string " +
			"was counted as opening a continuation block")
	}
}

// CONTROL: a quoted string with no parentheses must leave the following record
// alone. Fails before or after the fix only if the harness is wrong.
func TestParseZone_QuotedStringWithoutParens(t *testing.T) {
	records := parseQuotedThenA(t, "plain text here", 60)
	if !hasARecord(records, 60) {
		t.Error("A record 192.0.2.60 was swallowed by a paren-free TXT record")
	}
}

// CONTROL: balanced parentheses inside a quoted string net to zero and must stay
// harmless.
func TestParseZone_BalancedParensInsideQuotedString(t *testing.T) {
	records := parseQuotedThenA(t, "a ( b ) c", 63)
	if !hasARecord(records, 63) {
		t.Error("A record 192.0.2.63 was swallowed by a TXT with balanced parens")
	}
}

// CONTROL: a genuine parenthesised block must still be tracked. The SOA in the
// header carries one, and the indented record after it is only parsed on its own
// if that line's parens net to zero.
func TestParseZone_RecordAfterRealParenBlock(t *testing.T) {
	records, err := ParseZone("example.com.", []byte(zoneParenHdr+"\tIN A 192.0.2.70\n"))
	if err != nil {
		t.Fatalf("unexpected error after a real paren block: %v", err)
	}
	var soa int
	for _, r := range records {
		if r.Type == TypeSOA {
			soa++
		}
	}
	if soa != 1 {
		t.Errorf("expected exactly 1 SOA record, got %d", soa)
	}
	if !hasARecord(records, 70) {
		t.Error("A record 192.0.2.70 was lost after a genuine closed paren block")
	}
}

// CONTROL: escaped quotes must end the quoted string where stripComment already
// decides it does. The paren counter must agree with that boundary.
func TestParseZone_EscapedQuotesInsideQuotedString(t *testing.T) {
	records, err := ParseZone("example.com.",
		[]byte(zoneParenHdr+"txt\tIN TXT \"say \\\" (hi)\\\" now\"\n\tIN A 192.0.2.90\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasARecord(records, 90) {
		t.Error("A record 192.0.2.90 was lost after a TXT with escaped quotes")
	}
}

// parenDelta is unit-tested directly so the quote and escape boundaries are
// pinned independently of how the parser recovers from them.
func TestParenDelta(t *testing.T) {
	tests := []struct {
		line string
		want int
	}{
		{"", 0},
		{"( 1 3600 600 86400 300 )", 0},
		{"( 1 3600 600 86400 300", 1},
		{`"note ) here"`, 0},
		{`"note ( here"`, 0},
		{`"a ( b ) c"`, 0},
		{`say \" (hi)\" now`, 0},
		{`unquoted ) paren`, -1},
		{`( unquoted ( nested`, 2},
		{`"mixed ) unquoted (`, 0},
		{`"escaped \" ( paren`, 0},
	}
	for _, tc := range tests {
		if got := parenDelta(tc.line); got != tc.want {
			t.Errorf("parenDelta(%q) = %d, want %d", tc.line, got, tc.want)
		}
	}
}
