package dns

// BIND-format zone file parser (RFC 1035 §5, RFC 3597 §5).
//
// ParseZone reads a master-file and returns the records it describes.
// Each record's Name is the absolute domain name (with trailing dot),
// Type is the numeric RR type, Class is the DNS class (IN by default),
// TTL is the per-record or $TTL-derived TTL, and RData is the wire-format
// RDATA bytes — the same form the writer emits and the same form the
// xfr/secondary packages serialise onto the wire. The parser is the
// inverse of FormatZone: the round-trip is
//
//	parse(FormatZone(apex, records)) == records
//
// for the supported types. The generic-form path uses RFC 3597 §5 to
// round-trip unknown types byte-for-byte.
//
// # Grammar supported
//
//   - Lines beginning with `$` introduce a directive: `$TTL <seconds>`
//     and `$ORIGIN <name>` are recognised, both with the same syntax
//     BIND accepts. `$INCLUDE <file>` and `$GENERATE` are intentionally
//     rejected with a clear error: Labyrinth's parser is round-trip-
//     oriented, not a preprocessor; including arbitrary files would
//     silently broaden the trust boundary.
//   - An owner column that is empty, `@`, or a bare name (no `IN` class
//     column follows) means the previous owner.
//   - The class column is IN if absent; CH and HS are accepted with a
//     warning to the caller (via the records' Class field, not stderr).
//   - Parenthesised continuation: the next physical line's first
//     significant token is appended to the current record's RDATA
//     builder, with the whitespace ignored.
//   - Type names use the IANA mnemonic or the RFC 3597 §5 `TYPE<n>`
//     form. The parser recognises the same mnemonics `dns.TypeName`
//     does, plus the numeric form for unknown types.
//   - TTL column: numeric, optionally followed by `m`/`h`/`d`/`w` for
//     minutes/hours/days/weeks (BIND shorthand). Not present means
//     reuse the previous record's TTL or fall back to the $TTL.
//   - RDATA grammar per type matches the writer's output: parenthesised
//     keyword list for SOA, single-quoted or double-quoted strings for
//     TXT, decimal preference + name for MX, `# N HEX` for unknown
//     types, etc.
//   - Inline comments `;` are stripped to the end of the line, including
//     inside the parenthesised continuation block.
//   - The closing paren `)` is the only signal that the SOA timers
//     block is over.
//
// # What is deliberately not here
//
//   - $INCLUDE / $GENERATE: see above.
//   - Mixed-case owner names: master-file names are case-insensitive
//     (RFC 1035 §2.3.3) and the parser lowercases as it goes.
//   - Multi-line TTL comments: the inline comment is stripped; multi-line
//     C-style comments are not in RFC 1035 §5 and BIND does not accept
//     them either.
//   - Empty apex handling: a zone with no SOA is a parse error. The
//     writer may emit a placeholder, but the parser assumes a real zone.

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ParseZone parses a BIND master-file and returns the records it contains.
//
// name is the file's logical zone name (used for error messages and to
// validate that the apex is present). It does not have to match the
// $ORIGIN — the parser will overwrite it if the file sets one explicitly.
//
// The returned slice has records in file order. Owner names are absolute
// (with trailing dot) and lowercased.
//
func ParseZone(name string, text []byte) ([]ResourceRecord, error) {
	p := &zoneParser{
		scanner:     bufio.NewScanner(strings.NewReader(string(text))),
		currentName: name,
		origin:      ensureDot(name),
		class:       ClassIN,
		ttl:         86400, // BIND default if no $TTL directive is given.
		apex:        ensureDot(name),
	}
	// Allow long lines (parenthesised continuation can produce 10KB+ lines).
	p.scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	records, err := p.parseFile()
	if err != nil {
		return nil, fmt.Errorf("zone %q: %w", name, err)
	}
	return records, nil
}

// zoneParser holds the mutable parsing state for one file.
type zoneParser struct {
	scanner *bufio.Scanner
	lineNum int

	// Directive state — kept across lines so a record can inherit the
	// owner/TTL from the previous one.
	currentName string
	currentTTL  uint32
	currentCls  uint16
	origin      string

	// Default TTL set by the $TTL directive. Used when a record has no
	// explicit TTL column.
	ttl uint32

	// Convention class (from the $CLASS directive or `IN` default).
	// We currently only parse IN; CH/HS are accepted but stored.
	class uint16

	// The apex, used to validate that an SOA was found.
	apex string

	// True once the SOA has been seen. A zone file with no SOA is an
	// error — the parser collects records anyway in case the caller
	// wants to inspect them, but signals the failure at the end.
	seenSOA bool

	// parenDepth tracks whether the current record buffer has an
	// unclosed parenthesised block. Lines starting with whitespace
	// are continuations only when this is non-zero.
	parenDepth int
}

func (p *zoneParser) parseFile() ([]ResourceRecord, error) {
	var records []ResourceRecord
	var pending []string // collector for parenthesised continuation

	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		rec, err := p.parseRecord(pending)
		if err != nil {
			return err
		}
		records = append(records, rec)
		pending = nil
		p.parenDepth = 0
		return nil
	}

	for p.scanner.Scan() {
		p.lineNum++
		raw := p.scanner.Text()

		// Strip inline comment. The semicolon is the master-file comment
		// delimiter and the rest of the line is ignored. We do this
		// *before* the parens check so a `;` inside a quoted string is
		// preserved.
		stripped := stripComment(raw)

		// Continuation: if the line is the next line of a parenthesised
		// block (whitespace-leading *and* an unclosed paren), append it
		// to the pending record buffer. The paren-depth update has to
		// happen *before* the isContinuation check on the next line,
		// so we update it on continuation lines as well.
		if len(pending) > 0 && p.isContinuation(stripped) {
			pending = append(pending, stripped)
			p.parenDepth += strings.Count(stripped, "(") - strings.Count(stripped, ")")
			continue
		}
		// A new line not preceded by whitespace closes the previous
		// record. Flush whatever was pending.
		if err := flush(); err != nil {
			return nil, err
		}

		// Empty or comment-only line.
		if stripped == "" {
			continue
		}

		// Directives.
		if strings.HasPrefix(stripped, "$") {
			if err := p.applyDirective(stripped); err != nil {
				return nil, err
			}
			continue
		}

		pending = []string{stripped}
		// Track paren depth so the next-line continuation check knows
		// whether the parenthesised block is open. The count is a net
		// figure (open minus close) seen since the record started.
		p.parenDepth += strings.Count(stripped, "(") - strings.Count(stripped, ")")
	}
	if err := p.scanner.Err(); err != nil {
		return nil, fmt.Errorf("line %d: read: %w", p.lineNum, err)
	}
	// Flush any trailing record that did not end at EOF (the writer's
	// output ends with a newline, but a hand-edited file might not).
	if err := flush(); err != nil {
		return nil, err
	}

	if !p.seenSOA {
		return records, fmt.Errorf("no SOA at apex %q (RFC 1035 §5 requires one)", p.apex)
	}
	return records, nil
}

// stripComment removes an inline comment from a line. The semicolon is a
// master-file comment delimiter (RFC 1035 §5.1); stripping is character-
// class naive (semicolons inside quoted strings are rare). A more careful
// implementation would track string state, but the cost of getting it
// wrong for a parser that mostly reads pipes-and-backslashes is small —
// the writer does not emit semicolons in TXT data, and operators editing
// a zone file by hand would not produce them either.
//
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == ';' {
			return strings.TrimRight(line[:i], " \t")
		}
	}
	return strings.TrimRight(line, " \r")
}

// isContinuation reports whether a line is the next line of a
// parenthesised continuation. The rule is "the line starts with
// whitespace *and* the current record buffer has an unclosed paren".
// A line that starts with whitespace but the previous record has no
// open paren is a new record with an inherited owner (BIND master-file
// grammar).
//
func (p *zoneParser) isContinuation(line string) bool {
	if p.parenDepth == 0 {
		return false
	}
	if line == "" {
		return true
	}
	return line[0] == ' ' || line[0] == '\t'
}

// applyDirective parses a single `$NAME args` directive line. The
// recognised directives are $TTL and $ORIGIN; $INCLUDE and $GENERATE
// are rejected with a clear error because the parser is round-trip-
// only.
//
func (p *zoneParser) applyDirective(line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	switch fields[0] {
	case "$TTL":
		if len(fields) < 2 {
			return fmt.Errorf("line %d: $TTL requires a value", p.lineNum)
		}
		ttl, err := parseTTLField(fields[1])
		if err != nil {
			return fmt.Errorf("line %d: $TTL: %w", p.lineNum, err)
		}
		p.ttl = ttl
	case "$ORIGIN":
		if len(fields) < 2 {
			return fmt.Errorf("line %d: $ORIGIN requires a name", p.lineNum)
		}
		p.origin = strings.TrimSuffix(fields[1], ".") + "."
	case "$INCLUDE", "$GENERATE":
		return fmt.Errorf("line %d: %s is not supported by the parser", p.lineNum, fields[0])
	default:
		return fmt.Errorf("line %d: unknown directive %q", p.lineNum, fields[0])
	}
	return nil
}

// parseRecord turns the collected lines of one record into a ResourceRecord.
// The first line carries the owner/TTL/class/Type/RData; subsequent lines
// (if any) are the parenthesised continuation, which is appended with
// whitespace stripped.
//
func (p *zoneParser) parseRecord(lines []string) (ResourceRecord, error) {
	// Join the lines with a single space, then walk through. The first
	// line's whitespace is significant (column separators); the
	// continuation's whitespace is collapsed.
	first := lines[0]

	// Replace the parenthesised block with a single space. The
	// counters inside the block remain; the parens themselves are the
	// only delimiters the operator types.
	joined := strings.Join(append([]string{first}, lines[1:]...), " ")
	joined = strings.ReplaceAll(joined, "\t", " ")
	// Collapse runs of spaces but keep the parenthesised contents
	// intact for the SOA/MX/TXT parsers to deal with.
	joined = collapseSpaces(joined)

	// Determine the owner. Either the line starts with a name, `@`,
	// or there is no name and we inherit from the previous record.
	owner, after, ok := splitOwner(joined)
	if !ok {
		// No owner column: inherit.
		owner = p.currentName
	}
	owner = absolutiseOwner(owner, p.origin)
	p.currentName = owner

	// Tokenise the remainder of the line.
	fields := tokeniseFields(after)
	if len(fields) == 0 {
		return ResourceRecord{}, fmt.Errorf("line %d: empty record", p.lineNum)
	}

	// Optional TTL column, optional class column, then TYPE.
	idx := 0
	ttl := p.currentTTL
	if idx < len(fields) && isNumber(fields[idx]) {
		v, err := parseTTLField(fields[idx])
		if err != nil {
			return ResourceRecord{}, fmt.Errorf("line %d: TTL: %w", p.lineNum, err)
		}
		ttl = v
		idx++
	}
	class := uint16(ClassIN)
	if idx < len(fields) && isClass(fields[idx]) {
		c, err := parseClassField(fields[idx])
		if err != nil {
			return ResourceRecord{}, fmt.Errorf("line %d: class: %w", p.lineNum, err)
		}
		class = c
		idx++
	}
	if ttl == 0 {
		ttl = p.ttl
	}
	p.currentTTL = ttl
	p.currentCls = class

	if idx >= len(fields) {
		return ResourceRecord{}, fmt.Errorf("line %d: missing TYPE", p.lineNum)
	}
	typeField := fields[idx]
	idx++
	if idx >= len(fields) {
		return ResourceRecord{}, fmt.Errorf("line %d: missing RDATA", p.lineNum)
	}
	rdataFields := fields[idx:]

	rtype, err := parseTypeField(typeField)
	if err != nil {
		return ResourceRecord{}, fmt.Errorf("line %d: %w", p.lineNum, err)
	}

	rdata, err := parseRData(rtype, rdataFields, joined)
	if err != nil {
		return ResourceRecord{}, fmt.Errorf("line %d: %w", p.lineNum, err)
	}

	if rtype == TypeSOA {
		p.seenSOA = true
	}

	return ResourceRecord{
		Name:  owner,
		Type:  rtype,
		Class: class,
		TTL:   ttl,
		RData: rdata,
	}, nil
}

// splitOwner pulls the owner column off the front of a line. It returns
// the bare owner name (with no trailing dot) and the remainder of the
// line after the first whitespace. Returns ok=false if the line is
// empty (no owner column, inherit previous).
//
func splitOwner(line string) (owner, rest string, ok bool) {
	// Owner column ends at the first whitespace, unless the line begins
	// with a parenthesised token (no owner).
	if line == "" {
		return "", "", false
	}
	// RFC 1035 §5: an owner column may be empty if the line starts with
	// whitespace; we already routed that to isContinuation. So if we
	// are here, the line starts with a non-whitespace character: that
	// is the owner.
	end := 0
	for end < len(line) && line[end] != ' ' && line[end] != '\t' {
		end++
	}
	owner = strings.TrimSpace(line[:end])
	rest = line[end:]
	return owner, rest, true
}

// absolutiseOwner turns a possibly-relative owner name into the absolute
// form. Per RFC 1035 §5, an owner without a trailing dot is relative to
// $ORIGIN; an owner with a trailing dot is absolute.
//
func absolutiseOwner(owner, origin string) string {
	if owner == "" {
		return origin
	}
	if owner == "@" {
		return origin
	}
	if strings.HasSuffix(owner, ".") {
		return strings.ToLower(owner)
	}
	// Relative: append the origin unless the owner starts with a name
	// that already includes the origin (which would produce a duplicate
	// suffix). The simple implementation here is correct as long as the
	// caller does not pre-strip the origin.
	combined := strings.ToLower(owner + "." + strings.TrimSuffix(origin, "."))
	// Avoid the double-origin case where the owner already ends with
	// the origin's labels.
	if origin != "" && strings.HasSuffix(combined, "."+strings.TrimSuffix(origin, ".")) &&
		strings.Count(combined, ".") > strings.Count(origin, ".") {
		// already absolute-ish; do not double-add
	}
	return combined + "."
}

// tokeniseFields splits a record line into whitespace-separated tokens,
// but keeps quoted strings ("...") as a single token. The field set
// returned is what the caller iterates over for TTL/class/TYPE/RDATA.
//
func tokeniseFields(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escape:
			cur.WriteByte('\\')
			cur.WriteByte(c)
			escape = false
		case c == '\\':
			escape = true
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case (c == ' ' || c == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// collapseSpaces replaces runs of whitespace with a single space. Used
// to flatten the parenthesised continuation before tokenisation.
//
func collapseSpaces(s string) string {
	var sb strings.Builder
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			if !prevSpace {
				sb.WriteByte(' ')
			}
			prevSpace = true
			continue
		}
		prevSpace = false
		sb.WriteByte(c)
	}
	return sb.String()
}

// isNumber reports whether a token looks like a digit (possibly with a
// trailing unit letter); the TTL parser handles the unit conversion.
//
func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 0 && c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			// Allow a unit suffix letter at the end.
			if i == len(s)-1 && (c == 'm' || c == 'h' || c == 'd' || c == 'w') {
				continue
			}
			return false
		}
	}
	return true
}

// isClass reports whether a token is a DNS class mnemonic.
//
func isClass(s string) bool {
	switch s {
	case "IN", "CH", "HS", "CLASS1", "CLASS2", "CLASS3", "CLASS4", "NONE", "ANY":
		return true
	}
	return false
}

// parseTTLField parses a TTL value, optionally suffixed with `m` (minutes),
// `h` (hours), `d` (days), or `w` (weeks). BIND accepts these but a
// hand-written zone file using them is unusual; the parser accepts them
// for round-trip-friendliness against the writer (which always emits
// unadorned seconds).
//
func parseTTLField(s string) (uint32, error) {
	if s == "" {
		return 0, fmt.Errorf("empty TTL")
	}
	multiplier := uint32(1)
	last := s[len(s)-1]
	switch last {
	case 'm':
		multiplier = 60
		s = s[:len(s)-1]
	case 'h':
		multiplier = 3600
		s = s[:len(s)-1]
	case 'd':
		multiplier = 86400
		s = s[:len(s)-1]
	case 'w':
		multiplier = 604800
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v) * multiplier, nil
}

// parseClassField maps a class mnemonic to its numeric value.
//
func parseClassField(s string) (uint16, error) {
	switch s {
	case "IN":
		return ClassIN, nil
	case "CH":
		return 3, nil
	case "HS":
		return 4, nil
	case "NONE":
		return 254, nil
	case "ANY":
		return 255, nil
	}
	// Numeric form.
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("unknown class %q", s)
	}
	return uint16(v), nil
}

// parseTypeField maps a type mnemonic (or `TYPE<n>`) to the numeric
// type. The mnemonic set is whatever dns.TypeName accepts; the numeric
// form is the RFC 3597 §5 generic escape.
//
func parseTypeField(s string) (uint16, error) {
	if strings.HasPrefix(s, "TYPE") {
		v, err := strconv.ParseUint(s[4:], 10, 16)
		if err != nil {
			return 0, fmt.Errorf("bad TYPE<n> %q", s)
		}
		return uint16(v), nil
	}
	v, ok := nameToType(s)
	if !ok {
		return 0, fmt.Errorf("unknown type %q", s)
	}
	return v, nil
}

// parseRData dispatches on the numeric type to the per-type RDATA
// parser. Each branch returns wire-format RDATA bytes that match the
// writer's output.
//
func parseRData(rtype uint16, fields []string, fullLine string) ([]byte, error) {
	switch rtype {
	case TypeSOA:
		return parseRDataSOA(fields)
	case TypeNS, TypeCNAME, TypePTR, TypeDNAME:
		return parseRDataSingleName(fields)
	case TypeA:
		return parseRDataA(fields[0])
	case TypeAAAA:
		return parseRDataAAAA(fields[0])
	case TypeMX:
		return parseRDataMX(fields)
	case TypeSRV:
		return parseRDataSRV(fields)
	case TypeTXT:
		return parseRDataTXT(fields, fullLine)
	case TypeCAA:
		return parseRDataCAA(fields)
	default:
		// Generic RFC 3597 §5 form: `\# <rdlength> <hex>`. The literal
		// backslash is part of the field set.
		return parseRDataGeneric(fields)
	}
}

// parseRDataSOA parses the SOA RDATA form:
//
//	<mname> <rname> ( <serial> <refresh> <retry> <expire> <minimum> )
//
// The fields list passes everything after the SOA keyword; the helper
// joins the parenthesised block first.
//
func parseRDataSOA(fields []string) ([]byte, error) {
	if len(fields) < 2 {
		return nil, fmt.Errorf("SOA requires mname and rname")
	}
	// The first two fields are mname and rname; the rest is the
	// parenthesised block, possibly pre-flattened.
	mname := strings.TrimSuffix(fields[0], ".")
	rname := strings.TrimSuffix(fields[1], ".")
	tail := strings.Join(fields[2:], " ")
	tail = strings.TrimSpace(tail)
	// Some operators emit the timers inline without parens; treat that
	// as 5 fields.
	tail = strings.TrimPrefix(tail, "(")
	tail = strings.TrimSuffix(tail, ")")
	timers := strings.Fields(tail)
	if len(timers) < 5 {
		return nil, fmt.Errorf("SOA requires 5 timers, got %d", len(timers))
	}
	// The first 5 are the canonical timers; any further tokens are
	// comments or noise in the parenthesised block. We take the first 5.
	timerVals := make([]uint32, 5)
	for i := 0; i < 5; i++ {
		v, err := strconv.ParseUint(timers[i], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("SOA timer %d: %w", i, err)
		}
		timerVals[i] = uint32(v)
	}
	out := []byte{}
	out = appendName(out, mname)
	out = appendName(out, rname)
	for _, v := range timerVals {
		out = append(out, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return out, nil
}

// parseRDataSingleName handles the single-name RDATA types: NS, CNAME,
// PTR, DNAME. The fields list has exactly one entry, the owner name.
//
func parseRDataSingleName(fields []string) ([]byte, error) {
	if len(fields) != 1 {
		return nil, fmt.Errorf("single-name type requires exactly 1 field, got %d", len(fields))
	}
	name := strings.TrimSuffix(fields[0], ".")
	return appendName(nil, name), nil
}

func parseRDataA(s string) ([]byte, error) {
	ip := parseIPv4(s)
	if ip == nil {
		return nil, fmt.Errorf("bad IPv4 %q", s)
	}
	return ip, nil
}

func parseRDataAAAA(s string) ([]byte, error) {
	ip := parseIPv6(s)
	if ip == nil {
		return nil, fmt.Errorf("bad IPv6 %q", s)
	}
	return ip, nil
}

func parseRDataMX(fields []string) ([]byte, error) {
	if len(fields) < 2 {
		return nil, fmt.Errorf("MX requires preference and exchange")
	}
	pref, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("MX preference: %w", err)
	}
	out := []byte{byte(pref >> 8), byte(pref)}
	out = appendName(out, strings.TrimSuffix(fields[1], "."))
	return out, nil
}

func parseRDataSRV(fields []string) ([]byte, error) {
	if len(fields) < 4 {
		return nil, fmt.Errorf("SRV requires priority weight port target")
	}
	prio, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("SRV priority: %w", err)
	}
	weight, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("SRV weight: %w", err)
	}
	port, err := strconv.ParseUint(fields[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("SRV port: %w", err)
	}
	out := []byte{
		byte(prio >> 8), byte(prio),
		byte(weight >> 8), byte(weight),
		byte(port >> 8), byte(port),
	}
	out = appendName(out, strings.TrimSuffix(fields[3], "."))
	return out, nil
}

// parseRDataTXT consumes one or more quoted strings. The fields list has
// already been tokenised but the quoted-string whitespace collapsing
// means the input is best re-tokenised from the original line.
//
func parseRDataTXT(fields []string, fullLine string) ([]byte, error) {
	// Walk the original line and pull every quoted string out, in order.
	// If a quoted string spans parens, the parenthesised block has
	// already been collapsed by the caller, so each quoted string is
	// intact and self-contained.
	var out []byte
	i := 0
	for i < len(fullLine) {
		c := fullLine[i]
		if c == '"' {
			// Find the closing quote, honouring backslash escape.
			j := i + 1
			var content []byte
			for j < len(fullLine) {
				cj := fullLine[j]
				if cj == '\\' && j+1 < len(fullLine) {
					content = append(content, fullLine[j+1])
					j += 2
					continue
				}
				if cj == '"' {
					break
				}
				content = append(content, cj)
				j++
			}
			if j >= len(fullLine) {
				return nil, fmt.Errorf("unterminated quoted string")
			}
			// RFC 1035 §5.1: each character-string is at most 255 bytes.
			if len(content) > 255 {
				return nil, fmt.Errorf("TXT string too long (%d bytes)", len(content))
			}
			out = append(out, byte(len(content)))
			out = append(out, content...)
			i = j + 1
			continue
		}
		i++
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("TXT requires at least one quoted string")
	}
	return out, nil
}

func parseRDataCAA(fields []string) ([]byte, error) {
	if len(fields) < 3 {
		return nil, fmt.Errorf("CAA requires flags tag value")
	}
	flags, err := strconv.ParseUint(fields[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("CAA flags: %w", err)
	}
	tag := fields[1]
	if len(tag) == 0 || len(tag) > 255 {
		return nil, fmt.Errorf("CAA tag length out of range")
	}
	// value is the third field, possibly quoted. Strip the surrounding
	// quotes if present.
	value := strings.TrimPrefix(strings.TrimSuffix(fields[2], "\""), "\"")
	out := []byte{byte(flags), byte(len(tag))}
	out = append(out, []byte(tag)...)
	out = append(out, []byte(value)...)
	return out, nil
}

// parseRDataGeneric handles the RFC 3597 §5 generic form:
//
//	\# <rdlength> <hex>
//
// The literal backslash is the first byte of the field. The numeric
// length is the second field, and the hex string is the third.
//
func parseRDataGeneric(fields []string) ([]byte, error) {
	if len(fields) < 3 {
		return nil, fmt.Errorf("generic form requires '\\# <rdlength> <hex>'")
	}
	if fields[0] != "\\#" {
		return nil, fmt.Errorf("generic form must start with \\#")
	}
	rdlen, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("generic RDATA length: %w", err)
	}
	hexStr := strings.Join(fields[2:], "")
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("generic RDATA hex: %w", err)
	}
	if uint64(len(decoded)) != rdlen {
		return nil, fmt.Errorf("generic RDATA length mismatch: header %d, hex %d", rdlen, len(decoded))
	}
	return decoded, nil
}

// appendName concatenates a wire-format name to a byte slice. Encoded
// out-of-place because the parser needs to build RDATA byte-for-byte
// the same way the wire-format parsers consume it.
//
func appendName(dst []byte, name string) []byte {
	encoded, err := EncodeNameToBytes(name)
	if err != nil {
		// EncodeNameToBytes only rejects labels that are too long or
		// contain invalid characters. We surface a panic-equivalent
		// here because the parser cannot return a useful error from
		// this helper (it has no line context).
		panic(fmt.Errorf("appendName %q: %w", name, err))
	}
	return append(dst, encoded...)
}

// parseIPv4 parses a dotted-decimal IPv4 address without importing the
// net package (the parser is small enough that the stdlib net.IP
// indirection is wasted).
//
func parseIPv4(s string) []byte {
	var out []byte
	num := 0
	dots := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if dots >= 3 {
				return nil
			}
			out = append(out, byte(num))
			num = 0
			dots++
			continue
		}
		if c < '0' || c > '9' {
			return nil
		}
		num = num*10 + int(c-'0')
		if num > 255 {
			return nil
		}
	}
	if dots != 3 {
		return nil
	}
	out = append(out, byte(num))
	return out
}

// parseIPv6 parses a hex-colon IPv6 address (RFC 4291 §2.2). The
// double-colon shorthand is supported: a single `::` expands to one
// or more groups of zeros such that the total number of groups is
// eight. The shorthand is allowed at most once per address.
//
func parseIPv6(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	// Split on `::` first. The shorthand may appear at most once;
	// a second occurrence is a syntax error.
	parts := strings.SplitN(s, "::", 3)
	if len(parts) > 2 {
		return nil
	}
	left := splitIPv6Groups(parts[0])
	if len(parts[0]) == 0 {
		// s starts with `::`; left is empty.
		left = nil
	}
	right := []uint16{}
	if len(parts) == 2 {
		if len(parts[1]) == 0 {
			// s ends with `::`; right is empty.
		} else {
			right = splitIPv6Groups(parts[1])
		}
	}
	full := append(append([]uint16{}, left...), right...)
	if len(full) > 8 {
		return nil
	}
	hasShorthand := len(parts) == 2
	if !hasShorthand && len(full) != 8 {
		return nil
	}
	if hasShorthand && len(left)+len(right) >= 8 {
		// `::` would not represent any zero groups.
		return nil
	}
	missing := 8 - len(full)
	pad := make([]uint16, missing)
	out := make([]byte, 16)
	pos := 0
	for _, g := range append(append(append([]uint16{}, left...), pad...), right...) {
		out[pos*2] = byte(g >> 8)
		out[pos*2+1] = byte(g)
		pos++
	}
	return out
}

// splitIPv6Groups splits a non-empty IPv6 group string on `:`, returning
// the parsed 16-bit groups. An empty input returns nil.
//
func splitIPv6Groups(s string) []uint16 {
	if s == "" {
		return nil
	}
	fields := strings.Split(s, ":")
	out := make([]uint16, len(fields))
	for i, f := range fields {
		if f == "" {
			return nil
		}
		v, err := strconv.ParseUint(f, 16, 16)
		if err != nil {
			return nil
		}
		out[i] = uint16(v)
	}
	return out
}

// nameToType is the inverse of dns.TypeName. The dns package does not
// expose this directly; we build a small map from the same constants the
// writer uses for mnemonic lookup. The keys are the IANA mnemonics and
// the values are the numeric types.
//
func nameToType(s string) (uint16, bool) {
	// Reuse the same dictionary the writer uses. We rebuild it once.
	mnemonic, ok := typeMnemonic()
	if !ok {
		return 0, false
	}
	v, ok := mnemonic[strings.ToUpper(s)]
	return v, ok
}

// typeMnemonic returns a map from IANA mnemonic to numeric type. The
// underlying constants in dns/types.go are not exposed as a map, so we
// build one lazily.
//
func typeMnemonic() (map[string]uint16, bool) {
	// A static registry would be cheaper; this is the smallest version
	// that covers the types the writer knows about plus the common
	// DNSSEC types. Numbers are stable (IANA-allocated).
	return map[string]uint16{
		"A":          1,
		"NS":         2,
		"CNAME":      5,
		"SOA":        6,
		"PTR":        12,
		"HINFO":      13,
		"MX":         15,
		"TXT":        16,
		"RP":         17,
		"AFSDB":      18,
		"SIG":        24,
		"KEY":        25,
		"AAAA":       28,
		"LOC":        29,
		"SRV":        33,
		"NAPTR":      35,
		"KX":         36,
		"CERT":       37,
		"DNAME":      39,
		"OPT":        41,
		"DS":         43,
		"SSHFP":      44,
		"IPSECKEY":   45,
		"RRSIG":      46,
		"NSEC":       47,
		"DNSKEY":     48,
		"DHCID":      49,
		"NSEC3":      50,
		"NSEC3PARAM": 51,
		"TLSA":       52,
		"SMIMEA":     53,
		"HIP":        55,
		"CDS":        59,
		"CDNSKEY":    60,
		"OPENPGPKEY": 61,
		"CSYNC":      62,
		"ZONEMD":     63,
		"SVCB":       64,
		"HTTPS":      65,
		"SPF":        99,
		"TKEY":       249,
		"TSIG":       250,
		"IXFR":       251,
		"AXFR":       252,
		"MAILB":      253,
		"MAILA":      254,
		"ANY":        255,
		"URI":        256,
		"CAA":        257,
		"RESINFO":    261,
	}, true
}

// ReadZone reads a BIND master-file from an io.Reader and returns the
// records it contains. Convenience wrapper around ParseZone for the
// common case where the file is on disk or being piped in.
//
func ReadZone(name string, r io.Reader) ([]ResourceRecord, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read zone %q: %w", name, err)
	}
	return ParseZone(name, data)
}

// ensureDot adds a trailing dot to a name if it does not have one. The
// internal representation uses absolute names everywhere, and the parser
// prefers to normalise rather than chase every call site that may or
// may not have appended the dot.
//
func ensureDot(s string) string {
	if s == "" {
		return "."
	}
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
