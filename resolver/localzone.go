package resolver

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// LocalZoneType controls how a local zone behaves.
type LocalZoneType int

const (
	// LocalStatic returns configured records or NXDOMAIN.
	LocalStatic LocalZoneType = iota
	// LocalDeny silently drops the query (returns nil response).
	LocalDeny
	// LocalRefuse returns REFUSED rcode.
	LocalRefuse
	// LocalRedirect returns configured records for any name in the zone.
	LocalRedirect
	// LocalTransparent returns configured records if found, otherwise
	// falls through to recursive resolution.
	LocalTransparent
)

// localZoneTypeNames maps type name strings to LocalZoneType values.
var localZoneTypeNames = map[string]LocalZoneType{
	"static":      LocalStatic,
	"deny":        LocalDeny,
	"refuse":      LocalRefuse,
	"redirect":    LocalRedirect,
	"transparent": LocalTransparent,
}

// ParseLocalZoneType converts a string to a LocalZoneType.
func ParseLocalZoneType(s string) (LocalZoneType, bool) {
	t, ok := localZoneTypeNames[strings.ToLower(s)]
	return t, ok
}

// LocalRecord holds a single record within a local zone.
type LocalRecord struct {
	Name  string
	Type  uint16
	RData []byte
	TTL   uint32
}

// LocalZone represents a locally-served DNS zone.
type LocalZone struct {
	Name    string
	Type    LocalZoneType
	Records []LocalRecord
}

// LocalZoneTable stores local zones sorted by specificity (longest name first)
// for efficient longest-suffix matching.
type LocalZoneTable struct {
	zones []LocalZone
}

// NewLocalZoneTable creates a LocalZoneTable from the given zones, sorting them
// so the most specific (longest name) zone comes first.
func NewLocalZoneTable(zones []LocalZone) *LocalZoneTable {
	// Normalize zone names to lowercase, no trailing dot.
	for i := range zones {
		zones[i].Name = normalizeName(zones[i].Name)
		for j := range zones[i].Records {
			zones[i].Records[j].Name = normalizeName(zones[i].Records[j].Name)
		}
	}

	// Sort by label count descending (longest/most specific first).
	sort.Slice(zones, func(i, j int) bool {
		return strings.Count(zones[i].Name, ".") > strings.Count(zones[j].Name, ".")
	})

	return &LocalZoneTable{zones: zones}
}

// Lookup checks whether the query matches a local zone and returns the
// appropriate result. Returns nil if no local zone matches or if the zone
// type allows fall-through (e.g. LocalTransparent with no matching record).
func (t *LocalZoneTable) Lookup(name string, qtype uint16, qclass uint16) *ResolveResult {
	if qclass != dns.ClassIN {
		return nil
	}

	name = normalizeName(name)

	zone := t.findZone(name)
	if zone == nil {
		return nil
	}

	switch zone.Type {
	case LocalStatic:
		return t.lookupStatic(zone, name, qtype)
	case LocalDeny:
		// Return a sentinel "drop" result — the caller should silently discard.
		return &ResolveResult{RCODE: dns.RCodeRefused, DNSSECStatus: "local-deny"}
	case LocalRefuse:
		return &ResolveResult{RCODE: dns.RCodeRefused}
	case LocalRedirect:
		return t.lookupRedirect(zone, name, qtype)
	case LocalTransparent:
		return t.lookupTransparent(zone, name, qtype)
	}

	return nil
}

// findZone returns the most specific zone whose name is a suffix of (or equal
// to) the query name. Because zones are sorted longest-first, the first match
// is the best.
func (t *LocalZoneTable) findZone(name string) *LocalZone {
	for i := range t.zones {
		zn := t.zones[i].Name
		if name == zn || strings.HasSuffix(name, "."+zn) {
			return &t.zones[i]
		}
	}
	return nil
}

// lookupStatic returns matching records or NXDOMAIN.
func (t *LocalZoneTable) lookupStatic(zone *LocalZone, name string, qtype uint16) *ResolveResult {
	records := matchRecords(zone.Records, name, qtype)
	if len(records) > 0 {
		return &ResolveResult{
			Answers: records,
			RCODE:   dns.RCodeNoError,
		}
	}
	// Check if the name exists at all (any type).
	for _, r := range zone.Records {
		if r.Name == name {
			// Name exists but no matching type → NODATA (NoError + empty answer).
			return &ResolveResult{RCODE: dns.RCodeNoError}
		}
	}
	return &ResolveResult{RCODE: dns.RCodeNXDomain}
}

// lookupRedirect returns zone records rewritten to the query name.
func (t *LocalZoneTable) lookupRedirect(zone *LocalZone, name string, qtype uint16) *ResolveResult {
	// Match records by type only (ignore record name), rewrite to query name.
	var answers []dns.ResourceRecord
	for _, r := range zone.Records {
		if r.Type == qtype {
			answers = append(answers, dns.ResourceRecord{
				Name:     name,
				Type:     r.Type,
				Class:    dns.ClassIN,
				TTL:      r.TTL,
				RDLength: uint16(len(r.RData)),
				RData:    r.RData,
			})
		}
	}
	if len(answers) > 0 {
		return &ResolveResult{
			Answers: answers,
			RCODE:   dns.RCodeNoError,
		}
	}
	return &ResolveResult{RCODE: dns.RCodeNoError}
}

// lookupTransparent returns matching records if found, nil otherwise to allow
// fall-through to recursive resolution.
func (t *LocalZoneTable) lookupTransparent(zone *LocalZone, name string, qtype uint16) *ResolveResult {
	records := matchRecords(zone.Records, name, qtype)
	if len(records) > 0 {
		return &ResolveResult{
			Answers: records,
			RCODE:   dns.RCodeNoError,
		}
	}
	return nil
}

// matchRecords finds records matching both name and type, returning them as
// ResourceRecords suitable for a response.
func matchRecords(records []LocalRecord, name string, qtype uint16) []dns.ResourceRecord {
	var result []dns.ResourceRecord
	for _, r := range records {
		if r.Name == name && r.Type == qtype {
			result = append(result, dns.ResourceRecord{
				Name:     name,
				Type:     r.Type,
				Class:    dns.ClassIN,
				TTL:      r.TTL,
				RDLength: uint16(len(r.RData)),
				RData:    r.RData,
			})
		}
	}
	return result
}

// normalizeName lowercases a name and strips any trailing dot.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// --- Record parsing ---

// stringToType maps type name strings to dns type constants.
var stringToType = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"CNAME": dns.TypeCNAME,
	"TXT":   dns.TypeTXT,
	"PTR":   dns.TypePTR,
	"MX":    dns.TypeMX,
}

// ParseLocalRecord parses a string in "name TYPE rdata" format into a LocalRecord.
// Examples:
//
//	"localhost. A 127.0.0.1"
//	"localhost. AAAA ::1"
//	"example.com. CNAME www.example.com."
//	"example.com. TXT \"hello world\""
//	"example.com. MX 10 mail.example.com."
//	"1.0.0.127.in-addr.arpa. PTR localhost."
func ParseLocalRecord(s string) (*LocalRecord, error) {
	s = strings.TrimSpace(s)
	parts := strings.Fields(s)
	if len(parts) < 3 {
		return nil, fmt.Errorf("local record: expected at least 3 fields, got %d: %q", len(parts), s)
	}

	name := normalizeName(parts[0])
	typeName := strings.ToUpper(parts[1])

	qtype, ok := stringToType[typeName]
	if !ok {
		return nil, fmt.Errorf("local record: unsupported type %q", typeName)
	}

	rdataStr := strings.Join(parts[2:], " ")

	rdata, err := encodeRData(qtype, rdataStr)
	if err != nil {
		return nil, fmt.Errorf("local record: %w", err)
	}

	return &LocalRecord{
		Name:  name,
		Type:  qtype,
		RData: rdata,
		TTL:   3600, // default TTL for local records
	}, nil
}

// encodeRData converts the textual RDATA into wire-format bytes.
func encodeRData(qtype uint16, s string) ([]byte, error) {
	switch qtype {
	case dns.TypeA:
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %q", s)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("not an IPv4 address: %q", s)
		}
		return []byte(ip4), nil

	case dns.TypeAAAA:
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %q", s)
		}
		ip6 := ip.To16()
		if ip6 == nil {
			return nil, fmt.Errorf("not an IPv6 address: %q", s)
		}
		return []byte(ip6), nil

	case dns.TypeCNAME, dns.TypePTR:
		// Encode as uncompressed wire-format domain name.
		return encodeNameWire(s), nil

	case dns.TypeTXT:
		// Strip surrounding quotes if present.
		text := strings.Trim(s, "\"")
		return encodeTXT(text), nil

	case dns.TypeMX:
		// Format: "preference exchange"
		fields := strings.Fields(s)
		if len(fields) != 2 {
			return nil, fmt.Errorf("MX record: expected \"preference exchange\", got %q", s)
		}
		pref, err := strconv.Atoi(fields[0])
		if err != nil || pref < 0 || pref > 65535 {
			return nil, fmt.Errorf("MX record: invalid preference %q", fields[0])
		}
		nameBytes := encodeNameWire(fields[1])
		buf := make([]byte, 2+len(nameBytes))
		binary.BigEndian.PutUint16(buf[0:2], uint16(pref))
		copy(buf[2:], nameBytes)
		return buf, nil

	default:
		return nil, fmt.Errorf("unsupported record type %d", qtype)
	}
}

// encodeNameWire encodes a domain name into uncompressed wire format.
func encodeNameWire(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}
	}
	labels := strings.Split(name, ".")
	var buf []byte
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)
	return buf
}

// encodeTXT encodes a TXT string into wire format (length-prefixed chunks of
// up to 255 bytes each).
func encodeTXT(s string) []byte {
	var buf []byte
	data := []byte(s)
	for len(data) > 0 {
		chunk := data
		if len(chunk) > 255 {
			chunk = chunk[:255]
		}
		buf = append(buf, byte(len(chunk)))
		buf = append(buf, chunk...)
		data = data[len(chunk):]
	}
	if len(buf) == 0 {
		// Empty TXT record: single zero-length string.
		buf = []byte{0}
	}
	return buf
}
