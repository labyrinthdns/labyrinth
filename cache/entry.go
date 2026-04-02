package cache

import (
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// NegativeType indicates the type of negative cache entry.
type NegativeType uint8

const (
	NegNone     NegativeType = 0
	NegNXDomain NegativeType = 1
	NegNoData   NegativeType = 2
)

// Entry represents a cached DNS result.
type Entry struct {
	Records    []dns.ResourceRecord
	Authority  []dns.ResourceRecord
	InsertedAt time.Time
	OrigTTL    uint32
	Negative   bool
	NegType    NegativeType
	SOA        *dns.ResourceRecord
	RCODE      uint8
}

// RemainingTTL returns the remaining TTL in seconds.
func (e *Entry) RemainingTTL() uint32 {
	elapsed := uint32(time.Since(e.InsertedAt).Seconds())
	if elapsed >= e.OrigTTL {
		return 0
	}
	return e.OrigTTL - elapsed
}

// Expired returns true if the entry has expired.
func (e *Entry) Expired() bool {
	return e.RemainingTTL() == 0
}

// WithDecayedTTL returns a deep copy of the entry with TTL adjusted.
func (e *Entry) WithDecayedTTL(remaining uint32) *Entry {
	decayed := &Entry{
		Records:    make([]dns.ResourceRecord, len(e.Records)),
		Authority:  make([]dns.ResourceRecord, len(e.Authority)),
		InsertedAt: e.InsertedAt,
		OrigTTL:    e.OrigTTL,
		Negative:   e.Negative,
		NegType:    e.NegType,
		SOA:        e.SOA,
		RCODE:      e.RCODE,
	}

	copy(decayed.Records, e.Records)
	for i := range decayed.Records {
		decayed.Records[i].TTL = remaining
	}

	copy(decayed.Authority, e.Authority)
	for i := range decayed.Authority {
		decayed.Authority[i].TTL = remaining
	}

	return decayed
}
