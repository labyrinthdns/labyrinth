package cache

import (
	"sync/atomic"
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

	// DNSSECStatus records the validator's verdict on the cached records:
	// "secure", "insecure", "bogus", or "" (unknown). Used by the server
	// to set the AD bit on responses served from cache without re-running
	// validation.
	DNSSECStatus string

	// ECSScope is the SCOPE PREFIX-LENGTH the authoritative server
	// returned in its ECS option (RFC 7871 §6). Echoed back to the client
	// in the response OPT when the client itself sent ECS. Zero means the
	// answer is not subnet-scoped (global cache entry shared across all
	// clients).
	ECSScope uint8

	// prefetched is set atomically to 1 the first time a prefetch is
	// triggered for this entry, preventing duplicate background fetches.
	prefetched atomic.Int32
}

// tryPrefetch atomically marks this entry as prefetched. Returns true only
// the first time it is called (i.e. the caller should trigger the prefetch).
func (e *Entry) tryPrefetch() bool {
	return e.prefetched.CompareAndSwap(0, 1)
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
		Records:      make([]dns.ResourceRecord, len(e.Records)),
		Authority:    make([]dns.ResourceRecord, len(e.Authority)),
		InsertedAt:   e.InsertedAt,
		OrigTTL:      e.OrigTTL,
		Negative:     e.Negative,
		NegType:      e.NegType,
		SOA:          e.SOA,
		RCODE:        e.RCODE,
		DNSSECStatus: e.DNSSECStatus,
		ECSScope:     e.ECSScope,
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
