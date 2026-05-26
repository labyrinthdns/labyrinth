package cache

import (
	"strings"
	"sync"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

const shardCount = 256

const (
	defaultShardMapCapacity = 512
	negativeTTLFallback     = 60
)

// Cache is a sharded in-memory DNS cache with TTL-based expiration.
type Cache struct {
	shards     [shardCount]shard
	maxEntries int
	minTTL     uint32
	maxTTL     uint32
	negMaxTTL  uint32
	serveStale bool
	staleTTL   uint32
	metrics    *metrics.Metrics

	// hardenBelowNX enables RFC 8020: if a parent domain has an NXDOMAIN
	// cache entry, sub-domain queries return NXDOMAIN immediately.
	hardenBelowNX bool

	// prefetchEnabled enables proactive cache refresh: entries are
	// re-resolved in the background when their remaining TTL drops below
	// 10% of the original TTL.
	prefetchEnabled bool
	prefetchFunc    func(name string, qtype, qclass uint16)
}

type shard struct {
	mu      sync.RWMutex
	entries map[cacheKey]*Entry
	evictQ  evictionQueue
}

type cacheKey struct {
	name      string
	qtype     uint16
	class     uint16
	ecsPrefix string // ECS source prefix (e.g. "192.168.1.0/24"), empty if no ECS
}

// NewCache creates a new sharded DNS cache.
func NewCache(maxEntries int, minTTL, maxTTL, negMaxTTL uint32, m *metrics.Metrics) *Cache {
	return NewCacheWithStale(maxEntries, minTTL, maxTTL, negMaxTTL, false, 30, m)
}

// NewCacheWithStale creates a cache with optional serve-stale support (RFC 8767).
func NewCacheWithStale(maxEntries int, minTTL, maxTTL, negMaxTTL uint32, serveStale bool, staleTTL uint32, m *metrics.Metrics) *Cache {
	c := &Cache{
		maxEntries: maxEntries,
		minTTL:     minTTL,
		maxTTL:     maxTTL,
		negMaxTTL:  negMaxTTL,
		serveStale: serveStale,
		staleTTL:   staleTTL,
		metrics:    m,
	}
	for i := range c.shards {
		c.shards[i].resetEntries()
	}
	return c
}

func (c *Cache) shardIndex(name string) uint8 {
	h := fnv32a(name)
	return uint8(h)
}

func fnv32a(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// Get retrieves an entry from the cache with TTL decay.
func (c *Cache) Get(name string, qtype uint16, class uint16) (*Entry, bool) {
	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class}
	lookupKey := key
	idx := c.shardIndex(name)

	s := &c.shards[idx]
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok {
		// RFC 2308 §3: NXDOMAIN covers all types — check sentinel (qtype=0)
		if qtype != 0 {
			nxKey := cacheKey{name: name, qtype: 0, class: class}
			s.mu.RLock()
			entry, ok = s.entries[nxKey]
			s.mu.RUnlock()
			if ok {
				lookupKey = nxKey
			}
		}
		if !ok {
			// RFC 8020 harden-below-nxdomain: walk up parent labels
			if c.hardenBelowNX && qtype != 0 {
				if nxEntry, found := c.checkParentNXDomain(name, class); found {
					return nxEntry, true
				}
			}
			return nil, false
		}
	}

	remaining := entry.RemainingTTL()
	if remaining == 0 {
		// Don't delete expired entries if serve-stale is enabled;
		// they may still be served via GetStale on upstream failure.
		if !c.serveStale {
			s.mu.Lock()
			delete(s.entries, lookupKey)
			s.mu.Unlock()
			if c.metrics != nil {
				c.metrics.IncCacheEvictions("expired")
			}
		}
		return nil, false
	}

	// Prefetch: trigger async re-resolution when TTL drops below 10% of original
	if c.prefetchEnabled && c.prefetchFunc != nil && remaining > 0 {
		threshold := entry.OrigTTL / 10
		if threshold == 0 {
			threshold = 1
		}
		if remaining < threshold && entry.tryPrefetch() {
			go c.prefetchFunc(name, qtype, class)
		}
	}

	decayed := entry.WithDecayedTTL(remaining)
	return decayed, true
}

// checkParentNXDomain walks up the label hierarchy looking for a cached
// NXDOMAIN sentinel (qtype=0). Returns the parent NXDOMAIN entry if found.
func (c *Cache) checkParentNXDomain(name string, class uint16) (*Entry, bool) {
	// Walk up labels: for "sub.nonexist.com", check "nonexist.com", then "com"
	for {
		dotIdx := strings.IndexByte(name, '.')
		if dotIdx < 0 {
			break
		}
		parent := name[dotIdx+1:]
		if parent == "" {
			break
		}

		parentIdx := c.shardIndex(parent)
		ps := &c.shards[parentIdx]
		nxKey := cacheKey{name: parent, qtype: 0, class: class}
		ps.mu.RLock()
		entry, ok := ps.entries[nxKey]
		ps.mu.RUnlock()

		if ok {
			remaining := entry.RemainingTTL()
			if remaining > 0 {
				decayed := entry.WithDecayedTTL(remaining)
				return decayed, true
			}
		}

		name = parent
	}
	return nil, false
}

// SetHardenBelowNX enables or disables RFC 8020 harden-below-nxdomain.
func (c *Cache) SetHardenBelowNX(enabled bool) {
	c.hardenBelowNX = enabled
}

// SetPrefetchEnabled enables or disables proactive cache prefetching.
func (c *Cache) SetPrefetchEnabled(enabled bool) {
	c.prefetchEnabled = enabled
}

// SetPrefetchFunc sets the callback used to re-resolve entries nearing expiry.
func (c *Cache) SetPrefetchFunc(fn func(name string, qtype, qclass uint16)) {
	c.prefetchFunc = fn
}

// GetStale retrieves an expired entry from the cache for serve-stale (RFC 8767).
// Returns the entry with staleTTL if serve-stale is enabled and the entry exists but is expired.
//
// The returned entry's DNSSECStatus is cleared: when records are served past
// their TTL the covering RRSIGs may also be past their signature-inception/
// expiration window, so we cannot honestly carry over the original "secure"
// verdict. Downstream validators that care will re-verify; the AD bit on a
// stale serve would be a lie.
func (c *Cache) GetStale(name string, qtype uint16, class uint16) (*Entry, bool) {
	if !c.serveStale {
		return nil, false
	}

	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class}
	idx := c.shardIndex(name)

	s := &c.shards[idx]
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok {
		return nil, false
	}

	// Only serve stale if entry is actually expired
	if entry.RemainingTTL() > 0 {
		return nil, false
	}

	// Return with stale TTL; suppress DNSSEC verdict (see method comment).
	stale := entry.WithDecayedTTL(c.staleTTL)
	stale.DNSSECStatus = ""
	return stale, true
}

// Store caches a positive DNS result.
func (c *Cache) Store(name string, qtype uint16, class uint16, answers []dns.ResourceRecord, authority []dns.ResourceRecord) {
	c.StoreWithStatus(name, qtype, class, answers, authority, "")
}

// StoreWithStatus caches a positive DNS result together with the validator's
// verdict ("secure", "insecure", "bogus", or ""). The status is consumed by
// the server to set the AD bit on cache-served responses without re-running
// DNSSEC validation per lookup.
func (c *Cache) StoreWithStatus(name string, qtype uint16, class uint16, answers []dns.ResourceRecord, authority []dns.ResourceRecord, dnssecStatus string) {
	// RFC 2181 §8: TTL=0 means "use for the current transaction only and
	// do NOT cache." Honour that here rather than promoting up to minTTL.
	if c.extractTTL(answers) == 0 {
		return
	}
	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class}
	idx := c.shardIndex(name)

	ttl := c.extractTTL(answers)
	ttl = c.clampTTL(ttl)

	entry := &Entry{
		Records:      cloneRRs(answers),
		Authority:    cloneRRs(authority),
		InsertedAt:   time.Now(),
		OrigTTL:      ttl,
		DNSSECStatus: dnssecStatus,
	}

	s := &c.shards[idx]
	s.mu.Lock()
	s.entries[key] = entry
	s.pushEvictionEntry(key, entry)
	c.enforceMaxEntriesLocked(s)
	s.mu.Unlock()
}

// StoreWithECSStatus caches a positive DNS result keyed by ECS source prefix
// along with the DNSSEC validator's verdict and the authoritative server's
// returned ECS SCOPE PREFIX-LENGTH (echoed to the client per RFC 7871 §7.2.1).
// ecsPrefix == "" routes to StoreWithStatus (global, all clients share).
func (c *Cache) StoreWithECSStatus(
	name string, qtype uint16, class uint16,
	ecsPrefix string, ecsScope uint8,
	answers []dns.ResourceRecord, authority []dns.ResourceRecord,
	dnssecStatus string,
) {
	if ecsPrefix == "" {
		// Global scope (RFC 7871 §7.3.1): one entry covers all clients.
		c.StoreWithStatus(name, qtype, class, answers, authority, dnssecStatus)
		return
	}
	// RFC 2181 §8 — same TTL=0 don't-cache rule as the global path.
	if c.extractTTL(answers) == 0 {
		return
	}
	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class, ecsPrefix: ecsPrefix}
	idx := c.shardIndex(name)

	ttl := c.extractTTL(answers)
	ttl = c.clampTTL(ttl)

	entry := &Entry{
		Records:      cloneRRs(answers),
		Authority:    cloneRRs(authority),
		InsertedAt:   time.Now(),
		OrigTTL:      ttl,
		DNSSECStatus: dnssecStatus,
		ECSScope:     ecsScope,
	}

	s := &c.shards[idx]
	s.mu.Lock()
	s.entries[key] = entry
	s.pushEvictionEntry(key, entry)
	c.enforceMaxEntriesLocked(s)
	s.mu.Unlock()
}

// StoreNegative caches a negative DNS result (NXDOMAIN/NODATA).
// NXDOMAIN applies to the entire name (RFC 2308 §3) so it is stored
// with qtype=0 as a sentinel. NODATA is type-specific.
func (c *Cache) StoreNegative(name string, qtype uint16, class uint16, negType NegativeType, rcode uint8, authority []dns.ResourceRecord) {
	// RFC 2308 §3 defense-in-depth: refuse to cache a negative response whose
	// authority section carries an SOA but the SOA's owner does not cover the
	// queried name. The resolver classifier already filters out-of-bailiwick
	// SOAs before producing the NODATA/NXDOMAIN verdict, but this guard
	// prevents any future caller from accidentally bypassing that check and
	// poisoning the negative cache with an attacker-attached SOA.
	if hasAnySOA(authority) && !authorityCoversName(name, authority) {
		return
	}
	// RFC 2181 §8 / RFC 2308 §4: a TTL of zero on the SOA Minimum field
	// or the SOA RR itself means the negative answer is for this query
	// only and MUST NOT be cached.
	rawTTL := c.extractNegativeTTL(authority)
	if rawTTL == 0 {
		return
	}
	name = strings.ToLower(name)
	storeType := qtype
	if negType == NegNXDomain {
		storeType = 0 // sentinel: NXDOMAIN covers all types for this name
	}
	key := cacheKey{name: name, qtype: storeType, class: class}
	idx := c.shardIndex(name)

	ttl := c.clampNegativeTTL(rawTTL)

	var soa *dns.ResourceRecord
	for i, rr := range authority {
		if rr.Type == dns.TypeSOA {
			soa = &authority[i]
			break
		}
	}

	entry := &Entry{
		Authority:  cloneRRs(authority),
		InsertedAt: time.Now(),
		OrigTTL:    ttl,
		Negative:   true,
		NegType:    negType,
		SOA:        soa,
		RCODE:      rcode,
	}

	s := &c.shards[idx]
	s.mu.Lock()
	s.entries[key] = entry
	s.pushEvictionEntry(key, entry)
	c.enforceMaxEntriesLocked(s)
	s.mu.Unlock()
}

func (c *Cache) extractTTL(records []dns.ResourceRecord) uint32 {
	if len(records) == 0 {
		return c.minTTL
	}
	minTTL := sanitizeWireTTL(records[0].TTL)
	for _, rr := range records[1:] {
		t := sanitizeWireTTL(rr.TTL)
		if t < minTTL {
			minTTL = t
		}
	}
	return minTTL
}

// MaxFailureTTL is the RFC 9520 §4 ceiling on resolution-failure caching.
// "DNS resolvers SHOULD cache resolution failures … TTL … MUST NOT exceed
// 5 minutes." We pick a tighter 30-second cap so transient outages clear
// quickly while still protecting upstream from the per-query stampede.
const MaxFailureTTL uint32 = 30

// DefaultFailureTTL is the typical RFC 9520 §3 "small number of seconds"
// negative-failure window: 5 s by default, balancing fast recovery on
// transient flakes against worthwhile suppression of repeat work.
const DefaultFailureTTL uint32 = 5

// StoreFailure records a resolution-failure (SERVFAIL) negative entry for
// the (name, qtype, class) triple, with TTL clamped to [1, MaxFailureTTL].
// RFC 9520 §3: "Recursive servers MUST cache resolution failures." Without
// this cap, a client retrying a broken name every 100 ms re-runs the full
// iterative chain every time — a small loop can swamp an upstream auth
// server with thousands of QPS. The entry stores no records and emits
// RCODE=SERVFAIL on cache hit, just like the upstream would have.
func (c *Cache) StoreFailure(name string, qtype uint16, class uint16, ttl uint32) {
	if ttl == 0 {
		ttl = DefaultFailureTTL
	}
	if ttl > MaxFailureTTL {
		ttl = MaxFailureTTL
	}
	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class}
	idx := c.shardIndex(name)

	entry := &Entry{
		InsertedAt: time.Now(),
		OrigTTL:    ttl,
		Negative:   true,
		NegType:    NegServFail,
		RCODE:      dns.RCodeServFail,
	}

	s := &c.shards[idx]
	s.mu.Lock()
	s.entries[key] = entry
	s.pushEvictionEntry(key, entry)
	c.enforceMaxEntriesLocked(s)
	s.mu.Unlock()
}

// hasAnySOA reports whether the authority section contains any SOA record.
func hasAnySOA(authority []dns.ResourceRecord) bool {
	for _, rr := range authority {
		if rr.Type == dns.TypeSOA {
			return true
		}
	}
	return false
}

// authorityCoversName reports whether at least one SOA record in the authority
// section has an owner name that is qname itself or an ancestor of qname.
// RFC 2308 §3 requires the SOA accompanying a negative response to come from
// a zone that covers the queried name; an SOA whose owner is unrelated to
// qname is illegitimate and must not contribute to negative caching.
func authorityCoversName(qname string, authority []dns.ResourceRecord) bool {
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	for _, rr := range authority {
		if rr.Type != dns.TypeSOA {
			continue
		}
		owner := strings.ToLower(strings.TrimSuffix(rr.Name, "."))
		if owner == "" {
			return true // root SOA covers everything
		}
		if owner == q {
			return true
		}
		if strings.HasSuffix(q, "."+owner) {
			return true
		}
	}
	return false
}

// sanitizeWireTTL applies the RFC 2181 §8 ceiling to a TTL value read off
// the wire. The on-wire TTL field is a 32-bit *signed* integer but is
// transmitted in the unsigned half; values with the most-significant bit
// set (≥ 2^31) MUST be treated as if the entire value were zero. Without
// this clamp a hostile authoritative server could ship a ~68-year TTL,
// making a cache entry effectively permanent and giving cache-poisoning
// attempts unbounded persistence.
func sanitizeWireTTL(ttl uint32) uint32 {
	if ttl&0x80000000 != 0 {
		return 0
	}
	return ttl
}

func (c *Cache) extractNegativeTTL(authority []dns.ResourceRecord) uint32 {
	for _, rr := range authority {
		if rr.Type == dns.TypeSOA && rr.RData != nil && len(rr.RData) > 0 {
			// RDATA is decompressed: MNAME(labels) + RNAME(labels) + 5×uint32
			// SOA.Minimum is the last uint32. Parse it properly.
			soa, err := dns.ParseSOA(rr.RData, 0)
			if err == nil {
				// RFC 2308: use min(SOA RR TTL, SOA.Minimum)
				// Both fields go through sanitizeWireTTL so a hostile
				// authoritative cannot smuggle a ≥2^31 value past the
				// negative-cache path either (RFC 2181 §8).
				ttl := sanitizeWireTTL(rr.TTL)
				if m := sanitizeWireTTL(soa.Minimum); m < ttl {
					ttl = m
				}
				return ttl
			}
			// Fallback to RR TTL if SOA parse fails
			return sanitizeWireTTL(rr.TTL)
		}
	}
	return negativeTTLFallback // fallback: 1 minute
}

func (c *Cache) clampTTL(ttl uint32) uint32 {
	if ttl < c.minTTL {
		return c.minTTL
	}
	if ttl > c.maxTTL {
		return c.maxTTL
	}
	return ttl
}

func (c *Cache) clampNegativeTTL(ttl uint32) uint32 {
	if ttl < c.minTTL {
		return c.minTTL
	}
	if ttl > c.negMaxTTL {
		return c.negMaxTTL
	}
	return ttl
}

func (c *Cache) enforceMaxEntriesLocked(s *shard) {
	if c.maxEntries <= 0 {
		return
	}
	for len(s.entries) > c.maxEntries/shardCount+1 {
		evictKey, _ := s.nextEvictionKeyLocked()
		delete(s.entries, evictKey)
		if c.metrics != nil {
			c.metrics.IncCacheEvictions("capacity")
		}
	}
}

// Lookup retrieves an entry from the cache without deleting expired entries.
// Unlike Get, this is a read-only operation suitable for inspection.
func (c *Cache) Lookup(name string, qtype uint16, class uint16) (*Entry, bool) {
	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class}
	idx := c.shardIndex(name)

	s := &c.shards[idx]
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok {
		return nil, false
	}

	remaining := entry.RemainingTTL()
	if remaining == 0 {
		return nil, false
	}

	decayed := entry.WithDecayedTTL(remaining)
	return decayed, true
}

// LookupAll returns all cached entries for the given name (across all types).
func (c *Cache) LookupAll(name string, class uint16) []*Entry {
	name = strings.ToLower(name)
	idx := c.shardIndex(name)

	s := &c.shards[idx]
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*Entry
	for key, entry := range s.entries {
		if key.name == name && key.class == class {
			remaining := entry.RemainingTTL()
			if remaining == 0 {
				continue
			}
			decayed := entry.WithDecayedTTL(remaining)
			results = append(results, decayed)
		}
	}
	return results
}

// Delete removes a specific entry from the cache.
// Returns true if the entry was found and deleted.
func (c *Cache) Delete(name string, qtype uint16, class uint16) bool {
	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class}
	idx := c.shardIndex(name)

	s := &c.shards[idx]
	s.mu.Lock()
	_, ok := s.entries[key]
	if ok {
		delete(s.entries, key)
	}
	s.mu.Unlock()
	return ok
}

// ResourceRecordInfo holds a human-readable representation of a DNS resource record.
type ResourceRecordInfo struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	RData string `json:"rdata"`
}

// NegativeEntryInfo holds information about a negative cache entry.
type NegativeEntryInfo struct {
	Name         string               `json:"name"`
	QType        string               `json:"qtype"`
	NegType      string               `json:"neg_type"`
	RCODE        string               `json:"rcode"`
	RemainingTTL uint32               `json:"remaining_ttl"`
	Authority    []ResourceRecordInfo `json:"authority"`
}

// NegativeEntries returns up to limit negative cache entries across all shards.
func (c *Cache) NegativeEntries(limit int) []NegativeEntryInfo {
	var result []NegativeEntryInfo

	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		for key, entry := range s.entries {
			if !entry.Negative {
				continue
			}
			remaining := entry.RemainingTTL()
			if remaining == 0 {
				continue
			}

			negTypeStr := "UNKNOWN"
			switch entry.NegType {
			case NegNXDomain:
				negTypeStr = "NXDOMAIN"
			case NegNoData:
				negTypeStr = "NODATA"
			case NegServFail:
				negTypeStr = "SERVFAIL"
			}

			rcodeStr := dns.RCodeToString[entry.RCODE]
			if rcodeStr == "" {
				rcodeStr = "UNKNOWN"
			}

			qtypeStr := dns.TypeToString[key.qtype]
			if qtypeStr == "" {
				if key.qtype == 0 && entry.NegType == NegNXDomain {
					qtypeStr = "*" // NXDOMAIN covers all types (RFC 2308)
				} else {
					qtypeStr = "UNKNOWN"
				}
			}

			auth := make([]ResourceRecordInfo, 0, len(entry.Authority))
			for _, rr := range entry.Authority {
				typeStr := dns.TypeToString[rr.Type]
				if typeStr == "" {
					typeStr = "UNKNOWN"
				}
				auth = append(auth, ResourceRecordInfo{
					Name:  rr.Name,
					Type:  typeStr,
					TTL:   remaining,
					RData: formatAuthorityRData(rr),
				})
			}

			result = append(result, NegativeEntryInfo{
				Name:         key.name,
				QType:        qtypeStr,
				NegType:      negTypeStr,
				RCODE:        rcodeStr,
				RemainingTTL: remaining,
				Authority:    auth,
			})

			if limit > 0 && len(result) >= limit {
				s.mu.RUnlock()
				return result
			}
		}
		s.mu.RUnlock()
	}

	return result
}

// formatAuthorityRData formats the RDATA of an authority record as a string.
func formatAuthorityRData(rr dns.ResourceRecord) string {
	switch rr.Type {
	case dns.TypeSOA:
		soa, err := dns.ParseSOA(rr.RData, 0)
		if err == nil {
			return soa.MName + " " + soa.RName
		}
	case dns.TypeNS:
		name, _, err := dns.DecodeName(rr.RData, 0)
		if err == nil {
			return name
		}
	}
	return ""
}

// GetWithECS retrieves a cache entry using an ECS-aware key.
// If ecsPrefix is empty, it behaves like Get.
func (c *Cache) GetWithECS(name string, qtype uint16, class uint16, ecsPrefix string) (*Entry, bool) {
	if ecsPrefix == "" {
		return c.Get(name, qtype, class)
	}

	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class, ecsPrefix: ecsPrefix}
	idx := c.shardIndex(name)

	s := &c.shards[idx]
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok {
		return nil, false
	}

	remaining := entry.RemainingTTL()
	if remaining == 0 {
		return nil, false
	}

	decayed := entry.WithDecayedTTL(remaining)
	return decayed, true
}

// StoreWithECS caches a positive DNS result with an ECS prefix key.
// If ecsPrefix is empty, it behaves like Store.
func (c *Cache) StoreWithECS(name string, qtype uint16, class uint16, ecsPrefix string, answers []dns.ResourceRecord, authority []dns.ResourceRecord) {
	if ecsPrefix == "" {
		c.Store(name, qtype, class, answers, authority)
		return
	}

	name = strings.ToLower(name)
	key := cacheKey{name: name, qtype: qtype, class: class, ecsPrefix: ecsPrefix}
	idx := c.shardIndex(name)

	ttl := c.extractTTL(answers)
	ttl = c.clampTTL(ttl)

	entry := &Entry{
		Records:    cloneRRs(answers),
		Authority:  cloneRRs(authority),
		InsertedAt: time.Now(),
		OrigTTL:    ttl,
	}

	s := &c.shards[idx]
	s.mu.Lock()
	s.entries[key] = entry
	s.pushEvictionEntry(key, entry)
	c.enforceMaxEntriesLocked(s)
	s.mu.Unlock()
}

func cloneRRs(rrs []dns.ResourceRecord) []dns.ResourceRecord {
	if rrs == nil {
		return nil
	}
	cloned := make([]dns.ResourceRecord, len(rrs))
	copy(cloned, rrs)
	for i, rr := range cloned {
		if rr.RData != nil {
			cloned[i].RData = make([]byte, len(rr.RData))
			copy(cloned[i].RData, rr.RData)
		}
	}
	return cloned
}
