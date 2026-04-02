package cache

// Negative caching types and helpers for NXDOMAIN / NODATA responses (RFC 2308).
//
// Negative cache entries are stored via Cache.StoreNegative() and retrieved
// via Cache.Get() like normal entries. They are distinguished by the Negative
// flag and NegType field on the Entry struct.
//
// TTL for negative entries is computed as min(SOA RR TTL, SOA.Minimum)
// per RFC 2308 §5, then clamped by the configured NegMaxTTL.
//
// Type definitions (NegativeType, NegNone, NegNXDomain, NegNoData)
// and Entry fields (Negative, NegType, SOA, RCODE) are in entry.go.
// Storage and retrieval logic is in cache.go (StoreNegative, extractNegativeTTL).
