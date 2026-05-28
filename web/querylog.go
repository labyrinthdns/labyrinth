package web

import (
	"sync"
	"sync/atomic"
)

// QueryEntry represents a single DNS query log entry.
type QueryEntry struct {
	ID           uint64  `json:"id"`
	GlobalNum    uint64  `json:"global_num"`
	ClientNum    uint64  `json:"client_num"`
	Timestamp    string  `json:"ts"`
	Client       string  `json:"client"`
	QName        string  `json:"qname"`
	QType        string  `json:"qtype"`
	RCode        string  `json:"rcode"`
	Cached       bool    `json:"cached"`
	DurationMs   float64 `json:"duration_ms"`
	Blocked      bool    `json:"blocked"`
	DNSSECStatus string  `json:"dnssec_status,omitempty"`
}

// QueryLog is a thread-safe ring buffer of DNS query entries with pub/sub support.
type QueryLog struct {
	mu       sync.RWMutex
	entries  []QueryEntry
	head     int
	count    int
	capacity int

	subMu   sync.Mutex
	subs    map[uint64]chan QueryEntry
	nextSub atomic.Uint64
}

// MaxQueryLogCapacity caps the QueryLog ring buffer size. Each
// QueryEntry is ~80 bytes (a few strings, int64s, a float64, a bool),
// so a 1M-entry ring holds ~80 MiB of buffered query history — enough
// for a dashboard to display many minutes of activity even on a
// busy resolver, and small enough that the worst-case footprint
// stays bounded. Without this cap, a typo in YAML (`query_log_buffer:
// 1000000000` instead of `1000000`) or a malicious config-raw PUT
// that planted a 1 GB+ value would allocate that slice upfront in
// NewQueryLog and OOM the resolver at startup.
const MaxQueryLogCapacity = 1_000_000

// MaxQueryLogSubscribers caps the number of concurrent WS subscribers
// the query-log fanout will hold. Each subscriber owns a
// `make(chan QueryEntry, 128)` channel — with a QueryEntry of ~80
// bytes plus pointer overhead, that's ~10 KiB per subscriber. The
// `/api/queries/stream` endpoint is behind requireAuth, so only an
// authenticated client can hit Subscribe; even so, a misbehaving
// dashboard that opens-and-leaks WebSocket connections in a tight
// reload loop, or an authenticated attacker, could grow `ql.subs`
// past memory limits. 256 is well above any plausible legitimate
// load (one operator + a handful of monitoring scripts) and bounds
// the fanout footprint to ~2.5 MiB. When the cap is hit, Subscribe
// returns id=0 and a CLOSED channel so the caller's read loop exits
// immediately — the client gets a clean disconnect instead of a
// silently-dropped subscription.
const MaxQueryLogSubscribers = 256

// NewQueryLog creates a new QueryLog with the given ring buffer
// capacity. Values <= 0 fall back to the 1000-entry default; values
// above MaxQueryLogCapacity are clamped to MaxQueryLogCapacity rather
// than rejected so an over-eager config doesn't fail-stop the
// resolver — it just trims the buffer to the cap.
func NewQueryLog(capacity int) *QueryLog {
	if capacity <= 0 {
		capacity = 1000
	}
	if capacity > MaxQueryLogCapacity {
		capacity = MaxQueryLogCapacity
	}
	return &QueryLog{
		entries:  make([]QueryEntry, capacity),
		capacity: capacity,
		subs:     make(map[uint64]chan QueryEntry),
	}
}

// Record adds an entry to the ring buffer and fans out to all subscribers.
func (ql *QueryLog) Record(entry QueryEntry) {
	ql.mu.Lock()
	ql.entries[ql.head] = entry
	ql.head = (ql.head + 1) % ql.capacity
	if ql.count < ql.capacity {
		ql.count++
	}
	ql.mu.Unlock()

	// Fan-out to subscribers (non-blocking send)
	ql.subMu.Lock()
	for _, ch := range ql.subs {
		select {
		case ch <- entry:
		default:
			// Drop if subscriber is slow
		}
	}
	ql.subMu.Unlock()
}

// Recent returns the last n entries in chronological order.
func (ql *QueryLog) Recent(n int) []QueryEntry {
	ql.mu.RLock()
	defer ql.mu.RUnlock()

	if n > ql.count {
		n = ql.count
	}
	if n <= 0 {
		return nil
	}

	result := make([]QueryEntry, n)
	// The most recent entry is at (head-1), oldest of the n is at (head-n)
	for i := 0; i < n; i++ {
		idx := (ql.head - n + i + ql.capacity) % ql.capacity
		result[i] = ql.entries[idx]
	}
	return result
}

// Subscribe returns a unique subscription ID and a channel that receives new entries.
// When the subscriber cap is hit, returns id=0 and a closed channel so the caller's
// read loop exits immediately — the client gets a clean disconnect instead of a
// silently-dropped subscription.
func (ql *QueryLog) Subscribe() (uint64, <-chan QueryEntry) {
	ql.subMu.Lock()
	if len(ql.subs) >= MaxQueryLogSubscribers {
		ql.subMu.Unlock()
		closed := make(chan QueryEntry)
		close(closed)
		return 0, closed
	}
	id := ql.nextSub.Add(1)
	ch := make(chan QueryEntry, 128)
	ql.subs[id] = ch
	ql.subMu.Unlock()
	return id, ch
}

// Unsubscribe removes a subscriber and closes its channel. id=0 is the
// sentinel returned by Subscribe when the cap was hit; no-op in that case.
func (ql *QueryLog) Unsubscribe(id uint64) {
	if id == 0 {
		return
	}
	ql.subMu.Lock()
	if ch, ok := ql.subs[id]; ok {
		delete(ql.subs, id)
		close(ch)
	}
	ql.subMu.Unlock()
}
