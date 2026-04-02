package web

import (
	"sync"
	"sync/atomic"
)

// QueryEntry represents a single DNS query log entry.
type QueryEntry struct {
	ID         uint64  `json:"id"`
	GlobalNum  uint64  `json:"global_num"`
	ClientNum  uint64  `json:"client_num"`
	Timestamp  string  `json:"ts"`
	Client     string  `json:"client"`
	QName      string  `json:"qname"`
	QType      string  `json:"qtype"`
	RCode      string  `json:"rcode"`
	Cached     bool    `json:"cached"`
	DurationMs float64 `json:"duration_ms"`
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

// NewQueryLog creates a new QueryLog with the given ring buffer capacity.
func NewQueryLog(capacity int) *QueryLog {
	if capacity <= 0 {
		capacity = 1000
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
func (ql *QueryLog) Subscribe() (uint64, <-chan QueryEntry) {
	id := ql.nextSub.Add(1)
	ch := make(chan QueryEntry, 128)
	ql.subMu.Lock()
	ql.subs[id] = ch
	ql.subMu.Unlock()
	return id, ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (ql *QueryLog) Unsubscribe(id uint64) {
	ql.subMu.Lock()
	if ch, ok := ql.subs[id]; ok {
		delete(ql.subs, id)
		close(ch)
	}
	ql.subMu.Unlock()
}
