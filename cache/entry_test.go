package cache

import (
	"testing"
	"time"

	"github.com/labyrinth-dns/labyrinth/dns"
)

func TestEntryRemainingTTL(t *testing.T) {
	e := &Entry{
		InsertedAt: time.Now().Add(-30 * time.Second),
		OrigTTL:    60,
	}

	remaining := e.RemainingTTL()
	if remaining > 31 || remaining < 29 {
		t.Errorf("expected ~30, got %d", remaining)
	}
}

func TestEntryExpired(t *testing.T) {
	e := &Entry{
		InsertedAt: time.Now().Add(-120 * time.Second),
		OrigTTL:    60,
	}

	if !e.Expired() {
		t.Error("entry should be expired")
	}
}

func TestEntryNotExpired(t *testing.T) {
	e := &Entry{
		InsertedAt: time.Now(),
		OrigTTL:    300,
	}

	if e.Expired() {
		t.Error("entry should not be expired")
	}
}

func TestWithDecayedTTL(t *testing.T) {
	e := &Entry{
		Records: []dns.ResourceRecord{
			{Name: "test.com", Type: dns.TypeA, TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4}},
			{Name: "test.com", Type: dns.TypeA, TTL: 300, RDLength: 4, RData: []byte{5, 6, 7, 8}},
		},
		Authority: []dns.ResourceRecord{
			{Name: "test.com", Type: dns.TypeNS, TTL: 3600},
		},
		InsertedAt: time.Now(),
		OrigTTL:    300,
		Negative:   false,
		RCODE:      dns.RCodeNoError,
	}

	decayed := e.WithDecayedTTL(150)

	// Check decayed TTLs
	for i, rr := range decayed.Records {
		if rr.TTL != 150 {
			t.Errorf("record[%d].TTL: expected 150, got %d", i, rr.TTL)
		}
	}
	for i, rr := range decayed.Authority {
		if rr.TTL != 150 {
			t.Errorf("authority[%d].TTL: expected 150, got %d", i, rr.TTL)
		}
	}

	// Original should be unchanged
	if e.Records[0].TTL != 300 {
		t.Error("original record TTL should not be modified")
	}

	// Metadata preserved
	if decayed.RCODE != dns.RCodeNoError {
		t.Error("RCODE not preserved")
	}
}
