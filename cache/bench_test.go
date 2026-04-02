package cache

import (
	"fmt"
	"testing"

	"github.com/labyrinth-dns/labyrinth/dns"
	"github.com/labyrinth-dns/labyrinth/metrics"
)

func BenchmarkCacheGet(b *testing.B) {
	m := metrics.NewMetrics()
	c := NewCache(100000, 5, 86400, 3600, m)

	// Pre-populate cache with 1000 entries.
	for i := 0; i < 1000; i++ {
		name := fmt.Sprintf("bench%d.example.com", i)
		answers := []dns.ResourceRecord{{
			Name:     name,
			Type:     dns.TypeA,
			Class:    dns.ClassIN,
			TTL:      300,
			RDLength: 4,
			RData:    []byte{10, 0, byte(i >> 8), byte(i)},
		}}
		c.Store(name, dns.TypeA, dns.ClassIN, answers, nil)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := fmt.Sprintf("bench%d.example.com", i%1000)
			c.Get(name, dns.TypeA, dns.ClassIN)
			i++
		}
	})
}

func BenchmarkCacheSet(b *testing.B) {
	m := metrics.NewMetrics()
	c := NewCache(100000, 5, 86400, 3600, m)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := fmt.Sprintf("bench%d.example.com", i%10000)
			answers := []dns.ResourceRecord{{
				Name:     name,
				Type:     dns.TypeA,
				Class:    dns.ClassIN,
				TTL:      300,
				RDLength: 4,
				RData:    []byte{10, 0, byte(i >> 8), byte(i)},
			}}
			c.Store(name, dns.TypeA, dns.ClassIN, answers, nil)
			i++
		}
	})
}

func BenchmarkFNV32a(b *testing.B) {
	keys := []string{
		"google.com",
		"example.com",
		"www.very-long-subdomain.deeply.nested.domain.example.org",
		"a.b",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fnv32a(keys[i%len(keys)])
	}
}
