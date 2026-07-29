package server

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/security"
)

func TestBuildCacheResponseFiltersPrivateAddresses(t *testing.T) {
	h := testHandler()
	h.SetPrivateFilter(true)
	queryRaw := buildTestQueryWithEDNS("cached-private.example.com", dns.TypeA, 1232)
	query, err := dns.Unpack(queryRaw)
	if err != nil {
		t.Fatalf("unpack query: %v", err)
	}
	entry := &cache.Entry{Records: []dns.ResourceRecord{
		{Name: "cached-private.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 30, RDLength: 4, RData: []byte{10, 0, 0, 1}},
		{Name: "cached-private.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 30, RDLength: 4, RData: []byte{93, 184, 216, 34}},
	}}

	resp, err := h.buildCacheResponse(query, entry)
	if err != nil {
		t.Fatalf("buildCacheResponse: %v", err)
	}
	msg, err := dns.Unpack(resp)
	if err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if len(msg.Answers) != 1 || len(msg.Answers[0].RData) != 4 || msg.Answers[0].RData[0] != 93 {
		t.Fatalf("cached answers = %#v, want only public A record", msg.Answers)
	}

	var sawForgedAnswer bool
	for _, rr := range msg.Additional {
		if rr.Type != dns.TypeOPT {
			continue
		}
		edns, parseErr := dns.ParseOPT(&rr)
		if parseErr != nil {
			t.Fatalf("ParseOPT: %v", parseErr)
		}
		for _, option := range edns.Options {
			if option.Code != dns.EDNSOptionCodeEDE {
				continue
			}
			code, _, parseErr := dns.ParseEDEOption(option.Data)
			if parseErr == nil && code == dns.EDECodeForgedAnswer {
				sawForgedAnswer = true
			}
		}
	}
	if !sawForgedAnswer {
		t.Fatal("filtered cached response did not carry Forged Answer EDE")
	}
}

func TestServeStaleAppliesPrivateFilterAndRRL(t *testing.T) {
	m := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(100, 1, 60, 60, true, 30, m)
	qname := "stale-private.example.com"
	ca.Store(qname, dns.TypeA, dns.ClassIN, []dns.ResourceRecord{
		{Name: qname, Type: dns.TypeA, Class: dns.ClassIN, TTL: 1, RDLength: 4, RData: []byte{10, 0, 0, 1}},
		{Name: qname, Type: dns.TypeA, Class: dns.ClassIN, TTL: 1, RDLength: 4, RData: []byte{93, 184, 216, 34}},
	}, nil)
	time.Sleep(1100 * time.Millisecond)

	rrl := security.NewRRL(1, 1, 24, 56)
	h := NewMainHandler(newPanickingResolver(ca), ca, nil, rrl, nil, m, discardLogger())
	h.SetPrivateFilter(true)
	query := buildTestQuery(qname, dns.TypeA)
	addr := &mockAddr{network: "udp", addr: "192.0.2.44:5300"}

	first, err := h.Handle(query, addr)
	if err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	msg, err := dns.Unpack(first)
	if err != nil {
		t.Fatalf("unpack first response: %v", err)
	}
	if len(msg.Answers) != 1 || msg.Answers[0].RData[0] != 93 {
		t.Fatalf("stale answers = %#v, want only public A record", msg.Answers)
	}

	second, err := h.Handle(query, addr)
	if err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	if len(second) < 4 || binary.BigEndian.Uint16(second[2:4])&(1<<9) == 0 {
		t.Fatal("second stale response was not RRL-slipped with TC=1")
	}
}
