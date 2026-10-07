package xfr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

type ixfrMemoryConn struct{ *bytes.Reader }

func (c *ixfrMemoryConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *ixfrMemoryConn) Close() error                     { return nil }
func (c *ixfrMemoryConn) LocalAddr() net.Addr              { return nil }
func (c *ixfrMemoryConn) RemoteAddr() net.Addr             { return nil }
func (c *ixfrMemoryConn) SetDeadline(time.Time) error      { return nil }
func (c *ixfrMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *ixfrMemoryConn) SetWriteDeadline(time.Time) error { return nil }

func readMemoryIXFR(t *testing.T, parts [][]dns.ResourceRecord, serial uint32) (*Result, error) {
	t.Helper()
	var stream bytes.Buffer
	for i, part := range parts {
		msg := &dns.Message{Header: dns.Header{ID: 123, Flags: dns.NewFlagBuilder().SetQR(true).SetAA(true).Build()}, Answers: part}
		if i == 0 {
			msg.Questions = []dns.Question{{Name: "example.com", Type: dns.TypeIXFR, Class: dns.ClassIN}}
		}
		wire, err := dns.Pack(msg, make([]byte, 8192))
		if err != nil {
			t.Fatal(err)
		}
		if err = binary.Write(&stream, binary.BigEndian, uint16(len(wire))); err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	res, err := readStream(&ixfrMemoryConn{bytes.NewReader(stream.Bytes())}, ClientConfig{Zone: "example.com"}, 123, dns.TypeIXFR, serial, nil)
	if res != nil {
		// Wire offsets depend on message partitioning and are not zone data.
		for i := range res.Records {
			res.Records[i].RDataOffset = 0
		}
		for i := range res.Deltas {
			for j := range res.Deltas[i].Deleted {
				res.Deltas[i].Deleted[j].RDataOffset = 0
			}
			for j := range res.Deltas[i].Added {
				res.Deltas[i].Added[j].RDataOffset = 0
			}
		}
	}
	return res, err
}
func incrementalTestRecords(t *testing.T) []dns.ResourceRecord {
	return []dns.ResourceRecord{testSOA(t, "example.com", 3), testSOA(t, "example.com", 1), testA("example.com", 10), testSOA(t, "example.com", 2), testA("example.com", 20), testSOA(t, "example.com", 2), testA("example.com", 30), testSOA(t, "example.com", 3), testA("example.com", 40), testSOA(t, "example.com", 3)}
}

func TestXFR_IXFRMessageBoundaries(t *testing.T) {
	records := incrementalTestRecords(t)
	expected, err := parseIXFR(records)
	if err != nil {
		t.Fatal(err)
	}
	for split := 1; split < len(records); split++ {
		t.Run(fmt.Sprintf("split_%d", split), func(t *testing.T) {
			got, err := readMemoryIXFR(t, [][]dns.ResourceRecord{records[:split], records[split:]}, 1)
			if err != nil || !reflect.DeepEqual(got, expected) {
				t.Fatalf("got %+v, error %v; want %+v", got, err, expected)
			}
		})
	}
	t.Run("one_record_per_message", func(t *testing.T) {
		var parts [][]dns.ResourceRecord
		for i := range records {
			parts = append(parts, records[i:i+1])
		}
		got, err := readMemoryIXFR(t, parts, 1)
		if err != nil || !reflect.DeepEqual(got, expected) {
			t.Fatalf("got %+v, error %v; want %+v", got, err, expected)
		}
	})
	t.Run("up_to_date", func(t *testing.T) {
		got, err := readMemoryIXFR(t, [][]dns.ResourceRecord{{testSOA(t, "example.com", 3)}}, 3)
		if err != nil || !got.UpToDate || got.Serial != 3 {
			t.Fatalf("got %+v, error %v", got, err)
		}
	})
	t.Run("full_fallback", func(t *testing.T) {
		soa := testSOA(t, "example.com", 3)
		full := []dns.ResourceRecord{soa, testA("example.com", 1), soa}
		got, err := readMemoryIXFR(t, [][]dns.ResourceRecord{full[:1], full[1:2], full[2:]}, 1)
		if err != nil || got.Incremental || got.UpToDate || len(got.Records) != 2 || got.Serial != 3 {
			t.Fatalf("got %+v, error %v", got, err)
		}
	})
	t.Run("empty_delta", func(t *testing.T) {
		soa := testSOA(t, "example.com", 3)
		parts := [][]dns.ResourceRecord{{soa}, {testSOA(t, "example.com", 1)}, {soa}, {soa}}
		got, err := readMemoryIXFR(t, parts, 1)
		if err != nil || !got.Incremental || len(got.Deltas) != 1 || got.Deltas[0].ToSerial != 3 || len(got.Deltas[0].Added) != 0 {
			t.Fatalf("got %+v, error %v", got, err)
		}
	})
	t.Run("incomplete_stream", func(t *testing.T) {
		for end := 1; end < len(records); end++ {
			got, err := readMemoryIXFR(t, [][]dns.ResourceRecord{records[:end]}, 1)
			if err == nil || got != nil {
				t.Fatalf("prefix %d accepted: %+v, error %v", end, got, err)
			}
		}
	})
	t.Run("empty_stream", func(t *testing.T) {
		got, err := readMemoryIXFR(t, nil, 1)
		if err == nil || got != nil {
			t.Fatalf("empty stream accepted: %+v, error %v", got, err)
		}
	})
}
