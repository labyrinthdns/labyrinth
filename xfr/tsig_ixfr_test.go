package xfr

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// Zone transfer with TSIG authentication (RFC 8945) and incremental transfer
// (RFC 1995).
//
// The IXFR tests carry most of the weight here, because RFC 1995 lets a server
// answer the same query three structurally different ways and signals which
// one it chose nowhere in the header — the client has to work it out from the
// record stream. Misreading a full-zone fallback as a delta produces a zone
// that is silently, arbitrarily wrong rather than an error.

// --- mock primary -----------------------------------------------------------

// mockPrimary serves a scripted response stream, optionally TSIG-signed.
type mockPrimary struct {
	t        *testing.T
	ln       net.Listener
	answers  []dns.ResourceRecord
	tsigKey  dns.TSIGKey
	useTSIG  bool
	gotQuery chan *dns.Message
}

func startMockPrimary(t *testing.T, answers []dns.ResourceRecord, key dns.TSIGKey, useTSIG bool) *mockPrimary {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &mockPrimary{
		t: t, ln: ln, answers: answers, tsigKey: key, useTSIG: useTSIG,
		gotQuery: make(chan *dns.Message, 1),
	}
	go p.serve()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *mockPrimary) addr() string { return p.ln.Addr().String() }

func (p *mockPrimary) serve() {
	conn, err := p.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return
	}
	queryWire := make([]byte, length)
	if _, err := io.ReadFull(conn, queryWire); err != nil {
		return
	}
	qmsg, err := dns.Unpack(queryWire)
	if err != nil {
		return
	}
	select {
	case p.gotQuery <- qmsg:
	default:
	}

	// A signed request carries the MAC the response must be bound to.
	var requestMAC []byte
	if p.useTSIG {
		rec, mac, verr := dns.TSIGVerify(queryWire, func(string) (dns.TSIGKey, bool) {
			return p.tsigKey, true
		}, nil, time.Now())
		if verr != nil || rec == nil {
			return
		}
		requestMAC = mac
	}

	resp := &dns.Message{
		Header: dns.Header{
			ID:      qmsg.Header.ID,
			Flags:   dns.NewFlagBuilder().SetQR(true).SetAA(true).Build(),
			QDCount: 1,
		},
		Questions: qmsg.Questions,
		Answers:   p.answers,
	}
	wire, err := dns.Pack(resp, make([]byte, 8192))
	if err != nil {
		return
	}
	out := make([]byte, len(wire))
	copy(out, wire)

	if p.useTSIG {
		out, _, err = dns.TSIGSign(out, p.tsigKey, time.Now(), dns.DefaultTSIGFudge, requestMAC)
		if err != nil {
			return
		}
	}

	_ = binary.Write(conn, binary.BigEndian, uint16(len(out)))
	_, _ = conn.Write(out)
}

func testSOA(t *testing.T, zone string, serial uint32) dns.ResourceRecord {
	t.Helper()
	return dns.ResourceRecord{
		Name:  zone,
		Type:  dns.TypeSOA,
		Class: dns.ClassIN,
		TTL:   3600,
		RData: buildSOARDATA("ns1."+zone, "admin."+zone, serial, 3600, 900, 604800, 86400),
	}
}

func testA(zone string, last byte) dns.ResourceRecord {
	return dns.ResourceRecord{
		Name: zone, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300,
		RData: []byte{192, 0, 2, last}, RDLength: 4,
	}
}

func xfrTestKey() dns.TSIGKey {
	return dns.TSIGKey{
		Name:      "transfer-key.example",
		Algorithm: dns.TSIGHMACSHA256,
		Secret:    []byte("shared secret for zone transfer"),
	}
}

// --- TSIG -------------------------------------------------------------------

// TestRFC8945_SignedAXFR pins the end-to-end signed transfer: the client signs
// its request, the primary verifies it, and the client verifies the response
// against the request MAC.
func TestRFC8945_SignedAXFR(t *testing.T) {
	const zone = "example.com"
	key := xfrTestKey()
	soa := testSOA(t, zone, 2026080701)
	p := startMockPrimary(t, []dns.ResourceRecord{soa, testA(zone, 1), soa}, key, true)

	records, err := AXFR(context.Background(), ClientConfig{
		PrimaryAddr: p.addr(),
		Zone:        zone,
		Timeout:     5 * time.Second,
		TSIGKey:     key,
	})
	if err != nil {
		t.Fatalf("signed AXFR: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (SOA + A, closing SOA trimmed)", len(records))
	}

	// The primary must have received a signed query, or it was not
	// authenticating us at all.
	select {
	case q := <-p.gotQuery:
		if len(q.Additional) == 0 {
			t.Fatal("query reached the primary with no additional section — unsigned")
		}
		var sawTSIG bool
		for _, rr := range q.Additional {
			if rr.Type == dns.TypeTSIG {
				sawTSIG = true
			}
		}
		if !sawTSIG {
			t.Error("query carried no TSIG record")
		}
	case <-time.After(time.Second):
		t.Fatal("primary never received the query")
	}
}

// TestRFC8945_WrongKeyRejectsTransfer pins that a mis-keyed response is
// refused rather than accepted as zone data. This is the failure that matters:
// the transport may be plaintext TCP, so without TSIG verification an on-path
// attacker could substitute an entire zone.
func TestRFC8945_WrongKeyRejectsTransfer(t *testing.T) {
	const zone = "example.com"
	serverKey := xfrTestKey()
	soa := testSOA(t, zone, 2026080701)
	p := startMockPrimary(t, []dns.ResourceRecord{soa, testA(zone, 1), soa}, serverKey, true)

	clientKey := serverKey
	clientKey.Secret = []byte("a completely different secret")

	_, err := AXFR(context.Background(), ClientConfig{
		PrimaryAddr: p.addr(),
		Zone:        zone,
		Timeout:     5 * time.Second,
		TSIGKey:     clientKey,
	})
	if err == nil {
		t.Fatal("transfer succeeded despite a TSIG key mismatch — zone data from " +
			"an unauthenticated source would have been accepted")
	}
}

// TestRFC8945_UnsignedResponseRejectedWhenTSIGExpected pins that configuring a
// key means requiring one. A primary that answers unsigned must not be
// silently accepted, or enabling TSIG would be decorative.
func TestRFC8945_UnsignedResponseRejectedWhenTSIGExpected(t *testing.T) {
	const zone = "example.com"
	key := xfrTestKey()
	soa := testSOA(t, zone, 2026080701)
	// useTSIG=false: the primary ignores the signature and answers unsigned.
	p := startMockPrimary(t, []dns.ResourceRecord{soa, testA(zone, 1), soa}, key, false)

	_, err := AXFR(context.Background(), ClientConfig{
		PrimaryAddr: p.addr(),
		Zone:        zone,
		Timeout:     5 * time.Second,
		TSIGKey:     key,
	})
	if err == nil {
		t.Fatal("unsigned response accepted while a TSIG key was configured")
	}
	if !errors.Is(err, dns.ErrTSIGNotSigned) {
		t.Errorf("error = %v, want ErrTSIGNotSigned", err)
	}
}

// --- IXFR -------------------------------------------------------------------

// TestRFC1995_IncrementalTransfer pins the delta shape of §2: SOA(new), then
// per version step an SOA naming the serial being moved from with the deleted
// records, an SOA naming the serial being moved to with the added records, and
// finally SOA(new) again.
func TestRFC1995_IncrementalTransfer(t *testing.T) {
	const zone = "example.com"
	stream := []dns.ResourceRecord{
		testSOA(t, zone, 3), // final serial
		testSOA(t, zone, 1), // step 1: from serial 1
		testA(zone, 10),     // ...delete
		testSOA(t, zone, 2), // ...to serial 2
		testA(zone, 20),     // ...add
		testSOA(t, zone, 2), // step 2: from serial 2
		testA(zone, 30),     // ...delete
		testSOA(t, zone, 3), // ...to serial 3
		testA(zone, 40),     // ...add
		testSOA(t, zone, 3), // closing SOA
	}
	p := startMockPrimary(t, stream, dns.TSIGKey{}, false)

	res, err := IXFR(context.Background(), ClientConfig{
		PrimaryAddr: p.addr(), Zone: zone, Timeout: 5 * time.Second,
	}, 1)
	if err != nil {
		t.Fatalf("IXFR: %v", err)
	}

	if !res.Incremental {
		t.Fatal("result not marked incremental")
	}
	if res.Serial != 3 {
		t.Errorf("serial = %d, want 3", res.Serial)
	}
	if len(res.Deltas) != 2 {
		t.Fatalf("got %d deltas, want 2", len(res.Deltas))
	}

	d0 := res.Deltas[0]
	if d0.FromSerial != 1 || d0.ToSerial != 2 {
		t.Errorf("delta 0 = %d->%d, want 1->2", d0.FromSerial, d0.ToSerial)
	}
	if len(d0.Deleted) != 1 || d0.Deleted[0].RData[3] != 10 {
		t.Errorf("delta 0 deletions = %+v, want the .10 record", d0.Deleted)
	}
	if len(d0.Added) != 1 || d0.Added[0].RData[3] != 20 {
		t.Errorf("delta 0 additions = %+v, want the .20 record", d0.Added)
	}

	d1 := res.Deltas[1]
	if d1.FromSerial != 2 || d1.ToSerial != 3 {
		t.Errorf("delta 1 = %d->%d, want 2->3", d1.FromSerial, d1.ToSerial)
	}
}

// TestRFC1995_UpToDate pins the single-SOA response of §2: the client's serial
// was already current and there is nothing to apply.
func TestRFC1995_UpToDate(t *testing.T) {
	const zone = "example.com"
	p := startMockPrimary(t, []dns.ResourceRecord{testSOA(t, zone, 7)}, dns.TSIGKey{}, false)

	res, err := IXFR(context.Background(), ClientConfig{
		PrimaryAddr: p.addr(), Zone: zone, Timeout: 5 * time.Second,
	}, 7)
	if err != nil {
		t.Fatalf("IXFR: %v", err)
	}
	if !res.UpToDate {
		t.Error("single-SOA response not recognised as up-to-date")
	}
	if len(res.Deltas) != 0 || len(res.Records) != 0 {
		t.Error("up-to-date response yielded records to apply")
	}
	if res.Serial != 7 {
		t.Errorf("serial = %d, want 7", res.Serial)
	}
}

// TestRFC1995_FallbackToFullZone pins the case most likely to be got wrong.
// A server with no history far enough back answers an IXFR query with an
// ordinary AXFR-shaped response (§2), and says so nowhere in the header. A
// client that assumed its IXFR query produced deltas would parse the zone's
// own records as a version step and end up with an arbitrary subset.
func TestRFC1995_FallbackToFullZone(t *testing.T) {
	const zone = "example.com"
	soa := testSOA(t, zone, 9)
	stream := []dns.ResourceRecord{
		soa,
		testA(zone, 1),
		testA(zone, 2),
		soa,
	}
	p := startMockPrimary(t, stream, dns.TSIGKey{}, false)

	res, err := IXFR(context.Background(), ClientConfig{
		PrimaryAddr: p.addr(), Zone: zone, Timeout: 5 * time.Second,
	}, 1)
	if err != nil {
		t.Fatalf("IXFR: %v", err)
	}

	if res.Incremental {
		t.Fatal("a full-zone fallback was parsed as an incremental transfer — " +
			"the resulting zone would be silently wrong, not an error")
	}
	if res.UpToDate {
		t.Error("full-zone fallback misreported as up-to-date")
	}
	if len(res.Records) != 3 { // opening SOA + 2 A records; closing SOA trimmed
		t.Fatalf("got %d records, want 3", len(res.Records))
	}
	if res.Serial != 9 {
		t.Errorf("serial = %d, want 9", res.Serial)
	}
}

// TestXFR_TransactionIDChecked pins that a response bearing the wrong
// transaction ID is refused. On plaintext TCP this is a real (if awkward)
// injection vector, and the previous client sent ID 0 and checked nothing.
func TestXFR_TransactionIDChecked(t *testing.T) {
	const zone = "example.com"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		var length uint16
		if binary.Read(conn, binary.BigEndian, &length) != nil {
			return
		}
		qwire := make([]byte, length)
		if _, rerr := io.ReadFull(conn, qwire); rerr != nil {
			return
		}
		qmsg, uerr := dns.Unpack(qwire)
		if uerr != nil {
			return
		}
		resp := &dns.Message{
			Header:    dns.Header{ID: qmsg.Header.ID ^ 0xFFFF, Flags: dns.NewFlagBuilder().SetQR(true).Build(), QDCount: 1},
			Questions: qmsg.Questions,
			Answers:   []dns.ResourceRecord{testSOA(t, zone, 1)},
		}
		wire, perr := dns.Pack(resp, make([]byte, 512))
		if perr != nil {
			return
		}
		_ = binary.Write(conn, binary.BigEndian, uint16(len(wire)))
		_, _ = conn.Write(wire)
	}()

	_, err = AXFR(context.Background(), ClientConfig{
		PrimaryAddr: ln.Addr().String(), Zone: zone, Timeout: 2 * time.Second,
	})
	if !errors.Is(err, ErrTXIDMismatch) {
		t.Fatalf("error = %v, want ErrTXIDMismatch", err)
	}
}

// TestXFR_MetadataNotTreatedAsZoneData pins that only the answer section
// contributes records. The previous client folded in the authority and
// additional sections too, which meant the transfer's own OPT and TSIG records
// were inserted into the zone it was loading.
func TestXFR_MetadataNotTreatedAsZoneData(t *testing.T) {
	const zone = "example.com"
	key := xfrTestKey()
	soa := testSOA(t, zone, 1)
	p := startMockPrimary(t, []dns.ResourceRecord{soa, testA(zone, 1), soa}, key, true)

	records, err := AXFR(context.Background(), ClientConfig{
		PrimaryAddr: p.addr(), Zone: zone, Timeout: 5 * time.Second, TSIGKey: key,
	})
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	for _, rr := range records {
		if rr.Type == dns.TypeTSIG || rr.Type == dns.TypeOPT {
			t.Errorf("message metadata (type %s) was collected as zone data",
				dns.TypeName(rr.Type))
		}
	}
}
