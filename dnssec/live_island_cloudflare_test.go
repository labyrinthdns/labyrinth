//go:build live

package dnssec

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

type udpRecurseQuerier struct{ addr string }

func (q udpRecurseQuerier) QueryDNSSEC(name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	msg, err := q.exchange(name, qtype, qclass, "udp")
	if err != nil {
		return nil, err
	}
	// Root DNSKEY and other large RRsets truncate over UDP; follow TC with TCP
	// so live trust-chain probes match production's iterative resolver.
	if msg.Header.TC() {
		return q.exchange(name, qtype, qclass, "tcp")
	}
	return msg, nil
}

func (q udpRecurseQuerier) exchange(name string, qtype uint16, qclass uint16, network string) (*dns.Message, error) {
	conn, err := net.DialTimeout(network, q.addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	msg := &dns.Message{
		Header:    dns.Header{ID: 0x4242, Flags: dns.NewFlagBuilder().SetRD(true).Build(), QDCount: 1},
		Questions: []dns.Question{{Name: name, Type: qtype, Class: qclass}},
		Additional: []dns.ResourceRecord{{
			Name: ".", Type: dns.TypeOPT, Class: 1232, TTL: 1 << 15,
		}},
	}
	raw, err := dns.Pack(msg, make([]byte, 4096))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if network == "tcp" {
		var hdr [2]byte
		hdr[0] = byte(len(raw) >> 8)
		hdr[1] = byte(len(raw))
		if _, err := conn.Write(hdr[:]); err != nil {
			return nil, err
		}
	}
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	var payload []byte
	if network == "tcp" {
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, err
		}
		n := int(hdr[0])<<8 | int(hdr[1])
		if n > len(buf) {
			return nil, fmt.Errorf("tcp response too large: %d", n)
		}
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return nil, err
		}
		payload = buf[:n]
	} else {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		payload = buf[:n]
	}
	return dns.Unpack(payload)
}

func fetchAuth(name string, qtype uint16) (*dns.Message, error) {
	// Ask 1.1.1.1 for the answer with DO — then validate locally with our querier
	return udpRecurseQuerier{addr: "1.1.1.1:53"}.QueryDNSSEC(name, qtype, dns.ClassIN)
}

func TestLive_CloudflareIsland_Turkmmo_NotBogus(t *testing.T) {
	if testing.Short() {
		t.Skip("live")
	}
	resp, err := fetchAuth("www.turkmmo.com", dns.TypeA)
	if err != nil {
		t.Skip(err)
	}
	v := NewValidator(udpRecurseQuerier{addr: "1.1.1.1:53"}, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	verdict, reason := v.ValidateResponseWithReason(resp, "www.turkmmo.com", dns.TypeA)
	t.Logf("verdict=%v reason=%v answers=%d", verdict, reason, len(resp.Answers))
	if verdict == Bogus {
		t.Fatalf("island Cloudflare zone marked Bogus — want Insecure")
	}
}

func TestLive_CloudflareIsland_Pulse_NotBogus(t *testing.T) {
	if testing.Short() {
		t.Skip("live")
	}
	resp, err := fetchAuth("pulse.yesilbeyazhosting.com", dns.TypeA)
	if err != nil {
		t.Skip(err)
	}
	v := NewValidator(udpRecurseQuerier{addr: "1.1.1.1:53"}, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	verdict, reason := v.ValidateResponseWithReason(resp, "pulse.yesilbeyazhosting.com", dns.TypeA)
	t.Logf("verdict=%v reason=%v", verdict, reason)
	if verdict == Bogus {
		t.Fatalf("island marked Bogus — want Insecure")
	}
}

// TestLive_UnrelatedSigner_Telefonica_NotBogus: telefonica.com has no DS in
// com, and its servers sign the A RRset as cloudflare.net.
func TestLive_UnrelatedSigner_Telefonica_NotBogus(t *testing.T) {
	if testing.Short() {
		t.Skip("live")
	}
	addrs, err := net.LookupHost("dns1.movistar.es")
	if err != nil || len(addrs) == 0 {
		t.Skip(err)
	}
	resp, err := udpRecurseQuerier{addr: net.JoinHostPort(addrs[0], "53")}.QueryDNSSEC("telefonica.com", dns.TypeA, dns.ClassIN)
	if err != nil {
		t.Skip(err)
	}
	unrelated := false
	for _, rr := range resp.Answers {
		if rr.Type != dns.TypeRRSIG {
			continue
		}
		if sig, err := dns.ParseRRSIG(rr.RData, 0); err == nil && !isInBailiwick("telefonica.com.", normalizeName(sig.SignerName)) {
			unrelated = true
		}
	}
	if !unrelated {
		t.Skip("answer no longer carries an unrelated signer")
	}
	v := NewValidator(udpRecurseQuerier{addr: "1.1.1.1:53"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	verdict, reason := v.ValidateResponseWithReason(resp, "telefonica.com", dns.TypeA)
	t.Logf("verdict=%v reason=%v", verdict, reason)
	if verdict != Insecure {
		t.Fatalf("verdict=%v, want Insecure", verdict)
	}
}
