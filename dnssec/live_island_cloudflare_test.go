//go:build live

package dnssec

import (
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

type udpRecurseQuerier struct{ addr string }

func (q udpRecurseQuerier) QueryDNSSEC(name string, qtype uint16, qclass uint16) (*dns.Message, error) {
	conn, err := net.DialTimeout("udp", q.addr, 3*time.Second)
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
	raw, err := dns.Pack(msg, nil)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return dns.Unpack(buf[:n])
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
