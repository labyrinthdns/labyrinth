package secondary

import (
	"bytes"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/xfr"
)

func newApplyManager(t *testing.T) (*Manager, *zoneState) {
	t.Helper()
	m := NewManager(testResolver(t), nil, []ZoneConfig{{Name: "example.com"}}, nil, discardLogger())
	return m, m.zones["example.com"]
}
func servedSOASerial(t *testing.T, m *Manager) uint32 {
	t.Helper()
	got := m.res.LocalZones().Lookup("example.com", dns.TypeSOA, dns.ClassIN)
	if got == nil || len(got.Answers) != 1 {
		t.Fatalf("SOA lookup: %+v", got)
	}
	soa, err := dns.ParseSOA(got.Answers[0].RData, 0)
	if err != nil {
		t.Fatal(err)
	}
	return soa.Serial
}

func TestApplyIXFR_ServedSOASerial(t *testing.T) {
	cases := []struct {
		name     string
		from, to uint32
	}{
		{"ordinary", 1, 2}, {"zero_serial", ^uint32(0), 0}, {"wraparound", ^uint32(0), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, z := newApplyManager(t)
			initial := []dns.ResourceRecord{testSOA(t, "example.com", tc.from), rr("www.example.com", dns.TypeA, 192, 0, 2, 1)}
			originalSOA := append([]byte(nil), initial[0].RData...)
			m.applyFull(z, initial)
			held := m.res.LocalZones()
			// Hold the old published table until after the new version is applied.
			updated := make(chan struct{})
			oldSerial := make(chan uint32, 1)
			go func() {
				<-updated
				answer := held.Lookup("example.com", dns.TypeSOA, dns.ClassIN)
				soa, err := dns.ParseSOA(answer.Answers[0].RData, 0)
				if err != nil {
					oldSerial <- tc.to
					return
				}
				oldSerial <- soa.Serial
			}()
			m.applyIXFR(z, &xfr.Result{Incremental: true, Serial: tc.to, Deltas: []xfr.Delta{{FromSerial: tc.from, ToSerial: tc.to,
				Deleted: []dns.ResourceRecord{rr("www.example.com", dns.TypeA, 192, 0, 2, 1)},
				Added:   []dns.ResourceRecord{rr("www.example.com", dns.TypeA, 192, 0, 2, 2)},
			}}})
			close(updated)
			previous := <-oldSerial
			if got := servedSOASerial(t, m); got != tc.to || z.serial != tc.to {
				t.Fatalf("served=%d held=%d, want %d", got, z.serial, tc.to)
			}
			if previous != tc.from {
				t.Fatalf("old table changed serial: %d, want %d", previous, tc.from)
			}
			if !bytes.Equal(initial[0].RData, originalSOA) {
				t.Fatal("input SOA mutated")
			}
			got := m.res.LocalZones().Lookup("www.example.com", dns.TypeA, dns.ClassIN)
			if len(got.Answers) != 1 || got.Answers[0].RData[3] != 2 {
				t.Fatalf("A replacement: %+v", got)
			}
			// The change must preserve every SOA byte except the serial.
			soa := findSOA(z.records)
			serialOffset := len(originalSOA) - 20
			if !bytes.Equal(soa.RData[:serialOffset], originalSOA[:serialOffset]) || !bytes.Equal(soa.RData[serialOffset+4:], originalSOA[serialOffset+4:]) {
				t.Fatal("SOA names or timers changed")
			}
		})
	}
	t.Run("empty_delta_and_repeated_update", func(t *testing.T) {
		m, z := newApplyManager(t)
		m.applyFull(z, []dns.ResourceRecord{testSOA(t, "example.com", 1)})
		for serial := uint32(2); serial <= 3; serial++ {
			m.applyIXFR(z, &xfr.Result{Incremental: true, Serial: serial, Deltas: []xfr.Delta{{FromSerial: serial - 1, ToSerial: serial}}})
			if got := servedSOASerial(t, m); got != serial {
				t.Fatalf("served=%d, want %d", got, serial)
			}
		}
	})
	t.Run("full_fallback_and_up_to_date", func(t *testing.T) {
		m, z := newApplyManager(t)
		m.applyFull(z, []dns.ResourceRecord{testSOA(t, "example.com", 1)})
		m.applyIXFR(z, &xfr.Result{Serial: 2, Records: []dns.ResourceRecord{testSOA(t, "example.com", 2)}})
		m.applyIXFR(z, &xfr.Result{Serial: 2, UpToDate: true})
		if got := servedSOASerial(t, m); got != 2 {
			t.Fatalf("served=%d, want 2", got)
		}
	})
}

func TestApplyFull_ExpireReset(t *testing.T) {
	cases := []struct {
		name          string
		before, after uint32
		want          time.Duration
	}{
		{"short_to_zero", 7200, 0, defaultExpire},
		{"long_to_zero", 864000, 0, defaultExpire},
		{"zero_to_positive", 0, 7200, 2 * time.Hour},
		{"zero_to_zero", 0, 0, defaultExpire},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, z := newApplyManager(t)
			for i, expire := range []uint32{tc.before, tc.after} {
				soa := testSOA(t, "example.com", uint32(i+1))
				soa.RData = buildSOARDATA("ns1.example.com", "admin.example.com", uint32(i+1), 3600, 900, expire, 86400)
				m.applyFull(z, []dns.ResourceRecord{soa})
			}
			if z.expire != tc.want {
				t.Fatalf("expire=%v, want %v", z.expire, tc.want)
			}
			if got := servedSOASerial(t, m); got != 2 {
				t.Fatalf("served=%d, want 2", got)
			}
		})
	}
}
