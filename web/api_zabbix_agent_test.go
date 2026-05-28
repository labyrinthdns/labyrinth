package web

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestZabbixAgent_UnknownKey_NoReflection pins the same anti-
// reflection contract on the raw ZBXD TCP listener as the HTTP
// variant carries (v0.7.47). The Zabbix agent listener has no
// authentication and is typically reachable from anywhere on the
// operator's internal network — echoing attacker-supplied bytes
// back into the ZBX_NOTSUPPORTED reason (which Zabbix server logs
// verbatim) is a real log-injection vector.
func TestZabbixAgent_UnknownKey_NoReflection(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 60, 10, m)

	done := make(chan struct{})
	go func() {
		handleZabbixConn(left, m, c, slog.Default())
		close(done)
	}()

	const sentinel = "canary-XYZ-sentinel"
	_ = right.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := right.Write([]byte(sentinel + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	body, err := io.ReadAll(right)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	<-done

	// Strip ZBXD\x01 + 8-byte length prefix.
	if len(body) < 13 || string(body[:5]) != "ZBXD\x01" {
		t.Fatalf("missing/short ZBXD header: %q", body)
	}
	payload := body[13:]
	if bytes.Contains(payload, []byte(sentinel)) {
		t.Errorf("response payload reflected the user-supplied key %q:\n%q",
			sentinel, payload)
	}
	if !strings.Contains(string(payload), "ZBX_NOTSUPPORTED") {
		t.Errorf("expected ZBX_NOTSUPPORTED in payload, got %q", payload)
	}
}

// TestZabbixAgent_RejectsOverlongKey pins the length cap on the
// Zabbix agent. A key past `maxZabbixKeyLength` must be refused
// without any echo into the response (the handler emits an empty
// ZBXD payload). A regression that removed the cap would let an
// attacker reflect a multi-hundred-byte sentinel.
func TestZabbixAgent_RejectsOverlongKey(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()

	m := metrics.NewMetrics()
	c := cache.NewCache(100, 5, 60, 10, m)

	done := make(chan struct{})
	go func() {
		handleZabbixConn(left, m, c, slog.Default())
		close(done)
	}()

	const sentinel = "TOOMUCH-canary-XYZ"
	huge := sentinel + strings.Repeat("z", maxZabbixKeyLength)
	_ = right.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := right.Write([]byte(huge + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	body, err := io.ReadAll(right)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	<-done

	if bytes.Contains(body, []byte(sentinel)) {
		t.Errorf("over-cap key was reflected back in response:\n%q", body)
	}
}
