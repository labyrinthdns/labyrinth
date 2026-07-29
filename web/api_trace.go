package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// MaxConcurrentDiagnosticTraces bounds the process work created by diagnostic
// WebSockets. Production DNS traffic remains independent; only the explicitly
// requested, event-heavy diagnostic traces consume these slots.
const MaxConcurrentDiagnosticTraces = 8

type diagnosticTraceLimiter struct {
	slots chan struct{}
}

func newDiagnosticTraceLimiter(limit int) *diagnosticTraceLimiter {
	if limit < 1 {
		limit = 1
	}
	return &diagnosticTraceLimiter{slots: make(chan struct{}, limit)}
}

func (l *diagnosticTraceLimiter) tryAcquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *diagnosticTraceLimiter) release() {
	<-l.slots
}

var globalDiagnosticTraceLimiter = newDiagnosticTraceLimiter(MaxConcurrentDiagnosticTraces)

type diagnosticTraceRun struct {
	generation uint64
	cancel     context.CancelFunc
	done       chan struct{}
}

type diagnosticTraceSession struct {
	mu             sync.Mutex
	nextGeneration uint64
	current        *diagnosticTraceRun
}

func (s *diagnosticTraceSession) start(cancel context.CancelFunc) *diagnosticTraceRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextGeneration++
	run := &diagnosticTraceRun{generation: s.nextGeneration, cancel: cancel, done: make(chan struct{})}
	s.current = run
	return run
}

func (s *diagnosticTraceSession) cancelAndWait() {
	s.mu.Lock()
	run := s.current
	if run != nil {
		run.cancel()
	}
	s.mu.Unlock()
	if run != nil {
		<-run.done
	}
}

func (s *diagnosticTraceSession) finish(run *diagnosticTraceRun) {
	// Publish completion before clearing current. A concurrent cancelAndWait
	// either observes this closed channel or sees nil after all cleanup is done;
	// there is no window where it mistakes a still-cleaning run for no run.
	close(run.done)
	s.mu.Lock()
	if s.current != nil && s.current.generation == run.generation {
		s.current = nil
	}
	s.mu.Unlock()
}

// traceClientMsg is what the UI may send to the WS to start / abort a trace.
type traceClientMsg struct {
	Action      string `json:"action"` // "start" or "cancel"
	Name        string `json:"name"`
	Type        string `json:"type"` // "A", "AAAA", "MX", ...
	BypassCache bool   `json:"bypass_cache"`
	SkipDNSSEC  bool   `json:"skip_dnssec"`
}

// traceServerMsg wraps each event sent to the UI. `kind` differentiates
// progress events from terminal payloads so the UI can render appropriately.
type traceServerMsg struct {
	Kind   string               `json:"kind"` // "event", "result", "error", "busy"
	Event  *resolver.TraceEvent `json:"event,omitempty"`
	Result *traceResultPayload  `json:"result,omitempty"`
	Error  string               `json:"error,omitempty"`
}

type traceResultPayload struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	RCode        string    `json:"rcode"`
	DNSSECStatus string    `json:"dnssec_status,omitempty"`
	Answers      []traceRR `json:"answers,omitempty"`
	Authority    []traceRR `json:"authority,omitempty"`
	ElapsedMs    int64     `json:"elapsed_ms"`
	Error        string    `json:"error,omitempty"`
}

type traceRR struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Class uint16 `json:"class"`
	Data  string `json:"data"`
}

// parseQType maps the UI's textual type into the numeric DNS type.
// Defaults to A on unknown input — the UI guards this but be lenient.
func parseQType(s string) (uint16, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "A":
		return dns.TypeA, true
	case "AAAA":
		return dns.TypeAAAA, true
	case "MX":
		return dns.TypeMX, true
	case "TXT":
		return dns.TypeTXT, true
	case "NS":
		return dns.TypeNS, true
	case "CNAME":
		return dns.TypeCNAME, true
	case "SOA":
		return dns.TypeSOA, true
	case "PTR":
		return dns.TypePTR, true
	case "SRV":
		return dns.TypeSRV, true
	case "DNSKEY":
		return dns.TypeDNSKEY, true
	case "DS":
		return dns.TypeDS, true
	}
	return 0, false
}

func qtypeString(qtype uint16) string {
	if s, ok := dns.TypeToString[qtype]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

func rcodeString(code uint8) string {
	if s, ok := dns.RCodeToString[code]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", code)
}

// validateTraceName guards against obviously bad input that could turn the
// diagnostic tool into a query-flood vector. Hard cap at 253 bytes (DNS limit)
// and reject anything that doesn't look name-shaped.
func validateTraceName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("name is required")
	}
	if len(name) > 253 {
		return errors.New("name longer than 253 bytes")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return errors.New("name contains invalid character")
		}
	}
	return nil
}

// formatRR renders an RR's RDATA into a human-readable string for the trace
// result payload. Falls back to a hex-ish placeholder for types we don't
// pretty-print here — the UI mostly cares about A/AAAA/CNAME.
func formatRR(rr dns.ResourceRecord) traceRR {
	out := traceRR{
		Name:  rr.Name,
		Type:  qtypeString(rr.Type),
		TTL:   rr.TTL,
		Class: rr.Class,
	}
	switch rr.Type {
	case dns.TypeA:
		if ip, err := dns.ParseA(rr.RData); err == nil {
			out.Data = ip.String()
		}
	case dns.TypeAAAA:
		if ip, err := dns.ParseAAAA(rr.RData); err == nil {
			out.Data = ip.String()
		}
	case dns.TypeCNAME:
		if t, err := dns.ParseCNAME(rr.RData, 0); err == nil {
			out.Data = t
		}
	case dns.TypeNS:
		if t, err := dns.ParseNS(rr.RData, 0); err == nil {
			out.Data = t
		}
	case dns.TypeTXT:
		if t, err := dns.ParseTXT(rr.RData); err == nil {
			out.Data = strings.Join(t, " ")
		}
	}
	if out.Data == "" {
		out.Data = fmt.Sprintf("(%d-byte RDATA)", len(rr.RData))
	}
	return out
}

// handleDiagnosticsTrace serves the diagnostic trace WebSocket.
//
// Protocol:
//
//	client → server: {action:"start"|"cancel", name, type, bypass_cache, skip_dnssec}
//	server → client: {kind:"event"|"result"|"error"|"busy", ...}
//
// Cancelling closes the trace cleanly without tearing down the socket — the
// UI can issue another "start" message immediately. The trace runs on a
// background goroutine so the handler keeps reading messages and can process
// "cancel" while the resolution is still in flight. WS frames are serialised
// through writeMu so the resolver goroutine and the handler can't interleave
// writes on the underlying TCP connection.
func (s *AdminServer) handleDiagnosticsTrace(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		s.logger.Error("diagnostics trace accept failed", "error", err)
		return
	}
	conn.SetReadLimit(MaxWebSocketMessageBytes)
	defer conn.Close(websocket.StatusNormalClosure, "closing")

	rootCtx := r.Context()
	limiter := globalDiagnosticTraceLimiter
	session := &diagnosticTraceSession{}
	writeMu := &sync.Mutex{}

	writeMsg := func(m traceServerMsg) {
		writeMu.Lock()
		defer writeMu.Unlock()
		writeTraceMsg(rootCtx, conn, m)
	}

	// Joining the canceled generation is what enforces one resolver trace per
	// WebSocket. A fixed grace period would permit overlap when an upstream is
	// slow to observe cancellation and would let an old defer clear new state.
	defer session.cancelAndWait()

	for {
		_, raw, readErr := conn.Read(rootCtx)
		if readErr != nil {
			return
		}
		var msg traceClientMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			writeMsg(traceServerMsg{Kind: "error", Error: "invalid client message"})
			continue
		}

		switch msg.Action {
		case "cancel":
			session.cancelAndWait()
			continue

		case "start":
			if err := validateTraceName(msg.Name); err != nil {
				writeMsg(traceServerMsg{Kind: "error", Error: err.Error()})
				continue
			}
			qtype, ok := parseQType(msg.Type)
			if !ok {
				writeMsg(traceServerMsg{Kind: "error", Error: "unsupported query type"})
				continue
			}
			if s.resolver == nil {
				writeMsg(traceServerMsg{Kind: "error", Error: "resolver not initialised"})
				continue
			}

			// Cancel and join the previous generation before acquiring a global
			// slot for the replacement. This preserves the per-WS single-flight
			// invariant even if the resolver needs time to unwind cancellation.
			session.cancelAndWait()
			if !limiter.tryAcquire() {
				writeMsg(traceServerMsg{Kind: "busy", Error: "too many diagnostic traces are running"})
				continue
			}

			traceCtx, cancel := context.WithTimeout(rootCtx, 60*time.Second)
			run := session.start(cancel)

			name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(msg.Name), "."))
			startMsg := msg
			startType := qtype

			// Run the trace off the read loop so a cancel frame can interrupt it.
			// Only this generation may clear itself, and every acquired global
			// slot is released by the same defer.
			go func() {
				defer func() {
					cancel()
					limiter.release()
					session.finish(run)
				}()
				runTraceLocked(traceCtx, conn, writeMu, s.resolver, name, startType, startMsg)
			}()

		default:
			writeMsg(traceServerMsg{Kind: "error", Error: "unknown action"})
		}
	}
}

// runTraceLocked bridges resolver.Trace events into the websocket and emits
// the terminal result message. All conn.Write calls are serialised under
// writeMu so the handler goroutine (writing "busy" / "error" replies to other
// client messages) can't interleave with this goroutine on the same socket.
// Returns when the trace ends or ctx is cancelled.
func runTraceLocked(
	ctx context.Context,
	conn *websocket.Conn,
	writeMu *sync.Mutex,
	r *resolver.Resolver,
	name string,
	qtype uint16,
	msg traceClientMsg,
) {
	write := func(m traceServerMsg) {
		writeMu.Lock()
		defer writeMu.Unlock()
		writeTraceMsg(ctx, conn, m)
	}

	events := make(chan resolver.TraceEvent)

	type resultPair struct {
		result *resolver.ResolveResult
		err    error
	}
	resCh := make(chan resultPair, 1)

	go func() {
		res, err := r.Trace(ctx, name, qtype, dns.ClassIN, resolver.TraceOptions{
			BypassCache: msg.BypassCache,
			SkipDNSSEC:  msg.SkipDNSSEC,
		}, events)
		resCh <- resultPair{result: res, err: err}
	}()

	start := time.Now()
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			localEv := ev
			write(traceServerMsg{Kind: "event", Event: &localEv})

		case res := <-resCh:
			// Drain remaining events if any survive close. If the close was
			// already observed above, events is nil and ranging it would block
			// forever, leaking the session and its global limiter slot.
			if events != nil {
				for ev := range events {
					localEv := ev
					write(traceServerMsg{Kind: "event", Event: &localEv})
				}
			}
			payload := buildResultPayload(name, qtype, res.result, res.err, time.Since(start).Milliseconds())
			write(traceServerMsg{Kind: "result", Result: &payload})
			return

		case <-ctx.Done():
			// Join the resolver call instead of abandoning it after a grace
			// period. Releasing the session/global slot before Trace returns would
			// make the limit cosmetic and allow a replacement generation to overlap
			// the canceled one. Resolver I/O is context-bound, so cancellation
			// drives this receive to completion.
			res := <-resCh
			payload := buildResultPayload(name, qtype, res.result, res.err, time.Since(start).Milliseconds())
			if payload.Error == "" {
				payload.Error = "cancelled"
			}
			write(traceServerMsg{Kind: "result", Result: &payload})
			return
		}
	}
}

func buildResultPayload(name string, qtype uint16, result *resolver.ResolveResult, err error, elapsedMs int64) traceResultPayload {
	payload := traceResultPayload{
		Name:      name,
		Type:      qtypeString(qtype),
		ElapsedMs: elapsedMs,
	}
	if err != nil {
		payload.Error = err.Error()
	}
	if result == nil {
		if payload.Error == "" {
			payload.Error = "no result"
		}
		payload.RCode = "SERVFAIL"
		return payload
	}
	payload.RCode = rcodeString(result.RCODE)
	payload.DNSSECStatus = result.DNSSECStatus
	for _, rr := range result.Answers {
		payload.Answers = append(payload.Answers, formatRR(rr))
	}
	for _, rr := range result.Authority {
		payload.Authority = append(payload.Authority, formatRR(rr))
	}
	return payload
}

func writeTraceMsg(ctx context.Context, conn *websocket.Conn, msg traceServerMsg) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = conn.Write(writeCtx, websocket.MessageText, data)
}
