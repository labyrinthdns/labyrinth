package resolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

const fallbackLogMaxBytes = 32 << 20 // 32 MiB then rotate to .1

// fallbackLogRecord is one JSONL line written whenever a query engages
// the public-resolver fallback path. Independent of logging.level so
// operators can debug SERVFAIL→fallback with logging: error.
type fallbackLogRecord struct {
	Time            string `json:"time"`
	Name            string `json:"name"`
	QType           uint16 `json:"qtype"`
	QTypeName       string `json:"qtype_name"`
	Reason          string `json:"reason"`
	DNSSECStatus    string `json:"dnssec_status,omitempty"`
	DNSSECReason    string `json:"dnssec_reason,omitempty"`
	FailureReason   string `json:"failure_reason,omitempty"`
	PrimaryRCODE    string `json:"primary_rcode,omitempty"`
	Recovered       bool   `json:"recovered"`
	FallbackAddr    string `json:"fallback_addr,omitempty"`
	FallbackRCODE   string `json:"fallback_rcode,omitempty"`
	FallbackError   string `json:"fallback_error,omitempty"`
	FallbackTried   int    `json:"fallback_tried"`
}

type fallbackFileLog struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

func newFallbackFileLog(path string) *fallbackFileLog {
	if path == "" {
		return nil
	}
	return &fallbackFileLog{path: path}
}

func (l *fallbackFileLog) write(rec fallbackLogRecord) {
	if l == nil {
		return
	}
	if rec.Time == "" {
		rec.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureOpenLocked(); err != nil {
		return
	}
	if st, err := l.f.Stat(); err == nil && st.Size()+int64(len(line)) > fallbackLogMaxBytes {
		_ = l.f.Close()
		l.f = nil
		if err := os.Rename(l.path, l.path+".1"); err != nil {
			return
		}
		if err := l.ensureOpenLocked(); err != nil {
			return
		}
	}
	_, _ = l.f.Write(line)
}

func (l *fallbackFileLog) ensureOpenLocked() error {
	if l.f != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	l.f = f
	return nil
}

func qtypeName(qtype uint16) string {
	if s, ok := dns.TypeToString[qtype]; ok {
		return s
	}
	return ""
}

func primaryFallbackFields(primary *ResolveResult) (status, reason, failReason, rcode string) {
	if primary == nil {
		return "", "", "", ""
	}
	return primary.DNSSECStatus, primary.DNSSECReason, primary.FailureReason, rcodeName(primary.RCODE)
}

// rcodeNameForEvent formats an event RCODE for JSONL. Unlike rcodeName, a
// zero value with a transport error is left empty so timeouts are not
// mislabeled as NOERROR.
func rcodeNameForEvent(rcode uint8, transportErr string) string {
	if transportErr != "" && rcode == 0 {
		return ""
	}
	return rcodeName(rcode)
}
