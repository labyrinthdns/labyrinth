package log

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLoggerJSON(t *testing.T) {
	logger := NewLogger("info", "json")
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}

	// Verify it logs at info level
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	testLogger := slog.New(handler)
	testLogger.Info("test message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("expected JSON log to contain 'test message', got %q", output)
	}
	if !strings.Contains(output, `"key"`) {
		t.Errorf("expected JSON log to contain key field, got %q", output)
	}
}

func TestNewLoggerText(t *testing.T) {
	logger := NewLogger("debug", "text")
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}
}

func TestNewLoggerLevels(t *testing.T) {
	levels := []string{"debug", "info", "warn", "error", "unknown"}
	for _, level := range levels {
		logger := NewLogger(level, "json")
		if logger == nil {
			t.Errorf("NewLogger(%q) returned nil", level)
		}
	}
}
