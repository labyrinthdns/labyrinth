package main

import (
	"testing"
	"time"
)

func TestBuildRunConfig_ExecutionBounds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		qps      int
		workers  int
		duration string
		wantErr  bool
	}{
		{"ordinary", 10, 1, "1s", false},
		{"minimum", 1, 1, "1ns", false},
		{"ticker resolution boundary", int(time.Second), 1, "1s", false},
		{"zero QPS", 0, 1, "1s", true},
		{"negative QPS", -1, 1, "1s", true},
		{"zero ticker interval", int(time.Second) + 1, 1, "1s", true},
		{"zero workers", 10, 0, "1s", true},
		{"negative workers", 10, -1, "1s", true},
		{"zero duration", 10, 1, "0s", true},
		{"negative duration", 10, 1, "-1s", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildRunConfig("127.0.0.1:53", tc.qps, tc.duration, tc.workers, "builtin", "A", "", "local")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
