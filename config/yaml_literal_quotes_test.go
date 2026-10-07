package config

import "testing"

func TestParseYAMLLiteralQuotes(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{`"/tmp/fallback'"`, "/tmp/fallback'"},
		{`'/tmp/fallback"'`, `/tmp/fallback"`},
		{`"'/tmp/fallback'"`, "'/tmp/fallback'"},
		{`'"/tmp/fallback"'`, `"/tmp/fallback"`},
		{`"/tmp/fallback'" # comment`, "/tmp/fallback'"},
		{`/tmp/fallback'`, "/tmp/fallback'"},
		{`"/tmp/fallback.jsonl"`, "/tmp/fallback.jsonl"},
		{`""`, ""},
		{`''`, ""},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got, err := parseYAML([]byte("logging:\n  fallback_log: " + tc.value + "\n"))
			if err != nil || got["logging.fallback_log"] != tc.want {
				t.Fatalf("scalar=%q err=%v, want %q", got["logging.fallback_log"], err, tc.want)
			}
			got, err = parseYAML([]byte("paths:\n  - " + tc.value + "\n"))
			if err != nil || got["paths"] != tc.want {
				t.Fatalf("list=%q err=%v, want %q", got["paths"], err, tc.want)
			}
		})
	}
}
