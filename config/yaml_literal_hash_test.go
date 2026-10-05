package config

import "testing"

func TestParseYAML_LiteralHashes(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{`'/tmp/fallback#daily.jsonl' # comment`, "/tmp/fallback#daily.jsonl"},
		{`"/tmp/fallback#daily.jsonl" # comment`, "/tmp/fallback#daily.jsonl"},
		{`https://example.test/list#daily # comment`, "https://example.test/list#daily"},
		{`/tmp/o'brien.jsonl # comment`, "/tmp/o'brien.jsonl"},
		{`"/tmp/escaped\"#daily.jsonl" # comment`, `/tmp/escaped\"#daily.jsonl`},
		{`'/tmp/it''s#daily.jsonl' # comment`, "/tmp/it''s#daily.jsonl"},
		{`'/tmp/control.jsonl' # comment`, "/tmp/control.jsonl"},
	} {
		values, err := parseYAML([]byte("logging:\n  fallback_log: " + tc.value + "\n"))
		if err != nil || values["logging.fallback_log"] != tc.want {
			t.Errorf("value %q: got %q, err %v; want %q", tc.value, values["logging.fallback_log"], err, tc.want)
		}
	}
	values, err := parseYAML([]byte("sources:\n  - 'https://example.test/a#one' # comment\n  - \"https://example.test/b#two\"\n"))
	if err != nil || values["sources"] != "https://example.test/a#one,https://example.test/b#two" {
		t.Errorf("array literal hashes: %v, err %v", values, err)
	}
}
