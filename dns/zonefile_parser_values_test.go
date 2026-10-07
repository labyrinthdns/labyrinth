package dns

import (
	"bytes"
	"fmt"
	"testing"
)

func TestParseZone_TXTLiterals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  []string
	}{
		{"control", `"plain text"`, []string{"plain text"}},
		{"semicolon", `"route; note"`, []string{"route; note"}},
		{"spaces", `"two  spaces"`, []string{"two  spaces"}},
		{"tab", "\"a\tb\"", []string{"a\tb"}},
		{"empty", `""`, []string{""}},
		{"comment", `"kept; text" ; ignored "other"`, []string{"kept; text"}},
		{"escaped quote", `"a\";  b"`, []string{"a\";  b"}},
		{"escaped backslash", `"a\\; b"`, []string{`a\; b`}},
		{"multiple", `"first;  part"  "second  part"`, []string{"first;  part", "second  part"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "@ IN SOA ns.example. hostmaster.example. 1 2 3 4 5\n" + "txt\tIN\tTXT\t" + tc.input + "\n"
			records, err := ParseZone("example.", []byte(text))
			if err != nil || len(records) != 2 {
				t.Fatalf("ParseZone: count=%d err=%v", len(records), err)
			}
			var want []byte
			for _, part := range tc.want {
				want = append(want, byte(len(part)))
				want = append(want, part...)
			}
			if got := records[1].RData; !bytes.Equal(got, want) {
				t.Errorf("TXT RDATA = %x, want %x", got, want)
			}
		})
	}
}

func TestParseZone_ZeroTTL(t *testing.T) {
	for _, directive := range []string{"$TTL 300\n", ""} {
		t.Run(fmt.Sprintf("directive=%q", directive), func(t *testing.T) {
			text := directive + "@ IN SOA ns.example. hostmaster.example. 1 2 3 4 5\n" +
				"zero 0 IN A 192.0.2.1\n" +
				"inherited IN A 192.0.2.2\n" +
				"positive 600 IN A 192.0.2.3\n" +
				"positive-inherited IN A 192.0.2.4\n"
			records, err := ParseZone("example.", []byte(text))
			if err != nil || len(records) != 5 {
				t.Fatalf("ParseZone: count=%d err=%v", len(records), err)
			}
			defaultTTL := uint32(86400)
			if directive != "" {
				defaultTTL = 300
			}
			for i, want := range []uint32{defaultTTL, 0, 0, 600, 600} {
				if got := records[i].TTL; got != want {
					t.Errorf("record %q TTL = %d, want %d", records[i].Name, got, want)
				}
			}
		})
	}
}
