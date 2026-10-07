package blocklist

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseHostsFile_AllAliases(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"0.0.0.0 first.example second.example\n", []string{"first.example", "second.example"}},
		{"127.0.0.1 localhost ALIAS.Example other.example # ignored.example\n", []string{"alias.example", "other.example"}},
		{"0.0.0.0 single.example\n", []string{"single.example"}},
		{"192.0.2.1 first.example second.example\n", nil},
		{"# comment\n\n", nil},
	}
	for _, tc := range cases {
		if got := ParseHostsFile(strings.NewReader(tc.input)); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseHostsFile(%q)=%v, want %v", tc.input, got, tc.want)
		}
	}
}
