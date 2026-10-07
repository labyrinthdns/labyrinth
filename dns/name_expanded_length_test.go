package dns

import (
	"strings"
	"testing"
)

func TestEncodeNameExpandedLength(t *testing.T) {
	prefix := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "."
	for _, tc := range []struct {
		name string
		want error
	}{
		{"", nil}, {".", nil},
		{prefix + strings.Repeat("d", 60), nil},
		{prefix + strings.Repeat("d", 61), nil},
		{prefix + strings.Repeat("d", 61) + ".", nil},
		{prefix + strings.Repeat("d", 62), errNameTooLong},
		{prefix + strings.Repeat("d", 62) + ".", errNameTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Seed a compressible suffix: expanded length must still be checked.
			w := newWireWriter(make([]byte, 1024))
			suffix := strings.Repeat("d", 62)
			if err := EncodeName(w, suffix); err != nil {
				t.Fatal(err)
			}
			before := w.offset
			if err := EncodeName(w, tc.name); err != tc.want {
				t.Fatalf("EncodeName error=%v, want %v", err, tc.want)
			}
			if tc.want != nil && w.offset != before {
				t.Fatal("rejected name changed writer")
			}
			msg := &Message{Questions: []Question{{Name: tc.name, Type: TypeA, Class: ClassIN}}}
			if _, err := Pack(msg, make([]byte, 1024)); err != tc.want {
				t.Fatalf("Pack error=%v, want %v", err, tc.want)
			}
		})
	}
}
