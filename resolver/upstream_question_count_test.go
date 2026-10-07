package resolver

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func TestValidateResponseQuestionCount(t *testing.T) {
	question := dns.Question{Name: "example.test", Type: dns.TypeA, Class: dns.ClassIN}
	other := dns.Question{Name: "other.test", Type: dns.TypeAAAA, Class: dns.ClassIN}
	for _, tc := range []struct {
		name          string
		questions     []dns.Question
		query         dns.Question
		caseSensitive bool
		wantError     bool
	}{
		{name: "one", questions: []dns.Question{question}, query: question},
		{name: "none", query: question, wantError: true},
		{name: "duplicate", questions: []dns.Question{question, question}, query: question, wantError: true},
		{name: "extra different question", questions: []dns.Question{question, other}, query: question, wantError: true},
		{name: "three", questions: []dns.Question{question, question, question}, query: question, wantError: true},
		{name: "case insensitive", questions: []dns.Question{{Name: "EXAMPLE.TEST.", Type: dns.TypeA, Class: dns.ClassIN}}, query: question},
		{name: "case sensitive", questions: []dns.Question{question}, query: question, caseSensitive: true},
		{name: "case sensitive duplicate", questions: []dns.Question{question, question}, query: question, caseSensitive: true, wantError: true},
		{name: "case sensitive mismatch", questions: []dns.Question{{Name: "EXAMPLE.TEST", Type: dns.TypeA, Class: dns.ClassIN}}, query: question, caseSensitive: true, wantError: true},
		{name: "root", questions: []dns.Question{{Name: "", Type: dns.TypeNS, Class: dns.ClassIN}}, query: dns.Question{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN}},
		{name: "wrong type", questions: []dns.Question{{Name: "example.test", Type: dns.TypeAAAA, Class: dns.ClassIN}}, query: question, wantError: true},
		{name: "wrong class", questions: []dns.Question{{Name: "example.test", Type: dns.TypeA, Class: 0}}, query: question, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Exercise the decoded representation callers pass to the validator.
			packed, err := dns.Pack(&dns.Message{Questions: tc.questions}, make([]byte, 1024))
			if err != nil {
				t.Fatal(err)
			}
			msg, err := dns.Unpack(packed)
			if err != nil {
				t.Fatal(err)
			}
			err = validateResponseQuestionEx(msg, tc.query.Name, tc.query.Type, tc.query.Class, tc.caseSensitive)
			if (err != nil) != tc.wantError {
				t.Fatalf("validation error=%v, wantError=%v", err, tc.wantError)
			}
			if !tc.caseSensitive {
				err = validateResponseQuestion(msg, tc.query.Name, tc.query.Type, tc.query.Class)
				if (err != nil) != tc.wantError {
					t.Fatalf("forward validation error=%v, wantError=%v", err, tc.wantError)
				}
			}
		})
	}
}
