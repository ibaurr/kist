package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type fakePrompter struct{ answers []string }

func (f *fakePrompter) Secret(string) ([]byte, error) {
	if len(f.answers) == 0 {
		return nil, errors.New("no more answers")
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return []byte(a), nil
}

func TestReadStdinStripsOneNewline(t *testing.T) {
	cases := map[string]string{
		"value\n":     "value",
		"value\r\n":   "value",
		"value":       "value",
		"value\n\n":   "value\n",
		"":            "",
		"multi\nline": "multi\nline",
	}
	for in, want := range cases {
		got, err := ReadStdin(strings.NewReader(in))
		if err != nil || string(got) != want {
			t.Errorf("%q -> %q, %v (want %q)", in, got, err, want)
		}
	}
}

func TestReadStdinBounded(t *testing.T) {
	if _, err := ReadStdin(bytes.NewReader(make([]byte, MaxStdin+1))); err == nil {
		t.Fatal("oversized input accepted")
	}
	if _, err := ReadStdin(bytes.NewReader(make([]byte, MaxStdin))); err != nil {
		t.Fatalf("input at the limit rejected: %v", err)
	}
}

func TestNewPassphrase(t *testing.T) {
	if got, err := NewPassphrase(&fakePrompter{[]string{"pw", "pw"}}); err != nil || got != "pw" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := NewPassphrase(&fakePrompter{[]string{"a", "b"}}); err == nil {
		t.Fatal("mismatch accepted")
	}
	if _, err := NewPassphrase(&fakePrompter{[]string{"", ""}}); err == nil {
		t.Fatal("empty accepted")
	}
	if _, err := NewPassphrase(&fakePrompter{[]string{"only one"}}); err == nil {
		t.Fatal("missing confirmation accepted")
	}
}
