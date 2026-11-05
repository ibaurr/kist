package envfile

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ibaurr/kist/internal/vault"
)

func TestParseValid(t *testing.T) {
	cases := []struct {
		name, in string
		want     []Entry
	}{
		{"basic", "A=1\nB=two\n", []Entry{{"A", "1"}, {"B", "two"}}},
		{"no trailing newline", "A=1", []Entry{{"A", "1"}}},
		{"comments and blanks", "# c\n\n  # indented\nA=1\n\n", []Entry{{"A", "1"}}},
		{"export prefix", "export A=1\nexport\tB=2\n", []Entry{{"A", "1"}, {"B", "2"}}},
		{"export as a name", "export=1\n", []Entry{{"export", "1"}}},
		{"empty value", "A=\nB=''\nC=\"\"\n", []Entry{{"A", ""}, {"B", ""}, {"C", ""}}},
		{"unquoted trimmed", "A=  spaced value  \n", []Entry{{"A", "spaced value"}}},
		{"hash without space is literal", "A=pa#ss\nB=#start\n", []Entry{{"A", "pa#ss"}, {"B", "#start"}}},
		{"equals in value", "A=b=c==\n", []Entry{{"A", "b=c=="}}},
		{"single quoted literal", `A='a "b" \n $x'` + "\n", []Entry{{"A", `a "b" \n $x`}}},
		{"double quoted escapes", `A="a\nb\t\"q\"\\ \r"` + "\n", []Entry{{"A", "a\nb\t\"q\"\\ \r"}}},
		{"hash inside quotes", `A="x # y"` + "\nB='x # y'\n", []Entry{{"A", "x # y"}, {"B", "x # y"}}},
		{"comment after quote", `A="x" # why` + "\n", []Entry{{"A", "x"}}},
		{"multiline double", "A=\"l1\nl2\"\nB=1\n", []Entry{{"A", "l1\nl2"}, {"B", "1"}}},
		{"multiline single", "A='l1\nl2'\nB=1\n", []Entry{{"A", "l1\nl2"}, {"B", "1"}}},
		{"crlf", "A=1\r\nB=\"x\r\ny\"\r\n", []Entry{{"A", "1"}, {"B", "x\ny"}}},
		{"unicode", "A=pässwörd ✓\n", []Entry{{"A", "pässwörd ✓"}}},
		{"empty file", "", nil},
	}
	for _, c := range cases {
		got, err := Parse([]byte(c.in))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name, in string
		line     int
	}{
		{"no equals", "A=1\nJUSTAWORD\n", 2},
		{"bad name", "my-key=1\n", 1},
		{"name with space", "A B=1\n", 1},
		{"space before equals", "A =1\n", 1},
		{"empty name", "=1\n", 1},
		{"leading digit", "1A=1\n", 1},
		{"inline comment", "A=1\nB=val # note\n", 2},
		{"comment after space-equals", "A= #x\n", 1},
		{"duplicate", "A=1\nB=2\nA=3\n", 3},
		{"unterminated double", "A=1\nB=\"oops\nC=3\n", 2},
		{"unterminated single", "A='oops\n", 1},
		{"trailing backslash", "A=\"x\\", 1},
		{"unknown escape", `A="a\qb"` + "\n", 1},
		{"junk after quote", `A="x" y` + "\n", 1},
		{"junk after single", "A='x'y\n", 1},
		{"bare export", "export A\n", 1},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.in))
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Errorf("%s: want ParseError, got %v", c.name, err)
			continue
		}
		if pe.Line != c.line {
			t.Errorf("%s: line %d, want %d (%v)", c.name, pe.Line, c.line, err)
		}
	}
}

func TestParseRejectsBadFiles(t *testing.T) {
	for name, in := range map[string]string{
		"invalid utf8": "A=\xff\n",
		"NUL":          "A=a\x00b\n",
		"too large":    "A=" + strings.Repeat("x", MaxSize) + "\n",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Error messages must never quote the file: it is secret material.
func TestErrorsDoNotLeakContents(t *testing.T) {
	inputs := []string{
		"SECRETMARKER\n",
		"SECRET MARKER=1\n",
		"A=ok # SECRETMARKER\n",
		"A=\"SECRETMARKER\\q\"\n",
		"A=\"SECRETMARKER\" SECRETMARKER\n",
		"A='SECRETMARKER\n",
		"A=1\nA=SECRETMARKER\n",
		"my-SECRETMARKER=1\n",
	}
	for _, in := range inputs {
		_, err := Parse([]byte(in))
		if err == nil {
			t.Errorf("%q accepted", in)
			continue
		}
		if strings.Contains(err.Error(), "SECRETMARKER") {
			t.Errorf("error leaks input for %q: %v", in, err)
		}
	}
}

func TestFormat(t *testing.T) {
	got := string(Format([]Entry{
		{"PLAIN", "abc-1.2/x:y@z%+,="},
		{"EMPTY", ""},
		{"SPACE", "a b"},
		{"HASH", "#x"},
		{"NL", "l1\nl2"},
		{"QUOTE", `say "hi"`},
		{"BS", `a\b`},
		{"TAB_CR", "t\tc\r"},
	}))
	want := "PLAIN=abc-1.2/x:y@z%+,=\nEMPTY=\nSPACE=\"a b\"\nHASH=\"#x\"\nNL=\"l1\\nl2\"\n" +
		"QUOTE=\"say \\\"hi\\\"\"\nBS=\"a\\\\b\"\nTAB_CR=\"t\\tc\\r\"\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRoundTripTrickyValues(t *testing.T) {
	values := []string{
		"", " ", "  lead", "trail  ", "a b", "#", "x #y", "'", `"`, `\`, `\n`, "\\\n", `a"b'c`,
		"\n", "\r", "\r\n", "\t", "-----BEGIN KEY-----\nabc\n-----END KEY-----\n", "$HOME `cmd` $(x)",
		"é✓", "export A=1", "a=b", "=", "'quoted'", `"quoted"`, "# comment",
	}
	var in []Entry
	for i, v := range values {
		in = append(in, Entry{Name: "K" + strings.Repeat("_", i), Value: v})
	}
	out, err := Parse(Format(in))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		for i := range in {
			if i < len(out) && in[i] != out[i] {
				t.Errorf("value %q came back as %q", in[i].Value, out[i].Value)
			}
		}
		t.Fatal("round trip mismatch")
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"A=1\n", "export A='x'\n", "A=\"a\\nb\" # c\n", "A=\n\n#c\nB=x y\n", "A=b # c\n",
		"A='\n'\n", "A=\"\\", "\xff", "A=1\r\nB=2\r\n", "=", "A", "export", "A=\"\"\"",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := Parse(data)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("non-ParseError: %T", err)
			}
			return
		}
		// Whatever the parser accepts must survive format -> parse unchanged.
		again, err := Parse(Format(entries))
		if err != nil {
			t.Fatalf("formatted output rejected: %v", err)
		}
		if !reflect.DeepEqual(entries, again) && !(len(entries) == 0 && len(again) == 0) {
			t.Fatalf("round trip changed entries:\n%q\n%q", entries, again)
		}
	})
}

func FuzzRoundTrip(f *testing.F) {
	for _, v := range []string{"", "x", "a b", "\n", `"`, "\\", "#", "é"} {
		f.Add("NAME", v)
	}
	f.Fuzz(func(t *testing.T, name, value string) {
		// Format's contract: valid names and values (callers validate first).
		if vault.ValidateName(name) != nil || vault.ValidateValue(value) != nil {
			t.Skip()
		}
		in := []Entry{{Name: name, Value: value}}
		out, err := Parse(Format(in))
		if err != nil {
			t.Fatalf("formatted entry rejected: %v", err)
		}
		if len(out) != 1 || out[0] != in[0] {
			t.Fatalf("round trip: %q -> %q", in, out)
		}
	})
}
