// Package envfile parses and formats a strict dialect of .env files for
// `kist import` and `kist export`.
//
// The dialect (see DESIGN.md):
//
//	# comment and blank lines are ignored
//	NAME=value                unquoted: trimmed, taken literally, " #" is an error
//	export NAME=value         optional "export " prefix
//	NAME='literal'            single quotes: no escapes, may span lines
//	NAME="esc\n\"aped"        double quotes: \n \r \t \" \\ only, may span lines
//
// Strictness is the point: anything ambiguous is an error instead of a guess,
// because a guess would silently store the wrong secret. Error messages carry
// line numbers and fixed text only, never file contents, since the input is
// secret material.
package envfile

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ibaurr/kist/internal/vault"
)

// MaxSize bounds the input accepted by Parse.
const MaxSize = 1 << 20

// Entry is one NAME=VALUE pair.
type Entry struct{ Name, Value string }

// ParseError reports a problem on a 1-based line without quoting the input.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	if e.Line == 0 {
		return e.Msg
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

// Parse reads a whole .env document. Entries are returned in file order.
// CRLF line endings are normalised to LF before parsing.
func Parse(data []byte) ([]Entry, error) {
	switch {
	case len(data) > MaxSize:
		return nil, &ParseError{Msg: "file is larger than 1 MiB"}
	case !utf8.Valid(data):
		return nil, &ParseError{Msg: "file is not valid UTF-8"}
	case strings.IndexByte(string(data), 0) >= 0:
		return nil, &ParseError{Msg: "file contains NUL"}
	}
	p := &parser{s: strings.ReplaceAll(string(data), "\r\n", "\n"), line: 1}
	return p.parse()
}

type parser struct {
	s    string
	i    int
	line int
}

func (p *parser) fail(line int, msg string) error { return &ParseError{Line: line, Msg: msg} }

func (p *parser) parse() ([]Entry, error) {
	var out []Entry
	seen := map[string]int{}
	for {
		p.skipBlank()
		if p.i >= len(p.s) {
			return out, nil
		}
		if p.s[p.i] == '#' {
			p.skipLine()
			continue
		}
		startLine := p.line
		e, err := p.entry()
		if err != nil {
			return nil, err
		}
		if first, dup := seen[e.Name]; dup {
			return nil, p.fail(startLine, fmt.Sprintf("duplicate name %s (first defined on line %d)", e.Name, first))
		}
		seen[e.Name] = startLine
		out = append(out, e)
	}
}

// skipBlank advances over spaces, tabs and empty lines.
func (p *parser) skipBlank() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t':
		case '\n':
			p.line++
		default:
			return
		}
		p.i++
	}
}

func (p *parser) skipLine() {
	for p.i < len(p.s) && p.s[p.i] != '\n' {
		p.i++
	}
}

func (p *parser) skipSpaces() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *parser) entry() (Entry, error) {
	line := p.line
	if rest := p.s[p.i:]; strings.HasPrefix(rest, "export") && len(rest) > 6 && (rest[6] == ' ' || rest[6] == '\t') {
		p.i += 6
		p.skipSpaces()
	}
	j := p.i
	for j < len(p.s) && p.s[j] != '=' && p.s[j] != '\n' {
		j++
	}
	if j >= len(p.s) || p.s[j] != '=' {
		return Entry{}, p.fail(line, "expected NAME=VALUE")
	}
	name := p.s[p.i:j]
	// The name is not echoed: a malformed line may have a secret where the
	// name should be.
	if vault.ValidateName(name) != nil {
		return Entry{}, p.fail(line, "invalid name (must match [A-Za-z_][A-Za-z0-9_]*)")
	}
	p.i = j + 1

	var value string
	var err error
	switch q := p.peekAfterSpaces(); q {
	case '"':
		p.skipSpaces()
		value, err = p.doubleQuoted(line)
	case '\'':
		p.skipSpaces()
		value, err = p.singleQuoted(line)
	default:
		value, err = p.unquoted(line)
	}
	if err != nil {
		return Entry{}, err
	}
	return Entry{Name: name, Value: value}, nil
}

func (p *parser) peekAfterSpaces() byte {
	j := p.i
	for j < len(p.s) && (p.s[j] == ' ' || p.s[j] == '\t') {
		j++
	}
	if j < len(p.s) {
		return p.s[j]
	}
	return 0
}

func (p *parser) unquoted(line int) (string, error) {
	start := p.i
	p.skipLine()
	raw := p.s[start:p.i]
	for k := 1; k < len(raw); k++ {
		if raw[k] == '#' && (raw[k-1] == ' ' || raw[k-1] == '\t') {
			return "", p.fail(line, "unquoted value contains ' #': quote the value if '#' is part of it, or remove the comment")
		}
	}
	return strings.Trim(raw, " \t\r"), nil
}

func (p *parser) singleQuoted(line int) (string, error) {
	p.i++ // opening quote
	end := strings.IndexByte(p.s[p.i:], '\'')
	if end < 0 {
		return "", p.fail(line, "unterminated single-quoted value")
	}
	v := p.s[p.i : p.i+end]
	p.line += strings.Count(v, "\n")
	p.i += end + 1
	return v, p.afterQuote()
}

func (p *parser) doubleQuoted(line int) (string, error) {
	p.i++ // opening quote
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch c {
		case '"':
			p.i++
			return b.String(), p.afterQuote()
		case '\\':
			if p.i+1 >= len(p.s) {
				return "", p.fail(line, "unterminated double-quoted value")
			}
			esc, ok := map[byte]byte{'n': '\n', 'r': '\r', 't': '\t', '"': '"', '\\': '\\'}[p.s[p.i+1]]
			if !ok {
				return "", p.fail(p.line, `unknown escape in double-quoted value (allowed: \n \r \t \" \\)`)
			}
			b.WriteByte(esc)
			p.i += 2
		default:
			if c == '\n' {
				p.line++
			}
			b.WriteByte(c)
			p.i++
		}
	}
	return "", p.fail(line, "unterminated double-quoted value")
}

// afterQuote permits only spaces and an optional comment after a closing quote.
func (p *parser) afterQuote() error {
	p.skipSpaces()
	if p.i >= len(p.s) || p.s[p.i] == '\n' {
		return nil
	}
	if p.s[p.i] == '#' {
		p.skipLine()
		return nil
	}
	return p.fail(p.line, "unexpected text after closing quote")
}

// Format renders entries in the dialect Parse accepts, so that
// Parse(Format(e)) == e. Values must satisfy vault.ValidateValue (valid UTF-8,
// no NUL). Plain values are written bare; anything else is double-quoted with
// escapes so newlines, quotes and '#' survive.
func Format(entries []Entry) []byte {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Name)
		b.WriteByte('=')
		b.WriteString(formatValue(e.Value))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func formatValue(v string) string {
	if isPlain(v) {
		return v
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// isPlain reports whether v can be written without quotes and read back
// unchanged: a conservative allow-list, so whitespace, quotes, '#' and
// backslashes always force quoting.
func isPlain(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("_./:@%+,-=", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}
