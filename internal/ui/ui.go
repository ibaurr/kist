// Package ui holds the small amount of terminal handling kist needs: hidden
// prompts, TTY detection and bounded stdin reads. Secrets are never accepted
// on the command line; they come from here.
package ui

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/term"

	"github.com/ibaurr/kist/internal/crypto"
)

// MaxStdin bounds `--stdin` and similar reads.
const MaxStdin = 1 << 20

// Prompter reads one hidden line. It is an interface so tests can supply
// answers without a pseudo-terminal.
type Prompter interface {
	Secret(prompt string) ([]byte, error)
}

// Terminal prompts on the controlling terminal (/dev/tty), not on stdin, so
// that stdin stays free for `--stdin` and pipelines. The prompt text goes to
// stderr so stdout carries only data.
type Terminal struct{}

var ErrNoTerminal = errors.New("no terminal available for a hidden prompt")

func (Terminal) Secret(prompt string) ([]byte, error) {
	path := "/dev/tty"
	if runtime.GOOS == "windows" {
		path = "CONIN$"
	}
	tty, err := os.Open(path)
	if err != nil {
		return nil, ErrNoTerminal
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read from terminal: %w", err)
	}
	return b, nil
}

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// ReadStdin reads all of r (at most MaxStdin bytes) and strips exactly one
// trailing newline, so `echo value | kist set X --stdin` stores "value". Use
// printf '%s' to control the exact bytes.
func ReadStdin(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxStdin+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxStdin {
		crypto.Wipe(b)
		return nil, errors.New("input larger than 1 MiB")
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	return b, nil
}

// NewPassphrase asks twice and returns the passphrase. It rejects an empty
// passphrase and a mismatch. No other strength policy is enforced; that choice
// is documented in DESIGN.md.
func NewPassphrase(p Prompter) (string, error) {
	first, err := p.Secret("New passphrase: ")
	if err != nil {
		return "", err
	}
	defer crypto.Wipe(first)
	if len(first) == 0 {
		return "", errors.New("passphrase must not be empty")
	}
	second, err := p.Secret("Repeat passphrase: ")
	if err != nil {
		return "", err
	}
	defer crypto.Wipe(second)
	if !bytes.Equal(first, second) {
		return "", errors.New("passphrases do not match")
	}
	return string(first), nil
}
