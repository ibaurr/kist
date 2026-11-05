// Package vault defines the plaintext vault document (version 1), its on-disk
// envelope (an age file with two recipients) and the atomic file handling
// around it.
//
// The plaintext is a small JSON document. Decoding is deliberately strict and
// every error it returns is built from offsets and fixed text only, never from
// the input, because the input is secret.
package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Version is the only plaintext format version this build understands.
const Version = 1

// Limits. They bound work on hostile or corrupt files and keep values usable
// as environment variables.
const (
	MaxNameLen    = 255
	MaxValueBytes = 64 << 10
)

// ErrUnsupportedVersion is returned for a vault written by a newer kist.
var ErrUnsupportedVersion = errors.New("vault: unsupported version (upgrade kist)")

// ErrMalformed wraps every structural decoding failure.
var ErrMalformed = errors.New("vault: malformed contents")

// Secret is one stored value.
type Secret struct {
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Vault is the decrypted document.
type Vault struct {
	Version int               `json:"version"`
	Secrets map[string]Secret `json:"secrets"`
}

// New returns an empty vault.
func New() *Vault {
	return &Vault{Version: Version, Secrets: map[string]Secret{}}
}

// ValidateName enforces ^[A-Za-z_][A-Za-z0-9_]*$ so that every name is a valid
// environment variable name. It is hand-written instead of using regexp to
// keep the rule obvious and the fuzz oracle independent.
func ValidateName(name string) error {
	if name == "" || len(name) > MaxNameLen {
		return errors.New("invalid name: must be 1-255 characters")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		isAlpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
		isDigit := c >= '0' && c <= '9'
		if !isAlpha && !(isDigit && i > 0) {
			return errors.New("invalid name: must match [A-Za-z_][A-Za-z0-9_]*")
		}
	}
	return nil
}

// ValidateValue rejects values that cannot round-trip through JSON or be put
// in an environment: invalid UTF-8 (JSON would silently substitute U+FFFD),
// NUL (not allowed in environment strings) and oversized values.
func ValidateValue(value string) error {
	switch {
	case len(value) > MaxValueBytes:
		return errors.New("invalid value: larger than 64 KiB")
	case !utf8.ValidString(value):
		return errors.New("invalid value: not valid UTF-8")
	case strings.IndexByte(value, 0) >= 0:
		return errors.New("invalid value: contains NUL")
	}
	return nil
}

// Set creates or updates a secret. now is a parameter so tests are exact.
func (v *Vault) Set(name, value string, now time.Time) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := ValidateValue(value); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	v.Secrets[name] = Secret{Value: value, UpdatedAt: now.UTC().Truncate(time.Second)}
	return nil
}

// Get returns a secret's value.
func (v *Vault) Get(name string) (string, bool) {
	s, ok := v.Secrets[name]
	return s.Value, ok
}

// Delete removes a secret and reports whether it existed.
func (v *Vault) Delete(name string) bool {
	_, ok := v.Secrets[name]
	delete(v.Secrets, name)
	return ok
}

// Names returns all secret names in sorted order.
func (v *Vault) Names() []string {
	names := make([]string, 0, len(v.Secrets))
	for n := range v.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Encode returns the canonical plaintext. Output is deterministic (map keys
// are sorted by encoding/json) and compact, which is what the golden vectors
// pin down.
func (v *Vault) Encode() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, errors.New("vault: encode failed")
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Decode parses and validates a plaintext vault. It rejects unknown fields,
// trailing data, unknown versions, invalid names and invalid values.
func Decode(data []byte) (*Vault, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var v Vault
	if err := dec.Decode(&v); err != nil {
		return nil, sanitize(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	if v.Version != Version {
		return nil, ErrUnsupportedVersion
	}
	if v.Secrets == nil {
		v.Secrets = map[string]Secret{}
	}
	for name, s := range v.Secrets {
		if err := ValidateName(name); err != nil {
			return nil, fmt.Errorf("%w: bad secret name", ErrMalformed)
		}
		if err := ValidateValue(s.Value); err != nil {
			return nil, fmt.Errorf("%w: bad value for a secret", ErrMalformed)
		}
	}
	return &v, nil
}

// sanitize converts encoding/json errors, which can quote input bytes, into
// errors that carry only an offset.
func sanitize(err error) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Errorf("%w: syntax error at byte %d", ErrMalformed, syn.Offset)
	case errors.As(err, &typ):
		return fmt.Errorf("%w: wrong type at byte %d", ErrMalformed, typ.Offset)
	default:
		// Includes unknown fields and unexpected EOF; their text may quote input.
		return fmt.Errorf("%w: unexpected structure", ErrMalformed)
	}
}
