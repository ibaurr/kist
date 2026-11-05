// Package crypto is the only place in kist that touches cryptography, and it
// does so exclusively through filippo.io/age. There are no primitives, no
// custom KDF and no hand-rolled framing here: every function is a thin,
// error-classifying wrapper so the rest of the code never imports age.
package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

// PassphraseWorkFactor is the scrypt work factor (log2 N) used when encrypting
// with a passphrase. Zero means age's default (18, roughly one second). It is
// a variable only so tests can lower it; production code never sets it.
var PassphraseWorkFactor = 0

// maxDecryptWorkFactor caps the scrypt work we will do when decrypting, so a
// crafted identity file cannot make us burn minutes of CPU. It equals age's
// default; stating it here keeps the limit visible to a reader.
const maxDecryptWorkFactor = 22

// MaxPlaintext bounds how much plaintext Decrypt will buffer. A vault is a
// small JSON document; this only exists to stop a corrupt or hostile file from
// exhausting memory.
const MaxPlaintext = 64 << 20

var (
	// ErrWrongPassphrase means the passphrase did not decrypt the file.
	ErrWrongPassphrase = errors.New("incorrect passphrase")
	// ErrNotRecipient means the identity is not one of the file's recipients.
	ErrNotRecipient = errors.New("key is not a recipient of this file")
	// ErrCorrupt means the file is not a valid age file or failed authentication.
	ErrCorrupt = errors.New("file is corrupt or not an age file")
)

// Identity is an age X25519 private key.
type Identity struct{ id *age.X25519Identity }

// Recipient is an age X25519 public key.
type Recipient struct{ r *age.X25519Recipient }

// GenerateIdentity creates a fresh X25519 identity using age's CSPRNG usage.
func GenerateIdentity() (*Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	return &Identity{id}, nil
}

// ParseIdentity parses an "AGE-SECRET-KEY-1..." string. The error never
// includes the input, which is key material.
func ParseIdentity(s string) (*Identity, error) {
	id, err := age.ParseX25519Identity(s)
	if err != nil {
		return nil, errors.New("not a valid age secret key")
	}
	return &Identity{id}, nil
}

// String returns the secret key encoding. Treat the result as a secret.
func (i *Identity) String() string { return i.id.String() }

// Recipient returns the matching public key.
func (i *Identity) Recipient() *Recipient { return &Recipient{i.id.Recipient()} }

// ParseRecipient parses an "age1..." public key.
func ParseRecipient(s string) (*Recipient, error) {
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, errors.New("not a valid age public key")
	}
	return &Recipient{r}, nil
}

// String returns the "age1..." encoding.
func (r *Recipient) String() string { return r.r.String() }

// EncryptWithPassphrase encrypts plaintext to a single scrypt recipient.
func EncryptWithPassphrase(plaintext []byte, passphrase string) ([]byte, error) {
	rcpt, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	if PassphraseWorkFactor != 0 {
		rcpt.SetWorkFactor(PassphraseWorkFactor)
	}
	return encrypt(plaintext, rcpt)
}

// DecryptWithPassphrase reverses EncryptWithPassphrase.
func DecryptWithPassphrase(ciphertext []byte, passphrase string) ([]byte, error) {
	ident, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	ident.SetMaxWorkFactor(maxDecryptWorkFactor)
	pt, err := decrypt(ciphertext, ident)
	if errors.Is(err, ErrNotRecipient) {
		// For a passphrase file the only way to "not match" is a wrong
		// passphrase (or a file that was never passphrase-encrypted).
		return nil, ErrWrongPassphrase
	}
	return pt, err
}

// Encrypt encrypts plaintext so that any one of the recipients can decrypt it.
func Encrypt(plaintext []byte, recipients ...*Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("encrypt: no recipients")
	}
	rs := make([]age.Recipient, len(recipients))
	for i, r := range recipients {
		rs[i] = r.r
	}
	return encrypt(plaintext, rs...)
}

// Decrypt decrypts ciphertext with an X25519 identity.
func Decrypt(ciphertext []byte, id *Identity) ([]byte, error) {
	return decrypt(ciphertext, id.id)
}

func encrypt(plaintext []byte, recipients ...age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return buf.Bytes(), nil
}

// decrypt maps age's errors onto this package's sentinel errors so callers can
// give precise advice without importing age or parsing error strings.
func decrypt(ciphertext []byte, id age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, ErrNotRecipient
		}
		return nil, ErrCorrupt
	}
	pt, err := io.ReadAll(io.LimitReader(r, MaxPlaintext+1))
	if err != nil {
		return nil, ErrCorrupt
	}
	if len(pt) > MaxPlaintext {
		return nil, ErrCorrupt
	}
	return pt, nil
}

// Wipe overwrites b with zeros. It is best effort: Go may have copied the
// data elsewhere, and strings cannot be wiped at all.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
