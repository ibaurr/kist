package vault

import (
	"errors"
	"strings"

	"github.com/ibaurr/kist/internal/crypto"
)

// SaveIdentity writes the user's age identity to path, encrypted with the
// passphrase (age scrypt). The file replaces any existing one atomically.
func SaveIdentity(path string, id *crypto.Identity, passphrase string) error {
	pt := []byte(id.String() + "\n")
	defer crypto.Wipe(pt)
	ct, err := crypto.EncryptWithPassphrase(pt, passphrase)
	if err != nil {
		return err
	}
	return writeAtomic(path, ct)
}

// LoadIdentity decrypts the identity file. It returns crypto.ErrWrongPassphrase
// for a bad passphrase.
func LoadIdentity(path, passphrase string) (*crypto.Identity, error) {
	ct, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	pt, err := crypto.DecryptWithPassphrase(ct, passphrase)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(pt)
	return crypto.ParseIdentity(strings.TrimSpace(string(pt)))
}

// SaveRecovery stores only the recovery key's public recipient. The private
// half is shown once at init and never written anywhere.
func SaveRecovery(path string, r *crypto.Recipient) error {
	return writeAtomic(path, []byte(r.String()+"\n"))
}

// LoadRecovery reads the stored recovery recipient.
func LoadRecovery(path string) (*crypto.Recipient, error) {
	b, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	r, err := crypto.ParseRecipient(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, errors.New("recovery.pub is corrupt")
	}
	return r, nil
}
