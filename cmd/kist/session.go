package main

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/ibaurr/kist/internal/crypto"
	"github.com/ibaurr/kist/internal/vault"
)

// session is an unlocked identity. In v0.1 Week 1 every command unlocks with a
// passphrase prompt; the session agent (Week 2) will replace that prompt.
type session struct {
	e  *env
	id *crypto.Identity
}

// open prompts for the passphrase and decrypts the identity file.
func (e *env) open() (*session, error) {
	if ok, err := vault.Exists(e.paths.Identity()); err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("no vault found; run `kist init` first")
	}
	pass, err := e.prompt.Secret("Passphrase: ")
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(pass)
	id, err := vault.LoadIdentity(e.paths.Identity(), string(pass))
	if err != nil {
		if errors.Is(err, crypto.ErrWrongPassphrase) {
			return nil, errors.New("incorrect passphrase")
		}
		return nil, fmt.Errorf("read identity: %w", err)
	}
	return &session{e: e, id: id}, nil
}

func (s *session) load() (*vault.Vault, error) {
	v, err := vault.Load(s.e.paths.Vault(), s.id)
	switch {
	case err == nil:
		return v, nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, errors.New("identity exists but the vault file is missing; restore it or see `kist recover`")
	case errors.Is(err, crypto.ErrNotRecipient):
		return nil, errors.New("this vault is not encrypted to your identity (try `kist recover` if you have the recovery key)")
	case errors.Is(err, crypto.ErrCorrupt):
		return nil, fmt.Errorf("vault is corrupt; the previous version may be at %s", s.e.paths.Backup())
	}
	return nil, err
}

// view runs fn on the decrypted vault without writing anything.
func (s *session) view(fn func(*vault.Vault) error) error {
	v, err := s.load()
	if err != nil {
		return err
	}
	return fn(v)
}

// update runs a read-modify-write cycle under the file lock, then saves to the
// user's recipient and the stored recovery recipient. If fn fails, nothing is
// written.
func (s *session) update(fn func(*vault.Vault) error) error {
	recovery, err := vault.LoadRecovery(s.e.paths.Recovery())
	if err != nil {
		return fmt.Errorf("cannot read recovery recipient (%s): %w; run `kist recover` to restore it", s.e.paths.Recovery(), err)
	}
	unlock, err := vault.Lock(s.e.paths.Lock())
	if err != nil {
		return fmt.Errorf("lock vault: %w", err)
	}
	defer unlock()
	v, err := s.load()
	if err != nil {
		return err
	}
	if err := fn(v); err != nil {
		return err
	}
	return vault.Save(s.e.paths.Vault(), v, s.id.Recipient(), recovery)
}
