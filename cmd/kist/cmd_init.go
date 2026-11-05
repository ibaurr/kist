package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/ibaurr/kist/internal/crypto"
	"github.com/ibaurr/kist/internal/ui"
	"github.com/ibaurr/kist/internal/vault"
)

// cmdInit creates the identity, the recovery key and an empty vault.
//
// Order matters for crash safety: the vault is written last, and everything
// written so far is removed on failure, so a failed init leaves nothing that
// could be mistaken for a working (or half-working) setup.
func cmdInit(e *env, args []string) error {
	if len(args) != 0 {
		return usageError("init takes no arguments")
	}
	// The recovery key is shown exactly once, so insist on a real terminal
	// rather than risk it landing in a log file.
	if !e.stderrTTY {
		return errors.New("init must run in an interactive terminal: the recovery key is shown once")
	}
	for _, p := range []string{e.paths.Identity(), e.paths.Recovery(), e.paths.Vault()} {
		if ok, err := vault.Exists(p); err != nil {
			return err
		} else if ok {
			return fmt.Errorf("already initialised: %s exists; refusing to overwrite (if you really want to start over, move your kist directories away first)", p)
		}
	}
	if err := vault.EnsureDirs(e.paths); err != nil {
		return err
	}

	pass, err := ui.NewPassphrase(e.prompt)
	if err != nil {
		return err
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return err
	}
	rec, err := crypto.GenerateIdentity()
	if err != nil {
		return err
	}

	var created []string
	fail := func(err error) error {
		for _, p := range created {
			os.Remove(p)
		}
		return err
	}
	write := func(path string, w func() error) error {
		if err := w(); err != nil {
			return err
		}
		created = append(created, path)
		return nil
	}
	if err := write(e.paths.Identity(), func() error { return vault.SaveIdentity(e.paths.Identity(), id, pass) }); err != nil {
		return fail(err)
	}
	if err := write(e.paths.Recovery(), func() error { return vault.SaveRecovery(e.paths.Recovery(), rec.Recipient()) }); err != nil {
		return fail(err)
	}
	if err := write(e.paths.Vault(), func() error {
		return vault.Save(e.paths.Vault(), vault.New(), id.Recipient(), rec.Recipient())
	}); err != nil {
		return fail(err)
	}

	fmt.Fprintf(e.stderr, `
kist is ready.
  identity: %s
  vault:    %s

RECOVERY KEY (shown once; kist does not store it):

    %s

Write it down and keep it somewhere safe and offline. It is the ONLY way to
open the vault if you forget your passphrase. Without both, the secrets are
gone for good. Do not store it in the vault or a file next to it.

Next: kist set NAME
`, e.paths.Identity(), e.paths.Vault(), rec.String())
	return nil
}

// cmdRecover regains access using the recovery key: it decrypts the vault with
// that key, makes a fresh identity under a new passphrase, and re-encrypts the
// vault to the new identity plus the same recovery recipient.
func cmdRecover(e *env, args []string) error {
	if len(args) != 0 {
		return usageError("recover takes no arguments (the key is read from the terminal)")
	}
	if ok, err := vault.Exists(e.paths.Vault()); err != nil {
		return err
	} else if !ok {
		return errors.New("no vault found; nothing to recover")
	}

	raw, err := e.prompt.Secret("Recovery key: ")
	if err != nil {
		return err
	}
	defer crypto.Wipe(raw)
	recID, err := crypto.ParseIdentity(strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}

	// Hold the lock for the whole operation so no other kist process writes
	// between our read and our rewrite.
	unlock, err := vault.Lock(e.paths.Lock())
	if err != nil {
		return fmt.Errorf("lock vault: %w", err)
	}
	defer unlock()

	v, err := vault.Load(e.paths.Vault(), recID)
	switch {
	case errors.Is(err, crypto.ErrNotRecipient):
		return errors.New("that recovery key does not belong to this vault")
	case errors.Is(err, fs.ErrNotExist):
		return errors.New("no vault found; nothing to recover")
	case err != nil:
		return err
	}

	pass, err := ui.NewPassphrase(e.prompt)
	if err != nil {
		return err
	}
	newID, err := crypto.GenerateIdentity()
	if err != nil {
		return err
	}
	if err := vault.EnsureDirs(e.paths); err != nil {
		return err
	}

	// The new identity is persisted before any vault depends on it. If we
	// crash after this line the old vault is still readable with the recovery
	// key, so running `kist recover` again always works.
	if err := vault.SaveIdentity(e.paths.Identity(), newID, pass); err != nil {
		return err
	}
	// The recovery recipient is derived from the key just presented, so a
	// lost or tampered recovery.pub is healed here.
	if err := vault.SaveRecovery(e.paths.Recovery(), recID.Recipient()); err != nil {
		return err
	}
	if err := vault.Save(e.paths.Vault(), v, newID.Recipient(), recID.Recipient()); err != nil {
		return fmt.Errorf("%w (the old vault is intact; run `kist recover` again)", err)
	}
	// Prove the new setup works before destroying the old-identity backup.
	if _, err := vault.Load(e.paths.Vault(), newID); err != nil {
		return fmt.Errorf("verification failed: %w (the previous vault is at %s)", err, e.paths.Backup())
	}
	// vault.age.bak is encrypted to the identity we just replaced. If the old
	// passphrase was compromised, keeping it would defeat the recovery.
	if err := vault.RemoveBackup(e.paths.Vault()); err != nil {
		return fmt.Errorf("remove old backup: %w", err)
	}
	fmt.Fprintln(e.stderr, "kist: recovered. New passphrase set; your recovery key is unchanged.")
	return nil
}
