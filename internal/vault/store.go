package vault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ibaurr/kist/internal/crypto"
)

// maxFileBytes bounds how much of an on-disk file we will read.
const maxFileBytes = crypto.MaxPlaintext + 1<<20

// Test seams for the failure paths of the atomic write. Production code never
// reassigns them.
var (
	renameFn  = os.Rename
	syncDirFn = syncDir
)

// Paths locates kist's files. ConfigDir holds the identity and the recovery
// recipient; DataDir holds the vault.
type Paths struct{ ConfigDir, DataDir string }

// DefaultPaths resolves XDG locations. Per the XDG spec, relative values of
// XDG_* variables are ignored.
func DefaultPaths(getenv func(string) string, home func() (string, error)) (Paths, error) {
	resolve := func(env, fallback string) (string, error) {
		if d := getenv(env); filepath.IsAbs(d) {
			return filepath.Join(d, "kist"), nil
		}
		h, err := home()
		if err != nil || h == "" {
			return "", errors.New("cannot determine home directory; set " + env)
		}
		return filepath.Join(h, fallback, "kist"), nil
	}
	cfg, err := resolve("XDG_CONFIG_HOME", ".config")
	if err != nil {
		return Paths{}, err
	}
	data, err := resolve("XDG_DATA_HOME", filepath.Join(".local", "share"))
	if err != nil {
		return Paths{}, err
	}
	return Paths{ConfigDir: cfg, DataDir: data}, nil
}

func (p Paths) Identity() string { return filepath.Join(p.ConfigDir, "identity.age") }
func (p Paths) Recovery() string { return filepath.Join(p.ConfigDir, "recovery.pub") }
func (p Paths) Vault() string    { return filepath.Join(p.DataDir, "vault.age") }
func (p Paths) Backup() string   { return p.Vault() + ".bak" }
func (p Paths) Lock() string     { return p.Vault() + ".lock" }

// EnsureDirs creates kist's directories with mode 0700 and tightens them if
// they already exist with looser permissions. These directories are ours
// (".../kist"), so tightening them is safe.
func EnsureDirs(p Paths) error {
	for _, d := range []string{p.ConfigDir, p.DataDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// Exists reports whether path exists, treating only "not found" as false.
func Exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Load reads and decrypts the vault at path.
func Load(path string, id *crypto.Identity) (*Vault, error) {
	ct, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	pt, err := crypto.Decrypt(ct, id)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault: %w", err)
	}
	defer crypto.Wipe(pt)
	return Decode(pt)
}

// Save encrypts v to the given recipients and replaces the vault at path
// atomically. If a vault already exists, its bytes are first copied to
// path+".bak" (itself written atomically) so one previous version survives.
// Callers must have loaded the existing vault successfully first, otherwise a
// corrupt file could overwrite a good backup.
func Save(path string, v *Vault, recipients ...*crypto.Recipient) error {
	pt, err := v.Encode()
	if err != nil {
		return err
	}
	defer crypto.Wipe(pt)
	ct, err := crypto.Encrypt(pt, recipients...)
	if err != nil {
		return err
	}
	if old, err := readBounded(path); err == nil {
		if err := writeAtomic(path+".bak", old); err != nil {
			return fmt.Errorf("write backup: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeAtomic(path, ct)
}

// RemoveBackup deletes path+".bak" if present. Used after recovery, where the
// backup is encrypted to the identity that was just replaced.
func RemoveBackup(path string) error {
	err := os.Remove(path + ".bak")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileBytes {
		return nil, errors.New("file too large")
	}
	return b, nil
}

// writeAtomic replaces path with data so that a crash leaves either the old or
// the new content, never a mix: temp file in the same directory, fsync,
// rename over the target, fsync the directory.
func writeAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".kist-tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = renameFn(name, path); err != nil {
		return err
	}
	// If this fails the new content is in place but may not survive power
	// loss; report it rather than hide it.
	return syncDirFn(dir)
}
