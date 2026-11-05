package vault

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ibaurr/kist/internal/crypto"
)

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics; verified in CI on Linux/macOS")
	}
}

func newIDs(t *testing.T) (user, rec *crypto.Identity) {
	t.Helper()
	user, err := crypto.GenerateIdentity()
	must(t, err)
	rec, err = crypto.GenerateIdentity()
	must(t, err)
	return
}

func tempPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	p := Paths{ConfigDir: filepath.Join(root, "cfg", "kist"), DataDir: filepath.Join(root, "data", "kist")}
	must(t, EnsureDirs(p))
	return p
}

func TestSaveLoadRoundTripBothKeys(t *testing.T) {
	p := tempPaths(t)
	user, rec := newIDs(t)
	v := goldenVault(t)
	must(t, Save(p.Vault(), v, user.Recipient(), rec.Recipient()))
	for name, id := range map[string]*crypto.Identity{"user": user, "recovery": rec} {
		got, err := Load(p.Vault(), id)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		a, _ := v.Encode()
		b, _ := got.Encode()
		if !bytes.Equal(a, b) {
			t.Fatalf("%s: contents differ", name)
		}
	}
}

func TestLoadWrongKeyAndCorruptFile(t *testing.T) {
	p := tempPaths(t)
	user, rec := newIDs(t)
	stranger, _ := newIDs(t)
	must(t, Save(p.Vault(), New(), user.Recipient(), rec.Recipient()))
	if _, err := Load(p.Vault(), stranger); !errors.Is(err, crypto.ErrNotRecipient) {
		t.Fatalf("want ErrNotRecipient, got %v", err)
	}
	must(t, os.WriteFile(p.Vault(), []byte("garbage"), 0o600))
	if _, err := Load(p.Vault(), user); !errors.Is(err, crypto.ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
	if _, err := Load(filepath.Join(p.DataDir, "missing"), user); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("want not-exist, got %v", err)
	}
}

func TestLoadRejectsFutureVersion(t *testing.T) {
	p := tempPaths(t)
	user, _ := newIDs(t)
	ct, err := crypto.Encrypt([]byte(`{"version":2,"secrets":{}}`), user.Recipient())
	must(t, err)
	must(t, os.WriteFile(p.Vault(), ct, 0o600))
	if _, err := Load(p.Vault(), user); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("got %v", err)
	}
}

func TestBackupKeepsExactlyOnePreviousVersion(t *testing.T) {
	p := tempPaths(t)
	user, rec := newIDs(t)
	rs := []*crypto.Recipient{user.Recipient(), rec.Recipient()}

	v := New()
	must(t, v.Set("A", "1", goldenTime))
	must(t, Save(p.Vault(), v, rs...))
	if ok, _ := Exists(p.Backup()); ok {
		t.Fatal("backup created on first save")
	}
	first, _ := os.ReadFile(p.Vault())

	must(t, v.Set("A", "2", goldenTime))
	must(t, Save(p.Vault(), v, rs...))
	bak, _ := os.ReadFile(p.Backup())
	if !bytes.Equal(bak, first) {
		t.Fatal("backup is not the previous vault")
	}
	old, err := Load(p.Backup(), user)
	must(t, err)
	if val, _ := old.Get("A"); val != "1" {
		t.Fatalf("backup holds %q, want previous value", val)
	}

	must(t, RemoveBackup(p.Vault()))
	must(t, RemoveBackup(p.Vault())) // idempotent
	if ok, _ := Exists(p.Backup()); ok {
		t.Fatal("backup not removed")
	}
}

func TestFilePermissions(t *testing.T) {
	skipWindows(t)
	root := t.TempDir()
	// Pre-create loose directories to prove EnsureDirs tightens them.
	p := Paths{ConfigDir: filepath.Join(root, "c"), DataDir: filepath.Join(root, "d")}
	must(t, os.MkdirAll(p.ConfigDir, 0o755))
	must(t, os.MkdirAll(p.DataDir, 0o755))
	must(t, EnsureDirs(p))

	user, rec := newIDs(t)
	must(t, SaveIdentity(p.Identity(), user, "pw"))
	must(t, SaveRecovery(p.Recovery(), rec.Recipient()))
	must(t, Save(p.Vault(), New(), user.Recipient(), rec.Recipient()))
	must(t, Save(p.Vault(), New(), user.Recipient(), rec.Recipient())) // creates .bak
	unlock, err := Lock(p.Lock())
	must(t, err)
	must(t, unlock())

	for _, f := range []string{p.Identity(), p.Recovery(), p.Vault(), p.Backup(), p.Lock()} {
		if m := mode(t, f); m != 0o600 {
			t.Errorf("%s mode %o, want 600", filepath.Base(f), m)
		}
	}
	for _, d := range []string{p.ConfigDir, p.DataDir} {
		if m := mode(t, d); m != 0o700 {
			t.Errorf("dir %s mode %o, want 700", filepath.Base(d), m)
		}
	}
	leftovers, _ := filepath.Glob(filepath.Join(p.DataDir, ".kist-tmp-*"))
	if len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}

func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	must(t, err)
	return fi.Mode().Perm()
}

func TestAtomicWriteFailureLeavesOldContentAndNoTemp(t *testing.T) {
	p := tempPaths(t)
	user, rec := newIDs(t)
	rs := []*crypto.Recipient{user.Recipient(), rec.Recipient()}
	v := New()
	must(t, v.Set("A", "old", goldenTime))
	must(t, Save(p.Vault(), v, rs...))
	before, _ := os.ReadFile(p.Vault())

	orig := renameFn
	defer func() { renameFn = orig }()
	renameFn = func(a, b string) error {
		if strings.HasSuffix(b, ".bak") {
			return orig(a, b) // let the backup through; fail the real replace
		}
		return errors.New("injected rename failure")
	}

	must(t, v.Set("A", "new", goldenTime))
	if err := Save(p.Vault(), v, rs...); err == nil {
		t.Fatal("expected failure")
	}
	after, _ := os.ReadFile(p.Vault())
	if !bytes.Equal(before, after) {
		t.Fatal("vault changed despite failed write")
	}
	got, err := Load(p.Vault(), user)
	must(t, err)
	if val, _ := got.Get("A"); val != "old" {
		t.Fatalf("got %q", val)
	}
	leftovers, _ := filepath.Glob(filepath.Join(p.DataDir, ".kist-tmp-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

func TestDirSyncFailureIsReported(t *testing.T) {
	p := tempPaths(t)
	orig := syncDirFn
	defer func() { syncDirFn = orig }()
	syncDirFn = func(string) error { return errors.New("injected fsync failure") }
	if err := writeAtomic(filepath.Join(p.DataDir, "x"), []byte("x")); err == nil {
		t.Fatal("dir fsync failure swallowed")
	}
}

func TestWriteIntoMissingDirFails(t *testing.T) {
	if err := writeAtomic(filepath.Join(t.TempDir(), "nope", "x"), []byte("x")); err == nil {
		t.Fatal("expected error")
	}
}

func TestIdentityFile(t *testing.T) {
	p := tempPaths(t)
	id, _ := newIDs(t)
	must(t, SaveIdentity(p.Identity(), id, "correct horse"))

	raw, _ := os.ReadFile(p.Identity())
	if bytes.Contains(raw, []byte("AGE-SECRET-KEY")) {
		t.Fatal("identity stored in plaintext")
	}
	got, err := LoadIdentity(p.Identity(), "correct horse")
	must(t, err)
	if got.String() != id.String() {
		t.Fatal("identity changed")
	}
	if _, err := LoadIdentity(p.Identity(), "wrong"); !errors.Is(err, crypto.ErrWrongPassphrase) {
		t.Fatalf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestRecoveryRecipientFile(t *testing.T) {
	p := tempPaths(t)
	_, rec := newIDs(t)
	must(t, SaveRecovery(p.Recovery(), rec.Recipient()))
	got, err := LoadRecovery(p.Recovery())
	must(t, err)
	if got.String() != rec.Recipient().String() {
		t.Fatal("recipient changed")
	}
	raw, _ := os.ReadFile(p.Recovery())
	if bytes.Contains(raw, []byte("SECRET")) {
		t.Fatal("secret key material in recovery.pub")
	}
	must(t, os.WriteFile(p.Recovery(), []byte("junk"), 0o600))
	if _, err := LoadRecovery(p.Recovery()); err == nil {
		t.Fatal("corrupt recipient accepted")
	}
}

func TestDefaultPaths(t *testing.T) {
	home := func() (string, error) { return filepath.FromSlash("/home/u"), nil }
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	p, err := DefaultPaths(env(nil), home)
	must(t, err)
	if p.ConfigDir != filepath.FromSlash("/home/u/.config/kist") || p.DataDir != filepath.FromSlash("/home/u/.local/share/kist") {
		t.Fatalf("defaults wrong: %+v", p)
	}
	abs := filepath.FromSlash("/x")
	if runtime.GOOS == "windows" {
		abs = `C:\x`
	}
	p, err = DefaultPaths(env(map[string]string{"XDG_CONFIG_HOME": abs, "XDG_DATA_HOME": "relative/ignored"}), home)
	must(t, err)
	if p.ConfigDir != filepath.Join(abs, "kist") {
		t.Fatalf("XDG_CONFIG_HOME ignored: %+v", p)
	}
	if p.DataDir != filepath.FromSlash("/home/u/.local/share/kist") {
		t.Fatalf("relative XDG_DATA_HOME must be ignored: %+v", p)
	}
	if _, err := DefaultPaths(env(nil), func() (string, error) { return "", errors.New("no home") }); err == nil {
		t.Fatal("expected error without a home directory")
	}
}

func TestLockSerialises(t *testing.T) {
	skipWindows(t)
	p := tempPaths(t)
	unlock1, err := Lock(p.Lock())
	must(t, err)

	var acquired atomic.Bool
	done := make(chan struct{})
	go func() {
		unlock2, err := Lock(p.Lock())
		if err == nil {
			acquired.Store(true)
			unlock2()
		}
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	if acquired.Load() {
		t.Fatal("second lock acquired while first held")
	}
	must(t, unlock1())
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("second lock never acquired after release")
	}
	if !acquired.Load() {
		t.Fatal("second lock failed")
	}
}
