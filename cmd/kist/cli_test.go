package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ibaurr/kist/internal/crypto"
	"github.com/ibaurr/kist/internal/vault"
)

func init() { crypto.PassphraseWorkFactor = 8 } // fast scrypt in tests

// scripted answers hidden prompts in order and fails the test on any prompt it
// was not told to expect, so a command cannot silently ask for more than it
// should.
type scripted struct {
	t       *testing.T
	answers []string
	prompts []string
}

func (s *scripted) Secret(prompt string) ([]byte, error) {
	s.prompts = append(s.prompts, prompt)
	if len(s.answers) == 0 {
		s.t.Errorf("unexpected prompt %q", prompt)
		return nil, errors.New("unexpected prompt")
	}
	a := s.answers[0]
	s.answers = s.answers[1:]
	return []byte(a), nil
}

type harness struct {
	t     *testing.T
	paths vault.Paths
	tty   bool // stdout is a terminal
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	return &harness{t: t, paths: vault.Paths{
		ConfigDir: filepath.Join(root, "config", "kist"),
		DataDir:   filepath.Join(root, "data", "kist"),
	}}
}

type result struct {
	code        int
	out, errOut string
}

// run executes one kist invocation in-process. It is safe to call from
// several goroutines.
func (h *harness) run(stdin string, answers []string, args ...string) result {
	h.t.Helper()
	var out, errOut bytes.Buffer
	e := &env{
		stdin: strings.NewReader(stdin), stdout: &out, stderr: &errOut,
		stdoutTTY: h.tty, stderrTTY: true,
		paths:  h.paths,
		prompt: &scripted{t: h.t, answers: answers},
		now:    func() time.Time { return time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC) },
	}
	code := run(args, e)
	return result{code, out.String(), errOut.String()}
}

func (h *harness) ok(stdin string, answers []string, args ...string) result {
	h.t.Helper()
	r := h.run(stdin, answers, args...)
	if r.code != 0 {
		h.t.Fatalf("kist %v: exit %d: %s", args, r.code, r.errOut)
	}
	return r
}

const pw = "correct horse"

// init runs `kist init` and returns the recovery key it printed.
func (h *harness) init() string {
	h.t.Helper()
	r := h.ok("", []string{pw, pw}, "init")
	for _, f := range strings.Fields(r.errOut) {
		if strings.HasPrefix(f, "AGE-SECRET-KEY-1") {
			return f
		}
	}
	h.t.Fatalf("no recovery key in init output:\n%s", r.errOut)
	return ""
}

func TestInitCreatesVaultAndShowsRecoveryKeyOnce(t *testing.T) {
	h := newHarness(t)
	key := h.init()

	for _, p := range []string{h.paths.Identity(), h.paths.Recovery(), h.paths.Vault()} {
		if ok, _ := vault.Exists(p); !ok {
			t.Errorf("%s not created", p)
		}
	}
	// The recovery key must open the vault and must not be stored anywhere.
	rid, err := crypto.ParseIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Load(h.paths.Vault(), rid); err != nil {
		t.Fatalf("recovery key cannot open vault: %v", err)
	}
	filepath.WalkDir(filepath.Dir(h.paths.ConfigDir), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(key)) {
				t.Errorf("recovery key found on disk in %s", p)
			}
		}
		return nil
	})
	// And no later command may print it.
	for _, args := range [][]string{{"list"}, {"export", "--yes"}} {
		r := h.ok("", []string{pw}, args...)
		if strings.Contains(r.out+r.errOut, key) {
			t.Fatalf("kist %v printed the recovery key", args)
		}
	}
}

func TestInitRefusesExistingAndNonTerminal(t *testing.T) {
	h := newHarness(t)
	h.init()
	before, _ := os.ReadFile(h.paths.Vault())
	if r := h.run("", []string{pw, pw}, "init"); r.code == 0 || !strings.Contains(r.errOut, "already initialised") {
		t.Fatalf("second init: %+v", r)
	}
	after, _ := os.ReadFile(h.paths.Vault())
	if !bytes.Equal(before, after) {
		t.Fatal("second init touched the vault")
	}

	// An existing identity alone (no vault) must also be protected.
	h2 := newHarness(t)
	h2.init()
	os.Remove(h2.paths.Vault())
	if r := h2.run("", []string{pw, pw}, "init"); r.code == 0 {
		t.Fatal("init overwrote an existing identity")
	}

	// Non-terminal stderr.
	h3 := newHarness(t)
	var errOut bytes.Buffer
	e := &env{stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &errOut, paths: h3.paths,
		prompt: &scripted{t: t}, now: time.Now}
	if code := run([]string{"init"}, e); code == 0 {
		t.Fatal("init ran without a terminal")
	}
}

func TestInitFailsCleanly(t *testing.T) {
	h := newHarness(t)
	for _, answers := range [][]string{{"a", "b"}, {"", ""}} {
		if r := h.run("", answers, "init"); r.code == 0 {
			t.Fatalf("init succeeded with bad passphrase %q", answers)
		}
		for _, p := range []string{h.paths.Identity(), h.paths.Recovery(), h.paths.Vault()} {
			if ok, _ := vault.Exists(p); ok {
				t.Errorf("%s left behind after failed init", p)
			}
		}
	}
}

func TestSetGetListDelete(t *testing.T) {
	h := newHarness(t)
	h.init()

	h.ok("s3cret-one\n", []string{pw}, "set", "ONE", "--stdin")
	h.ok("", []string{pw, "s3cret-two"}, "set", "TWO")
	h.ok("x", []string{pw}, "set", "--stdin", "AFTER") // flags before the name

	if r := h.ok("", []string{pw}, "get", "ONE"); r.out != "s3cret-one" {
		t.Fatalf("get ONE = %q (want exact bytes, no newline)", r.out)
	}
	if r := h.ok("", []string{pw}, "get", "TWO"); r.out != "s3cret-two" {
		t.Fatalf("get TWO = %q", r.out)
	}
	if r := h.ok("", []string{pw}, "list"); r.out != "AFTER\nONE\nTWO\n" {
		t.Fatalf("list = %q", r.out)
	}
	if r := h.ok("", []string{pw}, "list", "--long"); !strings.Contains(r.out, "ONE\t2026-03-04T05:06:07Z\n") {
		t.Fatalf("list --long = %q", r.out)
	}
	// Overwrite.
	h.ok("new", []string{pw}, "set", "ONE", "--stdin")
	if r := h.ok("", []string{pw}, "get", "ONE"); r.out != "new" {
		t.Fatalf("after update got %q", r.out)
	}
	h.ok("", []string{pw}, "delete", "ONE")
	if r := h.run("", []string{pw}, "get", "ONE"); r.code != 1 || r.out != "" {
		t.Fatalf("deleted secret still readable: %+v", r)
	}
	if r := h.run("", []string{pw}, "delete", "ONE"); r.code != 1 {
		t.Fatalf("deleting a missing secret should fail: %+v", r)
	}
	if r := h.ok("", []string{pw}, "list"); r.out != "AFTER\nTWO\n" {
		t.Fatalf("list after delete = %q", r.out)
	}
}

func TestSecretsNeverReachOutputOrArgv(t *testing.T) {
	h := newHarness(t)
	h.init()
	const secret = "TOPSECRETVALUE-12345"

	for _, r := range []result{
		h.ok(secret, []string{pw}, "set", "A", "--stdin"),
		h.ok("", []string{pw}, "list", "--long"),
		h.ok("", []string{pw}, "list"),
	} {
		if strings.Contains(r.out+r.errOut, secret) {
			t.Fatalf("secret leaked into output: %+v", r)
		}
	}

	// A value given as an argument is refused, and never echoed back.
	r := h.run("", nil, "set", "A", secret)
	if r.code != 2 || strings.Contains(r.out+r.errOut, secret) {
		t.Fatalf("value as argument: %+v", r)
	}
	// Even a malformed name (a value typed where the name goes) is not echoed.
	r = h.run("", nil, "get", "not a valid name "+secret)
	if r.code == 0 || strings.Contains(r.out+r.errOut, secret) {
		t.Fatalf("bad name: %+v", r)
	}
	// Failed commands (wrong passphrase) are quiet about contents too.
	r = h.run("", []string{"wrong"}, "get", "A")
	if r.code != 1 || !strings.Contains(r.errOut, "incorrect passphrase") || strings.Contains(r.out+r.errOut, secret) {
		t.Fatalf("wrong passphrase: %+v", r)
	}
}

func TestGetOnTerminalWarnsAndAddsNewline(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v", []string{pw}, "set", "A", "--stdin")
	h.tty = true
	r := h.ok("", []string{pw}, "get", "A")
	if r.out != "v\n" || !strings.Contains(r.errOut, "warning") {
		t.Fatalf("tty get: %+v", r)
	}
	r = h.ok("", []string{pw}, "get", "-q", "A")
	if r.out != "v\n" || strings.Contains(r.errOut, "warning") {
		t.Fatalf("tty get -q: %+v", r)
	}
}

func TestSetInputValidation(t *testing.T) {
	h := newHarness(t)
	h.init()
	for name, tc := range map[string]struct {
		stdin   string
		answers []string
		args    []string
	}{
		"bad name":       {"v", nil, []string{"set", "1BAD", "--stdin"}},
		"no name":        {"v", nil, []string{"set", "--stdin"}},
		"NUL value":      {"a\x00b", []string{pw}, []string{"set", "A", "--stdin"}},
		"invalid utf8":   {"\xff\xfe", []string{pw}, []string{"set", "A", "--stdin"}},
		"empty prompted": {"", []string{pw, ""}, []string{"set", "A"}},
	} {
		if r := h.run(tc.stdin, tc.answers, tc.args...); r.code == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	if r := h.ok("", []string{pw}, "list"); r.out != "" {
		t.Fatalf("a rejected set stored something: %q", r.out)
	}
}

func TestMultilineAndUnicodeValuesSurvive(t *testing.T) {
	h := newHarness(t)
	h.init()
	val := "-----BEGIN KEY-----\nabc\n-----END KEY-----"
	h.ok(val, []string{pw}, "set", "PEM", "--stdin")
	h.ok("pässwörd ✓", []string{pw}, "set", "UNI", "--stdin")
	if r := h.ok("", []string{pw}, "get", "PEM"); r.out != val {
		t.Fatalf("PEM = %q", r.out)
	}
	if r := h.ok("", []string{pw}, "get", "UNI"); r.out != "pässwörd ✓" {
		t.Fatalf("UNI = %q", r.out)
	}
}

func TestCommandsRequireInit(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"get", "A"}, {"list"}, {"set", "A", "--stdin"}, {"delete", "A"}, {"export", "--yes"}} {
		r := h.run("v", nil, args...)
		if r.code != 1 || !strings.Contains(r.errOut, "kist init") {
			t.Errorf("%v: %+v", args, r)
		}
	}
}

func TestImportExport(t *testing.T) {
	h := newHarness(t)
	h.init()
	envPath := filepath.Join(t.TempDir(), ".env")
	content := "# my keys\nexport API_KEY=abc123\nDB_URL='postgres://u:p@h/db?x=1#frag'\nPEM=\"l1\\nl2\"\nEMPTY=\n"
	os.WriteFile(envPath, []byte(content), 0o600)

	r := h.ok("", []string{pw}, "import", envPath)
	if !strings.Contains(r.errOut, "imported 4") || !strings.Contains(r.errOut, "delete it") {
		t.Fatalf("import output: %q", r.errOut)
	}
	if r := h.ok("", []string{pw}, "get", "PEM"); r.out != "l1\nl2" {
		t.Fatalf("PEM = %q", r.out)
	}
	if r := h.ok("", []string{pw}, "get", "DB_URL"); r.out != "postgres://u:p@h/db?x=1#frag" {
		t.Fatalf("DB_URL = %q", r.out)
	}

	// Export must round-trip into an identical set of secrets.
	exp := h.ok("", []string{pw}, "export").out
	h2 := newHarness(t)
	h2.init()
	p2 := filepath.Join(t.TempDir(), "exported.env")
	os.WriteFile(p2, []byte(exp), 0o600)
	h2.ok("", []string{pw}, "import", p2)
	if exp2 := h2.ok("", []string{pw}, "export").out; exp2 != exp {
		t.Fatalf("export/import round trip differs:\n%s\n---\n%s", exp, exp2)
	}
}

func TestImportIsAtomicAndSafe(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("old", []string{pw}, "set", "API_KEY", "--stdin")
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}

	// Existing name without --overwrite: nothing imported, existing value kept.
	r := h.run("", []string{pw}, "import", write("a.env", "NEW=1\nAPI_KEY=new\n"))
	if r.code == 0 || !strings.Contains(r.errOut, "API_KEY") {
		t.Fatalf("clash: %+v", r)
	}
	if h.ok("", []string{pw}, "list").out != "API_KEY\n" {
		t.Fatal("partial import happened")
	}
	// --overwrite replaces.
	h.ok("", []string{pw}, "import", "--overwrite", write("b.env", "NEW=1\nAPI_KEY=new\n"))
	if h.ok("", []string{pw}, "get", "API_KEY").out != "new" {
		t.Fatal("--overwrite did not replace")
	}

	// Parse errors report a line, never the content, and fail before unlocking.
	const marker = "LEAKMARKER"
	r = h.run("", nil, "import", write("c.env", "OK=1\nbad line "+marker+"\n"))
	if r.code == 0 || !strings.Contains(r.errOut, "line 2") || strings.Contains(r.errOut, marker) {
		t.Fatalf("parse error: %+v", r)
	}
	// Invalid secret values (NUL in a quoted value is rejected by the parser).
	if r = h.run("", nil, "import", write("d.env", "A=\"x\x00y\"\n")); r.code == 0 {
		t.Fatal("NUL accepted")
	}
	if r = h.run("", nil, "import", write("e.env", "# only comments\n")); r.code == 0 {
		t.Fatal("empty import should fail")
	}
	if r = h.run("", nil, "import", filepath.Join(dir, "missing.env")); r.code == 0 {
		t.Fatal("missing file accepted")
	}
}

func TestExportRefusesTerminalWithoutYes(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v", []string{pw}, "set", "A", "--stdin")
	h.tty = true
	if r := h.run("", nil, "export"); r.code != 2 || r.out != "" {
		t.Fatalf("export to tty without --yes: %+v", r)
	}
	if r := h.ok("", []string{pw}, "export", "--yes"); r.out != "A=v\n" {
		t.Fatalf("export --yes: %q", r.out)
	}
}

func TestRecoverFlow(t *testing.T) {
	h := newHarness(t)
	key := h.init()
	h.ok("one", []string{pw}, "set", "A", "--stdin")
	h.ok("two", []string{pw}, "set", "B", "--stdin") // creates vault.age.bak
	if ok, _ := vault.Exists(h.paths.Backup()); !ok {
		t.Fatal("precondition: expected a backup before recovery")
	}
	oldIdentity, _ := os.ReadFile(h.paths.Identity())

	// Wrong key and malformed key are rejected without changing anything.
	other, _ := crypto.GenerateIdentity()
	for _, bad := range []string{other.String(), "not-a-key"} {
		if r := h.run("", []string{bad}, "recover"); r.code == 0 {
			t.Fatalf("recover accepted key %q", bad)
		}
	}
	if cur, _ := os.ReadFile(h.paths.Identity()); !bytes.Equal(cur, oldIdentity) {
		t.Fatal("failed recovery modified the identity")
	}

	// Forgot the passphrase: recover with the key and set a new one.
	h.ok("", []string{key, "new pass", "new pass"}, "recover")
	if r := h.run("", []string{pw}, "list"); r.code == 0 {
		t.Fatal("old passphrase still works")
	}
	if r := h.ok("", []string{"new pass"}, "list"); r.out != "A\nB\n" {
		t.Fatalf("secrets lost in recovery: %q", r.out)
	}
	if h.ok("", []string{"new pass"}, "get", "A").out != "one" {
		t.Fatal("value changed")
	}
	// The stale backup (encrypted to the replaced identity) must be gone.
	if ok, _ := vault.Exists(h.paths.Backup()); ok {
		t.Fatal("vault.age.bak survived recovery")
	}
	// Writes keep working, and the same recovery key still works afterwards.
	h.ok("three", []string{"new pass"}, "set", "C", "--stdin")
	h.ok("", []string{key, "third pass", "third pass"}, "recover")
	if r := h.ok("", []string{"third pass"}, "list"); r.out != "A\nB\nC\n" {
		t.Fatalf("after second recovery: %q", r.out)
	}
}

func TestRecoverHealsMissingRecoveryPub(t *testing.T) {
	h := newHarness(t)
	key := h.init()
	os.Remove(h.paths.Recovery())
	// Writes fail loudly rather than silently dropping the recovery recipient.
	if r := h.run("v", []string{pw}, "set", "A", "--stdin"); r.code == 0 || !strings.Contains(r.errOut, "kist recover") {
		t.Fatalf("set without recovery.pub: %+v", r)
	}
	h.ok("", []string{key, "np", "np"}, "recover")
	h.ok("v", []string{"np"}, "set", "A", "--stdin")
	rid, _ := crypto.ParseIdentity(key)
	if _, err := vault.Load(h.paths.Vault(), rid); err != nil {
		t.Fatalf("recovery key lost access after heal: %v", err)
	}
}

func TestVaultEncryptedToBothKeysAfterEveryWrite(t *testing.T) {
	h := newHarness(t)
	key := h.init()
	h.ok("v", []string{pw}, "set", "A", "--stdin")
	h.ok("", []string{pw}, "delete", "A")
	rid, _ := crypto.ParseIdentity(key)
	if _, err := vault.Load(h.paths.Vault(), rid); err != nil {
		t.Fatalf("recovery key cannot open vault after writes: %v", err)
	}
}

func TestConcurrentSetsDoNotLoseUpdates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock is Linux/macOS only; verified in CI")
	}
	h := newHarness(t)
	h.init()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ok("v", []string{pw}, "set", fmt.Sprintf("N%d", i), "--stdin")
		}()
	}
	wg.Wait()
	if got := strings.Count(h.ok("", []string{pw}, "list").out, "\n"); got != 8 {
		t.Fatalf("%d of 8 concurrent writes survived", got)
	}
}

func TestFilePermissionsViaCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions; verified in CI")
	}
	h := newHarness(t)
	h.init()
	h.ok("v", []string{pw}, "set", "A", "--stdin")
	h.ok("v", []string{pw}, "set", "B", "--stdin")
	for _, p := range []string{h.paths.Identity(), h.paths.Recovery(), h.paths.Vault(), h.paths.Backup()} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", filepath.Base(p), fi.Mode().Perm(), err)
		}
	}
	for _, d := range []string{h.paths.ConfigDir, h.paths.DataDir} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, fi.Mode().Perm(), err)
		}
	}
}

func TestDispatch(t *testing.T) {
	h := newHarness(t)
	if r := h.run("", nil); r.code != 2 {
		t.Errorf("no args: %+v", r)
	}
	if r := h.run("", nil, "frobnicate"); r.code != 2 || !strings.Contains(r.errOut, "unknown command") {
		t.Errorf("unknown: %+v", r)
	}
	if r := h.run("", nil, "help"); r.code != 0 || !strings.Contains(r.out, "usage:") {
		t.Errorf("help: %+v", r)
	}
	if r := h.run("", nil, "version"); r.code != 0 || !strings.HasPrefix(r.out, "kist ") {
		t.Errorf("version: %+v", r)
	}
	if r := h.run("", nil, "list", "--bogus"); r.code != 2 {
		t.Errorf("bad flag: %+v", r)
	}
	if r := h.run("", nil, "get", "-h"); r.code != 0 {
		t.Errorf("-h: %+v", r)
	}
	// `--` ends flag parsing.
	if r := h.run("", nil, "set", "--", "--stdin"); r.code != 2 {
		t.Errorf("-- handling: %+v", r)
	}
}
