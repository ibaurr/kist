package vault

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ibaurr/kist/internal/crypto"
)

func init() { crypto.PassphraseWorkFactor = 8 }

// update regenerates testdata/golden. Run it only for a deliberate format
// change, and review the diff: the golden files are the format's contract.
var update = flag.Bool("update", false, "regenerate golden test vectors")

var goldenTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func goldenVault(t *testing.T) *Vault {
	t.Helper()
	v := New()
	for name, val := range map[string]string{
		"API_KEY": `value with "quotes" & <html>`,
		"MULTI":   "line1\nline2\n",
		"_UNI9":   "pässwörd ✓",
		"EMPTY":   "",
	} {
		if err := v.Set(name, val, goldenTime); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func TestValidateName(t *testing.T) {
	ok := []string{"A", "_", "a1", "_9", "API_KEY", strings.Repeat("a", 255)}
	bad := []string{"", "1A", "A-B", "A B", "é", "A.B", "A\n", strings.Repeat("a", 256)}
	for _, n := range ok {
		if err := ValidateName(n); err != nil {
			t.Errorf("%q rejected: %v", n, err)
		}
	}
	for _, n := range bad {
		if ValidateName(n) == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestValidateValue(t *testing.T) {
	for _, v := range []string{"", "ok", "multi\nline", "✓"} {
		if err := ValidateValue(v); err != nil {
			t.Errorf("%q rejected: %v", v, err)
		}
	}
	for _, v := range []string{"a\x00b", "\xff\xfe", strings.Repeat("x", MaxValueBytes+1)} {
		if ValidateValue(v) == nil {
			t.Errorf("value of len %d accepted", len(v))
		}
	}
}

func TestSetGetDeleteNames(t *testing.T) {
	v := New()
	now := time.Date(2026, 5, 6, 7, 8, 9, 123456789, time.FixedZone("x", 3600))
	if err := v.Set("B", "2", now); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("A", "1", now); err != nil {
		t.Fatal(err)
	}
	if got := v.Names(); len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("names %v", got)
	}
	if val, ok := v.Get("A"); !ok || val != "1" {
		t.Fatal("get A")
	}
	if got := v.Secrets["A"].UpdatedAt; !got.Equal(now.Truncate(time.Second)) || got.Location() != time.UTC {
		t.Fatalf("updated_at not normalised: %v", got)
	}
	if err := v.Set("1bad", "x", now); err == nil {
		t.Fatal("bad name accepted")
	}
	if !v.Delete("A") || v.Delete("A") {
		t.Fatal("delete semantics")
	}
	if _, ok := v.Get("A"); ok {
		t.Fatal("still present")
	}
}

func TestSetErrorDoesNotLeakValue(t *testing.T) {
	err := New().Set("K", "bad\x00SECRETMARKER", goldenTime)
	if err == nil || strings.Contains(err.Error(), "SECRETMARKER") {
		t.Fatalf("error missing or leaks value: %v", err)
	}
}

func TestEncodeGolden(t *testing.T) {
	got, err := goldenVault(t).Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "golden", "v1_basic.json")
	if *update {
		must(t, os.MkdirAll(filepath.Dir(path), 0o755))
		must(t, os.WriteFile(path, got, 0o644))
	}
	want, err := os.ReadFile(path)
	must(t, err)
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding changed.\n got: %s\nwant: %s\n(format changes must be deliberate: bump the version or run -update)", got, want)
	}
}

func TestDecodeGolden(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "golden", "v1_basic.json"))
	must(t, err)
	v, err := Decode(data)
	must(t, err)
	want := goldenVault(t)
	if len(v.Secrets) != len(want.Secrets) {
		t.Fatalf("got %d secrets", len(v.Secrets))
	}
	for name, s := range want.Secrets {
		g := v.Secrets[name]
		if g.Value != s.Value || !g.UpdatedAt.Equal(s.UpdatedAt) {
			t.Errorf("%s differs", name)
		}
	}
}

// The ciphertext golden pins the on-disk envelope: a vault written today must
// stay readable by both the user key and the recovery key in the future.
func TestGoldenCiphertext(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	userKey, recKey := filepath.Join(dir, "user.key"), filepath.Join(dir, "recovery.key")
	ctPath := filepath.Join(dir, "v1_basic.age")
	if *update {
		user, err := crypto.GenerateIdentity()
		must(t, err)
		rec, err := crypto.GenerateIdentity()
		must(t, err)
		must(t, os.WriteFile(userKey, []byte(user.String()+"\n"), 0o644))
		must(t, os.WriteFile(recKey, []byte(rec.String()+"\n"), 0o644))
		must(t, Save(ctPath+".tmp", goldenVault(t), user.Recipient(), rec.Recipient()))
		must(t, os.Rename(ctPath+".tmp", ctPath))
	}
	plain, err := os.ReadFile(filepath.Join(dir, "v1_basic.json"))
	must(t, err)
	for _, keyFile := range []string{userKey, recKey} {
		raw, err := os.ReadFile(keyFile)
		must(t, err)
		id, err := crypto.ParseIdentity(strings.TrimSpace(string(raw)))
		must(t, err)
		v, err := Load(ctPath, id)
		if err != nil {
			t.Fatalf("%s cannot open golden vault: %v", filepath.Base(keyFile), err)
		}
		got, _ := v.Encode()
		if !bytes.Equal(got, plain) {
			t.Fatalf("%s: plaintext mismatch", filepath.Base(keyFile))
		}
	}
}

const goldenPassphrase = "golden-test-passphrase"

func TestGoldenIdentityFile(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	idPath := filepath.Join(dir, "identity_v1.age")
	if *update {
		raw, err := os.ReadFile(filepath.Join(dir, "user.key"))
		must(t, err)
		id, err := crypto.ParseIdentity(strings.TrimSpace(string(raw)))
		must(t, err)
		must(t, SaveIdentity(idPath, id, goldenPassphrase))
	}
	id, err := LoadIdentity(idPath, goldenPassphrase)
	must(t, err)
	raw, _ := os.ReadFile(filepath.Join(dir, "user.key"))
	if id.String() != strings.TrimSpace(string(raw)) {
		t.Fatal("identity file decrypts to a different key")
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"empty":           ``,
		"not json":        `nope`,
		"unknown version": `{"version":2,"secrets":{}}`,
		"zero version":    `{"secrets":{}}`,
		"unknown field":   `{"version":1,"secrets":{},"extra":1}`,
		"trailing data":   `{"version":1,"secrets":{}} {}`,
		"bad name":        `{"version":1,"secrets":{"1x":{"value":"v","updated_at":"2026-01-01T00:00:00Z"}}}`,
		"NUL value":       `{"version":1,"secrets":{"X":{"value":"a\u0000b","updated_at":"2026-01-01T00:00:00Z"}}}`,
		"bad time":        `{"version":1,"secrets":{"X":{"value":"v","updated_at":"yesterday"}}}`,
		"wrong type":      `{"version":"1","secrets":{}}`,
		"secret unknown":  `{"version":1,"secrets":{"X":{"value":"v","updated_at":"2026-01-01T00:00:00Z","x":1}}}`,
	}
	for name, in := range cases {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Decode([]byte(`{"version":2,"secrets":{}}`)); err != ErrUnsupportedVersion {
		t.Errorf("version error = %v", err)
	}
}

func TestDecodeErrorsDoNotLeakInput(t *testing.T) {
	inputs := []string{
		`{"version":1,"secrets":{"X":{"value":"SECRETMARKER","updated_at":"bad"}}}`,
		`{"version":1,"secrets":{"SECRETMARKER":}}`,
		`{"version":1,"SECRETMARKER":1}`,
		`SECRETMARKER`,
	}
	for _, in := range inputs {
		_, err := Decode([]byte(in))
		if err == nil || strings.Contains(err.Error(), "SECRETMARKER") {
			t.Errorf("%q: error missing or leaks input: %v", in, err)
		}
	}
}

func TestDecodeMissingSecretsIsEmpty(t *testing.T) {
	v, err := Decode([]byte(`{"version":1}`))
	if err != nil || v.Secrets == nil || len(v.Secrets) != 0 {
		t.Fatalf("got %v, %v", v, err)
	}
}

func FuzzDecode(f *testing.F) {
	golden, _ := os.ReadFile(filepath.Join("testdata", "golden", "v1_basic.json"))
	for _, s := range [][]byte{
		golden,
		[]byte(`{"version":1,"secrets":{}}`),
		[]byte(`{"version":1,"secrets":{"A":{"value":"v","updated_at":"2026-01-01T00:00:00+02:00"}}}`),
		[]byte(`{"version":2}`),
		[]byte(`{`),
		nil,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Decode(data)
		if err != nil {
			return // leak-freedom of errors is covered by TestDecodeErrorsDoNotLeakInput
		}
		// Anything accepted must re-encode, and re-encoding must be stable.
		enc1, err := v.Encode()
		if err != nil {
			t.Fatalf("accepted input cannot be encoded: %v", err)
		}
		v2, err := Decode(enc1)
		if err != nil {
			t.Fatalf("encoded output rejected: %v", err)
		}
		enc2, _ := v2.Encode()
		if !bytes.Equal(enc1, enc2) {
			t.Fatalf("encoding not stable:\n%s\n%s", enc1, enc2)
		}
		for name := range v.Secrets {
			if ValidateName(name) != nil {
				t.Fatalf("invalid name survived decode")
			}
		}
	})
}

var nameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func FuzzValidateName(f *testing.F) {
	for _, s := range []string{"", "A", "1A", "a_b9", "é", "A\n", "a b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		want := nameRE.MatchString(name) && len(name) <= MaxNameLen
		// regexp's $ also matches before a trailing newline in some engines;
		// Go's does not, but check the oracle against the explicit rule too.
		if got := ValidateName(name) == nil; got != want {
			t.Fatalf("ValidateName(%q)=%v, oracle=%v", name, got, want)
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
