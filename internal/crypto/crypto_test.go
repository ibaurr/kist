package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func init() { PassphraseWorkFactor = 8 } // fast scrypt for tests

func mustID(t *testing.T) *Identity {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPassphraseRoundTrip(t *testing.T) {
	ct, err := EncryptWithPassphrase([]byte("payload"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptWithPassphrase(ct, "pw")
	if err != nil || string(pt) != "payload" {
		t.Fatalf("got %q, %v", pt, err)
	}
}

func TestWrongPassphrase(t *testing.T) {
	ct, _ := EncryptWithPassphrase([]byte("payload"), "right")
	_, err := DecryptWithPassphrase(ct, "wrong")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestEmptyPassphraseRejected(t *testing.T) {
	if _, err := EncryptWithPassphrase([]byte("x"), ""); err == nil {
		t.Fatal("empty passphrase accepted")
	}
}

func TestTwoRecipientsEitherDecrypts(t *testing.T) {
	user, recovery, other := mustID(t), mustID(t), mustID(t)
	ct, err := Encrypt([]byte("vault"), user.Recipient(), recovery.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]*Identity{"user": user, "recovery": recovery} {
		pt, err := Decrypt(ct, id)
		if err != nil || string(pt) != "vault" {
			t.Fatalf("%s: got %q, %v", name, pt, err)
		}
	}
	if _, err := Decrypt(ct, other); !errors.Is(err, ErrNotRecipient) {
		t.Fatalf("stranger: want ErrNotRecipient, got %v", err)
	}
}

func TestEncryptNeedsRecipients(t *testing.T) {
	if _, err := Encrypt([]byte("x")); err == nil {
		t.Fatal("expected error with zero recipients")
	}
}

func TestCorruptionDetected(t *testing.T) {
	id := mustID(t)
	ct, _ := Encrypt([]byte("some plaintext of reasonable length"), id.Recipient())

	if _, err := Decrypt([]byte("not an age file"), id); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("garbage: want ErrCorrupt, got %v", err)
	}
	// Flip a bit in the payload (last byte lies inside the final AEAD tag).
	bad := bytes.Clone(ct)
	bad[len(bad)-1] ^= 1
	if _, err := Decrypt(bad, id); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered: want ErrCorrupt, got %v", err)
	}
	// Truncation must not yield partial plaintext.
	if _, err := Decrypt(ct[:len(ct)-5], id); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
}

func TestIdentityStringRoundTrip(t *testing.T) {
	id := mustID(t)
	back, err := ParseIdentity(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if back.Recipient().String() != id.Recipient().String() {
		t.Fatal("recipient mismatch after round trip")
	}
	r, err := ParseRecipient(id.Recipient().String())
	if err != nil || r.String() != id.Recipient().String() {
		t.Fatalf("recipient round trip: %v", err)
	}
}

func TestParseErrorsDoNotEchoInput(t *testing.T) {
	const marker = "AGE-SECRET-KEY-1MARKERMARKERMARKER"
	_, err := ParseIdentity(marker)
	if err == nil || strings.Contains(err.Error(), "MARKER") {
		t.Fatalf("error missing or leaks input: %v", err)
	}
}

func TestWipe(t *testing.T) {
	b := []byte("secret")
	Wipe(b)
	if !bytes.Equal(b, make([]byte, 6)) {
		t.Fatal("not wiped")
	}
}
