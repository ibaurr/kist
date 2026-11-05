# kist design notes

Status: covers what exists after milestone 1 (core vault). The agent, shell hook
and "what I deliberately left out" sections are added with their milestones.

## Trust boundaries (milestone 1)

- `internal/crypto` is the only package that imports `filippo.io/age`. It exposes
  generate/parse for X25519 keys, passphrase (scrypt) encrypt/decrypt, and
  multi-recipient encrypt/decrypt. No primitives, no KDF, no framing of our own.
- `internal/vault` owns the plaintext document, the file envelope and atomic
  writes. It imports `crypto`, never `age`.
- `cmd/kist` handles prompts, flags and exit codes. Secrets arrive only through
  hidden TTY prompts or `--stdin`; never argv.

## Files

| File | Location | Mode | Contents |
| --- | --- | --- | --- |
| identity | `$XDG_CONFIG_HOME/kist/identity.age` (default `~/.config/kist/`) | 0600 | age X25519 secret key, encrypted with the user's passphrase (age scrypt recipient, work factor 18) |
| recovery recipient | `$XDG_CONFIG_HOME/kist/recovery.pub` | 0600 | the recovery key's *public* `age1...` recipient. The private key is shown once at `init` and never stored |
| vault | `$XDG_DATA_HOME/kist/vault.age` (default `~/.local/share/kist/`) | 0600 | age file encrypted to two recipients: the user's and the recovery recipient |
| backup | `vault.age.bak` | 0600 | the previous vault version (one copy) |
| lock | `vault.age.lock` | 0600 | empty; `flock` target serialising read-modify-write |

Directories are created 0700 and tightened if they pre-exist looser. Relative
`XDG_*` values are ignored, per the XDG spec.

### Vault plaintext, version 1

Compact UTF-8 JSON, map keys sorted, timestamps UTC at second precision:

```json
{"version":1,"secrets":{"NAME":{"value":"...","updated_at":"2026-01-02T03:04:05Z"}}}
```

- Names match `^[A-Za-z_][A-Za-z0-9_]*$`, at most 255 bytes.
- Values are valid UTF-8, contain no NUL, and are at most 64 KiB. (Invalid UTF-8
  would be silently rewritten by JSON; NUL cannot live in an environment.)
- Decoding rejects unknown fields, trailing data and any version other than 1.
  Decoding errors contain byte offsets only, never input.
- Golden vectors in `internal/vault/testdata/golden` pin the plaintext encoding,
  the two-recipient envelope and the identity file. Changing the format must
  change those files deliberately (`go test ./internal/vault -run Golden -update`).

### Atomic writes

Temp file in the destination directory (0600) → write → fsync → rename over the
target → fsync the directory. Before replacing the vault, the existing bytes are
copied to `vault.age.bak` by the same procedure. A failed dir fsync is reported,
not swallowed. Linux and macOS only; other platforms compile stubs for
development, with no durability or locking.

## Decisions made while building (PRD ambiguities)

- **Recovery recipient storage.** age files carry no custom metadata and the
  plaintext schema is fixed by the PRD, so the recovery recipient lives in
  `recovery.pub`. `kist recover` derives it from the key presented, so a lost or
  edited `recovery.pub` is repaired by recovering. Writes refuse to proceed
  without it rather than silently dropping the recovery recipient.
- **The user's own recipient is never stored in plaintext.** It is derived from
  the unlocked identity. Because age encryption is public-key, anyone who knew
  your recipient could forge a vault you would accept; keeping it secret removes
  that. (Anyone who can write the data directory can still delete or roll back
  the vault to an older valid copy; v0.1 does not defend against that.)
- **`recover` removes `vault.age.bak`.** The backup is encrypted to the identity
  being replaced; if recovery was triggered by a compromised passphrase, keeping
  it would defeat the point. The new vault is read back and verified first.
- **Recovery ordering.** The new identity is persisted before the vault is
  re-encrypted to it. A crash between the two leaves the old vault readable with
  the recovery key, so re-running `kist recover` always works. The recovery key
  itself cannot be rotated in v0.1.
- **`delete` is not a secure erase.** The deleted secret remains in
  `vault.age.bak` (still encrypted) until the next write replaces the backup.
- **Passphrase policy.** Only "non-empty and typed twice". scrypt makes guessing
  expensive, but a weak passphrase is still weak; the README should say so.
- **`init` safety.** It refuses if any of identity, recovery recipient or vault
  exists, writes the vault last, removes whatever it wrote on failure, and
  insists on an interactive terminal because the recovery key is shown once.
- **`get` output (open question 18).** Piped: exact bytes, no trailing newline.
  On a terminal: a newline and a scrollback warning on stderr, silenced by
  `--quiet`.
- **`--stdin` strips one trailing newline** (`\n` or `\r\n`), so `echo v | kist set
  X --stdin` stores `v`. Use `printf '%s'` for exact bytes.
- **No passphrase from environment or flags.** A passphrase in the environment is
  a secret in an inherited, inspectable place. Until the session agent exists,
  every command prompts on the terminal (about one scrypt unlock each).
- **Concurrent writers.** `flock` on `vault.age.lock` serialises
  read-modify-write across processes; atomic rename alone prevents corruption
  but not lost updates.

## `.env` dialect for import/export (`internal/envfile`)

```
# comment                      ignored, as are blank lines
NAME=value                     unquoted: trimmed, literal; " #" is an error
export NAME=value              optional prefix
NAME='literal'                 no escapes; may span lines
NAME="a\nb \"q\" \\ \t \r"     only these escapes; may span lines
```

Strict on purpose: unquoted `#` after whitespace, unknown escapes, duplicate
names, bad names and trailing junk are errors that cite a line number (never
the content). Import is all-or-nothing and refuses to replace existing names
without `--overwrite`. `export` writes the same dialect (plain values bare,
everything else double-quoted) and is fuzzed to round-trip. CRLF input is
normalised to LF, including inside quoted values.

## Known limitations

- Go strings cannot be zeroed. Byte buffers we own are wiped best-effort;
  decrypted values copied into strings are not. Do not rely on memory hygiene.
- Without the agent (milestone 2), each command pays one passphrase prompt.
- The only code not covered by an automated test is `ui.Terminal.Secret`
  (`/dev/tty` + `term.ReadPassword`); it needs a pseudo-terminal harness.

## Open questions (PRD section 18)

- Namespaces / per-project vaults: deferred to v0.2; v0.1 is one flat vault.
- `kist get` warning on a TTY: decided above.
- Agent idle timeout: decided with the agent in milestone 2.
