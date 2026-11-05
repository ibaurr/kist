# kist: Product Requirements Document

**Status:** v0.1 scope, ready for implementation **Language:** Go (1.22+) **Audience:** Claude Code, working in an empty repository **Goal of the project:** an open-source credibility builder. Optimize for code that a skeptical reader can audit in one sitting, not for features or adoption.

## 1. One-line pitch

`kist` is a single static binary that keeps your secrets in an age-encrypted file and injects them into commands or your shell on demand. No server, no account, no cloud. The whole crypto path is small enough to read in 20 minutes.

## 2. Name

**kist** (Scots for "chest"). Four letters, easy to type, unlikely to be mistaken for an existing tool. Binary name `kist`, module path `github.com/<owner>/kist`, manifest file `.kist`.

Before the first commit, check that the name is free on GitHub, pkg.go.dev, Homebrew and crates/npm (for the squatting risk only). Fallbacks if it is taken: `strongroom`, `muniment`.

## 3. Positioning (read this before building)

This space is crowded, so "it exists" is not the pitch. A scan of GitHub and package registries in October 2026 found, among others: **Tene** (Go, local-first, encrypted SQLite, `tene run`, optional paid cloud sync), **envsecrets** (Go, AES-256-GCM, Argon2id), **Envault** (git-backed, age/SOPS style, `run`/`exec`), **EnvSeal** (several unrelated projects), **HASP** (local broker for agent workflows). Established options: dotenvx, SOPS + age, direnv, Infisical, Doppler, 1Password CLI.

Therefore kist does **not** compete on capabilities. It competes on:

1. **Auditability.** Small codebase, one crypto library (age), no custom primitives, a written threat model.
2. **Zero infrastructure.** One binary, no account, no server, no sync.
3. **Good first five minutes.** `init` to first injected secret in under a minute.
4. **Honesty.** The README states exactly what it does and does not protect against.

If a design choice trades any of these for a feature, choose the first four.

## 4. Goals and non-goals

### Goals (v0.1)

- Encrypted local secret store with `set`, `get`, `list`, `delete`.
- `run` to execute a command with secrets injected as environment variables.
- Passphrase unlock with an in-memory session agent (default 8 hours) so the passphrase is not re-prompted.
- Recovery key generated at `init`.
- Shell hook (bash, zsh, fish) for direnv-style auto-injection driven by a `.kist` manifest, with an allow-list for safety.
- Visible quality signals: tests, fuzzing, CI, signed releases, threat model.

### Non-goals (v0.1, and probably forever)

- Sync, servers, teams, access control, key rotation across people. (Future idea: commit the encrypted file to a git repo and add recipients. Not in scope.)
- SQLite or SQLCipher. A single encrypted file is simpler and easier to audit.
- Windows support.
- A GUI, browser extension, or cloud product.
- Defending against malware already running as the user, or a compromised kernel. State this plainly.

## 5. Users and use cases

- **Solo developer** with API keys for several projects who currently keeps them in plaintext `.env` files.
- **Small team member** who wants local secrets encrypted at rest and is fine sharing via their own channel for now.
- **Skeptical security-minded developer** who will read the source before trusting it. This is the real target audience.

## 6. Threat model (must ship as `THREAT_MODEL.md`)

**Protects against**

- Stolen or lost laptop (disk is encrypted at the file level; session agent is memory-only).
- Accidental commit of secrets (they never live in project files).
- Secrets leaking through shell history and process lists (values are never accepted on argv).
- Casual disk inspection or backups that include the home directory.

**Does not protect against**

- Malware or any process running as the same user while the agent is unlocked. The agent trusts same-UID peers, exactly like ssh-agent.
- Child processes you launch with secrets: they receive them in their environment by design.
- Interactive shell hook mode exposes injected variables to every process started from that shell. Prefer `kist run` for sensitive work.
- Memory forensics. Go cannot guarantee zeroing of secrets due to its garbage collector; mitigations are best effort.
- A malicious `.kist` file in a cloned repo, **unless** the user has not run `kist allow` (see section 9).

## 7. Architecture

```
cmd/kist/            main, subcommand dispatch (stdlib flag, no CLI framework)
internal/crypto/     thin wrapper over filippo.io/age (the only crypto code)
internal/vault/      vault format, load/save, atomic writes, backup
internal/agent/      session agent: socket server and client
internal/manifest/   .kist parser
internal/allow/      allow-list for manifests
internal/hook/       shell hook script generation
internal/ui/         hidden prompts, TTY detection, output helpers
```

**Dependencies (hard cap of 3 direct):** `filippo.io/age`, `golang.org/x/term`, `golang.org/x/sys`. No CLI framework, no logging framework, no YAML. Justify any addition in the PR description.

**Size budget:** at most roughly 4,000 lines of Go excluding tests. If it grows past that, something is being over-built.

## 8. Cryptographic design

All cryptography comes from age. kist writes no primitives and no custom KDF.

- **Identity:** at `init`, generate an age X25519 identity. Store it at `$XDG_CONFIG_HOME/kist/identity.age` (default `~/.config/kist/identity.age`), encrypted with the user's passphrase using age's scrypt recipient. File mode 0600.
- **Vault:** a single file at `$XDG_DATA_HOME/kist/vault.age` (default `~/.local/share/kist/vault.age`), mode 0600, age-encrypted to **two** recipients: the user's X25519 recipient and a **recovery** X25519 recipient.
- **Recovery key:** generated at `init`, printed once to the terminal with a clear warning, never stored on disk. Only its public recipient is kept (inside the vault header metadata or in the config dir). `kist recover` takes the recovery identity, decrypts the vault, creates a new identity with a new passphrase, and re-encrypts to the new recipient plus the same recovery recipient.
- **Passphrase forgotten and no recovery key:** the vault is lost. Say so in `init` output and in the README.
- **Plaintext format inside the vault:** UTF-8 JSON, `{"version":1,"secrets":{"NAME":{"value":"...","updated_at":"RFC3339"}}}`. Reject unknown versions with a clear error.
- **Atomic writes:** write to a temp file in the same directory, fsync, rename over the target, fsync the directory. Keep one previous copy as `vault.age.bak`.
- **Names:** secret names must match `^[A-Za-z_][A-Za-z0-9_]*$` so they are valid environment variable names.

Note: the original idea mentioned Argon2. Using age's scrypt passphrase mode instead keeps the crypto surface to one reviewed library. Do not add Argon2.

## 9. CLI specification

General rules: secret values are **never** accepted as command-line arguments. Prompts read from the TTY with echo disabled; `--stdin` reads from standard input for scripting. Errors go to stderr, data to stdout. Exit code 0 on success, non-zero on failure. No telemetry, no network calls, ever.

| Command | Behavior |
| --- | --- |
| `kist init` | Create identity and empty vault, prompt for passphrase twice, print the recovery key once. Refuse if a vault exists. |
| `kist set NAME` | Prompt for value (hidden), or `--stdin`. Creates or updates. |
| `kist get NAME` | Print the value to stdout with no trailing decoration. Non-zero exit if missing. |
| `kist list` | Print names, one per line, with `--long` adding updated\_at. Never prints values. |
| `kist delete NAME` | Remove a secret. |
| `kist run [--only A,B] -- CMD [ARGS]` | Exec CMD with secrets injected. If a `.kist` manifest applies (and is allowed), inject its keys; otherwise require `--only` or `--all`. Uses exec so signals and exit codes pass through. |
| `kist import FILE` | Import `KEY=VALUE` lines from a `.env` file. Prints a reminder to delete the plaintext file. |
| `kist export` | Print `KEY=VALUE` lines to stdout. Requires `--yes` when stdout is a TTY. |
| `kist unlock` / `kist lock` | Prompt for passphrase and start the agent session / zero and stop it. |
| `kist status` | Show whether the agent is running and time remaining. |
| `kist recover` | Recover using the recovery key and set a new passphrase. |
| `kist allow [PATH]` / `kist deny [PATH]` | Approve or revoke a `.kist` manifest. |
| \`kist hook bash | zsh |
| `kist version` | Print version, commit, Go version. |

Commands that need the identity use the agent if running; otherwise they prompt for the passphrase and, on success, start the agent.

## 10. Session agent

- **Process model:** `kist agent` runs as a background process started on first unlock (fork/exec of the same binary with an internal flag). It holds the decrypted age identity in memory only.
- **Socket:** Unix domain socket in a directory with mode 0700. Linux: `$XDG_RUNTIME_DIR/kist/agent.sock`. macOS: `$TMPDIR/kist-<uid>/agent.sock`. Socket mode 0600.
- **Peer authentication:** verify the connecting peer's UID equals the agent's UID using SO\_PEERCRED (Linux) or LOCAL\_PEERCRED (macOS). Reject otherwise.
- **Protocol:** newline-delimited JSON requests and responses. Operations: `status`, `get` (list of names, returns only those values), `decrypt` (returns the full plaintext vault, used by write commands), `lock`.
- **Statelessness:** the agent reads the vault file from disk on each request, so edits by other kist invocations are always seen.
- **Lifetime:** absolute TTL, default 8 hours, configurable via `KIST_SESSION_TTL`. On expiry or `lock`, zero key material best effort, remove the socket, exit.
- **Hardening:** disable core dumps (`setrlimit RLIMIT_CORE 0`), set non-dumpable on Linux (`prctl PR_SET_DUMPABLE 0`), `mlock` where permitted (best effort, never fatal), refuse to run as root unless `--allow-root`.

## 11. Shell hook and manifest

**Manifest `.kist`:** plain text, one entry per line. `NAME` injects secret NAME as env var NAME. `ENV_VAR=NAME` maps a differently named secret. Lines beginning with `#` and blank lines are ignored. The parser must be strict, bounded in size (e.g. 64 KiB), and fuzzed.

**Discovery:** nearest `.kist` walking up from the current directory, stopping at the home directory or filesystem root.

**Allow-list (security-critical):** a manifest only takes effect if its absolute path and content hash appear in `$XDG_STATE_HOME/kist/allow` (created by `kist allow`). If the manifest changes, it must be re-allowed. Rationale: otherwise a cloned repository could pull secrets into your shell environment, where a malicious script could exfiltrate them. This mirrors `direnv allow`.

**Hook behavior:**

1. The shell function runs on directory change.
2. It first does a pure-shell walk up the tree looking for `.kist`. If none is found and nothing is currently loaded, it returns immediately without executing the binary. This keeps ordinary `cd` free.
3. If a manifest is found and allowed, it calls `kist hook-load`, which asks the agent for the listed keys and prints shell-safe `export` statements.
4. When leaving the directory tree, the hook unsets exactly the variables it set.
5. If the agent is locked, the hook prints a one-line notice to stderr and does not prompt.

Supported shells: bash, zsh, fish. Use proper quoting for values containing quotes, newlines or shell metacharacters (test this heavily).

**Performance budget:** no manifest in the tree: under 1 ms overhead, no process spawn. Manifest present, warm agent: p95 under 30 ms end to end. Add a benchmark script and publish the numbers in the README.

## 12. Security requirements (acceptance gates)

- Secret values never appear in argv, logs, error messages, panics or crash output.
- No network access anywhere in the codebase. CI check: fail if `net/http` or `net` dialing is imported outside the agent's Unix socket code.
- All files and directories created with the minimum permissions (0600 files, 0700 directories); verify and test.
- Constant-time handling is delegated to age; do not compare secrets manually.
- Do not log or print the recovery key anywhere except the single `init` display.
- `govulncheck` clean on every release.

## 13. Testing and quality

- Unit tests for vault round trips, atomic write failure paths, manifest parsing, allow-list, name validation.
- **Fuzz tests** for the manifest parser and the vault JSON decoder (`go test -fuzz`).
- Golden test vectors for the vault format so format changes are deliberate.
- Integration tests with a pseudo-terminal for hidden prompts, plus agent start/lock/expiry tests using a short TTL.
- Hook tests per shell (bash, zsh, fish) in CI, including quoting edge cases.
- CI (GitHub Actions) on Linux and macOS: `go vet`, `staticcheck`, `govulncheck`, race detector, tests, fuzz smoke run.

## 14. Distribution and release

- goreleaser producing static binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64.
- Checksums and signatures (cosign keyless), SBOM attached to releases.
- Homebrew tap and `go install github.com/<owner>/kist/cmd/kist@latest`.
- License: MIT or Apache-2.0.
- Reproducible build instructions in the README.

## 15. Documentation deliverables

- `README.md`: pitch, 60-second quickstart, honest comparison table, benchmark numbers, link to threat model.
- `THREAT_MODEL.md`: section 6 expanded.
- `DESIGN.md`: file formats, agent protocol, and a "what I deliberately left out and why" section (sync, SQLite, Windows, GUI).
- `SECURITY.md`: how to report vulnerabilities.
- `CONTRIBUTING.md`: the dependency cap and size budget.

## 16. Milestones

**Week 1: core.** Repo scaffold, CI, crypto wrapper, vault format with golden vectors, `init`, `set/get/list/delete`, `import/export`, recovery flow, tests and fuzzing for the vault.

**Week 2: runtime.** `run`, session agent with peer auth and TTL, `unlock/lock/status`, hardening, agent tests.

**Week 3: shell integration and polish.** Manifest parser, allow-list, hook for bash/zsh/fish, benchmarks, goreleaser and signing, README, threat model, design doc.

**Ship v0.1.** Then stop. Afterward only security fixes and issue triage.

## 17. Definition of done for v0.1

- A new user can install, run `kist init`, `kist set X`, and `kist run -- env | grep X` in under one minute.
- Every acceptance gate in section 12 passes in CI.
- Hook latency numbers are measured and published.
- Direct dependencies: exactly the three listed. Go code under about 4,000 lines excluding tests.
- `THREAT_MODEL.md`, `DESIGN.md` and `SECURITY.md` exist and match the implementation.
- A third party could read `internal/crypto`, `internal/vault` and `internal/agent` and understand the trust boundaries without running the code.

## 18. Open questions (decide during build, record in DESIGN.md)

- Namespaces or per-project vaults in v0.2? v0.1 uses one flat vault.
- Should `kist get` warn when stdout is a TTY? (Leaning yes, with a `--quiet` flag.)
- Should the agent also support an idle timeout in addition to the absolute TTL?

## 19. Instructions for Claude Code

- Work milestone by milestone. At the end of each milestone, run the full test suite and summarize what was built and what was deferred.
- Prefer boring, standard-library solutions. Ask before adding any dependency beyond the three listed.
- Never invent cryptography. If a requirement seems to need a new primitive, stop and flag it.
- Write tests alongside code, not afterward. Treat any test that prints a secret value as a failure.
- Keep functions small and comments focused on *why*, since the goal is a codebase a stranger can audit.
