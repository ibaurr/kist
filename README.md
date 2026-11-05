# kist

A single static binary that keeps your secrets in an age-encrypted file.
No server, no account, no cloud.

> **Status: work in progress (milestone 1 of 3).** The vault, `init`,
> `set/get/list/delete`, `import/export` and recovery work. `run`, the session
> agent and the shell hook are not built yet. Not ready for real secrets.

```sh
go install github.com/ibaurr/kist/cmd/kist@latest

kist init                 # passphrase + one-time recovery key
kist set GITHUB_TOKEN     # hidden prompt; values are never arguments
kist list
kist get GITHUB_TOKEN
```

If you forget your passphrase **and** lose the recovery key, the vault is
unrecoverable. That is by design.

See [DESIGN.md](DESIGN.md) for file formats and decisions, and
[CONTRIBUTING.md](CONTRIBUTING.md) for the dependency cap and size budget. The
threat model, security policy and benchmarks arrive in milestone 3. Linux and
macOS only; requires Go 1.26+ to build.

MIT licensed.
