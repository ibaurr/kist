# Contributing

kist is meant to be audited in one sitting. Two rules protect that.

1. **Dependency cap: three direct dependencies** — `filippo.io/age`,
   `golang.org/x/term`, `golang.org/x/sys`. CI (`scripts/check-deps.sh`) fails on
   anything else. Justify any proposed addition in the PR description.
2. **Size budget: about 4,000 lines of Go, excluding tests.** If a change blows
   through it, something is being over-built.

Also:

- All cryptography goes through `internal/crypto` and `filippo.io/age`. Never
  invent a primitive or a KDF; if a requirement seems to need one, open an issue.
- No network code outside the agent's Unix-socket code (`scripts/check-no-net.sh`).
- Secrets never appear in argv, logs, errors, panics or test output. A test that
  prints a secret value is a failing test.
- Run before pushing: `go vet ./... && go test -race ./...`, and the fuzz targets
  you touched, e.g. `go test ./internal/vault -run '^$' -fuzz '^FuzzDecode$' -fuzztime 30s`.
- Changing the vault format means regenerating the golden vectors on purpose
  (`go test ./internal/vault -run Golden -update`) and explaining why in the PR.
