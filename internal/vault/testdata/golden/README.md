# Golden vectors for vault format v1

These files pin the on-disk format. **Every key in this directory is a
throwaway test key with no value; never use them for anything real.**

| File | What it pins |
| --- | --- |
| `v1_basic.json` | Canonical plaintext encoding (compact JSON, sorted keys, UTC timestamps) |
| `v1_basic.age` | The `v1_basic.json` vault encrypted to *both* `user.key` and `recovery.key` |
| `identity_v1.age` | `user.key` encrypted with passphrase `golden-test-passphrase` (scrypt) |

`TestEncodeGolden`, `TestGoldenCiphertext` and `TestGoldenIdentityFile` fail if
the format drifts. If a change is deliberate, bump the vault `version` (or note
the reason in the commit) and regenerate with:

    go test ./internal/vault -run Golden -update

then review the diff by hand.
