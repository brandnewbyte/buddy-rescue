# Buddy Rescue

Buddy Rescue is the standalone recovery utility for
[Buddy Password Manager](https://pwbuddy.com). It inspects, decrypts, and
exports a Buddy vault without the desktop application, a Buddy account, or a
network connection.

The tool is deliberately narrow:

- `inspect` validates a Buddy SQLite database and lists every vault it contains
  without asking for a password.
- `export` authenticates one vault's master password and writes a documented
  JSON or CSV export, including recoverable attachments.

Buddy Rescue opens the source database read-only. It does not run migrations,
change vault settings, or write beside the source database.

## Install

Prebuilt releases will be published on the
[GitHub releases page](https://github.com/brandnewbyte/buddy-rescue/releases).
To build the current source:

```shell
cargo build --release --locked
```

The binary is `target/release/buddy-rescue` on macOS and Linux, and
`target\release\buddy-rescue.exe` on Windows.

## Inspect a database

```shell
buddy-rescue inspect /path/to/buddy.sqlite
```

Inspection reports SQLite integrity, schema compatibility, vault IDs and
versions, KDF parameters, live and trashed entry counts, and whether each
attachment ciphertext file is present.

Use `--json` for a machine-readable report:

```shell
buddy-rescue inspect /path/to/buddy.sqlite --json
```

## Export a vault

A database may contain more than one vault. Inspect it first, then pass the
exact vault ID:

```shell
buddy-rescue export /path/to/buddy.sqlite \
  --vault 11111111-1111-4111-8111-111111111111 \
  --format json \
  --output buddy-export
```

When the database contains one vault, `--vault` is optional. The master
password is read from a hidden prompt and is never accepted as a command-line
argument. For controlled automation, `--password-stdin` reads one password
line exactly, removing only its line ending:

```shell
password-source |
  buddy-rescue export /path/to/buddy.sqlite --password-stdin
```

The default attachment tree is `attachments/` beside the SQLite file:

```text
data/
├── buddy.sqlite
└── attachments/
    └── <vault_id>/
        └── <blob_id>
```

For a copied database or backup, point to the original tree explicitly:

```shell
buddy-rescue export backup.sqlite --attachments /path/to/attachments
```

An existing destination is refused. `--force` replaces it only when its
`manifest.json` identifies it as a prior Buddy Rescue export; unrelated paths
and symlinks are never removed.

## Export contents

Every export is a directory:

```text
buddy-export/
├── manifest.json
├── entries.json              # or entries.csv
└── attachments/
    └── <blob_id>/
        └── <original_filename>
```

JSON is the full-fidelity recovery format. It preserves entry and group IDs,
all field shapes and roles, password history, usage timestamps, trash state,
icons, and attachment references.

CSV uses the same 11-column compatibility shape as Buddy's desktop exporter.
It is convenient for migration to other password managers, but it omits data
that cannot be represented in those columns. Use JSON when preserving all
data matters.

Buddy Rescue attempts every independently authenticated record. If one entry
or attachment is missing, malformed, or fails authentication, it is not
exported; the other records are still recovered and the problem is recorded
in `manifest.json`.

The complete output contract is in
[`docs/export-format-v1.md`](docs/export-format-v1.md). The encrypted vault
contract is maintained by
[`buddy-crypto-core`](https://github.com/brandnewbyte/buddy-crypto-core/blob/main/docs/vault-format-v1.md).

## Exit status

| Status | Meaning |
| --- | --- |
| `0` | Inspection passed, or every requested record was exported |
| `1` | The command could not run, credentials were rejected, or no export was written |
| `2` | Inspection found incompatibility/damage, or an export completed with record issues |

## Security boundary

Buddy Rescue contains no licensing, updater, analytics, browser integration,
or application UI code. Its runtime has no networking feature. Cryptographic
operations come from the pinned public `buddy-crypto-core` revision.

Recovered JSON, CSV, and attachments are plaintext secrets. On Unix, Buddy
Rescue creates export files with owner-only permissions; storage, backup, and
secure deletion remain the operator's responsibility.

This project and `buddy-crypto-core` have not yet completed an independent
third-party security audit. See [`SECURITY.md`](SECURITY.md) to report a
vulnerability.

## Development

```shell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets --locked
```

Tests synthesize their own small, low-cost vaults. They do not contain or read
real credentials.

## License

Licensed under either Apache License 2.0 or the MIT license, at your option.
