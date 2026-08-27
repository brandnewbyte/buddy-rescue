# Buddy Rescue export format v1

This document describes output with the profile identifier
`buddy-rescue-export-v1`. It is a plaintext recovery format, not an encrypted
backup format.

## Directory

An export directory contains:

- `manifest.json`
- `entries.json` or `entries.csv`
- zero or more plaintext files below `attachments/`

All JSON is UTF-8, pretty-printed, and terminated by a newline. JSON object
member order is not significant. Timestamps are signed Unix timestamps in
seconds.

## `manifest.json`

The manifest identifies the tool and selected vault, names the entry file,
counts recovered and skipped entries, inventories attachments, and records any
per-record recovery issues.

```json
{
  "format": "buddy-rescue-export-v1",
  "tool": {
    "name": "buddy-rescue",
    "version": "0.1.0"
  },
  "exported_at": 1700000000,
  "vault": {
    "id": "vault-id",
    "name": "Personal",
    "color": "#445566",
    "version": 1,
    "created_at": 1690000000,
    "updated_at": 1695000000,
    "password_changed_at": 1690000000
  },
  "entries": {
    "path": "entries.json",
    "format": "json",
    "recovered": 12,
    "skipped": 0
  },
  "attachments": [],
  "issues": [],
  "warnings": []
}
```

Attachment `status` is one of:

- `recovered`
- `missing_metadata`
- `missing_ciphertext`
- `invalid_metadata`
- `authentication_failed`

`path` is present only for a recovered plaintext file. The manifest retains
the original ID, entry relationship, filename, MIME type, declared size, and
database timestamps where those values are available. Output filenames are
sanitized for cross-platform filesystem safety.

An issue contains `record_type`, `id`, and a non-secret diagnostic `message`.
The presence of an issue means the command exits with status 2.

## `entries.json`

The JSON document uses profile `buddy-rescue-entries-v1`:

```json
{
  "format": "buddy-rescue-entries-v1",
  "vault_id": "vault-id",
  "entries": []
}
```

Each entry combines cleartext database metadata with the authenticated,
decrypted entry payload:

```text
{
  "id": string,
  "created_at": integer,
  "updated_at": integer,
  "used_at"?: integer,
  "used_count": integer,
  "deleted_at"?: integer,
  "icon": string | null,
  "groups": EntryGroup[]
}
```

The `groups` contract, field roles, field values, history records, TOTP
configuration, and file references are defined in the
[Buddy vault format specification](https://github.com/brandnewbyte/buddy-crypto-core/blob/main/docs/vault-format-v1.md#entry-json-payload).
Unknown authenticated payload properties are preserved.

## `entries.csv`

CSV is UTF-8 with the following header:

```text
Title,Tags,Notes,Username,Password,URL,Two-Factor Secret,Cardholder Name,Card Number,Card Expiration,Card CVV
```

Rows use RFC 4180-style quoting as implemented by the Rust `csv` crate. Tags
are joined with `, `. TOTP configurations are emitted as `otpauth://` URIs.

CSV cannot preserve arbitrary groups, custom fields, SSH fields, history,
trash state, IDs, icons, or attachment references. Attachments are still
recovered and inventoried in `manifest.json`.

## Compatibility

A v1 reader must ignore unknown object properties. New optional properties may
be added without changing the profile identifier. Any incompatible structural
change requires a new profile identifier and a new document.

