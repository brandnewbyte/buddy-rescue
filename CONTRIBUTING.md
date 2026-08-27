# Contributing

Bug reports and focused pull requests are welcome. For security reports, use
the private process in [`SECURITY.md`](SECURITY.md).

Before submitting a change:

```shell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets --locked
```

Changes to encrypted data handling must remain compatible with the published
`buddy-crypto-core` vectors. Changes to plaintext output must update
`docs/export-format-v1.md` and add an integration test.

Never commit a real vault, export, password, key, or attachment. Test fixtures
must be synthetic and obviously non-production.

Unless explicitly stated otherwise, contributions are licensed under Apache
License 2.0 or MIT, at the contributor's option.

