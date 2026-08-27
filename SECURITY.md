# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Send reports to `support@pwbuddy.com` with:

- the affected Buddy Rescue and `buddy-crypto-core` versions or commits;
- the operating system and architecture;
- a concise reproduction or proof of concept; and
- the impact you believe is possible.

Do not include real vault files, master passwords, recovered exports, or other
credentials. A synthetic reproducer is strongly preferred.

We will acknowledge a report as soon as practical, investigate it privately,
and coordinate disclosure when a fix is available.

## Scope

Security-sensitive areas include vault authentication and decryption, record
context binding, SQLite parsing, attachment path handling, plaintext output,
and accidental disclosure through diagnostics.

The published code has not yet completed an independent third-party audit.

