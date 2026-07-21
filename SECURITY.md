# Security policy

## Supported versions

Security fixes are developed for the current `1.1.x` line and the latest
commit on `main`. Older snapshots are not supported.

## Reporting a vulnerability

Do not report security vulnerabilities in a public issue. Use GitHub's private
[security advisory form](https://github.com/Efe34254/MailScope/security/advisories/new).

Include:

- the affected version or commit;
- the component and preconditions;
- reproducible steps using synthetic or safely redacted data;
- the expected and observed security boundary;
- suggested mitigations, if known.

Do not attach real emails, credentials, API keys, malware samples, customer
data or device-specific logs. Prefer hashes and minimal synthetic fixtures.

An initial acknowledgement is targeted within seven calendar days. Timing for
validation, remediation and disclosure depends on severity and reproducibility.

## Security boundaries

MailScope performs static analysis. It parses untrusted email and attachment
formats but does not intentionally execute attachment content. A finding of
"clean" or "no match" is not a guarantee that a file is safe.

Online lookups are restricted by per-indicator query policy. The application
does not automatically upload complete emails or attachments. Dynamic malware
execution belongs in a separately administered, isolated sandbox environment.

Official Windows binaries must be code-signed and accompanied by SHA-256
checksums. Until such a release exists, treat locally built executables as
development artifacts.

## Public-repository hygiene

Contributions must not contain:

- `.eml`, database, backup or extracted-evidence files;
- API keys, tokens, passwords or certificate material;
- absolute workstation paths or user identifiers;
- screenshots containing unredacted message or indicator values.

The continuous-integration workflow runs `scripts/check-public-repo.ps1` to
enforce the most important repository-level checks.
