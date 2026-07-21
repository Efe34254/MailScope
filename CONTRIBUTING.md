# Contributing to MailScope

Thank you for helping improve MailScope. Changes should preserve the project's
privacy-first, static-analysis security boundary.

## Before opening a change

- Open an issue for substantial behavior or data-model changes.
- Use synthetic email fixtures. Never commit real mailbox data, credentials,
  customer identifiers or malware samples.
- Keep full-email and attachment uploads disabled unless a separately reviewed
  design explicitly changes the product's privacy contract.
- Do not add dynamic execution to the desktop analysis engine.

## Development setup

Follow [INSTALL.md](INSTALL.md) for the Windows prerequisites and initial build.

Create a focused branch, make the change and run:

```powershell
.\engine\.venv\Scripts\python.exe -m pytest -q .\engine\tests
npm --prefix .\apps\desktop ci
npm --prefix .\apps\desktop run build
cargo check --locked --manifest-path .\apps\desktop\src-tauri\Cargo.toml
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-public-repo.ps1
```

Add or update tests for analyzer, risk-model, query-policy, report, backup or UI
behavior changes. Keep network-dependent behavior mocked in unit tests.

## Pull requests

A pull request should explain:

- what changed and why;
- user and security impact;
- tests performed;
- privacy or outbound-network effects;
- screenshots for UI changes, with sensitive values selectively redacted.

Keep generated build output, local databases, evidence workspaces, downloaded
tools and secrets out of commits. By contributing, you agree that your
contribution is licensed under the Apache License 2.0.
