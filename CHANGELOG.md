# Changelog

All notable changes to MailScope are documented in this file. The project uses
semantic versioning for application releases.

## [Unreleased]

### Added

- Apache License 2.0 and public-project governance documentation.
- Windows continuous integration for privacy checks, verified SOC tools,
  Python tests, frontend builds and Rust checks.
- A tag-based, code-signing-gated draft release workflow.
- Detailed source-build and security reporting documentation.
- Public npm dependency metadata and a hygiene check that rejects internal
  build-service hostnames.

## [1.1.0] - 2026-07-21

### Added

- Recursive, bounded static inspection for PDF, ZIP/GZIP, Office and OLE
  embedded content.
- Managed and integrity-checked YARA rule packs with custom-rule lifecycle
  controls.
- Bundled capa, FLOSS and ExifTool support with pinned hashes.
- DNS-backed DKIM, SPF and DMARC revalidation.
- Privacy-controlled online reputation providers and hashed audit records.
- Case workflow, reports, backups, retention controls and duplicate-analysis
  prevention.
- Selectively redacted interface gallery in the project README.

### Security

- Static-analysis workers use time, memory, output and extraction limits.
- Complete email and attachment uploads remain disabled.
- This source version has no official signed binary release yet.
