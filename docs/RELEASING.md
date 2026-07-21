# Maintainer release process

MailScope Windows executables must be signed before public distribution. The
release workflow deliberately fails before building when the signing secrets
are unavailable.

## Required repository secrets

- `WINDOWS_SIGNING_CERTIFICATE_BASE64`: base64-encoded PFX certificate
- `WINDOWS_SIGNING_CERTIFICATE_PASSWORD`: PFX password

The certificate must be valid for Windows code signing. Store it only as an
encrypted GitHub Actions secret; never commit the PFX, password or thumbprint.

## Prepare a release

1. Update the version consistently in:
   - `apps/desktop/package.json` and `package-lock.json`;
   - `apps/desktop/src-tauri/Cargo.toml` and `tauri.conf.json`;
   - `scripts/build.ps1`;
   - `README.md` and `CHANGELOG.md`.
2. Run the full local validation in [INSTALL.md](../INSTALL.md).
3. Merge the version change into `main` and wait for CI to pass.
4. Create and push an annotated `vMAJOR.MINOR.PATCH` tag from that exact commit.
5. The `Signed Windows release` workflow imports the certificate temporarily,
   runs the verified build and creates a **draft** GitHub Release containing:
   - NSIS installer;
   - portable ZIP;
   - `SHA256SUMS.txt`;
   - `release-manifest.json`.
6. Download the draft assets on a clean Windows system. Verify Authenticode,
   checksums, installation, launch, uninstall and basic offline analysis.
7. Review generated release notes and publish the draft manually.

If certificate import, signature verification, tests, tool integrity or the
build fails, do not publish artifacts from that run.

## Certificate cleanup

The workflow removes the imported certificate and temporary PFX in an
`always()` cleanup step. GitHub-hosted runners are ephemeral, but cleanup is
kept explicit to minimize secret lifetime.
