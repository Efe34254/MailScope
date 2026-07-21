# Third-party visual references

Provider marks are used only to identify their corresponding threat-intelligence services. All trademarks remain the property of their respective owners.

The compact provider-avatar presentation and the provider icon files in `apps/desktop/src/assets/providers` and `engine/assets/provider_icons` were sourced from the open-source OSINT Toolkit project for the user-requested interoperability-style presentation:

- Project: https://github.com/dev-lu/osint_toolkit
- License: GNU Affero General Public License v3.0

MailScope does not copy OSINT Toolkit application code or components. The provider images remain subject to the upstream project license and the trademark rights of their respective service owners.

The urlscan.io and CIRCL provider marks were obtained directly from their official service websites:

- urlscan.io: https://urlscan.io/img/urlscan_256.png
- CIRCL: https://www.circl.lu/assets/images/circl-logo.png

# Bundled static-analysis tools

MailScope v1.1.0 redistributes the following unmodified official Windows binaries so attachment triage works without separate system-wide installations:

- capa 9.4.0 — Apache License 2.0 — https://github.com/mandiant/capa
- FLOSS 3.1.1 — Apache License 2.0 — https://github.com/mandiant/flare-floss
- ExifTool 13.59 — licensed under the same terms as Perl — https://exiftool.org/

The corresponding license and upstream README files are included in `engine/tools/licenses`. Package source URLs and SHA-256 values are pinned in `engine/tools/manifest.json`. MailScope verifies the bundled executable hashes before every process lifetime and does not resolve these tools from the system `PATH`.

# Email-authentication libraries

MailScope v1.1.0 also packages the following Python libraries for DNS-backed email-authentication revalidation:

- dkimpy 1.1.8 — BSD-like license — https://launchpad.net/dkimpy
- pyspf 2.0.14 — Python Software Foundation License — https://github.com/sdgathman/pyspf
- dnspython 2.8.0 — ISC License — https://www.dnspython.org/
