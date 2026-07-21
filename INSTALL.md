# Building and installing MailScope

MailScope is a Windows-only desktop application. Until a signed binary release
is published, build it from source on a trusted Windows workstation.

## Supported environment

- Windows 10 version 1803 or later, or Windows 11, x64
- PowerShell 5.1 or later
- Microsoft Edge WebView2 Runtime
- Microsoft C++ Build Tools with **Desktop development with C++**
- Rust stable with the `x86_64-pc-windows-msvc` toolchain
- Node.js 22 LTS version 22.12.0 or later and npm
- Python 3.13 x64
- Winget is optional; the setup script can use it to install Python 3.13 when
  Python is missing
- Internet access during setup for pinned Python, npm, Cargo and SOC-tool
  dependencies

The Microsoft C++ Build Tools and WebView2 requirements come from Tauri's
Windows toolchain. WebView2 is normally already present on supported Windows
10 and Windows 11 systems.

## Build from source

1. Clone or download the repository into a clean directory.
2. Open a normal PowerShell or File Explorer session. Administrator rights are
   not required for the current-user installer.
3. Run `Build-MailScope.cmd`.
4. The script performs the following operations:
   - locates or installs Python 3.13;
   - downloads capa, FLOSS and ExifTool from their pinned official sources;
   - verifies downloaded archives and executable SHA-256 hashes;
   - creates `engine\.venv` and installs pinned Python dependencies;
   - runs the Python test suite;
   - installs the locked npm dependencies;
   - builds the Python analysis engine and Tauri desktop application;
   - creates the NSIS installer and portable ZIP under `output\`;
   - creates `SHA256SUMS.txt` and `release-manifest.json`.
5. When the build succeeds, the local installer opens automatically.

Detailed output is written to `build-log.txt`.

## Development mode

After the initial setup:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1
```

The desktop application and local analysis engine are started together. Do not
run development mode against untrusted production evidence.

## Local validation

Run the same major checks used by continuous integration:

```powershell
Push-Location .\engine
& .\.venv\Scripts\python.exe -m pytest -q
Pop-Location
npm --prefix .\apps\desktop ci
npm --prefix .\apps\desktop run build
.\scripts\check-rust.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-public-repo.ps1
```

The bundled-tool integrity test requires the verified tools created by
`scripts\download-soc-tools.ps1`.

## Code signing and public distribution

Local builds are unsigned unless `MAILSCOPE_SIGN_CERT_THUMBPRINT` references a
valid code-signing certificate in the current user's Windows certificate
store. Unsigned executables are suitable only for local development and must
not be represented as an official MailScope release.

The tag-based GitHub workflow refuses to publish a release when its signing
certificate secrets are absent. See [docs/RELEASING.md](docs/RELEASING.md).

## Uninstall and local data

Uninstall MailScope through Windows **Installed apps**. Analysis history,
settings and evidence workspaces are stored separately from the program files.
Use the application's retention, backup and deletion controls before uninstall
if that local data also needs to be exported or removed.

## Troubleshooting

- Restart PowerShell after installing Python, Node.js, Rust or Build Tools so
  the updated PATH is visible.
- Confirm `rustup default stable-msvc` selects the MSVC toolchain.
- If the Tauri window cannot start, install or repair Microsoft Edge WebView2
  Runtime.
- If a SOC tool fails verification, do not bypass the check. Remove only that
  tool's downloaded directory and run the build again.
- Review `build-log.txt` before opening an issue. Remove local paths, usernames,
  email content, API keys and analysis evidence from any shared log.
