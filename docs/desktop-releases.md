# Veloce Desktop releases for Windows and macOS

Veloce Desktop is a click-to-use local interface for qSearch and the Veloce
cryptographic runtime. Double-clicking `Veloce.exe` on Windows or `Veloce.app`
on macOS starts a loopback-only UI and opens it in the default browser.

The UI provides:

- a folder picker and **Start qSearch** button;
- finding counts, risk classification, algorithm visualization, and a findings
  table;
- generated JSON, CSV, CycloneDX 1.6, M-23-02, workbook, and executive-summary
  reports under `Documents/Veloce Reports`;
- live Veloce agent status, FIPS module version and certificate, pre-load
  SHA-256 verification, module status, CAST results, local entropy verification
  counters, and PQC provider self-test state;
- an on-demand **Run self-tests** button;
- an Entropy page with streaming specifications and the cloud EMS mix-in
  toggle.

The interface does not perform cryptography. It invokes the native qSearch
binary and reads validation evidence from the local Veloce agent through the
native CLI.

## Interface design

The page follows the operating system light or dark appearance
(`color-scheme: light dark`) and uses the system type stack (SF Pro on macOS,
Segoe UI on Windows). Type scale: 13, 14, 15, 17, 24, and 30 px with
sentence-case labels. Surfaces and text stay neutral; the Lightrider gradient
palette is the accent:

| Token | Value | Use |
|---|---|---|
| `--lr-yellow` | `#fff802` | gradient start |
| `--lr-amber` | `#ffdc0c` | gradient stop |
| `--lr-orange` | `#fd8c27` | gradient stop, boundary notes |
| `--lr-red` | `#f82848` | gradient stop, focus rings |
| `--lr-crimson` | `#a72848` | gradient end |

The full gradient marks the brand ring, the active navigation indicator, and
metric card accents; the warm segment (orange to crimson) fills primary
buttons, progress bars, and the mix-in switch. State colors (good, warn, bad)
are reserved for live status values. Element IDs and CSS state classes are a
contract with `app.js` and are locked by `tests/test_windows_artifacts.py`.
The page ships no inline styles or scripts, so the Content Security Policy
stays `style-src 'self'; script-src 'self'`.

## Release modes

Every platform package has an embedded `release-manifest.json` and is built in
exactly one mode.

### Full runtime

A full-runtime release contains qSearch, the CLI, the platform-native agent,
the FIPS shared library, the PQC provider, and both build records. When the UI
cannot reach an existing agent, it starts the packaged agent for the current
user with EMS disabled and then obtains fresh runtime evidence.

The dashboard reports approved mode only when all of the following come from a
live agent response:

- FIPS library hash verified before loading;
- FIPS module status is zero;
- power-on and conditional algorithm self-tests passed;
- the Lightrider seed callback's SP 800-90B health tests on the configured
  seed source (CPU RDSEED by default) are passing;
- the FIPS DRBG is instantiated;
- the PQC provider self-test passed.

Recorded metadata alone never turns the dashboard green.

### Discovery only

A discovery-only release contains the UI, qSearch, and the CLI. qSearch is
fully usable, but the security dashboard displays **Agent unavailable** and
**No live data**. This mode is intended for desktop UI testing and standalone
cryptographic discovery; it makes no live FIPS claim.

The build must use the explicit `--discovery-only` option. A missing native
runtime never silently downgrades a requested full-runtime build.

## Native full-runtime input contract

Create a staging directory on the target operating system before running the
desktop packager.

Windows x86-64:

```text
runtime/
  bin/
    veloce-agent.exe
  lib/
    wolfssl-fips.dll              (named by wolfcrypt-fips.build-record.json)
    veloce-pqc.dll                (named by veloce-pqc.build-record.json)
    wolfcrypt-fips.build-record.json
    veloce-pqc.build-record.json
```

macOS x86-64 or arm64:

```text
runtime/
  bin/
    veloce-agent
  lib/
    <FIPS dylib named by wolfcrypt-fips.build-record.json>
    <PQC dylib named by veloce-pqc.build-record.json>
    wolfcrypt-fips.build-record.json
    veloce-pqc.build-record.json
```

The release builder rejects missing recorded libraries, invalid or mismatched
SHA-256 values, build records whose `operating_environment` does not name the
target platform and architecture, and PE/Mach-O inputs that do not contain the
requested native architecture. Both the FIPS and PQC build records are checked.
The agent independently verifies the library hashes again before loading them
through a restricted absolute-path loader.

The platform libraries and records must be produced and approved on the native
release machine (Windows: `docs/windows.md`; macOS: `docs/macos.md`). Never
rename a DLL/dylib without updating and regenerating its signed build record.

## Branding assets

`assets/branding/veloce.svg` is the single source for the mark (black disc,
Lightrider gradient ring, white V). `scripts/gen_branding.py` renders it with
Pillow into the committed binary assets, so release hosts need no image
tooling:

| Asset | Use |
|---|---|
| `veloce.ico` | `Veloce.exe` icon (PyInstaller `--icon`), Start Menu shortcut, Apps and features entry |
| `veloce.icns` | `Veloce.app` icon |
| `veloce-256.png` | documentation |
| `wix-banner.bmp` (493 x 58) | WixUI top banner |
| `wix-dialog.bmp` (493 x 312) | WixUI welcome and exit dialogs |
| `desktop/static/favicon.svg` | browser tab icon (byte-identical copy of `veloce.svg`) |

Rerun `python3 scripts/gen_branding.py` after changing the mark or palette and
commit the outputs; `tests/test_windows_artifacts.py` checks their formats and
dimensions.

## Windows build

Requirements on Windows x86-64:

- Python 3 and PyInstaller;
- Rust with the stable MSVC toolchain;
- WiX Toolset 5.0.2 (`dotnet tool install --global wix --version 5.0.2`)
  for MSI output. The `Files` harvesting element in
  `installer/windows/veloce.wxs` requires v5; WiX v7 and later require
  accepting the Open Source Maintenance Fee EULA before use, so the tool is
  pinned and the build script refuses other major versions. The script adds
  the matching `WixToolset.UI.wixext` and `WixToolset.Util.wixext`
  extensions;
- the Windows SDK `signtool.exe` when signing;
- the approved native runtime directory for a full-runtime package.

Install the desktop build dependency:

```powershell
python -m pip install -r desktop\requirements-build.txt
```

Build the full portable ZIP and MSI:

```powershell
.\installer\windows\build-release.ps1 `
    -Version 1.2.0 `
    -RuntimeDir C:\secure\veloce-runtime-windows-x86_64
```

Build an explicitly labeled qSearch/UI preview:

```powershell
.\installer\windows\build-release.ps1 `
    -Version 1.2.0 `
    -DiscoveryOnly `
    -SkipMsi
```

Sign a distribution build with the Lightrider Authenticode certificate
(SHA-1 thumbprint from the certificate store):

```powershell
.\installer\windows\build-release.ps1 `
    -Version 1.2.0 `
    -RuntimeDir C:\secure\veloce-runtime-windows-x86_64 `
    -CertificateThumbprint <thumbprint>
```

Signing covers `Veloce.exe`, the bundled Rust executables, the agent, and the
final MSI. Files under `lib\` are never signed: they are the hash-recorded
FIPS module and PQC provider, and rewriting them breaks the recorded SHA-256
and the module's in-core integrity check.

Outputs:

```text
build/dist/veloce-1.2.0-windows-x86_64.zip
build/dist/veloce-1.2.0-windows-x86_64.msi
build/dist/SHA256SUMS-windows-x86_64.txt
```

The MSI installs under `Program Files\Veloce`, adds a **Veloce Desktop** Start
Menu shortcut with the Veloce icon, registers the icon and description in
Apps and features, and shows the license (rendered from `LICENSE` at build
time) and install-directory dialogs with Lightrider artwork. The checksum
file is `sha256sum -c` compatible.

Two workflows build Windows packages in CI (`.github/workflows/`):
`Desktop discovery release` produces workflow artifacts for testing, and
`Release` (tag push `v*` or manual dispatch) builds the Windows ZIP and MSI
and the macOS DMG, then attaches them with checksums and the Windows quick
start to a draft GitHub Release for the owner to publish. End users then
download and run without building (`docs/windows-quickstart.md`). The exit
dialog of the MSI offers to launch Veloce Desktop.

## macOS build

Requirements on the target macOS architecture:

- Python 3 and PyInstaller;
- Rust;
- Xcode command-line tools;
- the approved native runtime directory for a full-runtime package.

```bash
python3 -m pip install -r desktop/requirements-build.txt
```

Build a full arm64 app and DMG:

```bash
export VELOCE_CODESIGN_IDENTITY="Developer ID Application: Lightrider Inc (TEAMID)"
export VELOCE_NOTARY_PROFILE="lightrider-notary"

installer/macos/build-release.sh \
    --version 1.2.0 \
    --arch arm64 \
    --runtime-dir /secure/veloce-runtime-macos-arm64
```

For Intel macOS, use `--arch x86_64` and build on an x86-64 Python/Rust host.
The builder fails if `--arch` does not match the native build host, preventing
an app label from disagreeing with its bundled Rust executables.
For an explicitly labeled UI preview, replace `--runtime-dir ...` with
`--discovery-only`. The app bundle carries `assets/branding/veloce.icns`.

Output:

```text
build/dist/veloce-1.2.0-macos-arm64.dmg
```

When `VELOCE_CODESIGN_IDENTITY` is absent, the script creates an ad-hoc signed
development app. Set both signing variables for a distribution build; the
script signs the app and DMG, submits the DMG with `notarytool`, and staples the
ticket.

## Agent build portability

`agent/CMakeLists.txt` builds the same agent sources with platform-native FIPS
and PQC header sets:

```bash
cmake -S agent -B build/agent-native \
    -DVELOCE_FIPS_INCLUDE=/secure/native-fips-headers \
    -DVELOCE_PQC_INCLUDE=/secure/native-pqc-headers
cmake --build build/agent-native --config Release
```

The agent uses authenticated UNIX-domain sockets on Linux/macOS and the
`\\.\pipe\LightRider.PQC.v1` byte-mode named pipe with a protected, local-only
ACL on Windows. Shared libraries are loaded by absolute path with restricted
search semantics after SHA-256 verification.

## Current certification boundary

The source and packaging paths are implemented, but a distributable green
full-runtime package still requires approved native wolfSSL object code and an
operating-environment record for that exact platform and architecture.

- Windows: wolfSSL confirmed (2026-08-27) that the FIPS module is built as a
  DLL from `IDE/WIN10/wolfssl-fips.sln` (`DLL Release|x64`) with the
  vendor-supplied v5.2.1 `user_settings.h`, and that testing of the
  Windows 11 Pro (i7-1260P) OE is complete and awaiting publication on
  certificate #4718. A full-runtime package may be built and validated
  internally (`docs/windows.md`), but until the certificate and Security
  Policy list the OE, Windows packages carry `pending_publication` and no
  validated-deployment claim.
- macOS: no #4718 macOS operating environment or approved FIPS dylib is recorded
  in this repository. A macOS package may provide qSearch, but must remain
  discovery-only unless a separately approved native module and build record
  are supplied.

The UI always exposes this distinction: metadata may identify certificate
`#4718`, but only live agent evidence can show approved mode.

## Local UI security

- Listens only on `127.0.0.1` using an operating-system-selected port.
- Requires a 256-bit random token for every API request.
- Sets a restrictive Content Security Policy and does not enable CORS.
- Serves only the four static files it ships (`/`, `/app.js`, `/styles.css`,
  `/favicon.svg`); no inline styles or scripts.
- Runs native tools without a shell.
- Opens only report directories created by the current UI process.
- Performs qSearch locally and sends no scanned content over the network.
