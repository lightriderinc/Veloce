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
  counters, and
  PQC provider self-test state;
- an on-demand **Run self-tests** button.

The interface does not perform cryptography. It invokes the native qSearch
binary and reads validation evidence from the local Veloce agent through the
native CLI.

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
- the Lightrider seed callback's RCT/APT verification is passing;
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
    <FIPS DLL named by wolfcrypt-fips.build-record.json>
    <PQC DLL named by veloce-pqc.build-record.json>
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
release machine. Never rename a DLL/dylib without updating and regenerating its
signed build record.

## Windows build

Requirements on Windows x86-64:

- Python 3 and PyInstaller;
- Rust with the stable MSVC toolchain;
- WiX Toolset v4 for MSI output;
- the approved native runtime directory for a full-runtime package.

Install the desktop build dependency:

```powershell
python -m pip install -r desktop\requirements-build.txt
```

Build the full portable ZIP and MSI:

```powershell
.\installer\windows\build-release.ps1 `
    -Version 1.0.0 `
    -RuntimeDir C:\secure\veloce-runtime-windows-x86_64
```

Build an explicitly labeled qSearch/UI preview:

```powershell
.\installer\windows\build-release.ps1 `
    -Version 1.0.0 `
    -DiscoveryOnly `
    -SkipMsi
```

Outputs:

```text
build/dist/veloce-1.0.0-windows-x86_64.zip
build/dist/veloce-1.0.0-windows-x86_64.msi
```

The MSI installs under `Program Files\Veloce` and adds a **Veloce Desktop**
Start Menu shortcut. Authenticode-sign the PE binaries and final MSI with the
Lightrider release certificate before distribution.

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
    --version 1.0.0 \
    --arch arm64 \
    --runtime-dir /secure/veloce-runtime-macos-arm64
```

For Intel macOS, use `--arch x86_64` and build on an x86-64 Python/Rust host.
The builder fails if `--arch` does not match the native build host, preventing
an app label from disagreeing with its bundled Rust executables.
For an explicitly labeled UI preview, replace `--runtime-dir ...` with
`--discovery-only`.

Output:

```text
build/dist/veloce-1.0.0-macos-arm64.dmg
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

- Windows: the repository does not yet contain the vendor-approved FIPS DLL
  configuration or a completed #4718 operating-environment approval. Until
  those inputs exist, build discovery-only packages and do not make a Windows
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
- Runs native tools without a shell.
- Opens only report directories created by the current UI process.
- Performs qSearch locally and sends no scanned content over the network.
