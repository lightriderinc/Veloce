# Veloce on Windows

Windows x86-64 is a supported build, discovery, and desktop platform. The
FIPS posture follows the wolfSSL written response of 2026-08-27: the Windows
FIPS module is built only as a DLL from `IDE/WIN10/wolfssl-fips.sln`, and
testing of the Windows 11 Pro (Intel i7-1260P) operational environment is
complete and awaiting publication on certificate #4718. Until the certificate
and its Security Policy list that OE, a Windows runtime carries no
validated-deployment claim: `validation_status()` reports
`pending_publication`, and the desktop dashboard turns green only on live
self-test evidence.

## What works on Windows

| Component | Status |
|---|---|
| qSearch source/cert scan | Full |
| qSearch system inventory | Native collectors: installed cryptographic libraries, system cryptography policy, certificate stores; unreadable locations are reported as explicit blind spots |
| Veloce agent + SDK + CLI | Builds and runs: named pipe `\\.\pipe\LightRider.PQC.v1` with a protected local ACL, `LoadLibraryExW` restricted search after SHA-256 verification, `BCryptGenRandom` as the Lightrider seed source |
| Desktop app | Full UI (security dashboard, qSearch, entropy page); portable ZIP and MSI; full-runtime or discovery-only packaging |

## Release artifacts

| Artifact | Content |
|---|---|
| `veloce-<ver>-windows-x86_64.zip` | Portable payload: `Veloce.exe` plus `_internal\` (UI, qSearch, CLI, optional runtime) |
| `veloce-<ver>-windows-x86_64.msi` | WiX 5.0.2 installer: `Program Files\Veloce`, Start Menu shortcut, Apps and features entry with the Veloce icon, license and install-directory dialogs with Lightrider artwork |
| `SHA256SUMS-windows-x86_64.txt` | `sha256sum -c` compatible checksums of the artifacts above |

Build commands, signing, and the full-runtime input contract:
`docs/desktop-releases.md`. The `Desktop discovery release` GitHub Actions
workflow produces the discovery-only ZIP and MSI on `windows-latest`.

## Build the native runtime (on Windows)

Prerequisites: Visual Studio 2022 Build Tools (C++ x64), CMake 3.20 or
later, rustup with the stable MSVC toolchain, Python 3, WiX 5.0.2
(`dotnet tool install --global wix --version 5.0.2`; later majors require
the Open Source Maintenance Fee EULA), and the licensed wolfSSL FIPS bundle
together with the vendor-supplied `user_settings.h` for module v5.2.1
(`HAVE_FIPS_VERSION_MAJOR 5`, `HAVE_FIPS_VERSION_MINOR 2`,
`HAVE_FIPS_VERSION_PATCH 1`).

The steps below follow the bundle's `IDE/WIN10/README.txt`, the repository
build recipes (`scripts/build_fips.sh`, `scripts/build_pqc.sh`,
`agent/CMakeLists.txt`), and the wolfSSL response. Native execution on a
Windows host remains an open item (docs/STATUS.md, G1/G4); the smoke gate in
step 8 is the acceptance check.

1. **FIPS DLL.** Replace `IDE\WIN10\user_settings.h` with the vendor v5.2.1
   variant. Keep `WC_RNG_SEED_CB` defined: the agent registers the Lightrider
   seed callback through `wc_SetSeed_Cb`, and the module makes no entropy
   claim. Build the `DLL Release|x64` configuration:

   ```powershell
   msbuild IDE\WIN10\wolfssl-fips.sln /p:Configuration="DLL Release" /p:Platform=x64
   ```

   Output: `IDE\WIN10\DLL Release\x64\wolfssl-fips.dll`. The project already
   disables ASLR (`/DYNAMICBASE:NO`), incremental linking, and enables a
   fixed base address, as the in-core integrity check requires. The
   README's static-library statement is a legacy error (wolfSSL PR #11142).

2. **In-core hash.** Build and run the `test` project from the same solution.
   The first run fails the power-on integrity test and prints the computed
   HMAC-SHA-256. Copy it into the `verifyCore[]` initializer in
   `wolfcrypt\src\fips_test.c`, rebuild the DLL, and rerun until
   `testwolfcrypt` reports `Test complete`. This is the Windows counterpart
   of `fips-hash.sh` in `scripts/build_fips.sh`.

3. **FIPS build record.** Write `wolfcrypt-fips.build-record.json` beside the
   DLL with the same fields as the Linux record:

   ```json
   {
     "component": "wolfcrypt-fips",
     "library": "wolfssl-fips.dll",
     "sha256": "<sha256 of wolfssl-fips.dll>",
     "source_version": "<bundle directory name>",
     "fips_module_version": "5.2.1",
     "fips_certificate": "#4718",
     "entropy_source": "lightrider-local (CPU RDSEED hardware entropy + SP 800-90B RCT/APT health tests)",
     "build_flags": "IDE/WIN10 wolfssl-fips.sln DLL Release|x64; vendor user_settings.h v5.2.1",
     "compiler": "MSVC <version>",
     "operating_environment": "Windows 11 Pro x86_64 (Intel i7-1260P)",
     "validation_claim": "pending_publication",
     "oe_note": "Windows 11 OE tested by wolfSSL, awaiting publication on certificate #4718; no validated-deployment claim"
   }
   ```

   `operating_environment` must contain `windows` and `x86_64`; the desktop
   packager rejects other values. Compute the hash with
   `Get-FileHash -Algorithm SHA256`.

4. **PQC provider DLL.** Compile the same public-tree sources as
   `scripts/build_pqc.sh` (wolfSSL v5.9.2-stable) with the repository
   settings header and DLL export macros:

   ```powershell
   cl /O2 /LD /DWOLFSSL_USER_SETTINGS /DWOLFSSL_DLL /DBUILDING_WOLFSSL `
      /I scripts\pqc /I <public-tree> `
      <public-tree>\wolfcrypt\src\sha3.c <public-tree>\wolfcrypt\src\wc_mlkem.c `
      <public-tree>\wolfcrypt\src\wc_mlkem_poly.c <public-tree>\wolfcrypt\src\wc_mldsa.c `
      <public-tree>\wolfcrypt\src\random.c <public-tree>\wolfcrypt\src\sha256.c `
      <public-tree>\wolfcrypt\src\hash.c <public-tree>\wolfcrypt\src\memory.c `
      <public-tree>\wolfcrypt\src\wc_port.c <public-tree>\wolfcrypt\src\error.c `
      <public-tree>\wolfcrypt\src\logging.c <public-tree>\wolfcrypt\src\ed25519.c `
      <public-tree>\wolfcrypt\src\ge_operations.c <public-tree>\wolfcrypt\src\fe_operations.c `
      <public-tree>\wolfcrypt\src\sha512.c `
      /Fe:veloce-pqc.dll /link advapi32.lib bcrypt.lib
   cl /DWOLFSSL_USER_SETTINGS /I scripts\pqc /I <public-tree> scripts\pqc\selftest.c veloce-pqc.lib
   .\selftest.exe
   ```

   The self-test must print `all checks passed`. Write
   `veloce-pqc.build-record.json` with `"library": "veloce-pqc.dll"`,
   `"pqc_inside_fips_boundary": false`, the SHA-256, and the same
   `operating_environment` string as the FIPS record.

5. **Agent.** `agent/src/fips_core.cpp` includes `<wolfssl/options.h>` and
   compiles against the FIPS header set; the IDE build has no generated
   `options.h`. Prepare a header directory containing the bundle's `wolfssl\`
   tree, the vendor `user_settings.h` at its root, and a
   `wolfssl\options.h` stub with the single line
   `#define WOLFSSL_USER_SETTINGS`. Then:

   ```powershell
   cmake -S agent -B build\agent-windows -A x64 `
       -DVELOCE_FIPS_INCLUDE=<fips-header-dir> `
       -DVELOCE_PQC_INCLUDE=<public-tree>
   cmake --build build\agent-windows --config Release
   ```

   Output: `build\agent-windows\Release\veloce-agent.exe`. The agent's
   cloud entropy client uses the FIPS DLL's TLS functions and Winsock
   (`ws2_32`, linked by CMake); no other network library is needed.

6. **qSearch and CLI.**

   ```powershell
   cargo build --release --locked --manifest-path qsearch\Cargo.toml
   cargo build --release --locked --manifest-path cli\Cargo.toml
   ```

7. **Stage the runtime directory** in the desktop contract layout:

   ```text
   runtime\
     bin\veloce-agent.exe
     lib\wolfssl-fips.dll
     lib\veloce-pqc.dll
     lib\wolfcrypt-fips.build-record.json
     lib\veloce-pqc.build-record.json
   ```

   Never rename a DLL without regenerating its record.

8. **Smoke gate.** Copy `bin\veloce.exe` into `runtime\bin\` and
   `installer\windows\veloce-fire-up.ps1` into `runtime\installer\`, then:

   ```powershell
   powershell -ExecutionPolicy Bypass -File runtime\installer\veloce-fire-up.ps1
   ```

   `veloce --json status` must report `"approved_mode": true`, entropy
   `healthy`, and `veloce --json self-test` must pass. Any other result blocks
   the release.

9. **Package.**

   ```powershell
   .\installer\windows\build-release.ps1 -Version 1.2.0 -RuntimeDir runtime
   ```

## Run it

| Delivery | Start |
|---|---|
| MSI | Start Menu, `Veloce Desktop`; the UI starts the packaged agent for the signed-in user with EMS disabled |
| Portable ZIP | Extract and run `Veloce.exe` |
| Runtime bundle | `powershell -ExecutionPolicy Bypass -File installer\veloce-fire-up.ps1`; `-Stop` stops the recorded agent |

The launcher writes `%LOCALAPPDATA%\Lightrider\Veloce\agent.json`, starts
`veloce-agent.exe` on the named pipe, and prints status and self-test JSON.
Logs: `%LOCALAPPDATA%\Lightrider\Veloce\agent.log`. The CLI reads
`VELOCE_PIPE` to reach a non-default pipe.

Registration as the `VelocePqcAgent` service under `LocalService` is a
separate managed deployment step and is not performed by the MSI.

## Entropy seed source

The agent seeds the FIPS DRBG from the processor's RDSEED instruction by
default (`entropy.source: rdseed`), applying SP 800-90B RCT/APT health
tests to every block, and fails closed when RDSEED is unavailable. Virtual
machines must expose RDSEED to the guest (check `Get-CimInstance
Win32_Processor` on the host or run `veloce --json status` and read
`entropy.source_kind`). Setting `entropy.source` to `os-drbg` uses
`BCryptGenRandom` instead; that is operating system DRBG output, an
SP 800-90C RBGC chain that status reports with no security-strength claim.

## Validation posture

The Windows records carry `"validation_claim": "pending_publication"`. Do not
represent a Windows deployment as FIPS validated until the CMVP entry for
certificate #4718 and its Security Policy list the Windows 11 OE. When they
do, the build flow is unchanged and only the claim flips. User affirmation
under CMVP Management Manual 7.9.2 becomes available once an OS row exists;
until then no porting basis exists.

## Open items

- CMVP publication of the Windows 11 OE on certificate #4718 (wolfSSL
  notifies).
- Native execution of steps 1 to 8 on the release host (G1/G4).
- Authenticode signing with the Lightrider release certificate
  (`-CertificateThumbprint`).
