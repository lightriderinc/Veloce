# Veloce installers

Deliverables include the Windows MSI, macOS app/DMG, and Linux package inputs.
Installers are produced on a native release machine. The clickable qSearch and
FIPS dashboard workflow is documented in `docs/desktop-releases.md`.

## Linux (deb/rpm, systemd)

Layout installed by the packages:

| Path | Content |
|---|---|
| `/opt/veloce/bin/veloce-agent` | agent |
| `/opt/veloce/bin/veloce`, `/opt/veloce/bin/qsearch` | CLI, qSearch |
| `/opt/veloce/lib/libwolfssl.so.*` | wolfCrypt FIPS module (object code only) |
| `/opt/veloce/lib/libveloce-pqc.so` | PQC provider (object code only) |
| `/opt/veloce/lib/*.build-record.json` | recorded build hashes (CBOM) |
| `/etc/veloce/agent.json` | configuration, EMS disabled by default |
| `/lib/systemd/system/veloce-agent.service` | service unit (`linux/veloce-agent.service`) |

Post-install prints the one-line branded confirmation with version and FIPS
certificate (spec 7.3). Build the staged tree with
`bash scripts/make_release.sh` from the repository root, then wrap it with
`fpm` or native `dpkg-deb`/`rpmbuild` tooling.

The same release command produces a self-contained client tarball for hosts
that do not use deb/rpm. It includes both cryptographic libraries as object
code and does not require the licensed wolfSSL source bundle on the client:

```bash
tar -xzf veloce-1.2.0-linux-x86_64.tar.gz
cd veloce-1.2.0-linux-x86_64
bin/veloce-fire-up
```

The launcher generates paths for the extracted location, starts the agent,
and runs status and self-test checks. See `docs/client-quickstart.md` in the
repository or `docs/quickstart.md` inside the client archive.

## Windows (desktop executable + MSI)

Spec references: named pipe `\\.\pipe\LightRider.PQC.v1` with explicit ACL,
service `VelocePqcAgent` under `NT AUTHORITY\LocalService`, libraries under
`Program Files` loaded with `SetDefaultDllDirectories` +
`LoadLibraryExW` restricted search, Authenticode-signed MSI.

The desktop full-runtime bundle currently starts a fail-closed agent for the
signed-in user. Registration under `LocalService` remains a separate managed
deployment step and is not implied by the desktop MSI.

| File | Purpose |
|---|---|
| `windows/build-release.ps1` | Packages the Veloce Desktop executable (with the Veloce icon), qSearch, CLI, and an approved native runtime into a portable ZIP and a WiX v5 MSI; optional Authenticode signing (`-CertificateThumbprint`); writes `SHA256SUMS-windows-x86_64.txt`. Supports an explicit discovery-only build. |
| `windows/veloce.wxs` | WiX package: `Program Files\Veloce`, Start Menu shortcut, Apps and features icon, license and install-directory dialogs with Lightrider artwork from `assets/branding/`. |
| `windows/veloce-fire-up.ps1` | Windows counterpart of the Linux/macOS launchers: writes `%LOCALAPPDATA%\Lightrider\Veloce\agent.json` from the build records, starts the agent on the named pipe, prints status and self-test JSON; `-Stop` stops it. |

Signing never touches `lib\`: the FIPS module and PQC provider are hash
recorded, and rewriting them would break the recorded SHA-256 and the
module's in-core integrity check.

The Windows module build uses the wolfSSL-provided `IDE/WIN10` FIPS
solution (`wolfssl-fips.sln`, `DLL Release|x64`) with the vendor-supplied
v5.2.1 `user_settings.h`; wolfSSL confirmed on 2026-08-27 that Windows FIPS
supports DLL builds only (the README's static-library statement is a legacy
error, correction in wolfSSL PR #11142). The Windows 11 Pro OE is tested and
awaiting publication on certificate #4718; until published, Windows carries
`pending_publication` and no validated-deployment claim. Runtime build steps:
`docs/windows.md`.

The agent and CLI implement the Windows named-pipe transport with a protected
local ACL behind the same framing and protocol (`ipc/protocol.md`). qSearch has
native Windows library, policy, and certificate-store collectors.

## macOS (desktop app + DMG)

`macos/build-release.sh` packages `Veloce.app`, signs it, creates a compressed
DMG, and optionally submits/staples notarization. qSearch includes native macOS
Security-framework and Keychain inventory. The agent uses a peer-authorized
UNIX-domain socket and restricted dylib loading.

No approved macOS FIPS dylib/OE record is currently present. The macOS builder
therefore produces a qSearch/UI discovery release unless an approved native
runtime directory is supplied.
