# Veloce installers

Deliverables per spec 7.2: Windows MSI and Linux deb/rpm. This directory
holds the packaging inputs; installers are produced on the release machine.

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
tar -xzf veloce-1.0.0-linux-x86_64.tar.gz
cd veloce-1.0.0-linux-x86_64
bin/veloce-fire-up
```

The launcher generates paths for the extracted location, starts the agent,
and runs status and self-test checks. See `docs/client-quickstart.md` in the
repository or `docs/quickstart.md` inside the client archive.

## Windows (MSI)

Spec references: named pipe `\\.\pipe\LightRider.PQC.v1` with explicit ACL,
service `VelocePqcAgent` under `NT AUTHORITY\LocalService`, libraries under
`Program Files` loaded with `SetDefaultDllDirectories` +
`LoadLibraryExW` restricted search, Authenticode-signed MSI.

The Windows module build uses the wolfSSL-provided `IDE/WIN10` FIPS
solution (`wolfssl-fips.sln`, x64). Open vendor items before shipping
(spec 5.2): approved DLL build configuration (the IDE ships static-library
settings) and the `user_settings.h` variant matching module v5.2.1.

The agent, CLI, and qSearch sources are portable; the Windows IPC transport
(named pipe + ACL) replaces the UNIX socket transport in `agent/src/main.cpp`
and `cli/src/main.rs` behind the same framing and protocol (ipc/protocol.md).
