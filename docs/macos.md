# Veloce on macOS

macOS is a supported build and discovery platform with one hard limit: no
wolfCrypt certificate lists a macOS operational environment, so a macOS
runtime never carries a FIPS validated-deployment claim. The agent, CLI,
qSearch, and desktop app all run; `validation_status()` reports the OE
honestly and the dashboard turns green only on live self-test evidence.

## What works on macOS

| Component | Status |
|---|---|
| qSearch source/cert scan | Full |
| qSearch system inventory | Native collector: Security.framework, on-disk dylibs (`/usr/local/lib`, `/opt/homebrew/lib`, `/opt/local/lib`), system Keychain roots, `/etc/ssl/cert.pem`, LibreSSL/OpenSSL version, `/etc/ssh` host keys and sshd policy; dyld-shared-cache and process-map limits are reported as explicit blind spots |
| Veloce agent + SDK + CLI | Builds and runs (UNIX socket, `dlopen`, launchd); FIPS module loads and self-tests, with no validated-OE claim |
| Desktop app | Full UI (security dashboard, qSearch, entropy page); full-runtime or discovery-only packaging |

## Build the runtime (on a Mac)

Prerequisites: Xcode command line tools, rustup, Python 3, and the licensed
wolfSSL bundle linked at `vendor/wolfssl`.

```
bash scripts/build_macos.sh            # build + smoke gate + tar.gz bundle
bash scripts/build_macos.sh --package  # additionally builds Veloce.app + DMG
```

The script builds the FIPS dylib (`--enable-fips=v5`, fips-hash flow,
testwolfcrypt), the PQC provider dylib, the agent, qSearch, and the CLI,
then runs a smoke gate: PQC self-test, agent boot, `veloce --json status`
must report approved mode, and self-tests must pass. It stages
`build/desktop-runtime-macos-<arch>/` for the desktop packager and writes
`build/dist/veloce-<ver>-macos-<arch>.tar.gz`.

The pytest gate battery remains the Linux reference gate; the smoke gate is
the macOS acceptance check until a macOS OE exists.

## Run it

From an extracted `veloce-<ver>-macos-<arch>` bundle:

```
bin/veloce-fire-up             # start the agent in the foreground session
bin/veloce-fire-up --launchd   # install and start a per-user LaunchAgent
bin/veloce status              # agent health from the CLI
```

`--launchd` renders `installer/macos/com.lightrider.veloce-agent.plist`
into `~/Library/LaunchAgents/` and bootstraps it with `launchctl`, so the
agent restarts on login and on failure.

Desktop app without a runtime (discovery-only):

```
python3 desktop/veloce_desktop.py                       # from the repo
bash installer/macos/build-release.sh --discovery-only  # packaged .app/DMG
```

## Validation posture

The build record carries
`"oe_note": "no macOS OE exists on any wolfCrypt certificate; no
validated-deployment claim"`. Do not represent a macOS deployment as FIPS
validated. If wolfSSL ever adds a macOS OE to a certificate, the same build
flow applies and only the claim flips.
