# Veloce Desktop on macOS: quick start

Veloce Desktop is a click-to-run application for macOS 13 or later. No
build tools are required.

## 1. Download

From the GitHub Releases page, download `veloce-<version>-macos-arm64.dmg`
(Apple silicon) and `SHA256SUMS-macos-arm64.txt`. Verify in Terminal:

```bash
shasum -a 256 -c SHA256SUMS-macos-arm64.txt
```

## 2. Install

Open the DMG and drag `Veloce` to the `Applications` shortcut beside it.

## 3. Open

Open Veloce from Applications. What happens next depends on how the build
was signed; the file `How to open Veloce.txt` inside the DMG states which
case applies.

**Developer ID signed and notarized builds** open without a prompt.

**Ad-hoc signed builds** (the current 1.2.0 download) are blocked once by
Gatekeeper with the message "Apple could not verify Veloce is free of
malware". To allow the app:

1. Click `Done` on the message.
2. Open `System Settings`, choose `Privacy & Security`, scroll to
   `Security`, and click `Open Anyway` next to the Veloce entry.
3. Confirm with your password or Touch ID, then open Veloce again.

This is needed once per installation. Alternative in Terminal, before the
first launch:

```bash
xattr -dr com.apple.quarantine /Applications/Veloce.app
```

On macOS 14 and earlier, Control-click Veloce and choose `Open` instead.

## 4. Use

Veloce Desktop starts a local service on this computer only and opens your
browser. Nothing listens on the network, and no scanned content leaves the
machine.

- **qSearch**: choose a folder, click `Start qSearch`, and read the counts,
  algorithm chart, and findings table. `Open report folder` shows the
  reports under `Documents/Veloce Reports`.
- **Security dashboard** and **Entropy**: live data appears only when the
  Veloce FIPS runtime is installed. Release downloads are discovery-only and
  show `Agent unavailable` and `No live data`; that is expected.

Click `Quit Veloce` in the sidebar to stop the local service.

## FIPS status of this package

Discovery-only packages contain no cryptographic module and make no FIPS
claim. No wolfCrypt certificate lists a macOS operating environment, so a
macOS runtime never carries a validated-deployment claim.
