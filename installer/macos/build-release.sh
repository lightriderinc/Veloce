#!/bin/bash
# Package Veloce Desktop for macOS: Veloce.app inside a DMG.
#
# Signing and notarization (Gatekeeper):
#   VELOCE_CODESIGN_IDENTITY  "Developer ID Application: Lightrider Inc (TEAMID)".
#                             Absent: ad-hoc signature; macOS shows "Apple could
#                             not verify ..." and the user must allow the app in
#                             System Settings > Privacy & Security.
#   VELOCE_NOTARY_PROFILE     notarytool keychain profile name; with the identity
#                             set, the DMG is submitted, stapled, and verified.
#   VELOCE_NOTARY_KEYCHAIN    optional keychain path holding that profile (CI).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="${VELOCE_VERSION:-1.3.0}"
ARCH="${VELOCE_ARCH:-$(uname -m)}"
RUNTIME_DIR=""
DISCOVERY_ONLY=0

usage() {
    echo "usage: $0 (--runtime-dir DIR | --discovery-only) [--arch x86_64|arm64] [--version VERSION]" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --runtime-dir) [ "$#" -ge 2 ] || usage; RUNTIME_DIR="$2"; shift 2 ;;
        --discovery-only) DISCOVERY_ONLY=1; shift ;;
        --arch) [ "$#" -ge 2 ] || usage; ARCH="$2"; shift 2 ;;
        --version) [ "$#" -ge 2 ] || usage; VERSION="$2"; shift 2 ;;
        *) usage ;;
    esac
done

if [ "$(uname -s)" != "Darwin" ]; then
    echo "macOS releases must be built on macOS" >&2
    exit 1
fi
if [ -n "$RUNTIME_DIR" ] && [ "$DISCOVERY_ONLY" = 1 ]; then usage; fi
if [ -z "$RUNTIME_DIR" ] && [ "$DISCOVERY_ONLY" = 0 ]; then usage; fi

args=(--platform macos --arch "$ARCH" --version "$VERSION")
if [ "$DISCOVERY_ONLY" = 1 ]; then
    args+=(--discovery-only)
else
    args+=(--runtime-dir "$RUNTIME_DIR")
fi
python3 "$ROOT/scripts/build_desktop_release.py" "${args[@]}"

APP="$ROOT/build/desktop/macos-$ARCH/dist/Veloce.app"
DIST="$ROOT/build/dist"
DMG="$DIST/veloce-$VERSION-macos-$ARCH.dmg"
DMG_STAGE="$ROOT/build/desktop/macos-$ARCH/dmg"
mkdir -p "$DIST"

# ------------------------------------------------------------- signing
SIGNED_WITH_IDENTITY=0
if [ -n "${VELOCE_CODESIGN_IDENTITY:-}" ]; then
    codesign --force --deep --options runtime --timestamp \
        --sign "$VELOCE_CODESIGN_IDENTITY" "$APP"
    SIGNED_WITH_IDENTITY=1
else
    codesign --force --deep --sign - "$APP"
    echo "macOS release: ad-hoc signed; Gatekeeper will block first launch until the user allows it (set VELOCE_CODESIGN_IDENTITY and VELOCE_NOTARY_PROFILE for a notarized build)" >&2
fi
codesign --verify --deep --strict --verbose=2 "$APP"

# ------------------------------------------------------------- DMG layout
# Veloce.app, an Applications shortcut for drag-install, and a plain-text
# note explaining Gatekeeper for the build type produced here.
rm -rf "$DMG_STAGE"
mkdir -p "$DMG_STAGE"
cp -R "$APP" "$DMG_STAGE/"
ln -s /Applications "$DMG_STAGE/Applications"
if [ "$SIGNED_WITH_IDENTITY" = 1 ] && [ -n "${VELOCE_NOTARY_PROFILE:-}" ]; then
    cat > "$DMG_STAGE/How to open Veloce.txt" <<'TXT'
Veloce Desktop (Lightrider Inc)

1. Drag Veloce to the Applications folder.
2. Open Veloce from Applications.

This build is signed with the Lightrider Developer ID and notarized by
Apple, so it opens without a security prompt.
TXT
else
    cat > "$DMG_STAGE/How to open Veloce.txt" <<'TXT'
Veloce Desktop (Lightrider Inc)

1. Drag Veloce to the Applications folder.
2. Open Veloce from Applications. macOS shows "Apple could not verify
   Veloce is free of malware". Click Done.
3. Open System Settings > Privacy & Security, scroll to Security, and
   click "Open Anyway" next to the Veloce message. Confirm with your
   password or Touch ID. This is needed once.

Alternative (Terminal), before opening the app:
   xattr -dr com.apple.quarantine /Applications/Veloce.app

Why: this build is signed with an ad-hoc signature rather than an Apple
Developer ID and is not notarized. Lightrider release builds signed with a
Developer ID and notarized by Apple open without this step.
TXT
fi

rm -f "$DMG"
hdiutil create -volname "Veloce $VERSION" -srcfolder "$DMG_STAGE" \
    -ov -format UDZO "$DMG"

# ------------------------------------------------------------- notarization
if [ "$SIGNED_WITH_IDENTITY" = 1 ] && [ -n "${VELOCE_NOTARY_PROFILE:-}" ]; then
    codesign --force --timestamp --sign "$VELOCE_CODESIGN_IDENTITY" "$DMG"
    notary_args=(--keychain-profile "$VELOCE_NOTARY_PROFILE" --wait)
    if [ -n "${VELOCE_NOTARY_KEYCHAIN:-}" ]; then
        notary_args+=(--keychain "$VELOCE_NOTARY_KEYCHAIN")
    fi
    xcrun notarytool submit "$DMG" "${notary_args[@]}"
    xcrun stapler staple "$DMG"
    xcrun stapler validate "$DMG"
    # Gatekeeper assessment of the stapled disk image.
    spctl --assess --type open --context context:primary-signature -v "$DMG"
    echo "macOS release: Developer ID signed, notarized, and stapled" >&2
elif [ -n "${VELOCE_NOTARY_PROFILE:-}" ]; then
    echo "macOS release: VELOCE_NOTARY_PROFILE set without VELOCE_CODESIGN_IDENTITY; notarization skipped" >&2
fi

echo "macOS DMG release: $DMG"
