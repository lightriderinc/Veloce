#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="${VELOCE_VERSION:-1.0.0}"
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
mkdir -p "$DIST"

if [ -n "${VELOCE_CODESIGN_IDENTITY:-}" ]; then
    codesign --force --deep --options runtime --timestamp \
        --sign "$VELOCE_CODESIGN_IDENTITY" "$APP"
else
    codesign --force --deep --sign - "$APP"
    echo "macOS release: ad-hoc signed (set VELOCE_CODESIGN_IDENTITY for distribution signing)" >&2
fi
codesign --verify --deep --strict --verbose=2 "$APP"

rm -f "$DMG"
hdiutil create -volname "Veloce $VERSION" -srcfolder "$APP" \
    -ov -format UDZO "$DMG"

if [ -n "${VELOCE_NOTARY_PROFILE:-}" ]; then
    if [ -n "${VELOCE_CODESIGN_IDENTITY:-}" ]; then
        codesign --force --timestamp --sign "$VELOCE_CODESIGN_IDENTITY" "$DMG"
    fi
    xcrun notarytool submit "$DMG" --keychain-profile "$VELOCE_NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
fi

echo "macOS DMG release: $DMG"
