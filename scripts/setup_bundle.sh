#!/bin/bash
# Link an authorized wolfSSL commercial FIPS bundle into this checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUNDLE_NAME="wolfssl-5.9.2-commercial-fips-linuxv5.2.1"
DEFAULT_BUNDLE="$HOME/veloce-private/$BUNDLE_NAME"
LINK="$ROOT/vendor/wolfssl"

die() {
    echo "setup_bundle: $*" >&2
    exit 1
}

bundle="${1:-}"
if [ -z "$bundle" ]; then
    for candidate in "$DEFAULT_BUNDLE" "$ROOT/$BUNDLE_NAME"; do
        if [ -f "$candidate/configure" ]; then
            bundle="$candidate"
            break
        fi
    done
fi

if [ -z "$bundle" ]; then
    found_config="$(find "$HOME" -maxdepth 6 -type f \
        -path "*/$BUNDLE_NAME/configure" -print -quit 2>/dev/null || true)"
    [ -z "$found_config" ] || bundle="${found_config%/configure}"
fi

if [ -z "$bundle" ] || [ ! -d "$bundle" ]; then
    cat >&2 <<EOF
setup_bundle: authorized bundle not found

Copy and unpack the licensed directory at:
  $DEFAULT_BUNDLE

Then run:
  cd $ROOT
  bash scripts/setup_bundle.sh

Or pass its actual directory:
  bash scripts/setup_bundle.sh /absolute/path/$BUNDLE_NAME

The bundle is commercial licensed material and cannot be downloaded from GitHub.
EOF
    exit 2
fi

bundle="$(cd "$bundle" && pwd -P)"
[ -f "$bundle/configure" ] || die "missing $bundle/configure"
[ -f "$bundle/fips-hash.sh" ] || die "missing $bundle/fips-hash.sh"

mkdir -p "$ROOT/vendor"
if [ -L "$LINK" ]; then
    current="$(readlink -f "$LINK" || true)"
    if [ "$current" = "$bundle" ]; then
        echo "setup_bundle: ready ($LINK -> $bundle)"
        exit 0
    fi
    unlink "$LINK"
elif [ -e "$LINK" ]; then
    die "$LINK exists and is not a symlink; move it aside and rerun"
fi

ln -s "$bundle" "$LINK"
[ -f "$LINK/configure" ] || die "created link does not resolve to configure"
echo "setup_bundle: ready ($LINK -> $bundle)"

