#!/bin/bash
# Veloce macOS runtime build (spec 7.3 platform/macos). Run ON A MAC.
#
# Builds, in order: the wolfCrypt FIPS module as a dylib from the licensed
# bundle (vendor/wolfssl), the PQC provider dylib from the public wolfSSL
# tree, the native agent, qSearch and the CLI, then runs an inline smoke
# gate (testwolfcrypt, PQC self-test, agent boot + status/self-test) and
# stages a desktop full-runtime directory plus a distributable bundle.
#
# Validation posture: no wolfCrypt certificate lists a macOS operational
# environment, so a macOS runtime never carries a validated-deployment
# claim. validation_status() reports the OE honestly; the desktop dashboard
# turns green only on live self-test evidence, never on a certificate claim
# for this OE. The pytest gate battery remains the Linux reference gate;
# this script's smoke gate is the macOS acceptance check until a macOS OE
# exists (docs/STATUS.md).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(uname -m)"
PACKAGE=0
[ "${1:-}" = "--package" ] && PACKAGE=1

[ "$(uname -s)" = "Darwin" ] || { echo "build_macos: run this on macOS" >&2; exit 1; }
export PATH="$HOME/.cargo/bin:$PATH"
command -v cargo >/dev/null 2>&1 || { echo "build_macos: install rustup/cargo" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "build_macos: install Python 3" >&2; exit 1; }

# ------------------------------------------------------------ 1. FIPS dylib
SRC="$ROOT/vendor/wolfssl"
BUILD="$ROOT/build/fips-src"
FIPS_OUT="$ROOT/build/lib/fips"
[ -e "$SRC/configure" ] || { echo "build_macos: licensed bundle not found at vendor/wolfssl" >&2; exit 1; }
mkdir -p "$ROOT/build" "$FIPS_OUT"

RSYNC_EXCLUDES=()
SRC_REAL="$(cd "$SRC" && pwd -P)"
SELF_LINK="$SRC/$(basename "$SRC_REAL")"
if [ -L "$SELF_LINK" ]; then
    RSYNC_EXCLUDES+=("--exclude=/$(basename "$SELF_LINK")")
fi
rsync -a --delete --delete-excluded --copy-links "${RSYNC_EXCLUDES[@]:-}" \
    "$SRC/" "$BUILD/"
chmod +x "$BUILD/configure" "$BUILD/fips-hash.sh" "$BUILD"/build-aux/* 2>/dev/null || true

cd "$BUILD"
# wolfEntropy is not built: never tested with module v5.2.1 (wolfSSL
# 2026-08-27). Seeding is the Lightrider callback registered at runtime.
./configure --enable-fips=v5 >configure-fips.log 2>&1
make -j"$(sysctl -n hw.ncpu)" >make-1.log 2>&1
./fips-hash.sh
make -j"$(sysctl -n hw.ncpu)" >make-2.log 2>&1
./wolfcrypt/test/testwolfcrypt | tee testwolfcrypt.log
grep -q "Test complete" testwolfcrypt.log

FIPS_DYLIB="$(find src/.libs -maxdepth 1 -type f -name 'libwolfssl.*.dylib' | head -1)"
[ -n "$FIPS_DYLIB" ] || { echo "build_macos: no versioned libwolfssl dylib produced" >&2; exit 1; }
cp -a "$FIPS_DYLIB" "$FIPS_OUT/"
FIPS_SO="$FIPS_OUT/$(basename "$FIPS_DYLIB")"

python3 - "$FIPS_SO" "$FIPS_OUT/build-record.json" <<'EOF'
import hashlib, json, platform, subprocess, sys, os
so, out = sys.argv[1], sys.argv[2]
h = hashlib.sha256(open(so, "rb").read()).hexdigest()
cc = subprocess.run(["cc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
mac = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True).stdout.strip()
json.dump({
    "component": "wolfcrypt-fips",
    "library": os.path.basename(so),
    "sha256": h,
    "source_version": "wolfssl-5.9.2-commercial-fips-linuxv5.2.1",
    "fips_module_version": "5.2.1",
    "fips_certificate": "#4718",
    "entropy_source": "lightrider-local (CPU RDSEED hardware entropy + SP 800-90B RCT/APT health tests; os-drbg only by explicit configuration, reported as an unvalidated chain)",
    "build_flags": "--enable-fips=v5",
    "compiler": cc,
    "operating_environment": "macOS " + mac + " " + platform.machine(),
    "oe_note": "no macOS OE exists on any wolfCrypt certificate; no validated-deployment claim",
}, open(out, "w"), indent=2)
print("recorded", h, "->", out)
EOF

# ----------------------------------------------------------- 2. PQC dylib
VER="5.9.2"
TARBALL_URL="https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${VER}-stable.tar.gz"
CACHE="$ROOT/build/wolfssl-public-v${VER}-stable.tar.gz"
SRCROOT="$ROOT/build/pqc-src"
PQC_SRC="$SRCROOT/wolfssl-${VER}-stable"
PQC_BUILD="$ROOT/build/pqc-obj"
PQC_OUT="$ROOT/build/lib/pqc"
CFG="$ROOT/scripts/pqc"

mkdir -p "$PQC_OUT"
if [ ! -d "$PQC_SRC" ]; then
    [ -s "$CACHE" ] || curl -fsSL -o "$CACHE" "$TARBALL_URL"
    mkdir -p "$SRCROOT"
    tar -xzf "$CACHE" -C "$SRCROOT"
fi
rm -rf "$PQC_BUILD"
mkdir -p "$PQC_BUILD"

PQC_CFLAGS="-O2 -fPIC -DWOLFSSL_USER_SETTINGS -I$CFG -I$PQC_SRC -Wall"
PQC_SOURCES=(
    wolfcrypt/src/sha3.c
    wolfcrypt/src/wc_mlkem.c
    wolfcrypt/src/wc_mlkem_poly.c
    wolfcrypt/src/wc_mldsa.c
    wolfcrypt/src/random.c
    wolfcrypt/src/sha256.c
    wolfcrypt/src/hash.c
    wolfcrypt/src/memory.c
    wolfcrypt/src/wc_port.c
    wolfcrypt/src/error.c
    wolfcrypt/src/logging.c
    wolfcrypt/src/ed25519.c
    wolfcrypt/src/ge_operations.c
    wolfcrypt/src/fe_operations.c
    wolfcrypt/src/sha512.c
)
PQC_OBJS=()
for s in "${PQC_SOURCES[@]}"; do
    o="$PQC_BUILD/$(basename "$s" .c).o"
    cc $PQC_CFLAGS -c "$PQC_SRC/$s" -o "$o" &
    PQC_OBJS+=("$o")
done
wait

cc -dynamiclib -install_name "$PQC_OUT/libveloce-pqc.dylib" \
    -o "$PQC_OUT/libveloce-pqc.dylib" "${PQC_OBJS[@]}"

cc $PQC_CFLAGS "$CFG/selftest.c" -o "$PQC_BUILD/pqc-selftest" \
    "$PQC_OUT/libveloce-pqc.dylib"
"$PQC_BUILD/pqc-selftest" | tee "$PQC_BUILD/selftest.log"
grep -q "all checks passed" "$PQC_BUILD/selftest.log"

python3 - "$PQC_OUT/libveloce-pqc.dylib" "$PQC_OUT/build-record.json" <<'EOF'
import hashlib, json, platform, subprocess, sys, os
so, out = sys.argv[1], sys.argv[2]
h = hashlib.sha256(open(so, "rb").read()).hexdigest()
cc = subprocess.run(["cc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
mac = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True).stdout.strip()
json.dump({
    "component": "veloce-pqc-provider",
    "library": os.path.basename(so),
    "sha256": h,
    "source_version": "wolfssl-5.9.2-stable (public tree, same release as the licensed FIPS bundle)",
    "source_provenance_note": "standalone wc_mlkem/wc_mldsa/sha3 compilation (spec Appendix A fallback); distributed as object code under the Lightrider commercial wolfSSL agreement; vendor confirmation open item (spec 5.3)",
    "pqc_inside_fips_boundary": False,
    "algorithms": ["ML-KEM-768 (FIPS 203)", "ML-DSA-65 (FIPS 204)", "Ed25519 verify (RFC 8032; EMS receipt verification only)"],
    "build_flags": "WOLFSSL_HAVE_MLKEM WOLFSSL_HAVE_MLDSA WOLFSSL_SHA3 SHAKE128/256 WC_MLKEM_FAULT_HARDEN WC_RNG_SEED_CB HAVE_ED25519(verify-only) WOLFSSL_SHA512 SINGLE_THREADED",
    "compiler": cc,
    "operating_environment": "macOS " + mac + " " + platform.machine(),
}, open(out, "w"), indent=2)
print("recorded", h, "->", out)
EOF

# --------------------------------------------------- 3. agent, qsearch, cli
make -C "$ROOT/agent"
(cd "$ROOT/qsearch" && cargo build --release)
(cd "$ROOT/cli" && cargo build --release)
mkdir -p "$ROOT/build/bin"
cp "$ROOT/qsearch/target/release/qsearch" "$ROOT/cli/target/release/veloce" \
    "$ROOT/build/bin/"

# ------------------------------------------------------- 4. smoke gate
STATE="$(mktemp -d)"
trap 'kill "$AGENT_PID" 2>/dev/null || true; rm -rf "$STATE"' EXIT
python3 "$ROOT/scripts/gen_config.py" \
    --out "$STATE/agent.json" --socket "$STATE/agent.sock"
"$ROOT/build/bin/veloce-agent" --config "$STATE/agent.json" --quiet \
    >"$STATE/agent.log" 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 40); do
    [ -S "$STATE/agent.sock" ] && break
    sleep 0.25
done
[ -S "$STATE/agent.sock" ] || { cat "$STATE/agent.log" >&2; \
    echo "build_macos: agent did not start" >&2; exit 1; }
export VELOCE_SOCKET="$STATE/agent.sock"
"$ROOT/build/bin/veloce" --json status | tee "$STATE/status.json"
grep -q '"approved_mode":true' "$STATE/status.json" || \
    grep -q '"approved_mode": true' "$STATE/status.json" || \
    { echo "build_macos: agent not in approved mode" >&2; exit 1; }
"$ROOT/build/bin/veloce" --json self-test >/dev/null
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
trap - EXIT
rm -rf "$STATE"
echo "build_macos: smoke gate passed (module, PQC, agent boot, self-test)"

# ------------------------------------ 5. desktop runtime + release staging
RUNTIME="$ROOT/build/desktop-runtime-macos-$ARCH"
rm -rf "$RUNTIME"
mkdir -p "$RUNTIME/bin" "$RUNTIME/lib"
cp "$ROOT/build/bin/veloce-agent" "$RUNTIME/bin/"
cp "$FIPS_SO" "$RUNTIME/lib/"
cp "$FIPS_OUT/build-record.json" "$RUNTIME/lib/wolfcrypt-fips.build-record.json"
cp "$PQC_OUT/libveloce-pqc.dylib" "$RUNTIME/lib/"
cp "$PQC_OUT/build-record.json" "$RUNTIME/lib/veloce-pqc.build-record.json"

VER="${VELOCE_VERSION:-1.3.0}"
DIST="$ROOT/build/dist/veloce-$VER-macos-$ARCH"
rm -rf "$DIST"
mkdir -p "$DIST/bin" "$DIST/lib" "$DIST/docs"
cp "$ROOT/build/bin/veloce-agent" "$ROOT/build/bin/veloce" \
    "$ROOT/build/bin/qsearch" "$DIST/bin/"
cp "$ROOT/installer/macos/veloce-fire-up" "$DIST/bin/"
chmod +x "$DIST/bin/veloce-fire-up"
mkdir -p "$DIST/installer/macos"
cp "$ROOT/installer/macos/com.lightrider.veloce-agent.plist" "$DIST/installer/macos/"
cp "$RUNTIME/lib/"* "$DIST/lib/"
cp "$ROOT/LICENSE" "$ROOT/THIRD_PARTY_NOTICES.md" "$DIST/"
cp "$ROOT/docs/client-quickstart.md" "$DIST/docs/quickstart.md" 2>/dev/null || true
tar -czf "$ROOT/build/dist/veloce-$VER-macos-$ARCH.tar.gz" \
    -C "$ROOT/build/dist" "veloce-$VER-macos-$ARCH"
echo "build_macos: runtime bundle: build/dist/veloce-$VER-macos-$ARCH.tar.gz"

if [ "$PACKAGE" = 1 ]; then
    VELOCE_VERSION="$VER" VELOCE_ARCH="$ARCH" \
        bash "$ROOT/installer/macos/build-release.sh" --runtime-dir "$RUNTIME" \
        --arch "$ARCH" --version "$VER"
fi
echo "build_macos: OK"
