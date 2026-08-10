#!/bin/bash
# Veloce build recipe, spec Appendix A: PQC provider beside the FIPS boundary.
#
# The commercial FIPS bundle strips SHAKE/XOF from sha3.c/sha3.h, so the
# ML-KEM / ML-DSA sources cannot compile from that bundle (spec 5.3: PQC
# cannot link inside the v5 FIPS build). Appendix A's fallback is used:
# standalone compilation of wc_mlkem.*, wc_mldsa.* and sha3.c with SHAKE
# enabled, taken from the public wolfSSL tree of the exact same release
# (v5.9.2-stable, the archive wolfSSL signs on GitHub). The provider is
# shipped as object code under the Lightrider commercial wolfSSL agreement.
# [VENDOR: confirm the commercial agreement covers the same-version
# public-tree sources used for this provider build.]
#
# Randomness policy (spec 5.3): the agent supplies all provider randomness
# from the FIPS DRBG, via the *WithRandom APIs and a WC_RNG_SEED_CB seed
# callback. The artifact is named libveloce-pqc.so so the two builds can
# never be confused at load time.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="5.9.2"
TARBALL_URL="https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${VER}-stable.tar.gz"
CACHE="$ROOT/build/wolfssl-public-v${VER}-stable.tar.gz"
SRCROOT="$ROOT/build/pqc-src"
SRC="$SRCROOT/wolfssl-${VER}-stable"
BUILD="$ROOT/build/pqc-obj"
OUT="$ROOT/build/lib/pqc"
CFG="$ROOT/scripts/pqc"
JOBS="$(nproc)"

mkdir -p "$ROOT/build" "$OUT"
if [ ! -d "$SRC" ]; then
    [ -s "$CACHE" ] || curl -fsSL -o "$CACHE" "$TARBALL_URL"
    mkdir -p "$SRCROOT"
    tar -xzf "$CACHE" -C "$SRCROOT"
fi

rm -rf "$BUILD"
mkdir -p "$BUILD"

CFLAGS="-O2 -fPIC -DWOLFSSL_USER_SETTINGS -I$CFG -I$SRC -Wall"
SOURCES=(
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
)

OBJS=()
for s in "${SOURCES[@]}"; do
    o="$BUILD/$(basename "$s" .c).o"
    gcc $CFLAGS -c "$SRC/$s" -o "$o" &
    OBJS+=("$o")
done
wait

gcc -shared -Wl,-soname,libveloce-pqc.so -o "$OUT/libveloce-pqc.so" "${OBJS[@]}"

# Gate: provider self-test (roundtrip + negative tests) must pass.
gcc $CFLAGS "$CFG/selftest.c" -o "$BUILD/pqc-selftest" "$OUT/libveloce-pqc.so" -Wl,-rpath,"$OUT"
"$BUILD/pqc-selftest" | tee "$BUILD/selftest.log"
grep -q "all checks passed" "$BUILD/selftest.log"

python3 - "$OUT/libveloce-pqc.so" "$OUT/build-record.json" <<'EOF'
import hashlib, json, subprocess, sys, os
so, out = sys.argv[1], sys.argv[2]
h = hashlib.sha256(open(so, "rb").read()).hexdigest()
cc = subprocess.run(["gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
json.dump({
    "component": "veloce-pqc-provider",
    "library": os.path.basename(so),
    "sha256": h,
    "source_version": "wolfssl-5.9.2-stable (public tree, same release as the licensed FIPS bundle)",
    "source_provenance_note": "standalone wc_mlkem/wc_mldsa/sha3 compilation (spec Appendix A fallback); distributed as object code under the Lightrider commercial wolfSSL agreement; vendor confirmation open item (spec 5.3)",
    "pqc_inside_fips_boundary": False,
    "algorithms": ["ML-KEM-768 (FIPS 203)", "ML-DSA-65 (FIPS 204)"],
    "build_flags": "WOLFSSL_HAVE_MLKEM WOLFSSL_HAVE_MLDSA WOLFSSL_SHA3 SHAKE128/256 WC_MLKEM_FAULT_HARDEN WC_RNG_SEED_CB SINGLE_THREADED",
    "compiler": cc,
    "operating_environment": os.uname().sysname + " " + os.uname().release + " " + os.uname().machine,
}, open(out, "w"), indent=2)
print("recorded", h, "->", out)
EOF
echo "build_pqc: OK ($OUT)"
