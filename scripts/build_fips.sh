#!/bin/bash
# Veloce build recipe, spec Appendix A: Linux FIPS module.
# Builds wolfCrypt FIPS 140-3 (cert #4718, module v5.2.1) from the licensed
# bundle referenced by vendor/wolfssl. The licensed tree is copied to
# build/fips-src so the vendor source stays pristine; fips-hash.sh patches
# the in-core integrity hash inside the copy only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/vendor/wolfssl"
BUILD="$ROOT/build/fips-src"
OUT="$ROOT/build/lib/fips"
JOBS="$(nproc)"

[ -e "$SRC/configure" ] || { echo "build_fips: licensed bundle not found at vendor/wolfssl" >&2; exit 1; }

mkdir -p "$ROOT/build" "$OUT"
rsync -a --delete --copy-links "$SRC/" "$BUILD/"
chmod +x "$BUILD/configure" "$BUILD/fips-hash.sh" "$BUILD"/build-aux/* 2>/dev/null || true

cd "$BUILD"
./configure --enable-fips=v5 --enable-wolfEntropy=nofallback >configure-fips.log 2>&1
make -j"$JOBS" >make-1.log 2>&1
./fips-hash.sh
make -j"$JOBS" >make-2.log 2>&1

# Gate G0: FIPS module passes self-tests on the reference machine.
./wolfcrypt/test/testwolfcrypt | tee testwolfcrypt.log
grep -q "Test complete" testwolfcrypt.log

# Stage artifacts and the per-build record (feeds the CBOM, spec 5.2).
cp -a src/.libs/libwolfssl.so* "$OUT/"
SO="$(ls "$OUT"/libwolfssl.so.*.*.* | head -1)"
python3 - "$SO" "$OUT/build-record.json" <<'EOF'
import hashlib, json, subprocess, sys, os
so, out = sys.argv[1], sys.argv[2]
h = hashlib.sha256(open(so, "rb").read()).hexdigest()
cc = subprocess.run(["gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
json.dump({
    "component": "wolfcrypt-fips",
    "library": os.path.basename(so),
    "sha256": h,
    "source_version": "wolfssl-5.9.2-commercial-fips-linuxv5.2.1",
    "fips_module_version": "5.2.1",
    "fips_certificate": "#4718",
    "entropy_source": "wolfEntropy (SP 800-90B, ESV)",
    "build_flags": "--enable-fips=v5 --enable-wolfEntropy=nofallback",
    "compiler": cc,
    "operating_environment": os.uname().sysname + " " + os.uname().release + " " + os.uname().machine,
}, open(out, "w"), indent=2)
print("recorded", h, "->", out)
EOF
echo "build_fips: OK ($OUT)"
