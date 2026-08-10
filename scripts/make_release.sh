#!/bin/bash
# Assemble the distributable Veloce release archive (Linux x86-64).
#
# Contents: binaries, object-code libraries with recorded hashes, Python
# wheel, docs, license and notices. The wolfSSL agreement permits
# object-code redistribution only (spec 8.1): this script hard-fails if any
# wolfSSL source path leaks into the archive.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VER="${VELOCE_VERSION:-1.0.0}"
NAME="veloce-${VER}-linux-x86_64"
STAGE="$ROOT/build/dist/$NAME"

for f in build/bin/veloce-agent build/lib/pqc/libveloce-pqc.so; do
    [ -e "$f" ] || { echo "make_release: missing $f (run scripts/run_gates.sh first)" >&2; exit 1; }
done

rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/docs" "$STAGE/examples" \
         "$STAGE/installer"

cp build/bin/veloce-agent "$STAGE/bin/"
[ -f build/bin/veloce ] && cp build/bin/veloce "$STAGE/bin/"
[ -f build/bin/qsearch ] && cp build/bin/qsearch "$STAGE/bin/"

# Object code only, with the recorded build hashes that feed the CBOM.
cp build/lib/fips/libwolfssl.so.*.*.* "$STAGE/lib/"
cp build/lib/fips/build-record.json "$STAGE/lib/wolfcrypt-fips.build-record.json"
cp build/lib/pqc/libveloce-pqc.so "$STAGE/lib/"
cp build/lib/pqc/build-record.json "$STAGE/lib/veloce-pqc.build-record.json"

cp LICENSE THIRD_PARTY_NOTICES.md "$STAGE/"
cp docs/quickstart.md docs/STATUS.md ipc/protocol.md "$STAGE/docs/"
cp examples/python-demo.py examples/README.md "$STAGE/examples/"
cp installer/linux/veloce-agent.service installer/README.md "$STAGE/installer/"
cp scripts/gen_config.py "$STAGE/bin/veloce-gen-config"

# Python wheel (pure Python, platform independent).
python3 -m pip wheel --no-deps -q -w "$ROOT/build/dist" ./python
cp "$ROOT"/build/dist/veloce_pqc-*.whl "$STAGE/" 2>/dev/null || true

cat > "$STAGE/README.txt" <<EOF
Veloce PQC SDK $VER (Linux x86-64), Lightrider Inc
FIPS 140-3 module: wolfCrypt v5.2.1, CMVP certificate #4718 (object code)

Quick start:
  1. bin/veloce-gen-config          (writes ~/.veloce/agent.json; edit
                                     fips_lib/pqc_lib to the lib/ paths)
  2. bin/veloce-agent --config ~/.veloce/agent.json &
  3. bin/veloce status
  4. pip install veloce_pqc-*.whl ; python3 -c "import veloce; \
     veloce.initialize(); print(veloce.banner())"

See docs/quickstart.md. License: LICENSE (Lightrider commercial),
THIRD_PARTY_NOTICES.md (wolfSSL attribution).
EOF

# Distribution safety gate: no wolfSSL source, no licensed-bundle paths.
if find "$STAGE" -name '*.c' -o -name '*.h' -o -name 'configure' \
        | grep -q .; then
    echo "make_release: source files detected in release stage; aborting" >&2
    find "$STAGE" -name '*.c' -o -name '*.h' | head >&2
    exit 1
fi

tar -C "$ROOT/build/dist" -czf "$ROOT/build/dist/$NAME.tar.gz" "$NAME"
( cd "$ROOT/build/dist" && sha256sum "$NAME.tar.gz" veloce_pqc-*.whl \
      2>/dev/null > SHA256SUMS )
echo "release: build/dist/$NAME.tar.gz"
cat "$ROOT/build/dist/SHA256SUMS"
