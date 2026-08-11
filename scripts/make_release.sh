#!/bin/bash
# Assemble the distributable Veloce release archive (Linux x86-64).
#
# Contents: binaries, object-code libraries with recorded hashes, optional
# Python wheel, docs, license and notices. The wolfSSL agreement permits
# object-code redistribution only (spec 8.1): this script hard-fails if any
# wolfSSL source path leaks into the archive.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VER="${VELOCE_VERSION:-1.0.0}"
INCLUDE_PYTHON_SDK="${VELOCE_INCLUDE_PYTHON_SDK:-1}"
NAME="veloce-${VER}-linux-x86_64"
STAGE="$ROOT/build/dist/$NAME"

case "$INCLUDE_PYTHON_SDK" in
    0|1) ;;
    *) echo "make_release: VELOCE_INCLUDE_PYTHON_SDK must be 0 or 1" >&2; exit 1 ;;
esac

for f in build/bin/veloce-agent build/lib/pqc/libveloce-pqc.so; do
    [ -e "$f" ] || { echo "make_release: missing $f (run scripts/run_gates.sh first)" >&2; exit 1; }
done

rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/docs" "$STAGE/installer"

cp build/bin/veloce-agent "$STAGE/bin/"
[ -f build/bin/veloce ] && cp build/bin/veloce "$STAGE/bin/"
[ -f build/bin/qsearch ] && cp build/bin/qsearch "$STAGE/bin/"

# Object code only, with the recorded build hashes that feed the CBOM.
cp build/lib/fips/libwolfssl.so.*.*.* "$STAGE/lib/"
cp build/lib/fips/build-record.json "$STAGE/lib/wolfcrypt-fips.build-record.json"
cp build/lib/pqc/libveloce-pqc.so "$STAGE/lib/"
cp build/lib/pqc/build-record.json "$STAGE/lib/veloce-pqc.build-record.json"

cp LICENSE THIRD_PARTY_NOTICES.md "$STAGE/"
cp docs/client-quickstart.md "$STAGE/docs/quickstart.md"
cp docs/two-server-manual-test.md "$STAGE/docs/"
cp docs/STATUS.md ipc/protocol.md "$STAGE/docs/"
cp installer/linux/veloce-agent.service installer/README.md "$STAGE/installer/"
cp installer/linux/veloce-fire-up "$STAGE/bin/veloce-fire-up"
chmod +x "$STAGE/bin/veloce-fire-up"

# Python wheel (pure Python, platform independent). Use the release host's
# validated build backend instead of downloading a newer backend at release
# time; this keeps the build offline and avoids build-backend drift.
find "$ROOT/build/dist" -maxdepth 1 -type f -name 'veloce_pqc-*.whl' -delete
WHEEL=""
if [ "$INCLUDE_PYTHON_SDK" = 1 ]; then
    python3 -m pip wheel --no-build-isolation --no-deps -q \
        -w "$ROOT/build/dist" ./python
    wheel_files=("$ROOT"/build/dist/veloce_pqc-*.whl)
    [ -f "${wheel_files[0]}" ] || {
        echo "make_release: Python wheel was not produced" >&2; exit 1; }
    [ "${#wheel_files[@]}" -eq 1 ] || {
        echo "make_release: expected one Python wheel" >&2; exit 1; }
    WHEEL="${wheel_files[0]}"
    cp "$WHEEL" "$STAGE/"
    mkdir -p "$STAGE/examples/two-server"
    cp examples/python-demo.py "$STAGE/examples/"
    cp examples/two-server/two_party_demo.py "$STAGE/examples/two-server/"
fi

cat > "$STAGE/README.txt" <<EOF
Veloce PQC SDK $VER (Linux x86-64), Lightrider Inc
FIPS 140-3 module: wolfCrypt v5.2.1, CMVP certificate #4718 (object code)

Quick start:
  1. bin/veloce-fire-up             (writes ~/.veloce/agent.json, starts
                                     the local agent, runs self-tests)
  2. bin/veloce status

See docs/quickstart.md. License: LICENSE (Lightrider commercial),
THIRD_PARTY_NOTICES.md (wolfSSL attribution).
EOF

if [ "$INCLUDE_PYTHON_SDK" = 1 ]; then
    cat >> "$STAGE/README.txt" <<'EOF'

Optional Python SDK:
  pip install veloce_pqc-*.whl
  python3 examples/python-demo.py
EOF
else
    cat >> "$STAGE/README.txt" <<'EOF'

SDK-free runtime delivery: the inspectable pure-Python SDK is not included.
EOF
fi

# Distribution safety gate: no wolfSSL source, no licensed-bundle paths.
if find "$STAGE" \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \
        -o -name '*.cxx' -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' \
        -o -name '*.hxx' -o -name '*.rs' -o -name '*.go' \
        -o -name 'configure' \) \
        | grep -q .; then
    echo "make_release: native source files detected in release stage; aborting" >&2
    find "$STAGE" \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \
        -o -name '*.cxx' -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' \
        -o -name '*.hxx' -o -name '*.rs' -o -name '*.go' \
        -o -name 'configure' \) | head >&2
    exit 1
fi

# A client archive is runtime-only: no licensed source trees, build copies,
# repository metadata, or internal plan may be present.
if find "$STAGE" \( -name .git -o -name vendor -o -name fips-src \
        -o -name pqc-src -o -name plan \) | grep -q .; then
    echo "make_release: internal/source directory detected; aborting" >&2
    exit 1
fi

# Do not inherit a release host's umask or default ACL into the client
# archive. This also supports extraction by root followed by use from an
# unprivileged account.
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/bin/veloce-agent" "$STAGE/bin/veloce-fire-up"
for executable in "$STAGE/bin/veloce" "$STAGE/bin/qsearch" \
        "$STAGE/examples/python-demo.py" \
        "$STAGE/examples/two-server/two_party_demo.py"; do
    [ ! -e "$executable" ] || chmod 0755 "$executable"
done

tar -C "$ROOT/build/dist" -czf "$ROOT/build/dist/$NAME.tar.gz" "$NAME"
checksum_files=("$NAME.tar.gz")
[ -z "$WHEEL" ] || checksum_files+=("$(basename "$WHEEL")")
( cd "$ROOT/build/dist" && sha256sum "${checksum_files[@]}" > SHA256SUMS )
chmod 0644 "$ROOT/build/dist/$NAME.tar.gz" "$ROOT/build/dist/SHA256SUMS"
[ -z "$WHEEL" ] || chmod 0644 "$WHEEL"
echo "release: build/dist/$NAME.tar.gz"
cat "$ROOT/build/dist/SHA256SUMS"
