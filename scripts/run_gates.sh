#!/bin/bash
# Veloce gate battery (spec 9, 10): builds every component that is not yet
# staged, then runs the release-gate test suite. Release rule: V1 does not
# ship until every gate passes.
#
#   bash scripts/run_gates.sh          build as needed + run all gates
#   FORCE_REBUILD=1 bash scripts/run_gates.sh   rebuild everything
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"
FAIL=0

step() { printf '\n=== %s ===\n' "$1"; }

step "S0: wolfCrypt FIPS module (gate G0)"
if [ "${FORCE_REBUILD:-0}" = "1" ] || ! ls build/lib/fips/libwolfssl.so.*.*.* >/dev/null 2>&1; then
    bash scripts/build_fips.sh || { echo "GATE G0 FAILED"; exit 1; }
else
    echo "already staged (build/lib/fips); FORCE_REBUILD=1 to rebuild"
fi

step "S1: PQC provider beside the FIPS boundary"
if [ "${FORCE_REBUILD:-0}" = "1" ] || [ ! -f build/lib/pqc/libveloce-pqc.so ]; then
    bash scripts/build_pqc.sh || { echo "PQC PROVIDER GATE FAILED"; exit 1; }
else
    echo "already staged (build/lib/pqc)"
fi

step "S1: Veloce agent"
make -C agent || exit 1

step "S2/S3: qSearch + CLI (Rust)"
if command -v cargo >/dev/null 2>&1; then
    (cd qsearch && cargo build --release) || exit 1
    (cd cli && cargo build --release) || exit 1
    mkdir -p build/bin
    cp qsearch/target/release/qsearch cli/target/release/veloce build/bin/
else
    echo "cargo not found; skipping Rust builds (install rustup)"
fi

step "Configuration"
python3 scripts/gen_config.py

step "Gate battery (pytest)"
if ! python3 -c "import pytest" >/dev/null 2>&1; then
    python3 -m pip install --user --quiet pytest || {
        echo "cannot install pytest"; exit 1; }
fi
python3 -m pytest tests -v --tb=short || FAIL=1

step "Result"
if [ "$FAIL" = "0" ]; then
    echo "ALL GATES GREEN"
else
    echo "GATE FAILURES PRESENT"
fi
exit $FAIL
