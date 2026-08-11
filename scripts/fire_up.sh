#!/bin/bash
# Build, validate, configure, and start the local Veloce agent.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE_DIR="$HOME/.veloce"
GATE_LOG="$STATE_DIR/run-gates.log"

die() {
    echo "fire_up: $*" >&2
    exit 1
}

cd "$ROOT"
umask 077

available_kib="$(df -Pk "$ROOT" | awk 'NR == 2 {print $4}')"
if [ "$available_kib" -lt 5242880 ]; then
    df -h "$ROOT" >&2
    die "at least 5 GiB free is required before building"
fi

if [ ! -f vendor/wolfssl/configure ]; then
    echo "fire_up: licensed bundle is not ready" >&2
    echo "Run: bash scripts/setup_bundle.sh [optional-bundle-directory]" >&2
    exit 2
fi

install -d -m 700 "$STATE_DIR"
echo "fire_up: building and running release gates (log: $GATE_LOG)"
if ! bash scripts/run_gates.sh 2>&1 | tee "$GATE_LOG"; then
    die "release gates failed; inspect the first failure above"
fi
grep -qx 'ALL GATES GREEN' "$GATE_LOG" || \
    die "release gates did not finish with ALL GATES GREEN"

compgen -G 'build/lib/fips/libwolfssl.so.*.*.*' >/dev/null || \
    die "FIPS library was not staged"
[ -f build/lib/pqc/libveloce-pqc.so ] || die "PQC provider was not staged"
[ -x build/bin/veloce-agent ] || die "agent binary was not staged"
[ -x build/bin/veloce ] || die "CLI binary was not staged"

python3 scripts/gen_config.py \
    --out "$STATE_DIR/agent.json" --socket "$STATE_DIR/agent.sock"

if [ -s "$STATE_DIR/agent.pid" ]; then
    recorded_pid="$(cat "$STATE_DIR/agent.pid")"
    if kill -0 "$recorded_pid" 2>/dev/null; then
        echo "fire_up: agent already running as PID $recorded_pid"
        build/bin/veloce --json status
        build/bin/veloce --json self-test
        exit 0
    fi
fi

running_agents="$(pgrep -u "$USER" -x veloce-agent || true)"
if [ -n "$running_agents" ]; then
    die "untracked veloce-agent PID(s): $running_agents"
fi

rm -f "$STATE_DIR/agent.pid" "$STATE_DIR/agent.sock"
nohup "$ROOT/build/bin/veloce-agent" \
    --config "$STATE_DIR/agent.json" --quiet \
    >"$STATE_DIR/agent.log" 2>&1 &
agent_pid=$!
printf '%s\n' "$agent_pid" >"$STATE_DIR/agent.pid"

for _ in $(seq 1 20); do
    if ! kill -0 "$agent_pid" 2>/dev/null; then
        tail -n 100 "$STATE_DIR/agent.log" >&2 || true
        die "agent exited during startup"
    fi
    [ -S "$STATE_DIR/agent.sock" ] && break
    sleep 0.25
done

if [ ! -S "$STATE_DIR/agent.sock" ]; then
    tail -n 100 "$STATE_DIR/agent.log" >&2 || true
    die "agent did not create $STATE_DIR/agent.sock"
fi

build/bin/veloce --json status
build/bin/veloce --json self-test
echo "fire_up: Veloce is running as PID $agent_pid"
echo "fire_up: log: $STATE_DIR/agent.log"

