#!/bin/sh
# Gate G1: p11scope attaches at discovered offsets and counts a
# deterministic workload exactly. Oracle: spike/expected.txt, the ground
# truth for spike/harness.c.
set -eu
cd "$(dirname "$0")/.."

MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/e2e
WPID=
SPID=
. scripts/lib.sh
require_non_root_caller
mkdir -p "$WORK"

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    [ -z "$WPID" ] || kill "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || true
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

echo "=== build ==="
rm -rf "$WORK/build"
cargo +1.88 build --locked --release --workspace --target-dir "$WORK/build"
gcc -O0 -o "$WORK/harness" spike/harness.c -ldl

echo "=== softhsm token ==="
# harness.c calls C_GetSlotList(tokenPresent=1, ...) and requires at least
# one initialized token. The system-wide /etc/softhsm/softhsm2.conf and
# /var/lib/softhsm/tokens are root:softhsm-only on this host, so point
# SOFTHSM2_CONF at a private, disposable token store instead of requiring
# host-level SoftHSM setup.
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
rm -rf "$WORK/tokens"
mkdir -p "$WORK/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $PWD/$WORK/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
softhsm2-util --init-token --free --label e2e --so-pin 1234 --pin 1234 >/dev/null

echo "=== discover ==="
"$WORK/build/release/p11scope-discover" --module "$MODULE" -o "$WORK/manifest.json"

echo "=== observe ==="
# The workload waits for a go-file so probes are attached before it runs
# a single call — attach-before-run is the whole point. The `exec` inside
# the subshell replaces the subshell's process image with the harness, so
# $! (captured before exec runs) stays valid as the harness's real pid.
rm -f "$WORK/go"
( while [ ! -f "$WORK/go" ]; do sleep 0.05; done; exec "$WORK/harness" "$MODULE" ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$WORK/build/release/p11scope" profile \
    --manifest "$WORK/manifest.json" --pid "$WPID" \
    --mode metrics --duration 20 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/profile.log" aggregate-only metrics
touch "$WORK/go"
if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "workload failed: $status"; exit "$status"; fi
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "profiler failed: $status"; tail -n 20 "$WORK/profile.log" || true; exit "$status"; fi
tail -n 20 "$WORK/profile.log"
reclaim_root_output "$WORK/observed.json"

echo "=== verify against spike/expected.txt ==="
python3 scripts/check-capture-evidence.py clean-metrics \
    "$WORK/observed.json" spike/expected.txt

echo "=== e2e: ALL OK ==="
