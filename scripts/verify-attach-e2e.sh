#!/bin/sh
# Gate G1: p11scope attaches at discovered offsets and counts a
# deterministic workload exactly. Oracle: spike/expected.txt, the ground
# truth for spike/harness.c.
#
# Two lanes, same oracle:
#   1. manifest-free — the memory scan is the only source of offsets;
#   2. manifest      — the same manifest the helper produces, corroborated
#                      against the scan (sources ["scan","manifest"], agreed).
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

# One capture, one lane. $1 is the output basename, the rest are the extra
# p11scope arguments this lane adds. The workload dlopens the provider, then
# blocks on the go-file: the scan needs the provider mapped before it runs,
# and the oracle needs every PKCS#11 call to happen after the probes are on.
run_lane() {
    lane=$1
    mode=$2
    shift 2
    rm -f "$WORK/$lane-go"
    "$WORK/harness" "$MODULE" "$WORK/$lane-go" > "$WORK/$lane-workload.log" 2>&1 &
    WPID=$!
    wait_for_mapped_provider "$WPID" libsofthsm2.so
    sudo --preserve-env=SOFTHSM2_CONF "$WORK/build/release/p11scope" profile \
        "$@" --pid "$WPID" \
        --mode metrics --duration 20 -o "$WORK/$lane.json" \
        > "$WORK/$lane.log" 2>&1 &
    SPID=$!
    wait_for_capture_ready "$WORK/$lane.log" aggregate-only metrics
    touch "$WORK/$lane-go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "workload failed: $status"; cat "$WORK/$lane-workload.log"; exit "$status"; fi
    if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "profiler failed: $status"; tail -n 20 "$WORK/$lane.log" || true; exit "$status"; fi
    tail -n 3 "$WORK/$lane.log"
    reclaim_root_output "$WORK/$lane.json"
    python3 scripts/check-capture-evidence.py "$mode" \
        "$WORK/$lane.json" spike/expected.txt
}

echo "=== observe (manifest-free: memory scan only) ==="
run_lane observed-scan clean-metrics
python3 - "$WORK/observed-scan.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
ev = doc["evidence"]
assert ev["authority"] == "hash-pinned", ev["authority"]
assert [m["sources"] for m in ev["discovery"]] == [["scan"]], ev["discovery"]
assert [m["corroborated"] for m in ev["discovery"]] == [False], ev["discovery"]
assert [m["corroboration"] for m in ev["discovery"]] == [["single_source"]], ev["discovery"]
assert doc["capture"]["modules"][0]["path"].endswith("libsofthsm2.so"), doc["capture"]
print("manifest-free lane: OK")
PY

echo "=== discover (the helper still produces a manifest, for the corroboration lane) ==="
"$WORK/build/release/p11scope-discover" --module "$MODULE" -o "$WORK/manifest.json"

echo "=== observe (manifest corroborated against the scan) ==="
run_lane observed clean-metrics-corroborated --manifest "$WORK/manifest.json"
python3 - "$WORK/observed.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
ev = doc["evidence"]
assert ev["authority"] == "hash-pinned", ev["authority"]
assert [m["sources"] for m in ev["discovery"]] == [["scan", "manifest"]], ev["discovery"]
assert [m["corroborated"] for m in ev["discovery"]] == [True], ev["discovery"]
assert [m["corroboration"] for m in ev["discovery"]] == [["agreed"]], ev["discovery"]
assert ev["discovery_conflicts"] == 0, ev["discovery_conflicts"]
assert ev["discovery_uncorroborated"] == 0, ev["discovery_uncorroborated"]
print("manifest-corroboration lane: OK")
PY

echo "=== e2e: ALL OK ==="
