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

# The lane oracle, in one place. `--self-test` runs it over synthetic evidence
# and requires every claimed field to refuse a mutation, unprivileged.
assert_lane_evidence() {
    python3 - "$@" <<'PY'
import copy
import json
import sys


def oracle(document, lane):
    evidence = document["evidence"]
    discovery = evidence["discovery"]
    assert evidence["authority"] == "hash-pinned", evidence["authority"]
    assert document["capture"]["modules"][0]["path"].endswith("libsofthsm2.so"), document["capture"]
    if lane == "scan":
        assert [m["sources"] for m in discovery] == [["scan"]], discovery
        assert [m["corroborated"] for m in discovery] == [False], discovery
        assert [m["corroboration"] for m in discovery] == [["single_source"]], discovery
    else:
        assert [m["sources"] for m in discovery] == [["scan", "manifest"]], discovery
        assert [m["corroborated"] for m in discovery] == [True], discovery
        assert [m["corroboration"] for m in discovery] == [["agreed"]], discovery
        assert evidence["discovery_conflicts"] == 0, evidence["discovery_conflicts"]
        assert evidence["discovery_uncorroborated"] == 0, evidence["discovery_uncorroborated"]


def good(lane):
    corroborated = lane != "scan"
    return {
        "evidence": {
            "authority": "hash-pinned",
            "discovery": [
                {
                    "sources": ["scan", "manifest"] if corroborated else ["scan"],
                    "corroborated": corroborated,
                    "corroboration": ["agreed"] if corroborated else ["single_source"],
                }
            ],
            "discovery_conflicts": 0,
            "discovery_uncorroborated": 0,
        },
        "capture": {"modules": [{"path": "/usr/lib/softhsm/libsofthsm2.so"}]},
    }


def mutate(document, path, value):
    mutated = copy.deepcopy(document)
    cursor = mutated
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return mutated


if sys.argv[1] == "--self-test":
    lanes = {
        "scan": [
            ("authority", ["evidence", "authority"], "unpinned"),
            ("scan-only sources", ["evidence", "discovery", 0, "sources"], ["scan", "manifest"]),
            ("uncorroborated flag", ["evidence", "discovery", 0, "corroborated"], True),
            ("single-source label", ["evidence", "discovery", 0, "corroboration"], ["agreed"]),
            ("captured module", ["capture", "modules", 0, "path"], "/tmp/other.so"),
        ],
        "manifest": [
            ("authority", ["evidence", "authority"], "unpinned"),
            ("corroborated sources", ["evidence", "discovery", 0, "sources"], ["scan"]),
            ("corroborated flag", ["evidence", "discovery", 0, "corroborated"], False),
            ("agreement label", ["evidence", "discovery", 0, "corroboration"], ["single_source"]),
            ("discovery conflicts", ["evidence", "discovery_conflicts"], 1),
            ("uncorroborated count", ["evidence", "discovery_uncorroborated"], 1),
        ],
    }
    for lane, mutations in lanes.items():
        oracle(good(lane), lane)
        for label, path, value in mutations:
            try:
                oracle(mutate(good(lane), path, value), lane)
            except (AssertionError, KeyError, IndexError):
                continue
            raise SystemExit(f"mutation accepted: {lane} {label}")
    print("attach-e2e lane oracle mutations rejected: OK")
    raise SystemExit(0)

lane, path = sys.argv[1], sys.argv[2]
oracle(json.load(open(path)), lane)
print(f"{lane} lane: OK")
PY
}

if [ "${1-}" = "--self-test" ]; then
    [ "$#" -eq 1 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
    assert_lane_evidence --self-test
    echo "verify-attach-e2e self-test: OK"
    exit 0
fi

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
assert_lane_evidence scan "$WORK/observed-scan.json"

echo "=== discover (the helper still produces a manifest, for the corroboration lane) ==="
"$WORK/build/release/p11scope-discover" --module "$MODULE" -o "$WORK/manifest.json"

echo "=== observe (manifest corroborated against the scan) ==="
run_lane observed clean-metrics-corroborated --manifest "$WORK/manifest.json"
assert_lane_evidence manifest "$WORK/observed.json"

echo "=== e2e: ALL OK ==="
