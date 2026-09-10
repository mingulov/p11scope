#!/bin/sh
# Gate G3: hostile pointer aliases across the complete capture-policy matrix.
# Live BPF work is approval-gated; this file is kept syntactically and
# statically testable even when the gate remains UNRUN.
set -eu
cd "$(dirname "$0")/.."

WORK=${P11SCOPE_TASK4_WORK-target/canaries}
if [ "${P11SCOPE_TASK4_WORK+set}" = set ]; then
    case $WORK in /*) ;; *) echo "P11SCOPE_TASK4_WORK must be absolute" >&2; exit 2 ;; esac
fi
# The observer stays x86-64; this selects the workload, providers, helper, and
# their native-width scalar oracle together.
TARGET_BITS=${P11SCOPE_CANARY_TARGET_BITS-64}
case $TARGET_BITS in
    32|64) TARGET_CC_FLAG=-m$TARGET_BITS ;;
    *) echo "P11SCOPE_CANARY_TARGET_BITS must be 32 or 64" >&2; exit 2 ;;
esac

assert_lanes() {
    case ${1-} in
        --raw-events|--hostile-starts|--fault-starts)
            sudo python3 -I scripts/check-canary-evidence.py "$@" "$TARGET_BITS"
            ;;
        *) python3 -I scripts/check-canary-evidence.py "$@" "$TARGET_BITS" ;;
    esac
}

if [ "${1-}" = "--self-test" ]; then
    python3 -I scripts/check-capture-evidence.py --self-test
    assert_lanes --self-test
    python3 -I tests/python/test_canary_evidence.py --target-bits "$TARGET_BITS" -v
    python3 -I tests/python/test_canary_workload.py --target-bits "$TARGET_BITS" -v
    exit 0
fi

P11SCOPE_PRODUCT_BUILD_MODE=${P11SCOPE_PRODUCT_BUILD_MODE:-ordinary}
. scripts/product-build.sh

. scripts/lib.sh
require_non_root_caller
# The observer refuses to publish into a directory that has a group/world-writable
# non-sticky ancestor (src/output.rs), and a checkout under a shared source root
# has one, so the standalone default cannot live in the tree. Root it in a private
# 0700 directory on sticky /tmp; a supplied path stays the caller's to keep private.
[ "${P11SCOPE_TASK4_WORK+set}" = set ] || {
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-verify-XXXXXX")/$WORK
    echo "work root: $WORK"
}
(umask 077; mkdir -p "$WORK")

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v clang-18 >/dev/null || { echo "clang-18 required"; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
WPID=
WORKLOAD_STARTTIME=
SPID=
OBSERVER_PID=
OBSERVER_STARTTIME=
WORKER_STOPPED=
PUBLISH_TMP=
cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    if [ -n "$OBSERVER_PID" ] && [ -n "$WORKER_STOPPED" ]; then
        signal_verified_root_process CONT "$OBSERVER_PID" "$OBSERVER_STARTTIME" \
            2>/dev/null || true
        [ -z "$SPID" ] || kill -CONT "$SPID" 2>/dev/null || true
        WORKER_STOPPED=
    fi
    if [ -n "$OBSERVER_PID" ] && [ -n "$OBSERVER_STARTTIME" ]; then
        signal_verified_root_process TERM "$OBSERVER_PID" "$OBSERVER_STARTTIME" \
            2>/dev/null || true
    elif [ -n "$SPID" ]; then
        kill -TERM "$SPID" 2>/dev/null || true
    fi
    if [ -n "$WPID" ] && [ -n "$WORKLOAD_STARTTIME" ]; then
        signal_verified_process KILL "$WPID" "$WORKLOAD_STARTTIME" 2>/dev/null || true
    fi
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    [ -z "$PUBLISH_TMP" ] || cleanup_step rm -f -- "$PUBLISH_TMP"
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build ==="
rm -rf "$WORK/default-build" "$WORK/feature-build" "$WORK/helper-build"
p11scope_product_build "$P11SCOPE_PRODUCT_BUILD_MODE" \
    --release --workspace --target-dir "$WORK/default-build"
p11scope_product_build "$P11SCOPE_PRODUCT_BUILD_MODE" \
    --release --workspace --features unsafe-unvalidated-metadata \
    --target-dir "$WORK/feature-build"
P11SCOPE_DEFAULT="$WORK/default-build/release/p11scope"
P11SCOPE_FEATURE="$WORK/feature-build/release/p11scope"
case $TARGET_BITS in
    32)
        p11scope_product_build "$P11SCOPE_PRODUCT_BUILD_MODE" \
            --release -p p11scope-discover \
            --target i686-unknown-linux-gnu --target-dir "$WORK/helper-build"
        P11SCOPE_DISCOVER="$WORK/helper-build/i686-unknown-linux-gnu/release/p11scope-discover"
        ;;
    64) P11SCOPE_DISCOVER="$WORK/default-build/release/p11scope-discover" ;;
esac
rm -rf "$WORK/task-storage-reader"
scripts/build-task-storage-reader.sh "$WORK/task-storage-reader"
TASK_STORAGE_READER=$WORK/task-storage-reader/dump-task-storage
TASK_STORAGE_OBJECT=$WORK/task-storage-reader/dump-task-storage.bpf.o
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
gcc "$TARGET_CC_FLAG" -std=c11 -O0 -Wall -Wextra -o "$WORK/canary_workload" \
    scripts/fixtures/canary_workload.c -ldl -pthread
gcc "$TARGET_CC_FLAG" -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 \
    -o "$WORK/matrix-provider.so" crates/discover/tests/fixture/version_matrix.c
gcc "$TARGET_CC_FLAG" -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 -DPRIVACY_BLOCKS=1 \
    -o "$WORK/privacy-provider.so" crates/discover/tests/fixture/version_matrix.c
python3 -I - "$TARGET_BITS" "$WORK/canary_workload" "$WORK/matrix-provider.so" \
    "$WORK/privacy-provider.so" "$P11SCOPE_DISCOVER" "$P11SCOPE_DEFAULT" \
    "$P11SCOPE_FEATURE" <<'PY'
from pathlib import Path
import struct
import sys

bits = int(sys.argv[1])
expected_target = (1 if bits == 32 else 2, 3 if bits == 32 else 62)
for path in map(Path, sys.argv[2:6]):
    header = path.read_bytes()[:20]
    actual = (header[4], struct.unpack_from("<H", header, 18)[0])
    assert header[:4] == b"\x7fELF" and header[5] == 1 and actual == expected_target, (
        path, bits, actual
    )
for path in map(Path, sys.argv[6:]):
    header = path.read_bytes()[:20]
    actual = (header[4], struct.unpack_from("<H", header, 18)[0])
    assert header[:4] == b"\x7fELF" and header[5] == 1 and actual == (2, 62), (path, actual)
print(f"target/helper ELF{bits} and x86-64 observers: OK")
PY
python3 -I scripts/dump-owned-bpf-maps.py --self-test

set -- "$WORK"/default-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "default BPF object is not unique"; exit 1; }
DEFAULT_BPF=$1
set -- "$WORK"/feature-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "feature BPF object is not unique"; exit 1; }
FEATURE_BPF=$1
python3 -I scripts/check-bpf-map-defs.py --policy-inventory "$DEFAULT_BPF" "$FEATURE_BPF"

wait_for_stopped() {
    wfs_pid=$1
    wfs_starttime=$2
    wfs_attempt=0
    while [ "$wfs_attempt" -lt 160 ]; do
        root_process_matches_starttime "$wfs_pid" "$wfs_starttime" || {
            echo "observer $wfs_pid exited or changed identity" >&2
            return 1
        }
        wfs_state=$(sudo awk '$1 == "State:" { print $2; exit }' \
            "/proc/$wfs_pid/status" 2>/dev/null || true)
        [ "$wfs_state" = T ] && return 0
        wfs_attempt=$((wfs_attempt + 1))
        sleep 0.05
    done
    echo "observer $wfs_pid did not reach State: T after SIGSTOP" >&2
    return 1
}

wait_for_workload_stopped() {
    wfws_pid=$1
    wfws_starttime=$2
    wfws_attempt=0
    while [ "$wfws_attempt" -lt 160 ]; do
        process_matches_starttime "$wfws_pid" "$wfws_starttime" || {
            echo "workload $wfws_pid exited or changed identity" >&2
            return 1
        }
        wfws_state=$(awk '$1 == "State:" { print $2; exit }' \
            "/proc/$wfws_pid/status" 2>/dev/null || true)
        [ "$wfws_state" = T ] && return 0
        wfws_attempt=$((wfws_attempt + 1))
        sleep 0.05
    done
    echo "workload $wfws_pid did not stop after completing its calls" >&2
    return 1
}

run_lane() {
    lane=$1
    build=$2
    kind=$3
    case $build in
        default) lane_observer=$P11SCOPE_DEFAULT; lane_unsafe= ;;
        feature) lane_observer=$P11SCOPE_FEATURE; lane_unsafe= ;;
        feature-unsafe) lane_observer=$P11SCOPE_FEATURE; lane_unsafe=1 ;;
        *) echo "unknown lane build: $build" >&2; exit 1 ;;
    esac
    case $kind in
        profile) lane_command=profile; lane_mode=profile ;;
        trace) lane_command=trace; lane_mode= ;;
        metrics) lane_command=profile; lane_mode=metrics ;;
        *) echo "unknown lane kind: $kind" >&2; exit 1 ;;
    esac

    echo "=== $lane ($build $kind) ==="
    rm -f "$WORK/$lane.ready" "$WORK/$lane.go" "$WORK/$lane.output" \
        "$WORK/$lane.observer.log" "$WORK/$lane.workload.log" \
        "$WORK/$lane".*.raw \
        "$WORK"/mapdump_*_"$lane".json "$WORK"/mapdump_*_"$lane".bin \
        "$WORK/mapdump_manifest_$lane.json"
    "$WORK/canary_workload" "$WORK/matrix-provider.so" matrix \
        "$WORK/$lane.ready" "$WORK/$lane.go" \
        > "$WORK/$lane.workload.log" 2>&1 &
    WPID=$!
    WORKLOAD_STARTTIME=$(process_starttime "$WPID") || {
        echo "$lane workload identity unavailable"
        exit 1
    }
    lane_workload_pid=$WPID
    lane_ready_attempt=0
    while [ ! -f "$WORK/$lane.ready" ] && [ "$lane_ready_attempt" -lt 160 ]; do
        kill -0 "$WPID" 2>/dev/null || { echo "$lane workload exited before ready"; exit 1; }
        lane_ready_attempt=$((lane_ready_attempt + 1))
        sleep 0.05
    done
    test -f "$WORK/$lane.ready" || { echo "$lane workload never became ready"; exit 1; }

    set -- "$lane_observer" "$lane_command" \
        --manifest "$WORK/matrix-manifest.json" --pid "$WPID"
    [ -z "$lane_mode" ] || set -- "$@" --mode "$lane_mode"
    [ -z "$lane_unsafe" ] || set -- "$@" --unsafe-unvalidated-metadata
    set -- "$@" --duration 6 -o "$WORK/$lane.output"
    launch_root_recorded_process "$WORK/$lane.observer.pid" "$WORK/$lane.observer.log" "$@" \
        || { echo "$lane observer identity invalid"; exit 1; }
    SPID=$ROOT_LAUNCH_PID
    OBSERVER_PID=$ROOT_PROCESS_PID
    OBSERVER_STARTTIME=$ROOT_PROCESS_STARTTIME
    case $build in
        feature-unsafe) lane_privacy=unsafe-unvalidated-metadata ;;
        *) [ "$kind" = metrics ] && lane_privacy=aggregate-only || lane_privacy=allowlisted ;;
    esac
    wait_for_capture_ready "$WORK/$lane.observer.log" "$lane_privacy" "$kind"
    signal_verified_root_process STOP "$OBSERVER_PID" "$OBSERVER_STARTTIME"
    WORKER_STOPPED=1
    wait_for_stopped "$OBSERVER_PID" "$OBSERVER_STARTTIME"
    touch "$WORK/$lane.go"
    wait_for_workload_stopped "$WPID" "$WORKLOAD_STARTTIME"
    sudo python3 -I scripts/dump-owned-bpf-maps.py \
        "$OBSERVER_PID" "$WORK" "$lane" 0 16384 \
        "$TASK_STORAGE_READER" "$TASK_STORAGE_OBJECT"
    assert_lanes --raw-events "$WORK/mapdump_manifest_$lane.json" "$lane" \
        "$lane_workload_pid" "$WORK/$lane"
    reclaim_root_output "$WORK"/mapdump_*_"$lane".json \
        "$WORK/$lane".*.raw
    signal_verified_root_process CONT "$OBSERVER_PID" "$OBSERVER_STARTTIME"
    # sudo suspends itself when its command stops; resume it too or `wait`
    # below never returns (and the exited observer stays a zombie under it).
    kill -CONT "$SPID"
    WORKER_STOPPED=
    if wait "$SPID"; then SPID=; OBSERVER_PID=; OBSERVER_STARTTIME=; else status=$?; SPID=; OBSERVER_PID=; OBSERVER_STARTTIME=; echo "$lane observer failed: $status"; exit "$status"; fi
    signal_verified_process CONT "$WPID" "$WORKLOAD_STARTTIME"
    if wait "$WPID"; then
        WPID=
        WORKLOAD_STARTTIME=
    else
        status=$?
        WPID=
        WORKLOAD_STARTTIME=
        echo "$lane workload failed: $status"
        exit "$status"
    fi
    reclaim_root_output "$WORK/$lane.output"
    python3 -I scripts/check-capture-evidence.py canary "$lane" "$WORK/$lane.output" \
        "$TARGET_BITS"
}

echo "=== discover deterministic matrix providers ==="
"$P11SCOPE_DISCOVER" \
    --module "$WORK/matrix-provider.so" -o "$WORK/matrix-manifest.json"
"$P11SCOPE_DISCOVER" \
    --module "$WORK/privacy-provider.so" -o "$WORK/privacy-manifest.json"
rm -f "$WORK"/mapdump_*.json "$WORK"/mapdump_*.bin "$WORK"/mapdump_manifest_*.json

while read -r lane build kind; do
    run_lane "$lane" "$build" "$kind"
done <<'LANES'
default-safe-profile default profile
default-safe-trace default trace
feature-safe-profile feature profile
feature-safe-trace feature trace
feature-unsafe-profile feature-unsafe profile
feature-unsafe-trace feature-unsafe trace
aggregate-only-metrics default metrics
LANES

run_start_lane() {
    start_lane=$1
    start_build=$2
    start_mode=$3
    start_entries=$4
    start_oracle=$5
    case $start_build in
        default) start_observer=$P11SCOPE_DEFAULT; start_privacy=allowlisted; start_unsafe= ;;
        feature) start_observer=$P11SCOPE_FEATURE; start_privacy=allowlisted; start_unsafe= ;;
        feature-unsafe) start_observer=$P11SCOPE_FEATURE; start_privacy=unsafe-unvalidated-metadata; start_unsafe=1 ;;
        *) echo "unknown START build: $start_build" >&2; exit 1 ;;
    esac
    rm -f "$WORK/$start_lane.ready" "$WORK/$start_lane.go" \
        "$WORK/$start_lane.output" "$WORK/$start_lane.observer.log" \
        "$WORK/$start_lane.workload.log" "$WORK"/mapdump_*_"$start_lane".json \
        "$WORK"/mapdump_*_"$start_lane".bin \
        "$WORK/$start_lane".*.raw \
        "$WORK/mapdump_manifest_$start_lane.json"
    "$WORK/canary_workload" "$WORK/privacy-provider.so" "$start_mode" \
        "$WORK/$start_lane.ready" "$WORK/$start_lane.go" \
        > "$WORK/$start_lane.workload.log" 2>&1 &
    WPID=$!
    WORKLOAD_STARTTIME=$(process_starttime "$WPID") || {
        echo "$start_lane workload identity unavailable"
        exit 1
    }
    start_workload_pid=$WPID
    start_ready_attempt=0
    while [ ! -f "$WORK/$start_lane.ready" ] && [ "$start_ready_attempt" -lt 160 ]; do
        kill -0 "$WPID" 2>/dev/null || {
            echo "$start_lane workload exited before complete READY"
            exit 1
        }
        start_ready_attempt=$((start_ready_attempt + 1))
        sleep 0.05
    done
    test -f "$WORK/$start_lane.ready" || {
        echo "$start_lane workload never published complete READY"
        exit 1
    }
    set -- "$start_observer" profile --manifest "$WORK/privacy-manifest.json" \
        --pid "$WPID" \
        --mode profile --duration 8 -o "$WORK/$start_lane.output"
    [ -z "$start_unsafe" ] || set -- "$@" --unsafe-unvalidated-metadata
    launch_root_recorded_process "$WORK/$start_lane.observer.pid" \
        "$WORK/$start_lane.observer.log" "$@" \
        || { echo "$start_lane observer identity invalid"; exit 1; }
    SPID=$ROOT_LAUNCH_PID
    OBSERVER_PID=$ROOT_PROCESS_PID
    OBSERVER_STARTTIME=$ROOT_PROCESS_STARTTIME
    wait_for_capture_ready "$WORK/$start_lane.observer.log" "$start_privacy" profile
    touch "$WORK/$start_lane.go"
    sudo python3 -I scripts/dump-owned-bpf-maps.py "$OBSERVER_PID" "$WORK" \
        "$start_lane" "$start_entries" 16384 \
        "$TASK_STORAGE_READER" "$TASK_STORAGE_OBJECT"
    assert_lanes --raw-events "$WORK/mapdump_manifest_$start_lane.json" \
        "$start_lane" "$start_workload_pid" "$WORK/$start_lane"
    reclaim_root_output "$WORK"/mapdump_*_"$start_lane".json \
        "$WORK/$start_lane".*.raw
    if [ "$start_oracle" = --fault-starts ]; then
        assert_lanes "$start_oracle" "$WORK/mapdump_manifest_$start_lane.json" \
            "$start_workload_pid"
    else
        assert_lanes "$start_oracle" "$WORK/mapdump_manifest_$start_lane.json" \
            "$WORK/$start_lane.workload.log" "$start_workload_pid"
    fi
    process_matches_starttime "$WPID" "$WORKLOAD_STARTTIME" || {
        echo "$start_lane workload exited before START oracle completed"
        exit 1
    }
    signal_verified_process TERM "$WPID" "$WORKLOAD_STARTTIME" || {
        echo "$start_lane workload could not be terminated"
        exit 1
    }
    if wait "$WPID"; then
        start_status=0
        WPID=
        WORKLOAD_STARTTIME=
    else
        start_status=$?
        WPID=
        WORKLOAD_STARTTIME=
    fi
    [ "$start_status" -eq 143 ] || {
        echo "$start_lane workload exit status $start_status, expected SIGTERM status 143"
        exit 1
    }
    if wait "$SPID"; then SPID=; OBSERVER_PID=; OBSERVER_STARTTIME=; else status=$?; SPID=; OBSERVER_PID=; OBSERVER_STARTTIME=; echo "$start_lane observer failed: $status"; exit "$status"; fi
    reclaim_root_output "$WORK/$start_lane.output"
    if [ "$start_lane" = default-safe-start ]; then
        PUBLISH_TMP=$(mktemp "$WORK/.mapdump_START_live.XXXXXXXX")
        cp "$WORK/mapdump_START_$start_lane.json" "$PUBLISH_TMP"
        mv -f "$PUBLISH_TMP" "$WORK/mapdump_START_live.json"
        PUBLISH_TMP=
    fi
}

echo "=== live safe START policy: hostile exact-name and mechanism controls ==="
while read -r lane build; do
    run_start_lane "$lane" "$build" blocked 4 --hostile-starts
done <<'BLOCKED_LANES'
default-safe-start default
feature-safe-start feature
BLOCKED_LANES

echo "=== live diagnostic START policy: distinct template faults ==="
run_start_lane feature-unsafe-fault feature-unsafe faults 2 --fault-starts

echo "=== assert capture-policy matrix ==="
assert_lanes "$WORK"
echo "=== canary matrix: ALL OK ==="
