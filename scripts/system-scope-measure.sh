#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# system-scope-measure.sh — controlled per-PID and --system captures for the
# measurement protocol (docs/testing/system-scope-measurement.md):
# identical deterministic workload, exact binary identity,
# and one JSON record + human summary per condition with phase timings,
# every loss counter, verdict, admission truth, and observer CPU/RSS/fds.
#
# Method: the gated two-phase workload (system-scope-workload.c) maps the
# provider and opens a session, waits for attach (the harness holds the go
# file until the discovery marker AND the attach-complete line land on
# stderr — the in-observer attach-end signal), then fires exactly N
# C_GenerateRandom calls. A /proc sampler
# (system-scope-sample.py, under sudo) records CPU/RSS/fds at 20 Hz; a
# timestamp pipe (system-scope-ts.py) dates stderr markers;
# system-scope-measure.py joins the observer report + traces + workload
# TRUTH into the record.
#
# Usage: scripts/system-scope-measure.sh [--scope pid|system|both]
#   [--mode metrics|profile|trace|both|all] [--duration S] [--n-calls N]
#   [--pace-us US] [--seed N] [--ring-bytes B] [--drain-interval-ms MS]
#   [--sink file|discard|slow-pipe] [--sink-rate-kbps KBPS]
#   [--work DIR] [--profile release|debug] [--binary PATH] [--no-build]
#
# both = metrics+profile (Task 1.4 shape); all adds trace. The sink selects
# the observer's stdout destination: file (default), discard (/dev/null: no
# sink backpressure), slow-pipe (a throttled FIFO reader: explicit
# downstream backpressure). Non-file sinks and trace mode use the weaker
# marker+settle attach gate (no attach-complete signal); the gate used is
# recorded per condition and validated post-hoc.
set -eu
cd "$(dirname "$0")/.."
. scripts/lib.sh

SCOPE=both
MODE=both
DURATION=8
N_CALLS=20000
PACE_US=0
SEED=1
RING_BYTES=
DRAIN_MS=
SINK=file
SINK_RATE_KBPS=4
# Under /var/tmp (sticky, root-owned) by default: the observer fails closed
# on output dirs with a writable ancestor, which rules out target/.
WORK=/var/tmp/p11scope-system-scope-measure
PROFILE=release
BINARY=
NO_BUILD=0
SOURCE_MODULE=/usr/lib/softhsm/libsofthsm2.so
MODULE=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --scope) SCOPE=$2; shift 2 ;;
        --mode) MODE=$2; shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --n-calls) N_CALLS=$2; shift 2 ;;
        --pace-us) PACE_US=$2; shift 2 ;;
        --seed) SEED=$2; shift 2 ;;
        --ring-bytes) RING_BYTES=$2; shift 2 ;;
        --drain-interval-ms) DRAIN_MS=$2; shift 2 ;;
        --sink) SINK=$2; shift 2 ;;
        --sink-rate-kbps) SINK_RATE_KBPS=$2; shift 2 ;;
        --work) WORK=$2; shift 2 ;;
        --profile) PROFILE=$2; shift 2 ;;
        --binary) BINARY=$2; shift 2 ;;
        --no-build) NO_BUILD=1; shift ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "$SCOPE" in pid|system|both) ;; *) echo "bad --scope: $SCOPE" >&2; exit 2 ;; esac
case "$MODE" in metrics|profile|trace|both|all) ;; *) echo "bad --mode: $MODE" >&2; exit 2 ;; esac
case "$SINK" in file|discard|slow-pipe) ;; *) echo "bad --sink: $SINK" >&2; exit 2 ;; esac
case "$PROFILE" in release|debug) ;; *) echo "bad --profile: $PROFILE" >&2; exit 2 ;; esac
case "$WORK" in /*) ;; *) WORK="$PWD/$WORK" ;; esac

WPID=
WPID_STARTTIME=
WPID_RECEIPT=
WTARGET_PID=
WTARGET_STARTTIME=
SPID=
SPID_STARTTIME=
SPID_RECEIPT=
STARGET_PID=
STARGET_STARTTIME=
SMPID=
SMPID_STARTTIME=
SMPID_RECEIPT=
TSPID=
TSPID_STARTTIME=
TSPID_RECEIPT=
TPID=
TPID_STARTTIME=
TPID_RECEIPT=
CFIFO=
SFIFO=
P11SCOPE_RECEIPT_HELPER="$PWD/scripts/system-scope-receipt.py"
export P11SCOPE_RECEIPT_HELPER
. scripts/system-scope-owned.sh

cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [ -n "$TSPID" ] && [ -n "$TSPID_STARTTIME" ] &&
       ! owned_finish "$TSPID" "$TSPID_STARTTIME" "$TSPID_RECEIPT" 0; then
        echo "timestamp helper teardown failed; left unreaped" >&2
    fi
    if [ -n "$TPID" ] && [ -n "$TPID_STARTTIME" ] &&
       ! owned_finish "$TPID" "$TPID_STARTTIME" "$TPID_RECEIPT" 0; then
        echo "sink helper teardown failed; left unreaped" >&2
    fi
    if [ -n "$SMPID" ] && [ -n "$SMPID_STARTTIME" ] &&
       ! owned_finish "$SMPID" "$SMPID_STARTTIME" "$SMPID_RECEIPT" 0; then
        echo "sampler teardown failed; left unreaped" >&2
    fi
    if [ -n "$SPID" ] && [ -n "$SPID_STARTTIME" ] &&
       ! owned_finish "$SPID" "$SPID_STARTTIME" "$SPID_RECEIPT" 0; then
        echo "observer teardown failed; left unreaped" >&2
    fi
    if [ -n "$WPID" ] && [ -n "$WPID_STARTTIME" ] &&
       ! owned_finish "$WPID" "$WPID_STARTTIME" "$WPID_RECEIPT" 0; then
        echo "workload teardown failed; left unreaped" >&2
    fi
    [ -z "$CFIFO" ] || rm -f "$CFIFO" || true
    [ -z "$SFIFO" ] || rm -f "$SFIFO" || true
    exit "$status"
}
. scripts/cleanup-traps.sh

require_non_root_caller
command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
command -v timeout >/dev/null || { echo "timeout required"; exit 1; }
sudo -n true || { echo "passwordless sudo required"; exit 1; }
test -f "$SOURCE_MODULE" || { echo "SoftHSM2 not installed at $SOURCE_MODULE"; exit 1; }
export TMPDIR=/var/tmp/p11scope-ws-tmp
mkdir -p "$TMPDIR" "$WORK"
# The observer fails closed on untrusted output dirs: 0700 caller-owned.
chmod 700 "$WORK"

# Every run gets a private provider inode. System-scope totals from an
# unrelated host process using the packaged SoftHSM object can therefore never
# satisfy this workload's physical-identity oracle.
mkdir -p "$WORK/provider"
chmod 700 "$WORK/provider"
MODULE="$WORK/provider/libsofthsm2-owned.so"
rm -f "$MODULE"
python3 -I scripts/system-scope-receipt.py file --path "$SOURCE_MODULE" \
    > "$WORK/provider-source.identity.json"
install -m 0555 "$SOURCE_MODULE" "$MODULE"
python3 -I scripts/system-scope-receipt.py file --path "$MODULE" \
    > "$WORK/provider-copy.identity.json"

echo "=== build ==="
gcc -O0 -o "$WORK/workload" scripts/system-scope-workload.c -ldl
if [ -z "$BINARY" ]; then
    if [ "$NO_BUILD" -eq 0 ]; then
        if [ "$PROFILE" = release ]; then
            scripts/cargo.sh "+$(cat .release-rust-version)" build --locked --offline --release -p p11scope -p p11scope-discover
        else
            scripts/cargo.sh "+$(cat .release-rust-version)" build --locked --offline -p p11scope -p p11scope-discover
        fi
    fi
    BINARY="$PWD/target/$PROFILE/p11scope"
    DISCOVER="$PWD/target/$PROFILE/p11scope-discover"
else
    case "$BINARY" in /*) ;; *) BINARY="$PWD/$BINARY" ;; esac
    DISCOVER="$(dirname "$BINARY")/p11scope-discover"
    PROFILE="explicit-binary"
fi
test -x "$BINARY" || { echo "no observer binary at $BINARY"; exit 1; }
test -x "$DISCOVER" || { echo "no discover binary at $DISCOVER"; exit 1; }
OBSERVER_SOURCE=$BINARY
DISCOVER_SOURCE=$DISCOVER
mkdir -p "$WORK/observer"
chmod 700 "$WORK/observer"
rm -f "$WORK/observer/p11scope" "$WORK/observer/p11scope-discover"
install -m 0555 "$OBSERVER_SOURCE" "$WORK/observer/p11scope"
install -m 0555 "$DISCOVER_SOURCE" "$WORK/observer/p11scope-discover"
BINARY="$WORK/observer/p11scope"
DISCOVER="$WORK/observer/p11scope-discover"
chmod 500 "$WORK/observer"
python3 -I scripts/system-scope-receipt.py file --path "$OBSERVER_SOURCE" \
    > "$WORK/observer-source.identity.json"
python3 -I scripts/system-scope-receipt.py file --path "$BINARY" \
    > "$WORK/observer.identity.json"

echo "=== private softhsm token ==="
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
rm -rf "$WORK/tokens"
mkdir -p "$WORK/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
softhsm2-util --init-token --free --label sys-scope-measure --so-pin 1234 --pin 1234 >/dev/null

echo "=== discover ==="
"$DISCOVER" --module "$MODULE" -o "$WORK/manifest.json"

GIT_REV=$(git rev-parse HEAD)
if [ -z "$(git status --porcelain)" ]; then GIT_CLEAN=true; else GIT_CLEAN=false; fi
# Tracked-tree cleanliness is the binary-identity signal: untracked helper
# scripts never affect the build, but a modified src/ file would.
if [ -z "$(git status --porcelain | grep -v '^??')" ]; then GIT_TRACKED_CLEAN=true; else GIT_TRACKED_CLEAN=false; fi
HARNESS_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Monotonic nanoseconds for phase math (wall clock would mix epochs with the
# sampler's CLOCK_MONOTONIC; fork cost is a constant sub-50ms offset).
mono_ns() {
    python3 -I -c 'import time; print(time.monotonic_ns())'
}
KERNEL=$(uname -r)
CPU=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
NCPU=$(nproc)

# wait_file <path> <timeout_s> — poll for a file to appear.
wait_file() {
    end=$(( $(date +%s) + $2 ))
    while [ ! -f "$1" ]; do
        [ "$(date +%s)" -lt "$end" ] || return 1
        sleep 0.05
    done
    return 0
}

# Classify one exact process generation without signalling it. Permission to
# send a signal says nothing about liveness for a root observer.
owned_require_live() {
    owned_live_state=$(owned_process_state "$1" "$2") || return 2
    case "$owned_live_state" in
        live) return 0 ;;
        terminal) return 1 ;;
        unknown) return 2 ;;
    esac
    return 2
}

# wait_file_alive <path> <observer-pid> <observer-birth>
#   <workload-pid> <workload-birth> <timeout_s> — a missing mapped handshake is a
# harness failure, and an observer that exits before owned calls are released
# cannot be turned into a short successful capture.
wait_file_alive() {
    end=$(( $(date +%s) + $6 ))
    while [ ! -f "$1" ]; do
        owned_live_status=0
        owned_require_live "$2" "$3" || owned_live_status=$?
        case "$owned_live_status" in 0) ;; 1) return 2 ;; *) return 4 ;; esac
        owned_live_status=0
        owned_require_live "$4" "$5" || owned_live_status=$?
        case "$owned_live_status" in 0) ;; 1) return 3 ;; *) return 5 ;; esac
        [ "$(date +%s)" -lt "$end" ] || return 1
        sleep 0.05
    done
    return 0
}

# collect_receipt <condition-dir> — run while the owned child is alive and
# gated. Root is used only to cross hosts whose ptrace policy denies a sibling
# process access to map_files; the output file is opened by this user.
collect_receipt() {
    python3 -I scripts/system-scope-receipt.py verify-file \
        --identity "$WORK/provider-source.identity.json" \
        --path "$SOURCE_MODULE" >/dev/null || return 1
    python3 -I scripts/system-scope-receipt.py verify-file \
        --identity "$WORK/provider-copy.identity.json" --path "$MODULE" >/dev/null \
        || return 1
    timeout --signal=TERM --kill-after=5s 30s \
      sudo -n python3 -I "$PWD/scripts/system-scope-receipt.py" mapping \
        --handshake "$1/mapped" --expected-file "$MODULE" \
        --source-file "$SOURCE_MODULE" > "$1/workload-mapping-receipt.json" \
        || return 1
    timeout --signal=TERM --kill-after=5s 30s \
      python3 -I scripts/system-scope-receipt.py metadata \
        --receipt "$1/workload-mapping-receipt.json" --observer "$BINARY" \
        --observer-source "$OBSERVER_SOURCE" \
        --source-file "$SOURCE_MODULE" --copy-file "$MODULE" \
        > "$1/receipt-metadata.json" || return 1
}

# wait_attach <cond_dir> <observer_pid> <observer_birth> <timeout_s> — hold the go file
# until discovery is done (marker on the timestamped stderr passthrough)
# AND the attach session is complete: the observer prints
# "p11scope: capturing: N probe(s) attached; stop with Ctrl-C" on stderr
# once probes are attached and the capture loop starts (capture_ready_line
# in src/run.rs — "the one readiness line ... scripts and supervisors
# wait for this line"), so that line is the in-observer attach-end signal.
# The 0801e79c "p11scope: attached N probe(s)" line is dead: merge
# 79a54f53 dropped it as a duplicate of the capturing line, so gating on
# it waits forever. The old first-live-frame stdout signal died with M-10
# (7eb86f0d made live frames terminal-only) while the harness captures
# observer stdout to a file, so a frame gate could never fire. An fd
# plateau is NOT the gate — under load attach stalls for seconds mid-ramp
# and a plateau detector fires early, releasing the workload burst into a
# half-attached observer (observed once: 1/20000 calls). A zero-probe
# capturing line still fires the gate (unlike bench-overhead.sh's
# zero-probe refusal): readiness means the attach session completed, and
# post-hoc counts prove the window. Returns 2 if the observer is terminal
# and 3 if its exact identity cannot be inspected.
wait_attach() {
    end=$(( $(date +%s) + $4 ))
    while :; do
        owned_live_status=0
        owned_require_live "$2" "$3" || owned_live_status=$?
        case "$owned_live_status" in 0) ;; 1) return 2 ;; *) return 3 ;; esac
        [ "$(date +%s)" -lt "$end" ] || return 1
        if grep -q "p11scope: discovery:" "$1/stderr.txt" 2>/dev/null \
            && grep -q -E "p11scope: capturing: [0-9]+ probe\(s\) attached" "$1/stderr.txt" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
}

# wait_marker <cond_dir> <observer_pid> <observer_birth> <timeout_s> — hold until the
# discovery marker lands on stderr. Weaker than wait_attach (no
# in-observer attach-end signal): used only for trace mode and the
# discard sink. Settles after the marker; post-hoc counts prove the
# window.
wait_marker() {
    end=$(( $(date +%s) + $4 ))
    while :; do
        owned_live_status=0
        owned_require_live "$2" "$3" || owned_live_status=$?
        case "$owned_live_status" in 0) ;; 1) return 2 ;; *) return 3 ;; esac
        [ "$(date +%s)" -lt "$end" ] || return 1
        if grep -q "p11scope: discovery:" "$1/stderr.txt" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
}

# fd_plateau_state <samples.jsonl> — prints "max_fds last_ns n_rows" from
# the sampler trace (empty when no rows yet).
fd_plateau_state() {
    python3 -I -c "
import json, sys
rows = []
try:
    with open(sys.argv[1], encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
except (OSError, ValueError):
    pass
if not rows:
    print('')
else:
    print(max(int(row['fds']) for row in rows), int(rows[-1]['t_mono_ns']), len(rows))
" "$1"
}

# wait_fd_plateau <cond_dir> <observer_pid> <observer_birth> <timeout_s> — hold until the
# fd trace stops climbing: no new max for 15 s and at least 40 s past the
# discovery marker (attach ramps links for ~50 s on --system; a bare
# plateau fires early when attach stalls mid-ramp under load). Prints the
# plateau fd count. Returns 2 if the observer is terminal and 3 if its exact
# identity cannot be inspected.
wait_fd_plateau() {
    dir=$1
    pid=$2
    birth=$3
    end=$(( $(date +%s) + $4 ))
    marker_s=$(date +%s)
    best=0
    best_s=$marker_s
    while :; do
        owned_live_status=0
        owned_require_live "$pid" "$birth" || owned_live_status=$?
        case "$owned_live_status" in 0) ;; 1) return 2 ;; *) return 3 ;; esac
        now=$(date +%s)
        [ "$now" -lt "$end" ] || return 1
        # shellcheck disable=SC2086
        set -- $(fd_plateau_state "$dir/samples.jsonl")
        if [ "$#" -eq 3 ]; then
            if [ "$1" -gt "$best" ]; then best=$1; best_s=$now; fi
            if [ $(( now - best_s )) -ge 15 ] && [ $(( now - marker_s )) -ge 40 ]; then
                echo "$best"
                return 0
            fi
        fi
        sleep 2
    done
}

# run_condition <scope> <mode>
run_condition() {
    scope=$1
    mode=$2
    cond="${scope}-${mode}"
    dir="$WORK/$cond"
    rm -rf "$dir"
    mkdir -p "$dir"
    chmod 700 "$dir"
    echo "=== condition: $cond ==="

    # Per-PID runs map late (bench-style: attach fails on this HEAD when the
    # provider is already mapped); --system runs map early so the scan
    # corroborates the workload provider. The generated-call truth is
    # identical either way; map_early is recorded per condition.
    if [ "$scope" = pid ]; then MAP_EARLY=0; else MAP_EARLY=1; fi
    rm -f "$dir/go" "$dir/mapped" "$dir/receipt-ready" \
        "$dir/workload-mapping-receipt.json" "$dir/receipt-metadata.json"
    owned_launch user - "$dir/workload.log" = -- env P11SCOPE_MEASURE_SEED="$SEED" \
        "$WORK/workload" "$MODULE" "$N_CALLS" "$PACE_US" "$MAP_EARLY" \
        "$dir/ready" "$dir/go" "$dir/mapped" "$dir/receipt-ready"
    WPID=$OWNED_PID
    WPID_STARTTIME=$OWNED_STARTTIME
    WPID_RECEIPT=$OWNED_RECEIPT
    owned_verify_launch "$WPID" "$WPID_STARTTIME" "$WPID_RECEIPT" || exit 1
    WTARGET_PID=$OWNED_COMMAND_PID
    WTARGET_STARTTIME=$OWNED_COMMAND_STARTTIME
    wait_file "$dir/ready" 60 || { echo "workload never became ready" >&2; cat "$dir/workload.log" >&2; exit 1; }
    T_MAPPING_READY=null
    T_RECEIPT_READY=null
    if [ "$MAP_EARLY" -eq 1 ]; then
        wait_file "$dir/mapped" 60 || {
            echo "early-mapped workload published no mapping handshake" >&2
            cat "$dir/workload.log" >&2
            exit 1
        }
        T_MAPPING_READY=$(mono_ns)
        collect_receipt "$dir" || {
            echo "could not pin early workload mapping for $cond" >&2
            exit 1
        }
        T_RECEIPT_READY=$(mono_ns)
        touch "$dir/receipt-ready"
    fi

    CFIFO="$dir/stderr.fifo"
    rm -f "$CFIFO"
    mkfifo "$CFIFO"
    owned_launch user "$CFIFO" /dev/null "$dir/ts-helper.stderr" -- \
        python3 -I scripts/system-scope-ts.py --out "$dir/stderr-ts.jsonl" \
        --passthrough "$dir/stderr.txt"
    TSPID=$OWNED_PID
    TSPID_STARTTIME=$OWNED_STARTTIME
    TSPID_RECEIPT=$OWNED_RECEIPT

    # Per-PID runs take the manifest (repo convention: deterministic attach);
    # --system runs use true discovery (the workload already mapped the
    # provider, so the scan corroborates it). Trace runs publish a line
    # stream, not a JSON report: the -o file is the record source and the
    # loss oracle's input, while stdout is the experimental sink.
    TRACE_OUT=
    if [ "$mode" = trace ]; then TRACE_OUT="$dir/trace.out"; fi
    if [ "$scope" = pid ]; then
        if [ "$mode" = trace ]; then
            # shellcheck disable=SC2086
            set -- "$BINARY" trace \
                --pid "$WTARGET_PID" --manifest "$WORK/manifest.json" \
                --duration "$DURATION" --max-events 10000000 -o "$TRACE_OUT"
        else
            # shellcheck disable=SC2086
            set -- "$BINARY" profile \
                --pid "$WTARGET_PID" --manifest "$WORK/manifest.json" \
                --mode "$mode" --duration "$DURATION" -o "$dir/report.json"
        fi
    else
        if [ "$mode" = trace ]; then
            # shellcheck disable=SC2086
            set -- "$BINARY" trace \
                --system --duration "$DURATION" --max-events 10000000 -o "$TRACE_OUT"
        else
            # shellcheck disable=SC2086
            set -- "$BINARY" profile \
                --system --mode "$mode" --duration "$DURATION" -o "$dir/report.json"
        fi
    fi
    if [ -n "$RING_BYTES" ]; then set -- "$@" --ring-bytes "$RING_BYTES"; fi
    if [ -n "$DRAIN_MS" ]; then set -- "$@" --drain-interval-ms "$DRAIN_MS"; fi
    OBS_ARGV_JSON=$(python3 -I -c "import json,sys; print(json.dumps(sys.argv[1:]))" "$@")
    T_SPAWN=$(mono_ns)
    # Sink routing: the observer's stdout destination. slow-pipe interposes
    # a throttled FIFO reader that still keeps every byte in
    # observer.stdout (the gate file), so the observer blocks on a slow
    # sink exactly as it would on a slow terminal.
    SFIFO=
    TPID=
    case "$SINK" in
        file)
            owned_launch root - "$dir/observer.stdout" "$CFIFO" -- "$@"
            SPID=$OWNED_PID; SPID_STARTTIME=$OWNED_STARTTIME
            SPID_RECEIPT=$OWNED_RECEIPT
            ;;
        discard)
            owned_launch root - /dev/null "$CFIFO" -- "$@"
            SPID=$OWNED_PID; SPID_STARTTIME=$OWNED_STARTTIME
            SPID_RECEIPT=$OWNED_RECEIPT
            ;;
        slow-pipe)
            SFIFO="$dir/stdout.fifo"
            rm -f "$SFIFO"
            mkfifo "$SFIFO"
            owned_launch user "$SFIFO" /dev/null "$dir/sink-helper.stderr" -- \
                python3 -I -c "
import sys, time
rate = float(sys.argv[1]) * 1024
out = open(sys.argv[2], 'wb')
start = time.monotonic()
written = 0
while True:
    chunk = sys.stdin.buffer.read1(4096)
    if not chunk:
        break
    out.write(chunk)
    out.flush()
    written += len(chunk)
    ahead = written - rate * (time.monotonic() - start)
    if ahead > 0:
        time.sleep(ahead / rate)
out.close()
" "$SINK_RATE_KBPS" "$dir/observer.stdout"
            TPID=$OWNED_PID; TPID_STARTTIME=$OWNED_STARTTIME
            TPID_RECEIPT=$OWNED_RECEIPT
            owned_launch root - "$SFIFO" "$CFIFO" -- "$@"
            SPID=$OWNED_PID; SPID_STARTTIME=$OWNED_STARTTIME
            SPID_RECEIPT=$OWNED_RECEIPT
            ;;
    esac
    owned_verify_launch "$TSPID" "$TSPID_STARTTIME" "$TSPID_RECEIPT" || exit 1
    [ -z "$TPID" ] || owned_verify_launch "$TPID" "$TPID_STARTTIME" "$TPID_RECEIPT" || exit 1
    owned_verify_launch "$SPID" "$SPID_STARTTIME" "$SPID_RECEIPT" || exit 1
    STARGET_PID=$OWNED_COMMAND_PID
    STARGET_STARTTIME=$OWNED_COMMAND_STARTTIME
    owned_launch root - "$dir/sampler.stdout" "$dir/sampler.stderr" -- \
        python3 -I "$PWD/scripts/system-scope-sample.py" \
        --pid "$STARGET_PID" --starttime "$STARGET_STARTTIME" \
        --out "$dir/samples.jsonl" --interval 0.05
    SMPID=$OWNED_PID
    SMPID_STARTTIME=$OWNED_STARTTIME
    SMPID_RECEIPT=$OWNED_RECEIPT
    owned_verify_launch "$SMPID" "$SMPID_STARTTIME" "$SMPID_RECEIPT" || exit 1

    # Attach gate: the stderr attach-complete line (profile/metrics to a
    # kept sink) is the in-observer attach-end signal; everywhere else
    # fall back to marker+settle and let post-hoc counts prove the
    # window. The gate used is recorded.
    GATE=frame
    if [ "$mode" != trace ] && [ "$SINK" != discard ]; then
        if wait_attach "$dir" "$STARGET_PID" "$STARGET_STARTTIME" 600; then
            :
        else
            rc=$?
            if [ "$rc" -eq 2 ]; then
                echo "observer died during attach for $cond:" >&2
                cat "$dir/stderr.txt" >&2
            elif [ "$rc" -eq 3 ]; then
                echo "observer identity became unknown during attach for $cond:" >&2
                cat "$dir/stderr.txt" >&2
            else
                echo "attach never settled for $cond (see $dir/stderr.txt)" >&2
            fi
            exit 1
        fi
    else
        if wait_marker "$dir" "$STARGET_PID" "$STARGET_STARTTIME" 600; then
            :
        else
            rc=$?
            if [ "$rc" -eq 2 ]; then
                echo "observer died during attach for $cond:" >&2
                cat "$dir/stderr.txt" >&2
            elif [ "$rc" -eq 3 ]; then
                echo "observer identity became unknown during attach for $cond:" >&2
                cat "$dir/stderr.txt" >&2
            else
                echo "attach never settled for $cond (see $dir/stderr.txt)" >&2
            fi
            exit 1
        fi
        if [ "$scope" = system ]; then
            plateau_fds=$(wait_fd_plateau "$dir" "$STARGET_PID" "$STARGET_STARTTIME" 600) || {
                echo "fd plateau never reached for $cond" >&2
                exit 1
            }
            echo "gate: marker + fd plateau at $plateau_fds fds + 20s settle"
            sleep 20
            GATE="marker+plateau(fds=$plateau_fds)+settle:20s"
        else
            sleep 10
            GATE="marker+settle:10s"
        fi
    fi
    T_INITIAL_GO=$(mono_ns)
    T_GO=$T_INITIAL_GO
    LOADAVG=$(cat /proc/loadavg)
    owned_live_status=0
    owned_require_live "$STARGET_PID" "$STARGET_STARTTIME" || owned_live_status=$?
    case "$owned_live_status" in
        0) ;;
        1) echo "observer exited before owned calls were released" >&2; exit 1 ;;
        *) echo "observer identity unknown before owned calls were released" >&2; exit 1 ;;
    esac
    touch "$dir/go"

    if [ "$MAP_EARLY" -eq 0 ]; then
        if wait_file_alive "$dir/mapped" "$STARGET_PID" "$STARGET_STARTTIME" \
            "$WTARGET_PID" "$WTARGET_STARTTIME" 60; then
            :
        else
            rc=$?
            if [ "$rc" -eq 2 ]; then
                echo "observer exited before late workload mapping was receipted" >&2
            elif [ "$rc" -eq 3 ]; then
                echo "late workload exited before publishing its mapping" >&2
            elif [ "$rc" -eq 4 ]; then
                echo "observer identity became unknown before late workload mapping" >&2
            elif [ "$rc" -eq 5 ]; then
                echo "late workload identity became unknown before mapping" >&2
            else
                echo "late workload published no mapping handshake" >&2
            fi
            cat "$dir/workload.log" >&2
            exit 1
        fi
        T_MAPPING_READY=$(mono_ns)
        collect_receipt "$dir" || {
            echo "could not pin late workload mapping for $cond" >&2
            exit 1
        }
        owned_live_status=0
        owned_require_live "$STARGET_PID" "$STARGET_STARTTIME" || owned_live_status=$?
        case "$owned_live_status" in
            0) ;;
            1) echo "observer exited before owned calls were released" >&2; exit 1 ;;
            *) echo "observer identity unknown before owned calls were released" >&2; exit 1 ;;
        esac
        T_RECEIPT_READY=$(mono_ns)
        touch "$dir/receipt-ready"
    fi

    if ! owned_finish "$WPID" "$WPID_STARTTIME" "$WPID_RECEIPT" 120; then
        echo "workload settlement failed for $cond; left unreaped" >&2
        exit 1
    fi
    WORKLOAD_RC=$OWNED_EXIT
    [ "$WORKLOAD_RC" -eq 0 ] || {
        echo "workload failed for $cond (exit=$WORKLOAD_RC)" >&2
        cat "$dir/workload.log" >&2
        exit 1
    }
    WPID=
    WPID_STARTTIME=

    # The observer exits on its own after --duration + detach + publish;
    # detach taper dominates on --system (minutes under concurrent build
    # load), so the deadline is generous and the escalation signals the
    # real observer child, never just its sudo parent.
    OBSERVER_TIMED_OUT=false
    OBSERVER_SIGNAL=null
    observer_wait_state=0
    owned_wait_supervisor_terminal "$SPID_RECEIPT" $(( DURATION + 600 )) || \
        observer_wait_state=$?
    case "$observer_wait_state" in
        0) ;;
        1)
            echo "observer hung for $cond; interrupting" >&2
            OBSERVER_TIMED_OUT=true
            ;;
        *)
            echo "observer terminal state is unknown for $cond" >&2
            exit 1
            ;;
    esac
    owned_finish "$SPID" "$SPID_STARTTIME" "$SPID_RECEIPT" 0 || {
        echo "observer descendant settlement failed for $cond; left unreaped" >&2
        exit 1
    }
    owned_command_outcome "$SPID_RECEIPT" || {
        echo "observer receipt has no exact command outcome for $cond" >&2
        exit 1
    }
    OBS_RC=$OWNED_COMMAND_EXIT
    if [ "$OWNED_COMMAND_SIGNAL" != null ]; then
        OBSERVER_SIGNAL="\"$OWNED_COMMAND_SIGNAL\""
    fi
    SPID=
    SPID_STARTTIME=
    T_EXIT=$(mono_ns)
    python3 -I scripts/system-scope-receipt.py verify-file \
        --identity "$WORK/observer.identity.json" --path "$BINARY" >/dev/null || {
        echo "observer binary changed during $cond" >&2
        exit 1
    }

    # Sampler/ts/trickle exit on their own once the observer is gone;
    # bound the wait.
    owned_finish "$SMPID" "$SMPID_STARTTIME" "$SMPID_RECEIPT" 15 || {
        echo "sampler teardown failed for $cond; left unreaped" >&2
        exit 1
    }
    SMPID=
    SMPID_STARTTIME=
    owned_command_outcome "$SMPID_RECEIPT" || {
        echo "sampler receipt has no exact command outcome for $cond" >&2
        exit 1
    }
    if [ "$OWNED_COMMAND_EXIT" -ne 0 ] || [ "$OWNED_COMMAND_SIGNAL" != null ]; then
        echo "sampler failed for $cond: exit=$OWNED_COMMAND_EXIT signal=$OWNED_COMMAND_SIGNAL" >&2
        exit 1
    fi
    owned_finish "$TSPID" "$TSPID_STARTTIME" "$TSPID_RECEIPT" 15 || {
        echo "timestamp helper teardown failed for $cond; left unreaped" >&2
        exit 1
    }
    TSPID=
    TSPID_STARTTIME=
    if [ -n "$TPID" ]; then
        owned_finish "$TPID" "$TPID_STARTTIME" "$TPID_RECEIPT" 60 || {
            echo "sink helper teardown failed for $cond; left unreaped" >&2
            exit 1
        }
        TPID=
        TPID_STARTTIME=
    fi
    rm -f "$CFIFO"
    CFIFO=
    rm -f "$SFIFO"
    SFIFO=
    # A nonzero observer exit with a report is still a measurement (the rc is
    # recorded); a missing report is a harness failure.
    REPORT_SRC="$dir/report.json"
    if [ "$mode" = trace ]; then REPORT_SRC="$dir/trace.out"; fi
    if [ ! -f "$REPORT_SRC" ]; then
        echo "observer exit=$OBS_RC wrote no report for $cond:" >&2
        cat "$dir/stderr.txt" >&2
        exit 1
    fi
    reclaim_root_output "$REPORT_SRC" "$dir/samples.jsonl"

    WORKLOAD_ARGV_JSON=$(python3 -I -c "import json; print(json.dumps(['$WORK/workload', '$MODULE', '$N_CALLS', '$PACE_US', '$MAP_EARLY', '$dir/ready', '$dir/go', '$dir/mapped', '$dir/receipt-ready']))")
    MANIFEST_JSON="null"
    if [ "$scope" = pid ]; then MANIFEST_JSON="\"$WORK/manifest.json\""; fi
    RING_JSON="\"default\""; [ -z "$RING_BYTES" ] || RING_JSON="\"$RING_BYTES\""
    DRAIN_JSON="\"default\""; [ -z "$DRAIN_MS" ] || DRAIN_JSON="\"$DRAIN_MS\""
    cat > "$dir/meta.json" <<EOF
{"harness": {"name": "system-scope-measure.sh", "git_rev": "$GIT_REV", "git_clean": $GIT_CLEAN,
  "git_tracked_clean": $GIT_TRACKED_CLEAN, "started_iso": "$HARNESS_START_ISO",
  "observer_exit": $OBS_RC, "observer_timed_out": $OBSERVER_TIMED_OUT,
  "observer_signal": $OBSERVER_SIGNAL},
 "condition": {"scope": "$scope", "mode": "$mode", "duration_s": $DURATION,
  "n_calls": $N_CALLS, "pace_us": $PACE_US, "seed": $SEED, "map_early": $MAP_EARLY,
  "ring_bytes": $RING_JSON, "drain_interval_ms": $DRAIN_JSON,
  "sink": "$SINK", "sink_rate_kbps": $SINK_RATE_KBPS, "gate": "$GATE",
  "manifest": $MANIFEST_JSON, "binary": "$BINARY", "build_profile": "$PROFILE",
  "observer_source_revision": null,
  "observer_argv": $OBS_ARGV_JSON, "workload_argv": $WORKLOAD_ARGV_JSON,
  "mapping_gate": "$([ "$MAP_EARLY" -eq 1 ] && echo pre-observer || echo post-attach)"},
 "host": {"kernel": "$KERNEL", "cpu": "$CPU", "ncpu": $NCPU, "loadavg": "$LOADAVG"},
 "timing": {"t_spawn_mono_ns": $T_SPAWN, "t_initial_go_mono_ns": $T_INITIAL_GO,
  "t_mapping_ready_mono_ns": $T_MAPPING_READY, "t_receipt_ready_mono_ns": $T_RECEIPT_READY,
  "t_go_mono_ns": $T_GO, "t_exit_mono_ns": $T_EXIT},
 "artifacts": {"dir": "$dir", "report": "$REPORT_SRC", "samples": "$dir/samples.jsonl",
  "stderr_ts": "$dir/stderr-ts.jsonl", "stderr": "$dir/stderr.txt",
  "workload_log": "$dir/workload.log", "mapping_receipt": "$dir/workload-mapping-receipt.json"}}
EOF
    python3 -I - "$dir/meta.json" "$dir/receipt-metadata.json" <<'PY'
import json
import sys
from pathlib import Path

meta_path = Path(sys.argv[1])
receipt_path = Path(sys.argv[2])
meta = json.loads(meta_path.read_text(encoding="utf-8"))
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
meta["condition"].update(receipt)
meta_path.write_text(json.dumps(meta, sort_keys=True) + "\n", encoding="utf-8")
PY
    python3 -I scripts/system-scope-measure.py --meta "$dir/meta.json" \
        --report "$REPORT_SRC" --samples "$dir/samples.jsonl" \
        --stderr-ts "$dir/stderr-ts.jsonl" --workload-log "$dir/workload.log" \
        --out "$dir/record.json" --summary "$dir/summary.txt"
    # The record files are the deliverable; a closed terminal must not fail
    # the run (never pipe this script's stdout to `head` — redirect to a
    # file and grep that instead).
    cat "$dir/summary.txt" || true
    if [ "$OBSERVER_TIMED_OUT" = true ] || [ "$OBS_RC" -ne 0 ] || \
       [ "$OBSERVER_SIGNAL" != null ]; then
        echo "observer outcome invalid for $cond: exit=$OBS_RC timeout=$OBSERVER_TIMED_OUT signal=$OBSERVER_SIGNAL" >&2
        return 1
    fi
}

case "$SCOPE" in
    pid) SCOPES="pid" ;;
    system) SCOPES="system" ;;
    both) SCOPES="pid system" ;;
esac
case "$MODE" in
    metrics) MODES="metrics" ;;
    profile) MODES="profile" ;;
    trace) MODES="trace" ;;
    both) MODES="metrics profile" ;;
    all) MODES="metrics profile trace" ;;
esac

for scope in $SCOPES; do
    for mode in $MODES; do
        run_condition "$scope" "$mode"
    done
done

python3 -I -c "
import glob, json
records = {}
for path in sorted(glob.glob('$WORK/*/record.json')):
    with open(path) as handle:
        record = json.load(handle)
    key = record['condition']['scope'] + '/' + record['condition']['mode']
    records[key] = record
with open('$WORK/matrix.json', 'w') as handle:
    with open('$WORK/observer.identity.json') as observer_handle:
        observer_identity = json.load(observer_handle)
    json.dump({'schema': 'p11scope/system-scope-matrix/v1',
               'harness_git_rev': '$GIT_REV',
               'observer_source_revision': None,
               'observer_binary_identity': observer_identity,
               'records': records}, handle, indent=2)
try:
    print('matrix: $WORK/matrix.json', flush=True)
except BrokenPipeError:
    pass
"

echo "=== system-scope-measure: DONE ==="
