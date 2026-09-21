#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# system-scope-measure.sh — controlled per-PID and --system captures for the
# system-scale acceptance matrix (docs/superpowers/plans/2026-09-19-system-scale.md,
# Task 1.4 Step 2): identical deterministic workload, exact binary identity,
# and one JSON record + human summary per condition with phase timings,
# every loss counter, verdict, admission truth, and observer CPU/RSS/fds.
#
# Method: the gated two-phase workload (system-scope-workload.c) maps the
# provider and opens a session, waits for attach (the harness holds the go
# file until the discovery marker lands on stderr AND the observer's first
# live frame lands on stdout — the in-observer attach-end signal), then
# fires exactly N C_GenerateRandom calls. A /proc sampler
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
# the observer's stdout destination: file (default, kept for the attach
# gate), discard (/dev/null: no sink backpressure), slow-pipe (a throttled
# FIFO reader: explicit downstream backpressure). Non-file sinks and trace
# mode use the weaker marker+settle attach gate (no first-frame signal);
# the gate used is recorded per condition and validated post-hoc.
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
MODULE=/usr/lib/softhsm/libsofthsm2.so

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
SPID=
SMPID=
TSPID=
TPID=
CFIFO=
SFIFO=

# signal_proc <pid> <signal>: signal a sudo-launched process AND its real
# child. Signalling only the sudo parent orphans the child: it is reparented
# and keeps running (observed: a stuck observer survived cleanup and sampled
# for 19 minutes).
signal_proc() {
    for kid in $(cat /proc/$1/task/*/children 2>/dev/null); do
        case "$kid" in ''|*[!0-9]*) continue ;; esac
        sudo -n kill "-$2" "$kid" 2>/dev/null || kill "-$2" "$kid" 2>/dev/null || true
    done
    sudo -n kill "-$2" "$1" 2>/dev/null || kill "-$2" "$1" 2>/dev/null || true
}

cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$TSPID" ] || kill "$TSPID" 2>/dev/null || true
    [ -z "$TPID" ] || kill "$TPID" 2>/dev/null || true
    [ -z "$SMPID" ] || signal_proc "$SMPID" TERM
    [ -z "$SPID" ] || signal_proc "$SPID" INT
    [ -z "$WPID" ] || kill "$WPID" 2>/dev/null || true
    [ -z "$TSPID" ] || wait "$TSPID" 2>/dev/null || true
    [ -z "$TPID" ] || wait "$TPID" 2>/dev/null || true
    [ -z "$SMPID" ] || wait "$SMPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$CFIFO" ] || rm -f "$CFIFO" || true
    [ -z "$SFIFO" ] || rm -f "$SFIFO" || true
    exit "$status"
}
. scripts/cleanup-traps.sh

require_non_root_caller
command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
sudo -n true || { echo "passwordless sudo required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }
export TMPDIR=/var/tmp/p11scope-ws-tmp
mkdir -p "$TMPDIR" "$WORK"
# The observer fails closed on untrusted output dirs: 0700 caller-owned.
chmod 700 "$WORK"

echo "=== build ==="
gcc -O0 -o "$WORK/workload" scripts/system-scope-workload.c -ldl
if [ -z "$BINARY" ]; then
    if [ "$NO_BUILD" -eq 0 ]; then
        if [ "$PROFILE" = release ]; then
            scripts/cargo.sh +1.88 build --locked --offline --release -p p11scope -p p11scope-discover
        else
            scripts/cargo.sh +1.88 build --locked --offline -p p11scope -p p11scope-discover
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

# wait_gone <pid> <timeout_s> — poll for a process to exit.
wait_gone() {
    end=$(( $(date +%s) + $2 ))
    while kill -0 "$1" 2>/dev/null; do
        [ "$(date +%s)" -lt "$end" ] || return 1
        sleep 0.1
    done
    return 0
}

# wait_attach <cond_dir> <observer_pid> <timeout_s> — hold the go file
# until discovery is done (marker on the timestamped stderr passthrough)
# AND the capture loop is live: the observer renders its first live frame
# to stdout on tick one (last_frame starts a full drain interval in the
# past), strictly after the attach session completes, so the frame's
# "probes attached" line is an in-observer attach-end signal. An fd
# plateau is NOT the gate — under load attach stalls for seconds mid-ramp
# and a plateau detector fires early, releasing the workload burst into a
# half-attached observer (observed once: 1/20000 calls). Returns 2
# immediately if the observer dies first.
wait_attach() {
    end=$(( $(date +%s) + $3 ))
    while :; do
        kill -0 "$2" 2>/dev/null || return 2
        [ "$(date +%s)" -lt "$end" ] || return 1
        if grep -q "p11scope: discovery:" "$1/stderr.txt" 2>/dev/null \
            && grep -q "probes attached" "$1/observer.stdout" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
}

# wait_marker <cond_dir> <observer_pid> <timeout_s> — hold until the
# discovery marker lands on stderr. Weaker than wait_attach (no
# in-observer attach-end signal): used only where no first live frame
# exists (trace mode) or the frame is not kept (discard/slow-pipe sinks).
# Settles after the marker; post-hoc counts prove the window.
wait_marker() {
    end=$(( $(date +%s) + $3 ))
    while :; do
        kill -0 "$2" 2>/dev/null || return 2
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

# wait_fd_plateau <cond_dir> <observer_pid> <timeout_s> — hold until the
# fd trace stops climbing: no new max for 15 s and at least 40 s past the
# discovery marker (attach ramps links for ~50 s on --system; a bare
# plateau fires early when attach stalls mid-ramp under load). Prints the
# plateau fd count. Returns 2 if the observer dies first.
wait_fd_plateau() {
    dir=$1
    pid=$2
    end=$(( $(date +%s) + $3 ))
    marker_s=$(date +%s)
    best=0
    best_s=$marker_s
    while :; do
        kill -0 "$pid" 2>/dev/null || return 2
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
    rm -f "$dir/go"
    P11SCOPE_MEASURE_SEED="$SEED" "$WORK/workload" "$MODULE" "$N_CALLS" "$PACE_US" "$MAP_EARLY" \
        "$dir/ready" "$dir/go" > "$dir/workload.log" 2>&1 &
    WPID=$!
    wait_file "$dir/ready" 60 || { echo "workload never became ready" >&2; cat "$dir/workload.log" >&2; exit 1; }

    CFIFO="$dir/stderr.fifo"
    rm -f "$CFIFO"
    mkfifo "$CFIFO"
    python3 -I scripts/system-scope-ts.py --out "$dir/stderr-ts.jsonl" \
        --passthrough "$dir/stderr.txt" < "$CFIFO" &
    TSPID=$!

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
            set -- sudo --preserve-env=SOFTHSM2_CONF "$BINARY" trace \
                --pid "$WPID" --manifest "$WORK/manifest.json" \
                --duration "$DURATION" --max-events 10000000 -o "$TRACE_OUT"
        else
            # shellcheck disable=SC2086
            set -- sudo --preserve-env=SOFTHSM2_CONF "$BINARY" profile \
                --pid "$WPID" --manifest "$WORK/manifest.json" \
                --mode "$mode" --duration "$DURATION" -o "$dir/report.json"
        fi
    else
        if [ "$mode" = trace ]; then
            # shellcheck disable=SC2086
            set -- sudo --preserve-env=SOFTHSM2_CONF "$BINARY" trace \
                --system --duration "$DURATION" --max-events 10000000 -o "$TRACE_OUT"
        else
            # shellcheck disable=SC2086
            set -- sudo --preserve-env=SOFTHSM2_CONF "$BINARY" profile \
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
        file) "$@" > "$dir/observer.stdout" 2> "$CFIFO" & SPID=$! ;;
        discard) "$@" > /dev/null 2> "$CFIFO" & SPID=$! ;;
        slow-pipe)
            SFIFO="$dir/stdout.fifo"
            rm -f "$SFIFO"
            mkfifo "$SFIFO"
            python3 -I -c "
import sys, time
rate = float(sys.argv[1]) * 1024
out = open(sys.argv[2], 'wb')
start = time.monotonic()
written = 0
while True:
    # read1, not read: BufferedReader.read(n) waits to fill n bytes,
    # which would hold back small frames for seconds and break the
    # attach gate (observed: a whole 3 KB run never reached 4096).
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
" "$SINK_RATE_KBPS" "$dir/observer.stdout" < "$SFIFO" &
            TPID=$!
            "$@" > "$SFIFO" 2> "$CFIFO" & SPID=$!
            ;;
    esac
    sudo -n python3 -I "$PWD/scripts/system-scope-sample.py" --ppid "$SPID" \
        --out "$dir/samples.jsonl" --interval 0.05 &
    SMPID=$!

    # Attach gate: the first live frame (profile/metrics to a kept sink)
    # is an in-observer attach-end signal; everywhere else (trace has no
    # frames; discard keeps nothing) fall back to marker+settle and let
    # post-hoc counts prove the window. The gate used is recorded.
    GATE=frame
    if [ "$mode" != trace ] && [ "$SINK" != discard ]; then
        if wait_attach "$dir" "$SPID" 600; then
            :
        else
            rc=$?
            if [ "$rc" -eq 2 ]; then
                echo "observer died during attach for $cond:" >&2
                cat "$dir/stderr.txt" >&2
            else
                echo "attach never settled for $cond (see $dir/stderr.txt)" >&2
            fi
            exit 1
        fi
    else
        if wait_marker "$dir" "$SPID" 600; then
            :
        else
            rc=$?
            if [ "$rc" -eq 2 ]; then
                echo "observer died during attach for $cond:" >&2
                cat "$dir/stderr.txt" >&2
            else
                echo "attach never settled for $cond (see $dir/stderr.txt)" >&2
            fi
            exit 1
        fi
        if [ "$scope" = system ]; then
            plateau_fds=$(wait_fd_plateau "$dir" "$SPID" 600) || {
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
    T_GO=$(mono_ns)
    LOADAVG=$(cat /proc/loadavg)
    touch "$dir/go"

    if ! wait_gone "$WPID" 120; then
        echo "workload hung for $cond" >&2
        exit 1
    fi
    wait "$WPID" || { echo "workload failed for $cond" >&2; cat "$dir/workload.log" >&2; exit 1; }
    WPID=

    # The observer exits on its own after --duration + detach + publish;
    # detach taper dominates on --system (minutes under concurrent build
    # load), so the deadline is generous and the escalation signals the
    # real observer child, never just its sudo parent.
    if ! wait_gone "$SPID" $(( DURATION + 600 )); then
        echo "observer hung for $cond; interrupting" >&2
        signal_proc "$SPID" INT
        wait_gone "$SPID" 300 || signal_proc "$SPID" KILL
    fi
    OBS_RC=0
    wait "$SPID" || OBS_RC=$?
    SPID=
    T_EXIT=$(mono_ns)

    # Sampler/ts/trickle exit on their own once the observer is gone;
    # bound the wait.
    wait_gone "$SMPID" 15 || signal_proc "$SMPID" KILL
    wait "$SMPID" 2>/dev/null || true
    SMPID=
    wait_gone "$TSPID" 15 || kill -KILL "$TSPID" 2>/dev/null || true
    wait "$TSPID" 2>/dev/null || true
    TSPID=
    if [ -n "$TPID" ]; then
        wait_gone "$TPID" 60 || kill -KILL "$TPID" 2>/dev/null || true
        wait "$TPID" 2>/dev/null || true
        TPID=
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

    WORKLOAD_ARGV_JSON=$(python3 -I -c "import json; print(json.dumps(['$WORK/workload', '$MODULE', '$N_CALLS', '$PACE_US', '$MAP_EARLY']))")
    MANIFEST_JSON="null"
    if [ "$scope" = pid ]; then MANIFEST_JSON="\"$WORK/manifest.json\""; fi
    RING_JSON="\"default\""; [ -z "$RING_BYTES" ] || RING_JSON="\"$RING_BYTES\""
    DRAIN_JSON="\"default\""; [ -z "$DRAIN_MS" ] || DRAIN_JSON="\"$DRAIN_MS\""
    cat > "$dir/meta.json" <<EOF
{"harness": {"name": "system-scope-measure.sh", "git_rev": "$GIT_REV", "git_clean": $GIT_CLEAN,
  "git_tracked_clean": $GIT_TRACKED_CLEAN, "started_iso": "$HARNESS_START_ISO",
  "observer_exit": $OBS_RC},
 "condition": {"scope": "$scope", "mode": "$mode", "duration_s": $DURATION,
  "n_calls": $N_CALLS, "pace_us": $PACE_US, "seed": $SEED, "map_early": $MAP_EARLY,
  "ring_bytes": $RING_JSON, "drain_interval_ms": $DRAIN_JSON,
  "sink": "$SINK", "sink_rate_kbps": $SINK_RATE_KBPS, "gate": "$GATE",
  "manifest": $MANIFEST_JSON, "binary": "$BINARY", "build_profile": "$PROFILE",
  "observer_argv": $OBS_ARGV_JSON, "workload_argv": $WORKLOAD_ARGV_JSON},
 "host": {"kernel": "$KERNEL", "cpu": "$CPU", "ncpu": $NCPU, "loadavg": "$LOADAVG"},
 "timing": {"t_spawn_mono_ns": $T_SPAWN, "t_go_mono_ns": $T_GO, "t_exit_mono_ns": $T_EXIT},
 "artifacts": {"dir": "$dir", "report": "$REPORT_SRC", "samples": "$dir/samples.jsonl",
  "stderr_ts": "$dir/stderr-ts.jsonl", "stderr": "$dir/stderr.txt",
  "workload_log": "$dir/workload.log"}}
EOF
    python3 -I scripts/system-scope-measure.py --meta "$dir/meta.json" \
        --report "$REPORT_SRC" --samples "$dir/samples.jsonl" \
        --stderr-ts "$dir/stderr-ts.jsonl" --workload-log "$dir/workload.log" \
        --out "$dir/record.json" --summary "$dir/summary.txt"
    # The record files are the deliverable; a closed terminal must not fail
    # the run (never pipe this script's stdout to `head` — redirect to a
    # file and grep that instead).
    cat "$dir/summary.txt" || true
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
    json.dump({'schema': 'p11scope/system-scope-matrix/v1',
               'git_rev': '$GIT_REV', 'records': records}, handle, indent=2)
try:
    print('matrix: $WORK/matrix.json', flush=True)
except BrokenPipeError:
    pass
"

echo "=== system-scope-measure: DONE ==="
