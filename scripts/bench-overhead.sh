#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Phase 5 Task 3: measured overhead of each capture mode against
# unobserved SoftHSM2, deliberately the worst case for this measurement
# — its C_GenerateRandom calls are microsecond-scale software crypto, so
# probe overhead (uprobe+uretprobe trap, map update, ring submit) is
# proportionally largest here; a network HSM's millisecond-scale calls
# would flatter the numbers. scripts/fixtures/hammer.c (the induced-gaps
# suite's tight-loop workload) fires C_GenerateRandom back to back with
# no per-call delay, so a large call count is resolvable above process
# start/attach noise.
#
# Method: RUNS interleaved rounds of unobserved/metrics/profile/trace
# (ABAB..., not blocked by condition, so host drift cannot masquerade as
# a mode difference). Each round times only the workload process's own
# wall-clock via go-file synchronization: the observer attaches first,
# the harness waits for its attach-complete stderr line
# ("p11scope: capturing: N probe(s) attached", src/run.rs capture_ready_line) with
# a bounded timeout, then releases a short gated warm-up burst whose
# observation the harness requires (trace: warm-up lines in the live log
# before the measured window opens; profile/metrics: warm-up calls proven
# post-hoc in the aggregate count authority, since file output carries no
# live frames) before timing the measured N calls. Attach latency and
# warm-up are never counted inside the measured window.
#
# Equal coverage: every observed sample must prove the observer counted
# exactly the workload's calls — hammer prints its exact main (N) and
# warm-up (W) counts; the report's per-function authority must show N+W
# C_GenerateRandom calls (profile/metrics functions[]) or N+W+5 total
# calls (trace COUNT_EVIDENCE stats_returned: the burst plus Initialize,
# GetSlotList, OpenSession, CloseSession, Finalize). A sample whose
# captured count differs is INVALID: it is excluded from the statistics,
# counted, and fails the run at the end. Any observer failure, non-zero
# exit, missing or malformed report, "attach failed" line, or wait timeout
# fails the run immediately — nothing is tolerated or skipped silently.
#
# Reports median and min..max wall-clock per condition plus per-call
# overhead in ns ((observed - baseline)/calls). Usage:
#   scripts/bench-overhead.sh [--self-test]
# Environment: RUNS (default 5), N_CALLS (default 1000000),
# WARMUP_CALLS (default 1000), ATTACH_TIMEOUT_S (default 30),
# WARMUP_TIMEOUT_S (default 15).
set -eu
cd "$(dirname "$0")/.."
. scripts/lib.sh

MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=
FIX=scripts/fixtures
RUNS=${RUNS:-5}
N_CALLS=${N_CALLS:-1000000}
WARMUP_CALLS=${WARMUP_CALLS:-1000}
ATTACH_TIMEOUT_S=${ATTACH_TIMEOUT_S:-30}
WARMUP_TIMEOUT_S=${WARMUP_TIMEOUT_S:-15}
ATTACH_MARKER="p11scope: capturing: "
WPID=
SPID=

# Prints the probe count from the observer's attach-complete stderr line in
# $1, or nothing when the line has not landed yet.
observer_attach_count() {
    sed -n "s/.*p11scope: capturing: \([0-9][0-9]*\) probe.*/\1/p" "$1" 2>/dev/null | tail -n 1
}

# wait_for_observer_attach <log> <timeout_s>: poll for the observer's
# attach-complete stderr line, refusing a zero-probe attach. Fails on
# timeout or when $SPID dies first (with a recheck for a marker that
# landed between the last poll and the exit).
wait_for_observer_attach() {
    wfoa_end=$(( $(date +%s) + $2 ))
    while :; do
        if grep -Fq "$ATTACH_MARKER" "$1" 2>/dev/null; then
            wfoa_count=$(observer_attach_count "$1")
            case $wfoa_count in ''|*[!0-9]*)
                echo "unparseable attach count in $1" >&2
                return 1
                ;;
            esac
            if [ "$wfoa_count" -le 0 ]; then
                echo "observer attached 0 probes: $1" >&2
                return 1
            fi
            return 0
        fi
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            if grep -Fq "$ATTACH_MARKER" "$1" 2>/dev/null; then
                wfoa_count=$(observer_attach_count "$1")
                case $wfoa_count in ''|*[!0-9]*) return 1 ;; esac
                [ "$wfoa_count" -gt 0 ] && return 0
                echo "observer attached 0 probes: $1" >&2
                return 1
            fi
            echo "observer exited before attach completed: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        fi
        [ "$(date +%s)" -lt "$wfoa_end" ] || {
            echo "observer never reported attach completion within $2s: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        }
        sleep 0.05
    done
}

# wait_for_workload_file <path> <pid> <timeout_s> <what>: poll for a
# workload handshake file, failing when the workload dies first or the
# timeout expires.
wait_for_workload_file() {
    wfwd_end=$(( $(date +%s) + $3 ))
    while [ ! -f "$1" ]; do
        if ! kill -0 "$2" 2>/dev/null; then
            echo "workload $2 died waiting for $4 ($1)" >&2
            return 1
        fi
        [ "$(date +%s)" -lt "$wfwd_end" ] || {
            echo "timed out waiting for $4 ($1)" >&2
            return 1
        }
        sleep 0.05
    done
    return 0
}

# wait_for_trace_warmup <log> <min_lines> <timeout_s>: poll the trace
# stdout log until at least <min_lines> C_GenerateRandom lines have
# landed, proving probes are firing before the measured window opens.
wait_for_trace_warmup() {
    wftw_end=$(( $(date +%s) + $3 ))
    while :; do
        wftw_seen=$(grep -c "C_GenerateRandom" "$1" 2>/dev/null || true)
        case $wftw_seen in ''|*[!0-9]*) wftw_seen=0 ;; esac
        [ "$wftw_seen" -ge "$2" ] && return 0
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            echo "observer exited with only $wftw_seen/$2 warm-up lines: $1" >&2
            return 1
        fi
        if [ -n "${WPID-}" ] && ! kill -0 "$WPID" 2>/dev/null; then
            echo "workload exited with only $wftw_seen/$2 warm-up lines: $1" >&2
            return 1
        fi
        [ "$(date +%s)" -lt "$wftw_end" ] || {
            echo "only $wftw_seen/$2 warm-up lines within $3s: $1" >&2
            return 1
        }
        sleep 0.05
    done
}

if [ "${1-}" = "--self-test" ]; then
    [ "$#" -eq 1 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
    # Unprivileged: the coverage oracle's mutation suite plus this script's
    # readiness-wait positive/negative controls on synthetic logs. No BPF,
    # no sudo, no workload, no build of the observer.
    python3 -I scripts/lane-bench-overhead-oracle-3.py --self-test
    python3 -I scripts/lane-bench-overhead-oracle-1.py --self-test
    SELF_TEST_WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-bench-selftest-XXXXXX")
    trap 'rm -rf "$SELF_TEST_WORK"' EXIT INT TERM
    SPID=
    WPID=
    printf 'p11scope: discovery: 1 module(s)\np11scope: capturing: 136 probe(s) attached; stop with Ctrl-C\n' \
        > "$SELF_TEST_WORK/attached.log"
    wait_for_observer_attach "$SELF_TEST_WORK/attached.log" 5 \
        || { echo "self-test: attach wait missed the marker" >&2; exit 1; }
    printf 'p11scope: capturing: 0 probe(s) attached; stop with Ctrl-C\n' > "$SELF_TEST_WORK/zero.log"
    if wait_for_observer_attach "$SELF_TEST_WORK/zero.log" 1 2>/dev/null; then
        echo "self-test: zero-probe attach accepted" >&2
        exit 1
    fi
    : > "$SELF_TEST_WORK/empty.log"
    if wait_for_observer_attach "$SELF_TEST_WORK/empty.log" 1 2>/dev/null; then
        echo "self-test: missing attach marker accepted" >&2
        exit 1
    fi
    touch "$SELF_TEST_WORK/ready"
    sleep 5 > /dev/null 2>&1 &
    SELF_TEST_PID=$!
    wait_for_workload_file "$SELF_TEST_WORK/ready" "$SELF_TEST_PID" 5 "self-test handshake" \
        || { echo "self-test: present handshake missed" >&2; kill "$SELF_TEST_PID" 2>/dev/null || true; exit 1; }
    kill "$SELF_TEST_PID" 2>/dev/null || true
    wait "$SELF_TEST_PID" 2>/dev/null || true
    if wait_for_workload_file "$SELF_TEST_WORK/absent" "$$" 1 "self-test absence" 2>/dev/null; then
        echo "self-test: absent handshake accepted" >&2
        exit 1
    fi
    echo "bench-overhead self-test: OK"
    exit 0
fi
[ "$#" -eq 0 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
# The observer refuses an output directory below any group- or other-writable
# ancestor, which a checkout under a 0775 home tree has, so the bench works
# in a private directory under TMPDIR. It is kept for the numbers.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-bench-overhead-XXXXXX")
echo "work: $WORK"

cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$WPID" ] || kill "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || true
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    exit "$status"
}
. scripts/cleanup-traps.sh

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

echo "=== build ==="
scripts/cargo.sh "+$(cat .release-rust-version)" build --locked --release --workspace
DISCOVER=./target/release/p11scope-discover
P11SCOPE=./target/release/p11scope
gcc -O0 -o "$WORK/hammer" "$FIX/hammer.c" -ldl

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
softhsm2-util --init-token --free --label bench-overhead --so-pin 1234 --pin 1234 >/dev/null

echo "=== discover ==="
"$DISCOVER" --module "$MODULE" -o "$WORK/manifest.json"

echo "=== machine ==="
KERNEL=$(uname -r)
CPU=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
echo "kernel: $KERNEL"
echo "cpu: $CPU"
echo "runs per condition: $RUNS"
echo "calls per run: $N_CALLS"
echo "warm-up calls per observed run: $WARMUP_CALLS"
echo "attach timeout: ${ATTACH_TIMEOUT_S}s; warm-up timeout: ${WARMUP_TIMEOUT_S}s"

# Runs the hammer workload alone (no p11scope), appending its wall-clock in
# nanoseconds to unobserved.times. Same go-file gate as the observed
# conditions below, for a like-for-like measured window even though nothing
# needs a warm-up here. Any workload failure fails the run.
measure_unobserved() {
    n=$1
    rm -f "$WORK/go"
    ( while [ ! -f "$WORK/go" ]; do sleep 0.02; done
      exec "$WORK/hammer" "$MODULE" "$N_CALLS" ) > "$WORK/unobserved_${n}.log" 2>&1 &
    WPID=$!
    T0=$(date +%s%N)
    touch "$WORK/go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "unobserved workload $n failed: $status" >&2; return "$status"; fi
    T1=$(date +%s%N)
    python3 -I scripts/lane-bench-overhead-oracle-3.py hammer "$WORK/unobserved_${n}.log" "$N_CALLS" 0 \
        || { echo "unobserved workload $n published no valid count" >&2; return 1; }
    echo $((T1 - T0)) >> "$WORK/unobserved.times"
}

# Runs the hammer workload under `p11scope profile --mode <mode>`, attached
# before the workload's first call: the harness waits for the observer's
# attach-complete line (bounded, fails the run), releases a gated warm-up
# burst, then times only the measured N calls. Ends the observer with SIGINT
# after the workload finishes so its -o report is valid. Appends the timing
# to <label>.times on exact equal coverage, or to <label>.invalid_times when
# the report is well-formed but counted differently (INVALID, excluded from
# statistics); any observer failure, non-zero exit, missing/malformed report,
# "attach failed" line, or wait timeout fails the run immediately.
measure_profile() {
    n=$1
    mode=$2
    label=$3
    rm -f "$WORK/${label}_warmup_go_$n" "$WORK/${label}_warmed_$n" "$WORK/${label}_main_go_$n"
    P11SCOPE_HAMMER_WARMUP_GO="$WORK/${label}_warmup_go_$n" \
    P11SCOPE_HAMMER_WARMED="$WORK/${label}_warmed_$n" \
    P11SCOPE_HAMMER_MAIN_GO="$WORK/${label}_main_go_$n" \
    P11SCOPE_HAMMER_WARMUP_CALLS="$WARMUP_CALLS" \
        "$WORK/hammer" "$MODULE" "$N_CALLS" > "$WORK/${label}_hammer_${n}.log" 2>&1 &
    WPID=$!
    sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile \
        --manifest "$WORK/manifest.json" --pid "$WPID" \
        --mode "$mode" --duration 60 -o "$WORK/${label}_${n}.json" \
        > "$WORK/${label}_p11scope_${n}.log" 2>&1 &
    SPID=$!
    wait_for_observer_attach "$WORK/${label}_p11scope_${n}.log" "$ATTACH_TIMEOUT_S" \
        || { echo "$label run $n: attach gate failed" >&2; return 1; }
    if grep -q "attach failed" "$WORK/${label}_p11scope_${n}.log"; then
        echo "ATTACH FAILURE in $label run $n:" >&2
        cat "$WORK/${label}_p11scope_${n}.log" >&2
        return 1
    fi
    touch "$WORK/${label}_warmup_go_$n"
    wait_for_workload_file "$WORK/${label}_warmed_$n" "$WPID" "$WARMUP_TIMEOUT_S" "$label run $n warm-up" \
        || return 1
    T0=$(date +%s%N)
    touch "$WORK/${label}_main_go_$n"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "$label workload $n failed: $status" >&2; return "$status"; fi
    T1=$(date +%s%N)
    kill -INT "$SPID" 2>/dev/null || true
    if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "$label observer $n exited $status" >&2; cat "$WORK/${label}_p11scope_${n}.log" >&2; return 1; fi
    if grep -q "attach failed" "$WORK/${label}_p11scope_${n}.log"; then
        echo "ATTACH FAILURE in $label run $n:" >&2
        cat "$WORK/${label}_p11scope_${n}.log" >&2
        return 1
    fi
    reclaim_root_output "$WORK/${label}_${n}.json"
    python3 -I scripts/lane-bench-overhead-oracle-3.py hammer "$WORK/${label}_hammer_${n}.log" "$N_CALLS" "$WARMUP_CALLS" \
        || { echo "$label run $n: workload published no valid count" >&2; return 1; }
    mpc_expected=$((N_CALLS + WARMUP_CALLS))
    if python3 -I scripts/lane-bench-overhead-oracle-3.py profile "$WORK/${label}_${n}.json" "$mpc_expected"; then
        mpc_status=0
    else
        mpc_status=$?
    fi
    if [ "$mpc_status" -eq 10 ]; then
        echo $((T1 - T0)) >> "$WORK/${label}.invalid_times"
        echo "$label run $n: INVALID coverage (excluded from statistics)" >&2
        return 0
    fi
    [ "$mpc_status" -eq 0 ] || { echo "$label run $n: report validation failed" >&2; return 1; }
    echo $((T1 - T0)) >> "$WORK/${label}.times"
    return 0
}

# Runs the hammer workload under `p11scope trace`. Output is sent to a
# file with -o AND the observer's own stdout is redirected to a plain
# file rather than a terminal — `trace` prints one line per call, and on
# a real tty that I/O would become the bottleneck being measured instead
# of probe overhead. The warm-up burst must land as live lines before the
# measured window opens; final equal coverage comes from COUNT_EVIDENCE.
# Timing, INVALID, and failure handling are the same as measure_profile.
measure_trace() {
    n=$1
    rm -f "$WORK/trace_warmup_go_$n" "$WORK/trace_warmed_$n" "$WORK/trace_main_go_$n"
    P11SCOPE_HAMMER_WARMUP_GO="$WORK/trace_warmup_go_$n" \
    P11SCOPE_HAMMER_WARMED="$WORK/trace_warmed_$n" \
    P11SCOPE_HAMMER_MAIN_GO="$WORK/trace_main_go_$n" \
    P11SCOPE_HAMMER_WARMUP_CALLS="$WARMUP_CALLS" \
        "$WORK/hammer" "$MODULE" "$N_CALLS" > "$WORK/trace_hammer_${n}.log" 2>&1 &
    WPID=$!
    sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" trace \
        --manifest "$WORK/manifest.json" --pid "$WPID" \
        --duration 60 -o "$WORK/trace_${n}.txt" \
        > "$WORK/trace_p11scope_${n}.log" 2>&1 &
    SPID=$!
    wait_for_observer_attach "$WORK/trace_p11scope_${n}.log" "$ATTACH_TIMEOUT_S" \
        || { echo "trace run $n: attach gate failed" >&2; return 1; }
    if grep -q "attach failed" "$WORK/trace_p11scope_${n}.log"; then
        echo "ATTACH FAILURE in trace run $n:" >&2
        cat "$WORK/trace_p11scope_${n}.log" >&2
        return 1
    fi
    touch "$WORK/trace_warmup_go_$n"
    wait_for_workload_file "$WORK/trace_warmed_$n" "$WPID" "$WARMUP_TIMEOUT_S" "trace run $n warm-up" \
        || return 1
    wait_for_trace_warmup "$WORK/trace_p11scope_${n}.log" "$WARMUP_CALLS" "$WARMUP_TIMEOUT_S" \
        || { echo "trace run $n: warm-up positive control failed" >&2; return 1; }
    T0=$(date +%s%N)
    touch "$WORK/trace_main_go_$n"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "trace workload $n failed: $status" >&2; return "$status"; fi
    T1=$(date +%s%N)
    kill -INT "$SPID" 2>/dev/null || true
    if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "trace observer $n exited $status" >&2; cat "$WORK/trace_p11scope_${n}.log" >&2; return 1; fi
    if grep -q "attach failed" "$WORK/trace_p11scope_${n}.log"; then
        echo "ATTACH FAILURE in trace run $n:" >&2
        cat "$WORK/trace_p11scope_${n}.log" >&2
        return 1
    fi
    reclaim_root_output "$WORK/trace_${n}.txt"
    python3 -I scripts/lane-bench-overhead-oracle-3.py hammer "$WORK/trace_hammer_${n}.log" "$N_CALLS" "$WARMUP_CALLS" \
        || { echo "trace run $n: workload published no valid count" >&2; return 1; }
    mtc_expected=$((N_CALLS + WARMUP_CALLS + 5))
    if python3 -I scripts/lane-bench-overhead-oracle-3.py trace "$WORK/trace_${n}.txt" "$mtc_expected"; then
        mtc_status=0
    else
        mtc_status=$?
    fi
    if [ "$mtc_status" -eq 10 ]; then
        echo $((T1 - T0)) >> "$WORK/trace.invalid_times"
        echo "trace run $n: INVALID coverage (excluded from statistics)" >&2
        return 0
    fi
    [ "$mtc_status" -eq 0 ] || { echo "trace run $n: report validation failed" >&2; return 1; }
    echo $((T1 - T0)) >> "$WORK/trace.times"
    return 0
}

verify_trace_bound() {
    rm -f "$WORK/go"
    ( while [ ! -f "$WORK/go" ]; do sleep 0.02; done
      exec "$WORK/hammer" "$MODULE" "$N_CALLS" ) > "$WORK/trace_bound_hammer.log" 2>&1 &
    WPID=$!
    sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" trace \
        --manifest "$WORK/manifest.json" --pid "$WPID" \
        --duration 60 --max-events 1 -o "$WORK/trace_bound.txt" \
        > "$WORK/trace_bound_p11scope.log" 2>&1 &
    SPID=$!
    wait_for_observer_attach "$WORK/trace_bound_p11scope.log" "$ATTACH_TIMEOUT_S" \
        || { echo "bounded trace lane: attach gate failed" >&2; return 1; }
    touch "$WORK/go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; return "$status"; fi
    if wait "$SPID"; then status=0; else status=$?; fi
    SPID=
    [ "$status" -eq 0 ] || {
        echo "bounded trace lane exited $status" >&2
        cat "$WORK/trace_bound_p11scope.log" >&2
        return 1
    }
    reclaim_root_output "$WORK/trace_bound.txt"
    python3 -I scripts/lane-bench-overhead-oracle-1.py "$WORK/trace_bound.txt"
}

echo "=== interleaved benchmark: $RUNS rounds of unobserved/metrics/profile/trace ==="
: > "$WORK/unobserved.times"
: > "$WORK/metrics.times"
: > "$WORK/metrics.invalid_times"
: > "$WORK/profile.times"
: > "$WORK/profile.invalid_times"
: > "$WORK/trace.times"
: > "$WORK/trace.invalid_times"
i=1
while [ "$i" -le "$RUNS" ]; do
    echo "--- round $i/$RUNS ---"
    measure_unobserved "$i" || exit 1
    measure_profile "$i" metrics metrics || exit 1
    measure_profile "$i" profile profile || exit 1
    measure_trace "$i" || exit 1
    i=$((i + 1))
done
verify_trace_bound || exit 1

echo "=== results ==="
for cond in unobserved metrics profile trace; do
    if [ ! -s "$WORK/$cond.times" ]; then
        echo "no valid samples for $cond (all invalid or missing)" >&2
        exit 1
    fi
done
python3 -I scripts/lane-bench-overhead-oracle-2.py "$WORK" "$N_CALLS" "$KERNEL" "$CPU"

echo "invalid samples excluded from statistics:"
invalid_total=0
for cond in metrics profile trace; do
    inv=$(wc -l < "$WORK/$cond.invalid_times")
    inv=$(echo "$inv" | tr -d '[:space:]')
    echo "$cond: $inv invalid of $RUNS"
    invalid_total=$((invalid_total + inv))
done
if [ "$invalid_total" -gt 0 ]; then
    echo "bench-overhead: FAILED: $invalid_total sample(s) had unequal coverage" >&2
    exit 1
fi

echo "=== bench-overhead: DONE ==="
