#!/bin/sh
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
# Method: each condition is timed by wrapping only the workload process's
# own wall-clock (go-file synchronization, same pattern as every other
# verify-*.sh in this repo — the observer/attacher is given a warm-up
# window before the workload's first call, so attach latency is never
# counted as part of the measured window). >=5 runs per condition;
# reports median and min..max spread, not a single number.
set -eu
cd "$(dirname "$0")/.."

MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/bench-overhead
FIX=scripts/fixtures
RUNS=${RUNS:-5}
N_CALLS=${N_CALLS:-1000000}
WPID=
SPID=
mkdir -p "$WORK"

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
cargo build --release --workspace
DISCOVER=./target/release/p11scope-discover
P11SCOPE=./target/release/p11scope
gcc -O0 -o "$WORK/hammer" "$FIX/hammer.c" -ldl

echo "=== private softhsm token ==="
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

# Runs the hammer workload alone (no p11scope), returning its wall-clock
# in nanoseconds. Same go-file gate as the observed conditions below, for
# a like-for-like measured window even though nothing needs a warm-up here.
measure_unobserved() {
    n=$1
    rm -f "$WORK/go"
    ( while [ ! -f "$WORK/go" ]; do sleep 0.02; done
      exec "$WORK/hammer" "$MODULE" "$N_CALLS" ) > "$WORK/unobserved_${n}.log" 2>&1 &
    WPID=$!
    T0=$(date +%s%N)
    touch "$WORK/go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; return "$status"; fi
    T1=$(date +%s%N)
    echo $((T1 - T0))
}

# Runs the hammer workload under `p11scope profile --mode <mode>`,
# attached before the workload's first call (3s warm-up after the
# process exists, same margin the rest of this repo's scripts use).
# Ends the observer with SIGINT after the workload finishes (Task 2's
# clean-shutdown path) so its -o report is valid, then sanity-checks
# that every probe actually attached — an unattached run would silently
# measure "unobserved" a second time under a different label.
measure_profile() {
    n=$1
    mode=$2
    label=$3
    rm -f "$WORK/go"
    ( while [ ! -f "$WORK/go" ]; do sleep 0.02; done
      exec "$WORK/hammer" "$MODULE" "$N_CALLS" ) > "$WORK/${label}_hammer_${n}.log" 2>&1 &
    WPID=$!
    sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile \
        --manifest "$WORK/manifest.json" --pid "$WPID" \
        --mode "$mode" --duration 60 -o "$WORK/${label}_${n}.json" \
        > "$WORK/${label}_p11scope_${n}.log" 2>&1 &
    SPID=$!
    sleep 3
    T0=$(date +%s%N)
    touch "$WORK/go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; return "$status"; fi
    T1=$(date +%s%N)
    kill -INT "$SPID" 2>/dev/null || true
    wait "$SPID" 2>/dev/null || true
    SPID=
    sudo chown "$(id -u):$(id -g)" "$WORK/${label}_${n}.json"
    if grep -q "attach failed" "$WORK/${label}_p11scope_${n}.log"; then
        echo "ATTACH FAILURE in $label run $n:" >&2
        cat "$WORK/${label}_p11scope_${n}.log" >&2
        exit 1
    fi
    python3 -c "
import json, sys
ev = json.load(open('$WORK/${label}_${n}.json'))['evidence']
assert ev['attached_probes'] > 0, 'no probes attached: ' + repr(ev)
" || { echo "sanity check failed for $label run $n" >&2; exit 1; }
    echo $((T1 - T0))
}

# Runs the hammer workload under `p11scope trace`. Output is sent to a
# file with -o AND the observer's own stdout is redirected to a plain
# file rather than a terminal — `trace` prints one line per call, and on
# a real tty that I/O would become the bottleneck being measured instead
# of probe overhead. Sanity check here is "no attach failed lines and no
# 0-line trace file", trace has no JSON evidence block to inspect.
measure_trace() {
    n=$1
    rm -f "$WORK/go"
    ( while [ ! -f "$WORK/go" ]; do sleep 0.02; done
      exec "$WORK/hammer" "$MODULE" "$N_CALLS" ) > "$WORK/trace_hammer_${n}.log" 2>&1 &
    WPID=$!
    sudo --preserve-env=SOFTHSM2_CONF "$P11SCOPE" trace \
        --manifest "$WORK/manifest.json" --pid "$WPID" \
        --duration 60 -o "$WORK/trace_${n}.txt" \
        > "$WORK/trace_p11scope_${n}.log" 2>&1 &
    SPID=$!
    sleep 3
    T0=$(date +%s%N)
    touch "$WORK/go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; return "$status"; fi
    T1=$(date +%s%N)
    kill -INT "$SPID" 2>/dev/null || true
    wait "$SPID" 2>/dev/null || true
    SPID=
    sudo chown "$(id -u):$(id -g)" "$WORK/trace_${n}.txt"
    if grep -q "attach failed" "$WORK/trace_p11scope_${n}.log"; then
        echo "ATTACH FAILURE in trace run $n:" >&2
        cat "$WORK/trace_p11scope_${n}.log" >&2
        exit 1
    fi
    lines=$(wc -l < "$WORK/trace_${n}.txt")
    if [ "$lines" -lt 1 ]; then
        echo "trace run $n produced no output lines" >&2
        exit 1
    fi
    echo $((T1 - T0))
}

echo "=== unobserved ==="
: > "$WORK/unobserved.times"
i=1
while [ "$i" -le "$RUNS" ]; do
    measure_unobserved "$i" >> "$WORK/unobserved.times"
    i=$((i + 1))
done

echo "=== profile --mode metrics ==="
: > "$WORK/metrics.times"
i=1
while [ "$i" -le "$RUNS" ]; do
    measure_profile "$i" metrics metrics >> "$WORK/metrics.times"
    i=$((i + 1))
done

echo "=== profile --mode profile ==="
: > "$WORK/profile.times"
i=1
while [ "$i" -le "$RUNS" ]; do
    measure_profile "$i" profile profile >> "$WORK/profile.times"
    i=$((i + 1))
done

echo "=== trace ==="
: > "$WORK/trace.times"
i=1
while [ "$i" -le "$RUNS" ]; do
    measure_trace "$i" >> "$WORK/trace.times"
    i=$((i + 1))
done

echo "=== results ==="
python3 - "$WORK" "$N_CALLS" "$KERNEL" "$CPU" <<'PY'
import statistics, sys

work, n_calls, kernel, cpu = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

conditions = [
    ("unobserved", "unobserved.times"),
    ("profile --mode metrics", "metrics.times"),
    ("profile --mode profile", "profile.times"),
    ("trace", "trace.times"),
]

print(f"kernel: {kernel}")
print(f"cpu: {cpu}")
print(f"calls per run: {n_calls}")
print()

rows = []
baseline_percall_median = None
for label, fname in conditions:
    ns = [int(x) for x in open(f"{work}/{fname}") if x.strip()]
    ms = [x / 1e6 for x in ns]
    percall = [x / n_calls for x in ns]
    med_ms = statistics.median(ms)
    med_percall = statistics.median(percall)
    if label == "unobserved":
        baseline_percall_median = med_percall
    rows.append((label, ms, med_ms, percall, med_percall))

print(f"{'condition':<26} {'median ms':>10} {'min..max ms':>18} {'median ns/call':>15} {'overhead ns/call':>18}")
for label, ms, med_ms, percall, med_percall in rows:
    overhead = med_percall - baseline_percall_median
    print(f"{label:<26} {med_ms:>10.1f} {min(ms):>7.1f}..{max(ms):<8.1f} {med_percall:>15.1f} {overhead:>18.1f}")
PY

echo "=== bench-overhead: DONE ==="
