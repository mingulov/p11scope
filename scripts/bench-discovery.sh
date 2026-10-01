#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Phase 2 Task D2: cold/warm discovery benchmark over the owned lifecycle
# fixture (the D1 harness,
# `cold_and_warm_discovery_agree_on_catalog_attach_sets_and_call_counts`).
#
# Method: RUNS rounds (default 5). Each round runs the D1 harness once in a
# fresh test process; the harness runs the same discover -> refresh ->
# quiet-tail procedure twice back to back (cold, then warm) over the same
# loaded owned child and prints one BENCH_DISCOVERY JSON sample line per
# run (wall time, per-stage ms/call counts, tail and newcomer numbers).
#
# Equal coverage: the harness asserts catalog/attach/call equality between
# its cold and warm runs. A round whose harness reports
# BENCH_DISCOVERY_INVALID is INVALID: it is excluded from the statistics,
# counted, and fails the run at the end. Any harness failure without the
# INVALID marker, a missing sample line, or a malformed line fails the run
# immediately — nothing is tolerated or skipped silently.
#
# Reports median and min..max wall-clock per run kind plus the median
# per-stage numbers and the queue/tail evidence. Live-capture stages
# (drain spans, inter-drain gaps, the resource timeline) need a privileged
# capture loop: the default unprivileged subset lists them as UNMEASURED.
# `--full` is the privileged controller-lane matrix: it fails loudly,
# listing the unmeasured stages, when the samples lack capture evidence,
# and passes once the samples carry it — a nonzero
# `stage_invocations.drain` plus the optional `inter_drain_gap_samples`
# and `resource_samples` keys the privileged harness maps from the
# capture report (see bench-discovery-stats.py). The controller runs the
# privileged 5x matched matrix with it.
#
# Usage:
#   scripts/bench-discovery.sh [--self-test] [--full]
# Environment: RUNS (default 5), TOOLCHAIN (default +1.88),
# TMPDIR (test temp I/O; repo rule: /var/tmp/p11scope-ws-tmp, never /tmp),
# CARGO_BUILD_JOBS (default 2).
set -eu
cd "$(dirname "$0")/.."

RUNS=${RUNS:-5}
TOOLCHAIN=${TOOLCHAIN:-+1.88}
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
WORK=${TMPDIR:-/var/tmp/p11scope-ws-tmp}/bench-discovery-$$
HARNESS=cold_and_warm_discovery_agree_on_catalog_attach_sets_and_call_counts

case "${1:-}" in
    --self-test)
        python3 -I scripts/bench-discovery-stats.py --self-test
        echo "bench-discovery: self-test ok"
        exit 0
        ;;
    --full) FULL=1; shift ;;
    "") FULL=0 ;;
    *) echo "usage: $0 [--self-test] [--full]" >&2; exit 2 ;;
esac
[ "$#" -eq 0 ] || { echo "usage: $0 [--self-test] [--full]" >&2; exit 2; }

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT INT TERM

echo "=== bench-discovery: $RUNS rounds of cold/warm ($TOOLCHAIN) ==="
: > "$WORK/samples.jsonl"
: > "$WORK/invalid.log"
invalid=0
i=1
while [ "$i" -le "$RUNS" ]; do
    echo "--- round $i/$RUNS ---"
    log="$WORK/round_$i.log"
    if TMPDIR="$WORK" mise exec -- ./scripts/cargo.sh "$TOOLCHAIN" \
        test --locked --lib -- "$HARNESS" --nocapture \
        > "$log" 2>&1; then
        status=0
    else
        status=$?
    fi
    if grep -q "BENCH_DISCOVERY_INVALID" "$log" 2>/dev/null; then
        echo "round $i: INVALID coverage (excluded from statistics)" >&2
        grep "BENCH_DISCOVERY_INVALID" "$log" >> "$WORK/invalid.log"
        invalid=$((invalid + 1))
    elif [ "$status" -ne 0 ]; then
        echo "round $i: harness failed without INVALID marker" >&2
        tail -n 20 "$log" >&2
        exit 1
    else
        count=$(grep -c "^BENCH_DISCOVERY {" "$log" || true)
        if [ "$count" -ne 2 ]; then
            echo "round $i: want 2 sample lines, got $count" >&2
            tail -n 20 "$log" >&2
            exit 1
        fi
        grep "^BENCH_DISCOVERY {" "$log" | sed 's/^BENCH_DISCOVERY //' \
            >> "$WORK/samples.jsonl"
    fi
    i=$((i + 1))
done

echo "=== results ==="
python3 -I scripts/bench-discovery-stats.py "$WORK/samples.jsonl"

echo "invalid samples excluded from statistics: $invalid of $RUNS"
if [ "$invalid" -gt 0 ]; then
    echo "bench-discovery: FAILED: $invalid sample(s) had unequal coverage" >&2
    exit 1
fi
if [ "$FULL" -eq 1 ]; then
    python3 -I scripts/bench-discovery-stats.py --check-only "$WORK/samples.jsonl"
fi
echo "=== bench-discovery: DONE (unprivileged subset) ==="
