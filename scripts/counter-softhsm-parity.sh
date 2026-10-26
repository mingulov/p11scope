#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Counter-mode parity against real SoftHSM: run one deterministic
# PKCS#11 workload twice under `run --mode metrics` (once plain, once
# per counter mode) and compare the `-o` JSON documents.
#
# Usage: counter-softhsm-parity.sh OBSERVER MODULE OUTDIR [MODES]
#
# OBSERVER is the prebuilt observer under test, MODULE the SoftHSM
# library under test, OUTDIR a writable directory for the workload
# binary, token store, reports and logs. MODES defaults to
# "counts timestamps latency". Needs root/BPF privilege (the observer
# attaches uprobes) and a kernel whose verifier accepts the counter
# programs (6.6+); on older kernels the counter runs refuse by name
# and the script fails naming the refusal. Exits 0 only when every
# run exits 0 and every parity comparison passes.
set -eu

if [ $# -lt 3 ]; then
    echo "usage: counter-softhsm-parity.sh OBSERVER MODULE OUTDIR [MODES]" >&2
    exit 2
fi
OBSERVER=$1
MODULE=$2
OUTDIR=$3
MODES=${4:-"counts timestamps latency"}
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
COMPARE="$SCRIPT_DIR/../tests/python/test_counter_softhsm_parity.py"
WORKLOAD_SRC="$SCRIPT_DIR/../tests/fixtures/counter-softhsm-workload.c"

[ -x "$OBSERVER" ] || { echo "observer not executable: $OBSERVER" >&2; exit 2; }
[ -r "$MODULE" ] || { echo "module not readable: $MODULE" >&2; exit 2; }
command -v cc >/dev/null || { echo "cc required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }
mkdir -p "$OUTDIR"
WORKLOAD="$OUTDIR/counter-softhsm-workload"
cc -O2 -Wall -Wextra -o "$WORKLOAD" "$WORKLOAD_SRC" -ldl || exit 2

TOKENS="$OUTDIR/tokens"
rm -rf "$TOKENS"
mkdir -p "$TOKENS"
export SOFTHSM2_CONF="$OUTDIR/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
    "$TOKENS" > "$SOFTHSM2_CONF"

ITERATIONS=200
SETTLE=${SETTLE_SECONDS:-30}
FAILED=0
ulimit -n 65536 2>/dev/null || true
if [ "$(id -u)" -eq 0 ] && [ -z "${SUDO_UID:-}" ]; then
    # A root observer drops the owned child to a non-root uid; default
    # to 1000 like the owned-run cells when the caller sets none.
    export SUDO_UID=1000 SUDO_GID="${SUDO_GID:-1000}"
    echo "# SUDO_UID unset: dropping owned children to $SUDO_UID:$SUDO_GID"
fi

run_capture() {
    name=$1
    shift
    log="$OUTDIR/$name.log"
    echo "## $name"
    rc=0
    timeout -k 30 300 "$OBSERVER" "$@" >"$log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "# error: $name exited $rc"
        tail -5 "$log"
        FAILED=1
        return 1
    fi
    grep -h -E '^(SETTLED|LEDGER) ' "$log" | tail -2 || true
}

run_capture plain run --mode metrics -o "$OUTDIR/plain.json" -- \
    "$WORKLOAD" "$MODULE" "$ITERATIONS" "$SETTLE" || true
if [ "$FAILED" -ne 0 ]; then
    echo "# error: plain run failed; refusing to compare"
    exit 1
fi
for mode in $MODES; do
    run_capture "counter-$mode" run --mode metrics --counter-mode "$mode" \
        -o "$OUTDIR/counter-$mode.json" -- "$WORKLOAD" "$MODULE" "$ITERATIONS" "$SETTLE" || true
    if [ ! -f "$OUTDIR/counter-$mode.json" ]; then
        echo "# error: counter-$mode left no report"
        FAILED=1
        continue
    fi
    if ! python3 -I "$COMPARE" --compare "$OUTDIR/plain.json" \
        "$OUTDIR/counter-$mode.json" --mode "$mode"; then
        FAILED=1
    fi
done
if [ "$FAILED" -ne 0 ]; then
    echo "# parity FAILED"
    exit 1
fi
echo "# parity OK: $MODES"
