#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Load the real observer's BPF programs inside throwaway vng guests and
# report every program's verifier cost per kernel.
#
# Usage: check-bpf-load-kernels.sh [--budgets FILE] OBSERVER PROBE OUTDIR [KERNEL...]
#
# OBSERVER is the prebuilt observer under test, PROBE the verifier-stats
# probe built by `measure-verifier-headroom.py build`, OUTDIR a directory
# under /home/user/.cache/p11scope-vng/<tag>/ shared with the guests.
# Default kernels: v5.15.221 v6.1.188 v6.6.157 v6.12.111 v6.18.58.
# --budgets defaults to the checked-in tests/bpf-verifier-budgets.json
# when that file exists, so a budgeted program with no probe row FAILs
# without any flag. Exits 0 only when every kernel passes; a timeout, a
# missing count or a nonzero report is FAIL.
#
# Counter-bank programs (p11_counter_bank_entry/_return) are absent from
# the default build and no guest command can load them yet: doctor
# preflights StaticRoots::Detailed only, `--counter-mode` returns
# counter-mode-unwired, and the bank objects build only with
# P11SCOPE_COUNTER_ARTIFACTS=1. When A2.7-A2.10 wire the modes, add a
# second guest command here running the wired counter capture with the
# probe on a second JSONL file, feed both files to the report, and only
# then add the two bank roots to the budgets file (earlier reds the gate
# via budgeted-but-missing).
set -eu

BUDGETS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --budgets)
            [ $# -ge 2 ] || { echo "missing value for --budgets" >&2; exit 2; }
            BUDGETS="$2"
            shift 2
            ;;
        --budgets=*)
            BUDGETS="${1#--budgets=}"
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "check-bpf-load-kernels.sh: unknown option $1" >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done
if [ $# -lt 3 ]; then
    echo "usage: check-bpf-load-kernels.sh [--budgets FILE] OBSERVER PROBE OUTDIR [KERNEL...]" >&2
    exit 2
fi
OBSERVER=$1
PROBE=$2
OUTDIR=$3
shift 3
if [ $# -eq 0 ]; then
    set -- v5.15.221 v6.1.188 v6.6.157 v6.12.111 v6.18.58
fi
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPORT="$SCRIPT_DIR/bpf-load-report.py"
if [ -z "$BUDGETS" ] && [ -f "$SCRIPT_DIR/../tests/bpf-verifier-budgets.json" ]; then
    BUDGETS="$SCRIPT_DIR/../tests/bpf-verifier-budgets.json"
fi

[ -f "$OBSERVER" ] || { echo "observer not found: $OBSERVER" >&2; exit 2; }
[ -f "$PROBE" ] || { echo "probe not found: $PROBE" >&2; exit 2; }
[ -d "$OUTDIR" ] || { echo "output dir not found: $OUTDIR" >&2; exit 2; }
[ -f "$REPORT" ] || { echo "report script not found: $REPORT" >&2; exit 2; }
if [ -n "$BUDGETS" ] && [ ! -f "$BUDGETS" ]; then
    echo "budgets not found: $BUDGETS" >&2
    exit 2
fi
command -v vng >/dev/null || { echo "vng not on PATH" >&2; exit 2; }

OBSERVER_SHA=$(sha256sum "$OBSERVER" | cut -d' ' -f1)
echo "# observer: $OBSERVER"
echo "# observer-sha256: $OBSERVER_SHA"
echo "# probe: $PROBE"
if [ -n "$BUDGETS" ]; then
    echo "# budgets: $BUDGETS"
else
    echo "# budgets: none (gate is loaded + stats + 5% headroom)"
fi

# Single-quote a path for the guest shell.
q() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

FAILED=0
for KERNEL in "$@"; do
    echo "## kernel $KERNEL"
    PROBE_JSON="$OUTDIR/probe-$KERNEL.jsonl"
    DOCTOR_TXT="$OUTDIR/doctor-$KERNEL.txt"
    VNG_LOG="$OUTDIR/vng-$KERNEL.log"
    rm -f "$PROBE_JSON" "$DOCTOR_TXT" "$VNG_LOG"
    EXEC="cd $(q "$OUTDIR") && LD_PRELOAD=$(q "$PROBE") P11SCOPE_VERIFIER_STATS_FD=9 $(q "$OBSERVER") doctor 9>$(q "probe-$KERNEL.jsonl") >$(q "doctor-$KERNEL.txt") 2>&1; rc=\$?; echo guest-release=\$(uname -r); echo rc=\$rc"
    if ! timeout -k 30 300 vng --run "$KERNEL" --user root --cpus 4 --memory 4G \
        --rwdir "$OUTDIR" --exec "$EXEC" < /dev/null >"$VNG_LOG" 2>&1; then
        echo "# error: vng run failed or timed out on $KERNEL (see $VNG_LOG)"
        FAILED=1
        continue
    fi
    if ! grep -q '^rc=' "$VNG_LOG"; then
        echo "# error: no guest exit line on $KERNEL (see $VNG_LOG)"
        FAILED=1
        continue
    fi
    GUEST_RELEASE=$(grep '^guest-release=' "$VNG_LOG" | tail -1 | cut -d= -f2)
    case "$GUEST_RELEASE" in
        "${KERNEL#v}"*)
            echo "# guest release $GUEST_RELEASE (expected $KERNEL)"
            ;;
        *)
            echo "# error: guest booted $GUEST_RELEASE, expected $KERNEL"
            FAILED=1
            continue
            ;;
    esac
    echo "# doctor $(grep '^rc=' "$VNG_LOG" | tail -1)"
    if [ ! -f "$DOCTOR_TXT" ] || ! grep -q 'host program preflight' "$DOCTOR_TXT"; then
        echo "# error: doctor never reached host program preflight on $KERNEL"
        FAILED=1
        continue
    fi
    grep 'host program preflight' "$DOCTOR_TXT" | head -1
    if [ -n "$BUDGETS" ]; then
        # No word splitting: the budgets path stays quoted in its own arm.
        if ! python3 -I "$REPORT" --budgets "$BUDGETS" --kernel "$KERNEL" \
            --observer-sha256 "$OBSERVER_SHA" "$PROBE_JSON"; then
            FAILED=1
        fi
    else
        if ! python3 -I "$REPORT" --kernel "$KERNEL" \
            --observer-sha256 "$OBSERVER_SHA" "$PROBE_JSON"; then
            FAILED=1
        fi
    fi
done

if [ "$FAILED" -ne 0 ]; then
    echo "# OVERALL: FAIL"
    exit 1
fi
echo "# OVERALL: PASS"
