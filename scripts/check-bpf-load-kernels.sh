#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Load the real observer's BPF programs inside throwaway vng guests and
# report every program's verifier cost per kernel.
#
# Usage: check-bpf-load-kernels.sh [--budgets FILE] [--counter-budgets FILE] OBSERVER PROBE OUTDIR [KERNEL...]
#
# OBSERVER is the prebuilt observer under test, PROBE the verifier-stats
# probe built by `measure-verifier-headroom.py build`, OUTDIR a directory
# under /home/user/.cache/p11scope-vng/<tag>/ shared with the guests.
# Default kernels: v5.15.221 v6.1.188 v6.6.157 v6.12.111 v6.18.58.
# --budgets defaults to the checked-in tests/bpf-verifier-budgets.json
# when that file exists, so a budgeted program with no probe row FAILs
# without any flag. --counter-budgets defaults to the checked-in
# tests/counter-bpf-verifier-budgets.json the same way. Exits 0 only when
# every kernel passes; a timeout, a missing count or a nonzero report
# is FAIL.
#
# Per kernel five throwaway guests run one command each under the probe:
# `doctor` (Detailed plus Inventory objects in one file, probe-K.jsonl,
# grouped by BTF id and scored as detailed; the Inventory groups in
# that file are ignored there), a bounded
# `inventory --system --capture native` (Inventory object,
# inventory-probe-K.jsonl), and one bounded `profile --system --mode
# metrics --counter-mode <mode>` per mode (that mode's counter bank
# object, counter-<mode>-probe-K.jsonl). Separate guests because virtme
# carries --exec base64 on the kernel command line (2048 bytes); one
# combined command overflows it and the guest then silently never runs.
# Separate counter runs per mode because probe rows key programs by root
# name only while all three bank objects export the same
# p11_counter_bank_entry/p11_counter_bank_return roots: one combined run
# would collide in by_root. Before each command, the guest stages its
# kernel's /boot/config from the virtme-ng cache (the kernel round's
# cells-guest.sh pattern), so the instance hooks load the way they do on
# ordinary hosts instead of refusing on unverifiable LTO status. The
# inventory run raises the guest descriptor limit first (the guest hard
# limit is 4096, below the 4163 a 4096-endpoint Singles session needs)
# and is bounded by `timeout -s INT`, passing on rc 0 (one pass
# finished) or rc 124 (bounded stop); any other exit, or a crash marker
# in its log, is FAIL. Each counter run likewise raises the descriptor
# limit and is bounded by `timeout -s INT` past its own --duration 5s.
# The probe rewrites log_level, so doctor's counter-modes footer under
# the probe is a gate artifact ("probe failed unexpectedly"), never
# product behaviour: the gate checks only the host program preflight
# line in doctor output and never scores or quotes that footer.
#
# Coverage: the 18 Detailed programs doctor loads in the guest (13
# defaults, p11_image_query, 4 instance hooks), scored from the Detailed
# BTF groups in doctor's probe file against their per-kernel per-object
# budgets, and the 12 Inventory programs the system inventory loads,
# scored against their own per-kernel per-object budgets. Doctor's file
# also holds its Inventory preflight loads under other BTF ids; those
# groups never supply Detailed coverage, so a Detailed program doctor
# stops loading is still reported missing. Both sides fail on a refused
# load, a missing probe row, or a count over budget. Per counter mode the
# 15 programs the profile run loads from that mode's counter object (the
# 13 defaults, including the sched_process_exec/exit lifecycle pair that
# loads in every counter profile run, plus the 2 bank roots), scored per
# object (counter-<mode>) against the numeric per-kernel budgets in
# tests/counter-bpf-verifier-budgets.json (a separate file with its own
# kernel set, since the main file's shape pin requires one kernel set
# for every program), so a missing program or growth FAILs. The probe
# file's 16th load (the lone Detailed return) belongs to no counter
# group and is ignored when scoring counter modes. 5.15 refuses before
# loading (no bpf_loop, no counter program tried) and 6.1 refuses at
# load with the named counter-mode-unavailable-on-kernel at-load refusal
# (verifier E2BIG on a named counter program); the gate passes those
# kernels only when the observer log names the token, no bank program
# loaded, and (on 6.1) the probe file holds a non-auxiliary E2BIG row
# for a named counter program. Known gaps, not gated:
# p11_selected_bootstrap (loads only for a promoted live process, which
# needs a provider mapped in the guest), the dormant
# p11_selected_cgroup_migrate (present in the object, no load call
# site), and the lazily loaded p11_inventory_image_baseline iterator (no
# provider in the guest loads it).
set -eu

BUDGETS=""
COUNTER_BUDGETS=""
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
        --counter-budgets)
            [ $# -ge 2 ] || { echo "missing value for --counter-budgets" >&2; exit 2; }
            COUNTER_BUDGETS="$2"
            shift 2
            ;;
        --counter-budgets=*)
            COUNTER_BUDGETS="${1#--counter-budgets=}"
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
    echo "usage: check-bpf-load-kernels.sh [--budgets FILE] [--counter-budgets FILE] OBSERVER PROBE OUTDIR [KERNEL...]" >&2
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
if [ -z "$COUNTER_BUDGETS" ] && [ -f "$SCRIPT_DIR/../tests/counter-bpf-verifier-budgets.json" ]; then
    COUNTER_BUDGETS="$SCRIPT_DIR/../tests/counter-bpf-verifier-budgets.json"
fi

[ -f "$OBSERVER" ] || { echo "observer not found: $OBSERVER" >&2; exit 2; }
[ -f "$PROBE" ] || { echo "probe not found: $PROBE" >&2; exit 2; }
[ -d "$OUTDIR" ] || { echo "output dir not found: $OUTDIR" >&2; exit 2; }
[ -f "$REPORT" ] || { echo "report script not found: $REPORT" >&2; exit 2; }
if [ -n "$BUDGETS" ] && [ ! -f "$BUDGETS" ]; then
    echo "budgets not found: $BUDGETS" >&2
    exit 2
fi
if [ -n "$COUNTER_BUDGETS" ] && [ ! -f "$COUNTER_BUDGETS" ]; then
    echo "counter budgets not found: $COUNTER_BUDGETS" >&2
    exit 2
fi
command -v vng >/dev/null || { echo "vng not on PATH" >&2; exit 2; }

OBSERVER_SHA=$(sha256sum "$OBSERVER" | cut -d' ' -f1)
echo "# observer: $OBSERVER"
echo "# observer-sha256: $OBSERVER_SHA"
echo "# probe: $PROBE"
if [ -n "$COUNTER_BUDGETS" ]; then
    echo "# counter-budgets: $COUNTER_BUDGETS"
else
    echo "# counter-budgets: none (gate is loaded + stats + 5% headroom)"
fi
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
VNG_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/virtme-ng"
# Guest shell below: every $ for the guest is \$ here; only single
# quotes travel (virtme hands the string to the guest shell as one
# argument). Staging never aborts the chain: a staging failure is
# caught by the marker check below, and the hooks it would enable
# are caught by the budgets when they never load.
STAGE="K=\$(uname -r); if [ ! -r /boot/config-\$K ]; then C=\$(ls $(q "$VNG_CACHE")/*/amd64/boot/config-\$K 2>/dev/null | head -n 1); if [ x\$C = x ]; then echo no-kernel-config-for-\$K; else mount -t tmpfs -o mode=755 guestboot /boot && cp \$C /boot/ && echo staged-boot-config-\$K || echo stage-boot-failed-\$K; fi; else echo boot-config-present-\$K; fi"
for KERNEL in "$@"; do
    echo "## kernel $KERNEL"
    PROBE_JSON="$OUTDIR/probe-$KERNEL.jsonl"
    DOCTOR_TXT="$OUTDIR/doctor-$KERNEL.txt"
    INV_PROBE_JSON="$OUTDIR/inventory-probe-$KERNEL.jsonl"
    INV_TXT="$OUTDIR/inventory-$KERNEL.txt"
    VNG_LOG="$OUTDIR/vng-$KERNEL.log"
    VNG_INV_LOG="$OUTDIR/vng-inv-$KERNEL.log"
    rm -f "$PROBE_JSON" "$DOCTOR_TXT" "$INV_PROBE_JSON" "$INV_TXT" "$VNG_LOG" "$VNG_INV_LOG"
    EXEC1="cd $(q "$OUTDIR") && $STAGE; LD_PRELOAD=$(q "$PROBE") P11SCOPE_VERIFIER_STATS_FD=9 $(q "$OBSERVER") doctor 9>$(q "probe-$KERNEL.jsonl") >$(q "doctor-$KERNEL.txt") 2>&1; echo doctor-rc=\$?; echo guest-release=\$(uname -r)"
    EXEC2="cd $(q "$OUTDIR") && $STAGE; ulimit -n 65536; timeout -k 10 -s INT 20 env LD_PRELOAD=$(q "$PROBE") P11SCOPE_VERIFIER_STATS_FD=9 $(q "$OBSERVER") inventory --system --capture native --identity-backend userspace 9>$(q "inventory-probe-$KERNEL.jsonl") >$(q "inventory-$KERNEL.txt") 2>&1; echo inventory-rc=\$?; echo guest-release=\$(uname -r)"
    # Fail fast past the kernel command line: 950 raw bytes encode to
    # ~1270 base64 bytes, which still fits the 2048 budget beside
    # virtme's own arguments; past it the guest silently never runs.
    if [ "${#EXEC1}" -gt 950 ] || [ "${#EXEC2}" -gt 950 ]; then
        echo "# error: guest command exceeds the kernel-cmdline budget on $KERNEL"
        FAILED=1
        continue
    fi
    if ! timeout -k 30 300 vng --run "$KERNEL" --user root --cpus 4 --memory 4G \
        --rwdir "$OUTDIR" --exec "$EXEC1" < /dev/null >"$VNG_LOG" 2>&1; then
        echo "# error: vng doctor run failed or timed out on $KERNEL (see $VNG_LOG)"
        FAILED=1
        continue
    fi
    if ! grep -q '^doctor-rc=' "$VNG_LOG"; then
        echo "# error: no guest exit line on $KERNEL (see $VNG_LOG)"
        FAILED=1
        continue
    fi
    if ! grep -Eq '^(staged-boot-config|boot-config-present)-' "$VNG_LOG"; then
        echo "# error: kernel config not staged on $KERNEL (see $VNG_LOG)"
        FAILED=1
        continue
    fi
    grep -E '^(staged-boot-config|boot-config-present)-' "$VNG_LOG" | tail -1
    GUEST_RELEASE=$(grep '^guest-release=' "$VNG_LOG" | tail -1 | cut -d= -f2)
    case "$GUEST_RELEASE" in
        "${KERNEL#v}"|"${KERNEL#v}-"*)
            echo "# guest release $GUEST_RELEASE (expected $KERNEL)"
            ;;
        *)
            echo "# error: guest booted $GUEST_RELEASE, expected $KERNEL"
            FAILED=1
            continue
            ;;
    esac
    echo "# doctor rc=$(grep '^doctor-rc=' "$VNG_LOG" | tail -1 | cut -d= -f2)"
    if [ ! -f "$DOCTOR_TXT" ] || ! grep -q 'host program preflight' "$DOCTOR_TXT"; then
        echo "# error: doctor never reached host program preflight on $KERNEL"
        FAILED=1
        continue
    fi
    grep 'host program preflight' "$DOCTOR_TXT" | head -1
    if ! timeout -k 30 300 vng --run "$KERNEL" --user root --cpus 4 --memory 4G \
        --rwdir "$OUTDIR" --exec "$EXEC2" < /dev/null >"$VNG_INV_LOG" 2>&1; then
        echo "# error: vng inventory run failed or timed out on $KERNEL (see $VNG_INV_LOG)"
        FAILED=1
        continue
    fi
    if ! grep -q '^inventory-rc=' "$VNG_INV_LOG"; then
        echo "# error: no inventory exit line on $KERNEL (see $VNG_INV_LOG)"
        FAILED=1
        continue
    fi
    if ! grep -Eq '^(staged-boot-config|boot-config-present)-' "$VNG_INV_LOG"; then
        echo "# error: kernel config not staged for inventory on $KERNEL (see $VNG_INV_LOG)"
        FAILED=1
        continue
    fi
    grep -E '^(staged-boot-config|boot-config-present)-' "$VNG_INV_LOG" | tail -1
    INV_RELEASE=$(grep '^guest-release=' "$VNG_INV_LOG" | tail -1 | cut -d= -f2)
    case "$INV_RELEASE" in
        "${KERNEL#v}"|"${KERNEL#v}-"*)
            echo "# inventory guest release $INV_RELEASE (expected $KERNEL)"
            ;;
        *)
            echo "# error: inventory guest booted $INV_RELEASE, expected $KERNEL"
            FAILED=1
            continue
            ;;
    esac
    # A failed inventory command still falls through to the reports: its
    # probe rows name the refused program, and the Detailed rows from the
    # first guest stay valid. Only infrastructure failures above skip the
    # kernel; a wrong-kernel guest never reaches scoring.
    INV_RC=$(grep '^inventory-rc=' "$VNG_INV_LOG" | tail -1 | cut -d= -f2)
    case "$INV_RC" in
        0|124)
            echo "# inventory rc=$INV_RC (0 finished, 124 bounded stop)"
            ;;
        *)
            echo "# error: inventory --system exited rc=$INV_RC on $KERNEL (see $INV_TXT)"
            FAILED=1
            ;;
    esac
    if [ ! -f "$INV_TXT" ] || grep -Eqi 'panicked at|traceback|SIGSEGV|SIGABRT' "$INV_TXT"; then
        echo "# error: inventory --system crashed or left no log on $KERNEL (see $VNG_INV_LOG)"
        FAILED=1
    fi
    if [ -n "$BUDGETS" ]; then
        # No word splitting: the budgets path stays quoted in its own arm.
        if ! python3 -I "$REPORT" --budgets "$BUDGETS" --object detailed --kernel "$KERNEL" \
            --observer-sha256 "$OBSERVER_SHA" "$PROBE_JSON"; then
            FAILED=1
        fi
    else
        if ! python3 -I "$REPORT" --object detailed --kernel "$KERNEL" \
            --observer-sha256 "$OBSERVER_SHA" "$PROBE_JSON"; then
            FAILED=1
        fi
    fi
    if [ -n "$BUDGETS" ]; then
        if ! python3 -I "$REPORT" --budgets "$BUDGETS" --object inventory --kernel "$KERNEL" \
            --observer-sha256 "$OBSERVER_SHA" "$INV_PROBE_JSON"; then
            FAILED=1
        fi
    else
        if ! python3 -I "$REPORT" --object inventory --kernel "$KERNEL" \
            --observer-sha256 "$OBSERVER_SHA" "$INV_PROBE_JSON"; then
            FAILED=1
        fi
    fi
    for MODE in counts timestamps latency; do
        C_PROBE_JSON="$OUTDIR/counter-$MODE-probe-$KERNEL.jsonl"
        C_TXT="$OUTDIR/counter-$MODE-$KERNEL.txt"
        C_VNG_LOG="$OUTDIR/vng-counter-$MODE-$KERNEL.log"
        rm -f "$C_PROBE_JSON" "$C_TXT" "$C_VNG_LOG"
        EXEC_C="cd $(q "$OUTDIR") && $STAGE; ulimit -n 65536; timeout -k 10 -s INT 60 env LD_PRELOAD=$(q "$PROBE") P11SCOPE_VERIFIER_STATS_FD=9 $(q "$OBSERVER") profile --system --mode metrics --counter-mode $MODE --duration 5s 9>$(q "counter-$MODE-probe-$KERNEL.jsonl") >$(q "counter-$MODE-$KERNEL.txt") 2>&1; echo counter-rc=\$?; echo guest-release=\$(uname -r)"
        if [ "${#EXEC_C}" -gt 950 ]; then
            echo "# error: counter guest command exceeds the kernel-cmdline budget on $KERNEL"
            FAILED=1
            continue
        fi
        if ! timeout -k 30 300 vng --run "$KERNEL" --user root --cpus 4 --memory 4G \
            --rwdir "$OUTDIR" --exec "$EXEC_C" < /dev/null >"$C_VNG_LOG" 2>&1; then
            echo "# error: vng counter-$MODE run failed or timed out on $KERNEL (see $C_VNG_LOG)"
            FAILED=1
            continue
        fi
        if ! grep -q '^counter-rc=' "$C_VNG_LOG"; then
            echo "# error: no counter exit line on $KERNEL (see $C_VNG_LOG)"
            FAILED=1
            continue
        fi
        if ! grep -Eq '^(staged-boot-config|boot-config-present)-' "$C_VNG_LOG"; then
            echo "# error: kernel config not staged for counter-$MODE on $KERNEL (see $C_VNG_LOG)"
            FAILED=1
            continue
        fi
        C_RELEASE=$(grep '^guest-release=' "$C_VNG_LOG" | tail -1 | cut -d= -f2)
        case "$C_RELEASE" in
            "${KERNEL#v}"|"${KERNEL#v}-"*)
                echo "# counter-$MODE guest release $C_RELEASE (expected $KERNEL)"
                ;;
            *)
                echo "# error: counter-$MODE guest booted $C_RELEASE, expected $KERNEL"
                FAILED=1
                continue
                ;;
        esac
        C_RC=$(grep '^counter-rc=' "$C_VNG_LOG" | tail -1 | cut -d= -f2)
        case "$KERNEL" in
            v5.15.*|v6.1.*)
                # The specified refusal: the observer names the token, and
                # the probe file holds refusal rows (6.1 E2BIG at load) or
                # the bare summary (5.15 refuses before loading). A behavior
                # flip (loads where none were specified) names no token and
                # FAILs here, so new loads need new budgets before they pass.
                if [ ! -f "$C_TXT" ] || ! grep -q 'counter-mode-unavailable-on-kernel' "$C_TXT"; then
                    echo "# error: counter-$MODE on $KERNEL left no specified refusal (see $C_TXT)"
                    FAILED=1
                    continue
                fi
                if grep -Eqi 'panicked at|traceback|SIGSEGV|SIGABRT' "$C_TXT"; then
                    echo "# error: counter-$MODE profile crashed on $KERNEL (see $C_TXT)"
                    FAILED=1
                    continue
                fi
                if [ ! -f "$C_PROBE_JSON" ] || ! grep -q -E '"record": ?"probe-summary"' "$C_PROBE_JSON"; then
                    echo "# error: counter-$MODE probe never finished on $KERNEL (see $C_VNG_LOG)"
                    FAILED=1
                    continue
                fi
                if grep 'p11_counter_bank' "$C_PROBE_JSON" | grep -q -E '"loaded": ?true'; then
                    echo "# error: counter-$MODE on $KERNEL loaded where refusal was specified (see $C_PROBE_JSON)"
                    FAILED=1
                    continue
                fi
                REFUSED=$(grep -E '"loaded": ?false' "$C_PROBE_JSON" | wc -l)
                case "$KERNEL" in
                    v6.1.*)
                        # At-load proof: a non-auxiliary, non-unresolved row
                        # refused with E2BIG (exactly errno 7, not 70+).
                        # Auxiliary aya probes and the bpf_loop probe
                        # (unresolved) do not count;
                        # only a named counter program proves the specified
                        # at-load path ran. Prints the program name.
                        E2BIG_PROG=$(grep -E '"loaded": ?false' "$C_PROBE_JSON" \
                            | grep -E '"auxiliary": ?null' \
                            | grep -v -E '"root": ?"unresolved"' \
                            | grep -E '"errno": ?7([^0-9]|$)' \
                            | sed -n 's/.*"root": *"\([^"]*\)".*/\1/p' \
                            | sort -u | head -n 1)
                        if [ -z "$E2BIG_PROG" ]; then
                            echo "# error: counter-$MODE on $KERNEL left no at-load refusal rows (expected E2BIG from a named counter program)"
                            FAILED=1
                            continue
                        fi
                        echo "# counter-$MODE refused as specified on $KERNEL (rc=$C_RC refusal-rows=$REFUSED e2big-program=$E2BIG_PROG)"
                        ;;
                    *)
                        echo "# counter-$MODE refused as specified on $KERNEL (rc=$C_RC refusal-rows=$REFUSED)"
                        ;;
                esac
                ;;
            *)
                # A failed counter run still falls through to per-program
                # scoring like inventory does: the probe rows name the
                # refused program. Only infrastructure failures above skip
                # the mode; a wrong-kernel guest never reaches scoring.
                case "$C_RC" in
                    0)
                        echo "# counter-$MODE rc=0 on $KERNEL"
                        ;;
                    *)
                        echo "# error: counter-$MODE profile exited rc=$C_RC on $KERNEL (see $C_TXT)"
                        FAILED=1
                        ;;
                esac
                if [ ! -f "$C_TXT" ] || grep -Eqi 'panicked at|traceback|SIGSEGV|SIGABRT' "$C_TXT"; then
                    echo "# error: counter-$MODE profile crashed or left no log on $KERNEL (see $C_VNG_LOG)"
                    FAILED=1
                fi
                if [ -n "$COUNTER_BUDGETS" ]; then
                    # No word splitting: the budgets path stays quoted in its own arm.
                    if ! python3 -I "$REPORT" --budgets "$COUNTER_BUDGETS" --object "counter-$MODE" --kernel "$KERNEL" \
                        --observer-sha256 "$OBSERVER_SHA" "$C_PROBE_JSON"; then
                        FAILED=1
                    fi
                else
                    if ! python3 -I "$REPORT" --object "counter-$MODE" --kernel "$KERNEL" \
                        --observer-sha256 "$OBSERVER_SHA" "$C_PROBE_JSON"; then
                        FAILED=1
                    fi
                fi
                ;;
        esac
    done
done

if [ "$FAILED" -ne 0 ]; then
    echo "# OVERALL: FAIL"
    exit 1
fi
echo "# OVERALL: PASS"
