#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Load the gate-1 observer's Detailed BPF programs inside throwaway vng
# guests and report every program's verifier cost per kernel.
#
# Usage: check-bpf-load-gate1.sh [--budgets FILE] OBSERVER PROBE OUTDIR [KERNEL...]
#
# OBSERVER is the gate-1 observer under test (built with
# P11SCOPE_LOADER_GATE=1), PROBE the verifier-stats probe built by
# `measure-verifier-headroom.py build`, OUTDIR a directory under
# /home/user/.cache/p11scope-vng/<tag>/ shared with the guests.
# Default kernels: v6.6.157 v6.12.111 v6.18.58 v7.0.14 (the budgeted
# gate-1 set). --budgets defaults to the checked-in
# tests/bpf-verifier-budgets.json when that file exists, so a budgeted
# program with no probe row FAILs without any flag. Exits 0 only when
# every kernel passes; a timeout, a missing count, a refused load, a
# count over budget or a nonzero doctor exit is FAIL.
#
# Per kernel one throwaway guest runs `doctor -v` under the probe: the
# gate-1 delta is the Detailed object alone (Inventory and counter
# objects are byte-identical to gate-0, proven by
# scripts/check-gate0-identity.py), so only doctor's Detailed BTF
# groups are scored, as detailed-gate1/<root> against budget keys of
# that form. The guest stages its kernel's /boot/config from the
# virtme-ng cache first (the kernel round's cells-guest.sh pattern),
# so the instance hooks load the way they do on ordinary hosts. The
# probe rewrites log_level, so doctor's counter-modes footer under the
# probe is a gate artifact ("probe failed unexpectedly"), never
# product behaviour: the gate checks only the host program preflight
# line in doctor output and never scores or quotes that footer. Doctor
# runs with -v: the concise default hides Ok rows, including that line.
#
# Coverage: the 18 Detailed programs doctor loads in the guest (13
# defaults, p11_image_query, 4 instance hooks), scored from the
# Detailed BTF groups in doctor's probe file against their per-kernel
# per-object budgets. Doctor's file also holds its Inventory
# preflight loads under other BTF ids; those groups never supply
# Detailed coverage, so a Detailed program doctor stops loading is
# still reported missing. Both a refused load, a missing probe row, or
# a count over budget FAILs. Stock pre-Multi hosts use the separate
# combined check-multi-host-refusal.py control, never this load/cost
# campaign. Known gaps, not gated (as in check-bpf-load-kernels.sh):
# p11_selected_bootstrap (loads only for a promoted live process),
# the dormant p11_selected_cgroup_migrate (no load call site), and
# the lazily loaded p11_inventory_image_baseline iterator.
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
            echo "check-bpf-load-gate1.sh: unknown option $1" >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done
if [ $# -lt 3 ]; then
    echo "usage: check-bpf-load-gate1.sh [--budgets FILE] OBSERVER PROBE OUTDIR [KERNEL...]" >&2
    exit 2
fi
OBSERVER=$1
PROBE=$2
OUTDIR=$3
shift 3
if [ $# -eq 0 ]; then
    set -- v6.6.157 v6.12.111 v6.18.58 v7.0.14
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
# Guest release match, shared with the kernels driver: sourced from
# one file, never copied per driver.
[ -f "$SCRIPT_DIR/bpf-guest-release.sh" ] || { echo "release match not found: $SCRIPT_DIR/bpf-guest-release.sh" >&2; exit 2; }
. "$SCRIPT_DIR/bpf-guest-release.sh"
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
VNG_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/virtme-ng"
GUEST_ENV="$OUTDIR/guest-env.sh"
WORK_IMAGE="$OUTDIR/guest-work.img"
if [ -e "$GUEST_ENV" ] || [ -L "$GUEST_ENV" ] || [ -e "$WORK_IMAGE" ] || [ -L "$WORK_IMAGE" ]; then
    echo "# error: guest helper/work image already exists; use a fresh output directory" >&2
    exit 2
fi
# Only this invocation owns the image. Sequential fresh guests reuse it
# after checked unmount/detach; product temp I/O never inherits host /tmp/9p.
(umask 077; set -C; : > "$WORK_IMAGE"; truncate -s 536870912 "$WORK_IMAGE")
mkfs.ext4 -q -F "$WORK_IMAGE"
(
    umask 077
    set -C
    {
        printf 'BPF_VNG_CACHE=%s\nBPF_GUEST_IMAGE=%s\n' "$(q "$VNG_CACHE")" "$(q "$WORK_IMAGE")"
        cat <<'GUEST_ENV_EOF'
umask 022
BPF_GUEST_LOOP=
BPF_GUEST_MOUNTED=0
BPF_GUEST_TMP=
BPF_GUEST_TMP_OWNED=0
bpf_guest_cleanup() {
    BPF_GUEST_RC=$?
    trap - 0
    cd / || BPF_GUEST_RC=1
    if [ "$BPF_GUEST_TMP_OWNED" = 1 ]; then
        rm -rf --one-file-system -- "$BPF_GUEST_TMP" || BPF_GUEST_RC=1
    fi
    if [ "$BPF_GUEST_MOUNTED" = 1 ]; then
        umount /var/tmp || BPF_GUEST_RC=1
    fi
    if [ -n "$BPF_GUEST_LOOP" ]; then
        losetup -d "$BPF_GUEST_LOOP" || BPF_GUEST_RC=1
    fi
    exit "$BPF_GUEST_RC"
}
trap bpf_guest_cleanup 0
[ "$(id -u)" = 0 ] || return 1
K=$(uname -r)
if [ ! -r "/boot/config-$K" ]; then
    C=$(ls "$BPF_VNG_CACHE"/*/amd64/boot/config-"$K" 2>/dev/null | head -n 1)
    [ -n "$C" ] || { echo "no-kernel-config-for-$K"; return 1; }
    mount -t tmpfs -o mode=755 guestboot /boot && cp "$C" /boot/ || { echo "stage-boot-failed-$K"; return 1; }
    echo "staged-boot-config-$K"
else
    echo "boot-config-present-$K"
fi
BPF_GUEST_LOOP=$(losetup -f --show "$BPF_GUEST_IMAGE") || return 1
case "$BPF_GUEST_LOOP" in /dev/loop[0-9]*) ;; *) BPF_GUEST_LOOP=; return 1;; esac
mount -t ext4 -o nodev,nosuid "$BPF_GUEST_LOOP" /var/tmp || return 1
BPF_GUEST_MOUNTED=1
BPF_GUEST_TMP=$(mktemp -d /var/tmp/p11scope-bpf.XXXXXX) || return 1
case "$BPF_GUEST_TMP" in /var/tmp/*) ;; *) return 1;; esac
[ "$(stat -c '%u:%a' "$BPF_GUEST_TMP")" = 0:700 ] || return 1
BPF_GUEST_TMP_OWNED=1
TMPDIR=$BPF_GUEST_TMP
export TMPDIR
BPF_GUEST_READY=1
echo "guest-work-ready=ext4 uid-mode=0:700 TMPDIR=$TMPDIR"
GUEST_ENV_EOF
    } > "$GUEST_ENV"
)
# A short sourced helper fits virtme's kernel command line. Reset readiness
# before sourcing: a missing, bad or failed setup never runs the observer.
STAGE="{ BPF_GUEST_READY=0; . $(q "$GUEST_ENV") && [ x\$BPF_GUEST_READY = x1 ]; } || exit 2"
for KERNEL in "$@"; do
    echo "## kernel $KERNEL"
    PROBE_JSON="$OUTDIR/probe-$KERNEL.jsonl"
    DOCTOR_TXT="$OUTDIR/doctor-$KERNEL.txt"
    VNG_LOG="$OUTDIR/vng-$KERNEL.log"
    rm -f "$PROBE_JSON" "$DOCTOR_TXT" "$VNG_LOG"
    EXEC1="cd $(q "$OUTDIR") && $STAGE; LD_PRELOAD=$(q "$PROBE") P11SCOPE_VERIFIER_STATS_FD=9 $(q "$OBSERVER") doctor -v 9>$(q "probe-$KERNEL.jsonl") >$(q "doctor-$KERNEL.txt") 2>&1; echo doctor-rc=\$?; echo guest-release=\$(uname -r)"
    # Fail fast past the kernel command line: 950 raw bytes encode to
    # ~1270 base64 bytes, which still fits the 2048 budget beside
    # virtme's own arguments; past it the guest silently never runs.
    if [ "${#EXEC1}" -gt 950 ]; then
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
    if release_ok "$KERNEL" "$GUEST_RELEASE"; then
        echo "# guest release $GUEST_RELEASE (expected $KERNEL)"
    else
        echo "# error: guest booted $GUEST_RELEASE, expected $KERNEL"
        FAILED=1
        continue
    fi
    DOCTOR_RC=$(grep '^doctor-rc=' "$VNG_LOG" | tail -1 | cut -d= -f2)
    echo "# doctor rc=$DOCTOR_RC"
    if [ ! -f "$DOCTOR_TXT" ] || ! grep -q 'host program preflight' "$DOCTOR_TXT"; then
        echo "# error: doctor never reached host program preflight on $KERNEL"
        FAILED=1
        continue
    fi
    grep 'host program preflight' "$DOCTOR_TXT" | head -1
    # A nonzero doctor exit is FAIL on its own: gate-1 must report
    # capture available, and the report below names the refused program.
    case "$DOCTOR_RC" in
        0) ;;
        *)
            echo "# error: gate-1 doctor exited rc=$DOCTOR_RC on $KERNEL"
            FAILED=1
            ;;
    esac
    if [ -n "$BUDGETS" ]; then
        # No word splitting: the budgets path stays quoted in its own arm.
        if ! python3 -I "$REPORT" --budgets "$BUDGETS" --object detailed-gate1 --kernel "$KERNEL" \
            --observer-sha256 "$OBSERVER_SHA" "$PROBE_JSON"; then
            FAILED=1
        fi
    else
        if ! python3 -I "$REPORT" --object detailed-gate1 --kernel "$KERNEL" \
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
