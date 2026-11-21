#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Load the journal object in throwaway vng guests and score its verifier cost.
#
# Usage: check-bpf-load-journal.sh [--budgets FILE] [--object journal|journal-gate1]
#        [--expect-journal 0|1] OBSERVER PROBE MANIFEST OUTDIR [KERNEL...]
#
# OBSERVER is the prebuilt observer under test (a build with the journal
# object; it must live on the vng shared filesystem, never under /var/tmp
# which the shared fs hides), PROBE the verifier-stats probe built by
# `measure-verifier-headroom.py build`, MANIFEST a p11scope-discover manifest
# for the guest-visible SoftHSM provider, OUTDIR an existing empty directory
# under /home/user/.cache/p11scope-vng/<tag>/ shared with the guests.
# Default kernels: v6.6.157 v6.12.111 v6.18.58 v7.0.14.
# --budgets defaults to the checked-in tests/bpf-verifier-budgets.json when
# that file exists. The journal rows are scored against it only when it
# carries journal/ keys for the kernel; otherwise the gate is loaded +
# stats + 5% headroom and the row says unbudgeted. A corrupt or
# unreadable budgets file is a harness error (exit 2), never a silent
# unbudgeted pass. --object journal-gate1 scores a gate-1 observer's
# journal object (P11SCOPE_LOADER_GATE=1 gates every Detailed flavor,
# the journal object included) against journal-gate1/ keys instead;
# the object's BTF groups are the same, only the key prefix differs.
# --expect-journal defaults to 1 (each load kernel is a load proof);
# 0 turns each load kernel into an exact-refusal control for a build
# that omits the journal object (a SMALL build): the same command
# must refuse with journal-pair-unavailable-in-build, run its ordinary
# retry to rc 0, load no journal roots and crash nothing. A load, a
# different outcome or a crash is FAIL, never a skip. Pre-Multi kernels
# keep the refusal control below either way.
#
# Per kernel one throwaway guest runs a bounded linked inventory,
# `inventory -v --system --capture native --key-operations --manifest
# MANIFEST --duration 60s`, under the probe. Before the observer starts,
# the guest initializes a guest-local SoftHSM token and starts one
# persistent ledger caller (eighty mech iterations a second apart,
# then held) against the guest SoftHSM module, so the linked lane
# seals on
# an attested provider and observes a full call stream from an admitted
# caller. The caller, token and logs live on guest-local storage (the
# work image); only the finished probe rows, observer text and ledger
# log are copied back to OUTDIR.
#
# A load kernel passes only when the probe rows carry both journal roots
# loaded with verifier stats, the per-program report passes, and the
# observer text proves the linked lane sealed and live: the `semantic
# lane ready` line, no `p11scope: key operations unavailable` refusal
# diagnostic (the refused-linked arm prints exactly that before its
# ordinary retry; verbose per-process gap detail also names the
# condition, so the bare phrase is not matched), and joined semantic
# calls from an admitted binding. Zero journal
# rows, a refused journal start, an idle lane, a timeout, a crash or a
# missing count is FAIL. The finite refusal reasons
# (`journal-pair-unavailable-in-build` on a build that omits the
# object, the `live capture ...` refusal on pre-Multi kernels) are named in
# the row detail, never mistaken for a pass. The key-operations display
# latch does not complete in production runs at this base, so the
# display state is recorded in the row, never gated.
#
# --key-sizes 1 (v0.8.0 keymeta Task 2) additionally loads and scores
# the length pair (p11_entry_journal_length/p11_return_journal_length):
# the guest run passes --key-sizes and the pair check requires all four
# roots. The budgets file must carry the journal-gate1 length cells
# (recorded via scripts/record-verifier-budgets.py), or the report fails
# on the observed-but-unbudgeted roots.
#
# Pre-Multi kernels (v5.15.*, v6.1.*) are a refusal control, not a
# load: the finite live-capture refusal with no loaded
# journal row is a pass for that cell; a load or a crash is FAIL.
#
# Every verdict comes from scripts/journal-load-verdict.py, which holds
# one strict record grammar per input (guest status records, probe
# stream, observer proof lines). The probe stream is parsed by the
# verifier report's own parser, so no gate counts a row the report
# rejects; a missing, malformed, repeated, reordered or contradictory
# record refuses with a named reason.
#
# Writes OUTDIR/results.jsonl, one row per kernel:
# {"cell": "journal-load-<kernel>", "pass": bool,
#  "qualification": "qualified"|"failed"|"nonqualifying", "detail": str}.
# Exit 0 only when every row passes; 1 when a cell failed or could not
# run; 2 on harness misuse; 77 when a prerequisite is missing.
#
# Apt prerequisites on the host (a vng guest runs the host userspace,
# so the guest needs the same): gcc, softhsm2, libsofthsm2, python3,
# and virtme-ng (`pipx install virtme-ng`) with a kernel cache holding
# the requested kernels. Expected time is about three minutes per
# kernel, mostly one guest boot plus the 60 s linked run.
set -eu

BUDGETS=""
OBJECT=journal
EXPECT_JOURNAL=1
KEY_SIZES=0
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
        --object)
            [ $# -ge 2 ] || { echo "missing value for --object" >&2; exit 2; }
            OBJECT="$2"
            shift 2
            ;;
        --object=*)
            OBJECT="${1#--object=}"
            shift
            ;;
        --expect-journal)
            [ $# -ge 2 ] || { echo "missing value for --expect-journal" >&2; exit 2; }
            EXPECT_JOURNAL="$2"
            shift 2
            ;;
        --expect-journal=*)
            EXPECT_JOURNAL="${1#--expect-journal=}"
            shift
            ;;
        --key-sizes)
            [ $# -ge 2 ] || { echo "missing value for --key-sizes" >&2; exit 2; }
            KEY_SIZES="$2"
            shift 2
            ;;
        --key-sizes=*)
            KEY_SIZES="${1#--key-sizes=}"
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "check-bpf-load-journal.sh: unknown option $1" >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done
if [ $# -lt 4 ]; then
    echo "usage: check-bpf-load-journal.sh [--budgets FILE] [--object journal|journal-gate1] [--expect-journal 0|1] [--key-sizes 0|1] OBSERVER PROBE MANIFEST OUTDIR [KERNEL...]" >&2
    exit 2
fi
case "$KEY_SIZES" in
    0|1) ;;
    *) echo "check-bpf-load-journal.sh: --key-sizes needs 0 or 1" >&2; exit 2 ;;
esac
case "$OBJECT" in
    journal|journal-gate1) ;;
    *) echo "check-bpf-load-journal.sh: unknown object $OBJECT" >&2; exit 2 ;;
esac
case "$EXPECT_JOURNAL" in
    0|1) ;;
    *) echo "check-bpf-load-journal.sh: --expect-journal must be 0 or 1" >&2; exit 2 ;;
esac
OBSERVER=$1
PROBE=$2
MANIFEST=$3
OUTDIR=$4
shift 4
if [ $# -eq 0 ]; then
    set -- v6.6.157 v6.12.111 v6.18.58 v7.0.14
fi
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPORT="$SCRIPT_DIR/bpf-load-report.py"
VERDICT="$SCRIPT_DIR/journal-load-verdict.py"
SELECTOR="$SCRIPT_DIR/release-matrix-contract.py"
WORKLOAD_SRC="$SCRIPT_DIR/../tests/fixtures/public-cli/inventory-ledger.c"
if [ -z "$BUDGETS" ] && [ -f "$SCRIPT_DIR/../tests/bpf-verifier-budgets.json" ]; then
    BUDGETS="$SCRIPT_DIR/../tests/bpf-verifier-budgets.json"
fi

[ -f "$OBSERVER" ] || { echo "observer not found: $OBSERVER" >&2; exit 2; }
[ -f "$PROBE" ] || { echo "probe not found: $PROBE" >&2; exit 2; }
[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }
[ -d "$OUTDIR" ] || { echo "output dir not found: $OUTDIR" >&2; exit 2; }
[ -f "$REPORT" ] || { echo "report script not found: $REPORT" >&2; exit 2; }
[ -f "$VERDICT" ] || { echo "verdict helper not found: $VERDICT" >&2; exit 2; }
[ -f "$WORKLOAD_SRC" ] || { echo "workload source not found: $WORKLOAD_SRC" >&2; exit 2; }
# Guest release match, shared with the kernels driver: sourced from
# one file, never copied per driver.
[ -f "$SCRIPT_DIR/bpf-guest-release.sh" ] || { echo "release match not found: $SCRIPT_DIR/bpf-guest-release.sh" >&2; exit 2; }
. "$SCRIPT_DIR/bpf-guest-release.sh"
if [ -n "$BUDGETS" ] && [ ! -f "$BUDGETS" ]; then
    echo "budgets not found: $BUDGETS" >&2
    exit 2
fi
case "$OBSERVER" in
    /*) ;;
    *) echo "observer must be an absolute guest-visible path: $OBSERVER" >&2; exit 2 ;;
esac
case "$OBSERVER" in
    /var/tmp/*) echo "observer under /var/tmp is hidden from vng guests: $OBSERVER" >&2; exit 2 ;;
esac
case "$OUTDIR" in
    /*) ;;
    *) echo "output dir must be absolute: $OUTDIR" >&2; exit 2 ;;
esac
case "$OUTDIR" in
    /var/tmp/*) echo "output dir under /var/tmp is hidden from vng guests: $OUTDIR" >&2; exit 2 ;;
esac
command -v vng >/dev/null || { echo "vng not on PATH" >&2; exit 77; }
command -v cc >/dev/null || { echo "cc not on PATH" >&2; exit 77; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util not on PATH" >&2; exit 77; }
MODULE=""
if ! MODULE=$(python3 -I "$SELECTOR" --select-module 2>/dev/null); then
    echo "no SoftHSM provider module found" >&2
    exit 77
fi
[ -f "$MODULE" ] || { echo "provider module not found: $MODULE" >&2; exit 77; }
if [ -n "$BUDGETS" ]; then
    # A corrupt or unreadable budgets file is a harness error, never
    # a silent unbudgeted pass: require the same shape the report
    # requires before any guest runs. This sits past the
    # prerequisite checks so a missing tool still reports 77 first.
    if ! BUDGETS_ERROR=$(python3 -I "$VERDICT" budgets "$BUDGETS" 2>&1); then
        echo "budgets invalid: $BUDGETS: $BUDGETS_ERROR" >&2
        exit 2
    fi
fi

OBSERVER_SHA=$(sha256sum "$OBSERVER" | cut -d' ' -f1)
echo "# observer: $OBSERVER"
echo "# observer-sha256: $OBSERVER_SHA"
echo "# object: $OBJECT"
echo "# probe: $PROBE"
echo "# manifest: $MANIFEST"
echo "# module: $MODULE"
if [ -n "$BUDGETS" ]; then
    echo "# budgets: $BUDGETS"
else
    echo "# budgets: none (gate is loaded + stats + 5% headroom)"
fi

# Single-quote a path for the guest shell.
q() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# One results.jsonl row. $1=cell $2=pass(1/0) $3=qualification $4=detail.
emit_row() {
    python3 -I "$VERDICT" row "$1" "$2" "$3" "$4" >>"$OUTDIR/results.jsonl"
}

FAILED=0
VNG_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/virtme-ng"
GUEST_ENV="$OUTDIR/guest-env.sh"
WORK_IMAGE="$OUTDIR/guest-work.img"
GUEST_LEG="$OUTDIR/journal-guest.sh"
STAGED_PROBE="$OUTDIR/journal-probe.so"
STAGED_MANIFEST="$OUTDIR/journal-manifest.json"
STAGED_WORKLOAD="$OUTDIR/j-workload"
if [ -e "$GUEST_ENV" ] || [ -L "$GUEST_ENV" ] || [ -e "$WORK_IMAGE" ] || [ -L "$WORK_IMAGE" ] \
    || [ -e "$GUEST_LEG" ] || [ -L "$GUEST_LEG" ] || [ -e "$OUTDIR/results.jsonl" ]; then
    echo "# error: guest helper/work image/results already exist; use a fresh output directory" >&2
    exit 2
fi
# The probe and manifest are staged into OUTDIR so any host path works:
# the guest sees them through the shared dir even when the caller keeps
# the originals somewhere the shared fs hides. The observer runs from
# its own path (checked guest-visible above), like the kernels driver.
cp "$PROBE" "$STAGED_PROBE"
cp "$MANIFEST" "$STAGED_MANIFEST"
chmod 644 "$STAGED_PROBE" "$STAGED_MANIFEST"
if ! cc -O1 -Wall -Wextra -Werror -o "$STAGED_WORKLOAD" "$WORKLOAD_SRC" -ldl -lpthread; then
    echo "# error: cannot compile the guest workload" >&2
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
# One journal leg inside the guest: a guest-local token, a background
# loop of short PKCS#11 info workloads, then the bounded linked
# inventory under the probe. All guest-local I/O stays on the work
# image; only finished artifacts are copied back to OUTDIR.
(umask 022; set -C; cat <<'GUEST_LEG_EOF' > "$GUEST_LEG")
#!/bin/sh
# One journal-load guest leg, invoked after STAGE sets TMPDIR.
set -eu
KERNEL=$1
OBSERVER=$2
PROBE=$3
MANIFEST=$4
WORKLOAD=$5
MODULE=$6
KEY_SIZES=${7:-0}
TOKENS=$TMPDIR/journal-tokens
CONF=$TMPDIR/softhsm2.conf
mkdir -p "$TOKENS"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$TOKENS" > "$CONF"
if SOFTHSM2_CONF="$CONF" softhsm2-util --init-token --free --label "journal-$KERNEL" --so-pin 5678 --pin 1234 >/dev/null 2>&1; then
    echo "guest-stage=token-ok"
else
    echo "guest-stage=token-failed"
    exit 3
fi
# One persistent caller with spread key-operation iterations: it maps
# the provider once, sets up a session, prints READY, then paces eighty
# mech iterations a second apart and holds until killed. Short-lived
# burst callers exit before admission and shed every call as
# use-before-admission, so the leg waits for READY before the observer
# starts and the caller outlives the whole run.
LEDGER_LOG=$TMPDIR/ledger-$KERNEL.log
# Eighty paced iterations (~85 s of calls) cover even very slow guest
# startups: a 6.18 leg admitted its caller only after a 45 s window
# closed and collected nothing. The ledger is killed when the observer
# exits whether or not its iterations finished.
SOFTHSM2_CONF="$CONF" "$WORKLOAD" mech --cell jwork --module "$MODULE" --iters 80 --sleep-us 1000000 --rsa-sign --hold >>"$LEDGER_LOG" 2>&1 &
LEDGER_PID=$!
cleanup_ledger() {
    kill "$LEDGER_PID" 2>/dev/null || true
    N=0
    while [ "$N" -lt 10 ] && kill -0 "$LEDGER_PID" 2>/dev/null; do
        sleep 1
        N=$((N + 1))
    done
    kill -9 "$LEDGER_PID" 2>/dev/null || true
    wait "$LEDGER_PID" 2>/dev/null || true
}
trap cleanup_ledger EXIT INT TERM
N=0
while [ "$N" -lt 30 ]; do
    if grep -q '^READY ' "$LEDGER_LOG" 2>/dev/null; then
        break
    fi
    sleep 1
    N=$((N + 1))
done
if grep -q '^READY ' "$LEDGER_LOG" 2>/dev/null; then
    echo "guest-stage=workload-ready"
else
    echo "guest-stage=workload-not-ready"
    exit 3
fi
ulimit -n 65536
RC=0
if [ "$KEY_SIZES" = "1" ]; then set -- --key-sizes; else set --; fi
timeout -k 10 -s INT 150 env LD_PRELOAD="$PROBE" P11SCOPE_VERIFIER_STATS_FD=9 "$OBSERVER" inventory -v --system --capture native --key-operations "$@" --manifest "$MANIFEST" --duration 60s 9>"journal-probe-$KERNEL.jsonl" >"journal-$KERNEL.txt" 2>&1 || RC=$?
echo "guest-stage=observer-rc=$RC"
if [ -f "$LEDGER_LOG" ]; then
    cp "$LEDGER_LOG" "./workload-$KERNEL.log"
fi
trap - EXIT INT TERM
cleanup_ledger
exit "$RC"
GUEST_LEG_EOF
chmod 755 "$GUEST_LEG"
: > "$OUTDIR/results.jsonl"
# A short sourced helper fits virtme's kernel command line. Reset readiness
# before sourcing: a missing, bad or failed setup never runs the observer.
STAGE="{ BPF_GUEST_READY=0; . $(q "$GUEST_ENV") && [ x\$BPF_GUEST_READY = x1 ]; } || exit 2"

# $1=detail: a kernel whose gate could not run (guest, staging or
# command-line failure, never a product verdict).
infra_fail() {
    echo "# error: $1 (see $VNG_LOG)"
    emit_row "journal-load-$KERNEL" 0 nonqualifying "$1"
    FAILED=1
}

for KERNEL in "$@"; do
    echo "## kernel $KERNEL"
    case "$KERNEL" in
        v5.15.*|v6.1.*) CONTROL=1 ;;
        *) CONTROL=0 ;;
    esac
    J_TXT="$OUTDIR/journal-$KERNEL.txt"
    J_PROBE="$OUTDIR/journal-probe-$KERNEL.jsonl"
    J_WL="$OUTDIR/workload-$KERNEL.log"
    J_REPORT="$OUTDIR/journal-report-$KERNEL.txt"
    VNG_LOG="$OUTDIR/vng-journal-$KERNEL.log"
    rm -f "$J_TXT" "$J_PROBE" "$J_WL" "$J_REPORT" "$VNG_LOG"
    EXEC="cd $(q "$OUTDIR") && $STAGE; sh ./journal-guest.sh $(q "$KERNEL") $(q "$OBSERVER") $(q "$STAGED_PROBE") $(q "$STAGED_MANIFEST") $(q "$STAGED_WORKLOAD") $(q "$MODULE") $(q "$KEY_SIZES"); echo journal-rc=\$?; echo guest-release=\$(uname -r)"
    # Fail fast past the kernel command line: 950 raw bytes encode to
    # ~1270 base64 bytes, which still fits the 2048 budget beside
    # virtme's own arguments; past it the guest silently never runs.
    if [ "${#EXEC}" -gt 950 ]; then
        infra_fail "guest command exceeds the kernel-cmdline budget"
        continue
    fi
    if ! timeout -k 30 300 vng --run "$KERNEL" --user root --cpus 4 --memory 4G \
        --rwdir "$OUTDIR" --exec "$EXEC" < /dev/null >"$VNG_LOG" 2>&1; then
        infra_fail "vng run failed or timed out"
        continue
    fi
    # Every verdict below comes from scripts/journal-load-verdict.py,
    # which owns one strict record grammar per input: the guest status
    # records here, then the probe stream (the verifier report's own
    # parser) and the observer proof lines. A missing, corrupt,
    # repeated, reordered or contradictory record refuses with a named
    # reason, never falls back to an older well-shaped line.
    GUEST_OUT=""
    if ! GUEST_OUT=$(python3 -I "$VERDICT" guest --kernel "$KERNEL" "$VNG_LOG"); then
        infra_fail "guest status unreadable (verdict helper failed)"
        continue
    fi
    # The boot-config staging line is printed but not gated: vng's
    # console capture demonstrably garbles it (a bare `-generic` tail
    # was observed on 6.6/6.12) while the leg runs fine. The
    # guest-work-ready record is the stronger gate: guest-env.sh prints
    # it strictly after successful boot staging, loop mount and tmp
    # checks, and every staging failure returns before it.
    grep -aE '^(staged-boot-config|boot-config-present)-' "$VNG_LOG" | tail -1
    TAB=$(printf '\t')
    case "$GUEST_OUT" in
        "ok$TAB"*) ;;
        "infra$TAB"*)
            infra_fail "${GUEST_OUT#infra"$TAB"}"
            continue
            ;;
        *)
            infra_fail "guest status unreadable (verdict helper output)"
            continue
            ;;
    esac
    GUEST_REST=${GUEST_OUT#ok"$TAB"}
    J_RC=${GUEST_REST%%"$TAB"*}
    GUEST_RELEASE=${GUEST_REST#*"$TAB"}
    if release_ok "$KERNEL" "$GUEST_RELEASE"; then
        echo "# guest release $GUEST_RELEASE (expected $KERNEL)"
    else
        infra_fail "guest booted $GUEST_RELEASE, expected $KERNEL"
        continue
    fi
    echo "# journal rc=$J_RC"
    # Refusal controls: pre-Multi kernels refuse live capture (finite
    # refusal, rc 1, no journal loads); --expect-journal 0 builds
    # refuse with journal-pair-unavailable-in-build and retry to rc 0.
    # Load kernels: both journal roots (and the length pair under
    # --key-sizes) loaded within the object's BTF groups, the
    # per-program report passes, and the observer text proves the
    # linked lane sealed and live.
    if [ "$CONTROL" = 1 ]; then
        MODE=control
    elif [ "$EXPECT_JOURNAL" = 0 ]; then
        MODE=omitted
    else
        MODE=load
    fi
    VERDICT_RC=0
    python3 -I "$VERDICT" verdict --mode "$MODE" --kernel "$KERNEL" \
        --object "$OBJECT" --key-sizes "$KEY_SIZES" --rc "$J_RC" \
        --text "$J_TXT" --probe "$J_PROBE" --workload "$J_WL" \
        --budgets "$BUDGETS" \
        --observer-sha256 "$OBSERVER_SHA" --report-out "$J_REPORT" \
        --results "$OUTDIR/results.jsonl" || VERDICT_RC=$?
    case "$VERDICT_RC" in
        0) ;;
        10) FAILED=1 ;;
        *) infra_fail "verdict helper failed (rc=$VERDICT_RC)" ;;
    esac
done

if [ "$FAILED" -ne 0 ]; then
    echo "# OVERALL: FAIL"
    exit 1
fi
echo "# OVERALL: PASS"
