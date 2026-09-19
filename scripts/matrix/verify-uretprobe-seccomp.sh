#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Does attaching a uretprobe kill a seccomp-hardened target on THIS kernel?
#
# Linux 6.11 made a returning uretprobe issue __NR_uretprobe (x86-64 nr 335)
# from inside the target. Until the seccomp passthrough fix, a filter that did
# not allow 335 killed the target the first time one of p11scope's five
# uretprobes fired -- and delivered zero events, so the observer destroyed
# what it observed and learned nothing.
#
# The affected set is NOT a version range. Measured 2026-09-05: Ubuntu
# 6.11.0-17 is affected and 6.11.0-29 is clean -- same upstream minor, same
# distro, same series. Only probing answers the question, which is why this
# cell exists and why `uname` must never be used for it.
#
# Exit 0 = the cell reached a trustworthy verdict (printed as RESULT:).
# Exit 1 = the cell could not trust itself; the verdict is unknown.
set -eu
cd "$(dirname "$0")/../.."
. scripts/lib.sh
require_non_root_caller

WORK=target/matrix-uretprobe
BIN=$WORK/harness
SRC=scripts/matrix/uretprobe-seccomp-harness.c

SELF_TEST_ONLY=0
[ "${1-}" = --self-test ] && SELF_TEST_ONLY=1

# The self-test needs only a compiler: it proves the harness can still detect a
# kill, which is the part that rots silently. The probe prerequisites are
# checked after it, so the oracle runs on a plain hosted runner.
command -v cc >/dev/null || { echo "SKIP: no cc to build the harness"; exit 0; }
case "$(uname -m)" in
    x86_64) ;;
    *) echo "SKIP: harness pins AUDIT_ARCH_X86_64 and nr 335"; exit 0 ;;
esac

mkdir -p "$WORK"
cc -O1 -static -o "$BIN" "$SRC"
BINPATH=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

# Run the harness, optionally under a probe, and report "<status> <hits>".
# status is the shell convention: 128+N when a signal ended it.
run_case() {
    probe=$1; action=$2; control=${3:-}
    out=$(mktemp); bt=$(mktemp)
    "$BINPATH" "$action" $control >"$out" 2>&1 &
    pid=$!
    i=0; while [ $i -lt 200 ]; do
        grep -q 'ARMED\|ARM-FAILED' "$out" && break
        i=$((i + 1)); sleep 0.05
    done
    grep -q '^ARMED$' "$out" || { echo "arm-failed 0 0"; rm -f "$out" "$bt"; return; }

    btpid=
    if [ "$probe" != none ]; then
        sudo bpftrace -e "${probe}:${BINPATH}:probe_me { @hits = count(); }
            tracepoint:raw_syscalls:sys_enter
              /comm == \"harness\" && args->id == 335/ { @sys335 = count(); }" \
            -p "$pid" >"$bt" 2>&1 &
        btpid=$!
        i=0; while [ $i -lt 200 ]; do
            grep -q 'Attaching' "$bt" && break
            i=$((i + 1)); sleep 0.05
        done
        sleep 2   # let several probe_me calls return under the probe
    fi

    kill -TERM "$pid" 2>/dev/null || true
    st=0; wait "$pid" || st=$?
    if [ -n "$btpid" ]; then kill -TERM "$btpid" 2>/dev/null || true; wait "$btpid" 2>/dev/null || true; fi

    hits=$(sed -n 's/^@hits: \([0-9]*\)$/\1/p' "$bt"); hits=${hits:-0}
    s335=$(sed -n 's/^@sys335: \([0-9]*\)$/\1/p' "$bt"); s335=${s335:-0}
    rm -f "$out" "$bt"
    echo "$st $hits $s335"
}

describe() {
    case "$1" in
        143) echo "survived (ended by our SIGTERM)" ;;
        159) echo "KILLED by SIGSYS" ;;
        139) echo "KILLED by SIGSEGV" ;;
        0)   echo "survived (loop completed)" ;;
        *)   echo "ended with status $1" ;;
    esac
}

# --- Control: the filter must bite, or nothing below means anything. ------
set -- $(run_case none kill control)
if [ "$1" != 159 ]; then
    echo "RESULT: UNKNOWN -- seccomp control did not kill: $(describe "$1")"
    echo "The harness cannot detect a kill, so a clean verdict would be vacuous."
    exit 1
fi
echo "control: blocked syscall kills the target with SIGSYS -- filter is live"

if [ "$SELF_TEST_ONLY" = 1 ]; then
    echo "verify-uretprobe-seccomp self-test: OK"; exit 0
fi

command -v bpftrace >/dev/null || { echo "SKIP: bpftrace required to attach"; exit 0; }
sudo -n true 2>/dev/null || { echo "SKIP: passwordless sudo required to attach"; exit 0; }

# --- Entry-only uprobe: the documented fallback must be safe here. --------
set -- $(run_case uprobe kill)
entry_status=$1; entry_hits=$2
if [ "$entry_status" = 159 ] || [ "$entry_status" = 139 ]; then
    echo "RESULT: UNKNOWN -- entry-only uprobe killed the target: $(describe "$entry_status")"
    echo "Entry probes do not use the trampoline; this is a different defect."
    exit 1
fi
[ "$entry_hits" -gt 0 ] || { echo "RESULT: UNKNOWN -- entry uprobe recorded no hits"; exit 1; }
echo "entry-only uprobe: $(describe "$entry_status"), $entry_hits hits -- fallback is safe"

# --- The question. -------------------------------------------------------
set -- $(run_case uretprobe kill)
ret_status=$1; ret_hits=$2; ret_s335=$3

echo "uretprobe:         $(describe "$ret_status"), $ret_hits hits, $ret_s335 uretprobe syscalls seen"
echo "kernel:            $(uname -r)"
case "$ret_status" in
    159|139)
        echo "RESULT: AFFECTED -- attaching a uretprobe kills a seccomp-filtered target"
        echo "p11scope must not attach uretprobes to a filtered target on this kernel."
        ;;
    *)
        if [ "$ret_hits" -gt 0 ]; then
            echo "RESULT: CLEAN -- uretprobes fired and the filtered target survived"
        else
            echo "RESULT: UNKNOWN -- target survived but no uretprobe ever fired"
            exit 1
        fi
        ;;
esac
