#!/bin/sh
# Measure finite doctor capability tiers against the documented fixed host
# baseline (kernel.yama.ptrace_scope=1 and kernel.perf_event_paranoid=4).
set -eu
cd "$(dirname "$0")/.."

check_row() {
    python3 -I - "$@" <<'PY'
import os
import re
import sys

if len(sys.argv) != 6:
    raise SystemExit("usage: checker TIER ASSESSMENT EXPECTED_STATUS ACTUAL_STATUS OUTPUT")
expected_tier, assessment, raw_expected_status, raw_status, path = sys.argv[1:]
try:
    expected_status = int(raw_expected_status)
    status = int(raw_status)
except ValueError:
    raise SystemExit(f"{assessment}: invalid exit status")
if expected_status not in (0, 1) or status != expected_status:
    raise SystemExit(f"{assessment}: expected doctor exit {expected_status}, got {status}")
if not os.path.isfile(path):
    raise SystemExit(f"{assessment}: produced no output")
with open(path, encoding="utf-8") as source:
    lines = source.read().splitlines()
tiers = [line for line in lines if line.startswith("capability tier:")]
if len(tiers) != 1:
    raise SystemExit(f"{assessment}: expected one capability tier line, got {tiers!r}")
match = re.fullmatch(
    r"capability tier: (T[0-4]) (offline|host attach|target readable|lifecycle|current full) "
    r"\(target (assessed|unassessed)\)",
    tiers[0],
)
if not match:
    raise SystemExit(f"{assessment}: malformed finite tier line {tiers[0]!r}")
labels = {"T0": "offline", "T1": "host attach", "T2": "target readable", "T3": "lifecycle", "T4": "current full"}
if labels[match.group(1)] != match.group(2):
    raise SystemExit(f"{assessment}: tier number and label disagree")
if match.group(1) != expected_tier:
    raise SystemExit(f"{assessment}: expected {expected_tier}, got {match.group(1)}")
if match.group(3) != assessment:
    raise SystemExit(f"{assessment}: target state is {match.group(3)!r}")
print(f"{assessment}: {match.group(1)} {match.group(2)}")
PY
}

write_self_test_document() {
    path=$1
    tier=$2
    assessment=$3
    case "$tier" in
        T0) label=offline ;;
        T1) label='host attach' ;;
        T2) label='target readable' ;;
        T3) label=lifecycle ;;
        T4) label='current full' ;;
        *) echo "unknown self-test tier $tier" >&2; return 2 ;;
    esac
    printf 'capability tier: %s %s (target %s)\n' "$tier" "$label" "$assessment" >"$path"
}

self_test() {
    work=$(mktemp -d)
    self_test_cleanup() { rm -rf "$work"; }
    trap self_test_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    for tier in T0 T1 T2 T3 T4; do
        baseline="$work/$tier.txt"
        write_self_test_document "$baseline" "$tier" assessed
        check_row "$tier" assessed 0 0 "$baseline"
    done
    unassessed="$work/unassessed.txt"
    write_self_test_document "$unassessed" T1 unassessed
    check_row T1 unassessed 1 1 "$unassessed"
    reject() {
        expected=$1
        assessment=$2
        expected_status=$3
        actual_status=$4
        document=$5
        mutation=$6
        if check_row "$expected" "$assessment" "$expected_status" "$actual_status" "$document"; then
            echo "capability-tier $expected oracle accepted $mutation" >&2
            exit 1
        fi
    }
    reject T0 assessed 0 0 "$work/missing.txt" missing-document
    reject T0 assessed 0 2 "$work/T0.txt" invalid-exit-status
    for expected in T0 T1 T2 T3 T4; do
        for actual in T0 T1 T2 T3 T4; do
            [ "$actual" = "$expected" ] && continue
            document="$work/$expected-$actual.txt"
            write_self_test_document "$document" "$actual" assessed
            reject "$expected" assessed 0 0 "$document" "$actual-for-$expected"
        done
    done
    reject T1 unassessed 1 1 "$work/T1.txt" wrong-assessment
    echo "capability-tier self-test: OK"
}

[ "${1-}" != "--self-test" ] || { [ "$#" -eq 1 ] || exit 2; self_test; exit 0; }
[ "$#" -eq 0 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
command -v cargo >/dev/null || { echo "UNRUN: cargo unavailable"; exit 0; }
command -v gcc >/dev/null || { echo "UNRUN: gcc unavailable"; exit 0; }
command -v capsh >/dev/null || { echo "UNRUN: capsh unavailable"; exit 0; }
sudo -n true 2>/dev/null || { echo "UNRUN: passwordless sudo unavailable"; exit 0; }

PERF_EVENT_PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true)
[ "$PERF_EVENT_PARANOID" = 4 ] || {
    echo "UNRUN: kernel.perf_event_paranoid must be 4 (got ${PERF_EVENT_PARANOID:-unavailable})"
    exit 0
}
PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true)
[ "$PTRACE_SCOPE" = 1 ] || {
    echo "UNRUN: kernel.yama.ptrace_scope must be 1 (got ${PTRACE_SCOPE:-unavailable})"
    exit 0
}

MODULE=${P11SCOPE_PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}
[ -f "$MODULE" ] || { echo "UNRUN: SoftHSM2 unavailable at configured module path"; exit 0; }
# See verify-canaries.sh: the observer refuses an output directory with a
# group/world-writable non-sticky ancestor, which this checkout has. This lane
# has no work-path override, so the private 0700 root is its only work root.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-verify-XXXXXX")/target/capability-tier
echo "work root: $WORK"
BIN="$PWD/target/release/p11scope"
HARNESS="$WORK/harness"
TARGET_PID=
CURRENT_ROW=

record_metadata() {
    {
        printf 'head='; git rev-parse HEAD
        printf 'binary_sha256='; sha256sum "$BIN" | awk '{print $1}'
        printf 'uid_gid='; id
        printf 'capabilities='; grep '^Cap' /proc/self/status
        printf 'capsh='; capsh --print
        printf 'kernel='; uname -a
        printf 'perf_event_paranoid='; cat /proc/sys/kernel/perf_event_paranoid
        printf 'ptrace_scope='; cat /proc/sys/kernel/yama/ptrace_scope
        printf 'tracefs_mounts\n'; grep -E 'tracefs|debugfs' /proc/mounts || true
        for path in /sys/kernel/tracing /sys/kernel/debug/tracing \
            /sys/kernel/tracing/events/sched/sched_process_exec/id \
            /sys/kernel/debug/tracing/events/sched/sched_process_exec/id; do
            if stat -c 'stat %n mode=%a uid=%u gid=%g' "$path"; then :; else
                printf 'stat %s unavailable\n' "$path"
            fi
            if [ -r "$path" ]; then printf 'readable %s=yes\n' "$path"; else
                printf 'readable %s=no\n' "$path"
            fi
        done
    } >"$WORK/metadata.txt"
}
row_metadata() { printf '%s\n' "$2" >>"$WORK/$1.metadata"; }

stop_target() {
    [ -n "$TARGET_PID" ] || return 0
    target=$TARGET_PID
    if kill -TERM "$target" 2>/dev/null; then signal=sent; else signal=not-needed; fi
    set +e
    wait "$target"
    wait_status=$?
    set -e
    TARGET_PID=
    if [ "$wait_status" -eq 127 ]; then
        row_metadata "${CURRENT_ROW:-cleanup}" "cleanup signal=$signal wait_status=$wait_status quiescent=no"
        return 1
    fi
    row_metadata "${CURRENT_ROW:-cleanup}" "cleanup signal=$signal wait_status=$wait_status quiescent=yes"
}
cleanup() {
    if ! stop_target; then
        echo "capability-tier cleanup could not quiesce target" >&2
        return 1
    fi
}
on_exit() {
    status=$?
    trap - EXIT
    if ! cleanup && [ "$status" -eq 0 ]; then status=1; fi
    exit "$status"
}
on_signal() { status=$1; trap - EXIT INT TERM; cleanup || :; exit "$status"; }
trap on_exit EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

cargo +1.88 build --locked --release --workspace
(umask 077; mkdir -p "$WORK")
record_metadata
gcc -O2 -o "$HARNESS" spike/harness.c -ldl

wait_for_mapping() {
    tries=0
    while [ "$tries" -lt 100 ]; do
        grep -Fq libsofthsm2.so "/proc/$TARGET_PID/maps" 2>/dev/null && return 0
        kill -0 "$TARGET_PID" 2>/dev/null || return 1
        tries=$((tries + 1))
        sleep 0.05
    done
    return 1
}
start_target() {
    rm -f "$WORK/go"
    "$HARNESS" "$MODULE" "$WORK/go" >"$WORK/harness.log" 2>&1 &
    TARGET_PID=$!
    row_metadata "$CURRENT_ROW" "target_pid=$TARGET_PID"
    if wait_for_mapping; then
        row_metadata "$CURRENT_ROW" "target_mapping=observed"
    else
        row_metadata "$CURRENT_ROW" "target_mapping=not-observed"
        stop_target || true
        return 1
    fi
}
run_row() {
    label=$1
    caps=$2
    ambient=$3
    CURRENT_ROW=$label
    out="$WORK/$label.doctor"
    stderr="$WORK/$label.stderr"
    meta="$WORK/$label.metadata"
    rm -f "$out" "$stderr" "$meta"
    start_target || return 1
    set +e
    sudo capsh --caps="$caps" --keep=1 --user="$(id -un)" $ambient -- \
        -c "{
            printf 'uid_gid='; id
            printf 'capabilities='; grep '^Cap' /proc/self/status
            printf 'capsh='; capsh --print
            printf 'command=%s\\n' '$BIN doctor --pid $TARGET_PID'
        } >> '$meta'
        exec '$BIN' doctor --pid '$TARGET_PID'" >"$out" 2>"$stderr"
    status=$?
    set -e
    row_metadata "$label" "exit_status=$status"
    row_metadata "$label" "stderr=$stderr"
    if [ -f "$stderr" ]; then
        printf 'stderr_sha256=' >>"$meta"
        sha256sum "$stderr" | awk '{print $1}' >>"$meta"
    fi
    if ! stop_target; then
        row_metadata "$label" "row_status=cleanup-failed"
        return 125
    fi
    return "$status"
}

SYSADMIN_CAPS='cap_sys_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep'
SYSADMIN_AMBIENT='--addamb=cap_sys_admin'
BPF_PERFMON_CAPS='cap_bpf,cap_perfmon+eip cap_setpcap,cap_setuid,cap_setgid+ep'
BPF_PERFMON_AMBIENT='--addamb=cap_bpf --addamb=cap_perfmon'

if run_row sysadmin "$SYSADMIN_CAPS" "$SYSADMIN_AMBIENT"; then SYSADMIN_RC=0; else SYSADMIN_RC=$?; fi
check_row T1 assessed 1 "$SYSADMIN_RC" "$WORK/sysadmin.doctor"
row_metadata sysadmin "row_status=oracle-accepted"
if run_row bpf-perfmon "$BPF_PERFMON_CAPS" "$BPF_PERFMON_AMBIENT"; then BPF_PERFMON_RC=0; else BPF_PERFMON_RC=$?; fi
check_row T0 assessed 1 "$BPF_PERFMON_RC" "$WORK/bpf-perfmon.doctor"
row_metadata bpf-perfmon "row_status=oracle-accepted"
echo "capability-tier: finite assessed doctor rows"
