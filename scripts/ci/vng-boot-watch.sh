#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# vng-boot-watch.sh --marker FILE --console FILE --diag FILE -- COMMAND...
#
# Run COMMAND (a vng guest invocation, usually under `timeout`) with a
# boot watchdog. virtme-ng 1.41 script mode sends the whole boot console
# to /dev/null with quiet loglevel=0 and offers no --show-boot-console
# through the `vng` wrapper, so a guest that stalls before its script
# prints is silent: CI saw qemu reaped by the 1200s timeout with 0 guest
# bytes and no evidence. If neither CONSOLE nor the MARKER file (the
# first file the guest script writes through the 9p rwdir, e.g.
# uname.txt) shows guest progress within VNG_BOOT_TIMEOUT_S (default
# 300; a healthy CI boot prints in ~4s), kill the whole process group,
# write a diagnostics bundle to DIAG, report VNG_BOOT_TIMEOUT on stderr
# and exit 2. Either signal cancels the trip: a progressing guest is
# never killed, and a child that exits on its own (fast vng failure,
# timeout budget) passes its exit code through untouched.
#
# Before starting, prove host KVM can create a VM (open VNG_KVM_NODE,
# default /dev/kvm, KVM_GET_API_VERSION, KVM_CREATE_VM): without that
# qemu's accel=kvm:tcg falls back to silent TCG. Failure is
# VNG_KVM_UNUSABLE on stderr plus DIAG, exit 2, without starting vng.
# VNG_BOOT_WATCH_TEST=1 skips the probe for stubbed-vng unit tests.
#
# Exit codes: COMMAND's exit code on a completed run; 2 on a boot trip,
# a KVM failure or bad usage; 77 when python3 is missing for the probe.
set -u

MARKER=""
CONSOLE=""
DIAG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --marker) [ $# -ge 2 ] || { echo "vng-boot-watch.sh: --marker needs a value" >&2; exit 2; }; MARKER=$2; shift 2;;
        --console) [ $# -ge 2 ] || { echo "vng-boot-watch.sh: --console needs a value" >&2; exit 2; }; CONSOLE=$2; shift 2;;
        --diag) [ $# -ge 2 ] || { echo "vng-boot-watch.sh: --diag needs a value" >&2; exit 2; }; DIAG=$2; shift 2;;
        --) shift; break;;
        *) echo "vng-boot-watch.sh: bad argument: $1" >&2; exit 2;;
    esac
done
if [ -z "$MARKER" ] || [ -z "$CONSOLE" ] || [ -z "$DIAG" ] || [ $# -eq 0 ]; then
    echo "usage: vng-boot-watch.sh --marker FILE --console FILE --diag FILE -- COMMAND..." >&2
    exit 2
fi
BOOT_TIMEOUT="${VNG_BOOT_TIMEOUT_S:-300}"
case "$BOOT_TIMEOUT" in ''|*[!0-9]*)
    echo "vng-boot-watch.sh: VNG_BOOT_TIMEOUT_S must be a non-negative integer: '${VNG_BOOT_TIMEOUT_S:-}'" >&2
    exit 2;;
esac
KVM_NODE="${VNG_KVM_NODE:-/dev/kvm}"

: >"$DIAG" || { echo "vng-boot-watch.sh: cannot write diag file: $DIAG" >&2; exit 2; }
{
    echo "vng_boot_watch=1"
    echo "start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "boot_timeout_s=$BOOT_TIMEOUT"
    echo "marker=$MARKER"
    echo "console=$CONSOLE"
    echo "child_cmd=$*"
    if command -v vng >/dev/null; then
        echo "vng_version=$(vng --version 2>/dev/null || echo unknown)"
    else
        echo "vng_version=(not on PATH)"
    fi
    if command -v qemu-system-x86_64 >/dev/null; then
        echo "qemu_version=$(qemu-system-x86_64 --version 2>/dev/null | head -n 1 || echo unknown)"
    else
        echo "qemu_version=(not on PATH)"
    fi
    echo "host_kernel=$(uname -r 2>/dev/null || echo unknown)"
    if command -v nproc >/dev/null; then
        echo "nproc=$(nproc 2>/dev/null || echo unknown)"
    fi
    echo "loadavg=$(cat /proc/loadavg 2>/dev/null || echo unknown)"
    if command -v free >/dev/null; then
        echo "mem=$(free -m 2>/dev/null | awk 'NR==2{print "total="$2"MB avail="$7"MB"}')"
    fi
} >>"$DIAG"

# Prove KVM can create a VM. Prints the kvm_probe transcript line on
# stdout; returns 0 when usable. Every failure mode is named: a missing
# node, a denied open, a wrong API version, a refused CREATE_VM and a
# wedged ioctl (the 30s timeout) each fail here instead of hanging vng.
kvm_probe() {
    if [ "${VNG_BOOT_WATCH_TEST:-0}" = 1 ]; then
        echo "kvm_probe=skipped(test)"
        return 0
    fi
    command -v python3 >/dev/null || { echo "kvm_probe=fail reason=python3-missing"; return 1; }
    [ -c "$KVM_NODE" ] || { echo "kvm_probe=fail reason=node-missing-or-not-char dev=$KVM_NODE"; return 1; }
    # A -c string, not a heredoc: bash warns on heredocs inside $(...).
    probe_out=$(timeout 30 python3 -I -c '
import fcntl
import os
import sys
node = sys.argv[1]
KVM_GET_API_VERSION = 0xAE00
KVM_CREATE_VM = 0xAE01
try:
    fd = os.open(node, os.O_RDWR)
except OSError as exc:
    print(f"kvm_probe=fail reason=open:{exc.strerror or exc}")
    sys.exit(1)
try:
    api = fcntl.ioctl(fd, KVM_GET_API_VERSION, 0)
except OSError as exc:
    print(f"kvm_probe=fail reason=api:{exc.strerror or exc}")
    sys.exit(1)
if api != 12:
    print(f"kvm_probe=fail reason=api-version:{api}")
    sys.exit(1)
try:
    vm = fcntl.ioctl(fd, KVM_CREATE_VM, 0)
except OSError as exc:
    print(f"kvm_probe=fail reason=create-vm:{exc.strerror or exc}")
    sys.exit(1)
os.close(vm)
os.close(fd)
print("kvm_probe=ok api=12")
' "$KVM_NODE" 2>&1)
    rc=$?
    if [ "$rc" -eq 124 ]; then
        echo "kvm_probe=fail reason=probe-timed-out dev=$KVM_NODE"
        return 1
    fi
    printf '%s\n' "$probe_out"
    [ "$rc" -eq 0 ]
}

KVM_LINE=$(kvm_probe) || {
    {
        echo "$KVM_LINE"
        echo "result=VNG_KVM_UNUSABLE"
    } >>"$DIAG"
    echo "vng-boot-watch.sh: VNG_KVM_UNUSABLE host KVM cannot create a VM ($KVM_LINE; see $DIAG)" >&2
    exit 2
}
echo "$KVM_LINE" >>"$DIAG"
echo "kvm_node=$KVM_NODE" >>"$DIAG"

# Start the child in its own process group so the trip kill reaches vng
# and its qemu grandchild together. setsid only forks when it is already
# a group leader; our background job never is, so $! is the new leader —
# verified below before any group kill (a wrong group kill would hit our
# own process group).
USE_GROUP_KILL=0
if command -v setsid >/dev/null; then
    setsid "$@" >"$CONSOLE" 2>&1 &
    CHILD=$!
    pgid=$(ps -o pgid= -p "$CHILD" 2>/dev/null | tr -d ' ' || true)
    if [ "$pgid" = "$CHILD" ]; then
        USE_GROUP_KILL=1
    fi
else
    "$@" >"$CONSOLE" 2>&1 &
    CHILD=$!
fi
echo "child_pid=$CHILD group_kill=$USE_GROUP_KILL" >>"$DIAG"

kill_child() {
    if [ "$USE_GROUP_KILL" = 1 ] && command -v pkill >/dev/null; then
        pkill "-$1" -g "$CHILD" 2>/dev/null || true
    else
        kill "-$1" "$CHILD" 2>/dev/null || true
        if command -v pkill >/dev/null; then
            for p in $(pgrep -P "$CHILD" 2>/dev/null || true); do
                kill "-$1" "$p" 2>/dev/null || true
                for g in $(pgrep -P "$p" 2>/dev/null || true); do
                    kill "-$1" "$g" 2>/dev/null || true
                done
            done
        fi
    fi
}
# A step cancel must not orphan qemu in the detached group.
trap 'kill_child TERM >/dev/null 2>&1; exit 143' TERM INT

child_alive() {
    [ -r "/proc/$1/stat" ] || return 1
    [ "$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)" != "Z" ]
}

booted=0
start_s=$(date +%s)
while :; do
    if [ -s "$CONSOLE" ] || [ -s "$MARKER" ]; then booted=1; break; fi
    if ! child_alive "$CHILD"; then break; fi
    if [ "$(( $(date +%s) - start_s ))" -ge "$BOOT_TIMEOUT" ]; then break; fi
    sleep 2
done

console_bytes() {
    wc -c <"$CONSOLE" 2>/dev/null | tr -d ' ' || echo unknown
}

if [ "$booted" = 0 ] && child_alive "$CHILD"; then
    # One last look: a guest that started printing between the final
    # poll and now must not be killed.
    if [ -s "$CONSOLE" ] || [ -s "$MARKER" ]; then
        booted=1
    fi
fi
if [ "$booted" = 1 ] || ! child_alive "$CHILD"; then
    # Booted, or the child exited on its own: pass its exit through
    # untouched (fast vng failures and timeout budgets behave exactly
    # as without the watchdog).
    wait "$CHILD"
    rc=$?
    {
        echo "result=passthrough rc=$rc booted=$booted"
        echo "console_bytes=$(console_bytes)"
        if [ -e "$MARKER" ]; then
            [ -s "$MARKER" ] && echo "marker=present-nonempty" || echo "marker=present-empty"
        else
            echo "marker=missing"
        fi
    } >>"$DIAG"
    exit "$rc"
fi

# Trip: capture qemu's state BEFORE the kill, then stop the group.
# Snapshot the signals once: qemu's death notice lands in the console
# after the kill, and must not rewrite the at-trip numbers.
TRIP_CONSOLE_BYTES=$(console_bytes)
if [ -e "$MARKER" ]; then
    [ -s "$MARKER" ] && TRIP_MARKER=present-nonempty || TRIP_MARKER=present-empty
else
    TRIP_MARKER=missing
fi
{
    echo "result=VNG_BOOT_TIMEOUT"
    echo "trip_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "console_bytes=$TRIP_CONSOLE_BYTES"
    echo "marker=$TRIP_MARKER"
    echo "--- group ---"
    if command -v ps >/dev/null && [ "$USE_GROUP_KILL" = 1 ]; then
        ps -e -o pid= -o pgid= -o stat= -o etime= -o %cpu= -o args= 2>/dev/null \
            | awk -v g="$CHILD" '$2 == g {print "proc pid="$1" stat="$3" etime="$4" pcpu="$5" args="$6" " $7" " $8" " $9}' \
            || echo "(process listing failed)"
    else
        ps -o pid= -o ppid= -o stat= -o etime= -o %cpu= -o args= -p "$CHILD" 2>/dev/null \
            | awk '{print "proc pid="$1" ppid="$2" stat="$3" etime="$4" pcpu="$5" args="$6" " $7" " $8" " $9}' \
            || echo "(process listing unavailable)"
    fi
    echo "--- qemu ---"
    found_qemu=0
    for q in $(pgrep -f "qemu-system" 2>/dev/null || true); do
        qpgid=$(ps -o pgid= -p "$q" 2>/dev/null | tr -d ' ' || true)
        if [ "$USE_GROUP_KILL" = 1 ] && [ "$qpgid" != "$CHILD" ]; then
            continue
        fi
        found_qemu=1
        echo "qemu_pid=$q"
        if [ -r "/proc/$q/cmdline" ]; then
            echo "qemu_cmdline=$(tr '\0' ' ' </proc/$q/cmdline 2>/dev/null)"
        fi
        if [ -d "/proc/$q/task" ]; then
            # vCPU threads are named CPU N/KVM (or /TCG); before they
            # spawn, KVM worker threads (kvm-*) still betray the accel.
            accel=$(for t in /proc/$q/task/*/comm; do cat "$t" 2>/dev/null; done \
                | grep -oiE 'kvm|tcg' | tr 'a-z' 'A-Z' | sort -u | tr '\n' ',' || true)
            echo "qemu_accel=${accel%,}"
            echo "qemu_threads=$(for t in /proc/$q/task/*/comm; do cat "$t" 2>/dev/null; done | tr '\n' ' ' || true)"
        fi
    done
    [ "$found_qemu" = 1 ] || echo "qemu_pid=(none of ours running)"
    echo "--- kvm ---"
    ls -l "$KVM_NODE" 2>/dev/null || echo "(cannot stat $KVM_NODE)"
    echo "--- load ---"
    echo "loadavg=$(cat /proc/loadavg 2>/dev/null || echo unknown)"
    if command -v free >/dev/null; then
        free -m 2>/dev/null | head -n 2 || true
    fi
    echo "--- dmesg tail ---"
    if dmesg >/dev/null 2>&1; then
        dmesg 2>/dev/null | tail -n 20 || true
    else
        echo "(dmesg unavailable)"
    fi
} >>"$DIAG"
kill_child TERM
sleep 5
if child_alive "$CHILD"; then
    kill_child KILL
    sleep 2
fi
wait "$CHILD" 2>/dev/null || true
accel_line=$(grep -m 1 '^qemu_accel=' "$DIAG" 2>/dev/null || echo "qemu_accel=(unknown)")
echo "vng-boot-watch.sh: VNG_BOOT_TIMEOUT no guest progress within ${BOOT_TIMEOUT}s (console $TRIP_CONSOLE_BYTES bytes, marker $MARKER $TRIP_MARKER)" >&2
echo "vng-boot-watch.sh: $accel_line (see $DIAG)" >&2
echo "--- $DIAG ---" >&2
cat "$DIAG" >&2
exit 2
