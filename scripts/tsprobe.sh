#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# tsprobe.sh — manual LOST-timeline probe (Task 3.1 G4m method): pid/trace
# duration-expired run with externally timestamped stdout, splitting
# capture-tick loss from detach-window loss across the detach silence gap.
#
# I1 fix (2026-09-20): the throwaway /tmp/tsprobe.sh ran every cell in one
# fixed workdir and opened with `rm -rf $W`, so the G4m-2 run wiped G4m-1's
# raw artifacts. This committed version gives every cell its own workdir
# ($ROOT/$CELL) and only ever clears a directory carrying this script's
# ownership marker for that cell — a re-run cannot wipe a sibling cell's
# artifacts again. `--self-test` pins the workdir logic (unprivileged).
#
# Privileged lane body (the observer runs under sudo): manual/local run
# only, never CI. UNRUN hosted — only the self-test runs in CI.
set -eu
cd "$(dirname "$0")/.."

usage() {
    cat >&2 <<'EOF'
usage: tsprobe.sh --self-test
       tsprobe.sh --cell NAME [--root DIR] [--module PATH]
                  [--n-calls N] [--pace-us US] [--duration S]
                  [--drain-interval-ms MS] [--settle-s S] [--profile P]
EOF
    exit 2
}

# Cell names are single path segments: no separators, no parent refs.
valid_cell() {
    case ${1-} in
        '' | .* | -*) return 1 ;;
    esac
    case $1 in
        *..*) return 1 ;;
        *[!A-Za-z0-9._-]*) return 1 ;;
        *) return 0 ;;
    esac
}

# Resolve $ROOT/$CELL, refusing escapes. Prints the workdir.
cell_dir() {
    case ${1-} in /*) ;; *) echo "root must be absolute: ${1-}" >&2; return 1 ;; esac
    valid_cell "${2-}" || { echo "bad cell name: ${2-}" >&2; return 1; }
    printf '%s/%s\n' "$1" "$2"
}

# Create (or re-prepare) a cell workdir. Prints the workdir. A re-run
# clears ONLY a directory carrying our ownership marker for this cell;
# anything else (foreign dir, marker mismatch, non-directory) fails
# closed without deleting. The root itself is created, never removed.
prepare_cell() {
    W=$(cell_dir "$1" "$2") || return 1
    cell=$2
    mkdir -p "$1"
    if [ -e "$W" ] && [ ! -d "$W" ]; then
        echo "cell path is not a directory: $W" >&2
        return 1
    fi
    if [ -d "$W" ]; then
        if [ -f "$W/.tsprobe-cell" ] && [ "$(cat "$W/.tsprobe-cell")" = "$cell" ]; then
            find "$W" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
        else
            echo "refusing to clear non-owned dir: $W" >&2
            return 1
        fi
    else
        mkdir -p "$W"
    fi
    printf '%s\n' "$cell" >"$W/.tsprobe-cell"
    printf '%s\n' "$W"
}

run_self_test() {
    [ "$#" -eq 0 ] || usage
    passed=0
    note() { passed=$((passed + 1)); }
    fail() { echo "self-test FAIL: $1" >&2; exit 1; }
    SELF_TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-tsprobe-selftest-XXXXXX")
    trap 'rm -rf "$SELF_TEST_ROOT"' EXIT INT TERM

    # 1. Distinct cells resolve to distinct workdirs.
    A=$(prepare_cell "$SELF_TEST_ROOT" g4m-1) || fail "prepare g4m-1"
    B=$(prepare_cell "$SELF_TEST_ROOT" g4m-2) || fail "prepare g4m-2"
    [ "$A" != "$B" ] || fail "cells share a workdir"
    [ "$A" = "$SELF_TEST_ROOT/g4m-1" ] || fail "cell dir shape: $A"
    note

    # 2. I1 regression: (re-)preparing a sibling cell leaves this
    # cell's artifacts byte-identical.
    printf 'LOST 5847 events\n' >"$A/stdout.txt"
    printf '{"t_mono_ns": 1, "line": "LOST 5847 events"}\n' >"$A/stdout-ts.jsonl"
    sum_before=$(cksum "$A/stdout.txt" "$A/stdout-ts.jsonl")
    B2=$(prepare_cell "$SELF_TEST_ROOT" g4m-2) || fail "re-prepare g4m-2"
    [ "$B2" = "$B" ] || fail "re-prepare moved the cell"
    printf 'probe-output\n' >"$B/marker.txt"
    B3=$(prepare_cell "$SELF_TEST_ROOT" g4m-2) || fail "re-prepare populated g4m-2"
    [ "$B3" = "$B" ] || fail "re-prepare moved the populated cell"
    [ ! -e "$B/marker.txt" ] || fail "re-prepare did not clear its own cell"
    sum_after=$(cksum "$A/stdout.txt" "$A/stdout-ts.jsonl")
    [ "$sum_before" = "$sum_after" ] || fail "sibling artifacts changed"
    note

    # 3. A pre-existing dir without the ownership marker fails closed
    # with its contents intact.
    mkdir -p "$SELF_TEST_ROOT/foreign"
    printf 'keep\n' >"$SELF_TEST_ROOT/foreign/keep.txt"
    if prepare_cell "$SELF_TEST_ROOT" foreign >/dev/null 2>&1; then
        fail "cleared a non-owned dir"
    fi
    [ "$(cat "$SELF_TEST_ROOT/foreign/keep.txt")" = "keep" ] || fail "foreign contents changed"
    note

    # 4. A marker naming another cell fails closed too.
    mkdir -p "$SELF_TEST_ROOT/renamed"
    printf 'other-cell\n' >"$SELF_TEST_ROOT/renamed/.tsprobe-cell"
    printf 'keep\n' >"$SELF_TEST_ROOT/renamed/keep.txt"
    if prepare_cell "$SELF_TEST_ROOT" renamed >/dev/null 2>&1; then
        fail "cleared a marker-mismatched dir"
    fi
    [ "$(cat "$SELF_TEST_ROOT/renamed/keep.txt")" = "keep" ] || fail "mismatched contents changed"
    note

    # 5. Dangerous cell names are rejected outright.
    for bad in '' '..' '../x' 'a/b' '/abs' '.hidden' '-rf' 'a b'; do
        if cell_dir "$SELF_TEST_ROOT" "$bad" >/dev/null 2>&1; then
            fail "accepted cell name: [$bad]"
        fi
    done
    for bad in '' '..' 'a/b'; do
        if prepare_cell "$SELF_TEST_ROOT" "$bad" >/dev/null 2>&1; then
            fail "prepared cell name: [$bad]"
        fi
    done
    note

    # 6. A relative root is rejected (workdirs must stay absolute).
    if cell_dir rel/root g4m-1 >/dev/null 2>&1; then
        fail "accepted a relative root"
    fi
    note

    echo "tsprobe workdir self-test: OK ($passed groups)"
}

# Defaults reproduce the G4m cells exactly (pid/trace, weak gate).
CELL=""
ROOT=/var/tmp/p11scope-31-tsprobe
MODULE=/usr/lib/softhsm/libsofthsm2.so
N_CALLS=40000
PACE_US=500
DURATION_S=20
DRAIN_MS=1000
SETTLE_S=10
PROFILE=release

while [ "$#" -gt 0 ]; do
    case $1 in
        --self-test)
            shift
            run_self_test "$@"
            exit 0
            ;;
        --cell | --root | --module | --n-calls | --pace-us | --duration | --drain-interval-ms | --settle-s | --profile)
            [ "$#" -ge 2 ] || usage
            case $1 in
                --cell) CELL=$2 ;;
                --root) ROOT=$2 ;;
                --module) MODULE=$2 ;;
                --n-calls) N_CALLS=$2 ;;
                --pace-us) PACE_US=$2 ;;
                --duration) DURATION_S=$2 ;;
                --drain-interval-ms) DRAIN_MS=$2 ;;
                --settle-s) SETTLE_S=$2 ;;
                --profile) PROFILE=$2 ;;
            esac
            shift 2
            ;;
        -h | --help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done
[ -n "$CELL" ] || usage

W=$(prepare_cell "$ROOT" "$CELL") || exit 1
export SOFTHSM2_CONF=$W/softhsm2.conf
chmod 700 "$W"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' "$W" >"$SOFTHSM2_CONF"
mkdir -p "$W/tokens"
softhsm2-util --init-token --free --label g4 --so-pin 1234 --pin 1234 >/dev/null
gcc -O0 -o "$W/workload" scripts/system-scope-workload.c -ldl
./target/release/p11scope-discover --module "$MODULE" -o "$W/manifest.json"
rm -f "$W/ready" "$W/go" "$W/out.fifo"
"$W/workload" "$MODULE" "$N_CALLS" "$PACE_US" 0 "$W/ready" "$W/go" >"$W/wl.log" 2>&1 &
WPID=$!
for _ in $(seq 1 100); do [ -f "$W/ready" ] && break; sleep 0.2; done
mkfifo "$W/out.fifo"
python3 -I scripts/system-scope-ts.py --out "$W/stdout-ts.jsonl" --passthrough "$W/stdout.txt" <"$W/out.fifo" &
TSPID=$!
if [ "$PROFILE" = release ]; then OBSERVER=./target/release/p11scope; else OBSERVER=./target/debug/p11scope; fi
sudo --preserve-env=SOFTHSM2_CONF "$OBSERVER" trace --pid "$WPID" \
    --manifest "$W/manifest.json" --duration "$DURATION_S" --drain-interval-ms "$DRAIN_MS" \
    --max-events 10000000 -o "$W/trace.out" \
    >"$W/out.fifo" 2>"$W/stderr.txt" &
SPID=$!
for _ in $(seq 1 3000); do grep -q "p11scope: discovery:" "$W/stderr.txt" 2>/dev/null && break; sleep 0.2; done
python3 -I -c 'import time; print("marker_mono_ns:", time.monotonic_ns())' | tee "$W/gate.log"
echo "marker seen; settling ${SETTLE_S}s (weak gate)"
sleep "$SETTLE_S"
touch "$W/go"
python3 -I -c 'import time; print("go_mono_ns:", time.monotonic_ns())' | tee -a "$W/gate.log"
LOADAVG=$(cat /proc/loadavg)
printf 'go_loadavg: %s\n' "$LOADAVG" | tee -a "$W/gate.log"
printf '{"cell": "%s", "profile": "%s", "go_loadavg": "%s", "n_calls": %s, "pace_us": %s, "duration_s": %s, "drain_interval_ms": %s, "settle_s": %s}\n' \
    "$CELL" "$PROFILE" "$LOADAVG" "$N_CALLS" "$PACE_US" "$DURATION_S" "$DRAIN_MS" "$SETTLE_S" >"$W/meta.json"
echo "go released"
wait "$SPID"; echo "observer rc=$?"
wait "$WPID" 2>/dev/null; echo "workload done"
wait "$TSPID" 2>/dev/null; echo "ts done"
