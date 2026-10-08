#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# bench-count-overhead.sh — Stage 2 M2 cost gate: per-edge counting overhead.
#
# Method: a self-timed PKCS#11 call-churn workload (scripts/fixtures/mt_count.c:
# N threads hammer C_GenerateRandom for SECS seconds behind a gate file,
# CLOCK_MONOTONIC around the window only) runs under a live
# `p11scope inventory --pid --capture native` capture, with counting on
# (CAND_BIN: the lane tip, V1 non-fetch atomic add in CALLER_USE plus the
# count-refresh reader and counted publish) or off (BASE_BIN: the exact
# pre-counting base c34b4d4, witness-only CALLER_USE, no refresh, no
# counted publish). Same CLI, same workload, same attach machinery on both
# arms: the with/without delta is exactly the counting feature. An
# unobserved arm (no observer) times the bare call cost per cell.
#
# Why a binary toggle: counting is unconditional in-tree (BPF adds on
# every entry, the refresh runs every pass); no runtime switch disables
# it, and this lane must not touch production code. The base predates C1
# by one commit line (only 18f6501 touches the caller-entry files since),
# carries the same native uprobe-multi attach path, and never attaches
# Stage A hooks (inventory has no InstanceTracking), so the arms differ
# only by counting. See the M2 gate section of task-2c34fix-report.md.
#
# Cells (2 arms x ROUNDS rounds of ABBA/BAAB-interleaved samples each,
# plus one unobserved sample per round per cell):
#   relevant-call-t1 / -t4 / -t12: mt_count hammering the observed
#     provider (every call counted; pinned CPUs per the C5 M2 precedent:
#     t1->2, t4->2-5, t12->0-9 with the observer on 10,11)
#   relevant-call-t12-nolock: t12 with cache-line-padded per-thread
#     counters (no false sharing)
#   unrelated-mmap: file-mapping churn (map_churn.c, 1M ops) on a private
#     temp file beside an idle-anchor capture (no calls, no rows, the
#     refresh idles: the attribution control, expects ~0 delta)
# Interleaving is ABBA within a round (round 1: on off off on) with the
# starting arm alternating per round, so linear host drift cannot masquerade
# as an arm difference. Pairs for the analysis are the i-th on with the
# i-th off sample of a round in log order (adjacent under ABBA/BAAB).
#
# Per-sample gates (any failure fails the campaign immediately; nothing is
# excluded silently): quiet-host load gate (load1 < MAX_LOAD1 AND load5 <
# MAX_LOAD5, defaults 4/4 per the M2 discipline, no cargo/rustc; bounded
# COOLDOWN, default 300 s, else the campaign is refused; plus a
# load1 < 2.0 settle at cell boundaries), workload READY,
# observer lane-active line with a recorded attach mechanism, two
# per-pass progress lines before the gate opens (extend precedes commit in
# a pass, so endpoint probes are attached), exact workload op count +
# shape, observer exit 0, no "attach failed", no "count refresh:"
# failures, BPF entry-program set identical across the window with
# monotone run-time counters, and the count-exactness gate: the on-arm
# edge reads counted with exactly TOTAL+2*THREADS+1 (0 error), the off-arm
# edge reads witnessed. BPF run-time deltas (kernel.bpf_stats_enabled,
# set for the campaign and restored after) corroborate the workload-side
# numbers independently; the verdict math lives in
# scripts/bench-count-overhead-analyze.py, which also runs standalone on
# the campaign log.
#
# Usage: flock "$LOCK" scripts/bench-count-overhead.sh [--self-test]
# The script refuses unless an ancestor holds LOCK (default
# /var/tmp/p11scope-ws-tmp/privileged.lock), the tree is clean, and no
# p11scope processes or p11_* BPF programs are already live (another
# capture's probes would charge both arms). Run as a user with
# passwordless sudo; the observer, bpftool and sysctl go through sudo -n,
# everything else runs unprivileged. The candidate binary is rebuilt
# in-script before any sample (builds never run during a measurement
# window); the base binary must be prebuilt (BASE_BIN). Environment:
# CELLS (default: all five), ROUNDS (default 10), SECS (default 5),
# OPS (default 1000000, unrelated cell), MAX_LOAD1/MAX_LOAD5 (default 4),
# COOLDOWN (default 300), DURATION (default 120), ATTACH_TIMEOUT_S
# (default 60), PASSES_REQUIRED (default 2), MODULE (default the system
# SoftHSM2), CAND_BIN (default ./target/release/p11scope),
# BASE_BIN (default /var/tmp/p11scope-ws-tmp/m2-base/target/release/p11scope),
# OBS_CPUS (default 10,11), WCPUS_T1/T4/T12, LOCK, TMPDIR (must be a disk
# filesystem; the campaign keeps per-sample evidence under its work dir).
set -eu
cd "$(dirname "$0")/.."
REPO=$PWD
. scripts/lib.sh

MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
CAND_BIN=${CAND_BIN:-$REPO/target/release/p11scope}
BASE_BIN=${BASE_BIN:-/var/tmp/p11scope-ws-tmp/m2-base/target/release/p11scope}
OPS=${OPS:-1000000}
SECS=${SECS:-5}
ROUNDS=${ROUNDS:-10}
CELLS=${CELLS:-relevant-call-t1 relevant-call-t4 relevant-call-t12 relevant-call-t12-nolock unrelated-mmap}
MAX_LOAD1=${MAX_LOAD1:-4}
MAX_LOAD5=${MAX_LOAD5:-4}
COOLDOWN=${COOLDOWN:-300}
DURATION=${DURATION:-120}
ATTACH_TIMEOUT_S=${ATTACH_TIMEOUT_S:-60}
PASSES_REQUIRED=${PASSES_REQUIRED:-2}
OBS_CPUS=${OBS_CPUS:-10,11}
WCPUS_T1=${WCPUS_T1:-2}
WCPUS_T4=${WCPUS_T4:-2-5}
WCPUS_T12=${WCPUS_T12:-0-9}
LANE_MARKER="p11scope: native usage lane active"
KIND=p11scope-control-plane
WORK=
APID=
SPID=
WPID=
KIND_PAUSED=0
BPF_STATS_BEFORE=
FIX=scripts/fixtures

say() {
    echo "$*"
    echo "$*" >> "$LOG"
}

die() {
    echo "bench-count-overhead: $*" >&2
    exit 1
}

refuse() {
    echo "bench-count-overhead: REFUSED: $*" >&2
    exit 3
}

is_positive_int() {
    case $1 in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -gt 0 ]
}

if [ "${1-}" = "--self-test" ]; then
    [ "$#" -eq 1 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
    # Unprivileged: fixture compiles + exact-count smokes + usage
    # refusals + the analyzer self-test. No BPF, no sudo, no observer, no
    # build of the workspace.
    SELF_TEST_WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-count-selftest-XXXXXX")
    trap 'rm -rf "$SELF_TEST_WORK"' EXIT INT TERM
    command -v gcc >/dev/null || { echo "self-test: gcc required" >&2; exit 1; }
    command -v python3 >/dev/null || { echo "self-test: python3 required" >&2; exit 1; }
    gcc -O2 -Wall -Wextra -Werror -pthread -o "$SELF_TEST_WORK/mt_count" "$FIX/mt_count.c" -ldl \
        || { echo "self-test: mt_count does not compile" >&2; exit 1; }
    gcc -O2 -Wall -Wextra -Werror -o "$SELF_TEST_WORK/map_churn" "$FIX/map_churn.c" \
        || { echo "self-test: map_churn does not compile" >&2; exit 1; }
    if [ -r "$MODULE" ] && command -v softhsm2-util >/dev/null 2>&1; then
        export SOFTHSM2_CONF="$SELF_TEST_WORK/softhsm2.conf"
        mkdir -p "$SELF_TEST_WORK/tokens"
        printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' \
            "$SELF_TEST_WORK/tokens" > "$SOFTHSM2_CONF"
        softhsm2-util --init-token --free --label selftest --so-pin 1234 --pin 1234 >/dev/null \
            || { echo "self-test: token init failed" >&2; exit 1; }
        touch "$SELF_TEST_WORK/gate-open"
        for pad in 0 1; do
            ST_LINE=$("$SELF_TEST_WORK/mt_count" "$MODULE" 2 1 "$SELF_TEST_WORK/gate-open" "$pad") \
                || { echo "self-test: mt_count pad=$pad failed" >&2; exit 1; }
            case $ST_LINE in "READY pid="*"MT_COUNT ops="*" wall_ns="*" threads=2 pad=$pad") : ;; *)
                echo "self-test: bad mt_count line: $ST_LINE" >&2; exit 1 ;;
            esac
        done
        if "$SELF_TEST_WORK/mt_count" "$MODULE" 0 1 "$SELF_TEST_WORK/gate-open" 0 >/dev/null 2>&1; then
            echo "self-test: zero threads accepted" >&2; exit 1
        fi
        if "$SELF_TEST_WORK/mt_count" "$MODULE" 2 1 "$SELF_TEST_WORK/gate-open" 2 >/dev/null 2>&1; then
            echo "self-test: bad pad accepted" >&2; exit 1
        fi
    else
        echo "self-test: mt_count run skipped (softhsm2-util or $MODULE missing)"
    fi
    head -c 8192 /dev/zero > "$SELF_TEST_WORK/f.bin" 2>/dev/null \
        || { echo "self-test: cannot write a temp file" >&2; exit 1; }
    ST_LINE=$("$SELF_TEST_WORK/map_churn" "$SELF_TEST_WORK/f.bin" 2000 mmap) \
        || { echo "self-test: mmap smoke failed" >&2; exit 1; }
    case $ST_LINE in "MAP_CHURN ops=2000 wall_ns="*" mode=mmap") : ;; *)
        echo "self-test: bad mmap line: $ST_LINE" >&2; exit 1 ;;
    esac
    python3 -I scripts/bench-count-overhead-analyze.py --self-test \
        || { echo "self-test: analyzer self-test failed" >&2; exit 1; }
    echo "bench-count-overhead self-test: OK"
    exit 0
fi
[ "$#" -eq 0 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }

for knob in OPS SECS ROUNDS COOLDOWN DURATION ATTACH_TIMEOUT_S PASSES_REQUIRED; do
    eval "value=\$$knob"
    is_positive_int "$value" || { echo "usage: $knob is a positive integer" >&2; exit 2; }
done
for cell in $CELLS; do
    case $cell in
        relevant-call-t1|relevant-call-t4|relevant-call-t12|relevant-call-t12-nolock|unrelated-mmap) : ;;
        *) echo "usage: unknown cell $cell" >&2; exit 2 ;;
    esac
done

# The observer refuses an output directory below any group- or other-writable
# ancestor, which a checkout under a 0775 home tree has, so the campaign works
# in a private directory under TMPDIR. It is kept for the numbers.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-bench-count-XXXXXX")
LOG=$WORK/campaign.log
chmod 0700 "$WORK"
echo "work: $WORK"

cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$WPID" ] || kill "$WPID" 2>/dev/null || true
    [ -z "$APID" ] || kill "$APID" 2>/dev/null || true
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || true
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$APID" ] || wait "$APID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    if [ -n "$BPF_STATS_BEFORE" ]; then
        sudo -n sysctl -w kernel.bpf_stats_enabled="$BPF_STATS_BEFORE" >/dev/null 2>&1 || true
    fi
    if [ "$KIND_PAUSED" = 1 ]; then
        docker unpause "$KIND" >/dev/null 2>&1 || true
    fi
    exit "$status"
}
. scripts/cleanup-traps.sh

command -v gcc >/dev/null || die "gcc required"
command -v softhsm2-util >/dev/null || die "softhsm2-util required"
command -v python3 >/dev/null || die "python3 required"
command -v bpftool >/dev/null || die "bpftool required"
command -v sudo >/dev/null || die "sudo required"
command -v taskset >/dev/null || die "taskset required"
test -f "$MODULE" || die "SoftHSM2 not installed at $MODULE"
[ "$(id -u)" -ne 0 ] || die "run as a non-root user with passwordless sudo"
sudo -n true 2>/dev/null || die "passwordless sudo required"
test -x "$BASE_BIN" || die "prebuilt base binary missing: $BASE_BIN"

# An ancestor must hold the privileged lock: a concurrent privileged test or
# capture would charge these samples. Run under `flock "$LOCK" $0`.
python3 -I - "$LOCK" "$$" <<'EOF' || refuse "run under flock $LOCK: no ancestor holds the privileged lock"
import os, sys
path, me = sys.argv[1], int(sys.argv[2])
try:
    inode = str(os.stat(path).st_ino)
except OSError:
    sys.exit(1)
holders = []
for line in open("/proc/locks"):
    fields = line.split()
    if "->" in fields:
        continue
    if (len(fields) >= 6 and fields[1] == "FLOCK" and fields[3] == "WRITE"
            and fields[5].rsplit(":", 1)[-1] == inode):
        holders.append(int(fields[4]))
chain, pid = {me}, me
while pid > 1:
    try:
        status = open(f"/proc/{pid}/status").read()
    except OSError:
        break
    pid = int(next(l.split()[1] for l in status.splitlines() if l.startswith("PPid:")))
    chain.add(pid)
sys.exit(0 if any(h in chain for h in holders) else 1)
EOF

# Another capture's probes would charge both arms equally and flatten the
# comparison, so a live p11scope or live p11_* BPF programs refuse the run.
if pgrep -x p11scope >/dev/null 2>&1; then
    refuse "a p11scope process is already running"
fi
if sudo -n bpftool prog show 2>/dev/null | grep -q "p11_"; then
    refuse "p11_* BPF programs are already attached"
fi
[ -z "$(git status --porcelain -- . ':!target')" ] || refuse "the tree is not clean"

build_processes() {
    cat /proc/[0-9]*/comm 2>/dev/null | grep -cxE 'cargo|rustc'
}

# M2 discipline: load1 AND load5 below their bounds (the C5 campaign gates
# load5 < 4 on M2 as well as load1).
host_hot() {
    awk -v max1="$1" -v max5="$2" '{exit !(($1 >= max1) || ($2 >= max5))}' /proc/loadavg
}

# wait_cool: bounded quiet-host wait before every sample (the previous
# sample's observer and workload heat the host). False when the host never
# cools: the campaign is refused, never measured hot.
wait_cool() {
    waited=0
    while host_hot "$MAX_LOAD1" "$MAX_LOAD5" || [ "$(build_processes)" != 0 ]; do
        if [ "$waited" -ge "$COOLDOWN" ]; then
            return 1
        fi
        sleep 5
        waited=$((waited + 5))
    done
    return 0
}

# wait_settle: deeper quiet wait at cell boundaries (a hot cell's heat must
# not step into the next cell's first round: the smoke showed a t12-hot
# first unrelated sample). False when the host never settles: refused.
wait_settle() {
    waited=0
    while awk '{exit !($1 >= 2.0)}' /proc/loadavg || [ "$(build_processes)" != 0 ]; do
        if [ "$waited" -ge "$COOLDOWN" ]; then
            return 1
        fi
        sleep 5
        waited=$((waited + 5))
    done
    return 0
}

record_load() {
    {
        echo "uptime_$2=$(uptime)"
        echo "loadavg_$2=$(cat /proc/loadavg)"
        echo "build_processes_$2=$(build_processes)"
        echo "at_$2=$(date --iso-8601=ns)"
    } >> "$1"
}

# lane_mechanism LOG: multi|singles from the lane-active line, else empty.
lane_mechanism() {
    if grep -Fq "$LANE_MARKER" "$1" 2>/dev/null; then
        if grep -F "$LANE_MARKER" "$1" | grep -q "multi"; then
            echo multi
        elif grep -F "$LANE_MARKER" "$1" | grep -q "singles"; then
            echo singles
        fi
    fi
}

wait_for_lane_active() {
    wfla_end=$(( $(date +%s) + $2 ))
    while :; do
        if grep -Fq "$LANE_MARKER" "$1" 2>/dev/null; then
            return 0
        fi
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            echo "observer exited before the lane went active: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        fi
        [ "$(date +%s)" -lt "$wfla_end" ] || {
            echo "lane never went active within $2s: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        }
        sleep 0.05
    done
}

# wait_for_passes STDERRLOG N TIMEOUT: N per-pass stderr progress lines prove
# passes are committing (extend precedes commit in a pass, so endpoint
# probes are attached before the gate opens). The event log is root-owned
# while the observer runs, so readiness polls the user-readable stderr.
wait_for_passes() {
    wfp_end=$(( $(date +%s) + $3 ))
    while :; do
        wfp_n=$(grep -c '^p11scope: pass [0-9][0-9]*: .* scanned' "$1" 2>/dev/null || true)
        case $wfp_n in ''|*[!0-9]*) wfp_n=0 ;; esac
        if [ "$wfp_n" -ge "$2" ]; then
            return 0
        fi
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            echo "observer exited before $2 passes committed: $1" >&2
            return 1
        fi
        [ "$(date +%s)" -lt "$wfp_end" ] || {
            echo "only $wfp_n/$2 passes committed within $3s: $1" >&2
            return 1
        }
        sleep 0.1
    done
}

# bpf_entry_names: sorted p11_usage_entry_* program names + IDs, one per
# line ("<id> <name>"). Empty when none are attached.
bpf_entry_names() {
    sudo -n bpftool -j prog show 2>/dev/null | python3 -I -c '
import json, sys
try:
    progs = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for prog in sorted(progs, key=lambda p: p.get("id", 0)):
    name = prog.get("name", "")
    if name.startswith("p11_usage_entry"):
        print(prog.get("id"), name)
'
}

# bpf_entry_totals: "<run_time_ns sum> <run_cnt sum>" over the entry
# programs (kernel.bpf_stats_enabled=1 for the campaign). Fails when none
# are attached.
bpf_entry_totals() {
    sudo -n bpftool -j prog show 2>/dev/null | python3 -I -c '
import json, sys
try:
    progs = json.load(sys.stdin)
except Exception:
    sys.exit(1)
ns = cnt = n = 0
for prog in progs:
    if str(prog.get("name", "")).startswith("p11_usage_entry"):
        n += 1
        ns += prog.get("run_time_ns", 0)
        cnt += prog.get("run_cnt", 0)
if n == 0:
    sys.exit(1)
print(f"{ns} {cnt}")
'
}

echo "=== build ==="
scripts/cargo.sh "+$(cat .release-rust-version)" build --locked --release --bin p11scope
test -x "$CAND_BIN" || die "candidate observer missing: $CAND_BIN"
mkdir -m 0700 -p "$WORK/bin"
gcc -O2 -Wall -Wextra -Werror -pthread -o "$WORK/bin/mt_count" "$FIX/mt_count.c" -ldl \
    || die "mt_count does not compile"
gcc -O2 -Wall -Wextra -Werror -o "$WORK/bin/map_churn" "$FIX/map_churn.c" \
    || die "map_churn does not compile"
gcc -O1 -Wall -Wextra -Werror -o "$WORK/bin/gated" tests/fixtures/public-cli/gated.c -ldl \
    || die "gated does not compile"
head -c 8192 /dev/zero > "$WORK/unrelated.bin" || die "cannot write the unrelated file"

echo "=== private softhsm token ==="
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
rm -rf "$WORK/tokens"
mkdir -p "$WORK/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
softhsm2-util --init-token --free --label bench-count --so-pin 1234 --pin 1234 >/dev/null \
    || die "token init failed"

echo "=== machine ==="
KERNEL=$(uname -r)
CPU=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
VIRT=$(systemd-detect-virt 2>/dev/null || echo bare)
COMMIT=$(git rev-parse HEAD)
CAND_SHA=$(sha256sum "$CAND_BIN" | cut -d' ' -f1)
BASE_SHA=$(sha256sum "$BASE_BIN" | cut -d' ' -f1)
echo "kernel: $KERNEL"
echo "cpu: $CPU"
echo "virt: $VIRT"
echo "commit: $COMMIT"
echo "candidate: $CAND_SHA"
echo "base: $BASE_SHA"
echo "cells: $CELLS"
echo "rounds: $ROUNDS secs: $SECS"
say "MACHINE kernel=$KERNEL cpu=$CPU virt=$VIRT nproc=$(nproc) date=$(date -u +%FT%TZ) host=$(uname -n)"
say "BINARY role=candidate path=$CAND_BIN sha256=$CAND_SHA commit=$COMMIT"
say "BINARY role=base path=$BASE_BIN sha256=$BASE_SHA commit=c34b4d4605581bca8d89cb3a136cb7eb91f9e19e"

if command -v docker >/dev/null 2>&1 && docker inspect "$KIND" >/dev/null 2>&1; then
    if [ "$(docker inspect -f '{{.State.Status}}' "$KIND" 2>/dev/null)" = running ]; then
        docker pause "$KIND" >/dev/null || die "cannot pause $KIND"
        KIND_PAUSED=1
        echo "paused $KIND for the campaign"
    fi
else
    echo "no $KIND container: nothing to pause"
fi

BPF_STATS_BEFORE=$(cat /proc/sys/kernel/bpf_stats_enabled)
sudo -n sysctl -w kernel.bpf_stats_enabled=1 >/dev/null \
    || die "cannot enable BPF stats"
echo "bpf_stats_enabled 1 for the campaign (was $BPF_STATS_BEFORE; restored after)"

SAMPLE_SEQ=0

# start_mt DIR THREADS PAD CPUS: launch mt_count pinned to CPUS, waiting on
# DIR/gate. Sets WPID; fails unless READY with a live pid lands.
start_mt() {
    smt_dir=$1 smt_threads=$2 smt_pad=$3 smt_cpus=$4
    rm -f "$smt_dir/gate"
    taskset -c "$smt_cpus" "$WORK/bin/mt_count" "$MODULE" \
        "$smt_threads" "$SECS" "$smt_dir/gate" "$smt_pad" \
        > "$smt_dir/workload.log" 2> "$smt_dir/workload.stderr" &
    WPID=$!
    smt_end=$(( $(date +%s) + 60 ))
    while ! grep -q "^READY" "$smt_dir/workload.log" 2>/dev/null; do
        kill -0 "$WPID" 2>/dev/null || { echo "workload died:" >&2; cat "$smt_dir/workload.stderr" >&2; return 1; }
        [ "$(date +%s)" -lt "$smt_end" ] || { echo "workload never READY" >&2; return 1; }
        sleep 0.05
    done
    WPID_PID=$(sed -n 's/^READY pid=//p' "$smt_dir/workload.log" | tail -n 1)
    case $WPID_PID in ''|*[!0-9]*) echo "unparseable workload pid" >&2; return 1 ;; esac
    kill -0 "$WPID_PID" 2>/dev/null || { echo "workload pid $WPID_PID not alive" >&2; return 1; }
}

# mt_totals LOG THREADS PAD: "<ops> <wall_ns>" from the MT_COUNT line.
# Fails unless the line carries exactly THREADS/PAD with positive values.
mt_totals() {
    python3 -I - "$1" "$2" "$3" <<'EOF'
import sys
path, threads, pad = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for line in open(path):
    if not line.startswith("MT_COUNT "):
        continue
    fields = dict(token.split("=", 1) for token in line.split()[1:])
    if (int(fields["threads"]) != threads or int(fields["pad"]) != pad
            or int(fields["ops"]) <= 0 or int(fields["wall_ns"]) <= 0):
        sys.exit(1)
    print(f"{fields['ops']} {fields['wall_ns']}")
    sys.exit(0)
sys.exit(1)
EOF
}

# start_observer DIR PID BIN: launch inventory native pinned to OBS_CPUS.
# Sets SPID; fails unless the lane goes active and PASSES_REQUIRED passes
# commit (endpoint probes attached before the gate opens).
start_observer() {
    so_dir=$1 so_pid=$2 so_bin=$3
    sudo -n --preserve-env=SOFTHSM2_CONF taskset -c "$OBS_CPUS" "$so_bin" inventory \
        --pid "$so_pid" --capture native \
        --duration "$DURATION" -o "$so_dir/inventory.json" \
        --event-log "$so_dir/events.jsonl" \
        > "$so_dir/observer.log" 2> "$so_dir/observer.stderr" &
    SPID=$!
    wait_for_lane_active "$so_dir/observer.stderr" "$ATTACH_TIMEOUT_S" || return 1
    if grep -q "attach failed" "$so_dir/observer.stderr"; then
        echo "ATTACH FAILURE in $so_dir:" >&2
        cat "$so_dir/observer.stderr" >&2
        return 1
    fi
    wait_for_passes "$so_dir/observer.stderr" "$PASSES_REQUIRED" "$ATTACH_TIMEOUT_S" || return 1
}

# stop_observer DIR: SIGINT the observer, require exit 0/130 and no
# attach/refresh failures. Reclaims the root-owned outputs.
stop_observer() {
    so_dir=$1
    kill -INT "$SPID" 2>/dev/null || true
    if wait "$SPID"; then SPID=; else so_status=$?; SPID=;
        [ "$so_status" = 130 ] || { echo "observer exited $so_status" >&2; return 1; }
    fi
    if grep -q "attach failed" "$so_dir/observer.stderr"; then
        echo "ATTACH FAILURE in $so_dir:" >&2
        cat "$so_dir/observer.stderr" >&2
        return 1
    fi
    if grep -q "count refresh:" "$so_dir/observer.stderr" "$so_dir/observer.log" 2>/dev/null; then
        echo "COUNT REFRESH FAILURE in $so_dir:" >&2
        grep -h "count refresh:" "$so_dir/observer.stderr" "$so_dir/observer.log" >&2
        return 1
    fi
    reclaim_root_output "$so_dir/inventory.json"
    reclaim_root_output "$so_dir/events.jsonl"
}

# check_counted DIR OPS THREADS: the on-arm exactness gate. inventory.json
# must hold exactly one SoftHSM2 edge reading counted with exactly
# OPS+2*THREADS+1 and unsaturated. Prints "<count> counted".
check_counted() {
    python3 -I - "$1/inventory.json" "$2" "$3" <<'EOF'
import json, sys
doc = json.load(open(sys.argv[1]))
ops, threads = int(sys.argv[2]), int(sys.argv[3])
lanes = doc.get("observation", {}).get("lane", None)
if lanes != "native":
    sys.exit(f"lane is {lanes!r}, want native")
soft = [m.get("id") for m in doc.get("modules", [])
        if any("softhsm" in str(p).lower() or "libsofthsm2" in str(p)
               for p in m.get("paths", []))]
if len(soft) != 1:
    sys.exit(f"want exactly 1 softhsm module, have {len(soft)}")
edges = [e for e in doc.get("edges", []) if e.get("module") == soft[0]]
if len(edges) != 1:
    sys.exit(f"want exactly 1 softhsm edge, have {len(edges)}")
entries = edges[0].get("entries", {})
state = entries.get("coverage", {}).get("state")
want = ops + 2 * threads + 1
if state != "counted":
    sys.exit(f"edge state is {state!r}, want counted")
if entries.get("count") != want:
    sys.exit(f"edge count {entries.get('count')} != {want} (ops={ops} threads={threads})")
if entries.get("saturated"):
    sys.exit("edge saturated")
print(f"{want} counted")
EOF
}

# check_witnessed DIR: the off-arm gate. Exactly one SoftHSM2 edge reading
# witnessed. Prints "none witnessed".
check_witnessed() {
    python3 -I - "$1/inventory.json" <<'EOF'
import json, sys
doc = json.load(open(sys.argv[1]))
lanes = doc.get("observation", {}).get("lane", None)
if lanes != "native":
    sys.exit(f"lane is {lanes!r}, want native")
soft = [m.get("id") for m in doc.get("modules", [])
        if any("softhsm" in str(p).lower() or "libsofthsm2" in str(p)
               for p in m.get("paths", []))]
if len(soft) != 1:
    sys.exit(f"want exactly 1 softhsm module, have {len(soft)}")
edges = [e for e in doc.get("edges", []) if e.get("module") == soft[0]]
if len(edges) != 1:
    sys.exit(f"want exactly 1 softhsm edge, have {len(edges)}")
state = edges[0].get("entries", {}).get("coverage", {}).get("state")
if state != "witnessed":
    sys.exit(f"edge state is {state!r}, want witnessed")
print("none witnessed")
EOF
}

# check_native_lane DIR: the unrelated-cell gate. The idle anchor makes no
# calls, so no counted edge is owed; the lane must be native and clean.
check_native_lane() {
    python3 -I - "$1/inventory.json" <<'EOF'
import json, sys
doc = json.load(open(sys.argv[1]))
lanes = doc.get("observation", {}).get("lane", None)
if lanes != "native":
    sys.exit(f"lane is {lanes!r}, want native")
print("none none")
EOF
}

# run_call_sample CELL ARM ROUND: one gated mt_count window under an
# observed (on/off) or unobserved capture. Any gate failure fails the
# campaign; only a persistently hot host refuses it (exit 3).
run_call_sample() {
    rs_cell=$1 rs_arm=$2 rs_round=$3
    case $rs_cell in
        relevant-call-t1) rs_threads=1 rs_pad=0 rs_cpus=$WCPUS_T1 ;;
        relevant-call-t4) rs_threads=4 rs_pad=0 rs_cpus=$WCPUS_T4 ;;
        relevant-call-t12) rs_threads=12 rs_pad=0 rs_cpus=$WCPUS_T12 ;;
        relevant-call-t12-nolock) rs_threads=12 rs_pad=1 rs_cpus=$WCPUS_T12 ;;
    esac
    case $rs_arm in
        on) rs_bin=$CAND_BIN ;;
        off) rs_bin=$BASE_BIN ;;
        unobserved) rs_bin= ;;
    esac
    SAMPLE_SEQ=$((SAMPLE_SEQ + 1))
    S=$WORK/sample-$(printf '%03d' "$SAMPLE_SEQ")-$rs_cell-$rs_arm-r$rs_round
    # 0700 regardless of umask: the observer refuses a group-writable -o dir.
    mkdir -m 0700 -p "$S" || die "sample dir"
    echo "--- sample $SAMPLE_SEQ: $rs_cell $rs_arm round $rs_round ---"
    wait_cool || refuse "host stayed hot (load gates $MAX_LOAD1/$MAX_LOAD5, $COOLDOWN s)"
    record_load "$S/load.txt" start
    start_mt "$S" "$rs_threads" "$rs_pad" "$rs_cpus" || return 1
    if [ -n "$rs_bin" ]; then
        start_observer "$S" "$WPID_PID" "$rs_bin" || return 1
        rs_lane=$(lane_mechanism "$S/observer.stderr")
        case $rs_lane in multi|singles) : ;; *)
            echo "unparseable lane mechanism in $S/observer.stderr" >&2; return 1 ;;
        esac
        rs_bpf_names_before=$(bpf_entry_names) || { echo "bpf names before-read failed" >&2; return 1; }
        [ -n "$rs_bpf_names_before" ] || { echo "no entry programs attached" >&2; return 1; }
        rs_bpf_before=$(bpf_entry_totals) || { echo "bpf before-read failed" >&2; return 1; }
    else
        rs_lane=none
    fi
    touch "$S/gate" || return 1
    if wait "$WPID"; then WPID=; else rs_status=$?; WPID=; echo "workload exited $rs_status" >&2; return 1; fi
    rs_totals=$(mt_totals "$S/workload.log" "$rs_threads" "$rs_pad") || { echo "workload totals failed" >&2; return 1; }
    rs_ops=${rs_totals% *} rs_wall=${rs_totals#* }
    if [ -n "$rs_bin" ]; then
        rs_bpf_names_after=$(bpf_entry_names) || { echo "bpf names after-read failed" >&2; return 1; }
        [ "$rs_bpf_names_after" = "$rs_bpf_names_before" ] \
            || { echo "entry program set changed mid-sample" >&2; return 1; }
        rs_bpf_after=$(bpf_entry_totals) || { echo "bpf after-read failed" >&2; return 1; }
        rs_bns0=${rs_bpf_before% *} rs_bcnt0=${rs_bpf_before#* }
        rs_bns1=${rs_bpf_after% *} rs_bcnt1=${rs_bpf_after#* }
        [ "$rs_bns1" -ge "$rs_bns0" ] && [ "$rs_bcnt1" -ge "$rs_bcnt0" ] \
            || { echo "bpf counters went backwards" >&2; return 1; }
        rs_bpf_ns=$((rs_bns1 - rs_bns0)) rs_bpf_cnt=$((rs_bcnt1 - rs_bcnt0))
        stop_observer "$S" || return 1
        if [ "$rs_arm" = on ]; then
            rs_edge=$(check_counted "$S" "$rs_ops" "$rs_threads") || { echo "exactness gate: $rs_edge" >&2; return 1; }
            rs_expected=$((rs_ops + 2 * rs_threads + 1))
        else
            rs_edge=$(check_witnessed "$S") || { echo "witness gate: $rs_edge" >&2; return 1; }
            rs_expected=none
        fi
        rs_edge_count=${rs_edge% *} rs_edge_state=${rs_edge#* }
    else
        rs_bpf_ns=none rs_bpf_cnt=none
        rs_edge_count=none rs_edge_state=none rs_expected=none
    fi
    record_load "$S/load.txt" end
    say "SAMPLE cell=$rs_cell arm=$rs_arm round=$rs_round threads=$rs_threads ops=$rs_ops wall_ns=$rs_wall pad=$rs_pad mode=call parallel=1 lane=$rs_lane edge_count=$rs_edge_count edge_expected=$rs_expected edge_state=$rs_edge_state bpf_ns=$rs_bpf_ns bpf_cnt=$rs_bpf_cnt"
}

# run_map_sample CELL ARM ROUND: one gated-anchor capture with an unrelated
# mapping-churn window beside it (the attribution control). Unobserved runs
# the churn alone.
run_map_sample() {
    rs_cell=$1 rs_arm=$2 rs_round=$3
    case $rs_arm in
        on) rs_bin=$CAND_BIN ;;
        off) rs_bin=$BASE_BIN ;;
        unobserved) rs_bin= ;;
    esac
    SAMPLE_SEQ=$((SAMPLE_SEQ + 1))
    S=$WORK/sample-$(printf '%03d' "$SAMPLE_SEQ")-$rs_cell-$rs_arm-r$rs_round
    mkdir -m 0700 -p "$S" || die "sample dir"
    echo "--- sample $SAMPLE_SEQ: $rs_cell $rs_arm round $rs_round ---"
    wait_cool || refuse "host stayed hot (load gates $MAX_LOAD1/$MAX_LOAD5, $COOLDOWN s)"
    record_load "$S/load.txt" start
    if [ -n "$rs_bin" ]; then
        "$WORK/bin/gated" "$MODULE" 0 0 "$S/gate-never" > "$S/anchor.log" 2>&1 &
        APID=$!
        rs_end=$(( $(date +%s) + 60 ))
        while ! grep -q "^READY" "$S/anchor.log" 2>/dev/null; do
            kill -0 "$APID" 2>/dev/null || { echo "anchor died:" >&2; cat "$S/anchor.log" >&2; return 1; }
            [ "$(date +%s)" -lt "$rs_end" ] || { echo "anchor never READY" >&2; return 1; }
            sleep 0.05
        done
        start_observer "$S" "$APID" "$rs_bin" || return 1
        rs_lane=$(lane_mechanism "$S/observer.stderr")
        case $rs_lane in multi|singles) : ;; *)
            echo "unparseable lane mechanism in $S/observer.stderr" >&2; return 1 ;;
        esac
        rs_bpf_names_before=$(bpf_entry_names) || { echo "bpf names before-read failed" >&2; return 1; }
        [ -n "$rs_bpf_names_before" ] || { echo "no entry programs attached" >&2; return 1; }
        rs_bpf_before=$(bpf_entry_totals) || { echo "bpf before-read failed" >&2; return 1; }
    else
        rs_lane=none
    fi
    "$WORK/bin/map_churn" "$WORK/unrelated.bin" "$OPS" mmap > "$S/churn.log" 2>&1 \
        || { echo "churn window failed" >&2; return 1; }
    rs_totals=$(python3 -I - "$S/churn.log" "$OPS" <<'EOF'
import sys
path, ops = sys.argv[1], int(sys.argv[2])
for line in open(path):
    if not line.startswith("MAP_CHURN "):
        continue
    fields = dict(token.split("=", 1) for token in line.split()[1:])
    if int(fields["ops"]) != ops or fields["mode"] != "mmap" or int(fields["wall_ns"]) <= 0:
        sys.exit(1)
    print(f"{fields['ops']} {fields['wall_ns']}")
    sys.exit(0)
sys.exit(1)
EOF
    ) || { echo "churn totals failed" >&2; return 1; }
    rs_ops=${rs_totals% *} rs_wall=${rs_totals#* }
    if [ -n "$rs_bin" ]; then
        rs_bpf_names_after=$(bpf_entry_names) || { echo "bpf names after-read failed" >&2; return 1; }
        [ "$rs_bpf_names_after" = "$rs_bpf_names_before" ] \
            || { echo "entry program set changed mid-sample" >&2; return 1; }
        rs_bpf_after=$(bpf_entry_totals) || { echo "bpf after-read failed" >&2; return 1; }
        rs_bns0=${rs_bpf_before% *} rs_bcnt0=${rs_bpf_before#* }
        rs_bns1=${rs_bpf_after% *} rs_bcnt1=${rs_bpf_after#* }
        [ "$rs_bns1" -ge "$rs_bns0" ] && [ "$rs_bcnt1" -ge "$rs_bcnt0" ] \
            || { echo "bpf counters went backwards" >&2; return 1; }
        rs_bpf_ns=$((rs_bns1 - rs_bns0)) rs_bpf_cnt=$((rs_bcnt1 - rs_bcnt0))
        stop_observer "$S" || return 1
        rs_edge=$(check_native_lane "$S") || { echo "lane gate: $rs_edge" >&2; return 1; }
        kill -TERM "$APID" 2>/dev/null || true
        wait "$APID" 2>/dev/null || true
        APID=
        rs_edge_count=none rs_edge_state=none rs_expected=none
    else
        rs_bpf_ns=none rs_bpf_cnt=none
        rs_edge_count=none rs_edge_state=none rs_expected=none
    fi
    record_load "$S/load.txt" end
    say "SAMPLE cell=$rs_cell arm=$rs_arm round=$rs_round threads=1 ops=$rs_ops wall_ns=$rs_wall pad=0 mode=mmap parallel=1 lane=$rs_lane edge_count=$rs_edge_count edge_expected=$rs_expected edge_state=$rs_edge_state bpf_ns=$rs_bpf_ns bpf_cnt=$rs_bpf_cnt"
}

first_cell=1
for cell in $CELLS; do
    if [ "$first_cell" = 1 ]; then
        first_cell=0
    else
        echo "--- settling before cell $cell ---"
        wait_settle || refuse "host never settled below load1 2.0 ($COOLDOWN s)"
    fi
    round=1
    while [ "$round" -le "$ROUNDS" ]; do
        if [ $((round % 2)) -eq 1 ]; then
            arms="on off off on"
        else
            arms="off on on off"
        fi
        for arm in $arms; do
            case $cell in
                unrelated-mmap) run_map_sample "$cell" "$arm" "$round" || exit 1 ;;
                *) run_call_sample "$cell" "$arm" "$round" || exit 1 ;;
            esac
        done
        case $cell in
            unrelated-mmap) run_map_sample "$cell" unobserved "$round" || exit 1 ;;
            *) run_call_sample "$cell" unobserved "$round" || exit 1 ;;
        esac
        round=$((round + 1))
    done
done

echo "=== results ==="
python3 -I scripts/bench-count-overhead-analyze.py "$LOG" || exit 1
echo "=== bench-count-overhead: DONE ($LOG) ==="
