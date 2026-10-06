#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# bench-stagea-overhead.sh — Task 1d ABBA: Stage A continuity-hook overhead.
#
# Method: a self-timed file-mapping churn workload (scripts/fixtures/map_churn.c:
# tight mmap/munmap or mremap loops, CLOCK_MONOTONIC around the loop only) runs
# beside a live `p11scope profile --pid` capture of an idle SoftHSM2 anchor,
# with the Stage A hooks attached (default) or refused
# (P11SCOPE_T3A_DISABLE_HOOKS=1, the test-only 1d toggle: same binary, only the
# three fentry hooks differ). RELEVANT churn maps the watched provider file, so
# each event runs the hook's full per-(process,file) path; UNRELATED churn maps
# a private temp file, so each event costs one WATCHED_FILES hash miss. The
# churn process makes no PKCS#11 calls, so no entry/return probe fires for it:
# the with/without delta is exactly the three hooks (uprobe_mmap,
# uprobe_munmap, copy_vma).
#
# Cells (2 arms x ROUNDS rounds of ABBA/BAAB-interleaved samples each):
#   relevant-mmap / unrelated-mmap (ROUNDS_MMAP, default 3)
#   relevant-mremap / unrelated-mremap (ROUNDS_MREMAP, default 2)
#   relevant-mmap-p8 / unrelated-mmap-p8: PARALLEL (default 8) concurrent
#   churn workers, aggregate ns/op (ROUNDS_PARALLEL, default 2)
# Interleaving is ABBA within a round (round 1: on off off on) with the
# starting arm alternating per round, so linear host drift cannot masquerade
# as an arm difference.
#
# Per-sample gates (any failure fails the campaign immediately; nothing is
# excluded silently): quiet-host load gate (load1 <= MAX_LOAD1, default 4, no
# cargo/rustc; bounded COOLDOWN, default 300 s, else the campaign is refused),
# anchor READY, observer attach line with >0 probes and no "attach failed",
# bpftool hook presence (exactly the 3 p11_inst_vma_* programs on, none off),
# exactly this observer's 3 attached hook links on (none off; P2-3: loaded
# programs alone would certify an attach failure), a watched file on (none
# off), workload-consistent hook execution on (>= 1 event per churn op,
# positive run time, within 4x above — a zero delta fails), exact churn op
# count and mode, observer exit 0, profile.json parses with
# evidence.attached_probes > 0. BPF run-time deltas (kernel.bpf_stats_enabled,
# set for the campaign and restored after) corroborate the workload-side
# numbers independently. The campaign pre-declares a manifest
# ($WORK/campaign.manifest.json: expected cells, rounds, workload params)
# before the first sample and closes the log with a DONE marker; the verdict
# math lives in scripts/bench-stagea-overhead-analyze.py, which also runs
# standalone on the campaign log with --manifest and rejects any campaign
# that does not match its manifest or lacks completion.
#
# Usage: flock "$LOCK" scripts/bench-stagea-overhead.sh [--self-test]
# The script refuses unless an ancestor holds LOCK (default
# /var/tmp/p11scope-ws-tmp/privileged.lock), the tree is clean, and no
# p11_inst_* programs or p11scope processes are already live (another capture's
# hooks would charge both arms). Run as a user with passwordless sudo; the
# observer, bpftool and sysctl go through sudo -n, everything else runs
# unprivileged. Environment: CELLS (default: all six), OPS (default 1000000,
# even for mremap), PARALLEL, ROUNDS_MMAP, ROUNDS_MREMAP, ROUNDS_PARALLEL,
# MAX_LOAD1, COOLDOWN, DURATION (default 60), ATTACH_TIMEOUT_S (default 60),
# MODULE (default the system SoftHSM2), CHURN_CPUS (default unset: unpinned),
# LOCK, TMPDIR (must be a disk filesystem; the campaign keeps per-sample
# evidence under its work dir).
set -eu
cd "$(dirname "$0")/.."
REPO=$PWD
. scripts/lib.sh

MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
OPS=${OPS:-1000000}
PARALLEL=${PARALLEL:-8}
ROUNDS_MMAP=${ROUNDS_MMAP:-3}
ROUNDS_MREMAP=${ROUNDS_MREMAP:-2}
ROUNDS_PARALLEL=${ROUNDS_PARALLEL:-2}
CELLS=${CELLS:-relevant-mmap unrelated-mmap relevant-mremap unrelated-mremap relevant-mmap-p8 unrelated-mmap-p8}
MAX_LOAD1=${MAX_LOAD1:-4}
COOLDOWN=${COOLDOWN:-300}
DURATION=${DURATION:-60}
ATTACH_TIMEOUT_S=${ATTACH_TIMEOUT_S:-60}
CHURN_CPUS=${CHURN_CPUS:-}
ATTACH_MARKER="p11scope: capturing: "
KIND=p11scope-control-plane
WORK=
APID=
SPID=
KIND_PAUSED=0
BPF_STATS_BEFORE=
FIX=scripts/fixtures

say() {
    echo "$*"
    echo "$*" >> "$LOG"
}

die() {
    echo "bench-stagea-overhead: $*" >&2
    exit 1
}

refuse() {
    echo "bench-stagea-overhead: REFUSED: $*" >&2
    exit 3
}

is_positive_int() {
    case $1 in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -gt 0 ]
}

# write_manifest: pre-declares the campaign for the analyzer (P2-4): every
# expected cell with its rounds and workload parameters, the ABBA
# arms-per-round, hook events per op, and the DONE completion marker. Runs
# before the first sample; the analyzer rejects any campaign that does not
# match it or lacks the DONE line. Writes $WORK/campaign.manifest.json.
write_manifest() {
    CELLS="$CELLS" OPS="$OPS" PARALLEL="$PARALLEL" ROUNDS_MMAP="$ROUNDS_MMAP" \
    ROUNDS_MREMAP="$ROUNDS_MREMAP" ROUNDS_PARALLEL="$ROUNDS_PARALLEL" \
    python3 -I - > "$WORK/campaign.manifest.json" <<'EOF' || die "manifest write failed"
import json, os
cells = {}
for cell in os.environ["CELLS"].split():
    if cell in ("relevant-mmap", "unrelated-mmap"):
        rounds, mode, parallel = int(os.environ["ROUNDS_MMAP"]), "mmap", 1
    elif cell in ("relevant-mremap", "unrelated-mremap"):
        rounds, mode, parallel = int(os.environ["ROUNDS_MREMAP"]), "mremap", 1
    elif cell in ("relevant-mmap-p8", "unrelated-mmap-p8"):
        rounds, mode, parallel = (
            int(os.environ["ROUNDS_PARALLEL"]), "mmap", int(os.environ["PARALLEL"]))
    else:
        raise SystemExit(f"unknown cell {cell}")
    ops = int(os.environ["OPS"]) * parallel
    cells[cell] = {"rounds": rounds, "ops": ops, "mode": mode, "parallel": parallel}
print(json.dumps({"cells": cells, "arms_per_round": 4, "events_per_op": 2,
                  "completion": {"marker": "DONE"}}))
EOF
}

if [ "${1-}" = "--self-test" ]; then
    [ "$#" -eq 1 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
    # Unprivileged: churn fixture compile + exact-count smokes + usage
    # refusals + the analyzer self-test. No BPF, no sudo, no observer, no
    # build of the workspace.
    SELF_TEST_WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-stagea-selftest-XXXXXX")
    trap 'rm -rf "$SELF_TEST_WORK"' EXIT INT TERM
    command -v gcc >/dev/null || { echo "self-test: gcc required" >&2; exit 1; }
    command -v python3 >/dev/null || { echo "self-test: python3 required" >&2; exit 1; }
    gcc -O2 -Wall -Wextra -Werror -o "$SELF_TEST_WORK/map_churn" "$FIX/map_churn.c" \
        || { echo "self-test: map_churn does not compile" >&2; exit 1; }
    head -c 8192 /dev/zero > "$SELF_TEST_WORK/f.bin" 2>/dev/null \
        || { echo "self-test: cannot write a temp file" >&2; exit 1; }
    ST_LINE=$("$SELF_TEST_WORK/map_churn" "$SELF_TEST_WORK/f.bin" 2000 mmap) \
        || { echo "self-test: mmap smoke failed" >&2; exit 1; }
    case $ST_LINE in "MAP_CHURN ops=2000 wall_ns="*" mode=mmap") : ;; *)
        echo "self-test: bad mmap line: $ST_LINE" >&2; exit 1 ;;
    esac
    ST_LINE=$("$SELF_TEST_WORK/map_churn" "$SELF_TEST_WORK/f.bin" 2000 mremap) \
        || { echo "self-test: mremap smoke failed" >&2; exit 1; }
    case $ST_LINE in "MAP_CHURN ops=2000 wall_ns="*" mode=mremap") : ;; *)
        echo "self-test: bad mremap line: $ST_LINE" >&2; exit 1 ;;
    esac
    if "$SELF_TEST_WORK/map_churn" "$SELF_TEST_WORK/f.bin" 2000 bogus >/dev/null 2>&1; then
        echo "self-test: bad mode accepted" >&2; exit 1
    fi
    if "$SELF_TEST_WORK/map_churn" "$SELF_TEST_WORK/f.bin" 2001 mremap >/dev/null 2>&1; then
        echo "self-test: odd mremap ops accepted" >&2; exit 1
    fi
    if "$SELF_TEST_WORK/map_churn" "$SELF_TEST_WORK/no-such-file" 10 mmap >/dev/null 2>&1; then
        echo "self-test: missing file accepted" >&2; exit 1
    fi
    CELLS="relevant-mmap unrelated-mmap-p8" OPS=1000 PARALLEL=8 ROUNDS_MMAP=3 \
    ROUNDS_MREMAP=2 ROUNDS_PARALLEL=2 WORK="$SELF_TEST_WORK" write_manifest \
        || { echo "self-test: manifest write failed" >&2; exit 1; }
    python3 -I - "$SELF_TEST_WORK/campaign.manifest.json" <<'EOF' \
        || { echo "self-test: bad manifest" >&2; exit 1; }
import json, sys
doc = json.load(open(sys.argv[1]))
assert set(doc["cells"]) == {"relevant-mmap", "unrelated-mmap-p8"}, doc
assert doc["cells"]["relevant-mmap"] == {
    "rounds": 3, "ops": 1000, "mode": "mmap", "parallel": 1}, doc
assert doc["cells"]["unrelated-mmap-p8"] == {
    "rounds": 2, "ops": 8000, "mode": "mmap", "parallel": 8}, doc
assert doc["arms_per_round"] == 4 and doc["events_per_op"] == 2, doc
assert doc["completion"] == {"marker": "DONE"}, doc
EOF
    python3 -I scripts/bench-stagea-overhead-analyze.py --self-test \
        || { echo "self-test: analyzer self-test failed" >&2; exit 1; }
    echo "bench-stagea-overhead self-test: OK"
    exit 0
fi
[ "$#" -eq 0 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }

for knob in OPS PARALLEL ROUNDS_MMAP ROUNDS_MREMAP ROUNDS_PARALLEL COOLDOWN DURATION ATTACH_TIMEOUT_S; do
    eval "value=\$$knob"
    is_positive_int "$value" || { echo "usage: $knob is a positive integer" >&2; exit 2; }
done
[ $((OPS % 2)) -eq 0 ] || { echo "usage: OPS is even (mremap ping-pong)" >&2; exit 2; }
for cell in $CELLS; do
    case $cell in
        relevant-mmap|unrelated-mmap|relevant-mremap|unrelated-mremap|relevant-mmap-p8|unrelated-mmap-p8) : ;;
        *) echo "usage: unknown cell $cell" >&2; exit 2 ;;
    esac
done

# The observer refuses an output directory below any group- or other-writable
# ancestor, which a checkout under a 0775 home tree has, so the campaign works
# in a private directory under TMPDIR. It is kept for the numbers.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-bench-stagea-XXXXXX")
LOG=$WORK/campaign.log
chmod 0700 "$WORK"
echo "work: $WORK"

cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$APID" ] || kill "$APID" 2>/dev/null || true
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || true
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
if [ -n "$CHURN_CPUS" ]; then
    command -v taskset >/dev/null || die "taskset required for CHURN_CPUS"
fi
test -f "$MODULE" || die "SoftHSM2 not installed at $MODULE"
[ "$(id -u)" -ne 0 ] || die "run as a non-root user with passwordless sudo"
sudo -n true 2>/dev/null || die "passwordless sudo required"

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

# Another capture's hooks would charge both arms equally and flatten the
# comparison, so a live p11scope or live p11_inst_* programs refuse the run.
if pgrep -x p11scope >/dev/null 2>&1; then
    refuse "a p11scope process is already running"
fi
if sudo -n bpftool prog show 2>/dev/null | grep -q "p11_inst_vma_"; then
    refuse "p11_inst_vma_* programs are already attached"
fi
[ -z "$(git status --porcelain -- . ':!target')" ] || refuse "the tree is not clean"

build_processes() {
    cat /proc/[0-9]*/comm 2>/dev/null | grep -cxE 'cargo|rustc'
}

host_hot() {
    awk -v max="$1" '{exit !($1 > max)}' /proc/loadavg
}

# wait_cool: bounded quiet-host wait before every sample (the previous
# sample's observer and churn heat the host). False when the host never
# cools: the campaign is refused, never measured hot.
wait_cool() {
    waited=0
    while host_hot "$MAX_LOAD1" || [ "$(build_processes)" != 0 ]; do
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

observer_attach_count() {
    sed -n "s/.*p11scope: capturing: \([0-9][0-9]*\) probe.*/\1/p" "$1" 2>/dev/null | tail -n 1
}

wait_for_observer_attach() {
    wfoa_end=$(( $(date +%s) + $2 ))
    while :; do
        if grep -Fq "$ATTACH_MARKER" "$1" 2>/dev/null; then
            wfoa_count=$(observer_attach_count "$1")
            case $wfoa_count in ''|*[!0-9]*)
                echo "unparseable attach count in $1" >&2
                return 1
                ;;
            esac
            if [ "$wfoa_count" -le 0 ]; then
                echo "observer attached 0 probes: $1" >&2
                return 1
            fi
            return 0
        fi
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            echo "observer exited before attach completed: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        fi
        [ "$(date +%s)" -lt "$wfoa_end" ] || {
            echo "observer never reported attach completion within $2s: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        }
        sleep 0.05
    done
}

# hook_prog_count: live p11_inst_vma_* programs system-wide (the preflight
# proved zero, so the on-arm sample must read exactly 3 and off exactly 0).
hook_prog_count() {
    sudo -n bpftool prog show 2>/dev/null | grep -c "p11_inst_vma_" || true
}

# hook_link_count: tracing links attached to the three p11_inst_vma_*
# programs (P2-3: loaded programs alone prove nothing — an attach failure
# detaches links while leaving programs loaded — so the on-arm sample must
# read exactly 3 attached links and off exactly 0; the preflight proved
# zero, so these links belong to this observer). Prints the count; fails
# when bpftool output is unusable.
hook_link_count() {
    sudo -n bpftool -j prog show 2>/dev/null > "$WORK/bpf-prog.json" || return 1
    sudo -n bpftool -j link show 2>/dev/null > "$WORK/bpf-link.json" || return 1
    python3 -I - "$WORK/bpf-prog.json" "$WORK/bpf-link.json" <<'EOF'
import json, sys
try:
    progs = json.load(open(sys.argv[1]))
    links = json.load(open(sys.argv[2]))
except Exception:
    sys.exit(1)
want = {"p11_inst_vma_map", "p11_inst_vma_unmap", "p11_inst_vma_copy"}
ids = {p.get("id") for p in progs if p.get("name") in want}
if not ids:
    print(0)
elif len(ids) != 3:
    sys.exit(1)
else:
    print(sum(1 for link in links if link.get("prog_id") in ids))
EOF
}

# watched_file_count: entries in this observer's WATCHED_FILES map (P2-3:
# hooks without a watched file never take the per-(process,file) path, so
# the on-arm sample must read at least 1 and off exactly 0; the preflight
# proved no p11scope was live, so the map is this observer's). Prints the
# count; a missing map reads 0.
watched_file_count() {
    sudo -n bpftool -j map show 2>/dev/null | python3 -I -c '
import json, subprocess, sys
try:
    maps = json.load(sys.stdin)
except Exception:
    sys.exit(1)
ids = [m["id"] for m in maps if m.get("name") == "WATCHED_FILES"]
if not ids:
    print(0)
    sys.exit(0)
if len(ids) != 1:
    sys.exit(1)
dumped = subprocess.run(
    ["sudo", "-n", "bpftool", "-j", "map", "dump", "id", str(ids[0])],
    capture_output=True, text=True)
if dumped.returncode != 0:
    sys.exit(1)
try:
    entries = json.loads(dumped.stdout or "[]")
except Exception:
    sys.exit(1)
print(len(entries) if isinstance(entries, list) else 0)
'
}

# bpf_hook_totals: "<run_time_ns sum> <run_cnt sum>" over the three hooks
# (kernel.bpf_stats_enabled=1 for the campaign). Fails unless all three are
# present with counters.
bpf_hook_totals() {
    sudo -n bpftool -j prog show 2>/dev/null | python3 -I -c '
import json, sys
try:
    progs = json.load(sys.stdin)
except Exception:
    sys.exit(1)
want = {"p11_inst_vma_map", "p11_inst_vma_unmap", "p11_inst_vma_copy"}
ns, cnt, seen = 0, 0, set()
for prog in progs:
    if prog.get("name") in want:
        seen.add(prog["name"])
        ns += prog.get("run_time_ns", 0)
        cnt += prog.get("run_cnt", 0)
if seen != want:
    sys.exit(1)
print(f"{ns} {cnt}")
'
}

echo "=== build ==="
scripts/cargo.sh "+$(cat .release-rust-version)" build --locked --release --workspace
DISCOVER=./target/release/p11scope-discover
P11SCOPE=$REPO/target/release/p11scope
test -x "$P11SCOPE" || die "release observer missing"
mkdir -m 0700 -p "$WORK/bin"
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
softhsm2-util --init-token --free --label bench-stagea --so-pin 1234 --pin 1234 >/dev/null \
    || die "token init failed"

echo "=== discover ==="
"$DISCOVER" --module "$MODULE" -o "$WORK/manifest.json" || die "discover failed"

echo "=== machine ==="
KERNEL=$(uname -r)
CPU=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
COMMIT=$(git rev-parse HEAD)
BIN_SHA=$(sha256sum "$P11SCOPE" | cut -d' ' -f1)
echo "kernel: $KERNEL"
echo "cpu: $CPU"
echo "commit: $COMMIT"
echo "binary: $BIN_SHA"
echo "cells: $CELLS"
echo "ops: $OPS parallel workers: $PARALLEL"
say "MACHINE kernel=$KERNEL cpu=$CPU nproc=$(nproc) date=$(date -u +%FT%TZ) host=$(uname -n)"
say "BINARY path=$P11SCOPE sha256=$BIN_SHA commit=$COMMIT"
write_manifest
echo "campaign manifest: $WORK/campaign.manifest.json"

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

# run_churn FILE OPS MODE PARALLEL LOGDIR: appends worker MAP_CHURN lines to
# LOGDIR/churn.log, fails unless every worker ran exactly OPS in MODE.
run_churn() {
    rc_churn_file=$1 rc_churn_ops=$2 rc_churn_mode=$3 rc_churn_n=$4 rc_churn_dir=$5
    rc_churn_i=1 rc_churn_pids=
    while [ "$rc_churn_i" -le "$rc_churn_n" ]; do
        if [ -n "$CHURN_CPUS" ]; then
            taskset -c "$CHURN_CPUS" "$WORK/bin/map_churn" \
                "$rc_churn_file" "$rc_churn_ops" "$rc_churn_mode" \
                > "$rc_churn_dir/churn.log.$rc_churn_i" 2>&1 &
        else
            "$WORK/bin/map_churn" "$rc_churn_file" "$rc_churn_ops" "$rc_churn_mode" \
                > "$rc_churn_dir/churn.log.$rc_churn_i" 2>&1 &
        fi
        rc_churn_pids="$rc_churn_pids $!"
        rc_churn_i=$((rc_churn_i + 1))
    done
    rc_churn_fail=0
    for pid in $rc_churn_pids; do
        wait "$pid" || rc_churn_fail=1
    done
    cat "$rc_churn_dir"/churn.log.* > "$rc_churn_dir/churn.log"
    [ "$rc_churn_fail" -eq 0 ] || return 1
    python3 -I - "$rc_churn_dir/churn.log" "$rc_churn_ops" "$rc_churn_mode" "$rc_churn_n" <<'EOF'
import sys
path, ops, mode, workers = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
seen = 0
for line in open(path):
    if not line.startswith("MAP_CHURN "):
        continue
    fields = dict(token.split("=", 1) for token in line.split()[1:])
    if int(fields["ops"]) != ops or fields["mode"] != mode or int(fields["wall_ns"]) <= 0:
        sys.exit(1)
    seen += 1
sys.exit(0 if seen == workers else 1)
EOF
}

# churn_totals LOGDIR: "<ops sum> <wall_ns sum>" over the worker lines.
churn_totals() {
    python3 -I - "$1/churn.log" <<'EOF'
import sys
ops = wall = 0
for line in open(sys.argv[1]):
    if not line.startswith("MAP_CHURN "):
        continue
    fields = dict(token.split("=", 1) for token in line.split()[1:])
    ops += int(fields["ops"])
    wall += int(fields["wall_ns"])
print(f"{ops} {wall}")
EOF
}

# run_sample CELL ARM ROUND: one gated anchor + one observer + one churn
# window. Any gate failure fails the campaign; only a persistently hot host
# refuses it (exit 3).
run_sample() {
    rs_cell=$1 rs_arm=$2 rs_round=$3
    case $rs_cell in
        relevant-mmap) rs_file=$MODULE rs_mode=mmap rs_n=1 ;;
        unrelated-mmap) rs_file=$WORK/unrelated.bin rs_mode=mmap rs_n=1 ;;
        relevant-mremap) rs_file=$MODULE rs_mode=mremap rs_n=1 ;;
        unrelated-mremap) rs_file=$WORK/unrelated.bin rs_mode=mremap rs_n=1 ;;
        relevant-mmap-p8) rs_file=$MODULE rs_mode=mmap rs_n=$PARALLEL ;;
        unrelated-mmap-p8) rs_file=$WORK/unrelated.bin rs_mode=mmap rs_n=$PARALLEL ;;
    esac
    SAMPLE_SEQ=$((SAMPLE_SEQ + 1))
    S=$WORK/sample-$(printf '%03d' "$SAMPLE_SEQ")-$rs_cell-$rs_arm-r$rs_round
    # 0700 regardless of umask: the observer refuses a group-writable -o dir.
    mkdir -m 0700 -p "$S" || die "sample dir"
    echo "--- sample $SAMPLE_SEQ: $rs_cell $rs_arm round $rs_round ---"
    wait_cool || refuse "host stayed hot (load gate $MAX_LOAD1, $COOLDOWN s)"
    record_load "$S/load.txt" start
    "$WORK/bin/gated" "$MODULE" 0 0 "$S/gate-never" > "$S/anchor.log" 2>&1 &
    APID=$!
    rs_end=$(( $(date +%s) + 60 ))
    while ! grep -q "^READY" "$S/anchor.log" 2>/dev/null; do
        kill -0 "$APID" 2>/dev/null || { echo "anchor died:" >&2; cat "$S/anchor.log" >&2; return 1; }
        [ "$(date +%s)" -lt "$rs_end" ] || { echo "anchor never READY" >&2; return 1; }
        sleep 0.05
    done
    if [ "$rs_arm" = off ]; then
        sudo -n --preserve-env=SOFTHSM2_CONF env P11SCOPE_T3A_DISABLE_HOOKS=1 "$P11SCOPE" profile \
            --manifest "$WORK/manifest.json" --pid "$APID" \
            --mode profile --duration "$DURATION" -o "$S/profile.json" \
            > "$S/observer.log" 2> "$S/observer.stderr" &
    else
        sudo -n --preserve-env=SOFTHSM2_CONF "$P11SCOPE" profile \
            --manifest "$WORK/manifest.json" --pid "$APID" \
            --mode profile --duration "$DURATION" -o "$S/profile.json" \
            > "$S/observer.log" 2> "$S/observer.stderr" &
    fi
    SPID=$!
    wait_for_observer_attach "$S/observer.stderr" "$ATTACH_TIMEOUT_S" || return 1
    if grep -q "attach failed" "$S/observer.stderr"; then
        echo "ATTACH FAILURE in $S:" >&2
        cat "$S/observer.stderr" >&2
        return 1
    fi
    rs_hooks=$(hook_prog_count)
    if [ "$rs_arm" = on ]; then
        [ "$rs_hooks" = 3 ] || { echo "on-arm sample has $rs_hooks hook programs, want 3" >&2; return 1; }
    else
        [ "$rs_hooks" = 0 ] || { echo "off-arm sample has $rs_hooks hook programs, want 0" >&2; return 1; }
    fi
    # P2-3: loaded programs alone prove nothing — an attach failure detaches
    # links while leaving programs loaded — so the on-arm sample must also
    # hold exactly this observer's 3 attached links and a watched file.
    rs_links=$(hook_link_count) || { echo "hook link query failed" >&2; return 1; }
    rs_watched=$(watched_file_count) || { echo "watched-file query failed" >&2; return 1; }
    if [ "$rs_arm" = on ]; then
        [ "$rs_links" = 3 ] || { echo "on-arm sample has $rs_links hook links, want 3 (loaded but unattached?)" >&2; return 1; }
        [ "$rs_watched" -ge 1 ] || { echo "on-arm sample watches $rs_watched files, want >= 1" >&2; return 1; }
    else
        [ "$rs_links" = 0 ] || { echo "off-arm sample has $rs_links hook links, want 0" >&2; return 1; }
        [ "$rs_watched" = 0 ] || { echo "off-arm sample watches $rs_watched files, want 0" >&2; return 1; }
    fi
    if [ "$rs_arm" = on ]; then
        rs_bpf_before=$(bpf_hook_totals) || { echo "bpf before-read failed" >&2; return 1; }
    fi
    run_churn "$rs_file" "$OPS" "$rs_mode" "$rs_n" "$S" || { echo "churn window failed" >&2; return 1; }
    rs_totals=$(churn_totals "$S") || { echo "churn totals failed" >&2; return 1; }
    rs_tops=${rs_totals% *} rs_twall=${rs_totals#* }
    if [ "$rs_arm" = on ]; then
        rs_bpf_after=$(bpf_hook_totals) || { echo "bpf after-read failed" >&2; return 1; }
        rs_bns0=${rs_bpf_before% *} rs_bcnt0=${rs_bpf_before#* }
        rs_bns1=${rs_bpf_after% *} rs_bcnt1=${rs_bpf_after#* }
        [ "$rs_bns1" -ge "$rs_bns0" ] && [ "$rs_bcnt1" -ge "$rs_bcnt0" ] \
            || { echo "bpf counters went backwards" >&2; return 1; }
        rs_bpf_ns=$((rs_bns1 - rs_bns0)) rs_bpf_cnt=$((rs_bcnt1 - rs_bcnt0))
        # P2-3: a zero delta would certify unattached hooks. The workload
        # runs ~2 hook events per op (map+unmap / copy+unmap), so require at
        # least one event per op and positive run time, within 4x above.
        [ "$rs_bpf_ns" -gt 0 ] || { echo "on-arm sample ran $rs_tops ops with zero hook run time" >&2; return 1; }
        [ "$rs_bpf_cnt" -ge "$rs_tops" ] || { echo "on-arm sample ran $rs_tops ops with $rs_bpf_cnt hook events (< 1/op)" >&2; return 1; }
        [ "$rs_bpf_cnt" -le $((rs_tops * 4)) ] || { echo "on-arm sample ran $rs_tops ops with $rs_bpf_cnt hook events (> 4/op)" >&2; return 1; }
    else
        rs_bpf_ns=none rs_bpf_cnt=none
    fi
    kill -INT "$SPID" 2>/dev/null || true
    if wait "$SPID"; then SPID=; else rs_status=$?; SPID=; echo "observer exited $rs_status" >&2; return 1; fi
    if grep -q "attach failed" "$S/observer.stderr"; then
        echo "ATTACH FAILURE in $S:" >&2
        cat "$S/observer.stderr" >&2
        return 1
    fi
    reclaim_root_output "$S/profile.json"
    python3 -I - "$S/profile.json" <<'EOF' || { echo "profile.json validation failed" >&2; return 1; }
import json, sys
doc = json.load(open(sys.argv[1]))
if doc.get("evidence", {}).get("attached_probes", 0) <= 0:
    sys.exit(1)
EOF
    kill -TERM "$APID" 2>/dev/null || true
    wait "$APID" 2>/dev/null || true
    APID=
    record_load "$S/load.txt" end
    say "SAMPLE cell=$rs_cell arm=$rs_arm round=$rs_round ops=$rs_tops wall_ns=$rs_twall mode=$rs_mode parallel=$rs_n bpf_ns=$rs_bpf_ns bpf_cnt=$rs_bpf_cnt"
}

rounds_for() {
    case $1 in
        relevant-mmap|unrelated-mmap) echo "$ROUNDS_MMAP" ;;
        relevant-mremap|unrelated-mremap) echo "$ROUNDS_MREMAP" ;;
        *) echo "$ROUNDS_PARALLEL" ;;
    esac
}

for cell in $CELLS; do
    rounds=$(rounds_for "$cell")
    round=1
    while [ "$round" -le "$rounds" ]; do
        if [ $((round % 2)) -eq 1 ]; then
            arms="on off off on"
        else
            arms="off on on off"
        fi
        for arm in $arms; do
            run_sample "$cell" "$arm" "$round" || exit 1
        done
        round=$((round + 1))
    done
done

say "DONE samples=$SAMPLE_SEQ"
echo "=== results ==="
python3 -I scripts/bench-stagea-overhead-analyze.py "$LOG" \
    --manifest "$WORK/campaign.manifest.json" || exit 1
echo "=== bench-stagea-overhead: DONE ($LOG) ==="
