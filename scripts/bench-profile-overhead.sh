#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# bench-profile-overhead.sh — Phase A measurement-overhead harness: A0 counter
# cost under `profile --system`.
#
# Method: the same ABBA/BAAB-interleaved two-arm comparison as
# scripts/bench-count-overhead.sh (which drives the inventory lane only).
# Here the workload is the A0 tracked churn driver (scripts/mem-churn.py)
# at RATE iterations/s under a live `profile --system` capture, and the
# arms are two prebuilt binaries: BASE_BIN (the exact pre-A0 base,
# 1df155a16) vs CAND_BIN (the A0 candidate). Same CLI, same workload,
# same attach machinery on both arms: the with/without delta is exactly
# the counter feature (60 s `-v` snapshot + R5 seal measurement).
#
# Samples interleave ABBA within a round (round 1: base cand cand base)
# with the starting arm alternating per round, so linear host drift
# cannot masquerade as an arm difference. Pairs for the analysis are
# the i-th base with the i-th cand sample of a round in log order
# (adjacent under ABBA/BAAB).
#
# Per-sample metrics (all recorded in the campaign log):
#   churn_rate   workload iterations/s from the driver's own `done` line
#                (CLOCK_MONOTONIC around the window only)
#   churn_iters  completed iterations (exactness: matches rate x wall)
#   obs_wall     observer wall seconds (start to exit)
#   peak_rss     observer peak VmRSS in KiB (2 s /proc sampler)
#   mem_lines    `p11scope: memory` stderr lines: >= 1 on cand (the end
#                line; `-v` always on), exactly 0 on base. This doubles
#                as the arm-identity check: a base that emits counter
#                lines (or a cand that emits none) fails the sample.
#   mem_live/dead  R10+R12 live/dead owner processes from the cand end
#                memory line (cand SAMPLE rows only; the sample refuses
#                when the line is missing, unparsable, or stale-named).
#   mem_dead_rows/bytes  dead-owned row counts/bytes summed over the
#                eight R10/R12 maps (cand rows only).
#   mem_sample_us  the 60 s sample cost in microseconds (cand rows only).
#
# Per-sample gates (any failure fails the campaign immediately; nothing
# is excluded silently): quiet-host load gate (load1 < MAX_LOAD1 AND
# load5 < MAX_LOAD5, no cargo/rustc; bounded COOLDOWN, else refused),
# workload `done` line with the exact requested window, observer exit 0,
# no "attach failed", the arm-identity line count above, and observer
# still attached when the churn window closes (attach ate the spare
# otherwise: lengthen OBS_SPARE, never shrink the window silently).
#
# No verdict gate lives here: A0 records the delta (harness green is the
# step-6 expectation). The < 1% target / 3% ceiling gate runs in A1 and
# B4 on longer campaigns with this script.
#
# REQUIRE_QUIET (default 1) keeps the M2 quiet-host wait (load bounds
# plus no cargo/rustc) before every sample. Set 0 only to validate the
# harness itself on a shared host: per-sample loads are still recorded
# and the delta is provisional noise, never a gate verdict.
#
# Usage: flock "$LOCK" scripts/bench-profile-overhead.sh [--self-test]
# The script refuses unless an ancestor holds LOCK (default
# /var/tmp/p11scope-ws-tmp/privileged.lock), the tree is clean, and no
# p11scope processes or p11_* BPF programs are already live (another
# capture's probes would charge both arms). Run as a user with
# passwordless sudo; the observer goes through sudo -n, everything else
# runs unprivileged. Both binaries must be prebuilt (BASE_BIN has no
# default: pass the exact pre-A0 build; builds never run during a
# measurement window) and both must be named `p11scope` (basename):
# the observer pid is resolved via `pgrep -x p11scope` under the sudo
# parentage, and a differently named binary is unresolvable (refuse).
# Environment: BASE_BIN (required), CAND_BIN
# (default ./target/release/p11scope), RATE (default 5000 iters/s,
# ~10k calls/s: an ok-iteration is open+close), FAIL_SHARE (default
# 0.2), FORK_EVERY (default 0), SECS (default 60), ROUNDS (default 1),
# OBS_SPARE (default 150: observer --duration is SECS + OBS_SPARE),
# ATTACH_TIMEOUT (default 180), MAX_LOAD1/MAX_LOAD5 (default 4),
# COOLDOWN (default 300), CHURN (default scripts/mem-churn.py), OUTDIR
# (default $TMPDIR/bench-profile-overhead-<ts>; TMPDIR must be set to a
# disk filesystem), LOCK.
set -eu
cd "$(dirname "$0")/.."
REPO=$PWD

BASE_BIN=${BASE_BIN:-}
CAND_BIN=${CAND_BIN:-$REPO/target/release/p11scope}
RATE=${RATE:-5000}
FAIL_SHARE=${FAIL_SHARE:-0.2}
FORK_EVERY=${FORK_EVERY:-0}
SECS=${SECS:-60}
ROUNDS=${ROUNDS:-1}
OBS_SPARE=${OBS_SPARE:-150}
ATTACH_TIMEOUT=${ATTACH_TIMEOUT:-180}
MAX_LOAD1=${MAX_LOAD1:-4}
MAX_LOAD5=${MAX_LOAD5:-4}
COOLDOWN=${COOLDOWN:-300}
REQUIRE_QUIET=${REQUIRE_QUIET:-1}
LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
CHURN=${CHURN:-$REPO/scripts/mem-churn.py}
TMPDIR=${TMPDIR:-}
OUTDIR=${OUTDIR:-}
READY_MARK="p11scope: capturing: "
LOG=

say() {
    echo "$*"
    echo "$*" >> "$LOG"
}

die() {
    echo "bench-profile-overhead: $*" >&2
    exit 1
}

refuse() {
    echo "bench-profile-overhead: REFUSED: $*" >&2
    exit 3
}

is_positive_int() {
    case $1 in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -gt 0 ]
}

# round_arms ROUND: sample arms in run order (ABBA on odd rounds, BAAB
# on even), echoing "base"/"cand" tokens. Same interleave as
# bench-count-overhead.sh round_arms.
round_arms() {
    if [ $(( $1 % 2 )) -eq 1 ]; then
        echo "base cand cand base"
    else
        echo "cand base base cand"
    fi
}

build_processes() {
    cat /proc/[0-9]*/comm 2>/dev/null | grep -cxE 'cargo|rustc'
}

host_hot() {
    awk -v max1="$1" -v max5="$2" '{exit !(($1 >= max1) || ($2 >= max5))}' /proc/loadavg
}

# wait_cool: bounded quiet-host wait before every sample (the previous
# sample's observer and workload heat the host). False when the host
# never cools: the campaign is refused, never measured hot.
wait_cool() {
    end=$(( $(date +%s) + COOLDOWN ))
    while host_hot "$MAX_LOAD1" "$MAX_LOAD5" || [ "$(build_processes)" -gt 0 ]; do
        [ "$(date +%s)" -ge "$end" ] && return 1
        sleep 5
    done
    return 0
}

record_load() {
    echo "load $(cat /proc/loadavg) cargo_rustc=$(build_processes)" >> "$LOG"
}

guards() {
    [ "$(id -u)" -ne 0 ] || die "run as a non-root user with passwordless sudo"
    sudo -n true 2>/dev/null || die "passwordless sudo required"
    [ -n "$BASE_BIN" ] || die "BASE_BIN is required (the exact pre-A0 build)"
    test -x "$BASE_BIN" || die "base binary missing or not executable: $BASE_BIN"
    test -x "$CAND_BIN" || die "candidate binary missing or not executable: $CAND_BIN"
    test -x "$CHURN" || die "churn driver missing or not executable: $CHURN"
    is_positive_int "$SECS" || die "SECS must be a positive integer"
    is_positive_int "$ROUNDS" || die "ROUNDS must be a positive integer"
    is_positive_int "$OBS_SPARE" || die "OBS_SPARE must be a positive integer"
    is_positive_int "$ATTACH_TIMEOUT" || die "ATTACH_TIMEOUT must be a positive integer"
    case "$REQUIRE_QUIET" in
        0|1) : ;;
        *) die "REQUIRE_QUIET must be 0 or 1" ;;
    esac
    [ -n "$TMPDIR" ] || die "TMPDIR must be set to a disk filesystem"
    [ -d "$TMPDIR" ] || die "TMPDIR is not a directory: $TMPDIR"
    [ "$(stat -f -c %T "$TMPDIR" 2>/dev/null)" != "tmpfs" ] \
        || refuse "TMPDIR $TMPDIR is memory-backed; use a disk filesystem"

    # An ancestor must hold the privileged lock: a concurrent privileged
    # test or capture would charge these samples. Run under `flock $LOCK $0`.
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

    # Another capture's probes would charge both arms equally and flatten
    # the comparison, so a live p11scope or live p11_* BPF programs refuse
    # the run.
    if pgrep -x p11scope >/dev/null 2>&1; then
        refuse "a p11scope process is already running"
    fi
    if sudo -n bpftool prog show 2>/dev/null | grep -q "p11_"; then
        refuse "p11_* BPF programs are already attached"
    fi
    [ -z "$(git status --porcelain -- . ':!target')" ] || refuse "the tree is not clean"
}

# rss_sampler OUT PID: poll /proc/PID/status every 2 s until PID dies,
# appending "rss <VmRSS> hwm <VmHWM>" (KiB). The caller resolves PID
# through the sudo parentage: matching the full command line catches
# the flock/sudo wrapper instead (mem-a0 round-1 lesson), and a global
# first-match could catch another lane's capture.
rss_sampler() {
    out=$1
    pid=$2
    # Liveness via /proc presence, never `kill -0`: the observer runs
    # as root and signal 0 fails across users on this host.
    while [ -d "/proc/$pid" ]; do
        awk '/^VmRSS:/{rss=$2} /^VmHWM:/{hwm=$2} END{if (rss != "") print "rss " rss " hwm " hwm}' \
            "/proc/$pid/status" >> "$out" 2>/dev/null || true
        sleep 2
    done
}

# cleanup_sample: refuse-path reaper for one sample. A refuse exits
# immediately, so without this the sudo'd observer and the RSS sampler
# outlive the campaign; the next campaign then refuses on the live
# capture until they end. run_sample arms this as the EXIT trap once
# the observer exists and disarms it after both are waited. The
# observer runs as root, so an unprivileged kill fails across the sudo
# boundary (sudo-rs here): signal it via sudo, preferring the resolved
# observer pid and otherwise the sudo parent's children. Empty-safe so
# a refuse before either pid exists reaps nothing.
cleanup_sample() {
    if [ -n "${obs_pid:-}" ]; then
        sudo -n kill -TERM "$obs_pid" 2>/dev/null || true
    elif [ -n "${sudo_pid:-}" ]; then
        sudo -n pkill -TERM -P "$sudo_pid" 2>/dev/null || true
    fi
    # Same-user fallback for the self-test probes (which use sudo_pid
    # as a plain sleeper pid) plus the user-owned sampler and wrapper.
    if [ -n "${sudo_pid:-}" ]; then
        kill -TERM "$sudo_pid" 2>/dev/null || true
    fi
    if [ -n "${sampler_pid:-}" ]; then
        kill "$sampler_pid" 2>/dev/null || true
    fi
}

# parse_mem_line JSON: validate one `p11scope: memory {...}` object
# against the A0 wire keys and print the A1 attribution fields:
# "mem_live=<n> mem_dead=<n> mem_dead_rows=<n> mem_dead_bytes=<n>
# mem_sample_us=<n>". Requires the round-4 names (r10_r12_live/dead,
# the eight *_dead rows, sample_us) as uints; a null or missing key
# fails, as does an exact stale key (r12_live_processes,
# r12_dead_processes). The stale check runs on parsed keys, never on
# substrings: "r10_r12_live_processes" contains "r12_live_processes".
# Fails loudly (nonzero + message); run_sample refuses the sample.
parse_mem_line() {
    python3 -I - "$1" <<'EOF'
import json, sys

try:
    obj = json.loads(sys.argv[1])
except ValueError as exc:
    sys.exit(f"parse_mem_line: invalid JSON: {exc}")
if not isinstance(obj, dict):
    sys.exit("parse_mem_line: memory line is not a JSON object")
for stale in ("r12_live_processes", "r12_dead_processes"):
    if stale in obj:
        sys.exit(f"parse_mem_line: stale key {stale} (pre-round-4 build?)")


def uint(key):
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        sys.exit(f"parse_mem_line: {key} is not a uint ({value!r})")
    return value


dead_keys = ("r10_reduced_dead", "r12_open_dead", "r12_active_ops_dead",
             "r12_next_pseudonym_dead", "r12_find_active_dead",
             "r12_pending_dead", "r12_detached_dead",
             "r12_inherited_ambiguous_dead")
rows = bytes_ = 0
for key in dead_keys:
    row = obj.get(key)
    if not isinstance(row, dict):
        sys.exit(f"parse_mem_line: {key} is not a row ({row!r})")
    for field in ("len", "bytes"):
        value = row.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            sys.exit(f"parse_mem_line: {key}.{field} is not a uint ({value!r})")
    rows += row["len"]
    bytes_ += row["bytes"]
print(f"mem_live={uint('r10_r12_live_processes')} "
      f"mem_dead={uint('r10_r12_dead_processes')} "
      f"mem_dead_rows={rows} mem_dead_bytes={bytes_} "
      f"mem_sample_us={uint('sample_us')}")
EOF
}

# run_sample DIR ARM BIN: one measured sample. Starts the observer,
# waits for the `capturing:` line, runs the churn window, waits for the
# observer to end, then gates and records. Prints the SAMPLE line on
# stdout (also appended to the log); any gate failure refuses the run.
run_sample() {
    dir=$1
    arm=$2
    bin=$3
    mkdir -p "$dir"
    obs_dur=$(( SECS + OBS_SPARE ))

    if [ "$REQUIRE_QUIET" = 1 ]; then
        wait_cool || refuse "host never cooled below $MAX_LOAD1/$MAX_LOAD5"
    fi
    # Re-check exclusivity per sample: another lane may have started a
    # capture since the campaign began, and its probes would charge
    # this sample. Never measure beside a live capture.
    if pgrep -x p11scope >/dev/null 2>&1; then
        refuse "sample $arm: a p11scope process started before this sample"
    fi
    record_load
    echo "sample arm=$arm bin=$bin sha=$(sha256sum "$bin" | cut -d' ' -f1)" >> "$LOG"

    obs_start=$(date +%s)
    # The redirects intentionally run as the invoking user (SC2024): the
    # campaign dir is user-owned and stays readable without sudo, while
    # only the observer itself runs privileged.
    # shellcheck disable=SC2086,SC2024
    sudo -n "$bin" profile --system --duration "${obs_dur}s" -v \
        -o "$dir/report.json" >"$dir/stdout.txt" 2>"$dir/stderr.txt" &
    sudo_pid=$!
    # A refuse below exits immediately: arm the reaper now, with the
    # sampler pid cleared (it still names the previous sample's reaped
    # sampler, whose pid may already be reused).
    sampler_pid=
    trap cleanup_sample EXIT
    # The observer pid, resolved through the sudo parentage (never a
    # global first-match: another lane's capture must not be sampled).
    obs_pid=
    deadline=$(( $(date +%s) + ATTACH_TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if grep -qF "$READY_MARK" "$dir/stderr.txt" 2>/dev/null; then
            obs_pid=$(pgrep -P "$sudo_pid" -x p11scope | head -n 1 || true)
            [ -n "$obs_pid" ] && break
        fi
        [ -d "/proc/$sudo_pid" ] || break
        sleep 2
    done
    grep -qF "$READY_MARK" "$dir/stderr.txt" 2>/dev/null \
        || refuse "sample $arm: no capturing line within ${ATTACH_TIMEOUT}s ($(basename "$dir"))"
    grep -q "probes attached" "$dir/stderr.txt" 2>/dev/null \
        || refuse "sample $arm: observer attached 0 probes (still waiting for a provider)"
    [ -n "$obs_pid" ] || refuse "sample $arm: observer pid unresolvable"
    attach_secs=$(( $(date +%s) - obs_start ))
    echo "sample arm=$arm attach_secs=$attach_secs obs_pid=$obs_pid" >> "$LOG"

    rss_sampler "$dir/rss.txt" "$obs_pid" &
    sampler_pid=$!

    # Every fallible step guards `set -e` and refuses loudly: a bare
    # nonzero exit here would end the campaign with no message.
    churn_rc=0
    "$CHURN" --rate "$RATE" --fail-share "$FAIL_SHARE" \
        --fork-every "$FORK_EVERY" --duration "$SECS" \
        >"$dir/churn.txt" 2>&1 || churn_rc=$?
    [ "$churn_rc" -eq 0 ] || refuse "sample $arm: churn exited $churn_rc"
    [ -d "/proc/$sudo_pid" ] \
        || refuse "sample $arm: observer ended before the churn window closed (attach ${attach_secs}s ate the ${OBS_SPARE}s spare)"

    obs_rc=0
    wait "$sudo_pid" || obs_rc=$?
    obs_end=$(date +%s)
    wait "$sampler_pid" 2>/dev/null || true
    # Both sample processes are waited: later refuses carry no orphans.
    trap - EXIT
    [ "$obs_rc" -eq 0 ] || refuse "sample $arm: observer exited $obs_rc"
    if grep -q "attach failed" "$dir/stderr.txt" 2>/dev/null; then
        refuse "sample $arm: attach failure on stderr"
    fi

    done_line=$(grep -F "mem-churn: done" "$dir/churn.txt" | tail -n 1 || true)
    [ -n "$done_line" ] || refuse "sample $arm: churn printed no done line"
    iters=$(echo "$done_line" | sed -n 's/.* iterations=\([0-9]*\) .*/\1/p')
    rate=$(echo "$done_line" | sed -n 's/.* rate=\([0-9.]*\)\/s.*/\1/p')
    [ -n "$iters" ] && [ -n "$rate" ] || refuse "sample $arm: unparsable done line"
    mem_lines=$(grep -c "p11scope: memory " "$dir/stderr.txt" || true)
    mem_fields=
    if [ "$arm" = "cand" ]; then
        [ "$mem_lines" -ge 1 ] || refuse "sample cand: no memory line (not an A0 build?)"
        # The end-of-capture line carries the full attribution: it must
        # parse against the round-4 keys, else the sample refuses (a
        # stale cand that counts lines but names old keys is no soak
        # input).
        mem_json=$(grep -F "p11scope: memory " "$dir/stderr.txt" | tail -n 1)
        mem_json=${mem_json#*p11scope: memory }
        if ! mem_fields=$(parse_mem_line "$mem_json" 2>"$dir/mem-err.txt"); then
            refuse "sample cand: memory line has no A0 keys ($(cat "$dir/mem-err.txt"))"
        fi
    else
        [ "$mem_lines" -eq 0 ] || refuse "sample base: $mem_lines memory lines (not a pre-A0 build?)"
    fi
    [ -f "$dir/rss.txt" ] || refuse "sample $arm: RSS sampler wrote nothing"
    peak_rss=$(awk '$1 == "rss" {if ($2 > max) max = $2} END{print max + 0}' "$dir/rss.txt")
    obs_wall=$(( obs_end - obs_start ))
    line="SAMPLE arm=$arm iters=$iters rate=$rate obs_wall=$obs_wall attach_secs=$attach_secs peak_rss_kb=$peak_rss mem_lines=$mem_lines dir=$(basename "$dir")"
    if [ -n "$mem_fields" ]; then
        line="$line $mem_fields"
    fi
    say "$line"
}

# analyze LOG: per-arm medians and cand-vs-base deltas over the SAMPLE
# lines. Prints the DELTA summary plus the cand-only MEM medians over
# the mem_* fields (also appended to the log). A log whose cand rows
# carry no mem_* fields (pre-round-5) prints no MEM line; a mixed log
# refuses. No verdict: the < 1% / 3% gate runs in A1 and B4.
analyze() {
    # No pipe: the pipeline exit would be tee's and mask a python
    # failure. A failed analysis refuses loudly instead.
    if ! out=$(python3 -I - "$1" <<'EOF'
import statistics, sys

base, cand = [], []
for line in open(sys.argv[1]):
    if not line.startswith("SAMPLE "):
        continue
    row = dict(part.split("=", 1) for part in line.split()[1:])
    (cand if row["arm"] == "cand" else base).append(row)

if not base or not cand:
    sys.exit("analyze: need SAMPLE lines for both arms")
if len(base) != len(cand):
    sys.exit(f"analyze: unbalanced arms base={len(base)} cand={len(cand)}")


def med(rows, key):
    return statistics.median(float(r[key]) for r in rows)


for key in ("rate", "obs_wall", "peak_rss_kb"):
    b, c = med(base, key), med(cand, key)
    delta = (c - b) / b * 100 if b else float("nan")
    print(f"DELTA {key}: base_med={b:.1f} cand_med={c:.1f} delta_pct={delta:+.2f} n={len(base)}")

mem = [r for r in cand if "mem_sample_us" in r]
if mem:
    if len(mem) != len(cand):
        sys.exit("analyze: mixed SAMPLE lines (some cand rows lack mem_* fields)")

    def mmed(key):
        return statistics.median(float(r[key]) for r in mem)

    print(f"MEM live_med={mmed('mem_live'):.1f} dead_med={mmed('mem_dead'):.1f} "
          f"dead_rows_med={mmed('mem_dead_rows'):.1f} "
          f"dead_bytes_med={mmed('mem_dead_bytes'):.1f} "
          f"sample_us_med={mmed('mem_sample_us'):.1f} n={len(mem)}")
EOF
    ); then
        refuse "analysis failed"
    fi
    printf '%s\n' "$out" | tee -a "$1"
}

# self_test: validate the SAMPLE parsing and delta math on fixture lines
# (no privileged run, no binaries). Fails loudly on any mismatch.
# Note: the trap probe below uses same-user sleepers, so it does NOT
# cover the sudo path (`sudo -n kill/pkill` for the root observer);
# that path is probed once under sudo (see the round-4 report).
self_test() {
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    cat > "$tmp/log" <<'EOF'
SAMPLE arm=base rate=1000.0 obs_wall=200 attach_secs=10 peak_rss_kb=100000 mem_lines=0 dir=r1s1 iters=60000
SAMPLE arm=cand rate=990.0 obs_wall=202 attach_secs=11 peak_rss_kb=101000 mem_lines=1 dir=r1s2 iters=59400 mem_live=3 mem_dead=12 mem_dead_rows=36 mem_dead_bytes=360 mem_sample_us=400
SAMPLE arm=cand rate=1010.0 obs_wall=198 attach_secs=9 peak_rss_kb=99000 mem_lines=1 dir=r1s3 iters=60600 mem_live=5 mem_dead=10 mem_dead_rows=30 mem_dead_bytes=300 mem_sample_us=600
SAMPLE arm=base rate=1000.0 obs_wall=200 attach_secs=10 peak_rss_kb=100000 mem_lines=0 dir=r1s4 iters=60000
EOF
    # Derived fixtures come first: analyze appends to the log it reads,
    # so anything derived after the first call would carry DELTA/MEM lines.
    strip_mem() {
        sed 's/ mem_live=[^ ]* mem_dead=[^ ]* mem_dead_rows=[^ ]* mem_dead_bytes=[^ ]* mem_sample_us=[^ ]*//'
    }
    strip_mem < "$tmp/log" > "$tmp/oldlog"
    head -n 2 "$tmp/log" > "$tmp/mixed"
    strip_mem < "$tmp/log" | tail -n 2 >> "$tmp/mixed"
    out=$(analyze "$tmp/log")
    echo "$out" | grep -q "DELTA rate: base_med=1000.0 cand_med=1000.0 delta_pct=+0.00" \
        || { echo "self-test: rate delta wrong: $out" >&2; return 1; }
    echo "$out" | grep -q "DELTA obs_wall: base_med=200.0 cand_med=200.0 delta_pct=+0.00" \
        || { echo "self-test: wall delta wrong: $out" >&2; return 1; }
    echo "$out" | grep -q "DELTA peak_rss_kb: base_med=100000.0 cand_med=100000.0 delta_pct=+0.00" \
        || { echo "self-test: rss delta wrong: $out" >&2; return 1; }
    echo "$out" | grep -q "MEM live_med=4.0 dead_med=11.0 dead_rows_med=33.0 dead_bytes_med=330.0 sample_us_med=500.0 n=2" \
        || { echo "self-test: MEM medians wrong: $out" >&2; return 1; }
    # A pre-round-5 log (cand rows without mem_* fields) still analyzes,
    # with no MEM line; a mixed log (some cand rows with, some without)
    # refuses instead of summarizing half the rows.
    old_out=$(analyze "$tmp/oldlog")
    if echo "$old_out" | grep -q "^MEM "; then
        echo "self-test: old log gained a MEM line: $old_out" >&2; return 1
    fi
    rc=0
    mixed_out=$(analyze "$tmp/mixed" 2>/dev/null) || rc=$?
    [ "$rc" -eq 3 ] || { echo "self-test: mixed log analyzed (rc=$rc, must refuse): $mixed_out" >&2; return 1; }
    # Round 5: the end memory line parses against the round-4 keys.
    mem_json='{"command":"profile","elapsed_secs":210,"r10_r12_live_processes":3,"r10_r12_dead_processes":12,"r10_reduced_dead":{"len":1,"bytes":10},"r12_open_dead":{"len":2,"bytes":20},"r12_active_ops_dead":{"len":3,"bytes":30},"r12_next_pseudonym_dead":{"len":4,"bytes":40},"r12_find_active_dead":{"len":5,"bytes":50},"r12_pending_dead":{"len":6,"bytes":60},"r12_detached_dead":{"len":7,"bytes":70},"r12_inherited_ambiguous_dead":{"len":8,"bytes":80},"sample_us":456}'
    [ "$(parse_mem_line "$mem_json")" = "mem_live=3 mem_dead=12 mem_dead_rows=36 mem_dead_bytes=360 mem_sample_us=456" ] \
        || { echo "self-test: mem line parsed wrong" >&2; return 1; }
    # Stale key names (pre-round-4) fail even on an otherwise valid line;
    # the exact-key check must not trip on the "r10_r12_" prefix.
    stale_json='{"r10_r12_live_processes":3,"r10_r12_dead_processes":12,"r12_live_processes":3,"r12_dead_processes":12,"r10_reduced_dead":{"len":0,"bytes":0},"r12_open_dead":{"len":0,"bytes":0},"r12_active_ops_dead":{"len":0,"bytes":0},"r12_next_pseudonym_dead":{"len":0,"bytes":0},"r12_find_active_dead":{"len":0,"bytes":0},"r12_pending_dead":{"len":0,"bytes":0},"r12_detached_dead":{"len":0,"bytes":0},"r12_inherited_ambiguous_dead":{"len":0,"bytes":0},"sample_us":1}'
    if parse_mem_line "$stale_json" >/dev/null 2>&1; then
        echo "self-test: stale keys parsed (must fail)" >&2; return 1
    fi
    # Null, short, and truncated shapes fail too.
    null_json='{"r10_r12_live_processes":3,"r10_r12_dead_processes":0,"r10_reduced_dead":{"len":0,"bytes":0},"r12_open_dead":{"len":0,"bytes":0},"r12_active_ops_dead":{"len":0,"bytes":0},"r12_next_pseudonym_dead":{"len":0,"bytes":0},"r12_find_active_dead":{"len":0,"bytes":0},"r12_pending_dead":{"len":0,"bytes":0},"r12_detached_dead":{"len":0,"bytes":0},"r12_inherited_ambiguous_dead":{"len":0,"bytes":0},"sample_us":null}'
    if parse_mem_line "$null_json" >/dev/null 2>&1; then
        echo "self-test: null sample_us parsed (must fail)" >&2; return 1
    fi
    if parse_mem_line '{"r10_r12_live_processes":3}' >/dev/null 2>&1; then
        echo "self-test: short line parsed (must fail)" >&2; return 1
    fi
    if parse_mem_line '{"r10_r12_live_processes": 3' >/dev/null 2>&1; then
        echo "self-test: truncated JSON parsed (must fail)" >&2; return 1
    fi
    [ "$(round_arms 1)" = "base cand cand base" ] || return 1
    [ "$(round_arms 2)" = "cand base base cand" ] || return 1
    # The refuse-path trap reaps the in-flight sample pids: a subshell
    # with two probe sleepers, the trap armed, and an exit-3 refuse
    # must leave neither sleeper alive.
    rc=0
    ( sleep 60 & echo $! > "$tmp/probe-a"
      sleep 60 & echo $! > "$tmp/probe-b"
      sudo_pid=$(cat "$tmp/probe-a")
      sampler_pid=$(cat "$tmp/probe-b")
      trap cleanup_sample EXIT
      exit 3 ) || rc=$?
    [ "$rc" -eq 3 ] || { echo "self-test: trap probe exited $rc, want 3" >&2; return 1; }
    tries=0
    while [ -d "/proc/$(cat "$tmp/probe-a")" ] || [ -d "/proc/$(cat "$tmp/probe-b")" ]; do
        if [ "$tries" -ge 50 ]; then break; fi
        sleep 0.1
        tries=$(( tries + 1 ))
    done
    if [ -d "/proc/$(cat "$tmp/probe-a")" ] || [ -d "/proc/$(cat "$tmp/probe-b")" ]; then
        echo "self-test: refuse-path trap left a probe sleeper alive" >&2
        kill -9 "$(cat "$tmp/probe-a")" "$(cat "$tmp/probe-b")" 2>/dev/null || true
        return 1
    fi
    trap - EXIT
    rm -rf "$tmp"
    echo "bench-profile-overhead: self-test OK"
}

main() {
    if [ "${1:-}" = "--self-test" ]; then
        LOG=/dev/null
        self_test
        return 0
    fi
    [ $# -eq 0 ] || die "usage: flock \$LOCK $0 [--self-test]"
    guards
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    if [ -z "$OUTDIR" ]; then
        OUTDIR=$TMPDIR/bench-profile-overhead-$ts
    fi
    # The 0700 mode targets the campaign dir itself (SC2174): the parent
    # is the caller's TMPDIR, whose mode is the caller's business.
    # shellcheck disable=SC2174
    mkdir -p -m 0700 "$OUTDIR"
    if [ -e "$OUTDIR/campaign.log" ]; then
        refuse "OUTDIR $OUTDIR already holds a campaign; use a fresh dir"
    fi
    LOG=$OUTDIR/campaign.log
    : > "$LOG"
    say "bench-profile-overhead ts=$ts base=$BASE_BIN cand=$CAND_BIN rate=$RATE fail_share=$FAIL_SHARE fork_every=$FORK_EVERY secs=$SECS rounds=$ROUNDS obs_spare=$OBS_SPARE quiet=$REQUIRE_QUIET max_load=$MAX_LOAD1/$MAX_LOAD5"
    say "base_sha=$(sha256sum "$BASE_BIN" | cut -d' ' -f1)"
    say "cand_sha=$(sha256sum "$CAND_BIN" | cut -d' ' -f1)"
    say "base_version=$("$BASE_BIN" --version 2>/dev/null | head -n 1 || echo unknown)"
    say "cand_version=$("$CAND_BIN" --version 2>/dev/null | head -n 1 || echo unknown)"
    round=1
    while [ "$round" -le "$ROUNDS" ]; do
        idx=1
        for arm in $(round_arms "$round"); do
            if [ "$arm" = "cand" ]; then bin=$CAND_BIN; else bin=$BASE_BIN; fi
            run_sample "$OUTDIR/r${round}s${idx}-${arm}" "$arm" "$bin"
            idx=$(( idx + 1 ))
        done
        round=$(( round + 1 ))
    done
    analyze "$LOG"
    say "bench-profile-overhead: campaign complete: $OUTDIR"
}

main "$@"
