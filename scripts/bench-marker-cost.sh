#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# bench-marker-cost.sh — birth-marker cost: per-exec and per-call.
#
# Method: two self-measured workloads run beside a live observer under
# four arms — no observer (none), the off build profiling (off-profile),
# the on build profiling with the marker disarmed (on-profile), and the
# on build with --key-operations armed (on-armed; gated read only at
# this revision — no production session writes READY, so the cost table
# labels it honestly instead of claiming an armed-marker cost):
#   exec-storm: scripts/fixtures/exec-storm.c fork+execs /bin/true
#     EXEC_OPS times (default 2000), CLOCK_MONOTONIC around the loop.
#     Measure: wall ns per exec, workload-side.
#   call-rate: tests/fixtures/joint-throughput/gen-calls.c single mode at
#     CALL_RATE (default 10k) for CALL_DURATION s (default 20). The loop
#     paces itself, so the wall is fixed; the measures are the achieved
#     rate (ledgered calls per wall second) and the per-call latency
#     distribution (t1-t0 over the ledger call rows, workload-side).
# BPF run-time deltas (kernel.bpf_stats_enabled, set for the campaign,
# re-asserted per sample against concurrent cells, restored after)
# corroborate independently: the sched_process_exec total beside
# exec-storm, the p11_entry total beside call-rate, except the armed
# call-rate arm reads the sealed journal pair (p11_entry_journal plus
# p11_return_journal, summed as p11_journal_pair, with ordinary
# p11_entry fallback when the pair is absent). A before-read over
# attached-but-idle hooks is 0/0 (bpftool omits zero counters with
# stats on); after the workload the window must show positive run time
# and at least one hook event per op, else the sample fails (a zero
# delta would certify unattached hooks). A hook program that is not
# loaded at all records absent per arm and is reported, never read
# as zero.
#
# Arms run ABBA across rounds (odd rounds forward, even rounds
# reversed), so linear host drift cannot masquerade as an arm
# difference. Per-sample gates (any
# failure fails the campaign immediately): quiet-host load gate (load1 <=
# MAX_LOAD1, default 4, no cargo/rustc; bounded COOLDOWN, default 300 s,
# else the campaign is refused), seed READY, observer attach (profile arms:
# the capturing line with >0 probes and no "attach failed"; the armed arm:
# the semantic seal line plus pass-1 start, so the storm lands on a
# steady-state scan, not mid-pass-0 attach), exact workload op count,
# observer exit 0, the report parses with evidence of attachment. The
# campaign pre-declares a
# manifest before the first sample and closes the log with a DONE marker;
# the verdict math lives in scripts/bench-marker-cost-analyze.py, which
# also runs standalone on the campaign log with --manifest and rejects any
# campaign that does not match its manifest or lacks completion.
#
# The result is recorded, not gated: the analyzer prints the on-versus-off
# deltas for the disarmed and armed arms beside the 2% owner figure
# (CP-5) as data, and exits nonzero only on a malformed campaign.
#
# Usage: flock "$LOCK" scripts/bench-marker-cost.sh ON_OBSERVER OFF_OBSERVER OUTDIR
#        scripts/bench-marker-cost.sh --self-test   # unprivileged
#        scripts/bench-marker-cost.sh --dry-run      # print the plan
# The script refuses unless an ancestor holds LOCK (default
# /var/tmp/p11scope-ws-tmp/privileged.lock), no p11scope is already live,
# and no p11_entry programs are already loaded (another capture's hooks
# would charge every arm). Run as a user with passwordless sudo; the
# observer, bpftool and sysctl go through sudo -n, everything else runs
# unprivileged. Environment: CELLS (default "exec-storm call-rate"),
# ROUNDS (default 2), EXEC_OPS, CALL_RATE, CALL_DURATION, MAX_LOAD1,
# COOLDOWN, DURATION (default 120: observer backstop per sample),
# ATTACH_TIMEOUT_S (default 120), MODULE (default the system SoftHSM2),
# LOCK, P11SCOPE_BENCH_COMMIT (the source commit; required outside a
# git repo, where the tree records unknown-no-git),
# TMPDIR (disk filesystem; the campaign keeps per-sample evidence
# under a private work dir and copies the log, manifest and cost table
# to OUTDIR at the end).
#
# Apt prerequisites on an ubuntu-26.04 runner: gcc, softhsm2, python3,
# sudo, flock (util-linux), bpftool.
set -eu
cd "$(dirname "$0")/.."
. scripts/lib.sh
SIGNAL_EXEC=$PWD/scripts/ci/run_default_signals.py

MODULE=${MODULE:-}
LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
SUDO="sudo -n"
CELLS=${CELLS:-exec-storm call-rate}
ROUNDS=${ROUNDS:-2}
EXEC_OPS=${EXEC_OPS:-2000}
CALL_RATE=${CALL_RATE:-10k}
CALL_DURATION=${CALL_DURATION:-20}
MAX_LOAD1=${MAX_LOAD1:-4}
COOLDOWN=${COOLDOWN:-300}
DURATION=${DURATION:-120}
ATTACH_TIMEOUT_S=${ATTACH_TIMEOUT_S:-120}
ATTACH_MARKER="p11scope: capturing: "
SEAL_LINE="p11scope: semantic lane ready"
ARMS="none off-profile on-profile on-armed"
WORK=
APID=
SPID=
BPF_STATS_BEFORE=
FIX=scripts/fixtures

say() {
    echo "$*"
    echo "$*" >> "$LOG"
}

die() {
    echo "bench-marker-cost: $*" >&2
    exit 1
}

refuse() {
    echo "bench-marker-cost: REFUSED: $*" >&2
    exit 3
}

is_positive_int() {
    case $1 in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -gt 0 ]
}

# write_manifest: pre-declares the campaign for the analyzer. Runs before
# the first sample; the analyzer rejects any campaign that does not match
# it or lacks the DONE line. Writes $WORK/campaign.manifest.json.
write_manifest() {
    CELLS="$CELLS" ROUNDS="$ROUNDS" ARMS="$ARMS" EXEC_OPS="$EXEC_OPS" \
    CALL_RATE="$CALL_RATE" CALL_DURATION="$CALL_DURATION" \
    python3 -I - > "$WORK/campaign.manifest.json" <<'EOF' || die "manifest write failed"
import json, os
cells = {}
for cell in os.environ["CELLS"].split():
    if cell == "exec-storm":
        cells[cell] = {"rounds": int(os.environ["ROUNDS"]),
                       "ops": int(os.environ["EXEC_OPS"])}
    elif cell == "call-rate":
        cells[cell] = {"rounds": int(os.environ["ROUNDS"]),
                       "rate": os.environ["CALL_RATE"],
                       "duration_s": int(os.environ["CALL_DURATION"])}
    else:
        raise SystemExit(f"unknown cell {cell}")
print(json.dumps({"cells": cells,
                  "arms": os.environ["ARMS"].split(),
                  "rotation": "ABBA: odd rounds forward, even rounds reversed",
                  "completion": {"marker": "DONE"}}))
EOF
}

# plan_order: the arm order per round (ABBA). Prints one line per
# round: "round N: arm arm arm arm". Odd rounds run the base order,
# even rounds run it reversed, so every arm shares the same mean
# temporal position across a round pair.
plan_order() {
    python3 -I - "$ARMS" "$ROUNDS" <<'EOF'
import sys
arms = sys.argv[1].split()
for r in range(1, int(sys.argv[2]) + 1):
    order = list(arms)
    if r % 2 == 0:
        order.reverse()
    print(f"round {r}: {' '.join(order)}")
EOF
}

# bpf_parse_totals PROG STATS: read `bpftool -j prog show` JSON on
# stdin, print "<run_time_ns> <run_cnt>" summed over every program
# named PROG (or its 15-byte kernel truncation). Exit 0 on a reading;
# exit 4 with "absent" when no program matches (a miss is recorded
# absence, never a zero); exit 1 on any corrupt read. With stats on,
# a matched program whose counters are omitted reads as zero: bpftool
# omits run_time_ns/run_cnt until the program first runs, so a
# before-read over attached-but-idle hooks is 0/0, not a failure.
bpf_parse_totals() {
    python3 -I -c '
import json, sys
want, stats = sys.argv[1], sys.argv[2]
try:
    progs = json.load(sys.stdin)
except Exception as exc:
    sys.exit(f"bpftool output is not JSON with stats={stats}: {exc}")
if type(progs) is not list:
    sys.exit(f"bpftool output is not a prog list with stats={stats}")
total_ns = total_cnt = 0
found = False
for prog in progs:
    if type(prog) is not dict:
        continue
    name = prog.get("name", "")
    if name != want and name != want[:15]:
        continue
    found = True
    row = []
    for field in ("run_time_ns", "run_cnt"):
        value = prog.get(field)
        if value is None and stats == "1":
            value = 0
        if type(value) is not int or value < 0:
            if value is None:
                sys.exit(f"prog {name!r} has no {field} with stats={stats}"
                         f" (a concurrent cell may have restored stats=0 or unloaded it)")
            sys.exit(f"prog {name!r} has invalid {field} {value!r} with stats={stats}")
        row.append(value)
    total_ns += row[0]
    total_cnt += row[1]
if not found:
    print("absent")
    sys.exit(4)
print(total_ns, total_cnt)
' "$1" "$2"
}

# bpf_parse_armed_call_rate STATS: read `bpftool -j prog show` JSON on
# stdin, print "<prog> <run_time_ns> <run_cnt>" for the armed call-rate
# arm. Prefers the journal pair (p11_entry_journal + p11_return_journal,
# each with 15-byte truncation, all twins summed) as p11_journal_pair;
# falls back to ordinary p11_entry when the pair is absent. Exit 0 on a
# reading; exit 4 with "absent" when neither pair nor ordinary matches;
# exit 1 on corrupt input or a one-sided pair (entry without return or
# vice versa: incomplete hooks, never absence or fallback).
bpf_parse_armed_call_rate() {
    python3 -I -c '
import json, sys
stats = sys.argv[1]
try:
    progs = json.load(sys.stdin)
except Exception as exc:
    sys.exit(f"bpftool output is not JSON with stats={stats}: {exc}")
if type(progs) is not list:
    sys.exit(f"bpftool output is not a prog list with stats={stats}")


def read_counters(prog, want):
    name = prog.get("name", "")
    if name != want and name != want[:15]:
        return None
    row = []
    for field in ("run_time_ns", "run_cnt"):
        value = prog.get(field)
        if value is None and stats == "1":
            value = 0
        if type(value) is not int or value < 0:
            if value is None:
                sys.exit(f"prog {name!r} has no {field} with stats={stats}"
                         f" (a concurrent cell may have restored stats=0 or unloaded it)")
            sys.exit(f"prog {name!r} has invalid {field} {value!r} with stats={stats}")
        row.append(value)
    return row


entry_ns = entry_cnt = return_ns = return_cnt = 0
entry_found = return_found = ordinary_found = False
ordinary_ns = ordinary_cnt = 0
for prog in progs:
    if type(prog) is not dict:
        continue
    row = read_counters(prog, "p11_entry_journal")
    if row is not None:
        entry_found = True
        entry_ns += row[0]
        entry_cnt += row[1]
        continue
    row = read_counters(prog, "p11_return_journal")
    if row is not None:
        return_found = True
        return_ns += row[0]
        return_cnt += row[1]
        continue
    row = read_counters(prog, "p11_entry")
    if row is not None:
        ordinary_found = True
        ordinary_ns += row[0]
        ordinary_cnt += row[1]
if entry_found or return_found:
    if not (entry_found and return_found):
        sys.exit("one-sided journal pair: entry_found=%s return_found=%s" % (entry_found, return_found))
    print("p11_journal_pair", entry_ns + return_ns, entry_cnt + return_cnt)
elif ordinary_found:
    print("p11_entry", ordinary_ns, ordinary_cnt)
else:
    print("absent")
    sys.exit(4)
' "$1"
}

# bpf_delta BEFORE AFTER OPS ARM: print the "<ns> <cnt>" window delta.
# Fail on backwards counters or a vacuous window: zero hook run time,
# or fewer than one event per op, means unattached hooks, which must
# fail the sample rather than certify zero cost.
bpf_delta() {
    bd_ns0=${1% *} bd_cnt0=${1#* }
    bd_ns1=${2% *} bd_cnt1=${2#* }
    [ "$bd_ns1" -ge "$bd_ns0" ] && [ "$bd_cnt1" -ge "$bd_cnt0" ] || {
        echo "bpf counters went backwards" >&2
        return 1
    }
    bd_ns=$((bd_ns1 - bd_ns0)) bd_cnt=$((bd_cnt1 - bd_cnt0))
    [ "$bd_ns" -gt 0 ] || {
        echo "$4 sample ran $3 ops with zero hook run time" >&2
        return 1
    }
    [ "$bd_cnt" -ge "$3" ] || {
        echo "$4 sample ran $3 ops with $bd_cnt hook events (< 1/op)" >&2
        return 1
    }
    echo "$bd_ns $bd_cnt"
}

# bpf_check_prog_stable BEFORE_PROG AFTER_PROG: fail when the armed
# call-rate reader flips programs mid-window (p11_journal_pair vs
# p11_entry). A flip means the before/after counters come from
# different hooks, so the sample must fail rather than mix them.
bpf_check_prog_stable() {
    if [ "$1" != "$2" ]; then
        echo "bpf prog changed mid-sample: $1 vs $2" >&2
        return 1
    fi
}

# resolve_commit: set COMMIT and TREE_STATUS. P11SCOPE_BENCH_COMMIT
# wins when set (required outside a git repo, e.g. the Fedora rsync
# mirror); otherwise the commit comes from git. Outside a repo the
# tree reads unknown-no-git. Returns nonzero when neither source works.
resolve_commit() {
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        rc_git=1
    else
        rc_git=
    fi
    if [ -n "${P11SCOPE_BENCH_COMMIT-}" ]; then
        COMMIT=$P11SCOPE_BENCH_COMMIT
    elif [ -n "$rc_git" ]; then
        COMMIT=$(git rev-parse HEAD) || return 1
    else
        return 1
    fi
    if [ -n "$rc_git" ]; then
        TREE_STATUS=$(git status --porcelain -- . ':!target' | head -n 20 | tr '\n' ';')
    else
        TREE_STATUS=unknown-no-git
    fi
}

if [ "${1-}" = "--dry-run" ]; then
    [ "$#" -eq 1 ] || { echo "usage: $0 [--self-test|--dry-run]" >&2; exit 2; }
    for knob in ROUNDS EXEC_OPS CALL_DURATION DURATION; do
        case $knob in
            ROUNDS) value=$ROUNDS ;;
            EXEC_OPS) value=$EXEC_OPS ;;
            CALL_DURATION) value=$CALL_DURATION ;;
            DURATION) value=$DURATION ;;
        esac
        is_positive_int "$value" || { echo "usage: $knob is a positive integer" >&2; exit 2; }
    done
    for cell in $CELLS; do
        case $cell in exec-storm|call-rate) : ;; *)
            echo "usage: unknown cell $cell" >&2; exit 2 ;;
        esac
    done
    echo "cells: $CELLS"
    echo "rounds: $ROUNDS arms: $ARMS"
    plan_order
    samples=0
    for cell in $CELLS; do samples=$((samples + ROUNDS * 4)); done
    echo "samples: $samples (≈ $((samples * 2)) min at ~2 min/sample with attach+cooldown)"
    echo "exec-storm: $EXEC_OPS execs; call-rate: $CALL_RATE for ${CALL_DURATION}s"
    exit 0
fi

if [ "${1-}" = "--self-test" ]; then
    [ "$#" -eq 1 ] || { echo "usage: $0 [--self-test|--dry-run]" >&2; exit 2; }
    # Unprivileged: fixture compiles + smokes + usage refusals + manifest
    # + the analyzer self-test + a dry-run smoke. No BPF, no sudo, no
    # observer, no workspace build.
    SELF_TEST_WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-markercost-selftest-XXXXXX")
    trap 'rm -rf "$SELF_TEST_WORK"' EXIT INT TERM
    command -v gcc >/dev/null || { echo "self-test: gcc required" >&2; exit 1; }
    command -v python3 >/dev/null || { echo "self-test: python3 required" >&2; exit 1; }
    command -v git >/dev/null || { echo "self-test: git required" >&2; exit 1; }
    gcc -O2 -Wall -Wextra -Werror -o "$SELF_TEST_WORK/exec-storm" \
        "$FIX/exec-storm.c" \
        || { echo "self-test: exec-storm does not compile" >&2; exit 1; }
    ST_LINE=$("$SELF_TEST_WORK/exec-storm" /bin/true 5) \
        || { echo "self-test: exec-storm smoke failed" >&2; exit 1; }
    case $ST_LINE in "EXEC_STORM ops=5 wall_ns="*" prog=/bin/true") : ;; *)
        echo "self-test: bad exec-storm line: $ST_LINE" >&2; exit 1 ;;
    esac
    if "$SELF_TEST_WORK/exec-storm" /bin/true 0 >/dev/null 2>&1; then
        echo "self-test: zero ops accepted" >&2; exit 1
    fi
    if "$SELF_TEST_WORK/exec-storm" /nonexistent-prog-xyz 3 >/dev/null 2>&1; then
        echo "self-test: bad prog accepted" >&2; exit 1
    fi
    gcc -O2 -Wall -Wextra -Werror -o "$SELF_TEST_WORK/gen-calls" \
        tests/fixtures/joint-throughput/gen-calls.c -ldl -lpthread \
        || { echo "self-test: gen-calls does not compile" >&2; exit 1; }
    "$SELF_TEST_WORK/gen-calls" --help >/dev/null \
        || { echo "self-test: gen-calls --help failed" >&2; exit 1; }
    "$SELF_TEST_WORK/gen-calls" --dry-run /nonexistent.so single 1k 2 \
        "$SELF_TEST_WORK/ledger.jsonl" >/dev/null \
        || { echo "self-test: gen-calls --dry-run failed" >&2; exit 1; }
    CELLS="exec-storm call-rate" ROUNDS=2 ARMS="$ARMS" EXEC_OPS=1000 \
    CALL_RATE=1k CALL_DURATION=2 WORK="$SELF_TEST_WORK" write_manifest \
        || { echo "self-test: manifest write failed" >&2; exit 1; }
    python3 -I - "$SELF_TEST_WORK/campaign.manifest.json" <<'EOF' \
        || { echo "self-test: bad manifest" >&2; exit 1; }
import json, sys
doc = json.load(open(sys.argv[1]))
assert set(doc["cells"]) == {"exec-storm", "call-rate"}, doc
assert doc["cells"]["exec-storm"] == {"rounds": 2, "ops": 1000}, doc
assert doc["cells"]["call-rate"] == {
    "rounds": 2, "rate": "1k", "duration_s": 2}, doc
assert doc["arms"] == ["none", "off-profile", "on-profile", "on-armed"], doc
assert doc["completion"] == {"marker": "DONE"}, doc
EOF
    python3 -I scripts/bench-marker-cost-analyze.py --self-test \
        || { echo "self-test: analyzer self-test failed" >&2; exit 1; }
    sh "$0" --dry-run >/dev/null \
        || { echo "self-test: dry-run failed" >&2; exit 1; }
    # bpf_parse_totals twins: bpftool omits zero counters, so with
    # stats on an attached-but-idle program reads 0/0; a program that
    # is not loaded reports absent (exit 4, never 0/0); stats off or a
    # non-integer counter fails the read.
    BPT_OUT=$(echo '[{"name": "p11_entry"}]' | bpf_parse_totals p11_entry 1) \
        || { echo "self-test: absent counters misread" >&2; exit 1; }
    [ "$BPT_OUT" = "0 0" ] \
        || { echo "self-test: absent counters gave $BPT_OUT" >&2; exit 1; }
    BPT_OUT=$(echo '[{"name": "p11_entry", "run_time_ns": 107, "run_cnt": 2006}]' \
        | bpf_parse_totals p11_entry 1) \
        || { echo "self-test: present counters misread" >&2; exit 1; }
    [ "$BPT_OUT" = "107 2006" ] \
        || { echo "self-test: present counters gave $BPT_OUT" >&2; exit 1; }
    BPT_OUT=$(echo '[{"name": "sched_process_e", "run_time_ns": 100, "run_cnt": 2007}, {"name": "sched_process_e", "run_time_ns": 120, "run_cnt": 2007}]' \
        | bpf_parse_totals sched_process_exec 1) \
        || { echo "self-test: twin programs misread" >&2; exit 1; }
    [ "$BPT_OUT" = "220 4014" ] \
        || { echo "self-test: twin programs gave $BPT_OUT" >&2; exit 1; }
    BPT_OUT=$(echo '[{"name": "p11_entry", "run_time_ns": 50, "run_cnt": 9}, {"name": "p11_entry"}]' \
        | bpf_parse_totals p11_entry 1) \
        || { echo "self-test: mixed counters misread" >&2; exit 1; }
    [ "$BPT_OUT" = "50 9" ] \
        || { echo "self-test: mixed counters gave $BPT_OUT" >&2; exit 1; }
    if echo '[{"name": "p11_entry"}]' | bpf_parse_totals p11_entry 0 >/dev/null 2>&1; then
        echo "self-test: stats-off read accepted" >&2; exit 1
    fi
    BPT_RC=0
    echo '[]' | bpf_parse_totals p11_entry 1 >"$SELF_TEST_WORK/bpt.out" 2>/dev/null || BPT_RC=$?
    [ "$BPT_RC" -eq 4 ] \
        || { echo "self-test: missing program exit $BPT_RC" >&2; exit 1; }
    [ "$(cat "$SELF_TEST_WORK/bpt.out")" = "absent" ] \
        || { echo "self-test: missing program gave $(cat "$SELF_TEST_WORK/bpt.out")" >&2; exit 1; }
    BPT_RC=0
    echo '[{"name": "other", "run_time_ns": 1, "run_cnt": 1}]' | bpf_parse_totals p11_entry 1 >/dev/null 2>&1 || BPT_RC=$?
    [ "$BPT_RC" -eq 4 ] \
        || { echo "self-test: wrong-program exit $BPT_RC" >&2; exit 1; }
    if echo '[{"name": "p11_entry", "run_time_ns": "107", "run_cnt": 5}]' | bpf_parse_totals p11_entry 1 >/dev/null 2>&1; then
        echo "self-test: non-integer counter accepted" >&2; exit 1
    fi
    if echo '[{"name": "p11_entry", "run_time_ns": -1, "run_cnt": 5}]' | bpf_parse_totals p11_entry 1 >/dev/null 2>&1; then
        echo "self-test: negative counter accepted" >&2; exit 1
    fi
    if echo 'not json' | bpf_parse_totals p11_entry 1 >/dev/null 2>&1; then
        echo "self-test: non-JSON accepted" >&2; exit 1
    fi
    # bpf_parse_armed_call_rate twins: the sealed journal lane loads the
    # journal pair, not ordinary entry. The armed call-rate reader prefers
    # the pair (summed, each with 15-byte truncation) and falls back to
    # ordinary entry when the pair is absent. A one-sided pair fails.
    BPA_OUT=$(echo '[{"name": "p11_entry_journal", "run_time_ns": 100, "run_cnt": 1000}, {"name": "p11_return_journal", "run_time_ns": 120, "run_cnt": 1000}]' \
        | bpf_parse_armed_call_rate 1) \
        || { echo "self-test: journal pair misread" >&2; exit 1; }
    [ "$BPA_OUT" = "p11_journal_pair 220 2000" ] \
        || { echo "self-test: journal pair gave $BPA_OUT" >&2; exit 1; }
    BPA_OUT=$(echo '[{"name": "p11_entry_journ", "run_time_ns": 50, "run_cnt": 500}, {"name": "p11_return_jour", "run_time_ns": 60, "run_cnt": 500}]' \
        | bpf_parse_armed_call_rate 1) \
        || { echo "self-test: truncated journal pair misread" >&2; exit 1; }
    [ "$BPA_OUT" = "p11_journal_pair 110 1000" ] \
        || { echo "self-test: truncated pair gave $BPA_OUT" >&2; exit 1; }
    BPA_OUT=$(echo '[{"name": "p11_entry_journal"}, {"name": "p11_return_journal"}]' | bpf_parse_armed_call_rate 1) \
        || { echo "self-test: idle journal pair misread" >&2; exit 1; }
    [ "$BPA_OUT" = "p11_journal_pair 0 0" ] \
        || { echo "self-test: idle pair gave $BPA_OUT" >&2; exit 1; }
    BPA_OUT=$(echo '[{"name": "p11_entry_journal", "run_time_ns": 100, "run_cnt": 1000}, {"name": "p11_entry_journal", "run_time_ns": 100, "run_cnt": 1000}, {"name": "p11_return_journal", "run_time_ns": 120, "run_cnt": 1000}]' \
        | bpf_parse_armed_call_rate 1) \
        || { echo "self-test: twin journal entry misread" >&2; exit 1; }
    [ "$BPA_OUT" = "p11_journal_pair 320 3000" ] \
        || { echo "self-test: twin journal gave $BPA_OUT" >&2; exit 1; }
    BPA_OUT=$(echo '[{"name": "p11_entry", "run_time_ns": 200, "run_cnt": 1500}]' | bpf_parse_armed_call_rate 1) \
        || { echo "self-test: ordinary fallback misread" >&2; exit 1; }
    [ "$BPA_OUT" = "p11_entry 200 1500" ] \
        || { echo "self-test: fallback gave $BPA_OUT" >&2; exit 1; }
    BPA_OUT=$(echo '[{"name": "p11_entry"}]' | bpf_parse_armed_call_rate 1) \
        || { echo "self-test: idle fallback misread" >&2; exit 1; }
    [ "$BPA_OUT" = "p11_entry 0 0" ] \
        || { echo "self-test: idle fallback gave $BPA_OUT" >&2; exit 1; }
    BPA_RC=0
    echo '[]' | bpf_parse_armed_call_rate 1 >"$SELF_TEST_WORK/bpa.out" 2>/dev/null || BPA_RC=$?
    [ "$BPA_RC" -eq 4 ] \
        || { echo "self-test: armed missing exit $BPA_RC" >&2; exit 1; }
    [ "$(cat "$SELF_TEST_WORK/bpa.out")" = "absent" ] \
        || { echo "self-test: armed missing gave $(cat "$SELF_TEST_WORK/bpa.out")" >&2; exit 1; }
    BPA_RC=0
    echo '[{"name": "other", "run_time_ns": 1, "run_cnt": 1}]' | bpf_parse_armed_call_rate 1 >/dev/null 2>&1 || BPA_RC=$?
    [ "$BPA_RC" -eq 4 ] \
        || { echo "self-test: armed wrong-program exit $BPA_RC" >&2; exit 1; }
    BPA_RC=0
    echo '[{"name": "p11_entry_journal", "run_time_ns": 100, "run_cnt": 1000}]' | bpf_parse_armed_call_rate 1 >/dev/null 2>&1 || BPA_RC=$?
    [ "$BPA_RC" -eq 1 ] \
        || { echo "self-test: one-sided pair exit $BPA_RC" >&2; exit 1; }
    if echo '[{"name": "p11_entry_journal"}]' | bpf_parse_armed_call_rate 0 >/dev/null 2>&1; then
        echo "self-test: armed stats-off read accepted" >&2; exit 1
    fi
    if echo '[{"name": "p11_entry_journal", "run_time_ns": "100", "run_cnt": 5}, {"name": "p11_return_journal", "run_time_ns": 120, "run_cnt": 5}]' | bpf_parse_armed_call_rate 1 >/dev/null 2>&1; then
        echo "self-test: armed non-integer accepted" >&2; exit 1
    fi
    if echo 'not json' | bpf_parse_armed_call_rate 1 >/dev/null 2>&1; then
        echo "self-test: armed non-JSON accepted" >&2; exit 1
    fi
    # bpf_delta twins: the after-read gate. A vacuous window (no hook
    # run time, or fewer than one event per op) fails the sample.
    BPD_OUT=$(bpf_delta "0 0" "50000 2006" 2000 test) \
        || { echo "self-test: healthy delta refused" >&2; exit 1; }
    [ "$BPD_OUT" = "50000 2006" ] \
        || { echo "self-test: bad delta $BPD_OUT" >&2; exit 1; }
    BPD_OUT=$(bpf_delta "100 10" "300 2010" 2000 test) \
        || { echo "self-test: nonzero-base delta refused" >&2; exit 1; }
    [ "$BPD_OUT" = "200 2000" ] \
        || { echo "self-test: bad nonzero-base delta $BPD_OUT" >&2; exit 1; }
    if bpf_delta "0 0" "0 0" 2000 test >/dev/null 2>&1; then
        echo "self-test: vacuous delta accepted" >&2; exit 1
    fi
    if bpf_delta "0 0" "0 2000" 2000 test >/dev/null 2>&1; then
        echo "self-test: zero-time delta accepted" >&2; exit 1
    fi
    if bpf_delta "100 10" "200 20" 2000 test >/dev/null 2>&1; then
        echo "self-test: short-count delta accepted" >&2; exit 1
    fi
    if bpf_delta "200 2010" "100 10" 2000 test >/dev/null 2>&1; then
        echo "self-test: backwards delta accepted" >&2; exit 1
    fi
    # bpf_check_prog_stable twins: the mid-window guard. A stable
    # program passes; a flip fails the sample with the same message.
    bpf_check_prog_stable p11_journal_pair p11_journal_pair >/dev/null \
        || { echo "self-test: stable prog refused" >&2; exit 1; }
    if bpf_check_prog_stable p11_journal_pair p11_entry >/dev/null 2>&1; then
        echo "self-test: changed prog accepted" >&2; exit 1
    fi
    BCS_OUT=$(bpf_check_prog_stable p11_journal_pair p11_entry 2>&1 >/dev/null || true)
    case $BCS_OUT in *"changed mid-sample"*) : ;; *)
        echo "self-test: bad prog-change message: $BCS_OUT" >&2; exit 1 ;;
    esac
    # resolve_commit twins: outside a repo the env commit is required
    # and the tree reads unknown-no-git; inside a repo git stays.
    RC_DIR=$(mktemp -d "$SELF_TEST_WORK/norepo-XXXXXX") \
        || { echo "self-test: mktemp failed" >&2; exit 1; }
    RC_OUT=$(cd "$RC_DIR" || exit 1; export GIT_CEILING_DIRECTORIES="$RC_DIR"; P11SCOPE_BENCH_COMMIT=deadbeef1234; export P11SCOPE_BENCH_COMMIT; resolve_commit || exit 1; printf '%s|%s' "$COMMIT" "$TREE_STATUS") \
        || { echo "self-test: env commit refused outside a repo" >&2; exit 1; }
    [ "$RC_OUT" = "deadbeef1234|unknown-no-git" ] \
        || { echo "self-test: bad env resolve $RC_OUT" >&2; exit 1; }
    if RC_OUT=$(cd "$RC_DIR" || exit 1; export GIT_CEILING_DIRECTORIES="$RC_DIR"; unset P11SCOPE_BENCH_COMMIT; resolve_commit); then
        echo "self-test: missing commit accepted outside a repo" >&2; exit 1
    fi
    RC_REPO=$(mktemp -d "$SELF_TEST_WORK/repo-XXXXXX") \
        || { echo "self-test: mktemp failed" >&2; exit 1; }
    git -c init.defaultBranch=main init -q "$RC_REPO" \
        || { echo "self-test: git init failed" >&2; exit 1; }
    git -C "$RC_REPO" -c user.email=selftest@example -c user.name=selftest -c commit.gpgsign=false commit -q --allow-empty -m test \
        || { echo "self-test: git commit failed" >&2; exit 1; }
    RC_SHA=$(git -C "$RC_REPO" rev-parse HEAD) \
        || { echo "self-test: git rev-parse failed" >&2; exit 1; }
    RC_OUT=$(cd "$RC_REPO" || exit 1; unset P11SCOPE_BENCH_COMMIT; resolve_commit || exit 1; printf '%s|%s' "$COMMIT" "$TREE_STATUS") \
        || { echo "self-test: git resolve failed" >&2; exit 1; }
    [ "$RC_OUT" = "$RC_SHA|" ] \
        || { echo "self-test: bad git resolve $RC_OUT" >&2; exit 1; }
    echo dirty > "$RC_REPO/dirty.txt" \
        || { echo "self-test: dirty write failed" >&2; exit 1; }
    RC_OUT=$(cd "$RC_REPO" || exit 1; unset P11SCOPE_BENCH_COMMIT; resolve_commit || exit 1; printf '%s' "$TREE_STATUS") \
        || { echo "self-test: dirty resolve failed" >&2; exit 1; }
    case $RC_OUT in *"dirty.txt"*) : ;; *)
        echo "self-test: dirty tree gave $RC_OUT" >&2; exit 1 ;;
    esac
    RC_OUT=$(cd "$RC_REPO" || exit 1; P11SCOPE_BENCH_COMMIT=envwins123; export P11SCOPE_BENCH_COMMIT; resolve_commit || exit 1; printf '%s|%s' "$COMMIT" "$TREE_STATUS") \
        || { echo "self-test: env-over-repo resolve failed" >&2; exit 1; }
    case $RC_OUT in "envwins123|"*"dirty.txt"*) : ;; *)
        echo "self-test: env-over-repo gave $RC_OUT" >&2; exit 1 ;;
    esac
    echo "bench-marker-cost self-test: OK"
    exit 0
fi
[ "$#" -eq 3 ] || { echo "usage: $0 ON_OBSERVER OFF_OBSERVER OUTDIR" >&2; exit 2; }
ON_OBSERVER=$1 OFF_OBSERVER=$2 OUTDIR=$3
[ -x "$ON_OBSERVER" ] || { echo "usage: ON_OBSERVER not executable" >&2; exit 2; }
[ -x "$OFF_OBSERVER" ] || { echo "usage: OFF_OBSERVER not executable" >&2; exit 2; }
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"

for knob in ROUNDS EXEC_OPS CALL_DURATION COOLDOWN DURATION ATTACH_TIMEOUT_S; do
    eval "value=\$$knob"
    is_positive_int "$value" || { echo "usage: $knob is a positive integer" >&2; exit 2; }
done
case $CALL_RATE in 1k|10k|100k) : ;; *)
    echo "usage: CALL_RATE is 1k, 10k or 100k" >&2; exit 2 ;;
esac
for cell in $CELLS; do
    case $cell in exec-storm|call-rate) : ;; *)
        echo "usage: unknown cell $cell" >&2; exit 2 ;;
    esac
done

# The observer refuses an output directory below any group- or
# other-writable ancestor, so the campaign works in a private directory
# under TMPDIR and copies the log, manifest and cost table to OUTDIR.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-bench-markercost-XXXXXX")
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
    exit "$status"
}
. scripts/cleanup-traps.sh

command -v gcc >/dev/null || die "gcc required"
command -v softhsm2-util >/dev/null || die "softhsm2-util required"
command -v python3 >/dev/null || die "python3 required"
command -v bpftool >/dev/null || die "bpftool required"
command -v sudo >/dev/null || die "sudo required"
[ "$(id -u)" -ne 0 ] || die "run as a non-root user with passwordless sudo"
sudo -n true 2>/dev/null || die "passwordless sudo required"

# An ancestor must hold the privileged lock: a concurrent privileged test
# or capture would charge these samples. Run under `flock "$LOCK" $0 ...`.
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

# Another capture's hooks would charge every arm and flatten the
# comparison, so a live p11scope or live entry programs refuse the run.
if pgrep -x p11scope >/dev/null 2>&1; then
    refuse "a p11scope process is already running"
fi
if sudo -n bpftool prog show 2>/dev/null | grep -q "name p11_entry"; then
    refuse "p11_entry programs are already loaded"
fi

build_processes() {
    cat /proc/[0-9]*/comm 2>/dev/null | grep -cxE 'cargo|rustc'
}

host_hot() {
    awk -v max="$1" '{exit !($1 > max)}' /proc/loadavg
}

# wait_cool: bounded quiet-host wait before every sample. False when the
# host never cools: the campaign is refused, never measured hot.
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

wait_for_profile_attach() {
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

wait_for_seal() {
    wfos_end=$(( $(date +%s) + $2 ))
    while ! grep -Fq "$SEAL_LINE" "$1" 2>/dev/null; do
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            echo "observer exited before the seal line: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        fi
        [ "$(date +%s)" -lt "$wfos_end" ] || {
            echo "observer never sealed within $2s: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        }
        sleep 0.2
    done
    return 0
}
wait_for_first_pass() {
    # The seal readies the lane before pass 0 finishes; a storm that
    # lands mid-pass-0 measures attach, not steady-state hook cost, and
    # stops with 0 endpoints. Pass 1 starting means pass 0 completed.
    wffp_end=$(( $(date +%s) + $2 ))
    while ! grep -Fq "p11scope: pass 1:" "$1" 2>/dev/null; do
        if [ -n "${SPID-}" ] && ! kill -0 "$SPID" 2>/dev/null; then
            echo "observer exited before pass 1 started: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        fi
        [ "$(date +%s)" -lt "$wffp_end" ] || {
            echo "observer never started pass 1 within $2s: $1" >&2
            tail -n 20 "$1" >&2 2>/dev/null || true
            return 1
        }
        sleep 0.5
    done
    return 0
}

# bpf_totals PROG: "<run_time_ns> <run_cnt>" summed over every loaded
# program whose name is PROG or its 15-byte kernel truncation, or
# "absent" when none is loaded. Sums (never picks one): with uprobe_multi
# there is one program per hook anyway, and a sum cannot hide a twin.
# A "0 0" reading means attached-but-idle with stats on (bpftool omits
# zero counters); it is not absence.
bpf_totals() {
    bpf_json=$(sudo -n bpftool -j prog show 2>"$WORK/bpftool.stderr")
    bpf_rc=$?
    if [ "$bpf_rc" -ne 0 ] || [ -z "$bpf_json" ]; then
        echo "bpftool prog show failed (exit $bpf_rc):" >&2
        tail -n 3 "$WORK/bpftool.stderr" >&2 2>/dev/null || true
        echo "bpf_stats_enabled=$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null)" >&2
        return 1
    fi
    bpf_stats=$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo unknown)
    if bpf_out=$(printf '%s' "$bpf_json" | bpf_parse_totals "$1" "$bpf_stats"); then
        printf '%s\n' "$bpf_out"
    else
        bpf_rc=$?
        if [ "$bpf_rc" -eq 4 ]; then
            printf '%s\n' "$bpf_out"
            return 0
        fi
        return 1
    fi
}

# bpf_totals_armed_call_rate: "<prog> <run_time_ns> <run_cnt>" for the
# armed call-rate arm (journal pair preferred, ordinary fallback), or
# "absent" when neither is loaded. See bpf_parse_armed_call_rate.
bpf_totals_armed_call_rate() {
    bpf_json=$(sudo -n bpftool -j prog show 2>"$WORK/bpftool.stderr")
    bpf_rc=$?
    if [ "$bpf_rc" -ne 0 ] || [ -z "$bpf_json" ]; then
        echo "bpftool prog show failed (exit $bpf_rc):" >&2
        tail -n 3 "$WORK/bpftool.stderr" >&2 2>/dev/null || true
        echo "bpf_stats_enabled=$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null)" >&2
        return 1
    fi
    bpf_stats=$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo unknown)
    if bpf_out=$(printf '%s' "$bpf_json" | bpf_parse_armed_call_rate "$bpf_stats"); then
        printf '%s\n' "$bpf_out"
    else
        bpf_rc=$?
        if [ "$bpf_rc" -eq 4 ]; then
            printf '%s\n' "$bpf_out"
            return 0
        fi
        return 1
    fi
}

if [ -n "$MODULE" ]; then
    PROVIDER=$MODULE
else
    PROVIDER=$(python3 -I scripts/release-matrix-contract.py --select-module 2>/dev/null) \
        || die "no SoftHSM provider (release-matrix-contract --select-module failed)"
fi
test -f "$PROVIDER" || die "SoftHSM2 not installed at $PROVIDER"

echo "=== build ==="
mkdir -p "$WORK/bin" && chmod 0700 "$WORK/bin"
gcc -O2 -Wall -Wextra -Werror -o "$WORK/bin/exec-storm" "$FIX/exec-storm.c" \
    || die "exec-storm does not compile"
gcc -O2 -Wall -Wextra -Werror -o "$WORK/bin/gen-calls" \
    tests/fixtures/joint-throughput/gen-calls.c -ldl -lpthread \
    || die "gen-calls does not compile"
gcc -O1 -Wall -Wextra -Werror -o "$WORK/bin/gated" tests/fixtures/public-cli/gated.c -ldl \
    || die "gated does not compile"
ON_DISCOVER=$(dirname "$ON_OBSERVER")/p11scope-discover
test -x "$ON_DISCOVER" || die "p11scope-discover missing beside $ON_OBSERVER"

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
softhsm2-util --init-token --free --label bench-marker --so-pin 1234 --pin 1234 >/dev/null \
    || die "token init failed"

echo "=== discover ==="
"$ON_DISCOVER" --module "$PROVIDER" -o "$WORK/manifest.json" || die "discover failed"

echo "=== machine ==="
KERNEL=$(uname -r)
CPU=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
resolve_commit || die "no git repo in $PWD: set P11SCOPE_BENCH_COMMIT to the built commit"
ON_SHA=$(sha256sum "$ON_OBSERVER" | cut -d' ' -f1)
OFF_SHA=$(sha256sum "$OFF_OBSERVER" | cut -d' ' -f1)
echo "kernel: $KERNEL"
echo "cpu: $CPU"
echo "commit: $COMMIT"
echo "on binary: $ON_SHA"
echo "off binary: $OFF_SHA"
echo "cells: $CELLS rounds: $ROUNDS"
say "MACHINE kernel=$KERNEL cpu=$CPU nproc=$(nproc) date=$(date -u +%FT%TZ) host=$(uname -n)"
say "BINARY which=on path=$ON_OBSERVER sha256=$ON_SHA commit=$COMMIT"
say "BINARY which=off path=$OFF_OBSERVER sha256=$OFF_SHA commit=$COMMIT"
say "TREE status=${TREE_STATUS:-clean}"
write_manifest
echo "campaign manifest: $WORK/campaign.manifest.json"

BPF_STATS_BEFORE=$(cat /proc/sys/kernel/bpf_stats_enabled)
sudo -n sysctl -w kernel.bpf_stats_enabled=1 >/dev/null \
    || die "cannot enable BPF stats"
echo "bpf_stats_enabled 1 for the campaign (was $BPF_STATS_BEFORE; restored after)"

SAMPLE_SEQ=0

# run_exec_storm S: run the storm, print "<ops> <wall_ns>", fail unless
# the line parses with exactly EXEC_OPS.
run_exec_storm() {
    "$WORK/bin/exec-storm" /bin/true "$EXEC_OPS" > "$1/storm.log" 2>&1 || return 1
    python3 -I - "$1/storm.log" "$EXEC_OPS" <<'EOF'
import sys
ops = wall = None
for line in open(sys.argv[1]):
    if not line.startswith("EXEC_STORM "):
        continue
    fields = dict(token.split("=", 1) for token in line.split()[1:])
    ops, wall = int(fields["ops"]), int(fields["wall_ns"])
if ops != int(sys.argv[2]) or wall <= 0:
    sys.exit(1)
print(f"{ops} {wall}")
EOF
}

# run_call_rate S: run gen-calls single mode, print
# "<calls> <wall_ns> <lat_med_ns> <lat_p90_ns> <unhealthy>".
run_call_rate() {
    wall_start=$(date +%s%N)
    "$WORK/bin/gen-calls" "$PROVIDER" single "$CALL_RATE" "$CALL_DURATION" \
        "$1/calls.jsonl" > "$1/caller.log" 2>&1 || return 1
    wall_end=$(date +%s%N)
    python3 -I - "$1/calls.jsonl" "$((wall_end - wall_start))" <<'EOF'
import json, sys
latencies = []
unhealthy = 0
for line in open(sys.argv[1]):
    row = json.loads(line)
    if row.get("kind") != "call":
        continue
    latencies.append(row["t1"] - row["t0"])
    unhealthy += row.get("rv", 0) != 0
if not latencies:
    sys.exit(1)
latencies.sort()
n = len(latencies)
med = latencies[n // 2]
p90 = latencies[min(n - 1, (n * 9) // 10)]
if any(v < 0 for v in (med, p90)) or int(sys.argv[2]) <= 0:
    sys.exit(1)
print(f"{n} {sys.argv[2]} {med} {p90} {unhealthy}")
EOF
}

# run_sample CELL ARM ROUND: one gated seed + one observer (except none)
# + one workload window. Any gate failure fails the campaign; only a
# persistently hot host refuses it (exit 3).
run_sample() {
    rs_cell=$1 rs_arm=$2 rs_round=$3
    case $rs_cell in
        exec-storm) rs_prog=sched_process_exec ;;
        call-rate) rs_prog=p11_entry ;;
    esac
    rs_armed_call_rate=no
    if [ "$rs_cell" = call-rate ] && [ "$rs_arm" = on-armed ]; then
        rs_armed_call_rate=yes
    fi
    SAMPLE_SEQ=$((SAMPLE_SEQ + 1))
    S=$WORK/sample-$(printf '%03d' "$SAMPLE_SEQ")-$rs_cell-$rs_arm-r$rs_round
    mkdir -p "$S" && chmod 0700 "$S" || die "sample dir"
    echo "--- sample $SAMPLE_SEQ: $rs_cell $rs_arm round $rs_round ---"
    wait_cool || refuse "host stayed hot (load gate $MAX_LOAD1, $COOLDOWN s)"
    record_load "$S/load.txt" start
    "$WORK/bin/gated" "$PROVIDER" 0 0 "$S/gate-never" > "$S/anchor.log" 2>&1 &
    APID=$!
    rs_end=$(( $(date +%s) + 60 ))
    while ! grep -q "^READY" "$S/anchor.log" 2>/dev/null; do
        kill -0 "$APID" 2>/dev/null || { echo "anchor died:" >&2; cat "$S/anchor.log" >&2; return 1; }
        [ "$(date +%s)" -lt "$rs_end" ] || { echo "anchor never READY" >&2; return 1; }
        sleep 0.05
    done
    if [ "$rs_arm" != none ]; then
        case $rs_arm in
            off-profile)
                # shellcheck disable=SC2086
                $SUDO --preserve-env=SOFTHSM2_CONF python3 -I "$SIGNAL_EXEC" "$OFF_OBSERVER" profile \
                    --system --duration "$DURATION" -o "$S/profile.json" \
                    > "$S/observer.log" 2> "$S/observer.stderr" &
                ;;
            on-profile)
                # shellcheck disable=SC2086
                $SUDO --preserve-env=SOFTHSM2_CONF python3 -I "$SIGNAL_EXEC" "$ON_OBSERVER" profile \
                    --system --duration "$DURATION" -o "$S/profile.json" \
                    > "$S/observer.log" 2> "$S/observer.stderr" &
                ;;
            on-armed)
                # shellcheck disable=SC2086
                $SUDO --preserve-env=SOFTHSM2_CONF python3 -I "$SIGNAL_EXEC" "$ON_OBSERVER" inventory \
                    --system --capture native --key-operations \
                    --manifest "$WORK/manifest.json" --duration "$DURATION" \
                    -o "$S/out.json" \
                    > "$S/observer.log" 2> "$S/observer.stderr" &
                ;;
        esac
        SPID=$!
        case $rs_arm in
            off-profile|on-profile)
                wait_for_profile_attach "$S/observer.stderr" "$ATTACH_TIMEOUT_S" || return 1
                ;;
            on-armed)
                wait_for_seal "$S/observer.stderr" "$ATTACH_TIMEOUT_S" || return 1
                wait_for_first_pass "$S/observer.stderr" "$ATTACH_TIMEOUT_S" || return 1
                ;;
        esac
        if grep -q "attach failed" "$S/observer.stderr"; then
            echo "ATTACH FAILURE in $S:" >&2
            cat "$S/observer.stderr" >&2
            return 1
        fi
        # bpf_stats_enabled is host-global: a concurrent BPF cell can
        # restore 0 mid-campaign, which drops run_time_ns from bpftool
        # and fails the read. Re-assert per sample (a no-op on the
        # exclusive host the real numbers come from).
        sudo -n sysctl -w kernel.bpf_stats_enabled=1 >/dev/null 2>&1 \
            || { echo "bpf stats re-assert failed" >&2; return 1; }
        if [ "$rs_armed_call_rate" = yes ]; then
            rs_bpf_before=$(bpf_totals_armed_call_rate) || { echo "bpf before-read failed" >&2; return 1; }
        else
            rs_bpf_before=$(bpf_totals "$rs_prog") || { echo "bpf before-read failed" >&2; return 1; }
        fi
    else
        rs_bpf_before=none
    fi
    case $rs_cell in
        exec-storm)
            rs_out=$(run_exec_storm "$S") || { echo "exec-storm window failed" >&2; return 1; }
            rs_ops=${rs_out% *} rs_wall=${rs_out#* }
            rs_extra=""
            ;;
        call-rate)
            rs_out=$(run_call_rate "$S") || { echo "call-rate window failed" >&2; return 1; }
            set -- $rs_out
            rs_ops=$1 rs_wall=$2 rs_lat_med=$3 rs_lat_p90=$4 rs_unhealthy=$5
            rs_rate=$(python3 -I -c "print(int('$rs_ops') * 1000000000 / int('$rs_wall'))")
            rs_extra=" rate_per_s=$rs_rate lat_med_ns=$rs_lat_med lat_p90_ns=$rs_lat_p90 unhealthy=$rs_unhealthy"
            ;;
    esac
    if [ "$rs_arm" != none ]; then
        if [ "$rs_armed_call_rate" = yes ]; then
            rs_bpf_after=$(bpf_totals_armed_call_rate) || { echo "bpf after-read failed" >&2; return 1; }
            if [ "$rs_bpf_before" = absent ] || [ "$rs_bpf_after" = absent ]; then
                rs_prog=p11_journal_pair
                rs_bpf_ns=absent rs_bpf_cnt=absent
            else
                rs_prog_before=${rs_bpf_before%% *}
                rs_rest_before=${rs_bpf_before#* }
                rs_prog_after=${rs_bpf_after%% *}
                rs_rest_after=${rs_bpf_after#* }
                bpf_check_prog_stable "$rs_prog_before" "$rs_prog_after" || return 1
                rs_prog=$rs_prog_before
                rs_bpf=$(bpf_delta "$rs_rest_before" "$rs_rest_after" "$rs_ops" "$rs_arm") || return 1
                rs_bpf_ns=${rs_bpf% *} rs_bpf_cnt=${rs_bpf#* }
            fi
        else
            rs_bpf_after=$(bpf_totals "$rs_prog") || { echo "bpf after-read failed" >&2; return 1; }
            if [ "$rs_bpf_before" = absent ] || [ "$rs_bpf_after" = absent ]; then
                rs_bpf_ns=absent rs_bpf_cnt=absent
            else
                rs_bpf=$(bpf_delta "$rs_bpf_before" "$rs_bpf_after" "$rs_ops" "$rs_arm") || return 1
                rs_bpf_ns=${rs_bpf% *} rs_bpf_cnt=${rs_bpf#* }
            fi
        fi
        kill -INT "$SPID" 2>/dev/null || true
        if wait "$SPID"; then SPID=; else rs_status=$?; SPID=; echo "observer exited $rs_status" >&2; return 1; fi
        if grep -q "attach failed" "$S/observer.stderr"; then
            echo "ATTACH FAILURE in $S:" >&2
            cat "$S/observer.stderr" >&2
            return 1
        fi
        case $rs_arm in
            off-profile|on-profile) rs_report=$S/profile.json ;;
            on-armed) rs_report=$S/out.json ;;
        esac
        reclaim_root_output "$rs_report"
        python3 -I - "$rs_report" "$rs_arm" <<'EOF' || { echo "report validation failed" >&2; return 1; }
import json, sys
doc = json.load(open(sys.argv[1]))
if sys.argv[2] == "on-armed":
    observation = doc.get("observation", {})
    capture = observation.get("semantic_capture", {})
    attach = observation.get("attach", {})
    admitted = capture.get("admitted_endpoints", 0)
    if type(admitted) is not int or admitted <= 0:
        sys.exit("armed report shows no admitted endpoints")
    if attach.get("mechanism") != "uprobe-multi":
        sys.exit("armed report is not a native uprobe-multi capture")
elif doc.get("evidence", {}).get("attached_probes", 0) <= 0:
    sys.exit(1)
EOF
    else
        rs_bpf_ns=none rs_bpf_cnt=none
    fi
    kill -TERM "$APID" 2>/dev/null || true
    wait "$APID" 2>/dev/null || true
    APID=
    record_load "$S/load.txt" end
    say "SAMPLE cell=$rs_cell arm=$rs_arm round=$rs_round ops=$rs_ops wall_ns=$rs_wall${rs_extra} bpf_prog=$rs_prog bpf_ns=$rs_bpf_ns bpf_cnt=$rs_bpf_cnt"
}

round=1
while [ "$round" -le "$ROUNDS" ]; do
    arms=$(plan_order | sed -n "${round}s/^round $round: //p")
    for cell in $CELLS; do
        for arm in $arms; do
            run_sample "$cell" "$arm" "$round" || exit 1
        done
    done
    round=$((round + 1))
done

say "DONE samples=$SAMPLE_SEQ"
echo "=== results ==="
python3 -I scripts/bench-marker-cost-analyze.py "$LOG" \
    --manifest "$WORK/campaign.manifest.json" --out "$WORK/cost-table.txt" || exit 1
cat "$WORK/cost-table.txt"
cp "$LOG" "$WORK/campaign.manifest.json" "$WORK/cost-table.txt" "$OUTDIR/" || die "copy to OUTDIR failed"
echo "=== bench-marker-cost: DONE ($LOG copied to $OUTDIR) ==="
