#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# run-run-tree.sh TESTBIN OUTDIR
# run-run-tree.sh --self-test
#
# Runs the 9 run-tree CLI cells (tests/run_tree.rs) as root
# with exact-positive judging: every cell drives the real command line
# against SoftHSM and must exit 0 with exactly one passed test. The
# run-tree CI job calls this on the host leg directly and inside vng
# guests via scripts/ci/run-tree-vng.sh.
#
# Cells (exact test names, one row per test in OUTDIR/results.jsonl):
#   privileged_run_tree_shell_wrapper_shows_grandchild_calls
#   privileged_run_tree_double_fork_shows_reparented_calls
#   privileged_run_tree_outliving_child_is_disclosed
#   privileged_run_tree_many_children_land_exact
#   privileged_run_tree_unprearmed_shortlived_descendants_reach_high_coverage
#   privileged_run_tree_unprearmed_shortlived_never_pause_still_learns
#   privileged_run_tree_unprearmed_shortlived_parallel_never_pause_covers_waves
#   privileged_run_tree_arming_exhaustion_still_stages_and_counts
#   privileged_run_tree_non_member_provider_is_never_staged
#
# Declared intermittent failures (EXPECTED_FAILURES below) fail only
# with one of their known signatures: such a row is qualification
# expected-failure (judged a pass); a pass stays an ordinary qualified
# pass (the cells pass on some legs and runs and fail on others, so a
# strict unexpected-pass gate would itself be flaky), and any other
# failure, a timeout included, stays failed, never masked.
#
# Each results.jsonl row carries exactly cell/pass/qualification/detail
# (the shared cell-result contract). A zero exit alone is not a pass:
# the log must show exactly one passed test, so a cell that gained
# #[ignore] (libtest exits 0 on "0 passed, 1 ignored") fails instead
# of passing silently.
#
# Arguments:
#   TESTBIN  the built run_tree test executable (cargo test
#            --test run_tree --no-run); the observer it drives
#            is its build-time CARGO_BIN_EXE_p11scope sibling.
#   OUTDIR   receives results.jsonl, summary.txt and one <test>.log
#            per cell.
#
# --self-test runs the cell judgment and the summary gate against fixture
# logs (no root, no build, no cells) and fails on any misjudged fixture.
#
# Exit codes: 0 every cell passed; 1 a cell failed; 2 harness error (bad
# arguments, missing binary, selection drift); 77 prerequisite missing
# (not root, or a required tool absent).
#
# Apt prerequisites on ubuntu-26.04: gcc (the cells compile their
# runtime SoftHSM workload) and softhsm2 (provider plus token tooling),
# beyond the base image (bash, coreutils incl. timeout/realpath/date,
# python3).
set -u
umask 022

CELLS=(
privileged_run_tree_shell_wrapper_shows_grandchild_calls
privileged_run_tree_double_fork_shows_reparented_calls
privileged_run_tree_outliving_child_is_disclosed
privileged_run_tree_many_children_land_exact
privileged_run_tree_unprearmed_shortlived_descendants_reach_high_coverage
privileged_run_tree_unprearmed_shortlived_never_pause_still_learns
privileged_run_tree_unprearmed_shortlived_parallel_never_pause_covers_waves
privileged_run_tree_arming_exhaustion_still_stages_and_counts
privileged_run_tree_non_member_provider_is_never_staged
)

# Declared intermittent failures: one entry per (cell, known failure
# signature, reason); a cell may carry several signatures. A signature
# is an ERE the cell log must contain. Keep this list, the workflow's
# --intermittent-failure flags and run-tree-vng.sh in step.
#
# Revert note: when the named lane lands, delete its entries here; when
# a cell has no entry left, turn the workflow's --intermittent-failure
# for it back into --require.
#
# The cells judge exact accounting (owner ruling 2026-11-15): every call
# that entered after its function's first attach must be observed, so any
# miss fails, however small. The declared signature matches only a miss
# the report itself ties to a replace: the cell names a "replace witness"
# (a second counter-slot row for that endpoint, or a failed replacement's
# null attached_at_ns) and the loss fits in the calls that entered before
# the last re-attach. Any other partial loss is an "unexplained miss";
# it, overcounts, invented functions and a function that lost every call
# (probe loss) fail under their own text, never the declared signature.
#
# never_pause_still_learns:
# - PLAN-REPLACE-GAP (base bug, not the run-tree learning). A new worker's
#   view makes the provider slots shared, the rebuilt plan downgrades
#   them to count-only and the replace path detaches and reattaches all
#   68 probes; calls in that 33-59 ms window are lost after the first
#   attach: an undisclosed miss (CI 43704790202 under the old floor:
#   0.9355 on v6.12, 0.8459 on v7.3).
# - SLOT-RECLAIM (plan.rs lane). The same downgrade leaves the
#   descriptor-replaced slots of one pinned object unreclaimed, so each
#   worker grows the plan by 68 slots until the attach plan exceeds the
#   2112-slot ceiling and the capture aborts (CI 43704790202 host:
#   2176 > 2112).
# parallel_never_pause_covers_waves:
# - PLAN-REPLACE-GAP, as above: witnessed misses after the first attach
#   (host 2026-11-15: 21 of 80 C_GetSlotInfo calls; 7 slot rows each).
# arming_exhaustion_still_stages_and_counts:
# - PLAN-REPLACE-GAP, as above: undisclosed misses after the first
#   provider attach (CI 43704790202 v6.6 under the old floor: 0.8996).
#   It passes on the CI host.
EXPECTED_FAILURES=(
privileged_run_tree_unprearmed_shortlived_never_pause_still_learns
privileged_run_tree_unprearmed_shortlived_never_pause_still_learns
privileged_run_tree_unprearmed_shortlived_parallel_never_pause_covers_waves
privileged_run_tree_arming_exhaustion_still_stages_and_counts
)
EXPECTED_SIGNATURES=(
'undisclosed miss: [0-9]+ calls after the pre-attach window \([^)]*; replace witness: [^)]+\)'
'attach plan requires [0-9]+ allocated slots but only [0-9]+ are available'
'undisclosed miss: [0-9]+ calls after the pre-attach window \([^)]*; replace witness: [^)]+\)'
'undisclosed miss: [0-9]+ calls after the pre-attach window \([^)]*; replace witness: [^)]+\)'
)
EXPECTED_REASONS=(
'PLAN-REPLACE-GAP: the replace detach gap of a mid-load plan rebuild loses first calls'
'SLOT-RECLAIM: descriptor-replaced slots of the same pinned object are never reused'
'PLAN-REPLACE-GAP: the replace detach gap of a mid-load plan rebuild loses first calls'
'PLAN-REPLACE-GAP: the replace detach gap of a mid-load plan rebuild loses first calls'
)

# expected_index NAME prints the cell's first EXPECTED_FAILURES index, or
# nothing (status 1) for a required cell.
expected_index() {
    local i
    for i in "${!EXPECTED_FAILURES[@]}"; do
        if [ "${EXPECTED_FAILURES[$i]}" = "$1" ]; then
            printf '%s' "$i"
            return 0
        fi
    done
    return 1
}

# expected_match NAME LOG prints "INDEX<TAB>MATCH" for the first declared
# signature of NAME that LOG contains, or nothing (status 1).
expected_match() {
    local i match
    for i in "${!EXPECTED_FAILURES[@]}"; do
        [ "${EXPECTED_FAILURES[$i]}" = "$1" ] || continue
        match=$(grep -m1 -oE "${EXPECTED_SIGNATURES[$i]}" "$2" 2>/dev/null | head -1)
        if [ -n "$match" ]; then
            printf '%s\t%s' "$i" "$match"
            return 0
        fi
    done
    return 1
}

# One results.jsonl row: exactly cell/pass/qualification/detail.
result() {
    python3 -I - "$1" "$2" "$3" "$4" <<'PY' | tee -a "$OUT/results.jsonl"
import json,sys
print(json.dumps({'cell':sys.argv[1],'pass':sys.argv[2]=='1','detail':sys.argv[3],'qualification':sys.argv[4]}))
PY
}

# judge_cell NAME LOG RC DURATION_MS appends the cell's row and returns 0
# for a pass. A zero rc alone is not a pass: the log must show exactly
# one passed test (libtest exits 0 on "0 passed, 1 ignored" when a cell
# gains #[ignore]), so a drifted or silent cell fails loudly.
judge_cell() {
    local name=$1 log=$2 rc=$3 duration_ms=$4
    local first detail matched index signature
    if [ "$rc" -eq 0 ] \
        && grep -q 'test result: ok\. 1 passed' "$log" 2>/dev/null; then
        result "$name" 1 "rc=0 ${duration_ms}ms ok" qualified
        return 0
    fi
    if [ "$rc" -ne 124 ] && matched=$(expected_match "$name" "$log"); then
        index=${matched%%$'\t'*}
        signature=${matched#*$'\t'}
        result "$name" 0 "${EXPECTED_REASONS[$index]}: rc=$rc ${duration_ms}ms: $signature" expected-failure
        return 0
    fi
    if [ "$rc" -eq 124 ]; then
        detail="TIMEOUT after 300s (${duration_ms}ms)"
    else
        first=$(grep -m1 -E 'panicked|FAILED|failures:|error|assertion' "$log" 2>/dev/null | tr -d '[:cntrl:]' | head -c 300)
        [ -n "$first" ] || first="see $(basename "$log")"
        detail="rc=$rc ${duration_ms}ms: $first"
    fi
    result "$name" 0 "$detail" failed
    return 1
}

# The terminal gate: SUMMARY over the rows, failing on a failed cell or
# a row set that is not exactly the expected cells.
write_summary() {
    local results=$1 summary=$2
    shift 2
    python3 -I - "$results" "$@" <<'PY' | tee "$summary"
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
expected=sys.argv[2:]; ids=[row['cell'] for row in rows]
valid=len(ids)==len(set(ids)) and set(ids)==set(expected)
failed=[r['cell'] for r in rows if r['qualification']=='failed']
# A passing expected-failure row is inconsistent (the judge never writes one).
failed+=[r['cell'] for r in rows if r['qualification']=='expected-failure' and r['pass']]
print('SUMMARY pass=%d fail=%d failed=%s terminal_rows_valid=%s' % (sum(r['pass'] for r in rows),len(failed),failed,valid))
sys.exit(1 if failed or not valid else 0)
PY
    [ "${PIPESTATUS[0]}" -eq 0 ]
}

# Fixture run of the judgment and the summary gate: no root, no build,
# no cells. Each check feeds judge_cell a canned libtest log and asserts
# the row; the tail asserts the 4-key row shape and the summary gate.
# Exit 0 only when every fixture is judged rightly.
run_self_test() {
    local self_tmp fails=0 n=0
    self_tmp=$(mktemp -d) || exit 2
    chmod 700 "$self_tmp" || exit 2
    OUT="$self_tmp/out"
    mkdir -p "$OUT" || exit 2
    : >"$OUT/results.jsonl"
    fail() {
        echo "self-test FAIL: $1" >&2
        fails=$((fails + 1))
    }
    # check NAME RC WANT_JUDGE_RC WANT_PASS WANT_QUAL WANT_DETAIL_SUBSTR < log-body-lines...
    check() {
        local name=$1 rc=$2 want_rc=$3 want_pass=$4 want_qual=$5 want_detail=$6
        local log="$self_tmp/case-$n.log" got_rc row got
        n=$((n + 1))
        printf '%s\n' "$LOG_BODY" >"$log"
        if judge_cell "$name" "$log" "$rc" 42; then got_rc=0; else got_rc=1; fi
        [ "$got_rc" -eq "$want_rc" ] || fail "$name rc=$rc: judge returned $got_rc, want $want_rc"
        row=$(tail -1 "$OUT/results.jsonl")
        got=$(printf '%s' "$row" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["pass"])')
        [ "$got" = "$want_pass" ] || fail "$name rc=$rc: pass=$got, want $want_pass ($row)"
        got=$(printf '%s' "$row" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["qualification"])')
        [ "$got" = "$want_qual" ] || fail "$name rc=$rc: qualification=$got, want $want_qual ($row)"
        case "$row" in
            *"$want_detail"*) ;;
            *) fail "$name rc=$rc: detail misses $want_detail ($row)" ;;
        esac
    }
    POSITIVE='test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
    # Every curated cell passes on the healthy shape (this also pins the
    # nine names: a dropped or renamed cell fails here, not silently). A
    # declared intermittent cell's pass is an ordinary qualified pass.
    for cell in "${CELLS[@]}"; do
        LOG_BODY=$POSITIVE
        check "$cell" 0 0 True qualified 'rc=0 42ms ok'
    done
    local never=privileged_run_tree_unprearmed_shortlived_never_pause_still_learns
    local arming=privileged_run_tree_arming_exhaustion_still_stages_and_counts
    local parallel=privileged_run_tree_unprearmed_shortlived_parallel_never_pause_covers_waves
    # Each declared signature of a cell is an expected failure...
    LOG_BODY="thread 'x' panicked at tests/run_tree.rs:330:5:
exact accounting failed: [\"undisclosed miss: 9 calls after the pre-attach window (C_GetInfo: observed 30 of 31 that entered after its first attach at 1; replace witness: 25 slot rows, 31 calls entered before the last re-attach)\"]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s"
    check "$never" 101 0 False expected-failure 'PLAN-REPLACE-GAP: the replace detach gap'
    LOG_BODY="p11scope: attach plan requires 2176 allocated slots but only 2112 are available; refusing to attach a prefix
thread 'x' panicked at tests/run_tree.rs:1249:5:
run exits with the shell's status
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s"
    check "$never" 101 0 False expected-failure 'SLOT-RECLAIM: descriptor-replaced slots'
    LOG_BODY="thread 'x' panicked at tests/run_tree.rs:330:5:
exact accounting failed: [\"undisclosed miss: 28 calls after the pre-attach window (C_GetSlotList: observed 50 of 62 that entered after its first attach at 1; replace witness: 7 slot rows, 62 calls entered before the last re-attach)\"]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 60.00s"
    check "$arming" 101 0 False expected-failure 'PLAN-REPLACE-GAP: the replace detach gap'
    check "$parallel" 101 0 False expected-failure 'PLAN-REPLACE-GAP: the replace detach gap'
    # ...while any other failure of it stays failed (never masked): the
    # arming cell declares no capacity signature, and its reserve-row
    # failure is not declared at all...
    LOG_BODY="p11scope: attach plan requires 2176 allocated slots but only 2112 are available; refusing to attach a prefix
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s"
    check "$arming" 101 1 False failed 'rc=101'
    LOG_BODY="thread 'x' panicked at tests/run_tree.rs:1503:5:
the reserve row is disclosed
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 60.00s"
    check "$arming" 101 1 False failed 'rc=101'
    LOG_BODY="thread 'x' panicked at tests/run_tree.rs:1249:5:
run exits with the shell's status
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s"
    check "$never" 101 1 False failed 'rc=101'
    # An overcount or probe loss is never the declared miss, even beside
    # one (the cell then names neither under the undisclosed-miss text).
    LOG_BODY="exact accounting failed (not an undisclosed miss): [\"C_GetInfo: observed 40 exceeds the 31 calls after its first attach plus 0 during it\"]; misses 1 ; window end 1
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s"
    check "$never" 101 1 False failed 'rc=101'
    LOG_BODY="exact accounting failed (not an undisclosed miss): [\"probe loss: C_GetInfo observed none of 31 calls after its first attach\"]; misses 0 ; window end 1
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s"
    check "$parallel" 101 1 False failed 'rc=101'
    # A partial miss without the report's replace evidence (no witness,
    # or more than could enter before the last re-attach) is not the
    # declared gap, and neither is a miss text that names no witness.
    LOG_BODY="exact accounting failed (not an undisclosed miss): [\"unexplained miss: C_GetInfo lost 1 calls after its first attach at 1 with no replace witness (one slot row, attached)\"]; misses 0 ; window end 1
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s"
    check "$never" 101 1 False failed 'rc=101'
    LOG_BODY="exact accounting failed (not an undisclosed miss): [\"unexplained miss: C_GetInfo lost 3 calls after its first attach at 1, more than the 2 that entered before the last re-attach at 8 (2 slot rows)\"]; misses 0 ; window end 1
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s"
    check "$parallel" 101 1 False failed 'rc=101'
    LOG_BODY="exact accounting failed: [\"undisclosed miss: 9 calls after the pre-attach window (C_GetInfo: observed 30 of 31 that started after 1)\"]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s"
    check "$arming" 101 1 False failed 'rc=101'
    # ...and so does a timeout, even with a signature in the log.
    LOG_BODY='undisclosed miss: 9 calls after the pre-attach window (C_GetInfo: observed 1 of 2)'
    check "$never" 124 1 False failed 'TIMEOUT after 300s'
    # A failing cell keeps its shape.
    LOG_BODY='test one ... FAILED
failures:
    one
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s'
    check 'privileged_run_tree_shell_wrapper_shows_grandchild_calls' 101 1 False failed 'rc=101'
    # A cell that gained #[ignore]: libtest exits 0 with nothing passed.
    LOG_BODY='test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 1 filtered out; finished in 0.00s'
    check 'privileged_run_tree_double_fork_shows_reparented_calls' 0 1 False failed 'rc=0'
    # A passing run with no result line fails instead of passing blind.
    LOG_BODY='test one ... ok'
    check 'privileged_run_tree_outliving_child_is_disclosed' 0 1 False failed 'rc=0'
    # Timeouts keep their shape, including the timeout detail.
    LOG_BODY='test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 300.00s'
    check 'privileged_run_tree_many_children_land_exact' 124 1 False failed 'TIMEOUT after 300s'
    # Rows carry exactly the four contract keys.
    while IFS= read -r row; do
        [ -n "$row" ] || continue
        keys=$(printf '%s' "$row" | python3 -I -c 'import json,sys; print(" ".join(sorted(json.load(sys.stdin).keys())))')
        [ "$keys" = "cell detail pass qualification" ] || fail "row keys drifted: $keys ($row)"
    done <"$OUT/results.jsonl"
    # The summary gate accepts exactly the full pass set.
    : >"$OUT/results.jsonl"
    for cell in "${CELLS[@]}"; do
        result "$cell" 1 'rc=0 42ms ok' qualified >/dev/null
    done
    write_summary "$OUT/results.jsonl" "$OUT/summary.txt" "${CELLS[@]}" >/dev/null \
        || fail "summary gate rejected the full pass set"
    grep -q 'terminal_rows_valid=True' "$OUT/summary.txt" \
        || fail "summary misses terminal_rows_valid=True"
    # The gate accepts the declared expected failures as failed rows...
    : >"$OUT/results.jsonl"
    for cell in "${CELLS[@]}"; do
        if expected_index "$cell" >/dev/null; then
            result "$cell" 0 'PLAN-REPLACE-GAP: rc=101 42ms' expected-failure >/dev/null
        else
            result "$cell" 1 'rc=0 42ms ok' qualified >/dev/null
        fi
    done
    write_summary "$OUT/results.jsonl" "$OUT/xfail.txt" "${CELLS[@]}" >/dev/null \
        || fail "summary gate rejected the declared expected failure"
    # ...and rejects an inconsistent passing expected-failure row.
    : >"$OUT/results.jsonl"
    for cell in "${CELLS[@]}"; do
        if expected_index "$cell" >/dev/null; then
            result "$cell" 1 'inconsistent' expected-failure >/dev/null
        else
            result "$cell" 1 'rc=0 42ms ok' qualified >/dev/null
        fi
    done
    if write_summary "$OUT/results.jsonl" "$OUT/xpass.txt" "${CELLS[@]}" >/dev/null 2>&1; then
        fail "summary gate accepted a passing expected-failure row"
    fi
    # A dropped row fails the gate.
    head -n 3 "$OUT/results.jsonl" >"$OUT/short.jsonl"
    if write_summary "$OUT/short.jsonl" "$OUT/short.txt" "${CELLS[@]}" >/dev/null 2>&1; then
        fail "summary gate accepted a dropped row"
    fi
    # A failed row fails the gate (no duplicate: the set stays exact).
    : >"$OUT/results.jsonl"
    for cell in "${CELLS[@]}"; do
        if [ "$cell" = 'privileged_run_tree_many_children_land_exact' ]; then
            result "$cell" 0 'rc=101 42ms: FAILED' failed >/dev/null
        else
            result "$cell" 1 'rc=0 42ms ok' qualified >/dev/null
        fi
    done
    if write_summary "$OUT/results.jsonl" "$OUT/fail.txt" "${CELLS[@]}" >/dev/null 2>&1; then
        fail "summary gate accepted a failed row"
    fi
    rm -rf "$self_tmp"
    if [ "$fails" -eq 0 ]; then
        echo "run-run-tree self-test: OK ($n fixtures judged rightly, rows and summary gate ok)"
        return 0
    fi
    echo "self-test: $fails failure(s)" >&2
    return 1
}

if [ $# -eq 1 ] && [ "${1-}" = "--self-test" ]; then
    run_self_test
    exit $?
fi

[ $# -eq 2 ] || {
    echo 'usage: run-run-tree.sh TESTBIN OUTDIR' >&2
    exit 2
}
BIN=$(realpath -e -- "$1") || exit 2
[ -x "$BIN" ] && [ -f "$BIN" ] || {
    echo "run-run-tree: TESTBIN is not executable: $1" >&2
    exit 2
}
OUT=$2
mkdir -p "$OUT" && chmod 755 "$OUT" || exit 2
OUT=$(realpath -e -- "$OUT") || exit 2

[ "$(id -u)" = 0 ] || {
    echo 'run-run-tree: must run as root (invoke via sudo -n)' >&2
    exit 77
}
command -v python3 >/dev/null 2>&1 || {
    echo 'run-run-tree: python3 is required' >&2
    exit 77
}
command -v timeout >/dev/null 2>&1 || {
    echo 'run-run-tree: timeout(1) is required' >&2
    exit 77
}

PRIVTMP=$(mktemp -d) || exit 2
chmod 700 "$PRIVTMP" || exit 2
if [ -n "${SUDO_UID:-}" ]; then
    chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$PRIVTMP" || exit 2
fi
cleanup() {
    if command -v pkill >/dev/null 2>&1; then
        # Best effort: only our own strays can name the fresh private
        # dir in their argv (the workload and capture take their
        # go/ledger/output paths there).
        pkill -f "$PRIVTMP" 2>/dev/null || true
    fi
    rm -rf "$PRIVTMP"
}
trap cleanup EXIT
trap 'exit 2' HUP TERM INT

: >"$OUT/results.jsonl"
failed=0
for cell in "${CELLS[@]}"; do
    # The script and the tests ship in one patch: selection drift is a
    # harness error, never a silent skip.
    selected=$("$BIN" --list --exact --ignored "$cell" --format terse 2>/dev/null | grep -c ': test')
    [ "$selected" -eq 1 ] || {
        echo "run-run-tree: $cell selects $selected tests, want 1" >&2
        exit 2
    }
    log="$OUT/$cell.log"
    start=$(date +%s%N)
    TMPDIR="$PRIVTMP" timeout 300 "$BIN" --exact --ignored "$cell" --nocapture --test-threads=1 >"$log" 2>&1
    rc=$?
    end=$(date +%s%N)
    duration_ms=$(((end - start) / 1000000))
    judge_cell "$cell" "$log" "$rc" "$duration_ms" || failed=1
done

write_summary "$OUT/results.jsonl" "$OUT/summary.txt" "${CELLS[@]}" || failed=1
test "$failed" -eq 0
