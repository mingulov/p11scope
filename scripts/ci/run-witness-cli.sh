#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# run-witness-cli.sh TESTBIN OUTDIR
# run-witness-cli.sh --self-test
#
# Runs the 7 pre-arm witness / learned-provider CLI cells (tests/prearm_witness_cli.rs)
# as root with exact-positive judging: every cell drives the real
# command line against SoftHSM and must exit 0 with exactly one passed
# test. The witness-cli CI job calls this on the host leg directly and
# inside vng guests via scripts/ci/witness-cli-vng.sh.
#
# Cells (exact test names, one row per test in OUTDIR/results.jsonl):
#   privileged_profile_pid_prearm_clean_exact_counts
#   privileged_profile_cgroup_prearm_clean_exact_counts
#   privileged_profile_system_prearm_clean_exact_counts
#   privileged_profile_system_learned_provider_second_round_catches_oneshots
#   privileged_profile_metrics_system_prearm_clean_exact_counts
#   privileged_profile_pid_prearm_twin_exact_window
#   privileged_trace_system_prearm_clean_exact_counts
#   #
# Each results.jsonl row carries exactly cell/pass/qualification/detail
# (the shared cell-result contract). A zero exit alone is not a pass:
# the log must show exactly one passed test, so a cell that gained
# #[ignore] (libtest exits 0 on "0 passed, 1 ignored") fails instead
# of passing silently.
#
# Arguments:
#   TESTBIN  the built prearm_witness_cli test executable (cargo test
#            --test prearm_witness_cli --no-run); the observer it drives
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
privileged_profile_pid_prearm_clean_exact_counts
privileged_profile_cgroup_prearm_clean_exact_counts
privileged_profile_system_prearm_clean_exact_counts
privileged_profile_system_learned_provider_second_round_catches_oneshots
privileged_profile_metrics_system_prearm_clean_exact_counts
privileged_profile_pid_prearm_twin_exact_window
privileged_trace_system_prearm_clean_exact_counts
)

# One results.jsonl row: exactly cell/pass/qualification/detail.
result() {
    python3 - "$1" "$2" "$3" "$4" <<'PY' | tee -a "$OUT/results.jsonl"
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
    local first detail
    if [ "$rc" -eq 0 ] \
        && grep -q 'test result: ok\. 1 passed' "$log" 2>/dev/null; then
        result "$name" 1 "rc=0 ${duration_ms}ms ok" qualified
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
    python3 - "$results" "$@" <<'PY' | tee "$summary"
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
expected=sys.argv[2:]; ids=[row['cell'] for row in rows]
valid=len(ids)==len(set(ids)) and set(ids)==set(expected)
failed=[r['cell'] for r in rows if r['qualification']=='failed']
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
        got=$(printf '%s' "$row" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pass"])')
        [ "$got" = "$want_pass" ] || fail "$name rc=$rc: pass=$got, want $want_pass ($row)"
        got=$(printf '%s' "$row" | python3 -c 'import json,sys; print(json.load(sys.stdin)["qualification"])')
        [ "$got" = "$want_qual" ] || fail "$name rc=$rc: qualification=$got, want $want_qual ($row)"
        case "$row" in
            *"$want_detail"*) ;;
            *) fail "$name rc=$rc: detail misses $want_detail ($row)" ;;
        esac
    }
    POSITIVE='test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
    # Every curated cell passes on the healthy shape (this also pins the
    # seven names: a dropped or renamed cell fails here, not silently).
    for cell in "${CELLS[@]}"; do
        LOG_BODY=$POSITIVE
        check "$cell" 0 0 True qualified 'rc=0 42ms ok'
    done
    # A failing cell keeps its shape.
    LOG_BODY='test one ... FAILED
failures:
    one
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s'
    check 'privileged_profile_pid_prearm_clean_exact_counts' 101 1 False failed 'rc=101'
    # A cell that gained #[ignore]: libtest exits 0 with nothing passed.
    LOG_BODY='test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 1 filtered out; finished in 0.00s'
    check 'privileged_profile_cgroup_prearm_clean_exact_counts' 0 1 False failed 'rc=0'
    # A passing run with no result line fails instead of passing blind.
    LOG_BODY='test one ... ok'
    check 'privileged_profile_system_prearm_clean_exact_counts' 0 1 False failed 'rc=0'
    # Timeouts keep their shape, including the timeout detail.
    LOG_BODY='test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 300.00s'
    check 'privileged_trace_system_prearm_clean_exact_counts' 124 1 False failed 'TIMEOUT after 300s'
    # Rows carry exactly the four contract keys.
    while IFS= read -r row; do
        [ -n "$row" ] || continue
        keys=$(printf '%s' "$row" | python3 -c 'import json,sys; print(" ".join(sorted(json.load(sys.stdin).keys())))')
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
    # A dropped row fails the gate.
    head -n 5 "$OUT/results.jsonl" >"$OUT/short.jsonl"
    if write_summary "$OUT/short.jsonl" "$OUT/short.txt" "${CELLS[@]}" >/dev/null 2>&1; then
        fail "summary gate accepted a dropped row"
    fi
    # A failed row fails the gate (no duplicate: the set stays exact).
    : >"$OUT/results.jsonl"
    for cell in "${CELLS[@]}"; do
        if [ "$cell" = 'privileged_profile_pid_prearm_twin_exact_window' ]; then
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
        echo "run-witness-cli self-test: OK ($n fixtures judged rightly, rows and summary gate ok)"
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
    echo 'usage: run-witness-cli.sh TESTBIN OUTDIR' >&2
    exit 2
}
BIN=$(realpath -e -- "$1") || exit 2
[ -x "$BIN" ] && [ -f "$BIN" ] || {
    echo "run-witness-cli: TESTBIN is not executable: $1" >&2
    exit 2
}
OUT=$2
mkdir -p "$OUT" && chmod 755 "$OUT" || exit 2
OUT=$(realpath -e -- "$OUT") || exit 2

[ "$(id -u)" = 0 ] || {
    echo 'run-witness-cli: must run as root (invoke via sudo -n)' >&2
    exit 77
}
command -v python3 >/dev/null 2>&1 || {
    echo 'run-witness-cli: python3 is required' >&2
    exit 77
}
command -v timeout >/dev/null 2>&1 || {
    echo 'run-witness-cli: timeout(1) is required' >&2
    exit 77
}

PRIVTMP=$(mktemp -d) || exit 2
chmod 700 "$PRIVTMP" || exit 2
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
        echo "run-witness-cli: $cell selects $selected tests, want 1" >&2
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
