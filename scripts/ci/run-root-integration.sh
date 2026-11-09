#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# run-root-integration.sh P11SCOPE OUTDIR [TEST_BIN_DIR]
# run-root-integration.sh --self-test
#
# Runs the dual-outcome integration tests plus the second-SIGINT
# report-truth test as root with the positive branch required: every cell
# runs with P11SCOPE_REQUIRE_CAPTURE=1, which turns the
# capture-unavailable branch of a converted test into a named failure
# instead of a passing refusal. Without the variable the tests keep
# their historical two-branch behavior (ordinary CI).
#
# Cells (exact test names, one row per test in OUTDIR/results.jsonl):
#   run_lifecycle::an_owned_run_reports_the_exact_child_status_and_reaps_it
#   run_lifecycle::a_signalled_child_reports_the_signal_status_the_shell_would
#   run_lifecycle::duration_expiry_hands_back_a_running_child_unless_kill_on_timeout_was_asked_for
#   run_lifecycle::the_run_only_evidence_field_reaches_the_written_document
#   pause::explicit_never_publishes_the_neutral_lattice
#   pause::explicit_auto_falls_back_to_a_partial_attempt_instead_of_failing
#   pause::explicit_always_refuses_rather_than_completing_unpaused
#   t2_cold_start::cold_start_profile_lane_is_honest_without_ambient_state
#   t2_cold_start::cold_start_run_lane_is_honest_without_ambient_state
#   ux_journeys::b6_doctor_reports_rows_and_verdict
#   ux_journeys::b7_run_refuses_without_capture_lane
#   ux_journeys::t3_f3_doctor_verdict_ends_with_newline
#   ux_journeys::j3_script_target_runs_like_any_program
#   run_abandon_report::second_sigint_during_teardown_publishes_truthful_report_and_exits_130
#
# Each results.jsonl row carries exactly cell/pass/qualification/detail (the
# shared cell-result contract); the detail embeds the observed branch (the
# test's P11SCOPE_TEST_BRANCH line) and the cell duration in milliseconds.
# A zero exit alone is not a pass: the log must show exactly one passed
# test, and the branch must be the cell's required one (positive for the
# converted cells, positive or refused for the always-refuses cell,
# completed for the abandon cell).
#
# Arguments:
#   P11SCOPE      the observer binary under test (exported to the cells
#                 as P11SCOPE_E2E_OBSERVER; the cells honor it over their
#                 build-time binary path).
#   OUTDIR        receives results.jsonl, summary.txt and one
#                 <target>.<test>.log per cell.
#   TEST_BIN_DIR  directory of prebuilt integration-test executables
#                 (CI build job output). When absent, the script builds
#                 the five targets itself; that build path is for
#                 development hosts only.
#
# --self-test runs the cell judgment and the summary gate against fixture
# logs (no root, no build, no cells) and fails on any misjudged fixture.
#
# Exit codes: 0 every qualified cell passed (expected failures aside);
# 1 a cell failed or passed unexpectedly; 2 harness error (bad arguments,
# missing binary, selection drift, local build failure); 77 prerequisite
# missing (not root, or a required tool absent).
#
# Apt prerequisites on ubuntu-26.04: none beyond the base image
# (bash, coreutils incl. timeout/realpath/date, procps, python3).
# The cells spawn only /bin/sh, /bin/true, sleep and bash fixtures;
# no provider packages are needed.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
ROOT=$(cd "$HERE/../.." && pwd) || exit 2
umask 022

# Expected failures: cell -> reason. A listed cell that fails is recorded
# as expected-failure; a listed cell that passes is recorded as qualified
# with an XPASS note and fails the run (an unexpected pass is a failure).
expected_reason() {
    case "$1" in
        *) return 1 ;;
    esac
}

# The branches that count as a pass for one cell, one per line: the
# converted dual-outcome cells must take the positive branch, the
# always-refuses cell passes on either of its genuine outcomes, and the
# abandon cell must complete. Anything else (unavailable, unknown, a
# drifted branch line) fails the cell.
expected_branch() {
    case "$1" in
        run_abandon_report::second_sigint_during_teardown_publishes_truthful_report_and_exits_130)
            printf 'completed\n'
            ;;
        pause::explicit_always_refuses_rather_than_completing_unpaused)
            printf 'positive\nrefused\n'
            ;;
        *)
            printf 'positive\n'
            ;;
    esac
}

# Resolve one integration-test executable: from the local-build map, else
# an exact file name in the bin dir, else exactly one hashed cargo
# artifact (name-<hash>).
resolve_bin() {
    local target=$1 exact match count=0
    if [ -n "$BIN_MAP" ]; then
        exact=$(sed -n "s/^$target=//p" "$BIN_MAP")
        [ -x "$exact" ] && [ -f "$exact" ] || {
            echo "run-root-integration: mapped $target binary is not executable: $exact" >&2
            return 1
        }
        printf '%s\n' "$exact"
        return 0
    fi
    exact="$BIN_DIR/$target"
    if [ -x "$exact" ] && [ -f "$exact" ]; then
        printf '%s\n' "$exact"
        return 0
    fi
    for match in "$BIN_DIR/$target"-*; do
        [ -x "$match" ] && [ -f "$match" ] || continue
        printf '%s\n' "$match"
        count=$((count + 1))
    done
    [ "$count" -eq 1 ] || {
        echo "run-root-integration: want exactly one $target executable in $BIN_DIR, found $count" >&2
        return 1
    }
}

# One results.jsonl row: exactly cell/pass/qualification/detail.
result() {
    python3 - "$1" "$2" "$3" "$4" <<'PY' | tee -a "$OUT/results.jsonl"
import json,sys
print(json.dumps({'cell':sys.argv[1],'pass':sys.argv[2]=='1','detail':sys.argv[3],'qualification':sys.argv[4]}))
PY
}

# judge_cell NAME LOG RC DURATION_MS appends the cell's row and returns 0
# for a pass or a recorded expected failure. A zero rc alone is not a pass: the log must show exactly one
# passed test (libtest exits 0 on "0 passed, 1 ignored" when a cell gains
# #[ignore]) and the observed branch must be the cell's required one, so a
# drifted or silent cell fails instead of passing as branch=unknown.
judge_cell() {
    local name=$1 log=$2 rc=$3 duration_ms=$4
    local branch first detail reason
    branch=$(grep -o 'P11SCOPE_TEST_BRANCH=[a-z]*' "$log" 2>/dev/null | tail -1 | cut -d= -f2)
    [ -n "$branch" ] || branch=unknown
    if [ "$rc" -eq 0 ] \
        && grep -q 'test result: ok\. 1 passed' "$log" 2>/dev/null \
        && expected_branch "$name" | grep -Fxq "$branch"; then
        if reason=$(expected_reason "$name"); then
            result "$name" 1 "XPASS (${duration_ms}ms): $reason no longer reproduces; drop the entry" qualified
            return 1
        fi
        result "$name" 1 "branch=$branch rc=0 ${duration_ms}ms" qualified
        return 0
    fi
    if [ "$rc" -eq 124 ]; then
        detail="branch=$branch TIMEOUT after 300s (${duration_ms}ms)"
    else
        first=$(grep -m1 -E 'P11SCOPE_REQUIRE_CAPTURE|panicked|FAILED|failures:|error' "$log" 2>/dev/null | tr -d '[:cntrl:]' | head -c 300)
        [ -n "$first" ] || first="see $(basename "$log")"
        detail="branch=$branch rc=$rc ${duration_ms}ms: $first"
    fi
    if reason=$(expected_reason "$name"); then
        result "$name" 0 "$detail (expected: $reason)" expected-failure
        return 0
    else
        result "$name" 0 "$detail" failed
    fi
    return 1
}

# The terminal gate: SUMMARY over the rows, failing on a failed cell, an
# unexpected pass, or a row set that is not exactly the expected cells.
write_summary() {
    local results=$1 summary=$2
    shift 2
    python3 - "$results" "$@" <<'PY' | tee "$summary"
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
expected=sys.argv[2:]; ids=[row['cell'] for row in rows]
valid=len(ids)==len(set(ids)) and set(ids)==set(expected)
failed=[r['cell'] for r in rows if r['qualification']=='failed']
xpass=[r['cell'] for r in rows if 'XPASS' in r['detail']]
print('SUMMARY pass=%d fail=%d expected_fail=%d xpass=%s failed=%s terminal_rows_valid=%s' % (sum(r['pass'] for r in rows),len(failed),sum(1 for r in rows if r['qualification']=='expected-failure'),xpass,failed,valid))
sys.exit(1 if failed or xpass or not valid else 0)
PY
    [ "${PIPESTATUS[0]}" -eq 0 ]
}

# Fixture run of the judgment and the summary gate: no root, no build, no
# cells. Each check feeds judge_cell a canned libtest log and asserts the
# row; the tail asserts the 4-key row shape, the observer-variable name,
# and the summary gate. Exit 0 only when every fixture is judged rightly.
run_self_test() {
    local self_tmp fails=0 n=0
    self_tmp=$(mktemp -d) || exit 2
    chmod 700 "$self_tmp" || exit 2
    OUT="$self_tmp/out"
    mkdir -p "$OUT" || exit 2
    : >"$OUT/results.jsonl"
    # In self-test only, one fixture cell is an expected failure, so both
    # the expected-failure and the XPASS paths are exercised.
    expected_reason() {
        case "$1" in
            fixture::expected_failure_cell) printf 'self-test expected reason\n' ;;
            *) return 1 ;;
        esac
    }
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
    POSITIVE='P11SCOPE_TEST_BRANCH=positive
test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
    # A cell that gained #[ignore]: libtest exits 0 with nothing passed.
    LOG_BODY='test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 1 filtered out; finished in 0.00s'
    check 'run_lifecycle::an_owned_run_reports_the_exact_child_status_and_reaps_it' 0 1 False failed 'branch=unknown rc=0'
    # A converted cell on its unavailable branch must fail even with rc 0.
    LOG_BODY='P11SCOPE_TEST_BRANCH=unavailable
test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
    check 'pause::explicit_never_publishes_the_neutral_lattice' 0 1 False failed 'branch=unavailable rc=0'
    # A passing run that printed no branch line fails instead of passing
    # as branch=unknown.
    LOG_BODY='test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
    check 't2_cold_start::cold_start_profile_lane_is_honest_without_ambient_state' 0 1 False failed 'branch=unknown rc=0'
    # The healthy paths.
    LOG_BODY=$POSITIVE
    check 'ux_journeys::b6_doctor_reports_rows_and_verdict' 0 0 True qualified 'branch=positive rc=0'
    LOG_BODY='P11SCOPE_TEST_BRANCH=refused
test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
    check 'pause::explicit_always_refuses_rather_than_completing_unpaused' 0 0 True qualified 'branch=refused rc=0'
    LOG_BODY=$POSITIVE
    check 'pause::explicit_always_refuses_rather_than_completing_unpaused' 0 0 True qualified 'branch=positive rc=0'
    LOG_BODY='P11SCOPE_TEST_BRANCH=completed
test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.21s'
    check 'run_abandon_report::second_sigint_during_teardown_publishes_truthful_report_and_exits_130' 0 0 True qualified 'branch=completed rc=0'
    # The completed branch on a converted cell is a misjudged branch, not a pass.
    LOG_BODY='P11SCOPE_TEST_BRANCH=completed
test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
    check 'ux_journeys::b6_doctor_reports_rows_and_verdict' 0 1 False failed 'branch=completed rc=0'
    # Ordinary failures keep their shape, including the timeout detail.
    LOG_BODY='test one ... FAILED
failures:
    one
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s'
    check 'ux_journeys::b7_run_refuses_without_capture_lane' 101 1 False failed 'rc=101'
    LOG_BODY='test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 300.00s'
    check 'ux_journeys::t3_f3_doctor_verdict_ends_with_newline' 124 1 False failed 'TIMEOUT after 300s'
    # Expected-failure paths: a failing listed cell is recorded without
    # failing the run, a passing listed cell fails the run.
    LOG_BODY='test one ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s'
    check 'fixture::expected_failure_cell' 101 0 False expected-failure '(expected: self-test expected reason)'
    LOG_BODY=$POSITIVE
    check 'fixture::expected_failure_cell' 0 1 True qualified 'XPASS'
    # Every emitted row carries exactly the shared 4-key shape.
    python3 - "$OUT/results.jsonl" <<'PY' || fail 'row shape drifted from cell/pass/qualification/detail'
import json,sys
for number, line in enumerate(open(sys.argv[1]), 1):
    if not line.strip():
        continue
    row = json.loads(line)
    assert set(row) == {'cell', 'pass', 'qualification', 'detail'}, (number, sorted(row))
PY
    # The staged observer reaches the cells through the dedicated variable,
    # never the matrix one a stray export would smuggle in. The needle is
    # spelled in two halves so this check does not match its own source.
    if ! grep -q 'P11SCOPE_E2E_OBSERVER="$P"' "${BASH_SOURCE[0]}"; then
        fail 'the P11SCOPE_E2E_OBSERVER export is missing'
    fi
    matrix_var="P11SCOPE_""BIN"
    if grep -v '^[[:space:]]*#' "${BASH_SOURCE[0]}" | grep -q "$matrix_var"; then
        fail 'the matrix observer variable is still referenced outside comments'
    fi
    # The terminal gate: green and expected-failure rows pass; a failed
    # cell, an XPASS row, a missing row, a duplicate row, and an extra row
    # each fail.
    gate="$self_tmp/gate.jsonl"
    printf '%s\n' '{"cell": "a", "pass": true, "detail": "ok", "qualification": "qualified"}' >"$gate"
    write_summary "$gate" "$self_tmp/gate.txt" a >/dev/null 2>&1 || fail 'summary rejects a green row set'
    printf '%s\n' '{"cell": "a", "pass": false, "detail": "no", "qualification": "failed"}' >"$gate"
    write_summary "$gate" "$self_tmp/gate.txt" a >/dev/null 2>&1 && fail 'summary accepts a failed cell'
    printf '%s\n' '{"cell": "a", "pass": true, "detail": "XPASS: fixed", "qualification": "qualified"}' >"$gate"
    write_summary "$gate" "$self_tmp/gate.txt" a >/dev/null 2>&1 && fail 'summary accepts an unexpected pass'
    printf '%s\n' '{"cell": "a", "pass": true, "detail": "ok", "qualification": "qualified"}' >"$gate"
    write_summary "$gate" "$self_tmp/gate.txt" a b >/dev/null 2>&1 && fail 'summary accepts a missing row'
    printf '%s\n' '{"cell": "a", "pass": true, "detail": "ok", "qualification": "qualified"}' '{"cell": "a", "pass": true, "detail": "ok", "qualification": "qualified"}' >"$gate"
    write_summary "$gate" "$self_tmp/gate.txt" a >/dev/null 2>&1 && fail 'summary accepts a duplicate row'
    printf '%s\n' '{"cell": "a", "pass": true, "detail": "ok", "qualification": "qualified"}' '{"cell": "b", "pass": true, "detail": "ok", "qualification": "qualified"}' >"$gate"
    write_summary "$gate" "$self_tmp/gate.txt" a >/dev/null 2>&1 && fail 'summary accepts an extra row'
    printf '%s\n' '{"cell": "a", "pass": false, "detail": "no (expected: reason)", "qualification": "expected-failure"}' >"$gate"
    write_summary "$gate" "$self_tmp/gate.txt" a >/dev/null 2>&1 || fail 'summary rejects an expected-failure row'
    rm -rf "$self_tmp"
    if [ "$fails" -eq 0 ]; then
        echo "self-test: $n fixtures judged rightly, rows and summary gate ok"
        return 0
    fi
    echo "self-test: $fails failure(s)" >&2
    return 1
}

if [ $# -eq 1 ] && [ "${1-}" = "--self-test" ]; then
    run_self_test
    exit $?
fi

[ $# -ge 2 ] && [ $# -le 3 ] || {
    echo 'usage: run-root-integration.sh P11SCOPE OUTDIR [TEST_BIN_DIR]' >&2
    exit 2
}
P=$(realpath -e -- "$1") || exit 2
[ -x "$P" ] || {
    echo "run-root-integration: P11SCOPE is not executable: $1" >&2
    exit 2
}
OUT=$2
TEST_BIN_DIR=${3:-}
mkdir -p "$OUT" && chmod 755 "$OUT" || exit 2
OUT=$(realpath -e -- "$OUT") || exit 2

[ "$(id -u)" = 0 ] || {
    echo 'run-root-integration: must run as root (invoke via sudo -n)' >&2
    exit 77
}
command -v python3 >/dev/null 2>&1 || {
    echo 'run-root-integration: python3 is required' >&2
    exit 77
}
command -v timeout >/dev/null 2>&1 || {
    echo 'run-root-integration: timeout(1) is required' >&2
    exit 77
}

TARGETS=(run_lifecycle pause t2_cold_start ux_journeys run_abandon_report)
# target:test[:ignored]
CELLS=(
    run_lifecycle:an_owned_run_reports_the_exact_child_status_and_reaps_it
    run_lifecycle:a_signalled_child_reports_the_signal_status_the_shell_would
    run_lifecycle:duration_expiry_hands_back_a_running_child_unless_kill_on_timeout_was_asked_for
    run_lifecycle:the_run_only_evidence_field_reaches_the_written_document
    pause:explicit_never_publishes_the_neutral_lattice
    pause:explicit_auto_falls_back_to_a_partial_attempt_instead_of_failing
    pause:explicit_always_refuses_rather_than_completing_unpaused
    t2_cold_start:cold_start_profile_lane_is_honest_without_ambient_state
    t2_cold_start:cold_start_run_lane_is_honest_without_ambient_state
    ux_journeys:b6_doctor_reports_rows_and_verdict
    ux_journeys:b7_run_refuses_without_capture_lane
    ux_journeys:t3_f3_doctor_verdict_ends_with_newline
    ux_journeys:j3_script_target_runs_like_any_program
    run_abandon_report:second_sigint_during_teardown_publishes_truthful_report_and_exits_130:ignored
)

PRIVTMP=$(mktemp -d) || exit 2
chmod 700 "$PRIVTMP" || exit 2
cleanup() {
    if command -v pkill >/dev/null 2>&1; then
        # Best effort: only our own strays can name the fresh private
        # dir or the suite's distinctive markers in their argv.
        pkill -f "$PRIVTMP" 2>/dev/null || true
        pkill -f 'abandon-probe-sleep' 2>/dev/null || true
        pkill -f 'sleep 287.4139' 2>/dev/null || true
    fi
    rm -rf "$PRIVTMP"
}
trap cleanup EXIT
trap 'exit 2' HUP TERM INT

BIN_DIR=""
BIN_MAP=""
if [ -n "$TEST_BIN_DIR" ]; then
    BIN_DIR=$(realpath -e -- "$TEST_BIN_DIR") || exit 2
else
    # Development-only build path: CI always passes TEST_BIN_DIR with
    # the build job's executables.
    command -v cargo >/dev/null 2>&1 || {
        echo 'run-root-integration: local build needs cargo on PATH (or pass TEST_BIN_DIR)' >&2
        exit 2
    }
    toolchain=$(cat "$ROOT/.release-rust-version") || exit 2
    test_args=()
    for target in "${TARGETS[@]}"; do test_args+=(--test "$target"); done
    (cd "$ROOT" && ./scripts/cargo.sh "+$toolchain" test --locked --no-run \
        --target-dir "$OUT/target" "${test_args[@]}" \
        --message-format=json >"$OUT/build.jsonl") || {
        echo 'run-root-integration: local test-target build failed' >&2
        exit 2
    }
    BIN_MAP="$OUT/test-bins.map"
    python3 - "$OUT/build.jsonl" "$BIN_MAP" <<'PY' || exit 2
import json,sys
bins={}
for line in open(sys.argv[1]):
    d=json.loads(line)
    if d.get('reason')=='compiler-artifact' and d.get('executable') and 'test' in d['target']['kind']:
        bins[d['target']['name']]=d['executable']
want=['run_lifecycle','pause','t2_cold_start','ux_journeys','run_abandon_report']
missing=[t for t in want if t not in bins]
if missing:
    sys.stderr.write('missing test executables: %s\n' % ' '.join(missing))
    sys.exit(1)
with open(sys.argv[2],'w') as out:
    for t in want:
        out.write('%s=%s\n' % (t,bins[t]))
PY
fi

: >"$OUT/results.jsonl"
failed=0
EXPECTED=()
for cell in "${CELLS[@]}"; do
    target=${cell%%:*}
    rest=${cell#*:}
    test=${rest%%:*}
    ignored=""
    [ "$rest" = "$test" ] || ignored="--ignored"
    bin=$(resolve_bin "$target") || exit 2
    # The script and the tests ship in one patch: selection drift is a
    # harness error, never a silent skip.
    if [ -n "$ignored" ]; then
        selected=$("$bin" --list --exact --ignored "$test" --format terse 2>/dev/null | grep -c ': test')
    else
        selected=$("$bin" --list --exact "$test" --format terse 2>/dev/null | grep -c ': test')
    fi
    [ "$selected" -eq 1 ] || {
        echo "run-root-integration: $target :: $test selects $selected tests, want 1" >&2
        exit 2
    }
    log="$OUT/$target.$test.log"
    start=$(date +%s%N)
    if [ -n "$ignored" ]; then
        P11SCOPE_REQUIRE_CAPTURE=1 P11SCOPE_E2E_OBSERVER="$P" TMPDIR="$PRIVTMP" \
            timeout 300 "$bin" --exact --ignored "$test" --nocapture --test-threads=1 >"$log" 2>&1
    else
        P11SCOPE_REQUIRE_CAPTURE=1 P11SCOPE_E2E_OBSERVER="$P" TMPDIR="$PRIVTMP" \
            timeout 300 "$bin" --exact "$test" --nocapture --test-threads=1 >"$log" 2>&1
    fi
    rc=$?
    end=$(date +%s%N)
    duration_ms=$(((end - start) / 1000000))
    name="$target::$test"
    EXPECTED+=("$name")
    judge_cell "$name" "$log" "$rc" "$duration_ms" || failed=1
done

write_summary "$OUT/results.jsonl" "$OUT/summary.txt" "${EXPECTED[@]}" || failed=1
test "$failed" -eq 0
