#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# run-root-integration.sh P11SCOPE OUTDIR [TEST_BIN_DIR]
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
#   pause::omitted_pause_is_never_and_publishes_the_neutral_lattice
#   pause::explicit_auto_falls_back_to_a_partial_attempt_instead_of_failing
#   pause::explicit_always_refuses_rather_than_completing_unpaused
#   t2_cold_start::cold_start_profile_lane_is_honest_without_ambient_state
#   t2_cold_start::cold_start_run_lane_is_honest_without_ambient_state
#   ux_journeys::b6_doctor_reports_rows_and_verdict
#   ux_journeys::b7_run_refuses_without_capture_lane
#   ux_journeys::t3_f3_doctor_verdict_ends_with_newline
#   run_abandon_report::second_sigint_during_teardown_publishes_truthful_report_and_exits_130
#
# Each results.jsonl row carries cell/pass/qualification/detail plus the
# observed branch (the test's P11SCOPE_TEST_BRANCH line: positive,
# unavailable, refused, completed) and the cell duration in milliseconds.
#
# Arguments:
#   P11SCOPE      the observer binary under test (exported to the cells
#                 as P11SCOPE_BIN; the cells honor it over their
#                 build-time binary path).
#   OUTDIR        receives results.jsonl, summary.txt and one
#                 <target>.<test>.log per cell.
#   TEST_BIN_DIR  directory of prebuilt integration-test executables
#                 (CI build job output). When absent, the script builds
#                 the five targets itself; that build path is for
#                 development hosts only.
#
# Exit codes: 0 every qualified cell passed (expected failures aside);
# 1 a cell failed; 2 harness error (bad arguments, missing binary,
# selection drift, local build failure); 77 prerequisite missing
# (not root, or a required tool absent).
#
# Apt prerequisites on ubuntu-26.04: none beyond the base image
# (bash, coreutils incl. timeout/realpath/date, procps, python3).
# The cells spawn only /bin/sh, /bin/true, sleep and bash fixtures;
# no provider packages are needed.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
ROOT=$(cd "$HERE/../.." && pwd) || exit 2
umask 022

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
    pause:omitted_pause_is_never_and_publishes_the_neutral_lattice
    pause:explicit_auto_falls_back_to_a_partial_attempt_instead_of_failing
    pause:explicit_always_refuses_rather_than_completing_unpaused
    t2_cold_start:cold_start_profile_lane_is_honest_without_ambient_state
    t2_cold_start:cold_start_run_lane_is_honest_without_ambient_state
    ux_journeys:b6_doctor_reports_rows_and_verdict
    ux_journeys:b7_run_refuses_without_capture_lane
    ux_journeys:t3_f3_doctor_verdict_ends_with_newline
    run_abandon_report:second_sigint_during_teardown_publishes_truthful_report_and_exits_130:ignored
)

# Expected failures: cell -> reason. A listed cell that fails is recorded
# as expected-failure; a listed cell that passes is recorded as qualified
# with an XPASS note (the product may have been fixed; drop the entry).
expected_reason() {
    case "$1" in
        *) return 1 ;;
    esac
}

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

result() {
    python3 - "$1" "$2" "$3" "$4" "$5" "$6" <<'PY' | tee -a "$OUT/results.jsonl"
import json,sys
print(json.dumps({'cell':sys.argv[1],'pass':sys.argv[2]=='1','detail':sys.argv[3],'qualification':sys.argv[4],'branch':sys.argv[5],'duration_ms':int(sys.argv[6])}))
PY
}

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
        P11SCOPE_REQUIRE_CAPTURE=1 P11SCOPE_BIN="$P" TMPDIR="$PRIVTMP" \
            timeout 300 "$bin" --exact --ignored "$test" --nocapture --test-threads=1 >"$log" 2>&1
    else
        P11SCOPE_REQUIRE_CAPTURE=1 P11SCOPE_BIN="$P" TMPDIR="$PRIVTMP" \
            timeout 300 "$bin" --exact "$test" --nocapture --test-threads=1 >"$log" 2>&1
    fi
    rc=$?
    end=$(date +%s%N)
    duration_ms=$(((end - start) / 1000000))
    branch=$(grep -o 'P11SCOPE_TEST_BRANCH=[a-z]*' "$log" 2>/dev/null | tail -1 | cut -d= -f2)
    [ -n "$branch" ] || branch=unknown
    name="$target::$test"
    EXPECTED+=("$name")
    if [ "$rc" -eq 0 ]; then
        if reason=$(expected_reason "$name"); then
            result "$name" 1 "XPASS (${duration_ms}ms): $reason no longer reproduces; drop the entry" qualified "$branch" "$duration_ms"
        else
            result "$name" 1 "branch=$branch rc=0 ${duration_ms}ms" qualified "$branch" "$duration_ms"
        fi
        continue
    fi
    if [ "$rc" -eq 124 ]; then
        detail="branch=$branch TIMEOUT after 300s (${duration_ms}ms)"
    else
        first=$(grep -m1 -E 'P11SCOPE_REQUIRE_CAPTURE|panicked|FAILED|failures:|error' "$log" 2>/dev/null | tr -d '[:cntrl:]' | head -c 300)
        [ -n "$first" ] || first="see $target.$test.log"
        detail="branch=$branch rc=$rc ${duration_ms}ms: $first"
    fi
    if reason=$(expected_reason "$name"); then
        result "$name" 0 "$detail (expected: $reason)" expected-failure "$branch" "$duration_ms"
    else
        result "$name" 0 "$detail" failed "$branch" "$duration_ms"
        failed=1
    fi
done

python3 - "$OUT/results.jsonl" "${EXPECTED[@]}" <<'PY' | tee "$OUT/summary.txt"
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
expected=sys.argv[2:]; ids=[row['cell'] for row in rows]
valid=len(ids)==len(set(ids)) and set(ids)==set(expected)
failed=[r['cell'] for r in rows if r['qualification']=='failed']
xpass=[r['cell'] for r in rows if 'XPASS' in r['detail']]
print('SUMMARY pass=%d fail=%d expected_fail=%d xpass=%s failed=%s terminal_rows_valid=%s' % (sum(r['pass'] for r in rows),len(failed),sum(1 for r in rows if r['qualification']=='expected-failure'),xpass,failed,valid))
sys.exit(1 if failed or not valid else 0)
PY
[ "${PIPESTATUS[0]}" -eq 0 ] || failed=1
test "$failed" -eq 0
