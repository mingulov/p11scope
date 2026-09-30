#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# release-gate.sh — checked-in ordinary release gate runner.
#
# Runs the ordinary (unprivileged, host) release gates in order — a fmt
# check, then per-profile check/test/clippy — logging each step to
# OUTDIR/<step>.log and writing a machine-readable OUTDIR/result.json
# verdict. The verdict never trusts an exit code alone: every
# "test result:" line of each test step is parsed, and the gate fails on
# any failure, any empty run, or any test target without a result line.
# The first failing step stops the gate (fail fast); result.json then
# holds the steps that ran.
#
# Cargo always runs through "mise exec -- ./scripts/cargo.sh +<release>"
# (release Rust version from .release-rust-version), with
# TMPDIR=/var/tmp/p11scope-ws-tmp and CARGO_BUILD_JOBS (default 4). The
# wide profile follows .github/workflows/ci.yml: it selects the p11scope
# package ("-p p11scope --features wide-detailed-2112") instead of the
# workspace, since the feature belongs to that package.
set -eu

GATE_ROOT=$(CDPATH= cd -P "$(dirname "$0")/.." && pwd)

GATE_TMPDIR=/var/tmp/p11scope-ws-tmp
JOBS=${CARGO_BUILD_JOBS:-4}
WIDE_FEATURE=wide-detailed-2112
SELF_TEST_WORK=
VERDICT_PASSED=0
VERDICT_FAILED=0
VERDICT_IGNORED=0

usage_text() {
    cat <<'EOF'
usage: release-gate.sh OUTDIR [--profile default|wide|both] [--target-dir DIR] [--allow-dirty] [--dry-run]
       release-gate.sh --self-test
EOF
}

usage() {
    usage_text >&2
    exit 2
}

# A nohup-poisoned environment (SIGHUP ignored) breaks the signal tests the
# gate runs while everything else looks green. Prove SIGHUP still kills
# before doing anything else: a shell that HUPs itself must die with 129.
positive_control() {
    set +e
    # The outer redirect swallows only bash's own "Hangup" death notice for
    # the deliberately killed child; the exit code still comes through.
    { sh -c 'kill -HUP $$' >/dev/null 2>&1; } 2>/dev/null
    control_status=$?
    set -e
    if [ "$control_status" -ne 129 ]; then
        echo "release-gate: ABORT: positive control failed: sh -c 'kill -HUP \$\$' exited $control_status, want 129 (SIGHUP is ignored here; a nohup-poisoned environment breaks signal tests)" >&2
        exit 1
    fi
}

ensure_gate_tmpdir() {
    if [ ! -d "$GATE_TMPDIR" ]; then
        (umask 077; mkdir -p "$GATE_TMPDIR")
    fi
}

# Sum of the "N <word>" counters across every "test result:" line in a log.
sum_field() {
    grep 'test result:' "$1" | grep -o "[0-9][0-9]* $2" | grep -o '^[0-9][0-9]*' | {
        total=0
        while read -r count; do
            total=$((total + count))
        done
        echo "$total"
    }
}

# verdict_test_log <log>: 0 when the log proves a real passing run — no
# failure marker, failed=0, passed>0, and at least one result line per
# "Running " target (doc-tests add result lines without a Running line,
# so more results than targets is fine). Sets VERDICT_PASSED/
# VERDICT_FAILED/VERDICT_IGNORED for result.json either way. Pure: reads
# the log, reports to stderr, never writes to the log.
verdict_test_log() {
    local log running results
    log=$1
    VERDICT_PASSED=0
    VERDICT_FAILED=0
    VERDICT_IGNORED=0
    if [ ! -f "$log" ]; then
        echo "release-gate: test verdict: missing log $log" >&2
        return 1
    fi
    running=$(grep -c 'Running ' "$log" || true)
    results=$(grep -c 'test result:' "$log" || true)
    VERDICT_PASSED=$(sum_field "$log" passed)
    VERDICT_FAILED=$(sum_field "$log" failed)
    VERDICT_IGNORED=$(sum_field "$log" ignored)
    if grep -q 'FAILED' "$log"; then
        echo "release-gate: test verdict: $log contains a failed test target" >&2
        return 1
    fi
    if [ "$VERDICT_FAILED" -ne 0 ]; then
        echo "release-gate: test verdict: $log reports failed=$VERDICT_FAILED" >&2
        return 1
    fi
    if [ "$VERDICT_PASSED" -eq 0 ]; then
        echo "release-gate: test verdict: $log reports 0 passed" >&2
        return 1
    fi
    if [ "$results" -lt "$running" ]; then
        echo "release-gate: test verdict: $log ran $running test targets but has $results result lines" >&2
        return 1
    fi
    return 0
}

expect_accept() {
    if verdict_test_log "$1" 2>/dev/null; then
        return 0
    fi
    echo "self-test FAIL: $2 unexpectedly rejected" >&2
    exit 1
}

expect_reject() {
    if verdict_test_log "$1" 2>/dev/null; then
        echo "self-test FAIL: $2 unexpectedly accepted" >&2
        exit 1
    fi
    return 0
}

self_test_cleanup() {
    rm -rf "$SELF_TEST_WORK"
}

self_test() {
    local work clean zero failed missing empty doctest stray
    ensure_gate_tmpdir
    work=$(mktemp -d "$GATE_TMPDIR/release-gate-selftest-XXXXXX")
    SELF_TEST_WORK=$work
    trap self_test_cleanup EXIT
    clean=$work/clean.log
    {
        echo '     Running unittests src/lib.rs (target/debug/deps/p11scope-abc123)'
        echo 'test result: ok. 12 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s'
        echo '     Running tests/artifact_contracts.rs (target/debug/deps/artifact_contracts-def456)'
        echo 'test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s'
    } >"$clean"
    expect_accept "$clean" clean-sample
    zero=$work/zero.log
    {
        echo '     Running unittests src/lib.rs (target/debug/deps/p11scope-abc123)'
        echo 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s'
    } >"$zero"
    expect_reject "$zero" zero-passed-target
    failed=$work/failed.log
    {
        echo '     Running unittests src/lib.rs (target/debug/deps/p11scope-abc123)'
        echo 'test result: FAILED. 3 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
    } >"$failed"
    expect_reject "$failed" failed-result
    missing=$work/missing.log
    {
        echo '     Running unittests src/lib.rs (target/debug/deps/p11scope-abc123)'
        echo 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
        echo '     Running tests/artifact_contracts.rs (target/debug/deps/artifact_contracts-def456)'
    } >"$missing"
    expect_reject "$missing" missing-result-line
    empty=$work/empty.log
    : >"$empty"
    expect_reject "$empty" empty-log
    doctest=$work/doctest.log
    {
        echo '     Running unittests src/lib.rs (target/debug/deps/p11scope-abc123)'
        echo 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
        echo '   Doc-tests p11scope'
        echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.30s'
    } >"$doctest"
    expect_accept "$doctest" doctest-extra-result
    stray=$work/stray.log
    {
        echo '     Running unittests src/lib.rs (target/debug/deps/p11scope-abc123)'
        echo 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
        echo 'note: quarantined probe marked FAILED upstream'
    } >"$stray"
    expect_reject "$stray" stray-failed-token
    rm -rf "$work"
    SELF_TEST_WORK=
    trap - EXIT
    echo "release-gate self-test: OK"
}

# One exact, re-runnable command line for a gate step.
display_cmd() {
    local line word
    line="TMPDIR=$GATE_TMPDIR CARGO_BUILD_JOBS=$JOBS mise exec -- ./scripts/cargo.sh +$(cat "$GATE_ROOT/.release-rust-version")"
    for word in "$@"; do
        line="$line $(printf '%q' "$word")"
    done
    printf '%s\n' "$line"
}

# Invoke the callback once per gate step, in order:
# callback <name> <kind> <cargo args...>. Stops at the first callback
# failure so a red step fails the gate fast.
for_each_step() {
    local callback profile
    callback=$1
    "$callback" fmt other fmt --all -- --check || return 1
    for profile in "${PROFILES[@]}"; do
        if [ "$profile" = "wide" ]; then
            "$callback" "check-$profile" other check --locked --offline -p p11scope --all-targets --features "$WIDE_FEATURE" "${TARGET_ARGS[@]}" || return 1
            "$callback" "test-$profile" test test --locked --offline -p p11scope --all-targets --features "$WIDE_FEATURE" "${TARGET_ARGS[@]}" --no-fail-fast || return 1
            "$callback" "clippy-$profile" other clippy --locked --offline -p p11scope --all-targets --features "$WIDE_FEATURE" "${TARGET_ARGS[@]}" -- -D warnings || return 1
        else
            "$callback" "check-$profile" other check --locked --offline --workspace --all-targets "${TARGET_ARGS[@]}" || return 1
            "$callback" "test-$profile" test test --locked --offline --workspace --all-targets "${TARGET_ARGS[@]}" --no-fail-fast || return 1
            "$callback" "clippy-$profile" other clippy --locked --offline --workspace --all-targets "${TARGET_ARGS[@]}" -- -D warnings || return 1
        fi
    done
    return 0
}

print_step() {
    shift 2
    display_cmd "$@"
}

run_step() {
    local name kind log start_ts start_s end_ts end_s seconds code
    local passed failed ignored step_ok verdict_code row
    name=$1
    kind=$2
    shift 2
    log="$OUTDIR_ABS/$name.log"
    start_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    start_s=$(date +%s)
    {
        echo "=== release-gate step $name start $start_ts ==="
        printf '+ %s\n' "$(display_cmd "$@")"
    } >"$log"
    set +e
    TMPDIR="$GATE_TMPDIR" CARGO_BUILD_JOBS="$JOBS" mise exec -- ./scripts/cargo.sh "+$(cat "$GATE_ROOT/.release-rust-version")" "$@" >>"$log" 2>&1
    code=$?
    set -e
    end_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    end_s=$(date +%s)
    seconds=$((end_s - start_s))
    echo "=== release-gate step $name end $end_ts exit $code seconds $seconds ===" >>"$log"
    passed=0
    failed=0
    ignored=0
    step_ok=1
    if [ "$code" -ne 0 ]; then
        step_ok=0
    fi
    if [ "$kind" = "test" ]; then
        set +e
        verdict_test_log "$log"
        verdict_code=$?
        set -e
        passed=$VERDICT_PASSED
        failed=$VERDICT_FAILED
        ignored=$VERDICT_IGNORED
        if [ "$verdict_code" -ne 0 ]; then
            step_ok=0
            echo "release-gate: test totals for $name: passed=$passed failed=$failed ignored=$ignored verdict=FAIL" >>"$log"
        else
            echo "release-gate: test totals for $name: passed=$passed failed=$failed ignored=$ignored verdict=PASS" >>"$log"
        fi
    fi
    printf -v row '{"name":"%s","exit":%d,"seconds":%d,"test_totals":{"passed":%d,"failed":%d,"ignored":%d}}' \
        "$name" "$code" "$seconds" "$passed" "$failed" "$ignored"
    JSON_ROWS+=("$row")
    if [ "$step_ok" -eq 0 ]; then
        echo "release-gate: step $name FAILED (exit $code; log $log)" >&2
        return 1
    fi
    echo "release-gate: step $name ok (${seconds}s; log $log)"
    return 0
}

write_result_json() {
    local passed_json first row
    if [ "$GATE_PASSED" -eq 1 ]; then
        passed_json=true
    else
        passed_json=false
    fi
    {
        printf '{"commit":"%s","tree_clean":%s,"steps":[' "$COMMIT" "$TREE_CLEAN_JSON"
        first=1
        for row in "${JSON_ROWS[@]}"; do
            if [ "$first" -eq 1 ]; then
                first=0
            else
                printf ','
            fi
            printf '%s' "$row"
        done
        printf '],"passed":%s}\n' "$passed_json"
    } >"$OUTDIR_ABS/result.json"
}

PROFILE=both
ALLOW_DIRTY=0
DRY_RUN=0
OUTDIR=
SELF_TEST=0
TARGET_ARGS=()

if [ "$#" -eq 1 ] && [ "${1-}" = "--self-test" ]; then
    SELF_TEST=1
else
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --self-test)
                echo "release-gate: --self-test takes no other arguments" >&2
                exit 2
                ;;
            --profile)
                if [ "$#" -lt 2 ]; then usage; fi
                PROFILE=$2
                shift 2
                continue
                ;;
            --profile=*)
                PROFILE=${1#--profile=}
                ;;
            --target-dir)
                if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                    echo "release-gate: --target-dir needs a directory" >&2
                    usage
                fi
                TARGET_ARGS=(--target-dir "$2")
                shift 2
                continue
                ;;
            --target-dir=*)
                value=${1#--target-dir=}
                if [ -z "$value" ]; then
                    echo "release-gate: --target-dir needs a directory" >&2
                    usage
                fi
                TARGET_ARGS=(--target-dir "$value")
                ;;
            --allow-dirty)
                ALLOW_DIRTY=1
                ;;
            --dry-run)
                DRY_RUN=1
                ;;
            -h|--help)
                usage_text
                exit 0
                ;;
            --)
                shift
                while [ "$#" -gt 0 ]; do
                    if [ -n "$OUTDIR" ]; then
                        echo "release-gate: only one OUTDIR" >&2
                        usage
                    fi
                    OUTDIR=$1
                    shift
                done
                ;;
            -*)
                echo "release-gate: unknown option $1" >&2
                usage
                ;;
            *)
                if [ -n "$OUTDIR" ]; then
                    echo "release-gate: only one OUTDIR" >&2
                    usage
                fi
                OUTDIR=$1
                ;;
        esac
        shift
    done
    if [ -z "$OUTDIR" ]; then usage; fi
fi

positive_control

if [ "$SELF_TEST" -eq 1 ]; then
    self_test
    exit 0
fi

case "$PROFILE" in
    default) PROFILES=(default) ;;
    wide) PROFILES=(wide) ;;
    both) PROFILES=(default wide) ;;
    *)
        echo "release-gate: bad --profile $PROFILE (want default|wide|both)" >&2
        exit 2
        ;;
esac

if [ "$DRY_RUN" -eq 1 ]; then
    for_each_step print_step
    exit 0
fi

ensure_gate_tmpdir
mkdir -p "$OUTDIR" || { echo "release-gate: cannot create OUTDIR $OUTDIR" >&2; exit 1; }
OUTDIR_ABS=$(cd "$OUTDIR" && pwd) || { echo "release-gate: cannot resolve OUTDIR $OUTDIR" >&2; exit 1; }
ROOT=$(CDPATH= cd -P "$(dirname "$0")/.." && pwd)
cd "$ROOT" || { echo "release-gate: cannot cd to $ROOT" >&2; exit 1; }
COMMIT=$(git rev-parse HEAD) || { echo "release-gate: git rev-parse HEAD failed" >&2; exit 1; }
if [ -n "$(git status --porcelain)" ]; then
    TREE_CLEAN_JSON=false
    if [ "$ALLOW_DIRTY" -eq 0 ]; then
        echo "release-gate: refusing to run on a dirty tree (git status --porcelain is non-empty); pass --allow-dirty to override" >&2
        exit 1
    fi
else
    TREE_CLEAN_JSON=true
fi

JSON_ROWS=()
set +e
for_each_step run_step
steps_code=$?
set -e
if [ "$steps_code" -ne 0 ]; then
    GATE_PASSED=0
else
    GATE_PASSED=1
fi
write_result_json
if [ "$GATE_PASSED" -eq 1 ]; then
    echo "release-gate: PASS (result $OUTDIR_ABS/result.json)"
    exit 0
fi
echo "release-gate: FAIL (result $OUTDIR_ABS/result.json)"
exit 1
