#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# run-flake-quarantine.sh — serial, isolated re-runs of the seven ledgered
# flakes (docs/notes/known-flakes.md, mapping in
# docs/notes/test-quarantine.md). Triage evidence only: a green quarantine
# run never greens the workflow (CI runs it failure-gated), and no test is
# weakened, retried-until-green, or skipped here — each flake runs exactly
# once, serially, with a private target dir and a single test thread.
#
# Usage: scripts/run-flake-quarantine.sh
set -eu
cd "$(dirname "$0")/.."

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/quarantine}"
export TMPDIR="${TMPDIR:-/var/tmp/p11scope-ws-tmp}"

# Build once; run serially. Exact filters, one test thread each: the
# ledgered flakes are wall-clock contention (parallel siblings, shared
# build IO), not logic, so isolation is serial execution, not retries.
cargo +1.88 test --locked --offline --test artifact_contracts --no-run
cargo +1.88 test --locked --offline --lib --no-run

pass=0
fail=0
report() {
    # $1 = filter, $2 = exit status
    if [ "$2" -eq 0 ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        echo "quarantine: $1 FAILED in isolation"
    fi
}

run_artifact() {
    echo "--- quarantine: $1"
    set +e
    cargo +1.88 test --locked --offline --test artifact_contracts "$1" -- --exact --nocapture --test-threads=1
    status=$?
    set -e
    report "$1" "$status"
}

run_lib() {
    echo "--- quarantine: $1"
    set +e
    cargo +1.88 test --locked --offline --lib "$1" -- --exact --nocapture --test-threads=1
    status=$?
    set -e
    report "$1" "$status"
}

run_artifact "lane13_evidence_finalizes_only_after_owned_cleanup"
run_artifact "metadata_canary_matrix"
run_artifact "stopped_canary_capture_lifecycle"
run_artifact "native_helper_suite_recorded_launcher_requires_authenticated_generations_and_bounded_cleanup"
run_lib "actual_handoff_helpers_preserve_errno_and_retry_without_renewing_deadlines"
run_artifact "release_seal_denies_the_caller_path_to_every_reached_command"
run_lib "signal_settlement_observes_second_sigint_during_fallback_term_grace"

echo "quarantine: $pass passed, $fail failed in isolation"
[ "$fail" -eq 0 ]
