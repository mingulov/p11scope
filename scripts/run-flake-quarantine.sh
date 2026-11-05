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

# Compile both targets before any case runs. Serial exact filters remove
# sibling load and shared build IO as confounders; an isolated pass does
# not diagnose or clear the original failure.
build_output=$(mktemp "$TMPDIR/p11scope-quarantine.XXXXXX")
trap 'rm -f "$build_output"' 0
if cargo "+$(cat .release-rust-version)" test --locked --offline --lib --test artifact_contracts --no-run --message-format=json >"$build_output"; then
    :
else
    status=$?
    cat "$build_output"
    exit "$status"
fi
executables=$(python3 -I - "$build_output" "$CARGO_TARGET_DIR" <<'PY'
import json
import os
from pathlib import Path
import sys

root = Path.cwd().resolve()
target_root = Path(sys.argv[2]).resolve()
wanted = (("p11scope", ["lib"], root / "src/lib.rs"),
          ("artifact_contracts", ["test"], root / "tests/artifact_contracts.rs"))
matches = [[], []]
try:
    for line in Path(sys.argv[1]).read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError("Cargo output is not a JSON object")
        if record.get("reason") == "compiler-message":
            rendered = record.get("message", {}).get("rendered")
            if rendered:
                print(rendered, end="", file=sys.stderr)
        if record.get("reason") != "compiler-artifact" or record.get("profile", {}).get("test") is not True:
            continue
        target = record.get("target", {})
        for index, (name, kind, source) in enumerate(wanted):
            if (target.get("name") == name and target.get("kind") == kind
                    and Path(target.get("src_path")).resolve() == source):
                matches[index].append(record.get("executable"))
    paths = []
    for (name, _kind, _source), candidates in zip(wanted, matches):
        if len(candidates) != 1 or not isinstance(candidates[0], str) or not candidates[0]:
            raise ValueError(f"expected one {name} test executable, got {candidates!r}")
        path = Path(candidates[0]).resolve(strict=True)
        if (not path.is_relative_to(target_root) or not path.is_file()
                or not os.access(path, os.X_OK) or "\n" in str(path)):
            raise ValueError(f"invalid executable in private target: {path}")
        paths.append(str(path))
    print("\n".join(paths))
except (OSError, TypeError, ValueError) as error:
    print(f"quarantine: cannot select test executables: {error}", file=sys.stderr)
    sys.exit(1)
PY
)
lib_exe=$(printf '%s\n' "$executables" | sed -n '1p')
artifact_exe=$(printf '%s\n' "$executables" | sed -n '2p')

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

# Guard: --exact with a stale filter runs 0 tests yet exits 0, which would
# fake-green the quarantine count. Fail unless exactly one test ran.
guard_single() {
    # $1 = filter, $2 = captured output, $3 = executable exit status
    echo "$2"
    if [ "$3" -ne 0 ]; then
        return "$3"
    fi
    case "$2" in
        *"test result: ok. 1 passed; 0 failed"*)
            return 0
            ;;
        *)
            echo "quarantine: $1 ran != 1 test (filter stale?)"
            return 1
            ;;
    esac
}

run_artifact() {
    echo "--- quarantine: $1"
    set +e
    out=$("$artifact_exe" "$1" --exact --nocapture --test-threads=1 2>&1)
    status=$?
    guard_single "$1" "$out" "$status"
    status=$?
    set -e
    report "$1" "$status"
}

run_lib() {
    echo "--- quarantine: $1"
    set +e
    out=$("$lib_exe" "$1" --exact --nocapture --test-threads=1 2>&1)
    status=$?
    guard_single "$1" "$out" "$status"
    status=$?
    set -e
    report "$1" "$status"
}

run_artifact "lane13_evidence_finalizes_only_after_owned_cleanup"
run_artifact "metadata_canary_matrix"
run_artifact "stopped_canary_capture_lifecycle"
run_artifact "native_helper_suite_recorded_launcher_requires_authenticated_generations_and_bounded_cleanup"
run_lib "run::tests::actual_handoff_helpers_preserve_errno_and_retry_without_renewing_deadlines"
run_artifact "release_seal_denies_the_caller_path_to_every_reached_command"
run_lib "run::tests::signal_settlement_observes_second_sigint_during_fallback_term_grace"

echo "quarantine: $pass passed, $fail failed in isolation"
[ "$fail" -eq 0 ]
