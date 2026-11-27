#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""The one declaration of the repository inputs each runner mode reads.

release-matrix-contract.py stages and binds exactly the inputs of the
`stage` modes (plus those runners and this file). Each runner calls

    python3 -I scripts/runner_inputs.py check ROOT RUNNER MODE

before any setup; a missing input refuses with exit 64 and its path.
tests/python/test_release_matrix_contract.py checks each mode against the
files its code references and runs every refusal (stdlib only).
"""
import os
import sys

STAGE, CHECKOUT = "stage", "checkout"
SELF = "scripts/runner_inputs.py"
# Every declared .sh input is launched directly and must be executable,
# except these, which are only sourced (`. scripts/lib.sh`) or read.
SOURCED = ("scripts/cleanup-traps.sh", "scripts/lib.sh", "scripts/product-build.sh",
           "scripts/prepared-dependency-tools.sh", "scripts/prepared-dependency-snapshot.sh")
# Runs a mode's self-test suite strictly, in a copy of that mode's declared
# inputs (no skip passes; an undeclared file is absent there).
_STRICT = "scripts/strict-selftest.py"

_PIN = "scripts/mapped-provider-pin.py"
_COUNTER = ("tests/fixtures/counter-banks.c", "tests/fixtures/counter-bank-growth.c")
_WRAP = ("tests/fixtures/operator-output/prepare-diagnostics-wrap.py",
         "tests/fixtures/operator-output/diagnostics-wrap-ledger.c",
         "tests/fixtures/public-cli/demotion-ledger.c", _PIN)
_CI = ("scripts/ci/build-counter-fixtures.sh", "scripts/ci/build-wrap-fixtures.sh",
       "scripts/ci/prepare-btrfs-tmpdir.sh", "scripts/ci/joint_stop_verdict.py")
_LIB = _CI + _COUNTER + _WRAP
_PUBLIC = ("scripts/public-cli-oracle.py", "scripts/check-capture-evidence.py", "scripts/system-scope-measure.py",
           "scripts/qualify_records.py", "scripts/release-matrix-contract.py", _PIN,
           "scripts/inventory-mt-oracle.py", "scripts/system-cell-census.py", "scripts/inventory-mt-gate.py",
           # Read by check-capture-evidence.py's self-test, which parses the
           # version-matrix fixture to pin the derived canary expectation.
           "crates/discover/tests/fixture/version_matrix.c",
           "tests/fixtures/public-cli/gated.c", "tests/fixtures/public-cli/mt.c",
           "tests/fixtures/public-cli/prearm-first-use.c", "tests/fixtures/public-cli/cgroup-fork.c",
           "tests/fixtures/public-cli/chain-parent.c", "tests/fixtures/public-cli/mt_mixed.c",
           "tests/fixtures/public-cli/mt_fork.c")
# The native lanes, their C8 gate and the oracle's capacity run (every
# capacity population compiles the catalog driver; synthetic ones also the
# version-matrix provider). One mode: a run may take any of these paths.
_NATIVE = ("scripts/inventory-native-oracle.py", "scripts/qualify-cgroup-trace.py", "scripts/cgroup-trace-oracle.py",
           _PIN, "tests/fixtures/public-cli/inventory-ledger.c", "tests/fixtures/catalog-driver.c",
           "crates/discover/tests/fixture/version_matrix.c")
_MATRIX_RUNNERS = ("scripts/qualify-public-cli.sh", "scripts/qualify-inventory-native.sh",
                   "scripts/run-privileged-lib-tests.sh")
_MATRIX_STAGE = tuple(dict.fromkeys(_MATRIX_RUNNERS + _PUBLIC + _NATIVE + _LIB))
# The canary object inputs release-matrix-contract.py hashes and stages for
# --object-input (sources, runtime sources, producer sources).
CANARY_SOURCE_FILES = ("scripts/verify-canaries.sh", "scripts/product-build.sh", "scripts/lib.sh",
    "scripts/lane-lib-oracle-1.py", "scripts/cleanup-traps.sh", "scripts/_loader.py",
    "scripts/capture-stopped-canary.py", "scripts/canary_process_custody.py",
    "scripts/check-canary-evidence.py", "scripts/check-capture-evidence.py", "scripts/check-bpf-map-defs.py",
    "scripts/dump-owned-bpf-maps.py", "scripts/qualify-task-storage-canary.py", ".release-rust-version",
    "scripts/fixtures/canary_workload.c", "scripts/fixtures/privacy-stack-workload.c")
CANARY_RUNTIME_SOURCES = ("scripts/fixtures/canary_workload.c", "crates/discover/tests/fixture/version_matrix.c",
    "scripts/build-task-storage-reader.sh", "scripts/native/dump-task-storage.c", "scripts/native/dump-task-storage.bpf.c")
CANARY_PRODUCER_SOURCES = ("scripts/verify-canaries.sh", "scripts/product-build.sh", "scripts/cargo.sh",
    "scripts/release-matrix-contract.py", ".release-rust-version", "build.rs", "src/lib.rs")
_CANARY = CANARY_SOURCE_FILES + CANARY_RUNTIME_SOURCES + CANARY_PRODUCER_SOURCES
# The compiler pin, the candidate build and its fixture.
_MATRIX_HOST = (".release-rust-version", "scripts/cargo.sh", "scripts/prepare-dependencies.py",
                "scripts/fixtures/exec_churn.c")
# --self-test runs the contract suite strictly, in a copy of these inputs:
# it and every file it or its children load, read or run.
_MATRIX_SELF_TEST = (
    _STRICT, "scripts/_loader.py", "scripts/canary_process_custody.py",
    "tests/python/json_signal_lifetime_probe.py",
    "tests/python/test_release_matrix_contract.py", "tests/python/test_canary_evidence.py",
    "tests/python/test_canary_object.py", "tests/python/test_canary_workload.py",
    "tests/python/test_inventory_capacity_oracle.py", "tests/python/test_public_cli_oracle.py",
    "tests/python/test_qualify_records.py", "tests/python/test_task_storage_canary.py",
    "scripts/build-task-storage-canary.sh", "scripts/build-task-storage-reader.sh",
    "scripts/capture-stopped-canary.py", "scripts/check-bpf-map-defs.py", "scripts/check-canary-evidence.py",
    "scripts/check-ignored-tests.py", "scripts/cleanup-traps.sh",
    "scripts/dump-owned-bpf-maps.py", "scripts/fixtures/canary_workload.c",
    "scripts/fixtures/privacy-stack-workload.c", "scripts/lane-lib-oracle-1.py", "scripts/lane-lib-oracle-2.py",
    "scripts/lane-lib-oracle-3.py", "scripts/lane-lib-oracle-4.py", "scripts/lane-lib-oracle-5.py",
    "scripts/lane-lib-oracle-6.py", "scripts/lib.sh", "scripts/native/dump-task-storage.bpf.c",
    "scripts/native/dump-task-storage.c", "scripts/product-build.sh",
    "scripts/qualify-task-storage-canary.py", "scripts/recorded-process-exec.py", "scripts/verify-canaries.sh",
    # Closure reachability via the matrix-build guard test, which reads the
    # induced-gaps script for its provider builds; the walk pulls the whole
    # transitive graph. Checkout-only (this tuple), never staged.
    "scripts/verify-induced-gaps.sh", "scripts/lane-induced-gaps-oracle-1.py",
    "scripts/lane-induced-gaps-oracle-2.py", "scripts/lane-induced-gaps-oracle-3.py",
    "scripts/lane-induced-gaps-oracle-4.py", "scripts/lane-induced-gaps-oracle-5.py",
    "scripts/lane-induced-gaps-oracle-6.py", "scripts/lane-induced-gaps-oracle-7.py",
    "scripts/check-prepared-dependencies.py", "scripts/prepared-dependency-evidence.py",
    "scripts/prepared-dependency-snapshot.sh", "scripts/prepared-dependency-tools.sh",
    "scripts/merge-checksum-ledgers.py", "crates/discover/tests/fixture/provider.c",
    "crates/discover/tests/fixture/helper.c")

# runner -> mode -> (where the mode runs, its inputs). A `stage` mode runs
# from the checkout-free release stage; a `checkout` mode only from a
# source checkout and is never staged.
RUNNERS = {
    "scripts/qualify-public-cli.sh": {"run": (STAGE, _PUBLIC)},
    "scripts/qualify-inventory-native.sh": {
        "run": (STAGE, _NATIVE),
        "self-test": (CHECKOUT, _NATIVE + ("tests/python/test_inventory_capacity_oracle.py", _STRICT))},
    # run: the campaign; list: --list/--list-integration print the curation
    # and run no helper.
    "scripts/run-privileged-lib-tests.sh": {"run": (STAGE, _LIB), "list": (STAGE, ())},
    "scripts/ci/build-counter-fixtures.sh": {"run": (STAGE, _COUNTER)},
    "scripts/ci/build-wrap-fixtures.sh": {"run": (STAGE, _WRAP)},
    "scripts/ci/prepare-btrfs-tmpdir.sh": {"run": (STAGE, ())},
    # stage: the guest's inner script; its bootstrap check names the judge
    # and this file, then --verify-inputs binds every staged source.
    # checkout: the host driver. Every host mode (dry run, plan, build,
    # stage writing, --object-input) reads the whole guest stage from the
    # checkout plus the host-only files and the canary object inputs, refused
    # before the first read; self-test also the suite.
    "scripts/qualify-release-matrix.sh": {
        "stage": (STAGE, _MATRIX_STAGE),
        "checkout": (CHECKOUT, tuple(dict.fromkeys(_MATRIX_STAGE + _MATRIX_HOST + _CANARY))),
        "self-test": (CHECKOUT, tuple(dict.fromkeys(_MATRIX_STAGE + _MATRIX_HOST + _CANARY + _MATRIX_SELF_TEST)))},
}


def required(runner, mode):
    return RUNNERS[runner][mode][1]


def staged_sources():
    """The staged source list: every stage-mode runner and input, and this file."""
    names = {SELF}
    for runner, modes in RUNNERS.items():
        for where, inputs in modes.values():
            if where == STAGE:
                names.add(runner)
                names.update(inputs)
    return tuple(sorted(names))


def executable(name):
    return name.endswith(".sh") and name not in SOURCED


def problems(root, runner, mode):
    """(path, state) for every input that is missing, unreadable or (a
    directly launched shell) not executable."""
    out = []
    for name in required(runner, mode):
        path = os.path.normpath(os.path.join(root, name))
        if not os.path.isfile(path):
            out.append((path, "missing"))
        elif not os.access(path, os.R_OK):
            out.append((path, "unreadable"))
        elif executable(name) and not os.access(path, os.X_OK):
            out.append((path, "not executable"))
    return out


def missing(root, runner, mode):
    return [path for path, _ in problems(root, runner, mode)]


def main(argv):
    if len(argv) != 4 or argv[0] != "check":
        print("usage: runner_inputs.py check ROOT RUNNER MODE", file=sys.stderr)
        return 2
    root, runner, mode = argv[1:]
    if mode not in RUNNERS.get(runner, {}):
        print("runner_inputs.py: undeclared runner mode: %s %s" % (runner, mode), file=sys.stderr)
        return 2
    gone = problems(root, runner, mode)
    for path, state in gone:
        print("%s: required input %s: %s" % (os.path.basename(runner), state, path), file=sys.stderr)
    return 64 if gone else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
