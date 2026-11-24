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

_PIN = "scripts/mapped-provider-pin.py"
_COUNTER = ("tests/fixtures/counter-banks.c", "tests/fixtures/counter-bank-growth.c")
_WRAP = ("tests/fixtures/operator-output/prepare-diagnostics-wrap.py",
         "tests/fixtures/operator-output/diagnostics-wrap-ledger.c",
         "tests/fixtures/public-cli/demotion-ledger.c", _PIN)
_CI = ("scripts/ci/build-counter-fixtures.sh", "scripts/ci/build-wrap-fixtures.sh",
       "scripts/ci/prepare-btrfs-tmpdir.sh")
_LIB = _CI + _COUNTER + _WRAP
_PUBLIC = ("scripts/public-cli-oracle.py", "scripts/check-capture-evidence.py", "scripts/system-scope-measure.py",
           "scripts/qualify_records.py", "scripts/release-matrix-contract.py", _PIN,
           "scripts/inventory-mt-oracle.py", "scripts/system-cell-census.py", "scripts/inventory-mt-gate.py",
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

# runner -> mode -> (where the mode runs, its inputs). A `stage` mode runs
# from the checkout-free release stage; a `checkout` mode only from a
# source checkout and is never staged.
RUNNERS = {
    "scripts/qualify-public-cli.sh": {"run": (STAGE, _PUBLIC)},
    "scripts/qualify-inventory-native.sh": {
        "run": (STAGE, _NATIVE),
        "self-test": (CHECKOUT, _NATIVE + ("tests/python/test_inventory_capacity_oracle.py",))},
    # run: the campaign; list: --list/--list-integration print the curation
    # and run no helper.
    "scripts/run-privileged-lib-tests.sh": {"run": (STAGE, _LIB), "list": (STAGE, ())},
    "scripts/ci/build-counter-fixtures.sh": {"run": (STAGE, _COUNTER)},
    "scripts/ci/build-wrap-fixtures.sh": {"run": (STAGE, _WRAP)},
    "scripts/ci/prepare-btrfs-tmpdir.sh": {"run": (STAGE, ())},
    # stage: the guest's inner script; its preflight is --verify-inputs,
    # which binds every staged source. checkout: the host driver (build,
    # self-test and stage writing), refused here before any of them.
    "scripts/qualify-release-matrix.sh": {
        "stage": (STAGE, tuple(dict.fromkeys(_MATRIX_RUNNERS + _PUBLIC + _NATIVE + _LIB))),
        "checkout": (CHECKOUT, ("scripts/cargo.sh", "scripts/prepare-dependencies.py", "scripts/fixtures/exec_churn.c",
                                "tests/python/test_release_matrix_contract.py"))},
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


def missing(root, runner, mode):
    out = []
    for name in required(runner, mode):
        path = os.path.normpath(os.path.join(root, name))
        executable = name.endswith(".sh")
        if not os.path.isfile(path) or (executable and not os.access(path, os.X_OK)):
            out.append(path)
    return out


def main(argv):
    if len(argv) != 4 or argv[0] != "check":
        print("usage: runner_inputs.py check ROOT RUNNER MODE", file=sys.stderr)
        return 2
    root, runner, mode = argv[1:]
    if mode not in RUNNERS.get(runner, {}):
        print("runner_inputs.py: undeclared runner mode: %s %s" % (runner, mode), file=sys.stderr)
        return 2
    gone = missing(root, runner, mode)
    for path in gone:
        print("%s: required input missing: %s" % (os.path.basename(runner), path), file=sys.stderr)
    return 64 if gone else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
