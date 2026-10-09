#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""One entry point for every tests/python suite (audit F-62).

Every `tests/python/test_*.py` file is registered here exactly once, in one
of three ways:

- RUN: a standalone suite this script runs, as a script
  (`python3 -I tests/python/<file> [args] -v`; the suites are not an
  importable package, so `-m unittest` cannot address them).
- DRIVEN: a suite that needs a built artifact (an eBPF object, a fixture
  binary, a prepared toolchain) and is run by the named driver, which must
  name it. The driver is a cargo integration test or a self-test the hosted
  pipeline already runs.
- EXCLUDED: a suite that cannot run anywhere today, with the reason.

The registry is checked against the directory both ways before anything
runs: a new suite nobody registered, a registered suite that is gone, or a
driver that no longer names its suite fails the run. That is what keeps a
suite from silently running nowhere again.

Usage:
  python3 -I scripts/run-python-suites.py            # check, then run RUN
  python3 -I scripts/run-python-suites.py --check    # registry check only
  python3 -I scripts/run-python-suites.py --list     # print the registry
  python3 -I scripts/run-python-suites.py SUITE...   # check, run only these
"""

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITE_DIR = "tests/python"

# (file, extra args). A file may appear more than once with different args.
RUN = [
    ("test_bpf_noninterference.py", []),
    ("test_cargo_wrapper.py", []),
    ("test_e16_oracle.py", []),
    ("test_canary_evidence.py", ["--target-bits", "32"]),
    ("test_canary_evidence.py", ["--target-bits", "64"]),
    ("test_ci_dependency_selection.py", []),
    ("test_cgroup_trace_harness.py", []),
    ("test_cgroup_trace_oracle.py", []),
    ("test_dashboard_pty_cleanup.py", []),
    ("test_help_usage_drift.py", []),
    ("test_loader.py", []),
    ("test_measure_e03.py", []),
    ("test_merge_checksum_ledgers.py", []),
    ("test_package_release.py", []),
    ("test_prepare_dependencies.py", []),
    ("test_prepared_dependency_evidence.py", []),
    ("test_prepared_dependency_metadata.py", []),
    ("test_prepared_dependency_tools.py", []),
    ("test_public_cli_oracle.py", []),
    ("test_python_suite_registry.py", []),
    ("test_release_matrix_contract.py", []),
    ("test_release_notices.py", []),
    ("test_residual_gates.py", []),
    ("test_schema_json.py", []),
    ("test_skip_reason_vocabulary.py", []),
    ("test_system_first_use_fixture.py", []),
    ("test_system_first_use_receipt.py", []),
    ("test_system_scope_measure_launch.py", []),
    ("test_system_scope_receipt.py", []),
    ("test_system_scope_sample.py", []),
    ("test_system_test_manifest.py", []),
    ("test_t7_campaign.py", []),
]

_ARTIFACT_CONTRACTS = "tests/artifact_contracts.rs"
_RECEIPTS = "tests/receipt_build_subjects.rs"

# file -> driver path. The driver must contain the quoted repo-relative path
# (`"tests/python/<file>"`) or, for a discover-by-pattern driver, the quoted
# file name.
DRIVEN = {
    "test_audit_oracle.py": _ARTIFACT_CONTRACTS,
    "test_bpf_map_defs.py": "tests/bpf_map_contracts.rs",
    "test_build_offline.py": _ARTIFACT_CONTRACTS,
    "test_canary_process_custody.py": _ARTIFACT_CONTRACTS,
    "test_canary_workload.py": _ARTIFACT_CONTRACTS,
    "test_capability_prepared_dependencies.py": _ARTIFACT_CONTRACTS,
    "test_diagnostic_linkage.py": _ARTIFACT_CONTRACTS,
    "test_discovery_flow_object.py": _ARTIFACT_CONTRACTS,
    "test_dual_build_callers.py": _ARTIFACT_CONTRACTS,
    "test_export_source.py": _ARTIFACT_CONTRACTS,
    "test_ia32_lifecycle.py": _ARTIFACT_CONTRACTS,
    "test_image_identity_core.py": _ARTIFACT_CONTRACTS,
    "test_inventory_caller_object.py": "tests/inventory_caller_bpf_contracts.rs",
    "test_inventory_object.py": "tests/inventory_bpf_contracts.rs",
    "test_lane02_prepared_dependencies.py": _ARTIFACT_CONTRACTS,
    "test_lane13_evidence.py": _ARTIFACT_CONTRACTS,
    "test_live_freeze_prepared_dependencies.py": "scripts/check-live-discovery-evidence.py",
    "test_loss_share_measure.py": _ARTIFACT_CONTRACTS,
    "test_offline_dependencies.py": _ARTIFACT_CONTRACTS,
    "test_oracle_lifecycle.py": _ARTIFACT_CONTRACTS,
    "test_ordinary_build_callers.py": _ARTIFACT_CONTRACTS,
    "test_owned_process_group.py": _ARTIFACT_CONTRACTS,
    "test_prepared_abi_driver.py": _ARTIFACT_CONTRACTS,
    "test_prepared_container_driver.py": _ARTIFACT_CONTRACTS,
    "test_prepared_four_callers.py": _ARTIFACT_CONTRACTS,
    "test_prepared_release_drivers.py": _ARTIFACT_CONTRACTS,
    "test_process_session_snapshot.py": _ARTIFACT_CONTRACTS,
    "test_product_build.py": _ARTIFACT_CONTRACTS,
    "test_receipt_borrowed_descriptor_admission.py": _RECEIPTS,
    "test_receipt_discovery_api.py": _RECEIPTS,
    "test_receipt_input_v1_contract.py": _RECEIPTS,
    "test_receipt_ledger.py": _RECEIPTS,
    "test_receipt_semantic_close.py": _RECEIPTS,
    "test_receipt_semantic_dup.py": _RECEIPTS,
    "test_receipt_semantic_dup2.py": _RECEIPTS,
    "test_receipt_semantic_exec.py": _RECEIPTS,
    "test_receipt_semantic_fd_table_mutator.py": _RECEIPTS,
    "test_receipt_semantic_open_description.py": _RECEIPTS,
    "test_receipt_semantic_syscall.py": _RECEIPTS,
    "test_receipt_semantic_topology.py": _RECEIPTS,
    "test_release_seal.py": _ARTIFACT_CONTRACTS,
    "test_root_affiliation.py": "tests/root_affiliation_contracts.rs",
    "test_root_recorded_launcher.py": _ARTIFACT_CONTRACTS,
    "test_stop_gate_object.py": _ARTIFACT_CONTRACTS,
    "test_stopped_canary_capture.py": _ARTIFACT_CONTRACTS,
    "test_subset_oracle.py": _ARTIFACT_CONTRACTS,
    "test_task_storage_canary.py": _ARTIFACT_CONTRACTS,
}

EXCLUDED = {
    "test_entry_object.py": (
        "needs the default and the unsafe-unvalidated-metadata eBPF objects "
        "at once (--default-object/--unsafe-object), which no single build "
        "has; run against current objects (2026-10-03) it fails 8 of 40 on "
        "pinned stack offsets and registers, so its instruction pins predate "
        "the current object and need a refresh before it can be wired in"
    ),
}


def registry_problems(present, run, driven, excluded, read):
    """Every way the registry and the directory disagree, as messages.

    `present` is the set of suite file names on disk; `read(path)` returns a
    driver's text (or None when it is missing).
    """
    problems = []
    run_names = [name for name, _ in run]
    kinds = {}
    for kind, names in (
        ("RUN", set(run_names)),
        ("DRIVEN", set(driven)),
        ("EXCLUDED", set(excluded)),
    ):
        for name in names:
            kinds.setdefault(name, []).append(kind)
    for name, where in sorted(kinds.items()):
        if len(where) > 1:
            problems.append(f"{name} is registered more than once: {', '.join(where)}")
        if name not in present:
            problems.append(f"{name} is registered but {SUITE_DIR}/{name} does not exist")
    for name in sorted(present - set(kinds)):
        problems.append(
            f"{SUITE_DIR}/{name} is not registered: add it to RUN, DRIVEN or "
            "EXCLUDED in scripts/run-python-suites.py"
        )
    for name, driver in sorted(driven.items()):
        text = read(driver)
        if text is None:
            problems.append(f"{name}: driver {driver} does not exist")
        elif f'"{SUITE_DIR}/{name}"' not in text and f'"{name}"' not in text:
            problems.append(f"{name}: driver {driver} no longer names it")
    for name, reason in sorted(excluded.items()):
        if not reason.strip():
            problems.append(f"{name} is excluded without a reason")
    return problems


def present_suites(root):
    return {path.name for path in (root / SUITE_DIR).glob("test_*.py")}


def read_driver(root):
    def read(path):
        try:
            return (root / path).read_text(encoding="utf-8")
        except FileNotFoundError:
            return None

    return read


def check(root=ROOT):
    return registry_problems(present_suites(root), RUN, DRIVEN, EXCLUDED, read_driver(root))


def print_registry():
    for name, args in RUN:
        print(f"RUN       {name} {' '.join(args)}".rstrip())
    for name, driver in sorted(DRIVEN.items()):
        print(f"DRIVEN    {name} by {driver}")
    for name, reason in sorted(EXCLUDED.items()):
        print(f"EXCLUDED  {name}: {reason}")


def run_suites(selected):
    failed = []
    for name, args in RUN:
        if selected and name not in selected:
            continue
        label = " ".join([name, *args])
        start = time.monotonic()
        print(f"=== {label}", flush=True)
        result = subprocess.run(
            [sys.executable, "-I", f"{SUITE_DIR}/{name}", *args, "-v"],
            cwd=ROOT,
            env=os.environ.copy(),
        )
        seconds = time.monotonic() - start
        verdict = "PASS" if result.returncode == 0 else f"FAIL rc={result.returncode}"
        print(f"=== {verdict} {label} ({seconds:.0f}s)", flush=True)
        if result.returncode != 0:
            failed.append(label)
    return failed


def main(argv):
    if argv[:1] == ["--list"]:
        print_registry()
        return 0
    problems = check()
    for problem in problems:
        print(f"run-python-suites: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(
        f"run-python-suites: registry covers all {len(present_suites(ROOT))} suites "
        f"({len(RUN)} runs here, {len(DRIVEN)} driven, {len(EXCLUDED)} excluded)"
    )
    if argv[:1] == ["--check"]:
        return 0
    selected = set(argv)
    unknown = selected - {name for name, _ in RUN}
    if unknown:
        print(f"run-python-suites: not a RUN suite: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    failed = run_suites(selected)
    if failed:
        print(f"run-python-suites: {len(failed)} failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("run-python-suites: all suites passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
