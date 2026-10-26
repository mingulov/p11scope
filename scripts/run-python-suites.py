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
  drive it through an invocation-shaped reference: the suite path as an
  argument of a python/pytest/unittest call or of the runner's own suite
  list. The driver is a cargo integration test or a self-test the hosted
  pipeline already runs.
- EXCLUDED: a suite that cannot run anywhere today, with the reason.

The registry is checked against the directory both ways before anything
runs: a new suite nobody registered, a registered suite that is gone, or a
driver that no longer drives its suite fails the run. That is what keeps a
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

# Tokens of an invocation or an argument list. A quoted suite path counts
# as driven only in argument position (after `(`, `,` or `[`) with one of
# these within two lines: a python/pytest/unittest call, the Rust suite
# runners, or a python argument flag. A bare mention in a comment or a
# message has neither and fails.
INVOCATION_MARKERS = (
    "python", "pytest", "unittest", "run_ok", "run_native_python_suite",
    "Command::new", ".args", ".arg(", ".join(", "vec!", "-I", "-p",
)

# (file, extra args). A file may appear more than once with different args.
RUN = [
    ("test_automatic_exec_oracle.py", []),
    ("test_automatic_exec_system_disclosures.py", []),
    ("test_automatic_initial_readiness.py", []),
    ("test_bench_count_overhead.py", []),
    ("test_bpf_kernels_contract.py", []),
    ("test_bpf_load_report.py", []),
    ("test_bpf_noninterference.py", []),
    ("test_browser_cells.py", []),
    ("test_cargo_wrapper.py", []),
    ("test_e16_oracle.py", []),
    ("test_first_use_oracle.py", []),
    ("test_canary_evidence.py", ["--target-bits", "32"]),
    ("test_canary_evidence.py", ["--target-bits", "64"]),
    ("test_canary_object.py", []),
    ("test_ci_dependency_selection.py", []),
    ("test_counter_object.py", []),
    ("test_counter_timing_object.py", []),
    ("test_cgroup_replacement.py", []),
    ("test_cgroup_stop_acceptance.py", []),
    ("test_cgroup_trace_harness.py", []),
    ("test_cgroup_trace_oracle.py", []),
    ("test_container_cells_oracle.py", []),
    ("test_dashboard_pty_cleanup.py", []),
    ("test_detailed_leader_held_entry.py", []),
    ("test_h6_cgroup_operator_path.py", []),
    ("test_h6_initial_exec_controller.py", []),
    ("test_h6_initial_exec_process.py", []),
    ("test_h6_provider_receipt.py", []),
    ("test_h6_system_dispatch.py", []),
    ("test_help_usage_drift.py", []),
    ("test_ia32_automatic_exec.py", []),
    ("test_ignored_tests.py", []),
    ("test_inventory_capacity_oracle.py", []),
    ("test_inventory_count_only_hooks.py", []),
    ("test_inventory_output_readiness.py", []),
    ("test_inventory_provider_identity.py", []),
    ("test_inventory_readiness_cadence.py", []),
    ("test_inventory_system_recovery_disclosures.py", []),
    ("test_inventory_system_sibling.py", []),
    ("test_joint_abi_oracle.py", []),
    ("test_joint_async_oracle.py", []),
    ("test_joint_h9_oracle.py", []),
    ("test_joint_ledger_oracle.py", []),
    ("test_joint_owner_proof_oracle.py", []),
    ("test_joint_promotion_oracle.py", []),
    ("test_joint_two_provider_oracle.py", []),
    ("test_key_operation_ledger.py", []),
    ("test_loader.py", []),
    ("test_loader_lifetimes.py", []),
    ("test_measure_e03.py", []),
    ("test_merge_checksum_ledgers.py", []),
    ("test_narrow_scope_oracle.py", []),
    ("test_object_journal_qualification.py", []),
    ("test_object_observations.py", []),
    ("test_observed_key_operations.py", []),
    ("test_operator_output_qualification.py", []),
    ("test_package_release.py", []),
    ("test_prepare_dependencies.py", []),
    ("test_prepared_dependency_evidence.py", []),
    ("test_prepared_dependency_metadata.py", []),
    ("test_prepared_dependency_tools.py", []),
    ("test_public_cli_oracle.py", []),
    ("test_python_suite_registry.py", []),
    ("test_release_matrix_contract.py", []),
    ("test_release_notices.py", []),
    ("test_release_recipient.py", []),
    ("test_residual_gates.py", []),
    ("test_s1_throughput_compare.py", []),
    ("test_schema_json.py", []),
    ("test_skip_reason_vocabulary.py", []),
    ("test_system_first_use_fixture.py", []),
    ("test_system_first_use_receipt.py", []),
    ("test_system_scope_measure_launch.py", []),
    ("test_system_scope_receipt.py", []),
    ("test_system_scope_sample.py", []),
    ("test_system_scope_soak.py", []),
    ("test_system_test_manifest.py", []),
    ("test_t7_campaign.py", []),
    ("test_uprobe_close_throughput_probe.py", []),
]

_ARTIFACT_CONTRACTS = "tests/artifact_contracts.rs"
_RECEIPTS = "tests/receipt_build_subjects.rs"

# file -> driver path. The driver must pass the quoted repo-relative path
# (`"tests/python/<file>"`) or, for a discover-by-pattern driver, the quoted
# file name as an invocation argument (see INVOCATION_MARKERS); a bare
# mention in a comment or a message does not count.
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
    "test_entry_object.py": "tests/entry_object_paired.rs",
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
    "test_process_session_dying_members.py": _ARTIFACT_CONTRACTS,
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

EXCLUDED = {}


def _strip_driver_comments(text, driver):
    """Driver text with line comments blanked (strings are kept).

    Rust drivers lose `//` comments, Python and shell drivers `#` ones;
    a marker inside a string literal never starts a comment.
    """
    marker = "//" if driver.endswith(".rs") else "#"
    out = []
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char in "\"'":
            quote = char
            out.append(char)
            i += 1
            while i < n:
                out.append(text[i])
                if text[i] == "\\":
                    i += 1
                    if i < n:
                        out.append(text[i])
                        i += 1
                    continue
                i += 1
                if out[-1] == quote:
                    break
        elif marker == "//" and text.startswith("r", i) and text[i + 1:i + 2] in "#\"":
            hashes = 0
            j = i + 1
            while text[j:j + 1] == "#":
                hashes += 1
                j += 1
            if text[j:j + 1] != '"':
                out.append(char)
                i += 1
            else:
                close = '"' + "#" * hashes
                end = text.find(close, j + 1)
                end = n if end < 0 else end + len(close)
                out.append(text[i:end])
                i = end
        elif text.startswith(marker, i):
            while i < n and text[i] != "\n":
                i += 1
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _invocation_shaped(stripped, needle):
    """True when some occurrence is passed as an invocation argument.

    An occurrence counts when it sits in argument position (after `(`, `,`
    or `[`, closed by `,`, `)` or `]` or whitespace) with an invocation
    marker within two lines; a bare mention has neither and fails.
    """
    lines = stripped.splitlines()
    start = 0
    while True:
        at = stripped.find(needle, start)
        if at < 0:
            return False
        start = at + len(needle)
        before = stripped[:at].rstrip()
        if before and before[-1] in "(,[":
            after = stripped[at + len(needle):]
            if after == "" or after[0] in ",)]" or after[0].isspace():
                row = stripped.count("\n", 0, at)
                window = lines[max(0, row - 2):row + 3]
                if any(marker in line
                       for marker in INVOCATION_MARKERS for line in window):
                    return True
    return False


def driven_state(text, name, driver):
    """How a driver references a suite: "driven", "named" or "missing"."""
    stripped = _strip_driver_comments(text, driver)
    needles = (f'"{SUITE_DIR}/{name}"', f'"{name}"')
    if not any(needle in stripped for needle in needles):
        return "missing"
    if any(_invocation_shaped(stripped, needle) for needle in needles):
        return "driven"
    return "named"


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
        else:
            state = driven_state(text, name, driver)
            if state == "named":
                problems.append(
                    f"{name}: driver {driver} names it without driving it "
                    "(no invocation-shaped reference)")
            elif state == "missing":
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
