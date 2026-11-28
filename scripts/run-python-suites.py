#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""One entry point for every tests/python suite (audit F-62).

Every `tests/python/test_*.py` file is registered here exactly once, in one
of three ways:

- RUN: a standalone suite this script runs, as a script
  (`python3 -I tests/python/<file> [args] -v`; the suites are not an
  importable package, so `-m unittest` cannot address them).
- DRIVEN: a suite that needs a built artifact (an eBPF object, a fixture
  binary, a prepared toolchain), or that is too slow for the serial lane
  and runs on its own schedule instead, and is run by the named driver,
  which must drive it through an invocation-shaped reference: the suite
  path as an argument of a python/pytest/unittest call or of the runner's
  own suite list. The driver is a cargo integration test, a self-test the
  hosted pipeline already runs, or a scheduled workflow whose `run:` line
  is exactly `python3 -I scripts/run-python-suites.py <file>`.
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
  # (a bare run covers RUN; SUITE... may also name DRIVEN suites)
"""

import fnmatch
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITE_DIR = "tests/python"
# Every terminal state the fragment producer can emit for a suite event.
# Anything else is malformed evidence, not a quieter pass.
SUITE_EVENT_STATES = {"passed", "failed", "error", "skipped", "unexpected_success"}


def checker_module():
    """The typed-ledger checker, shared for its strict JSON document loader.

    Fragments are typed gate evidence, so they are admitted with the same
    strictness as result documents: duplicate keys and non-strict
    constants are rejected instead of silently coerced.
    """
    spec = importlib.util.spec_from_file_location(
        "known_failing_checker_strict",
        Path(__file__).resolve().parent / "check-known-failing.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

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
    ("test_abi_execution_qualification.py", []),
    ("test_add_copyright_headers.py", []),
    ("test_apparmor_profile.py", []),
    ("test_automatic_exec_oracle.py", []),
    ("test_automatic_exec_system_disclosures.py", []),
    ("test_automatic_initial_readiness.py", []),
    ("test_bank_object_proof_off_on.py", []),
    ("test_bench_count_overhead.py", []),
    ("test_bench_marker_cost.py", []),
    ("test_bench_profile_overhead.py", []),
    ("test_benign_loader_evidence.py", []),
    ("test_bpf_kernels_contract.py", []),
    ("test_check_bpf_load_journal.py", []),
    ("test_journal_load_verdict.py", []),
    ("test_privileged_tests_workflow.py", []),
    ("test_bpf_load_report.py", []),
    ("test_bpf_noninterference.py", []),
    ("test_multi_host_refusal.py", []),
    ("test_browser_cells.py", []),
    ("test_cargo_wrapper.py", []),
    ("test_cell_results.py", []),
    ("test_pkcs11_check_cell.py", []),
    ("test_e16_oracle.py", []),
    ("test_event_stdout_judge.py", []),
    ("test_first_use_oracle.py", []),
    ("test_first_use_sweep.py", []),
    ("test_gate0_identity.py", []),
    ("test_getter_manifest.py", []),
    ("test_h4a_prepost_userspace.py", ["--self-test"]),
    ("test_caller_reasons_overflow_oracle.py", []),
    ("test_discovery_retry_classes_oracle.py", []),
    ("test_canary_evidence.py", ["--target-bits", "32"]),
    ("test_canary_evidence.py", ["--target-bits", "64"]),
    ("test_canary_object.py", []),
    ("test_canary_observer_verbosity.py", []),
    ("test_ci_dependency_selection.py", []),
    ("test_ci_stop_races.py", []),
    ("test_ci_test_partition.py", []),
    ("test_counter_object.py", []),
    ("test_counter_timing_object.py", []),
    ("test_counter_softhsm_parity.py", []),
    ("test_cgroup_replacement.py", []),
    ("test_cgroup_stop_acceptance.py", []),
    ("test_cgroup_trace_harness.py", []),
    ("test_cgroup_trace_oracle.py", []),
    ("test_container_cells.py", []),
    ("test_container_cells_oracle.py", []),
    ("test_container_image_cell.py", []),
    ("test_container_publish.py", []),
    ("test_dashboard_pty_cleanup.py", []),
    ("test_deploy_defaults.py", []),
    ("test_detailed_leader_held_entry.py", []),
    ("test_docker_runtime_workflow.py", []),
    ("test_h6_cgroup_operator_path.py", []),
    ("test_h6_initial_exec_controller.py", []),
    ("test_h6_initial_exec_process.py", []),
    ("test_h6_provider_receipt.py", []),
    ("test_h6_system_dispatch.py", []),
    ("test_help_usage_drift.py", []),
    ("test_hosted_delivery_dispatch.py", []),
    ("test_intermittent_bounds.py", []),
    ("test_ia32_automatic_exec.py", []),
    ("test_ignored_tests.py", []),
    ("test_image_bank_object.py", []),
    ("test_inventory_capacity_oracle.py", []),
    ("test_inventory_cgroup_oracle.py", []),
    ("test_inventory_count_only_hooks.py", []),
    ("test_inventory_mt_oracle.py", []),
    ("test_inventory_output_readiness.py", []),
    ("test_inventory_provider_identity.py", []),
    ("test_inventory_provider_info_oracle.py", []),
    ("test_inventory_readiness_cadence.py", []),
    ("test_inventory_system_recovery_disclosures.py", []),
    ("test_inventory_system_sibling.py", []),
    ("test_joint_abi_oracle.py", []),
    ("test_joint_async_oracle.py", []),
    ("test_joint_h9_oracle.py", []),
    ("test_joint_ledger_oracle.py", []),
    ("test_joint_owner_proof_oracle.py", []),
    ("test_joint_promotion_oracle.py", []),
    ("test_joint_stall_live.py", []),
    ("test_joint_stop_verdict.py", []),
    ("test_joint_throughput_cells.py", []),
    ("test_joint_two_provider_oracle.py", []),
    ("test_key_operation_ledger.py", []),
    ("test_key_operations_fixture.py", []),
    ("test_key_operations_linked_control.py", []),
    ("test_key_operations_shortlived.py", []),
    ("test_key_operations_system.py", []),
    ("test_known_failing.py", []),
    ("test_kubernetes_runtime.py", []),
    ("test_kubernetes_runtime_workflow.py", []),
    ("test_legacy32_shape.py", []),
    ("test_lib_cells_vng.py", []),
    ("test_lifecycle_cli_oracle.py", []),
    ("test_loader.py", []),
    ("test_loader_lifetimes.py", []),
    ("test_matched_cost_run.py", []),
    ("test_measure_e03.py", []),
    ("test_mem_churn.py", []),
    ("test_merge_checksum_ledgers.py", []),
    ("test_narrow_scope_oracle.py", []),
    ("test_nodata_matrix_oracle.py", []),
    ("test_object_journal_qualification.py", []),
    ("test_object_observations.py", []),
    ("test_object_observations_v5.py", []),
    ("test_object_observations_v6.py", []),
    ("test_observed_key_operations.py", []),
    ("test_openssl_pkcs11_cells.py", []),
    ("test_operator_output_qualification.py", []),
    ("test_package_release.py", []),
    ("test_package_preview.py", []),
    ("test_prepare_dependencies.py", []),
    ("test_prepared_dependency_evidence.py", []),
    ("test_prepared_dependency_metadata.py", []),
    ("test_prepared_dependency_tools.py", []),
    ("test_provider_matrix_cell.py", []),
    ("test_provider_observations_v8.py", []),
    ("test_public_cli_breadth.py", []),
    ("test_public_cli_oracle.py", []),
    ("test_public_cli_qualifier.py", []),
    ("test_qualifier_guard_blocks.py", []),
    ("test_p11kit_transparency_oracle.py", []),
    ("test_real_provider_oracle.py", []),
    ("test_python_suite_registry.py", []),
    ("test_qualify_inventory_judge.py", []),
    ("test_qualify_records.py", []),
    ("test_release_matrix_contract.py", []),
    ("test_release_build_jobs.py", []),
    ("test_release_notices.py", []),
    ("test_release_recipient.py", []),
    ("test_residual_gates.py", []),
    ("test_return_probe_admission.py", []),
    ("test_run_outer_layers.py", []),
    ("test_runtime_observer_download.py", []),
    ("test_s1_throughput_compare.py", []),
    ("test_scan_only_layout_oracle.py", []),
    ("test_schema_json.py", []),
    ("test_seccomp_profile.py", []),
    ("test_skip_reason_vocabulary.py", []),
    ("test_stop_race_oracle.py", []),
    ("test_system_first_use_fixture.py", []),
    ("test_system_first_use_receipt.py", []),
    ("test_system_manifest_soak_oracle.py", []),
    ("test_system_scope_equality.py", []),
    ("test_system_scope_measure_launch.py", []),
    ("test_system_scope_receipt.py", []),
    ("test_system_scope_sample.py", []),
    ("test_system_scope_soak.py", []),
    ("test_system_test_manifest.py", []),
    ("test_t7_campaign.py", []),
    ("test_tls_server_resumption.py", []),
    ("test_uprobe_close_throughput_probe.py", []),
    ("test_upgrade_regenerate.py", []),
    ("test_vng_boot_watch.py", []),
    ("test_vng_wrapper_exits.py", []),
    ("test_wide_curation_message.py", []),
    ("test_witness_cli_vng.py", []),
]

_ARTIFACT_CONTRACTS = "tests/artifact_contracts.rs"
_RECEIPTS = "tests/receipt_build_subjects.rs"

# file -> driver path. The driver must pass the quoted repo-relative path
# (`"tests/python/<file>"`) or, for a discover-by-pattern driver, the quoted
# file name as an invocation argument (see INVOCATION_MARKERS); a bare
# mention in a comment or a message does not count.
DRIVEN = {
    "test_audit_oracle.py": _ARTIFACT_CONTRACTS,
    "test_guard_removal_sweep.py": ".github/workflows/guard-sweep-nightly.yml",
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
    "test_journal_descriptor_source.py": "tests/journal_descriptor_source.rs",
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
    (Workflow drivers take the exact run-line rule instead.)
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


WORKFLOW_RUNNER_INVOCATION = "python3 -I scripts/run-python-suites.py"


def workflow_drives_suite(text, name):
    """A workflow step drives a suite only for the exact registered
    runner invocation. Echoes, env vars, comments and multiline blocks
    never count: the `run:` line must equal the invocation exactly."""
    want = f"{WORKFLOW_RUNNER_INVOCATION} {name}"
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped.startswith("- run:"):
            command = stripped[len("- run:"):].strip()
        elif stripped.startswith("run:"):
            command = stripped[len("run:"):].strip()
        else:
            continue
        if command == want:
            return True
    return False


def driven_state(text, name, driver):
    """How a driver references a suite: "driven", "named" or "missing"."""
    if driver.endswith((".yml", ".yaml")):
        if workflow_drives_suite(text, name):
            return "driven"
        uncommented = "\n".join(
            line.split("#", 1)[0] for line in text.splitlines())
        if name in uncommented:
            return "named"
        return "missing"
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
    """(names, problems): test_*.py entries in tests/python.

    Uses os.scandir, which raises on listing failure: pathlib glob
    swallows it and would report an unreadable directory as an
    empty, check-passing suite set.
    """
    try:
        with os.scandir(root / SUITE_DIR) as entries:
            return ({entry.name for entry in entries
                     if fnmatch.fnmatchcase(entry.name, "test_*.py")}, [])
    except OSError as exc:
        return set(), [f"{root / SUITE_DIR}: cannot list suite directory: {exc.strerror or exc}"]


def read_driver(root):
    def read(path):
        try:
            return (root / path).read_text(encoding="utf-8")
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            return None

    return read


def check(root=ROOT):
    present, scan_problems = present_suites(root)
    return scan_problems + registry_problems(
        present, RUN, DRIVEN, EXCLUDED, read_driver(root))


def print_registry():
    for name, args in RUN:
        print(f"RUN       {name} {' '.join(args)}".rstrip())
    for name, driver in sorted(DRIVEN.items()):
        print(f"DRIVEN    {name} by {driver}")
    for name, reason in sorted(EXCLUDED.items()):
        print(f"EXCLUDED  {name}: {reason}")


def merge_typed_fragments(fragment_specs, output, host):
    """Merge per-suite fragments into the typed result document.

    The outer runner owns the invocation selection. In addition to unittest
    cases it selects two integrity rows per suite invocation: one for the
    process-exit/terminal-outcome consistency proof and one for module or
    class-level terminal events. Those rows are typed executable state, not
    log text, so a pass-then-nonzero-exit or tearDownModule error cannot be
    erased after every selected test passed. The fragment's self-reported
    process_exit must also equal the outer-observed returncode, since the
    fragment is written before interpreter shutdown and a teardown crash
    never reaches it.
    """
    selection = []
    results = []
    complete = True
    process_problems = []
    failure_states = {"failed", "error", "unexpected_success", "not_run"}
    event_failure_states = {"failed", "error", "unexpected_success"}
    required_keys = {"schema", "path", "invocation", "process_exit", "complete", "selection", "results", "suite_events"}
    checker = checker_module()

    for spec in fragment_specs:
        fragment_path, name, outer_invocation = spec[0], spec[1], spec[2]
        # The outer exit code is authoritative: the fragment is written before
        # interpreter shutdown, so a teardown crash never reaches it. Legacy
        # 3-tuples (unit callers) carry no outer code and keep the old shape.
        observed_returncode = spec[3] if len(spec) > 3 else None
        suite_path = f"{SUITE_DIR}/{name}"
        invocation = list(outer_invocation)
        fragment = None
        invalid = True
        try:
            text = fragment_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            fragment = None
        else:
            fragment, _load_problems = checker.strict_json(text, str(fragment_path))
        if type(fragment) is dict and set(fragment) == required_keys:
            actual_invocation = fragment.get("invocation")
            invalid = not (
                fragment.get("schema") == "p11scope/python-suite-fragment/v1"
                and fragment.get("path") == suite_path
                and type(actual_invocation) is list
                and all(type(item) is str for item in actual_invocation)
                and actual_invocation == invocation
                and type(fragment.get("process_exit")) is int
                and type(fragment.get("complete")) is bool
                and type(fragment.get("selection")) is list
                and type(fragment.get("results")) is list
                and type(fragment.get("suite_events")) is list
            )
        if invalid:
            complete = False
            fragment = {
                "complete": False, "process_exit": None, "selection": [], "results": [], "suite_events": [],
            }

        selected_tests = []
        for item in fragment["selection"]:
            if (type(item) is dict and set(item) == {"test"}
                    and type(item.get("test")) is str and item["test"]):
                selected_tests.append(item["test"])
                selection.append({"path": suite_path, "test": item["test"], "invocation": invocation})
            else:
                invalid = True
                complete = False
        outcome_rows = []
        failure_present = False
        for item in fragment["results"]:
            if (type(item) is not dict or set(item) != {"test", "state", "signature"}
                    or type(item.get("test")) is not str or not item["test"]
                    or type(item.get("state")) is not str or not item["state"]):
                invalid = True
                complete = False
                continue
            state = item.get("state")
            outcome_rows.append(item)
            if state in failure_states:
                failure_present = True
            results.append({
                "path": suite_path,
                "test": item["test"],
                "invocation": invocation,
                "state": state,
                "signature": item.get("signature"),
            })
        if len(set(selected_tests)) != len(selected_tests) or len({row["test"] for row in outcome_rows}) != len(outcome_rows):
            complete = False
        if {row["test"] for row in outcome_rows} != set(selected_tests):
            complete = False
        if fragment.get("complete") is not True:
            complete = False

        suite_events = []
        for event in fragment["suite_events"]:
            if (type(event) is dict and set(event) == {"event", "state", "signature"}
                    and type(event.get("event")) is str and event["event"]
                    and type(event.get("state")) is str
                    and event.get("state") in SUITE_EVENT_STATES
                    and (event.get("signature") is None
                         or type(event.get("signature")) is dict)):
                suite_events.append(event)
                if event["state"] in event_failure_states:
                    failure_present = True
            else:
                invalid = True
                complete = False

        process_identity = {"path": suite_path, "test": "<suite-process>", "invocation": invocation}
        events_identity = {"path": suite_path, "test": "<suite-events>", "invocation": invocation}
        selection.extend([process_identity, events_identity])
        process_exit = fragment.get("process_exit")
        if observed_returncode is None:
            observed_returncode = process_exit
        process_consistent = (
            not invalid
            and process_exit in (0, 1)
            and ((process_exit == 1) == failure_present)
            and observed_returncode == process_exit
        )
        if process_consistent:
            process_state = "passed"
            process_signature = None
        else:
            process_state = "failed"
            branch = "fragment_invalid" if invalid else "process_exit_inconsistent"
            process_signature = {"oracle": "python-suite-process", "branch": branch, "exit_code": process_exit}
            process_problems.append((str(fragment_path), name, list(invocation)))
        results.append({**process_identity, "state": process_state, "signature": process_signature})

        failing_events = [event for event in suite_events if event["state"] in event_failure_states]
        if failing_events:
            event_rows = [
                {"event": event["event"], "state": event["state"], "signature": event.get("signature")}
                for event in failing_events
            ]
            results.append({**events_identity, "state": "failed",
                            "signature": {"oracle": "python-suite-events", "events": event_rows}})
        else:
            results.append({**events_identity, "state": "passed", "signature": None})

    document = {
        "schema": "p11scope/known-failing-results/v1",
        "runner": "python-suite",
        "host": host,
        "complete": complete,
        "selection": selection,
        "results": results,
    }
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as exc:
        print(f"run-python-suites: cannot write typed results {output}: {exc}", file=sys.stderr)
        return None
    return process_problems


def run_suites(selected):
    failed = []
    typed_output = os.environ.get("P11SCOPE_KNOWN_FAILING_RESULTS")
    typed_host = os.environ.get("P11SCOPE_KNOWN_FAILING_HOST")
    typed = bool(typed_output or typed_host)
    fragments = []
    entries = list(RUN) + [
        (name, []) for name in sorted(DRIVEN) if name in selected
    ]
    with tempfile.TemporaryDirectory(prefix="python-suite-fragments-") as temporary:
        for index, (name, args) in enumerate(entries):
            if selected and name not in selected:
                continue
            label = " ".join([name, *args])
            start = time.monotonic()
            print(f"=== {label}", flush=True)
            if typed:
                fragment = Path(temporary) / f"fragment-{index}.json"
                command = [
                    sys.executable, "-I", "scripts/typed-python-suite.py",
                    f"{SUITE_DIR}/{name}", str(fragment), *args, "-v",
                ]
            else:
                command = [sys.executable, "-I", f"{SUITE_DIR}/{name}", *args, "-v"]
            result = subprocess.run(command, cwd=ROOT, env=os.environ.copy())
            if typed:
                fragments.append((fragment, name, list(args), result.returncode))
            seconds = time.monotonic() - start
            verdict = "PASS" if result.returncode == 0 else f"FAIL rc={result.returncode}"
            print(f"=== {verdict} {label} ({seconds:.0f}s)", flush=True)
            if result.returncode != 0:
                failed.append(label)
        if typed:
            if not typed_output or not typed_host:
                print("run-python-suites: typed results need both P11SCOPE_KNOWN_FAILING_RESULTS and P11SCOPE_KNOWN_FAILING_HOST", file=sys.stderr)
                return [*failed, "typed-result configuration"]
            output = Path(typed_output)
            process_problems = merge_typed_fragments(fragments, output, typed_host)
            if process_problems is None:
                return [*failed, "typed-result output"]
            checker = subprocess.run(
                [sys.executable, "-I", "scripts/check-known-failing.py", "--results", str(output)],
                cwd=ROOT,
            )
            if checker.returncode != 0:
                return [*failed, "known-failing ledger judgment"]
            if process_problems:
                return [*failed, *[f"{name} process-integrity" for _path, name, _args in process_problems]]
            if failed:
                print("run-python-suites: nonzero suite outcomes are exactly covered by the typed known-failing ledger")
                return []
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
    present, _scan_problems = present_suites(ROOT)
    print(
        f"run-python-suites: registry covers all {len(present)} suites "
        f"({len(RUN)} runs here, {len(DRIVEN)} driven, {len(EXCLUDED)} excluded)"
    )
    if argv[:1] == ["--check"]:
        return 0
    selected = set(argv)
    runnable = {name for name, _ in RUN} | set(DRIVEN)
    unknown = selected - runnable
    if unknown:
        print(f"run-python-suites: not a runnable suite: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    failed = run_suites(selected)
    if failed:
        print(f"run-python-suites: {len(failed)} failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("run-python-suites: all suites passed")
    return 0


def entry(argv):
    """CLI entry point: every operational failure is a typed refusal, never a traceback."""
    try:
        return main(argv)
    except (OSError, RecursionError, TypeError, ValueError, KeyError, UnicodeError) as exc:
        print(f"run-python-suites: internal refusal: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(entry(sys.argv[1:]))
