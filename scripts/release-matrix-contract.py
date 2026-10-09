#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Versioned release-matrix selection and fail-closed artifact judge (stdlib only)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid

SCHEMA = "p11scope/release-matrix-contract/v1"
ROOT = Path(__file__).resolve().parents[1]
LANES = ("5.15.221", "6.1.188", "6.6.157", "6.8.0-142-generic", "6.12.111", "7.2.6", "host")
PID_TEST = "tests::the_pid_filter_probe_reaches_the_kernel"
# Exact source registrations; only an actual candidate list establishes membership.
DEFAULT_LIB_TESTS = (
    'attach::identity_iter::tests::anchor_maps_validate_real_handles',
    'attach::identity_iter::tests::functional_probe_proves_hardlink_match_and_copy_none',
    'attach::identity_iter::tests::whole_system_run_covers_all_children',
    'attach::identity_iter::tests::wronly_anchor_fds_refuse_reads_with_eperm',
    'attach::instance_tests::privileged_instance_attach_during_reload_loop_has_zero_false_joins',
    'attach::instance_tests::privileged_instance_exec_renews_the_instance',
    'attach::instance_tests::privileged_instance_fork_without_exec_stays_consistent',
    'attach::instance_tests::privileged_instance_hooks_attach_for_profile_but_not_metrics',
    'attach::instance_tests::privileged_instance_mapping_controls_never_join_old_state',
    'attach::instance_tests::privileged_instance_mremap_dontunmap_keeps_both_and_renews',
    'attach::instance_tests::privileged_instance_nonleader_exec_detaches_without_misrouting',
    'attach::instance_tests::privileged_instance_overflow_at_ninth_file_is_unknown',
    'attach::instance_tests::privileged_instance_pre_attachment_sharer_globalizes',
    'attach::instance_tests::privileged_instance_reload_race_has_zero_false_joins',
    'attach::instance_tests::privileged_instance_routing_separates_reload_sibling_and_mutation',
    'attach::instance_tests::privileged_instance_vfork_unmap_globalizes',
    'attach::instance_tests::privileged_instance_zombie_leader_sharer_globalizes',
    'attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_auto_excludes_foreign_and_reused_pid_lp64',
    'attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_forced_multi_names_the_target_or_refuses_lp64',
    'attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_singles_excludes_foreign_and_reused_pid_lp64',
    'attach::inventory::activation::privileged_tests::privileged_detailed_auto_backend_same_cpu_preemption_keeps_frames',
    'attach::inventory::activation::privileged_tests::privileged_detailed_multithread_owner_accounting_exact',
    'attach::inventory::activation::privileged_tests::privileged_detailed_multithread_same_slot_allowlisted_exact',
    'attach::inventory::activation::privileged_tests::privileged_detailed_owner_poison_is_disclosed',
    'attach::inventory::activation::privileged_tests::privileged_detailed_same_cpu_preemption_keeps_frames',
    'attach::inventory::activation::privileged_tests::privileged_inventory_activation_cgroup_separates_owned_callers',
    'attach::inventory::activation::privileged_tests::privileged_inventory_activation_failure_preserves_usage_and_releases_resources',
    'attach::inventory::activation::privileged_tests::privileged_inventory_activation_stop_with_owned_calls_in_progress',
    'attach::inventory::activation::privileged_tests::privileged_inventory_activation_system_ia32',
    'attach::inventory::activation::privileged_tests::privileged_inventory_activation_system_lp64',
    'attach::inventory::activation::privileged_tests::privileged_inventory_caller_cgroup_lp64',
    'attach::inventory::activation::privileged_tests::privileged_inventory_caller_partial_activation_lp64',
    'attach::inventory::activation::privileged_tests::privileged_inventory_caller_system_ia32',
    'attach::inventory::activation::privileged_tests::privileged_inventory_caller_system_lp64',
    'attach::inventory::activation::privileged_tests::privileged_stop_gate_freezes_capture_state_after_quiescence',
    'attach::inventory::activation::privileged_tests::privileged_stop_gate_keeps_calls_in_flight_as_residual',
    'attach::inventory::activation::privileged_tests::privileged_t7_detailed_hot_slot_third_rv_lp64',
    'attach::inventory::activation::privileged_tests::privileged_t7_inventory_n1024_lp64',
    'attach::inventory::activation::privileged_tests::privileged_t7_inventory_n576_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_detailed_n512_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_detailed_physical_identity_controls',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_2112_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2048_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2049_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_n511_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_n512_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_n513_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_physical_identity_controls',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_cookie_query_matches_row_and_changes_on_nonleader_exec_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_extend_late_provider_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_leader_exit_probe_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_pid_scope_excludes_foreign_and_reused_pid_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_pid_scope_leader_exit_probe_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_stop_with_held_call_reports_unsettled_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_stop_before_activation_repolls_custody_lp64',
    'attach::inventory::privileged_tests::privileged_inventory_caller_preparation_faults_release_exact_resources',
    'attach::inventory::privileged_tests::privileged_inventory_caller_preparation_freezes_native_maps_and_publishes_binding',
    'attach::inventory::privileged_tests::privileged_inventory_preparation_failure_releases_owned_resources',
    'attach::inventory::privileged_tests::privileged_inventory_preparation_freezes_all_nine_protected_maps',
    'attach::inventory::privileged_tests::privileged_inventory_preparation_loads_multi_without_links',
    'attach::inventory::privileged_tests::privileged_inventory_preparation_loads_runtime_capacity_and_zero_links',
    'attach::lifecycle_tests::exec_tests::privileged_detailed_failed_nonleader_exec_preserves_start_and_image',
    'attach::lifecycle_tests::exec_tests::privileged_detailed_nonleader_exec_cleans_old_tid_before_same_session_rebind',
    'attach::lifecycle_tests::privileged_detailed_nonleader_exit_preserves_same_slot_sibling_start',
    'attach::lifecycle_tests::privileged_detailed_nonleader_exit_reclaims_start_and_preserves_leader',
    'discovery::confirm_shards::tests::privileged_sharded_confirmation_equals_the_serial_production_probe',
    'discovery::engine::publication_tests::broad_p11kit_admission_arithmetic',
    'discovery::inventory_workload::tests::privileged_inventory_attach_projection_n4097',
    'discovery::inventory_workload::tests::privileged_inventory_attach_projection_n6530',
    'discovery::inventory_workload::tests::privileged_inventory_attach_projection_n8192',
    'discovery::sweep_attribution::tests::privileged_a_data_only_mapper_of_an_identity_key_is_never_attributed_on_ext4',
    'discovery::sweep_attribution::tests::privileged_an_unmapped_file_whose_inode_is_reused_is_never_attributed_on_ext4',
    'events::runtime_tests::real_retained_consumer_keeps_one_cursor_across_all_drains',
    'events::runtime_tests::real_retained_discovery_consumer_owns_one_exact_map',
    'events::runtime_tests::real_uretprobe_hazard_self_probe_reaches_a_verdict',
    'inventory::privileged_tests::privileged_native_lane_pid_lp64',
    'inventory::privileged_tests::privileged_native_lane_sigint_during_extend_lp64',
    'inventory::privileged_tests::privileged_native_lane_stop_held_call_unsettled_lp64',
    'inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64',
    'inventory::privileged_tests::privileged_native_lane_system_late_dlopen_lp64',
    'inventory::privileged_tests::privileged_native_lane_system_ab_first_count_lp64',
    'inventory::privileged_tests::privileged_native_lane_system_many_endpoints_lp64',
    'inventory::privileged_tests::privileged_native_lane_dashboard_slow_pty_lp64',
)

BREADTH = tuple("attach::inventory::activation::privileged_tests::" + name for name in (
    "privileged_t7_inventory_n4097_lp64", "privileged_t7_inventory_n6530_lp64",
    "privileged_t7_inventory_n8192_boundary_lp64"))
IDENTITY_POSITIVE = tuple("attach::identity_iter::tests::" + name for name in (
    "functional_probe_proves_hardlink_match_and_copy_none", "whole_system_run_covers_all_children",
    "wronly_anchor_fds_refuse_reads_with_eperm"))
OTHER_LONG = {
    "attach::instance_tests::privileged_instance_continuity_experiment_softhsm":
        "separately owned SoftHSM continuity duration/rate and mapping-operation lane",
    "attach::inventory::activation::privileged_tests::privileged_bench_overhead_detailed_calls":
        "separately owned release-build timing baseline, quiet host and overhead budget",
}
PUBLIC = {
    "profile-pid": "owned-provider-counts", "metrics-pid": "owned-provider-counts",
    "mt-exact": "owned-provider-counts", "system": "owned-provider-counts",
    "names-pid": "semantic-names", "verdict-pid": "verdict-consistency",
    "doctor": "command-contract", "sigint": "command-contract",
    "second-sigint": "command-contract", "fifo-refused": "command-contract",
    "run-short": "nonqualifying", "run-cover": "nonqualifying",
    "trace-pid": "nonqualifying",
}
BASE_IDS = ("version", "doctor", "inventory-native", "pid-filter", "backend-pid", "backend-system")
EXITS = {"version.log": "version", "doctor.log": "doctor", "qual.log": "qual",
         "inv-native.log": "inv_native", "pidflt.log": "pidflt", "priv.log": "priv",
         "backend/inv-pid.stderr": "inv_pid", "backend/inv-sys.stderr": "inv_sys"}
RUNTIME_SOURCES = ("tests/fixtures/public-cli/inventory-ledger.c", "scripts/fixtures/exec_churn.c")
SOURCE_FILES = ("scripts/release-matrix-contract.py", "scripts/qualify-release-matrix.sh",
                "scripts/run-privileged-lib-tests.sh", "scripts/qualify-public-cli.sh",
                "scripts/qualify-inventory-native.sh", "scripts/inventory-native-oracle.py",
                "tests/fixtures/public-cli/gated.c", "tests/fixtures/public-cli/mt.c",
                "tests/fixtures/public-cli/inventory-ledger.c")
TOLERANCE_ENV = ("P11SCOPE_PRIV_LIFECYCLE_LOSS", "P11SCOPE_TEST_TIME_SCALE")
CLASSIC_MULTI = "attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_forced_multi_names_the_target_or_refuses_lp64"
MULTI_OUTCOMES = {
    CLASSIC_MULTI: "CLASSIC_PID_SCOPE selection=multi",
    "attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64": "C3_PID_SCOPE backend=Multi",
    "attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_leader_exit_probe_lp64": "C3_LEADER_EXIT_PROBE backend=Multi",
}
CHURN = "inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64"
BROAD = "discovery::engine::publication_tests::broad_p11kit_admission_arithmetic"


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def load(path):
    return decode(path.read_text())


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def relative(stage, name):
    require(isinstance(name, str) and name and not Path(name).is_absolute(), "invalid artifact path")
    path = stage / name
    require(path.resolve().is_relative_to(stage.resolve()), "artifact escapes stage: " + name)
    require(not path.is_symlink(), "symlink artifact: " + name)
    return path


def selection(lane, lib_tests=None, public_cells=None, scan=True):
    require(lane in LANES, "unregistered kernel lane: " + lane)
    require(type(scan) is bool, "invalid scan selection")
    defaults = DEFAULT_LIB_TESTS + BREADTH
    if lane == "5.15.221":
        defaults = tuple(n for n in defaults if n not in IDENTITY_POSITIVE)
    libs = list(defaults if lib_tests is None else lib_tests)
    publics = list(PUBLIC if public_cells is None else public_cells)
    require(libs and all(isinstance(n, str) and n for n in libs), "empty lib selection")
    require(len(libs) == len(set(libs)), "duplicate selected lib ID")
    require(set(libs) <= set(DEFAULT_LIB_TESTS + BREADTH) | set(OTHER_LONG), "unknown exact lib selector")
    require(lane != "5.15.221" or not set(libs) & set(IDENTITY_POSITIVE), "positive identity gate requires eligible BTF; 5.15 refusal selector is unready")
    require(publics and len(publics) == len(set(publics)) and set(publics) <= set(PUBLIC), "invalid public selection")
    ids = list(BASE_IDS) + (["inventory-scan"] if scan else [])
    ids += ["public:" + n for n in publics] + ["lib:" + n for n in libs]
    if lane == "5.15.221":
        ids.append("identity:5.15-denied")
    return {"schema": SCHEMA, "claim": "selected-release-matrix", "lane": lane,
            "required_ids": ids, "lib_tests": libs,
            "public_cells": [{"cell": n, "qualification": PUBLIC[n]} for n in publics],
            "include_scan": scan, "threads": 12, "pid_filter_test": PID_TEST,
            "tolerance_policy": {"environment": "unset-or-empty", "forbidden_environment": list(TOLERANCE_ENV),
                                 "retained_optins": "refuse", "lifecycle_loss_reported": "refuse"},
            "lib_outcomes": {name: "own-positive-or-pid-filter-refusal" if name in MULTI_OUTCOMES else
                             "rate100-lossless-and-rate1000-disclosed" if name == CHURN else
                             "selected-admission-and-broad-no-spill-or-whole-module-refusal" if name == BROAD else "exact-success"
                             for name in libs},
            "lib_argv": ["--include-long", *libs],
            "pid_backend": {"proven": ["uprobe-multi", "kernel-pid+bpf"],
                            "unproven": ["per-offset", "perf-task+bpf", "expected-fallback"],
                            "preparation_refused": ["per-offset", "perf-task+bpf", "expected-fallback"]},
            "system_backend": {"linked": ["uprobe-multi", None],
                               "unavailable": ["per-offset", None, "expected-fallback"],
                               "preparation_refused": ["per-offset", None, "expected-fallback"]},
            "full_stage5_ready": False,
            "obligations": [{"id": "D4:" + substrate, "status": "unready", "libtest": None,
                             "prerequisites": "accepted D3/D4 source bodies and kernel/userspace parity selectors"}
                            for substrate in ("btrfs", "overlay-6.1", "overlay-6.6", "overlay-6.8+", "ext4-inode-reuse")]
                + [{"id": "long:" + n, "status": "selected" if n in libs else "not-selected",
                    "libtest": n, "prerequisites": reason} for n, reason in OTHER_LONG.items()]
                + ([{"id": "identity:5.15-denied", "status": "unready", "libtest": None,
                     "prerequisites": "real BTF named-fix refusal selector; pure fixture denial tests do not prove this guest",
                     "excluded_positive_libtests": list(IDENTITY_POSITIVE)}] if lane == "5.15.221" else [])}


def validate_contract(contract):
    require(isinstance(contract, dict), "contract is not an object")
    publics = contract.get("public_cells", [])
    require(isinstance(publics, list) and all(isinstance(row, dict) for row in publics), "invalid public contract")
    core = selection(contract.get("lane", ""), contract.get("lib_tests", []),
                     [row.get("cell") for row in publics], contract.get("include_scan"))
    for key, value in core.items():
        require(contract.get(key) == value, "contract registration drift: " + key)
    require(isinstance(contract.get("run_id"), str) and re.fullmatch(r"[0-9a-f]{32}", contract["run_id"]), "invalid run binding")
    return core


def listed_names(text):
    names = re.findall(r"^(.+): test$", text, re.M)
    require(names and len(names) == len(set(names)), "missing or duplicate binary --list IDs")
    return names


def curated_names(text):
    groups = {"default": [], "long": [], "skipped": []}
    group = None
    counts = {}
    for line in text.splitlines():
        match = re.fullmatch(r"(default|long|skipped) \((\d+)(?:, --include-long only)?\)", line)
        if match:
            group, count = match.groups()
            require(group not in counts, "duplicate curation section")
            counts[group] = int(count)
        elif line.startswith("verify:"):
            require(re.fullmatch(r"verify: curation matches the binary \(\d+ tests\)", line), "failed curation receipt")
        elif line.strip():
            require(group is not None and "::" in line, "invalid curation line")
            groups[group].append(line.split(" :: ", 1)[0])
    require(set(counts) == set(groups), "missing curation sections")
    for key, values in groups.items():
        require(len(values) == counts[key], "curation section count mismatch")
    all_names = sum(groups.values(), [])
    require(all_names and len(all_names) == len(set(all_names)), "duplicate curation ID")
    footer = re.findall(r"^verify: curation matches the binary \((\d+) tests\)$", text, re.M)
    require(footer == [str(len(all_names))], "missing/conflicting curation verification")
    return groups


def membership(stage, contract):
    listed = listed_names((stage / "inputs/ignored.txt").read_text())
    curated = curated_names((stage / "inputs/curation.txt").read_text())
    all_curated = sum(curated.values(), [])
    require(set(listed) == set(all_curated), "curation does not exactly cover candidate ignored list")
    for name in contract["lib_tests"]:
        require(name in listed, "required ID absent from candidate: " + name)
        require(name not in curated["skipped"], "required ID is statically skipped: " + name)
        require([n for n in all_curated if name in n] == [name], "ambiguous runner substring selector: " + name)
    require(PID_TEST in listed_names((stage / "inputs/bpfmulti-list.txt").read_text()), "missing exact PID-filter binary selector")


def prepare(args):
    stage = args.prepare.resolve()
    stage.mkdir(parents=True, exist_ok=True)
    require(not (stage / "contract.json").exists(), "refuse to overwrite an execution contract")
    core = selection(args.lane, args.lib_test, args.public_cell, not args.without_scan)
    core["run_id"] = uuid.uuid4().hex
    bindings = {}
    sources = {"inputs/ignored.txt": args.binary_list, "inputs/curation.txt": args.curation,
               "inputs/bpfmulti-list.txt": args.bpfmulti_list}
    require(args.bin_dir and all(sources.values()), "prepare requires exact artifacts, list and curation receipts")
    require(args.candidate_receipt is not None, "prebuilt candidate requires a build-produced source-root receipt")
    candidate = validate_candidate(load(args.candidate_receipt), args.bin_dir / "p11scope-lib")
    sources["inputs/candidate-build.json"] = args.candidate_receipt
    for name in RUNTIME_SOURCES:
        sources["artifacts/lib-source/" + name] = Path(candidate["source_root"]) / name
    sources.update({"artifacts/" + name: args.bin_dir / name for name in
                    ("p11scope", "p11scope-lib", "p11scope-bpfmulti")})
    for name in SOURCE_FILES:
        sources["artifacts/source/" + name] = ROOT / name
    # Task2's accepted checker joins the integrated source pin; never invent it.
    if (ROOT / "scripts/public-cli-oracle.py").exists():
        sources["artifacts/source/scripts/public-cli-oracle.py"] = ROOT / "scripts/public-cli-oracle.py"
    for name, origin in sources.items():
        require(origin.is_file(), "missing input: " + str(origin))
        path = relative(stage, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, path)
        bindings[name] = sha(path)
    core["bindings"] = bindings
    membership(stage, core)
    save(stage / "contract.json", core)
    print(json.dumps({"contract": str(stage / "contract.json"), "sha256": sha(stage / "contract.json")}))


def expected_paths(contract):
    paths = set(EXITS) | {"uname.txt", "cells/results.jsonl", "run/results.txt",
                         "backend/inv-pid.json", "backend/inv-sys.json"}
    if contract["include_scan"]:
        paths.add("inv-scan.log")
    for name in contract["lib_tests"]:
        paths.add("run/logs/" + name.rsplit("::", 1)[-1] + ".log")
    return paths


def evidence_paths(stage, contract):
    paths = expected_paths(contract)
    for directory in ("cells", "run", "backend", "c8-native", "c8-scan"):
        for path in (stage / directory).rglob("*"):
            if path.is_file():
                name = str(path.relative_to(stage))
                relative(stage, name)
                paths.add(name)
    return paths


def seal(stage, contract_path, guest_exit):
    contract = load(contract_path)
    validate_contract(contract)
    require(type(guest_exit) is int and 0 <= guest_exit <= 255, "invalid guest exit")
    hashes = {}
    for name in sorted(evidence_paths(stage, contract)):
        path = relative(stage, name)
        if path.is_file():
            hashes[name] = sha(path)
    save(stage / "receipt.json", {"schema": "p11scope/release-matrix-execution/v1",
                                 "run_id": contract["run_id"], "contract_sha256": sha(contract_path),
                                 "guest_exit": guest_exit, "evidence_sha256": hashes})


def process_exit(text, name, run_id):
    exits = re.findall(r"^" + re.escape(name) + r"_exit=(\d+)$", text, re.M)
    require(len(exits) == 1, "missing/conflicting " + name + "_exit")
    require(re.findall(r"^matrix_run=(\S+)$", text, re.M) == [run_id], "stale/unbound " + name + " log")
    return int(exits[0])


def exact_test(text, name):
    # Totals alone and zero-filter matches never establish the executed ID.
    require(re.findall(r"^test (\S+) \.\.\.", text, re.M) == [name], "wrong/missing exact test log: " + name)
    summaries = re.findall(r"^test result: (.+)$", text, re.M)
    require(len(summaries) == 1 and re.match(r"ok\. 1 passed; 0 failed; 0 ignored;", summaries[0]), "test did not execute exactly once: " + name)


def validate_candidate(receipt, lib):
    require(isinstance(receipt, dict) and receipt.get("schema") == "p11scope/release-matrix-build/v1", "missing/invalid candidate build receipt")
    require(receipt.get("producer") == "cargo-build" and receipt.get("source_clean") is True,
            "candidate needs a clean actual Cargo build receipt, not a user declaration")
    root = Path(receipt.get("source_root", ""))
    require(root.is_absolute() and str(root.resolve()) == str(root) and root.is_dir(), "invalid compiled fixture source root")
    for key in ("source_revision", "source_tree"):
        require(isinstance(receipt.get(key), str) and re.fullmatch(r"[0-9a-f]{40}", receipt[key]), "missing exact build " + key)
    build = receipt.get("build", {})
    argv = build.get("argv", [])
    require(build.get("cwd") == str(root) and type(build.get("exit")) is int and build["exit"] == 0
            and isinstance(argv, list) and all(isinstance(value, str) and value for value in argv)
            and {"test", "--lib", "--no-run"} <= set(argv), "missing actual successful lib build command")
    require(receipt.get("lib_sha256") == sha(lib), "candidate build receipt binary mismatch")
    sources = receipt.get("runtime_sources", {})
    require(isinstance(sources, dict) and set(sources) == set(RUNTIME_SOURCES), "missing candidate runtime fixture closure")
    for name, digest in sources.items():
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest), "invalid candidate source hash")
        require(sha(root / name) == digest, "compiled fixture source changed: " + name)
    return receipt


def launch_policy():
    for name in TOLERANCE_ENV:
        require(not os.environ.get(name), "disallowed qualification tolerance: " + name)


def lib_outcome(name, text):
    require("LIFECYCLE_LOSS_REPORTED" not in text, "disallowed lifecycle loss tolerance: " + name)
    if name in MULTI_OUTCOMES:
        tag = MULTI_OUTCOMES[name]
        lines = re.findall(r"(?:^|\.\.\. )(" + re.escape(tag) + r"[^\n]*)", text, re.M)
        require(len(lines) == 1, "missing/contradictory own Multi branch: " + name)
        line = lines[0]
        if " refused=" in line:
            require(re.fullmatch(re.escape(tag) + r' refused="[^\n]+"', line) and "pid filter" in line,
                    "invalid own PID-filter refusal: " + name)
            require("C3_PID_REUSE_EXCLUDED" not in text and "CLASSIC_PID_FOREIGN" not in text,
                    "own refusal contradicts positive execution evidence")
            return "expected-refusal", line
        if name == CLASSIC_MULTI:
            match = re.fullmatch(re.escape(tag) + r' multi=true scope_filter=Some\("kernel-pid\+bpf"\) fallback=None target=([1-9]\d*) target_runs=(\d+) foreign_runs=0 reused_runs=0 foreign_ns_per_call_before=[\d.]+ foreign_ns_per_call_during=[\d.]+', line)
            require(match and int(match[2]) >= 1000, "invalid own classic positive branch")
        elif tag.startswith("C3_PID_SCOPE"):
            match = re.fullmatch(re.escape(tag) + r" target=([1-9]\d*) foreign=([1-9]\d*) rows=1", line)
            reuse = re.findall(r"(?:^|\.\.\. )C3_PID_REUSE_EXCLUDED backend=Multi pid=(\d+) rows=0 custody=lost$", text, re.M)
            require(match and match[1] != match[2] and reuse == [match[1]], "missing own Multi foreign/reused-PID assertions")
        else:
            match = re.fullmatch(re.escape(tag) + r' pid=[1-9]\d* before_exit_usage1=1 leader_state=Z pidfd_alive=true after_exit_usage2_3=\[([01]), ([01])\] fired_after_exit=(true|false) custody=PidUnproven \{ at_ns: \d+, reason: "[^\n]*leader[^\n]*" \}', line)
            require(match and (match[3] == "true") == ("1" in (match[1], match[2])), "missing/conflicting own Multi leader-exit assertions")
        return "positive-coverage", line
    if name == CHURN:
        branches = re.findall(r"(?:^|\.\.\. )C57_CHURN_BRANCH rate=(\d+) branch=(\w+)([^\n]*)", text, re.M)
        require(branches and all(rate in ("100", "1000") and branch in ("starved", "lossless", "loss") for rate, branch, _ in branches), "churn skipped/unknown required assertion")
        low = [(branch, rest) for rate, branch, rest in branches if rate == "100"]
        high = [(branch, rest) for rate, branch, rest in branches if rate == "1000"]
        require(len(low) in (1, 2) and low[-1][0] == "lossless" and all(branch == "starved" for branch, _ in low[:-1])
                and re.fullmatch(r" attempt=[12]", low[-1][1])
                and (len(low) == 1 or (re.fullmatch(r" attempt=1 achieved=[\d.]+", low[0][1]) and low[-1][1] == " attempt=2"))
                and len(high) == 1 and high[0][0] in ("loss", "lossless") and not high[0][1], "missing/contradictory churn rate100 zero-loss or rate1000 disclosure")
        return "positive-coverage", "rate100=lossless; rate1000=" + high[0][0]
    if name == BROAD:
        selected = re.findall(r"(?:^|\.\.\. )A2 selected: \d+ module\(s\) \d+ table\(s\) (\d+) slot\(s\) spill=\d+ refused=\d+$", text, re.M)
        broad = re.findall(r"(?:^|\.\.\. )A2 broad: ([^\n]+)", text, re.M)
        require(len(selected) == len(broad) == 1 and int(selected[0]) > 0, "missing/contradictory own p11-kit admission evidence")
        if broad[0].startswith("total refusal:"):
            require("refusing to attach a prefix" in broad[0], "invalid broad whole-module refusal")
            return "expected-refusal", "selected admission slots=" + selected[0] + "; broad " + broad[0]
        require(re.fullmatch(r"\d+ module\(s\) \d+ table\(s\) \d+ slot\(s\) spill=0 refused=\d+", broad[0]), "invalid own broad no-spill assertion")
        return "positive-coverage", "selected admission slots=" + selected[0] + "; broad " + broad[0]
    return "positive-coverage", "exact ID once, exit0, one test passed"


def verify_inputs(stage, contract_path):
    contract = load(contract_path)
    validate_contract(contract)
    bindings = contract.get("bindings")
    required = {
        "artifacts/p11scope", "artifacts/p11scope-lib", "artifacts/p11scope-bpfmulti",
        "inputs/ignored.txt", "inputs/curation.txt", "inputs/bpfmulti-list.txt",
        "inputs/candidate-build.json"}
    required.update("artifacts/source/" + name for name in SOURCE_FILES)
    required.update("artifacts/lib-source/" + name for name in RUNTIME_SOURCES)
    if (ROOT / "scripts/public-cli-oracle.py").exists():
        required.add("artifacts/source/scripts/public-cli-oracle.py")
    require(isinstance(bindings, dict) and set(bindings) >= required, "missing required source/artifact bindings")
    for name, digest in bindings.items():
        require(re.fullmatch(r"[0-9a-f]{64}", digest or ""), "invalid binding hash")
        require(sha(relative(stage, name)) == digest, "stale artifact hash: " + name)
        if name.startswith("artifacts/source/"):
            require(sha(ROOT / name.removeprefix("artifacts/source/")) == digest, "runtime source changed: " + name)
    require(bindings["artifacts/source/scripts/release-matrix-contract.py"] == sha(Path(__file__)), "judge source changed from contract")
    candidate = validate_candidate(load(stage / "inputs/candidate-build.json"), stage / "artifacts/p11scope-lib")
    for name, digest in candidate["runtime_sources"].items():
        require(bindings["artifacts/lib-source/" + name] == digest, "compiled fixture snapshot does not match build receipt")
    membership(stage, contract)
    return contract


def judge(stage, contract_path):
    contract = verify_inputs(stage, contract_path)
    receipt = load(stage / "receipt.json")
    require(receipt.get("schema") == "p11scope/release-matrix-execution/v1", "unknown execution receipt")
    require(receipt.get("run_id") == contract["run_id"] and receipt.get("contract_sha256") == sha(contract_path), "stale execution/contract hash")
    require(type(receipt.get("guest_exit")) is int and receipt["guest_exit"] == 0, "guest failed or timed out")
    hashes = receipt.get("evidence_sha256", {})
    require(set(hashes) == evidence_paths(stage, contract), "missing/unexpected required artifacts")
    for name, digest in hashes.items():
        require(sha(relative(stage, name)) == digest, "stale evidence hash: " + name)
    read = lambda name: relative(stage, name).read_text()
    require(contract["lane"] == "host" or read("uname.txt").strip().removeprefix("v") == contract["lane"], "wrong executed kernel lane")
    exits = {name: process_exit(read(path), name, contract["run_id"]) for path, name in EXITS.items()}
    if contract["include_scan"]:
        exits["inv_scan"] = process_exit(read("inv-scan.log"), "inv_scan", contract["run_id"])
        require(exits["inv_scan"] == 2, "scan must remain valid nonqualifying plumbing (exit2)")
    nonqual_public = any(row["qualification"] == "nonqualifying" for row in contract["public_cells"])
    for name, rc in exits.items():
        expected = 2 if name == "inv_scan" or (name == "qual" and nonqual_public) else 0
        require(rc == expected, "unexpected " + name + "_exit=" + str(rc))
    require("p11scope" in read("version.log").lower(), "missing observer version")
    require(len(re.findall(r"capability tier:\s*T[0-4]", read("doctor.log"))) == 1, "missing/duplicate capability tier")
    rows = []
    def row(id_, qualification, detail):
        rows.append({"id": id_, "pass": qualification != "nonqualifying", "qualification": qualification, "detail": detail})
    row("version", "command-contract", "bound candidate, exit0")
    row("doctor", "command-contract", "functional doctor ran, exit0")
    row("inventory-native", "positive-coverage", "independent native oracle exit0")
    if contract["include_scan"]:
        row("inventory-scan", "nonqualifying", "scan oracle exit2; no positive native coverage")
    public_rows = [load_json_line(line) for line in read("cells/results.jsonl").splitlines() if line.strip()]
    public_ids = [r.get("cell") for r in public_rows]
    require(len(public_ids) == len(set(public_ids)) and set(public_ids) == {r["cell"] for r in contract["public_cells"]}, "missing/duplicate/unexpected public cell ID")
    for result in public_rows:
        name = result["cell"]
        qualification = PUBLIC[name]
        require(set(result) == {"cell", "pass", "detail", "qualification"} and isinstance(result["detail"], str), "invalid public terminal row")
        require(result["qualification"] == qualification and result["pass"] is (qualification != "nonqualifying"), "failed/wrong public classification: " + name)
        row("public:" + name, qualification, result["detail"])
    exact_test(read("pidflt.log"), PID_TEST)
    proofs = re.findall(r"(?:^|\.\.\. )PIDFLT_PROBE own=(\d+) other=(\d+) proves=(true|false)$", read("pidflt.log"), re.M)
    require(len(proofs) <= 1, "duplicate PID-filter capability evidence")
    pid_proven = False
    if proofs:
        own, other, proves = proofs[0]
        require(int(own) <= 2 and int(other) <= 1, "invalid PID-filter probe counts")
        pid_proven = own == "2" and other == "0"
        require((proves == "true") == pid_proven, "conflicting functional PID-filter proof")
    row("pid-filter", "positive-coverage" if pid_proven else "expected-refusal", "own=2 other=0 proven" if pid_proven else "PID Multi unproven; fallback/refusal required")
    doctor_rows = re.findall(r"^uprobe-multi attach \(own libc\)\s*\.+\s*(ok|warn|n/a)\s*(.*)$", read("doctor.log"), re.M)
    require(len(doctor_rows) == 1, "missing/duplicate system functional probe")
    system_proven = doctor_rows[0][0] == "ok" and doctor_rows[0][1].strip() == "self-link attached and detached"
    require(system_proven or (doctor_rows[0][0] == "n/a" and "kernel" in doctor_rows[0][1]), "system capability remains unknown; no coverage claim")
    for scope, proven in (("pid", pid_proven), ("sys", system_proven)):
        attach = load(relative(stage, "backend/inv-" + scope + ".json")).get("observation", {}).get("attach", {})
        fallback = attach.get("fallback")
        preparation_refused = (proven and isinstance(fallback, str)
                               and fallback.startswith("the uprobe-multi preparation failed: ")
                               and len(fallback) > len("the uprobe-multi preparation failed: "))
        multi = proven and not preparation_refused
        expected_mechanism = "uprobe-multi" if multi else "per-offset"
        expected_filter = ("kernel-pid+bpf" if multi else "perf-task+bpf") if scope == "pid" else None
        require(attach.get("mechanism") == expected_mechanism and attach.get("scope_filter") == expected_filter, "unsupported/wrong " + scope + " backend or scope-filter")
        if multi:
            require(fallback is None, "capable backend unexpectedly fell back")
        elif not preparation_refused:
            marker = "pid filter" if scope == "pid" else "functional probe failed"
            require(isinstance(fallback, str) and marker in fallback, "missing declared " + scope + " fallback reason")
        row("backend-pid" if scope == "pid" else "backend-system", "positive-coverage" if multi else "expected-fallback", expected_mechanism + "/" + str(expected_filter))
    records = []
    require(not re.search(r"^# opt-in: (?:" + "|".join(TOLERANCE_ENV) + r")=", read("run/results.txt"), re.M), "disallowed retained qualification tolerance")
    require("LIFECYCLE_LOSS_REPORTED" not in read("priv.log"), "disallowed retained lifecycle loss tolerance")
    for line in read("run/results.txt").splitlines():
        if line.startswith(("PASS ", "FAIL ", "SKIP ")):
            match = re.fullmatch(r"PASS (\S+) rc=0 seconds=\d+ :: test result: ok\. 1 passed(?:;.*)?", line)
            require(match is not None, "failed/skipped/invalid required lib record: " + line)
            records.append(match[1])
    require(len(records) == len(set(records)) and set(records) == set(contract["lib_tests"]), "missing/duplicate/unexpected executed lib ID")
    for name in records:
        text = read("run/logs/" + name.rsplit("::", 1)[-1] + ".log")
        exact_test(text, name)
        qualification, detail = lib_outcome(name, text)
        row("lib:" + name, qualification, detail)
    if contract["lane"] == "5.15.221":
        row("identity:5.15-denied", "nonqualifying", "unready: no real executable guest refusal selector; not executed")
    require(len(rows) == len(contract["required_ids"]) and {r["id"] for r in rows} == set(contract["required_ids"]), "missing/duplicate/unexpected required ID")
    nonqual = any(r["qualification"] == "nonqualifying" for r in rows)
    return {"schema": "p11scope/release-matrix-verdict/v1", "claim": contract["claim"], "lane": contract["lane"],
            "pass": not nonqual, "qualification": "nonqualifying" if nonqual else "selected-coverage",
            "full_stage5_ready": False, "contract_sha256": sha(contract_path), "run_id": contract["run_id"],
            "rows": rows, "detail": "all exact selected assertions satisfied; full Stage5 remains pending"}, 2 if nonqual else 0


def load_json_line(line):
    result = decode(line)
    require(isinstance(result, dict), "non-object public row")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--plan", action="store_true")
    modes.add_argument("--prepare", type=Path)
    modes.add_argument("--seal", type=Path)
    modes.add_argument("--judge", type=Path)
    modes.add_argument("--verify-inputs", type=Path)
    modes.add_argument("--verify-launch-policy", action="store_true")
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--lane", default="host")
    parser.add_argument("--lib-test", action="append")
    parser.add_argument("--public-cell", action="append")
    parser.add_argument("--without-scan", action="store_true")
    parser.add_argument("--bin-dir", type=Path)
    parser.add_argument("--binary-list", type=Path)
    parser.add_argument("--curation", type=Path)
    parser.add_argument("--bpfmulti-list", type=Path)
    parser.add_argument("--candidate-receipt", type=Path)
    parser.add_argument("--guest-exit", type=int)
    args = parser.parse_args(argv)
    try:
        if args.verify_launch_policy:
            launch_policy()
            return 0
        if args.plan:
            print(json.dumps({"lanes": LANES, "execution": selection(args.lane, args.lib_test, args.public_cell, not args.without_scan)}, indent=2))
            return 0
        if args.prepare:
            prepare(args)
            return 0
        stage = (args.seal or args.judge or args.verify_inputs).resolve()
        require(args.contract is not None, "--contract required")
        require(args.contract.resolve() == (stage / "contract.json").resolve(), "contract must be the execution copy inside stage")
        if args.verify_inputs:
            verify_inputs(stage, args.contract)
            return 0
        if args.seal:
            seal(stage, args.contract, args.guest_exit)
            return 0
        result, rc = judge(stage, args.contract)
        print(json.dumps(result, sort_keys=True))
        return rc
    except (Invalid, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(json.dumps({"pass": False, "qualification": "failed", "detail": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
