# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Ignored-test inventory: every #[ignore] is a tracked obligation.

scripts/check-ignored-tests.py scans the workspace Rust sources for real
`#[ignore]` attributes and compares them both ways against
tests/ignored-tests.json: every `privileged` entry must be curated in
scripts/run-privileged-lib-tests.sh, every `feature` entry must name a
non-empty owning lane in `owner`, the wide-featured sites (wide `owner`
entries plus feature-gated macro expansions) must exactly match the
runner's WIDE_DETAILED_2112_TESTS list, and every `live-kernel` or
`privileged` integration entry must be curated in the runner's
INTEGRATION_TESTS list. These tests prove the checked-in inventory
matches the sources, then exercise each failure mode on synthetic
fixture trees so a regression in the checker cannot hide behind a clean
real tree. Final groups drive the runner's list and integration modes
against fake binaries: a matching binary is accepted, a default
or incomplete one is refused cleanly. Since v0.7.0 made 2,112 slots
the default profile, --wide-detailed-2112 is a no-op alias: the flag
is accepted and ignored, and the promoted wide cells run in the
default campaign.

Run: python3 -I tests/python/test_ignored_tests.py -v
"""

import json
import os
import re
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check-ignored-tests.py"
INVENTORY = ROOT / "tests" / "ignored-tests.json"
RUNNER = ROOT / "scripts" / "run-privileged-lib-tests.sh"
BTRFS_HELPER = ROOT / "scripts" / "ci" / "prepare-btrfs-tmpdir.sh"
CHECKER_MOD = runpy.run_path(str(CHECKER))

CELLS = {
    "privileged": "test cell",
    "live-kernel": "test cell",
    "feature": "test cell",
    "performance": "test cell",
    "helper": "test cell",
}

WIDE_OWNER = "wide-detailed-2112 runner"

# The 21 wide-only cells: curated tests that exist only in a
# wide-detailed-2112 binary (cfg wide, no FULL twin). A FULL-512 binary
# (--no-default-features, the journal flavor) must lack exactly these;
# the runner's WIDE_ONLY_TESTS pins them for --full-512 verification.
# Pinned literally so a runner edit that drops or renames one fails
# here, not silently; test_wide_only_matches_cfg_wide_sources pins the
# set against the cfg gates, so a gate change fails here too.
WIDE_ONLY_EXPECTED = [
    "attach::inventory::activation::privileged_tests::privileged_detailed_2112_stop_publishes_before_cleanup",
    "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n1024_lp64",
    "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n576_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_2112_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_highslot_2048_nonleader_exec",
    "attach::inventory::activation::privileged_tests::privileged_task4_highslot_2048_worker_exit",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n2048_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n2049_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n511_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n513_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_physical_identity_controls",
    "attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2048_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2049_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_inventory_n511_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_inventory_n512_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_inventory_n513_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_inventory_physical_identity_controls",
    "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n4097_lp64",
    "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6530_lp64",
    "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6531_lp64",
    "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n8192_boundary_lp64",
]

# The nine wide-Detailed cells, promoted to DEFAULT_TESTS since v0.7.0
# made 2,112 slots the default profile (the four wide-gated fns plus
# the five wide-gated detailed_sweep_test! expansions). Pinned
# literally so a runner edit that drops or renames one fails here, not
# silently. Kept for one release; remove with the --wide-detailed-2112
# no-op alias.
WIDE_EXPECTED = [
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_2112_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n511_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n512_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n513_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n2048_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n2049_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_highslot_2048_worker_exit",
    "attach::inventory::activation::privileged_tests::privileged_task4_highslot_2048_nonleader_exec",
    "attach::inventory::activation::privileged_tests::privileged_detailed_2112_stop_publishes_before_cleanup",
]


INTEGRATION_EXPECTED = [
    "tests/bpf_load_feasibility.rs:per_program_load_times",
    "tests/bpf_load_feasibility.rs:parallel_load_measures_kernel_overlap",
    "tests/bpf_load_feasibility.rs:parallel_load_partial_failure_retains_cleanup_owner",
    "tests/bpf_load_feasibility.rs:resident_service_cost_parts",
    "tests/entry_object_paired.rs:paired_default_and_unsafe_objects_satisfy_the_entry_contract",
    "tests/exec_task_continuity.rs:exec_task_core_shapes_kernel_load_without_attachment",
    "tests/identity_iter_standalone.rs:identity_loader_strict_gate_requires_btf_and_both_programs",
    "tests/inventory_identity.rs:d4_btrfs_scan_backends_match_exact_fixture_population",
    "tests/inventory_identity.rs:kernel_identity_positive_cell_rejects_refusal",
    "tests/object_producer_activation.rs:counter_bank_btf_maps_and_programs_load",
    "tests/run_abandon_report.rs:second_sigint_during_teardown_publishes_truthful_report_and_exits_130",
    "tests/prearm_witness_cli.rs:privileged_profile_pid_prearm_clean_exact_counts",
    "tests/prearm_witness_cli.rs:privileged_profile_cgroup_prearm_clean_exact_counts",
    "tests/prearm_witness_cli.rs:privileged_profile_system_prearm_clean_exact_counts",
    "tests/prearm_witness_cli.rs:privileged_profile_metrics_system_prearm_clean_exact_counts",
    "tests/prearm_witness_cli.rs:privileged_profile_pid_prearm_twin_exact_window",
    "tests/prearm_witness_cli.rs:privileged_trace_system_prearm_clean_exact_counts",
]

# The revived opt-in groups, pinned literally so a dropped or renamed
# member fails here, not silently.
BTRFS_EXPECTED = [
    "attach::instance_tests::privileged_instance_routing_on_btrfs_tmpdir",
    "discovery::sweep_attribution::tests::privileged_a_btrfs_collision_on_a_data_range_keeps_the_exec_proven_edge",
    "discovery::sweep_attribution::tests::privileged_a_file_swapped_behind_an_identical_line_is_proved_as_the_new_file",
    "discovery::sweep_attribution::tests::privileged_d4_btrfs_subvolume_collision_backend_parity",
    "discovery::sweep_attribution::tests::privileged_d4_btrfs_same_line_remap_backend_parity",
    "discovery::sweep_attribution::tests::privileged_d4_btrfs_deleted_mapping_backend_parity",
    "discovery::sweep_attribution::tests::privileged_d4_btrfs_hardlink_alias_backend_parity",
    "discovery::sweep_attribution::tests::privileged_d4_btrfs_bind_alias_backend_parity",
    "discovery::sweep_attribution::tests::privileged_d4_btrfs_live_thread_private_files_backend_parity",
    "discovery::sweep_attribution::tests::privileged_d4_btrfs_clone_without_files_backend_parity",
    "discovery::sweep_attribution::tests::privileged_d4_btrfs_zombie_leader_single_survivor_backend_parity",
    "discovery::sweep_attribution::tests::d4_zombie_cells::privileged_d4_btrfs_zombie_leader_collision_and_dataonly_twins",
    "discovery::sweep_attribution::tests::d4_zombie_cells::privileged_d4_btrfs_zombie_cold_admission_backend_parity",
    "discovery::sweep_attribution::tests::d4_population_cells::privileged_d4_kernel_positive_population_excludes_anchors",
    "discovery::sweep_attribution::tests::privileged_btrfs_equal_pin_twins_use_their_own_inspections",
    "discovery::sweep_attribution::tests::privileged_btrfs_snapshot_twins_do_not_merge",
    "discovery::unbound_exe::tests::privileged_btrfs_subvolume_collision_resolves_ambiguous",
]

# The two D3d forced-kernel cells fail their positive gate (observed on
# loop and physical btrfs alike) and wait for the owning file's
# stale-vs-product verdict, so they run as expected failures with the
# btrfs TMPDIR provisioned.
BTRFS_TMPDIR_XFAIL_EXPECTED = [
    "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64",
    "inventory::privileged_tests::privileged_identity_kernel_multipass_reuse_lp64",
]

XFAIL_EXPECTED = [
    "discovery::engine::tests::exit_loader_balanced_benign_transaction_needs_no_terminal_truncation",
    "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64",
    "inventory::privileged_tests::privileged_identity_kernel_multipass_reuse_lp64",
]

# The failure signatures and owners pinned beside each expected
# failure, index-aligned with XFAIL_EXPECTED. A signature is the fixed
# log string that proves the named failure (observed in a privileged
# run); the owner is the source file that owns the pin. Pinned
# literally so a weakened signature fails here, not silently.
XFAIL_SIGNATURE_EXPECTED = [
    "R57: balanced benign exit-time work needs a strong settlement receipt",
    "exactly one module for gate-k1.so",
    "exactly one module for gate-k2.so",
]

XFAIL_OWNER_EXPECTED = [
    "src/discovery/engine_tests.rs",
    "src/inventory/privileged_tests.rs",
    "src/inventory/privileged_tests.rs",
]

# Canned failing logs for the signature twins: real privileged-run
# excerpts per cell, plus refusal/fixture/provider-missing negatives
# that must match no signature.
XFAIL_EXCERPT_DIR = ROOT / "tests" / "fixtures" / "xfail-log-excerpts"
XFAIL_NEGATIVE_EXCERPTS = (
    "negative-ambient-refusal.log",
    "negative-backend-refusal.log",
    "negative-fixture-failure.log",
    "negative-missing-softhsm.log",
)

COUNTER_FIXTURE_EXPECTED = [
    "metrics::counter_reader::tests::counter_bank_session_old_return_survives_append_lp64",
    "metrics::counter_reader::tests::counter_bank_session_timing_old_return_survives_append_lp64",
    "metrics::counter_reader::tests::counter_bank_session_boundary_511_512_counts_growth_lp64",
    "metrics::counter_reader::tests::counter_bank_session_boundary_511_512_timestamps_growth_lp64",
    "metrics::counter_reader::tests::counter_bank_session_boundary_511_512_latency_growth_lp64",
    "metrics::counter_reader::tests::counter_bank_session_boundary_511_512_counts_growth_multi_lp64",
    "metrics::counter_reader::tests::counter_bank_session_useful_8192_counts_growth_lp64",
    "metrics::counter_reader::tests::counter_bank_session_useful_8192_counts_growth_multi_lp64",
    "metrics::counter_reader::tests::counter_bank_session_useful_8192_timestamps_growth_multi_lp64",
    "metrics::counter_reader::tests::counter_bank_session_useful_8192_latency_growth_multi_lp64",
    "metrics::counter_reader::tests::counter_engine_stages_first_512_counts_multi_lp64",
    "metrics::counter_reader::tests::counter_engine_growth_over_ceiling_refuses_atomically_lp64",
    "metrics::counter_reader::tests::counter_engine_growth_cgroup_counts_multi_lp64",
    "metrics::counter_reader::tests::counter_engine_growth_system_counts_multi_lp64",
    "metrics::counter_reader::tests::counter_engine_growth_timestamps_multi_lp64",
    "metrics::counter_reader::tests::counter_engine_growth_latency_multi_lp64",
    "metrics::counter_reader::tests::counter_start_raises_nofile_from_soft_1024_lp64",
    "metrics::counter_reader::tests::counter_start_without_raise_refuses_fd_exhausted_from_soft_1024_lp64",
    "metrics::counter_reader::tests::counter_collection_reads_live_and_terminal_lp64",
    "metrics::counter_reader::tests::counter_singles_stop_prints_detach_estimate_lp64",
    "metrics::counter_reader::tests::counter_multi_stop_prints_no_detach_estimate_lp64",
    "metrics::counter_reader::tests::counter_singles_stop_second_signal_abandons_lp64",
    "metrics::counter_reader::tests::counter_cli_profile_counts_matches_workload_ledger_lp64",
    "metrics::counter_reader::tests::counter_cli_profile_timestamps_matches_workload_ledger_lp64",
    "metrics::counter_reader::tests::counter_cli_profile_latency_matches_workload_ledger_lp64",
    "metrics::counter_reader::tests::selected_detail_cli_profile_counts_resolves_live_plan_and_conserves_aggregate_lp64",
    "metrics::counter_reader::tests::selected_detail_system_scope_refuses_live_plan_lp64",
]

# The DEFAULT_TESTS counter-reader members that need no runner-built
# fixture: the two map-reader cells plus the owned-child run cell (which
# needs CARGO_TARGET_TMPDIR instead). Any other counter-reader default
# member must join COUNTER_FIXTURE_TESTS.
COUNTER_READER_NOFIXTURE_EXPECTED = [
    "metrics::counter_reader::tests::counter_reader_native_maps_match_all_modes",
    "metrics::counter_reader::tests::counter_reader_requires_exact_maps_and_health",
    "metrics::counter_reader::tests::counter_cli_run_counts_with_owned_child_lp64",
]

# The LONG_TESTS diagnostics-wrap members that need the runner-built
# prebuilt32-object fixture (P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR).
# Every long wrap cell spawns through WrapWorkload, so any other long
# wrap member must join WRAP_FIXTURE_TESTS.
WRAP_FIXTURE_EXPECTED = [
    "inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_wrap_and_primary_parity_lp64",
    "inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_system_diagnostics_wrap_and_primary_parity_lp64",
    "inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_startup_probe_lp64",
    "inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_transition_pilot_lp64",
    "inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_accelerated_pilot_lp64",
    "inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_gate_cadence_probe_lp64",
    "inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_default_cadence_control_lp64",
]

INTEGRATION_SOURCES = {
    "tests/foo.rs": (
        '#[test]\n'
        '#[ignore = "needs the kernel lane"]\n'
        'fn t_live() {}\n'
    ),
}

INTEGRATION_ENTRY = {
    "file": "tests/foo.rs", "path": "t_live",
    "reason": "needs the kernel lane", "cell": "live-kernel",
}

# The src/ live-kernel cells and their campaign lists: the nonleader anchor
# stays a static skip, while the btrfs zombie parity cell runs in the
# btrfs group. Pinned literally so a dropped curation fails here.
SRC_LIVE_KERNEL_SKIP_EXPECTED = [
    "attach::identity_iter::tests::privileged_identity_nonleader_anchor_installs_nothing",
]

SRC_LIVE_KERNEL_BTRFS_EXPECTED = [
    "discovery::sweep_attribution::tests::d4_zombie_cells::privileged_d4_btrfs_zombie_leader_collision_and_dataonly_twins",
]

# The residual privileged cells: the installed linked control and the two
# B17 live twins run in the default campaign. Pinned literally so a
# dropped curation fails here.
RESIDUAL_DEFAULT_EXPECTED = [
    "attach::tests::sealed_session_drain_linkage_is_behavioral",
    "attach::instance_tests::privileged_instance_b17_counters_observe_sharer_churn",
    "attach::instance_tests::privileged_instance_b17_drain_yields_identity_once_live",
]

# The lane-B-only overlay campaign cells run with --include-overlay (the
# runner provisions nothing: each mounts its own loop overlays and
# fails loud off lane B): the K1 deep-scan twins plus the promoted
# copy-up no-re-edge positive. Pinned literally so a dropped curation
# fails here.
OVERLAY_EXPECTED = [
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_k1_deep_scan_fresh_upper_joins",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_k1_deep_scan_stale_lower_refuses",
    "discovery::sweep_attribution::tests::d4_overlay_cells::overlay_copy_up_userspace_edge_absent",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_lower_anchor_proves_stale_mapping",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_lower_anchor_refuses_fresh_mapping",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_stale_mapper_joins_proven_lower_file",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_metacopy_stale_mapper_joins_lower",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_second_lower_candidate_wins",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_upper_rewrite_keeps_stale_on_lower",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_candidate_opens_in_observer_namespace",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_witness_calibration_accepts_xino_overlay_files",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_witness_copyup_between_start_and_pin_refuses_proof",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_witness_pin_without_copyup_keeps_proof",
    "discovery::sweep_attribution::tests::d4_overlay_cells::privileged_witness_calibration_accepts_metacopy_upper",
]

# The R57 future positive: an unprivileged expected-RED cell that stays in
# the performance inventory cell but is curated as an expected failure so
# the runner's exact-cover check matches the binary and an unexpected
# pass gets noticed.
RESIDUAL_REDBYDESIGN_XFAIL_EXPECTED = (
    "discovery::engine::tests::exit_loader_balanced_benign_transaction_needs_no_terminal_truncation"
)

# The discover btrfs-subvolume twin: ignored (needs btrfs scratch) and
# curated for its privileged-btrfs cell. Pinned literally so a dropped
# or renamed curation fails here, not silently.
DISCOVER_BTRFS_SUBVOL_EXPECTED = [
    "crates/discover/tests/cli.rs:"
    "isolation_btrfs_subvolume_outside_the_output_is_denied",
]

DISCOVER_BTRFS_SUBVOL_OWNER = "discover-btrfs-subvol cell"


def write_fixture(root, sources, entries, registered, wide_registered=(),
                  integration_registered=(), counter_proof_registered=(),
                  counter_artifacts_registered=(),
                  discover_btrfs_subvol_registered=(), skip_registered=(),
                  manifest_version="0.5.0"):
    """A minimal checkable tree: sources {rel: text}, inventory, runner."""
    for rel, text in sources.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "Cargo.toml").write_text(
        f'[package]\nname = "fixture"\nversion = "{manifest_version}"\n',
        encoding="utf-8",
    )
    inv = root / "tests" / "ignored-tests.json"
    inv.parent.mkdir(parents=True, exist_ok=True)
    inv.write_text(
        json.dumps(
            {"schema": "p11scope/ignored-tests/v1",
             "cells": CELLS,
             "sites": entries},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    runner = root / "scripts" / "run-privileged-lib-tests.sh"
    runner.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        f"{name}=(\n"
        + "".join(f"{item}\n" for item in items)
        + "# end\n)\n"
        for name, items in (
            ("DEFAULT_TESTS", registered),
            ("ALTERNATIVE_TESTS", []),
            ("LONG_TESTS", []),
            ("BTRFS_TESTS", []),
            ("OVERLAY_TESTS", []),
            ("EXPECTED_FAILURE_TESTS", []),
            ("SKIP_TESTS", skip_registered),
            ("COUNTER_FIXTURE_TESTS", []),
            ("WRAP_FIXTURE_TESTS", []),
            ("BTRFS_TMPDIR_XFAIL_TESTS", []),
            ("WIDE_ONLY_TESTS", []),
            ("WIDE_DETAILED_2112_TESTS", wide_registered),
            ("INTEGRATION_TESTS", integration_registered),
            ("COUNTER_BANK_PROOF_TESTS", counter_proof_registered),
            ("COUNTER_ARTIFACTS_TESTS", counter_artifacts_registered),
            ("DISCOVER_BTRFS_SUBVOL_TESTS",
             discover_btrfs_subvol_registered),
        )
    )
    runner.write_text(body, encoding="utf-8")


def run_checker(root):
    return subprocess.run(
        [sys.executable, "-I", str(CHECKER), "--root", str(root)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


LIB_RS = "mod a;\nmod m;\n"

A_RS = """\
#[test]
fn t_plain() {}

#[test]
#[ignore = "privileged: needs the lane"]
fn t_priv() {}

#[test]
#[ignore]
fn t_timing() {}

// A prose mention of `#[ignore]` must not count as a site.
const NOTE: &str = "#[ignore = \\"in a string\\"]";
"""

M_RS = """\
macro_rules! sweep {
    ($name:ident) => {
        #[test]
        #[ignore = "privileged: sweep cell"]
        fn $name() {}
    };
}

sweep!(t_sweep);

#[cfg(feature = "wide")]
sweep!(t_wide);
"""

SOURCES = {"src/lib.rs": LIB_RS, "src/a.rs": A_RS, "src/m.rs": M_RS}

ENTRIES = [
    {"file": "src/a.rs", "path": "a::t_priv",
     "reason": "privileged: needs the lane", "cell": "privileged"},
    {"file": "src/a.rs", "path": "a::t_timing",
     "reason": "", "cell": "performance"},
    {"file": "src/m.rs", "path": "m::sweep!",
     "reason": "privileged: sweep cell", "cell": "privileged"},
]

REGISTERED = ["a::t_priv", "m::t_sweep"]

FEATURE_SOURCES = {
    "src/lib.rs": "mod f;\n",
    "src/f.rs": (
        '#[test]\n'
        '#[ignore = "needs feature x"]\n'
        'fn t_feat() {}\n'
    ),
}

FEATURE_ENTRY = {
    "file": "src/f.rs", "path": "f::t_feat",
    "reason": "needs feature x", "cell": "feature",
}

LIVE_KERNEL_SOURCES = {
    "src/lib.rs": "mod k;\n",
    "src/k.rs": (
        '#[test]\n'
        '#[ignore = "needs the hand-run lane"]\n'
        'fn t_live_kernel() {}\n'
    ),
}

LIVE_KERNEL_ENTRY = {
    "file": "src/k.rs", "path": "k::t_live_kernel",
    "reason": "needs the hand-run lane", "cell": "live-kernel",
}


def write_fake_binary(path, ignored):
    """An executable stub answering `--list --ignored` with canned tests."""
    lines = "".join(f"echo '{name}: test'\n" for name in ignored)
    path.write_text("#!/bin/sh\n" + lines, encoding="utf-8")
    path.chmod(0o755)


def write_fake_integration_binary(depsdir, stem, ignored):
    """A fake built integration binary: deps/<stem>-<hash>, executable."""
    path = depsdir / f"{stem}-0123456789abcdef"
    write_fake_binary(path, ignored)
    return path


def run_runner(*args):
    return subprocess.run(
        [str(RUNNER), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def unquote_shell(line):
    """Strip one pair of double quotes from a runner array entry."""
    if len(line) >= 2 and line.startswith('"') and line.endswith('"'):
        return line[1:-1]
    return line


def xfail_log_matches(signature, log_path):
    """The runner's own signature gate over a canned log.

    Sources the runner with --help (the same trick the branch tests
    use, so the trailing main call only prints usage) and asks
    xfail_log_matches; argv carries the signature, so no quoting can
    corrupt it.
    """
    result = subprocess.run(
        ["bash", "-c",
         'source "$0" --help >/dev/null 2>&1; xfail_log_matches "$1" "$2"',
         str(RUNNER), signature, str(log_path)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return result.returncode == 0


def run_btrfs_helper(helper, *args, path_prefix=(), env=None):
    """Run the btrfs TMPDIR helper with optional PATH stub overrides."""
    run_env = dict(env) if env else {}
    if path_prefix:
        run_env["PATH"] = (os.pathsep.join(str(p) for p in path_prefix)
                           + os.pathsep + os.environ["PATH"])
    merged = {**os.environ, **run_env} if run_env else None
    return subprocess.run(
        [str(helper), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=merged,
    )


def write_path_stub(bin_dir, name, body):
    """An executable PATH stub (mountpoint/umount stand-ins)."""
    path = Path(bin_dir) / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


def runner_array_lines(path, name):
    """Ordered entries of one `NAME=(...)` shell array, comments stripped.

    Quoted reason lines are kept whole (a `#` inside quotes is data);
    test lines strip `#` comments. Empty lines contribute nothing.
    """
    text = Path(path).read_text(encoding="utf-8")
    head = f"{name}=(\n"
    start = text.index(head) + len(head)
    end = text.index("\n)", start)
    lines = []
    for line in text[start:end].splitlines():
        stripped = line.strip()
        if stripped.startswith('"'):
            lines.append(stripped)
        else:
            entry = line.split("#")[0].strip()
            if entry:
                lines.append(entry.split()[0])
    return lines


class IgnoredTestsTests(unittest.TestCase):
    def test_private_image_proof_cells_require_the_explicit_full_build(self):
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        entries = json.loads(INVENTORY.read_text())["sites"]
        proof = {entry["path"] for entry in entries if entry["path"].startswith(prefix)}
        self.assertEqual(len(proof), 14)
        self.assertEqual(sum(entry["cell"] == "privileged" for entry in entries
                             if entry["path"] in proof), 13)
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        self.assertTrue(proof <= lists["SKIP_TESTS"])
        for group in ("DEFAULT_TESTS", "ALTERNATIVE_TESTS", "LONG_TESTS",
                      "BTRFS_TESTS", "OVERLAY_TESTS",
                      "EXPECTED_FAILURE_TESTS"):
            self.assertFalse(proof & lists[group])
        reasons = dict(zip(runner_array_lines(RUNNER, "SKIP_TESTS"),
                           runner_array_lines(RUNNER, "SKIP_REASONS")))
        for name in proof:
            for prerequisite in ("FULL", "P11SCOPE_IMAGE_BANK_PROOF=1", "--exact",
                                 "--ignored", "root", "BPF lane"):
                self.assertIn(prerequisite, reasons[name], name)
        overhead = reasons[prefix + "per_call_overhead"]
        for prerequisite in ("quiet exclusive host", "prior E3 acceptance",
                             "P11_BANK_N5_PRODUCTION_NS_1", "P11_BANK_N5_PRODUCTION_NS_4"):
            self.assertIn(prerequisite, overhead)

    def test_private_image_proof_list_covers_all_fourteen_without_execution(self):
        # Real runner + fake libtest boundary: the old 13/14 curation failed
        # --list only on N5. Never execute a proof or performance cell here.
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        proof = {entry["path"] for entry in json.loads(INVENTORY.read_text())["sites"]
                 if entry["path"].startswith(prefix)}
        self.assertEqual(len(proof), 14)
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        full = set().union(*(lists[group] for group in
                            ("DEFAULT_TESTS", "ALTERNATIVE_TESTS",
                             "LONG_TESTS", "BTRFS_TESTS",
                             "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS",
                             "SKIP_TESTS"))) | proof
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / "libtest-proof"
            # A run-shaped invocation fails; only the literal list request
            # may print the fixture's actual fourteen proof paths.
            write_fake_binary(binary, sorted(full))
            binary.write_text(binary.read_text().replace(
                "#!/bin/sh\n", "#!/bin/sh\n[ \"$*\" = '--list --ignored --format terse' ] || exit 97\n", 1))
            result = run_runner("--list", str(binary))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in proof:
                self.assertIn(name + " :: ", result.stdout)
            self.assertIn("verify: curation matches the binary", result.stdout)
            # Retain the old failing shape as a causal negative. Drop N5 and
            # its matching reason together so this tests membership, not a
            # generic reason-array length mismatch.
            text = RUNNER.read_text()
            names = runner_array_lines(RUNNER, "SKIP_TESTS")
            reasons = runner_array_lines(RUNNER, "SKIP_REASONS")
            overhead = prefix + "per_call_overhead"
            reason = reasons[names.index(overhead)]
            old = text.replace(overhead + "\n", "", 1).replace(reason + "\n", "", 1)
            runner = Path(raw) / "runner-thirteen.sh"
            runner.write_text(old)
            runner.chmod(0o755)
            negative = subprocess.run([str(runner), "--list", str(binary)], cwd=ROOT,
                                      capture_output=True, text=True)
        self.assertEqual(negative.returncode, 1, negative.stdout + negative.stderr)
        self.assertIn("ignored in the binary but not curated", negative.stderr)
        self.assertIn(overhead, negative.stderr)

    def test_private_image_proof_list_keeps_ordinary_builds_usable(self):
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        proof = {entry["path"] for entry in json.loads(INVENTORY.read_text())["sites"]
                 if entry["path"].startswith(prefix)}
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        full = set().union(*(lists[group] for group in
                            ("DEFAULT_TESTS", "ALTERNATIVE_TESTS",
                             "LONG_TESTS", "BTRFS_TESTS",
                             "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS",
                             "SKIP_TESTS")))
        ordinary = full - proof
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / "libtest-ordinary"
            write_fake_binary(binary, sorted(ordinary))
            result = run_runner("--list", str(binary))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("private image-bank proof group not built (0/14 present; no proof positive)",
                          result.stdout)
            self.assertIn(f"verify: curation matches the binary ({len(ordinary)} tests)", result.stdout)
            # A partially compiled proof never inherits the ordinary-build
            # exception: N5 is missing from this 13/14 binary listing.
            write_fake_binary(binary, sorted(full - {prefix + "per_call_overhead"}))
            partial = run_runner("--list", str(binary))
        self.assertEqual(partial.returncode, 1, partial.stderr)
        self.assertIn("curated but absent from the binary", partial.stderr)
        self.assertIn(prefix + "per_call_overhead", partial.stderr)

    def test_private_image_proof_list_refuses_renamed_or_unknown_members(self):
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        full = set().union(*(lists[group] for group in
                            ("DEFAULT_TESTS", "ALTERNATIVE_TESTS",
                             "LONG_TESTS", "BTRFS_TESTS",
                             "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS",
                             "SKIP_TESTS")))
        unknown = prefix + "unknown_cell"
        renamed = prefix + "verifier_stats_renamed"
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / "libtest-proof-drift"
            for names, unexpected in ((full | {unknown}, unknown),
                                      ((full - {prefix + "verifier_stats"}) | {renamed}, renamed)):
                with self.subTest(unexpected=unexpected):
                    write_fake_binary(binary, sorted(names))
                    result = run_runner("--list", str(binary))
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("ignored in the binary but not curated", result.stderr)
                    self.assertIn(unexpected, result.stderr)
                    self.assertNotIn("verify: curation matches", result.stdout)
                    self.assertNotIn("proof group not built", result.stdout)

    def test_marker_cells_run_and_keep_core_instance_cells(self):
        prefix = "attach::instance_tests::privileged_journal_marker_"
        cells = {prefix + name for name in (
            "abandoned_call_at_thread_exit_dirties",
            "cgroup_gap_sticks_across_reentry_and_exec",
            "cgroup_outsider_call_creates_dirty_row",
            "dirty_nonleader_exec_publishes_fresh_ready",
            "exec_after_closure_publishes_ready",
            "fork_without_exec_has_no_ready",
            "nonleader_exec_creates_fresh_ready_row",
            "ordinary_capture_mints_no_birth",
            "pid_outsider_stays_unobserved",
            "pid_reuse_exec_creates_no_row",
            "return_outside_scope_dirties",
        )}
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        self.assertEqual({name for name in lists["DEFAULT_TESTS"] if name.startswith(prefix)},
                         cells)
        self.assertFalse(cells & lists["SKIP_TESTS"])
        for name in ("exec_renews_the_instance", "fork_without_exec_stays_consistent",
                     "nonleader_exec_detaches_without_misrouting"):
            self.assertIn("attach::instance_tests::privileged_instance_" + name,
                          lists["DEFAULT_TESTS"])
        entries = json.loads(INVENTORY.read_text())["sites"]
        reasons = {entry["path"]: entry["reason"] for entry in entries
                   if entry["path"] in cells}
        self.assertEqual(set(reasons), cells)
        self.assertTrue(all(reason.startswith("privileged: birth marker ")
                            for reason in reasons.values()))

    def test_checked_in_inventory_matches_the_sources(self):
        result = run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        inventoried = len(json.loads(INVENTORY.read_text(encoding="utf-8"))
                           ["sites"])
        self.assertIn(f"all {inventoried} inventoried site(s) match",
                      result.stdout)
        self.assertIn("privileged, feature-owner and integration "
                      "curation verified", result.stdout)

    def test_count_manifest_cache_helper_is_only_run_by_its_parent(self):
        name = ("discovery::identity::tests::"
                "count_manifest_actual_full_copy_and_tail_fit_the_cached_read_allowance")
        parent = "count_manifest_full_and_tail_share_the_scan_inspection_cache"
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        self.assertIn(name, lists["SKIP_TESTS"])
        for group in ("DEFAULT_TESTS", "ALTERNATIVE_TESTS", "LONG_TESTS",
                      "BTRFS_TESTS", "OVERLAY_TESTS",
                      "EXPECTED_FAILURE_TESTS"):
            self.assertNotIn(name, lists[group])
        names = runner_array_lines(RUNNER, "SKIP_TESTS")
        reason = runner_array_lines(RUNNER, "SKIP_REASONS")[names.index(name)]
        self.assertIn(parent, reason)
        for variable in ("P11SCOPE_COUNT_MANIFEST_FULL", "P11SCOPE_COUNT_MANIFEST_TAIL"):
            self.assertIn(variable, reason)
        entries = json.loads(INVENTORY.read_text())["sites"]
        entry = next(entry for entry in entries if entry["path"] == name)
        self.assertEqual(entry["cell"], "helper")
        self.assertIn(parent, entry["reason"])
        source = (ROOT / "src/discovery/inventory_coordinator.rs").read_text()
        self.assertIn("fn " + parent + "()", source)
        self.assertIn('.args(["' + name + '", "--exact", "--ignored", "--nocapture"])', source)
        for variable in ("P11SCOPE_COUNT_MANIFEST_FULL", "P11SCOPE_COUNT_MANIFEST_TAIL"):
            self.assertIn('.env("' + variable + '",', source)

    def test_an_extra_ignored_test_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = dict(SOURCES)
            sources["src/a.rs"] += (
                '\n#[test]\n#[ignore = "privileged: sneaked in"]\n'
                "fn t_new() {}\n"
            )
            write_fixture(root, sources, ENTRIES, REGISTERED, ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("a::t_new has no inventory entry", result.stdout)

    def test_a_removed_inventory_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES[1:], REGISTERED,
                          ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("a::t_priv has no inventory entry", result.stdout)

    def test_an_inventory_entry_without_a_site_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entries = list(ENTRIES) + [
                {"file": "src/a.rs", "path": "a::t_gone",
                 "reason": "privileged: removed", "cell": "privileged"},
            ]
            write_fixture(root, SOURCES, entries, REGISTERED, ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("no matching #[ignore] site for src/a.rs a::t_gone",
                      result.stdout)

    def test_an_unregistered_privileged_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, ["m::t_sweep"],
                          ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("privileged a::t_priv is not curated", result.stdout)

    def test_privileged_marked_reason_in_a_curation_free_cell_fails(self):
        # A `privileged:`/`root:` #[ignore] reason filed as performance or
        # helper hides a privileged test from runner curation: the checker
        # must refuse it, naming the marker and the test. Leading
        # whitespace before the marker must not hide it.
        for marker in ("privileged: needs root", "root: needs mounts",
                       " privileged: needs root"):
            for cell in ("performance", "helper"):
                with self.subTest(marker=marker, cell=cell):
                    sources = {
                        "src/lib.rs": "mod a;\n",
                        "src/a.rs": (
                            "#[test]\n"
                            f'#[ignore = "{marker}"]\n'
                            "fn t_marked() {}\n"
                        ),
                    }
                    entries = [
                        {"file": "src/a.rs", "path": "a::t_marked",
                         "reason": marker, "cell": cell},
                    ]
                    with tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        write_fixture(root, sources, entries, [])
                        result = run_checker(root)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("a::t_marked", result.stdout)
                    self.assertIn("privileged", result.stdout)

    def test_privileged_marked_reason_passes_in_the_privileged_cell(self):
        # The same marker filed as privileged is the honest shape: curation
        # (not the marker) decides, so a curated entry passes.
        sources = {
            "src/lib.rs": "mod a;\n",
            "src/a.rs": (
                "#[test]\n"
                '#[ignore = "privileged: needs root"]\n'
                "fn t_marked() {}\n"
            ),
        }
        entries = [
            {"file": "src/a.rs", "path": "a::t_marked",
             "reason": "privileged: needs root", "cell": "privileged"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, sources, entries, ["a::t_marked"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_comment_and_string_mentions_are_not_sites(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, REGISTERED, ["m::t_wide"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 3 inventoried site(s) match", result.stdout)

    def test_macro_expansions_must_be_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, ["a::t_priv"],
                          ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("expands to m::t_sweep, not curated", result.stdout)

    def test_feature_gated_expansions_require_wide_curation(self):
        # m::t_wide is gated on cargo feature "wide": exempt from the
        # default lists, but it must be curated in WIDE_DETAILED_2112_TESTS.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, REGISTERED, [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("m::t_wide", result.stdout)
        self.assertIn("WIDE_DETAILED_2112_TESTS", result.stdout)

    def test_wide_list_member_without_a_wide_site_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, {"src/lib.rs": ""}, [], [],
                          ["f::t_nope"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_nope", result.stdout)
        self.assertIn("WIDE_DETAILED_2112_TESTS", result.stdout)

    def test_wide_member_from_non_privileged_expansion_fails(self):
        # Only a privileged macro entry owns the wide campaign: a
        # feature-gated expansion of a performance-gated macro must not
        # satisfy a WIDE list member.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = {"src/lib.rs": "mod m;\n", "src/m.rs": M_RS}
            entries = [
                {"file": "src/m.rs", "path": "m::sweep!",
                 "reason": "performance: sweep cell",
                 "cell": "performance"},
            ]
            write_fixture(root, sources, entries, [], ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("m::t_wide", result.stdout)
        self.assertIn("not a wide-owned inventory site or a "
                      "feature-gated expansion", result.stdout)

    def test_feature_entry_without_owner_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, FEATURE_SOURCES, [FEATURE_ENTRY], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("owner", result.stdout)

    def test_feature_entry_with_empty_owner_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="")
            write_fixture(root, FEATURE_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("owner", result.stdout)

    def test_feature_entry_with_whitespace_owner_fails(self):
        # A whitespace-only owner is refused as blank (not merely as
        # unknown): pinning the message kills a strip() regression even
        # though the closed owner set would also reject it.
        for owner in ("   ", "\t\n"):
            with self.subTest(owner=owner):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    entry = dict(FEATURE_ENTRY, owner=owner)
                    write_fixture(root, FEATURE_SOURCES, [entry], [])
                    result = run_checker(root)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("non-empty owner", result.stdout)

    def test_counter_bank_proof_entry_must_be_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="counter-bank-proof build")
            write_fixture(root, FEATURE_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_feat", result.stdout)
        self.assertIn("COUNTER_BANK_PROOF_TESTS", result.stdout)

    def test_counter_bank_proof_entry_passes_when_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="counter-bank-proof build")
            write_fixture(root, FEATURE_SOURCES, [entry], [],
                          counter_proof_registered=["src/f.rs:f::t_feat"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_counter_bank_proof_member_without_an_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, {"src/lib.rs": ""}, [], [],
                          counter_proof_registered=["src/f.rs:f::t_nope"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_nope", result.stdout)
        self.assertIn("COUNTER_BANK_PROOF_TESTS", result.stdout)

    def test_counter_artifacts_entry_must_be_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="counter-artifacts build")
            write_fixture(root, FEATURE_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_feat", result.stdout)
        self.assertIn("COUNTER_ARTIFACTS_TESTS", result.stdout)

    def test_counter_artifacts_entry_passes_when_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="counter-artifacts build")
            write_fixture(root, FEATURE_SOURCES, [entry], [],
                          counter_artifacts_registered=["src/f.rs:f::t_feat"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_counter_artifacts_member_without_an_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, {"src/lib.rs": ""}, [], [],
                          counter_artifacts_registered=["src/f.rs:f::t_nope"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_nope", result.stdout)
        self.assertIn("COUNTER_ARTIFACTS_TESTS", result.stdout)

    def test_feature_entry_with_unknown_owner_fails(self):
        # A typo'd owner ("wide-detailed-2112" without " runner") must
        # fail closed instead of silently exempting the test from
        # wide curation.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="wide-detailed-2112")
            write_fixture(root, FEATURE_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("unknown owner", result.stdout)
        self.assertIn("wide-detailed-2112", result.stdout)

    def test_wide_owned_feature_entry_must_be_wide_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner=WIDE_OWNER)
            write_fixture(root, FEATURE_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_feat", result.stdout)
        self.assertIn("WIDE_DETAILED_2112_TESTS", result.stdout)

    def test_wide_owned_feature_entry_passes_when_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner=WIDE_OWNER)
            write_fixture(root, FEATURE_SOURCES, [entry], [], ["f::t_feat"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_src_live_kernel_entry_must_be_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, LIVE_KERNEL_SOURCES, [LIVE_KERNEL_ENTRY],
                          [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("k::t_live_kernel", result.stdout)
        self.assertIn("not curated", result.stdout)

    def test_src_live_kernel_entry_passes_when_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, LIVE_KERNEL_SOURCES, [LIVE_KERNEL_ENTRY],
                          ["k::t_live_kernel"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_src_live_kernel_cells_are_skip_curated(self):
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        for name in SRC_LIVE_KERNEL_SKIP_EXPECTED:
            with self.subTest(name=name):
                self.assertIn(name, lists["SKIP_TESTS"])
        for name in SRC_LIVE_KERNEL_BTRFS_EXPECTED:
            with self.subTest(name=name):
                self.assertIn(name, lists["BTRFS_TESTS"])
                self.assertNotIn(name, lists["SKIP_TESTS"])

    def test_residual_privileged_cells_are_curated_in_their_campaign_lists(self):
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        runnable = (lists["DEFAULT_TESTS"] | lists["ALTERNATIVE_TESTS"]
                    | lists["LONG_TESTS"])
        for name in RESIDUAL_DEFAULT_EXPECTED:
            with self.subTest(name=name):
                self.assertIn(name, lists["DEFAULT_TESTS"])
                self.assertNotIn(name, lists["SKIP_TESTS"])
        for name in OVERLAY_EXPECTED:
            with self.subTest(name=name):
                self.assertIn(name, lists["OVERLAY_TESTS"])
                self.assertFalse({name} & runnable)
                self.assertNotIn(name, lists["SKIP_TESTS"])
                self.assertNotIn(name, lists["DEFAULT_TESTS"])
        xfail_names = runner_array_lines(RUNNER, "EXPECTED_FAILURE_TESTS")
        xfail_reasons = runner_array_lines(RUNNER, "XFAIL_REASONS")
        with self.subTest(name=RESIDUAL_REDBYDESIGN_XFAIL_EXPECTED):
            self.assertIn(RESIDUAL_REDBYDESIGN_XFAIL_EXPECTED,
                          lists["EXPECTED_FAILURE_TESTS"])
            self.assertFalse({RESIDUAL_REDBYDESIGN_XFAIL_EXPECTED} & runnable)
            self.assertNotIn(RESIDUAL_REDBYDESIGN_XFAIL_EXPECTED,
                             lists["SKIP_TESTS"])
            reason = xfail_reasons[
                xfail_names.index(RESIDUAL_REDBYDESIGN_XFAIL_EXPECTED)]
            self.assertIn("expected failure", reason)
            self.assertIn("R57", reason)

    def test_residual_inventory_cells_match_what_each_test_needs(self):
        entries = {entry["path"]: entry
                   for entry in json.loads(INVENTORY.read_text())["sites"]}
        for name in RESIDUAL_DEFAULT_EXPECTED + OVERLAY_EXPECTED:
            with self.subTest(name=name):
                self.assertEqual(entries[name]["cell"], "privileged")
        for name in OVERLAY_EXPECTED:
            with self.subTest(name=name):
                self.assertIn("--include-overlay", entries[name]["reason"])
        self.assertEqual(entries[RESIDUAL_REDBYDESIGN_XFAIL_EXPECTED]["cell"],
                         "performance")

    def test_discover_btrfs_subvol_cell_is_curated(self):
        # The ignored discover cli twin stays tracked: the runner list
        # holds exactly the pinned selector, and the inventory files it
        # under the cell's feature owner (never the lib campaign lists,
        # whose binaries do not contain it).
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        self.assertEqual(set(lists["DISCOVER_BTRFS_SUBVOL_TESTS"]),
                         set(DISCOVER_BTRFS_SUBVOL_EXPECTED))
        entries = {entry["path"]: entry
                   for entry in json.loads(INVENTORY.read_text())["sites"]}
        entry = entries[
            "isolation_btrfs_subvolume_outside_the_output_is_denied"]
        self.assertEqual(entry["file"], "crates/discover/tests/cli.rs")
        self.assertEqual(entry["cell"], "feature")
        self.assertEqual(entry["owner"], DISCOVER_BTRFS_SUBVOL_OWNER)
        self.assertIn("btrfs", entry["reason"])
        for name in ("DEFAULT_TESTS", "ALTERNATIVE_TESTS", "LONG_TESTS",
                     "BTRFS_TESTS", "OVERLAY_TESTS",
                     "EXPECTED_FAILURE_TESTS", "SKIP_TESTS"):
            self.assertNotIn(
                "isolation_btrfs_subvolume_outside_the_output_is_denied",
                lists[name], name)

    def test_skip_reasons_align_with_skip_tests(self):
        tests = runner_array_lines(RUNNER, "SKIP_TESTS")
        reasons = runner_array_lines(RUNNER, "SKIP_REASONS")
        self.assertEqual(
            len(tests), len(reasons),
            f"SKIP_TESTS={len(tests)} SKIP_REASONS={len(reasons)}",
        )
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        for name in [
            "metrics::counter_reader::tests::"
            "counter_cli_profile_counts_matches_workload_ledger_lp64",
            "metrics::counter_reader::tests::"
            "counter_cli_profile_timestamps_matches_workload_ledger_lp64",
            "metrics::counter_reader::tests::"
            "counter_cli_profile_latency_matches_workload_ledger_lp64",
            "metrics::counter_reader::tests::"
            "counter_cli_run_counts_with_owned_child_lp64",
        ]:
            with self.subTest(name=name):
                self.assertIn(name, lists["DEFAULT_TESTS"])
                self.assertNotIn(name, tests)

    def test_xfail_reasons_align_with_expected_failure_tests(self):
        tests = runner_array_lines(RUNNER, "EXPECTED_FAILURE_TESTS")
        reasons = runner_array_lines(RUNNER, "XFAIL_REASONS")
        self.assertEqual(
            len(tests), len(reasons),
            f"EXPECTED_FAILURE_TESTS={len(tests)} "
            f"XFAIL_REASONS={len(reasons)}",
        )
        for name, reason in zip(tests, reasons):
            with self.subTest(name=name):
                self.assertIn("expected failure", reason.lower())

    def test_xfail_signatures_and_owners_are_pinned(self):
        # Ordered equality pins alignment as well as content: a
        # dropped, reordered or weakened signature fails here. Every
        # owner names the source file that owns the pin.
        tests = runner_array_lines(RUNNER, "EXPECTED_FAILURE_TESTS")
        signatures = [unquote_shell(line) for line in
                      runner_array_lines(RUNNER, "XFAIL_SIGNATURES")]
        owners = [unquote_shell(line) for line in
                  runner_array_lines(RUNNER, "XFAIL_OWNERS")]
        self.assertEqual(tests, XFAIL_EXPECTED)
        self.assertEqual(signatures, XFAIL_SIGNATURE_EXPECTED)
        self.assertEqual(owners, XFAIL_OWNER_EXPECTED)
        for name, signature, owner in zip(tests, signatures, owners):
            with self.subTest(name=name):
                self.assertTrue(signature, "empty signature is vacuous")
                self.assertTrue((ROOT / owner).is_file(),
                                f"owner is not a file: {owner}")

    def test_xfail_signatures_match_only_their_own_failure_excerpt(self):
        # The named failure gives XFAIL: each signature matches its
        # cell's real failing excerpt through the runner's own gate.
        # The cross-matrix proves discrimination: no signature matches
        # another cell's failure.
        excerpts = {}
        for name in XFAIL_EXPECTED:
            path = (XFAIL_EXCERPT_DIR
                    / (name.rsplit("::", 1)[-1] + ".log"))
            self.assertTrue(path.is_file(), f"missing excerpt: {path}")
            excerpts[name] = path
        for name, signature in zip(XFAIL_EXPECTED,
                                   XFAIL_SIGNATURE_EXPECTED):
            with self.subTest(name=name, excerpt="own"):
                self.assertTrue(xfail_log_matches(signature,
                                                  excerpts[name]),
                                f"{signature!r} matches no real failure")
            for other in XFAIL_EXPECTED:
                if other == name:
                    continue
                with self.subTest(name=name,
                                   excerpt=other.rsplit("::", 1)[-1]):
                    self.assertFalse(
                        xfail_log_matches(signature, excerpts[other]),
                        f"{signature!r} also matches {other}")

    def test_xfail_signatures_match_no_refusal_or_fixture_failure(self):
        # A different failure gives FAIL, never XFAIL: backend and
        # ambient refusals, a fixture failure and a missing provider
        # match no signature through the runner's own gate.
        for excerpt in XFAIL_NEGATIVE_EXCERPTS:
            path = XFAIL_EXCERPT_DIR / excerpt
            self.assertTrue(path.is_file(), f"missing excerpt: {path}")
            for name, signature in zip(XFAIL_EXPECTED,
                                       XFAIL_SIGNATURE_EXPECTED):
                with self.subTest(excerpt=excerpt, name=name):
                    self.assertFalse(
                        xfail_log_matches(signature, path),
                        f"{signature!r} matches {excerpt}")

    def test_xfail_gate_rejects_an_empty_signature(self):
        # `grep -F ''` matches every line, so the gate refuses an
        # empty signature outright instead of XFAILing everything.
        excerpt = (XFAIL_EXCERPT_DIR
                   / "exit_loader_balanced_benign_transaction_needs_no_terminal_truncation.log")
        self.assertFalse(xfail_log_matches("", excerpt))

    def test_xfail_excerpts_contain_no_home_or_worktree_paths(self):
        # Canned logs are ground truth for the next editor: a baked-in
        # author path (/home/..., .worktrees/...) would be mistaken for
        # real content. TMPDIR-scoped /var/tmp names are the runner's
        # conventional temp location, not an author path.
        logs = sorted(XFAIL_EXCERPT_DIR.glob("*.log"))
        self.assertGreater(len(logs), 0, "no excerpts to check")
        for path in logs:
            text = path.read_text(encoding="utf-8")
            for marker in ("/home/", "/root/", ".worktrees/"):
                with self.subTest(excerpt=path.name, marker=marker):
                    self.assertNotIn(marker, text)

    def test_xfail_known_limit_citations_resolve_in_tree(self):
        # A reason that cites a known limit must name the in-tree file
        # that carries it, so the citation can be checked; a bare
        # "(doc Known limit ...)" with no path is dangling.
        reasons = runner_array_lines(RUNNER, "XFAIL_REASONS")
        cited = [reason for reason in reasons
                 if "Known limit" in reason]
        # No reason cites a limit today (the pressure cells were
        # promoted); the loop still guards every future citation.
        for reason in cited:
            with self.subTest(reason=reason[:60]):
                match = re.search(
                    r"\b((?:src|docs|tests|scripts)/"
                    r"[A-Za-z0-9_./-]+\.(?:rs|md|sh|py))",
                    reason)
                self.assertIsNotNone(
                    match, f"citation names no in-tree path: {reason}")
                target = ROOT / match.group(1)
                self.assertTrue(target.is_file(),
                                f"citation target missing: {target}")
                self.assertIn(
                    "Known limit", target.read_text(encoding="utf-8"),
                    f"citation target carries no limit: {target}")

    def test_runner_list_refuses_skip_misalignment(self):
        text = RUNNER.read_text(encoding="utf-8")
        match = re.search(r"^SKIP_REASONS=\(\n(.*?)\n\)", text, re.M | re.S)
        self.assertIsNotNone(match, "real runner has no SKIP_REASONS list")
        lines = match.group(1).splitlines()
        dropped = "\n".join(
            line for line in lines
            if not line.strip().startswith('"needs a P11SCOPE_SMALL_STATE_MAPS=1'))
        self.assertLess(len(dropped.splitlines()), len(lines),
                        "fixture must drop one reason")
        broken = text[:match.start(1)] + dropped + text[match.end(1):]
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp) / "run-privileged-lib-tests.sh"
            runner.write_text(broken, encoding="utf-8")
            runner.chmod(0o755)
            binary = Path(tmp) / "libtest-empty"
            write_fake_binary(binary, [])
            result = subprocess.run(
                [str(runner), "--list", str(binary)],
                capture_output=True, text=True, cwd=ROOT,
            )
        self.assertNotEqual(
            result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("differ in length", result.stderr)
        self.assertIn("SKIP_TESTS", result.stderr)

    def test_runner_list_refuses_xfail_misalignment(self):
        text = RUNNER.read_text(encoding="utf-8")
        match = re.search(r"^XFAIL_REASONS=\(\n(.*?)\n\)", text, re.M | re.S)
        self.assertIsNotNone(match, "real runner has no XFAIL_REASONS list")
        lines = match.group(1).splitlines()
        dropped = "\n".join(
            line for line in lines if "R57 future positive" not in line)
        self.assertLess(len(dropped.splitlines()), len(lines),
                        "fixture must drop one reason")
        broken = text[:match.start(1)] + dropped + text[match.end(1):]
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp) / "run-privileged-lib-tests.sh"
            runner.write_text(broken, encoding="utf-8")
            runner.chmod(0o755)
            binary = Path(tmp) / "libtest-empty"
            write_fake_binary(binary, [])
            result = subprocess.run(
                [str(runner), "--list", str(binary)],
                capture_output=True, text=True, cwd=ROOT,
            )
        self.assertNotEqual(
            result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("differ in length", result.stderr)
        self.assertIn("EXPECTED_FAILURE_TESTS", result.stderr)

    def test_runner_list_refuses_xfail_signature_misalignment(self):
        text = RUNNER.read_text(encoding="utf-8")
        match = re.search(r"^XFAIL_SIGNATURES=\(\n(.*?)\n\)", text, re.M | re.S)
        self.assertIsNotNone(match, "real runner has no XFAIL_SIGNATURES list")
        lines = match.group(1).splitlines()
        dropped = "\n".join(
            line for line in lines if "R57: balanced benign" not in line)
        self.assertLess(len(dropped.splitlines()), len(lines),
                        "fixture must drop one signature")
        broken = text[:match.start(1)] + dropped + text[match.end(1):]
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp) / "run-privileged-lib-tests.sh"
            runner.write_text(broken, encoding="utf-8")
            runner.chmod(0o755)
            binary = Path(tmp) / "libtest-empty"
            write_fake_binary(binary, [])
            result = subprocess.run(
                [str(runner), "--list", str(binary)],
                capture_output=True, text=True, cwd=ROOT,
            )
        self.assertNotEqual(
            result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("differ in length", result.stderr)
        self.assertIn("EXPECTED_FAILURE_TESTS", result.stderr)

    def test_btrfs_teardown_refuses_an_unmarked_mount(self):
        # Mounted but not this tool's: with mountpoint stubbed to
        # report mounted and no marker present, teardown refuses
        # before unmounting (the stub records any call) and removes
        # nothing.
        with tempfile.TemporaryDirectory() as tmp:
            mnt = Path(tmp) / "mnt"
            mnt.mkdir()
            sentinel = mnt / "sentinel.txt"
            sentinel.write_text("data", encoding="utf-8")
            img = Path(tmp) / "imgfile"
            img.write_text("image", encoding="utf-8")
            calls = Path(tmp) / "umount-calls"
            bindir = Path(tmp) / "bin"
            bindir.mkdir()
            write_path_stub(bindir, "mountpoint", "exit 0\n")
            write_path_stub(bindir, "umount", f'echo called >>"{calls}"\n')
            result = run_btrfs_helper(
                BTRFS_HELPER, "--teardown", str(img), str(mnt),
                path_prefix=[bindir])
            self.assertEqual(result.returncode, 1,
                             result.stdout + result.stderr)
            self.assertIn("refusing teardown", result.stderr)
            self.assertIn("not this tool", result.stderr)
            self.assertTrue(sentinel.is_file())
            self.assertTrue(img.is_file())
            self.assertFalse(calls.exists(), "teardown must not unmount")

    def test_btrfs_teardown_refuses_a_marker_for_another_image(self):
        # Mounted with a marker, but the marker records a different
        # image: cross-wired teardown refuses without unmounting.
        with tempfile.TemporaryDirectory() as tmp:
            mnt = Path(tmp) / "mnt"
            mnt.mkdir()
            (mnt / ".p11-btrfs-tmpdir").write_text(
                "p11scope-btrfs-tmpdir v1\nimg=/elsewhere/other.img\n",
                encoding="utf-8")
            sentinel = mnt / "sentinel.txt"
            sentinel.write_text("data", encoding="utf-8")
            img = Path(tmp) / "imgfile"
            img.write_text("image", encoding="utf-8")
            calls = Path(tmp) / "umount-calls"
            bindir = Path(tmp) / "bin"
            bindir.mkdir()
            write_path_stub(bindir, "mountpoint", "exit 0\n")
            write_path_stub(bindir, "umount", f'echo called >>"{calls}"\n')
            result = run_btrfs_helper(
                BTRFS_HELPER, "--teardown", str(img), str(mnt),
                path_prefix=[bindir])
            self.assertEqual(result.returncode, 1,
                             result.stdout + result.stderr)
            self.assertIn("refusing teardown", result.stderr)
            self.assertTrue(sentinel.is_file())
            self.assertTrue(img.is_file())
            self.assertFalse(calls.exists(), "teardown must not unmount")

    def test_btrfs_teardown_refuses_a_nonempty_unmarked_directory(self):
        # Unmounted (a plain dir is not a mount): the sentinel
        # directory and the plain image are left intact, exit 1.
        with tempfile.TemporaryDirectory() as tmp:
            mnt = Path(tmp) / "mnt"
            mnt.mkdir()
            sentinel = mnt / "sentinel.txt"
            sentinel.write_text("data", encoding="utf-8")
            img = Path(tmp) / "imgfile"
            img.write_text("image", encoding="utf-8")
            result = run_btrfs_helper(BTRFS_HELPER, "--teardown",
                                      str(img), str(mnt))
            self.assertEqual(result.returncode, 1,
                             result.stdout + result.stderr)
            self.assertIn("refusing teardown", result.stderr)
            self.assertTrue(sentinel.is_file())
            self.assertTrue(img.is_file())

    def test_btrfs_teardown_removes_only_an_empty_dir_and_plain_image(self):
        # Unmounted empty directory plus plain image file: both go,
        # exit 0.
        with tempfile.TemporaryDirectory() as tmp:
            mnt = Path(tmp) / "mnt"
            mnt.mkdir()
            img = Path(tmp) / "imgfile"
            img.write_text("image", encoding="utf-8")
            result = run_btrfs_helper(BTRFS_HELPER, "--teardown",
                                      str(img), str(mnt))
            self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
            self.assertFalse(mnt.exists())
            self.assertFalse(img.exists())

    def test_btrfs_teardown_is_idempotent_on_missing_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_btrfs_helper(
                BTRFS_HELPER, "--teardown",
                str(Path(tmp) / "imgfile"), str(Path(tmp) / "mnt"))
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)

    def test_btrfs_teardown_refuses_a_nonfile_image(self):
        # The image is validated before the empty directory is
        # removed: a directory image refuses with everything intact.
        with tempfile.TemporaryDirectory() as tmp:
            mnt = Path(tmp) / "mnt"
            mnt.mkdir()
            img = Path(tmp) / "imgdir"
            img.mkdir()
            result = run_btrfs_helper(BTRFS_HELPER, "--teardown",
                                      str(img), str(mnt))
            self.assertEqual(result.returncode, 1,
                             result.stdout + result.stderr)
            self.assertIn("refusing teardown", result.stderr)
            self.assertTrue(mnt.is_dir())
            self.assertTrue(img.is_dir())

    def test_btrfs_setup_refuses_an_occupied_mountpoint(self):
        # mountpoint stubbed to report mounted: setup refuses 77
        # naming the mountpoint. The check precedes privilege, so
        # this runs unprivileged and must not print the root reason.
        with tempfile.TemporaryDirectory() as tmp:
            mnt = Path(tmp) / "mnt"
            mnt.mkdir()
            img = Path(tmp) / "imgfile"
            bindir = Path(tmp) / "bin"
            bindir.mkdir()
            write_path_stub(bindir, "mountpoint", "exit 0\n")
            result = run_btrfs_helper(BTRFS_HELPER, str(img), str(mnt),
                                      path_prefix=[bindir])
            self.assertEqual(result.returncode, 77,
                             result.stdout + result.stderr)
            self.assertIn("already a mountpoint", result.stderr)
            self.assertNotIn("must run as root", result.stderr)
            self.assertFalse(img.exists())

    def test_btrfs_setup_refuses_a_nonempty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            mnt = Path(tmp) / "mnt"
            mnt.mkdir()
            sentinel = mnt / "sentinel.txt"
            sentinel.write_text("data", encoding="utf-8")
            img = Path(tmp) / "imgfile"
            result = run_btrfs_helper(BTRFS_HELPER, str(img), str(mnt))
            self.assertEqual(result.returncode, 77,
                             result.stdout + result.stderr)
            self.assertIn("not empty", result.stderr)
            self.assertTrue(sentinel.is_file())
            self.assertFalse(img.exists())

    def test_btrfs_setup_still_reports_missing_prerequisites(self):
        # No stubs: a non-root setup still exits 77 with the root
        # reason (the state checks kept the first-run path).
        if os.geteuid() == 0:
            self.skipTest("needs a non-root caller")
        with tempfile.TemporaryDirectory() as tmp:
            result = run_btrfs_helper(
                BTRFS_HELPER, str(Path(tmp) / "imgfile"),
                str(Path(tmp) / "mnt"))
            self.assertEqual(result.returncode, 77,
                             result.stdout + result.stderr)
            self.assertIn("must run as root", result.stderr)

    def test_binary_has_ignored_reports_present_on_large_early_match_lists(self):
        # The membership probe once ran `... | grep -qxF` under pipefail,
        # so grep's early exit SIGPIPE'd the upstream sort and the
        # pipeline returned 141 ("not present") at random, silently
        # dropping the alternative cell from --list and the campaign. A
        # large ignored list whose match sorts first must report
        # present on every iteration, and a missing name must report
        # absent (exit 1, never 141).
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-large"
            write_fake_binary(
                binary,
                ["aaa_match"] + [f"zzz_fill_{i:06d}" for i in range(20000)],
            )
            script = (
                f'source "{RUNNER}" --help >/dev/null 2>&1; '
                f"for i in 1 2 3 4 5; do "
                f'binary_has_ignored "{binary}" aaa_match '
                f"|| exit $((100 + i)); done; "
                f'binary_has_ignored "{binary}" absent_cell; '
                f"test $? -eq 1 || exit 106"
            )
            result = subprocess.run(
                ["bash", "-c", script],
                capture_output=True, text=True, cwd=ROOT,
            )
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)

    def test_cell_branch_suffix_records_the_taken_arm(self):
        # Branch recording: the runner appends ` branch=<name>` for the
        # arm a dual-outcome cell printed, the last branch line wins, a
        # cell without one gets no suffix, and a malformed value is
        # INVALID rather than silently dropped.
        with tempfile.TemporaryDirectory() as tmp:
            logs = {
                "none.log": "test result: ok. 1 passed\n",
                "one.log": ("IDENTITY_515_DENIAL outcome=eligible\n"
                            "P11SCOPE_CELL_BRANCH=eligible\n"
                            "test result: ok. 1 passed\n"),
                "two.log": ("P11SCOPE_CELL_BRANCH=first\n"
                            "P11SCOPE_CELL_BRANCH=second\n"),
                "bad.log": "P11SCOPE_CELL_BRANCH=has space\n",
                "empty.log": "P11SCOPE_CELL_BRANCH=\n",
            }
            paths = {}
            for name, body in logs.items():
                path = Path(tmp) / name
                path.write_text(body, encoding="utf-8")
                paths[name] = path
            probes = "; ".join(
                f'printf \'<@@%s@@>\\n\' "$(cell_branch_suffix "{path}")"'
                for path in paths.values()
            )
            script = (f'source "{RUNNER}" --help >/dev/null 2>&1; {probes}')
            result = subprocess.run(
                ["bash", "-c", script],
                capture_output=True, text=True, cwd=ROOT,
            )
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["<@@@@>", "<@@ branch=eligible@@>", "<@@ branch=second@@>",
             "<@@ branch=INVALID@@>", "<@@ branch=INVALID@@>"],
        )

    def test_run_selection_deduplicates_overlapping_groups(self):
        # Two groups may curate one cell (a revive overlapping
        # another lane's add); the run loop must run it once,
        # keeping the first curated position. Drives the runner's
        # own dedup over a crafted selection, plus the empty case.
        script = (
            f'source "{RUNNER}" --help >/dev/null 2>&1; '
            'probe=(b1 a1 b1 c1 a1); dedup_preserving_order probe; '
            'printf "<%s>\\n" "${probe[@]}"; '
            'empty=(); dedup_preserving_order empty; '
            'echo "empty:${#empty[@]}"'
        )
        result = subprocess.run(
            ["bash", "-c", script],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ["<b1>", "<a1>", "<c1>", "empty:0"])
        text = RUNNER.read_text(encoding="utf-8")
        self.assertIn("dedup_preserving_order selected_runnable", text)

    def test_run_loop_appends_the_branch_suffix_after_the_result_text(self):
        # The ` branch=` token goes after the test-result text so the
        # downstream `PASS <path> rc=0 seconds=<n> :: test result: ...`
        # shape keeps matching; pin the wiring, not just the helper.
        text = RUNNER.read_text(encoding="utf-8")
        self.assertIn('branch_suffix=$(cell_branch_suffix "$log")', text)
        self.assertIn(
            '"$verdict $name rc=$rc seconds=$seconds :: '
            '$result_line$branch_suffix"',
            text,
        )

    def test_revived_group_membership_is_exact(self):
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        self.assertEqual(set(lists["BTRFS_TESTS"]), set(BTRFS_EXPECTED))
        self.assertEqual(set(lists["OVERLAY_TESTS"]), set(OVERLAY_EXPECTED))
        self.assertEqual(set(lists["EXPECTED_FAILURE_TESTS"]),
                         set(XFAIL_EXPECTED))
        self.assertEqual(set(lists["COUNTER_FIXTURE_TESTS"]),
                         set(COUNTER_FIXTURE_EXPECTED))
        self.assertEqual(set(lists["WRAP_FIXTURE_TESTS"]),
                         set(WRAP_FIXTURE_EXPECTED))
        self.assertEqual(set(lists["BTRFS_TMPDIR_XFAIL_TESTS"]),
                         set(BTRFS_TMPDIR_XFAIL_EXPECTED))
        self.assertTrue(set(BTRFS_TMPDIR_XFAIL_EXPECTED)
                        <= lists["EXPECTED_FAILURE_TESTS"])
        for group in ("BTRFS_TESTS", "OVERLAY_TESTS",
                      "EXPECTED_FAILURE_TESTS"):
            with self.subTest(group=group):
                self.assertFalse(set(lists[group]) & lists["SKIP_TESTS"])
                self.assertFalse(set(lists[group]) & lists["DEFAULT_TESTS"])
        self.assertTrue(set(COUNTER_FIXTURE_EXPECTED)
                        <= lists["DEFAULT_TESTS"])
        self.assertTrue(set(WRAP_FIXTURE_EXPECTED)
                        <= lists["LONG_TESTS"])

    def test_counter_fixture_classification_is_complete(self):
        # Every DEFAULT_TESTS counter-reader member is classified: it
        # either needs the runner-built fixtures or is one of the three
        # named cells that do not. A new counter cell fails here until
        # its author classifies it.
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        default_counter = {name for name in lists["DEFAULT_TESTS"]
                           if name.startswith("metrics::counter_reader::tests::")}
        self.assertEqual(default_counter,
                         set(COUNTER_FIXTURE_EXPECTED)
                         | set(COUNTER_READER_NOFIXTURE_EXPECTED))
        self.assertFalse(set(COUNTER_FIXTURE_EXPECTED)
                         & set(COUNTER_READER_NOFIXTURE_EXPECTED))

    def test_wrap_fixture_classification_is_complete(self):
        # Every LONG_TESTS diagnostics-wrap member needs the fixture:
        # all of them spawn through WrapWorkload. A new long wrap cell
        # fails here until its author classifies it.
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        long_wrap = {name for name in lists["LONG_TESTS"]
                     if name.startswith(
                         "inventory::privileged_tests::"
                         "operator_diagnostics_wrap::")}
        self.assertEqual(long_wrap, set(WRAP_FIXTURE_EXPECTED))
        self.assertEqual(long_wrap, lists["WRAP_FIXTURE_TESTS"])

    def test_branch_prints_exist_in_dual_outcome_cells(self):
        inspect = (ROOT / "src/inspect_system.rs").read_text()
        self.assertEqual(inspect.count("P11SCOPE_CELL_BRANCH=denied"), 1)
        self.assertEqual(inspect.count("P11SCOPE_CELL_BRANCH=eligible"), 1)
        capture = (ROOT / "src/attach/inventory/capture"
                   / "privileged_tests.rs").read_text()
        self.assertEqual(
            capture.count("P11SCOPE_CELL_BRANCH=pid_filter_refused"), 1)

    def test_usage_names_the_group_flags(self):
        result = run_runner("--help")
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        for flag in ("--include-long", "--include-btrfs",
                     "--include-overlay",
                     "--include-expected-failures",
                     "--wide-detailed-2112"):
            with self.subTest(flag=flag):
                self.assertIn(flag, result.stdout)

    def test_list_mode_prints_the_revived_groups(self):
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        full = set().union(*(lists[group] for group in
                             ("DEFAULT_TESTS", "ALTERNATIVE_TESTS",
                              "LONG_TESTS", "BTRFS_TESTS",
                              "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS",
                              "SKIP_TESTS")))
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        proof = {name for name in full if name.startswith(prefix)}
        self.assertEqual(len(proof), 14)
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-groups"
            write_fake_binary(binary, sorted(full - proof))
            result = run_runner("--list", str(binary))
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        # The fake lists both load-gate alternatives (a real binary has
        # exactly one), so the default section shows 240 + 2.
        self.assertIn("default (242)", result.stdout)
        self.assertIn("btrfs (17, --include-btrfs only)", result.stdout)
        self.assertIn("overlay (14, --include-overlay only)", result.stdout)
        self.assertIn("expected-failures (3, --include-expected-failures "
                      "only)", result.stdout)
        self.assertIn(BTRFS_EXPECTED[0], result.stdout)
        self.assertIn(OVERLAY_EXPECTED[0], result.stdout)
        self.assertIn(XFAIL_EXPECTED[0] + " :: ", result.stdout)
        self.assertIn("verify: curation matches the binary (316 tests)",
                      result.stdout)

    def test_real_tree_skip_entries_carry_until(self):
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        skip = lists["SKIP_TESTS"]
        entries = json.loads(INVENTORY.read_text())["sites"]
        for entry in entries:
            with self.subTest(path=entry["path"]):
                if entry["path"] in skip:
                    self.assertIn("until", entry)
                else:
                    self.assertNotIn("until", entry)

    def test_skip_entry_without_until_fails(self):
        sources = {
            "src/lib.rs": "mod a;\n",
            "src/a.rs": (
                "#[test]\n"
                '#[ignore = "privileged: needs the lane"]\n'
                "fn t_skip() {}\n"
            ),
        }
        entries = [
            {"file": "src/a.rs", "path": "a::t_skip",
             "reason": "privileged: needs the lane", "cell": "privileged"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, sources, entries, [],
                          skip_registered=["a::t_skip"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("a::t_skip", result.stdout)
        self.assertIn("until", result.stdout)

    def test_skip_entry_with_expired_until_fails(self):
        # The release under development is 0.6.0 (DEVELOPMENT_VERSION),
        # so "0.6.0" (the stale "deferred to 0.6.0") is already expired.
        for until in ("0.5.0", "0.6.0", "0.6"):
            with self.subTest(until=until):
                sources = {
                    "src/lib.rs": "mod a;\n",
                    "src/a.rs": (
                        "#[test]\n"
                        '#[ignore = "privileged: needs the lane"]\n'
                        "fn t_skip() {}\n"
                    ),
                }
                entries = [
                    {"file": "src/a.rs", "path": "a::t_skip",
                     "reason": "privileged: needs the lane",
                     "cell": "privileged", "until": until},
                ]
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    write_fixture(root, sources, entries, [],
                                  skip_registered=["a::t_skip"])
                    result = run_checker(root)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("expired", result.stdout)

    def test_skip_entry_with_standing_until_passes(self):
        for until in ("0.7.0",
                      {"item": "kernel lanes", "owner": "WP-9"}):
            with self.subTest(until=until):
                sources = {
                    "src/lib.rs": "mod a;\n",
                    "src/a.rs": (
                        "#[test]\n"
                        '#[ignore = "privileged: needs the lane"]\n'
                        "fn t_skip() {}\n"
                    ),
                }
                entries = [
                    {"file": "src/a.rs", "path": "a::t_skip",
                     "reason": "privileged: needs the lane",
                     "cell": "privileged", "until": until},
                ]
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    write_fixture(root, sources, entries, [],
                                  skip_registered=["a::t_skip"])
                    result = run_checker(root)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertIn("all 1 inventoried site(s) match",
                              result.stdout)

    def test_development_version_pin_is_deliberate(self):
        # The checker judges skip expiry against max(manifest,
        # DEVELOPMENT_VERSION); a stale constant lets next-release
        # untils stand a whole cycle (fail-closed but late), so the
        # value is pinned and bumps are reviewed.
        self.assertEqual(CHECKER_MOD["DEVELOPMENT_VERSION"], "0.6.0")

    def test_malformed_until_fails(self):
        for until in ("0.6.x", "soon", 7,
                      {"item": "kernel lanes"},
                      {"item": "kernel lanes", "owner": ""},
                      {"item": "", "owner": "WP-9"},
                      {"item": "kernel lanes", "owner": "WP-9",
                       "extra": 1}):
            with self.subTest(until=until):
                sources = {
                    "src/lib.rs": "mod a;\n",
                    "src/a.rs": (
                        "#[test]\n"
                        '#[ignore = "privileged: needs the lane"]\n'
                        "fn t_skip() {}\n"
                    ),
                }
                entries = [
                    {"file": "src/a.rs", "path": "a::t_skip",
                     "reason": "privileged: needs the lane",
                     "cell": "privileged", "until": until},
                ]
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    write_fixture(root, sources, entries, [],
                                  skip_registered=["a::t_skip"])
                    result = run_checker(root)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("until", result.stdout)

    def test_until_on_a_nonskip_entry_fails(self):
        sources = {
            "src/lib.rs": "mod a;\n",
            "src/a.rs": (
                "#[test]\n"
                '#[ignore = "privileged: needs the lane"]\n'
                "fn t_run() {}\n"
            ),
        }
        entries = [
            {"file": "src/a.rs", "path": "a::t_run",
             "reason": "privileged: needs the lane",
             "cell": "privileged", "until": "0.7.0"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, sources, entries, ["a::t_run"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("a::t_run", result.stdout)
        self.assertIn("until", result.stdout)

    def test_manifest_version_rules_past_development(self):
        # After the 0.9.0 release is cut (Cargo.toml at 0.9.0) an
        # "0.8.0" deferral is expired even though the development
        # constant still says 0.6.0.
        sources = {
            "src/lib.rs": "mod a;\n",
            "src/a.rs": (
                "#[test]\n"
                '#[ignore = "privileged: needs the lane"]\n'
                "fn t_skip() {}\n"
            ),
        }
        entries = [
            {"file": "src/a.rs", "path": "a::t_skip",
             "reason": "privileged: needs the lane",
             "cell": "privileged", "until": "0.8.0"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, sources, entries, [],
                          skip_registered=["a::t_skip"],
                          manifest_version="0.9.0")
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("expired", result.stdout)

    def test_checker_prints_exact_per_list_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, REGISTERED, ["m::t_wide"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "ignored-tests counts: DEFAULT_TESTS=2 ALTERNATIVE_TESTS=0 "
            "LONG_TESTS=0 BTRFS_TESTS=0 OVERLAY_TESTS=0 "
            "EXPECTED_FAILURE_TESTS=0 SKIP_TESTS=0 "
            "COUNTER_FIXTURE_TESTS=0 WRAP_FIXTURE_TESTS=0 "
            "BTRFS_TMPDIR_XFAIL_TESTS=0 "
            "WIDE_ONLY_TESTS=0 "
            "WIDE_DETAILED_2112_TESTS=1 "
            "COUNTER_BANK_PROOF_TESTS=0 COUNTER_ARTIFACTS_TESTS=0 "
            "DISCOVER_BTRFS_SUBVOL_TESTS=0 "
            "INTEGRATION_TESTS=0",
            result.stdout,
        )

    def test_real_tree_per_list_counts_are_exact(self):
        result = run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for pin in (
            "DEFAULT_TESTS=240",
            "ALTERNATIVE_TESTS=2",
            "LONG_TESTS=17",
            "BTRFS_TESTS=17",
            "OVERLAY_TESTS=14",
            "EXPECTED_FAILURE_TESTS=3",
            "SKIP_TESTS=37",
            "COUNTER_FIXTURE_TESTS=27",
            "WRAP_FIXTURE_TESTS=7",
            "BTRFS_TMPDIR_XFAIL_TESTS=2",
            "WIDE_ONLY_TESTS=21",
            "WIDE_DETAILED_2112_TESTS=0",
            "COUNTER_BANK_PROOF_TESTS=0",
            "COUNTER_ARTIFACTS_TESTS=2",
            "DISCOVER_BTRFS_SUBVOL_TESTS=1",
            "INTEGRATION_TESTS=22",
        ):
            with self.subTest(pin=pin):
                self.assertIn(pin, result.stdout)

    def test_wide_flag_is_accepted_and_ignored_in_list_mode(self):
        # --wide-detailed-2112 is a no-op alias since v0.7.0: the flag
        # is accepted, a note names it on stderr, and the run lists the
        # default campaign exactly as without the flag. The nine
        # promoted cells now live in DEFAULT_TESTS; the wide list is
        # empty. Kept for one release; remove with the alias.
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        for name in WIDE_EXPECTED:
            with self.subTest(name=name):
                self.assertIn(name, lists["DEFAULT_TESTS"])
        self.assertEqual(len(lists["WIDE_DETAILED_2112_TESTS"]), 0)
        full = set().union(*(lists[group] for group in
                             ("DEFAULT_TESTS", "ALTERNATIVE_TESTS",
                              "LONG_TESTS", "BTRFS_TESTS",
                              "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS",
                              "SKIP_TESTS")))
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        proof = {name for name in full if name.startswith(prefix)}
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-wide-alias"
            write_fake_binary(binary, sorted(full - proof))
            plain = run_runner("--list", str(binary))
            aliased = run_runner("--list", "--wide-detailed-2112",
                                 str(binary))
        self.assertEqual(plain.returncode, 0,
                         plain.stdout + plain.stderr)
        self.assertEqual(aliased.returncode, 0,
                         aliased.stdout + aliased.stderr)
        self.assertEqual(aliased.stdout, plain.stdout)
        self.assertIn("wide-detailed-2112 is the default profile",
                      aliased.stderr)
        self.assertNotIn("wide-detailed-2112", plain.stderr)

    def test_wide_list_mode_refuses_a_default_binary(self):
        # A default binary carries none of the wide tests: the mode must
        # refuse (exit 1, missing tests named) instead of printing a
        # verify receipt or an empty PASS.
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-default"
            write_fake_binary(binary, ["plain::t_one", "plain::t_two"])
            result = run_runner("--list", "--wide-detailed-2112",
                                str(binary))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("wide-detailed-2112", result.stderr)
        self.assertIn("absent from the binary", result.stderr)
        self.assertIn("privileged_task4_detailed_2112_lp64", result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_wide_flag_ignores_a_duplicated_default_listing(self):
        # The old wide mode refused duplicated listings; the no-op alias
        # follows the default campaign, which dedupes the binary list
        # (sort -u), so a duplicated member still verifies. Kept for one
        # release; remove with the alias.
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        full = set().union(*(lists[group] for group in
                             ("DEFAULT_TESTS", "ALTERNATIVE_TESTS",
                              "LONG_TESTS", "BTRFS_TESTS",
                              "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS",
                              "SKIP_TESTS")))
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        proof = {name for name in full if name.startswith(prefix)}
        members = sorted(full - proof)
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-dup"
            write_fake_binary(binary, members + [members[0]])
            result = run_runner("--list", "--wide-detailed-2112",
                                str(binary))
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertIn("wide-detailed-2112 is the default profile",
                      result.stderr)
        self.assertIn("verify: curation matches the binary",
                      result.stdout)

    def test_integration_entry_without_curation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, INTEGRATION_SOURCES, [INTEGRATION_ENTRY],
                          [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("t_live", result.stdout)
        self.assertIn("INTEGRATION_TESTS", result.stdout)

    def test_privileged_integration_entry_requires_curation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(INTEGRATION_ENTRY, cell="privileged")
            write_fixture(root, INTEGRATION_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("t_live", result.stdout)
        self.assertIn("INTEGRATION_TESTS", result.stdout)

    def test_integration_entry_passes_when_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, INTEGRATION_SOURCES, [INTEGRATION_ENTRY],
                          [], integration_registered=["tests/foo.rs:t_live"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_integration_member_without_an_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, {"src/lib.rs": ""}, [], [],
                          integration_registered=["tests/foo.rs:t_nope"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("t_nope", result.stdout)
        self.assertIn("INTEGRATION_TESTS", result.stdout)

    def test_integration_list_mode_accepts_curated_binaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / "deps"
            deps.mkdir()
            write_fake_integration_binary(
                deps, "bpf_load_feasibility",
                ["per_program_load_times",
                 "parallel_load_measures_kernel_overlap",
                 "parallel_load_partial_failure_retains_cleanup_owner",
                 "resident_service_cost_parts"])
            write_fake_integration_binary(
                deps, "entry_object_paired",
                ["paired_default_and_unsafe_objects_satisfy_the_entry_contract"])
            write_fake_integration_binary(
                deps, "exec_task_continuity",
                ["exec_task_core_shapes_kernel_load_without_attachment",
                 "noise::t_other"])
            write_fake_integration_binary(
                deps, "identity_iter_standalone",
                ["identity_loader_strict_gate_requires_btf_and_both_programs"])
            write_fake_integration_binary(
                deps, "inventory_identity",
                ["d4_btrfs_scan_backends_match_exact_fixture_population",
                 "kernel_identity_positive_cell_rejects_refusal"])
            write_fake_integration_binary(
                deps, "object_producer_activation",
                ["counter_bank_btf_maps_and_programs_load"])
            write_fake_integration_binary(
                deps, "run_abandon_report",
                ["second_sigint_during_teardown_publishes_truthful_report_and_exits_130"])
            write_fake_integration_binary(
                deps, "prearm_witness_cli",
                ["privileged_profile_pid_prearm_clean_exact_counts",
                 "privileged_profile_cgroup_prearm_clean_exact_counts",
                 "privileged_profile_system_prearm_clean_exact_counts",
                 "privileged_profile_metrics_system_prearm_clean_exact_counts",
                 "privileged_profile_pid_prearm_twin_exact_window",
                 "privileged_trace_system_prearm_clean_exact_counts"])
            write_fake_integration_binary(
                deps, "run_tree",
                ["privileged_run_tree_shell_wrapper_shows_grandchild_calls",
                 "privileged_run_tree_double_fork_shows_reparented_calls",
                 "privileged_run_tree_outliving_child_is_disclosed",
                 "privileged_run_tree_many_children_land_exact"])
            write_fake_integration_binary(
                deps, "trace_pid_target",
                ["privileged_trace_pid_names_target_on_stderr"])
            result = run_runner("--list-integration", str(deps))
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertIn("integration (22)", result.stdout)
        for entry in INTEGRATION_EXPECTED:
            self.assertIn(entry, result.stdout)
        self.assertIn("verify: integration curation selects exactly one "
                      "test per entry (22 entries)", result.stdout)

    def test_integration_list_mode_refuses_zero_selection(self):
        # The inventory_identity binary below is missing one of its two
        # curated tests: the entry selects nothing and must be refused.
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / "deps"
            deps.mkdir()
            write_fake_integration_binary(
                deps, "exec_task_continuity",
                ["exec_task_core_shapes_kernel_load_without_attachment"])
            write_fake_integration_binary(
                deps, "identity_iter_standalone",
                ["identity_loader_strict_gate_requires_btf_and_both_programs"])
            write_fake_integration_binary(
                deps, "inventory_identity",
                ["kernel_identity_positive_cell_rejects_refusal"])
            write_fake_integration_binary(
                deps, "run_abandon_report",
                ["second_sigint_during_teardown_publishes_truthful_report_and_exits_130"])
            result = run_runner("--list-integration", str(deps))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("integration", result.stderr)
        self.assertIn("d4_btrfs_scan_backends_match_exact_fixture_population",
                      result.stderr)
        self.assertIn("selects 0 tests", result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_integration_list_mode_refuses_missing_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / "deps"
            deps.mkdir()
            write_fake_integration_binary(
                deps, "exec_task_continuity",
                ["exec_task_core_shapes_kernel_load_without_attachment"])
            result = run_runner("--list-integration", str(deps))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("run_abandon_report", result.stderr)
        self.assertIn("no test binary", result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_integration_list_mode_refuses_duplicated_selection(self):
        # The inventory_identity binary below lists one of its two
        # curated tests twice: the entry selects two tests, not exactly
        # one, and must be refused.
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / "deps"
            deps.mkdir()
            write_fake_integration_binary(
                deps, "exec_task_continuity",
                ["exec_task_core_shapes_kernel_load_without_attachment"])
            write_fake_integration_binary(
                deps, "identity_iter_standalone",
                ["identity_loader_strict_gate_requires_btf_and_both_programs"])
            write_fake_integration_binary(
                deps, "inventory_identity",
                ["d4_btrfs_scan_backends_match_exact_fixture_population",
                 "d4_btrfs_scan_backends_match_exact_fixture_population",
                 "kernel_identity_positive_cell_rejects_refusal"])
            write_fake_integration_binary(
                deps, "run_abandon_report",
                ["second_sigint_during_teardown_publishes_truthful_report_and_exits_130"])
            result = run_runner("--list-integration", str(deps))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("d4_btrfs_scan_backends_match_exact_fixture_population",
                      result.stderr)
        self.assertIn("selects 2 tests", result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_integration_list_mode_refuses_ambiguous_binary(self):
        # Two executables match one stem (a stale rebuild left behind):
        # the entry no longer identifies its binary, so it is refused.
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / "deps"
            deps.mkdir()
            write_fake_integration_binary(
                deps, "exec_task_continuity",
                ["exec_task_core_shapes_kernel_load_without_attachment"])
            extra = deps / "exec_task_continuity-fedcba9876543210"
            write_fake_binary(extra, ["exec_task_core_shapes_kernel_load_without_attachment"])
            write_fake_integration_binary(
                deps, "identity_iter_standalone",
                ["identity_loader_strict_gate_requires_btf_and_both_programs"])
            write_fake_integration_binary(
                deps, "inventory_identity",
                ["d4_btrfs_scan_backends_match_exact_fixture_population",
                 "kernel_identity_positive_cell_rejects_refusal"])
            write_fake_integration_binary(
                deps, "run_abandon_report",
                ["second_sigint_during_teardown_publishes_truthful_report_and_exits_130"])
            result = run_runner("--list-integration", str(deps))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("exec_task_continuity", result.stderr)
        self.assertIn("more than one test binary", result.stderr)
        self.assertNotIn("verify:", result.stdout)


PRIVILEGED_TESTS_RS = (ROOT / "src" / "attach" / "inventory" / "activation"
                       / "privileged_tests.rs")
PRIVILEGED_TESTS_MOD = "attach::inventory::activation::privileged_tests"
SWEEP_MACROS = ("inventory_sweep_test", "detailed_sweep_test")


def _attr_block_above(lines, index):
    """Consecutive #[...] lines directly above lines[index]."""
    attrs = []
    cursor = index - 1
    while cursor >= 0:
        stripped = lines[cursor].strip()
        if not stripped:
            cursor -= 1
            continue
        if stripped.startswith("#["):
            attrs.append(stripped)
            cursor -= 1
            continue
        break
    return attrs


def _gate_class(attrs):
    """wide when a positive wide-detailed-2112 cfg gates the site.

    A cfg(not(feature = "wide-detailed-2112")) twin (the n512 pair)
    and ungated sites are FULL-present, never wide-only.
    """
    cfgs = [attr for attr in attrs if "cfg" in attr]
    if not cfgs:
        return "full"
    wide = any("wide-detailed-2112" in cfg and "not(" not in cfg
               for cfg in cfgs)
    other = any("wide-detailed-2112" not in cfg or "not(" in cfg
                for cfg in cfgs)
    if wide and not other:
        return "wide"
    return "full"


def wide_only_from_sources():
    """Full paths of ignored lib tests gated wide-only in src/.

    A test is wide-only when every definition site (plain fn or
    sweep-macro invocation) carries a positive wide cfg and none is
    FULL-present. Macro-definition gates join the invocation gate.
    Only privileged_tests.rs holds ignore-bearing sweep macros (see
    the guard test); every other src file is guarded separately.
    """
    text = PRIVILEGED_TESTS_RS.read_text(encoding="utf-8")
    lines = text.splitlines()
    def_gate = {}
    for name in SWEEP_MACROS:
        match = re.search(rf"^macro_rules! {name} \{{", text, re.M)
        assert match is not None, f"missing macro def {name}"
        opening = text.count("\n", 0, match.start())
        template = "\n".join(lines[opening:opening + 12])
        assert "#[ignore" in template, f"{name} template lost #[ignore]"
        def_gate[name] = _gate_class(_attr_block_above(lines, opening))
    sites = {}
    for number, line in enumerate(lines):
        fn_match = re.match(r"fn (\w+)\s*\(", line.strip())
        if fn_match is not None:
            attrs = _attr_block_above(lines, number)
            if any(attr.startswith("#[ignore") for attr in attrs):
                sites.setdefault(fn_match.group(1), []).append(
                    _gate_class(attrs))
            continue
        for name in SWEEP_MACROS:
            if re.match(rf"{name}!\s*\(", line.strip()) is None:
                continue
            rest = "\n".join(lines[number:number + 4])
            arg = re.search(rf"{name}!\s*\(\s*(\w+)", rest)
            assert arg is not None, f"cannot parse {name} invocation"
            gate = _gate_class(_attr_block_above(lines, number))
            if gate == "full" and def_gate[name] == "wide":
                gate = "wide"
            sites.setdefault(arg.group(1), []).append(gate)
    return {f"{PRIVILEGED_TESTS_MOD}::{name}"
            for name, gates in sites.items()
            if gates and all(gate == "wide" for gate in gates)}


class Full512CurationTests(unittest.TestCase):
    def test_wide_only_list_is_pinned_and_curated(self):
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        members = lists.get("WIDE_ONLY_TESTS", set())
        self.assertEqual(sorted(members), sorted(WIDE_ONLY_EXPECTED))
        campaign = set(lists["DEFAULT_TESTS"]) | set(lists["LONG_TESTS"])
        for name in WIDE_ONLY_EXPECTED:
            with self.subTest(name=name):
                self.assertIn(name, campaign,
                              "every wide-only cell stays curated")

    def test_wide_only_matches_cfg_wide_sources(self):
        self.assertEqual(wide_only_from_sources(), set(WIDE_ONLY_EXPECTED))

    def test_no_other_file_holds_a_wide_gated_ignored_test(self):
        # The source scan covers privileged_tests.rs only; every other
        # src file with a wide cfg must keep ignored tests away from
        # it, so a new wide-gated test outside the scan fails here.
        offenders = []
        for path in sorted((ROOT / "src").rglob("*.rs")):
            if path == PRIVILEGED_TESTS_RS:
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
            for number, line in enumerate(lines):
                if "wide-detailed-2112" not in line or "cfg" not in line:
                    continue
                window = "\n".join(lines[number:number + 9])
                if "#[ignore" in window:
                    offenders.append(f"{path}:{number + 1}")
        self.assertEqual(offenders, [])

    def test_full512_list_mode_accepts_a_full_binary(self):
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        full = set().union(*(lists[group] for group in
                             ("DEFAULT_TESTS", "ALTERNATIVE_TESTS",
                              "LONG_TESTS", "BTRFS_TESTS",
                              "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS",
                              "SKIP_TESTS")))
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        proof = {name for name in full if name.startswith(prefix)}
        binary_tests = sorted(full - proof - set(WIDE_ONLY_EXPECTED))
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-full512"
            write_fake_binary(binary, binary_tests)
            result = run_runner("--list", "--full-512", str(binary))
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        # DEFAULT 240 minus the 17 wide members, plus both load-gate
        # alternatives the fake lists (a real binary has exactly one);
        # LONG 17 minus the 4 wide members.
        self.assertIn("default (225)", result.stdout)
        self.assertIn("long (13, --include-long only)", result.stdout)
        for name in WIDE_ONLY_EXPECTED:
            self.assertNotIn(name, result.stdout)
        self.assertIn("verify: full-512 curation matches the binary",
                      result.stdout)

    def test_full512_list_mode_refuses_a_wide_binary(self):
        # A wide binary contains the wide-only cells: --full-512 must
        # refuse it by name, never grade it as FULL-512.
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        full = set().union(*(lists[group] for group in
                             ("DEFAULT_TESTS", "ALTERNATIVE_TESTS",
                              "LONG_TESTS", "BTRFS_TESTS",
                              "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS",
                              "SKIP_TESTS")))
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        proof = {name for name in full if name.startswith(prefix)}
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-wide"
            write_fake_binary(binary, sorted(full - proof))
            result = run_runner("--list", "--full-512", str(binary))
        self.assertNotEqual(result.returncode, 0,
                            result.stdout + result.stderr)
        self.assertIn("unexpectedly contains wide-only", result.stderr)
        self.assertIn("privileged_task4_detailed_2112_lp64", result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_full512_list_mode_refuses_a_partial_binary(self):
        # Exactly one wide-only cell present is still a refusal, not a
        # quieter FULL-512: partial presence fails by name.
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        full = set().union(*(lists[group] for group in
                             ("DEFAULT_TESTS", "ALTERNATIVE_TESTS",
                              "LONG_TESTS", "BTRFS_TESTS",
                              "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS",
                              "SKIP_TESTS")))
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        proof = {name for name in full if name.startswith(prefix)}
        keep = WIDE_ONLY_EXPECTED[3]
        binary_tests = sorted(full - proof - set(WIDE_ONLY_EXPECTED)
                              | {keep})
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-partial"
            write_fake_binary(binary, binary_tests)
            result = run_runner("--list", "--full-512", str(binary))
        self.assertNotEqual(result.returncode, 0,
                            result.stdout + result.stderr)
        self.assertIn("unexpectedly contains wide-only", result.stderr)
        self.assertIn(keep, result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_full512_list_mode_refuses_an_uncurated_test(self):
        # The flavor check keeps the exact cover: a new ignored test
        # in a FULL-512 binary still fails as uncurated.
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        full = set().union(*(lists[group] for group in
                             ("DEFAULT_TESTS", "ALTERNATIVE_TESTS",
                              "LONG_TESTS", "BTRFS_TESTS",
                              "OVERLAY_TESTS", "EXPECTED_FAILURE_TESTS",
                              "SKIP_TESTS")))
        prefix = "attach::image_bank_proof::tests::privileged_image_bank_"
        proof = {name for name in full if name.startswith(prefix)}
        binary_tests = (sorted(full - proof - set(WIDE_ONLY_EXPECTED))
                        + ["attach::tests::brand_new_ignored_cell"])
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-newcell"
            write_fake_binary(binary, binary_tests)
            result = run_runner("--list", "--full-512", str(binary))
        self.assertNotEqual(result.returncode, 0,
                            result.stdout + result.stderr)
        self.assertIn("ignored in the binary but not curated",
                      result.stderr)
        self.assertIn("brand_new_ignored_cell", result.stderr)
        self.assertNotIn("verify:", result.stdout)


if __name__ == "__main__":
    unittest.main()
