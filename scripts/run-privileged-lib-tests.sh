#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Reproducible runner for the privileged (ignored) p11scope lib tests.
#
# Usage:
#   scripts/run-privileged-lib-tests.sh LIB_TEST_BINARY OUTDIR [--include-long] [SELECTOR...]
#   scripts/run-privileged-lib-tests.sh --list LIB_TEST_BINARY
#   scripts/run-privileged-lib-tests.sh --list-integration TEST_BINARY_DIR
#
# Run mode executes each selected ignored test once, one at a time, from the
# repo root, as:
#   <binary> --exact <full-path> --ignored --test-threads=1 --nocapture
# with TMPDIR pointed at a private dir under OUTDIR, `ulimit -n 65536`, and a
# fresh per-test evidence dir plus case index. It must run as root (exit 64
# otherwise) because the campaign loads BPF. --list mode prints the curated
# lists without running anything and works unprivileged.
#
# Per-test environment (from every std::env::var/var_os read in the files
# that define ignored tests):
#   P11SCOPE_TASK4_EVIDENCE_DIR + P11SCOPE_TASK4_CASE_INDEX: required by the
#     15 Task 4 / T7 tests (Task4Evidence::new_control, task4_fixture_receipt
#     and the identity-seal receipts in attach/inventory/activation tests).
#     The script provides a fresh OUTDIR/evidence/<seq>-<name>/ dir per test
#     and the run-order index 0..N (index < 100 is enforced by the tests; the
#     gates write offsets-<index>.json into the dir themselves, so a fresh
#     dir plus any index is sufficient). Set for every test; readers other
#     than the Task 4 gates do not exist, so it is inert elsewhere.
#   P11SCOPE_TASK4_SYNTHETIC_EVIDENCE_DIR / _DETAILED_: read only by
#     non-ignored synthetic replay tests, optional with a tempdir default;
#     the runner never executes those tests and does not set these.
#   P11SCOPE_I3A_RETIREMENT_* (retirement churn test), P11SCOPE_TEST_DISCOVERY_*
#     (manifest helper; set by its own fixture), P11SCOPE_TEST_PIDFD_DENIAL_*
#     (pidfd-denial helper; set by its parent test), P11SCOPE_ALIAS_COLLISION_*
#     (cross-device scan test), P11SCOPE_FIRST_USE_PROBE_CONFIG (first-use
#     probe), P11SCOPE_ROOT_RUNTIME_STAGE (root fence): each belongs to a
#     test on the static SKIP list below, which the script cannot provide a
#     fixture for, so they are never set here.
#   P11SCOPE_T3A_RELOADS (reload race, default 100), P11SCOPE_T3A_SECONDS
#     and P11SCOPE_T3A_RATE (SoftHSM continuity experiment, defaults 60 s and
#     0 unrelated mapping ops/s): optional Task 3 Stage A sizing knobs with
#     defaults; the runner leaves them unset.
#   P11SCOPE_COUNTER_BANK_FIXTURE_PROVIDER / _WORKLOAD: prebuilt LP64
#     fixtures for the default-build Counts-bank Session test. The runner
#     does not build or supply these inputs, so that cell is a documented skip.
#   P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER / _WORKLOAD: distinct8192
#     endpoint LP64 provider/driver for separately admitted boundary/population
#     cells; the default campaign neither builds nor supplies these inputs.
#   RLIMIT_NOFILE: the Task 4 gates sample soft/hard nofile per phase, the
#     T7 boundary cell pref lights live FD occupancy against it, and
#     Session::start may raise soft to hard at attach; wide cells attach
#     thousands of links, hence `ulimit -n 65536` before the campaign.
#
# Pass criterion: a test PASSES only if its log contains
#   "test result: ok. 1 passed"
# (exactly one test ran) and the harness exited 0. An exit code alone is not
# accepted, and "0 passed" (renamed/missing test) is a FAIL.
#
# Gate-run step (not a curated cell): doctor::tests::
# no_bpf_program_link_or_map_survives_a_doctor_probe is a non-ignored test,
# so it cannot be listed below without a product edit adding #[ignore];
# unprivileged it passes without loading anything. Its success path (doctor
# loads the Inventory object and releases it with no program, link, or map
# surviving) is exercised by running it once as root in a v6.6+ guest with
# the qualification libtest binary, e.g.:
#   <libtest> doctor::tests::no_bpf_program_link_or_map_survives_a_doctor_probe \
#     --exact --nocapture --test-threads=1
# Expect "test result: ok. 1 passed" and exit 0.
#
# DISCOVERY loss: cells that assert health under system scope require zero
# lifecycle-ring loss by default, a quiet-host property (vng guests, idle
# hosts). On a loaded host, P11SCOPE_PRIV_LIFECYCLE_LOSS=report (pass it
# through sudo, e.g. `sudo env P11SCOPE_PRIV_LIFECYCLE_LOSS=report ...`)
# tolerates ring loss only where the health read reports it (all other
# counters zero) and the capture's production consumer, fed that read,
# marks lifecycle loss; a missing owned lifecycle record is accepted on any
# reported ring loss. Each such read prints LIFECYCLE_LOSS_REPORTED. Never
# set it for a guest or qualification run. A set opt-in is recorded as an
# `# opt-in:` line in results.txt and echoed to stderr.
#
# Curation: default tests run normally, long tests only with --include-long,
# and static skips require their documented external prerequisites, with a
# reason. The feature-alternative load gates contribute exactly one member
# per binary (default vs stub-object-attributes builds). Both modes verify
# the curation against the binary's own `--list --ignored` output and refuse
# on drift, so a new ignored test can never be silently dropped and a
# renamed one can never silently pass. The wide-Detailed campaign below is
# separate: it selects only the ignored tests that exist in a
# --features wide-detailed-2112 libtest binary, when --wide-detailed-2112
# is passed in run or --list mode; any other binary is refused cleanly.
# The integration curation below that names the ignored integration tests
# as file:path selectors; --list-integration verifies each selector
# against built test binaries (exactly one binary, exactly one test) and
# never executes them.
set -uo pipefail

PROG=${0##*/}
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

# Default campaign: every ignored test except the long cells and the static
# skips. Order is the binary's --list order; each runs in its own process.
DEFAULT_TESTS=(
# W3-2 kernel-identity gates: WRONLY EPERM, the section 6.5 functional
# probe (hardlink-match vs copy-NONE plus the stale-generation phase),
# the whole-system shape cell, and the anchor-handle validator.
attach::identity_iter::tests::anchor_maps_validate_real_handles
attach::identity_iter::tests::functional_probe_proves_hardlink_match_and_copy_none
attach::identity_iter::tests::whole_system_run_covers_all_children
attach::identity_iter::tests::wronly_anchor_fds_refuse_reads_with_eperm
# 5.15 identity-denial cell: real BTF named-fix refusal through the
# production sink with zero bpf() syscalls; dual-outcome by running
# kernel (denied on 5.15, eligible elsewhere), lane-classified.
inspect_system::privileged_tests::privileged_identity_515_denial_is_disclosed
attach::instance_tests::privileged_full_image_native_multi_query_and_scan_ia32
attach::instance_tests::privileged_full_image_native_multi_query_and_scan_lp64
attach::instance_tests::privileged_semantic_capture_multi_reload_and_rebound_successor
attach::instance_tests::privileged_instance_attach_during_reload_loop_has_zero_false_joins
attach::instance_tests::privileged_instance_exec_renews_the_instance
attach::instance_tests::privileged_instance_fork_without_exec_stays_consistent
attach::instance_tests::privileged_instance_hooks_attach_for_profile_but_not_metrics
attach::instance_tests::privileged_instance_mapping_controls_never_join_old_state
attach::instance_tests::privileged_instance_mremap_dontunmap_keeps_both_and_renews
attach::instance_tests::privileged_instance_nonleader_exec_detaches_without_misrouting
attach::instance_tests::privileged_instance_overflow_at_ninth_file_is_unknown
attach::instance_tests::privileged_instance_pre_attachment_sharer_globalizes
attach::instance_tests::privileged_instance_reload_race_has_zero_false_joins
attach::instance_tests::privileged_instance_routing_separates_reload_sibling_and_mutation
attach::instance_tests::privileged_instance_vfork_unmap_globalizes
attach::instance_tests::privileged_instance_zombie_leader_sharer_globalizes
# Birth marker cells: live exec/fork/scope-gap marker words and admission
# counts through the session's instance maps.
attach::instance_tests::privileged_journal_marker_abandoned_call_at_thread_exit_dirties
attach::instance_tests::privileged_journal_marker_cgroup_gap_sticks_across_reentry_and_exec
attach::instance_tests::privileged_journal_marker_cgroup_outsider_call_creates_dirty_row
attach::instance_tests::privileged_journal_marker_dirty_nonleader_exec_publishes_fresh_ready
attach::instance_tests::privileged_journal_marker_exec_after_closure_publishes_ready
attach::instance_tests::privileged_journal_marker_fork_without_exec_has_no_ready
attach::instance_tests::privileged_journal_marker_nonleader_exec_creates_fresh_ready_row
attach::instance_tests::privileged_journal_marker_pid_outsider_stays_unobserved
attach::instance_tests::privileged_journal_marker_return_outside_scope_dirties
# H6 observer mapping interactions: owned idle target and genuine external
# mutation control; distinguish ordinary scans from System identity anchors.
attach::instance_tests::privileged_inventory_worker_scan_preserves_watched_instance
attach::instance_tests::privileged_system_identity_anchor_preserves_watched_instance
# DR-CLASSIC-PID0: classic --pid sessions (auto, singles, forced multi)
# keep a foreign process and a PID reuser out at the kernel boundary (BPF
# run statistics flat while they call) and in counts and call events; they
# print CLASSIC_PID_SCOPE with the non-target ns per call before and during
# the session. Needs ns_last_pid (CONFIG_CHECKPOINT_RESTORE).
attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_auto_excludes_foreign_and_reused_pid_lp64
attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_forced_multi_names_the_target_or_refuses_lp64
attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_singles_excludes_foreign_and_reused_pid_lp64
attach::inventory::activation::privileged_tests::privileged_detailed_auto_backend_same_cpu_preemption_keeps_frames
attach::inventory::activation::privileged_tests::privileged_detailed_multithread_owner_accounting_exact
attach::inventory::activation::privileged_tests::privileged_detailed_multithread_same_slot_allowlisted_exact
attach::inventory::activation::privileged_tests::privileged_detailed_owner_poison_is_disclosed
attach::inventory::activation::privileged_tests::privileged_detailed_same_cpu_preemption_keeps_frames
attach::inventory::activation::privileged_tests::privileged_inventory_activation_cgroup_separates_owned_callers
attach::inventory::activation::privileged_tests::privileged_inventory_activation_failure_preserves_usage_and_releases_resources
attach::inventory::activation::privileged_tests::privileged_inventory_activation_stop_with_owned_calls_in_progress
attach::inventory::activation::privileged_tests::privileged_inventory_activation_system_ia32
attach::inventory::activation::privileged_tests::privileged_inventory_activation_system_lp64
attach::inventory::activation::privileged_tests::privileged_inventory_caller_cgroup_lp64
attach::inventory::activation::privileged_tests::privileged_inventory_caller_partial_activation_lp64
attach::inventory::activation::privileged_tests::privileged_inventory_caller_system_ia32
attach::inventory::activation::privileged_tests::privileged_inventory_caller_system_lp64
attach::inventory::activation::privileged_tests::privileged_stop_gate_freezes_capture_state_after_quiescence
attach::inventory::activation::privileged_tests::privileged_stop_gate_keeps_calls_in_flight_as_residual
attach::inventory::activation::privileged_tests::privileged_t7_detailed_hot_slot_third_rv_lp64
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n1024_lp64
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n576_lp64
attach::inventory::activation::privileged_tests::privileged_task4_detailed_n512_lp64
attach::inventory::activation::privileged_tests::privileged_task4_detailed_physical_identity_controls
attach::inventory::activation::privileged_tests::privileged_task4_inventory_2112_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2048_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2049_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_n511_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_n512_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_n513_lp64
attach::inventory::activation::privileged_tests::privileged_task4_inventory_physical_identity_controls
# Task 6 C3 capture facade cells (each a few seconds, owned fixtures only):
# late-provider extend, PID scope vs foreign and reused-PID callers (writes
# /proc/sys/kernel/ns_last_pid to reuse the target's PID), pidfd cookie
# query across a nonleader exec, stop with a held call, and the leader-exit
# probe (leader pthread_exit while a worker keeps calling). C5.11: the
# foreign/reused-PID cell again with a PID-named uprobe-multi group (kernel
# pid filter plus the in-BPF guard); where the pid-filter probe fails (5.15)
# it asserts the PID-scoped Multi refusal instead; the leader-exit probe
# again under uprobe-multi (or the same refusal).
attach::inventory::capture::privileged_tests::privileged_inventory_capture_cookie_query_matches_row_and_changes_on_nonleader_exec_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_extend_late_provider_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_leader_exit_probe_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_pid_scope_excludes_foreign_and_reused_pid_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_pid_scope_leader_exit_probe_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_stop_with_held_call_reports_unsettled_lp64
# Task 6 C5.2: a PID capture stopped before activation keeps its pin, and
# its retiring and retired reads re-poll custody (held, then lost).
attach::inventory::capture::privileged_tests::privileged_inventory_capture_stop_before_activation_repolls_custody_lp64
# DR37 native Ready positive: the live selected loop (resolver, worker
# preparation, native CAS, install, wind-down, completion mint, retire)
# over a real capture. Root BPF lane, serial, about 7-8 s.
attach::inventory::capture::privileged_tests::privileged_dr37_selected_promotion_full_loop
attach::inventory::privileged_tests::privileged_inventory_caller_preparation_faults_release_exact_resources
attach::inventory::privileged_tests::privileged_inventory_caller_preparation_freezes_native_maps_and_publishes_binding
attach::inventory::privileged_tests::privileged_inventory_preparation_failure_releases_owned_resources
attach::inventory::privileged_tests::privileged_inventory_preparation_freezes_all_nine_protected_maps
attach::inventory::privileged_tests::privileged_inventory_preparation_loads_multi_without_links
attach::inventory::privileged_tests::privileged_inventory_preparation_loads_runtime_capacity_and_zero_links
attach::lifecycle_tests::exec_tests::privileged_detailed_failed_nonleader_exec_preserves_start_and_image
attach::lifecycle_tests::exec_tests::privileged_detailed_nonleader_exec_cleans_old_tid_before_same_session_rebind
attach::lifecycle_tests::privileged_detailed_nonleader_exit_preserves_same_slot_sibling_start
attach::lifecycle_tests::privileged_detailed_nonleader_exit_reclaims_start_and_preserves_leader
# Object-stop scrub cells over actual native OBJECT_START/STOP_GATE map
# definitions (owned maps only, each well under a second): scrub after
# quiescence, refusal without proven Q, and no false success on a frozen map.
attach::object_stop::tests::object_stop_scrubs_real_retained_map_after_q
attach::object_stop::tests::object_stop_refuses_real_unproven_q_without_mutation
attach::object_stop::tests::object_stop_reports_real_scrub_failure
# R1 native-retirement cells over a real Detailed Session with an owned
# provider child (each well under a minute): Multi close at Q then mint,
# Singles deferral to the terminal detach, and the partial-group guards.
attach::tests::collected_partial_group_real_session_guards_refuse_until_terminal_lp64
attach::tests::collected_retirement_singles_session_defers_close_to_terminal_detach_lp64
attach::tests::collected_retirement_stopped_session_q_closes_original_lp64
discovery::confirm_shards::tests::privileged_sharded_confirmation_equals_the_serial_production_probe
# T8 twin fullness control: the identical phase-1 arming with an empty
# request map admits the same head with zero loss, proving the twin's
# refusal pins the full blocked map rather than the head. Expected
# green on the fixed lane-A runtime (the pre-twin shape converges to
# admitted-head under any working fix); the known-failing twin/episode
# stay skipped below until the privileged campaign re-runs them.
discovery::engine::pressure_native_tests::pressure_live256_unparked_head_control_admits
# T8 FIRST live control: quiet window arms nothing, then a 3-child owned
# probe spends exactly tickets 1..=3 with zero loss (short; needs root,
# host vmlinux BTF, gcc-built fixtures, and a quiet window — any ambient
# EXEC refuses the cell, so run it on a controlled host).
discovery::engine::pressure_native_tests::pressure_live_ticket_spend_control_refuses_ambient
# life-1 (OD34 cell 3.6, loader half): 257 genuine provider loads in an
# owned cgroup overflow the 256 view slots, so the 257th strands at the
# view gate (views gate loader arms one to one and the loader refusal
# cannot fire here); the cell asserts the named view-capacity gap, nothing
# silently dropped, and no loader refusal. Cgroup-scoped so no ambient
# shares the slots (the boundary is forced, not host luck). Expected
# ~2-4 min (bounded ~7 min on a loaded host), 257 sleeping children,
# needs a writable cgroup v2 hierarchy.
discovery::engine::pressure_native_tests::pressure_257_provider_loads_name_the_view_capacity_gap
discovery::engine::publication_tests::broad_p11kit_admission_arithmetic
discovery::inventory_workload::tests::privileged_inventory_attach_projection_n4097
discovery::inventory_workload::tests::privileged_inventory_attach_projection_n6530
discovery::inventory_workload::tests::privileged_inventory_attach_projection_n8192
# D4 file-identity qualifying cells: ext4 inode-reuse confirmation
# parity (own loop ext4 per row) and overlay xino backend parity (own
# loop layers per mode). The copy-up RED reproducer stays skipped below:
# it fails by design and never qualifies.
discovery::sweep_attribution::tests::d4_ext4_cells::privileged_d4_ext4_inode_reuse_confirmation_parity
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_d4_overlay_xino_backend_parity
discovery::sweep_attribution::tests::privileged_a_data_only_mapper_of_an_identity_key_is_never_attributed_on_ext4
discovery::sweep_attribution::tests::privileged_an_unmapped_file_whose_inode_is_reused_is_never_attributed_on_ext4
events::runtime_tests::real_retained_consumer_keeps_one_cursor_across_all_drains
events::runtime_tests::real_retained_discovery_consumer_owns_one_exact_map
events::runtime_tests::real_uretprobe_hazard_self_probe_reaches_a_verdict
# Task 6 C5.1 native inventory lane cells (production classic loop over owned
# inventory-ledger workloads; need gcc, softhsm2-util and SoftHSM2 at
# /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so; about 5-20 s each): --pid
# stamps + witnessed edge + no foreign caller, --system late dlopen, stop with
# a held call, SIGINT during activation, --system under 100 and 1,000 execs/s
# exec churn (C5.7; about 1-2 min). The churn cell is load-sensitive: its
# zero-loss check at 100 execs/s retries once, and is skipped with a printed
# reason only when both attempts started at load1 above 4 and lost at most 1%
# of the lifecycle records.
inventory::privileged_tests::privileged_native_lane_pid_lp64
inventory::privileged_tests::privileged_native_lane_sigint_during_extend_lp64
inventory::privileged_tests::privileged_native_lane_stop_held_call_unsettled_lp64
inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64
inventory::privileged_tests::privileged_native_lane_system_late_dlopen_lp64
# Task 6 C5.1 cell 4: A-then-B — a late second provider instance for a cached
# caller publishes exactly one first count, holds it across idle passes,
# then grows; ledger-exact finals. Prints C51_AB (about 20 s).
inventory::privileged_tests::privileged_native_lane_system_ab_first_count_lp64
# Owned provider retirement: A -> shared A/B -> A unload -> B recovery;
# independent phased call ledger and production diagnostic decisions.
inventory::privileged_tests::privileged_native_lane_pid_provider_retirement_diagnostics_lp64
# Task 6 C5.11: --system over 544 endpoints (8 mapped copies of SoftHSM2)
# retires closed under uprobe-multi (per-offset links may read unsettled);
# under auto on a kernel whose functional probe links uprobe-multi it must
# take it. Prints C511_SCALE (about 10-30 s).
inventory::privileged_tests::privileged_native_lane_system_many_endpoints_lp64
# Task 6 C5.3: the native lane under the interactive dashboard on a pty never
# read for 20 s (same workload needs; about 30 s). A loaded host may declare
# P11SCOPE_TEST_TIME_SCALE (default 1, at most 4, pass it through sudo
# env): it scales only this cell's 100 ms tick-gap bound and its pass
# floor. The runner refuses a value outside 1..4 and records a set one.
inventory::privileged_tests::privileged_native_lane_dashboard_slow_pty_lp64
# R1.4 live joint-finish cell: a real semantic lane over a SoftHSM2 ledger
# target drives the T14 finish driver from begin to Published to WoundDown
# (the M1/M3 arms unit tests cannot build a live machine for). Prints
# JOINT_LIVE lines.
inventory::privileged_tests::privileged_joint_driver_live_finish_begin_poll_wound_down_lp64
# R1.6 live Joint root cells: the production classic Session with Joint on
# over the owned live-joint provider workload (needs gcc, softhsm2-util and
# SoftHSM2; each runs its own System-scope capture, a few minutes). First
# birth through a held q1 to q2 and stop; absence and S1Only siblings
# beside a post-attach exec; promotion retiring A before B is admitted.
# Print JOINT_R16 lines.
inventory::privileged_tests::privileged_joint_first_birth_q2_and_stop_lp64
inventory::privileged_tests::privileged_joint_absence_and_s1only_siblings_lp64
inventory::privileged_tests::privileged_joint_promotion_a_to_b_lp64
# v0.5.0 headline end to end: inventory --system --manifest over a live
# SoftHSM2 ledger workload (gates its dlopen on the observer's pass 0
# publish, strictly post-attach) exits 0 with populated S1 edges
# (mechanisms and API results) or named route-loss gaps, plus the
# journal_unavailable S1 marker. Spawns a real observer binary:
# P11SCOPE_E2E_OBSERVER, else the p11scope sibling of the test
# binary. Prints MAN1_E2E lines (about a minute).
inventory::manifest_e2e_tests::privileged_inventory_system_manifest_e2e_softhsm_edges_lp64
# Typed counter readers: real anonymous native maps, with no program load,
# attach, external workload or opt-in object build required.
metrics::counter_reader::tests::counter_reader_native_maps_match_all_modes
metrics::counter_reader::tests::counter_reader_requires_exact_maps_and_health
)

# Feature-alternative load gates: exactly one exists per binary. Default
# builds carry the FULL refusal classifier; stub-object-attributes builds
# carry the stubbed load pin. The drift check tolerates a curated-but-absent
# member only when its complement is present in the binary; run mode
# executes whichever member the binary has, as a default-campaign cell.
ALTERNATIVE_TESTS=(
attach::tests::full_root_load_refusal_is_classified
attach::tests::stubbed_roots_load
)

# Long campaign cells: run only with --include-long.
LONG_TESTS=(
attach::instance_tests::privileged_instance_continuity_experiment_softhsm
attach::inventory::activation::privileged_tests::privileged_bench_overhead_detailed_calls
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n4097_lp64
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6530_lp64
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6531_lp64
attach::inventory::activation::privileged_tests::privileged_t7_inventory_n8192_boundary_lp64
attach::inventory::activation::privileged_tests::privileged_inventory_multi_n8192_prefix_lp64
attach::inventory::activation::privileged_tests::privileged_inventory_multi_n8193_refuses_lp64
# G21 default-ring wrap needs 658 changing observed passes per paired run
# (~22 min total) and the controller-verified prebuilt32-body fixture.
# Required acceptance is scheduled explicitly, outside the default short lane.
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_wrap_and_primary_parity_lp64
# G21 cell 3: the same paired schedule under unfiltered system capture
# (same fixture/seam, owned-caller validators, strict off/on parity).
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_system_diagnostics_wrap_and_primary_parity_lp64
# G21 live short controls: the source-matched 3-round startup probe and the
# real 3-round accelerated-cadence pilot (bounded 90 s each, same
# prebuilt32-object fixture/seam as the wrap pair they calibrate).
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_startup_probe_lp64
# G21 short full-transition pilot (C=32/S=4, PID cell, diagnostics
# enabled; bounded 540 s): settling, gap shapes vs the oracle, and footer
# production at default cadence. Makes no wrap claim.
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_transition_pilot_lp64
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_accelerated_pilot_lp64
# S cadence lanes: env-driven gate interval probe + default-pinned cost/control
# (declared-cadence split; same fixture/seam as the short controls).
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_gate_cadence_probe_lp64
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_default_cadence_control_lp64
# life-1 (OD34 cell 3.6, image half): 16,385 genuine process births spend
# the 16,384 image tickets; births past the budget are counted identity
# refusals. Expected ~1-3 min, live 1 child, bounded 10 min, quiet host.
discovery::engine::pressure_native_tests::image_quota_16385_births_are_counted_identity_refusals
)

# Static skips: external fixture/driver/env the script cannot provide.
SKIP_TESTS=(
attach::instance_tests::privileged_instance_cross_process_punch_hole_renews
attach::instance_tests::privileged_instance_routing_on_btrfs_tmpdir
attach::instance_tests::privileged_instance_small_state_lru_eviction_never_joins
attach::inventory::activation::privileged_tests::privileged_inventory_retirement_controlled_churn
discovery::engine::tests::lifecycle_manifest_helper_entrypoint
discovery::identity::tests::map_files_name_timing_per_thousand
discovery::scan::tests::maps_reuse_timing_per_thousand_reads
discovery::scan::tests::privileged_cross_device_same_inode_alias_is_refused_on_scan_path
discovery::sweep_attribution::tests::privileged_a_btrfs_collision_on_a_data_range_keeps_the_exec_proven_edge
discovery::sweep_attribution::tests::privileged_a_file_swapped_behind_an_identical_line_is_proved_as_the_new_file
discovery::sweep_attribution::tests::privileged_d4_btrfs_subvolume_collision_backend_parity
discovery::sweep_attribution::tests::privileged_d4_btrfs_same_line_remap_backend_parity
first_use_probe::native::system_capture_observer_facts
process::tests::pidfd_denial::pidfd_denial_helper
run::root_fence_runtime::actual_original_exit_delayed_first_admission_retires_pending
inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64
inventory::privileged_tests::privileged_identity_kernel_multipass_reuse_lp64
metrics::counter_reader::tests::counter_bank_session_old_return_survives_append_lp64
s1_tests::resource_probe::native_semantic_resource_final_probe
s1_tests::resource_probe::native_semantic_resource_registry_probe
semantics_edge::resource_tests::native_semantic_resource_probe
# T8 live256 episodes: documented known-failing repros (see reasons); they
# re-enter the runnable campaign once the lane-A runtime fix lands.
discovery::engine::pressure_native_tests::pressure_live256_genuine_episode_admits_late_then_head
discovery::engine::pressure_native_tests::pressure_live256_all_blocked_twin_refuses_once
discovery::sweep_attribution::tests::privileged_d4_btrfs_deleted_mapping_backend_parity
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_counts_growth_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_counts_growth_lp64
discovery::sweep_attribution::tests::privileged_d4_btrfs_hardlink_alias_backend_parity
discovery::sweep_attribution::tests::privileged_d4_btrfs_bind_alias_backend_parity
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_counts_growth_multi_lp64
discovery::sweep_attribution::tests::privileged_d4_btrfs_live_thread_private_files_backend_parity
discovery::sweep_attribution::tests::d4_thread_mapping_helper
metrics::counter_reader::tests::counter_bank_session_useful_8192_counts_growth_multi_lp64
metrics::counter_reader::tests::counter_engine_stages_first_512_counts_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_over_ceiling_refuses_atomically_lp64
metrics::counter_reader::tests::counter_start_raises_nofile_from_soft_1024_lp64
metrics::counter_reader::tests::counter_start_without_raise_refuses_fd_exhausted_from_soft_1024_lp64
metrics::counter_reader::tests::counter_collection_reads_live_and_terminal_lp64
discovery::sweep_attribution::tests::privileged_d4_btrfs_clone_without_files_backend_parity
discovery::sweep_attribution::tests::d4_clone_without_files_mapping_helper
discovery::sweep_attribution::tests::privileged_d4_btrfs_zombie_leader_single_survivor_backend_parity
discovery::sweep_attribution::tests::d4_zombie_single_survivor_mapping_helper
# D4 copy-up RED reproducer: fails by design (the post-copy-up D-C7-3
# re-edge stands), investigation target, never qualifies.
discovery::sweep_attribution::tests::d4_overlay_cells::overlay_copy_up_userspace_edge_absent
# TID-scoped nonleader anchor run (installs nothing live; strict BPF
# load): needs root with a live nonleader thread, run by hand.
attach::identity_iter::tests::privileged_identity_nonleader_anchor_installs_nothing
# Zombie survivor collision parity: needs root Btrfs disk TMPDIR and
# eligible BTF/task_vma identity, run by hand.
discovery::sweep_attribution::tests::d4_zombie_cells::privileged_d4_btrfs_zombie_leader_collision_and_dataonly_twins
# Cold zombie admission parity: needs root Btrfs disk TMPDIR and
# eligible BTF/task_vma identity, run by hand.
discovery::sweep_attribution::tests::d4_zombie_cells::privileged_d4_btrfs_zombie_cold_admission_backend_parity
# Kernel-positive population excludes watched anchors: needs root Btrfs
# disk TMPDIR and eligible BTF/task_vma identity, run by hand.
discovery::sweep_attribution::tests::d4_population_cells::privileged_d4_kernel_positive_population_excludes_anchors
attach::counter_banks::tests::counter_bank_mode_objects_load_lp64
metrics::counter_reader::tests::counter_bank_session_timing_old_return_survives_append_lp64
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_timestamps_growth_lp64
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_latency_growth_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_timestamps_growth_multi_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_latency_growth_multi_lp64
attach::tests::bpf_loop_probe_reports_helper_presence_on_live_kernel
attach::counter_banks::tests::counter_preparation_refuses_without_bpf_loop_on_old_kernels
metrics::counter_reader::tests::counter_bank_session_verifier_complexity_refuses_clean_lp64
# Engine-driven counter growth and stop cells (cgroup/system scopes, timing
# modes, Singles/Multi stop estimates): root with prebuilt growth fixtures.
metrics::counter_reader::tests::counter_engine_growth_cgroup_counts_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_system_counts_multi_lp64
metrics::counter_reader::tests::counter_singles_stop_prints_detach_estimate_lp64
metrics::counter_reader::tests::counter_multi_stop_prints_no_detach_estimate_lp64
metrics::counter_reader::tests::counter_singles_stop_second_signal_abandons_lp64
metrics::counter_reader::tests::counter_engine_growth_timestamps_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_latency_multi_lp64
# CLI-shaped counter captures (parsed argv, real policy, real profile loop
# to -o JSON, numbers equal to the workload ledger): root with prebuilt
# growth fixtures.
metrics::counter_reader::tests::counter_cli_profile_counts_matches_workload_ledger_lp64
metrics::counter_reader::tests::counter_cli_profile_timestamps_matches_workload_ledger_lp64
metrics::counter_reader::tests::counter_cli_profile_latency_matches_workload_ledger_lp64
metrics::counter_reader::tests::counter_cli_run_counts_with_owned_child_lp64
# Unprivileged system-population graph sizing: memory, drain and release
# are hard gates, the stop time is measured and disclosed (R-40).
discovery::engine::tests::collected_graph_peak_fits_pool_at_system_scale
)
SKIP_REASONS=(
"needs punch-hole support under TMPDIR (btrfs/ext4/xfs; tmpfs refuses); no BPF-independent probe: run by hand as root: TMPDIR=<hole-capable dir> <binary> --exact <path> --ignored"
"needs TMPDIR on btrfs (it asserts the statfs magic); no BPF; run by hand as root: TMPDIR=<btrfs dir> <binary> --exact <path> --ignored"
"needs a P11SCOPE_SMALL_STATE_MAPS=1 libtest build (the default binary fails its build gate by design); run by hand as root from that build with the variable set"
"needs an external barrier controller: P11SCOPE_I3A_RETIREMENT_MODE=worker|synchronous plus a root-owned 0700 CONTROL_DIR, a NONCE, and an external party to write the release file; no in-repo controller exists, so run once per mode by hand"
"private helper re-executed by DiscoveryLifecycleFixture with P11SCOPE_TEST_DISCOVERY_PROVIDER/MANIFEST; its own docs say it is not a separate passing test"
"unprivileged C7 A2 timing loop (indicative wall time, no pass/fail bar); not a campaign cell: run by hand with --exact <path> --ignored --test-threads=1 --nocapture, ideally from a --release build"
"unprivileged C7 A2 timing loop (indicative wall time, no pass/fail bar); not a campaign cell: run by hand with --exact <path> --ignored --test-threads=1 --nocapture, ideally from a --release build"
"needs a live root-owned target with two private cross-device mounts (same inode, distinct dev) plus P11SCOPE_ALIAS_COLLISION_PID/HINT/TARGET/HARDLINK"
"needs TMPDIR on btrfs (it creates two subvolumes there and asserts the filesystem); no BPF; run by hand as root: TMPDIR=<btrfs dir> <binary> --exact <path> --ignored"
"needs TMPDIR on btrfs (it creates two subvolumes there and asserts the filesystem); no BPF; run by hand as root: TMPDIR=<btrfs dir> <binary> --exact <path> --ignored"
"needs root Btrfs disk TMPDIR and eligible BTF/task_vma kernel identity; no compiler/provider fixture; run exact ignored test in an authorized BPF lane with --test-threads=1 --nocapture"
"needs root Btrfs disk TMPDIR and eligible BTF/task_vma kernel identity; actual same-line remap parity with held physical files; no compiler/provider fixture; run exact ignored test in an authorized BPF lane with --test-threads=1 --nocapture"
"needs a frozen supervisor config via P11SCOPE_FIRST_USE_PROBE_CONFIG plus an exclusive BPF lane; its verdict requires an external owned oracle"
"private seccomp helper re-executed by real_pidfd_denial_preserves_proc_identity_without_signal_authority with P11SCOPE_TEST_PIDFD_DENIAL_*; that unprivileged test is its only passing form"
"needs a separately reviewed native stage via P11SCOPE_ROOT_RUNTIME_STAGE (provider.so, driver, provider.json); the test documents no runtime skip"
"needs TMPDIR on btrfs (it asserts the statfs magic) plus a kernel-identity-capable host (BTF, task_iter pidfd); run by hand as root: TMPDIR=<btrfs dir> <binary> --exact <path> --ignored"
"needs TMPDIR on btrfs (it asserts the statfs magic) plus a kernel-identity-capable host (BTF, task_iter pidfd); run by hand as root: TMPDIR=<btrfs dir> <binary> --exact <path> --ignored"
"needs a default libtest build with embedded counter objects and explicitly prebuilt LP64 fixtures via P11SCOPE_COUNTER_BANK_FIXTURE_PROVIDER/P11SCOPE_COUNTER_BANK_FIXTURE_WORKLOAD; run the exact ignored test as root in an authorized BPF lane"
"requires explicit controller-granted host measurement; spawns bounded child probes for the final multi-profile large4096 registry measurement, so schedule under a separate authorized measurement plan"
"requires explicit controller-granted host measurement; spawns bounded child probes for the multi-profile large4096 registry measurement, so schedule under a separate authorized measurement plan"
"requires explicit controller-granted host measurement; spawns bounded reducer-profile probes with at most 32 edges per profile, so schedule under a separate authorized measurement plan"
"known-failing repro (doc Known limit 2026-10-19: lane-A runtime does not converge, the rotation stalls); rerun by hand as root after the runtime fix: <binary> --exact <path> --ignored --test-threads=1 --nocapture"
"known-failing repro (doc Known limit: same lane-A view-capacity stall, post-settle refusal asserts unreachable until the runtime fix); rerun by hand as root after the runtime fix: <binary> --exact <path> --ignored --test-threads=1 --nocapture"
"needs root Btrfs disk TMPDIR and eligible BTF/task_vma identity; actual before-unlink positive and deleted-mapping negative; no compiler/provider fixture; run exact ignored test in an authorized BPF lane"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; separate authorized 513-endpoint native admission after resource preflight"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; separate authorized 8192-endpoint native FD/memory admission after boundary pilot"
"needs root Btrfs disk TMPDIR and eligible task_vma/BTF for required actual hardlink alias kernel/userspace parity; run exact selector with --ignored --test-threads=1 on a matching prebuilt binary"
"needs root/CAP_SYS_ADMIN, private child mount namespaces, Btrfs disk TMPDIR and eligible task_vma/BTF; actual bind alias parity requires a separately admitted exact ignored run with unchanged parent mounts"
"needs the default prebuilt libtest with embedded V2 objects and growth provider/workload inputs; explicit Multi PID-filter capability and separately admitted 513-endpoint native FD/memory/cleanup qualification, preserving required Singles coverage"
"needs root/proc access, Btrfs disk TMPDIR and eligible task_vma/BTF; explicit live nonleader/shared-and-private FD-table parity with owned re-exec helpers, separately admitted exact ignored run"
"private entrypoint re-executed only by the owned live-thread/private-files parity fixture; missing owned configuration fails and this helper never qualifies independently"
"needs qualified Multi513 pilot, the default prebuilt libtest with embedded V2 objects and growth provider/workload inputs; separately admitted 8192-endpoint FD/memory/native qualification with unchanged ledger/N+1/cleanup/deadline assertions, preserving required Singles coverage"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; proven kernel Multi PID filtering and separately admitted Engine-driven first-512 native Multi staging"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; separately admitted Engine-driven growth to 8192 plus an atomic over-ceiling refusal with the prefix intact"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; a high hard RLIMIT_NOFILE and separately admitted Engine-driven Multi staging from a soft-1024 start"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; a high hard RLIMIT_NOFILE and authorized native BPF for the bypassed-preparation FD-exhaustion twin"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; proven kernel Multi PID filtering and separately admitted Engine-driven Multi staging for live and terminal collection"
"needs root/proc access, Btrfs disk TMPDIR, x86-64 raw clone support and eligible task_vma/BTF; actual CLONE_THREAD without CLONE_FILES attribution parity requires a separately admitted exact ignored run"
"private re-exec entrypoint for the owned literal-clone parity fixture; missing owned configuration fails and this helper never qualifies independently"
"needs root x86-64 LP64 Btrfs disk TMPDIR and eligible BTF/task_vma; required single-survivor zombie-leader positive baseline currently exposes an unqualified production path; run exact ignored test in a separately admitted native lane"
"private re-exec entrypoint for the owned single-survivor zombie fixture; missing owning socket/source fails and this helper never qualifies independently"
"RED by design (post-copy-up D-C7-3 re-edge stands; investigation target, never qualifies): run by hand as root to reproduce: <binary> --exact <path> --ignored --test-threads=1 --nocapture"
"needs root with a live nonleader thread for the TID-scoped anchor run (strict BPF load, installs nothing live); run the exact ignored test by hand as root in an authorized BPF lane with --test-threads=1 --nocapture"
"needs root Btrfs disk TMPDIR and eligible BTF/task_vma identity; zombie survivor collision parity; run the exact ignored test by hand as root in an authorized BPF lane with --test-threads=1 --nocapture"
"needs root Btrfs disk TMPDIR and eligible BTF/task_vma identity; cold zombie admission parity; run the exact ignored test by hand as root in an authorized BPF lane with --test-threads=1 --nocapture"
"needs root Btrfs disk TMPDIR and eligible BTF/task_vma identity; kernel-positive population excludes watched anchors; run the exact ignored test by hand as root in an authorized BPF lane with --test-threads=1 --nocapture"
"needs the default build with embedded counter objects; run exact --ignored as root in an authorized BPF lane with LP64 map/program load and uprobe_multi"
"needs a default libtest build with embedded counter objects and explicitly prebuilt LP64 fixtures via P11SCOPE_COUNTER_BANK_FIXTURE_PROVIDER/P11SCOPE_COUNTER_BANK_FIXTURE_WORKLOAD; runs counts/timestamps/latency held-return legs; run the exact ignored test as root in an authorized BPF lane"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; explicit Multi PID-filter capability and separately admitted 513-endpoint timestamps native staging"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; explicit Multi PID-filter capability and separately admitted 513-endpoint latency native staging"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; proven kernel Multi PID filtering and separately admitted 8192-endpoint timestamps native FD/memory admission after boundary pilot"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; proven kernel Multi PID filtering and separately admitted 8192-endpoint latency native FD/memory admission after boundary pilot"
"live-kernel BPF lane: reports bpf_loop helper presence without asserting it; run exact --ignored as root in an authorized BPF lane"
"pre-5.17 kernel lane: proves preparation refuses cleanly without the bpf_loop helper (passes vacuously on newer hosts); run exact --ignored as root on that kernel lane"
"6.1 E2BIG lane: proves the verifier-budget refusal maps before lifecycle without activating; run exact --ignored as root on the 6.1 verifier-budget host"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; a cgroup v2 hierarchy, proven kernel Multi PID filtering and separately admitted Engine-driven cgroup growth to 8192 plus an atomic over-ceiling refusal"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; proven kernel Multi PID filtering and separately admitted Engine-driven system growth to 8192 plus an atomic over-ceiling refusal"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; separately admitted Engine-driven Singles growth to 8192, then a stop that prints the one-at-a-time detach estimate"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; proven kernel Multi PID filtering and a separately admitted Engine-driven Multi stop that prints no one-at-a-time detach estimate"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; separately admitted Engine-driven Singles staging; a second stop signal abandons the counter detach with the typed interruption"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; proven kernel Multi PID filtering and separately admitted Engine-driven timestamps growth to 8192 plus an atomic over-ceiling refusal"
"needs the default build with embedded V2 objects and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER/_WORKLOAD; proven kernel Multi PID filtering and separately admitted Engine-driven latency growth to 8192 plus an atomic over-ceiling refusal"
"needs root and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER and P11SCOPE_COUNTER_GROWTH_FIXTURE_WORKLOAD; run the exact ignored test by hand as root with TMPDIR, fixtures and timeout as in the evidence run"
"needs root and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER and P11SCOPE_COUNTER_GROWTH_FIXTURE_WORKLOAD; run the exact ignored test by hand as root with TMPDIR, fixtures and timeout as in the evidence run"
"needs root and prebuilt LP64 growth provider/workload via P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER and P11SCOPE_COUNTER_GROWTH_FIXTURE_WORKLOAD; run the exact ignored test by hand as root with TMPDIR, fixtures and timeout as in the evidence run"
"needs root with no fixture (the owned child maps no provider); run the exact ignored test by hand as root with TMPDIR and CARGO_TARGET_TMPDIR as in the evidence run"
"unprivileged system-population graph sizing (4096 pin files plus 16384 native links; memory, drain and release asserts gate, the stop time is measured, not gated); not a campaign cell: run by hand with --exact <path> --ignored --test-threads=1 --nocapture on a host whose hard RLIMIT_NOFILE fits the population"
)

# Wide-Detailed campaign: the ignored tests that exist only in a
# --features wide-detailed-2112 libtest binary — the four wide-gated fns
# plus the five wide-gated detailed_sweep_test! expansions (source order).
# Selected only with --wide-detailed-2112 in run or --list mode; the
# default campaign's exact-cover check cannot see these tests because a
# default binary does not contain them.
WIDE_DETAILED_2112_TESTS=(
attach::inventory::activation::privileged_tests::privileged_task4_detailed_2112_lp64
attach::inventory::activation::privileged_tests::privileged_task4_detailed_n511_lp64
attach::inventory::activation::privileged_tests::privileged_task4_detailed_n512_lp64
attach::inventory::activation::privileged_tests::privileged_task4_detailed_n513_lp64
attach::inventory::activation::privileged_tests::privileged_task4_detailed_n2048_lp64
attach::inventory::activation::privileged_tests::privileged_task4_detailed_n2049_lp64
attach::inventory::activation::privileged_tests::privileged_task4_highslot_2048_worker_exit
attach::inventory::activation::privileged_tests::privileged_task4_highslot_2048_nonleader_exec
attach::inventory::activation::privileged_tests::privileged_detailed_2112_stop_publishes_before_cleanup
)

# Counter-build curation (checker-enforced, never executed by this
# script): the ignored integration tests that exist only in dedicated
# counter builds. COUNTER_ARTIFACTS_TESTS members run with
# P11SCOPE_COUNTER_ARTIFACTS=1 in their own build with --ignored --exact
# (static object analysis). Selectors are `file:path` like
# INTEGRATION_TESTS. COUNTER_BANK_PROOF_TESTS is empty: the counter bank
# objects are built and embedded by default, its route and mutation cells
# run in the ordinary suite and the BTF/map/program-load cell is curated
# in INTEGRATION_TESTS.
# shellcheck disable=SC2034  # read by scripts/check-ignored-tests.py, by design
COUNTER_BANK_PROOF_TESTS=(
# (none: no ignored test needs a separate counter bank build)
)
# shellcheck disable=SC2034  # read by scripts/check-ignored-tests.py, by design
COUNTER_ARTIFACTS_TESTS=(
tests/object_producer_activation.rs:counter_artifact_modes_have_exact_maps_and_root_work
tests/object_producer_activation.rs:counter_artifact_mutations_are_causally_rejected
)

# Integration-test curation: `tests/<target>.rs:<exact test path>` entries
# for the ignored integration tests (each target builds one binary named
# after the file stem). Verified, never executed, by --list-integration
# against a directory of built test binaries: every entry must resolve to
# exactly one binary and select exactly one ignored test there.
INTEGRATION_TESTS=(
tests/entry_object_paired.rs:paired_default_and_unsafe_objects_satisfy_the_entry_contract
tests/exec_task_continuity.rs:exec_task_core_shapes_kernel_load_without_attachment
tests/identity_iter_standalone.rs:identity_loader_strict_gate_requires_btf_and_both_programs
tests/inventory_identity.rs:d4_btrfs_scan_backends_match_exact_fixture_population
tests/inventory_identity.rs:kernel_identity_positive_cell_rejects_refusal
tests/object_producer_activation.rs:counter_bank_btf_maps_and_programs_load
tests/run_abandon_report.rs:second_sigint_during_teardown_publishes_truthful_report_and_exits_130
)

usage() {
    cat <<EOF
usage: $PROG LIB_TEST_BINARY OUTDIR [--include-long] [SELECTOR...]
       $PROG LIB_TEST_BINARY OUTDIR --wide-detailed-2112 [SELECTOR...]
       $PROG --list LIB_TEST_BINARY
       $PROG --list --wide-detailed-2112 LIB_TEST_BINARY
       $PROG --list-integration TEST_BINARY_DIR
       $PROG --help

Run the curated privileged (ignored) p11scope lib tests, one at a time.
SELECTORs are literal substrings matched against full test paths; a test
runs when any SELECTOR matches (no SELECTOR runs the whole campaign).
--include-long additionally runs the long campaign cells.
--wide-detailed-2112 runs only the wide-Detailed campaign cells (a binary
built with --features wide-detailed-2112 is required; any other binary
is refused). It cannot be combined with --include-long.
--list prints the curated default, long, and skipped-with-reason lists and
verifies them against the binary, without running anything. With
--wide-detailed-2112 it prints and verifies only the wide-Detailed list.
--list-integration prints the curated integration-test selectors and
verifies each against the built test binaries in TEST_BINARY_DIR
(exactly one binary and exactly one selected test per entry), without
running anything.
EOF
}

# Print the binary's ignored-test full paths in listed order, keeping
# duplicates, so exact-count checks can spot duplicated listings.
binary_ignored_list_raw() {
    "$1" --list --ignored --format terse 2>/dev/null \
        | sed -e 's/:[[:space:]]*test$//' -e '/^[[:space:]]*$/d'
}

# Print the binary's ignored-test full paths, sorted unique, one per line.
binary_ignored_list() {
    binary_ignored_list_raw "$1" | sort -u
}

# True when the binary's ignored set contains the exact full path.
binary_has_ignored() {
    binary_ignored_list "$1" | grep -qxF "$2"
}

# Static skips pair each test with its reason by index. A length mismatch
# would print wrong reasons and, under `set -u` inside a `| tee` pipeline,
# fail only the forked subshell while the loop reports phantoms and exits 0.
# Refuse loudly before any print or selection touches the arrays.
check_skip_alignment() {
    if [ "${#SKIP_TESTS[@]}" -ne "${#SKIP_REASONS[@]}" ]; then
        echo "$PROG: SKIP_TESTS (${#SKIP_TESTS[@]}) and SKIP_REASONS (${#SKIP_REASONS[@]}) differ in length" >&2
        return 1
    fi
}

# Compare curation against the binary. Prints drift details to stderr and
# returns 1 on any mismatch, so new tests cannot be silently dropped.
check_curation() {
    check_skip_alignment || return 1
    local bin=$1 workdir bin_list cur_list missing_bin missing_cur
    workdir=$(mktemp -d) || { echo "$PROG: cannot create temp dir" >&2; return 1; }
    bin_list=$workdir/bin.txt
    cur_list=$workdir/cur.txt
    if ! binary_ignored_list "$bin" >"$bin_list"; then
        echo "$PROG: cannot list ignored tests in $bin" >&2
        rm -rf "$workdir"
        return 1
    fi
    {
        printf '%s\n' "${DEFAULT_TESTS[@]}"
        printf '%s\n' "${ALTERNATIVE_TESTS[@]}"
        printf '%s\n' "${LONG_TESTS[@]}"
        printf '%s\n' "${SKIP_TESTS[@]}"
    } | sort -u >"$cur_list"
    missing_bin=$(comm -13 "$bin_list" "$cur_list" || true)
    missing_cur=$(comm -23 "$bin_list" "$cur_list" || true)
    # Feature-alternative load gates: tolerate a curated-but-absent member
    # only when exactly one of the pair is present in the binary. A removed
    # or renamed member still fails: zero present keeps the absent member in
    # missing_bin, and a renamed member lands in missing_cur, never tolerated.
    if [ -n "$missing_bin" ]; then
        local alt_present=0 aname rest=
        for aname in "${ALTERNATIVE_TESTS[@]}"; do
            if grep -qxF "$aname" "$bin_list"; then alt_present=$((alt_present+1)); fi
        done
        while IFS= read -r aname; do
            [ -z "$aname" ] && continue
            local is_alt=0 alt
            for alt in "${ALTERNATIVE_TESTS[@]}"; do
                [ "$aname" = "$alt" ] && is_alt=1
            done
            if [ "$is_alt" -eq 1 ] && [ "$alt_present" -eq 1 ]; then continue; fi
            if [ -z "$rest" ]; then rest=$aname; else rest="$rest
$aname"; fi
        done <<<"$missing_bin"
        missing_bin=$rest
    fi
    rm -rf "$workdir"
    if [ -n "$missing_bin" ] || [ -n "$missing_cur" ]; then
        local -a names
        {
            echo "$PROG: curation drift against $bin"
            [ -n "$missing_bin" ] && {
                echo "curated but absent from the binary (renamed/removed?):"
                mapfile -t names <<<"$missing_bin"
                printf '  %s\n' "${names[@]}"
            }
            [ -n "$missing_cur" ] && {
                echo "ignored in the binary but not curated (new test?):"
                mapfile -t names <<<"$missing_cur"
                printf '  %s\n' "${names[@]}"
            }
        } >&2
        return 1
    fi
    return 0
}

# Compare the wide-Detailed curation against the binary. Every member must
# select exactly one ignored test; a default binary (or any binary missing
# a member) is refused with the missing names, never run empty.
check_wide_curation() {
    local bin=$1 bin_list name count missing=() multi=()
    # Count the raw listing: a deduped list could never select more
    # than one test per member, hiding duplicated listings.
    if ! bin_list=$(binary_ignored_list_raw "$bin"); then
        echo "$PROG: cannot list ignored tests in $bin" >&2
        return 1
    fi
    for name in "${WIDE_DETAILED_2112_TESTS[@]}"; do
        count=$(printf '%s\n' "$bin_list" | grep -cxF "$name" || true)
        if [ "$count" -eq 0 ]; then
            missing+=("$name")
        elif [ "$count" -ne 1 ]; then
            multi+=("$name")
        fi
    done
    if [ "${#missing[@]}" -ne 0 ] || [ "${#multi[@]}" -ne 0 ]; then
        {
            echo "$PROG: wide-detailed-2112 curation refused against $bin"
            if [ "${#missing[@]}" -ne 0 ]; then
                echo "curated but absent from the binary (a default build lacks these; rebuild with --features wide-detailed-2112):"
                printf '  %s\n' "${missing[@]}"
            fi
            if [ "${#multi[@]}" -ne 0 ]; then
                echo "selected more than one test (duplicated listing?):"
                printf '  %s\n' "${multi[@]}"
            fi
        } >&2
        return 1
    fi
    return 0
}

# --list mode: curated lists plus a verification footer. Unprivileged-safe.
list_mode() {
    local bin name i wide=0
    if [ "${1:-}" = "--wide-detailed-2112" ]; then wide=1; shift; fi
    [ $# -eq 1 ] || { usage >&2; return 2; }
    bin=$1
    [ -x "$bin" ] || { echo "$PROG: not an executable test binary: $bin" >&2; return 1; }
    check_skip_alignment || return 1
    if [ "$wide" -eq 1 ]; then
        echo "wide-detailed-2112 (${#WIDE_DETAILED_2112_TESTS[@]})"
        printf '%s\n' "${WIDE_DETAILED_2112_TESTS[@]}"
        if check_wide_curation "$bin"; then
            echo "verify: wide-detailed-2112 curation matches the binary (${#WIDE_DETAILED_2112_TESTS[@]} tests)"
            return 0
        fi
        return 1
    fi
    # The receipt stays per-binary exact: resolve the feature-alternative
    # load gate against this binary and list the present member (if any) as
    # a default-campaign cell. The drift check below still refuses a binary
    # with zero or two members.
    default_all=("${DEFAULT_TESTS[@]}")
    for name in "${ALTERNATIVE_TESTS[@]}"; do
        if binary_has_ignored "$bin" "$name"; then
            default_all+=("$name")
        fi
    done
    echo "default (${#default_all[@]})"
    for name in "${default_all[@]}"; do
        case $name in
            *_ia32) echo "$name :: preflight: host cc must compile -m32" ;;
            *broad_p11kit_admission_arithmetic)
                echo "$name :: preflight: host python3 must load libp11-kit.so.0" ;;
            *_never_attributed_on_ext4)
                echo "$name :: preflight: host must mkfs.ext4 and loop-mount an ext4 image" ;;
            *d4_ext4_cells::privileged_d4_ext4_inode_reuse_confirmation_parity)
                echo "$name :: preflight: host must mkfs.ext4 and loop-mount an ext4 image" ;;
            *) echo "$name" ;;
        esac
    done
    echo "long (${#LONG_TESTS[@]}, --include-long only)"
    printf '%s\n' "${LONG_TESTS[@]}"
    echo "skipped (${#SKIP_TESTS[@]})"
    for i in "${!SKIP_TESTS[@]}"; do
        echo "${SKIP_TESTS[$i]} :: ${SKIP_REASONS[$i]}"
    done
    if check_curation "$bin"; then
        echo "verify: curation matches the binary ($(( ${#default_all[@]} + ${#LONG_TESTS[@]} + ${#SKIP_TESTS[@]} )) tests)"
        return 0
    fi
    return 1
}

# --list-integration mode: print the curated integration selectors and
# verify each against the built test binaries in the directory. Every
# entry must resolve to exactly one binary (no missing or ambiguous
# stem) and select exactly one ignored test there; anything else is
# refused. Unprivileged-safe; verifies only, never executes.
list_integration_mode() {
    local depsdir entry file path stem bin bin_list count candidates failed=()
    [ $# -eq 1 ] || { usage >&2; return 2; }
    depsdir=$1
    [ -d "$depsdir" ] || { echo "$PROG: not a directory: $depsdir" >&2; return 1; }
    for entry in "${INTEGRATION_TESTS[@]}"; do
        file=${entry%%:*}
        path=${entry#*:}
        stem=$(basename "$file" .rs)
        candidates=$(find "$depsdir" -maxdepth 1 -type f -executable \
            -name "$stem-*" ! -name "*.*" -print | sort)
        if [ -z "$candidates" ]; then
            failed+=("$entry :: no test binary $stem-* in $depsdir")
            continue
        fi
        if [ "$(printf '%s\n' "$candidates" | wc -l)" -ne 1 ]; then
            failed+=("$entry :: more than one test binary matches $stem-* in $depsdir (stale rebuild?)")
            continue
        fi
        bin=$candidates
        # Count the raw listing: a deduped list could never select more
        # than one test per entry, hiding duplicated listings.
        if ! bin_list=$(binary_ignored_list_raw "$bin"); then
            failed+=("$entry :: cannot list ignored tests in $bin")
            continue
        fi
        count=$(printf '%s\n' "$bin_list" | grep -cxF "$path" || true)
        if [ "$count" -ne 1 ]; then
            failed+=("$entry :: selects $count tests in $bin (expected exactly 1)")
        fi
    done
    echo "integration (${#INTEGRATION_TESTS[@]})"
    printf '%s\n' "${INTEGRATION_TESTS[@]}"
    if [ "${#failed[@]}" -ne 0 ]; then
        {
            echo "$PROG: integration curation refused against $depsdir"
            printf '  %s\n' "${failed[@]}"
        } >&2
        return 1
    fi
    echo "verify: integration curation selects exactly one test per entry (${#INTEGRATION_TESTS[@]} entries)"
    return 0
}

# SELECTORS is the global selector list. selected() returns 0 when $1
# matches any selector (literal substring), or when there are no selectors.
SELECTORS=()
selected() {
    local name=$1 sel
    if [ "${#SELECTORS[@]}" -eq 0 ]; then
        return 0
    fi
    for sel in "${SELECTORS[@]}"; do
        case $name in
            *"$sel"*) return 0 ;;
        esac
    done
    return 1
}

main() {
    local bin outdir include_long=0 wide=0
    local selected_runnable=() selected_skipped=()
    local arg name i pass=0 fail=0 skipped=0 seq=0
    local tmpdir logdir eviddir results log evdir short start end seconds rc
    local result_line verdict m32_ok=0 p11kit_ok=0 need_m32=0 need_p11kit=0
    local need_ext4loop=0 ext4loop_skip=

    if [ $# -eq 0 ]; then
        usage >&2
        return 2
    fi
    case $1 in
        --list) shift; list_mode "$@"; return $? ;;
        --list-integration) shift; list_integration_mode "$@"; return $? ;;
        -h|--help) usage; return 0 ;;
    esac
    if [ $# -lt 2 ]; then
        usage >&2
        return 2
    fi
    bin=$1
    outdir=$2
    shift 2
    for arg in "$@"; do
        case $arg in
            --include-long) include_long=1 ;;
            --wide-detailed-2112) wide=1 ;;
            --*) echo "$PROG: unknown option: $arg" >&2; usage >&2; return 2 ;;
            *) SELECTORS+=("$arg") ;;
        esac
    done
    if [ "$wide" -eq 1 ] && [ "$include_long" -eq 1 ]; then
        echo "$PROG: --wide-detailed-2112 selects only the wide campaign; --include-long does not apply" >&2
        return 2
    fi

    if [ "$(id -u)" -ne 0 ]; then
        echo "$PROG: must be run as root (this campaign loads BPF)" >&2
        return 64
    fi
    [ -x "$bin" ] || { echo "$PROG: not an executable test binary: $bin" >&2; return 1; }

    # Resolve before cd-ing to the repo root so relative paths keep working.
    bin=$(CDPATH='' cd "$(dirname "$bin")" && pwd)/$(basename "$bin")
    mkdir -p "$outdir" || return 1
    outdir=$(CDPATH='' cd "$outdir" && pwd) || return 1

    # Fail fast when the curation no longer covers the binary exactly.
    if [ "$wide" -eq 1 ]; then
        check_wide_curation "$bin" || return 1
    else
        check_curation "$bin" || return 1
    fi

    # Narrow the campaign, preserving curated order and de-duplicating.
    if [ "$wide" -eq 1 ]; then
        for name in "${WIDE_DETAILED_2112_TESTS[@]}"; do
            if selected "$name"; then
                selected_runnable+=("$name")
            fi
        done
    else
        for name in "${DEFAULT_TESTS[@]}"; do
            if selected "$name"; then
                selected_runnable+=("$name")
            fi
        done
        # Feature-alternative load gate: run whichever member this binary has.
        for name in "${ALTERNATIVE_TESTS[@]}"; do
            if binary_has_ignored "$bin" "$name" && selected "$name"; then
                selected_runnable+=("$name")
            fi
        done
        if [ "$include_long" -eq 1 ]; then
            for name in "${LONG_TESTS[@]}"; do
                if selected "$name"; then
                    selected_runnable+=("$name")
                fi
            done
        fi
        for i in "${!SKIP_TESTS[@]}"; do
            if selected "${SKIP_TESTS[$i]}"; then
                selected_skipped+=("$i")
            fi
        done
    fi
    # Every SELECTOR must match at least one curated test.
    for arg in ${SELECTORS[@]+"${SELECTORS[@]}"}; do
        local matched=0 candidate
        if [ "$wide" -eq 1 ]; then
            for candidate in "${WIDE_DETAILED_2112_TESTS[@]}"; do
                case $candidate in *"$arg"*) matched=1; break ;; esac
            done
        else
            for candidate in "${DEFAULT_TESTS[@]}" "${ALTERNATIVE_TESTS[@]}" "${LONG_TESTS[@]}" "${SKIP_TESTS[@]}"; do
                case $candidate in *"$arg"*) matched=1; break ;; esac
            done
        fi
        if [ "$matched" -eq 0 ]; then
            echo "$PROG: selector matches no curated test: $arg" >&2
            return 1
        fi
        if [ "$wide" -eq 0 ] && [ "$include_long" -eq 0 ]; then
            for candidate in "${LONG_TESTS[@]}"; do
                case $candidate in
                    *"$arg"*)
                        echo "$PROG: note: '$arg' matches --include-long tests, skipped without the flag" >&2
                        break
                        ;;
                esac
            done
        fi
    done

    tmpdir=$outdir/tmp
    logdir=$outdir/logs
    eviddir=$outdir/evidence
    results=$outdir/results.txt
    mkdir -p "$tmpdir" "$logdir" "$eviddir" || return 1
    chmod 0700 "$tmpdir" || return 1
    export TMPDIR=$tmpdir

    if ! ulimit -n 65536 2>/dev/null; then
        echo "$PROG: cannot raise RLIMIT_NOFILE to 65536" >&2
        return 1
    fi
    local nofile
    nofile=$(ulimit -n)
    if [ "$nofile" != "unlimited" ] && [ "$nofile" -lt 65536 ]; then
        echo "$PROG: RLIMIT_NOFILE stuck at $nofile, need 65536" >&2
        return 1
    fi

    # Runtime preflights for external driver and host dependencies. A failed
    # probe records SKIP with a reason instead of a false FAIL.
    for name in ${selected_runnable[@]+"${selected_runnable[@]}"}; do
        case $name in
            *_ia32) need_m32=1 ;;
            *broad_p11kit_admission_arithmetic) need_p11kit=1 ;;
            *_never_attributed_on_ext4) need_ext4loop=1 ;;
            *d4_ext4_cells::privileged_d4_ext4_inode_reuse_confirmation_parity) need_ext4loop=1 ;;
        esac
    done
    if [ "$need_m32" -eq 1 ]; then
        if printf 'int main(void){return 0;}\n' >"$tmpdir/m32-probe.c" \
            && cc -m32 "$tmpdir/m32-probe.c" -o "$tmpdir/m32-probe" 2>/dev/null; then
            m32_ok=1
        fi
    fi
    if [ "$need_p11kit" -eq 1 ]; then
        if command -v python3 >/dev/null 2>&1 \
            && python3 -c "import ctypes; ctypes.CDLL('libp11-kit.so.0')" 2>/dev/null; then
            p11kit_ok=1
        fi
    fi

    # The ext4 inode-reuse cell needs mkfs.ext4 and a loop-mounted ext4.
    # Probe exactly that (make, loop-mount and unmount a small image); the
    # reason names the missing piece. A host that can do it runs the test,
    # which then fails only on a real regression.
    if [ "$need_ext4loop" -eq 1 ]; then
        local probe_img=$tmpdir/ext4-probe.img probe_mnt=$tmpdir/ext4-probe.mnt
        if ! command -v mkfs.ext4 >/dev/null 2>&1; then
            ext4loop_skip="mkfs.ext4 not found (install e2fsprogs)"
        elif ! truncate -s 8M "$probe_img" 2>/dev/null \
            || ! mkfs.ext4 -q -F "$probe_img" >/dev/null 2>&1; then
            ext4loop_skip="mkfs.ext4 could not make a probe image"
        elif ! mkdir -p "$probe_mnt" \
            || ! mount -o loop "$probe_img" "$probe_mnt" >/dev/null 2>&1; then
            ext4loop_skip="cannot loop-mount ext4 (no loop device or no ext4 in this kernel)"
        else
            umount "$probe_mnt" 2>/dev/null || umount -l "$probe_mnt" 2>/dev/null
        fi
        rm -rf "$probe_img" "$probe_mnt"
    fi

    # Opt-in tolerances are declared in the results, never applied silently.
    if [ -n "${P11SCOPE_TEST_TIME_SCALE:-}" ] \
        && ! awk -v s="$P11SCOPE_TEST_TIME_SCALE" \
            'BEGIN { exit !(s ~ /^[0-9]+([.][0-9]+)?$/ && s >= 1 && s <= 4) }'; then
        echo "$PROG: P11SCOPE_TEST_TIME_SCALE=$P11SCOPE_TEST_TIME_SCALE: must be a number from 1 to 4" >&2
        return 2
    fi
    {
        echo "# $PROG run: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# binary: $bin"
        echo "# include_long: $include_long"
        echo "# wide_detailed_2112: $wide"
        echo "# selectors: ${SELECTORS[*]:-<none>}"
        if [ -n "${P11SCOPE_PRIV_LIFECYCLE_LOSS:-}" ]; then
            echo "# opt-in: P11SCOPE_PRIV_LIFECYCLE_LOSS=$P11SCOPE_PRIV_LIFECYCLE_LOSS"
        fi
        if [ -n "${P11SCOPE_TEST_TIME_SCALE:-}" ]; then
            echo "# opt-in: P11SCOPE_TEST_TIME_SCALE=$P11SCOPE_TEST_TIME_SCALE"
        fi
    } >"$results"
    grep '^# opt-in: ' "$results" >&2 || true

    cd "$REPO_ROOT" || return 1

    # Static skips among the selection are recorded, never silently dropped.
    # The `| tee` pipeline forks the expansion into a subshell where `set -u`
    # cannot stop the loop, so a failed print must fail loudly here instead
    # of counting phantoms toward a lying SUMMARY.
    for i in ${selected_skipped[@]+"${selected_skipped[@]}"}; do
        echo "SKIP ${SKIP_TESTS[$i]} :: ${SKIP_REASONS[$i]}" | tee -a "$results"
        if [ "${PIPESTATUS[0]}" -ne 0 ]; then
            echo "$PROG: static skip print failed for index $i" >&2
            return 1
        fi
        skipped=$((skipped + 1))
    done

    for name in ${selected_runnable[@]+"${selected_runnable[@]}"}; do
        case $name in
            *_ia32)
                if [ "$m32_ok" -eq 0 ]; then
                    echo "SKIP $name :: host cc -m32 probe failed (ia32 multilib unavailable)" | tee -a "$results"
                    skipped=$((skipped + 1))
                    continue
                fi
                ;;
            *broad_p11kit_admission_arithmetic)
                if [ "$p11kit_ok" -eq 0 ]; then
                    echo "SKIP $name :: host python3 cannot load libp11-kit.so.0" | tee -a "$results"
                    skipped=$((skipped + 1))
                    continue
                fi
                ;;
            *_never_attributed_on_ext4)
                if [ -n "$ext4loop_skip" ]; then
                    echo "SKIP $name :: $ext4loop_skip" | tee -a "$results"
                    skipped=$((skipped + 1))
                    continue
                fi
                ;;
        esac
        short=${name##*::}
        log=$logdir/$short.log
        evdir=$eviddir/$seq-$short
        mkdir -p "$evdir" || { echo "$PROG: cannot create $evdir" >&2; return 1; }
        echo "RUN $name [case_index=$seq]"
        start=$(date +%s)
        P11SCOPE_TASK4_EVIDENCE_DIR=$evdir P11SCOPE_TASK4_CASE_INDEX=$seq \
            "$bin" --exact "$name" --ignored --test-threads=1 --nocapture \
            >"$log" 2>&1
        rc=$?
        end=$(date +%s)
        seconds=$((end - start))
        seq=$((seq + 1))
        result_line=$(command grep -F 'test result:' "$log" | tail -n 1 || true)
        [ -n "$result_line" ] || result_line="(no test result line)"
        verdict=FAIL
        if [ "$rc" -eq 0 ] \
            && command grep -qF 'test result: ok. 1 passed' "$log"; then
            verdict=PASS
        fi
        if [ "$verdict" = "PASS" ]; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
        fi
        echo "$verdict $name rc=$rc seconds=$seconds :: $result_line" | tee -a "$results"
    done

    echo "SUMMARY pass=$pass fail=$fail skipped=$skipped" | tee -a "$results"
    [ "$fail" -eq 0 ]
}

main "$@"
