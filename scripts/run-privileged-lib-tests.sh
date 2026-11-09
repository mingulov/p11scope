#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Reproducible runner for the privileged (ignored) p11scope lib tests.
#
# Usage:
#   scripts/run-privileged-lib-tests.sh LIB_TEST_BINARY OUTDIR [GROUP-FLAG...] [SELECTOR...]
#   scripts/run-privileged-lib-tests.sh --list LIB_TEST_BINARY
#   scripts/run-privileged-lib-tests.sh --list-integration TEST_BINARY_DIR
#
# Group flags (each runs its group plus the default campaign, narrowed by
# any SELECTORs): --include-long, --include-btrfs, --include-overlay,
# --include-expected-failures.
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
#   P11SCOPE_COUNTER_BANK_FIXTURE_PROVIDER / _WORKLOAD and
#     P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER / _WORKLOAD: the runner
#     builds tests/fixtures/counter-banks.c and counter-bank-growth.c
#     with cc (scripts/ci/build-counter-fixtures.sh) and points these at
#     the provider/driver pairs for the counter-bank default cells.
#     Without cc those cells SKIP with a reason instead of failing.
#   P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR: the runner builds the 97
#     prebuilt32-object inputs (scripts/ci/build-wrap-fixtures.sh) and
#     points this at them for the diagnostics-wrap long cells. An
#     already-set directory (a controller-delivered verified prebuilt)
#     is used as is and nothing is rebuilt. Without cc or python3
#     those cells SKIP with a reason instead of failing.
#   CARGO_TARGET_TMPDIR: the runner points this at an
#     owned-child-writable dir under OUTDIR for the owned-child counter
#     run cell only; every other cell inherits the ambient value.
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
# Dual-outcome cells print one `P11SCOPE_CELL_BRANCH=<name>` line for the
# arm they took; the runner appends ` branch=<name>` to that cell's
# results.txt line (after the test-result text). Judges match the branch
# against a per-host expectation table. The last branch line wins; a
# malformed value is recorded as `branch=INVALID`.
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
# Btrfs group (--include-btrfs): the 16 cells that assert TMPDIR is on
# btrfs. The runner loop-mounts one btrfs image for the group
# (scripts/ci/prepare-btrfs-tmpdir.sh), runs those cells with TMPDIR
# pointed at the mount, and unmounts it afterwards. Without mkfs.btrfs
# (or loop/btrfs support) the cells SKIP with a reason. The same mount
# is also provided to the two btrfs-needing expected-failure cells so
# their XFAIL reflects the named gate failure.
#
# Expected-failure group (--include-expected-failures): known-failing
# reproducers. A failing cell records XFAIL (counts as passed); a passing
# cell records XPASS and fails the run, so a silent fix gets noticed and
# the cell can be promoted to the runnable campaign.
#
# Curation: default tests run normally, the btrfs/long/
# expected-failure groups only with their --include-* flag, and static
# skips require their documented external prerequisites, with a reason.
# The feature-alternative load gates contribute exactly one member
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
# Async control value flags: an owned 3.2 stub provider driven through a
# real Session per ABI; an OK C_AsyncGetID with a NULL output sets the
# unreadable-value flag, a readable GetID/Join id carries no flag.
attach::async_value_flags_tests::privileged_async_getid_null_output_sets_value_unreadable_ia32
attach::async_value_flags_tests::privileged_async_getid_null_output_sets_value_unreadable_lp64
attach::async_value_flags_tests::privileged_async_getid_valid_output_reads_id_ia32
attach::async_value_flags_tests::privileged_async_getid_valid_output_reads_id_lp64
attach::async_value_flags_tests::privileged_async_join_reads_id_and_completes_ia32
attach::async_value_flags_tests::privileged_async_join_reads_id_and_completes_lp64
# W3-2 kernel-identity gates: WRONLY EPERM, the section 6.5 functional
# probe (hardlink-match vs copy-NONE plus the stale-generation phase),
# its nested-pidns twin (kind observers run nested), the whole-system
# shape cell, and the anchor-handle validator.
attach::identity_iter::tests::anchor_maps_validate_real_handles
attach::identity_iter::tests::functional_probe_proves_hardlink_match_and_copy_none
attach::identity_iter::tests::functional_probe_passes_in_nested_pid_namespace
attach::identity_iter::tests::whole_system_run_covers_all_children
attach::identity_iter::tests::wronly_anchor_fds_refuse_reads_with_eperm
# 5.15 identity-denial cell: real BTF named-fix refusal through the
# production sink with zero bpf() syscalls; dual-outcome by running
# kernel (denied on 5.15, eligible elsewhere), lane-classified.
inspect_system::privileged_tests::privileged_identity_515_denial_is_disclosed
inspect_system::tests::probe_dir_created_dir_exec_maps
inspect_system::tests::probe_dir_falls_back_when_temp_is_noexec
attach::instance_tests::privileged_full_image_native_multi_query_and_scan_ia32
attach::instance_tests::privileged_full_image_native_multi_query_and_scan_lp64
attach::instance_tests::privileged_semantic_capture_multi_reload_and_rebound_successor
attach::instance_tests::privileged_instance_attach_during_reload_loop_has_zero_false_joins
attach::instance_tests::privileged_instance_exec_renews_the_instance
attach::instance_tests::privileged_instance_fork_without_exec_stays_consistent
attach::instance_tests::privileged_instance_hooks_attach_for_profile_but_not_metrics
# B17 live twins: global-only sharer churn taints the router end to end
# (marker counters) and discloses the tainted identity exactly once
# through the capture report (drain). Same owned gcc fixtures and Singles
# Session as the neighboring instance cells.
attach::instance_tests::privileged_instance_b17_counters_observe_sharer_churn
attach::instance_tests::privileged_instance_b17_drain_yields_identity_once_live
attach::instance_tests::privileged_instance_mapping_controls_never_join_old_state
attach::instance_tests::privileged_instance_mremap_dontunmap_keeps_both_and_renews
attach::instance_tests::privileged_instance_nonleader_exec_detaches_without_misrouting
attach::instance_tests::privileged_instance_overflow_at_ninth_file_is_unknown
attach::instance_tests::privileged_instance_pre_attachment_sharer_globalizes
attach::instance_tests::privileged_instance_reload_race_has_zero_false_joins
attach::instance_tests::privileged_instance_routing_separates_reload_sibling_and_mutation
attach::instance_tests::privileged_instance_vfork_unmap_globalizes
attach::instance_tests::privileged_instance_zombie_leader_sharer_globalizes
attach::instance_tests::privileged_object_continuity_refusal_preserves_s1_base
# Birth-marker cells: live READY/DIRTY behavior on marker-enabled builds;
# on markerless builds each cell asserts the marker absence instead.
attach::instance_tests::privileged_journal_marker_abandoned_call_at_thread_exit_dirties
attach::instance_tests::privileged_journal_marker_cgroup_gap_sticks_across_reentry_and_exec
attach::instance_tests::privileged_journal_marker_cgroup_outsider_call_creates_dirty_row
attach::instance_tests::privileged_journal_marker_dirty_nonleader_exec_publishes_fresh_ready
attach::instance_tests::privileged_journal_marker_exec_after_closure_publishes_ready
attach::instance_tests::privileged_journal_marker_fork_without_exec_has_no_ready
attach::instance_tests::privileged_journal_marker_nonleader_exec_creates_fresh_ready_row
attach::instance_tests::privileged_journal_marker_ordinary_capture_mints_no_birth
attach::instance_tests::privileged_journal_marker_pid_outsider_stays_unobserved
attach::instance_tests::privileged_journal_marker_pid_reuse_exec_creates_no_row
attach::instance_tests::privileged_journal_marker_return_outside_scope_dirties
# Journal READY cell: post-closure exec publishes READY in a journal-object
# session; on builds that omit the journal it asserts the finite refusal.
attach::instance_tests::privileged_journal_ready_exec_after_closure_publishes_ready
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
attach::inventory::capture::privileged_tests::privileged_inventory_capture_active_spawn_exec_ticket_without_provider_call_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_cookie_query_matches_row_and_changes_on_nonleader_exec_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_extend_late_provider_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_leader_exec_ticket_and_delayed_drain_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_active_spawn_exec_ticket_without_provider_call_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_cookie_query_matches_row_and_changes_on_nonleader_exec_lp64
attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_leader_exec_ticket_and_delayed_drain_lp64
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
# Installed linked control: a real Session sealed over the loaded journal
# pair drains linked through the live wiring (behavioral seal-to-drain
# linkage, 6.06). Same owned fixture Session shape as the retirement
# cells above.
attach::tests::sealed_session_drain_linkage_is_behavioral
# Loader-gate activation: a live self-preflight session binds the gate and
# bank cells (gate-1 reads the published select word; gate-0 binds none).
attach::tests::gate_session_binds_live_gate_and_bank_cells
# C1 live twin: the doctor counter preflight loads every counter object
# through Session preparation (gate-1 must accept gate-free objects).
attach::counter_banks::tests::counter_object_preflight_loads_all_modes
discovery::confirm_shards::tests::privileged_sharded_confirmation_equals_the_serial_production_probe
# Stamped-legacy surface cell: a legacy-only fixture whose 68-slot list is
# stamped 3.0/3.1/3.2 (the Fedora SoftHSM 2.7 shape) decodes to a complete
# surface with no surface gap. BPF-free; scan, pin, reconcile, plan, verdict.
discovery::engine::tests::stamped_legacy_fixture_reports_no_surface_gap
# 6.14A exit-mapping split: live BPF kind-7 split over owned short-lived
# children with a default kind-6 twin (cgroup scope, ~25 s). Known-fail on
# 6.6.157 (pre-existing planner merge divergence, reproduced at lane base).
discovery::engine::tests::exit_mappings_live_cgroup_split_and_default_twin
# T8 twin fullness control: the identical phase-1 arming with an empty
# request map admits the same head with zero loss, proving the twin's
# refusal pins the full blocked map rather than the head. Expected
# green on the fixed lane-A runtime (the pre-twin shape converges to
# admitted-head under any working fix).
discovery::engine::pressure_native_tests::pressure_live256_unparked_head_control_admits
# T8 live256 episodes, re-run green by hand at the fixed tip (waiter-
# driven eviction converges the settle): the genuine 257-EXEC episode
# admits its late head, and the all-blocked twin refuses exactly once.
# Both are cgroup-scoped (the 257 cell's pattern), so unrelated host
# EXECs never enter the burst batch; the ambient gates stay as
# scope-leak detectors, not quiet-window lotteries.
discovery::engine::pressure_native_tests::pressure_live256_genuine_episode_admits_late_then_head
discovery::engine::pressure_native_tests::pressure_live256_all_blocked_twin_refuses_once
# T8 scope-sensitivity probe: out-of-scope EXECs never enter a
# cgroup-scoped batch while an in-scope non-owned EXEC is still
# flagged by the ambient gate (fast sleeper stimulus; pins the
# scope-leak detector's sensitivity for the cgroup-scoped episodes).
discovery::engine::pressure_native_tests::cgroup_scope_probe_flags_in_scope_ambient_only
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
# Pause exec-wrapper cells: run --pause auto/never through env, sh -c exec,
# a forking sh wrapper and a preload-then-exec wrapper with a SoftHSM
# workload (root, BPF, SoftHSM, pkcs11-tool); each wrapper run compares
# against the direct run's exact call count or neutral lattice. The
# default-flags cell pins the omitted --pause default end to end on a
# fast child, with a never twin. The SIGINT-during-hold cell stops that
# default run mid-hold: the run still writes its report.
discovery::pause::tests::privileged_pause_auto_env_wrapper_matches_direct_count_lp64
discovery::pause::tests::privileged_pause_auto_preloaded_exec_matches_direct_count_lp64
discovery::pause::tests::privileged_pause_auto_shexec_wrapper_matches_direct_count_lp64
discovery::pause::tests::privileged_pause_auto_shfork_wrapper_reports_honest_gap_lp64
discovery::pause::tests::privileged_pause_never_env_wrapper_publishes_neutral_lattice_lp64
discovery::pause::tests::privileged_pause_default_flags_count_fast_child_exact_lp64
discovery::pause::tests::privileged_pause_sigint_during_hold_still_writes_report_lp64
# Short-lived naming cell: one pkcs11-tool run under inventory --system
# must NAME the tool (its EXEC-joined pair resolved to the exact path,
# not just its pid) in modules[].unbound_use.executables and on the
# concise unidentified line (root, BPF, SoftHSM, pkcs11-tool; a holder
# keeps the module mapped; about 1-4 min with retries).
discovery::unbound_exe::tests::privileged_shortlived_tool_run_names_its_executable
# D4 file-identity qualifying cells: ext4 inode-reuse confirmation
# parity (own loop ext4 per row) and overlay xino backend parity (own
# loop layers per mode). The copy-up no-re-edge positive runs in the
# overlay campaign below (lane B only), never in the default campaign.
discovery::sweep_attribution::tests::d4_ext4_cells::privileged_d4_ext4_inode_reuse_confirmation_parity
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_d4_overlay_xino_backend_parity
# K1 sweep-side witness cell (own loop overlay per mode, capture watching
# the held provider): fresh-upper joins via the production witness,
# stale-lower keeps the named loss, the no-witness RED run keeps the loss,
# and the only-excluded-anchor install failure takes the same witness
# route (fresh joins, stale and no-witness runs keep the loss).
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_k1_sweep_witness_fresh_joins_stale_refuses
# K1 witness campaign siblings (own loop overlays per mode): the
# budget-exhaustion refusal, the same-key-twice proof, and the K2
# sweep-side no-fallback cell.
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_k1_witness_budget_exhaustion_refuses
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_k1_same_key_twice_proves
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_k2_sweep_overlay_no_fallback
# R1 no-route collect cell (own loop overlays per mode, SoftHSM
# provider): collect_system_with_identity twice (Auto, scripted
# no-kernel checks) plus one single-shot collect; fresh-upper joins,
# stale-lower refuses, the shared witness window advances by spent.
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_k1_no_route_collect_system_witness
discovery::sweep_attribution::tests::privileged_a_data_only_mapper_of_an_identity_key_is_never_attributed_on_ext4
discovery::sweep_attribution::tests::privileged_an_unmapped_file_whose_inode_is_reused_is_never_attributed_on_ext4
# Tmpfs inode-number uniqueness: the cell mounts its own inode32/inode64
# tmpfs pair, so it needs only root (no btrfs TMPDIR provisioning).
discovery::sweep_attribution::tests::privileged_tmpfs_inode32_refuses_while_inode64_merges
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
# Pre-arm live cell (pid scope): the declared proved set attaches through
# the activating extend and the watch reaches armed live (~4 s).
inventory::privileged_tests::privileged_prearm_reaches_armed_pid
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
# Joint init linkage latch: a linked lane latches its producers'
# linkage at init and reads bootstrap before any traffic, an
# unlinked lane stays unlatched and reads journal_unavailable, and
# neither stages a gap. Two short System-scope attaches (about a
# minute); on builds that omit the journal the linked half asserts
# the refusal instead. Prints KEY_OPS_LATCH lines.
inventory::privileged_tests::privileged_joint_init_latches_producer_linkage
# Linked key-operations cells: the live linked lane pumps discovery, a
# malformed discovery record faults the pump without latching while the
# next audited batch carries the coverage failure (its healthy linked
# control routes normally without one), and the seal generation
# publishes only with the journal pair. Each runs its own
# System-scope capture (about half a minute); on builds that omit the
# journal the linked cells assert the refusal instead. Print KEY_OPS
# lines.
inventory::privileged_tests::privileged_key_operations_linked_lane_pumps_live_discovery
inventory::privileged_tests::privileged_key_operations_live_discovery_fault_refuses_without_latching
inventory::privileged_tests::privileged_key_operations_seal_generation_gated_by_flag
inventory::privileged_tests::privileged_key_operations_linked_fault_fails_coverage_without_latching
inventory::privileged_tests::privileged_key_operations_linked_healthy_routes_without_coverage_failed
# v0.5.0 headline end to end: inventory --system --manifest over a live
# SoftHSM2 ledger workload (gates its dlopen on the observer's pass 0
# publish, strictly post-attach) exits 0 with populated S1 edges
# (mechanisms and API results) or named route-loss gaps, plus the
# journal_unavailable S1 marker. Spawns a real observer binary:
# P11SCOPE_E2E_OBSERVER, else the p11scope sibling of the test
# binary. Prints MAN1_E2E lines (about a minute).
inventory::manifest_e2e_tests::privileged_inventory_system_manifest_e2e_softhsm_edges_lp64
# Inventory scale with --manifest: the same headline command over 4,097+
# admitted endpoints (distinct SoftHSM2 copies held mapped plus the
# gated ledger caller) stops finitely with a populated S1 edge for the
# long-running caller and the journal_unavailable marker. Strict on
# edges (no route-loss fallback). P11SCOPE_SCALE2_TARGET raises the
# target up to 8192 for the full-scale run. Prints SCALE2_E2E lines
# (a few minutes).
inventory::manifest_e2e_tests::privileged_inventory_system_manifest_scale4097_softsm_edges_lp64
# MT per-key accounting: inventory --pid --capture native
# --key-operations --manifest over 8 threads x 50 C_Sign calls in
# one process attributes every sign to a key row or to a named MT
# race bucket (key_join_lost, unbound): rows plus unknown equal
# the LEDGER exactly. A build without the journal pins the
# journal_unavailable refusal. Prints MTKEY lines (about a minute).
inventory::manifest_e2e_tests::privileged_inventory_pid_key_operations_mt_sign_rows_exact
# Reload-disclosure cells: installed inventory captures over the owned
# fixture pair. The churn run publishes the disclosure naming the
# churned identity with exact counts; the clean control omits the key
# while both instance rows stay live. Each runs its own capture
# (about a minute); prints B17_LEG2 lines.
inventory_present::reload_disclosure_privileged_tests::privileged_inventory_reload_disclosure_lists_churned_identity
inventory_present::reload_disclosure_privileged_tests::privileged_inventory_reload_disclosure_omits_key_without_churn
# Typed counter readers: real anonymous native maps, with no program load,
# attach, external workload or opt-in object build required.
metrics::counter_reader::tests::counter_reader_native_maps_match_all_modes
metrics::counter_reader::tests::counter_reader_requires_exact_maps_and_health
# Revived fixture-free skips: the punch-hole renewal cell (needs a
# punch-hole-capable runner TMPDIR), the bank-mode object load cell
# (embedded counter objects, no fixture), and the owned-child
# counter run cell (the runner provides CARGO_TARGET_TMPDIR).
attach::instance_tests::privileged_instance_cross_process_punch_hole_renews
attach::counter_banks::tests::counter_bank_mode_objects_load_lp64
metrics::counter_reader::tests::counter_cli_run_counts_with_owned_child_lp64
# Revived counter-bank cells: the runner builds
# tests/fixtures/counter-banks.c and counter-bank-growth.c with cc
# and points P11SCOPE_COUNTER_BANK/GROWTH_FIXTURE_PROVIDER/WORKLOAD
# at them. Session append legs, 511/512 boundary and 8192
# population cells (Singles and Multi), engine-driven growth, the
# nofile twins, live/terminal collection, stop estimates,
# CLI-shaped captures and selected-detail controls.
metrics::counter_reader::tests::counter_bank_session_old_return_survives_append_lp64
metrics::counter_reader::tests::counter_bank_session_timing_old_return_survives_append_lp64
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_counts_growth_lp64
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_timestamps_growth_lp64
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_latency_growth_lp64
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_counts_growth_multi_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_counts_growth_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_counts_growth_multi_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_timestamps_growth_multi_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_latency_growth_multi_lp64
metrics::counter_reader::tests::counter_engine_stages_first_512_counts_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_over_ceiling_refuses_atomically_lp64
metrics::counter_reader::tests::counter_engine_growth_cgroup_counts_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_system_counts_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_timestamps_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_latency_multi_lp64
metrics::counter_reader::tests::counter_start_raises_nofile_from_soft_1024_lp64
metrics::counter_reader::tests::counter_start_without_raise_refuses_fd_exhausted_from_soft_1024_lp64
metrics::counter_reader::tests::counter_collection_reads_live_and_terminal_lp64
metrics::counter_reader::tests::counter_singles_stop_prints_detach_estimate_lp64
metrics::counter_reader::tests::counter_multi_stop_prints_no_detach_estimate_lp64
metrics::counter_reader::tests::counter_singles_stop_second_signal_abandons_lp64
metrics::counter_reader::tests::counter_cli_profile_counts_matches_workload_ledger_lp64
metrics::counter_reader::tests::counter_cli_profile_timestamps_matches_workload_ledger_lp64
metrics::counter_reader::tests::counter_cli_profile_latency_matches_workload_ledger_lp64
metrics::counter_reader::tests::selected_detail_cli_profile_counts_resolves_live_plan_and_conserves_aggregate_lp64
# Counter CLI and K0 selected-detail live cells over owned cc-built
# growth fixtures: the counts CLI cell (exact workload-ledger numbers,
# no selection), the K0 CLI cell (live-plan resolution plus the exact
# aggregate), and the six SoftHSM ledger cells (exact C_Sign detail,
# the exec-in-window negative, the owned-run positive, the two
# exit-in-window cells: owned run without --hold and a --pid target
# that ends before the duration, and the gate-less short owned run
# whose detail must match the main report). Root on a
# Multi-capable kernel; the ledger cells also need gcc, softhsm2-util,
# SoftHSM2 and an observer binary (P11SCOPE_E2E_OBSERVER or the
# p11scope sibling).
metrics::k0_live_cells::k0_live_detail_matches_ledger_counts_lp64
metrics::k0_live_cells::k0_live_exec_voids_detail_counts_lp64
metrics::k0_live_cells::k0_live_run_detail_matches_ledger_counts_lp64
metrics::k0_live_cells::k0_live_run_exit_in_window_counts_lp64
metrics::k0_live_cells::k0_live_pid_exit_in_window_counts_lp64
metrics::k0_live_cells::k0_live_run_gateless_exit_matches_main_counts_lp64
metrics::counter_reader::tests::selected_detail_system_scope_refuses_live_plan_lp64
# Pre-arm witness cells (P2-7 behavior cells plus the object/start/finalize
# live cells): each loads the short-lived witness on a Multi-capable
# kernel as root and needs no provider install. Seconds each.
attach::prearm_witness::prearm_witness_tests::privileged_map_and_call_after_finalize_is_clean
attach::prearm_witness::prearm_witness_tests::privileged_observer_self_map_during_startup_is_clean
attach::prearm_witness::prearm_witness_tests::privileged_readonly_mapped_before_start_is_found
attach::prearm_witness::prearm_witness_tests::privileged_mprotect_dance_before_finalize_is_found
attach::prearm_witness::prearm_witness_tests::privileged_map_unmap_inside_window_is_latched
attach::prearm_witness::prearm_witness_tests::privileged_zombie_leader_holding_file_is_found
attach::prearm_witness::prearm_witness_tests::privileged_held_teardown_is_pending
attach::prearm_witness::prearm_witness_tests::privileged_exec_departure_under_holder_is_pending
attach::prearm_witness::prearm_witness_tests::privileged_cgroup_member_migrated_out_is_migration
attach::prearm_witness::prearm_witness_tests::privileged_nested_pidns_observer_is_unavailable
attach::prearm_witness::prearm_witness_tests::privileged_walk_scale_completes
attach::prearm_witness::tests::privileged_prearm_witness_loads_and_attaches
attach::prearm_witness::tests::privileged_cgroup_id_matches_kernfs_id
attach::prearm_witness::tests::privileged_start_activates_on_host
attach::prearm_witness::tests::privileged_finalize_clears_clean_start
attach::prearm_witness::tests::privileged_finalize_settles_under_churn
# sudo -o ownership: reports created in an invoker-owned directory are
# handed to SUDO_UID:SUDO_GID (0600); elsewhere they stay root-owned.
output::tests::privileged_sudo_output_reports_are_owned_by_the_invoker
# Owned-child home restoration: a sudo-shaped drop to nobody carries the
# passwd HOME/USER into the exec'd environment (needs only root and the
# nobody account, no BPF).
run::tests::privileged_spawned_child_home_matches_the_target_passwd_row
# Run-owned cgroup placement: creating a subgroup, moving a child into it
# and proving the landing (needs only root and a cgroup v2 mount, no BPF).
scope::tests::privileged_run_cgroup_place_moves_a_real_child
# Run-owned cgroup nesting: the subgroup is created under the observer's
# own cgroup, never at the filesystem root (same prerequisites, no BPF).
scope::tests::privileged_run_cgroup_create_under_observer_stays_nested
)

# Counter-fixture membership: the DEFAULT_TESTS members that need the
# runner-built P11SCOPE_COUNTER_*_FIXTURE_* inputs (not a campaign list:
# every member also runs as a default cell). The runner builds the
# fixtures when any member is selected, points the variables at them for
# exactly these cells, and SKIPs them (with a reason) when cc is missing.
COUNTER_FIXTURE_TESTS=(
metrics::counter_reader::tests::counter_bank_session_old_return_survives_append_lp64
metrics::counter_reader::tests::counter_bank_session_timing_old_return_survives_append_lp64
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_counts_growth_lp64
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_timestamps_growth_lp64
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_latency_growth_lp64
metrics::counter_reader::tests::counter_bank_session_boundary_511_512_counts_growth_multi_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_counts_growth_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_counts_growth_multi_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_timestamps_growth_multi_lp64
metrics::counter_reader::tests::counter_bank_session_useful_8192_latency_growth_multi_lp64
metrics::counter_reader::tests::counter_engine_stages_first_512_counts_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_over_ceiling_refuses_atomically_lp64
metrics::counter_reader::tests::counter_engine_growth_cgroup_counts_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_system_counts_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_timestamps_multi_lp64
metrics::counter_reader::tests::counter_engine_growth_latency_multi_lp64
metrics::counter_reader::tests::counter_start_raises_nofile_from_soft_1024_lp64
metrics::counter_reader::tests::counter_start_without_raise_refuses_fd_exhausted_from_soft_1024_lp64
metrics::counter_reader::tests::counter_collection_reads_live_and_terminal_lp64
metrics::counter_reader::tests::counter_singles_stop_prints_detach_estimate_lp64
metrics::counter_reader::tests::counter_multi_stop_prints_no_detach_estimate_lp64
metrics::counter_reader::tests::counter_singles_stop_second_signal_abandons_lp64
metrics::counter_reader::tests::counter_cli_profile_counts_matches_workload_ledger_lp64
metrics::counter_reader::tests::counter_cli_profile_timestamps_matches_workload_ledger_lp64
metrics::counter_reader::tests::counter_cli_profile_latency_matches_workload_ledger_lp64
metrics::counter_reader::tests::selected_detail_cli_profile_counts_resolves_live_plan_and_conserves_aggregate_lp64
metrics::counter_reader::tests::selected_detail_system_scope_refuses_live_plan_lp64
)

# Wrap-fixture membership: the LONG_TESTS members that need the
# runner-built P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR inputs (not a
# campaign list: every member also runs as a long cell). The runner
# builds the fixtures when any member is selected and no directory is
# already set, points the variable at them for exactly these cells,
# and SKIPs them (with a reason) when cc or python3 is missing.
WRAP_FIXTURE_TESTS=(
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_wrap_and_primary_parity_lp64
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_system_diagnostics_wrap_and_primary_parity_lp64
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_startup_probe_lp64
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_transition_pilot_lp64
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_accelerated_pilot_lp64
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_gate_cadence_probe_lp64
inventory::privileged_tests::operator_diagnostics_wrap::privileged_native_lane_pid_diagnostics_three_round_default_cadence_control_lp64
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
attach::inventory::activation::privileged_tests::privileged_inventory_multi_n20480_default_lp64
attach::inventory::activation::privileged_tests::privileged_inventory_multi_n8193_refuses_lp64
# G21 default-ring wrap needs 266 changing observed rounds per leg (532 per
# two-leg cell; 260 counted + 4 shared + fence + proof per leg, 264 without
# fence/proof; ~12 min pid / ~27 min system per cell at declared 250ms pid /
# 50ms system cadence) and the
# controller-verified prebuilt32-body fixture. Required acceptance is
# scheduled explicitly, outside the default short lane.
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

# Static skips: external prerequisites or explicitly deferred build cells.
SKIP_TESTS=(
# Private image-bank cells require a separately enabled FULL proof build.
attach::image_bank_proof::tests::privileged_image_bank_verifier_stats
attach::image_bank_proof::tests::privileged_image_bank_exhaustion_16384_then_quota
attach::image_bank_proof::tests::privileged_image_bank_cut_16385th_leader_in_b
attach::image_bank_proof::tests::privileged_image_bank_concurrent_cut_counts_once
attach::image_bank_proof::tests::privileged_image_bank_held_return_across_cut
attach::image_bank_proof::tests::privileged_image_bank_late_incarnation_refused
attach::image_bank_proof::tests::privileged_image_bank_failure_modes_refuse_and_balance
attach::image_bank_proof::tests::privileged_image_bank_fork_burn_sentinel
attach::image_bank_proof::tests::privileged_image_bank_second_rollover
attach::image_bank_proof::tests::privileged_image_bank_omitted_route_refuses
attach::image_bank_proof::tests::privileged_image_bank_exec_query_span_cut
attach::image_bank_proof::tests::privileged_image_bank_attach_cookie_through_dispatcher
attach::image_bank_proof::tests::privileged_image_bank_inflight_cut_counts_once
attach::image_bank_proof::tests::privileged_image_bank_per_call_overhead
attach::instance_tests::privileged_instance_small_state_lru_eviction_never_joins
attach::inventory::activation::privileged_tests::privileged_inventory_retirement_controlled_churn
discovery::engine::tests::lifecycle_manifest_helper_entrypoint
discovery::identity::tests::count_manifest_actual_full_copy_and_tail_fit_the_cached_read_allowance
discovery::identity::tests::map_files_name_timing_per_thousand
discovery::scan::tests::maps_reuse_timing_per_thousand_reads
discovery::scan::tests::privileged_cross_device_same_inode_alias_is_refused_on_scan_path
first_use_probe::native::system_capture_observer_facts
process::tests::pidfd_denial::pidfd_denial_helper
run::root_fence_runtime::actual_original_exit_delayed_first_admission_retires_pending
s1_tests::resource_probe::native_semantic_resource_final_probe
s1_tests::resource_probe::native_semantic_resource_registry_probe
semantics_edge::resource_tests::native_semantic_resource_probe
discovery::sweep_attribution::tests::d4_thread_mapping_helper
discovery::sweep_attribution::tests::d4_clone_without_files_mapping_helper
discovery::sweep_attribution::tests::d4_zombie_single_survivor_mapping_helper
attach::prearm_witness::prearm_witness_tests::witness_fixture_entrypoint
# TID-scoped nonleader anchor run (installs nothing live; strict BPF
# load): needs root with a live nonleader thread, run by hand.
attach::identity_iter::tests::privileged_identity_nonleader_anchor_installs_nothing
attach::tests::bpf_loop_probe_reports_helper_presence_on_live_kernel
# Historical/private opt-in counter refusals; never current host positives.
attach::counter_banks::tests::counter_preparation_refuses_without_bpf_loop_on_old_kernels
metrics::counter_reader::tests::counter_bank_session_verifier_complexity_refuses_clean_lp64
# Unprivileged system-population graph sizing: memory, drain and release
# are hard gates, the stop time is measured and disclosed (R-40).
discovery::engine::tests::collected_graph_peak_fits_pool_at_system_scale
inventory::joint_stop_races_privileged_tests::privileged_joint_stop_after_last_waiter_resolves_publishes_final_lp64
)
SKIP_REASONS=(
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; run this --exact selector --ignored as root in an authorized BPF lane"
"needs default FULL libtest built with P11SCOPE_IMAGE_BANK_PROOF=1 and a Multi-capable host; prior E3 acceptance, a quiet exclusive host and matched production cost inputs P11_BANK_N5_PRODUCTION_NS_1/P11_BANK_N5_PRODUCTION_NS_4 required; run this --exact selector --ignored as root in an authorized BPF lane (E4/N5)"
"needs a P11SCOPE_SMALL_STATE_MAPS=1 libtest build (the default binary fails its build gate by design); run by hand as root from that build with the variable set"
"needs an external barrier controller: P11SCOPE_I3A_RETIREMENT_MODE=worker|synchronous plus a root-owned 0700 CONTROL_DIR, a NONCE, and an external party to write the release file; no in-repo controller exists, so run once per mode by hand"
"private helper re-executed by DiscoveryLifecycleFixture with P11SCOPE_TEST_DISCOVERY_PROVIDER/MANIFEST; its own docs say it is not a separate passing test"
"private count-manifest cache helper invoked only by count_manifest_full_and_tail_share_the_scan_inspection_cache with P11SCOPE_COUNT_MANIFEST_FULL/P11SCOPE_COUNT_MANIFEST_TAIL; the ordinary parent builds and validates its inputs, not an independent live cell"
"unprivileged C7 A2 timing loop (indicative wall time, no pass/fail bar); not a campaign cell: run by hand with --exact <path> --ignored --test-threads=1 --nocapture, ideally from a --release build"
"unprivileged C7 A2 timing loop (indicative wall time, no pass/fail bar); not a campaign cell: run by hand with --exact <path> --ignored --test-threads=1 --nocapture, ideally from a --release build"
"needs a live root-owned target with two private cross-device mounts (same inode, distinct dev) plus P11SCOPE_ALIAS_COLLISION_PID/HINT/TARGET/HARDLINK"
"needs a frozen supervisor config via P11SCOPE_FIRST_USE_PROBE_CONFIG plus an exclusive BPF lane; its verdict requires an external owned oracle"
"private seccomp helper re-executed by real_pidfd_denial_preserves_proc_identity_without_signal_authority with P11SCOPE_TEST_PIDFD_DENIAL_*; that unprivileged test is its only passing form"
"needs a separately reviewed native stage via P11SCOPE_ROOT_RUNTIME_STAGE (provider.so, driver, provider.json); the test documents no runtime skip"
"requires explicit controller-granted host measurement; spawns bounded child probes for the final multi-profile large4096 registry measurement, so schedule under a separate authorized measurement plan"
"requires explicit controller-granted host measurement; spawns bounded child probes for the multi-profile large4096 registry measurement, so schedule under a separate authorized measurement plan"
"requires explicit controller-granted host measurement; spawns bounded reducer-profile probes with at most 32 edges per profile, so schedule under a separate authorized measurement plan"
"private entrypoint re-executed only by the owned live-thread/private-files parity fixture; missing owned configuration fails and this helper never qualifies independently"
"private re-exec entrypoint for the owned literal-clone parity fixture; missing owned configuration fails and this helper never qualifies independently"
"private re-exec entrypoint for the owned single-survivor zombie fixture; missing owning socket/source fails and this helper never qualifies independently"
"private re-exec entrypoint for the P2-7 witness fixture children (P11SCOPE_PW_CHILD modes); missing fixture configuration fails and this helper never qualifies independently"
"needs root with a live nonleader thread for the TID-scoped anchor run (strict BPF load, installs nothing live); run the exact ignored test by hand as root in an authorized BPF lane with --test-threads=1 --nocapture"
"live-kernel BPF lane: reports bpf_loop helper presence without asserting it; run exact --ignored as root in an authorized BPF lane"
"pre-5.17 kernel lane: proves preparation refuses cleanly without the bpf_loop helper (passes vacuously on newer hosts); run exact --ignored as root on that kernel lane"
"6.1 E2BIG lane: proves the verifier-budget refusal maps before lifecycle without activating; run exact --ignored as root on the 6.1 verifier-budget host"
"unprivileged system-population graph sizing (4096 pin files plus 16384 native links; memory, drain and release asserts gate, the stop time is measured, not gated); not a campaign cell: run by hand with --exact <path> --ignored --test-threads=1 --nocapture on a host whose hard RLIMIT_NOFILE fits the population"
"needs root, gcc/softhsm tooling and a built observer with p11scope-discover beside it; run by hand via scripts/ci/stop-races.sh (results.jsonl entry), unscheduled in CI"
)

# Btrfs campaign cells: run only with --include-btrfs. Each needs
# TMPDIR on btrfs; the runner loop-mounts one image for the group
# (scripts/ci/prepare-btrfs-tmpdir.sh) and unmounts it afterwards.
BTRFS_TESTS=(
attach::instance_tests::privileged_instance_routing_on_btrfs_tmpdir
discovery::sweep_attribution::tests::privileged_a_btrfs_collision_on_a_data_range_keeps_the_exec_proven_edge
discovery::sweep_attribution::tests::privileged_a_file_swapped_behind_an_identical_line_is_proved_as_the_new_file
discovery::sweep_attribution::tests::privileged_d4_btrfs_subvolume_collision_backend_parity
discovery::sweep_attribution::tests::privileged_d4_btrfs_same_line_remap_backend_parity
discovery::sweep_attribution::tests::privileged_d4_btrfs_deleted_mapping_backend_parity
discovery::sweep_attribution::tests::privileged_d4_btrfs_hardlink_alias_backend_parity
discovery::sweep_attribution::tests::privileged_d4_btrfs_bind_alias_backend_parity
discovery::sweep_attribution::tests::privileged_d4_btrfs_live_thread_private_files_backend_parity
discovery::sweep_attribution::tests::privileged_d4_btrfs_clone_without_files_backend_parity
discovery::sweep_attribution::tests::privileged_d4_btrfs_zombie_leader_single_survivor_backend_parity
discovery::sweep_attribution::tests::d4_zombie_cells::privileged_d4_btrfs_zombie_leader_collision_and_dataonly_twins
discovery::sweep_attribution::tests::d4_zombie_cells::privileged_d4_btrfs_zombie_cold_admission_backend_parity
discovery::sweep_attribution::tests::d4_population_cells::privileged_d4_kernel_positive_population_excludes_anchors
discovery::sweep_attribution::tests::privileged_btrfs_equal_pin_twins_use_their_own_inspections
discovery::sweep_attribution::tests::privileged_btrfs_snapshot_twins_do_not_merge
discovery::unbound_exe::tests::privileged_btrfs_subvolume_collision_resolves_ambiguous
)

# Btrfs TMPDIR provisioning also covers these expected-failure cells,
# so their recorded XFAIL reflects the named gate failure rather than
# a missing-btrfs setup failure. Every member must also be curated in
# EXPECTED_FAILURE_TESTS.
BTRFS_TMPDIR_XFAIL_TESTS=(
inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64
inventory::privileged_tests::privileged_identity_kernel_multipass_reuse_lp64
)

# Overlay campaign cells: run only with --include-overlay on a lane-B
# host (kernel 6.8+, where the overlay inode is stable). Each mounts
# its own loop ext4 layers plus overlay merges and fails loud off
# lane B, so the runner provisions nothing for them. The xino
# backend-parity cell already runs in the default campaign; the K1
# deep-scan twins and the copy-up no-re-edge positive are curated
# here.
OVERLAY_TESTS=(
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_k1_deep_scan_fresh_upper_joins
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_k1_deep_scan_stale_lower_refuses
discovery::sweep_attribution::tests::d4_overlay_cells::overlay_copy_up_userspace_edge_absent
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_lower_anchor_proves_stale_mapping
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_lower_anchor_refuses_fresh_mapping
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_stale_mapper_joins_proven_lower_file
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_metacopy_stale_mapper_joins_lower
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_second_lower_candidate_wins
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_upper_rewrite_keeps_stale_on_lower
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_copyup_candidate_opens_in_observer_namespace
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_witness_calibration_accepts_xino_overlay_files
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_witness_copyup_between_start_and_pin_refuses_proof
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_witness_pin_without_copyup_keeps_proof
discovery::sweep_attribution::tests::d4_overlay_cells::privileged_witness_calibration_accepts_metacopy_upper
)

# Expected-failure campaign cells: run only with
# --include-expected-failures. A cell records XFAIL (counts as passed)
# only when it fails WITH its signature in the log; any other failure
# records FAIL, so a backend refusal, fixture failure or missing tool
# can never masquerade as the named failure. A cell that passes
# records XPASS and fails the run, so a silent fix or change gets
# noticed. Reasons name the expected failure, signatures are the fixed
# log strings that prove it, and owners name the source file that owns
# the pin; all three stay index-aligned with the tests.
EXPECTED_FAILURE_TESTS=(
discovery::engine::tests::exit_loader_balanced_benign_transaction_needs_no_terminal_truncation
inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64
inventory::privileged_tests::privileged_identity_kernel_multipass_reuse_lp64
)
XFAIL_REASONS=(
"expected failure: R57 future positive, RED until a provider-free settlement receipt lands (unprivileged, no BPF or root); an unexpected pass un-ignores the cell"
"expected failure: D3d forced-kernel positive gate fails at exactly-one-module for gate-k1.so on loop and physical btrfs alike (stale-vs-product verdict belongs to src/inventory/privileged_tests.rs); an unexpected pass promotes the cell to the btrfs group"
"expected failure: D3d forced-kernel positive gate fails at exactly-one-module for gate-k2.so on loop and physical btrfs alike (stale-vs-product verdict belongs to src/inventory/privileged_tests.rs); an unexpected pass promotes the cell to the btrfs group"
)
XFAIL_SIGNATURES=(
"R57: balanced benign exit-time work needs a strong settlement receipt"
"exactly one module for gate-k1.so"
"exactly one module for gate-k2.so"
)
XFAIL_OWNERS=(
"src/discovery/engine_tests.rs"
"src/inventory/privileged_tests.rs"
"src/inventory/privileged_tests.rs"
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

# Discover btrfs-subvolume curation (checker-enforced, never executed
# by this script): the ignored discover cli twin that needs scratch on
# btrfs. The privileged-btrfs job runs the equivalent
# scripts/ci/discover-btrfs-subvol.sh cell (loop-mounted btrfs, run as
# the runner user because the fence refuses root); the ignored test
# itself runs by hand with --exact --ignored on btrfs scratch.
# shellcheck disable=SC2034  # read by scripts/check-ignored-tests.py, by design
DISCOVER_BTRFS_SUBVOL_TESTS=(
crates/discover/tests/cli.rs:isolation_btrfs_subvolume_outside_the_output_is_denied
)

# Integration-test curation: `tests/<target>.rs:<exact test path>` entries
# for the ignored integration tests (each target builds one binary named
# after the file stem). Verified, never executed, by --list-integration
# against a directory of built test binaries: every entry must resolve to
# exactly one binary and select exactly one ignored test there.
INTEGRATION_TESTS=(
tests/bpf_load_feasibility.rs:per_program_load_times
tests/bpf_load_feasibility.rs:parallel_load_measures_kernel_overlap
tests/bpf_load_feasibility.rs:parallel_load_partial_failure_retains_cleanup_owner
tests/bpf_load_feasibility.rs:resident_service_cost_parts
tests/entry_object_paired.rs:paired_default_and_unsafe_objects_satisfy_the_entry_contract
tests/exec_task_continuity.rs:exec_task_core_shapes_kernel_load_without_attachment
tests/identity_iter_standalone.rs:identity_loader_strict_gate_requires_btf_and_both_programs
tests/inventory_identity.rs:d4_btrfs_scan_backends_match_exact_fixture_population
tests/inventory_identity.rs:kernel_identity_positive_cell_rejects_refusal
tests/object_producer_activation.rs:counter_bank_btf_maps_and_programs_load
tests/run_abandon_report.rs:second_sigint_during_teardown_publishes_truthful_report_and_exits_130
tests/prearm_witness_cli.rs:privileged_profile_pid_prearm_clean_exact_counts
tests/prearm_witness_cli.rs:privileged_profile_cgroup_prearm_clean_exact_counts
tests/prearm_witness_cli.rs:privileged_profile_system_prearm_clean_exact_counts
tests/prearm_witness_cli.rs:privileged_profile_metrics_system_prearm_clean_exact_counts
tests/prearm_witness_cli.rs:privileged_profile_pid_prearm_twin_exact_window
tests/prearm_witness_cli.rs:privileged_trace_system_prearm_clean_exact_counts
tests/run_tree.rs:privileged_run_tree_shell_wrapper_shows_grandchild_calls
tests/run_tree.rs:privileged_run_tree_double_fork_shows_reparented_calls
tests/run_tree.rs:privileged_run_tree_outliving_child_is_disclosed
tests/run_tree.rs:privileged_run_tree_many_children_land_exact
)

usage() {
    cat <<EOF
usage: $PROG LIB_TEST_BINARY OUTDIR [--include-long] [--include-btrfs]
           [--include-overlay] [--include-expected-failures] [SELECTOR...]
       $PROG LIB_TEST_BINARY OUTDIR --wide-detailed-2112 [SELECTOR...]
       $PROG --list LIB_TEST_BINARY
       $PROG --list --wide-detailed-2112 LIB_TEST_BINARY
       $PROG --list-integration TEST_BINARY_DIR
       $PROG --help

Run the curated privileged (ignored) p11scope lib tests, one at a time.
SELECTORs are literal substrings matched against full test paths; a test
runs when any SELECTOR matches (no SELECTOR runs the whole campaign).
--include-long additionally runs the long campaign cells.
--include-btrfs additionally runs the btrfs campaign cells (the runner
loop-mounts a btrfs image for them).
--include-overlay additionally runs the overlay campaign cells (the
K1 deep-scan twins, which mount their own loop overlays; lane B only).
--include-expected-failures additionally runs the known-failing
reproducers with inverted judging (failures record XFAIL, passes fail
the run as XPASS).
--wide-detailed-2112 runs only the wide-Detailed campaign cells (a binary
built with --features wide-detailed-2112 is required; any other binary
is refused). It cannot be combined with any --include-* flag.
--list prints the curated default, long, skipped-with-reason, btrfs,
overlay, and expected-failure lists and verifies them against
the binary, without running anything. With --wide-detailed-2112 it
prints and verifies only the wide-Detailed list.
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
# No `-q`: under pipefail an early-exiting grep SIGPIPEs the upstream
# sort, returning 141 ("not present") at random and silently dropping
# the cell. Without -q grep consumes the whole list; matches go to
# /dev/null and only the exit status (0/1) is used.
binary_has_ignored() {
    binary_ignored_list "$1" | grep -xF -- "$2" >/dev/null
}

# Branch recording: a dual-outcome cell prints one
# `P11SCOPE_CELL_BRANCH=<name>` line for the arm it took, and the run
# loop appends ` branch=<name>` to that cell's results.txt line, after
# the test-result text so downstream `PASS ...` parsers keep matching.
# Prints the suffix for a cell log, or nothing when the cell printed no
# branch line. The last branch line wins; a value outside the token
# charset is recorded as INVALID, never silently dropped.
cell_branch_suffix() {
    local line name
    line=$(command grep -F 'P11SCOPE_CELL_BRANCH=' "$1" | tail -n 1 || true)
    [ -n "$line" ] || return 0
    name=${line##*P11SCOPE_CELL_BRANCH=}
    case $name in
        ''|*[!A-Za-z0-9_.-]*|[.-]*) printf ' branch=INVALID' ;;
        *) printf ' branch=%s' "$name" ;;
    esac
}

# Expected-failure gate: true when the cell log contains the cell's
# named-failure signature (fixed string). An empty signature never
# matches: `grep -F ''` matches every line, so an empty pin would make
# the XFAIL vacuous.
xfail_log_matches() {
    [ -n "$1" ] && command grep -qF -- "$1" "$2"
}

# De-duplicate a selection array in place, keeping the first curated
# position of each cell. Two groups may curate one cell (a revive can
# overlap another lane's add); without this the cell runs twice.
dedup_preserving_order() {
    local -n _arr=$1
    local _name
    local -a _out=()
    local -A _seen=()
    for _name in ${_arr[@]+"${_arr[@]}"}; do
        if [ -z "${_seen[$_name]+present}" ]; then
            _seen[$_name]=1
            _out+=("$_name")
        fi
    done
    _arr=(${_out[@]+"${_out[@]}"})
}

# Static skips pair each test with its reason by index, and so do the
# expected-failure cells (reason, signature and owner each). A length
# mismatch would print wrong reasons and, under `set -u` inside a
# `| tee` pipeline, fail only the forked subshell while the loop
# reports phantoms and exits 0. Refuse loudly before any print or
# selection touches the arrays.
check_pair_alignment() {
    local -n _tests=$1 _reasons=$2
    if [ "${#_tests[@]}" -ne "${#_reasons[@]}" ]; then
        echo "$PROG: $1 (${#_tests[@]}) and $2 (${#_reasons[@]}) differ in length" >&2
        return 1
    fi
}
check_skip_alignment() {
    check_pair_alignment SKIP_TESTS SKIP_REASONS \
        && check_pair_alignment EXPECTED_FAILURE_TESTS XFAIL_REASONS \
        && check_pair_alignment EXPECTED_FAILURE_TESTS XFAIL_SIGNATURES \
        && check_pair_alignment EXPECTED_FAILURE_TESTS XFAIL_OWNERS
}

# Compare curation against the binary. Prints drift details to stderr and
# returns 1 on any mismatch, so new tests cannot be silently dropped.
# Exactly these private cells are cfg'd out together in an ordinary libtest.
# This is not a generic prefix exemption: unknown or partial proof lists fail.
private_image_proof_name() {
    local prefix=attach::image_bank_proof::tests::privileged_image_bank_
    case $1 in "$prefix"*) ;; *) return 1 ;; esac
    case ${1#"$prefix"} in
        verifier_stats|exhaustion_16384_then_quota|cut_16385th_leader_in_b|\
        concurrent_cut_counts_once|held_return_across_cut|late_incarnation_refused|\
        failure_modes_refuse_and_balance|fork_burn_sentinel|second_rollover|\
        omitted_route_refuses|exec_query_span_cut|attach_cookie_through_dispatcher|\
        inflight_cut_counts_once|per_call_overhead) return 0 ;;
        *) return 1 ;;
    esac
}

check_curation() {
    check_skip_alignment || return 1
    local bin=$1 workdir bin_list cur_list missing_bin missing_cur proof_present=0 name
    local -A proof_curated=()
    for name in "${SKIP_TESTS[@]}"; do
        if private_image_proof_name "$name"; then proof_curated["$name"]=1; fi
    done
    workdir=$(mktemp -d) || { echo "$PROG: cannot create temp dir" >&2; return 1; }
    bin_list=$workdir/bin.txt
    cur_list=$workdir/cur.txt
    if ! binary_ignored_list "$bin" >"$bin_list"; then
        echo "$PROG: cannot list ignored tests in $bin" >&2
        rm -rf "$workdir"
        return 1
    fi
    if grep -q '^attach::image_bank_proof::tests::privileged_image_bank_' "$bin_list"; then
        proof_present=1
    elif [ "$?" -ne 1 ]; then
        echo "$PROG: cannot inspect private proof membership in $bin" >&2
        rm -rf "$workdir"
        return 1
    fi
    {
        printf '%s\n' "${DEFAULT_TESTS[@]}"
        printf '%s\n' "${ALTERNATIVE_TESTS[@]}"
        printf '%s\n' "${LONG_TESTS[@]}"
        printf '%s\n' "${BTRFS_TESTS[@]}"
        printf '%s\n' "${OVERLAY_TESTS[@]}"
        printf '%s\n' "${EXPECTED_FAILURE_TESTS[@]}"
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
            # Only the exact curated private group may be entirely absent.
            # One present member disables this exception for all fourteen.
            if [ "$proof_present" -eq 0 ] && [ -n "${proof_curated[$aname]+present}" ]; then
                continue
            fi
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
    if [ "${#proof_curated[@]}" -ne 14 ]; then
        echo "$PROG: all 14 private image-proof names must remain static SKIPs" >&2
        return 1
    fi
    if [ "$proof_present" -eq 0 ]; then
        echo "$PROG: private image-bank proof group not built (0/14 present; no proof positive)"
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
    echo "btrfs (${#BTRFS_TESTS[@]}, --include-btrfs only)"
    printf '%s\n' "${BTRFS_TESTS[@]}"
    echo "overlay (${#OVERLAY_TESTS[@]}, --include-overlay only)"
    printf '%s\n' "${OVERLAY_TESTS[@]}"
    echo "expected-failures (${#EXPECTED_FAILURE_TESTS[@]}, --include-expected-failures only)"
    for i in "${!EXPECTED_FAILURE_TESTS[@]}"; do
        echo "${EXPECTED_FAILURE_TESTS[$i]} :: ${XFAIL_REASONS[$i]} [sig: ${XFAIL_SIGNATURES[$i]}] [owner: ${XFAIL_OWNERS[$i]}]"
    done
    if check_curation "$bin"; then
        local actual_count
        actual_count=$(binary_ignored_list "$bin" | wc -l) || return 1
        echo "verify: curation matches the binary ($actual_count tests)"
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

# Btrfs mount teardown: globals, because a trap handler runs after
# main()'s locals are gone. Set only by the btrfs setup in main(), for
# paths the runner itself constructed under OUTDIR.
BTRFS_TEARDOWN_IMG=
BTRFS_TEARDOWN_MNT=
cleanup_btrfs_mount() {
    [ -n "$BTRFS_TEARDOWN_MNT" ] || return 0
    if ! "$REPO_ROOT/scripts/ci/prepare-btrfs-tmpdir.sh" --teardown \
        "$BTRFS_TEARDOWN_IMG" "$BTRFS_TEARDOWN_MNT" 2>/dev/null; then
        echo "$PROG: warning: btrfs teardown failed for $BTRFS_TEARDOWN_MNT" >&2
    fi
    BTRFS_TEARDOWN_IMG=
    BTRFS_TEARDOWN_MNT=
}

main() {
    local bin outdir include_long=0 include_btrfs=0 include_overlay=0 include_xfail=0 wide=0
    local selected_runnable=() selected_skipped=()
    local arg name i pass=0 fail=0 skipped=0 xfail=0 xpass=0 seq=0
    local tmpdir logdir eviddir results log evdir short start end seconds rc
    local result_line verdict branch_suffix sig_line
    local m32_ok=0 p11kit_ok=0 need_m32=0 need_p11kit=0
    local need_ext4loop=0 ext4loop_skip=
    local need_counter=0 counter_skip=
    local need_wrap=0 wrap_skip=
    local need_btrfs_run=0 btrfs_mnt='' btrfs_skip=''
    local need_target_tmp=0 target_tmpdir=
    local cell_tmpdir
    local -A counter_fixture_set=() wrap_fixture_set=() btrfs_set=() xfail_reason=() xfail_sig=()
    local -a cell_env=()

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
            --include-btrfs) include_btrfs=1 ;;
            --include-overlay) include_overlay=1 ;;
            --include-expected-failures) include_xfail=1 ;;
            --wide-detailed-2112) wide=1 ;;
            --*) echo "$PROG: unknown option: $arg" >&2; usage >&2; return 2 ;;
            *) SELECTORS+=("$arg") ;;
        esac
    done
    if [ "$wide" -eq 1 ] && { [ "$include_long" -eq 1 ] || [ "$include_btrfs" -eq 1 ] \
        || [ "$include_overlay" -eq 1 ] \
        || [ "$include_xfail" -eq 1 ]; }; then
        echo "$PROG: --wide-detailed-2112 selects only the wide campaign; --include-* flags do not apply" >&2
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
        if [ "$include_btrfs" -eq 1 ]; then
            for name in "${BTRFS_TESTS[@]}"; do
                if selected "$name"; then
                    selected_runnable+=("$name")
                fi
            done
        fi
        if [ "$include_overlay" -eq 1 ]; then
            for name in "${OVERLAY_TESTS[@]}"; do
                if selected "$name"; then
                    selected_runnable+=("$name")
                fi
            done
        fi
        if [ "$include_xfail" -eq 1 ]; then
            for name in "${EXPECTED_FAILURE_TESTS[@]}"; do
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
    dedup_preserving_order selected_runnable
    # Every SELECTOR must match at least one curated test.
    for arg in ${SELECTORS[@]+"${SELECTORS[@]}"}; do
        local matched=0 candidate
        if [ "$wide" -eq 1 ]; then
            for candidate in "${WIDE_DETAILED_2112_TESTS[@]}"; do
                case $candidate in *"$arg"*) matched=1; break ;; esac
            done
        else
            for candidate in "${DEFAULT_TESTS[@]}" "${ALTERNATIVE_TESTS[@]}" "${LONG_TESTS[@]}" \
                "${BTRFS_TESTS[@]}" "${OVERLAY_TESTS[@]}" \
                "${EXPECTED_FAILURE_TESTS[@]}" "${SKIP_TESTS[@]}"; do
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
        if [ "$wide" -eq 0 ] && [ "$include_btrfs" -eq 0 ]; then
            for candidate in "${BTRFS_TESTS[@]}"; do
                case $candidate in
                    *"$arg"*)
                        echo "$PROG: note: '$arg' matches --include-btrfs tests, skipped without the flag" >&2
                        break
                        ;;
                esac
            done
        fi
        if [ "$wide" -eq 0 ] && [ "$include_overlay" -eq 0 ]; then
            for candidate in "${OVERLAY_TESTS[@]}"; do
                case $candidate in
                    *"$arg"*)
                        echo "$PROG: note: '$arg' matches --include-overlay tests, skipped without the flag" >&2
                        break
                        ;;
                esac
            done
        fi
        if [ "$wide" -eq 0 ] && [ "$include_xfail" -eq 0 ]; then
            for candidate in "${EXPECTED_FAILURE_TESTS[@]}"; do
                case $candidate in
                    *"$arg"*)
                        echo "$PROG: note: '$arg' matches --include-expected-failures tests, skipped without the flag" >&2
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

    # Counter fixtures, the owned-child marker dir, and the btrfs mount:
    # prepared only when a selected cell needs them. A missing tool (cc,
    # mkfs.btrfs) SKIPs the affected cells with a reason; a failure with
    # the tools present fails the run loudly.
    for name in "${COUNTER_FIXTURE_TESTS[@]}"; do counter_fixture_set[$name]=1; done
    for name in "${WRAP_FIXTURE_TESTS[@]}"; do wrap_fixture_set[$name]=1; done
    for name in "${BTRFS_TESTS[@]}" "${BTRFS_TMPDIR_XFAIL_TESTS[@]}"; do btrfs_set[$name]=1; done
    for i in "${!EXPECTED_FAILURE_TESTS[@]}"; do
        xfail_reason[${EXPECTED_FAILURE_TESTS[$i]}]=${XFAIL_REASONS[$i]}
        xfail_sig[${EXPECTED_FAILURE_TESTS[$i]}]=${XFAIL_SIGNATURES[$i]}
    done
    for name in ${selected_runnable[@]+"${selected_runnable[@]}"}; do
        if [ -n "${counter_fixture_set[$name]+present}" ]; then need_counter=1; fi
        if [ -n "${wrap_fixture_set[$name]+present}" ]; then need_wrap=1; fi
        if [ -n "${btrfs_set[$name]+present}" ]; then need_btrfs_run=1; fi
        if [ "$name" = "metrics::counter_reader::tests::counter_cli_run_counts_with_owned_child_lp64" ]; then
            need_target_tmp=1
        fi
    done
    if [ "$need_counter" -eq 1 ]; then
        "$REPO_ROOT/scripts/ci/build-counter-fixtures.sh" "$outdir/counter-fixtures" \
            >"$tmpdir/counter-fixtures.log" 2>&1
        rc=$?
        if [ "$rc" -eq 77 ]; then
            counter_skip="cc cannot build the counter fixtures ($(tail -n 1 "$tmpdir/counter-fixtures.log"))"
        elif [ "$rc" -ne 0 ]; then
            echo "$PROG: counter fixture build failed, see $tmpdir/counter-fixtures.log" >&2
            return 1
        else
            for fixture in counter-bank-provider.so counter-bank-driver \
                counter-bank-growth-provider.so counter-bank-growth-driver; do
                if [ ! -f "$outdir/counter-fixtures/$fixture" ]; then
                    echo "$PROG: fixture build reported success but $fixture is missing" >&2
                    return 1
                fi
            done
        fi
    fi
    if [ "$need_wrap" -eq 1 ] && [ -z "${P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR:-}" ]; then
        "$REPO_ROOT/scripts/ci/build-wrap-fixtures.sh" "$outdir/wrap-fixtures" \
            >"$tmpdir/wrap-fixtures.log" 2>&1
        rc=$?
        if [ "$rc" -eq 77 ]; then
            wrap_skip="cc or python3 cannot build the wrap fixtures ($(tail -n 1 "$tmpdir/wrap-fixtures.log"))"
        elif [ "$rc" -ne 0 ]; then
            echo "$PROG: wrap fixture build failed, see $tmpdir/wrap-fixtures.log" >&2
            return 1
        elif [ ! -x "$outdir/wrap-fixtures/workload" ]; then
            echo "$PROG: fixture build reported success but workload is missing" >&2
            return 1
        fi
    fi
    if [ "$need_target_tmp" -eq 1 ]; then
        target_tmpdir=$outdir/target-tmp
        mkdir -p "$target_tmpdir" || return 1
        if [ -n "${SUDO_UID:-}" ]; then
            chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$target_tmpdir" || return 1
        fi
        chmod 0700 "$target_tmpdir" || return 1
    fi
    if [ "$need_btrfs_run" -eq 1 ]; then
        "$REPO_ROOT/scripts/ci/prepare-btrfs-tmpdir.sh" "$outdir/btrfs.img" "$outdir/btrfs-mnt" \
            >"$tmpdir/btrfs-mnt.path" 2>"$tmpdir/btrfs.err"
        rc=$?
        if [ "$rc" -eq 77 ]; then
            btrfs_skip="btrfs unavailable: $(cat "$tmpdir/btrfs.err")"
        elif [ "$rc" -ne 0 ]; then
            echo "$PROG: btrfs setup failed, see $tmpdir/btrfs.err" >&2
            return 1
        else
            btrfs_mnt=$(cat "$tmpdir/btrfs-mnt.path")
            if [ "$btrfs_mnt" != "$outdir/btrfs-mnt" ]; then
                echo "$PROG: btrfs helper mounted an unexpected path: $btrfs_mnt" >&2
                return 1
            fi
            BTRFS_TEARDOWN_IMG=$outdir/btrfs.img
            BTRFS_TEARDOWN_MNT=$outdir/btrfs-mnt
            trap cleanup_btrfs_mount EXIT
        fi
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
        echo "# include_btrfs: $include_btrfs"
        echo "# include_overlay: $include_overlay"
        echo "# include_expected_failures: $include_xfail"
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
        cell_env=()
        cell_tmpdir=$TMPDIR
        if [ -n "${counter_fixture_set[$name]+present}" ]; then
            if [ -n "$counter_skip" ]; then
                echo "SKIP $name :: $counter_skip" | tee -a "$results"
                skipped=$((skipped + 1))
                continue
            fi
            cell_env+=(P11SCOPE_COUNTER_BANK_FIXTURE_PROVIDER="$outdir/counter-fixtures/counter-bank-provider.so"
                P11SCOPE_COUNTER_BANK_FIXTURE_WORKLOAD="$outdir/counter-fixtures/counter-bank-driver"
                P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER="$outdir/counter-fixtures/counter-bank-growth-provider.so"
                P11SCOPE_COUNTER_GROWTH_FIXTURE_WORKLOAD="$outdir/counter-fixtures/counter-bank-growth-driver")
        fi
        if [ -n "${wrap_fixture_set[$name]+present}" ]; then
            if [ -n "$wrap_skip" ]; then
                echo "SKIP $name :: $wrap_skip" | tee -a "$results"
                skipped=$((skipped + 1))
                continue
            fi
            if [ -z "${P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR:-}" ]; then
                cell_env+=(P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR="$outdir/wrap-fixtures")
            fi
        fi
        if [ -n "${btrfs_set[$name]+present}" ]; then
            if [ -n "$btrfs_skip" ]; then
                echo "SKIP $name :: $btrfs_skip" | tee -a "$results"
                skipped=$((skipped + 1))
                continue
            fi
            cell_tmpdir=$btrfs_mnt
        fi
        if [ "$name" = "metrics::counter_reader::tests::counter_cli_run_counts_with_owned_child_lp64" ]; then
            cell_env+=(CARGO_TARGET_TMPDIR="$target_tmpdir")
        fi
        short=${name##*::}
        log=$logdir/$short.log
        evdir=$eviddir/$seq-$short
        mkdir -p "$evdir" || { echo "$PROG: cannot create $evdir" >&2; return 1; }
        echo "RUN $name [case_index=$seq]"
        start=$(date +%s)
        P11SCOPE_TASK4_EVIDENCE_DIR=$evdir P11SCOPE_TASK4_CASE_INDEX=$seq TMPDIR=$cell_tmpdir \
            env ${cell_env[@]+"${cell_env[@]}"} \
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
        branch_suffix=$(cell_branch_suffix "$log")
        if [ -n "${xfail_reason[$name]+present}" ]; then
            if [ "$verdict" = "PASS" ]; then
                xpass=$((xpass + 1))
                echo "XPASS $name rc=$rc seconds=$seconds :: $result_line$branch_suffix (UNEXPECTED PASS; expected: ${xfail_reason[$name]})" | tee -a "$results"
            elif xfail_log_matches "${xfail_sig[$name]}" "$log"; then
                xfail=$((xfail + 1))
                sig_line=$(command grep -F -m 1 -- "${xfail_sig[$name]}" "$log" | head -c 300 || true)
                echo "XFAIL $name rc=$rc seconds=$seconds :: $result_line$branch_suffix (expected: ${xfail_reason[$name]}; sig: $sig_line)" | tee -a "$results"
            else
                fail=$((fail + 1))
                echo "FAIL $name rc=$rc seconds=$seconds :: $result_line$branch_suffix (EXPECTED-FAILURE SIGNATURE MISMATCH; want sig: ${xfail_sig[$name]}; expected: ${xfail_reason[$name]})" | tee -a "$results"
            fi
        else
            if [ "$verdict" = "PASS" ]; then
                pass=$((pass + 1))
            else
                fail=$((fail + 1))
            fi
            echo "$verdict $name rc=$rc seconds=$seconds :: $result_line$branch_suffix" | tee -a "$results"
        fi
    done

    echo "SUMMARY pass=$pass fail=$fail skipped=$skipped xfail=$xfail xpass=$xpass" | tee -a "$results"
    [ "$fail" -eq 0 ] && [ "$xpass" -eq 0 ]
}

main "$@"
