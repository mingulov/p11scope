<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Findings triage: FINDINGS.md vs SYSPLAN packages A/B/C/E0/D/E-perf/F/G

- Scope: every active finding in `audit-notes/FINDINGS.md` (8 High + 42 Medium
  + 25 Low = 75; see count note below) against `feat/system-capture` tip
  `bc9e7be` in `/home/user/src/m/p11scope-ws/p11scope`.
- Method: read-only. Six parallel reviewers inspected tip sources, package
  diffs (`ae0338a..bc9e7be`) and regression tests; the highest-stakes claims
  (F-75, F-01, F-70, F-73 live path) were re-verified by direct read.
  No full test suite was run.
- Count note: the task brief said "MEDIUM 36 incl. F-70..", but FINDINGS.md
  holds 36 historical mediums (F-09..F-44) *plus* 6 new mediums (F-70..F-75),
  i.e. 42 Medium and 75 active total. All 75 are triaged below.
- R-01..R-06 (refuted/mitigated/accepted/undecidable) were spot-checked for
  reopening only; see §5.

## 1. Counts

| Severity | ADDRESSED | RESIDUAL | Other |
|---|---|---|---|
| High (8) | 2 (F-01 core — PARTIAL, F-03) | 6 (F-02, F-04..F-08) | — |
| Medium (42) | 10 (F-09, F-11, F-13, F-20, F-70..F-75) | 31 (incl. F-16 narrowed) | 1 (F-38 refuted pre-package, unchanged) |
| Low (25) | 0 | 25 (F-45..F-69) | — |
| **Total (75)** | **12** | **62** | **1** |

Residual ID list: F-02, F-04, F-05, F-06, F-07, F-08,
F-10, F-12, F-14, F-15, F-16(narrowed), F-17, F-18, F-19, F-21, F-22, F-23,
F-24, F-25, F-26, F-27, F-28, F-29, F-30, F-31, F-32, F-33, F-34, F-35, F-36,
F-37, F-39, F-40, F-41, F-42, F-43, F-44,
F-45, F-46, F-47, F-48, F-49, F-50, F-51, F-52, F-53, F-54, F-55, F-56, F-57,
F-58, F-59, F-60, F-61, F-62, F-63, F-64, F-65, F-66, F-67, F-68, F-69.

## 2. Per-finding table (tip `bc9e7be`)

Verdicts: ADDRESSED = mechanism fixed + pinned at tip. PARTIAL = core fixed,
an explicit sub-clause remains (also listed in §3). RESIDUAL = open.
REFUTED = pre-package disposition stands, packages add nothing.

### High

| ID | Verdict | Evidence |
|---|---|---|
| F-01 | PARTIAL (core ADDRESSED) | Package A (merge `903026d`). `(Unknown,None)` → `Action::Refuse` (`src/uretprobe_hazard.rs:106-125`, verified by direct read); `run` lane preflights (`src/run.rs:1507-1514`, `:2151`, refuse mapping `:2339-2355`); unreadable-target + unrunnable-by-name arms. Commits: `cf35ac4`, `85042a2`, `f34a49e`, `9c2de0b`, `28f4617`, `9252cba`. Tests: `the_full_verdict_target_matrix_fails_closed`, `an_unprovable_kernel_with_an_unreadable_target_refuses`, `unrunnable_targets_are_refused_by_name_before_the_preflight`, `b7_run_refuses_without_capture_lane`, `t3_f7_attach_refusal_points_at_doctor`, `every_owned_run_error_category_is_named_and_distinct`. RESIDUAL sub-clause: override still stderr-warning only, not in durable report evidence (§3). |
| F-02 | RESIDUAL | Untouched: `run.rs` changed only for F-01/F-74/F-11/D call shapes; terminal `mark_terminal_drain_unproven` sites intact (`src/run.rs:3433,3885,7615`; `src/render.rs:2840`). Sticky PARTIAL at `src/run.rs:2190`. |
| F-03 | ADDRESSED | Package A (`903026d`). CI fetches/tests `-p2` trees (`.github/workflows/ci.yml:86-87,107-108`); `Cargo.toml:47-48` patch still p2; tracked `third-party/sources.json` + ledger make drift visible. Commits: `b04dd67`, `964f396`. Tests: `tests/python/test_ci_dependency_selection.py` (`test_patch_points_at_recipe_selected_trees`, `test_standalone_ci_tests_use_recipe_selected_trees`, `test_root_workspace_compilation_and_recipe_audit_retained`). |
| F-04 | RESIDUAL | `ci.yml` touched only by F-03 commits; UNRUN privileged lanes intact (`ci.yml:29-40`). |
| F-05 | RESIDUAL | No fuzz dir/targets/deps added in range (absence verified). |
| F-06 | RESIDUAL | B/C/F touches all additive; `src/discovery/engine.rs` now ~15,370 lines (`impl Engine` at `:6995`). No split. |
| F-07 | RESIDUAL | `run ⇄ attach ⇄ engine` imports/construction unchanged (`src/run.rs:15`, `:1520`, `:2179`); D changed drain call shapes only. |
| F-08 | RESIDUAL | Zero commits mention `profile_json`/`versioned_evidence`; `-> Value` constructors intact (`src/render.rs:1385`, `:1114`). |

### Medium

| ID | Verdict | Evidence |
|---|---|---|
| F-09 | ADDRESSED | Package A. Shared `UPROBE_ATTACH_SELF_ROW="uprobe attach (self)"` (`src/doctor.rs:519`), emitted `:537,:546`, classifier reads same const (`:1113-1115`). Commit `2e914d1`. Test: `tier_classification_reads_the_row_bpf_checks_actually_emits` (`doctor.rs:1467`, real producer+classifier composition). |
| F-10 | RESIDUAL | Zero commits mention `unsafe-unvalidated-metadata`; double gate intact (`src/attach.rs:696`, `:724`). |
| F-11 | ADDRESSED | Package A. `stdout_sink_from` (`src/sink.rs:163-205`): pipes/char reopened via `/proc/self/fd/N` (private description), sockets use per-call `MSG_DONTWAIT` (`:115-130`), files shared w/o flag change; `run.rs` retyped to `StdoutInner`. Commit `7e9f940`. Tests: `stdout_sink_from_a_pipe/socket/file_leaves_the_shared_description_blocking`, `stdout_sink_is_unbuffered_by_construction` (`sink.rs:600-673`). Proof gap only: E17 live backpressure reproduction still pending. |
| F-12 | RESIDUAL | `render.rs` touched once in range (doc-comment rename, Package F); metrics/profile split + selection-blind verdict intact (`src/render.rs:1101`). |
| F-13 | ADDRESSED | Package A. Producer const (`src/render.rs:644-645`, unchanged lines); validator joins `PHYSICAL_IDENTITY_AMBIGUITY` (`scripts/check-capture-evidence.py:252-260`, enforced `:979-980`); doc lists all 6 reasons (`docs/schema/observed-profile-v2.md:139`). Commit `3427bde`. Tests: `tests/python/test_skip_reason_vocabulary.py` (two-way producer↔validator + doc). |
| F-14 | RESIDUAL | `spans_for` hits in range are call-site/test additions only; version-table refusal intact (`src/discovery/scan.rs:1060`). |
| F-15 | RESIDUAL | Zero commits mention handoff paths; `run_owned_inner` handoff intact (`src/run.rs:2130`, `:194`, `:1456`). |
| F-16 | RESIDUAL (narrowed) | Silent-history/untracked-fallback refutation (revalidation) stands, untouched; lifetime-capacity facet still open. G inventoried `history_records`/`semantic_keys` (`src/capacity.rs:74-88`) but wired nothing; G marks broader admission non-qualifying (`:118`). |
| F-17 | RESIDUAL | Zero commits mention the default; `= 10_000_000` intact (`src/run.rs:2887`), TRUNCATED text intact (`src/trace.rs:171`). |
| F-18 | RESIDUAL | No signal-scope change; `SignalState`/`install_stop_flag` intact (`src/run.rs:1401`, `:1465`). |
| F-19 | RESIDUAL | `src/cli.rs` untouched in entire range; `CaptureArgs`/`RunArgs` still pub-field (`cli.rs:24`, `:65`). |
| F-20 | ADDRESSED | Package A. `emit_diagnosis` (`src/inspect.rs:326-352`): soft failure + `--json` → failure document (`:358-366`); hard failures still `Err` → stderr (`main.rs:19`). Commit `88e43fc`. Tests: `soft_diagnosis_failure_with_json_prints_a_failure_document`, `..._without_json_keeps_the_text_line` (`inspect.rs:385-409`); usage doc updated. |
| F-21 | RESIDUAL | Zero commits mention `params`; `params == Null` pins intact (`src/render.rs:3514`). |
| F-22 | RESIDUAL | "path is a label" typing intact (`src/render.rs:329`); only render touch was a doc nit. |
| F-23 | RESIDUAL (by design; false exhaustion reduced) | Ceilings unchanged (`scan.rs:35-37` 512/512, `engine.rs:2956` 256, `plan.rs:215` 512 slots). B/C reduced *false* exhaustion (repeat recognition, retention, rotation) without moving cliff edges; G publishes an unwired envelope (`broader_admission=unqualified`). |
| F-24 | RESIDUAL (mitigations preserved) | Generation/ExecRefresh machinery intact (`engine.rs:2314`); G's `scan.rs` diff is const-visibility only. Equal-snapshot ABA proof gap still open. |
| F-25 | RESIDUAL | Zero commits mention `PauseCoordinator`; coordinator intact (`src/discovery/pause.rs:338`). |
| F-26 | RESIDUAL | Zero commits mention `P11SCOPE_BROAD_ADMIT`; env check intact (`engine.rs:4032`); still help/evidence-invisible. |
| F-27 | RESIDUAL | No audit/deny gate added (absence verified). |
| F-28 | RESIDUAL | No release/musl/docker/SBOM job added; `build-release.sh` still UNRUN (`ci.yml:31`). |
| F-29 | RESIDUAL | Range added coverage (`artifact_contracts` D fixup, C `system_scope` matrix) but no flake-hardening. |
| F-30 | RESIDUAL | `usage.md` touched only for narrow F-01/F-20 feature docs; no drift gate/process. |
| F-31 | RESIDUAL | `completeness` hits in range are E07/E09/measure, not the 4-artifact predicate; verdict still replicated (e.g. `engine_tests.rs:6548` `evidence_verdict`). |
| F-32 | RESIDUAL | No recurring backend-equivalence gate added (absence verified). |
| F-33 | RESIDUAL | `crates/discover/*` untouched; still uid-drop only (`crates/discover/src/main.rs:314`). |
| F-34 | RESIDUAL | G's `task_owner.c` touch is comment-only; `main.rs` touch is a `MAX_SLOTS ==` capacity assert (`crates/ebpf/src/main.rs:56`). No trust-root/signing/attestation change. |
| F-35 | RESIDUAL | No hardening commits; only SUDO_UID pins exist. |
| F-36 | RESIDUAL | `Result<_, String>` pervasive, untouched. |
| F-37 | RESIDUAL | E-perf scope was reducer-only (`semantics.rs`); discovery clones persist (`engine.rs:1117` `begin_stage`, `:1195` `invalidate_discovery_proofs`, `:1401` merge path). |
| F-38 | REFUTED (pre-package, unchanged) | Revalidation refuted the per-call hotspot; E-perf explicitly rejected the O-15 test-only hot-path claim (`task-Eperf-report.md:110-115`) and changed no `function_id` path. Not residual. |
| F-39 | RESIDUAL | Prod `cfg(test)` intact (`hooks.rs:19`, `loader.rs:2`, `pause.rs:460`). |
| F-40 | RESIDUAL | No tarpaulin/llvm-cov added (absence verified). |
| F-41 | RESIDUAL | No proptest/quickcheck added; scan glue still `pub(crate)` (absence verified). |
| F-42 | RESIDUAL | D collapsed cursor ownership (single `OwnedDrain`, `src/events.rs:142`) but left STATS-vs-EVENTS authority reads unchanged ("domain checking unchanged"). |
| F-43 | RESIDUAL | A/F-03 only taught CI to resolve p2 trees; fork still pinned (`Cargo.toml:47`). |
| F-44 | RESIDUAL | Zero commits mention `fn identify`; callers still test-only (`process.rs:130`). |
| F-70 | ADDRESSED (designed residual noted) | Package C (merge `4407927`). Exploratory rotation: `MAX_EXPLORATORY_EVICTIONS_PER_PASS=8`, cooldown 2 sweeps (`src/discovery/scheduler.rs:38,45`, verified by direct read); rarity-first `select_rotation_candidates` (`engine.rs:3927`); evictability predicate (`:13322`, never-owned/empty/stable only); `select_over_cap_desired` (`:13517`, verified present); ordinary passes still fill free slots only, reconcile evicts + rarity-selects. Old zero-candidate expectation explicitly revised as mandated semantic change. Commits: `dd0fe8a` (RED), `ed0ab19`, `961eec2`, `c188e8b`, `959b699`. Tests: `e06_unique_provider_reached_within_bounded_frames`, `e06_shared_inode_control_stays_covered_across_rotation`, `e06_e14_rotation_and_lifecycle_recovery_at_scale`, `e05_cross_module_admission_at_256_and_above_cap`, `rotation_selection_tiers_fresh_before_stale_within_rarity`, scheduler units, `tests/system_scope.rs` matrix/over-cap. Designed residual: a cap full of *owned* views still blocks a 257th provider (rotation never displaces authoritative evidence, `scheduler.rs:342`, `engine.rs:13514-13516`) — outside the finding's provider-free-incumbent shape; constants provisional ("ratify by measurement"). |
| F-71 | ADDRESSED | Package B (merge `eb26cb9`). Repeat recognition under caps: identity-before-charge in `decode_candidate` (`src/discovery/scan.rs:1249-1265`), no-cardinality-pre-check (`:1379-1382`, `:1510-1513`), sticky refusal counters (`:521-522`, `:699`); retentive loader rescans: retention gate (`engine.rs:9687-9696`) + retention path (`:9697-9732`), replace-always fallback (`:9733-9746`); exec-refresh keeps replace-always deliberately (`:13196-13204`). Commits: `b7835e1` (RED), `bacda87`, `f5dd0f1`. Tests: `e07_unchanged_complete_loader_rescan_retires_nothing`, `e07_saturated_table_cap_unchanged_rescan_retires_nothing`, `e07_incomplete_loader_rescan_retains_validated_endpoints`, 4 negative controls (unmap/changed-bytes/deleted/replaced-files still retire), scan-unit `e07_saturated_table_budget_still_recognizes_unchanged_repeats`. |
| F-72 | ADDRESSED (authority gates intentionally retained) | Package F (merge `d6c5bea`). Shared ownership-validated count-only lowering: `lower_publication_record` file-backed arm (`engine.rs:5693`), `lower_heap_publication_record` heap arm (`:5899`, `resolve_heap_table_owner` `:5620,:6040-6050`), `process_selection_lowering` (`:9526`), dispatch (`:12899-12945`); NULL-name records pass gates (`selection_name_class` `:581-589`). Commits: `41fbff2` (RED), `d155a54`. Tests: `f_e08_named_gi_heap_matches_list_element`, `f_e08_forwarded_gi_keeps_distinct_endpoint_owners`, `f_e08_null_default_and_failure_request_matrix`, `f_e08_version_shape_matrix`, `f_package_known_abi_bounds_walk_full_only_for_supported_shapes` (`scan.rs:3433`), `f_e13_first_call_gap_and_precapture_boundary`, `f_e15_malicious_entries_refused_equally`, `f_e15_forged_exact_name_stays_count_only`, `f_e21_gi_public_output_carries_no_raw_pointers` (`publication_tests.rs`). By design retained: unknown-version refusal, unattributed/terminal never lower, ambiguous heap ownership refused, `SelectionCountOnly` authority still exact-standard+same-object+full-walk, first-call gap disclosed not closed. |
| F-73 | ADDRESSED (scan path; live-path observation noted) | Package B. `InterfaceIdentity` (table key + name + flags, `scan.rs:292-323`); `interface_identity()` (`:372-422`: file-backed key address-free for cross-process dedup, runtime key view-scoped + content-hashed, `None` always charges); repeat-aware admission (`:1569-1595`); `admit_interface`/`interface_already_admitted` (`:783-801`, verified by direct read). Commit `bacda87`. Tests: `e09_repeated_interface_rescans_charge_once_but_work_every_time` (513 rescans → 1 record), `e09_changed_table_at_a_reused_address_charges_again`, `e09_runtime_interface_repeats_are_view_scoped_and_content_sensitive` (`scan.rs:5053,5129,5211`). 512 ceiling retained by design. Observation (pre-existing, deliberate, not the finding's mechanism): live lowering arms charge `admit_interface()` per record (`engine.rs:5781-5787,6058-6066`, rationale `:5766-5767`); predates SYSPLAN (`git log -S admit_interface` → `ed2c557`, `4848b7a`, …). Open measurement, not counted residual: whether repeated *identical* live publications should dedup. |
| F-74 | ADDRESSED | Package A. Harness rewrite: `derive_phases` records `t_go` and feeds no inference (`scripts/system-scope-measure.py:747+,772-780`); BURST/window overlap (`:886-900`); loop-end markers (`TARGET_EXIT_RE` `:412`, anchored `:870-888`); discovery completion-shape only (`:415-419`); identity receipts (`:616-725`, pathnames display-only); `delivered_derived` non-oracle note (`:388-393`); producer marker (`src/run.rs:2881-2883`, emitted `:3285,:3717`). Commits: `0523989`, `b396ba9`. Tests: 21 in `tests/python/test_measure_e03.py` (8 collapse-inference incl. long-setup-burst + early-exit countercontrols, 8 identity incl. same-pathname-other-inode, delivered-note) + updated oracle/loss-share tests. Residual: fd-plateau boundaries still estimated (disclosed via `method_warnings`). |
| F-75 | ADDRESSED (verified still addressed at tip) | Package E0 (merge `e1f6d3a`) + E-perf FU-1 hardening (merge `672df5f`); F/G touched `semantics.rs` in one visibility-only hunk (`:1985-1986`). Tombstone verified by direct read at tip: `Detached::collided` (`src/semantics.rs:1930`, contract `:1920-1930`); key doc (`:2075-2081`); 2nd-owner GetID tombstones + drops newcomer (`:2886-2890`); FU-1 same-owner re-mint on live tombstone drops newcomer, keeps original (`:2891-2900`); non-collided re-mint countercontrol (`:2901-2912`); join refusal (`:2939-2944`); completion refusal (`:2843-2849`); cancel cannot clear (`:2793-2799`); FU-4 finalize scope via `scoped_detached` (`:3215-3222,:3231-3233`). Commits: `2ef93d1` (RED), `64874e1`, `fc24b41` (RED), `fe2f867`. Tests: `e20_collision_tombstone_lifecycle_matrix`, `e20_fu1_…_preserves_original`, `e20_fu2_…_preserve_refusal`, `e20_f75_same_domain_…_without_wrong_binding`, `e20_valid_cross_process_transfer_…`, FU-1/FU-2 history pins, FU-4 trio, `e20_collision_workload_ledgers_stay_independent`, `tests/e20_live_collision.rs` FU-3 fixture (always runs) + privileged-gated BPF cell (loud skip). |

### Low (all RESIDUAL)

| ID | Current mechanism (tip) | Why untouched |
|---|---|---|
| F-45 | `src/attach.rs:1776` re-round (`extend` `:1835/:1866`, re-round `:1876`) | attach.rs diff is 4 Package-D hunks only; F touched engine apply paths but nothing near `rebuild_discovered` (`engine.rs:5152`). |
| F-46 | `crates/bpf-multi/src/lib.rs:157` (`debug_assert_eq!` `:157-162`) | bpf-multi empty log. |
| F-47 | `src/cli.rs:743` (`parse_duration`, no zero-reject) | cli.rs empty log; `--duration 0` still accepted (spot-verified). |
| F-48 | `src/output.rs:41` (`AtomicFile`, no `must_use`; `Drop` `:182`) | output.rs empty log. |
| F-49 | `src/trace.rs:143` (`format_line` + line fns `:143-181`) | trace.rs empty log. |
| F-50 | `docs/schema/observed-profile-v2.md` + `-v3.md`; all 4 F3 fields still 0 hits, no `*.schema.json` | v2 1-liner adds only F-13 vocab; render 1-liner is a type-name doc comment. F5/SE-24 untouched. |
| F-51 | 174 `unsafe` sites vs 0 `# Safety` docs in `src/` (sample `run.rs:744`) | Zero `# Safety` added in range. |
| F-52 | No `[lints]`/`clippy.toml`/`rustfmt.toml`; `Cargo.toml` untouched | Confirmed absence. |
| F-53 | `crates/manifest/src/elf.rs:351` (`read_export_facts`, SAFETY `:359`) | manifest untouched; accepted disposition intact. |
| F-54 | 173 non-test `expect()` sites (sample `run.rs:263`) | No expect-removal in range. |
| F-55 | `src/render.rs:402` (`attach_failures: Vec<String>` raw) | render.rs diff comment-only; trace.rs untouched. |
| F-56 | `crates/discover/src/main.rs:460` (`fs::write`; `--help`→stderr `:419`) | discover empty log. |
| F-57 | `src/run.rs:452-504` (SUDO_UID/GID) + `output.rs:431` | run.rs diff has zero SUDO mentions; bounded disposition intact. |
| F-58 | R2 `src/events.rs:327` still counter-only; I3 `output.rs:239`; R5/sink diff F-11 only; R3/D7/D8/E4 files untouched/off-topic | Mixed facets all intact. |
| F-59 | `src/doctor.rs:1183` (verbatim detail `:1189-1192`, verdict `:1196-1197`) | doctor.rs hunks are F-09 rows/tiers/tests only; `render()` untouched. |
| F-60 | No index/runbook; `docs/*runbook*` absent | New files are capacity.rs, tests, E-perf report only. |
| F-61 | `src/process.rs:704` (`raise_nofile`); `run.rs:1145` (`let _ =` samples) | process.rs diff is 1-line visibility change. |
| F-62 | 4 `#[ignore]`d tests intact (`publication_tests.rs:3391`, `runtime_tests.rs:13,94`, `root_fence_runtime.rs:638`); no Python entry point | No runner added. |
| F-63 | No shellcheck/ruff in CI (`scripts/`: 27 sh + 67 py) | ci.yml diff is F-03 only. |
| F-64 | `src/discovery/noise.rs:154` aggregator (counts + first sample only); 29 direct `eprint` sites; no `--quiet` | noise.rs + cli.rs untouched. Aggregator predates packages; levels/timestamps/quiet still missing. |
| F-65 | `Cargo.toml:4` vs `crates/ebpf{,-common}/Cargo.toml:4` split; `pause.rs:145` re-export | All Cargo.tomls + pause.rs untouched. |
| F-66 | `src/cli.rs:1`, still ~1,466 lines, zero clap | cli.rs untouched. |
| F-67 | `src/discovery/engine.rs:5170` (collapse → PARTIAL `:5170-5173`) | Zero overlay/collapse changes; disclosed disposition intact. |
| F-68 | `src/cli.rs:162` (`--system` `:162/:194`); usage.md diff F-01/F-20 only | Accepted/info disposition intact. |
| F-69 | `crates/ebpf/` build object; `src/main.rs` whole-lifetime caps | ebpf diff (34 lines) has no sign/attest; main.rs untouched. Accepted/structural intact. |

## 3. RESIDUAL list, ranked, with fix sketches

### High residuals

- **F-02 — `completeness` always PARTIAL.** What remains: both terminal
  paths still call `mark_terminal_drain_unproven` (`run.rs:3433,3885,7615`,
  `render.rs:2840`); clean and lossy runs share a verdict. Fix: split the
  signal — add a machine-readable `drain_proven` latch + `verdict_detail`
  enum (clean-but-unproven vs concrete-gap) in `src/render.rs` terminal
  verdict + `scripts/check-capture-evidence.py` + schema docs; gate any
  future COMPLETE on a bounded quiescence/settlement experiment (the
  revalidation's "prove settlement first" condition). Do not just delete
  PARTIAL. Owned files: `src/render.rs`, `src/run.rs`, oracle, docs.
- **F-04 — no hosted E2E in CI.** What remains: UNRUN privileged lanes
  (`ci.yml:29-40`); this review's live cells don't recur. Fix: add one
  privileged CI job (self-hosted BPF-capable lane) running the gated
  SoftHSM PID/system × metrics/profile cells via
  `scripts/system-scope-measure.py` with the E03-fixed harness; pin
  expected-count oracles. Owned: `.github/workflows/ci.yml`, measure
  script. Refs: E03, `audit-notes/perf/SYSTEM-EXPERIMENTS.md` cells.
- **F-05 — privileged parser surface without fuzz/PBT.** What remains:
  zero coverage-guided/Sanitizer evidence; untracked harnesses under
  `audit-notes/fuzz-harnesses/` never executed. Fix: land 1–3 cargo-fuzz
  targets (manifest/ELF reader, maps parser, hook-spec parser), expose
  scan glue via `#[cfg(fuzzing)]`, add a short CI fuzz smoke + corpus.
  Owned: `fuzz/`, `src/discovery/scan.rs`, `crates/manifest/`.
- **F-06 — engine.rs god object (~15,370 lines).** Fix: extract
  rotation/selection (extend `scheduler.rs`), publication lowering, and
  rescan-retention into owned modules; pure moves + re-export shims, no
  behavior change; pin with the existing engine test suite. Owned:
  `src/discovery/`.
- **F-07 — run/attach/engine coupling.** Fix: declare one layering
  direction (attach→engine→run), move `impl EngineSession for Session`,
  split `capture_profile`/tick skeleton into lifecycle stages. Owned:
  `src/run.rs`, `src/attach.rs`, `src/discovery/engine.rs`.
- **F-08 — untyped evidence constructor.** Fix: make `profile_json` take a
  `VersionedEvidence` newtype so `versioned_evidence(ev)` is
  type-enforced, not call-site discipline; keep the Python oracle as a
  second reader. Owned: `src/render.rs`, contract tests. (Pairs with
  F-12/F-50.)

### Medium residuals

- **F-01 (partial) — override not in durable evidence.** Core fail-closed
  fixed; `--allow-uretprobe-on-confined-target` (and hazard `Proceed`
  overrides) still surface only as stderr warnings. Fix: record the
  override flag + hazard reason in report evidence
  (`src/render.rs` evidence struct + `src/run.rs:2339-2355` mapping) with
  an oracle pin. Lower severity than the original High by itself.
- **F-10 — unsafe-decoder build single point.** Fix: add an object-level
  absence assertion (scan release binary/map inventory for unsafe-decoder
  symbols — extend `build-release.sh:679-713` checks into a failing test)
  so a misbuild fails loudly. Owned: `build-release.sh`, release tests.
- **F-12 — metrics/profile evidence split.** Fix: document the split in
  the v3 schema doc (which 4 `#[serde(skip)]` fields, which verdict
  function each lane uses) and emit a `lane` discriminator; longer term,
  unify on `versioned_evidence`. Owned: `src/render.rs:1099-1127`,
  `docs/schema/`, oracle.
- **F-14 — future-minor tables silently invisible.** Fix: emit an explicit
  `unsupported_version` skip + counter when `spans_for` refuses
  (`scan.rs:1060`), and reconcile the Slice-1 vs v0.1 matrix docs.
- **F-15 — live-child handoff exits 0 unnamed.** Fix: print/persist the
  orphan PID + handoff state on the terminal path (`run.rs:194,1456`)
  and return it in a machine-readable field; keep exit 0 but name the
  child. Owned: `src/run.rs`, `src/cli.rs` help.
- **F-16 (narrowed) — lifetime capacity.** Silent-history part refuted;
  what remains is the lifetime-capacity experiment facet. Fix: wire G's
  `src/capacity.rs` inventory (`history_records`, append-only +
  tombstoned-for-lifetime) into admission + evidence, then run the
  E20-lifetime experiment (capacity exhaustion → disclosed refusal, no
  silent loss). Owned: `src/capacity.rs`, history/semantics admission,
  `tests/capacity_contract.rs`.
- **F-17 — hidden 10M trace cap.** Fix: surface the default in help +
  no-duration notice, and cite the effective cap (not `--max-events`)
  in the TRUNCATED message (`run.rs:2887`, `trace.rs:171`).
- **F-18 — global signal handlers.** Fix: add opt-out/RAII guard with
  double-registration protection and restoration on drop; keep CLI
  behavior. Owned: `src/run.rs:1401,1465`.
- **F-19 — unvalidated pub-field args.** Fix: add `validate()` constructors
  (or a builder) enforcing the CLI-only combination rules for library
  users; document the supported surface. Owned: `src/cli.rs:24,65`,
  `src/run.rs:1542` region.
- **F-21 — `params:null` ambiguity.** Fix: emit an explicit
  `params_omitted_reason` enum (policy-forbidden vs none-observed) beside
  `params`; update schema doc + oracle. Owned: `src/render.rs`, docs.
- **F-22 — path labels as strings.** Fix: newtype the label
  (`TargetPathLabel`) with a constructor refusing direct `open()`, and
  document the `{dev,ino,sha256}` identity as the machine key. Owned:
  `src/render.rs:329` region.
- **F-23 — scale cliff edges (by design).** Ceilings retained deliberately;
  B/C cut false exhaustion. Fix (product/docs): lead the product story
  with the 512/512/256 bounds and per-lane degradation table; emit G's
  admission envelope into output once wired. Owned: docs, `render.rs`, G.
- **F-24 — remap residual (ABA).** Mitigations preserved and intact. Fix:
  close the proof gap with an adversarial equal-snapshot ABA/content-
  mutation test (gated, owned fixtures); only then consider narrowing
  the pin→open window. Refs: F-24 proof gap.
- **F-25 — `--pause auto` wedge.** Fix: pause watchdog — bounded STOP
  window + forced CONT + evidence entry; owned NSS-cascade regression
  test. Owned: `src/discovery/pause.rs:338`, `docs/usage.md:333`.
- **F-26 — invisible `P11SCOPE_*` behavior switches.** Fix: list every
  `P11SCOPE_*` var in `--help`/usage + capture evidence (name, effect,
  active value); keep absent→narrow default. Owned: `src/cli.rs`,
  `src/render.rs`, `engine.rs:4032` region.
- **F-27 — no advisory scanning.** Fix: add `cargo audit`/`cargo deny` CI
  gate + `deny.toml`; schedule pin review for aya/object/pkcs11 deps.
- **F-28 — release bytes never built in CI.** Fix: release-preview job
  (musl build, docker build/lint, kubeconform, SBOM, `build-release.sh`
  wired). Owned: `.github/workflows/ci.yml`, `build-release.sh`.
- **F-29 — suite feedback time + flakes.** Fix: shard/schedule the 128
  hosted cases, quarantine + own the 7 documented flakes with wall-clock
  isolation (`CARGO_TARGET_DIR` per lane), keep the no-weakening rule.
- **F-30 — docs/help drift.** Fix: excerpt-equality tests for `*_HELP` vs
  USAGE + a CI drift check for flags (`--attach-backend`, `--version`,
  new Package A/B/C/F flags). Owned: `src/cli.rs` tests, `docs/usage.md`.
- **F-31 — 4-artifact verdict predicate.** Fix: pin the two surviving
  conjuncts (`initial_set_timing`, `known_pre_relocation`) with focused
  tests + a verdict-monotonicity property; single-source the predicate
  where feasible. Owned: `src/render.rs`, oracle, schema doc.
- **F-32 — dual-backend equivalence.** Fix: recurring CI gate running the
  Task 2.3 multi-vs-singles equivalence lane on every attach change.
- **F-33 — discover helper sandbox.** Fix: add seccomp/net/mount sandboxing
  to the helper (uid-drop stays), with an owned malicious-provider test.
  Owned: `crates/discover/`. Investigate separately from the observer.
- **F-34 — BPF trust root + attach binding.** Fix: open the remaining
  bodies (`scope_auth`, `store_start` agreement, `publish_descriptors`
  correctness, unsafe decoder depth) with owned adversarial tests; sign/
  attest the BPF object at build. Owned: `crates/ebpf/`, `identity.rs`.
- **F-35 — spoofing residuals.** Fix: bind loader contexts, assert
  `task_cookie` uniqueness, verify manifest re-check at pin time — each
  with a dedicated test. Owned: identity/scan/attach paths.
- **F-36 — stringly errors.** Fix: convert `Result<_, String>` to typed
  errors with kinds + sources, starting at existing `map_err` sites.
- **F-37 — history clones per transaction.** Fix: measure on system scope
  first (O-13 profile exists in `perf/REPORT.md`), then replace
  full/visible clones (`engine.rs:1117,1195,1401`) with structural
  sharing/RC; pin with discovery equivalence tests. E-perf deliberately
  did not touch this.
- **F-39 — `#[cfg(test)]` in prod.** Fix: move test-only fields/ctors to
  fixture modules behind a non-`test` cfg (e.g. `fuzzing`/audit) so the
  shipped binary matches the tested one.
- **F-40 — no coverage measurement.** Fix: add llvm-cov/tarpaulin CI gate
  with a ratchet on touched crates; use it to flag production-unreachable
  tested code (the F-44 class).
- **F-41 — decoder/budget/state-machine property gaps.** Fix: land the P1–P7
  in-crate property suites (needs proptest decision, gap 5) + the
  `spans_for`-vs-`select()` 2¹⁶ oracle; expose glue via `#[cfg(fuzzing)]`.
- **F-42 — dual-authority consumer discipline.** Fix: encode the
  STATS-vs-EVENTS authority split in types/accessors (one module owns
  each join) so new consumers cannot silently overclaim; add a consumer
  checklist test. Owned: `src/events.rs`, `src/semantics.rs`.
- **F-43 — aya fork with no exit plan.** Fix: rebase onto upstream
  multi-uprobe (merged 2026-07), or document the pinned-fork policy with
  a rebase cadence. Owned: `Cargo.toml:47`, `third-party/`.
- **F-44 — dead `Tracker::identify` + pidfd machinery.** Fix: delete or
  wire it (coverage gate F-40 flags the class); remove speculative
  allows/`TaskMembership` adapter. Owned: `src/process.rs:130`.

### Low residuals (brief sketches)

- F-45: dedup failure entries across re-rounds in `attach.rs:1776` loop.
- F-46: `debug_assert!` → `const` asserts in `crates/bpf-multi/src/lib.rs:157`.
- F-47: parser hardening batch in `src/cli.rs` (reject `--duration 0`,
  usage-2 for `--pid 0`, atomic trace `-o`, etc.).
- F-48: `#[must_use]` on `AtomicFile` + verify final-name stat policy
  (`src/output.rs:41,182`).
- F-49: machine-readable trace line option (documented grammar or JSONL).
- F-50: document the 4 missing F3 fields + F5 bundle + stringly enums in
  schema docs; publish a machine-readable JSON schema.
- F-51: `# Safety` docs on the 10 `unsafe` families; add `missing_docs`
  lint (F-52) to stop recurrence.
- F-52: add `[lints]`/clippy.toml/rustfmt.toml + `missing_docs` on the
  17-module pub surface.
- F-53: accepted; revisit only if the threat model changes (local write +
  µs race already documented in SAFETY comment).
- F-54: replace capture-aborting `expect()`s on target-byte paths with
  typed errors, starting with the cross-crate catalog invariant.
- F-55: escape/sanitize `attach_failures[]` bytes at ingestion
  (`render.rs:402`).
- F-56: `AtomicFile`-style atomic write + stdout `--help` in
  `crates/discover/src/main.rs:419,460`.
- F-57: bounded; document SUDO_UID/GID selector semantics in runbook (F-60).
- F-58: per-facet micro-fixes (saturating-rule consistency T7, chmod-before-
  truncate I3, EMFILE degrade D7, symlink policy matrix E4, …).
- F-59: sanitize newlines in `doctor.rs:1183` `render()` details.
- F-60: decision index + operator runbook mapping failure modes to actions.
- F-61: handle/log the discarded errors (`raise_nofile`, doctor `write!`,
  `fetch_update`).
- F-62: single Python entry point; schedule the 4 `#[ignore]`d tests into
  the privileged job.
- F-63: shellcheck/ruff in CI over `scripts/`.
- F-64: levels/timestamps/`--quiet` for diagnostics (aggregator already
  covers volume).
- F-65: document the edition split; remove the `PausePolicy` re-export.
- F-66: maintenance preference; adopt clap only with binary-size evidence.
- F-67: disclosed; no action unless the collapse heuristic changes.
- F-68: accepted; optional breadth warning for `--system` reports.
- F-69: accepted structural; sign/attest BPF object + privilege separation
  when release qualification demands it.

## 4. Cited line-number drift (FINDINGS.md → tip)

| Finding | Old cite | Tip location |
|---|---|---|
| F-01 | `uretprobe_hazard.rs:105`, `:184`; `run.rs:2305` | Unknown/None arm `:109-115`, Proceed→Refuse; `evaluate` `:198`; death report `run.rs:2314-2320` |
| F-02 | `run.rs:3394,3843`; `render.rs:792` | `run.rs:3433,3885,7615`; `render.rs:2840` |
| F-03 | `Cargo.toml:47`; `ci.yml:81,82,102,103` | `Cargo.toml:47` unchanged; fetch `:86-87`, tests `:107-108` |
| F-09 | `doctor.rs:531,542,:1103` | const `:519`, emissions `:537,:546`, classifier `:1113-1115`; producer renamed `(own libc)`→`(self)` |
| F-11 | `sink.rs:60-90`; `run.rs:2125,2157` | `stdout_sink_from` `:163-205`; `run_owned_inner` `:2133`, spawn `:2153` |
| F-13 | `render.rs:644-645`; validator `:249-254,:971` | producer unchanged; validator `:252-260`, `:979-980` |
| F-16 | `run.rs:2431-2439` etc. | admission/reject paths moved with run.rs growth; reverify by symbol |
| F-20 | `inspect.rs:307-310` | replaced by `emit_diagnosis` `:326-352` (JSON doc `:335-340`) |
| F-23 | ceilings prose | `scan.rs:35-37`, `engine.rs:2956`, `plan.rs:215` (values unchanged) |
| F-70 | `engine.rs:3992-4001,:12795,:12816,:12902`; `engine_tests.rs:4847-4853` | rotation `scheduler.rs:38-96,178-185,254,344`; selection `engine.rs:3927,13322,13500,13517`; old zero-expectation revised |
| F-71 | `scan.rs:1200,:1070`; `engine.rs:9302-9309`; `plan.rs:719-725`; `engine.rs:8485` | pre-check removed (`:1379-1382`); exemption `:1249-1265`; retention `:9687-9746`; retire `plan.rs:870`, detach `engine.rs:8681` |
| F-72 | `engine.rs:12440,:5699,:10108,:10158,:9714` | dispatch `:12899-12945`; heap arm `:5899-5929`; authority `:10544-10597`; file gate `:10478-10494`; readers `:10735/:10761` |
| F-73 | `scan.rs:1348,:609-617,:1329` | admit call `:1586` (repeat-guarded `:1582-1584`); `admit_interface` `:783-792`; stop `:787` |
| F-74 | `measure.py:708-718`; `run.rs:1509-1513,:3054` | `derive_phases` `:747+`; preflight `:1507-1514`; marker `:2881-2883` |
| F-75 | `semantics.rs:1600,2333,:2332-2349,:2358-2371,:2304-2312` | `collided` `:1930`; key `:2081`; tombstone `:2886-2900`; join `:2939-2944`; completion `:2843-2849` |
| F-12 | `render.rs:1099-1127` | `:1101` region (doc nit at `:453`) |
| F-17 | `run.rs:2851` | `:2887` |
| F-18 | `run.rs:1447,1508,2079` | `SignalState` `:1401`, `install_stop_flag` `:1465` |
| F-26 | `engine.rs:3884,:3496` | env check `:4032` |
| F-37 | `engine.rs:1095,1322` | clones `:1117,:1195,:1401` |

## 5. R-record reopen check

- R-01 (14 refuted insecure-defaults): not reopened. Package A narrowed
  the F-01 corner R-01#3 explicitly reserved; the FP verdicts (double
  gates, fail-secure defaults) are untouched — e.g. the attach
  double-gate R-01#2 cites is intact (`attach.rs:696`).
- R-02 (mitigated STRIDE): D4's control (cap + two-phase sweep + published
  cap-skip) survives Package C — `MAX_SCAN_PIDS=256` unchanged, rotation
  adds disclosed deferral/rotation evidence and over-cap bound tests.
  T6/I2/E5 controls untouched (no domain/pseudonym/SUDO changes).
- R-03/R-04/R-05/R-06: no package touched their subject matter
  (differential deltas, killed mutants, verified-safe notes, OASIS
  grounding) except E-perf's O-15 rejection, which is consistent with
  R-06's "catalog equality ≠ runtime conformance" stance.

