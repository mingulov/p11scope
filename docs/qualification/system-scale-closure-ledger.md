<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System-scale closure ledger

Finish plan Task 0 box 3 + Task 0b. One row per finding; columns are exactly
`ID | title | disposition | owner | check | evidence`.

## Rules applied

- `source-fixed` only with a fixing commit verified as an ancestor of `main`
  via `git merge-base --is-ancestor <sha> main` (run 2026-09-25, main =
  `90b44ff491ac5cfd5a0ef203b754e5906f99a9fd`). Plan checkmarks were never
  treated as evidence. Key fixes were additionally spot-checked present at
  the main tip (F-09 const, F-03 p2 CI, F-02 drain_proven, F-11 sink,
  F-44 cfg(test), F-75 collided, F-27 deny.toml, F-29 quarantine, F-63
  lint gates, F-40 floor 83).
- `runtime-verified@hash` only with a hash plus an evidence path. No finding
  qualified: E01's executed run established a *failed* baseline, and the
  audit F1–F9 reproductions verify defects, not fixes.
- Owner for every `source-fixed`, `refuted`, and `accepted-boundary` row is
  T13: the finish plan gives T13 the audit that reconciles every disposition
  against final source/evidence. Owners `recovery` and `stop-gate-done` are
  unused: recovery tasks are complete and stop-gate work closed no ledger
  finding (its I1–I4/M1–M2 items are stop-gate-local).
- Compound findings are split: F-58 into 8 facet rows, F-16 into refuted +
  open facets, F-61 into userspace + BPF-note facets.
- Doc abbreviations: FI = FINDINGS.md, TR = findings-triage.md,
  SE = SYSTEM-EXPERIMENTS.md, RP = perf/REPORT.md, AJ = findings.json,
  FB = Fable xhigh review.md, PD = product-defects plan, FP = finish plan,
  HV = harvest-followups report.

## Inputs (G-09: triage reachable from here)

| Doc | Path | SHA256 |
|---|---|---|
| FI | `p11scope/audit-notes/FINDINGS.md` | `612692cda4511fdba00ec2753b49b2f8f2535385f29e9482790aafb80f6f9766` |
| TR (UNTRACKED — controller to commit) | `/home/user/src/m/p11scope-ws/p11scope/findings-triage.md` | `9ed3df77157402aab87b0661f17cc6822fa131ce635e9738bde874b9d4807220` |
| AJ | `audit-system-scale-2026-09-20/findings.json` | `34097b5fb209bac73413f006be4bd5f31b2a3e290e4bd5f31b2a3e290e4d591076d9436c435fe0f8` |
| AJ writeups | `audit-system-scale-2026-09-20/findings/f1-..-f9/` (9 dirs) | see AJ |
| SE (E01–E25 live here, not in the audit dir) | `p11scope/audit-notes/perf/SYSTEM-EXPERIMENTS.md` | `658b36af2239d4e64257a1b5787d0d98097e3821436ee0e3b8185fbd9f084b83` |
| RP (O-1–O-18) | `p11scope/audit-notes/perf/REPORT.md` | `0b1ec9ddac3edc9fb9b7dae643b112a75e56315e25c87bd547473780e56d1c13` |
| FP | `docs/superpowers/plans/2026-09-22-system-scale-finish.md` | `8e754818363ac71929dbc235296cf21f3246cb1fb47f18bc9b5599d739f94578` |
| PD | `docs/superpowers/plans/2026-09-23-product-defects.md` | `8c75f43febb0529d2b1e5fd486fa90b36cf85a0350cf9fcb38fd40571adbd92e` |
| FB (only copy; U-12 source) | `/var/tmp/p11scope-ws-tmp/full-system-20260922.FbcpaT/claude-review/review.md` | `a7a267ac17500b64836f3d98403ac9976b3b0cd19666e471dfbf07fa0422c3c5` |
| HV (U-12 routing) | `docs/superpowers/reports/2026-09-23-harvest-followups.md` | `02333d4374d73e1630961ebfef5695a01b670e5a3a8fa4f865ce87051fb69d2e` |

Task 0b notes adjudicated:

- F-25 via PD T4: the claim exists (PD Task 4, "Bounded shutdown when a
  paused child cannot be released (F-25)"). Stronger than
  claimed-not-reverified: the PD T4 commits are on main (`b14d96e`,
  `7852c24`, `5b2bd01`, `e72b79b`, all ancestors of main; commit verdict:
  "no wedge remains in the current code", wedge caveat replaced by a stated
  shutdown bound). No rework. Disposition: `source-fixed`.
- F-03 recorded fixed with FI text correction: FI's revalidation text
  ("Confirmed, narrower CI defect") predates Package A and is stale. CI now
  fetches/tests the shipped `-p2` trees with drift visible via
  `third-party/sources.json`. Disposition: `source-fixed`.
- Task 0b "40 findings open" reconciles as 37 F-findings `required-open`
  (44 rows with F-58/F-16/F-61 splits) plus accepted-boundary items the
  estimate had counted as open. "24 with no fixing task" is now 6
  NEEDS-OWNER at that checkpoint; the 2026-09-26 product-quality plan routes
  those six below without changing their required-open disposition.

## F-01–F-75

| ID | title | disposition | owner | check | evidence |
|---|---|---|---|---|---|
| F-01 | uretprobe-vs-seccomp fail-open | source-fixed | T13 | `the_full_verdict_target_matrix_fails_closed` + oracle `exact_terminal_verdict` | `cf35ac4,85042a2,f34a49e,9c2de0b,28f4617,9252cba` (903026d) + `e29464b` (override in evidence) |
| F-02 | completeness always PARTIAL | source-fixed | T13 | oracle `exact_terminal_verdict` | `e29464b` (drain_proven latch + verdict_detail) |
| F-03 | CI tests stale -p1, ships -p2 | source-fixed | T13 | `tests/python/test_ci_dependency_selection.py` | `b04dd67,964f396`; FI "confirmed" text corrected (see above) |
| F-04 | no hosted E2E in CI | source-fixed | T13 | `ci.yml` privileged-e2e job | `b0c78ae` |
| F-05 | privileged parsers, no fuzz/PBT | required-open | T12 | NONE-YET | E21 campaign; `src/discovery/scan.rs`, `crates/manifest/` |
| F-06 | engine.rs god object | required-open | T6 | NONE-YET | `src/discovery/engine.rs` (~15,370 lines); split alongside T6 coordinator |
| F-07 | run/attach/engine coupling | required-open | T6 | NONE-YET | `src/run.rs`, `src/attach.rs`, `src/discovery/engine.rs` |
| F-08 | untyped evidence constructor | source-fixed | T13 | NONE-YET | `e29464b` (VersionedEvidence newtype) |
| F-09 | doctor always reads T0 | source-fixed | T13 | `tier_classification_reads_the_row_bpf_checks_actually_emits` | `2e914d1` |
| F-10 | unsafe-decoder build SPOF | required-open | T13 | NONE-YET | object-absence assertion; `build-release.sh:679-713`, `src/attach.rs:696,724` |
| F-11 | shared-stdout O_NONBLOCK leak | source-fixed | T13 | `stdout_sink_from_a_pipe_leaves_the_shared_description_blocking` (+socket/file) | `7e9f940`; E17 live backpressure repro still pending |
| F-12 | metrics/profile split undocumented | source-fixed | T13 | oracle lane discriminator | `e29464b` |
| F-13 | sixth skip reason rejected | source-fixed | T13 | `tests/python/test_skip_reason_vocabulary.py` | `3427bde` |
| F-14 | future-minor tables invisible | source-fixed | T13 | skip-reason vocab test (7 reasons) | `e29464b` |
| F-15 | unnamed live-child handoff | source-fixed | T13 | oracle `handoff_child_pid` pin | `e29464b` |
| F-16a | silent history loss facet | refuted | T13 | NONE-YET | FI revalidation: `State::reject_history` + `semantic_history_drops` gates completeness |
| F-16b | lifetime capacity facet | required-open | T7 | NONE-YET | wire `src/capacity.rs:74-88`; E20-lifetime experiment |
| F-17 | hidden 10M trace cap | source-fixed | T13 | NONE-YET | `e29464b` (help + notice + TRUNCATED cite cap) |
| F-18 | global signal handlers | required-open | T10 | NONE-YET | `src/run.rs:1401,1465`; opt-out/RAII guard |
| F-19 | unvalidated pub-field args | required-open | T10 | NONE-YET | `src/cli.rs:24,65`; validate() constructors |
| F-20 | inspect --json non-JSON path | source-fixed | T13 | `soft_diagnosis_failure_with_json_prints_a_failure_document` | `88e43fc` |
| F-21 | params:null ambiguity | required-open | T10 | NONE-YET | `src/render.rs:3514`; emit `params_omitted_reason` |
| F-22 | path labels as plain strings | required-open | T10 | NONE-YET | `src/render.rs:329`; TargetPathLabel newtype |
| F-23 | semantic collapse at scale | required-open | T12 | NONE-YET | `scan.rs:35-37`, `engine.rs:2956`, `plan.rs:215`; tested envelope + product story |
| F-24 | mid-scan remap ABA residual | required-open | T6 | NONE-YET | `engine.rs:2314`; adversarial equal-snapshot ABA test |
| F-25 | pause-auto wedge | source-fixed | T13 | `operator_stop_delivers_sigterm_to_a_held_child_then_escalates_within_the_bound` | `b14d96e,7852c24,5b2bd01,e72b79b` (PD T4, on main); no rework |
| F-26 | invisible P11SCOPE_* switches | source-fixed | T13 | oracle `p11scope_env` pin | `e29464b` |
| F-27 | no advisory scanning | source-fixed | T13 | `cargo audit` + `cargo deny check` (ci checks-and-e2e) | `b0c78ae` + `deny.toml` |
| F-28 | release bytes never built in CI | source-fixed | T13 | `ci.yml` release-preview job | `b0c78ae` |
| F-29 | suite time + flakes | source-fixed | T13 | `scripts/run-flake-quarantine.sh` (ci quarantine job) | `b0c78ae` |
| F-30 | docs/help drift | source-fixed | T13 | `usage_doc_documents_every_cli_flag` + `tests/python/test_help_usage_drift.py` | `e29464b,b0c78ae` |
| F-31 | 4-artifact verdict predicate | required-open | T10 | NONE-YET | pin `initial_set_timing` + `known_pre_relocation`; monotonicity property |
| F-32 | dual-backend equivalence gate | required-open | T13 | NONE-YET | recurring multi-vs-singles lane (manual owned lane) |
| F-33 | discover helper sandbox | required-open | T5/T13 | NONE-YET | `crates/discover/src/main.rs:314`; uid-drop only |
| F-34 | BPF trust root unaudited | required-open | T8 | NONE-YET | `crates/ebpf/`, `identity.rs`; open bodies + sign/attest |
| F-35 | spoofing residuals | required-open | T3 | NONE-YET | loader contexts, task_cookie, manifest re-check |
| F-36 | stringly-typed errors | required-open | T5/T6 | NONE-YET | `Result<_,String>` pervasive |
| F-37 | whole-history clones | required-open | T12 | NONE-YET | `engine.rs:1117,1195,1401`; E25/O-13 measurement first |
| F-38 | function_id per-call hotspot | refuted | T13 | NONE-YET | FI revalidation + `task-Eperf-report.md:110-115`; production caches id in SlotMeta |
| F-39 | cfg(test) in prod modules | required-open | T13 | NONE-YET | `hooks.rs:19`, `loader.rs:2`, `pause.rs:460` |
| F-40 | no coverage measurement | source-fixed | T13 | `cargo llvm-cov --lib --fail-under-lines "$(cat .coverage-floor)"` (floor 83) | `b0c78ae` |
| F-41 | decoder/budget property gaps | required-open | T12 | NONE-YET | P1–P7 suites + spans 2^16 oracle; E21/E22 |
| F-42 | dual-authority consumer risk | required-open | T8 | NONE-YET | type the STATS-vs-EVENTS split; `src/events.rs`, `src/semantics.rs` |
| F-43 | aya fork, no exit plan | required-open | T13 | NONE-YET | `Cargo.toml:47`; `third-party/`; rebase vs pinned-fork policy |
| F-44 | dead Tracker::identify | source-fixed | T13 | NONE-YET | `e29464b` (cfg(test) ladder; `retire` deleted) |
| F-45 | re-round duplicate failures | required-open | T5 | NONE-YET | `src/attach.rs:1776` |
| F-46 | debug_assert UAPI layouts | required-open | T8 | NONE-YET | `crates/bpf-multi/src/lib.rs:157`; const asserts |
| F-47 | CLI parser edge gaps | required-open | T10 | NONE-YET | `src/cli.rs:743`; SE-04..SE-11 batch |
| F-48 | AtomicFile must-use/stat | source-fixed | T13 | `final_name_is_never_stated_only_renamed_over` | `e29464b` |
| F-49 | trace line format | required-open | T10 | NONE-YET | `src/trace.rs:143`; machine-readable option |
| F-50 | schema-doc precision debt | source-fixed | T13 | `tests/python/test_schema_json.py` | `e29464b` |
| F-51 | unsafe w/o Safety docs | required-open | T13 | NONE-YET | 174 unsafe sites, 0 Safety docs in `src/` |
| F-52 | no shared lint config | required-open | T13 | NONE-YET | add `[lints]`/clippy.toml/rustfmt.toml + missing_docs |
| F-53 | mapped-file SIGBUS race | accepted-boundary | T13 | NONE-YET | `crates/manifest/src/elf.rs:351` SAFETY; plan-accepted |
| F-54 | expect()-as-invariant | required-open | T5/T8 | NONE-YET | 173 non-test `expect()` sites; target-byte paths first |
| F-55 | raw bytes in attach_failures | required-open | T10 | NONE-YET | `src/render.rs:402`; sanitize at ingestion |
| F-56 | discover -o hygiene | required-open | T5/T10 | NONE-YET | `crates/discover/src/main.rs:419,460` |
| F-57 | SUDO_UID selector semantics | accepted-boundary | T13 | NONE-YET | `src/run.rs:452-504`; bounded; document in runbook |
| F-58-T7 | u64 counter wraps in release | required-open | T8 | NONE-YET | saturating-rule consistency (STRIDE T7) |
| F-58-R2 | malformed-EVENTS forensics | required-open | T8 | NONE-YET | `src/events.rs:327` counter-only (STRIDE R2) |
| F-58-R3 | saturating context_failures | required-open | T6 | NONE-YET | loader contexts (STRIDE R3) |
| F-58-R5 | sink-by-convention only | required-open | T10 | NONE-YET | all-stdout-through-sink unenforced (STRIDE R5) |
| F-58-I3 | chmod-after-truncate window | required-open | T10 | NONE-YET | `src/output.rs:239` (STRIDE I3) |
| F-58-D7 | EMFILE ends whole run | required-open | T10 | NONE-YET | degrade instead of abort (STRIDE D7) |
| F-58-D8 | doctor detach-on-drop | required-open | T12 | NONE-YET | suspected; verification test on final bytes (STRIDE D8) |
| F-58-E4 | symlink policy matrix | required-open | T3 | NONE-YET | openers policy unstated (STRIDE E4) |
| F-59 | doctor render newline split | source-fixed | T13 | NONE-YET | `e29464b` (escape newlines/controls) |
| F-60 | notes sprawl, no runbook | required-open | T13 | NONE-YET | decision index + operator runbook |
| F-61a | discarded userspace errors | required-open | T10 | NONE-YET | `process.rs:704`, `run.rs:1145`, doctor `write!`, `fetch_update` |
| F-61b | BPF diagnostic notes | accepted-boundary | T13 | NONE-YET | correct/noted/unreachable-convention facets |
| F-62 | no Python entry point; ignored | required-open | T13 | NONE-YET | single runner; schedule 4 `#[ignore]`d tests |
| F-63 | no script lint in CI | source-fixed | T13 | `shellcheck -S error scripts/` + `ruff check scripts/ tests/python/` | `b0c78ae` |
| F-64 | no levels/timestamps/quiet | required-open | T10 | NONE-YET | 29 eprint sites; `noise.rs:154` aggregator exists |
| F-65 | edition split; re-export nit | required-open | T13 | NONE-YET | `Cargo.toml:4`; `pause.rs:145` |
| F-66 | hand-rolled CLI parser | optional | T13 | NONE-YET | `src/cli.rs` ~1,466 lines; clap only with binary-size evidence |
| F-67 | overlay-collapse uncertainty | accepted-boundary | T13 | NONE-YET | `engine.rs:5170`; disclosed |
| F-68 | --system breadth operator-gated | accepted-boundary | T13 | NONE-YET | documented behavior; optional breadth warning |
| F-69 | no privsep; unsigned BPF obj | accepted-boundary | T13 | NONE-YET | structural pre-release; sign/attest when demanded |
| F-70 | full view cap blocks explore | source-fixed | T13 | `e06_unique_provider_reached_within_bounded_frames` + T6/T12 live replay | `dd0fe8a,ed0ab19,961eec2,c188e8b,959b699` (4407927); owned-full residual by design |
| F-71 | budget rescan retires cover | source-fixed | T13 | `e07_unchanged_complete_loader_rescan_retires_nothing` + live replay | `b7835e1,bacda87,f5dd0f1` (eb26cb9) |
| F-72 | C_GetInterface admission gaps | source-fixed | T13 | `f_e08_named_gi_heap_matches_list_element` + live replay | `41fbff2,d155a54` (d6c5bea); authority gates retained by design |
| F-73 | interface rescans burn life | source-fixed | T13 | `e09_repeated_interface_rescans_charge_once_but_work_every_time` | `bacda87`; 512 ceiling retained by design |
| F-74 | harness invents collapse cause | source-fixed | T13 | `tests/python/test_measure_e03.py` (21 tests) | `0523989,b396ba9`; fd-plateau still estimated (disclosed) |
| F-75 | async cross-process collision | source-fixed | T13 | `e20_collision_tombstone_lifecycle_matrix` + live E20 same-domain check NOT implemented (open, T9) | `2ef93d1,64874e1,fc24b41,fe2f867` (e1f6d3a,672df5f) |

## R-01–R-06

| ID | title | disposition | owner | check | evidence |
|---|---|---|---|---|---|
| R-01 | insecure-defaults x14 | refuted | T13 | NONE-YET | FI:790-815; all FALSE POSITIVE / out of scope |
| R-02 | STRIDE mitigated x4 | accepted-boundary | T13 | NONE-YET | FI:817-827; T6/I2/D4/E5 controls kept as regression guards |
| R-03 | differential cleared | refuted | T13 | NONE-YET | FI:828-838; zero security regressions |
| R-04 | mutants killed | refuted | T13 | NONE-YET | FI:839-846; M3-M6 killed |
| R-05 | verified-safe notes | accepted-boundary | T13 | NONE-YET | FI:847-865 |
| R-06 | OASIS grounding gap | accepted-boundary | T13 | NONE-YET | header SHA256 `3a205ff9…cd182fa0`, 104/104; runtime remainder owned by E22 |

## O-1–O-18

| ID | title | disposition | owner | check | evidence |
|---|---|---|---|---|---|
| O-1 | per-tick consumer re-mmap | required-open | T6 | NONE-YET | `run.rs:3068,4377`; `events.rs:373-382`; E04 gate |
| O-2 | SlotMeta heap clone | optional | T12 | NONE-YET | `semantics.rs:1889`; E19-gated micro-opt |
| O-3 | String op labels | optional | T12 | NONE-YET | `semantics.rs:1973-1977`; E19-gated micro-opt |
| O-4 | repeated map lookups | optional | T12 | NONE-YET | `semantics.rs:1890-1893` etc.; E19-gated micro-opt |
| O-5 | trace emit allocs | optional | T12 | NONE-YET | `trace.rs:143-160`; `run.rs:4002`; E19-gated |
| O-6 | frame snapshot clones | required-open | T8 | NONE-YET | `run.rs:3156,3168`; `metrics.rs:73-115`; E18 |
| O-7 | record_template lookups | optional | T9 | NONE-YET | diagnostic-only path; `semantics.rs:2504-2510` |
| O-8 | receipt module recompile | optional | T13 | NONE-YET | `scripts/_loader.py:26`; test-only |
| O-9 | canary/mapdef reload | optional | T13 | NONE-YET | `test_canary_evidence.py`; test-only |
| O-10 | session→op index | required-open | T9 | NONE-YET | `semantics.rs:2540-2563`; E20-gated |
| O-11 | pending-eviction index | required-open | T9 | NONE-YET | `semantics.rs:2407-2438`; 16,384 saturation cliff |
| O-12 | contract-driver memoize | optional | T13 | NONE-YET | test-only; smallest CI win |
| O-13 | discovery tick clones | required-open | T12 | NONE-YET | F-37-adjacent; measured startup hotspot; E25 |
| O-14 | run-flow early ring loss | required-open | T6 | NONE-YET | 10–18% ramp-up loss; pre-warm/delay/ring decision |
| O-15 | function_id hoist | refuted | T13 | NONE-YET | RP:126; cited calls are in `corrective_tests` |
| O-16 | quadratic fork work | required-open | T9 | NONE-YET | `semantics.rs:2665,2689`; E20 work-count assertions |
| O-17 | lifetime resource policy | required-open | T7 | NONE-YET | `semantics.rs:1795-1810`; `history.rs:170`; E10 |
| O-18 | mechanism dedup | optional | T12 | NONE-YET | `apply_operations:2031-2043`; E19-gated micro-opt |

## E01–E25 (experiment gates; final replay in T12 unless noted)

| ID | title | disposition | owner | check | evidence |
|---|---|---|---|---|---|
| E01 | PID vs true system scope | required-open | T12 | `system-scope-measure.sh --scope both --mode both` on final bytes | SE:60; failed baseline @885ed65 — re-run required |
| E02 | doctor/contract reality | required-open | T12 | NONE-YET | SE:86; partly executed |
| E03 | benchmark validation | required-open | T12 | `tests/python/test_measure_e03.py` + re-run | SE:99; F-74 fixed harness |
| E04 | persistent EVENTS consumer | required-open | T6 | NONE-YET | SE:114; O-1 correctness gate + measure |
| E05 | cross-module admission | required-open | T7 | NONE-YET | SE:133 |
| E06 | fair exploration at full cap | required-open | T6 | `e06_unique_provider_reached_within_bounded_frames` + live replay | SE:153 |
| E07 | incomplete rescan retention | required-open | T6 | `e07_unchanged_complete_loader_rescan_retires_nothing` + live replay | SE:166 |
| E08 | factory-form equivalence | required-open | T5 | `f_e08_named_gi_heap_matches_list_element` + live replay | SE:180 |
| E09 | interface dedup budgets | required-open | T6 | `e09_repeated_interface_rescans_charge_once_but_work_every_time` + live replay | SE:193 |
| E10 | lifetime slot exhaustion | required-open | T7 | NONE-YET | SE:205 |
| E11 | kernel map ceilings | required-open | T7 | NONE-YET | SE:217 |
| E12 | reentrancy/missing returns | required-open | T8 | NONE-YET | SE:229 |
| E13 | first-call gap | required-open | T2 | NONE-YET | SE:241 |
| E14 | lifecycle recovery | required-open | T4 | NONE-YET | SE:253 |
| E15 | ABI/semantic authority | required-open | T5 | NONE-YET | SE:271 |
| E16 | unsupported surfaces | required-open | T11 | `python3 -I tests/python/test_e16_oracle.py -v` + `--test e16_execution_surfaces` | SE:281; FP-T11 gate |
| E17 | slow sink/burst/cancel | required-open | T10 | NONE-YET | SE:294 |
| E18 | metrics extraction cost | required-open | T8 | NONE-YET | SE:304; O-6 |
| E19 | reducer/trace allocs | required-open | T9 | NONE-YET | SE:316 |
| E20 | semantic scaling/isolation | required-open | T9 | `e20_collision_tombstone_lifecycle_matrix` (unit only); live E20 same-domain collision check NOT implemented | SE:327; F-75 unit-fixed; live check NOT implemented, open requirement |
| E21 | parser/privacy stress | required-open | T12 | NONE-YET | SE:355; F-05/F-41 |
| E22 | catalog vs real coverage | required-open | T9 | NONE-YET | SE:366; G-12 runtime conformance for all 104 |
| E23 | backend/kernel matrix | required-open | T12 | NONE-YET | SE:376; safety subset first |
| E24 | soak with envelope | required-open | T12 | NONE-YET | SE:400; 30m/4h/24h real wall time |
| E25 | startup reconciliation | required-open | T12 | NONE-YET | SE:412; O-13/F-37 |

## Audit A-F1–A-F9 (findings.json; no fix requested or applied there)

| ID | title | disposition | owner | check | evidence |
|---|---|---|---|---|---|
| A-F1 | E-burst point not lossless (P1) | required-open | T12 | NONE-YET | AJ f1; `raw/repair-burst-load24/pid-profile/record.json` |
| A-F2 | foreign traffic certifies refused workload (P1) | required-open | T12 | NONE-YET | AJ f2; `raw/baseline/oracle-poc.log`; T12 oracle mutations |
| A-F3 | terminal sink under-accounting (P2) | required-open | T10 | NONE-YET | AJ f3; `raw/sink-byte-accounting.json` |
| A-F4 | slow-sink cancel over 100ms (P2) | required-open | T10 | NONE-YET | AJ f4; `raw/cancel-result.json` |
| A-F5 | publication erases omission history (P2) | required-open | T7 | NONE-YET | AJ f5; `raw/admission-history-tests.log` |
| A-F6 | proxy oracle accepts call loss (P2) | required-open | T12 | NONE-YET | AJ f6; `raw/baseline/oracle-poc.log` |
| A-F7 | stale public provenance (P3) | required-open | T5 | NONE-YET | AJ f7; `raw/admission-history-tests.log` |
| A-F8 | oracle pins 3.2/104 shape (P3) | accepted-boundary | T12 | NONE-YET | AJ f8; already disclosed reference-host pin |
| A-F9 | inferred phase timing hides tail (P3) | required-open | T2 | NONE-YET | AJ f9; G-14 authoritative timestamps |

## Fable xhigh FB-F1/F3/F4/F6/F7 (U-12 adjudication; discovery fixes → T6)

| ID | title | disposition | owner | check | evidence |
|---|---|---|---|---|---|
| FB-F1 | first-come admission starvation | required-open | T6 | NONE-YET | FB:7-17; `plan.rs:1247,1353,1458` |
| FB-F3 | 64 KiB DISCOVERY ring vs large records | required-open | T6 | NONE-YET | FB:21; `ebpf-common/src/lib.rs:387`; `run.rs:2739`; `attach.rs:3428` |
| FB-F4 | per-process loader hook | required-open | T6 | NONE-YET | FB:23; `attach.rs:2779,2835`; `engine.rs:2956` |
| FB-F6 | BROAD_ADMIT fixture-only, no generic broad path | required-open | T6 | NONE-YET | FB:27; `engine.rs:3573`; `cli.rs:199`; see also T5 G-17 decision |
| FB-F7 | per-fork Event in system scope | required-open | T6 | NONE-YET | FB:29; `ebpf/src/main.rs:2636,2600`; `process.rs:11` |

Note: FB-F2 (512 lifetime budget), FB-F5 (aggregate path cost), FB-F8
(attach/detach scaling), FB-F9 (lifetime work ceilings), FB-F10 (same-inode
aliasing) exist in the same source but are outside the U-12 adjudication
scope; F2/F10 overlap E10/E14–E15 evidence owned above.

## Counts per disposition (147 rows)

| Disposition | F | R | O | E | A | FB | Total |
|---|---|---|---|---|---|---|---|
| source-fixed | 31 | 0 | 0 | 0 | 0 | 0 | 31 |
| runtime-verified@hash | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| required-open | 44 | 0 | 8 | 25 | 8 | 5 | 90 |
| accepted-boundary | 6 | 3 | 0 | 0 | 1 | 0 | 10 |
| refuted | 2 | 3 | 1 | 0 | 0 | 0 | 6 |
| optional | 1 | 0 | 9 | 0 | 0 | 0 | 10 |

## Ownership completed, checks still open (2026-09-26)

F-33 is owned by T5 implementation plus T13's helper trust/privilege policy;
F-36 by T5/T6 at touched runtime boundaries; F-39 by T13 maintenance;
F-43 by T13 dependency/update policy; F-54 by T5/T8 target-derived panic
handling; F-56 by T5/T10 discover output integrity and privacy. This follows
the product-quality review's deferred-disposition table. Assignment closes
no finding: all six still require concrete tests and final evidence.

## INPUT-MISSING

None. Every delegated input was located, including the Fable xhigh source
(FB, only copy under `/var/tmp`, mirrored path+sha above — controller
should preserve it per continuation-plan U-01).

Out of ledger scope (not findings): SPEC R01–R10 are requirements owned by
T13 reconciliation, not dispositions; SYSTEM-PLAN R1–R8, RP E-1/E-2, and
SB/DG/roadmap items were not in the delegated inventory.
