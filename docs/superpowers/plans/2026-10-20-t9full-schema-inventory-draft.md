<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T9-full schema-surface inventory — DRAFT (pre-freeze, NOT a freeze)

> **Status: DRAFT.** Read-only preparation for T9-full. No live runs, no
> product changes, no manifest regeneration were performed for this
> document. Tip surveyed: product `task/v040-t9prep` @
> `47292662` (2026-10-20). Nothing here freezes anything; the freeze
> checklist is a separate draft.

Conventions: `file:line` is anchored at the surveyed tip. "Owner" is the
test target or oracle that pins the shape today.

## A. Public presentation schemas (`docs/schema/`)

| # | Schema id | Doc | Producer | Owner (test/oracle) |
| --- | --- | --- | --- | --- |
| A1 | `p11scope/inventory/v1` | `docs/schema/inventory-v1.md` | `src/inventory.rs`, `src/inventory_output.rs` | `src/inventory_output_tests.rs`; `tests/artifact_contracts.rs` schema/counters/privacy contract; `tests/cross_command_journeys.rs` parity |
| A2 | `p11scope/inventory-events/v1` | `docs/schema/inventory-events-v1.md` | `src/inventory_events.rs` | `src/inventory_events_tests.rs` |
| A3 | `p11scope/inventory-diff/v1` | `docs/schema/inventory-diff-v1.md` | `src/inventory_diff/compare.rs:231` | `src/inventory_diff/compare_tests.rs:734`, `src/inventory_diff/render_tests.rs:658` |
| A4 | `p11scope/inventory-diagnostics/v1` (JSONL) | `docs/schema/inventory-diagnostics-v1.md` | `src/inventory_diagnostics_output.rs` | `src/inventory_diagnostics_tests.rs` |
| A5 | `p11scope/observed-profile/v2`, `.../v2-metrics` | `docs/schema/observed-profile-v2.md` | profile/metrics renderers | existing S1 regression suites (G29) |
| A6 | `p11scope/observed-profile/v3`, `.../v3-metrics` | `docs/schema/observed-profile-v3.md` + `docs/schema/observed-profile-v3.schema.json` | H9 immutable Presentation | `key_operation_schema_contract` in `src/key_operation_tests.rs` |
| A7 | `p11scope/inspect/v1`, `p11scope/inspect-system/v1` | `docs/schema/inspect-v1.md` | `src/inspect.rs`, `src/inspect_system.rs` | inspect/doctor journey tests |
| A8 | object_observations frozen subset | `docs/schema/inventory-v1-object-observations.schema.json` + golden `tests/fixtures/key-operations/object-observations.json` | H9 renderer | `tests/python/test_object_observations.py` (5 tests) + `key_operation_schema_contract` |

A8 is already described in-tree as "the frozen Task 4 consumer
contract". A1–A7 docs are unchanged since before the G25 refresh (see
drift draft); freezing them is a declaration, not a new constraint.

## B. BPF/host wire formats (`crates/ebpf-common/src/`)

| # | Artifact | Location | Owner |
| --- | --- | --- | --- |
| B1 | Base `EventRecord`, **368 bytes** | `lib.rs:1701` (struct), `:2070` (size assert) | producer/consumer twin tests; PA-01 608→368 path |
| B2 | Object CALL record, **608 bytes** + 240-byte tail | `object_wire.rs:17` (`OBJECT_RECORD_BYTES`), `:187` `ObjectEventRecord`, `:83/:98/:108/:119` descriptor/attribute/tail words, `:132` 432-byte `ObjectStart`, `:159` `ObjectCallWire`, `:238` `ValidatedObjectCall` | `tests/object_producer_adapters.rs`, `tests/object_producer_activation.rs`, `tests/object_producer_owner_store.rs`, canary lanes |
| B3 | Journal wire **v1** (`JOURNAL_VERSION=1`, `object_journal.rs:32`): BEGIN 224/232, END-full 632/640, END-compact 472/480, ABANDON 64/72 (`:33–:43`); kinds BEGIN=1/END=2/ABANDON=3 (`:46–:48`); `NO_END=0x01`, `TAIL_ABSENT=0x02`; abandon reasons 1–4 (`:61–:64`) | `object_journal.rs` | `tests/object_journal_contracts.rs`, `tests/python/test_object_journal_qualification.py` |
| B4 | Six-field capture policy vocabulary: `CKR_*` (`object_capture.rs:44–52`), `MAX_ATTRIBUTE_SLOTS=8`, `MAX_FIND_HANDLES=8` (`:55–:56`), slot states 0–10 (`:60–:70`) | `object_capture.rs`, `object_policy.rs` | object-policy/wire tests, read-spy adapter tests, canary lanes |
| B5 | BPF map definitions + pinned map-flag policy | `scripts/check-bpf-map-defs.py`, `scripts/check-canary-evidence.py` | `tests/python/test_canary_*.py`, `scripts/verify-canaries.sh` (G23 IMAGE-flag twins) |

Diet warning: the uncommitted BPF-diet work edits B4's
implementation (`object_capture.rs`, `object_flow.rs`). Any semantic
change there (loop bounds, captured-field selection) moves B2/B4 and
must be re-proven before the freeze (see drift draft).

## C. Receipt shapes

| # | Receipt | Producer | Consumer/owner |
| --- | --- | --- | --- |
| C1 | `p11scope/test-execution/v1` (cell_id, subject, evidence_level, kernel_profile, test_ids, command, artifact_hashes, evidence_paths, entrypoint, executed_test_ids, exit_code, outcome, observed_behavior; soak adds `start/end_mono_ns`, installed adds `installed_artifact_sha256`) | `scripts/system-scope-soak-oracle.py:403` (`build_receipt`) | `scripts/verify-system-test-manifest.py:196` (`verify_pass`) |
| C2 | `p11scope/release-matrix-build/v1` | candidate build capture | `scripts/release-matrix-contract.py:389` (`validate_candidate`) |
| C3 | `p11scope/release-matrix-execution/v1` | stage seal | `scripts/release-matrix-contract.py:558` (`judge`) |
| C4 | `p11scope/soak-run/v1`, `p11scope/system-scope-measurement/v1`, `p11scope/workload-mapping-receipt/v1` | `scripts/system-scope-soak.sh` + workload | `scripts/system-scope-soak-oracle.py:45–49` |
| C5 | E17 cell receipt (unversioned dict: image/pid/provider binding, `ring_requested`/`ring_actual_bytes`, `issued_calls`, `sink`, `cancel`, `signals`, `cancellation_ack_ns`, `observer_rc`, `cleanup_seconds`, blocked-stderr extension `reporter_ack`/`reporter_controls`) | E17 harness | `tests/fixtures/operator-output/oracle.py:92` (`evaluate`), `tests/fixtures/operator-output/blocked_stderr.py:70` (`verdict`) |
| C6 | DR37 activation receipts (native CAS mint): `NativeActivationSource` minter twins, `SelectedSessionIdentity` (`src/attach/selected_detailed.rs:750`), `SelectedConstructionPermit` (`:764`), `PromotionRequest` (`src/inventory_promotion.rs:147`), `PromotionUi` (`:347`), `PromotionRequestError` (`:193`) | `src/attach/selected_detailed.rs:121+` | selected-detailed unit twins, `src/inventory_dashboard_tests.rs`, curated privileged full-loop cell |
| C7 | In-memory object/key facts (pre-presentation): `ReceiptSnapshot` (`src/semantics_objects.rs:316`), `OriginFact` (`:620`), `CompletedFact` (`:641`), `LostOutcome::{Ticket,Refused,Voided}` (`:1055`), `KeyUseEvidence`/`OpenKeyUse`/`AggKey` (`src/semantics_key_use.rs:1179/:1255/:1034`) | H7/H8/H9 pipeline | journal/key-operation contract suites |

## D. Oracle verdict enums

| # | Oracle | Verdict vocabulary | Owner |
| --- | --- | --- | --- |
| D1 | `scripts/release-matrix-contract.py:443` `lib_outcome` | `positive-coverage` / `expected-refusal` (+ `expected-fallback` for backends in `judge`) | `tests/python/test_release_matrix_contract.py` |
| D2 | `scripts/release-matrix-contract.py:558` `judge` → `p11scope/release-matrix-verdict/v1` | `selected-coverage` / `nonqualifying` / `failed` (exit 0/2/1) | same suite; judge self-hash bind at `:550` |
| D3 | Boundary cell (`:493` `boundary_outcome`) | all-8192-IDs positive vs `T7_ENVELOPE_REFUSAL` preflight/post-failure refusal | G01 methods in the same suite |
| D4 | 5.15 denial lane (`:416` `denial_outcome`, `IDENTITY_515_DENIAL` marker) | `expected-refusal` (denied, 5.15.221 lane) / `positive-coverage` (eligible, elsewhere) | 5 hermetic tests from `e31f7aa9`; privileged cell curated 127/127 |
| D5 | `scripts/verify-system-test-manifest.py:22` | cell `OUTCOMES = {PASS, FAIL, INVALID, NOT_RUN, UNSUPPORTED, BLOCKED}`; run verdict `STRUCTURE_VALID` / `PASS` (`:266`) | `tests/python/test_system_test_manifest.py` |
| D6 | E17 `tests/fixtures/operator-output/oracle.py:196` | `PASS` / `FAIL` / `NOT_RUN` + `errors` / `unqualified` | `tests/python/test_operator_output_qualification.py` |
| D7 | E17 trace rows `scripts/cgroup-trace-oracle.py:28` `parse_trace` | ROW records + exactly one `COUNT_EVIDENCE` + one `EVIDENCE` (`:72–:73`); `IMAGE_FIELDS` (`:24`); `N3LEDGER` fixture records | same suite; G22 twins |
| D8 | E16 `scripts/qualify-e16-surfaces.py:1244` | per-cell `PASS` / `UNKNOWN`; campaign `status` (`:1330`) | `tests/python/test_e16_oracle.py`, `tests/e16_execution_surfaces.rs` |
| D9 | Native `scripts/inventory-native-oracle.py:2346` | `QUALIFIED` / `FAILED` / `NON-QUALIFYING` (+ `LEDGERS-CONSISTENT` / `LEDGERS-FAILED`) | native-oracle self-tests; `qualify-inventory-native.sh` |
| D10 | M2 `scripts/bench-count-overhead-analyze.py:476` | gate `PASS` / `FAIL`; row `MATERIAL` / `immaterial` | in-file self-tests (`:643–:650`); G34 validity battery |
| D11 | Soak `scripts/system-scope-soak-oracle.py:390` → `p11scope/soak-verdict/v1` | `PASS` / `FAIL` over 7 gates: duration, installed_identity, ownership, workload_continuity, loss_accounting, resource_accounting, clean_exit (`:52–:53`) | `tests/python/test_system_scope_soak.py` (red-green battery) |
| D12 | RSA ledger `scripts/key-operation-ledger.py` (`LedgerError` fail-closed; 31 sign / 24 verify / 13 setup = 68 calls) | ledger valid / `LedgerError` | `tests/python/test_key_operation_ledger.py`; fixture `tests/fixtures/key-operations/rsa-ledger.c` |

Gap (not at tip): the installed H9 observer oracle
`scripts/qualify-key-operations.py` proposed by G14 does not exist.
T9-full must either land it or record the G14 observer comparison as
open; the application ledger (D12) alone does not qualify observation.

## E. Dashboard outputs

| # | Artifact | Location | Owner |
| --- | --- | --- | --- |
| E1 | `DisplayFrame` (immutable presentation + paired log tail), handoff capacity 1, counted `dropped_frames` | `src/inventory_dashboard.rs:177`, `:49–:50`, `:213–:222` | `src/inventory_dashboard_tests.rs` (4,348 lines) |
| E2 | Operator controls: `d` request Detailed capture for the selected pair, `x` cancel; `d` needs a fully drawn frame, `x` also works after shed/cut frames; both ignored on the gaps page; honest refusals (stale view, busy, unsupported scope, scan-only) | `docs/usage.md` dashboard section; `src/cli.rs` field doc; `src/inventory_dashboard.rs` module docs | dashboard tests incl. `eb116c9b` retention pins |
| E3 | Promotion pipeline: staged admission → pre-view full64 baseline → draw-commit → capture-lane acquisition → scheduler | `src/discovery/inventory_coordinator/semantics/promotion.rs`, `src/attach/selected_detailed/baseline.rs`, `src/inventory_promotion.rs` | promotion + dashboard + selected-detailed twins |

## F. Privacy allowlist

| # | Artifact | Location | Owner |
| --- | --- | --- | --- |
| F1 | Allowlist v1 (**preserve; never broaden implicitly**) | `docs/privacy/allowlist-v1.md` (178 lines) | canary suites below |
| F2 | Allowlist v2 | `docs/privacy/allowlist-v2.md` (126 lines) | same |
| F3 | Allowlist v3 (finite approved extensions incl. H7-E4 six-field activation) | `docs/privacy/allowlist-v3.md` (1,004 lines) | `tests/object_producer_activation.rs` six-field/refusal tests; `tests/python/test_canary_evidence.py`, `test_canary_object.py`, `test_canary_process_custody.py`, `test_canary_workload.py`, `test_stopped_canary_capture.py`, `test_task_storage_canary.py`; `scripts/verify-canaries.sh` |

## G. Acceptance-manifest schema (frozen by hash chain)

- Manifest schema `p11scope/system-test-manifest/v1`:
  `tests/fixtures/system-qualification/system-test-manifest.json`
  (4,667 lines, 215 cells, all `NOT_RUN` at tip).
- Authority catalogs: `closure-ledger.json`
  (`p11scope/system-closure-ledger/v1`, 147 findings),
  `system-deferred-gates.json`
  (`p11scope/system-deferred-gates/v1`, 43 groups),
  `system-bounded-scope.json`
  (`p11scope/system-bounded-scope/v1`, IN/OUT partition of
  system-product). Membership is pinned by the `*_sha256` fields in
  the manifest; any catalog edit invalidates every downstream verdict.
- Cell vocabulary: `expected_behavior` ∈ {regression 147,
  deferred-gate 43, public-contract 10, capture 7,
  installed-contract 4, continuous-owned-workload 3,
  expected-refusal 1}; `evidence_level` ∈ {live-mechanism 107,
  artifact 80, public-command 21, installed 4, soak 3};
  `required_for_claims` ⊆ {system-product, bounded-release,
  t7-static}.
- Key cells: `soak.1800s` / `soak.14400s` / `soak.86400s`
  (test_ids now seeded, D11 vehicle), `finding:E17`, eight
  `T7.{profile}.{slug}` selectors, four `installed.*` cells, ten
  `R{NN}.public` cells.
- Owner: `scripts/verify-system-test-manifest.py` + doc
  `docs/qualification/system-test-manifest.md` +
  `tests/python/test_system_test_manifest.py`.
