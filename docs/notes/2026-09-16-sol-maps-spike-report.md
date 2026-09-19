<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Invalid maps snapshot implementation report

## Baseline and governing instructions

- Read `BRIEF.md` in full (95 lines), including all six controller rulings.
- Read `.superpowers/sdd/w7-continuation-2026-09-12/HOUSE-RULES.md` in full (73 lines).
- Read `DESIGN.md` in full (248 lines).
- Baseline source commit: `961a65c` (`fix: refuse an argv[0] multiplexer as a pinned build tool`).
- Initial `git status --short`: only controller-supplied `BRIEF.md` and `DESIGN.md` were untracked; there were no pre-existing source edits.
- Precedence applied: no commit will be created, despite the generic house-rule statement that commits are normally expected.
- Only focused single-test/filter Cargo runs will be used. No workspace-wide test, check, clippy, privileged, container, tag, or push operation will be run.

## Mutation-first lane 1: manifest invalid-snapshot distinction

Mutation target: if invalid index construction is collapsed to `Resolved::Unmapped`, an overlapping snapshot and a valid snapshot with a genuinely absent queried address become observably identical. The test input is made from literal `MapEntry` values and does not use `parse_maps` or the validator to construct its expectations. It also checks an address in an otherwise valid mapping so sorting or dropping the unrelated overlap cannot satisfy the test.

First RED attempt did **not** execute the test and is not counted as evidence:

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --lib -- invalid_snapshot_is_distinguishable_from_valid_absence
mise WARN  tracking config: failed to ln -sf /home/user/src/m/p11scope-ws/p11scope/.claude/worktrees/sol-maps/mise.toml /home/user/.local/state/mise/tracked-configs/d63f171127a52934: Read-only file system (os error 30)
prepare-dependencies: refusal: cannot download https://static.crates.io/crates/aya/aya-0.14.0.crate: <urlopen error [Errno -3] Temporary failure in name resolution>
```

The test result is unknown for that attempt. Root-cause inspection found that ignored `third-party/src` trees were absent, `scripts/cargo.sh` therefore invoked online reconstruction, network name resolution is unavailable, and the exact pinned archives already exist in Cargo's local registry cache. The repository-supported recovery is to run `scripts/prepare-dependencies.py --archive-dir` against that cache; the preparer independently verifies archive, patch, and final-tree digests.

A second attempt without the crate's feature-gated `maps` module also did not count: it reported `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. Source inspection identified `#[cfg(feature = "identify")] pub mod maps;`, so all focused manifest runs below explicitly enable `--features identify`.

RED (executed against unfixed production code):

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --features identify --lib -- invalid_snapshot_is_distinguishable_from_valid_absence
running 1 test
test maps::tests::invalid_snapshot_is_distinguishable_from_valid_absence ... FAILED
assertion `left != right` failed
  left: Unmapped
 right: Unmapped
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 11 filtered out; finished in 0.00s
```

GREEN (same test, after changing `MapIndex::new` and free `resolve` to the approved fallible API):

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --features identify --lib -- invalid_snapshot_is_distinguishable_from_valid_absence
running 1 test
test maps::tests::invalid_snapshot_is_distinguishable_from_valid_absence ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 0.00s
```

## Mutation-first lane 2: file-offset representability

Mutation target: removing constructor-time last-byte offset validation must admit `file_offset + (end - start - 1)` overflow. The positive control uses literal endpoints and offset to make the last byte exactly `u64::MAX`, then checks that indexed lookup returns that literal offset.

RED (executed before overflow validation):

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --features identify --lib -- map_index_rejects_file_offset_overflow
running 1 test
test maps::tests::map_index_rejects_file_offset_overflow ... FAILED
assertion failed: MapIndex::new(&overflowing).is_err()
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s
```

GREEN (same test, after validating the last byte during construction and removing the overflow-to-`Unmapped` fallback):

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --features identify --lib -- map_index_rejects_file_offset_overflow
running 1 test
test maps::tests::map_index_rejects_file_offset_overflow ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s
```

## Offline acquisition integration

The pre-load, post-acquisition, and final maps snapshots are validated once at their acquisition boundaries. Ordinary module/export/table/provenance resolution receives a `MapIndex`, so invalid data cannot be reached as a lookup result and no empty-work path can bypass validation.

Focused discover compilation/control after the ordinary-path API migration:

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-discover --lib -- relative_module_is_rejected_before_loading
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 0.00s
```

## Mutation-first lane 3: offline selection bracket

Mutation target: removing validation of A or B, or comparing only file-backed entries, must allow an anonymous overlap to pass. The test uses literal entries, covers invalid A, invalid B, identical invalid A/B, verifies invalid A does not invoke the dependent resolver, and includes a valid stable positive control.

RED (executed before bracket validation):

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-discover --lib -- selection_bracket_refuses_invalid_snapshots
running 1 test
test discover::tests::selection_bracket_refuses_invalid_snapshots ... FAILED
assertion `left == right` failed
  left: Ok(7)
 right: Err(ProviderChanged)
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s
```

GREEN (same test, after validating both snapshots and passing a validated index to the resolver):

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-discover --lib -- selection_bracket_refuses_invalid_snapshots
running 1 test
test discover::tests::selection_bracket_refuses_invalid_snapshots ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s
```

Additional focused controls after integration:

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --features identify --lib -- map_index_requires_sorted_non_overlapping_intervals
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-discover --lib -- loaded_module_key_reports_invalid_snapshot_before_export_absence
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.38s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-discover --lib -- selection_bracket_validation_overrides_absence_classifications
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- p2_bracket_incomplete_a_never_scans
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 973 filtered out; finished in 0.01s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- selection_assessment_rejects_remap_view_loss_and_pin_change
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 973 filtered out; finished in 0.00s
```

An earlier invocation of the last root filter ended during compilation without emitting any `test result:` line. It is UNPROVEN and not counted; the fresh rerun shown above is the evidence.

## Final implementation inventory

- `crates/manifest/src/maps.rs:183-312`: added `InvalidMapSnapshot` with distinct invalid-range, ordering/overlap, and file-offset-overflow categories; changed `MapIndex::new` and free `resolve` to `Result`; validated the absolute-file last-byte offset during construction; removed the overflow-to-`Unmapped` fallback. `MapIndex::resolve` remains infallible, and `Ok(Resolved::Unmapped)` now comes only from absence in an accepted snapshot.
- `crates/manifest/src/maps.rs:428-582`: migrated existing resolver/rejection assertions and added independent literal-fixture coverage for descending/equal/empty/inverted intervals, overlap versus valid absence, valid adjacency/gaps/exclusive ends, overflow, and the greatest representable offset.
- `crates/discover/src/maps.rs:5-8`: re-exported the fallible index API and error alongside the compatibility resolver.
- `crates/discover/src/discover.rs:50-180`: validated pre-load, post-acquisition, and final maps snapshots at acquisition boundaries and passed indexes through ordinary offline resolution/provenance paths.
- `crates/discover/src/discover.rs:818-836`: validated both offline selection snapshots, prevented dependent reads after invalid A, passed A's index to the resolver, and converted acquisition/validation failures to `SelectionFailure::ProviderChanged` before accepting any result.
- `crates/discover/src/discover.rs:1129-1202,1524-1554`: selection and ordinary table/function resolution now consume validated indexes; `OutsideProvider` and `UnresolvedFunction` remain classifications only for accepted snapshots.
- `crates/discover/src/discover.rs:1743-2077`: added exact acquisition-diagnostic/no-export controls, invalid A/B/identical-A-B bracket controls, absence-classification controls, and fixed the old synthetic-remap fixture to keep both ranges individually valid.
- `src/discovery/scan.rs:1379-1385`: mechanically translated the constructor error while preserving the existing live refusal string and charged one-index behavior. `src/discovery/scan.rs:2401-2442` adds invalid-A/no-memory-read coverage plus a successful control.
- `src/discovery/engine.rs:687-705`: mechanically translated both live bracket constructor errors to `Err(())`; the live bracket sequence and downstream assessment-loss behavior are otherwise unchanged. Eight test/helper free-resolver sites now construct one index and fail setup explicitly on validation failure; `src/discovery/engine.rs:20563-20648` distinguishes valid absence from invalid A/B.
- `src/doctor.rs:726`: mechanically translated constructor failure while preserving the exact `"maps invalid"` diagnostic.

## Call-site migration accounting

The approved design's baseline inventory had 21 free-resolver calls. All 21 are accounted for and none remain unmigrated:

- 6 offline production calls in `crates/discover/src/discover.rs` now use acquisition-boundary indexes.
- 8 root-crate test/helper calls in `src/discovery/engine.rs` now use one explicit index per snapshot and fail setup on invalid acquisition.
- 7 existing manifest resolver-test calls now assert the fallible `Result` API.

The 24 baseline `MapIndex::new` calls are also all accounted for. The compatibility wrapper and four production error translations use `Result`; two rejection assertions changed from `is_none` to explicit error matching; existing positive test constructors continue using `unwrap`/`expect` and compile against `Result`. No constructor caller could not be migrated.

Repository-wide Rust-source searches found no production free-resolver caller outside the compatibility wrapper, no `.unwrap_or(Resolved::Unmapped)`, no `.ok()` followed by absence handling, no unreported `if let Ok(File ..)` fallthrough, and no remaining `MapIndex::new(...).ok_or*`/`.is_none()` migration.

## Final focused verification

Every command below was run after the final source formatting. Each filter executed exactly one test; the literal result is included.

Manifest API and preservation controls:

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --features identify --lib -- invalid_snapshot_is_distinguishable_from_valid_absence
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --features identify --lib -- map_index_rejects_file_offset_overflow
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --features identify --lib -- map_index_requires_sorted_non_overlapping_intervals
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --features identify --lib -- map_index_resolves_gaps_adjacency_and_exclusive_ends
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope-manifest --features identify --lib -- classifies_anonymous_and_unmapped
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope-manifest --features identify --lib -- unusable_file_paths_remain_file_evidence
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope-manifest --features identify --lib -- resolves_with_segment_offset_arithmetic
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s
```

Offline acquisition and selection controls:

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope-discover --lib -- loaded_module_key_reports_invalid_snapshot_before_export_absence
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.40s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope-discover --lib -- selection_bracket_refuses_invalid_snapshots
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope-discover --lib -- selection_bracket_validation_overrides_absence_classifications
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope-discover --lib -- selection_bracket_rejects_synthetic_remap
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope-discover --lib -- selection_bracket_ignores_unrelated_anonymous_mapping_churn
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope-discover --lib -- selection_bracket_orders_snapshots_around_resolution
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.00s
```

Unchanged live-path controls:

```text
$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib -- p2_bracket_incomplete_a_never_scans
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 973 filtered out; finished in 0.01s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib -- p2_bracket_unavailable_b
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 973 filtered out; finished in 2.02s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib -- p2_bracket_stable_and_unrelated_vma_positive_controls
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 973 filtered out; finished in 0.02s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib -- source_pins_one_index_per_live_snapshot
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 973 filtered out; finished in 0.00s

$ mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib -- selection_assessment_rejects_remap_view_loss_and_pin_change
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 973 filtered out; finished in 0.00s
```

The first final manifest batch stopped before its fifth test because Cargo attempted to create a missing unpacked `block-buffer-0.12.1` directory in the read-only shared registry. That invocation emitted no `test result:` line and is not counted. Once the complete cached source directory was present, the same named test was rerun with the repository's offline form and passed as shown above. The recurring mise tracked-config symlink warning is environmental and did not change any command's exit status or test count.

## Status, unknowns, and rulings

- **Status: COMPLETE for the assigned implementation and focused evidence.** All three mutation-first lanes have literal RED and matching GREEN captures above; all final named filters executed exactly one test and passed.
- No workspace-wide test, check, or clippy command was run, by controller prohibition. Those serialized controller gates remain UNRUN here, so workspace-wide status is unproven.
- No privileged/container experiment or broader integration test was run. No live BPF/release qualification claim is made.
- No controller ruling appeared wrong. No privacy allowlist, budget/performance behavior, live production resolution flow, schema, generated output, or controller progress ledger was changed.
- No commit was created, per the higher-precedence brief.

Final non-Cargo checks:

```text
$ mise exec -- rustfmt +1.88 --edition 2024 --check crates/manifest/src/maps.rs crates/discover/src/maps.rs crates/discover/src/discover.rs src/discovery/scan.rs src/discovery/engine.rs src/doctor.rs
exit 0
$ git diff --check
exit 0
$ forbidden collapse-pattern and remaining production free-resolver scans
no matches; exit 0
```
