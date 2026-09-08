# Dependency Patch Series Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. The primary owns acceptance, sequencing and integration; Luna handles exact incremental local commits.

**Goal:** Reconstruct locally patched dependencies from pinned archives and readable patch series after checkout, with Cargo source selection included in build evidence.

**Architecture:** A finite JSON recipe drives immutable source preparation. A separate verifier checks Cargo-produced metadata against that recipe and reuses the same tree verification code. Existing build and release callers consume one generated-source ledger.

**Tech Stack:** Python standard library, Git patch application, Cargo/Rust 1.88, the existing pinned BPF toolchain, shell entry points.

**Spec:** [Selected design](../specs/2026-09-09-dependency-patch-series-design.md)

## Global constraints

- Preserve Rust 1.88, edition 2024, Linux x86-64/ia32 support and `docs/privacy/allowlist-v1.md`.
- Preserve all 131 current Aya/aya-obj source files and their package lockfiles until exact reconstruction passes.
- Keep the initial locked dependency graph; path-generation changes are intentional, dependency upgrades are separate.
- No root Cargo, container experiments, publication, push, tag, global cache edits, automatic source replacement or automatic garbage collection in these tasks.
- At most one Cargo-heavy command against the shared checkout/target. Writers own disjoint files and stop before independent review.
- Native Python tests belong in Python files. Rust bridges select complete native test classes and require successful, nonempty, unskipped execution.
- Each accepted unit gets a local commit. A preservation checkpoint with unresolved checks must explicitly say WIP.

## Task 1: Archive recipes and the preparer

**Own:** `third-party/sources.json`, five logical patch files under `third-party/patches/`, `scripts/prepare-dependencies.py`, `tests/python/test_prepare_dependencies.py`.

**Inputs:** Committed package copies at `35fc237`, the design, and explicitly supplied upstream archives. **Outputs:** The finite manifest and a directly runnable preparer; source copies remain tracked and Cargo paths remain unchanged in this task.

Initial archive pins:

| Archive | SHA-256 |
| --- | --- |
| `aya-0.14.0.crate` | `66e644424fada9fff4fdc63848db1732fb69b626e8328202ef55c03df1f4d939` |
| `aya-obj-0.3.0.crate` | `8c76b9c75d9cdc155ff8f6a06d61e873f67bf47be8cfa92a3b5aaea43f4b4077` |

Interfaces:

```text
python3 -I scripts/prepare-dependencies.py [--offline] [--archive-dir DIR]
python3 -I scripts/prepare-dependencies.py --check
python3 -I tests/python/test_prepare_dependencies.py
```

The script derives its root from its location. Test fixtures copy it into an
isolated source root with small synthetic archives and recipes; no Cargo is
needed to test missing manifests. Expose reusable recipe/tree verification
functions for Task 2 without duplicating them in another script.

- [ ] Freeze the current 131-file inventory, package manifests/locks and modes. Read original archives from an explicitly supplied location; do not discover or alter a global registry cache in maintained code.
- [ ] Write failing native tests for fresh reconstruction, an order-dependent two-patch series, a third package and another version added through data, offline absence/corruption, partial patch failure and changed same-revision recipe. Assert the specific refusal and unchanged pre-existing output.
- [ ] Add focused tests for archive traversal/links/duplicate entries, executable modes, output tampering, idempotent mtimes, two preparers, interrupted publication and preparing a new revision while the old tree is retained. Use only owned temporary files/processes.
- [ ] Implement one record loop and ordered patch loop, finite acquisition/extraction limits, the selected digest/recipe receipt, stable lock and publish-once behavior. No arbitrary recipe command hooks or package-specific Python branches.
- [ ] Generate three Aya patches (reader/tests, Rust 1.88 assertions, workspace) and two aya-obj patches (relocation/tests/note, workspace). Verify complete application against the exact archives, not an upstream Git draft.
- [ ] Run the native suite. Reconstruct real packages in an isolated fresh source export without `.git`, from an unrelated working directory, with explicit offline archives. Compare every original file byte/mode and both unchanged package lockfiles.
- [ ] Stop the writer; review source, negative controls and exact reconstruction independently. Commit only these maintained files through Luna after primary acceptance.

## Task 2: Cargo source binding

**Own:** `scripts/check-prepared-dependencies.py`, `tests/python/test_prepared_dependency_metadata.py`; narrowly extend reusable preparer interfaces only after Task 1's writer stops.

**Consumes:** Task 1 recipe and verified tree inventory. **Produces:** Metadata selection verification and a sorted ledger covering selected prepared files plus their preparation receipts.

```text
python3 -I scripts/check-prepared-dependencies.py \
  --sources third-party/sources.json \
  --metadata Cargo.toml=/absolute/root-metadata.json \
  --metadata crates/ebpf/Cargo.toml=/absolute/bpf-metadata.json --ledger
python3 -I tests/python/test_prepared_dependency_metadata.py
```

- [ ] Write fixtures for current generation, retained stale generation, registry fallback, transitive dependency, two versions of one crate, incomplete metadata, unknown generated package and separate BPF workspace. Each failure names the workspace/package/path and emits no partial ledger.
- [ ] Implement JSON graph traversal from Cargo workspace members using package IDs, require full resolve data, verify root identity and exact applicable manifest paths, and reuse Task 1's actual byte verification. Do not run arbitrary commands supplied through metadata or parse Cargo TOML.
- [ ] Prove metadata claiming the new tree cannot authorize a different on-disk tree. Prove a record for the root workspace does not authorize or require that package in BPF's independent graph.
- [ ] Run native tests and one real metadata check using an isolated migrated checkout. Compare package identities, features and dependency edges with the current locked graph, allowing only intended local manifest path changes.
- [ ] Stop, independently review and commit the bounded unit through Luna.

## Task 3: Build commands, CI and caller closure

**Own sequentially:** `Cargo.toml`, `.gitignore`, `scripts/cargo.sh`, `README.md`, `third-party/README.md`, `.github/workflows/ci.yml`, `scripts/gates.sh`, `scripts/build-release.sh`, `scripts/verify-task4-lane16.sh`, `scripts/verify-discover-containers.sh`, `scripts/matrix/verify-knative.sh`, `scripts/matrix/verify-abi-routing.sh`, and their existing focused Python/Rust fixtures.

Split this task into disjoint writer units if useful. Do not overlap writers
of the shared script fixtures or `tests/artifact_contracts.rs`. Root runtime
logic and generic build-subject architecture are outside ownership.

- [ ] Add the thin automatic preparation/Cargo entry point. Point the two Cargo overrides and workspace exclusions at explicit version/revision directories. Ignore generated sources, archives, lock and stage paths without ignoring maintained recipes/patches.
- [ ] Document fresh checkout, normal preparation/direct Cargo, offline preparation, patch addition/rebase/retirement and non-destructive recovery. Keep patch provenance with maintained files.
- [ ] Prepare before CI's first Cargo manifest operation; acquire ordinary locked dependencies for both workspaces before offline graph verification. Retain all root gates and both standalone dependency suites, with test targets outside prepared sources.
- [ ] Update release `task4_snapshot`, lane16 `source_snapshot`, Knative `lane13_record_inputs`, ABI-routing inventory and the container host-preparation boundary to consume the same verified generated-source ledger. Capture pinned root/BPF Cargo metadata before build resources; finalization invalidates changed recipe, manifest/lock or generated inputs.
- [ ] Keep acquisition outside sealed execution. A missing archive/source or metadata mismatch must fail before the controlled build/container/privilege marker in fixture tests.
- [ ] Replace the lane13 fixture's tracked-Aya assumption with synthetic prepared inputs. Test both current packages, another manifest-driven package, missing/tampered output, ignored targets and unrelated untracked consumed input. Keep complete Python class selection in the Rust bridge.
- [ ] Extend source export to carry original pinned archives and maintained recipe/patch/preparation inputs. Verify a fresh offline extraction with no `.git`, no generated trees, no original checkout access and no network fallback.
- [ ] Run focused native/caller tests as each bounded writer finishes, independently review, and commit accepted units through Luna. Do not wait for unrelated release qualification to preserve this work.

## Task 4: Remove copies and validate the integrated migration

**Own:** Removal of the exact tracked files under `third-party/aya/` and `third-party/aya-obj/`, plus any necessary final documentation correction. New generated trees stay ignored.

- [ ] Confirm Tasks 1–3 acceptance, unchanged old source hashes and the working replacement path. Preserve edits if any source differs; do not delete an unexpected tree.
- [ ] Remove the old tracked copies in a separate local commit through Luna. The earlier checkpoint retains full recovery history.
- [ ] From a fresh export of the committed result, perform preparation and locked metadata selection for root/BPF without relying on the original checkout. Verify generated sources and archive/export exclusions.
- [ ] Run `cargo +1.88 fmt --all -- --check`, locked workspace all-target check/test/clippy with warnings denied, and both existing standalone dependency test commands with external targets. Record actual results and distinguish pre-existing failures from migration regressions.
- [ ] Complete independent review of the integrated change and source-receipt closure. Update release status accurately; these checks do not close the pending runtime/kernel matrix or authorize publication.
