# Slice 1b-1 Semantic Authority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Owner decision (approved 2026-08-18):** Accepted explicit `--manifest` input is operator attestation of its exact function-name/offset claims; scan-only claims are never semantic authority.

**Goal:** Make every scan-only function-table candidate count-only, visibly incomplete, and ineligible for semantic joins, while allowing an accepted explicit manifest to authorize only its exact pinned-object, offset, and canonical-name claims.

**Architecture:** Keep discovery and attach architecture unchanged. Add one userspace-only `semantic_authorized: bool` to lowered targets, merged slots, and reports; combine it only under the existing `(PinnedObjectId, file_offset)` slot key and exact canonical name. Unverified slots publish the existing `SlotSemantics::COUNT_ONLY`; public v2 output keeps its existing source/corroboration vocabulary and derives `PARTIAL` from a non-serialized plan-owned gap.

**Tech Stack:** Rust 1.88, edition 2024, `std::collections::{BTreeMap, BTreeSet}`, existing Aya/eBPF `SlotSemantics::COUNT_ONLY`, Python 3 checker, POSIX shell canaries.

## Global Constraints

- Preserve `docs/privacy/allowlist-v1.md`; this change narrows descriptor-selected reads and must not add provider bytes, addresses, PID/TID, paths, handles, correlation IDs, or symbolic `CKA_CLASS`/`CKA_KEY_TYPE` output.
- Keep Rust 1.88, edition 2024, Linux x86-64-first support, current lockfiles, dependencies, common ABI, eBPF maps, and eBPF programs unchanged.
- `evidence.authority == "hash-pinned"` continues to mean opened object/offset identity only, never semantic authority.
- Existing public v2 fields remain unchanged. Semantic eligibility is derived from exact module `sources`, exact `corroboration[]`, function module ownership, alias flags, and completeness.
- Scan-only claims attach with `SlotSemantics::COUNT_ONLY`, preserve aggregate calls/errors/RVs/latency, produce no mechanism/session/login/template/async interpretation, force live and terminal `PARTIAL`, and are not P11Lab-joinable.
- An accepted explicit manifest is operator attestation only for the same `PinnedObjectId`, file offset, and exact canonical name. Hash equality, raw `ObjectKey`, path identity, scan agreement alone, stale fallback, or a neighboring claim never transfers attestation.
- `agreed` remains two-source target comparison, not selected-process acquisition. Slice 1b-2 alone may later introduce live-acquired authority.
- A conflict union remains `PARTIAL`; manifest claims may be semantic internally, scan-only claims remain count-only, and the whole conflict module is conservatively ineligible for P11Lab because v2 has no per-function source.
- No privileged, container, VM, or network gate may run without fresh explicit owner approval.

---

### Task 0: Persist the Owner-Approved Contract

**Files:**
- Create: `docs/superpowers/specs/2026-08-18-slice1b1-semantic-authority-contract.md`
- Modify: `docs/superpowers/plans/ROADMAP.md`

**Interfaces:**
- Consumes: explicit owner approval of manifest attestation and the three reviewed inputs `/tmp/discovery-policy-reconciliation.md`, `/tmp/slice1b1-semantic-authority-source-audit.md`, and `/tmp/slice1b1-semantic-authority-consumer-audit.md`.
- Produces: one authoritative Contract A statement whose exact terms are the Global Constraints above; later tasks may not reinterpret it.

- [ ] **Step 1: Write the contract document**

Write the exact acceptance statement below, followed by the threat boundary and P11Lab rule from Global Constraints:

```markdown
# Slice 1b-1 Semantic Authority Contract

Every scan-only exact target/name is heuristic and semantically unverified. It uses
`SlotSemantics::COUNT_ONLY`, retains aggregate calls/errors/RVs/latency, creates no
mechanism/session/login/template/async interpretation, forces live and terminal
`PARTIAL`, and is excluded from semantic joins.

Supplying an explicit manifest is operator attestation of only each accepted manifest
claim's exact pinned object, file offset, and canonical function name. Scan agreement,
hash pinning, raw `{dev,ino}`, path identity, stale fallback, and claim proximity never
transfer that attestation. A conflict remains `PARTIAL` and is wholly ineligible for
P11Lab semantic joining. Slice 1b-2 may later authorize exact live-acquired claims.
```

- [ ] **Step 2: Mark the ROADMAP gate selected but implementation open**

Change only the Slice 1b-1 owner-policy line to record “Contract A with explicit-manifest operator attestation selected; reviewed implementation and evidence remain OPEN.” Do not mark the slice complete.

- [ ] **Step 3: Verify the documentation-only change**

Run:

```sh
git diff --check
rg -n "scan-only|COUNT_ONLY|operator attestation|PinnedObjectId|P11Lab|OPEN" \
  docs/superpowers/specs/2026-08-18-slice1b1-semantic-authority-contract.md \
  docs/superpowers/plans/ROADMAP.md
```

Expected: commands exit 0; the new contract contains every term; ROADMAP remains OPEN.

- [ ] **Step 4: Obtain independent contract review**

Review exact diff for threat-model narrowing, manifest-path leakage, and contradiction with the approved Slice 1b-2 spec. Expected verdict: no Critical or Important finding before Task 1.

- [ ] **Step 5: Commit**

```sh
git add docs/superpowers/specs/2026-08-18-slice1b1-semantic-authority-contract.md \
  docs/superpowers/plans/ROADMAP.md
git commit -m "docs: select Slice 1b-1 semantic authority contract"
```

---

### Task 1: Enforce Exact-Claim Authority in the Planner

**Files:**
- Modify: `src/plan.rs`
- Modify: `src/main.rs`
- Test: unit tests in `src/plan.rs`
- Test: coordinator tests in `src/main.rs`

**Interfaces:**
- Consumes: `PinnedObjectId`, the existing `(PinnedObjectId, u64)` merge key, accepted manifests, `SlotSemantics::COUNT_ONLY`, and exact reconciled modules.
- Produces: `Slot::semantic_authorized: bool`; `Target::semantic_authorized: bool`; `Building::name_authority: BTreeMap<String, bool>`; exact-object corroboration; accepted `Agreed` manifest claims; cross-source entry deduplication.

- [ ] **Step 1: Write the scan-only RED**

Add `plan::tests::scan_only_target_is_unverified_and_count_only` using a known singleton `C_OpenSession`. Assert:

```rust
assert!(!slot.semantic_authorized);
assert_eq!(slot.semantics, SlotSemantics::COUNT_ONLY);
assert!(!slot.semantic_ambiguous);
assert_eq!(plan.entries_seen, 1);
```

- [ ] **Step 2: Run the scan-only RED**

```sh
cargo +1.88 test --locked --lib \
  plan::tests::scan_only_target_is_unverified_and_count_only -- --exact --nocapture
```

Expected: FAIL because the authority field does not exist and scan-only currently receives a semantic descriptor.

- [ ] **Step 3: Write exact merge REDs**

Add `plan::tests::authority_merges_only_for_exact_target_and_name` with these assertions in one compact table-driven test:

```rust
// same object + offset + same name: manifest upgrades exact claim
assert!(same_claim.semantic_authorized);
assert_ne!(same_claim.semantics, SlotSemantics::COUNT_ONLY);

// same object + offset + different scan-only name: whole alias remains unverified
assert!(!different_name.semantic_authorized);
assert_eq!(different_name.semantics, SlotSemantics::COUNT_ONLY);

// same raw ObjectKey but different PinnedObjectId: no transfer
assert!(!distinct_object.semantic_authorized);
assert_eq!(distinct_object.semantics, SlotSemantics::COUNT_ONLY);
```

Add `plan::tests::identical_scan_and_manifest_claim_counts_one_entry` and assert one slot, one `entries_seen`, two table-source records, and semantic authorization true.

- [ ] **Step 4: Run the exact merge REDs**

```sh
cargo +1.88 test --locked --lib \
  plan::tests::authority_merges_only_for_exact_target_and_name -- --exact --nocapture
cargo +1.88 test --locked --lib \
  plan::tests::identical_scan_and_manifest_claim_counts_one_entry -- --exact --nocapture
```

Expected: FAIL because merge stores only a name vector, counts claims by source, and has no authority bit.

- [ ] **Step 5: Implement the minimum planner representation**

In `src/plan.rs`, add only these fields:

```rust
pub struct Slot {
    // existing fields
    pub semantic_authorized: bool,
}

struct Target<'a> {
    // existing fields
    semantic_authorized: bool,
}

struct Building {
    // existing fields except `names`
    name_authority: BTreeMap<String, bool>,
}
```

Set `semantic_authorized: false` in `lower_scanned` and `true` in `lower_manifest`. During merge, combine only the exact name at the existing exact target:

```rust
slot.name_authority
    .entry(target.name.to_string())
    .and_modify(|authorized| *authorized |= target.semantic_authorized)
    .or_insert(target.semantic_authorized);
```

Build sorted names from the `BTreeMap` keys. Effective slot authority is `name_authority.values().all(|value| *value)`. Preserve `semantic_ambiguous` for alias/unknown/module ambiguity only. Publish `COUNT_ONLY` when either shared or not semantically authorized:

```rust
semantics: if shared || !semantic_authorized {
    SlotSemantics::COUNT_ONLY
} else {
    semantics
},
```

For `entries_seen`, remove source from the cross-source exact occurrence identity while retaining occurrence count, so one scan and one manifest description of the same name/object/offset count once; distinct claims and true repeated occurrences remain counted.

- [ ] **Step 6: Write coordinator REDs for Agreed and stale paths**

Add:

```rust
#[test]
fn agreed_manifest_is_an_exact_plan_claim_not_raw_key_promotion() { /* exact fixture */ }

#[test]
fn stale_attested_manifest_fallback_does_not_transfer_authority() { /* fallback fixture */ }
```

The first fixture must use two distinct pinned objects with the same raw `ObjectKey`; only the object exactly matched to the accepted manifest becomes authorized. The second must remove the stale manifest object through the existing fallback and assert the retained scan slot is count-only and public fallback remains path-free.

- [ ] **Step 7: Run the coordinator REDs**

```sh
cargo +1.88 test --locked --bin p11scope \
  tests::agreed_manifest_is_an_exact_plan_claim_not_raw_key_promotion -- --exact --nocapture
cargo +1.88 test --locked --bin p11scope \
  tests::stale_attested_manifest_fallback_does_not_transfer_authority -- --exact --nocapture
```

Expected: FAIL because `Agreed` currently drops the manifest from the plan and corroboration mutates module evidence through raw `ObjectKey` lookup.

- [ ] **Step 8: Make Agreed retain the exact manifest claim**

In `rebuild_discovered`, make `Corroboration::Agreed` use the same existing `retarget_to_pins`, accepted-manifest push, and `PinnedObjects::absorb` sequence as the non-stale manifest branches, while retaining its `agreed` counter and zero-conflict behavior. This makes the manifest a real exact plan claim; do not add an authority overlay or raw-key promotion table.

In `build_current_plan`, map each corroborated `(ProcessViewId, ObjectKey)` first to its exact `ReconciledModule.object`, then find `ModuleSummary` by that `PinnedObjectId`. Remove the raw-`ObjectKey` summary lookup. This reporting mutation may set only `corroborated`; plan authority comes solely from exact merged claims.

- [ ] **Step 9: Run the complete planner/coordinator slice**

```sh
cargo +1.88 test --locked --lib plan -- --nocapture
cargo +1.88 test --locked --bin p11scope discovery -- --nocapture
cargo +1.88 test --locked --test multi_module -- --nocapture
cargo +1.88 test --locked --test manifest_pinning -- --nocapture
```

Expected: all pass; existing alias/module ambiguity remains count-only; source/evidence counts change only where identical cross-source claims were previously counted twice.

- [ ] **Step 10: Commit**

```sh
git add src/plan.rs src/main.rs
git commit -m "fix: require exact semantic authority for discovery slots"
```

---

### Task 2: Propagate the Internal Gap and Prove Semantic Non-Use

**Files:**
- Modify: `src/metrics.rs`
- Modify: `src/render.rs`
- Modify: `src/trace.rs`
- Modify: `src/main.rs`
- Test: unit tests in `src/semantics.rs`, `src/render.rs`, and `src/trace.rs`

**Interfaces:**
- Consumes: `Slot::semantic_authorized`, existing `SlotSemantics::COUNT_ONLY`, `AttachPlan`, and `SlotReport`.
- Produces: `SlotReport::semantic_authorized`; non-serialized `Evidence::semantic_unverified_slots`; exact live/trace marker `[semantics unverified]`; `PARTIAL` predicate.

- [ ] **Step 1: Write the semantic non-use RED**

Add `semantics::tests::unverified_count_only_slot_creates_no_semantic_state`. Construct one scan-only/count-only slot and feed hostile non-default mechanism, session, template, operation, and async-looking event fields. Assert aggregate/cgroup calls may advance but these remain empty:

```rust
assert!(state.mechanisms().is_empty());
assert!(state.sessions().is_empty());
assert!(state.logins().is_empty());
assert!(state.templates().is_empty());
assert_eq!(state.pending_at_end(), 0);
```

- [ ] **Step 2: Run the semantic non-use RED**

```sh
cargo +1.88 test --locked --lib \
  semantics::tests::unverified_count_only_slot_creates_no_semantic_state -- --exact --nocapture
```

Expected: FAIL at fixture construction before propagation; after Task 1 it may already pass behaviorally, which is acceptable only if the test demonstrates the exact authority-to-count-only path rather than hand-constructing an unrelated descriptor.

- [ ] **Step 3: Write verdict and renderer REDs**

Add `render::tests::unverified_semantic_authority_alone_forces_partial` with every other gap zero. Assert:

```rust
evidence.verdict();
assert_eq!(evidence.completeness, "PARTIAL");
assert_eq!(evidence.semantic_unverified_slots, 1);
assert!(live_text.contains("1 semantics-unverified/count-only slot"));
```

Add an authorized control asserting the same otherwise-clean live evidence can remain `COMPLETE` before the independent terminal-drain downgrade.

- [ ] **Step 4: Write the trace RED**

Add `trace::tests::unverified_slot_is_explicit_and_semantically_empty`. Assert the line contains `[semantics unverified]`, retains the canonical heuristic label and aggregate result, and contains no session pseudonym, mechanism interpretation, template field, pointer, or path.

- [ ] **Step 5: Run renderer/trace REDs**

```sh
cargo +1.88 test --locked --lib \
  render::tests::unverified_semantic_authority_alone_forces_partial -- --exact --nocapture
cargo +1.88 test --locked --lib \
  trace::tests::unverified_slot_is_explicit_and_semantically_empty -- --exact --nocapture
```

Expected: FAIL because authority is not copied to reports/evidence/trace and verdict ignores it.

- [ ] **Step 6: Implement the minimum propagation**

Add `semantic_authorized: bool` to `SlotReport` and copy it from each plan slot in `metrics::read`.

Add this derived, non-public field to `Evidence`:

```rust
#[serde(skip)]
pub semantic_unverified_slots: usize,
```

Set it in `evidence_for` from `plan.slots.iter().filter(|slot| !slot.semantic_authorized).count()`. Require zero in `Evidence::verdict`. Include the finite count in live/text evidence, but do not serialize a duplicate JSON counter; terminal consumers derive the same policy from existing discovery sources/corroboration.

Change trace label construction to inspect the exact slot and append ` [semantics unverified]` only when its bit is false. Do not add a second semantic guard in BPF or `State`; the planner's existing count-only descriptor is the enforcement.

- [ ] **Step 7: Run the focused and neighboring suites**

```sh
cargo +1.88 test --locked --lib semantics -- --nocapture
cargo +1.88 test --locked --lib render -- --nocapture
cargo +1.88 test --locked --lib trace -- --nocapture
cargo +1.88 test --locked --test artifact_contracts -- --nocapture
```

Expected: all pass; authorized semantic fixtures explicitly set `semantic_authorized: true`; scan-derived fixtures do not silently inherit it.

- [ ] **Step 8: Commit**

```sh
git add src/metrics.rs src/render.rs src/trace.rs src/main.rs src/semantics.rs
git commit -m "fix: expose unverified discovery semantics"
```

---

### Task 3: Freeze the v2 Consumer and Privacy Contract

**Files:**
- Modify: `scripts/check-capture-evidence.py`
- Modify: `scripts/verify-canaries.sh`
- Modify: `docs/schema/observed-profile-v2.md`
- Modify: `docs/privacy/allowlist-v1.md`
- Test: `tests/artifact_contracts.rs`
- Test: affected fixtures only in `tests/multi_module.rs` and checker self-test data

**Interfaces:**
- Consumes: unchanged public source arrays, table `source`, corroboration outcomes, function module ownership/alias flags, and completeness.
- Produces: one pure producer-owned semantic-join predicate in `scripts/check-capture-evidence.py`; exact schema and privacy language; a scan-decoy canary proving aggregate-only behavior.

- [ ] **Step 1: Write checker RED mutations**

In the self-test, mutate one valid fixture at a time and require rejection for:

```text
unknown module source
unknown object source
unknown table source
unknown corroboration outcome
corroborated=false beside agreed
corroborated=false beside conflict
corroborated=true with no agreed/conflict
conflict counter unequal to conflict outcomes
unverified scan-only module reported COMPLETE
scan-only/aliased/null-module function treated as semantic-joinable
```

Also add positive controls for manifest-only attestation and exact agreed scan+manifest with no conflict.

- [ ] **Step 2: Run checker RED**

```sh
python3 scripts/check-capture-evidence.py --self-test
```

Expected: FAIL on the first newly added mutation currently accepted.

- [ ] **Step 3: Implement one pure eligibility helper and exact validation**

Add a pure helper with this contract:

```python
def semantic_join_eligible(function, module):
    if function["module"] is None or function["module_ambiguous"] or function["aliased"]:
        return False
    sources = module["sources"]
    outcomes = set(module["corroboration"])
    if sources == ["manifest"]:
        return True
    return (
        sources == ["scan", "manifest"]
        and "agreed" in outcomes
        and not outcomes.intersection({"conflict", "identity_mismatch", "object_fallback"})
    )
```

Validate exact source/table-source/corroboration enums, canonical ordering, counter/outcome consistency, and the current meaning of `corroborated`: true iff at least one comparable `agreed` or `conflict` outcome is recorded for the final module. Keep existing stale/fallback arithmetic unchanged.

- [ ] **Step 4: Write the decoy canary RED**

Add a self-test fixture with one scan-only provider-shaped table and hostile semantic-looking argument values. Require exact aggregate calls/RVs/latency, `PARTIAL`, no semantic state sections, and no descriptor-selected payload in profile or trace. Preserve all existing caps and negative-control expectations.

- [ ] **Step 5: Run checker/canary RED**

```sh
python3 scripts/check-capture-evidence.py --self-test
sh scripts/verify-canaries.sh --self-test
```

Expected before implementation: checker or canary fails on missing policy enforcement; after implementation both pass.

- [ ] **Step 6: Correct schema and privacy text**

Document:

```markdown
- `scan` is bounded heuristic discovery, not semantic acquisition.
- `manifest` is explicit operator attestation under the Slice 1b-1 contract.
- `hash-pinned` authorizes object bytes/offsets only.
- `corroborated` summarizes comparable `agreed` or `conflict`; consumers use the exact outcome array.
- Scan-only rows are aggregate observations and never semantic joins.
- Conflict modules are wholly ineligible for semantic joins in v2.
- Count-only is a reduction in provider-memory reads and adds no allowlisted field.
```

Remove the privacy allowlist's provider-honesty assumption as semantic authority. Preserve every existing privacy field and unsafe-mode restriction.

- [ ] **Step 7: Run focused contract suites**

```sh
python3 scripts/check-capture-evidence.py --self-test
sh scripts/verify-canaries.sh --self-test
cargo +1.88 test --locked --test multi_module -- --nocapture
cargo +1.88 test --locked --test artifact_contracts -- --nocapture
```

Expected: all pass without schema identifier change, dependency change, or allowlist expansion.

- [ ] **Step 8: Commit**

```sh
git add scripts/check-capture-evidence.py scripts/verify-canaries.sh \
  docs/schema/observed-profile-v2.md docs/privacy/allowlist-v1.md \
  tests/artifact_contracts.rs tests/multi_module.rs
git commit -m "docs: freeze semantic discovery eligibility"
```

---

### Task 4: Operator Docs, Full Gates, and Independent Closeout

**Files:**
- Modify: `src/cli.rs`
- Modify: `README.md`
- Modify: `docs/usage.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/superpowers/plans/ROADMAP.md`
- Modify only if exact assertions require it: `scripts/verify-attach-e2e.sh`, `scripts/matrix/verify-docker.sh`, `scripts/matrix/verify-kind.sh`, `scripts/matrix/verify-proxy-stack.sh`, `scripts/matrix/verify-shared-layer.sh`, `scripts/matrix/verify-oracle.sh`, `scripts/matrix/verify-fork-scope.sh`

**Interfaces:**
- Consumes: reviewed Tasks 0-3 and their exact evidence.
- Produces: explicit CLI attestation wording, honest product status, complete unprivileged verification, and a privileged/container gate request rather than an implicit run.

- [ ] **Step 1: Write CLI/docs contract tests**

Extend the existing CLI/help and artifact contract tests to require these exact concepts:

```text
--manifest is explicit operator attestation of exact accepted function-name/offset claims
scan-only discovery is semantics-unverified and count-only
aggregate counts/RVs/latency remain available
live and terminal evidence are PARTIAL while scan-only semantic claims remain
P11Lab joins reject scan-only and conflict modules
Slice 1b-2 live acquisition remains future work
```

- [ ] **Step 2: Run docs/CLI RED**

```sh
cargo +1.88 test --locked --lib cli -- --nocapture
cargo +1.88 test --locked --test artifact_contracts -- --nocapture
```

Expected: FAIL because current help/docs still describe the authority choice as open or trusted input without attestation semantics.

- [ ] **Step 3: Update operator-facing text**

Change CLI help, README, usage, and changelog only to the approved terms. Keep current privacy-first 1.0 exclusions: no object-handle correlation and no symbolic `CKA_CLASS`/`CKA_KEY_TYPE`. Update ROADMAP to “implementation complete, independent review and privileged matrix pending”; do not close Slice 1b-1 yet.

- [ ] **Step 4: Audit every exact matrix consumer without running privileged lanes**

Read each listed script and modify only assertions whose expected source/corroboration/completeness semantics changed. Do not broad-search/replace and do not weaken loss, lifecycle, identity, privacy, count, or negative-control oracles.

- [ ] **Step 5: Run fresh unprivileged gates**

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
python3 scripts/check-capture-evidence.py --self-test
sh scripts/verify-canaries.sh --self-test
git diff --check
```

Expected: every command exits 0; record exact test counts and candidate HEAD.

- [ ] **Step 6: Perform independent code, privacy, and exact-range security reviews**

Review the full Task 0-4 range. Required conclusions:

```text
no raw-key or path-based authority transfer
no unverified descriptor-selected read in safe or unsafe builds
no public schema contradiction
no allowlist expansion
no stale fallback attestation
no hidden P11Lab eligibility for scan-only/conflict rows
no eBPF ABI/map/program/dependency change
```

Resolve every Critical/Important finding with a fresh RED/GREEN round before closeout.

- [ ] **Step 7: Commit operator docs and reviewed matrix assertions**

```sh
git add src/cli.rs README.md docs/usage.md CHANGELOG.md \
  docs/superpowers/plans/ROADMAP.md \
  scripts/verify-attach-e2e.sh scripts/matrix/verify-docker.sh \
  scripts/matrix/verify-kind.sh scripts/matrix/verify-proxy-stack.sh \
  scripts/matrix/verify-shared-layer.sh scripts/matrix/verify-oracle.sh \
  scripts/matrix/verify-fork-scope.sh
git commit -m "docs: document semantic discovery authority"
```

- [ ] **Step 8: Request privileged/container gate approval**

Present the exact candidate HEAD, clean status, unprivileged results, scripts to run, expected runtime/resources, and cleanup scope. Do not execute until the owner approves.

- [ ] **Step 9: Close only after reviewed privileged evidence**

If approved, run the unchanged/focused privileged matrices serially, preserve every failure, rerun the four Rust gates after any fix, obtain final independent review, and only then mark Slice 1b-1 closed. Actual P11Lab integration remains an external release gate until an exact consumer checkout and contract test exist.

---

## Self-Review Checklist

- [ ] Every Contract A requirement maps to one task and one runnable check.
- [ ] No placeholder, future scaffolding, new dependency, ABI/map/program change, or generic provenance graph exists.
- [ ] Exact authority merge key is pinned object + offset + canonical name.
- [ ] `Agreed` retains a real manifest claim; raw `ObjectKey` remains evidence-only.
- [ ] Scan-only aggregate facts survive while semantic state stays empty.
- [ ] Existing public v2 vocabulary and schema identifiers remain unchanged.
- [ ] Conflict and stale fallback cannot borrow manifest attestation.
- [ ] Privileged/container execution remains separately approval-gated.
