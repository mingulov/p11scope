# Productization Slice 1b-1 Corrective Closeout — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development` to execute this plan one task at a time. Every production change starts with a witnessed failing regression, receives a task-specific review, and is committed only after the reviewer accepts it.

**Goal:** Close the confirmed Slice 1b-1 correctness, privacy, identity, and evidence gaps without broadening the privacy allowlist or beginning Slice 1b-2.

**Architecture:** Keep the existing scan → pin → reconcile → plan → attach pipeline. Add one capture-owned work budget, retain process-generation pins through attach, delay object/view collapse until comparable identity exists, bound interface-name reads to one VMA, and classify optional stale-manifest failures only after scan fallback is known. Reuse existing `Skipped`, `PARTIAL`, `PidPin`, pinned-object, and overlay-collapse paths; add no crate or speculative abstraction.

**Tech stack:** Rust 1.88, edition 2024, Linux x86-64, `/proc`, pidfd, Aya/eBPF, serde JSON schemas, shell/Python matrix oracles.

---

## Global constraints

- Work only in `/home/user/src/m/pkcs11-scope-codex-slice1b-1` on `codex/slice1b-1-recovery`.
- Preserve unrelated work and `docs/privacy/allowlist-v1.md`; do not broaden capture.
- The exact starting point is `8784aa0c89bb1142da5552cd2cc492aa7bfb18aa` with 297 tests passing.
- Do not implement Slice 1b-2 loader/export hooks, pause/resume, `run --`, or dynamic attach here.
- Do not change heuristic table semantic authority in Tasks 1–5. Before Task 6 can use any completion or security-clearance language, the owner must approve one explicit contract: evidence-strict scan-only tables (`heuristic-unverified`, count-only, `PARTIAL`, upgraded only by exact Slice 1b-2 acquisition evidence) or provider-honesty-assumed semantics with an explicit assurance label. Approval alone is not closure: the selected contract then needs a separate executable TDD plan, RED/GREEN implementation, schema/consumer/docs coverage, task review, and exact verification. Until all of that lands, independent fixes may land but Slice 1b-1 remains open on the canonical High finding.
- Treat selected process memory, paths, manifests, cgroup membership, and provider files as untrusted inputs. Never trade away privacy, identity, or bounded work for compatibility.
- A named PID is fail-closed. A disappearing/changing cgroup member becomes bounded skip evidence and `PARTIAL` without aborting unrelated members.
- If mapping identity cannot be compared, fail closed with explicit evidence. The inode-only fallback is not an accepted identity mechanism.
- Use the existing finite evidence vocabulary where it can state the result honestly. Any new serialized field needs schema, privacy, renderer, checker, and fixture coverage in the same task.
- No generated output is tracked. No new dependency or crate.
- The user approved the required local privileged/container tests. Resolve exact targets read-only before running them and preserve all external state.
- Every task uses RED → GREEN → focused tests → self-review → task review → commit. Do not weaken an oracle to make it green.

## Required final gates

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
```

Also run every applicable repository checker and matrix lane named in Task 6. A green unprivileged suite does not substitute for the approved privileged/container lanes.

**Execution order:** Task 1 → Task 2 → Task 4 → Task 3 → Task 5 → Task 6. Task 4 deliberately precedes Task 3 because process/view ownership must survive reconciliation before a stale cgroup member's contributions can be removed precisely.

---

## Task 1: One capture-wide scan, hash, and decoded-record budget

**Purpose:** Fix the per-PID reset of the documented 512 MiB capture ceiling and bound decoded candidate amplification before allocation. Also stop classifying a lone plausible version word as a truncated table.

**Files:**

- Modify: `src/main.rs`
- Modify: `src/discovery/scan.rs`
- Modify: `src/discovery/identity.rs`
- Modify: `tests/discovery_scan.rs`
- Modify: `tests/manifest_pinning.rs`
- Modify only if required by a new public evidence value: `src/render.rs`, `docs/schema/observed-profile-v2.md`, `scripts/check-capture-evidence.py`

### Step 1: Trace callers and freeze the budget contract

Before editing, trace every caller of `scan_pid`, `pin_scanned_objects`, `pin_scanned_object`, `detect_tables`, and `scan_interfaces`. Record in the task report:

- where bytes are currently charged;
- which reads can retry after failure;
- which allocations happen before the 512-slot planner ceiling;
- why the chosen caps are sufficient for all currently published tables and interfaces.

Use one small mutable capture-owned budget. Do not build a generic quota framework. Freeze these limits in the RED tests:

- one aggregate 512 MiB attempted-I/O ceiling per capture, shared by memory scanning and file hashing across every PID, retry, and failed pin;
- 64 MiB ceiling for each individual scanned-memory object and each individual hashed file, preserving the existing per-operation object rule while both charge the one capture total;
- at most 512 accepted table candidates per capture;
- at most 53,248 decoded table entries per capture (`512 * 104`);
- at most 512 accepted interface records per capture.

The byte counters are authoritative admission limits. Optional scan/hash telemetry may report how the aggregate was spent but must never create independently renewable allowances.

### Step 2: Write RED regressions

Add the narrowest tests that fail on the starting tree:

1. A coordinator-level test supplies two process scans and proves their scan and hash attempts consume the same capture budget rather than fresh copies.
2. A failed/changed pin attempt still charges bytes actually read; retrying cannot regain the budget.
3. Dense structurally plausible table and interface data stops at explicit candidate/table/entry/interface ceilings and emits deterministic skip/`PARTIAL` evidence without materializing the remainder.
4. A version header whose complete `N` pointer words do not fit is a silent non-candidate, exactly as the approved six-clause detector contract requires. Remove/update the old positive incomplete-body truncation test and retain no header-only evidence path.

Run the exact focused tests and retain the failure output in the task report:

```sh
cargo +1.88 test --locked --bin p11scope discovery -- --nocapture
cargo +1.88 test --locked --lib discovery -- --nocapture
cargo +1.88 test --locked --test discovery_scan -- --nocapture
cargo +1.88 test --locked --test manifest_pinning -- --nocapture
```

At least one new assertion in each affected defect path must fail for the expected reason before production edits.

### Step 3: Implement the minimum shared fix

- Own one `CaptureWorkBudget` (or an equally small concrete type) in `discover_plan` and borrow it through all PID scans and pin/hash attempts.
- Enforce the one aggregate 512 MiB attempted-I/O ceiling across scan and hash work for the entire capture. Preserve the existing 64 MiB ceiling for an individual scan object and for an individual hashed file; both kinds of work charge the aggregate. Separate scan/hash counters, if retained for telemetry, never authorize work.
- Charge attempted I/O at the shared read/hash boundary even if later identity or hashing checks fail. Do not refund completed work.
- Enforce the fixed 512-table, 53,248-entry, and 512-interface capture ceilings close to candidate creation. On exhaustion, stop the remaining relevant decode loop immediately before further candidate work, push, clone, or allocation; emit one bounded exhaustion result rather than repeatedly rediscovering the same cap.
- Convert every bounded omission into finite skip/evidence and `PARTIAL`; never silently truncate.
- Delete incomplete-body/truncated-table evidence: unless all version-selected pointer words are present and every detector clause passes, the bytes are not a table candidate.

### Step 4: Verify and review

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 test --locked --bin p11scope discovery -- --nocapture
cargo +1.88 test --locked --lib discovery -- --nocapture
cargo +1.88 test --locked --test discovery_scan -- --nocapture
cargo +1.88 test --locked --test manifest_pinning -- --nocapture
cargo +1.88 test --locked --test artifact_contracts -- --nocapture
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
```

Self-review for double charging, retry amplification, hidden allocation before the cap, evidence leakage, and changed ordinary provider output. Request task review and fix all Critical/Important findings before committing.

**Commit:** `fix: enforce capture-wide discovery work limits`

---

## Task 2: Bound interface names to their validated VMA

**Purpose:** Close the reproduced cross-VMA disclosure without changing the default capture allowlist.

**Files:**

- Modify: `src/discovery/scan.rs`
- Modify: `src/inspect.rs`
- Modify: `tests/discovery_scan.rs`
- Modify or add the narrowest inspect rendering unit test in `src/inspect.rs`

### Step 1: Write RED regressions

1. Construct a readable name starting near one VMA's end with no in-range NUL and controlled bytes/NUL in the adjacent VMA. Assert none of the adjacent bytes enter the discovered interface name or rendered output.
2. Assert quotes and ASCII control bytes cannot be interpolated raw into text inspect output.
3. Keep the existing ordinary in-VMA name and exact-standard classification green.

```sh
cargo +1.88 test --locked --test discovery_scan -- --nocapture
cargo +1.88 test --locked --lib inspect -- --nocapture
```

Retain the expected disclosure/render failure in the task report before editing production code.

### Step 2: Implement the shared boundary fix

- Carry or derive the containing readable mapping end from the already resolved maps entry.
- Limit the name read to `min(64, mapping_end - name_ptr)` with checked arithmetic.
- Accept/persist a name only when its NUL terminator occurs inside that mapping and the existing finite validation succeeds; otherwise record the existing unreadable/bounded status.
- Render text with an existing escaping facility or `escape_default`; add no encoder dependency.

### Step 3: Verify and review

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 test --locked --test discovery_scan -- --nocapture
cargo +1.88 test --locked --lib inspect -- --nocapture
cargo +1.88 test --locked --test artifact_contracts -- --nocapture
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
```

Self-review every caller of the name reader and all output modes. Request task review before commit.

**Commit:** `fix: confine interface names to one mapping`

---

## Task 3: Retain the selected process generation through attach

**Purpose:** Prevent PID reuse or cgroup churn from turning discovery evidence for one process generation into attach against another.

**Depends on:** Task 4's retained process/view provenance. Execute Task 4 first even though this task keeps its finding-oriented number.

**Files:**

- Modify: `src/main.rs`
- Modify: `src/process.rs`
- Modify: `src/discovery/scan.rs`
- Modify: `src/discovery/identity.rs`
- Modify only at the narrow attach boundary if needed: `src/attach.rs`
- Modify: `src/inspect.rs`
- Modify: `tests/manifest_pinning.rs`

### Step 1: Write RED lifecycle regressions

Create an injectable or pure lifecycle seam around existing `PidPin`; do not add a mock framework.

1. Named PID: change the recorded generation between scope resolution, scan/pin, attach start, and attach completion; assert no later `/proc/<pid>` action occurs, a generation change during attachment tears down the just-created session before events are consumed, and the command fails closed.
2. Cgroup: change one member generation; assert that member is skipped with `PARTIAL` evidence while stable members remain eligible.
3. Cgroup ownership: two accepted process generations share one mount namespace and one provider identity but expose divergent private table targets; retiring one removes only its owned contributions and leaves the other's targets/pins eligible.
4. Inspect: retain and recheck the same generation through its final target-memory operation.

```sh
cargo +1.88 test --locked --lib process -- --nocapture
cargo +1.88 test --locked --test manifest_pinning -- --nocapture
```

### Step 2: Implement ownership, not another identity system

- Make `Discovered`/capture state own the named `PidPin` and the Task 4 process/view records, including each accepted cgroup member's capture-unique `ProcessViewId`, pin, and precise module/pinned-object contributions, until attach completes. Sharing a mount namespace or physical provider never merges process-generation ownership.
- Pass references to the existing pins through scan and object-pinning code; do not reopen a generation implicitly.
- Recheck `still_the_same` immediately before attach and immediately after the Slice 1b-1 `Session::start` completes. A post-attach mismatch drops the just-created session/links and fails or skips before trace/profile/metrics consumes an event. Dynamic delta attachment remains Slice 1b-2 and is not introduced here.
- Preserve bounded cgroup churn behavior: member loss/change removes only that retained view's table/fd contributions before plan/attach. If detected only after the one-shot `Session::start`, tear down that whole new session before event consumption, remove every stale view found in that pass, and rebuild from stable members. Each retry must retire at least one originally accepted view, so retries are bounded by the initial accepted-member count (`MAX_SCAN_PIDS == 256`); one stale member never aborts otherwise stable members. Named-target loss/change is fatal.
- Keep the current 256-member cap. Check fd pressure but do not add a pin pool.

### Step 3: Verify and review

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 test --locked --bin p11scope -- --nocapture
cargo +1.88 test --locked --lib process -- --nocapture
cargo +1.88 test --locked --test manifest_pinning -- --nocapture
cargo +1.88 test --locked --test multi_module -- --nocapture
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
```

Self-review all `/proc/<pid>` and attach call sites for generation reopen/reuse. Request task review before commit.

**Commit:** `fix: keep process generations pinned through attach`

---

## Task 4: Preserve process views and paths until physical identity is comparable

**Purpose:** Fix same-key first-wins loss, btrfs subvolume aliasing, and inode-only fallback with one identity-boundary correction while preserving attach-once overlay behavior.

**Files:**

- Modify: `src/main.rs`
- Modify: `src/process.rs`
- Modify: `src/discovery/scan.rs`
- Modify: `src/discovery/identity.rs`
- Modify: `crates/manifest/src/identity.rs`
- Modify: `src/plan.rs`
- Modify: `src/attach.rs`
- Modify if reconciliation evidence changes: `src/render.rs`
- Modify: `tests/discovery_scan.rs`
- Modify: `tests/manifest_pinning.rs`
- Modify: `tests/multi_module.rs`
- Modify: `scripts/matrix/verify-shared-layer.sh`

### Step 1: Write RED regressions

1. Equal `ObjectKey` from two process views with differing table target sets: prove the later view is not silently dropped. Only observations with equal comparable full file identity and digest retain their safe target union; otherwise fail the collision group closed with bounded ambiguity and `PARTIAL`.
2. Equal raw `(mount namespace, ObjectKey, path)` and equal digest but distinct full `MappingFileKey` mount identities (the btrfs/path-replacement collision model): prove they remain separate through open/comparison/hash, then reject the ambiguous collision group before planning so neither can borrow the other's fd/offsets.
3. Forced `mapping_file_key` failure with same inode and different device: replace the current permissive test with fail-closed skip evidence.
4. Preserve the one explicit overlay exception: byte-identical candidates that satisfy the existing overlay-filesystem gate and full merge predicate still collapse to exactly one attach slot with one entry/return probe pair and publish the existing bounded physical-identity uncertainty/`PARTIAL` evidence.
5. Preserve differing non-empty target sets during election; no whole-module first-wins loss.

```sh
cargo +1.88 test --locked --bin p11scope discovery -- --nocapture
cargo +1.88 test --locked --lib discovery -- --nocapture
cargo +1.88 test --locked --test discovery_scan -- --nocapture
cargo +1.88 test --locked --test manifest_pinning -- --nocapture
cargo +1.88 test --locked --test multi_module -- --nocapture
```

### Step 2: Implement the minimum identity correction

- Add three concrete capture-local identities rather than teaching `ObjectKey` new semantics:
  - `ProcessViewId(u32)`, allocated monotonically once per accepted `PidPin`/process generation and never serialized;
  - `MountNamespaceId`, recorded separately from the retained pin for file-instance comparison;
  - `PinnedObjectId(u32)`, allocated only after one raw candidate instance has been opened, identity-checked, and hashed.
- Every scanned table/target contribution retains its owning `ProcessViewId` even after exact physical-object deduplication. A raw object instance is grouped by `(MountNamespaceId, ObjectKey, normalized target path)` while scanning/pinning, but this grouping never merges contribution ownership. The numeric PID is not identity and is never serialized from either key.
- Treat the raw instance key only as a grouping/indexing aid; it never authorizes a merge. Extend the internal comparable `MappingFileKey` fact with the fd's parsed mount id, then define exact ordinary-file equality as the same full mapping/file identity (mount id, maps device, inode, size, ctime pin) plus the same verified digest. Only exact-equal observations may merge their target-table union and share a `PinnedObjectId`.
- If one `ObjectKey` group contains unequal or unavailable full identities—even when raw keys and digests match—reject the whole collision group with bounded physical-identity ambiguity and `PARTIAL`; do not attach either candidate and do not choose first-wins. The sole exception is the existing overlay-only heuristic below.
- After reconciliation, convert every usable module/entry target to `PinnedObjectId`. `PinnedObjects` is keyed by that ID; `Slot` and attach lookup use that ID plus file offset. Keep the original `ObjectKey` only on module/evidence summaries so the public schema does not gain a process-derived identity.
- Preserve a capture-local ownership map from each `ProcessViewId` to its table/target/pin claims, including duplicate claims on one `PinnedObjectId`. Removing a stale view subtracts only its claims; a target/pin survives while any stable view still owns it.
- Remove the pre-hash key-only first-win merge and every `PinnedObjects::absorb` receiver-wins path for scan candidates.
- Open and establish comparable mapping/file identity before allocating a pinned ID. If mount-namespace identity, normalized path, full mapping identity, or digest cannot be established, skip with finite uncertainty evidence and `PARTIAL`.
- Do not accept inode alone. Prefer the existing `mapping_file_key`; where unavailable, fail closed rather than inventing a new fallback.
- Reuse current content/hash pin and `collapse_overlay_mappings` logic after candidates are comparable.
- For ordinary filesystems, attach once only after exact comparable identity establishes the shared physical object. Preserve the already approved overlay-only heuristic exception: it may elect one canonical fd only behind the existing overlay-filesystem gate plus full predicate, must publish bounded physical-identity uncertainty and `PARTIAL`, and must preserve the current shared-layer oracle. Never generalize that exception to squashfs/erofs/btrfs or call it exact identity. Preserve all non-empty target unions or name the discarded view and reason.

### Step 3: Verify locally and in the approved container lane

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 test --locked --bin p11scope discovery -- --nocapture
cargo +1.88 test --locked --lib discovery -- --nocapture
cargo +1.88 test --locked --test discovery_scan -- --nocapture
cargo +1.88 test --locked --test manifest_pinning -- --nocapture
cargo +1.88 test --locked --test multi_module -- --nocapture
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
scripts/matrix/verify-shared-layer.sh
```

Resolve the script's exact container/runtime targets read-only first. Do not weaken its exact slots/probes/provider-count/uncertainty oracle. Record host/kernel/runtime details and raw pass/fail evidence.

Self-review for double attach, silent undercount, cross-attribution, btrfs aliasing, overlay regressions, stale fds, and path/PID leakage in evidence. Request task review before commit.

**Commit:** `fix: reconcile discovery only after comparable identity`

---

## Task 5: Let a valid scan supersede stale optional manifest objects

**Purpose:** Restore the approved per-object fallback rule: stale optional pin/SHA failures are ignored only when a valid scanned table for that object exists, while malformed trusted input and stale sole sources remain fatal.

**Depends on:** Task 4's fail-closed identity/error vocabulary.

**Files:**

- Modify: `src/main.rs`
- Modify: `src/discovery/identity.rs`
- Modify: `tests/manifest_pinning.rs`
- Modify: `src/render.rs`
- Modify: `docs/schema/observed-profile-v2.md`
- Modify: `scripts/check-capture-evidence.py`

### Step 1: Write RED orchestration regressions

1. Valid scanned table plus stale manifest identity/SHA: continue with scan pins, ignore no more than the stale object, publish bounded ignored/uncorroborated evidence, and remain `PARTIAL` where the evidence contract requires it.
2. Stale manifest object as the sole source: fail after discovery establishes that no usable scanned table exists.
3. Structurally invalid/schema-invalid trusted manifest: fail immediately as configuration/usage error; it is never optional.
4. Multi-object manifest: decide fallback per object, never once per file. A mixed manifest with one corroborated stale object and one stale sole-source object must keep the former eligible and fail for the latter; evidence identifies bounded per-object outcomes without paths/PIDs.
5. No stale fd, slot, offset, or target enters the final plan.

```sh
cargo +1.88 test --locked --bin p11scope discovery -- --nocapture
cargo +1.88 test --locked --lib discovery -- --nocapture
cargo +1.88 test --locked --test manifest_pinning -- --nocapture
```

### Step 2: Implement typed deferred classification

- Keep manifest schema/structure validation eager and fatal.
- Represent open/identity/SHA staleness as a typed per-object result rather than matching strings.
- Accumulate stale optional object failures, build the scan view, then decide whether each object has a valid scanned replacement.
- Drop all stale pins/offsets. Reuse existing ignored/uncorroborated evidence where it is semantically exact.
- Do not turn arbitrary I/O, permission, or malformed-manifest failures into silent fallback.
- Change the v2 schema/docs/checker/fixtures from the current per-manifest identity-mismatch rule to the approved per-object rule. Serialize exact bounded mixed-object outcomes and reject documents that hide a stale sole-source object behind another object's valid scan.

### Step 3: Verify and review

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 test --locked --bin p11scope discovery -- --nocapture
cargo +1.88 test --locked --lib discovery -- --nocapture
cargo +1.88 test --locked --test manifest_pinning -- --nocapture
cargo +1.88 test --locked --test multi_module -- --nocapture
cargo +1.88 test --locked --test artifact_contracts -- --nocapture
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
```

Self-review error classification, per-object matching, evidence privacy, and pin lifetimes. Request task review before commit.

**Commit:** `fix: defer optional manifest staleness until fallback`

---

## Task 6: Honest CLI/docs, exact full gates, and corrective security review

**Purpose:** Remove the silently ignored `doctor --module`, update final status from fresh evidence, and prove the corrected Slice 1b-1 tree before Slice 1b-2 begins.

**Files:**

- Modify: `src/main.rs`
- Modify: the narrowest existing CLI test file
- Modify: `README.md`
- Modify: `docs/usage.md`
- Modify: `docs/superpowers/plans/ROADMAP.md`
- Modify: `CHANGELOG.md`
- Update corrective implementation/review reports under `.superpowers/` only if that is the repository's established convention; never track generated runtime output.

### Step 0: Resolve the canonical High policy gate

Obtain and record explicit owner approval for exactly one semantic-authority contract before using `complete`, `closed`, `security cleared`, or equivalent status:

1. **Evidence-strict (recommended):** scan-only table matches are `heuristic-unverified`, count-only, and force `PARTIAL`; only exact Slice 1b-2 acquisition-hook agreement upgrades semantics.
2. **Provider honesty assumed:** retain semantic descriptors for scan-only matches, but serialize and document the assumption/assurance qualifier in every consumer contract.

If neither is approved, do not improvise a hybrid and do not downgrade the canonical High finding. If one is approved, approval is still not implementation: write and independently review a concrete RED/GREEN plan for that exact branch, implement its planner/descriptor/verdict/schema/consumer/privacy/docs effects, run its focused and full gates, and obtain task review before continuing this task. Otherwise finish only the independent evidence and commits, leave Slice 1b-1 explicitly open, and hand the decision to the next controller turn.

### Step 1: RED for `doctor --module`

Add a CLI test proving supplied operator input is not ignored. Use the minimum honest behavior: reject `doctor --module` as unsupported unless an already-existing module-specific doctor path can be wired without new machinery. Do not implement speculative doctor discovery.

### Step 2: Update documentation from fresh facts

- State that Tasks 1–5 are Slice 1b-1 corrective closeout and Slice 1b-2 is still the loader/export-hook and `run` slice.
- Document capture-wide work/cardinality ceilings, retained PID-generation semantics, fail-closed incomparable identity, stale-manifest fallback, and VMA-bounded interface names.
- Preserve the approved privacy allowlist and the privacy-first 1.0 product boundary. Do not claim object correlation or symbolic `CKA_CLASS`/`CKA_KEY_TYPE`.
- Do not resolve the separate heuristic semantic-authority policy by implication.
- Replace stale test/commit/status counts only with exact final-tree measurements.
- Mark CI as pending unless it actually ran on the exact final commit.

### Step 3: Run all unprivileged gates

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
scripts/verify-inspect-doctor.sh
python3 scripts/check-capture-evidence.py --self-test
```

### Step 4: Run the approved exact privileged/container matrix

Resolve prerequisites and targets read-only, then run the current canonical entry points without oracle edits:

```sh
scripts/gates.sh
scripts/matrix/verify-docker.sh
scripts/matrix/verify-fork-scope.sh
scripts/matrix/verify-oracle.sh
scripts/matrix/verify-proxy-stack.sh
scripts/matrix/verify-shared-layer.sh
scripts/matrix/verify-kind-pod.sh
scripts/matrix/verify-knative.sh
scripts/verify-discover-containers.sh
scripts/build-release.sh
```

`scripts/gates.sh` is the canonical host bundle and must include `verify-inspect-doctor`, `verify-attach-e2e`, `verify-induced-gaps`, and `verify-canaries`; record that inventory from the exact script before relying on it. The seven matrix scripts cover Docker, fork/cgroup, oracle, proxy capacity fallback, shared-layer identity, kind, and Knative. `verify-discover-containers` and `build-release` are separate required decisions, not silently implied by another lane. `bench-overhead.sh` is `NOT APPLICABLE` unless an implementation task changes the BPF/event hot path; these corrective userspace discovery changes do not justify a benchmark rerun by themselves.

For every command, record one of `PASS`, `FAIL`, `BLOCKED`, or `NOT APPLICABLE` with a concrete reason. Knative is applicable to the claimed product matrix even if the local cluster cannot provision it; in that case it is `BLOCKED`, not omitted. Record exact kernel, sysctls, capabilities, Docker/kind/Knative versions, commands, exit status, slots/probes/calls/loss/skip evidence, and any environmental blocker. A blocked lane stays `BLOCKED`/`UNVERIFIED`; it is never converted to PASS.

### Step 5: Review the exact final tree

- Request a whole-range correctness/Rust/eBPF/privacy review from the Slice 1b-1 base to final HEAD.
- Run a fresh security diff scan over the same exact range and validate all candidates. Compare each of the eight prior canonical findings as fixed, approved policy with the exact recorded owner decision, still open, or contradicted with exact evidence. An unapproved semantic-authority policy can only be `still open`.
- Re-run all affected gates after review fixes.
- Confirm `git status --short` is clean and report final HEAD and exact diff statistics.

**Commit:** `docs: record slice 1b-1 corrective evidence`

Do not mark Slice 1b-1 complete while any Task 1–5 Important issue remains, required evidence is silently missing, or the approved heuristic semantic-authority contract lacks its separately reviewed implementation and verification. Independent corrective commits may still be handed off as complete work while the slice itself remains open.
