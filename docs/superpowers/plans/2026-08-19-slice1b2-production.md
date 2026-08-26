# Slice 1b-2 Live Discovery and `run` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use
> `superpowers:subagent-driven-development` to execute this plan task by task.
> Use `superpowers:test-driven-development` for every behavior change,
> `superpowers:systematic-debugging` for unexpected results, and
> `superpowers:requesting-code-review` before each task commit. Do not begin a
> later task while an earlier task has unresolved review findings.

**Goal:** Discover and attach PKCS#11 providers that appear after capture start,
without requiring a manifest or executing provider code, and add an owned-child
`run -- CMD` lane whose explicit pause policy can protect live attachment
windows without a BPF busy-wait.

**Architecture:** Keep the Slice 1b-1 scan/pin/reconcile/plan pipeline as the
single identity and table authority. First move static slot semantics into one
capture-independent frozen `DESCRIPTORS` table selected by the attach cookie;
then make slot allocation and links additive. A separate `DISCOVERY` ring feeds
one concrete `discovery::Engine`, which revalidates retained process generations,
refreshes mappings, reuses the existing bounded scanner and pinning code, and
adds exact targets to the live session. Loader and export hooks provide event
timing and ptrace-free table records. Only an owned, unreaped `run` child may be
paused, and its coordinator follows the approved no-busy-wait amendment with
one original pidfd and fail-closed cleanup.

**Tech Stack:** Rust 1.88, edition 2024, Linux x86-64, existing `aya = 0.14`,
`aya-ebpf = 0.2.1`, `object`, `libc`, `signal-hook`, Python 3 contract checkers,
POSIX/Bash gate scripts, and the retained Jammy 5.15/Noble 6.8 QEMU/KVM assets.
No new crate is planned.

## Authority and starting state

- Implementation base: `c68aa169672b91ed7a387a17afa282b4afa6d022`
  (`docs: amend slice 1b-2 pause protocol`), whose parent is the reviewed Slice
  1b-1 closeout `5f3bd607032057f8d04ced55fcb27ba185193416`.
- Binding product contract:
  `docs/superpowers/specs/2026-08-18-slice1b2-corrective-live-discovery-design.md`.
- Binding pause correction, which supersedes conflicting pause/Gate B wording:
  `docs/superpowers/specs/2026-08-19-slice1b2-no-busy-wait-pause-amendment.md`.
- Proposed D3 scope correction, which conservatively implements the recorded
  D3=`no` decision by removing the timing-catalog promotion requirement while
  retaining `PARTIAL` completeness, loader/context, and attach-first gates:
  `docs/superpowers/specs/2026-08-19-slice1b2-d3-scope-amendment.md`.
- Unchanged architecture facts may be taken from
  `docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md`;
  its older timing and pause assumptions are not authoritative.
- `docs/superpowers/plans/ROADMAP.md` controls phase order and promotion.
- The historical 120/120 busy-wait campaign and the later 120/120 no-delay
  outcome-B campaign are feasibility evidence only. Neither is promotable.
- The historical Task 8 attach-first 160/160 experiment is likewise
  non-promotable and contributes zero product attempts; it covered a narrower
  fixture/export-return experiment and is replaced by the frozen Task 9
  product campaign.
- Historical research-plan Task 9 timing-catalog work remains owner-declined
  (`D3 = no`). The product
  therefore ships no guessed loader tuple. An empty compiled-in catalog is
  valid: every-hit discovery continues, timing is `unproven`, and completeness
  remains honestly `PARTIAL` where required.
- **Implementation checkpoint (2026-08-24):** Tasks 3–7 are implemented and
  independently reviewed on the isolated productization branch. A short-lived
  Docker diagnostic then exposed capture-history ownership loss after ordinary
  workload exit. Task 6E below is a newly required correction and blocks Task
  8. This is implementation status only: public `run`, supported live-capture
  claims, product runtime gates, required CI, release, and security clearance
  remain incomplete or unclaimed. This dated checkpoint supersedes the
  historical unchecked implementation boxes below; those boxes are retained as
  the original task contract, not current status.

**Topology scope amendment (2026-08-27, Task 4):** The historical Lane 13
checker/invocation work is complete at checker/lifecycle commit
`34357b5dda71c670250dd3ab336b29c801120d5b` (tree
`ae3346e4b8e137f430f010d0937bcf186cfcff39`) and final invocation/contract
commit `fd3d08ad9bd2f58508eda1ee4a50882c0633d850` (tree
`0decc4dee974707468b5758107fb055c30d44d7d`); no new Task 4 checker or
invocation run is planned. Its zero-unavailable PASS oracle applies only to a
topology proposed for supported acceptance. Retain the evidenced Knative
shared-inode capture for the exact preattached provider: `136/136` probes and
expected cold-pod calls. The completed pre-r3 attempt-6 exclusion is bound to
immutable receipt
`/home/user/.local/state/p11scope/task4-lane13-a2fd9ee-20260826T2135EEST/facts.log`
(SHA-256
`b96cbed6cbc2963dab2c5963b5c52f6378d9bef313479b83a56c259df79b94f3`, exact
HEAD/tree `a2fd9ee8eddfaff34b3fb6b65267688b5a90aa03` /
`f90e2dfe8dbd0a211f9e32055a37ff7320080b88`). It binds the lane command/script
ledger, Kind/Knative releases/images, provider hash/build ID, kernel/storage,
node/workload identities, and clean start/end; any future negative-control
classification with different receipt-defined inputs is UNRUN/review and never
inherits the exclusion by outcome alone. In the reproduced Knative node-wide
retained-view topology, full late-provider discovery is
`UNSUPPORTED/NON-PASS`; one overlay plus one unavailable is evaluated only as
the required negative control, never by the PASS oracle. Attempt 6 is not rerun
in Task 4; Lane 13 runs once in 9.2d as the frozen-candidate negative control.
Remaining applicable Task 4 lanes and r3 may proceed only after this additive
amendment is independently reviewed and committed; Lane 13 PASS is not an
unlock condition. The Gate Closure Task 5 capability-validator integration is
complete through exact commit `7a0c1eddac0b0b81340206ac742884ca2f31f691`, and
its live capability gate exited 0 without changing Lane 13. README/usage
wording remains reserved for Task 10. This amendment changes no design spec,
production Rust/BPF/privacy/schema/allowlist, or procfs/mmap/eBPF fallback
behavior.

## Global constraints

1. Preserve `docs/privacy/allowlist-v1.md` until the explicit evidence task;
   that task may list only the approved aggregate vocabulary and must add
   matching canary negatives in the same commit.
2. Preserve scan-only semantic authority: live/scan targets are count-only
   unless an accepted manifest authorizes the exact final pinned object,
   offset, and canonical name. Live discovery never promotes semantic authority.
3. Reuse `ProcessView`, `CaptureWorkBudget`, `PinnedObjects`,
   `rebuild_discovered`, `AttachPlan`, `SlotSemantics`, and the existing
   process/object lifecycle checks. Do not add a second scanner, pin cache,
   manifest model, or process-identity type.
4. Policy maps remain published, verified, and frozen before the first probe.
   Only data/lifecycle maps explicitly named by the design remain writable.
5. One slot space, monotonically allocated up to `MAX_SLOTS = 512`; no slot ID,
   loader context ID, or pause epoch is reused in one capture.
6. No new public loader/pause PID/TID/task set, path/digest/build ID for loader/libc,
   runtime address, pointer, cookie, context ID, signed delta, signal record,
   marker, interface-name bytes, or per-event loader/pause timeline. The
   existing separately allowlisted trace PID/TID contract is unchanged.
7. No pause for `--pid` or `--cgroup`. Omitted `run --pause` is exactly `never`.
   `auto|always` are not enabled until the corrected Gate B campaign passes.
8. No new privilege. `/proc/<pid>/mem` denial degrades scan coverage but must
   not disable ptrace-free loader/export events. Pause uses only the owned
   child's original pidfd and same-credential signal authority.
9. Each task begins with a source/caller trace and a witnessed RED before
   production behavior changes. Each task ends with an independent review,
   exact final gates, one scoped commit, and a clean status readback.
10. Do not track generated BPF objects, VM images, logs, evidence, or reports
    under `.superpowers/sdd`. Private campaign evidence remains outside Git.
11. Privileged, VM, or container commands run only at the task that names them,
    after an unprivileged review checkpoint and using new output paths. The
    owner granted standing approval on 2026-08-24 for this exact worktree's
    named host/container tests; do not ask again for those lanes. A materially
    new external VM/target still needs explicit approval. An unapproved lane is
    `UNRUN` and cannot contribute to completion. Both kernel lanes run
    regardless of the first result; no rerun-until-green.
12. Every task must leave these commands green unless its own RED is being
    captured:

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
git diff --check
```

## Dependency graph and checkpoints

```text
Task 0 approve the D3 scope amendment and this plan
  -> Task 1 corrected isolated A/B candidate
  -> Task 2 A/B kernel campaign (pause promotion gate)

Task 3 descriptor/cookie static migration
  -> Task 4 dynamic slots and links
Task 2 reviewed PASS + Task 4
  -> Task 5 production discovery ABI/BPF
  -> Task 6 loader contexts and discovery engine
  -> Task 7 owned run child and pause coordinator (requires Task 2 PASS)
  -> Task 6E capture-history and lifecycle ownership correction
  -> Task 8 capture loops, evidence, privacy, and doctor
  -> Task 9 product/provider/kernel integration
  -> Task 10 final multi-artifact review and local integration
```

Tasks 3–4 may be implemented while a reviewed Task 2 campaign is running. Task
5 and every later task require an independently reviewed Task 2 PASS because
the production BPF inventory includes the pause path. A non-PASS leaves only
the already-existing research evidence and any completed static refactor; it
adds no dormant `auto|always` code and cannot complete Slice 1b-2.

Task 7's accepted review remains valid for its stated pause/owned-child scope.
Its earlier readiness verdict is qualified by the subsequently discovered Task
6E dependency; Task 8 cannot start until Task 6E is independently accepted.

## Task 0: Approve the D3 scope amendment and implementation plan

**Purpose:** Remove the only contradictory promotion boundary before source
implementation.

**Files:**

- Add: `docs/superpowers/specs/2026-08-19-slice1b2-d3-scope-amendment.md`
- Add: `docs/superpowers/plans/2026-08-19-slice1b2-production.md`
- Modify: `docs/superpowers/plans/ROADMAP.md`

- [ ] Independently review the D3 amendment against the corrective design,
  research decision, retained Task 6–8 evidence, privacy contract, and ROADMAP.
- [ ] Confirm the replacement critical path is: mandatory product-shaped
  ptrace-free every-hit/context preflight, 480-primary-plus-40-fallback
  both-kernel attach-first campaign, corrected A/B campaign, and
  production/provider/kernel gates; the 480-attempt relocation-witness catalog
  remains dormant.
- [ ] Confirm an empty catalog leaves timing `unproven`,
  `initial_set_capture.none`, and final `PARTIAL`; attach-first success protects
  only an observed live window and creates no replacement timing proof.
- [ ] Independently review this plan for task dependency, executable RED/GREEN
  boundaries, file/caller accuracy, lifecycle/privacy coverage, and YAGNI.
- [ ] Resolve every finding, correct the historical attach-first disposition in
  ROADMAP, run document consistency/placeholder/fence/diff checks, and commit
  exactly these three documentation files before Task 1.

Commit message: `docs: plan slice 1b-2 live discovery`

## Task 1: Correct and freeze the isolated A/B candidate

**Purpose:** Replace both historical Gate B protocols with the exact approved
no-busy-wait state machine while preserving the flat-initializer Gate A.

**Files:**

- Modify: `spike/slice1b2-kernel/common.rs`
- Modify: `spike/slice1b2-kernel/ebpf/src/main.rs`
- Modify: `spike/slice1b2-kernel/src/main.rs`
- Modify: `spike/slice1b2-kernel/run.sh`
- Modify only if the concurrent return-marker contract requires it:
  `spike/slice1b2-kernel/fixture.c`
- Preserve: `spike/slice1b2-kernel/check-init-shape.py` semantics and the exact
  four-map/six-program inventory

### Step 1: Freeze the RED contract

- [ ] Trace every producer, record decoder, owner transition, child-guard exit,
  validator branch, and shell lifecycle caller before editing.
- [ ] Add source/object guards that reject `STOP_SIGNAL_DELAY_POLLS`, any loop,
  backward edge, busy wait, or unapproved helper between winner CAS and
  terminal ring submit. Permit only the exact clock read and winner's sole
  signal helper; require `ktime` immediately before that helper.
- [ ] Add deterministic state-machine tests for:
  - reservation failure consuming no `ARMED` authorization;
  - accepted owner state recorded before every fallible userspace action;
  - Outcome A: one winner, one coalesced record, one attach closure, one resume;
  - Outcome B: first owner closes, successor is pre-armed while all tasks remain
    stopped, first owner resumes, deferred hook wins owner 2, then a second full
    closure and second resume;
  - successor consumption before the first resume is lifecycle FAIL;
  - accepted owner-2 confirmation timeout or cancellation retains and performs
    its original-pidfd resume obligation;
  - cancellation after successor pre-arm/resume but before decode treats the
    successor as unresolved, removes authorization, and performs the one
    separately recorded protective resume before kill/reap;
  - monotonic deadline checked before dequeue, immediately after dequeue/decode,
    and against the record timestamp;
  - rejected helper request removes authorization, drains through deadline plus
    one empty read, performs no `SIGCONT`, and does not rearm that child;
  - an ordinary failed `auto` epoch becomes sticky partial and cannot accept a
    delayed record into a later epoch;
  - Ctrl-C, SIGTERM, timeout, attach failure, malformed record, ring loss,
    duplicate winner, unknown record, resume failure, and guard drop all run
    non-short-circuiting cleanup;
  - exactly one original-pidfd resume per accepted stop plus at most one distinct
    protective successor resume in the amendment's exact unresolved state;
  - Rust runner and Python/shell validator reject the same mutated branch,
    lifecycle, timing, and inventory facts;
  - coalesced-before-winner arrival uses only a provisional deadline and is
    revalidated against the winner-relative deadline;
  - teardown order is detach -> bounded drain/decode -> authorization removal
    -> ledger-authorized protective resume -> kill/reap;
  - final `START` empty and every link detached.
- [ ] Add semantic-export mutations for every finite category and both valid
  outcome branches. Preserve `TIMEOUT/INCOMPLETE` as distinct from canonical
  runner FAIL and environment failure.
- [ ] Freeze private `SignalRecord.send_signal_rc == i64::MIN` as exactly
  coalesced/no-helper; zero is accepted helper request and every other value is
  the real signed helper return. No validator may infer this from case order.

Run the focused suite and retain the failures before production edits:

```sh
cargo +1.88 test --locked --manifest-path spike/slice1b2-kernel/Cargo.toml \
  -- --nocapture
```

Expected RED: the retained busy-wait/source contract, owner-2 cleanup, causal
deadline, and one-winner/one-resume oracle cannot satisfy the new assertions.

### Step 2: Implement the minimum corrected protocol

- [ ] Keep the four maps `EVENTS`, `DISCOVERY`, `START`, `COUNTERS`, the six
  programs, 896-byte record, 104/16 bounds, and flat 112-store initializer.
- [ ] Reuse the disjoint Gate B group key in `START`; do not add a fifth map.
- [ ] Implement reserve/init -> CAS -> `ktime` -> one helper -> straight stores
  -> submit, with no post-signal spin or wait.
- [ ] Represent exactly one current owner and one successor authorization in
  userspace. Store no raw process identity in exported evidence.
- [ ] Mark accepted-stop cleanup responsibility before any fallible sample,
  drain, attach, detach, marker, or evidence operation.
- [ ] Make cleanup idempotent and non-short-circuiting: resume obligations,
  link detach, owner removal, kill/reap, evidence close, VM cleanup, and final
  status are each attempted and each result retained.
- [ ] Use one absolute 100 ms winner-relative deadline per accepted cycle; the
  second record never resets it.
- [ ] Keep the fixture genuinely concurrent. A serialized/barrier-only control
  may diagnose scheduling but cannot satisfy the campaign oracle.

### Step 3: Verify and review before any VM

```sh
cargo +1.88 fmt --manifest-path spike/slice1b2-kernel/Cargo.toml --all -- --check
cargo +1.88 check --locked --manifest-path spike/slice1b2-kernel/Cargo.toml --all-targets
cargo +1.88 test --locked --manifest-path spike/slice1b2-kernel/Cargo.toml
cargo +1.88 clippy --locked --manifest-path spike/slice1b2-kernel/Cargo.toml \
  --all-targets -- -D warnings
bash -n spike/slice1b2-kernel/run.sh
```

- [ ] Run the locked BPF build into a new private directory and apply
  `check-init-shape.py`, exact map/program inventory, `llvm-objdump -dr`, and
  the no-busy-wait semantic guard.
- [ ] Compile the fixture with `-Werror`, run its self-check, and inspect the
  protected call sites with `objdump -dr`.
- [ ] Request an independent source/lifecycle review. Fix all Critical,
  Important, and Minor findings with new RED/GREEN evidence.
- [ ] Commit the reviewed source once. Freeze source archive, manifest, BPF,
  host runner, fixture, validator, common ABI, caps, timeouts, and oracle hashes.

Commit message: `spike: correct slice 1b-2 pause protocol`

## Task 2: Run the amended A/B kernel campaign

**Purpose:** Decide whether `auto|always` may enter product implementation.
This task changes no source after the candidate freeze.

**Private outputs:** one new mode-0700 campaign root outside Git, with one
manifest binding every source/tool/binary/kernel/oracle dependency.

### Step 1: Preflight

- [ ] Obtain explicit owner approval for the VM/root campaign immediately
  before execution. Without it, record Task 2 `UNRUN` and stop the pause path.
- [ ] Verify clean candidate commit, exact frozen hashes, signed/retained VM
  bases, QEMU identity, SSH host keys, backing chains, lifecycle lock, free
  space, and absence of QEMU/NBD/listeners.
- [ ] Provision/build one fresh guest bundle if the frozen candidate bytes are
  not already guest-built. Verify shutdown, base immutability, qemu-img, and
  post-space before campaign use.
- [ ] Do not modify a timeout, cap, fixture, validator, or oracle after freeze.

### Step 2: Run every predeclared lane

- [ ] Gate A once on Jammy 5.15 and once on Noble 6.8, identical final A/B
  bytes. Require four accepted verifier records, five exact cases, four maps,
  canonical status, bounded logs, privacy, and empty `START`.
- [ ] Gate B exactly three cold boots x 20 fresh children on Jammy and the same
  on Noble. Both kernels run even if the first lane fails.
- [ ] Each child must classify exclusively as Outcome A or Outcome B and satisfy
  its full causal, attach, marker, resume, cleanup, and record inventory.
- [ ] Preserve every first failure and every negative. Do not replace a failed
  row, mix accelerator identities, or rerun until a preferred branch appears.

Use only the reviewed `run.sh` public lifecycle commands. A representative
shape is:

```sh
bash spike/slice1b2-kernel/run.sh gate-a-lane jammy "$BUNDLE" "$RUN" "$EXPORT"
bash spike/slice1b2-kernel/run.sh gate-b-lane jammy "$BUNDLE" "$RUN" "$EXPORT"
```

### Step 3: Independent campaign review

- [ ] Recompute hashes, program/map/verifier cardinalities, all 120 Gate B
  predicates, privacy, cleanup, and base/bundle immutability independently.
- [ ] PASS requires both Gate A lanes and all six Gate B lanes. Any timeout,
  incomplete evidence, lifecycle error, oracle mismatch, or unclassified child
  is non-PASS.
- [ ] Record the exact disposition in the note and ROADMAP without rewriting
  historical evidence.

No product commit is made here. A reviewed PASS unlocks Task 5 and the rest of
the production path. A non-PASS stops that path; it does not authorize a
reduced or dormant pause implementation.

## Task 3: Migrate static attachment to descriptor cookies

**Purpose:** Make later dynamic slots possible without changing current static
capture behavior.

**Files:**

- Modify: `crates/ebpf-common/src/lib.rs`
- Modify: `crates/ebpf/src/main.rs`
- Modify: `src/kinds.rs`
- Modify: `src/plan.rs`
- Modify: `src/attach.rs`
- Modify: `scripts/check-bpf-map-defs.py`
- Modify: `scripts/verify-canaries.sh`
- Modify: `scripts/verify-induced-gaps.sh`
- Modify: `tests/artifact_contracts.rs`

### Step 1: Write RED ABI and behavior tests

- [ ] Freeze `DESCRIPTORS[0] == SlotSemantics::COUNT_ONLY` and one descriptor
  for each canonical published function, with no capture-dependent contents.
- [ ] Freeze attach-cookie layout:

```rust
pub const fn attach_cookie(slot: u32, descriptor: u32) -> u64 {
    u64::from(slot) | (u64::from(descriptor) << 32)
}
pub const fn cookie_slot(cookie: u64) -> u32;
pub const fn cookie_descriptor(cookie: u64) -> u32;
```

  These helpers define `SlotAttachCookie` semantics only. The loader context
  cookie has the unrelated §7.3 bit layout and must use separately named
  encode/decode functions in `discovery::loader`; neither decoder is reused by
  the other program family.

- [ ] Test round trips at zero and maxima, out-of-range descriptor fail-closed
  to `COUNT_ONLY`, and slot indices unchanged in `STATS`, `RV_COUNTS`, `START`,
  and `Event.slot`.
- [ ] Test exact canonical-name descriptor selection, agreeing aliases, unknown
  names, conflicting aliases, and scan-only targets. Scan-only remains
  count-only regardless of a known function name.
- [ ] Test map publication/readback/freeze occurs before every attachment and
  no `SLOT_SEMANTICS` map remains in the object or artifact contracts.
- [ ] Run current planner, metrics, semantics, trace, manifest, and attach tests
  as RED against the absent API/map.

### Step 2: Perform the static-only migration

- [ ] Reuse `SlotSemantics`; do not introduce a parallel descriptor struct.
- [ ] Add a stable descriptor index to `Slot`. Build the fixed descriptor slice
  once in `kinds.rs`; index 0 is count-only.
- [ ] Replace `SLOT_SEMANTICS` with fixed `DESCRIPTORS`. Publish every entry,
  read it back, and freeze it in `Session::start_inner` before program attach.
- [ ] Decode slot and descriptor independently in BPF. Unknown descriptor index
  yields count-only semantics without changing aggregate counting.
- [ ] Encode both indices at the existing entry/return attach sites. Keep the
  static `AttachPlan`, attachment order, failure accounting, and output exact.

### Step 3: Verify and review

```sh
cargo +1.88 test --locked --lib kinds
cargo +1.88 test --locked --lib plan
cargo +1.88 test --locked --lib attach
cargo +1.88 test --locked --test artifact_contracts
```

- [ ] Run all global gates and the existing unprivileged canary/checker
  self-tests.
- [ ] Independently review ABI compatibility, policy-map freeze ordering,
  fail-closed descriptor handling, semantic authority, and absence of dynamic
  behavior in this commit.

Commit message: `refactor: select slot descriptors by attach cookie`

## Task 4: Extend `AttachPlan` with monotonic slots and link lifecycle

**Purpose:** Allow exact targets discovered later to attach without reloading the
BPF object or mutating a frozen policy map.

**Files:**

- Modify: `src/plan.rs`
- Modify: `src/attach.rs`
- Modify: `src/metrics.rs`
- Modify: `src/semantics.rs`
- Modify: `src/trace.rs`
- Modify: `tests/multi_module.rs`

### Step 1: Freeze runtime invariants with RED tests

Extend the existing plan; do not add a peer slot table, trait, or alternate
planner:

```rust
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct AttachKey {
    pub object: PinnedObjectId,
    pub file_offset: u64,
}

// Private implementation detail of AttachPlan.
// exact key -> monotonically allocated slot; retired slots remain reserved
```

- [ ] Test initial `AttachPlan` insertion preserves today's indices and reports.
- [ ] Test a later exact key receives the next slot and attaches one entry/return
  pair with the encoded descriptor cookie.
- [ ] Test an existing key is never attached twice; names/module ownership merge
  into its userspace metadata only.
- [ ] Test a module that would cross `MAX_SLOTS` is refused whole and no prefix
  is attached.
- [ ] Test a shared target changes to count-only/module-ambiguous, purges all
  semantic state for every affected process/module, and leaves aggregate counts.
- [ ] Test a failed return attach suppresses its entry attach and produces one
  exact finite failure; another module can still attach.
- [ ] Test retire detaches every link for the affected module/key, purges state,
  never reuses the slot, and preserves already-collected aggregate counters.
- [ ] Test `Session::detach_producers` and `Drop` detach static, dynamic, loader,
  and export links without short-circuiting after one failure.
- [ ] Test metrics/trace lookup works for slots added after capture start and an
  unknown slot stays count-only/unattributed.

### Step 2: Split load from additive attachment

- [ ] Extend `AttachPlan` with one private `BTreeMap<AttachKey, usize>` and
  monotonic retired-slot set. At 512 entries this needs no dependency, cache,
  peer planner, or new module.
- [ ] Add one transactional `AttachPlan::extend_exact` operation that validates
  capacity, identity, ownership, descriptors, and every target before mutating
  the plan, and returns the finite attachment/retirement delta.
- [ ] Refactor `Session::start` into a policy/load phase and an additive
  `attach_plan`/`attach_targets` phase. Keep a wrapper that performs both for the
  existing static callers until Task 8 moves them.
- [ ] Store every Aya link ID needed for precise retirement and terminal detach.
  Never rely on numeric PID or a reopened path; attach via retained pinned fds.
- [ ] Keep slot allocation in userspace. Dynamic data-map keys may appear after
  freeze; descriptor/policy maps may not.
- [ ] Add `State::sync_plan`/`purge_modules` and `Tracer::sync_plan` using the
  same `AttachPlan` snapshot. Do not create a second slot-to-module index.
- [ ] On exact shared-target ambiguity, mark both module owners incomplete and
  purge semantic state before accepting another event through that slot.

### Step 3: Verify static equivalence and dynamic behavior

```sh
cargo +1.88 test --locked --lib plan
cargo +1.88 test --locked --lib attach
cargo +1.88 test --locked --test multi_module
cargo +1.88 test --locked --lib semantics
cargo +1.88 test --locked --lib trace
```

- [ ] Run the existing attach-evidence unit/integration tests without privileged
  attachment and prove the initial static report is byte-for-byte unchanged.
- [ ] Independently review slot non-reuse, capacity atomicity, link ownership,
  shared-target purge, frozen-map ordering, and terminal cleanup.

Commit message: `refactor: support additive live attachment slots`

## Task 5: Add the production discovery ABI and BPF programs

**Purpose:** Emit bounded loader/export/exec facts and pause requests from the
production object while keeping all private bytes out of public output.

**Promotion prerequisite:** Task 2 independently reviewed PASS. If Task 2 is
not PASS, Task 5 remains `UNRUN` and adds no Task 5 source, map, or program
code. After Task 2 PASS, this task may add the production pause ABI, map, and
program, but userspace arming remains disabled until Task 7.

**Files:**

- Modify: `crates/ebpf-common/src/lib.rs`
- Modify: `crates/ebpf-common/Cargo.toml`
- Modify: `crates/ebpf/src/main.rs`
- Modify: `crates/ebpf/Cargo.toml`
- Modify: `build.rs`
- Modify: `src/events.rs`
- Modify: `src/scope.rs`
- Modify: `src/attach.rs`
- Modify: `src/discovery/hooks.rs`
- Modify: `src/main.rs`
- Add: `scripts/check-live-discovery-object.py`
- Modify: `scripts/check-bpf-map-defs.py`
- Modify: `tests/artifact_contracts.rs`

### Step 1: Define and RED-test one bounded ABI

- [ ] Add one `#[repr(C)]`, 896-byte, alignment-8 `DiscoveryRecord` shared by
  product host/eBPF. Freeze every field offset, including 104 pointer words,
  16 interface records/classes, `announced_count @880`,
  `reserved_tail_zero: [u8; 4] @884`, and private `send_signal_rc: i64 @888`.
  All four tail bytes are zero; the host privately decodes and validates the
  field, but it never enters the public schema, evidence, or rendering.
- [ ] Freeze the finite kinds: `1=function_list_return`,
  `2=interface_list_element_return`, `3=loader`, `4=interface_return`,
  `5=exec`, and `6=leader_exit`; every other kind is malformed and increments
  userspace `discovery_truncated` once. Freeze name classes as `0=N/A`,
  `1=exact_standard`, `2=other`, `3=null`, and `4=unreadable`.
- [ ] Freeze status legality: kinds 1, 2, and 4 allow any subset of bits
  `0x01` and `0x02` only (status `0`, `0x01`, `0x02`, or `0x03`); kind 3
  permits exactly `0`, `0x02`, or `0x04` and never `0x02|0x04`; kind 5
  permits `0` or `0x02`; kind 6 permits only `0`. Any other bit pattern is
  malformed. `0x01=read_failure`, `0x02=coalesced_no_helper`, and
  `0x04=loader_context_invalid`.
- [ ] Freeze field legality: `table_ptr` is the export-table address for kinds
  1, 2, and 4; a nonzero loader runtime hook IP is valid only for kind 3 with
  status 0 or 0x02; otherwise it is zero. Kind 3 status 0x04 has zero
  `table_ptr`, `case_id`, `announced_count`, and context fields and performs no
  context/IP/delta/state work. `interface_flags` is used only by kinds 2 and
  4; `case_id` is the validated loader context-id-minus-one (zero for 0x04);
  `interface_index` is only kind 2 and is 0..15; `symbol_id` is only kinds 1,
  2, and 4; `announced_count` is the saturated interface count for kind 2,
  loader `r_state` for kind 3, and zero otherwise.
- [ ] Freeze bounded-read fields: `usable_n` is zero after a submitted read
  failure and otherwise is the usable prefix; `completed_prefix <=
  pointers_attempted <= 104`; unused pointer words and reserved bytes are
  zero.
- [ ] Freeze the kernel counter ABI numerically: `COUNTERS[0]` is ring loss,
  `[1]` export state failures, `[2]` export bounded-read failures, `[3]`
  loader hits, and `[4]` loader state-read failures. Do not reuse call-event
  `EVIDENCE` cells. The CAS winner stores the sign-extended helper result in
  `send_signal_rc`; a coalesced/no-helper record sets status bit `0x02` and
  stores `i64::MIN`, while an independently observed export read failure keeps
  bit `0x01` set and therefore yields status `0x03`. An ordinary unarmed or
  pause-ineligible record stores zero, and a context-invalid loader record
  stores zero. Zero is accepted as a request only for the exact generation
  epoch whose `ARMED -> REQUESTED` CAS was consumed. For every record, status
  bit `0x02` is set if and only if the field is `i64::MIN`.
- [ ] Test kind/status/field legality, signed helper return encoding,
  source/host record decode, short/long rejection, all-zero reserved fields,
  truncation limits, and no raw value renderer path.
- [ ] Add a product-object initializer guard that fails before implementation:
  every reservation path must have exactly 112 aligned volatile zero stores for
  offsets `0..=888`, no duplicate/narrow spill, no initializer call/back-edge,
  no field read before completion, and submit last. It must scope itself to the
  record reservation/use region rather than reject unrelated ELF `memset`.

### Step 2: Add maps and programs without enabling userspace pause

- [ ] Freeze the runtime maps exactly: `DISCOVERY` is a 65,536-byte ring;
  `DISCOVERY_STATE` is `HashMap<StateKey, StartState>` with key/value sizes
  16/16 and capacity 64; `COUNTERS` is `PerCpuArray<u64>` with capacity 5;
  and `PAUSE_PIDS` is `HashMap<PauseKey, u64>` with key/value sizes 16/8 and
  capacity 1. The four runtime maps declare flags `0`, remain writable, and
  are not frozen. `DISCOVERY_STATE` uses required `BPF_NOEXIST` insertion and
  return-path removal; every capacity-64 insertion failure is counted and
  forces partial.
  `COUNTERS` is summed in userspace with the fixed indices `0` ring loss, `1`
  export state failures, `2` export bounded-read failures, `3` loader hits,
  and `4` loader state-read failures.
- [ ] Change `PID_FILTER` to `HashMap<u32, u64>` (key/value sizes 4/8,
  capacity 1024, `BPF_F_RDONLY_PROG`). Every published PID token is nonzero.
  Non-pause PID scopes use fixed token `1`; an owned `run` session allocates
  one nonzero token and binds it privately to its retained original `PidPin`.
  Define `FLAG_PAUSE_ENABLED = 1 << 5`; set it only for an owned PID scope
  with `Some(OwnedPauseGeneration)`.
- [ ] Freeze `PauseKey` as `#[repr(C)] { tgid: u32, pad: u32,
  generation_token: u64 }`; `pad` is zero and values are exactly `ARMED = 1`
  or `REQUESTED = 2`. BPF obtains the token from the already scoped current-
  TGID `PID_FILTER` lookup and must match the full pause key before CAS. For
  `PAUSE_PIDS`, BPF performs only exact-key lookup and CAS; it never inserts or
  removes, and userspace owns both operations. `PAUSE_PIDS` is excluded from
  the frozen policy inventory.
  Userspace revalidates the bound `PidPin` immediately before insertion and
  after record decode, removes authorization and detaches pause-capable links
  before reap, and never reuses the token in one capture. No token map, token
  record field, or public epoch is added.
- [ ] Enforce the scope matrix: PID + `None` publishes token 1 with pause off;
  cgroup + `None` leaves `PID_FILTER` empty with pause off; PID +
  `Some(OwnedPauseGeneration)` is pause-enabled only for the owned run PID and
  its exact token; external
  `--pid` and cgroup + `Some` refuse before any mutation. When a PID scope
  uses `PID_FILTER`, a missing or zero token emits
  no record; cgroup scope bypasses PID_FILTER. After valid scope, an absent
  exact `PAUSE_PIDS` key, including a stale key for another generation, emits
  an ordinary discovery record with `send_signal_rc = 0` and performs no
  CAS/helper call. Separately, if `arm_pause()` observes a `PID_FILTER`
  readback token mismatch, it performs no `PAUSE_PIDS` insertion or arm; this
  mismatch does not suppress ordinary discovery from an otherwise valid scope.
- [ ] Define in `src/attach.rs` the public opaque capability exactly as
  `pub struct OwnedPauseGeneration { tgid: u32, generation: NonZeroU64 }` with
  both fields private. It has no public constructor, `from_parts`/conversion,
  field accessor, or public way to fabricate the exact PID/token state.
  Preserve the final API as
  `Session::start(..., pause_generation: Option<OwnedPauseGeneration>)`.
  Before any map mutation, `Session` rejects `Some(capability)` unless the
  scope is `Scope::Pid(pid)` and `capability.tgid == pid`; cgroup + `Some` and
  a PID/tgid mismatch refuse before scope/config/PID_FILTER/PAUSE_PIDS
  publication. After this precondition passes and `scope::publish` succeeds,
  private `Option<PauseKey>` is `Some` only for that exact owned PID/token and
  otherwise is `None`; `None` has no pause key even though PID scope publishes
  token 1. The exact two existing binary callers pass `None`; Task 5 has no
  `Some` caller or capability constructor. Crate-internal `arm_pause()` takes
  no PID or token, is the sole userspace insertion path, and has no Task 5
  caller. `Session`'s mutable `Ebpf` is non-public; the separate
  `src/main.rs` binary uses only fixed-purpose visible drain/read methods and
  exposes no mutable `Ebpf` or map handle.
- [ ] RED-test no arming: the exact two existing `start` callers pass `None`,
  `start`, `start_inner`, and `scope::publish` never insert or arm,
  `arm_pause()` is the sole production insertion path, and no production arm
  caller exists in Task 5. Also test exact PID_FILTER token readback,
  `PauseKey.pad == 0`, and full-key equality. Split the negative cases: a
  missing/zero `PID_FILTER` token under PID scope submits no record; an
  `arm_pause()` `PID_FILTER` readback mismatch inserts/arms nothing; and an
  absent/stale exact `PAUSE_PIDS` key submits the ordinary rc-zero record with
  no CAS/helper. Authorization removal uses the same full key.
- [ ] Add source and mutation guards before production implementation: prove
  `OwnedPauseGeneration` fields are private, no public constructor or raw
  token/parts conversion exists, the exact two existing `Session::start`
  callers pass `None`, and Task 5 contains no `Some` caller or constructor.
  The only permitted constructor/caller is the Task 7 path below. Mutate a
  PID/tgid mismatch and a cgroup + capability case and assert refusal occurs
  before any CONFIG, PID_FILTER, PAUSE_PIDS, link, or other map mutation.
- [ ] Add the pause-enabled `CONFIG` bit through `src/scope.rs`, read it back,
  and include this frozen policy inventory in `src/attach.rs`: `CONFIG`,
  `PID_FILTER`, `CGROUP_FILTER`, `DESCRIPTORS`, `ASYNC_FUNCTIONS`, and
  `MECH_SHAPE`; unsafe mode additionally requires `ATTR_BOOL_BITS` and the
  separately published, read-back, and frozen `TEMPLATE_TAIL`. Unknown bits
  or missing/unfrozen policy maps fail load.
- [ ] Implement loader every-hit uprobe with the §7.3 cookie/IP/state path:
  zero cookie rejected before lookup; absent-state sentinel and present zero
  delta remain distinct; `bpf_get_func_ip` plus x86-64 RIP fallback; optional
  one 4-byte `r_state` read at exact `+24`; invalid context sets `0x04` and
  performs no state arithmetic/read.
- [ ] Increment scoped loader hits before ring reservation. Count only actual
  state-address/helper read failures in loader state-read failures; cookie or
  registry failures belong to context/truncation accounting instead.
- [ ] Keep loader-cookie decode separate from slot-cookie decode. The loader
  path has no BPF context registry map: the cookie carries bounded arithmetic
  inputs, while userspace validates the monotonic registry shell after decode.
- [ ] Add one product object inventory for both manifests: the added programs
  are `dl_debug_state`, `function_list_entry`, `function_list_return`,
  `interface_list_entry`, `interface_list_return`, `interface_entry`,
  `interface_return`, `sched_process_exec`, and `sched_process_exit`. The
  default object has exactly 12 programs and 15 maps; unsafe has exactly 16
  programs and 17 maps.
- [ ] Implement separate entry/return programs for function-list,
  interface-list, and interface ABIs. Entry state is no-overwrite and cleaned on
  every return. Read only successful outputs, at most 104 function pointers,
  at most 16 interfaces, and only enough interface-name bytes to classify then
  discard them.
- [ ] Extend the existing `src/discovery/hooks.rs` and use one `HookRegistry` for standard,
  NSC/FC, and explicit `--hook-symbol` names/ABI selection, with the Task 4
  link registry shared by loader, export, and tracepoint links. Reserve ID 0;
  insertion positions are one-based; built-ins receive IDs 1..=5 in the
  current `BUILTIN` order; custom hooks append; duplicate replacement retains
  its ID. Export attach cookies are exactly `u64(symbol_id)`, and the decoder
  requires symbol ID, ABI, and kind to agree. Do not add another symbol
  registry in BPF or userspace.
- [ ] Add exec/leader-exit records needed by run/cgroup lifecycle. Exit cleanup
  does not establish process identity and never authorizes numeric-PID reuse.
- [ ] Implement the amendment's reserve/init/CAS/timestamp/helper/submit pause
  path, but leave userspace `PAUSE_PIDS` empty in this task. No copied delay,
  post-signal polling, or hidden rearm logic.
- [ ] Use the frozen-nightly-supported `core::intrinsics::atomic_cxchg` pattern
  already proved by the research artifact and require `cmpxchg_64` in
  disassembly. Do not add `target-cpu=v3` or emulate CAS in userspace.
- [ ] Add a distinct test-only `small-discovery-ring` build wired through both
  eBPF manifests and the existing build script; it changes only `DISCOVERY`
  from 65,536 to 4,096. Preserve the existing `small-ring` fixture and its
  `EVENTS` behavior; do not add a runtime sizing option.

### Step 3: Prove source/object shape before runtime use

```sh
cargo +1.88 test --locked -p p11scope-ebpf-common
cargo +1.88 test --locked --test artifact_contracts
cargo +1.88 check --locked --workspace --all-targets
```

- [ ] Locked nightly BPF build passes the semantic 112-store guard on every
  production discovery emitter, exact ABI/map/program inventory, helper and
  bounded-loop disassembly assertions, and no-busy-wait guard.
- [ ] Run the one object-validator interface on all four exact variants. This
  block declares every path before use and creates each manifest from source
  only before checking the corresponding fresh object:

```sh
set -eu
TASK5_OBJECT_ROOT="$(mktemp -d /tmp/p11scope-task5-object.XXXXXX)"
trap 'rm -rf "$TASK5_OBJECT_ROOT"' EXIT
SOURCE="$(realpath crates/ebpf/src/main.rs)"
DEFAULT_TARGET="$TASK5_OBJECT_ROOT/default-target"
UNSAFE_TARGET="$TASK5_OBJECT_ROOT/unsafe-target"
SMALL_RING_TARGET="$TASK5_OBJECT_ROOT/small-ring-target"
SMALL_DISCOVERY_TARGET="$TASK5_OBJECT_ROOT/small-discovery-ring-target"
DEFAULT_OBJECT="$DEFAULT_TARGET/bpfel-unknown-none/release/p11scope-ebpf"
UNSAFE_OBJECT="$UNSAFE_TARGET/bpfel-unknown-none/release/p11scope-ebpf"
SMALL_RING_OBJECT="$SMALL_RING_TARGET/bpfel-unknown-none/release/p11scope-ebpf"
SMALL_DISCOVERY_OBJECT="$SMALL_DISCOVERY_TARGET/bpfel-unknown-none/release/p11scope-ebpf"
DEFAULT_MANIFEST="$TASK5_OBJECT_ROOT/default.manifest.json"
UNSAFE_MANIFEST="$TASK5_OBJECT_ROOT/unsafe.manifest.json"
SMALL_RING_MANIFEST="$TASK5_OBJECT_ROOT/small-ring.manifest.json"
SMALL_DISCOVERY_MANIFEST="$TASK5_OBJECT_ROOT/small-discovery-ring.manifest.json"

cargo +nightly build --locked --release --target bpfel-unknown-none -Z build-std=core --manifest-path crates/ebpf/Cargo.toml --target-dir "$DEFAULT_TARGET"
cargo +nightly build --locked --release --target bpfel-unknown-none -Z build-std=core --manifest-path crates/ebpf/Cargo.toml --target-dir "$UNSAFE_TARGET" --features unsafe-unvalidated-metadata
cargo +nightly build --locked --release --target bpfel-unknown-none -Z build-std=core --manifest-path crates/ebpf/Cargo.toml --target-dir "$SMALL_RING_TARGET" --features small-ring
cargo +nightly build --locked --release --target bpfel-unknown-none -Z build-std=core --manifest-path crates/ebpf/Cargo.toml --target-dir "$SMALL_DISCOVERY_TARGET" --features small-discovery-ring

python3 scripts/check-live-discovery-object.py --self-test
python3 scripts/check-live-discovery-object.py --write-test-manifest --source "$SOURCE" --variant default --output "$DEFAULT_MANIFEST"
python3 scripts/check-live-discovery-object.py --write-test-manifest --source "$SOURCE" --variant unsafe --output "$UNSAFE_MANIFEST"
python3 scripts/check-live-discovery-object.py --write-test-manifest --source "$SOURCE" --variant small-ring --output "$SMALL_RING_MANIFEST"
python3 scripts/check-live-discovery-object.py --write-test-manifest --source "$SOURCE" --variant small-discovery-ring --output "$SMALL_DISCOVERY_MANIFEST"
python3 scripts/check-live-discovery-object.py --source "$SOURCE" --object "$DEFAULT_OBJECT" --manifest "$DEFAULT_MANIFEST"
python3 scripts/check-live-discovery-object.py --source "$SOURCE" --object "$UNSAFE_OBJECT" --manifest "$UNSAFE_MANIFEST"
python3 scripts/check-live-discovery-object.py --source "$SOURCE" --object "$SMALL_RING_OBJECT" --manifest "$SMALL_RING_MANIFEST"
python3 scripts/check-live-discovery-object.py --source "$SOURCE" --object "$SMALL_DISCOVERY_OBJECT" --manifest "$SMALL_DISCOVERY_MANIFEST"
```

  It owns the 112-store region check, exact map/program/ABI/helper inventory,
  including `COUNTERS[0..4] = {ring_loss, export_state_failures,
  export_bounded_read_failures, loader_hits, loader_state_read_failures}`,
  cookie namespaces, bounded loops, `cmpxchg_64`, and no-busy-wait assertions.
- [ ] Unit-test export state failure, read failure, truncation, invalid cookie,
  missing cookie, coalesced/no-helper, and ring reservation loss independently.
- [ ] Independently review verifier safety, unsafe-block scope, helper ordering,
  map mutability, counter ownership, privacy, and the lack of userspace arming.

Commit message: `feat: emit bounded live discovery records`

## Task 6: Bind loader contexts and build the incremental discovery engine

**Purpose:** Turn private discovery records into exact pinned targets and
additive attachments by reusing the Slice 1b-1 pipeline.

**Files:**

- Create: `src/discovery/loader.rs`
- Create: `src/discovery/engine.rs`
- Modify: `crates/manifest/src/elf.rs`
- Modify: `crates/manifest/tests/elf.rs`
- Modify: `src/discovery/mod.rs`
- Modify: `src/discovery/scan.rs`
- Modify: `src/discovery/identity.rs`
- Modify: `src/events.rs`
- Modify: `src/attach.rs`
- Modify: `src/main.rs`
- Modify: `tests/discovery_scan.rs`
- Create: `tests/live_discovery.rs`

### Step 1: RED-test the exact loader registry

Use one fixed-capacity concrete registry, not a generic arena:

```rust
const MAX_LOADER_CONTEXTS: usize = 256;

struct LoaderContext {
    // immutable payload: generation, exact pinned loader, hook/state vaddrs
    // mutable shell: prepared | attached(link) | tombstoned
}
```

- [ ] Test monotonic IDs 1..=256, no reuse after detach/tombstone, and the 257th
  context refusing with one `discovery_truncated` contribution.
- [ ] Add only the missing ELF facts to the existing manifest ELF parser:
  direct PT_INTERP bytes and a defined symbol's link-time virtual address.
  Reuse existing `exports_matching`/`symbol_file_offset`; do not add a second
  ELF module or reread the file once per fact.
- [ ] Test cookie examples exactly: absent state/context 1 -> `512`, present
  zero delta/context 1 -> `256`, zero invalid, signed positive/negative delta
  round trips, and overflow refusal.
- [ ] Test `prepared -> attached -> tombstoned -> removed` ordering; detach link,
  tombstone, drain queued records, then remove. A queued old record can never
  resolve as a new context.
- [ ] Test generation, exact loader mapping, pinned identity, and hook-IP
  formula at event time. With D3=`no` and the compiled-in timing catalog
  empty, do not select, guess, or bind a companion libc: timing remains
  `unproven`, `initial_set_capture = none`, and completeness is sticky
  `PARTIAL`. Any loader-context mismatch is one finite truncated/context
  failure and no scan/attach action.
- [ ] Freeze an empty compiled-in timing catalog. Unknown/current tuples remain
  `unproven`; they still use every-hit discovery. Do not add runtime config,
  package-name matching, version matching, or public catalog identity.

### Step 2: RED-test the engine as one direct state machine

- [ ] Construct engine tests from real `ProcessView`, `ScanInput`,
  `PinnedObjects`, and fixture mappings. Synthetic records may drive scheduling,
  but table/object/plan results must come from the real scanner/pinner/planner.
- [ ] Test an initial scan plan attaches once, then a fixture `dlopen`/export
  record produces only the new exact module/targets.
- [ ] Test duplicate loader/export hits are idempotent and never move the
  earliest causal timestamp later.
- [ ] Test a known pinned object exposing an additional table/target set later
  attaches only the delta and records the changed live surface without
  reallocating or double-attaching prior keys.
- [ ] Test ptrace-denied scan with a valid export record still pins mapped
  objects and attaches count-only targets; scan unavailability remains visible.
- [ ] Test scan/live agreement, conflict union, manifest exact authority, and
  live targets remaining count-only.
- [ ] Test ring loss, malformed record, read failure, state failure, context
  failure, capacity, attach failure, zero modules, and unknown loader all make
  the right sticky completeness loss without aborting safe discovery.
- [ ] Test cgroup view addition/removal and named-PID generation change. Every
  per-view action checks the retained generation before and after reads/attach.
- [ ] Test a later raw-key/full-identity collision prospectively before commit.
  If it would invalidate an already attached `PinnedObjectId`, retire and
  detach the complete affected module/key set, purge semantic state, publish
  ambiguity/PARTIAL, and never reuse slots. It must not silently remap a live
  attachment or let receiver order choose authority.
- [ ] Test a later exact shared target performs the Task 4 ambiguity purge but
  remains attached once for aggregate counting.
- [ ] Test capture-wide scan/hash/table/interface/process/context/slot budgets
  are cumulative across initial, periodic, and event-triggered work. A new
  event never renews a budget.

### Step 3: Implement the minimum engine

- [ ] Mechanically move the existing `Discovered` state,
  `rebuild_discovered`, stale-view retirement, manifest-input handling, and
  final-ID binding from `main.rs` into `discovery::Engine` first, with existing
  tests unchanged. Extend that one path; do not wrap or duplicate it.
- [ ] `DiscoveryDrain` decodes and drains only `DISCOVERY`; it does not share
  malformed/loss ownership with call events.
- [ ] `Engine` directly owns retained views, pristine scan inputs, manifests,
  loader registry, cumulative `CaptureWorkBudget`, the one extended
  `AttachPlan`, earliest causal timestamps, and sticky discovery completeness.
  `Session` owns only Aya link lifecycles and applies deltas returned by that
  plan. Do not create source traits, a peer slot table, or a second public
  module model.
- [ ] On every valid loader hit: revalidate context/generation, refresh maps,
  pin exact new mapped candidates, attach standard export hooks, and invoke the
  bounded scanner when available. Do not gate event handling on `RT_CONSISTENT`.
- [ ] On every valid export record: resolve pointers against a fresh mapping
  snapshot, pin every target object exactly, lower into existing scanned/manifest
  shapes, reconcile, plan, and attach only the delta.
- [ ] Periodically scan newly observed cgroup views within the existing 256-view
  cap. PID scope remains one generation and does not follow forks.
- [ ] Compute per-module attach gap from earliest causal event to the timestamp
  immediately after the last required successful attach. Loss makes it `null`;
  a later event never substitutes the missing start.
- [ ] Keep identity merge transactional: apply an incoming pin set to a clone,
  determine retirements/remaps first, then detach/purge and commit. Never call a
  destructive `absorb` on live state before deciding the effect on attachments.

### Step 4: Verify and review

```sh
cargo +1.88 test --locked --lib discovery
cargo +1.88 test --locked --test discovery_scan
cargo +1.88 test --locked --test live_discovery
cargo +1.88 test --locked --test manifest_pinning
cargo +1.88 test --locked --test multi_module
```

- [ ] Run all global gates, checker/canary self-tests, and the locked product
  BPF shape guards.
- [ ] Independently review identity transactionality, exact-ID authority,
  cumulative budgets, stale-view retirement, idempotence, causal timestamps,
  dynamic link cleanup, and public privacy.

Commit message: `feat: attach providers from live discovery events`

## Task 7: Add the owned-child `run` lifecycle and pause coordinator

**Reviewed boundary correction (2026-08-23):** Task 7 implements and tests the
owned-child and pause machinery inside the library. Task 8 owns the public
`RunArgs`, binary dispatch/polling integration, render/schema wiring, and the
external CLI/lifecycle acceptance tests. This supersedes only the older file
and test placement below: `src/main.rs` is a separate binary crate, and making
the coordinator public solely so Task 7 could wire it would broaden the API
before Task 8's complete public contract exists. The behavior and safety gates
in this task remain mandatory.

**Promotion prerequisite:** Task 2 independently reviewed PASS. If it is not
PASS, this task is `UNRUN`; do not add dormant `auto|always` code.

**Files:**

- Create: `src/run.rs`
- Create: `src/discovery/pause.rs`
- Modify: `src/process.rs`
- Modify: `src/discovery/mod.rs`
- Modify: `src/attach.rs`
- Modify: `src/events.rs`
- Modify: `src/discovery/engine.rs`
- Modify: `src/lib.rs`
- Modify: `tests/artifact_contracts.rs`
- Test in: `src/run.rs`, `src/process.rs`, and `src/discovery/pause.rs`

### Step 1: RED-test original-pidfd child ownership

- [ ] Add `PidPin` methods for same-generation signal-authority probe and signal
  delivery through its retained original pidfd. Do not expose the fd or add a
  numeric-PID signal fallback.
- [ ] Test child fork, `setsid`, private pre-exec barrier, exact exec errno/127,
  normal exit status, signal -> `128 + signal`, wait/reap, duration timeout,
  process-group TERM then KILL, first/second Ctrl-C, and SIGTERM forwarding.
- [ ] Test PATH-resolved direct ELF, absolute ELF, shebang, retargeted executable,
  and exec-chain cases. A direct ELF whose pinned executable/PT_INTERP
  revalidates after exec may pre-arm the exact loader hook; every empty-catalog
  case, including a stable direct ELF with a confirmed pause, still has timing
  `unproven`, records `initial_set_capture = none`, and is sticky `PARTIAL`.
- [ ] Test a PID-reuse/generation mismatch prevents the next child action.
- [ ] Test every failure after fork closes barrier fds and kills/reaps the owned
  child; every failure after an accepted stop also performs the exact resume
  obligation first.
- [ ] Test `child_still_running` is true only when duration ends and the child is
  deliberately left running; it is absent from non-`run` output. Before the
  observer returns, every pause authorization/owner is closed, the child is not
  stopped, and observer links/maps are detached even though the child is not
  reaped by this command.

### Step 2: RED-test the amendment as a pure coordinator

Use injected monotonic clock, task-state reader, queue drain, attach action, map
action, marker, pidfd signal, and cleanup actions. Keep real-fd lifecycle tests
separate; do not create a framework or async runtime.

- [ ] Omission and `never` create no owner, map entry, signal, or pause counter.
- [ ] `auto|always` outside an owned `run` child are refused by parsing/caller
  validation before BPF state changes.
- [ ] Preflight freezes expected task set and proves original-pidfd signal
  authority while holding the private `OwnedChild`. Task 7 then invokes the
  sole `OwnedPauseGeneration::from_owned_child(&OwnedChild)` crate-private
  constructor in `attach.rs`, requiring that `OwnedChild`
  (not merely a `PidPin`) and reading its exact owned PID plus private nonzero
  generation into `OwnedPauseGeneration`. It accepts no caller-supplied raw
  PID or token. `OwnedChild` allocates exactly one nonzero generation for the
  capture, never reuses it, and binds it to the retained original pidfd; a
  fallback-only `PidPin` cannot authorize pause. The coordinator revalidates
  the same `PidPin` immediately
  before inserting the full `{tgid, token}` `ARMED` key and again after every
  record decode; only then may it release the barrier.
- [ ] A decoded exact-child `send_signal_rc == 0` is only a stop candidate:
  ordinary unarmed records also store zero. Set `may_be_stopped` immediately
  on that candidate, before the post-dequeue clock, map read, generation check,
  cancellation check, or any other fallible action. Also set it immediately
  when the exact full key reads `REQUESTED`. Accept a winner only when the
  active authorization epoch and exact-key `REQUESTED` state agree. A consumed
  epoch with a malformed/lost winner or an unresolved successor retains its
  one owner/protective-resume obligation.
- [ ] One owner accepts one winner; coalesced records expand only its required
  attach set. Reservation loss before CAS consumes no authorization but becomes
  one finite attempt under explicit pause.
- [ ] Two exact-set/all-`T` snapshots at least 1 ms apart, both no later than the
  absolute 100 ms deadline, are mandatory. A changed task set, non-T state,
  `/proc` error, future timestamp, arithmetic overflow, or deadline crossing is
  finite failure.
- [ ] Poll task state no more frequently than once per millisecond and never
  reset the winner-relative deadline after queue delivery or a second record.
- [ ] While an authorization is `ARMED` or an owner is active, service the
  discovery queue on a monotonic 1 ms cadence so the ordinary capture refresh
  interval cannot consume the 100 ms causal budget. This explicit-pause-only
  polling is the intentional Slice 1b-2 ceiling; add epoll only if later
  measurement shows it is needed.
- [ ] `DiscoveryDrain` exposes one crate-private dequeue result exactly as
  `Record|Malformed`. Read the monotonic clock before and after every dequeue,
  including malformed records, and validate the same absolute deadline. Drop
  the ring borrow before applying one frozen batch through the existing Engine
  scanner/planner/registry/link authority. Top-level and nested retirement
  drains use this same injected collector; no second ring owner exists.
- [ ] After confirmation: drain exact-child records to empty, freeze keys,
  attach all keys, take a third all-T snapshot, verify marker absent and queue
  empty, then issue exactly one original-pidfd resume.
- [ ] Outcome A closes one owner. Outcome B pre-arms exactly one successor while
  all tasks remain stopped, resumes owner 1, accepts only the other deferred
  case into owner 2, then repeats the entire closure. No third owner.
- [ ] Rejected helper, malformed/unknown/duplicate/unaccounted record, ring
  loss, attach failure, marker race, map error, cancellation, detach failure,
  resume failure, and child exit cover every amendment cleanup branch.
- [ ] `auto` non-lifecycle failure safely closes the epoch, increments partial,
  disables rearming for that child, and remains sticky. `always` returns a
  required failure after safe resume/owner cleanup, then the owned-child guard
  terminates and reaps the command. Lifecycle failure is never rendered partial.
- [ ] `pause_confirmed + pause_partial == pause_attempts` for every normal
  result and the `none|sigstop|partial` lattice is exact.

Run REDs before implementation (the pure machinery remains private unit code;
Task 8 adds the external CLI/lifecycle tests):

```sh
cargo +1.88 test --locked --lib run::tests -- --nocapture
cargo +1.88 test --locked --lib discovery::pause::tests -- --nocapture
```

### Step 3: Implement one owner guard and one child guard

- [ ] `OwnedChild` owns barrier, process group, original `PidPin`, wait/reap,
  timeout, and forwarding. `PauseOwnerGuard` owns the accepted-stop obligation,
  authorization entry, exact records/keys, links, and resume/cleanup state.
- [ ] Mark `may_be_stopped` immediately when an accepted helper result is
  decoded, before any fallible operation.
- [ ] Cleanup is idempotent and non-short-circuiting. Signal handlers defer to
  the owner cleanup rather than re-entering it.
- [ ] Every terminal path — first/second SIGINT, SIGTERM, duration timeout,
  exec failure, child exit, cancellation, and guard drop — funnels through the
  same order before forwarding, killing, reaping, or deliberately releasing a
  still-running child: detach pause-capable links; bounded drain/decode;
  read/remove authorization; ledger-authorized accepted/protective original-
  pidfd resume. A second signal records escalation but cannot re-enter cleanup.
  Timeout escalation starts its fixed five-second grace only after process-
  group SIGTERM was actually forwarded. Duration without `--kill-on-timeout`
  returns observer success after safe detach and leaves the child running.
- [ ] The only `Some(OwnedPauseGeneration)` construction and caller is this
  owned-run path: its `attach.rs` crate-private constructor requires the
  private `OwnedChild`, binds the exact owned PID and generation, and cannot be
  reached from a `PidPin`-only or Task 5 path. No public constructor or raw
  token conversion exists.
- [ ] `Session` exposes crate-internal finite `arm_pause()` with no PID/token
  arguments, state read/remove, and discovery queue operations; it does not
  expose mutable `Ebpf`/map handles or own child policy.
- [ ] Insert successor `ARMED` only at the amendment's pre-resume boundary and
  remove it on resume failure/cancellation. A consumed successor before resume
  is lifecycle FAIL.
- [ ] The coordinator calls the Task 6 engine attachment method; it does not
  duplicate map parsing, scanning, pinning, planning, or link creation.

### Step 4: Verify and review

```sh
cargo +1.88 test --locked --lib run::tests
cargo +1.88 test --locked --lib discovery::pause::tests
cargo +1.88 test --locked --lib process
cargo +1.88 test --locked --test artifact_contracts
```

- [ ] Run all global gates and locked BPF/source guards.
- [ ] Independently review every early return, signal path, owner transition,
  map mutation, deadline read, drain closure, original-pidfd action, kill/reap,
  link detach, and counter update.

Commit message: `feat: coordinate owned-child live discovery pauses`

## Task 6E: Preserve capture history across live-resource retirement

**Purpose:** Correct the ownership boundary exposed by the short-lived Docker
diagnostic before any public Task 8 integration. Links, pins, process views,
loader contexts, and current topology must retire normally; accepted discovery,
allocated aggregate cells, successful static endpoints, exact attribution, and
semantic capture facts must survive for the capture lifetime.

**Evidence boundary (2026-08-24):** On the saved diagnostic, the first frame
records one provider, 68 slots, and 136/136 successful endpoints. After ordinary
workload exit, the final frame retains the expected calls but reports no
provider, zero endpoints, and one semantic reconciliation. Final JSON has
`table_entries=0` and unambiguous calls with `module=null`; the strict checker
rejects it. This is artifact evidence from an older source-bound run, not a
fresh runtime result for this task. The exact audit is saved privately as
`task-6-e-gap-audit.md`.

**Files:**

- Modify: `src/attach.rs`
- Modify: `src/plan.rs`
- Modify: `src/process.rs`
- Modify: `src/discovery/engine.rs`
- Modify: `src/discovery/pause.rs`
- Modify: `src/metrics.rs`
- Modify: `src/semantics.rs`
- Modify: `src/trace.rs`
- Modify focused owner/contract tests only as required

No public CLI, renderer, JSON/schema, privacy allowlist, BPF/common ABI, build
script, or dependency change belongs to Task 6E. If the final diff crosses one
of those boundaries, stop and re-evaluate its named downstream gates.

### Step 1: RED-test the active/history boundary

- [ ] Test `Session` records successful static endpoints as the lifetime set
  `(slot, return|entry)`. Selective/terminal detach and replacement do not erase
  or double-count it; a failed side remains absent and a genuinely new slot
  adds only its actual successes. Dynamic loader/export/lifecycle links never
  contribute.
- [ ] Test both ordinary and owned starts publish accepted history exactly once
  at their common successful return. A failure after static attach, loader arm,
  deferred retirement, or provisional candidate publishes nothing into a
  retry.
- [ ] Test unload-to-empty and exact reload restore one provider ID and one set
  of occurrences through the same `PinnedTimingKey`; a new exact identity,
  including a zero-slot or capacity-refused provider, receives a fresh
  non-reused ID.
- [ ] Test decoded occurrences are recorded before slot-capacity admission. A
  planner/history fixture with 513 exact decoded entries retains all 513, zero
  slots, and one whole-module refusal; an otherwise empty runtime capture keeps
  the existing fatal `refusal_error`. Module-free process/scope/object losses
  have their own exact deduplication key.
- [ ] Test same-provider refresh deduplicates entry/table/surface/skip facts;
  distinct providers accumulate. Manifest ordinals/source occurrences remain
  distinct. Later exact collision invalidation cannot resurrect an earlier
  corroboration or manifest-fallback proof.
- [ ] Test pre-mutation candidate refusal imports no positive provider facts or
  endpoints. A fully reconciled rejected co-owner still latches conservative
  ambiguity on an existing aggregate cell. A post-mutation generation failure
  retains actual slot/endpoint facts but no unaccepted provider owner.
- [ ] Distinguish identity-accepted decoded facts refused only by attach-slot
  capacity from identity/preflight/provisional candidate refusal. The first
  contributes decoded occurrence/refusal history but no public accepted module;
  the second contributes no positive history.
- [ ] Test partial target retirement cannot make current diagnostics dereference
  a retired pin. Current diagnostics use active slots; capture facts own the
  detached retired identity.

### Step 2: Implement three owners, not a peer planner

- [ ] `Session` remains the sole live Aya/link owner and separately retains the
  successful static endpoint set. `attached_probes()` reports that lifetime
  evidence; live-link selection remains derived from `Session::links`.
- [ ] `AttachPlan` remains the sole topology/allocation owner. Keep monotonic
  allocated slots and add only the smallest aggregate-owner state needed to
  distinguish `unowned`, one stable `ModuleId`, and permanently ambiguous.
  Expose separate active-owner and aggregate/decode-owner accessors. Retired
  slots retain frozen decode metadata; a real descriptor/owner/ambiguity
  downgrade remains immediate and count-only. Do not duplicate this slot-owner
  ledger in Engine capture facts.
- [ ] Engine capture facts own a checked monotonic module allocator and a
  bijection between exact `PinnedTimingKey` and `ModuleId`. Resolve candidate
  provider IDs through it before final plan binding. The same exact identity
  reuses its ID after an empty interval; unequal rebinding is refused and
  recorded as loss. A zero-slot/capacity-refused provider ID is private
  deduplication state, not a positive public discovery module. Gaps in the
  private numeric sequence are allowed; reuse is not.
- [ ] Engine capture facts retain sanitized accepted module snapshots, exact
  decoded occurrence sets, module-free losses, and field-specific discovery
  outcomes. They translate accepted provider identities into owner deltas
  applied to `AttachPlan` but retain no peer slot-owner ledger. They are
  structurally unable to contain
  `File`, `PinnedObjects`, `ProcessView`, Aya/link IDs, loader contexts, pause
  keys, cookies, raw addresses, or unallowlisted provider bytes.
- [ ] Represent corroboration/fallback invalidation as a field-specific
  tombstone or final conservative outcome. A generic union must never restore a
  proof invalidated by a later exact identity collision.
- [ ] Positive topology and occurrence facts merge only from an accepted final
  candidate. Actual endpoint successes merge at the Session attach seam.
  Sticky counter/loss/ambiguity facts merge at an error-safe batch finalizer,
  including rejected and error returns, under field-specific rules rather than
  generic sum/max/append.
- [ ] Replace the ambiguous `committed` boundary with an explicit accepted,
  conservative-retirement, or refused disposition. Postcheck loss commits only
  cleaned active pins/modules/views and pruned corroboration/fallback proofs;
  it retains only real monotonic slot allocations/endpoints. Finish every
  fallible identity/planner translation before mutation; after mutation,
  require one complete non-short-circuiting cleanup path rather than a
  speculative full rollback.
- [ ] Stage capture-fact changes for the whole `start_session_with` attempt and
  publish them once only after success. Both ordinary and owned routes use this
  seam; failure restores both prior capture history and aggregate-owner
  publication while normal active cleanup still runs.

### Step 3: Correct deferred and process lifecycle ownership

- [ ] Deferred pause-owned discovery round-trips the dequeue clocks plus one
  terminal-drain authority containing the tombstoned loader owner and exact
  export snapshot. That authority covers every matching record in the complete
  coordinator-owned batch, not only its first deferred record. A second
  simultaneous authority is an invariant failure.
- [ ] A private batch result distinguishes unconsumed transfer from a batch
  whose dispatch began. Retry only an unconsumed batch; after consumption,
  continue cleanup from the Engine journal without dispatching it twice. Pass
  pause ownership explicitly so an ordinary deadline-less batch cannot trigger
  another pause deferral.
- [ ] Persist retirement intent in Engine before any fallible nested drain.
  Replace the boolean with `ExecRefresh`, `ExpectedRemoval`, and
  `GenerationLost`; merging is deterministic, with expected removal dominating
  exec and genuine loss dominating both. Clean cgroup membership departure is
  expected removal, not generation loss.
- [ ] Bind an exec/exit record to the retained process-view interval using its
  existing kernel monotonic `hook_ts_ns`, a userspace monotonic view-admission
  lower bound, and the existing `PidPin` generation check. A delayed record from
  an older numeric-PID generation cannot retire the current view. Store the
  selected `ProcessViewId`; never authorize later cleanup by a second PID lookup.
- [ ] `ExecRefresh` requires the original pin still current, retires old
  loader/module state, and refreshes that retained generation. An observed
  leader exit becomes `ExpectedRemoval` only for a timestamp-matched view and
  finalizes only after its original pin reports exited. Expected removal
  completes context/plan cleanup, removes its view and scan input, requests no
  numeric-PID refresh, and does not make named-PID capture fatal. Genuine
  revalidation, generation, transport,
  identity, read, state, context, and truncation failures remain sticky loss and
  `PARTIAL`.
- [ ] Cover direct ELF, shebang, exec-chain, duplicate exec, exec+exit in one
  batch, delayed old-generation exit/PID reuse, exit-before-pin-readiness,
  expected named exit, clean cgroup departure, retry after an unconsumed
  deferred error, consumed-batch idempotence, and real stale-generation loss.

### Step 4: Preserve semantic and trace history without weakening invalidation

- [ ] Metrics reads all allocated aggregate cells and uses the aggregate owner,
  including an inactive sole-owner cell. An inactive ambiguous/unowned cell
  stays unattributed. Active attachment decisions continue to use active
  topology only.
- [ ] `State` and `Tracer` retain frozen metadata for every allocated slot so an
  older event drained after discovery retirement still has the correct name,
  descriptor, and module owner. A slot is never reused, so no grace timer or
  second event queue is needed.
- [ ] Ordinary slot inactivity and process exit preserve capture-lifetime
  mechanism, template, login, session, and cgroup aggregates and add no state
  reconciliation. A changed descriptor, owner, or latched ambiguity purges all
  affected process state and non-module-dimensional aggregates; increment
  reconciliation exactly once only when data was actually invalidated.
- [ ] RED-test nonempty mechanism/session/template/login/cgroup aggregates plus
  a trailing event across expected exit with reconciliation zero; empty real
  invalidation with reconciliation zero; nonempty owner/descriptor/ambiguity
  invalidation before trace rendering; and inactive sole-owner metrics retaining
  exact attribution.
- [ ] Freeze Task 8's orchestration requirement: after discovery, synchronize
  State/Tracer immediately so descriptor, owner, and ambiguity invalidations
  take effect before another event can be interpreted, while unchanged retired
  slots keep their frozen decode metadata. Then drain already-queued call
  events and only afterward retire exited process state. Synthetic
  exit-before-finalization output must keep exact call attribution, while an
  invalidated slot must never emit a semantic trace line that cannot be
  retracted.

### Step 5: Verify and independently review

Run focused owner tests first, then:

```sh
cargo +1.88 test --locked --lib attach::tests
cargo +1.88 test --locked --lib plan::tests
cargo +1.88 test --locked --lib discovery::engine::tests
cargo +1.88 test --locked --lib discovery::pause::tests
cargo +1.88 test --locked --lib semantics::tests
cargo +1.88 test --locked --lib trace::tests
cargo +1.88 test --locked --lib metrics::tests
python3 scripts/check-capture-evidence.py --self-test
sh scripts/verify-canaries.sh --self-test
cargo +1.88 test --locked --test artifact_contracts
```

- [ ] Run all global gates and `git diff --check`; read back exact HEAD and
  clean status after the scoped commit.
- [ ] Run the existing live-discovery/object/checker self-tests and statically
  prove the diff changes no BPF/common ABI, dependency, schema, allowlist, CLI,
  or renderer.
- [ ] Independently review accepted-history transactionality, exact identity,
  PID-reuse resistance, deferred terminal authority, every error/retry path,
  semantic invalidation, privacy, and active-resource release.
- [ ] Do not run a container merely to close Task 6E. Its saved artifact remains
  the pre-fix negative oracle; Task 8 first proves the public synthetic
  active-to-empty projection, and Task 9 performs fresh source-bound runtime
  validation.

Commit message: `fix: retain capture facts across live retirement`

## Task 8: Integrate capture loops, CLI, evidence, privacy, and doctor

**Purpose:** Make live discovery and `run` usable while publishing only the
approved finite aggregate contract.

**Files:**

- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Modify: `src/events.rs`
- Modify: `src/metrics.rs`
- Modify: `src/semantics.rs`
- Modify: `src/trace.rs`
- Modify: `src/render.rs`
- Modify: `src/doctor.rs`
- Create: `tests/run_lifecycle.rs`
- Create: `tests/pause.rs`
- Modify: `docs/schema/observed-profile-v2.md`
- Modify: `docs/privacy/allowlist-v1.md`
- Modify: `scripts/check-capture-evidence.py`
- Modify: `scripts/verify-canaries.sh`
- Modify: `tests/artifact_contracts.rs`
- Add or modify focused CLI/render/doctor integration tests as needed

### Step 1: RED-test the public contract

- [ ] Add `RunArgs` with capture options, `--trace`, exact
  `--pause never|auto|always`, `--kill-on-timeout`, and `-- CMD ARGS...`.
  Reject scope flags under `run`, pause under other commands, an empty command,
  and unknown pause values. Omission equals `never`. This task starts only
  after reviewed Gate B PASS; before that point `auto|always` do not exist as
  accepted CLI behavior.
- [ ] Add the external owned-run lifecycle and pause acceptance tests here.
  They exercise the one narrow public high-level production facade used by the
  binary; low-level coordinator clocks, maps, drains, guards, and injected
  actions remain crate-private and are not exported for tests.
- [ ] Test profile/metrics/trace final evidence contains exactly:
  `attach_gap_ms`, `pause`, `pause_attempts`, `pause_confirmed`,
  `pause_partial`, optional run-only `child_still_running`, four discovery loss
  counters, and the always-present finite `loader_discovery` aggregate.
- [ ] Extend each function row with `module_unresolved`, true exactly when a
  real allocated aggregate cell has no accepted sole owner (for example an
  actual post-mutation endpoint followed by failed generation validation).
  `module`, `module_ambiguous`, and `module_unresolved` are an exact exclusive
  relation: nonnull/false/false, null/true/false, or null/false/true. Unresolved
  forces `PARTIAL`; it is not relabelled as two-module ambiguity.
- [ ] Add one synthetic active-to-empty lifecycle fixture for profile, metrics,
  trace, and final JSON. After ordinary exit it retains historical modules,
  exact table entries, surfaces/skips, allocated slots, successful endpoints,
  aggregate calls, and exact function-module references while active links and
  views are empty. It reports neither an exit-generated discovery loss nor a
  false state reconciliation.
- [ ] Freeze every `loader_discovery` key: strategies
  `debug_state_every_hit|dlopen_return|unavailable`; both timing groups
  `qualified_pre_constructor|known_pre_relocation|unproven|none`;
  `initial_set_capture.eligible|none`; plus `hits` and
  `state_read_failures`. Every value is u64 and every key is always present.
- [ ] Test every u64 domain, nullable gap, exact enum, required key, and owner
  relationship. No duplicate/derived counter and no raw internal identity.
- [ ] Test strategy/timing/capture counts deduplicate the exact internal process
  generation plus optional bound tuple once, while `hits` and state-read
  failures come only from their BPF counters and never received-record counts.
- [ ] Test `PARTIAL` is sticky for scan-only semantic authority, any unprotected
  live window, loss/truncation/read/state/context failure, loader fallback or
  unproven timing, pause partial, attach failure, identity ambiguity, changed
  provider, zero modules, or initial-set capture none.
- [ ] With the exact empty catalog, test debug-state timing is `unproven` and
  both `qualified_pre_constructor`/`known_pre_relocation` counts stay zero.
  `initial_set_capture.eligible` also stays zero and final output is `PARTIAL`,
  including after a fully protected observed window.
- [ ] Test a fully protected exact window removes only its corresponding live
  gap; it cannot erase another evidence gap.
- [ ] Test metrics and trace see slots added mid-capture; terminal detach occurs
  before final drain/snapshot and retains the existing honesty boundary for
  in-flight callbacks.
- [ ] Test doctor finite classifications, nonzero requested-lane refusal, and
  that no BPF program/link/map survives doctor exit.
- [ ] Freeze doctor rows for loader build `bound|unbound`, debug-state hook
  `available|unavailable`, per-load timing, loader-state live read, live export
  reads, memory scan, run initial-set capture, and pause default/arming. Ordinary
  output never prints the identity/proof behind a row.
- [ ] Test verifier, helper, ring, export-state/read, loader-state/context,
  identity, attachment, pause observation, timing arithmetic, resume, detach,
  cancellation, kill/reap, provenance, validator, timeout, and environment
  errors retain distinct finite internal/operator categories. Only the exact
  aggregate owners named by the schema share public counters.
- [ ] Extend checker/canary mutation suites before renderer changes. Inject raw
  loader/pause PID/TID/task set into every new aggregate/object location, plus
  loader/libc path/digest/build ID, addresses, pointers,
  cookie/context/delta/sentinel, signal record, interface-name bytes, marker,
  and observer-owned map values; positive controls must be detected first. The
  checker permits PID/TID only in the pre-existing ordinary call-event trace
  fields already named by the allowlist, never in loader/pause evidence.
- [ ] Extend the strict checker with active-to-empty positive evidence and
  mutations for missing history and an undeclared slot owner. Reject
  `module=null,module_ambiguous=false,module_unresolved=false`; an explicitly
  unowned post-mutation/loss cell is null/false/true and forces `PARTIAL`. Do
  not relax the checker to accept the saved broken Docker artifact.

### Step 2: Integrate one polling loop

- [ ] Keep one profile loop and one trace loop. Each tick drains discovery,
  lets `Engine` extend `AttachPlan` and apply attachment deltas, synchronizes
  immediate semantic/trace invalidations while preserving unchanged retired
  decode metadata, drains call events, retires exited process state, snapshots
  metrics/counters, and checks retained generations/objects.
- [ ] `pause=never` keeps the existing refresh cadence. An ARMED/active explicit
  pause delegates to the coordinator's 1 ms bounded loop and returns to the
  ordinary capture loop only after owner closure; it never sleeps through an
  accepted stop.
- [ ] If Aya borrowing prevents simultaneous ring readers, make each drain own
  its taken map handle. Do not add threads, channels, epoll, or an async runtime
  in this slice.
- [ ] Initial capture still uses `discover_plan`; move its accepted state into
  `Engine` rather than rescanning/reopening. Manifests stay repeatable exact
  operator inputs and retain Slice 1b-1 authority/fallback rules.
- [ ] `run` arms pre-exec loader context before releasing the child barrier when
  exact PT_INTERP binding is safe. Otherwise it proceeds with
  `initial_set_capture = none`, sticky `PARTIAL`, and the selected pause policy.
- [ ] Freeze the consumer map explicitly. Metrics and function attribution use
  capture aggregate owners; semantic attachment decisions use active topology;
  final evidence/discovery and module labels use sanitized capture facts;
  coordinator fields use only its finite aggregate owner. Discard loader/pause
  identities before constructing render types.
- [ ] The binary is a separate crate: expose one immutable public
  `Engine::capture_facts()` view containing only render-ready sanitized history
  and aggregate getters. Keep `PinnedTimingKey`, internal occurrence keys,
  files/pins/views, loader/pause identities, and mutable owner state private.
- [ ] Choose and test one live-heading policy so current topology cannot print
  “no modules discovered” beside retained historical calls. Every ordinary
  heading uses capture-lifetime provider facts; active topology is omitted
  unless a future explicitly labelled diagnostic adds it. The terminal frame
  and JSON use the same capture facts.
- [ ] A named target's expected exit triggers normal final drain/finalization
  and observer success even without interrupt/duration expiry. A cgroup capture
  continues when one member exits and stops only by its normal capture policy.

### Step 3: Update schema, allowlist, checker, and canaries together

- [ ] Document the exact fields/types/owners and completeness lattice in schema
  v2. Do not publish a new schema ID because v2 is still unpublished.
- [ ] State that modules, discovery, table entries, allocated slots, successful
  endpoints, and aggregate ownership are capture-lifetime accepted facts, not a
  claim that their links, pins, or process views remain active at render time.
- [ ] Document the exact `module_unresolved` relation separately from
  two-module ambiguity and add that one finite boolean to the allowlist/canary
  mutations. Publish no reason string, process identity, path, cookie, or
  internal owner key with it.
- [ ] Add only approved aggregate fields to the privacy allowlist. Preserve the
  prohibition on object-handle correlation and symbolic CKA values.
- [ ] Checker verifies exact key sets, u64 ranges, enum values, aggregate
  cardinalities, run-only field presence, and payload absence.
- [ ] Canary scans profile, metrics, trace, logs, private temp output, and every
  map owned by the exact observer map IDs. Keep existing sentinels and use
  structural field checks so the pre-existing allowlisted call-event trace
  PID/TID positions do not mask or falsely trigger new loader/pause identities.
- [ ] Keep public capability prose out of README/usage until Task 9 runtime and
  CI evidence pass. Schema and allowlist text in this task describe the exact
  emitted contract, not promotion status.
- [ ] Preserve the non-promotional status wording established after Task 7:
  internal loader/export and owned-run components exist, but public integration
  and runtime gates remain incomplete. Remove only the public-path “scan once”
  limit that Task 8 actually replaces; do not claim supported capability before
  Task 9 and exact-tip CI.

### Step 4: Verify and review

```sh
python3 scripts/check-capture-evidence.py --self-test
sh scripts/verify-canaries.sh --self-test
cargo +1.88 test --locked --lib cli
cargo +1.88 test --locked --lib render
cargo +1.88 test --locked --lib doctor
cargo +1.88 test --locked --test artifact_contracts
```

- [ ] Run all global gates, shell syntax checks, locked product BPF guards, and
  fresh behavioral fixtures.
- [ ] Independently review CLI refusal, loop ordering, dynamic synchronization,
  completeness, schema/checker exactness, privacy allowlist, canary coverage,
  doctor cleanup, and documentation claim boundaries.

Commit message: `feat: expose live discovery and owned run evidence`

## Task 9: Run product integration, provider, and kernel gates

**Purpose:** Prove the exact production candidate, not the isolated spike, on
real process/provider/container shapes and both supported kernel baselines.

**Files:**

- Modify: `scripts/verify-attach-e2e.sh`
- Modify: `scripts/verify-induced-gaps.sh`
- Modify: `scripts/verify-inspect-doctor.sh`
- Modify: `scripts/verify-discover-containers.sh`
- Modify: `scripts/verify-canaries.sh`
- Add: `scripts/verify-live-discovery-preflight.sh`
- Add: `scripts/check-live-discovery-evidence.py`
- Add: `tests/fixtures/live-discovery-provider.c`
- Add: `tests/fixtures/live-discovery-driver.c`
- Modify as required: `scripts/matrix/*.sh`, `scripts/lib.sh`,
  `scripts/attach-pod.sh`, `scripts/gates.sh`, `scripts/build-release.sh`,
  `scripts/bench-overhead.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/artifact_contracts.rs`
- Update notes only after observed results

### Step 1: Add self-testing gates before privileged execution

- [ ] Build deterministic fixture lanes for provider present at start, provider
  loaded later by `dlopen`, exported tables, hidden tables, two providers,
  shared exact target, raw-key/full-identity collision, child exec failure,
  ring/state/read/truncation loss, pause partial, and zero modules.
- [ ] Build the production fixtures independently from the historical research
  binary. One provider source compiles with
  `P11SCOPE_EXPORT_TABLES=1|0` into reviewed exported/hidden bytes; each byte
  identity is used unchanged by a DT_NEEDED driver and a `dlopen` driver and
  implements all three standard return ABIs with per-surface
  constructor/application markers. The
  source may adapt the already-reviewed research behavior, but no old binary or
  campaign row is reused. Freeze compiler/linker identity and exact commands,
  including `-std=c11 -O2 -Wall -Wextra -Werror -fPIC`, shared-library
  `-Wl,-z,defs`, and driver `-ldl -pthread`, then hash sources and outputs into
  the execution manifest.
- [ ] Each script gets syntax and nonprivileged `--self-test` mutations for its
  exact validator. A mutation must fail for every claimed oracle field.
- [ ] Freeze the production map/program/ABI/helper inventory and apply the
  112-store/no-busy-wait guards to the exact release BPF object.
- [ ] Freeze a production lifecycle validator distinct from the A/B spike's
  four-map oracle.
- [ ] `scripts/verify-live-discovery-preflight.sh` builds the exact product
  object and drives the same frozen preflight on Jammy and Noble. Its canonical
  PASS requires: every production program accepted; all 256 context IDs and
  the absent/present/signed-delta cookie boundaries; zero-cookie and Aya
  no-cookie short-circuit before registry/IP/state work; exact function-IP and
  x86-64 fallback arithmetic; PT_INTERP/load-bias and `r_state +24`; lifecycle
  tombstone/drain; privacy; and distinct capacity, stale, generation, identity,
  and state-read outcomes.
- [ ] The exact unprivileged and evidence commands are frozen before the first
  privileged run:

```sh
python3 scripts/check-live-discovery-object.py \
  --source "$BPF_SOURCE" \
  --object "$BPF_OBJECT" --manifest "$BPF_INVENTORY"
python3 scripts/check-live-discovery-evidence.py --self-test
bash scripts/verify-live-discovery-preflight.sh --self-test
python3 scripts/check-live-discovery-evidence.py \
  --campaign "$CAMPAIGN_ROOT" --manifest "$EXECUTION_MANIFEST"
```

  The Python validator owns finite lifecycle/campaign semantics; the shell
  owns environment setup and cleanup only.
- [ ] The freeze step creates one new mode-0700 `PRIVATE_ROOT` and defines the
  command inputs before use. `BPF_SOURCE` is the canonical
  `realpath crates/ebpf/src/main.rs` from the exact clean candidate and is
  hashed/rechecked by the execution manifest; the generated inputs are exact
  files under the private root:
  `BPF_OBJECT=$PRIVATE_ROOT/frozen/p11scope-ebpf`,
  `BPF_INVENTORY=$PRIVATE_ROOT/frozen/bpf-inventory.json`,
  `CAMPAIGN_ROOT=$PRIVATE_ROOT/campaign`, and
  `EXECUTION_MANIFEST=$PRIVATE_ROOT/execution-manifest.json`. No script searches
  for or guesses an input path.
- [ ] Before the first non-self-test runtime attempt, freeze one execution
  manifest containing the exact `BPF_SOURCE`, product BPF, runner, validators, caps,
  deadlines, cold-boot/container topology, kernel/base identities,
  `initial_set`/DT_NEEDED and `dlopen` load kinds, exported/hidden provider
  bytes, exact interpreter/loader/companion-libc identities and digests,
  debug-state/export hook symbol identities and pinned file offsets, their
  source/tool provenance, and separate constructor/application markers plus
  target sets for
  `C_GetFunctionList`, `C_GetInterfaceList`, and `C_GetInterface`. No row,
  fixture, validator, or manifest is replaced after execution begins.
- [ ] Apply the recorded 2026-08-24 standing approval to this exact worktree's
  named root/container lanes after the unprivileged review checkpoint. Ask only
  for a materially new external VM/target. An unapproved required lane is
  `UNRUN` and blocks Slice completion.

### Step 2: Exercise real providers and deployment shapes

- [ ] SoftHSM2 direct: initial scan and a late `dlopen` under `run --pause never`
  and, when Task 2 passed, `auto` and `always`; exact aggregate counts and honest
  first-window protection status while empty-catalog completeness stays
  `PARTIAL`.
- [ ] p11-kit proxy + SoftHSM2 backend: both modules discovered/attributed,
  shared targets attached once, semantic ambiguity purged, within 512 slots.
- [ ] Existing deterministic fixture providers cover 2.00/2.40/3.0/3.2,
  alternate/null names, aliases, lazy dependency, hidden/exported tables.
- [ ] Ptrace-denied non-descendant target: scan unavailable, loader/export BPF
  path still produces bounded live discovery and `PARTIAL` rather than zero
  findings or fatal scan failure.
- [ ] Docker and kind: discover providers in container mount/process views
  without copying them out; validate host/container identity handling. Keep the
  short-lived Docker ordering in which the workload exits before observer
  finalization. Its required final evidence is 68 decoded entries, 68 allocated
  slots, 136 successful static endpoints, one retained provider, exact call
  attribution, `C_GenerateRandom=100`, `C_Digest=50`, `C_DigestInit=50`,
  `C_CloseSession=10`, `C_OpenSession=10`, `C_GetInfo=3`, and one each of
  `C_Finalize`, `C_GetFunctionList`, `C_GetSlotList`, and `C_Initialize`; no
  retirement-generated skips; and `state_reconciliations=0`. Before final
  projection the exited workload has zero active slots/links/views/loader
  contexts/pins; after observer exit no observer BPF resource remains. The
  strict clean-metrics checker passes. Extending workload lifetime does not
  satisfy this regression.
- [ ] Shared-layer, fork/cgroup, oracle, Knative, induced-gap, privacy canary,
  release-build, and overhead lanes retain existing oracles and cleanup.
- [ ] Knative's retained preattached-provider evidence remains the measured
  `136/136`/expected-cold-pod capture. The exact reproduced node-wide
  retained-view late-provider topology is an expected `UNSUPPORTED/NON-PASS`
  negative control with one overlay plus one unavailable; do not translate that
  result into a PASS or widen the checker oracle.
- [ ] Benchmark `run --pause never` separately from explicit `auto`; report the
  explicit-pause 1 ms userspace polling cost rather than folding it into normal
  capture overhead or adding epoll speculatively.
- [ ] CI builds the exact production BPF object and runs the unprivileged plus
  hosted SoftHSM live-discovery lane. Hosted-kernel success is useful evidence,
  not a substitute for the frozen 5.15/6.8 campaign. An actual required
  workflow run must be observed green before Slice completion; local success
  cannot relabel CI pending.
- [ ] Kryoptic/NSS/other provider expansion is post-Slice 1b-2 unless already
  locally available with no new dependency or oracle ambiguity. It cannot
  replace the mandatory SoftHSM/proxy/fixture matrix.

### Step 3: Run exact production kernel controls

- [ ] Fresh Jammy 5.15 and Noble 6.8 overlays, same frozen production source,
  BPF, runner, fixtures, schema, checker, caps, and oracle.
- [ ] Both kernels load every production program and verify the complete
  production map/program/helper inventory. Run initial, late exported, late
  hidden, no-cookie, invalid-cookie, registry-capacity, scan-denied, loss, and
  lifecycle controls declared before the first boot.
- [ ] On each retained glibc 2.35, glibc 2.39, glibc 2.41+, and Alpine/musl
  fixture, bind the exact interpreter/loader/libc identities, exercise the
  every-hit hook and all supported exact export-return attachments, and retain
  the timing classification only as a diagnostic. Also retain `dlopen_return`
  fallback effects without promoting package/version names or a timing catalog.
- [ ] Run the D3 amendment's exact production attach-first campaign:
  initial-set/dlopen x exported/hidden x public `never|auto|always` x 20
  children x two kernels = 480 primary attempts, plus 20 forced
  `dlopen_return` fallback attempts per kernel. Every child exercises all three
  standard return ABIs with predeclared per-surface markers. `never` rows
  require no owner/signal, eventual bounded attachment where available,
  initial-set capture none, and `PARTIAL`. `auto` rows require exact safe
  closure for every observed window. Sticky partial with rearming disabled is
  valid runtime failure handling but makes that primary campaign row non-PASS.
  `always` rows require the same closure and command failure after safe cleanup
  for any missed window. Mixed, missing, timed-out, replaced, lifecycle-failed,
  privacy-failed, or unclassified rows are campaign non-PASS. Add no private
  pause-count switch to the product runner. Every successful `auto|always` row
  still requires timing `unproven`, initial-set capture none, and final
  `PARTIAL`; attach-first success does not upgrade them.
- [ ] Exercise forced `dlopen_return` only when the exact pinned debug-state
  hook is absent, unresolved, or unsafe and an exact pinned companion libc
  supplies the reviewed fallback offset. Each row proves only the explicit
  post-return call, no constructor or DT_NEEDED coverage, timing none,
  initial-set capture none, and `PARTIAL`. Any other activation or a row
  failure is required-lane non-PASS and authorizes no fallback.
- [ ] When Task 2 passed, product Outcome A/B pause integration must satisfy the
  amendment on both kernels. The isolated six-lane Task 2 campaign remains the
  repeatability authority; product lanes prove integration only.
- [ ] All overlays, listeners, NBDs, children, stopped owners, links, and maps
  are quiesced. Retained bases and frozen bundles remain byte-identical.

### Step 4: Review the complete evidence

- [ ] Independently recompute every canonical hash, inventory, record count,
  provider oracle, completeness decision, privacy scan, lifecycle result, and
  negative classification from raw bounded evidence.
- [ ] A failed or unavailable optional provider is not hidden; a required
  SoftHSM/proxy/fixture/kernel/product lane is campaign non-PASS.
- [ ] Record the exact Knative late-provider negative-control disposition. The
  reproduced one-overlay/one-unavailable shape is the expected
  `UNSUPPORTED/NON-PASS` result and does not stop otherwise applicable lanes;
  any different public shape, additional gap, or lifecycle/input/cleanup
  failure stops the campaign.
- [ ] Confirm the historical Task 8 160/160 attach-first artifact remains
  diagnostic/non-promotable with zero attempts in this campaign.
- [ ] Run a security diff review of the whole Slice 1b-2 range, focusing BPF
  memory bounds, attach cookies, mutable maps, process identity, pidfd signal
  authority, `/proc` namespace paths, public privacy, cleanup, and fail-closed
  error classification.

Commit message for reviewed gate/script changes: `test: gate slice 1b-2 live discovery`

## Task 10: Final multi-artifact closeout and local integration

**Purpose:** Prove every contract against the exact final tree and merge only a
fully reviewed Slice 1b-2 result locally.

**Files:**

- Modify: `docs/superpowers/plans/ROADMAP.md`
- Modify: `docs/notes/slice1b2/README.md`
- Modify: `docs/notes/slice1b2-open-issues-and-consequences.md`
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `docs/usage.md`
- Modify: `tests/artifact_contracts.rs`
- Modify only other factual operator docs needed by final evidence

### Step 1: Freeze the final dependency graph

- [ ] Record exact source/tree, toolchain, BPF/runner/fixture/checker/schema,
  map/program/ABI, cap/deadline/oracle, kernel/userland, and campaign hashes for
  isolated A/B, retained diagnostic C inputs, D3 attach-first, and production
  nodes. Dormant catalog lanes are not fabricated as a required node.
- [ ] Verify every dependency edge. A changed shared source/ABI reruns every
  naming node; a schema-only change reruns schema/privacy/product integration,
  not unrelated spike verifier lanes.
- [ ] Preserve negative and historical evidence with its original disposition.
  Do not relabel feasibility PASS as promotion evidence.

### Step 2: Requirement-by-requirement completion audit

- [ ] Audit every numbered requirement in the corrective design, pause
  amendment, and accepted D3 amendment against exact
  source, tests, raw campaign artifacts, validators, and public docs.
- [ ] Classify each as proved, contradicted, incomplete, weak/indirect, or
  missing. Continue work for every non-proved required item.
- [ ] Confirm Slice 1b-1 manifest authority, privacy allowlist, capture budgets,
  process/object identities, and existing provider matrices did not regress.
- [ ] Confirm no generated output, private evidence, raw identifier, or unrelated
  main-worktree file is tracked.
- [ ] Confirm the required CI workflow was actually observed green on the exact
  final branch tip including the documentation/artifact-contract commit. Any
  later change reruns CI. If push/workflow authority is unavailable, leave
  Slice 1b-2 and ROADMAP completion pending; local integration alone is not
  completion.

### Step 3: Fresh final verification

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
python3 scripts/check-capture-evidence.py --self-test
sh scripts/verify-canaries.sh --self-test
git diff --check
```

- [ ] Re-run every final required local gate whose named dependency changed.
- [ ] Obtain independent correctness, lifecycle/evidence, privacy/security, and
  minimality reviews of the exact final range. Resolve all findings by TDD and
  rerun affected gates.
- [ ] Update ROADMAP/notes only with observed exact outcomes. Required CI must
  be observed green; release, publish, and security-clearance remain pending
  unless separately observed.
- [ ] Only after Task 9 runtime gates and its candidate CI pass, update
  README/usage with factual
  capability boundaries: no manifest is required for bounded live discovery;
  late `dlopen` is observed through supported hooks in supported measured
  topologies; full late-provider discovery in the reproduced Knative node-wide
  retained-view topology remains explicitly unsupported; all empty-catalog captures
  remain `PARTIAL`; external PID/cgroup windows are unpaused; owned `run` pause
  is explicit; only the owned child generation is followed; arbitrary
  descendants/nonstandard providers are not guaranteed; and observer SIGKILL
  during an accepted stop plus third-party stop interaction remain residuals.
- [ ] After independent review and all local checks pass, commit the final
  documentation/artifact-contract changes, then observe required CI green on
  that exact branch tip. Do not change the candidate after the green run; any
  required fix repeats review, commit, affected local gates, and CI.

### Step 4: Integrate locally

- [ ] Use `superpowers:finishing-a-development-branch` to compare the reviewed
  branch with local main, preserve unrelated/untracked user work, and merge the
  exact reviewed commits locally without pushing, tagging, packaging, or
  publishing.
- [ ] Re-run the four AGENTS gates and status/diff checks on merged main.
- [ ] Keep the broader persistent development goal active for later slices;
  Slice 1b-2 completion is not the end of product development.

Final documentation commit: `docs: close slice 1b-2 live discovery`

## Effort and critical-path estimate

| Work | Expected focused effort | Expected elapsed time |
| --- | ---: | ---: |
| Plan review/fix/commit | 4–8 h | < 1 working day |
| Correct A/B candidate + review | 1–2 days | 1–3 days |
| A/B VM campaign + review | 4–8 h hands-on | 8–20 h elapsed |
| Descriptor + dynamic slot migration | 1–2 days | 1–3 days |
| Product BPF + loader/engine | 2–4 days | 3–6 days |
| `run`/pause + public contract | 2–3 days | 2–5 days |
| Provider/kernel/final reviews | 2–4 days | 3–7 days |

Nominal critical path is 7–12 focused working days. Verifier, lifecycle, or
cross-kernel corrective rounds can make the realistic calendar range 2–3
weeks. These are planning ranges, not permission to skip a failed gate.

## Plan self-review checklist

- [ ] Every binding requirement maps to one task, test, campaign, and owner.
- [ ] Amendment supersedes historical pause behavior everywhere.
- [ ] No speculative dependency, trait, async runtime, generic resolver,
  external-target pause, new public identity, or timing catalog was added.
- [ ] Scan/pin/reconcile/manifest authority has one implementation.
- [ ] Dynamic policy uses frozen descriptors and mutable data indices only.
- [ ] Exact identity collisions cannot remap already attached state silently.
- [ ] Gate A/B, loader/context preflight, and production artifacts have
  distinct inventories and validators; historical Gate C remains dormant and
  contributes no product gate.
- [ ] Privileged/runtime gates occur only after source review and exact freeze.
- [ ] Public schema, allowlist, checker, and canaries change atomically.
- [ ] Historical evidence remains truthful and non-promotable.
- [ ] Final completion requires exact evidence, not absence of failing tests.
