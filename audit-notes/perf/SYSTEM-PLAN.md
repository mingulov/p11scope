<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System coverage and performance delivery plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development or superpowers:executing-plans to
> implement the selected package task-by-task. Steps use checkboxes.

**Status:** proposed design and staged delivery plan, 2026-09-21. Production
baseline is `feat/system-scale` at `885ed65`. This review changes documentation;
no proposed product behavior below is implemented by it. The user authorized
privileged/live BPF tests and subagent-driven execution for suitable work.

**Goal:** increase the PKCS#11 activity that `--system` can observe, preserve
already established coverage under churn and resource pressure, and make the
remaining gaps measurable without widening the privacy boundary.

**Architecture:** separate candidate exploration, stable physical ownership,
admission, capture and reduction. Use broad attachment for validated stable
file-backed endpoints within a measured capacity, supplemented by passive
publication for runtime tables and forwarded targets. Keep semantic authority
independent from discovery confidence and preserve per-endpoint history.

**Tech stack:** Rust 1.88, Linux eBPF/Aya with the repository's pinned patches,
native task storage, existing C fixtures and Python evidence oracles.

**Spec inputs:** this document's requirements and decisions;
[current review](../FINDINGS.md), [performance review](REPORT.md),
[experiment specifications](SYSTEM-EXPERIMENTS.md), and
`docs/superpowers/plans/2026-09-19-system-scale.md` plus its ledger. The older
plan's checked/unchecked boxes are not a fresh implementation status oracle.

## Global constraints

- Keep Rust 1.88, edition 2024, and Linux x86-64-first support.
- Preserve `docs/privacy/allowlist-v1.md`; never broaden capture implicitly.
- Keep exact pinned object/offset/ABI identity; equal names or hashes do not
  authorize merging distinct physical observations.
- Preserve default allowlisted/count-only behavior. No provider execution by
  the observer, arbitrary heap search, secret capture or raw-pointer output.
- Retain supported-kernel singles fallback and exact multi-group lifecycle.
- Every resource refusal and unproven interval remains explicit evidence.
- Generated logs, profiles, binaries and VM overlays remain outside Git.
- Preserve unrelated work, use disjoint writer ownership, one Cargo-heavy
  command per shared target directory and one privileged measurement lane.

## High-level roadmap: reliable system capture

This is the main plan for the requested multi-user, multi-provider system
work. Read this overview for priorities; use Packages A–H below for delivery
ownership and [SYSTEM-EXPERIMENTS.md](SYSTEM-EXPERIMENTS.md) for test details.
The stages are proposed work, not completed fixes. The reviewed production
baseline still misses the controlled system workload.

**Target outcome:** one privileged `--system` observer covers supported
PKCS#11 calls across multiple OS users and processes, including several
providers in one process and the same provider loaded independently in many
processes. It keeps correct ownership during process/provider churn and
reports any permission, unsupported-shape, capacity or timing gap explicitly.
Provider filters may narrow an operator's request; they are not needed to
make the system acceptance tests pass.

| Order | What improves | Gate before claiming the improvement | Delivery |
|---|---|---|---|
| 1 | Safe capture and trustworthy measurements: fix F-01/F-11, then doctor, evidence validation and benchmark boundaries | Owned targets survive supported safety cases; stdout behavior is preserved; intentionally missed calls fail coverage acceptance | A; E01–E03 plus E17/E23 safety subsets |
| 2 | Reliable coverage and ownership across users/processes: prevent scan-cap starvation, preserve valid providers after incomplete rescans, fix repeat accounting and isolate async state | The small multi-user/provider matrix below is covered within a stated discovery bound; late arrivals are reached; identical handles/IDs never cause collision-induced cross-owner attribution | B/C and early E0; E05–E07/E09/E14/E20 |
| 3 | Faster startup and continuous draining: reduce repeated history/plan rebuilding and retain one EVENTS consumer | Separate before/after measurements show lower cost with identical coverage, loss accounting and cleanup | B performance patch/D; E25/E04 |
| 4 | Broader provider support: normalize supported factory forms, heap tables, forwarded targets and default interface requests | Equivalent supported publications yield the same physical endpoint set; first-call gaps and unsupported surfaces remain measured | F; E08/E13/E15/E16 |
| 5 | Practical capacity and long captures: design the whole resource budget and admission behavior, including history and in-flight calls | Shared files, copied files and many providers fit the published envelope; overflow is explicit; serial churn does not silently consume the whole capture lifetime | G with E; E05/E10–E12/E18/E20 |
| 6 | Lower steady-state overhead: optimize measured allocations, map snapshots, session scans and fork work | Exact results and ownership survive load; observer cost and target slowdown improve beyond measurement noise | E; E17–E20 |
| 7 | Recurring system qualification and usable operator evidence | Exact-build host/VM, backend, ABI, privacy, failure-injection and soak results support a published operating envelope | H; E12/E14–E17/E21–E24 |

The first deliverable is a safe, measurable small system workload, then
reliable discovery and coverage at that size. Capacity is increased against
the same truth ledger. Stages 3–6 can overlap only after their correctness
dependencies pass and shared source files have one writer. Keep the
individual startup, draining and capacity results independently reviewable.

### Required multi-user and provider matrix

Start with two owned test UIDs, two processes per UID and two distinguishable
fixture providers at a low call rate. Add background provider-free processes
to exercise exploration fairly. Use fresh VM/fixture credentials and private
artifacts; do not modify or borrow unrelated users' workloads. Grow one axis
at a time after this small matrix passes.

| Scenario | Required behavior | Experiments |
|---|---|---|
| Different users/processes map the same provider inode | Reuse validated physical attachment where possible; count every process's calls without duplicate probes or unproven cross-process state joins | E05/E12/E20 |
| Equal provider bytes are copied to different inodes or installed at different paths/versions | Preserve independently validated physical objects; filename, function name or hash equality alone cannot collapse observations | E05/E14 |
| One process loads several providers or repeated loader instances | Preserve module/instance ownership even when session/async identifiers are numerically equal; ambiguous semantics remain count-only | E08/E14/E20 |
| Different users/processes deliberately reuse identical session handles and async IDs | No collision lets an operation, login, async join, close or finalize consume an independent owner's state; permit separately validated intentional custody transfers; foreign traffic cannot satisfy another workload's oracle | E12/E20 |
| A provider appears after capture starts or after exploration capacity is occupied | Reach it within the documented discovery bound; keep already validated providers covered through incomplete scans | E06/E07/E09/E13 |
| A process exits, execs, changes credentials/cgroups, or unmaps a provider while others continue | Retire only invalidated ownership; shared live endpoints remain covered and reused PIDs/addresses do not inherit old state | E10/E12/E14 |
| Mount/PID namespaces, restricted procfs, privilege differences or device-group access affect visibility | Observe the supported accessible target or report the precise coverage limitation; never turn unreadable memory into authoritative absence | E05/E14/E15/E23 |

**Identity rule:** attachment identity and application-state identity serve
different purposes. Stable physical endpoints may share probe work; process
generation, executable instance, module and invocation ownership must remain
distinct for correlation. Provider publication/occupancy can differ in two
processes mapping the same file. Validate process and provider isolation with
deliberate handle collisions, not just distinct happy-path identifiers.
E20 must distinguish independent equal-ID collisions from proven intentional
cross-process custody transfers; neither rejecting all such transfers nor
accepting all numerically matching IDs satisfies this contract.

For the initial milestones, multi-user support means correct capture across
OS users. The current privacy contract keeps raw PID/TID internal in
metrics/profile and exposes them only in bounded trace. UID/username reports
are not assumed by this plan; any new public identity fields require a
separate schema/privacy decision. Test oracles may retain private ownership
receipts to verify aggregate output without widening product output.

### Where every audit item goes

This routes all F-01–F-75 and O-1–O-18 items; it does not convert historical,
accepted or refuted claims into bugs. Recheck each candidate on the selected
implementation revision, record its reproduction/control, then fix, retain
as a tested boundary, or close it with evidence. Split compound findings
such as F-58 into independently verifiable tasks before assigning a writer.

| Workstream | Findings/opportunities | Order and treatment |
|---|---|---|
| Safety, interference and output ownership | F-01, F-11, F-25, F-48, F-53, F-55–F-58, F-69 | F-01/F-11 first in A. Recheck the others before broader qualification; accepted structural risks need an explicit design decision, not an automatic rewrite |
| Evidence, contracts and operator usability | F-02, F-08, F-09, F-12, F-13, F-20–F-22, F-42, F-45, F-47, F-49, F-50, F-59, F-60, F-64, F-68, F-74 | A/H: repair test-oracle blockers early, prove settlement before changing terminal completeness, then schema/CLI/runbook polish |
| Discovery, identity and provider coverage | F-14, F-23, F-24, F-26, F-34, F-35, F-67, F-70–F-73, F-75 | B/C/F/G and early E0, with H regression gates; preserve mitigations and distinguish unsupported shapes from exploitable bugs |
| Performance and resource behavior | F-17, F-29, F-37, F-61; O-1–O-14, O-16–O-18 | B/D/E/G: measured startup/drain costs first, then active/lifetime budgets and reducer work. O-7 is diagnostic-only; O-8/O-9/O-12 need fresh test-harness comparisons |
| Security tests, dependencies and release qualification | F-03–F-05, F-10, F-27, F-28, F-31–F-33, F-40, F-41, F-43, F-46, F-54, F-62, F-63 | A/H support track: align shipped dependency tests, run owned hostile/parser/privacy cases and make relevant gates recurring; investigate helper isolation separately from the non-executing observer |
| API and maintainability | F-06, F-07, F-15, F-18, F-19, F-30, F-36, F-39, F-44, F-51, F-52, F-65, F-66 | Separate small owned patches after current-path validation. Resolve lifecycle/API defects that affect the selected use case; defer broad module/parser rewrites until they have a concrete need |
| Corrected or non-finding claims | F-16, F-38; O-15; R-01–R-06 | Preserve regression controls and current dispositions. Do not implement the refuted per-call optimization or treat catalog equality as runtime conformance |

The primary owns this routing and promotes an item when new evidence changes
its impact. Each supporting task needs exact files, an acceptance check and
a stopped previous writer before implementation. Low-impact cleanup may run
alongside the roadmap; confirmed target harm, cross-owner attribution or
privacy violations stop the affected qualification path immediately.

## Requirements and design choices

R1. **Breadth:** a finite fair exploration policy must eventually examine each
eligible process while retaining authoritative ownership of admitted providers.
The scan cap must not become permanent exclusion by first arrival.

R2. **Continuity:** an incomplete scan is not proof that a provider disappeared.
Retain an old target only while its own process/image/mapping/file identity
remains valid; genuine invalidation still retires it immediately.

R3. **Publication:** equivalent supported factory forms must share a validated
count-only admission contract. Keep request classification, publication
evidence, physical endpoint ownership and semantic authorization distinct.

R4. **Capacity:** define separate limits for discovered tables/interfaces,
active and historical endpoints, in-flight calls, RV keys, processes, semantic
state, attempted I/O, CPU work, rings, links and FDs. Publish a measured
operating envelope rather than conceal pressure using provider filters.

R5. **Accuracy:** use an independent invocation denominator; distinguish
entry/return aggregation, event transport, semantic reduction and output.
Terminal PARTIAL cannot be removed until producer quiescence and settlement
are proven. It is useful to expose dimensions even when the overall verdict
remains conservative.

R6. **Interference:** bound observer memory, discovery work, reducer work and
output backpressure; avoid changing inherited stdout flags or leaving owned
children stopped. Measure target overhead independently from observer cost.

R7. **Compatibility and safety:** qualify ABI, loader, backend, kernel,
seccomp and privacy boundaries on actual fixtures; historical green lanes do
not qualify the next commit.

R8. **Multiple users and provider instances:** preserve exact coverage and
correlation across OS users, process/image generations and module instances,
including shared file mappings and equal numeric handles/async IDs. Reusing
physical attachment must not reuse another owner's semantic state. Unreadable
or ambiguous instances produce a bounded named gap under the privacy policy.

| Approach | Benefits | Coverage/cost trade-off | Decision |
|---|---|---|---|
| Keep selected admission at 512 and optimize only consumers | Small change; bounded resources | Does not fix the observed system miss or pre-published/dormant target gaps | Interim behavior only |
| Broadly attach every structural candidate | Best chance of catching dormant first calls | Untrusted structural lookalikes are not authoritative; current capacity, startup and teardown costs are unacceptable | Reject as an unconditional default |
| Broader validated file-backed attachment plus passive runtime publication | Preserves physical observations and reaches more provider shapes | Needs fair admission, complete capacity design, lifecycle proof and measured operating limits | Recommended staged direction |

Build-specific provider adapters may improve confidence or cost, but are
optional and exactly identified. A p11-kit fixture adapter is not the generic
system solution. Unknown layouts still need a safe generic path or a named gap.

## Review focus

1. Unknown wide-scope kernel safety must not silently proceed; output setup
   must not change a target's inherited stdout behavior (Package A, E23/E17
   safety subsets).
2. Lost/truncated scan output must not be mistaken for authoritative absence
   (Package B, E07).
3. A new unique provider after the process cap fills must be reached within
   a documented exploration bound (Package C, E06).
4. Heap/default-name/forwarded `C_GetInterface` results must preserve exact
   ownership and count-only authorization (Package F, E08).
5. Delayed events and nested calls must not use reclaimed identities or new
   semantic descriptors (Packages D/G, E10/E12).
6. A slow or closed consumer must preserve loss/cancellation accounting and
   the target's stdout behavior (Packages A/D/E, E17).

## Package A — Close safety gaps and repair trust signals

**Own:** `src/uretprobe_hazard.rs`, `src/sink.rs`, `src/run.rs`,
`src/doctor.rs`, `src/inspect.rs`, `src/cli.rs`,
`scripts/check-capture-evidence.py`, `scripts/system-scope-measure.py`,
its dedicated tests, `.github/workflows/ci.yml`, relevant usage/schema docs.
Split these into disjoint small patches where useful; do not mix product
fixes into the measurement change.

**Consumes:** actual kernel safety verdicts, target/output ownership, current
CLI/check rows, producer reason vocabulary, capture timestamps and pinned
dependency recipe. **Produces:** safe refusal/interference contracts and a
trustworthy baseline, with regressions for F-01/F-03/F-09/F-11/F-13/F-20/F-74.

- [ ] First make F-01's Unknown + unspecified/unreadable-target case fail
  closed through the existing policy/override mechanism. Cover the complete
  verdict/target matrix; preserve explicit warnings when risk is overridden.
- [ ] Apply a consistent safety contract to owned `run` captures. Require
  positive kernel evidence where a child can install seccomp after attach;
  an initial unconfined `/proc` status alone cannot qualify that future state.
  Run E23's owned safety subset before wider system qualification.
- [ ] Reproduce F-11 with a backpressured pipe and an owned child sharing
  stdout (E17 subset). Prevent the observer from changing shared open-file
  status flags; a second `dup` cannot provide isolation. Preserve bounded
  cancellation and final sink-loss accounting in the selected output design.

- [ ] Add a test feeding an actual successful `bpf_checks_with` row into tier
  classification; observe failure for `(own libc)` versus `(self)`.
- [ ] Test the inspect soft-diagnosis branch separately from hard errors;
  implement the selected JSON failure representation and validate stdout.
- [ ] Add a producer-to-validator test for every allowed discovery reason,
  including physical-identity ambiguity; fix the vocabulary at both ends.
- [ ] Test 60 s setup plus 8 s post-attach capture, early PID exit and multiple
  diagnostic summaries. Use the actual monotonic boundaries; remove the
  unsupported `setup > duration` collapse inference.
- [ ] Match workload identity from its own mapping/pin receipt. Keep pathname
  labels for display only; mark unresolved matching unknown.
- [ ] Point standalone dependency tests at recipe-selected p2 trees and retain
  root workspace compilation and recipe hash verification.
- [ ] Run E01/E02/E03; record which assertions passed, failed or remain unknown.
  Commit only the reviewed package after fresh checks.

## Package B — Preserve coverage through incomplete scans

**Own:** `src/discovery/scan.rs`, `src/discovery/engine.rs`,
`src/discovery/engine_tests.rs`; planner tests if the result contract requires it.
**Consumes:** stable view/image/pin identity and scan budgets.
**Produces:** explicit scan completeness/invalidation decisions and correct
repeat accounting. This package exclusively owns engine.rs while it runs.

- [ ] Add E07's saturated-repeat regression before changing behavior: 512
  candidate tables, few endpoints, unchanged full rescan, no spurious retirement.
- [ ] Add E09's repeated-interface test and a process-generation/address-reuse
  countercontrol; keep attempted I/O/work charges independent from uniqueness.
- [ ] Represent bounded/incomplete results separately from verified absence
  at the scan-to-live-candidate boundary. Do not retain targets solely because
  a scanner ran out of budget; revalidate their existing physical identity.
- [ ] Allow repeat recognition under the cardinality cap without admitting
  new distinct entries beyond that cap.
- [ ] Verify genuine unmap, changed bytes, stale generation and unavailable
  identity still retire or refuse safely. Run E07/E09 and existing scan,
  publication, planner and lifecycle tests; obtain independent review.
- [ ] In a separate performance patch after that correctness gate, use E25
  to evaluate batching/incremental `CaptureFacts::merge_current` and plan
  rebuilds during loader arming. Preserve proof tombstones and transactional
  publication; compare exact results with the original path before accepting
  reduced copying or comparisons.

## Package C — Fair bounded system exploration

**Own after B:** `src/discovery/scheduler.rs`, `src/discovery/engine.rs`,
`src/discovery/engine_tests.rs`, `tests/system_scope.rs`.
**Consumes:** B's complete/incomplete distinction and retained ownership.
**Produces:** a finite exploration bound and explicit deferred-work accounting.

- [ ] Make E06 fail using two long-lived provider-free views plus a new
  unique provider; include shared-inode capture as a control.
- [ ] Separate exploratory view/cache retention from ownership needed by
  active providers. Rotate exploratory capacity without dropping authoritative
  pins/history or recycling an identity into old runtime-table evidence.
- [ ] Keep per-tick work/time bounds, cancellation and periodic reconciliation;
  measure actual deep scans and hooks, not merely `/proc/maps` visits.
- [ ] Run E05/E06/E14 at 256 and above-cap process counts. State the resulting
  bound in frames/time and its assumptions; never claim universal instantaneous
  discovery of arbitrary short-lived processes.
- [ ] Run the small multi-user/provider matrix with exact private workload
  identity before increasing endpoints. Cover shared-inode, copied-inode and
  restricted-procfs cases; require explicit discovery evidence for each cell.

## Package D — Retain the EVENTS consumer

**Own:** `src/events.rs`, `src/attach.rs`, `src/run.rs`, relevant drain tests.
**Consumes:** one Session, its owned EVENTS map and immutable EventsDomain.
**Produces:** one sequentially accessed consumer/cursor for the session.

- [ ] Add regression cases for malformed-then-valid quanta, cursor continuity,
  root-tail draining, cancellation and terminal backlog.
- [ ] Move an owned map-backed consumer into Session or a separate owner;
  avoid a self-referential borrow of Session's own Ebpf.
- [ ] Expose per-poll malformed deltas, since existing callers sum fresh-drain
  counters. Preserve domain checking and exclusive consumer access.
- [ ] Keep record-drop advancement, terminal bounds and detach ordering.
- [ ] Run E04 alone before allocation changes. Compare syscall counts,
  setup/steady CPU separately, loss and exact output. Review lifecycle changes
  independently before merging.

## Package E — Preserve semantic ownership, then reduce reducer/map work

**Own:** early E0 owns `src/semantics.rs` and `src/history_tests.rs` for the
isolation gate below. E's subsequent performance work follows D and owns
`src/semantics.rs`, `src/history.rs`, `src/trace.rs`, `src/metrics.rs`;
`src/run.rs` only after D's writer stops. E0 does not edit D's run/attach/event
files and must finish before another writer changes semantic key structures.
**Consumes:** stable event/metadata identity and correct delivery accounting.
**Produces:** a validated semantic isolation contract, followed by equivalent
reduction with fewer allocations/traversals.

**Early E0 — multi-process isolation, alongside B/C:**

- [ ] Reproduce F-75 with E20's same-EVENTS-domain, distinct-task-cookie
  pair using equal module/slot/async IDs and different pending mechanisms.
  Confirm the provider/standard namespace assumptions independently.
- [ ] Require independent ownership or conservative ambiguity refusal.
  Evaluate a bounded collision tombstone that refuses ambiguous joins;
  richer instance keys require proven provider identity. Keep valid supported
  cross-process transfers as a separate countercontrol; adding PID alone is
  not an acceptable substitute for that contract.
- [ ] Check cancellation, finalize, exit and late completion after collision.
  No wrong mechanism/state binding may be published even when PARTIAL is set.
  Obtain independent lifecycle review before semantic optimization begins.

**Subsequent performance work, after E0/D:**

- [ ] Use E19 to select the first measured hotspot. Preserve immutable
  pending SlotMeta snapshots; shared immutable metadata is safer than naked
  slot re-resolution if future recycling is planned.
- [ ] Replace repeated operation-name allocation and map lookups while keeping
  admission-before-insertion and stable output ordering.
- [ ] Group parent operations by session during fork; add visit-count scaling
  tests to supplement the existing `<2s` test (E20).
- [ ] Use E20's deliberate cross-process/cross-module handle and async-ID
  collisions before changing key/index structures. Check return pairing,
  close/finalize and delayed joins against each workload's own state ledger.
- [ ] Evaluate ordered-key range processing before adding session indexes;
  any eviction index must be bounded under overwrite/join/purge.
- [ ] Measure E18 before adopting batch map reads or changed frame snapshots;
  preserve kernel fallback and full final evidence.
- [ ] Keep O-7 diagnostic-only and reject O-15's test-only hot-path claim.

## Package F — Generalize supported passive publication

**Own after C:** `src/discovery/engine.rs`, `src/discovery/scan.rs`,
`src/discovery/publication_tests.rs`, factory fixtures and documentation.
**Consumes:** factory observations, independently validated process/image,
table and executable endpoint owners, and B/C admission contracts.
**Produces:** a shared validated count-only publication result across factory forms.

- [ ] Implement E08's factory/storage/request/forwarding matrix first.
- [ ] Reuse a bounded ownership-validation/lowering path for supported
  `C_GetInterface` results instead of removing existing authority guards.
- [ ] Keep table owner distinct from each executable endpoint owner; require
  stable file-backed target identity and explicit known ABI bounds.
- [ ] Measure E13's first-call gap and pre-capture publication boundary.
  No passive userspace attach-after-return design may promise zero latency.
- [ ] Run E15/E21 privacy and malicious-pointer controls before accepting
  broader coverage. Provider-specific heuristics remain optional, not authority.

## Package G — Capacity and long-lived capture architecture

**Own:** `crates/ebpf-common/src/lib.rs`, `crates/ebpf/src/main.rs`,
`crates/ebpf/native/task_owner.c`, planner/metrics/loader definitions and
map/identity tests. This is a separate ABI project, not a constant bump.
**Consumes:** measured E05/E10/E11 demand and historical identity requirements.
**Produces:** a reviewed resource contract and a bounded implementation.

- [ ] Inventory capacity/occupancy for STATS, START, RV_COUNTS, descriptors,
  task ownership, candidates/interfaces, history, semantic keys, rings and links.
- [ ] Compare right-sized dense and bounded non-evicting sparse storage at
  idle/sparse/full residency on each CPU tier. Treat 8,192 as an experimental
  candidate, not a universal sufficiency claim; RV needs its own key budget.
- [ ] Prove first-touch initialization/relookup under concurrency and explicit
  failure accounting. Update native slot checks, counts and cleanup together.
- [ ] Decide append-only historical identity versus epoch reclamation using
  E10/E12/E20. Do not recycle slots or runtime view IDs into old evidence.
- [ ] Measure attachment/program-load/teardown separately; shared map values
  do not remove link cost. Qualify broader admission only after this contract.

## Package H — Qualification and operator evidence

**Own:** standing fixture runners/oracles, `.github/workflows/ci.yml`,
schema/usage/qualification docs; product evidence fields only through a
separately reviewed schema/privacy change.
**Consumes:** selected A–G commits and frozen binaries.
**Produces:** exact-tip supported-envelope results and recurring regression gates.

- [ ] Run E23's forced-backend/kernel matrix using owned fresh overlays and
  verified tool-equipped bases; include seccomp/cleanup and group rebuild.
- [ ] Run E12/E14/E15/E17 and privacy canaries on the exact candidate bytes.
- [ ] Repeat the multi-user/provider matrix across the chosen capacity tiers,
  including independent processes using identical provider bytes and handles.
  A foreign provider's traffic must not mask a refused owned workload.
- [ ] Own E16's supported/unsupported execution-surface fixtures and publish
  their coverage boundaries before accepting E24's final envelope.
- [ ] Publish measured coverage dimensions and remaining gaps; keep terminal
  PARTIAL until a producer-quiescence proof exists.
- [ ] Run E24 only after shorter correctness/capacity gates pass. Publish
  workload/rate/process/endpoint/CPU/duration limits with evidence references.
- [ ] Run repository-required fmt/check/test/clippy and scoped Python/native
  gates, obtain final independent review, then commit qualification docs.
  Publication/release is a separate action.

## Sequencing and acceptance

A's safety/output patches precede D's ownership of run.rs; its oracle
corrections precede trusted timing conclusions. B and C precede a promise of
stable eventual discovery. E0's isolation gate precedes multi-process semantic
qualification and may run alongside B/C with disjoint ownership. D may be
developed independently of B/C in an
isolated checkout after A releases the shared files, but shared run/attach
code must have one writer and timing cells must be serialized. E's performance
work follows E0 and D's measurement. F follows B/C; G is selected
from capacity experiments, not inferred from a single provider. H qualifies
the actual resulting combination.

Use subagent-driven execution for these bounded packages: one owner, a clear
testable deliverable and fresh review after the writer stops. The primary
keeps requirements, integration and acceptance gates. No recursive fan-out or
simultaneous writers of engine.rs/run.rs/attach.rs. If an experiment changes
the proposed design, update this plan before implementing the affected package.

**Fix priority:** first F-01/F-11 safety and interference, then the
doctor/validator/measurement contracts and B/C's coverage preservation and
fair exploration plus E0's semantic isolation. These scale defects are
correctness work. Lower-impact
JSON/CI/cleanup patches can proceed separately; completing every historical
finding is not a prerequisite to performance work.

**Recommended first performance changes:** B's separate measured O-13 startup
patch after its rescan correctness gate, and D's isolated O-1 consumer patch
after A releases run.rs. Compare E25/E04 results independently; do not merge
their performance claims. Broader default admission waits for F/G evidence;
O-1 alone cannot fix missing providers.
