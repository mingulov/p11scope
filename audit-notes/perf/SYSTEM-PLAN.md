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

## Package E — Reduce measured reducer/map work

**Own after D:** `src/semantics.rs`, `src/history.rs`, `src/trace.rs`,
`src/metrics.rs`; `src/run.rs` only after D's writer stops.
**Consumes:** stable event/metadata identity and correct delivery accounting.
**Produces:** equivalent reduction with fewer allocations/traversals.

- [ ] Use E19 to select the first measured hotspot. Preserve immutable
  pending SlotMeta snapshots; shared immutable metadata is safer than naked
  slot re-resolution if future recycling is planned.
- [ ] Replace repeated operation-name allocation and map lookups while keeping
  admission-before-insertion and stable output ordering.
- [ ] Group parent operations by session during fork; add visit-count scaling
  tests to supplement the existing `<2s` test (E20).
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
stable eventual discovery. D may be developed independently of B/C in an
isolated checkout after A releases the shared files, but shared run/attach
code must have one writer and timing cells must be serialized. E follows
D's measurement. F follows B/C; G is selected
from capacity experiments, not inferred from a single provider. H qualifies
the actual resulting combination.

Use subagent-driven execution for these bounded packages: one owner, a clear
testable deliverable and fresh review after the writer stops. The primary
keeps requirements, integration and acceptance gates. No recursive fan-out or
simultaneous writers of engine.rs/run.rs/attach.rs. If an experiment changes
the proposed design, update this plan before implementing the affected package.

**Fix priority:** first F-01/F-11 safety and interference, then the
doctor/validator/measurement contracts and B/C's coverage preservation and
fair exploration. These scale defects are correctness work. Lower-impact
JSON/CI/cleanup patches can proceed separately; completing every historical
finding is not a prerequisite to performance work.

**Recommended first performance changes:** B's separate measured O-13 startup
patch after its rescan correctness gate, and D's isolated O-1 consumer patch
after A releases run.rs. Compare E25/E04 results independently; do not merge
their performance claims. Broader default admission waits for F/G evidence;
O-1 alone cannot fix missing providers.
