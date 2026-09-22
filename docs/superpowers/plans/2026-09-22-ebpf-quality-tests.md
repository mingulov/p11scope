<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# eBPF quality test implementation plan

Date: 2026-09-22. Source review preserved from the parallel eBPF test-strategy task. Status: **bounded source review and proposed test queue; no new tests, Cargo builds, privileged experiments, or benchmarks run by this reviewer**.

**Goal:** prevent regressions in system-wide provider discovery, early scope rejection, caller identity, cumulative statistics, optional tracing, and lifecycle/cleanup without mistaking an incomplete observation for a fast or complete capture.

**Architecture:** extend the existing owned-workload, physical-receipt, raw-map, compiled-object, and evidence-parser harnesses. Keep one independent workload ledger and separate observations at each capture stage. Use fast behavioral regressions for known failures, a small live kernel matrix for integration, and measured performance/soak campaigns after correctness passes.

**Tech stack:** existing Rust 1.88 tests, C LP64/IA32 fixtures, Python evidence parsers, compiled BPF checkers, Linux host/VM lanes. No new testing dependency is required for the first tranche.

**Spec:** docs/superpowers/plans/2026-09-22-production-provider-usage.md; audit-notes/perf/SYSTEM-EXPERIMENTS.md, especially E03–E25; the workspace review .superpowers/sdd/SYSTEM-PLAN/task-scope-regression-coverage.md.

**Revision:** initial clean production worktree .worktrees/production-provider-usage at **4b37951a35a0a18eae816fa853a4b5d7dfe62d16**. Paths/line numbers below refer to that snapshot unless explicitly marked I3 WIP. Final readback at 14:26 UTC was clean **da52357059c9ffafde8b9e41919bc8a85082f0f7**; the concurrent committed changes since the baseline are scripts/check-bpf-map-defs.py, tests/python/test_inventory_object.py and src/discovery/scan.rs. Those separately owned scope-checker and module-alias repairs are not re-reviewed or re-qualified here; other cited implementation sources remain unchanged. Main at 7dee8b3 is historical and was not used as the current implementation baseline. This report does not update the last full-suite verdict.

## Global constraints and ownership

- Preserve Rust 1.88, edition 2024, Linux x86-64-first support, and docs/privacy/allowlist-v1.md. New key annotations remain a separate reviewed feature.
- System scope must remain the broad-coverage acceptance target. PID/run/cgroup/module lanes additionally prove their own isolation and cost; passing those lanes cannot replace system qualification.
- No secret material, active calls into a user's provider, implicit new public identity fields, or raw internal pointers are required by these tests. Private fixture receipts are distinct from public telemetry.
- One Cargo-heavy lane and one privileged/BPF lane, controlled by the primary. Use the existing owned launcher, locks, pidfd/process-generation checks and cleanup. Temporary data belongs under /var/tmp/p11scope-ws-tmp.
- Already owned, with scope-checker/module-alias fixes integrated during this review: I3 retirement-worker regressions and live stop-loss gate; module physical-alias repair; compiled Inventory early-scope mutation checks. **Extend their acceptance record; do not start competing implementations.**
- This is a prioritized test strategy for the existing authorized campaign. Capability-dependent items below enter their owning implementation task; they are not claims that caller-aware inventory, dynamic growth, operation counters, or JSONL already exist.

## Most valuable findings

1. **A named live test is still a procedure, not a test.** tests/e20_live_collision.rs:162 returns an apparent successful test with a SKIP message by default and panics when P11SCOPE_LIVE_BPF=1. It starts no observer. Its companion at :127 creates two live mappers but only checks their PIDs/inodes and constant function/mechanism values; despite its comment, it does not feed the real reducer. Existing semantic reducer tests do exercise collision behavior. Implement the missing live integration cell rather than counting these names as kernel coverage.
2. **The old overhead benchmark can report speed without coverage.** scripts/bench-overhead.sh:103–171 uses a fixed three-second warm-up, requires only a positive attached-probe count for profile, and a nonempty trace file for trace. That is insufficient to prove the measured N calls were observed. Reuse the stronger system-scope-measure/receipt machinery and reject performance samples with failed coverage.
3. **Real retained-ring tests currently exercise empty rings.** src/events/runtime_tests.rs:14,95 proves actual map identity, cursor ownership, and FD lifetime, explicitly with no attached producers. src/events.rs and src/run/capture_loop_tests.rs provide valuable scripted backlog/malformed/terminal tests. The missing complement is a populated real ring across ordinary polling, lifecycle/control work, cancellation, and final drain.
4. **Concurrent first-touch coverage is partly a userspace model.** tests/capacity_contract.rs:117 races FirstTouchLedger, not the kernel USAGE or RV maps. It cannot establish multi-CPU atomic use marking, shared-map insertion behavior, or exact kernel totals under concurrent scrapes. Preserve that test and add a small actual-object concurrency cell.
5. **Counter boundary behavior deserves a cheap regression.** src/metrics.rs:84,142,158 uses ordinary u64 sums for per-CPU RV/evidence/bucket totals; nearby STATS merging saturates. crates/ebpf/src/main.rs:2517 onward increments several counters with ordinary addition. Seed near-limit owned test cells to establish the chosen overflow contract and prevent wrap/decreasing cumulative output or debug panics. This is a source-backed boundary concern, not a natural-workload overflow reproduction.

The current teardown failure is specifically **DISCOVERY exec/leader-exit records**, not 931 PKCS#11 API calls. The separate I3 timing report records loss 0 immediately before synchronous stop and 931 afterward over 38.776640 seconds, while expected use remained positive. That experiment does not count ordinary CALL events, which that private Inventory slice does not emit. See task-I3a-root-timing-result.md and task-I3a-async-stop-design-review.md; the repair remains independently owned and unqualified until its gates pass.

## Existing coverage to reuse

| Area | Existing evidence-bearing test source | Remaining assurance |
|---|---|---|
| Owned system denominator | scripts/system-scope-receipt.py; scripts/system-scope-measure.py:108,684; tests/python/test_measure_e03.py:327–543; test_audit_oracle.py:130–317 | Execute the integrated binary with real owned calls; preserve identities through each new mode. Parser tests and receipt construction alone are not capture qualification. |
| Ring identity, malformed records, terminal order | src/events.rs:869–1041; runtime_tests.rs:14,95; run/capture_loop_tests.rs:134,212,652,1108 | Populated actual maps, concurrent producers, one cursor across slow control work, and final loss/byte accounting. |
| PID/run/cgroup | task-scope-regression-coverage.md; verify-attach-e2e.sh; verify-canaries.sh; matrix/verify-shared-layer.sh; matrix/verify-fork-scope.sh | Foreign-only same-endpoint phase, selected nonleader, deterministic cgroup migration, raw state/transport, explicit Singles/Multi. Avoid duplicating existing positive-only and sibling-cgroup totals. |
| Mapping/claim lifetime | discovery/inventory_claims_tests.rs:301,347,367,396,420,526,597,628; engine_tests.rs; scheduler.rs:382–588 | Live image authority and continuation/commit, more than 256 provider-bearing generations, unknown late object under continuing noise, event-loss recovery. Existing two-owner pin accounting already has meaningful regressions. |
| Native task/root ownership | tests/task_owner_contracts.rs; tests/root_affiliation_contracts.rs; tests/fixtures/task-owner/helper_tests.c; root-affiliation/birth_hook_tests.c | Actual kernel task storage under concurrent entry/return/exec/exit and interrupted returns. Native substituted-helper behavior is distinct from live kernel semantics. |
| Async/session isolation | src/semantics.rs:798,1185,1338; tests/e20_live_collision.rs | Implement the real same-EVENTS-domain integration cell, opposite completion order, same handles/IDs, and lifecycle interference. |
| ABI and compiled authority | inventory_bpf_contracts.rs; artifact_contracts.rs:4668,5211,5246,5307,5441,5497,5676,9547; check-entry-object.py; check-discovery-flow-object.py; check-bpf-map-defs.py | Exact final-object verifier loads and live ABI behavior on supported kernels; strengthen existing checkers with causal mutations instead of more source-string presence tests. |
| Deliberate loss and sink behavior | verify-induced-gaps.sh; src/sink.rs:445,770; tests/python/test_loss_share_measure.py:173–441 | Combined saturation, CPU pressure, control churn, cancellation and complete terminal accounting, including recovery afterward. |
| Parsing | tests/discovery_scan.rs:106,145,281,452,592,716,794,881; manifest/maps.rs:429,502,549,579; events.rs:139,144 | Generated boundary/state sequences and bounded coverage-guided parser fuzzing. No dedicated cargo-fuzz/property-testing dependency was found in the inspected manifests. |

Line numbers identify the inspected source, not a newly passed test. Existing E01–E25 already cover many desired themes; this queue makes their highest-value missing cells executable and connects them to the new Inventory/counter architecture.

## One measurement contract for every live cell

Use the existing receipt and custody pipeline rather than inventing another root controller. Extend its private evidence schema only for measurements needed by a test. A case records:

- Source revision/patch digest, binary and both embedded BPF-object hashes, toolchain recipe, build flags, fixture hash/ABI, actual kernel/config, backend requested and actually used, scope, CPU topology/affinity, and every resource bound.
- Physical target receipt from the owned retained object/target mapping, endpoint offsets, target PID plus process birth/generation and exec epoch, namespace identity where relevant. Equal path names or equal bytes are not physical identity.
- Readiness and attach acknowledgements, workload GO, actual completed workload ledger and return-code histogram, optional fixture-body ACKs for a held invocation, monotonic phase times, stop request, producer-stop completion, final drain and final sink settlement. Requested iterations are not the denominator if the workload failed midway.
- Separately: required/discovered/validated/admitted/attached targets; first use/caller association evidence; BPF entry/completion counts and update failures; CALL and DISCOVERY reserve losses; raw consumed/malformed/reducer-refused/terminal-abandoned records; accepted/delivered/dropped sink bytes; live and retained resource counts.

Observe maps through already-owned retained descriptors while capture is active. Release test observer references before asserting final release, and use non-owning ID enumeration for disappearance checks; opening a fresh object FD by ID changes the lifetime being measured. Preserve bounded delayed-release observations without relabelling an unexecuted success assertion as passed cleanup.

For a controlled normal-return, fully admitted, authoritative fixture with zero pairing/update failures, require workload completions = BPF completed calls = sum of RV counts after quiescence. For profile/trace, an exact CALL-record balance is valid only after accounting for policy and every pre-reservation refusal; lifecycle records are a separate stream. Never add overlapping diagnostic counters into a fabricated universal conservation equation. Bytes, records, calls, operations, and providers have different units.

Ordinary concurrent snapshots need not describe one atomic instant: reads of STATS and RV maps can straddle a completion. Require per-generation monotonic counters when no saturation/reset occurred, explicit snapshot intervals/uncertainty, and exact final totals after independently acknowledged quiescence. Two independent collectors must not reset maps or each other's baselines. An operation that started before a collection and completed after it is counted once at the documented completion boundary.

The owned ledger comes from the fixture/controller, never reconstructed from observer output. Shared-endpoint actor tests use separate process-generation attribution where supported and role-specific function/RV patterns as an additional check. Where a current output lacks caller attribution, record that dimension as unqualified; use private raw observation or an exclusive physical fixture rather than credit foreign global totals. Uncontrolled Firefox activity is useful realism but cannot supply an exact all-calls denominator by itself.

Before trusting each oracle, remove one owned observation while preserving foreign traffic, replace its object/PID generation, move GO outside capture, drop its final record, falsify the actual backend, and substitute a different object hash. Every applicable mutation must fail. Missing prerequisites, no work generated, skipped gates, unknown matching, or incomplete cleanup are not PASS. Keep failed raw runs; a later successful repeat does not erase them.

## Prioritized implementation queue

Runtime estimates below exclude compilation/VM provisioning and are planning estimates, not measured performance promises. Owners are work packages, not extra agents to spawn.

### Q0 — Fix the test denominator before expanding benchmarks (P0, M/H owner)

**Files:** scripts/system-scope-measure.py, scripts/system-scope-measure.sh, scripts/system-scope-receipt.py, tests/python/test_measure_e03.py, tests/python/test_audit_oracle.py; adapt scripts/bench-overhead.sh to consume their valid evidence.

- [ ] Make each measured profile/metrics sample require exact owned per-function/RV totals; trace requires attributable raw-record accounting, not a nonempty file. Preserve the unobserved baseline separately.
- [ ] Replace guessed warm-up as the readiness oracle with the existing authenticated ready/attach/GO protocol. Measure startup independently instead of hiding it in an arbitrary sleep.
- [ ] Exercise the actual parser/runner entrypoint with each negative mutation above. Existing foreign-only and physical-receipt tests should be extended only where the new mode adds a different acceptance path.
- [ ] Add an explicit capability/claim ledger: a named test that only prints SKIP cannot qualify its corresponding runtime row. Implement E20's missing live body in Q5; do not turn a placeholder panic into a skip that satisfies release gates.

**Pass:** a valid owned control passes; every negative sample is rejected with a reason. No speed result is included in the accepted set if its required calls were absent. **Cost:** Python regressions seconds; three serial live controls roughly 2–5 minutes. This is prerequisite to performance comparisons, not prerequisite to already-owned bug fixes.

### Q1 — Live transport during control work and shutdown (P0, existing I3/R owner)

**Files:** I3 WIP src/attach/inventory/activation/{tests,privileged_tests}.rs; src/events/runtime_tests.rs; src/run/capture_loop_tests.rs; existing sink/loss validators. The current worker repair already owns its blocked-close, custody, deadline, and error tests.

- [ ] Preserve the current real RED and the exact controlled-overlap protocol in task-I3a-async-stop-design-review.md. During stop, an independently runnable owned exec/exit workload must exceed ring capacity at a declared pace while the one reader remains active; prove overlap with phase ACKs, not sleeps.
- [ ] Extend afterward to activation, partial-attach rollback, late-provider attachment, and large snapshot/control work. A responsive stop does not prove those phases are responsive.
- [ ] Populate a real DISCOVERY ring and CALL ring where that mode supports it; test ordinary polling, deliberately bounded backlog, final draining, malformed handling via the appropriate test fixture, and no cursor remapping or double consumer. Keep direct kernel-record injection distinct from actual product producers.
- [ ] Run slow file/pipe consumer, EPIPE, cancellation during a blocked sink, and final drop/flush. Measure loop acknowledgement and cleanup completion separately; a pending worker is not completed cleanup. Inspect terminal counters after every final flush/drop action.

**Pass:** controlled in-envelope workload has all exact owned records, zero unexplained loss, bounded queues, preserved positive/history evidence, and fully accounted resource custody. Deliberate overload must report the correct stage and recover for a fresh post-overload batch. Do not pass by enlarging the ring, shortening the overlap, detaching lifecycle roots early, or weakening assertions. **Cost:** fast fault tests seconds; live small/default-ring cells 2–6 minutes, large-link stop cell bounded by its established outer deadline.

Kernel documentation explains why this is necessary: a full ring refuses reservations without blocking; a busy earlier reservation can delay visibility of later committed records. Producer/consumer positions are transient snapshots, not standalone completion proof. [Linux BPF ring-buffer documentation](https://docs.kernel.org/bpf/ringbuf.html).

### Q2 — Actual kernel counters and concurrent collection (P0, I2/I2c/O owner)

**Files:** extend the actual Inventory activation gate, src/metrics.rs tests, crates/ebpf-common/src/inventory_tests.rs; add one shared controlled-call fixture under tests/fixtures/ and a private evidence parser test under tests/python/. Keep one fixture for the following phases.

- [ ] For USAGE, many threads/processes concurrently hit the same previously-zero cell, then distinct cells; include foreign-only first, untouched endpoints, and mapping/publication-only controls. Result is exactly 0 or 1. Repeated use is not an exact-count promise. Verify absence of ordinary START/RV/EVENTS in the Inventory object/attachment.
- [ ] Once caller evidence exists, caller B must appear after caller A already set the shared endpoint bit. Include short-lived callers, multiple threads, second image after exec, and exhaustion of caller associations independent of endpoint capacity.
- [ ] For Detailed metrics and new counter mode, use 1, 2 and 8 runnable workers, a hot shared endpoint and independent endpoints, exact normal/error/vendor RV histograms, and zero/one/burst call phases. LP64 RV values exceeding 32 bits must survive where the target ABI permits them; IA32 normalizes according to its ABI.
- [ ] Scrape at 100 ms, 1 s and 10 s while producers run, including two collectors and one failed scrape. Do not reset maps. After quiescence, each collector's successive successful deltas telescope to the same cumulative total from its own baseline. Restarts create a new generation; stale baselines cannot silently subtract across it.
- [ ] When optional timestamps land, use injected clock samples to test a wall-clock step without changing the host clock. Monotonic capture intervals/durations stay valid, while displayed wall time carries its explicit correlation; second-resolution presentation must not merge distinct calls or count one operation twice.
- [ ] Seed private, owned map/test values near the numeric boundary and test per-CPU aggregation, latency totals/buckets, RV and loss counters. Require an explicitly chosen saturation/reset contract with visible evidence, no decreasing totals or panic. These fixtures do not justify claiming a natural long-duration overflow was reproduced.

**Pass:** exact post-quiescence totals and histograms, monotonic in-generation values within their defined range, no foreign collection, no reset-induced loss, and truthful unsupported attribution. A failed pairing/first-touch update must remain explicit. **Cost:** 1–3 minute live baseline matrix; deterministic numeric-boundary tests below a minute. Run the actual production BPF object, not only FirstTouchLedger.

### Q3 — Provider/caller churn, fairness and scope (P0, I2c/I4 owner)

**Files:** src/discovery/{scheduler.rs,engine_tests.rs,inventory_claims_tests.rs}; reuse scripts/verify-early-scope.sh and fixture proposed by task-scope-regression-coverage.md; existing live-discovery-provider/driver fixtures.

- [ ] Sequence 300 provider-bearing process generations, keep their compact mapping claims, then introduce a unique provider after scan-window exhaustion. Include a large candidate batch whose last provider is the only one used. Repeated noisy old providers cannot starve it; incomplete scans and expired leases cannot falsely retire earlier claims.
- [ ] Force one missed loader/exec/exit hint and then a burst overflow. A continuing provider must become correct through reconciliation within a declared number of completed fair sweeps and a measured wall-time envelope. Sticky loss history remains visible even after recovery.
- [ ] Exercise known-file reload after the initial mapper exits, two sharers where one unmaps, renamed/deleted retained file, pathname replacement with different inode, same-inode independent mappings, dlmopen where supported, and exec without PID change. Use actual image evidence, never stale numeric-PID association. Force true reuse in the observer's PID domain in a disposable VM; merely seeing PID 1 in two namespaces tests a namespace collision, not numeric kernel-PID reuse. Do not change the host-wide PID allocator.
- [ ] Hold an owned provider-bearing process until actual table acquisition and accepted scan/manifest agreement are acknowledged, then exit and reconcile through the production retirement path. Historical agreement and positive evidence must survive. Compare exit before service: no fabricated agreement and no discovery-loss charge merely for an ordinary exit. Loader-hit counts and elapsed sleeps are not acquisition acknowledgements. Existing synthetic history and exited-record tests are seeds, not substitutes for this combined path.
- [ ] Let the thread-group leader exit while an owned worker remains alive and continues an exact acknowledged call sequence. Separately exit a nonleader. Neither event alone proves the whole caller/provider is gone. Settle the whole group independently before asserting process retirement; record each thread's actual role and generation.
- [ ] Complement existing table-layout tests with actual late publication for C_GetFunctionList, C_GetInterfaceList and C_GetInterface, including heap tables and supported 2.40/3.x layouts. Use a held return to change/unmap the output table, successful return with null/invalid output, unreadable selector guard page, and counts at/over the interface bound. Require validated safe attachment or explicit refusal with no unauthorized user-memory reads; do not infer semantic authority from a function name or table-shaped bytes.
- [ ] Add immediate load → one call → unload without waiting for attachment, for both a known physical file and an unseen one. Report precisely whether execution was observed, missed, or unsupported. A delayed post-attachment success cannot satisfy the unseen first-use requirement, and a later mapping must never fabricate past use.
- [ ] Run the existing scope review's selected/foreign same-endpoint and held-call migration cases. Include run leader/thread/fork-child policy; cgroup in→out, out→in, nested and sibling groups; publication while outside; scope-specific discovery work and late selection continuity. Module-alias and compiled Inventory checks are already owned separately.

**Pass:** all supported exercised providers/callers in the declared envelope appear with correct identity/use/liveness distinctions; all out-of-scope ordinary state remains absent; every injected lost hint recovers or produces an explicit failed coverage verdict. No claim of atomic continuous cgroup membership follows from entry/return checks. **Cost:** most identity cells 1–3 minutes; 300-generation fairness/large-union lane 5–15 minutes initially. Record actual cost before putting it in per-change CI.

### Q4 — Independent capacity, growth and rollback boundaries (P1, I3/I4/D owner)

**Files:** tests/capacity_contract.rs; actual activation/loader tests; src/discovery/inventory_claims_tests.rs; future growth implementation tests at its production publication seam.

- [ ] Sweep 511/512/513 and 575/576/577 physical endpoints, then a larger union such as 4097 within the predeclared resource envelope. Vary number of physical files separately from endpoints. 576 is a regression size, not a supported maximum.
- [ ] Exhaust each independent resource cheaply using a reviewed small-bound test object or injection seam: START, RV keys, caller associations, task/image tickets, loader contexts, history, retained FDs/pins, scan bytes, queue and ring. Record which altered bound is being tested; later run at least one real-default boundary for each production claim.
- [ ] Keep endpoint count constant while adding callers and full return-code keys. Endpoint growth alone must not mask those independent ceilings. Exercise more than 256 provider-bearing generations/context churn and more than 512 sequential candidates.
- [ ] At growth/publication boundaries, hold calls across old/new segments, snapshot simultaneously, and fail allocation, map population, link attach N, metadata publication, and rollback separately. Stable identities and positive/cumulative evidence must survive; no double attachment, missed old segment, false successful publication, or copied-live-map reset.
- [ ] Repeated no-op scans and failed retries must not accumulate duplicate pins/claims; reuse the new two-owner tests rather than duplicating them. Measure actual retained FDs, links, kernel map memory, live keys and tombstones independently of estimated payload bytes.

**Pass:** within the declared supported envelope, exact observations continue across growth. Outside it, refusal is explicit and bounded, existing admitted work stays correct, and cleanup remains owned. Honest refusal is a failure-handling pass, not an all-provider coverage pass. **Cost:** small-bound fault cells seconds–2 minutes; large live cells 3–10 minutes or the existing stop deadline. Never choose a larger map constant as the test's success oracle.

### Q5 — Entry/return pairing and semantic operation isolation (P1, D/O owner)

**Files:** implement tests/e20_live_collision.rs:162 using its owned fixtures and existing capture machinery; src/semantics.rs; existing blocking_provider.c/blocking_workload.c and ABI fixture helpers.

- [ ] Start one actual observer over two callers of one physical provider. Drive equal numeric session handles/async IDs with different mechanism-ledger identities, both completion orders, one owner's close/finalize/exit, and a fresh image. Confirm captured records carry distinct authenticated caller generations in the same map domain and reach the real reducer. Preserve valid intentional transfers; equal numbers alone cannot authorize attribution.
- [ ] Pair calls that migrate CPUs, nested wrapper→backend calls, same-endpoint recursion/callback, missing return via thread/process exit, and longjmp. For unsupported same-slot recursion, assert explicit pairing uncertainty and no stale/wrong latency or mechanism rather than demanding invented exact correlation. Match START/owner cleanup after independently confirmed task termination.
- [ ] Exercise an actual nonleader thread entering an owned probed function, acknowledging entry from its body, then taking raw thread exit without returning. The surviving leader must subsequently complete its own independently counted calls. Through retained observer descriptors, verify removal of that thread's START keys, exactly the fixture's expected abandoned-start increment, and settled owner debt; keep completed calls/RVs separate from the abandoned entry. Do not infer this from a native helper simulation or receipt-only thread test.
- [ ] Hold one thread inside an owned call while another nonleader executes a new image. A successful exec must clean old physical-task keys and preserve correct new-image attribution; a failed exec is a separate control and must not pretend a new image existed. Use body/exec handshakes and an independent abandoned/completed ledger. The expected kernel return-probe behavior is a hypothesis until the real production object is exercised; never invent a successful return for the abandoned call.
- [ ] For new operation counters, use a separate operation ledger: successful single-part, multipart Init/Update/Final, successful size query and retry, error at each transition, cancellation, pending/completion, and operations crossing snapshots. API completions, operation attempts and successful operations are different expected totals.
- [ ] For later optional key enrichment, distinguish requested key-generation attributes from successful creation and later use; handle pre-existing/imported/destroyed/reused handles and cache eviction. Unknown remains unknown; cache behavior cannot reduce operation totals. Enable these cells only with the reviewed metadata/schema capability.

**Pass:** exact supported operation counts and outcome partitions, no cross-caller/provider/image contamination, and explicit unsupported or ambiguous cases. The live same-domain test must fail if one caller's captured sequence is removed or replaced with the other's. **Cost:** 2–5 minutes for the live isolation/pairing subset; semantic sequence tests seconds.

### Q6 — Generative tests where there is a real invariant (P1, owning component)

**Files:** src/events.rs, src/discovery/{scheduler.rs,engine_tests.rs,inventory_claims_tests.rs}, src/semantics.rs, crates/manifest/src/{maps.rs,elf.rs}; extend existing Python evidence tests. Start with deterministic exhaustive small-state/seeded generators using existing dependencies. A new property/fuzz library is a separate dependency choice, not required to write the first useful properties.

- [ ] **Drain partition invariance:** the same finite valid/malformed input, reduced with different positive poll quanta and snapshot placements, yields the same final accepted-event multiset, malformed total and cursor, while respecting each bounded prefix. Include busy/discard/wrap transport cases at the layer that actually understands ring headers. Do not mutate raw bytes and then demand malformed inputs round-trip.
- [ ] **Ownership state model:** generate complete/partial/unavailable scans, lost hints, lease rotation, exec, unmap, duplicate publication, and delayed callbacks. Assert an incomplete observation never grants absence authority; pin/claim totals match independent live references; historical positives survive retirement; old-generation work cannot alter a new generation. Reduce failures to a short reproducible sequence.
- [ ] **Independent-owner semantic permutations:** reorder independent callers while preserving each caller's valid happens-before sequence. Their outputs must be unchanged except legitimate shared-resource exhaustion. Do not assert arbitrary reorder invariance for Init/Final within one operation or real duplicate calls.
- [ ] **Map/ELF parser boundaries:** generated sorted disjoint intervals, holes, exact endpoints, maximum addresses/offset addition, truncated files, ABI/layout disagreement and bounded reads. Compare address lookup to a tiny simple interval oracle and enforce no out-of-budget read. Existing parser example tests remain seeds.
- [ ] **Targeted mutation tests:** delete a loss increment, accept an old generation, remove last queue item, reset a scrape map, skip a final flush, bypass scope/ABI authorization, or permit duplicate publication. Require the relevant behavioral test to kill each non-equivalent mutation. Reuse existing compiled checkers; do not demand a repository-wide mutation percentage.
- [ ] **Bounded fuzzing:** parser/record-decoder targets only, in isolated unprivileged processes with explicit input/memory/time limits, sanitizer-supported native seams where applicable, corpus coverage and minimized reproductions. A panic-only smoke loop is weaker evidence; no need to fuzz the host kernel or privileged cleanup controller indiscriminately.

**Pass:** deterministic seed replay and useful independent invariants; no vacuous generator or implementation-shaped oracle; zero accepted forbidden mutations in the selected contract set. **Cost:** 10–60 seconds targeted per-change; 10–30 minutes nightly fuzzing per selected parser family. This complements live scheduling; it cannot establish it.

### Q7 — Final-byte ABI, toolchain and verifier lanes (P1, toolchain/H owner)

**Files:** build.rs; tests/inventory_bpf_contracts.rs, tests/artifact_contracts.rs, tests/bpf_build_tools.rs; existing ABI/capability/uretprobe safety scripts and prepared VM recipes.

- [ ] Load and exercise both actual embedded objects built through the ordinary default pipeline; separately test the private patched LLVM pipeline. Verify program/map manifests, policy-map freezing, scope/ABI domination, BTF/CO-RE relocation, and representative live calls. Assertions remain enabled in the private compiler recipe.
- [ ] Pin compiler/linker patches and ISA selection; keep a minimized regression for each LLVM problem plus the complete product object. A tiny compile success alone is not verifier or runtime evidence; changing to a newer ISA must not silently change the supported floor.
- [ ] Small matrix: current host first; supported oldest-kernel lane (current project floor remains 5.15), a 6.8 fallback lane, and a capable current Multi lane. Force Singles/Multi/Auto where applicable and LP64/IA32; select glibc/musl and provider-shape representatives without a full Cartesian explosion. Record actual capability verdicts and confined-target safety, including late seccomp transition.

**Pass:** equivalent supported observations by backend/ABI, correct explicit refusal or tested fallback, no unexpected codegen/verifier regression. Unsupported environments are UNRUN with their prerequisite failure, never a passed substitute. **Cost:** 1–3 minute smoke per prepared guest plus potentially expensive first verifier loads; full matrix after integrated changes, not on every documentation edit. Kernel selftests provide useful upstream regression patterns, but passing unrelated selftests does not qualify this product. [Linux BPF development/testing guidance](https://docs.kernel.org/bpf/bpf_devel_QA.html).

## Performance experiment design

Extend the corrected M/overhead harness; retain one exact evidence format. Measure separately:

| Capability/phase | Workload | Measurements and acceptance |
|---|---|---|
| Idle discovery | Many mapped providers, no calls; same file across many callers versus distinct files | Tracer CPU, rescan bytes/syscalls, user RSS, kernel map bytes, FDs/links, scan fairness and allocation churn. Zero use/operation counts. Count actual clone/scan/attach work to expose superlinear growth; a loose elapsed-time timeout is not an algorithmic test. |
| First touch and steady use bit | One cold→hot endpoint, then uniform cold endpoints, then repeated hot calls | Application wall/CPU, tracer CPU, map writes/health, first-use visibility. No ordinary events/returns. Report caller-identity cost separately once enabled. |
| Cumulative API/outcome counters | Shared hot key and dispersed targets; mixed RVs; 1/2/8 workers | Exact final calls/RVs, failed updates, contention, kernel memory, scrape wall/CPU/syscalls at 100 ms/1 s/10 s. Counters must remain useful even when trace is disabled. |
| Semantic counts | Fixed independent Init/Update/Final/pending ledger, varied active sessions | Exact operations, reducer CPU/allocations/visited-state counts, association/history occupancy, snapshot cost. Distinguish cardinality from event rate. |
| Optional time/trace | Same calls with no latency, second-resolution activity if implemented, duration/histograms, then individual records | Incremental cost of each supported feature; CALL reservation/delivery, sink bytes and latency. Timestamp precision and duration are separate options. Do not compare an unimplemented mode under an existing label. |
| Control and growth | Add/remove providers, select/unselect detail while unrelated provider arrives, replace path, failed attach | Time to discover/attach/first observed use, largest consumer scheduling gap, queue high-water marks, error/recovery, ordinary workload impact. Selecting detail must not stall inventory. |
| Saturation and recovery | Declared rate sweep, finite burst, slow sink, CPU contention, then low-rate sentinel batch | Locate first coverage/loss boundary; preserve every failed run. Post-overload sentinel must again be exact, with previous losses sticky. Larger buffers cannot hide a stalled consumer or stuck scheduler. |

Start at one cheap deterministic provider; add SoftHSM, NSS/owned Firefox/Chrome workload, proxy+backend, stripped/heap/interface-only representatives. Give each real-world case its own independently controlled workload/receipt. The user's running Firefox can be observed for discovery realism, but an exact traffic experiment should use a separately owned browser/profile/fixture. Do not terminate or reconfigure the user's existing browser.

Use paired unobserved/baseline/candidate runs in randomized or alternating order, at least five pairs for a pilot, then more if noise is material. Record system load, throttling, migrations and CPU affinity; compare equal work, not just equal duration. Report medians/spread, ns per completed call, throughput, and application slowdown. Run correctness at ambient and induced contention; run performance attribution in a quiet reserved lane. Do not add per-call debug printing to the timed path. Record instrumentation cost.

Pilot endpoints: 1, 64, 576, 4097; callers: 1, 2, 32, then the dedicated >256 fairness case; rates: low control, geometric increases to observed saturation, finite bursts beyond buffer capacity. These are experiment inputs, not product limits. Separate possible-CPU map allocation from online worker concurrency; use prepared 2/12/64-CPU resource lanes only where actually available, and label estimates/model results as such.

**Predeclared gates:** correctness and forbidden attribution have zero tolerance in the declared supported envelope. Deliberate overload must be detected and attributable, not be called lossless. For performance, first establish noise and propose a reviewable regression budget before accepting a candidate; a reasonable initial alert is >10% median paired slowdown or memory increase without an explained capability increase, but this is a proposed triage threshold, not a promised product SLO. Discovery/recovery deadlines must state both configured work quanta and measured wall-time limits. Cancellation response and full cleanup have separate limits. Publish the greatest verified rate/cardinality/duration tuple rather than an unconditional throughput claim.

## Soak, CI cost and sequence

1. **Now:** finish the already-owned stop regressions and preserve the separately owned scope/module gates; Q0 oracle fixes and numeric boundary tests can proceed without privileged contention. Then run focused Q1/Q2 on their exact final artifacts.
2. **Core integration:** Q3's genuine late-provider/fairness/lost-hint cases, actual Q5 same-domain async integration, and Q4 small-bound fault tests as their capabilities land. Run the combined full workspace gate on the resulting integrated bytes; do not infer it from component greens.
3. **Per relevant code change:** targeted Rust/Python/native/compiled-object tests and selected causal mutations; aim for an additional 1–3 minutes, measured. Do not rerun every release harness for a small parser change.
4. **Nightly or dedicated integration lane:** a 10–20 minute serial host set with real populated rings, caller concurrency, identity/scope migration and one large-union cell; ABI/backend smoke in prepared VMs; bounded parser fuzzing independently. Measure startup/teardown before finalizing this budget because the current stop regression alone takes tens of seconds.
5. **Qualification after the core is green:** corrected paired performance campaign, then 30-minute, 4-hour and 24-hour churn soaks from E24. Include fixed high-cardinality, low-peak/high-lifetime churn, bursts/quiet periods, lost-hint recovery and repeated selection cycles. Keep an independent rotating workload ledger with per-window checks, resource high-water marks and end receipts. Check current resources plateau under bounded live load and quantify intentional historical retention separately. Actual wall time is required; faster churn is not a substitute for a 24-hour soak.
6. **Final result:** one row per capability/backend/kernel/ABI with PASS/FAIL/UNRUN, exact workload envelope, immutable artifact identity, raw evidence, oracle-mutation result and cleanup status. A late clean control does not turn a failed capacity, loss or privacy row green.

## Review focus / omissions deliberately retained

- No test can infer a never-observed transient provider's earlier use from its later absence. The unseen immediate-use cell is a requirement stress test and may remain a design blocker; do not downgrade it to a harmless warning.
- One global endpoint bit cannot prove all callers, exact counts, liveness, timing or outcome. Each needs its own testable evidence.
- Shared physical implementations can be observed exactly while logical publisher attribution remains ambiguous. Tests must not demand duplicate credit for each logical table.
- Close completion, empty ring, task exit and callback quiescence are different facts. Only claim the retirement properties actually established by the owned tests.
- Native mocks, scripted rings, artifact source checks, compiled-object path checks, real verifier load and real workload capture are complementary evidence classes. None substitutes for every other class.

## Sources and method

This review read the current plan, SYSPLAN experiment catalog, scope regression review, relevant Rust/C/Python tests and harnesses, plus the separately frozen I3 stop timing/design reports. It performed only read-only Git/source inspection, read primary Linux documentation, and wrote this report. Guessed absent parser paths were subsequently resolved to src/events.rs and crates/manifest/src/{maps,elf}.rs; missing guessed paths were not treated as missing tests.

Applied skill guidance:

- [Superpowers brainstorming](/home/user/.codex/plugins/cache/openai-curated-remote/superpowers/6.4.1/skills/brainstorming/SKILL.md) and [writing-plans](/home/user/.codex/plugins/cache/openai-curated-remote/superpowers/6.4.1/skills/writing-plans/SKILL.md): carry the already supplied product intent into concrete hypotheses, gates and sequencing; this assignment is a report, not a new implementation approval workflow.
- [Engineering audit property-based-testing](/home/user/src/m/muse-tool/engineering-audit/vendor/trailofbits/property-based-testing/skills/property-based-testing/SKILL.md), including references/generating.md: use independent invariants and valid-domain generators, explicit boundaries and reproducible seeds; avoid tautologies/vacuity.
- [Engineering audit data-pipeline lens](/home/user/src/m/muse-tool/engineering-audit/vendor/microsoft/skills/system-type-data-pipeline/SKILL.md): stage-specific data quality, state/cardinality, late arrivals and backpressure. Its distributed-platform/ELT recommendations are not applicable here; no Kafka/stream-processing platform is proposed.
- Read the engineering-audit README/runbook for selection. Vector-forge is specialized crypto vector generation, so it was not applied. The mutation-testing entrypoint targets mewt/muton campaigns; no such campaign or new tool was started. Existing p11scope causal mutation infrastructure is the immediate fit. The Linux philosophy reference was consulted but did not add a separate required workflow.

Primary external sources: [Linux ring-buffer semantics](https://docs.kernel.org/bpf/ringbuf.html), [Linux BPF maps](https://docs.kernel.org/bpf/maps.html), [Linux BPF testing guidance](https://docs.kernel.org/bpf/bpf_devel_QA.html), accessed 2026-09-22. Project-specific findings above rely on inspected source and separately named campaign evidence, not inferred benchmark results.
