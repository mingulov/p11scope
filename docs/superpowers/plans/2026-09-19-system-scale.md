<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System-Scale Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `p11scope --system` genuinely work on a busy desktop/server: attach what exists, refuse honestly what doesn't fit, stream without loss, and fail with one actionable message.

**Architecture:** Fix admission truthfulness first (the 6530-slot refusal is excessive candidate admission: 64 deliberate p11-kit closure templates admitted without publication evidence — see F-Scale-1 correction), then establish a measured post-fix baseline and repair consumer scheduling (loss is a scheduling defect, not just ring size), then collapse attach cost via uprobe_multi with a singles fallback. Order is gated: Phase 2 (multi) starts only after Tasks 1.4 + 3.1 are green.

**Tech Stack:** Rust, aya 0.14 (pinned) + vendored raw `bpf-sys` multi loader, BPF CO-RE, kernels 5.15 (floor, singles) / 6.9+ (multi).

**Spec:** this file argues from the 2026-09-19 sysprobe evidence bundle at `p11scope-ws/docs/sysprobe-2026-09-19/` (`FULL-slot.md`, `FULL-multi.md`, `FULL-live.md`, `replicate_scan.py`, `live_scan_parent*.py`); executors read those first. Prior art: `docs/superpowers/plans/2026-09-19-system-scope-review-fixes.md` (Tasks 1–6, merged).

## Global Constraints

- Product floor stays 5.15 with RHEL 9 5.14-backport support; anything 6.6+ only ships behind a runtime functional probe with fallback (no fail-closed refusal of old kernels).
- `MAX_SLOTS = 512` stays until Phase 1 proves otherwise; never raise it to paper over mis-admission.
- Offline/locked builds only (`--locked --offline`, toolchain 1.88 via `scripts/cargo.sh`); vendored code must be in-repo path crates (deps already in tree: `libc` is fine).
- No PID/path/secret bytes in public evidence, ever; diagnostics stay categorical outside the plan skip.
- Fail closed: a module that doesn't fit is refused whole; a capture that can't attach is PARTIAL/failed, never silently thin.
- Every behavior change carries its RED-then-GREEN test; oracles pin exact shapes — update recipe + mutations together, never delete a guard.

---

## Part 1 — Findings (what the investigation proved)

### F-Scale-1: the 6530-slot refusal is uncorroborated admission of 64 deliberate templates, not fan-out (P0)

One `libp11-kit.so.0.4.8` instance contains a contiguous 53,760-byte `.data` region (file `0x1caf20`) structured as **64 consecutive 840-byte records**, each headed by `0x203` (`CK_VERSION{3,2}`) followed by 104 non-null pointers into the library's own `.text`. `decode_candidate` ([scan.rs:738](src/discovery/scan.rs:738)) admits any 8-aligned plausible version word whose 104 slots are NULL-or-valid as a "full" 3.2 table, with **no corroboration** against actual publication (interface triple, live return, manifest). Overlap suppression ([scan.rs:969](src/discovery/scan.rs:969)) keeps all 64 (adjacent, non-overlapping).

Result per instance: 64 `ScannedTable` × 104 entries = 6656 records → **6530** distinct `AttachKey`s ([plan.rs:1118](src/plan.rs:1118)) > 512 → whole-module refusal ([plan.rs:1130](src/plan.rs:1130)). Reproduced to the digit offline (`replicate_scan.py`) and live across two ASLR bases (identical 64 table offsets `0x1caf20+k·840`). Dedup itself is verified correct (31 procs → 1 union); the "68 functions" intuition undercounts the true 3-surface union (224 offsets) by 3.3×.

**CORRECTION (deep review 2026-09-19, verified):** the 64 records are not proven false positives. Upstream p11-kit 0.26.2 deliberately generates `p11_virtual_fixed[64]`, an array of `CK_FUNCTION_LIST_3_2` closure templates (`gen-fixed-closures.py` defaults to `--closures 64`). Structural cross-check passes exactly: 2 targets shared by all 64 tables at ordinals 65/66 (`C_GetFunctionStatus`/`C_CancelFunction`, the two shared implementations), every other target unique — 64 × 102 + 2 = 6530. Read the record as "**64 structural candidates; publication/activity unresolved; strong evidence of fixed closure templates**." Consequence: admitting any top-4 by evidence proves a resource bound only — four templates can omit an active fifth wrapper, and a heap wrapper's address need not match its file-backed template. Coverage must be proven against published/called wrappers (Task 1.4 oracle), never inferred from admission counts.

**Safety sting (unchanged):** entry names come from `function_name(ordinal)` ([scan.rs:838](src/discovery/scan.rs:838)), so uncorroborated slots would carry wrong PKCS#11 names. The 512-refusal is currently **load-bearing** — it prevents ~6530 mislabeled uprobes. Any fix must not trade refusal for mislabeled attach. Generic heuristic-table mislabeling remains possible and still needs the Task 1.3 guard.

### F-Scale-2: fd exhaustion — fixed and live-verified (done)

Each slot costs ~4 fds (return link + entry link, each with its perf event). The NOFILE self-raise existed but fired only in `Tracker::new()` (tests) and then, after the first fix, in `for_producer` — which runs **after** attach. Live fd-trace proved it: pinned at 1023 fds through 137 EMFILE failures, raise to 524288 only after. Fix: raise at `Session::start`, before the first link. Live-verified on `--system`: **832/832 probes attached, 0 EMFILE, RC=0**. Plus an EMFILE fast-path: one summary naming `ulimit -n` instead of ~130 identical lines. (Merged: `fix: raise fd limit on capture path`, `fix: raise NOFILE at Session::start`.)

### F-Scale-3: the event path loses data under load (P1)

Live 30 s `--system` profile: **2620 events lost** (counter grew 101→2620 during capture); 15 s trace: 1996 lost. Verdicts correctly PARTIAL, but loss at this rate on an idle-ish desktop means the ring/drain path is undersized for system scope. Root cause not yet isolated (ring size vs drain cadence vs render backpressure).

### F-Scale-4: wall time ≫ capture duration (P1 for UX, P2 for correctness)

89 s wall for a 30 s profile (73 s for 15 s trace): ~9 s discovery scan plus **~40 s detach taper** (1023→325 fds) dominate. Per-link detach is O(links) syscalls; multi-links would collapse this with attach.

### F-Scale-5: discovery churn drowns the signal (~370 stderr lines/run)

Live `--system` run: 231× ESRCH on snap-firefox churn, 122× maps-snapshot refusals, 20× ENOENT — all individually honest, collectively burying. This is the known S1 problem with production counts attached.

### F-Scale-6: output-trust refusal is correct but costly (P3)

Run 1 exited 1 after an 8.6 s scan because `/var/tmp/sysprobe-live` (0775) is untrusted. Fail-closed is right; failing *before* the scan instead of after would respect the operator's time.

### F-Scale-7: uprobe_multi reuse verdict (survey)

`ossl-bpf-sys` (osslscope, 306 lines, `libc`-only, production since 1.0.0) is a candidate loader: zero aya coupling (raw syscalls), GPL-3.0-or-later, vendored as an in-repo path crate per the established copy-with-attribution pattern. Sibling-measured at 504 probes: multi **17.8 ms attach / 8 fds** vs singles 109 ms / 511 fds / 46 s teardown — these justify a p11scope experiment, not a p11scope speedup claim (grouping does not reduce per-call probe cost, ring loss, or teardown bounds). **Corrections:** multi-uprobe support is present in Linux **6.6** source — a sibling's 6.9 minimum is its support policy, not the introduction version; use functional tests plus a maintained policy. **Raw-UAPI `pid=0` ≠ libbpf `pid=0`** (raw zero means no task filter; libbpf converts zero to the calling process) — keep adapters explicit and test worker threads. p11scope must ship **dual-path** (functional probe → multi, else today's singles) to keep the 5.15 floor. Requires `expected_attach_type=48` at prog load; no eBPF source changes (plain `#[uprobe]` sections work). Rejected: kryprobe's 64-slot Pid-only spine (wrong shape), aya-master bump (breaks offline story). Notes: pid=0 + in-BPF tgid guard (6.9.x pid-filter thread bug), session probes rejected everywhere, `bisect_attach` for poison-offset isolation.

## Part 2 — Ideas, ranked

1. **Evidence-ordered admission + unresolved-heuristic cap** (fixes F-Scale-1). Order candidate tables by publication evidence — interface linkage (already computed as `ScannedInterface.table`, currently unused for admission), live-return `TableIdentity` match, manifest match. Cap **unresolved heuristic exploration at K=4 per object** (K·104 ≤ 512); corroborated surfaces bypass K and stay subject to the global budget with atomic whole-module refusal. Spill becomes evidence, never slots. Keep three decisions separate: **candidate confidence** (what the bytes support), **resource admission** (what fits), **operator authorization for semantic decoding** (scan-only stays count-only; linkage never authorizes names/descriptors by itself). Must *prefer*, never *gate on*, linkage — gating would break scan-only capture of never-called legacy providers (e.g. gnome-keyring's static table), the feature scan-only discovery exists for. K=4 proves a resource bound only, never coverage — coverage is proven by the Task 1.4 oracle.
2. **Vendor `ossl-bpf-sys`, dual-path multi attach** (fixes attach/teardown cost, F-Scale-4, future-proofs fds). One entry + one return multi-link per (path, program) group; 256 single-object slots go from ~1024 fds to 2. Keep singles for old kernels and dynamic loader/export probes. Biggest clash: multi links are immutable offset sets vs per-slot `detach_slots`/`replace_targets` — DECIDED: explicit group rebuild (or full-group demotion to singles); hybrid rejected (old group left attached would duplicate observations under a superseded decoder).
3. **Ring/drain loss work** (fixes F-Scale-3). Isolate first (ring size vs cadence vs backpressure) with a counting harness; then size/drain fixes. Cannot be a blind knob turn — loss counters are the acceptance metric.
4. **Discovery-noise aggregation** (fixes F-Scale-5, known S1). Collapse per-process discovery skips into per-class summaries with counts (first occurrence + `… ×N`), keeping one full sample. Categorical, no PIDs.
5. **Fail fast on untrusted output** (fixes F-Scale-6). Validate the output sink before discovery scan, not after. Small, independent.
6. **Per-table provenance in evidence** (diagnosability). Record table file_offset, entry count, linkage per admitted table so the next 64× instance is diagnosable from output alone.
7. **Explicitly deferred:** raising `MAX_SLOTS` (wrong lever until admission is truthful — revisit after Phase 1 with numbers); stride/array suppression for periodic candidates (heuristic-on-heuristic, keep as fallback if idea 1 stalls); identical-table content dedup (only 126/6656 here — low leverage); per-file cross-process slot sharing (moot if idea 1 lands: union already dedups correctly); doctor fd row (moot after the self-raise).

---

## Part 3 — Roadmap (phased, each phase shippable)

### Phase 0 — fd budget (DONE, merged, live-verified)

Raise at `Session::start` + EMFILE fast-path. Evidence: 832/832 probes on `--system`, 0 EMFILE. Nothing further.

### Phase 1 — truthful admission (kills the 6530 refusal)

**Files:**
- Modify: `src/discovery/scan.rs` (~738 `decode_candidate`, ~969 suppression) — score, don't just admit
- Modify: `src/plan.rs` (~1105 `merge` wanted-set, ~1130 refusal) — ordered admission + per-object cap
- Modify: `src/render.rs` + `src/discovery/engine.rs` counters — provenance + uncorroborated-candidate reporting
- Test: `src/discovery/engine_tests.rs`, `tests/system_scope.rs`, new fixture built from `sysprobe-2026-09-19/replicate_scan.py`

**Interfaces:**
- Produces: `admit_tables(tables, budget) -> (admitted, uncorroborated)` — exact signature TBD in Task 1.1; later tasks consume the split, never the raw list.

### Task 1.1: evidence score per candidate table

**Files:**
- Modify: `src/discovery/scan.rs`
- Test: `src/discovery/engine_tests.rs`

- [ ] **Step 1: Write the failing test.** A synthetic module with one linked table (interface triple present) and one unlinked lookalike; assert the linked table sorts first. Mirror existing scan unit tests; no live processes.
- [ ] **Step 2: Run it to verify it fails.** `mise exec -- ./scripts/cargo.sh +1.88 test --locked --offline -p p11scope --lib -- <test_name>` — FAIL, no scoring exists.
- [ ] **Step 3: Implement scoring.** Score = interface linkage (reuse `ScannedInterface.table`) > live-return identity match > manifest match > size/version plausibility. Pure function, no I/O.
- [ ] **Step 4: Run test to verify it passes.**
- [ ] **Step 5: Commit.** `feat: score candidate tables by publication evidence`

### Task 1.2: ordered admission with per-object cap

**Files:**
- Modify: `src/plan.rs`, `src/discovery/engine.rs` (budget plumbing)
- Test: `src/discovery/engine_tests.rs`, `tests/system_scope.rs`

- [ ] **Step 1: Write the failing tests.** (a) Resource-bound test: feed the 64-table replica (from `replicate_scan.py` bytes, checked in as a fixture): assert admitted unresolved-heuristic tables ≤ 4 per object, spill == 60 recorded as evidence, module NOT refused — framed as a bound, never as coverage. (b) Five disjoint published 2.40 tables (340 slots) with sufficient global budget are ALL admitted — corroborated surfaces bypass K. (c) With 400 slots allocated, a module needing 136 new targets is refused atomically and a later small module can still fit. (d) Two ASLR/process views of one provider share ONE per-object cap while preserving `entry_objects`, interface indexes, and exact target pins.
- [ ] **Step 2: Run them to verify they fail.** FAIL with whole-module refusal (current behavior).
- [ ] **Step 3: Implement.** Admit tables in score order until the per-object unresolved-heuristic cap (K=4, i.e. ≤416 heuristic slots/object); spill becomes `uncorroborated_candidates` evidence, never slots. Corroborated tables bypass K, subject to the global budget. Keep all-or-nothing refusal when even the top-1 table exceeds remaining global budget (existing `merge` semantics stay).
- [ ] **Step 4: Run tests to verify they pass**, including the existing refusal tests (they must still refuse genuinely oversized modules). Review gate: assert the degenerate order explicitly — `scan_interfaces` finds 0 interfaces for the 64 templates (FULL-slot.md), so all four score components tie and admission order is stable discovery order (first 4 win). Any score refinement (e.g. name-class-weighted linkage) belongs to Task 1.5, not here.
- [ ] **Step 5: Commit.** `feat: admit tables by evidence with per-object cap`

### Task 1.3: provenance + mislabel guard (one release unit with 1.2 — Phase 1 is not truthful until both land)

**Files:**
- Modify: `src/render.rs`, `src/discovery/scan.rs:838` (`function_name` use)
- Test: `src/render.rs` tests, `src/discovery/engine_tests.rs`

- [ ] **Step 1: Write the failing test.** Admitted table carries (file_offset, entry count, linkage kind) into evidence; a heuristic table with no linkage is either named `unknown` or refused — never labeled `C_Sign`.
- [ ] **Step 2: Run it to verify it fails.**
- [ ] **Step 3: Implement.** Provenance struct through plan→evidence; gate `function_name(ordinal)` behind linkage-or-manifest authorization.
- [ ] **Step 4: Run tests to verify they pass.**
- [ ] **Step 5: Commit.** `feat: table provenance and mislabel guard`

### Task 1.4: live acceptance + baseline matrix + capacity re-evaluation

- [ ] **Step 1: Owned active-wrapper fixture.** A fixture provider with ≥5 published wrappers where the workload activates a closure beyond index 3; assert observed counts/names match the workload oracle (count-only admission is NOT accepted). Plus: several simultaneous published wrappers, five corroborated tables, a runtime table copy, and a never-called legacy static provider (scan-only path must keep working).
- [ ] **Step 2: Post-fix baseline.** Controlled per-PID and `--system` runs with identical workload and exact binary identity. Record separately: discovery/load/attach/capture/drain/detach/publish times; workload truth vs observed; every loss counter (`EVIDENCE_RING_LOSS`, START failures, unmatched returns, RV-update failures, semantic drops — zero ordinary ring loss does not establish completeness).
- [ ] **Step 3: Decide capacity with numbers.** The requirement is the capture-wide union of exact targets plus retained historical allocations (slot IDs are never returned — `plan.rs:758-780`), not the largest single module. If the honest union fits 512 with headroom, close the question; else open a map-resize/epoch task. Report allocated-vs-active slots and the first exhausted dimension (slots, bytes, work units, semantic budgets).
- [ ] **Step 4: Record** the numbers in the task commit message. No code change expected.

### Task 1.5: publication-driven admission — heap wrappers + backend forwarding (option A)

Why: Task 1.2 (option C: structural-family recognition as explicit uncertain admission, K=4 as exploration budget) bounds heuristic exploration but cannot identify active wrappers. Upstream-verified (`virtual.c` @ 0.26.2): published tables are heap-`calloc`'d (`&wrapper->bound`), allocation takes the first free `fixed_closures` index (release clears to NULL, so holes are normal — "first K active" is invalid), and `init_wrapper_funcs_fixed` may substitute direct backend functions via `lookup_fall_through`. An active table therefore matches neither its template's address nor its entries pointer-for-pointer. The reusable architecture: observe successful factory calls that return tables, validate the exact returned table, normalize each target to its pinned executable object/offset, admit that actual target set, and retain candidate templates as unresolved inventory.

- [ ] **Step 1: Write the failing tests.** Nine cases, asserting exact target sets + workload counts (never just "≤4 tables survive"): no active wrappers; active index 17 with indices 0–3 free; five active wrappers; two processes using different indices of one inode; direct backend forwarding; allocation/free/reuse during capture; a table published before capture; an unknown p11-kit build; a non-p11-kit legacy static table.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement the ownership/provenance contract.** Gaps to close (all source-verified): `table_evidence_score` compares the returned address with the scanned template address (`scan.rs:705`) — a heap wrapper never matches; export lowering requires a usable file mapping (`engine.rs:5026–5036`); the selection path has a bounded exact-address reader (`engine.rs:9393–9469`) but admission requires table + all entries to belong to the provider (`:9252–9255`). Do NOT remove those guards — extend them with an explicit heap-wrapper/cross-object-target contract, kept separate from operator semantic authorization. Occupancy is process-local: union admitted targets across validated process views, preserve uncertainty for unscanned views. A free index may become occupied without a new mapping: needs a supported lifecycle/publication trigger or bounded revalidation with an explicit gap (loader events alone are insufficient); concurrent free/reuse degrades confidence rather than claiming proven absence. Add explicitly supported factory hooks where necessary.
- [ ] **Step 4: Run tests to verify they pass.** Count-only treatment retained unless the semantic-authorization contract is independently satisfied. Budget analysis required: cost the per-process heap-table read + 104 per-target maps resolutions + revalidation reads against the 512 MiB capture-wide I/O allowance, 16 Mi work ceiling, and per-operation caps — publication-driven admission must not trade slot exhaustion for budget exhaustion.
- [ ] **Step 5: Commit.** `feat: publication-driven admission for heap wrappers`

Deferred (option B, NOT Phase 1): a narrowly-scoped p11-kit occupancy adapter for startup coverage of already-running processes — recognized binary/build ID + ABI, occupancy array located via verified symbol/debug metadata or an explicit build-specific layout recipe, bounded reads with mapping/generation/pin validation. Hard constraints: filename/version strings are never sufficient identity; unknown layouts (including stripped binaries like the installed one, which exposes no `p11_virtual_fixed` symbol) fall back to generic uncertain discovery; a snapshot never proves future inactivity. Also forbidden: reading arbitrary heaps for "similar" structures, or calling into an observed provider to ask which wrappers are active.

### Phase 2 — uprobe_multi dual-path (collapses attach cost)

**Files:**
- Create: `crates/bpf-multi/` (vendored copy of `ossl-bpf-sys` + ported `bisect_attach`)
- Modify: `src/attach.rs` (~1237 loop regroup, ~2523 registry, ~2581 `Drop`), `Session::start_inner` (mixed loading), `src/run.rs:3997` + `scripts/check-capture-evidence.py:1975` (`attach_mechanisms`), `src/doctor.rs` (functional probe row)
- Test: lib unit tests + oracle updates + live matrix (6.9+ multi / 5.15 singles)

### Task 2.1: loader comparison spike (time-boxed)

Compare before committing — the vendored-helper choice is premature until the real object is tried:

- [ ] **Step 1: Candidate A — narrow Aya backport.** Investigate backporting multi-uprobe attach onto pinned Aya 0.14 (LEAD TO VERIFY: upstream Aya PR #1417, "add multi-uprobe attach support", reportedly merged 2026-07-31 — confirm content and applicability; do not assume a git-master upgrade is the only Aya option). Retains the existing ELF/BTF/relocation/map path; must still prove exact load flags, fallback, and tail-call compatibility.
- [ ] **Step 2: Candidate B — vendored raw helper.** Vendor `ossl-bpf-sys` (306 lines) as `crates/bpf-multi` with attribution header; wire as path dependency. Assert `cargo +1.88 metadata --locked --offline` still resolves. Note: raw loading takes ownership of relocation/BTF/program-fd correctness, and the sibling loader rejects BTF sections while p11scope has typed task storage, BTF, program arrays, and tail calls.
- [ ] **Step 3: Spike with the REAL object.** In `/tmp` (not the repo), load an actual p11scope BPF object (BTF/relocations, shared map IDs, frozen policy, both tail-call targets, default AND feature-safe objects) via each candidate and multi-link 68 offsets of one fixture `.so`; measure attach ms + fd count vs singles; verify raw-fd cleanup after every preparation failure. A trivial counting program does not test this integration. Decision: proceed with the winner if ≥5× fd reduction with identical events.
- [ ] **Step 4: Record** numbers + decision in `docs/notes/`. Commit vendor + note only if proceeding. Whichever wins, maintain the `third-party/sources.json` recipe, hashes, source-export closure, license attribution, offline resolution, and existing ring-reader correction.

### Task 2.2: mixed loading + regrouped attach

Follows FULL-multi.md reuse sketch steps 1–2 and 4–7 exactly (map freeze ordering, `PublishTailCalls` fd plumbing, `RegisteredLink::MultiUProbe`, `"multi"` mechanism value + golden updates, pid=0 + in-BPF `PID_FILTER`, doctor self-link row). Each sketch step is its own RED-then-GREEN task at execution time; oracles and goldens move with the code, never after. Keep dynamic loader/export probes on singles initially. Keep the 5.15 singles path and specifically qualified RHEL backports; multi stays an optional backend.

### Task 2.3: group retirement transaction (DECIDED: explicit group rebuild)

"Keep replaced slots on singles" is rejected as specified: leaving the old multi group attached while adding singles duplicates observations and executes a superseded decoder (`p11_entry_impl` has no per-slot generation gate; the pairing key carries task+slot, not attachment generation; a userspace deactivation does not revoke the kernel endpoint). The transaction is an explicit **group rebuild** (or demotion of the entire affected group to singles): (1) determine every affected member, retain exact pinned identities/program ownership; (2) detach old entries before returns; block additions on ownership uncertainty; (3) apply the existing conservative plan/semantic sync rules to ALL affected members and in-flight state — detach does not prove callback quiescence; (4) create replacement returns before entries; record exact success/failure + reactivation times for every member including unchanged siblings; (5) publish gaps and pairing uncertainty; subsequent calls must recover without pairing to stale starts. No overlapping make-before-break groups without a separately designed generation/dedup protocol. "Multi attached" requires every return/entry pair — no partial success.

### Phase 3 — event path + operator experience

- **Task 3.1: consumer scheduling repair (gates Phase 2).** Prime suspect with source-level mechanism: 256 KiB ring (~780 current-size records) drained on 1 s (profile) / 200 ms (trace) sleeps, 4096-record poll quantum, `EventDrain::poll`'s may-remain signal discarded by callers, discovery/plan-sync/reduction/snapshots/output all sharing the capture thread, trace writing synchronously per line. (a) Measure first: confirm loss shares (ring overflow vs cadence vs backpressure) with a counting harness — no blind knob turns. (b) Repair: readiness-driven draining (ringbuf adaptive notifications); on quantum exhaustion service cancellation/control work and drain again promptly; finite quanta + wall-time budgets for fairness; UI render + full aggregate-map reads on their own slower schedules; discovery on a separate bounded budget; buffered trace writes with an explicit slow-sink policy (a blocked pipe must not silently freeze draining — drop/refuse/terminate with explicit evidence, never silent sampling). Preserve discovery-before-semantic-consumption ordering; single ring consumer; queue overflow explicit, never an unbounded userspace queue. Acceptance: lossless inside a declared test envelope, explicit evidence outside it, cancellation responsive. Operator note: metrics mode (no ordinary call-event submission/reduction) is the recommended first system-inventory pass; profile for diagnosis, trace for bounded windows.
- **Task 3.1b: discovery scheduling.** Lifecycle/loader events enqueue bounded work + slower periodic reconciliation sweep (incremental cursor, generation revalidation, wall-time quantum, bounded pending queue); stop re-running the full over-cap maps sweep on ordinary ticks against the lifetime budget; fairness rotation among unscanned views without displacing authoritative provider evidence. Cache only stable file-derived facts. "All system" = all observable processes in the supported host/namespace config, with explicit coverage gaps.
- **Task 3.2: discovery-noise aggregation (S1).** Per-class summaries with counts (first full sample + `… ×N`), categorical. Assert exact class counts in tests; assert no PID leaks.
- **Task 3.3: output-sink validation before scan (F-Scale-6).** Move trust check ahead of discovery; test asserts exit-before-scan on untrusted dir.

### Phase 4 — re-evaluate, don't pre-build

- MAX_SLOTS resize only if Task 1.4 demands it.
- Stride suppression only if evidence-ordering leaves periodic false positives.
- Release-gate rows (kernel matrix incl. 5.15 singles + 6.9+ multi, container/SELinux lanes, bundle/receipt) once Phases 1–3 are green.

## Part 4 — Open questions, non-goals, live numbers

**Open:** (1) Exact K semantics for the unresolved-heuristic cap (4 proposed; Task 1.4 confirms against the oracle — coverage proof, not count). (2) Loss shares (Task 3.1 measures; scheduling mechanism is the prime suspect). (3) Whether `trace` should emit JSON lines instead of text (flagged, not decided). (4) Aya PR #1417 content/applicability (Task 2.1 verifies). (5) Public provenance schema/allowlist decision (aggregate counts + finite confidence categories preferred over raw addresses/PIDs). (6) Lifecycle/publication trigger mechanism for occupancy revalidation (Task 1.5 designs; loader events alone insufficient).
**Decided since v1:** Task 2.3 = explicit group rebuild (hybrid rejected); loader = compare Aya backport vs raw helper on the real object; Phase 2 gated on Tasks 1.4 + 3.1; K caps unresolved exploration only, corroborated surfaces bypass to the global budget.

**Acceptance matrix (operating envelope, not "works everywhere"):** publish supported kernel/backport policy, privileges, namespace visibility, and anonymous-code limits; keep Linux x86-64-first. Axes: processes (1/16/64/256/1024, same-inode vs versions vs mapping sets, short-lived, unreadable maps); providers/tables (1/4/8/32, shared targets, 64-template fixture with active index >3, five corroborated tables, runtime copy, never-called legacy); load (steady/burst, slow-HSM vs fast-software, threads, reentrancy, varied RVs — exact generated calls recorded); modes/sinks (metrics/profile/trace × terminal/discard/file/slow-pipe; ring bytes varied independently from drain/render cadence); lifetime (30 s → 5 min → churn; allocated-vs-active slots, semantic budgets, maps I/O, admission gaps); backends (forced singles vs forced multi on one capable kernel, auto fallback, both program objects); lifecycle/failure (long call across group replacement, poisoned offsets, entry/return-only failure, EMFILE/EPERM, exec/PID reuse, provider replacement, signal mid-scan/attach/detach, cleanup failure); environments (floor kernel, qualified RHEL 9 backports, 6.8, qualified modern multi kernel, host reference, container/SELinux/seccomp lanes when authorized). Collect per point: app throughput/latency vs unobserved, observer CPU/RSS/fds, scan bytes/work/cache hits, selected/admitted/refused providers+tables, active/allocated slots, queue occupancy + drain delay, attach/detach/publish time, kernel aggregate calls, userspace-reduced calls, every loss counter + resulting evidence. Bar: **zero unexplained loss inside the envelope**, accurate omissions outside it, bounded memory/work, no unintended semantic decoding, exact endpoint/count equivalence for backend comparisons. Throughput claims require a counting oracle — green exit, nonempty trace, positive attach count, or an unchanged PARTIAL verdict is insufficient (terminal capture stays conservatively PARTIAL: detach does not prove callback quiescence). Provisional targets (ratify by measurement): first progress <1 s, setup/shutdown within seconds on the reference desktop, cancellation/control <100 ms outside unavoidable kernel calls. Run noisy perf experiments separately from correctness gates; record exact command/revision/config/seed/reps/raw result; a green isolated retry never converts a red full run — preserve logs and compare the same signature on baseline without weakening assertions.

**Non-goals:** aya version bump (breaks offline story); session probes (rejected by siblings, fragile); per-file cross-process slot sharing (moot post-Phase-1); doctor fd row (moot post-raise); raising slots to paper over mis-admission.

**Live reference numbers (2026-09-19, this desktop, pre-Phase-1):** 416 slots planned; 832/832 probes post-fd-fix; 2 modules refused (6530/5762 wanted); 163–168 skipped; PARTIAL; 2620/1996 events lost; 89 s wall for 30 s profile (~9 s scan, ~40 s detach taper); ~380–514 stderr lines/run (231 ESRCH + 122 maps + 20 ENOENT + refusals). Per-PID baseline not yet captured.

## Self-review

- Spec coverage: every sysprobe finding (F-Scale-1..7) maps to an idea and a phase/task; the three FULL reports are all consumed (slot→Phase 1, multi→Phase 2, live→Phases 0/3 + numbers).
- Placeholder scan: no TBD/TODO/later; Phase 2.2 delegates to FULL-multi.md sketch steps (concrete, cited by file:line) rather than duplicating them; v2 amendments (deep-review corrections, loader comparison, group-rebuild decision, scheduling-first gating, acceptance matrix) are decided-and-recorded above, with remaining genuine unknowns (K semantics, loss shares, Aya PR lead, provenance schema) listed as open questions, not hidden.
- Type consistency: the only cross-task interface (`admit_tables` split) is flagged TBD-signature in Task 1.1 with consumers named — acceptable at plan stage since Task 1.1 lands first and later tasks adapt to it.

