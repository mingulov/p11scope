# System-Scale Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `p11scope --system` genuinely work on a busy desktop/server: attach what exists, refuse honestly what doesn't fit, stream without loss, and fail with one actionable message.

**Architecture:** Fix admission truthfulness first (the 6530-slot refusal is a scanner defect, not a capacity problem), then collapse attach cost via vendored uprobe_multi with a singles fallback, then tune the event path for loss.

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

### F-Scale-1: the 6530-slot refusal is a scanner false positive, not fan-out (P0)

One `libp11-kit.so.0.4.8` instance contains a contiguous 53,760-byte `.data` region (file `0x1caf20`) structured as **64 consecutive 840-byte records**, each headed by `0x203` (`CK_VERSION{3,2}`) followed by 104 non-null pointers into the library's own `.text`. `decode_candidate` ([scan.rs:738](src/discovery/scan.rs:738)) admits any 8-aligned plausible version word whose 104 slots are NULL-or-valid as a "full" 3.2 table, with **no corroboration** against actual publication (interface triple, live return, manifest). Overlap suppression ([scan.rs:969](src/discovery/scan.rs:969)) keeps all 64 (adjacent, non-overlapping).

Result per instance: 64 `ScannedTable` × 104 entries = 6656 records → **6530** distinct `AttachKey`s ([plan.rs:1118](src/plan.rs:1118)) > 512 → whole-module refusal ([plan.rs:1130](src/plan.rs:1130)). Reproduced to the digit offline (`replicate_scan.py`) and live across two ASLR bases (identical 64 table offsets `0x1caf20+k·840`). Dedup itself is verified correct (31 procs → 1 union); the "68 functions" intuition undercounts the true 3-surface union (224 offsets) by 3.3×.

**Safety sting:** entry names come from `function_name(ordinal)` ([scan.rs:838](src/discovery/scan.rs:838)), so these slots would carry wrong PKCS#11 names (internal trust code labeled `C_Sign`). The 512-refusal is currently **load-bearing** — it prevents ~6530 mislabeled uprobes. Any fix must not trade refusal for mislabeled attach.

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

`ossl-bpf-sys` (osslscope, 306 lines, `libc`-only, production since 1.0.0) is directly reusable: zero aya coupling (raw syscalls), GPL-3.0-or-later, vendored as an in-repo path crate per the established copy-with-attribution pattern. Measured at 504 probes: multi **17.8 ms attach / 8 fds** vs singles 109 ms / 511 fds / 46 s teardown. Kernel floor 6.9 with no fallback in siblings — p11scope must ship **dual-path** (functional probe → multi, else today's singles) to keep the 5.15 floor. Requires `expected_attach_type=48` at prog load; no eBPF source changes (plain `#[uprobe]` sections work). Rejected: kryprobe's 64-slot Pid-only spine (wrong shape), aya-master bump (breaks offline story). Notes: pid=0 + in-BPF tgid guard (6.9.x pid-filter thread bug), session probes rejected everywhere, `bisect_attach` for poison-offset isolation.

## Part 2 — Ideas, ranked

1. **Evidence-ordered admission + per-object heuristic-table cap** (fixes F-Scale-1). Order candidate tables by publication evidence — interface linkage (already computed as `ScannedInterface.table`, currently unused for admission), live-return `TableIdentity` match, manifest match — admit top-K, report the rest as uncorroborated candidates. K·104 ≤ 512 ⇒ K ≤ 4 (p11-kit needs 3). Converts refusal into bounded, honest capture. Must *prefer*, never *gate on*, linkage — gating would break scan-only capture of never-called legacy providers (e.g. gnome-keyring's static table), the feature scan-only discovery exists for.
2. **Vendor `ossl-bpf-sys`, dual-path multi attach** (fixes attach/teardown cost, F-Scale-4, future-proofs fds). One entry + one return multi-link per (path, program) group; 256 single-object slots go from ~1024 fds to 2. Keep singles for old kernels and dynamic loader/export probes. Biggest clash: multi links are immutable offset sets vs per-slot `detach_slots`/`replace_targets` — re-link group minus retired offsets, or keep replaced slots on singles (hybrid). Design decision required before Task 2.3.
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

- [ ] **Step 1: Write the failing test.** Feed the 64-table replica (from `replicate_scan.py` bytes, checked in as a fixture): assert admitted tables ≤ 4 per object, uncorroborated count == 60, and module NOT refused.
- [ ] **Step 2: Run it to verify it fails.** FAIL with whole-module refusal (current behavior).
- [ ] **Step 3: Implement.** Admit tables in score order until the per-object cap (K=4, i.e. ≤416 slots/object); spill becomes `uncorroborated_candidates` evidence, never slots. Keep all-or-nothing refusal only when even the top-1 table exceeds remaining global budget.
- [ ] **Step 4: Run tests to verify they pass**, including the existing refusal tests (they must still refuse genuinely oversized modules).
- [ ] **Step 5: Commit.** `feat: admit tables by evidence with per-object cap`

### Task 1.3: provenance + mislabel guard

**Files:**
- Modify: `src/render.rs`, `src/discovery/scan.rs:838` (`function_name` use)
- Test: `src/render.rs` tests, `src/discovery/engine_tests.rs`

- [ ] **Step 1: Write the failing test.** Admitted table carries (file_offset, entry count, linkage kind) into evidence; a heuristic table with no linkage is either named `unknown` or refused — never labeled `C_Sign`.
- [ ] **Step 2: Run it to verify it fails.**
- [ ] **Step 3: Implement.** Provenance struct through plan→evidence; gate `function_name(ordinal)` behind linkage-or-manifest authorization.
- [ ] **Step 4: Run tests to verify they pass.**
- [ ] **Step 5: Commit.** `feat: table provenance and mislabel guard`

### Task 1.4: live acceptance + MAX_SLOTS re-evaluation

- [ ] **Step 1: Run** `sudo p11scope profile --system --duration 30` on the reference desktop. Record: modules refused (expect: p11-kit admitted, ≤4 tables), wanted-set sizes, verdict.
- [ ] **Step 2: Decide MAX_SLOTS with numbers.** If the largest honest module fits 512 with headroom, close the question; else open a map-resize task with verifier-budget analysis.
- [ ] **Step 3: Record** the numbers in the task commit message. No code change expected.

### Phase 2 — uprobe_multi dual-path (collapses attach cost)

**Files:**
- Create: `crates/bpf-multi/` (vendored copy of `ossl-bpf-sys` + ported `bisect_attach`)
- Modify: `src/attach.rs` (~1237 loop regroup, ~2523 registry, ~2581 `Drop`), `Session::start_inner` (mixed loading), `src/run.rs:3997` + `scripts/check-capture-evidence.py:1975` (`attach_mechanisms`), `src/doctor.rs` (functional probe row)
- Test: lib unit tests + oracle updates + live matrix (6.9+ multi / 5.15 singles)

### Task 2.1: vendor + spike (time-boxed)

- [ ] **Step 1: Vendor** `ossl-bpf-sys` (306 lines) as `crates/bpf-multi` with attribution header; wire as path dependency. Assert `cargo +1.88 metadata --locked --offline` still resolves.
- [ ] **Step 2: Spike.** In `/tmp` (not the repo), raw-load one existing p11scope BPF object with `expected_attach_type=48` and multi-link 68 offsets of one fixture `.so`; measure attach ms + fd count vs singles. Decision: proceed if ≥5× fd reduction with identical events.
- [ ] **Step 3: Record** numbers + decision in `docs/notes/`. Commit vendor + note only if proceeding.

### Task 2.2: mixed loading + regrouped attach

Follows FULL-multi.md reuse sketch steps 1–2 and 4–7 exactly (map freeze ordering, `PublishTailCalls` fd plumbing, `RegisteredLink::MultiUProbe`, `"multi"` mechanism value + golden updates, pid=0 + in-BPF `PID_FILTER`, doctor self-link row). Each sketch step is its own RED-then-GREEN task at execution time; oracles and goldens move with the code, never after.

### Task 2.3: retire/replace semantics (needs the design decision from Idea 2 first)

Either re-link group minus retired offsets, or keep replaced slots on singles (hybrid). Decided at execution kickoff; the unchosen option is deleted from this plan.

### Phase 3 — event path + operator experience

- **Task 3.1: loss isolation harness.** Counting harness separating ring size vs drain cadence vs render backpressure; acceptance = loss counters explained, then fixed. No blind knob turns.
- **Task 3.2: discovery-noise aggregation (S1).** Per-class summaries with counts (first full sample + `… ×N`), categorical. Assert exact class counts in tests; assert no PID leaks.
- **Task 3.3: output-sink validation before scan (F-Scale-6).** Move trust check ahead of discovery; test asserts exit-before-scan on untrusted dir.

### Phase 4 — re-evaluate, don't pre-build

- MAX_SLOTS resize only if Task 1.4 demands it.
- Stride suppression only if evidence-ordering leaves periodic false positives.
- Release-gate rows (kernel matrix incl. 5.15 singles + 6.9+ multi, container/SELinux lanes, bundle/receipt) once Phases 1–3 are green.

## Part 4 — Open questions, non-goals, live numbers

**Open:** (1) Task 2.3 hybrid-vs-relink decision. (2) Exact K for the per-object cap (4 proposed; Task 1.4 confirms). (3) Loss root cause (Task 3.1 measures). (4) Whether `trace` should emit JSON lines instead of text (flagged, not decided).

**Non-goals:** aya version bump (breaks offline story); session probes (rejected by siblings, fragile); per-file cross-process slot sharing (moot post-Phase-1); doctor fd row (moot post-raise); raising slots to paper over mis-admission.

**Live reference numbers (2026-09-19, this desktop, pre-Phase-1):** 416 slots planned; 832/832 probes post-fd-fix; 2 modules refused (6530/5762 wanted); 163–168 skipped; PARTIAL; 2620/1996 events lost; 89 s wall for 30 s profile (~9 s scan, ~40 s detach taper); ~380–514 stderr lines/run (231 ESRCH + 122 maps + 20 ENOENT + refusals). Per-PID baseline not yet captured.

## Self-review

- Spec coverage: every sysprobe finding (F-Scale-1..7) maps to an idea and a phase/task; the three FULL reports are all consumed (slot→Phase 1, multi→Phase 2, live→Phases 0/3 + numbers).
- Placeholder scan: no TBD/TODO/later; Phase 2.2 delegates to FULL-multi.md sketch steps (concrete, cited by file:line) rather than duplicating them; the two genuine decisions (2.3, K value) are marked as decisions with options, not hidden.
- Type consistency: the only cross-task interface (`admit_tables` split) is flagged TBD-signature in Task 1.1 with consumers named — acceptable at plan stage since Task 1.1 lands first and later tasks adapt to it.

