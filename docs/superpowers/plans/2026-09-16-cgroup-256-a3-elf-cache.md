<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# cgroup-256 A3: identity-deduped ELF export facts (Task 5 blocker)

## Why this plan exists

Task 5's post-A2 scale-probe still shows `uniq_found=False`, 0 modules, PARTIAL.
Controller-measured per-charger breakdown of the 512 MiB attempted-I/O budget
(temporary `IoChargeSite` counters, since removed, tree clean at `abccfda`):

```
IO_DEBUG total=536870912 elf_snapshot=517249561 mountinfo=6276495 read_name=0
  read_mapping=5038080 maps_lines=6368816 engine_mem=0 identity_inspect=1937960
```

`read_elf_snapshot` burns 96.4% of the budget: the memory-scan path
(`scan_process_view_with_io_mode`, scan.rs:1697) re-reads every whole ELF per
mapped group per view. Fix A2's `inspected_files` cache covers only the
identity.rs pin path (`identity_inspect`=1.9 MB — the cache works where it
applies); the scan path never consults it.

## Global Constraints

- Branch is `refactor/extraction-rename`, worktree
  `.worktrees/refactor-extraction-rename`; never commit on main; never push.
- TDD red-green-refactor; gates `cargo +1.88 test --locked --workspace
  --all-targets`, `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy
  --locked --workspace --all-targets -- -D warnings`.
- No `sudo`, no timing/probe runs, no network: implementer runs unprivileged
  gates only. Scale proof stays controller-only (Task 5).
- No-misattribution guarantee holds: cache keys include the
  mountinfo-validated (device, inode) plus the `(ino, size, ctime)` pin — same
  path, different bytes across namespaces must never merge, and a file that
  changed mid-read is never cached.
- `docs/usage.md` needs no change (no user-visible behavior changes).

## File structure

- `src/discovery/scan.rs` — owns `CaptureWorkBudget`, `InspectedFileKey`
  (reused as the cache key), the new `ElfExportFacts` value + budget methods,
  and the lookup/record call site in `scan_process_view_with_io_mode`.
- `src/discovery/identity.rs` — `pin_of` becomes `pub(crate)` (one-line
  visibility change; `Pin` stays field-private).
- Tests: `src/discovery/scan.rs` tests module (mirror A2-Task-1's per-call
  delta assertions — mountinfo/maps reads also charge `attempted_io_bytes`).

## Task 1: cache ELF export facts per validated file identity

**Reference implementation (read completely before designing):**
`pin_scanned_object` (identity.rs:1572–1640): pin-before → lookup → re-pin
check on hit (zero reads) → read-with-budget on miss → re-pin check after
read (changed-mid-read errors, never cached) → cache only the stable read.
Mirror this shape exactly, including the too_large size gate before lookup.

**Controller-verified grounding (do not re-derive; verify while implementing):**

- (a) The scan path uses `ElfSnapshot` only for `abi()` (scan.rs:1941, 1958)
  and `exports_matching(&wanted)` (scan.rs:1942); offsets are dropped by the
  caller (`exports.into_iter().map(|(name, _)| name)`). The cached value
  `(ElfAbi, Vec<(String, u64)>)` is digest-sized and file-derived — safe to
  share cross-view. No per-view stamps involved (unlike A–C Task 1's
  `ScannedModule` trap).
- (b) `opened_file_identity_guard` (scan.rs:1361) validates the opened file's
  mountinfo-derived `(device, inode)` against the maps key before the snapshot
  read — the cache key's identity half is sound at the insertion point.
- (c) `wanted = request.hooks.names()` (scan.rs:1837); hooks come from
  `a.hooks.clone()` (engine.rs:3445). Step 1 must still prove `wanted` is
  identical across every scan call in one capture (see tripwire).

**Files:**

- Modify: `src/discovery/scan.rs` (`ElfExportFacts` struct near
  `InspectedFileKey` at line 243, `elf_export_facts: BTreeMap` field +
  `elf_export_facts_for`/`note_elf_export_facts` methods near
  `inspected_file` at 457, call site after the identity guard ~1936);
  `src/discovery/identity.rs` (`pin_of` visibility at ~line 37).
- Test: `src/discovery/scan.rs` tests module.

**Interfaces:**

- Consumes: `InspectedFileKey { device, inode, pin }` (unchanged, reused);
  `pin_of(&file)` (newly `pub(crate)`); `object_key` components from the
  already-validated `key: ObjectKey` at the call site.
- Produces: `pub(crate) struct ElfExportFacts { abi: ElfAbi, exports:
  Vec<(String, u64)> }` (derive `Debug, Clone, PartialEq, Eq`);
  `pub(crate) fn elf_export_facts_for(&self, key: &InspectedFileKey) ->
  Option<ElfExportFacts>`; `pub(crate) fn note_elf_export_facts(&mut self,
  key: InspectedFileKey, value: ElfExportFacts)`. Errors are never cached —
  a failed snapshot read keeps today's per-view behavior.

- [ ] **Step 1: Ground yourself + tripwire.** Read `pin_scanned_object`
  (identity.rs:1572–1640) completely. Trace `request.hooks` from engine.rs
  `a.hooks` through every `ScanRequest` construction site and PROVE `wanted`
  is identical for every scan call in one capture. **Tripwire:** if `wanted`
  can vary within a capture, STOP with NEEDS_CONTEXT — do not design around
  it; the controller will rule (fallback: cache the full dynsym export list).
  Also confirm the three `object.` uses (1941, 1942, 1958) are still the only
  ones. Report the trace in your report.
- [ ] **Step 2: Write the failing tests.** In the scan.rs tests module,
  mirroring A2-Task-1's delta-assertion pattern and fixtures:
  `second_view_of_same_file_reads_no_elf_bytes` — scan two views whose maps
  reference the same file; assert the second scan's `attempted_io_bytes`
  delta excludes any ELF-snapshot read (delta covers only maps/mountinfo —
  assert the delta is strictly less than the first scan's ELF bytes, and
  that both scans report identical abi + export names);
  `changed_file_rereads_elf` — same setup with the file rewritten
  (size-changing) between scans; assert the second scan reads ELF bytes
  again and reports the new exports. Expected RED: missing budget API
  (compile error), or the delta assertion fails showing the re-read.
- [ ] **Step 3: Run them to verify they fail.** `cargo +1.88 test --locked
  -p p11scope --lib elf_export_facts` + the two test names. If the delta
  assertion already passes, the test is wrong (re-reads happen today) —
  investigate before proceeding.
- [ ] **Step 4: Minimal implementation.** `pin_of` → `pub(crate)`; add
  `ElfExportFacts`, the budget field + two methods; insert the
  pin→lookup→(re-pin-check)→read→(re-pin-check)→record sequence at the scan
  call site, mirroring `pin_scanned_object` including the size gate. Nothing
  else: no signature changes, no new modules, no caching of errors.
- [ ] **Step 5: Focused tests.** The two new tests plus `cargo +1.88 test
  --locked -p p11scope --lib budget` and `-p p11scope --lib inspected`.
  Expected: PASS, pristine.
- [ ] **Step 6: Full suite, fmt, clippy.** Green, per Global Constraints.
  This is plan-mandated (A2-Task-3 lesson) — the review rejects
  `-p p11scope`-only evidence.
- [ ] **Step 7: Commit.** `git add` only touched files; `git commit -m
  "fix: read each unique ELF once per capture (scan path)"`.

## Self-review (controller, against the spec)

1. Spec coverage: the measured 96.4% burner (`elf_snapshot`) is cached with
   A2's exact key and stability discipline; mountinfo/maps/read_mapping
   remainder (~19 MB) fits the budget with headroom. No gaps.
2. Placeholder scan: no TBD/TODO; every step names exact files, line numbers,
   commands, and assertions. `wanted`-constancy is fenced behind a tripwire,
   not assumed.
3. Type consistency: `InspectedFileKey` reused unchanged; `ElfExportFacts`
   fixed here; `pin_of` visibility is the only identity.rs change.
