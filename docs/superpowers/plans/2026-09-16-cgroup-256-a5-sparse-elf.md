# cgroup-256 A5: demand-paged ELF export-facts reads (Task 5 blocker)

## Why this plan exists

Post-A4 scale-probe still `uniq_found=False`. Controller measurement
(Task 5 round 4, temporary per-charger counters, since removed):

```
IO_DEBUG total=536870912 elf_snapshot=464896067 mountinfo=49733107 read_name=0
  read_mapping=10452992 maps_lines=8582594 engine_mem=0 identity_inspect=3206152
```

`elf_snapshot` still burns 465 MB — but A3 works (each file read once). The
host maps **837 distinct `.so` files totaling 640 MB**: the burn is
FIRST-read volume, not re-read waste. `read_object_bytes_with`
(`crates/manifest/src/identity.rs:241`) reads every file ENTIRELY just to
answer "does it export a hook symbol?" plus the ABI. (A4's order fix is kept:
harmless, principled, and load-bearing whenever any budget binds; it just
cannot beat 640 MB of inherent first-reads with mapping-count rarity — 40
sweep groups tie at min-count-1 on this desktop.)

RESEARCH OUTCOME (user-requested deep research, controller, 2026-09-16):
no hand parser. Every Rust ELF library (`object`, `goblin`, `elf`,
`xmas-elf`) is zero-copy over `&[u8]` — none reads sparsely by itself, but
all become demand-paged over `memmap2::Mmap` (derefs to `&[u8]`; the kernel
faults in only touched pages). The codebase already parses with `object`
0.39.1, so the sparse path reuses the SAME parser core over an mmap:
identical semantics (error strings, arch gating, offset math) with ~KBs
touched per file instead of whole-file reads. `goblin` et al. rejected as a
second parser (anti-DRY). `memmap2` 0.9.11 (sole dep: `libc`, already
present) added by the controller (commit `47707f3`, minimal lock diff,
1.88 locked offline build verified) — implementers have no network access.

Fix: on the A3-cache MISS path only, mmap the file and query `(abi,
exports)` through the existing `object`-based helpers instead of
whole-file `read_elf_snapshot`. Projected total: ~100 MB worst case ≪
512 MB. This also fixes the user-reported libxul notice (184 MB file
skipped by the 64 MB per-object gate): mmap cost is proportional to touched
pages, not file size, so the whole-size gate is removed on this path only.

## Global Constraints

- Branch is `refactor/extraction-rename`, worktree
  `.worktrees/refactor-extraction-rename`; never commit on main; never push.
- TDD red-green-refactor; gates `cargo +1.88 test --locked --workspace
  --all-targets`, `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy
  --locked --workspace --all-targets -- -D warnings`.
- No `sudo`, no timing/probe runs, no network: implementer runs unprivileged
  gates only (the `memmap2` crate is already in the lockfile and local
  registry — `--locked --offline` builds work). Scale proof stays
  controller-only (Task 5).
- No NEW dependencies beyond the controller-added `memmap2`; no hand-rolled
  ELF parsing (reuse the `object`-based helpers), no hand-rolled `mmap`
  (use `memmap2`).
- Every mmap failure maps to today's read-failure skip behavior (skip, never
  cached); a file truncated mid-parse must error, never panic. (Truncation
  between map and access is the same exposure class as the dynamic linker,
  which also mmaps libraries; the post-read pin check still detects change.)
- `docs/usage.md`: document that provider export checks read only ELF tables
  via demand paging (bounded), and that the per-object gate no longer
  applies to the export check (it still guards memory snapshots and identity
  hashing).

## File structure

- `crates/manifest/src/elf.rs` — new `read_export_facts` built on `Mmap` +
  the existing `object`-based helpers; new unit tests in the crate's tests.
- `src/discovery/scan.rs` — A3 miss path (~line 1920): call the new reader
  instead of `read_elf_snapshot`; remove the whole-size `too_large` gate on
  this path only (keep `read_elf_snapshot`'s own gate for its other
  callers); charge the returned byte count through the budget with ceiling
  parity (see below); adapt/extend the A3 tests.
- Nothing else. `ElfSnapshot`, `read_elf_snapshot`, engine.rs loader callers,
  doctor/run offline callers: untouched.

## Task 1: demand-paged export-facts reads on the scan path

**API (frozen):**

```rust
// crates/manifest/src/elf.rs
pub fn read_export_facts(
    file: &std::fs::File,
    wanted: &[&str],
) -> Result<(ElfAbi, Vec<(String, u64)>, u64 /* charged_bytes */), String>
```

Semantics: `mmap` the file; run the EXISTING query core
(`classified_object` for the abi, the `exports_matching` walk for the
pairs — refactor the method to share one core, do not duplicate the walk);
return the facts plus the structural byte count the query logically
consumed (ELF header + program headers + section headers + `.dynsym` +
`.dynstr` + dynamic table as applicable — computed from the parsed tables,
an honest lower bound any correct implementation must move). The returned
facts have EXACTLY the semantics of `(object.abi(),
object.exports_matching(wanted))`: same order (dynsym order), same
filtering, same offsets.

**Budget/ceiling parity (frozen):** the manifest crate has no budget type,
so scan.rs applies the charge: on success, if `charged_bytes` exceeds the
remaining capture budget the path pushes the IDENTICAL ceiling skip
today's mid-read abort produces and uses no facts (attempted_io saturates
as today); else `record_io(charged_bytes)` and proceed. Per-file charges
are ~KBs against a 512 MB budget, so post-hoc all-or-nothing per file is
observably equivalent to today's incremental gating — the reviewer
verifies this claim. Deadline checks inside the microsecond parse are
unnecessary (nothing to abort).

**Controller-verified grounding (verify while implementing):**

- (a) `object::File::parse(&[u8])` is the existing call shape
  (`classified_object`); `&Mmap[..]` satisfies it. `parse`,
  `file_offset`, `load_memory_contains` are already free functions over
  `&[u8]`-parsed images — composable without new parsing.
- (b) The scan path consumes only `(abi, exports)` from the snapshot
  (verified for A3); offsets are cached but dropped by the caller — still
  compute them (cached-shape parity) via the shared walk.
- (c) The `too_large` gate at scan.rs:~1893 guards ONLY the snapshot read
  on this path (downstream memory reads have their own `object_bytes` gate
  at ~1988 plus `allowed_io` clamping) — safe to remove here. `actual_size`
  stays (hint attribution uses it).
- (d) Mmap failure modes (unmappable fd, empty file, vanished path) must
  map to skip-class errors like today's read failures; Step 1 tables them.

- [ ] **Step 1: Ground yourself + tripwire.** Read `classified_object`,
  `file_offset`, and `ElfSnapshot::exports_matching` (elf.rs) completely;
  enumerate EVERY error string the scan path can observe from
  `read_elf_snapshot` + `exports_matching` today and every test that pins
  a scan-path ELF error message; table how each maps onto the mmap design
  (same string where the same helper raises it; mmap-raised failures take
  the read-failure skip shape). **Tripwire:** if any scan-path error case
  cannot be reproduced with identical skip-vs-hard-error disposition,
  STOP with NEEDS_CONTEXT. Report the error table in your report.
- [ ] **Step 2: Write the failing tests.** Crate tests: oracle comparison
  — `read_export_facts` equals `(abi, exports_matching)` from a
  whole-file `ElfSnapshot` on real files (libc, softhsm GNU_HASH-only,
  p11-kit-trust, plus a 32-bit fixture if the repo has one); corrupt
  inputs (bad magic, truncated headers, dynsym past EOF) error without
  panic; empty file errors in the read-failure skip shape; charged_bytes
  is small (< 1 MB) and nonzero on real files. Scan tests: A3's two tests
  keep passing UNCHANGED (behavior parity); new
  `oversize_file_exports_are_checked_sparsely` — file larger than
  `per_object_bytes` with hook exports yields facts with charged bytes ≪
  file size (the libxul regression test); new
  `sparse_read_charges_bounded_bytes` — first scan of a real provider
  charges < 1 MB of ELF reads. Expected RED: missing API (compile error).
- [ ] **Step 3: Run them to verify they fail.** `cargo +1.88 test --locked
  -p p11scope-manifest export_facts` and the scan test filters. If
  anything passes pre-implementation, the test is wrong — investigate.
- [ ] **Step 4: Minimal implementation.** The mmap reader + shared-walk
  refactor + scan-path miss-path swap + gate removal on this path only +
  post-hoc charge with ceiling parity. Nothing else: no `ElfSnapshot`
  behavior changes, no engine/doctor/run changes, no new deps, no new
  knobs.
- [ ] **Step 5: Focused tests.** All new tests plus the A3 pair plus
  `cargo +1.88 test --locked -p p11scope-manifest` (whole crate).
  Expected: PASS, pristine.
- [ ] **Step 6: Full suite, fmt, clippy.** Green, per Global Constraints.
  Plan-mandated.
- [ ] **Step 7: Commit + docs.** `git add` only touched files +
  `docs/usage.md`; `git commit -m "fix: read ELF export tables sparsely
  on the scan path"`.

## Self-review (controller, against the spec)

1. Spec coverage: the measured 465 MB first-read burn becomes ~KBs/file
   via the existing parser over mmap; libxul-class files checkable (gate
   removed on this path); A3 cache semantics preserved (same facts shape,
   same stability discipline). Engine/doctor/run paths untouched.
2. Placeholder scan: no TBD/TODO; every step names exact files, commands,
   and assertions. Error-behavior parity fenced behind a tripwire.
   No new knob: the charge reuses the existing byte budget.
3. Type consistency: `(ElfAbi, Vec<(String, u64)>, u64)` extends
   `ElfExportFacts` fields with the charge; no new public types beyond
   the function.
