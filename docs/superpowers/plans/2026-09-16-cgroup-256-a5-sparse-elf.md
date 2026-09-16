# cgroup-256 A5: bounded ELF export-facts reads (Task 5 blocker)

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
groups tie at min-count 1 on this desktop.)

Fix: on the A3-cache MISS path only, read sparse export facts (ELF header +
program/section headers + `.dynsym` + `.dynstr`, KBs per file) instead of the
whole file. Projected total: ~100 MB worst case ≪ 512 MB. This also fixes the
user-reported libxul notice (184 MB file skipped by the 64 MB per-object
gate): sparse ranges are bounded by construction, so the whole-size gate is
removed on this path only.

## Global Constraints

- Branch is `refactor/extraction-rename`, worktree
  `.worktrees/refactor-extraction-rename`; never commit on main; never push.
- TDD red-green-refactor; gates `cargo +1.88 test --locked --workspace
  --all-targets`, `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy
  --locked --workspace --all-targets -- -D warnings`.
- No `sudo`, no timing/probe runs, no network: implementer runs unprivileged
  gates only. Scale proof stays controller-only (Task 5).
- No new dependencies. The `object` crate needs a contiguous image and cannot
  parse sparse ranges — hand-parse the fixed-layout tables (dynsym entries are
  24-byte LE64 / 16-byte LE32 records).
- Every range validated against the file size with checked arithmetic before
  reading; corrupt headers must error, never panic or over-read.
- `docs/usage.md`: document that provider export checks read only ELF tables
  (bounded), and that the per-object gate no longer applies to the export
  check (it still guards memory snapshots and identity hashing).

## File structure

- `crates/manifest/src/elf.rs` — new `read_export_facts_with` (+ thin
  `read_export_facts` wrapper mirroring the `ElfSnapshot::read` /
  `read_with_reader` pair); new unit tests in the crate's tests module.
- `src/discovery/scan.rs` — A3 miss path (~line 1920): call the sparse reader
  instead of `read_elf_snapshot`; remove the whole-size `too_large` gate on
  this path only (keep `read_elf_snapshot`'s own gate for its other callers);
  adapt/extend the A3 tests.
- Nothing else. `ElfSnapshot`, `read_elf_snapshot`, engine.rs loader callers,
  doctor/run offline callers: untouched.

## Task 1: sparse export-facts reads on the scan path

**API (frozen):**

```rust
// crates/manifest/src/elf.rs
pub fn read_export_facts_with(
    file: &std::fs::File,
    wanted: &[&str],
    budget: per-read charging reader callback, same shape as read_with_reader,
) -> Result<(ElfAbi, Vec<(String, u64)>), String>
```

Signature detail: mirror `read_with_reader`'s reader parameter exactly
(`impl FnMut(&File, &mut [u8], u64) -> io::Result<usize>`); the scan.rs
caller passes the same charging closure it uses today (ceiling errors
propagate as `IO_CEILING_REASON`, unchanged). The returned facts have
EXACTLY the semantics of `(object.abi(), object.exports_matching(wanted))`:
same abi mapping, same "defined + name in wanted + file-offset mapping"
rule, same `(name, file_offset)` pairs in the same order (dynsym order).

**Parser (frozen behavior):**

1. ELF header (64 B): validate magic/class/endianness/version; abi from
   class+machine with the EXACT error strings of `classified_object` for
   every rejection the scan path can hit (non-ELF, big-endian, exotic
   arch/class mismatch).
2. Program headers + section headers (validated counts/sizes; every offset
   checked against the file size from metadata).
3. Symbol table location, preferred order: (i) section headers when present
   (`.dynsym` size/entsize = exact count, `.dynstr` via `sh_link` — direct
   file offsets); (ii) otherwise `PT_DYNAMIC` (`DT_SYMTAB`/`DT_STRTAB`/
   `DT_STRSZ` are virtual addresses — translate via `PT_LOAD` exactly like
   `file_offset()`), count from `DT_HASH` (`nchain`) or `DT_GNU_HASH`
   (standard bucket/chain walk).
4. Walk entries: keep definitions (`shndx != SHN_UNDEF`, mirroring
   `symbol.is_definition()` for the dynamic-symbol cases the scan path
   hits) whose name is in `wanted`; map address → file offset with the
   `file_offset()` rule (delta < file_size, else skip the symbol, mirroring
   `exports_matching`'s `if let`).
5. Bound: the sum of all sparse ranges for one file must never exceed
   `per_object_bytes` (reuse the existing knob — no new constant); corrupt
   size claims that would exceed it error like any over-budget object.

**Controller-verified grounding (verify while implementing):**

- (a) All four probed real files (libc, softhsm, p11-kit-trust, libxul)
  carry BOTH section headers AND `PT_DYNAMIC`; softhsm/p11-kit/libxul use
  GNU_HASH only. Both parser paths are real; tests must cover the section
  path (real files), the dynamic+HASH path, and the dynamic+GNU_HASH-only
  path (synthetic fixtures).
- (b) The scan path consumes only `(abi, exports)` from the snapshot
  (verified for A3); offsets are cached but dropped by the caller — still
  compute them (cached-shape parity).
- (c) The `too_large` gate at scan.rs:~1893 guards ONLY the snapshot read on
  this path (downstream memory reads have their own `object_bytes` gate at
  ~1988 plus `allowed_io` clamping) — safe to remove here. `actual_size`
  stays (hint attribution uses it).
- (d) Ceiling behavior parity: the charging closure is unchanged, so
  mid-table ceiling errors surface exactly as today.

- [ ] **Step 1: Ground yourself + tripwire.** Read `classified_object`,
  `file_offset`, and `ElfSnapshot::exports_matching` (elf.rs) completely;
  enumerate EVERY error string the scan path can observe from
  `read_elf_snapshot` + `exports_matching` today (including
  `read_object_bytes_with` failures: non-file, over-`MAX_OBJECT_BYTES`,
  short reads) and every test that pins a scan-path ELF error message.
  **Tripwire:** if any scan-path error case cannot be reproduced with
  identical behavior by the sparse reader (same skip vs hard-error
  disposition — messages should match where tests pin them), STOP with
  NEEDS_CONTEXT. Report the error table in your report.
- [ ] **Step 2: Write the failing tests.** Crate tests (elf.rs tests
  module): section-path facts equal `ElfSnapshot::exports_matching` on
  real files (libc + a provider .so from the repo fixtures — oracle
  comparison, not hardcoded lists); dynamic+HASH and dynamic+GNU_HASH-only
  synthetic fixtures; corrupt-header cases (bad magic, truncated shdrs,
  dynsym past EOF, absurd counts) error without panic; over-`MAX_OBJECT_BYTES`
  short-circuit preserved. Scan tests: A3's two tests keep passing
  UNCHANGED (behavior parity — the cache still fills, hits still read
  zero); new `oversize_file_exports_are_checked_sparsely` — file larger
  than `per_object_bytes` with hook exports yields facts with charged
  bytes ≪ file size (the libxul regression test); new
  `sparse_read_charges_bounded_bytes` — first scan of a real provider
  charges < 1 MB of ELF reads (documents the bound). Expected RED:
  missing API (compile error).
- [ ] **Step 3: Run them to verify they fail.** `cargo +1.88 test --locked
  -p p11scope-manifest export_facts` and the scan test filters. If anything
  passes pre-implementation, the test is wrong — investigate.
- [ ] **Step 4: Minimal implementation.** The sparse reader + scan-path
  miss-path swap + gate removal on this path only. Nothing else: no
  `ElfSnapshot` changes, no engine/doctor/run changes, no new deps, no new
  knobs.
- [ ] **Step 5: Focused tests.** All new tests plus the A3 pair plus
  `cargo +1.88 test --locked -p p11scope-manifest` (whole crate).
  Expected: PASS, pristine.
- [ ] **Step 6: Full suite, fmt, clippy.** Green, per Global Constraints.
  Plan-mandated.
- [ ] **Step 7: Commit + docs.** `git add` only touched files +
  `docs/usage.md`; `git commit -m "fix: read ELF export tables sparsely on
  the scan path"`.

## Self-review (controller, against the spec)

1. Spec coverage: the measured 465 MB first-read burn becomes ~KBs/file;
   libxul-class files checkable (gate removed on this path); A3 cache
   semantics preserved (same facts shape, same stability discipline).
   Engine/doctor/run paths untouched (low volume, different needs). No gaps.
2. Placeholder scan: no TBD/TODO; every step names exact files, commands,
   and assertions. Error-behavior parity fenced behind a tripwire, not
   assumed. The sparse cap reuses `per_object_bytes` — no new knob to
   document or tune.
3. Type consistency: `(ElfAbi, Vec<(String, u64)>)` matches
   `ElfExportFacts` fields exactly; reader-callback shape reused from
   `read_with_reader`.
