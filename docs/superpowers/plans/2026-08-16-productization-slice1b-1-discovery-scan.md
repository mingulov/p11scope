# Productization Slice 1b-1 — Memory-Scan Discovery, `inspect`, `doctor` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Discover a target's PKCS#11 function tables by scanning its mapped memory — no manifest, no helper, no provider code executed — so `p11scope profile|trace --pid N` and `--cgroup PATH` work on their own, and add the two read-only operator commands (`inspect`, `doctor`) that explain what was found and what this host can do.

**Architecture:** A new `discovery::scan` reads `/proc/<pid>/maps`, filters objects whose `.dynsym` exports a hook-registry symbol, reads their non-executable mappings through `/proc/<pid>/mem`, and finds `CK_FUNCTION_LIST`/`CK_INTERFACE` structures by the version-word + code-pointer signature. Detected tables are decoded with the **same** `pkcs11-module` `tables_for`/`read_fn_pointers` machinery the offline helper uses, so scanned offsets equal manifest offsets by construction. Every discovered module is pinned by fd + SHA-256 (`discovery::identity`), merged into one `AttachPlan` with a global slot space, and attached by today's unchanged BPF object. Semantic state gains a module component so two modules in one process cannot collide.

**Non-goals (Slice 1b-2, the next plan):** BPF loader/export hooks and live discovery of modules loaded after attach, the `DESCRIPTORS`/attach-cookie + dynamic-slot refactor those require, `discovery::Engine`, `pause.rs`, `run -- cmd`, `attach_gap_ms`, mid-capture module-ambiguity purge (`state_reconciliations`). This slice scans **once, at attach time**; a module loaded later is not discovered, and the report says so.

**Tech Stack:** Rust 1.88, edition 2024, aya 0.14 (userspace only — the BPF object is untouched), `object` 0.39 (already in the tree via `p11scope-manifest`), `pkcs11-module` @ `a2aab6c`, `sha2`, `libc`, POSIX `sh`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md` — §4.1 (scan), §4.2 (elf), §4.5 (identity), §4.6 (CLI, `inspect`, `doctor`), §4.8 (evidence/schema v2), §4.9 (privileges), §4.10 (error handling), §4.12 (manifest corroboration), §4.13 (multi-module state), §5 (testing), §6 spikes 4 and 6, §8 (acceptance). The spec's §4.3, §4.4, §4.7 and spikes 1, 2, 3, 5 are Slice 1b-2.

## Global Constraints

- Rust 1.88, edition 2024, Linux x86-64 first (`CLAUDE.md`).
- All four checks green at every commit:
  `cargo +1.88 fmt --all -- --check`,
  `cargo +1.88 check --locked --workspace --all-targets`,
  `cargo +1.88 test --locked --workspace --all-targets`,
  `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings`.
- **No new external crates.** `object` and `sha2` are already in the lockfile via
  `p11scope-manifest`; all new ELF code goes **into that crate** so no new dependency edge is
  added to the root crate. No `clap`.
- **The eBPF object does not change in this slice.** `crates/ebpf/src/main.rs`,
  `crates/ebpf-common/src/lib.rs` and the frozen-policy publish/freeze order in `attach.rs`
  are untouched except where noted in Task 8 (attach path lookup by object key). If a task
  seems to need a BPF change, it belongs to Slice 1b-2 — stop and say so.
- Privacy allowlist (`docs/privacy/allowlist-v1.md`): capture output gains **no** new
  pointer-derived field. Interface **name bytes** never enter capture output; `inspect` and
  manifests may show the lossy name (they are discovery tools, not capture output — spec
  §4.3). Module `path`, `dev`, `ino`, `sha256`, `build_id` are added to output and must be
  added to the allowlist inventory in Task 15.
- Do not track generated output. Privileged/container experiments (`sudo`, docker, kind)
  require explicit owner approval; anything not run is recorded `UNRUN`/`PENDING`, never as
  green. Every script change is verified with `sh -n` and its `--self-test` where it has one.
- Manifest schema stays `p11scope-manifest/4`. Profile schema becomes
  `pkcs11-scope/observed-profile/v2` and `pkcs11-scope/observed-profile/v2-metrics`
  (breaking: `capture.module` → `capture.modules[]`).
- Scan bounds are hard: 64 MiB per object, 512 MiB per capture; anything larger is
  `skipped: too_large`, never truncated silently.
- Reuse, do not reimplement: `pkcs11_module::{tables_for, read_fn_pointers, Surface,
  TableSet, TableSpan}` for table layout, `p11scope_manifest::maps::{parse_maps, resolve}`
  for mappings, `p11scope_manifest::identity::{open_object, inspect_file, mapping_file_key}`
  for identity, `process.rs`'s existing pidfd/start-time logic for process pinning,
  `kinds::descriptor_slot` for semantics. A task that duplicates one of these is wrong.

---

## File map

| Path | Action | Responsibility after 1b-1 |
| --- | --- | --- |
| `docs/superpowers/plans/ROADMAP.md` | modify | records the 1b-1/1b-2 split and this slice's status (T1, T15) |
| `docs/notes/2026-08-16-slice1b-1-spikes.md` | create | measured `/proc` access matrix under Yama, `/proc/<pid>/root` identity findings (T2) |
| `crates/manifest/src/maps.rs` | modify | gains `ObjectKey`, `MappedPath`, `Resolved`, `resolve` (moved from discover) (T3) |
| `crates/manifest/src/elf.rs` | create | `exports_matching`, `symbol_file_offset`, ELF64/x86-64 refusal (T4) |
| `crates/manifest/src/lib.rs` | modify | `pub mod elf;` (T4) |
| `crates/discover/src/maps.rs` | modify | thin re-export of the moved types (T3) |
| `crates/discover/src/discover.rs` | modify | uses the shared `ObjectKey` (T3) |
| `src/discovery/hooks.rs` | create | `HookAbi`, `HookRegistry`, `--hook-symbol` parsing (T5) |
| `src/discovery/scan.rs` | create | `scan_pid` → `ScannedModule`s (T6) |
| `src/discovery/identity.rs` | modify | per-`ObjectKey` pins, `pin_scanned_objects`, keeps `pin_manifest_objects` (T7) |
| `src/process.rs` | modify | `PidPin` (pidfd/start-time), reusing the existing helpers (T7) |
| `src/plan.rs` | modify | `build_from_modules`, global slot space, shared-target ambiguity, capacity (T8) |
| `src/semantics.rs` | modify | session/op state keyed by `(process, module, handle)` (T9) |
| `src/inspect.rs` | create | `inspect --pid` rendering, text and `--json` (T10) |
| `src/doctor.rs` | create | host/target capability probes and verdict (T11) |
| `src/cli.rs` | modify | optional/repeatable `--module`/`--manifest`, `--hook-symbol`, `inspect`, `doctor` (T12) |
| `src/main.rs` | modify | scan → plan → attach wiring, manifest corroboration, new subcommands (T12) |
| `src/attach.rs` | modify | attach path lookup by `ObjectKey` (T8) |
| `src/render.rs` | modify | `discovery[]`, `authority`, new counters, `capture.modules[]`, schema v2 (T13) |
| `src/trace.rs` | modify | evidence line carries `authority` and the discovery counters (T13) |
| `docs/schema/observed-profile-v1.md` → `-v2.md` | rename+modify | v2 with a v1.4 → v2 migration section (T13) |
| `scripts/check-capture-evidence.py` | modify | v2 schema, `modules[]`, discovery counters (T13, T14) |
| `scripts/verify-attach-e2e.sh` | modify | manifest-free lane + manifest-corroboration lane (T14) |
| `scripts/verify-inspect-doctor.sh` | create | unprivileged `inspect`/`doctor` contract lane (T14) |
| `scripts/matrix/verify-proxy-stack.sh` | create | p11-kit proxy + SoftHSM2 in one process, two modules (T14) |
| `scripts/attach-pod.sh` | create | rewritten on the new CLI, nothing copied into the container (T14) |
| `scripts/matrix/*.sh`, `scripts/gates.sh` | modify | new CLI, no `--manifest` where the scan suffices (T14) |
| `.github/workflows/ci.yml` | modify | adds the unprivileged inspect/doctor lane (T14) |
| `tests/discovery_scan.rs` | create | scan-vs-helper oracle, negatives, bounds (T6) |
| `tests/multi_module.rs` | create | colliding handles, shared attach target (T8, T9) |
| `tests/artifact_contracts.rs` | modify | script/CLI contract updates (T14) |
| `README.md`, `docs/usage.md`, `docs/privacy/allowlist-v1.md`, `CHANGELOG.md` | modify | manifest-free default, new commands, privilege table (T15) |

## Model guidance for subagent execution

| Tasks | Model | Why |
| --- | --- | --- |
| T6, T7, T8, T9, T13 | Opus | Memory-scan correctness, identity/PID-reuse boundaries, slot-space invariants, state-key migration, schema contract |
| T1, T2, T3, T4, T5, T10, T11, T12, T14, T15 | Sonnet | Mechanical moves, pure parsers, rendering, scripts, docs |

---

## Task 1: ROADMAP records the 1b-1 / 1b-2 split

**Files:**
- Modify: `docs/superpowers/plans/ROADMAP.md:392` (the "Slice 1b" bullet)

**Interfaces:**
- Consumes: nothing.
- Produces: the status line every later task appends to (T15 finalises it).

- [ ] **Step 1: Replace the single Slice 1b bullet**

Replace the existing bullet:

```markdown
- **Slice 1b — discovery engine and commands**: memory-scan + loader/export-hook discovery,
  `run`, `inspect`, `doctor`, `--module` optional, schema v2. Plan written after 1a lands.
```

with:

```markdown
- **Slice 1b — discovery engine and commands.** Split in two independently shippable plans
  when 1a landed (2026-08-16), because the memory scan needs no BPF change while the live
  hooks need the attach-cookie/dynamic-slot refactor:
  - **Slice 1b-1 — memory-scan discovery, `inspect`, `doctor`**
    ([plan](2026-08-16-productization-slice1b-1-discovery-scan.md)): scan the target's
    mappings for `CK_FUNCTION_LIST`/`CK_INTERFACE`, pin and attach without a manifest or the
    helper, multi-module plans and per-module semantic state, `--module`/`--manifest`
    optional, evidence `discovery[]`/`authority`, schema v2. The eBPF object is unchanged.
    Scanning happens once at attach time; a module loaded later is not discovered (1b-2).
    **Status: IN PROGRESS (started 2026-08-16).**
  - **Slice 1b-2 — live discovery and `run`**: BPF loader (`_dl_debug_state`) and export
    uretprobes, `DESCRIPTORS` + attach-cookie semantics with dynamic slot allocation,
    `discovery::Engine`, `pause.rs`, `run -- cmd`, `attach_gap_ms`, mid-capture
    module-ambiguity purge. Plan written after 1b-1 lands.
```

- [ ] **Step 2: Verify the document still reads correctly**

Run: `grep -n "Slice 1b" docs/superpowers/plans/ROADMAP.md`
Expected: the two sub-bullets appear, no other "Slice 1b" line survives.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/ROADMAP.md docs/superpowers/plans/2026-08-16-productization-slice1b-1-discovery-scan.md
git commit -m "docs: ROADMAP — slice 1b split into 1b-1 (memory scan) and 1b-2 (live discovery)"
```

---

## Task 2: Spikes — measured `/proc` access matrix (spec §6.6 and the unprivileged half of §6.4)

**Files:**
- Create: `docs/notes/2026-08-16-slice1b-1-spikes.md`
- Create: `tests/proc_access.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: the documented answers Task 6 and Task 11 cite — whether `maps` is readable and
  `mem` refused for a same-uid non-descendant under Yama `ptrace_scope=1`, and whether
  `/proc/<pid>/root/<path>` + `mapping_file_key` agree on this host's filesystem.

**Why a test, not a one-off measurement:** the answers gate `scan_pid`'s fallback behaviour.
A committed test keeps the claim honest on any host CI runs on, and skips (loudly) where the
precondition does not hold.

- [ ] **Step 1: Write the probe test**

Create `tests/proc_access.rs`:

```rust
//! Measures the /proc access rules the scan depends on (spec §4.9, §6.6). Each test
//! states its precondition and SKIPs loudly rather than asserting a policy the host
//! does not have — the point is a recorded measurement, not a forced pass.

use std::io::Read as _;
use std::process::{Child, Command};

fn ptrace_scope() -> i32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse().unwrap_or(0))
        .unwrap_or(0)
}

/// A same-uid process that is NOT our descendant: spawn `sleep` from a
/// double-fork through `setsid` so it is reparented to init.
fn same_uid_non_descendant() -> (u32, Child) {
    let child = Command::new("setsid")
        .args(["--fork", "sleep", "30"])
        .spawn()
        .expect("spawn setsid sleep");
    // setsid --fork exits immediately; its grandchild survives, reparented.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let out = Command::new("pgrep").args(["-n", "-x", "sleep"]).output().unwrap();
    let pid: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().expect("pgrep sleep pid");
    (pid, child)
}

#[test]
fn maps_is_readable_and_mem_is_refused_for_a_same_uid_non_descendant() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("SKIP: running as root; Yama does not apply");
        return;
    }
    let (pid, mut spawner) = same_uid_non_descendant();
    let _ = spawner.wait();

    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"));
    assert!(maps.is_ok(), "/proc/{pid}/maps must be readable (PTRACE_MODE_READ): {maps:?}");

    let mem = std::fs::File::open(format!("/proc/{pid}/mem"))
        .and_then(|mut f| { let mut b = [0u8; 1]; f.read_exact(&mut b) });
    if ptrace_scope() >= 1 {
        assert!(mem.is_err(), "ptrace_scope={} must refuse mem for a non-descendant", ptrace_scope());
    } else {
        eprintln!("MEASURED: ptrace_scope=0, mem access allowed: {:?}", mem.is_ok());
    }
    let _ = Command::new("kill").arg(pid.to_string()).status();
}

#[test]
fn self_mem_is_always_readable_and_agrees_with_maps() {
    // The scan's unprivileged test path: read our own mapped bytes and confirm
    // they match what the mapping says is there.
    let maps = std::fs::read(format!("/proc/self/maps")).unwrap();
    let entries = p11scope_manifest::maps::parse_maps(&maps).unwrap();
    let exe = entries
        .iter()
        .find(|e| e.permissions[2] == b'x' && e.inode != 0)
        .expect("an executable file-backed mapping");
    let mut file = std::fs::File::open("/proc/self/mem").expect("/proc/self/mem");
    let mut buf = [0u8; 4];
    std::os::unix::fs::FileExt::read_exact_at(&mut file, &mut buf, exe.start)
        .expect("pread of our own executable mapping");
    eprintln!("MEASURED: first 4 bytes of {:?} = {buf:02x?}", exe.raw_path);
}

#[test]
fn proc_root_path_opens_the_same_inode_the_mapping_names() {
    let maps = std::fs::read("/proc/self/maps").unwrap();
    let entries = p11scope_manifest::maps::parse_maps(&maps).unwrap();
    let exe = entries
        .iter()
        .find(|e| e.permissions[2] == b'x' && e.inode != 0 && e.raw_path.as_deref().is_some_and(|p| p.starts_with(b"/")))
        .expect("an executable file-backed mapping");
    let path = String::from_utf8(exe.raw_path.clone().unwrap()).unwrap();
    let via_root = format!("/proc/self/root{path}");
    let file = p11scope_manifest::identity::open_object(std::path::Path::new(&via_root))
        .expect("open through /proc/self/root");
    let key = p11scope_manifest::identity::mapping_file_key(&file);
    match key {
        Ok(key) => {
            assert_eq!(key.inode, exe.inode, "inode via /proc/self/root must match the mapping");
            assert_eq!(
                (key.device_major, key.device_minor),
                (exe.device.major, exe.device.minor),
                "mountinfo-derived device must match the mapping's device"
            );
        }
        Err(error) => eprintln!("MEASURED: mapping_file_key unavailable on this filesystem: {error}"),
    }
}
```

- [ ] **Step 2: Run the probes and record what they print**

Run: `cargo +1.88 test --locked --test proc_access -- --nocapture`
Expected: PASS on this host (`ptrace_scope=1`), with the `MEASURED:` lines visible.

- [ ] **Step 3: Write the findings note**

Create `docs/notes/2026-08-16-slice1b-1-spikes.md` with the **actual** observed values from
Step 2 (kernel release from `uname -r`, `ptrace_scope`, `perf_event_paranoid`, whether
`mapping_file_key` resolved), plus this table filled from the run:

```markdown
# Slice 1b-1 spikes — measured /proc access (spec §6.4 unprivileged half, §6.6)

Host: <uname -r>, glibc <ldd --version>, ptrace_scope=<n>, perf_event_paranoid=<n>.

| Question | Answer | Evidence |
| --- | --- | --- |
| `/proc/<pid>/maps` for a same-uid non-descendant | <readable/refused> | `tests/proc_access.rs::maps_is_readable_and_mem_is_refused_for_a_same_uid_non_descendant` |
| `/proc/<pid>/mem` for the same target under `ptrace_scope=1` | <refused/allowed> | same test |
| `/proc/self/root/<path>` opens the mapped inode | <yes/no> | `tests/proc_access.rs::proc_root_path_opens_the_same_inode_the_mapping_names` |
| `mapping_file_key` resolves on this filesystem | <yes/no + fs type> | same test |

**Consequence for `scan_pid` (Task 6):** when `/proc/<pid>/mem` is refused the scan reports
`unavailable: ptrace` and the capture continues with whatever other source it has, per spec
§4.1 step 3 — it is never fatal.

**Not answered here (root/docker-gated, spec §6.4 second half):** whether
`mapping_file_key` agrees with the mapping device on overlay2 and btrfs. Recorded UNRUN;
Task 14's docker lane answers it under owner approval.
```

- [ ] **Step 4: Commit**

```bash
git add tests/proc_access.rs docs/notes/2026-08-16-slice1b-1-spikes.md
git commit -m "test/docs: measured /proc access matrix for the memory scan (Yama, /proc/pid/root identity)"
```

---

## Task 3: Share `resolve` and one `ObjectKey` in `p11scope-manifest::maps`

**Files:**
- Modify: `crates/manifest/src/maps.rs`
- Modify: `crates/discover/src/maps.rs`
- Modify: `crates/discover/src/discover.rs` (its private `ObjectKey` and `map_key` go)

**Interfaces:**
- Consumes: existing `parse_maps`, `MapEntry`, `Device`.
- Produces:

```rust
// crates/manifest/src/maps.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectKey { pub device: Device, pub inode: u64 }
impl ObjectKey { pub fn of(entry: &MapEntry) -> Self; }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedPath { Usable(std::path::PathBuf), Unusable { reason: String } }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    File { path: MappedPath, raw_path: Vec<u8>, file_offset: u64, device: Device, inode: u64, permissions: [u8; 4] },
    Anonymous,
    Unmapped,
}
pub fn resolve(maps: &[MapEntry], vaddr: u64) -> Resolved;
```

**Why:** spec §4.1 step 5 — "moved into `manifest::maps` so both binaries share it". The
observer must resolve pointers exactly the way the helper does, and one `ObjectKey`
definition prevents the two from drifting.

- [ ] **Step 1: Move the code**

Move `MappedPath`, `Resolved`, `mapped_path`, `resolve` and their four unit tests verbatim
from `crates/discover/src/maps.rs` into `crates/manifest/src/maps.rs`. Add `ObjectKey` with:

```rust
impl ObjectKey {
    pub fn of(entry: &MapEntry) -> Self {
        Self { device: entry.device, inode: entry.inode }
    }
}
```

`std::path::PathBuf` is available without a feature gate; keep `resolve` outside any
`#[cfg(feature = "identify")]` block so `p11scope-discover` and `p11scope` both see it.

- [ ] **Step 2: Reduce `crates/discover/src/maps.rs` to a re-export**

```rust
//! /proc/<pid>/maps parsing and vaddr → ELF-file-offset resolution now live in
//! `p11scope-manifest::maps` so the observer resolves pointers exactly as this
//! helper does (spec §4.1 step 5).

pub use p11scope_manifest::maps::{Device, MapEntry, MappedPath, ObjectKey, Resolved, parse_maps, resolve};
```

- [ ] **Step 3: Delete discover's private `ObjectKey`**

In `crates/discover/src/discover.rs` delete the local `struct ObjectKey` and `fn map_key`,
add `ObjectKey` to the `use crate::maps::{...}` list, and replace every `map_key(entry)`
call with `ObjectKey::of(entry)`. The struct field names (`device`, `inode`) are identical,
so no other change is needed.

- [ ] **Step 4: Run the checks**

Run: `cargo +1.88 test --locked --workspace --all-targets`
Expected: PASS — the moved tests run from the manifest crate now; discover's tests still pass.

- [ ] **Step 5: Commit**

```bash
git add crates/manifest/src/maps.rs crates/discover/src/maps.rs crates/discover/src/discover.rs
git commit -m "refactor: share maps::resolve and one ObjectKey from p11scope-manifest"
```

---

## Task 4: `p11scope-manifest::elf` — registry-restricted exports and symbol offsets

**Files:**
- Create: `crates/manifest/src/elf.rs`
- Modify: `crates/manifest/src/lib.rs`
- Test: `crates/manifest/tests/elf.rs`

**Interfaces:**
- Consumes: `object` (already a dependency behind the `identify` feature),
  `identity::read_object_bytes` (make it `pub(crate)`).
- Produces:

```rust
/// Names from `wanted` that the object exports in .dynsym, with their file offsets.
/// Offsets are ELF object-file byte offsets — the same domain as manifest offsets
/// and `UProbeAttachLocation::AbsoluteOffset` (docs/notes/aya-offset-semantics.md).
pub fn exports_matching(file: &std::fs::File, wanted: &[&str]) -> Result<Vec<(String, u64)>, String>;

/// File offset of one exported symbol, or `Ok(None)` when it is not exported.
pub fn symbol_file_offset(file: &std::fs::File, name: &str) -> Result<Option<u64>, String>;
```

**Why the file, not the process:** exports are a property of the object's bytes. Reading them
through the pinned fd means the answer cannot be changed by the target after we pinned it.

- [ ] **Step 1: Write the failing test**

Create `crates/manifest/tests/elf.rs`:

```rust
use p11scope_manifest::elf::{exports_matching, symbol_file_offset};
use std::path::{Path, PathBuf};
use std::process::Command;

fn cc_so(dir: &Path, name: &str, source: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let c = dir.join(format!("{name}.c"));
    let so = dir.join(format!("{name}.so"));
    std::fs::write(&c, source).unwrap();
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&c)
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc failed for {name}");
    so
}

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const REGISTRY: &[&str] = &[
    "C_GetFunctionList",
    "C_GetInterfaceList",
    "C_GetInterface",
    "NSC_GetFunctionList",
    "FC_GetFunctionList",
];

#[test]
fn only_registry_exports_are_reported_with_usable_offsets() {
    let d = tmp("elf-exports");
    let so = cc_so(
        &d,
        "provider",
        "unsigned long C_GetFunctionList(void **p){(void)p;return 0;}\n\
         unsigned long NSC_GetFunctionList(void **p){(void)p;return 0;}\n\
         unsigned long some_other_symbol(void){return 7;}\n",
    );
    let file = p11scope_manifest::identity::open_object(&so).unwrap();
    let mut found = exports_matching(&file, REGISTRY).unwrap();
    found.sort();
    let names: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["C_GetFunctionList", "NSC_GetFunctionList"]);

    // Every reported offset must land inside an executable segment — the same
    // property manifest offsets must satisfy.
    let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
    for (name, offset) in &found {
        assert!(
            inspected.contains_executable_offset(*offset),
            "{name} offset {offset:#x} is outside every executable segment"
        );
    }
    assert_eq!(symbol_file_offset(&file, "some_other_symbol").unwrap().is_some(), true);
    assert_eq!(symbol_file_offset(&file, "C_NotThere").unwrap(), None);
}

#[test]
fn a_table_less_object_reports_no_registry_exports() {
    let d = tmp("elf-empty");
    let so = cc_so(&d, "plain", "int unrelated(void){return 1;}\n");
    let file = p11scope_manifest::identity::open_object(&so).unwrap();
    assert!(exports_matching(&file, REGISTRY).unwrap().is_empty());
}

#[test]
fn non_elf_and_foreign_class_are_refused_with_a_named_reason() {
    let d = tmp("elf-refuse");
    let text = d.join("not-an-elf.so");
    std::fs::write(&text, b"#!/bin/sh\necho hi\n").unwrap();
    let file = p11scope_manifest::identity::open_object(&text).unwrap();
    let error = exports_matching(&file, REGISTRY).unwrap_err();
    assert!(error.contains("ELF"), "{error}");

    // 32-bit is a named refusal, not a misread (spec §4.2): build one if the
    // multilib compiler is available, otherwise state that it was not covered.
    let ok = Command::new("gcc")
        .args(["-m32", "-shared", "-fPIC", "-o"])
        .arg(d.join("m32.so"))
        .arg("-x")
        .arg("c")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write as _;
            c.stdin.as_mut().unwrap().write_all(b"unsigned long C_GetFunctionList(void**p){(void)p;return 0;}\n")?;
            c.wait()
        })
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: no -m32 toolchain; ELFCLASS32 refusal not covered on this host");
        return;
    }
    let file = p11scope_manifest::identity::open_object(&d.join("m32.so")).unwrap();
    let error = exports_matching(&file, REGISTRY).unwrap_err();
    assert!(error.contains("x86-64") || error.contains("64-bit"), "{error}");
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo +1.88 test --locked -p p11scope-manifest --test elf`
Expected: FAIL — `unresolved import p11scope_manifest::elf`.

- [ ] **Step 3: Implement `crates/manifest/src/elf.rs`**

```rust
//! ELF facts the observer needs about an object's *bytes*: which registry symbols it
//! exports and where they live as file offsets. Offsets are ELF object-file byte
//! offsets (docs/notes/aya-offset-semantics.md) — the same domain manifest records use,
//! so a scanned offset and a manifest offset are directly comparable.

use crate::identity::read_object_bytes;
use object::{Architecture, BinaryFormat, Object as _, ObjectSegment as _, ObjectSymbol as _};

fn parse(data: &[u8]) -> Result<object::File<'_>, String> {
    let object = object::File::parse(data)
        .map_err(|error| format!("not parseable as an object file: {error}"))?;
    if object.format() != BinaryFormat::Elf {
        return Err(format!("not an ELF object ({:?})", object.format()));
    }
    if !object.is_64() || object.architecture() != Architecture::X86_64 {
        return Err(format!(
            "not a 64-bit x86-64 ELF object (architecture {:?}); 32-bit and foreign \
             architectures are recorded as skipped, never misread",
            object.architecture()
        ));
    }
    Ok(object)
}

/// A virtual address inside a PT_LOAD segment → its byte offset in the file.
fn file_offset(object: &object::File<'_>, address: u64) -> Option<u64> {
    object.segments().find_map(|segment| {
        let start = segment.address();
        let end = start.checked_add(segment.size())?;
        if !(start..end).contains(&address) {
            return None;
        }
        let (file_start, file_size) = segment.file_range();
        let delta = address - start;
        (delta < file_size).then(|| file_start + delta)
    })
}

pub fn exports_matching(file: &std::fs::File, wanted: &[&str]) -> Result<Vec<(String, u64)>, String> {
    let data = read_object_bytes(file)?;
    let object = parse(&data)?;
    let mut found = Vec::new();
    for symbol in object.dynamic_symbols() {
        let Ok(name) = symbol.name() else { continue };
        if !wanted.contains(&name) || symbol.address() == 0 {
            continue;
        }
        if let Some(offset) = file_offset(&object, symbol.address()) {
            found.push((name.to_string(), offset));
        }
    }
    Ok(found)
}

pub fn symbol_file_offset(file: &std::fs::File, name: &str) -> Result<Option<u64>, String> {
    let data = read_object_bytes(file)?;
    let object = parse(&data)?;
    Ok(object
        .dynamic_symbols()
        .chain(object.symbols())
        .filter(|symbol| symbol.name() == Ok(name) && symbol.address() != 0)
        .find_map(|symbol| file_offset(&object, symbol.address())))
}
```

In `crates/manifest/src/identity.rs` change `fn read_object_bytes` to
`pub(crate) fn read_object_bytes`. In `crates/manifest/src/lib.rs` add, next to the existing
gated modules:

```rust
#[cfg(feature = "identify")]
pub mod elf;
```

Add to `crates/manifest/Cargo.toml`:

```toml
[[test]]
name = "elf"
required-features = ["identify"]
```

- [ ] **Step 4: Run the tests**

Run: `cargo +1.88 test --locked -p p11scope-manifest --features identify --test elf`
Expected: PASS (the `-m32` case may print SKIP).

- [ ] **Step 5: Run the full checks and commit**

```bash
cargo +1.88 fmt --all -- --check && cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
git add crates/manifest/src/elf.rs crates/manifest/src/lib.rs crates/manifest/src/identity.rs crates/manifest/Cargo.toml crates/manifest/tests/elf.rs
git commit -m "feat(manifest): elf — registry-restricted exports and symbol file offsets"
```

---

## Task 5: `discovery::hooks` — the hook registry and `--hook-symbol`

**Files:**
- Create: `src/discovery/hooks.rs`
- Modify: `src/discovery/mod.rs`

**Interfaces:**
- Consumes: nothing (pure).
- Produces:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAbi { FunctionList, InterfaceList, Interface }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRegistry { entries: Vec<(String, HookAbi)> }

impl HookRegistry {
    /// The five built-ins (spec §2): C_GetFunctionList, C_GetInterfaceList,
    /// C_GetInterface, NSC_GetFunctionList, FC_GetFunctionList.
    pub fn builtin() -> Self;
    /// `NAME`, `NAME:functionlist`, `NAME:interfacelist`, `NAME:interface`.
    /// Default ABI is `functionlist`. Duplicate names replace the earlier ABI.
    pub fn add_spec(&mut self, spec: &str) -> Result<(), String>;
    pub fn names(&self) -> Vec<&str>;
    pub fn abi(&self, name: &str) -> Option<HookAbi>;
}
```

**Why its own module:** which symbols matter is p11scope policy (extensible by the operator);
how to read them out of an ELF file is a mechanical fact (Task 4). Splitting them keeps the
manifest crate free of policy and gives `--hook-symbol` one place to be validated.

- [ ] **Step 1: Write the failing test (inline `#[cfg(test)]` module)**

Append to `src/discovery/hooks.rs` as you create it:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_is_the_five_documented_names() {
        let r = HookRegistry::builtin();
        let mut names = r.names();
        names.sort();
        assert_eq!(
            names,
            vec![
                "C_GetFunctionList",
                "C_GetInterface",
                "C_GetInterfaceList",
                "FC_GetFunctionList",
                "NSC_GetFunctionList",
            ]
        );
        assert_eq!(r.abi("C_GetFunctionList"), Some(HookAbi::FunctionList));
        assert_eq!(r.abi("C_GetInterfaceList"), Some(HookAbi::InterfaceList));
        assert_eq!(r.abi("C_GetInterface"), Some(HookAbi::Interface));
        assert_eq!(r.abi("NSC_GetFunctionList"), Some(HookAbi::FunctionList));
        assert_eq!(r.abi("nope"), None);
    }

    #[test]
    fn hook_symbol_specs_default_to_functionlist_and_accept_every_abi() {
        let mut r = HookRegistry::builtin();
        r.add_spec("V_GetTable").unwrap();
        assert_eq!(r.abi("V_GetTable"), Some(HookAbi::FunctionList));
        r.add_spec("V_List:interfacelist").unwrap();
        assert_eq!(r.abi("V_List"), Some(HookAbi::InterfaceList));
        r.add_spec("V_One:interface").unwrap();
        assert_eq!(r.abi("V_One"), Some(HookAbi::Interface));
        // A repeat replaces the ABI rather than duplicating the name.
        r.add_spec("V_GetTable:interface").unwrap();
        assert_eq!(r.abi("V_GetTable"), Some(HookAbi::Interface));
        assert_eq!(r.names().iter().filter(|n| **n == "V_GetTable").count(), 1);
    }

    #[test]
    fn malformed_hook_specs_are_refused_with_the_reason() {
        let mut r = HookRegistry::builtin();
        for bad in ["", ":", ":interface", "V_X:", "V_X:bogus", "V_X:interface:extra"] {
            let error = r.add_spec(bad).unwrap_err();
            assert!(!error.is_empty(), "{bad:?} must be refused with a reason");
        }
        // A name with a NUL or whitespace could never be an ELF symbol.
        assert!(r.add_spec("has space").is_err());
    }
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo +1.88 test --locked --lib discovery::hooks`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement**

```rust
//! Which exported symbols hand out a PKCS#11 function table, and with what ABI.
//! Built-ins cover the standard three plus NSS's `NSC_`/`FC_` pair; `--hook-symbol`
//! adds vendor names (spec §2, §4.3).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAbi {
    /// `CK_RV f(CK_FUNCTION_LIST_PTR_PTR)` — the table is written to `*arg0`.
    FunctionList,
    /// `CK_RV f(CK_INTERFACE_PTR, CK_ULONG_PTR)`.
    InterfaceList,
    /// `CK_RV f(name, version, CK_INTERFACE_PTR_PTR, flags)`.
    Interface,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRegistry {
    entries: Vec<(String, HookAbi)>,
}

const BUILTIN: [(&str, HookAbi); 5] = [
    ("C_GetFunctionList", HookAbi::FunctionList),
    ("C_GetInterfaceList", HookAbi::InterfaceList),
    ("C_GetInterface", HookAbi::Interface),
    ("NSC_GetFunctionList", HookAbi::FunctionList),
    ("FC_GetFunctionList", HookAbi::FunctionList),
];

impl HookRegistry {
    pub fn builtin() -> Self {
        Self {
            entries: BUILTIN.iter().map(|(name, abi)| ((*name).to_string(), *abi)).collect(),
        }
    }

    pub fn add_spec(&mut self, spec: &str) -> Result<(), String> {
        let mut parts = spec.split(':');
        let name = parts.next().unwrap_or_default();
        let abi = match parts.next() {
            None => HookAbi::FunctionList,
            Some("functionlist") => HookAbi::FunctionList,
            Some("interfacelist") => HookAbi::InterfaceList,
            Some("interface") => HookAbi::Interface,
            Some(other) => {
                return Err(format!(
                    "unknown hook ABI {other:?}; expected functionlist, interfacelist or interface"
                ));
            }
        };
        if parts.next().is_some() {
            return Err(format!("hook spec {spec:?} has more than one ':' separator"));
        }
        if name.is_empty() {
            return Err(format!("hook spec {spec:?} has an empty symbol name"));
        }
        if name.bytes().any(|b| b.is_ascii_whitespace() || b == 0) {
            return Err(format!("hook symbol {name:?} contains whitespace or NUL"));
        }
        match self.entries.iter_mut().find(|(existing, _)| existing == name) {
            Some(entry) => entry.1 = abi,
            None => self.entries.push((name.to_string(), abi)),
        }
        Ok(())
    }

    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|(name, _)| name.as_str()).collect()
    }

    pub fn abi(&self, name: &str) -> Option<HookAbi> {
        self.entries.iter().find(|(n, _)| n == name).map(|(_, abi)| *abi)
    }
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}
```

Add `pub mod hooks;` to `src/discovery/mod.rs`.

- [ ] **Step 4: Run the tests**

Run: `cargo +1.88 test --locked --lib discovery::hooks`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/discovery/hooks.rs src/discovery/mod.rs
git commit -m "feat(discovery): hook registry with --hook-symbol ABI specs"
```

---

## Task 6: `discovery::scan` — find function tables in the target's memory

**Files:**
- Create: `src/discovery/scan.rs`
- Modify: `src/discovery/mod.rs`
- Test: `tests/discovery_scan.rs`

**Interfaces:**
- Consumes: `p11scope_manifest::maps::{parse_maps, resolve, MapEntry, MappedPath, ObjectKey, Resolved}`,
  `p11scope_manifest::identity::open_object`, `p11scope_manifest::elf::exports_matching`,
  `pkcs11_module::{tables_for, read_fn_pointers, Surface, TableSet}`,
  `discovery::hooks::HookRegistry`.
- Produces:

```rust
pub struct ScanLimits { pub per_object_bytes: u64, pub total_bytes: u64 }
impl Default for ScanLimits { /* 64 MiB, 512 MiB */ }

pub struct ScanRequest<'a> {
    pub pid: u32,
    /// `--module` hints; empty means "every object exporting a registry symbol".
    pub hints: &'a [std::path::PathBuf],
    pub hooks: &'a HookRegistry,
    pub limits: ScanLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedEntry {
    pub name: &'static str,
    pub object: ObjectKey,
    pub object_path: String,
    pub file_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedTable {
    pub version: (u8, u8),
    /// "full" or "known_prefix" — the `WalkOutcome` label the manifest uses.
    pub walk: &'static str,
    pub entries: Vec<ScannedEntry>,
    /// Published names whose slot held a NULL pointer — evidence, not entries.
    pub null_entries: Vec<&'static str>,
    /// Address of the version word in the target, for interface cross-reference.
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedInterface {
    pub index: usize,
    /// "exact_standard" | "other" | "null" | "unreadable"
    pub name_class: &'static str,
    /// Kept for `inspect` and manifests only; never rendered in capture output.
    pub name_lossy: Option<String>,
    pub flags: u64,
    /// Index into `ScannedModule::tables` when the interface points at a table
    /// this scan decoded; `None` when it points elsewhere (recorded, undecoded).
    pub table: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped { pub subject: String, pub reason: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedModule {
    pub key: ObjectKey,
    pub path: String,
    pub exports: Vec<String>,
    pub tables: Vec<ScannedTable>,
    pub interfaces: Vec<ScannedInterface>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    Scanned { modules: Vec<ScannedModule>, skipped: Vec<Skipped>, scan_ms: u64 },
    /// `/proc/<pid>/mem` was not accessible (spec §4.1 step 3, §4.9) — never fatal.
    /// Objects are still identified from `maps` + `.dynsym`, so `inspect` can answer
    /// "which providers does this process map" without any ptrace access; their
    /// `tables` are empty because tables live only in memory.
    Unavailable { reason: &'static str, modules: Vec<ScannedModule>, skipped: Vec<Skipped> },
}

impl ScanOutcome {
    pub fn modules(&self) -> &[ScannedModule];
    pub fn skipped(&self) -> &[Skipped];
    /// `Some(reason)` when the table scan could not run.
    pub fn unavailable_reason(&self) -> Option<&'static str>;
}

pub fn scan_pid(request: &ScanRequest<'_>) -> Result<ScanOutcome, String>;
```

**Detection criterion (spec §4.1 step 4), stated exactly because the tests measure it:**
a candidate is an 8-byte-aligned word `w` in a **non-executable, readable, file-backed**
mapping of the candidate object such that

1. `w & !0xffff == 0`,
2. `major = w & 0xff` is 2 or 3,
3. `minor = (w >> 8) & 0xff` is `0..=40` for major 2 and `0..=2` for major 3,
4. `tables_for` for that version does not `Refuse`,
5. the following `N` words (`N` = the span field count: 67, 68, 92 or 104) are entirely
   inside the snapshot, and
6. **every** one of those words is either `0` (a NULL table slot — recorded as evidence, as
   the fixtures and real providers legitimately have them) or resolves via
   `maps::resolve` to a **file-backed executable** mapping, and at least one is non-zero.

Overlapping accepted candidates keep the longest; a shorter match inside a longer one is
dropped. Anything that fails is not a table and is silently not a candidate — only *objects*
that could not be examined at all become `Skipped` entries.

**Why the layout comes from `tables_for`/`read_fn_pointers`:** the offline helper decodes
tables with exactly those functions, so a scanned offset and a manifest offset for the same
provider are equal by construction rather than by coincidence — which is what makes the
acceptance criterion ("offsets equal `p11scope-discover`'s") testable rather than aspirational.

- [ ] **Step 1: Write the failing oracle test**

Create `tests/discovery_scan.rs`:

```rust
//! The scan's oracle is the offline helper: for the same provider loaded in this
//! process, every table entry the scan finds must have the offset
//! `p11scope-discover` computes. Both run in-process here; the helper dlopens the
//! fixture (test-only — the observer itself never does).

use p11scope::discovery::hooks::HookRegistry;
use p11scope::discovery::scan::{ScanLimits, ScanOutcome, ScanRequest, scan_pid};
use p11scope_manifest::manifest::{Resolution, SurfaceSource};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn build_fixture(dir: &Path, name: &str, defines: &[&str]) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/discover/tests/fixture/version_matrix.c");
    let so = dir.join(format!("{name}.so"));
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&source)
        .args(defines)
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc failed for {name}");
    so
}

/// dlopen + call C_GetFunctionList so the fixture's static tables are filled,
/// exactly as a real application would before the observer scans it.
fn load_and_populate(so: &Path) {
    let c = std::ffi::CString::new(so.to_str().unwrap()).unwrap();
    let handle = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen {}", so.display());
    let symbol = std::ffi::CString::new("C_GetFunctionList").unwrap();
    let entry = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    assert!(!entry.is_null(), "C_GetFunctionList missing");
    let entry: extern "C" fn(*mut *mut std::ffi::c_void) -> u64 =
        unsafe { std::mem::transmute(entry) };
    let mut table: *mut std::ffi::c_void = std::ptr::null_mut();
    assert_eq!(entry(&mut table), 0, "fixture C_GetFunctionList must succeed");
}

fn scan_self(hints: &[PathBuf]) -> ScanOutcome {
    let hooks = HookRegistry::builtin();
    scan_pid(&ScanRequest {
        pid: std::process::id(),
        hints,
        hooks: &hooks,
        limits: ScanLimits::default(),
    })
    .expect("scanning our own process must not fail")
}

fn helper_offsets(so: &Path) -> BTreeMap<String, u64> {
    let manifest = p11scope_discover::discover::discover(so).expect("helper discovery");
    let mut out = BTreeMap::new();
    for surface in &manifest.surfaces {
        if !matches!(surface.source, SurfaceSource::LegacyFunctionList) {
            continue;
        }
        for function in &surface.functions {
            if let Resolution::Resolved { file_offset, .. } = function.resolution {
                out.insert(function.name.clone(), file_offset);
            }
        }
    }
    out
}

#[test]
fn scanned_offsets_equal_the_helpers_for_the_legacy_table() {
    let dir = tmp("scan-oracle");
    let so = build_fixture(&dir, "oracle", &["-DMATRIX_INTERFACES=0"]);
    load_and_populate(&so);

    let ScanOutcome::Scanned { modules, .. } = scan_self(&[so.clone()]) else {
        panic!("/proc/self/mem must always be readable");
    };
    let module = modules
        .iter()
        .find(|m| m.path.ends_with("oracle.so"))
        .expect("the fixture must be discovered");

    let legacy = module
        .tables
        .iter()
        .find(|t| t.version == (2, 40))
        .expect("the 2.40 legacy table must be found");
    let scanned: BTreeMap<String, u64> = legacy
        .entries
        .iter()
        .map(|e| (e.name.to_string(), e.file_offset))
        .collect();

    let expected = helper_offsets(&so);
    assert!(!expected.is_empty(), "the helper must produce an oracle");
    assert_eq!(scanned, expected, "scanned offsets must equal the helper's exactly");
    assert!(legacy.entries.len() >= 60, "a 2.40 table has 68 slots: {}", legacy.entries.len());
}

#[test]
fn every_supported_version_layout_is_found_with_its_documented_entry_count() {
    // (major, minor, expected entry+null count) — the N of spec §4.1 step 4.
    for (major, minor, expected) in [(2u8, 0u8, 67usize), (2, 40, 68), (3, 0, 92), (3, 2, 104)] {
        let dir = tmp(&format!("scan-v{major}-{minor}"));
        let so = build_fixture(
            &dir,
            "versioned",
            &[
                &format!("-DLEGACY_MAJOR={major}"),
                &format!("-DLEGACY_MINOR={minor}"),
                "-DMATRIX_INTERFACES=0",
            ],
        );
        load_and_populate(&so);
        let ScanOutcome::Scanned { modules, .. } = scan_self(&[so.clone()]) else {
            panic!("scan must be available");
        };
        let module = modules.iter().find(|m| m.path.ends_with("versioned.so")).unwrap();
        let table = module
            .tables
            .iter()
            .find(|t| t.version == (major, minor))
            .unwrap_or_else(|| panic!("{major}.{minor} table not found"));
        assert_eq!(
            table.entries.len() + table.null_entries.len(),
            expected,
            "{major}.{minor} must decode {expected} slots"
        );
    }
}

#[test]
fn interfaces_are_recorded_with_their_name_class() {
    let dir = tmp("scan-interfaces");
    let so = build_fixture(&dir, "ifaces", &[]);
    load_and_populate(&so);
    // Populate the interface array too.
    let c = std::ffi::CString::new(so.to_str().unwrap()).unwrap();
    let handle = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    let symbol = std::ffi::CString::new("C_GetInterfaceList").unwrap();
    let entry = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    let entry: extern "C" fn(*mut std::ffi::c_void, *mut u64) -> u64 =
        unsafe { std::mem::transmute(entry) };
    let mut count = 0u64;
    assert_eq!(entry(std::ptr::null_mut(), &mut count), 0);
    let mut buffer = vec![0u8; count as usize * 24];
    assert_eq!(entry(buffer.as_mut_ptr().cast(), &mut count), 0);

    let ScanOutcome::Scanned { modules, .. } = scan_self(&[so.clone()]) else {
        panic!("scan must be available")
    };
    let module = modules.iter().find(|m| m.path.ends_with("ifaces.so")).unwrap();
    assert!(
        module.interfaces.iter().any(|i| i.name_class == "exact_standard"),
        "the fixture publishes a \"PKCS 11\" interface: {:?}",
        module.interfaces
    );
    assert!(
        module.interfaces.iter().any(|i| i.name_class == "other"),
        "the fixture publishes vendor-named interfaces too"
    );
}

#[test]
fn a_table_less_object_and_a_non_elf_hint_produce_no_module_and_no_panic() {
    let dir = tmp("scan-negative");
    let plain = dir.join("plain.so");
    let c = dir.join("plain.c");
    std::fs::write(&c, "int unrelated(void){return 1;}\n").unwrap();
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&plain)
            .arg(&c)
            .status()
            .unwrap()
            .success()
    );
    load_and_populate_ignoring_missing_entry(&plain);

    let ScanOutcome::Scanned { modules, .. } = scan_self(&[plain.clone()]) else {
        panic!("scan must be available")
    };
    assert!(
        modules.iter().all(|m| !m.path.ends_with("plain.so") || m.tables.is_empty()),
        "an object with no table must yield no tables"
    );

    let text = dir.join("not-elf.so");
    std::fs::write(&text, b"not an elf at all\n").unwrap();
    let ScanOutcome::Scanned { skipped, .. } = scan_self(&[text.clone()]) else {
        panic!("scan must be available")
    };
    // The hint names a file that is not mapped at all: recorded, never fatal.
    assert!(skipped.iter().any(|s| s.subject.contains("not-elf.so")), "{skipped:?}");
}

fn load_and_populate_ignoring_missing_entry(so: &Path) {
    let c = std::ffi::CString::new(so.to_str().unwrap()).unwrap();
    let handle = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen {}", so.display());
}

#[test]
fn the_per_object_byte_cap_is_enforced_as_a_skip_not_a_truncation() {
    let dir = tmp("scan-cap");
    let so = build_fixture(&dir, "capped", &["-DMATRIX_INTERFACES=0"]);
    load_and_populate(&so);
    let hooks = HookRegistry::builtin();
    let outcome = scan_pid(&ScanRequest {
        pid: std::process::id(),
        hints: &[so.clone()],
        hooks: &hooks,
        limits: ScanLimits { per_object_bytes: 1, total_bytes: 512 * 1024 * 1024 },
    })
    .unwrap();
    let ScanOutcome::Scanned { modules, skipped, .. } = outcome else {
        panic!("scan must be available")
    };
    assert!(
        modules.iter().all(|m| m.tables.is_empty()),
        "nothing may be decoded from a capped object"
    );
    assert!(
        skipped.iter().any(|s| s.reason.contains("too_large")),
        "the cap must be reported as too_large: {skipped:?}"
    );
}

#[test]
fn softhsm_if_installed_is_discovered_without_false_positives() {
    let module = Path::new("/usr/lib/softhsm/libsofthsm2.so");
    if !module.exists() {
        eprintln!("SKIP: SoftHSM2 not installed");
        return;
    }
    load_and_populate(module);
    let ScanOutcome::Scanned { modules, .. } = scan_self(&[module.to_path_buf()]) else {
        panic!("scan must be available")
    };
    let found = modules
        .iter()
        .find(|m| m.path.contains("libsofthsm2.so"))
        .expect("SoftHSM2 must be discovered");
    assert!(!found.tables.is_empty(), "SoftHSM2 must expose at least one table");
    let expected = helper_offsets(module);
    for table in &found.tables {
        for entry in &table.entries {
            if let Some(want) = expected.get(entry.name) {
                assert_eq!(
                    entry.file_offset, *want,
                    "{} offset disagrees with the helper",
                    entry.name
                );
            }
        }
    }
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo +1.88 test --locked --test discovery_scan`
Expected: FAIL — `unresolved import p11scope::discovery::scan`.

- [ ] **Step 3: Implement `src/discovery/scan.rs`**

Structure the module in this order; the two functions that carry the correctness argument
(`detect_tables`, `decode_candidate`) are given in full.

```rust
//! Finding PKCS#11 function tables by reading the target's mapped memory. No provider
//! code is executed and nothing is copied: `/proc/<pid>/maps` says what is mapped,
//! `.dynsym` says which objects could hand out a table, and the target's own
//! non-executable pages are searched for the `CK_FUNCTION_LIST` signature. Table
//! layout comes from `pkcs11_module::tables_for`/`read_fn_pointers` — the same
//! authority the offline helper uses — so a scanned offset equals a manifest offset.

use crate::discovery::hooks::HookRegistry;
use p11scope_manifest::elf::exports_matching;
use p11scope_manifest::identity::open_object;
use p11scope_manifest::maps::{MapEntry, MappedPath, ObjectKey, Resolved, parse_maps, resolve};
use pkcs11_module::{Surface, TableSet, read_fn_pointers, tables_for};
use std::collections::BTreeMap;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

const WORD: usize = 8;
const INTERFACE_NAME_CAP: usize = 64;

/* ScanLimits, ScanRequest, ScannedEntry, ScannedTable, ScannedInterface, Skipped,
   ScannedModule, ScanOutcome exactly as in the Interfaces block above. */

impl Default for ScanLimits {
    fn default() -> Self {
        Self { per_object_bytes: 64 * 1024 * 1024, total_bytes: 512 * 1024 * 1024 }
    }
}

/// Version word → the field spans that describe that layout. Returns `None` when the
/// word is not a plausible `CK_VERSION` header or the layout is one we refuse to walk.
fn spans_for(word: u64) -> Option<((u8, u8), &'static [pkcs11_module::TableSpan], &'static str)> {
    if word & !0xffff != 0 {
        return None;
    }
    let major = (word & 0xff) as u8;
    let minor = ((word >> 8) & 0xff) as u8;
    let plausible = match major {
        2 => minor <= 40,
        3 => minor <= 2,
        _ => false,
    };
    if !plausible {
        return None;
    }
    let version = cryptoki_sys::CK_VERSION { major, minor };
    // 2.x tables in memory are legacy CK_FUNCTION_LIST; 3.x tables are the
    // interface layouts (92/104 slots) — spec §4.1 step 4's N table.
    let surface = if major == 2 {
        Surface::LegacyFunctionList { version }
    } else {
        Surface::StandardInterface { version }
    };
    match tables_for(surface) {
        TableSet::Walk(spans) => Some(((major, minor), spans, "full")),
        TableSet::WalkKnownPrefix(spans) => Some(((major, minor), spans, "known_prefix")),
        TableSet::Refuse => None,
    }
}

/// How many bytes a layout occupies, including the version header word.
fn span_bytes(spans: &[pkcs11_module::TableSpan]) -> Option<usize> {
    spans
        .iter()
        .flat_map(|span| span.fields())
        .filter_map(|field| field.offset.checked_add(WORD))
        .max()
}

/// Decodes one candidate at `offset` inside `snapshot` (whose first byte is at
/// `base_address` in the target). Returns the table only when every published slot
/// is either NULL or points into a file-backed executable mapping — the criterion
/// that makes a run of pointers a function table rather than data that looks like one.
fn decode_candidate(
    snapshot: &[u8],
    offset: usize,
    base_address: u64,
    maps: &[MapEntry],
    objects: &mut ObjectPaths,
) -> Option<(ScannedTable, usize)> {
    let word = u64::from_ne_bytes(snapshot.get(offset..offset + WORD)?.try_into().ok()?);
    let (version, spans, walk) = spans_for(word)?;
    let len = span_bytes(spans)?;
    let bytes = snapshot.get(offset..offset.checked_add(len)?)?;

    let mut entries = Vec::new();
    let mut null_entries = Vec::new();
    let mut non_null = 0usize;
    for span in spans {
        let values = read_fn_pointers(bytes, span.fields()).ok()?;
        for (name, value) in values {
            if value == 0 {
                null_entries.push(name);
                continue;
            }
            non_null += 1;
            let Resolved::File { path, file_offset, device, inode, permissions, .. } =
                resolve(maps, value as u64)
            else {
                return None; // anonymous or unmapped ⇒ not a function table
            };
            if permissions[2] != b'x' {
                return None; // a pointer into data ⇒ not a function table
            }
            let MappedPath::Usable(path) = path else {
                return None; // deleted/ambiguous pathname ⇒ cannot become an attach target
            };
            let key = ObjectKey { device, inode };
            objects.remember(key, &path);
            entries.push(ScannedEntry {
                name,
                object: key,
                object_path: path.display().to_string(),
                file_offset,
            });
        }
    }
    if non_null == 0 {
        return None;
    }
    Some((
        ScannedTable {
            version,
            walk,
            entries,
            null_entries,
            address: base_address + offset as u64,
        },
        len,
    ))
}

/// Every 8-byte-aligned candidate in one snapshot, longest match kept on overlap.
fn detect_tables(
    snapshot: &[u8],
    base_address: u64,
    maps: &[MapEntry],
    objects: &mut ObjectPaths,
) -> Vec<ScannedTable> {
    let mut found: Vec<(usize, usize, ScannedTable)> = Vec::new();
    let mut offset = 0usize;
    while offset + WORD <= snapshot.len() {
        if let Some((table, len)) = decode_candidate(snapshot, offset, base_address, maps, objects) {
            found.push((offset, len, table));
        }
        offset += WORD;
    }
    // Longest first, then drop anything overlapping an already-kept match.
    found.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut kept: Vec<(usize, usize, ScannedTable)> = Vec::new();
    for candidate in found {
        let overlaps = kept.iter().any(|(start, len, _)| {
            candidate.0 < start + len && *start < candidate.0 + candidate.1
        });
        if !overlaps {
            kept.push(candidate);
        }
    }
    kept.sort_by_key(|(start, _, _)| *start);
    kept.into_iter().map(|(_, _, table)| table).collect()
}
```

The remaining private helpers, each small and mechanical:

- `struct ObjectPaths(BTreeMap<ObjectKey, String>)` with `remember(key, path)` — records
  every object an entry pointed into, so Task 7 can pin them all.
- `fn read_mapping(mem: &std::fs::File, entry: &MapEntry, limit: u64) -> Result<Vec<u8>, String>`
  — `read_at` in ≤1 MiB chunks over `entry.start..entry.end`; a short or failed read stops
  that mapping and returns what was read (a guard page mid-object must not lose the rest).
- `fn candidate_groups(maps: &[MapEntry]) -> BTreeMap<ObjectKey, Vec<&MapEntry>>` — groups
  by `ObjectKey::of`, keeping groups with `inode != 0` and at least one `r-x` mapping.
- `fn matches_hint(path: &Path, key: ObjectKey, hints: &[PathBuf], pid: u32) -> bool` — true
  when the hint's string equals the mapped path, or when the hint's own
  `open_object` + `fstat` inode equals `key.inode`.
- `fn open_in_target(pid: u32, path: &str) -> Result<std::fs::File, String>` — opens
  `/proc/<pid>/root/<path>` via `open_object` (spec §4.5: primary path, needs only
  `PTRACE_MODE_READ`; `map_files` is never required).
- `fn scan_interfaces(snapshot, base_address, maps, mem, tables) -> Vec<ScannedInterface>` —
  walks 24-byte `{name_ptr, table_ptr, flags}` triples at 8-byte alignment; a triple counts
  when `table_ptr` equals a detected table's `address` and `name_ptr` is 0 or reads as a
  NUL-terminated string of ≤ `INTERFACE_NAME_CAP` bytes through `/proc/<pid>/mem`. Name
  class is `"exact_standard"` for exactly `PKCS 11`, `"null"` for a null pointer,
  `"unreadable"` for a failed read, `"other"` otherwise.

`scan_pid` itself:

1. `let started = Instant::now();`
2. Read and parse `/proc/<pid>/maps`; an error here is `Err` (the caller decides whether the
   pid is gone or unreadable).
3. Open `/proc/<pid>/mem`. On `EACCES`/`EPERM` do **not** return early and **never** error
   (spec §4.1 step 3): continue through steps 4 and 8 to identify objects from `maps` +
   `.dynsym`, then return `Ok(ScanOutcome::Unavailable { reason: "ptrace", modules, skipped })`
   with every module's `tables`/`interfaces` empty.
4. For each candidate group: apply hints; open the object in the target; if
   `exports_matching` errors, push `Skipped { subject: path, reason }` and continue; when
   hints are empty and the object exports nothing from the registry, skip it silently.
5. Enforce `per_object_bytes` (sum of that group's readable non-executable mappings) and the
   running `total_bytes`; over either ⇒ `Skipped { reason: "too_large (…)" }`, no decode.
6. Read the group's `r--`/`rw-` mappings, run `detect_tables` and `scan_interfaces`.
7. Build the `ScannedModule` (`key`, `path`, `exports`, `tables`, `interfaces`).
8. Every hint that matched no mapping at all becomes
   `Skipped { subject: hint, reason: "not mapped in the target" }`.
9. Return `Ok(ScanOutcome::Scanned { modules, skipped, scan_ms: started.elapsed().as_millis() as u64 })`.

Add `pub mod scan;` to `src/discovery/mod.rs`. Add `cryptoki-sys` is already a root
dependency (used for `CK_VERSION` above) — confirm with `grep cryptoki-sys Cargo.toml`.

- [ ] **Step 4: Run the tests**

Run: `cargo +1.88 test --locked --test discovery_scan -- --test-threads=1`
Expected: PASS (SoftHSM2 case runs on this host; it is installed).

`--test-threads=1` because the tests dlopen fixtures into the shared process image and then
scan it; concurrent loads would make "which modules are mapped" nondeterministic.

- [ ] **Step 5: Run the full checks and commit**

```bash
cargo +1.88 fmt --all -- --check && cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
git add src/discovery/scan.rs src/discovery/mod.rs tests/discovery_scan.rs
git commit -m "feat(discovery): memory scan for CK_FUNCTION_LIST/CK_INTERFACE tables"
```

---

## Task 7: Pin what the scan found — `PidPin` and per-object pins

**Files:**
- Modify: `src/process.rs` (add `PidPin`, reusing the existing pidfd/start-time helpers)
- Modify: `src/discovery/identity.rs`
- Test: `tests/manifest_pinning.rs` (extend)

**Interfaces:**
- Consumes: `scan::{ScannedModule, ScannedEntry}`, `ObjectKey`,
  `p11scope_manifest::identity::{open_object, inspect_file, mapping_file_key}`.
- Produces:

```rust
// src/process.rs
/// A process identity that survives PID reuse: a pidfd when available, else the
/// /proc/<pid>/stat start time. Every per-pid action re-checks it (spec §4.5).
pub struct PidPin { /* private */ }
impl PidPin {
    pub fn open(pid: u32) -> Result<PidPin, String>;
    pub fn pid(&self) -> u32;
    /// False when the process exited or the pid was reused since `open`.
    pub fn still_the_same(&self) -> bool;
}

// src/discovery/identity.rs — additions; pin_manifest_objects keeps its signature
impl PinnedObjects {
    /// Attach path for an object discovered by the scan (`/proc/self/fd/N`).
    pub fn attach_path_for(&self, key: ObjectKey) -> Result<PathBuf, String>;
    /// (key, path, sha256, build_id) for every pinned object, for `discovery[]`.
    pub fn pinned(&self) -> impl Iterator<Item = PinnedSummary<'_>>;
}
pub struct PinnedSummary<'a> {
    pub key: ObjectKey,
    pub path: &'a str,
    pub sha256: &'a str,
    pub build_id: Option<&'a str>,
    /// "mountinfo" or "stat" — how the mapping identity was confirmed.
    pub identity_source: &'static str,
}
/// Opens, identity-checks, hashes once and pins every object the scan named.
/// Objects that cannot be pinned are returned as `Skipped`, never as errors:
/// one unusable dependency must not lose the whole capture (spec §4.10).
pub fn pin_scanned_objects(
    pid: u32,
    modules: &[ScannedModule],
) -> Result<(PinnedObjects, Vec<crate::discovery::scan::Skipped>), String>;
```

**Identity check, and its documented fallback:** the opened fd's identity is compared with
the mapping's `(dev, ino)` through `mapping_file_key` (fdinfo + mountinfo, so overlay/btrfs
device numbers match). When `mapping_file_key` cannot resolve — the mount is not in the
observer's own table — fall back to `fstat`'s `st_dev`/`st_ino` and record
`identity_source: "stat"`. A mismatch under whichever method applied is
`skipped: identity_mismatch`. Task 2 recorded that this host resolves via mountinfo; Task 14's
docker lane measures overlay2.

- [ ] **Step 1: Write the failing tests**

Append to `tests/manifest_pinning.rs`:

```rust
#[test]
fn a_pid_pin_detects_process_exit() {
    let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let pin = p11scope::process::PidPin::open(child.id()).expect("pin a live child");
    assert!(pin.still_the_same());
    child.kill().unwrap();
    child.wait().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while pin.still_the_same() {
        assert!(std::time::Instant::now() < deadline, "exit must become visible");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn scanned_objects_are_pinned_hashed_and_attachable() {
    use p11scope::discovery::hooks::HookRegistry;
    use p11scope::discovery::scan::{ScanLimits, ScanOutcome, ScanRequest, scan_pid};

    // Our own executable is a file-backed mapping with a stable identity; scan
    // our process with it as the hint and pin whatever the scan reports.
    let hooks = HookRegistry::builtin();
    let exe = std::env::current_exe().unwrap();
    let outcome = scan_pid(&ScanRequest {
        pid: std::process::id(),
        hints: &[exe.clone()],
        hooks: &hooks,
        limits: ScanLimits::default(),
    })
    .unwrap();
    let ScanOutcome::Scanned { modules, .. } = outcome else {
        panic!("/proc/self/mem is always readable")
    };
    let (pinned, skipped) =
        p11scope::discovery::identity::pin_scanned_objects(std::process::id(), &modules).unwrap();
    assert!(skipped.is_empty(), "nothing about our own process should be unpinnable: {skipped:?}");
    for summary in pinned.pinned() {
        assert_eq!(summary.sha256.len(), 64, "sha256 must be a full digest");
        let attach = pinned.attach_path_for(summary.key).unwrap();
        assert!(attach.starts_with("/proc/self/fd/"), "{attach:?}");
        assert!(std::fs::metadata(&attach).is_ok(), "the pinned fd must still be open");
    }
    assert!(pinned.check_unchanged().unwrap());
}
```

- [ ] **Step 2: Run and watch them fail**

Run: `cargo +1.88 test --locked --test manifest_pinning`
Expected: FAIL — `PidPin` and `pin_scanned_objects` do not exist.

- [ ] **Step 3: Implement `PidPin` in `src/process.rs`**

```rust
/// A process identity that survives PID reuse. `pidfd_open` is exact; the
/// `/proc/<pid>/stat` start time is the documented fallback where pidfds are
/// unavailable. Both already back `Tracker`; `PidPin` exposes them for the
/// discovery path, which must drop any per-pid action whose target was recycled.
pub struct PidPin {
    pid: u32,
    pidfd: Option<OwnedFd>,
    start_time: Option<u64>,
}

impl PidPin {
    pub fn open(pid: u32) -> Result<Self, String> {
        let start_time = process_start_time(pid).ok();
        let pidfd = pidfd_open(pid).ok();
        if pidfd.is_none() && start_time.is_none() {
            return Err(format!("cannot pin pid {pid}: no pidfd and no /proc/{pid}/stat"));
        }
        Ok(Self { pid, pidfd, start_time })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn still_the_same(&self) -> bool {
        match &self.pidfd {
            Some(fd) => !pidfd_ready(fd).unwrap_or(false),
            None => process_start_time(self.pid).ok() == self.start_time,
        }
    }
}
```

- [ ] **Step 4: Implement `pin_scanned_objects` in `src/discovery/identity.rs`**

Refactor `PinnedObjects` so both entry points share one store:

```rust
struct Entry {
    file: std::fs::File,
    pin: Pin,
    path: String,
    sha256: String,
    build_id: Option<String>,
    identity_source: &'static str,
}

pub struct PinnedObjects {
    by_key: BTreeMap<ObjectKey, Entry>,
    /// Manifest paths → key, so `attach_path(&str)` keeps working unchanged.
    by_path: BTreeMap<String, ObjectKey>,
    changed: std::cell::Cell<bool>,
}
```

`attach_path(&self, original: &str)` looks the path up in `by_path` then delegates to
`attach_path_for`. `check_unchanged` iterates `by_key`. `pin_manifest_objects` keeps its
current logic and fills both maps (its `ObjectKey` comes from `mapping_file_key`).

`pin_scanned_objects` then:

1. `let pin = PidPin::open(pid)?;`
2. Collect every distinct `ObjectKey` the modules name — both the table-owning module keys
   and every `ScannedEntry::object`.
3. For each: `open_object(Path::new(&format!("/proc/{pid}/root{path}")))`; on error push
   `Skipped { subject: path, reason }`.
4. `let key_now = mapping_file_key(&file).map(ObjectKey::from).ok()` → if `Some(k)` compare
   `k == key` (`identity_source = "mountinfo"`), else compare `st_dev`/`st_ino` from
   `file.metadata()` (`identity_source = "stat"`). Mismatch ⇒
   `Skipped { reason: "identity_mismatch" }`.
5. `let before = pin_of(&file)?;` → `inspect_file(&file)?` (SHA-256 **once**) →
   `let after = pin_of(&file)?;` and refuse the object when `before != after` (the
   write-during-hash window the 1a review closed — keep it).
6. `if !pin.still_the_same() { return Err("target exited during discovery".into()) }` before
   returning, so a report never claims objects pinned from a recycled pid.

- [ ] **Step 5: Run the tests**

Run: `cargo +1.88 test --locked --test manifest_pinning --test discovery_scan -- --test-threads=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/process.rs src/discovery/identity.rs tests/manifest_pinning.rs
git commit -m "feat(discovery): pin scanned objects by (dev,ino) and pin the target pid"
```

---

## Task 8: One attach plan from many modules

**Files:**
- Modify: `src/plan.rs`
- Modify: `src/attach.rs` (attach path lookup by `ObjectKey`)
- Test: `tests/multi_module.rs` (create)

**Interfaces:**
- Consumes: `scan::ScannedModule`, `PinnedObjects`, `kinds::descriptor_slot`.
- Produces:

```rust
/// Capture-local module index; the stable identity in output is {dev, ino, sha256, path}.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleId(pub u32);

pub struct Slot {
    pub index: u32,
    pub object: ObjectKey,       // was: String (path)
    pub object_path: String,
    pub file_offset: u64,
    pub names: Vec<String>,
    pub aliased: bool,
    pub semantics: SlotSemantics,
    pub semantic_ambiguous: bool,
    pub fork_safe: bool,
    /// Every module claiming this exact {object, offset}. Length ≥ 2 ⇒ ambiguous.
    pub module_ids: Vec<ModuleId>,
}

pub struct ModuleSummary {
    pub id: ModuleId,
    pub key: ObjectKey,
    pub path: String,
    pub tables: Vec<TableSummary>,
    pub interfaces: usize,
    pub source: &'static str,   // "scan" | "manifest"
    pub corroborated: bool,
}

pub struct AttachPlan {
    pub slots: Vec<Slot>,
    pub modules: Vec<ModuleSummary>,
    pub skipped: Vec<Skipped>,
    pub modules_skipped: Vec<Skipped>,
    pub entries_seen: usize,
    pub surfaces: Vec<SurfaceSummary>,
    pub vendor_interfaces: usize,
    pub interface_list: String,
    /// Slots claimed by ≥2 modules — count-only, forces PARTIAL (spec §4.7).
    pub module_ambiguous: usize,
}

impl AttachPlan {
    pub fn module_of_slot(&self, slot: u32) -> Option<ModuleId>;
}

/// Merges every scanned module into one plan over a single slot space.
pub fn build_from_modules(modules: &[ScannedModule]) -> AttachPlan;
```

**The two invariants this task must preserve:**
1. **One slot per unique `{object, file_offset}` across *all* modules.** A target claimed by
   two modules is attached once (no double counting), its slot is marked ambiguous by
   carrying two `module_ids`, its semantics degrade to `COUNT_ONLY`, and `module_ambiguous`
   is incremented — spec §4.7.
2. **Capacity is refused whole, never truncated.** With `MAX_SLOTS = 512`, actual modules are
   considered in first-seen discovery order; each module whose complete scan/manifest union
   would exceed the ceiling goes to `modules_skipped`, and later distinct modules are still considered.

- [ ] **Step 1: Write the failing test**

Create `tests/multi_module.rs`:

```rust
use p11scope::plan::{ModuleId, build_from_modules};
use p11scope_manifest::maps::{Device, ObjectKey};

fn key(inode: u64) -> ObjectKey {
    ObjectKey { device: Device { major: 8, minor: 1 }, inode }
}

fn module(inode: u64, path: &str, entries: &[(&'static str, u64, u64)]) -> p11scope::discovery::scan::ScannedModule {
    use p11scope::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
    ScannedModule {
        key: key(inode),
        path: path.to_string(),
        exports: vec!["C_GetFunctionList".into()],
        tables: vec![ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: entries
                .iter()
                .map(|(name, object_inode, offset)| ScannedEntry {
                    name,
                    object: key(*object_inode),
                    object_path: format!("/opt/obj{object_inode}.so"),
                    file_offset: *offset,
                })
                .collect(),
            null_entries: vec![],
            address: 0x1000 + inode,
        }],
        interfaces: vec![],
    }
}

#[test]
fn two_modules_get_distinct_slots_and_distinct_module_ids() {
    let plan = build_from_modules(&[
        module(10, "/opt/proxy.so", &[("C_Initialize", 10, 0x100), ("C_Sign", 10, 0x200)]),
        module(20, "/opt/backend.so", &[("C_Initialize", 20, 0x100), ("C_Sign", 20, 0x200)]),
    ]);
    assert_eq!(plan.slots.len(), 4, "no target is shared here");
    assert_eq!(plan.modules.len(), 2);
    assert_eq!(plan.module_ambiguous, 0);
    let ids: Vec<ModuleId> = plan.slots.iter().map(|s| s.module_ids[0]).collect();
    assert_eq!(ids.iter().filter(|id| **id == ModuleId(0)).count(), 2);
    assert_eq!(ids.iter().filter(|id| **id == ModuleId(1)).count(), 2);
    // Slot indices are dense and unique across modules.
    let mut indices: Vec<u32> = plan.slots.iter().map(|s| s.index).collect();
    indices.sort();
    assert_eq!(indices, vec![0, 1, 2, 3]);
}

#[test]
fn a_target_claimed_by_two_modules_is_attached_once_and_marked_ambiguous() {
    let plan = build_from_modules(&[
        module(10, "/opt/proxy.so", &[("C_Sign", 30, 0x400)]),
        module(20, "/opt/backend.so", &[("C_Sign", 30, 0x400)]),
    ]);
    assert_eq!(plan.slots.len(), 1, "one {{object, offset}} ⇒ one slot, never two probes");
    assert_eq!(plan.slots[0].module_ids, vec![ModuleId(0), ModuleId(1)]);
    assert_eq!(plan.module_ambiguous, 1);
    assert_eq!(
        plan.slots[0].semantics,
        p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
        "an ambiguous slot may not carry semantics"
    );
    assert!(plan.slots[0].semantic_ambiguous);
}

#[test]
fn capacity_overflow_skips_whole_modules_and_says_which() {
    // 512 slots available; three modules of 200 unique targets each.
    let big = |inode: u64| {
        let entries: Vec<(&'static str, u64, u64)> = (0..200u64)
            .map(|i| ("C_Sign", inode, 0x1000 + i * 0x10))
            .collect();
        module(inode, "/opt/big.so", &entries)
    };
    let plan = build_from_modules(&[big(1), big(2), big(3)]);
    assert!(plan.slots.len() <= 512, "never exceed MAX_SLOTS");
    assert_eq!(plan.modules.len(), 2, "two modules fit");
    assert_eq!(plan.modules_skipped.len(), 1);
    assert!(
        plan.modules_skipped[0].reason.contains("512"),
        "the ceiling must be named: {:?}",
        plan.modules_skipped[0]
    );
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `cargo +1.88 test --locked --test multi_module`
Expected: FAIL — `build_from_modules` does not exist.

- [ ] **Step 3: Implement**

Keep `plan::build(&Manifest)` (the manifest path still exists) but have it produce the new
`AttachPlan` shape by constructing one `ScannedModule`-equivalent internally, so there is
exactly one merge implementation. Concretely:

- Add `fn merge(modules: &[ScannedModule]) -> AttachPlan` holding a
  `BTreeMap<(ObjectKey, u64), usize>` from target to slot position; for each module, for each
  table entry: look the target up; on a hit push the module id into the existing slot's
  `module_ids` (and, when that makes it ≥2, set `semantics = COUNT_ONLY`,
  `semantic_ambiguous = true`, `module_ambiguous += 1`); on a miss allocate the next index.
- Per-module capacity: compute the module's unique new targets before inserting; if
  `used + new > MAX_SLOTS`, push `Skipped { subject: module.path, reason: format!("module needs {new} more of the {MAX_SLOTS} attach slots; {used} are in use — refusing to attach a prefix") }`
  and skip the whole module; continue with the next actual module in first-seen order.
- Names per slot: collect, sort, dedup, then `kinds::descriptor_slot(&names)` exactly as
  today; ambiguity from aliasing and ambiguity from shared modules both land on
  `COUNT_ONLY`.
- `surfaces`/`vendor_interfaces`/`interface_list` are filled from the scanned tables
  (`walk` label, `"ok"` acquisition, entry counts) so the existing evidence fields keep
  their meaning.

In `src/attach.rs`, change the attach-path lookup from
`objects.attach_path(&slot.object)` to `objects.attach_path_for(slot.object)` and update the
two `format!` error strings to print `slot.object_path`. Nothing else in `attach.rs` changes:
`SLOT_SEMANTICS` is still published from the complete plan before the freeze, because every
module is known before `Session::start`.

- [ ] **Step 4: Run the tests**

Run: `cargo +1.88 test --locked --workspace --all-targets`
Expected: PASS (existing `plan` tests updated for the new field names as part of this task).

- [ ] **Step 5: Commit**

```bash
git add src/plan.rs src/attach.rs tests/multi_module.rs
git commit -m "feat(plan): merge many modules into one slot space; shared targets are ambiguous"
```

---

## Task 9: Semantic state keyed by module (spec §4.13)

**Files:**
- Modify: `src/semantics.rs`
- Test: `tests/multi_module.rs` (extend)

**Interfaces:**
- Consumes: `plan::{AttachPlan, ModuleId}`.
- Produces: no new public type — `State` internally keys session-scoped state by
  `(ProcessKey, ModuleId, handle)` instead of `(ProcessKey, handle)`, and
  `State::with_policy` learns each slot's module from the plan.

**Why now:** the moment Task 8 can attach a proxy and its backend in one process, two modules
can hand out the same numeric session handle. Without the module component,
`C_CloseSession(5)` from the proxy would close the backend's session 5 in our state and every
later attribution would be wrong — silently.

- [ ] **Step 1: Write the failing test**

Append to `tests/multi_module.rs`:

```rust
use p11scope::semantics::{ProcessKey, State};
use p11scope_ebpf_common::{Event, event_type};

fn open_session_event(slot: u32, handle: u64) -> Event {
    // C_OpenSession's descriptor writes the handle at return; the decoded
    // event carries it in `session`.
    Event {
        slot,
        session: handle,
        pid_tgid: 4242 << 32,
        rv: 0,
        event_type: event_type::CALL,
        ..Event::default()
    }
}

#[test]
fn equal_session_handles_from_two_modules_do_not_interact() {
    let plan = build_from_modules(&[
        module(10, "/opt/proxy.so", &[("C_OpenSession", 10, 0x100), ("C_CloseSession", 10, 0x108)]),
        module(20, "/opt/backend.so", &[("C_OpenSession", 20, 0x100), ("C_CloseSession", 20, 0x108)]),
    ]);
    let proxy_open = plan.slots.iter().find(|s| s.object.inode == 10 && s.names == ["C_OpenSession"]).unwrap().index;
    let backend_open = plan.slots.iter().find(|s| s.object.inode == 20 && s.names == ["C_OpenSession"]).unwrap().index;
    let proxy_close = plan.slots.iter().find(|s| s.object.inode == 10 && s.names == ["C_CloseSession"]).unwrap().index;

    let mut state = State::new(&plan);
    let process = ProcessKey::from_pid(4242);
    // The same numeric handle 5 opened through both modules.
    state.observe_process(process, &open_session_event(proxy_open, 5));
    state.observe_process(process, &open_session_event(backend_open, 5));
    assert_eq!(state.sessions().opened, 2, "two distinct sessions, not one");

    // Closing the proxy's 5 must leave the backend's 5 open.
    state.observe_process(process, &open_session_event(proxy_close, 5));
    assert_eq!(state.sessions().closed, 1);
    assert_eq!(state.unmatched_closes(), 0, "the close matched the proxy's session");
    assert!(
        state.has_process_state(process),
        "the backend's session is still open, so the process still has state"
    );
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `cargo +1.88 test --locked --test multi_module equal_session_handles`
Expected: FAIL — both opens collapse onto one key, `opened == 1` or the close is unmatched.

- [ ] **Step 3: Implement**

In `State`:

- add `slot_modules: Vec<Option<ModuleId>>` filled in `with_key_limit` from
  `plan.module_of_slot(slot.index)`;
- add `fn module_of(&self, slot: u32) -> ModuleId` returning `ModuleId(u32::MAX)` for an
  unknown/ambiguous slot — one reserved id, so ambiguous traffic cannot alias a real module;
- change the key types:
  `open: BTreeMap<(ProcessKey, ModuleId, u64), SessionInfo>`,
  `active_ops: BTreeMap<(ProcessKey, ModuleId, u64, u16), Binding>`,
  `find_active: BTreeSet<(ProcessKey, ModuleId, u64)>`,
  `inherited_ambiguous: BTreeSet<(ProcessKey, ModuleId, u64)>`,
  `pending: BTreeMap<(ProcessKey, ModuleId, u64, u32), Pending>`;
- thread `module` through `observe_process`, `retire_process` (drop every key whose
  `ProcessKey` matches, regardless of module), `fork_process` (inherit per module),
  `session_pseudonym_process` (pseudonyms stay per `(process, module)` so two modules'
  handle 5 render as different pseudonyms), and `has_process_state`.

Ambiguous slots (`ModuleId(u32::MAX)`) are already `COUNT_ONLY` from Task 8, so they emit no
session-scoped events; the reserved id exists so that if one ever did, it could not be
attributed to a real module.

- [ ] **Step 4: Run the tests**

Run: `cargo +1.88 test --locked --workspace --all-targets`
Expected: PASS — including every pre-existing `semantics` test (single-module captures use
`ModuleId(0)` throughout and behave identically).

- [ ] **Step 5: Commit**

```bash
git add src/semantics.rs tests/multi_module.rs
git commit -m "feat(semantics): key session state by (process, module, handle)"
```

---

## Task 10: `p11scope inspect --pid N`

**Files:**
- Create: `src/inspect.rs`
- Modify: `src/lib.rs`
- Test: inline `#[cfg(test)]` in `src/inspect.rs` (rendering is pure), plus one end-to-end
  case in `tests/discovery_scan.rs`

**Interfaces:**
- Consumes: `scan::{ScanOutcome, ScannedModule, scan_pid}`, `identity::pin_scanned_objects`.
- Produces:

```rust
/// Renders a completed scan. Pure: takes the scan result and the pinned identities,
/// returns the text — so the layout is unit-testable without a target process.
pub fn render_text(pid: u32, outcome: &ScanOutcome, pinned: &PinnedObjects) -> String;
pub fn render_json(pid: u32, outcome: &ScanOutcome, pinned: &PinnedObjects) -> serde_json::Value;
/// `p11scope inspect` — scans, pins, prints. Exit code: 0 when the scan ran
/// (even with zero modules), 1 when the target could not be read at all.
pub fn run(pid: u32, hints: &[PathBuf], hooks: &HookRegistry, json: bool) -> Result<i32>;
```

**No BPF, no pause, no capture** (spec §4.6): `inspect` reads `/proc` and nothing else, so it
works unprivileged against a same-uid target and is the answer to "which providers does this
process actually use". Interface **names** are shown here — `inspect` is a discovery tool,
not capture output (spec §4.3).

JSON document id: `pkcs11-scope/inspect/v1`.

- [ ] **Step 1: Write the failing rendering tests**

In `src/inspect.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::scan::{ScannedEntry, ScannedInterface, ScannedModule, ScannedTable};
    use p11scope_manifest::maps::{Device, ObjectKey};

    fn key(inode: u64) -> ObjectKey {
        ObjectKey { device: Device { major: 8, minor: 1 }, inode }
    }

    fn sample() -> ScanOutcome {
        ScanOutcome::Scanned {
            modules: vec![ScannedModule {
                key: key(11),
                path: "/usr/lib/softhsm/libsofthsm2.so".into(),
                exports: vec!["C_GetFunctionList".into(), "C_GetInterfaceList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: vec![ScannedEntry {
                        name: "C_Initialize",
                        object: key(11),
                        object_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
                        file_offset: 0x1234,
                    }],
                    null_entries: vec!["C_GetFunctionStatus"],
                    address: 0x7f0000001000,
                }],
                interfaces: vec![ScannedInterface {
                    index: 0,
                    name_class: "exact_standard",
                    name_lossy: Some("PKCS 11".into()),
                    flags: 0,
                    table: Some(0),
                }],
            }],
            skipped: vec![],
            scan_ms: 3,
        }
    }

    #[test]
    fn text_names_the_module_version_counts_and_null_entries() {
        let out = render_text(4242, &sample(), &PinnedObjects::empty());
        assert!(out.contains("pid 4242"), "{out}");
        assert!(out.contains("/usr/lib/softhsm/libsofthsm2.so"), "{out}");
        assert!(out.contains("2.40"), "{out}");
        assert!(out.contains("1 entry") || out.contains("1 entries"), "{out}");
        assert!(out.contains("C_GetFunctionStatus"), "NULL slots are evidence: {out}");
        assert!(out.contains("PKCS 11"), "inspect may show interface names: {out}");
    }

    #[test]
    fn an_unavailable_scan_still_lists_the_modules_and_says_why() {
        let outcome = ScanOutcome::Unavailable {
            reason: "ptrace",
            modules: vec![ScannedModule {
                key: key(11),
                path: "/usr/lib/softhsm/libsofthsm2.so".into(),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![],
                interfaces: vec![],
            }],
            skipped: vec![],
        };
        let out = render_text(4242, &outcome, &PinnedObjects::empty());
        assert!(out.contains("libsofthsm2.so"), "modules are known without mem: {out}");
        assert!(out.contains("ptrace"), "the reason must be named: {out}");
        assert!(
            out.contains("CAP_SYS_PTRACE") || out.contains("ptrace_scope"),
            "say what would fix it: {out}"
        );
    }

    #[test]
    fn json_is_stable_and_carries_the_document_id() {
        let value = render_json(4242, &sample(), &PinnedObjects::empty());
        assert_eq!(value["schema"], "pkcs11-scope/inspect/v1");
        assert_eq!(value["pid"], 4242);
        assert_eq!(value["modules"][0]["path"], "/usr/lib/softhsm/libsofthsm2.so");
        assert_eq!(value["modules"][0]["tables"][0]["version"], "2.40");
        assert_eq!(value["modules"][0]["tables"][0]["entries"], 1);
    }
}
```

Add `PinnedObjects::empty()` (a `#[doc(hidden)]`-free, ordinary constructor returning empty
maps) to `src/discovery/identity.rs` — rendering tests need a `PinnedObjects` without a
process.

- [ ] **Step 2: Run and watch them fail**

Run: `cargo +1.88 test --locked --lib inspect`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement**

`render_text` layout (one module per block; keep it grep-friendly):

```
pid 4242 — 1 PKCS#11 module mapped (scan 3ms)

module  /usr/lib/softhsm/libsofthsm2.so
  identity   sha256 <64 hex>  build-id <hex or "-">  dev 8:1  ino 11
  exports    C_GetFunctionList, C_GetInterfaceList
  table      2.40  full  1 entry  (NULL: C_GetFunctionStatus)
  interface  [0] "PKCS 11"  flags 0x0  -> table 2.40
  entries in other objects: /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (2)

skipped: /opt/vendor.so — identity_mismatch
```

When `outcome.unavailable_reason()` is `Some("ptrace")`, print after the header:

```
table scan unavailable: /proc/4242/mem is not readable (ptrace).
  Same-uid targets need kernel.yama.ptrace_scope=0 or the target to be a descendant;
  otherwise CAP_SYS_PTRACE. Modules below come from /proc/4242/maps and .dynsym only.
```

`run` = `PidPin::open(pid)?` → `scan_pid` → `pin_scanned_objects` (skips are appended to the
printed skip list) → render → print → `Ok(0)`; a `maps` read failure returns `Ok(1)` after
printing `p11scope: cannot inspect pid N: <error>`.

- [ ] **Step 4: Add the end-to-end case**

Append to `tests/discovery_scan.rs`:

```rust
#[test]
fn inspect_renders_a_scanned_fixture_end_to_end() {
    let dir = tmp("inspect-e2e");
    let so = build_fixture(&dir, "inspected", &["-DMATRIX_INTERFACES=0"]);
    load_and_populate(&so);
    let hooks = HookRegistry::builtin();
    let outcome = scan_pid(&ScanRequest {
        pid: std::process::id(),
        hints: &[so.clone()],
        hooks: &hooks,
        limits: ScanLimits::default(),
    })
    .unwrap();
    let (pinned, _) =
        p11scope::discovery::identity::pin_scanned_objects(std::process::id(), outcome.modules())
            .unwrap();
    let text = p11scope::inspect::render_text(std::process::id(), &outcome, &pinned);
    assert!(text.contains("inspected.so"), "{text}");
    assert!(text.contains("2.40"), "{text}");
    let json = p11scope::inspect::render_json(std::process::id(), &outcome, &pinned);
    assert_eq!(json["schema"], "pkcs11-scope/inspect/v1");
    assert!(json["modules"][0]["identity"]["sha256"].as_str().unwrap().len() == 64);
}
```

- [ ] **Step 5: Run and commit**

Run: `cargo +1.88 test --locked --lib inspect && cargo +1.88 test --locked --test discovery_scan -- --test-threads=1`
Expected: PASS.

```bash
git add src/inspect.rs src/lib.rs src/discovery/identity.rs tests/discovery_scan.rs
git commit -m "feat: p11scope inspect --pid — list mapped providers, tables and identities"
```

---

## Task 11: `p11scope doctor`

**Files:**
- Create: `src/doctor.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `p11scope::EBPF_OBJECT`, `aya::Ebpf`, `scan`, `PidPin`.
- Produces:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status { Ok(String), Warn(String), Fail(String), NotApplicable(String) }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check { pub name: &'static str, pub status: Status }

/// Every probe this slice's lanes need. Pure formatting is separate so the
/// table layout is testable without any of the probes running.
pub fn probe(pid: Option<u32>, cgroup: Option<&Path>) -> Vec<Check>;
pub fn render(checks: &[Check]) -> String;
/// Exit code: 0 when the capture lane (and the scan lane, if `--pid` was given)
/// is available, 1 otherwise.
pub fn verdict(checks: &[Check]) -> i32;
pub fn run(pid: Option<u32>, cgroup: Option<&Path>) -> Result<i32>;
```

**Checks in this slice** (spec §4.6; the loader-hook and `bpf_send_signal` rows arrive with
Slice 1b-2 — do not print rows for lanes that do not exist yet):

| Row | Source |
| --- | --- |
| `kernel release` | `/proc/sys/kernel/osrelease`, compared with the documented ≥5.15 floor |
| `BTF` | `/sys/kernel/btf/vmlinux` exists and is readable |
| `lockdown` | `/sys/kernel/security/lockdown` (absent ⇒ `none`) |
| `kernel.perf_event_paranoid` | sysctl; ≥3 ⇒ warn that uprobes need `CAP_SYS_ADMIN` |
| `kernel.yama.ptrace_scope` | sysctl; ≥1 ⇒ warn that same-uid non-descendants need `CAP_SYS_PTRACE` |
| `effective capabilities` | `CapEff` from `/proc/self/status`, decoded to the five names that matter |
| `BPF map create` | `Ebpf::load(EBPF_OBJECT)` succeeds |
| `uprobe attach` | attach `p11_entry` to the observer's own libc at `symbol_file_offset(libc, "getpid")`, then drop |
| `/proc/<pid>/maps` | readable (only with `--pid`) |
| `/proc/<pid>/mem` | readable (only with `--pid`) — the scan lane |
| `cgroup path` | directory readable and `cgroup.procs` present (only with `--cgroup`) |

The `uprobe attach` probe finds the observer's own libc by parsing `/proc/self/maps` for the
executable mapping whose path contains `libc.so`, then uses
`p11scope_manifest::elf::symbol_file_offset` — reusing Task 4 rather than hardcoding an
offset. **No BPF program stays loaded after `doctor`:** the `Ebpf` is dropped before
rendering, and the last step asserts it.

- [ ] **Step 1: Write the failing rendering/verdict tests (inline)**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_pads_names_and_shows_every_status_kind() {
        let checks = vec![
            Check { name: "kernel release", status: Status::Ok("7.0.0 (floor 5.15)".into()) },
            Check { name: "kernel.perf_event_paranoid", status: Status::Warn("4 — uprobes need CAP_SYS_ADMIN".into()) },
            Check { name: "uprobe attach", status: Status::Fail("EACCES".into()) },
            Check { name: "/proc/<pid>/mem", status: Status::NotApplicable("no --pid".into()) },
        ];
        let out = render(&checks);
        assert!(out.contains("kernel release"), "{out}");
        assert!(out.contains("ok"), "{out}");
        assert!(out.contains("warn"), "{out}");
        assert!(out.contains("FAIL"), "{out}");
        assert!(out.contains("n/a"), "{out}");
        // Verdict line is always last and always present.
        assert!(out.lines().last().unwrap().starts_with("verdict:"), "{out}");
    }

    #[test]
    fn a_failed_capture_probe_is_a_nonzero_exit_but_warnings_are_not() {
        let ok = vec![Check { name: "uprobe attach", status: Status::Ok("attached and detached".into()) }];
        assert_eq!(verdict(&ok), 0);
        let warn = vec![Check { name: "kernel.yama.ptrace_scope", status: Status::Warn("1".into()) }];
        assert_eq!(verdict(&warn), 0, "a warning is not an unavailable lane");
        let fail = vec![Check { name: "BPF map create", status: Status::Fail("EPERM".into()) }];
        assert_eq!(verdict(&fail), 1);
    }
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `cargo +1.88 test --locked --lib doctor`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `probe`, `render`, `verdict`, `run`**

`render` pads `name` to 34 columns with dots and prints `ok` / `warn` / `FAIL` / `n/a`
followed by the detail, then a final `verdict:` line naming what is available:

```
kernel release .................... ok    7.0.0-28-generic (floor 5.15)
BTF /sys/kernel/btf/vmlinux ....... ok
lockdown .......................... ok    none
kernel.perf_event_paranoid ........ warn  4 — uprobes need CAP_SYS_ADMIN on this host
kernel.yama.ptrace_scope .......... warn  1 — same-uid non-descendants need CAP_SYS_PTRACE
effective capabilities ............ ok    CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE
BPF map create .................... ok
uprobe attach (own libc) .......... ok    attached and detached
/proc/4242/maps ................... ok
/proc/4242/mem .................... FAIL  EACCES — memory scan unavailable for this target
verdict: capture available; memory scan unavailable for pid 4242 (needs CAP_SYS_PTRACE)
```

Capability decoding uses the raw `CapEff` mask with these bit numbers:
`CAP_SYS_PTRACE = 19`, `CAP_SYS_ADMIN = 21`, `CAP_PERFMON = 38`, `CAP_BPF = 39`,
`CAP_CHECKPOINT_RESTORE = 40`.

`verdict` returns 1 when any `Fail` names a lane the invocation asked for: the capture lane
(`BPF map create`, `uprobe attach`) always, the scan lane (`/proc/<pid>/mem`) only with
`--pid`, the cgroup row only with `--cgroup`.

- [ ] **Step 4: Verify no BPF object stays loaded**

Run:

```bash
cargo +1.88 build --locked --release
sudo ./target/release/p11scope doctor; echo "exit=$?"
sudo bpftool prog show | grep -c p11 || echo "no p11scope programs remain (expected)"
```

Expected: the table prints; `bpftool` shows no residual `p11scope` programs.
**This step needs sudo — it is owner-gated.** Without approval, record it `UNRUN` in the
task's commit message and run it in Task 14's gate.

- [ ] **Step 5: Commit**

```bash
git add src/doctor.rs src/lib.rs
git commit -m "feat: p11scope doctor — host and target capability probes with a verdict"
```

---

## Task 12: CLI and capture wiring — manifest-free by default

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Test: `src/cli.rs` inline tests; `tests/artifact_contracts.rs` (usage contract)

**Interfaces:**
- Consumes: everything from Tasks 5–11.
- Produces:

```rust
pub enum Command { Profile(CaptureArgs), Trace(CaptureArgs), Inspect(InspectArgs), Doctor(DoctorArgs) }

pub struct CaptureArgs {
    pub kind: Kind,
    /// `--module` hints; empty ⇒ discover every PKCS#11-looking object in scope.
    pub modules: Vec<PathBuf>,
    /// `--manifest` inputs; empty ⇒ scan only. Repeatable (spec §4.6).
    pub manifests: Vec<PathBuf>,
    pub hooks: HookRegistry,
    pub scope: ScopeArg,
    pub metrics: bool,
    pub duration: Option<Duration>,
    pub out: Option<PathBuf>,
    pub unsafe_requested: bool,
}
pub struct InspectArgs { pub pid: u32, pub modules: Vec<PathBuf>, pub hooks: HookRegistry, pub json: bool }
pub struct DoctorArgs { pub pid: Option<u32>, pub cgroup: Option<PathBuf>, pub module: Option<PathBuf> }

pub fn parse(argv: impl Iterator<Item = String>) -> Result<Command, CliError>;
```

`USAGE` becomes (spec §4.6, minus the 1b-2 lines):

```
usage:
  p11scope profile [--pid <n> | --cgroup <path>] [--module <provider.so>]... [--manifest <m.json>]...
                   [--mode profile|metrics] [--duration <30|30s|5m|1h>] [-o <out.json>]
                   [--hook-symbol <NAME[:functionlist|interfacelist|interface]>]...
                   [--unsafe-unvalidated-metadata]
  p11scope trace   [same scope and discovery options] [--duration <…>] [-o <out.file>]
  p11scope inspect --pid <n> [--module <provider.so>]... [--hook-symbol <…>]... [--json]
  p11scope doctor  [--pid <n>] [--cgroup <path>] [--module <provider.so>]
  p11scope-discover --module <provider.so> [-o <manifest.json>]   (offline helper; executes provider code)

notes: discovery scans the target's mapped memory — no manifest and no helper are required.
--module narrows the scan to named providers; --manifest supplies offsets for a provider the
scan cannot read and is corroborated against the scan when possible. Scanning happens once,
at attach time.
```

**Capture flow in `main.rs`** (replacing `load_plan`):

1. Resolve the scope; for `--pid`, `PidPin::open(pid)` (refusing a pid that does not exist,
   as today).
2. `scan_pid` over the target — for `--cgroup`, over each pid currently in `cgroup.procs`,
   merging modules by `ObjectKey` (a shared provider mapped by ten pods is one module).
3. Read every `--manifest`: `read_manifest` → parse → schema check → `pin_manifest_objects`.
4. **Corroboration (spec §4.12)** for each manifest object:
   - object not mapped in scope, or the scan was unavailable ⇒ keep its offsets, mark the
     module `source: "manifest"`, `corroborated: false`;
   - mapped and the scan found the same `{object, offset}` set ⇒ `corroborated: true`;
   - mapped and the sets differ ⇒ attach the **union**, `discovery_conflicts += 1`;
   - manifest `sha256` ≠ the pinned object's ⇒ ignore that object with an evidence note; it
     is fatal only when it was the sole discovery source and nothing else found tables.
5. `plan::build_from_modules` over scan modules + manifest modules.
6. `pin_scanned_objects` + the manifest pins merge into one `PinnedObjects`.
7. `Session::start` exactly as today.
8. At the end, any manifest module still `corroborated: false` contributes
   `discovery_uncorroborated += 1`.
9. **Zero modules is not an error** (spec §4.10): attach nothing, run the loop, write the
   report, `PARTIAL`, and print
   `p11scope: no PKCS#11 modules discovered in <scope>; run `p11scope inspect --pid <n>` or `p11scope doctor --pid <n>` to see why`.

- [ ] **Step 1: Write the failing CLI tests**

Add to `src/cli.rs`'s test module:

```rust
#[test]
fn capture_needs_no_manifest_and_accepts_repeated_discovery_flags() {
    let Command::Profile(a) = parse(args(&[
        "profile", "--pid", "42",
        "--module", "/opt/a.so", "--module", "/opt/b.so",
        "--manifest", "/tmp/m1.json", "--manifest", "/tmp/m2.json",
        "--hook-symbol", "V_GetTable:interface",
    ]))
    .unwrap() else {
        panic!("expected profile")
    };
    assert_eq!(a.modules.len(), 2);
    assert_eq!(a.manifests.len(), 2);
    assert_eq!(a.hooks.abi("V_GetTable"), Some(HookAbi::Interface));
    assert_eq!(a.scope, ScopeArg::Pid(42));
}

#[test]
fn inspect_and_doctor_parse_with_their_own_rules() {
    let Command::Inspect(i) = parse(args(&["inspect", "--pid", "7", "--json"])).unwrap() else {
        panic!("expected inspect")
    };
    assert_eq!((i.pid, i.json), (7, true));
    assert!(matches!(parse(args(&["inspect"])), Err(CliError::Usage(m)) if m.contains("--pid")));

    let Command::Doctor(d) = parse(args(&["doctor"])).unwrap() else { panic!("expected doctor") };
    assert_eq!((d.pid, d.cgroup), (None, None));
}

#[test]
fn scope_is_still_exactly_one_of_pid_or_cgroup_and_removed_flags_still_hint() {
    assert!(matches!(parse(args(&["profile"])), Err(CliError::Usage(m)) if m.contains("exactly one")));
    assert!(matches!(
        parse(args(&["profile", "--pid", "1", "--cgroup", "/sys/fs/cgroup/x"])),
        Err(CliError::Usage(m)) if m.contains("mutually exclusive")
    ));
    assert!(matches!(
        parse(args(&["profile", "--pid", "1", "--provenance-module", "/opt/x.so"])),
        Err(CliError::Usage(m)) if m.contains("removed in productization slice 1a")
    ));
}

#[test]
fn a_malformed_hook_symbol_is_a_usage_error_naming_the_spec() {
    assert!(matches!(
        parse(args(&["profile", "--pid", "1", "--hook-symbol", "X:bogus"])),
        Err(CliError::Usage(m)) if m.contains("functionlist")
    ));
}
```

- [ ] **Step 2: Run and watch them fail**

Run: `cargo +1.88 test --locked --lib cli`
Expected: FAIL — `parse`/`Command` do not exist; `--manifest` is still required.

- [ ] **Step 3: Implement the parser and the wiring**

Keep `parse_capture` as the shared body and add `parse` dispatching on `argv[0]`. Delete the
`--manifest is required` check; keep the removed-flag hints; add `--module`, `--manifest`
(both `Vec`), `--hook-symbol` (validated through `HookRegistry::add_spec`, its error text
propagated verbatim), `--json` (inspect only).

Then rewrite `main.rs`'s `run()` to dispatch four subcommands and replace `load_plan` with

```rust
/// Discovery for one capture: scan the scope, read and corroborate any manifests,
/// merge into one plan, pin every object. Task 13 adds the evidence return value.
fn discover_plan(args: &CaptureArgs, scope: &Scope) -> Result<(plan::AttachPlan, PinnedObjects)>;
```

implementing steps 1–8 above. `capture_profile`/`capture_trace` keep their shape but take the
plan and the pins instead of `Manifest`; corroboration outcomes are collected into local
counters now and become `DiscoveryEvidence` in Task 13, which changes this signature to
return it as a third element. Keep the counters in a small local struct so Task 13 is a
rename, not a rewrite.

- [ ] **Step 4: Run the tests**

Run: `cargo +1.88 test --locked --workspace --all-targets`
Expected: PASS.

- [ ] **Step 5: Manual smoke (unprivileged)**

```bash
cargo +1.88 build --locked --release
./target/release/p11scope inspect --pid $$ ; echo "exit=$?"
./target/release/p11scope doctor ; echo "exit=$?"
./target/release/p11scope profile --pid 1 2>&1 | head -3   # expect a clean privilege error, not a panic
```

Expected: `inspect` prints "0 PKCS#11 modules mapped" for the shell; `doctor` prints its
table; `profile --pid 1` fails with the unsupported-environment hint (no BPF caps), never a
panic.

- [ ] **Step 6: Commit**

```bash
git add src/cli.rs src/main.rs
git commit -m "feat(cli): manifest-free capture, repeatable --module/--manifest, inspect and doctor"
```

---

## Task 13: Evidence and schema v2

**Files:**
- Modify: `src/render.rs`, `src/trace.rs`, `src/main.rs`
- Rename+modify: `docs/schema/observed-profile-v1.md` → `docs/schema/observed-profile-v2.md`
- Modify: `scripts/check-capture-evidence.py`

**Interfaces:**
- Consumes: `plan::{AttachPlan, ModuleSummary, ModuleId}`, `PinnedObjects`.
- Produces:

```rust
/// What discovery learned, carried into evidence (spec §4.8).
pub struct DiscoveryEvidence {
    pub authority: &'static str,               // "hash-pinned" — the only value this slice emits
    pub modules: Vec<DiscoveredModule>,
    pub conflicts: u64,
    pub uncorroborated: u64,
    pub module_ambiguous: u64,
    pub modules_skipped: Vec<SkippedOut>,
    /// `Some("ptrace")` when the memory scan could not run.
    pub scan_unavailable: Option<String>,
    pub scan_ms: u64,
}
pub struct DiscoveredModule {
    pub dev: (u64, u64),
    pub ino: u64,
    pub sha256: String,
    pub path: String,
    pub build_id: Option<String>,
    pub objects: Vec<ObjectSummary>,
    pub sources: Vec<&'static str>,            // "scan" | "manifest"
    pub corroborated: bool,
    pub tables: Vec<TableSummary>,             // {version, entries, source}
    pub interfaces: usize,
    pub skipped: Vec<SkippedOut>,
}
```

**Schema v2** (`pkcs11-scope/observed-profile/v2`, `…/v2-metrics`):

- `capture.module` → `capture.modules[]`, each `{path, dev, ino, sha256, build_id}`.
- `functions[]` items gain `module: {dev, ino, sha256}`.
- `evidence` gains `authority`, `discovery[]`, `discovery_conflicts`,
  `discovery_uncorroborated`, `module_ambiguous`, `modules_skipped[]`, `scan_unavailable`.
- **Not in this slice:** `attach_gap_ms`, `pause`, `discovery_ring_loss`,
  `discovery_state_failures`, `discovery_truncated`, `discovery_read_failures`,
  `child_still_running`. Slice 1b-2 adds them to the same v2 before anything is published;
  the migration section says so explicitly rather than shipping always-null fields.

**Verdict additions** — every one of these forces `PARTIAL`:
`module_ambiguous > 0`, `discovery_conflicts > 0`, `discovery_uncorroborated > 0`,
`!modules_skipped.is_empty()`, and — the one that is easy to get wrong —
**`discovery.modules.is_empty()`**: a capture that discovered nothing has no attach failures
and no skips, so without this it would read `COMPLETE` while having observed nothing.

- [ ] **Step 1: Write the failing tests**

In `src/render.rs`'s test module:

```rust
#[test]
fn a_capture_that_discovered_nothing_is_never_complete() {
    let mut ev = evidence_fixture();      // the existing all-zero helper
    ev.discovery.modules.clear();
    ev.verdict();
    assert_eq!(ev.completeness, "PARTIAL", "no modules ⇒ nothing was observed");
}

#[test]
fn discovery_gaps_each_force_partial() {
    for mutate in [
        |e: &mut Evidence| e.discovery.conflicts = 1,
        |e: &mut Evidence| e.discovery.uncorroborated = 1,
        |e: &mut Evidence| e.discovery.module_ambiguous = 1,
        |e: &mut Evidence| e.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/x.so".into(),
            reason: "capacity".into(),
        }),
    ] {
        let mut ev = evidence_fixture();
        mutate(&mut ev);
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
    }
}

#[test]
fn v2_json_publishes_modules_and_per_function_module_identity() {
    let v = profile_json(&reports_fixture(), &evidence_fixture(), &state_fixture(), &capture_fixture());
    assert_eq!(v["schema"], "pkcs11-scope/observed-profile/v2");
    assert_eq!(v["capture"]["modules"][0]["path"], "/opt/p11.so");
    assert_eq!(v["capture"]["modules"][0]["sha256"].as_str().unwrap().len(), 64);
    assert!(v["capture"]["module"].is_null(), "v1's singular field is gone");
    assert_eq!(v["evidence"]["authority"], "hash-pinned");
    assert_eq!(v["evidence"]["discovery"][0]["sources"][0], "scan");
    assert_eq!(v["functions"][0]["module"]["ino"], 11);
}

#[test]
fn interface_name_bytes_never_reach_capture_output() {
    // inspect may show names; capture output may not (spec §4.3, allowlist v1).
    let v = profile_json(&reports_fixture(), &evidence_fixture(), &state_fixture(), &capture_fixture());
    let text = serde_json::to_string(&v).unwrap();
    assert!(!text.contains("PKCS 11"), "interface names must not be rendered in capture output");
}
```

- [ ] **Step 2: Run and watch them fail**

Run: `cargo +1.88 test --locked --lib render`
Expected: FAIL — `Evidence.discovery` does not exist; schema is still v1.4.

- [ ] **Step 3: Implement**

Add `pub discovery: DiscoveryEvidence` to `Evidence`; extend `verdict()` with the five
conditions above; replace `CaptureMeta.module`/`build_id` with `CaptureMeta.modules:
&[DiscoveredModule]`; bump both schema ids; add `module` to each `functions[]` item from the
slot's `module_ids[0]` (an ambiguous slot renders `module: null` with `"ambiguous": true`);
add `authority` and the counters to `trace::evidence_line`.

- [ ] **Step 4: Rewrite the schema document**

`git mv docs/schema/observed-profile-v1.md docs/schema/observed-profile-v2.md`, retitle it
`# observed-profile.json schema v2`, update the field tables, and add:

```markdown
## v1.4 → v2 migration

Breaking:
- `capture.module` (one object) → `capture.modules[]` (one entry per discovered module,
  each `{path, dev, ino, sha256, build_id}`). A capture can now legitimately observe more
  than one provider in one process (a p11-kit proxy and its backend), so a single field
  could not stay honest.
- `functions[]` items gain `module: {dev, ino, sha256}`; a slot claimed by two modules
  renders `module: null, ambiguous: true` and is counted, never attributed.

Added:
- `evidence.authority` — `"hash-pinned"`: the provider was pinned by fd, hashed once with
  SHA-256, and re-checked by `fstat` `(ino, size, ctime)` during the capture.
- `evidence.discovery[]` — per module: identity, the objects its entries live in, whether it
  came from the memory `scan` or a `--manifest`, whether a manifest was corroborated by the
  scan, its tables and interface count, and anything skipped.
- `evidence.discovery_conflicts`, `evidence.discovery_uncorroborated`,
  `evidence.module_ambiguous`, `evidence.modules_skipped[]`, `evidence.scan_unavailable`.

Deferred to Slice 1b-2 (same v2, nothing is published yet): `attach_gap_ms`, `pause`,
`child_still_running` and the live-discovery loss counters (`discovery_ring_loss`,
`discovery_state_failures`, `discovery_truncated`, `discovery_read_failures`). They are
absent rather than null: this slice has no live discovery to report on.
```

- [ ] **Step 5: Update the evidence checker**

In `scripts/check-capture-evidence.py`: schema strings → `pkcs11-scope/observed-profile/v2`
and `…/v2-metrics`; `document["capture"]["module"]` → `document["capture"]["modules"][0]`;
add `authority == "hash-pinned"` and `discovery` presence to `exact_common`; add
`discovery_conflicts`/`discovery_uncorroborated`/`module_ambiguous` to the exact-zero counter
set. Extend its `--self-test` fixtures accordingly.

Run: `python3 scripts/check-capture-evidence.py --self-test`
Expected: `self-test: OK`.

- [ ] **Step 6: Run everything and commit**

```bash
cargo +1.88 test --locked --workspace --all-targets
git add src/render.rs src/trace.rs src/main.rs docs/schema/ scripts/check-capture-evidence.py
git commit -m "feat(evidence): discovery[], authority and schema v2 (capture.modules[])"
```

---

## Task 14: Gates, matrix and CI on the manifest-free CLI

**Files:**
- Modify: `scripts/verify-attach-e2e.sh`, `scripts/gates.sh`, `scripts/matrix/*.sh`
- Create: `scripts/verify-inspect-doctor.sh`, `scripts/matrix/verify-proxy-stack.sh`,
  `scripts/attach-pod.sh`
- Modify: `.github/workflows/ci.yml`, `tests/artifact_contracts.rs`

**Interfaces:**
- Consumes: the CLI from Task 12, the checker from Task 13.
- Produces: the evidence the ROADMAP status line in Task 15 cites.

- [ ] **Step 1: Add the manifest-free lane to `verify-attach-e2e.sh`**

Keep the existing manifest lane (it now exercises **corroboration**) and add a first lane
that passes no `--manifest` at all:

```sh
echo "=== observe (manifest-free: memory scan only) ==="
rm -f "$WORK/go"
( while [ ! -f "$WORK/go" ]; do sleep 0.05; done; exec "$WORK/harness" "$MODULE" ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$WORK/build/release/p11scope" profile \
    --pid "$WPID" --mode metrics --duration 20 -o "$WORK/observed-scan.json" \
    > "$WORK/profile-scan.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/profile-scan.log" aggregate-only metrics
touch "$WORK/go"
...
reclaim_root_output "$WORK/observed-scan.json"
python3 scripts/check-capture-evidence.py clean-metrics "$WORK/observed-scan.json" spike/expected.txt
python3 - "$WORK/observed-scan.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
ev = doc["evidence"]
assert ev["authority"] == "hash-pinned", ev["authority"]
assert [m["sources"] for m in ev["discovery"]] == [["scan"]], ev["discovery"]
assert doc["capture"]["modules"][0]["path"].endswith("libsofthsm2.so"), doc["capture"]
print("manifest-free lane: OK")
PY
```

The manifest lane then asserts `sources == ["scan", "manifest"]` and `corroborated == true`.

- [ ] **Step 2: Create `scripts/verify-inspect-doctor.sh` (unprivileged)**

```sh
#!/bin/sh
# Unprivileged contract lane: inspect finds a provider the harness loaded, and
# doctor's verdict matches what this host can actually do. No sudo, no BPF.
set -eu
cd "$(dirname "$0")/.."
MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/inspect
. scripts/lib.sh
mkdir -p "$WORK"
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }
cargo +1.88 build --locked --release --target-dir "$WORK/build"
gcc -O0 -o "$WORK/harness" spike/harness.c -ldl

# A descendant of this shell, so the scan works under yama ptrace_scope=1.
rm -f "$WORK/go"; ( while [ ! -f "$WORK/go" ]; do sleep 0.05; done; exec "$WORK/harness" "$MODULE" ) &
WPID=$!
sleep 0.3
"$WORK/build/release/p11scope" inspect --pid "$WPID" --json > "$WORK/inspect.json"
python3 - "$WORK/inspect.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["schema"] == "pkcs11-scope/inspect/v1", doc["schema"]
paths = [m["path"] for m in doc["modules"]]
assert any(p.endswith("libsofthsm2.so") for p in paths), paths
print("inspect: OK", paths)
PY
touch "$WORK/go"; wait "$WPID" || true
"$WORK/build/release/p11scope" doctor > "$WORK/doctor.txt" 2>&1 || true
grep -q "^verdict:" "$WORK/doctor.txt" || { echo "doctor printed no verdict"; exit 1; }
echo "=== inspect/doctor: ALL OK ==="
```

Note the harness only dlopens the module **after** the go-file, so this lane also proves the
scan sees a provider loaded by `dlopen` before capture starts.

- [ ] **Step 3: Create `scripts/matrix/verify-proxy-stack.sh` (root-gated)**

p11-kit proxy over SoftHSM2 in one process: the harness loads
`/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so`, which loads SoftHSM2 behind it. Assert the
capture reports **two** modules with distinct `sha256`, that `functions[]` entries carry
their module, and that any shared `{object, offset}` is counted once with
`module_ambiguous >= 1`. Skip with a clear message when `p11-kit-proxy.so` is absent.

- [ ] **Step 4: Rewrite `scripts/attach-pod.sh` on the new CLI**

The whole "copy a byte-identical provider out of the container and rewrite manifest paths"
apparatus is gone: attach by cgroup and let the scan read the container's own mapped bytes.

```sh
#!/bin/sh
# Attach to a Kubernetes pod's cgroup and profile whatever PKCS#11 providers its
# processes have mapped. Nothing is copied into or out of the container: the
# observer reads the pod's memory and opens its provider through /proc/<pid>/root.
set -eu
usage() { echo "usage: $0 <pod> [-n namespace] [-- p11scope args...]"; exit 2; }
...
CGROUP=$(kubectl exec ... )   # resolve the pod's cgroup path on the node
exec p11scope profile --cgroup "$CGROUP" "$@"
```

Keep its existing unprivileged argument-refusal self-test and update
`tests/artifact_contracts.rs` to match the new refusal strings.

- [ ] **Step 5: Update `gates.sh`, the matrix scripts and CI**

`gates.sh` gains `scripts/verify-inspect-doctor.sh` first (it is unprivileged and fast, so it
fails early). Every `scripts/matrix/*.sh` drops its `--manifest`/discover step where the scan
suffices, keeping one lane that still passes a manifest so the corroboration path stays
covered. `.github/workflows/ci.yml` gains, before the e2e step:

```yaml
      - run: scripts/verify-inspect-doctor.sh
```

- [ ] **Step 6: Verify the scripts**

Run: `for s in scripts/*.sh scripts/matrix/*.sh; do sh -n "$s" || echo "SYNTAX $s"; done`
Run: `cargo +1.88 test --locked --test artifact_contracts`
Expected: no syntax errors; contract tests pass.

- [ ] **Step 7: Root gates — owner-approved only**

```bash
scripts/verify-inspect-doctor.sh          # unprivileged, run now
sudo -v && scripts/gates.sh               # OWNER APPROVAL REQUIRED
scripts/matrix/verify-proxy-stack.sh      # OWNER APPROVAL REQUIRED (sudo)
scripts/matrix/verify-docker.sh           # OWNER APPROVAL REQUIRED (docker; answers spike §6.4 overlay2)
```

Anything not approved is recorded `UNRUN` in Task 15's status, never as green.

- [ ] **Step 8: Commit**

```bash
git add scripts .github/workflows/ci.yml tests/artifact_contracts.rs
git commit -m "gates/ci: manifest-free e2e lane, inspect/doctor lane, proxy stack, attach-pod on the new CLI"
```

---

## Task 15: Docs, privilege re-measurement and honest status

**Files:**
- Modify: `README.md`, `docs/usage.md`, `docs/privacy/allowlist-v1.md`, `CHANGELOG.md`,
  `docs/superpowers/plans/ROADMAP.md`, `docs/notes/2026-08-16-slice1b-1-spikes.md`

- [ ] **Step 1: `docs/usage.md` — the quickstart loses the discovery step**

Replace the three-step quickstart with:

```sh
# 1. What can this host do, and what does the target map?
p11scope doctor --pid 12345
p11scope inspect --pid 12345

# 2. Attach and aggregate — no manifest, no helper, no provider code executed.
sudo p11scope profile --pid 12345 --duration 60 -o observed-profile.json

# 3. Or stream one line per call.
sudo p11scope trace --cgroup /sys/fs/cgroup/... --duration 15
```

and add a subsection stating plainly what this slice does **not** do: a provider `dlopen`ed
**after** the capture starts is not discovered (the scan runs once, at attach); use
`--manifest` for it or wait for Slice 1b-2's live discovery.

- [ ] **Step 2: `docs/usage.md` — re-measure the privilege table**

Run, and paste the measured rows (this needs sudo — owner-gated; otherwise mark the table
`UNRUN` and keep the previous measured values with their date):

```bash
sudo -E capsh --caps="cap_bpf,cap_perfmon,cap_sys_ptrace+eip" -- -c \
  "./target/release/p11scope profile --pid <softhsm-app> --mode metrics --duration 5"
sudo -E capsh --caps="cap_bpf,cap_perfmon+eip" -- -c \
  "./target/release/p11scope profile --pid <same-uid-descendant> --mode metrics --duration 5"
```

Record for each: the capability set, `perf_event_paranoid`, `yama.ptrace_scope`, and whether
the scan or only the attach succeeded. The claim in the spec's §8 acceptance bullet is
exactly this measurement.

- [ ] **Step 3: `docs/privacy/allowlist-v1.md`**

Add to the allowed-capture inventory: module `path`, `dev`, `ino`, `sha256`, `build_id`
(operator-supplied or filesystem facts about the provider file, not process data), and state
that **interface name bytes are not capture output** — they appear only in `inspect` and
manifests, which are discovery tools. Confirm no new pointer-derived field was added.

- [ ] **Step 4: `README.md` and `CHANGELOG.md`**

README: the "Why" and quickstart lose the helper as a required step; add `inspect`/`doctor`
to the feature list; keep the helper documented as the optional offline path. CHANGELOG gains
an `## Unreleased — productization slice 1b-1` section listing: memory-scan discovery,
`--module`/`--manifest` optional, `inspect`, `doctor`, multi-module capture with per-module
session state, schema v2, and the stated limitation (scan runs once at attach).

- [ ] **Step 5: ROADMAP status**

Replace the 1b-1 bullet's `**Status: IN PROGRESS (started 2026-08-16).**` with a status
paragraph in the exact shape 1a used: commit range, net line delta, the four cargo checks,
the unprivileged suite, each root gate with its result **or `UNRUN`**, and the CI run URL
once observed — nothing claimed that was not run.

- [ ] **Step 6: Final verification**

```bash
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
scripts/verify-inspect-doctor.sh
git log --oneline 3b7c067..HEAD | wc -l          # 3b7c067 = main when 1b-1 started
git diff --stat 3b7c067..HEAD | tail -1
```

Expected: all four green; the inspect/doctor lane OK; the counts recorded in Step 5.

- [ ] **Step 7: Commit**

```bash
git add README.md docs CHANGELOG.md
git commit -m "docs: slice 1b-1 — manifest-free discovery, inspect/doctor, schema v2, measured privileges"
```

---

## Self-review

**Spec coverage.** §4.1 scan → T6. §4.2 elf → T4 (in the manifest crate; the hook *registry*
is T5, since which symbols matter is policy). §4.5 identity/pinning → T7. §4.6 CLI, `inspect`,
`doctor` → T10, T11, T12 (`run` is 1b-2). §4.8 evidence/schema v2 → T13, minus the
live-discovery fields, which the migration section names as 1b-2's. §4.9 privileges → T11
probes them, T15 measures them. §4.10 error handling → T6 (`Unavailable`, `Skipped`), T7
(skips not errors), T12 step 9 (zero modules still reports). §4.12 corroboration → T12
steps 4 and 8, evidence in T13. §4.13 multi-module state → T9. §5 unprivileged tests → T4,
T5, T6, T7, T8, T9, T10, T11; root gates → T14. §6 spikes: 4 (unprivileged half) and 6 → T2,
overlay2 half → T14 step 7; spikes 1, 2, 3, 5 are 1b-2's, as recorded in T1's ROADMAP text.
§8 acceptance: manifest-free `--pid` attach → T14 step 1; `inspect` matches the helper → T6
oracle test + T14 step 2; proxy + backend as two modules with independent state → T8, T9,
T14 step 3; docker/kind on the new CLI with nothing copied in → T14 steps 4–5; `doctor`
explains unavailable lanes → T11. The `run --` and pause bullets are explicitly 1b-2.

**Placeholders.** None: every step names its files, its command and its expected result;
every code step carries the code. The two places that legitimately cannot be filled now —
the measured privilege rows and the CI run URL — are marked as measurements to record, with
the fallback ("mark `UNRUN`") stated.

**Type consistency.** `ObjectKey` is `p11scope_manifest::maps::ObjectKey` everywhere (T3
onward). `ScanOutcome` is the two-variant enum with `modules()`/`skipped()`/
`unavailable_reason()` accessors (T6), used that way in T7, T10, T12. `ModuleId` is defined
in T8 and used in T9, T13. `PinnedObjects` gains `attach_path_for`/`pinned`/`empty` in T7 and
T10 and keeps `attach_path`/`check_unchanged`/`provider_changed` from 1a. `HookRegistry` is
built in T5 and consumed in T6, T10, T12. `DiscoveryEvidence` is defined in T13 and produced
by T12's `discover_plan`; T12 is executed before T13, so its first commit constructs the
struct in the same commit that adds it — if executed strictly in order, add the struct in T13
and have T12 return a placeholder-free tuple until then, or execute T13 before T12. **Chosen
order: T12 then T13**, with T12's `discover_plan` returning the plan and pins only, and T13
adding `DiscoveryEvidence` plus the call that fills it.
