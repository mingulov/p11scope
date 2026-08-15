# Productization Slice 1a — Trust Simplification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the lease/provenance/hardened-oracle authorization lane and its operational
requirements, replace it with hash-pinned object identity, simplify the CLI, and add a CI
skeleton — so that `p11scope profile|trace --manifest … --pid|--cgroup …` works with only the
BPF capabilities (plus `CAP_SYS_PTRACE` for cross-uid targets) and today's gates still pass.

**Architecture:** `verify.rs`, `oracle.rs`, `discover_cmd.rs` and the supervisor fork are
deleted (kept in git history). Two small modules replace what is still needed:
`manifest_input.rs` (bounded manifest read + structural validation, moved code) and
`discovery/identity.rs` (`PinnedObjects`: open + size + SHA-256 once + executable-offset check
+ `fstat` `(ino, size, ctime)` change detection). `output.rs` publishes the profile JSON
atomically (temp + rename). `cli.rs` is the single argument parser. `main.rs` becomes a
single-process capture loop. The `p11scope-discover` helper stays as a standalone offline
tool (its control-fd handshake and `suid_dumpable` requirement go). Every gate script drops
the trusted-staging/sysctl helpers and calls the binaries directly under `sudo`. A GitHub
Actions workflow runs the unprivileged checks and the e2e gate.

**Tech Stack:** Rust 1.88, edition 2024, aya 0.14, `signal-hook`, `libc`, existing
`p11scope-manifest` crate (`sha2`, `object`), POSIX `sh` scripts, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md`
(§4.5, §4.6, §4.10, §4.11, §5, §7 "Productization Slice 1a"; §2 decisions).

## Global Constraints

- Rust 1.88, edition 2024, Linux x86-64 first (`CLAUDE.md`).
- All four checks green at every commit: `cargo +1.88 fmt --all -- --check`,
  `cargo +1.88 check --locked --workspace --all-targets`,
  `cargo +1.88 test --locked --workspace --all-targets`,
  `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings`.
- Do not track generated output. Privileged or container experiments (running the gate
  scripts under `sudo`, docker, kind) require explicit owner approval — the plan runs them
  only in CI or on request; every script change is verified locally with `sh -n` and, where a
  script has one, its `--self-test`.
- Privacy allowlist (`docs/privacy/allowlist-v1.md`) unchanged; capture policy code in
  `attach.rs`/`crates/ebpf` unchanged.
- No new dependencies. No `clap`.
- Manifest schema stays `p11scope-manifest/4`; profile schema stays
  `pkcs11-scope/observed-profile/v1.4` / `v1.1-metrics` in this slice (the additive evidence
  field `provider_changed` is documented as a v1.4 addendum; the v2 bump is Slice 1b).
- The deletion commit message must record that the lane existed and was removed
  deliberately (spec §4.11).

---

## File map

| Path | Action | Responsibility after 1a |
| --- | --- | --- |
| `docs/superpowers/plans/ROADMAP.md` | modify | Productization slices recorded; old lane marked removed |
| `src/manifest_input.rs` | create | `read_manifest`, `validate_structure`, size caps (moved from `verify.rs`) |
| `src/discovery/mod.rs`, `src/discovery/identity.rs` | create | `PinnedObjects`, `pin_manifest_objects`, `check_unchanged`, `attach_path` |
| `src/output.rs` | create | `AtomicFile` temp+rename publish for `-o` profile JSON |
| `src/cli.rs` | create | `CaptureArgs`, `parse_capture`, `parse_duration`, removed-flag hints |
| `src/main.rs` | rewrite | dispatch, single-process capture loops, SIGINT+SIGTERM flag |
| `src/attach.rs` | modify | import `PinnedObjects`; drop `_config`/`_cgroup_file` dead fields |
| `src/render.rs` | modify | `Evidence.provider_changed` (verdict, live, JSON) |
| `src/trace.rs` | modify | delete `abort_evidence_line` (only the supervisor used it) |
| `src/lib.rs` | modify | module list |
| `src/verify.rs`, `src/oracle.rs`, `src/discover_cmd.rs` | delete | — |
| `crates/manifest/src/identity.rs` | modify | delete `inspect_elf_loader` + loader-graph validator (lines 232–543) |
| `crates/manifest/tests/identity.rs` | modify | delete loader-graph tests |
| `crates/discover/src/main.rs` | modify | delete `--control-fd` handshake and `suid_dumpable` requirement |
| `crates/discover/tests/control_protocol.rs` | delete | — |
| `tests/lease_break.rs`, `tests/provenance_lease_break.rs`, `tests/cli_discover.rs` | delete | — |
| `tests/reuse.rs` → `tests/manifest_pinning.rs` | rename+modify | pinning/structure tests on the new API |
| `tests/release_contracts.rs` → `tests/artifact_contracts.rs` | rename+modify | four artifact-executing tests only |
| `scripts/trusted-p11scope.sh` → `scripts/lib.sh` | rename+modify | shared script helpers minus staging/sysctl |
| `scripts/attach-pod.sh`, `scripts/container-authority.py` | delete | rewritten/replaced in Slice 1b |
| `scripts/*.sh`, `scripts/matrix/*.sh` | modify | new CLI, no staging, no sysctl |
| `scripts/gates.sh` | create | one local entry point for the root gates |
| `.github/workflows/ci.yml` | create | unprivileged checks + `sudo` e2e job |
| `README.md`, `docs/usage.md`, `CHANGELOG.md`, `docs/schema/observed-profile-v1.md` | modify | CLI sync, lane removal, `provider_changed` addendum |

---

### Task 1: ROADMAP records the productization slices

**Files:**
- Modify: `docs/superpowers/plans/ROADMAP.md`

- [ ] **Step 1: Add the productization section**

Append after the "Explicitly deferred" section:

```markdown
## Productization (2026-08-15 →)

Input: `docs/notes/2026-08-15-architecture-and-gap-analysis.md` (review + decisions A1–A7)
and `docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md`.

- **Slice 1a — trust simplification** ([plan](2026-08-15-productization-slice1a-trust-simplification.md)):
  the lease/provenance/hardened-oracle lane of `2026-08-13-manifest-provenance.md` is
  **removed** (kept in git history; see the spec §4.11 and §10.6). Object identity is
  hash-pinned (SHA-256 once, `fstat` change detection). CLI drops `--provenance-module`,
  `--trusted-workload`, the `p11scope discover` subcommand and exit code 78. CI skeleton.
- **Slice 1b — discovery engine and commands**: memory-scan + loader/export-hook discovery,
  `run`, `inspect`, `doctor`, `--module` optional, schema v2. Plan written after 1a lands.
- **Slice 2 — capture quality**: ring/epoll, budgets, safe-policy params, per-module profile
  sections, filters, snapshots.
- **Slice 3 — structure**: module split, evidence plumbing, docs consolidation, multi-kernel CI.
- Then AArch64, 32-bit counting mode, `uprobe_multi`, freezer pause, manifest catalog.

**Gate for each slice:** the four cargo checks, the unprivileged suite, and the CI e2e job
green; root gates run locally with owner approval.
```

- [ ] **Step 2: Mark the provenance plan status**

At the top of `docs/superpowers/plans/2026-08-13-manifest-provenance.md`, directly under the
title, add:

```markdown
> **Status (2026-08-15): removed by Productization Slice 1a.** The lane this plan built is
> deleted from the tree (restorable from git history); see
> `docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md`
> §4.11 and §10.6 for the reasoning. Kept as history.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/ROADMAP.md docs/superpowers/plans/2026-08-13-manifest-provenance.md
git commit -m "docs: ROADMAP — productization slices; provenance plan marked removed by slice 1a"
```

---

### Task 2: `manifest_input.rs` — bounded read and structural validation (moved code)

**Files:**
- Create: `src/manifest_input.rs`
- Modify: `src/lib.rs` (add `pub mod manifest_input;`)
- Test: `tests/manifest_pinning.rs` (new file; starts with the two input tests)

**Interfaces:**
- Produces: `pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;`
  `pub const MAX_TOTAL_OBJECT_BYTES: u64 = 512 * 1024 * 1024;`
  `pub fn read_manifest(path: &Path) -> Result<String, String>` (moved verbatim from
  `src/verify.rs:1329-1350`), `pub fn validate_structure(m: &Manifest) -> Vec<String>`
  (moved verbatim from `src/verify.rs:1602-2062`, together with every private helper and
  constant it uses: `MAX_OBJECTS`, `MAX_SURFACES`, `MAX_FUNCTIONS`, `MAX_PATH_BYTES`,
  `MAX_DETAIL_BYTES`).

- [ ] **Step 1: Write the failing tests**

Create `tests/manifest_pinning.rs` by copying the helper functions `tmpdir`, `cc_so`,
`cc_so_with_build_id`, `manifest_for`, `first_executable_offset`, `walked_legacy_manifest`
from `tests/reuse.rs` (lines 10–126, verbatim), then add these two tests copied from
`tests/reuse.rs` (`manifest_input_is_regular_utf8_and_bounded`,
`aggregate_object_bytes_are_refused_before_parsing`) with the call sites changed:

```rust
use p11scope::manifest_input::{read_manifest, MAX_MANIFEST_BYTES};
// ...body of manifest_input_is_regular_utf8_and_bounded, verbatim, calling read_manifest
```

For `aggregate_object_bytes_are_refused_before_parsing`, replace the call to
`p11scope::verify::check_reuse(&m)` with `p11scope::discovery::identity::pin_manifest_objects(&m)`
(the function lands in Task 3; keep the test but mark it `#[ignore = "task 3"]` until then).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo +1.88 test --locked --test manifest_pinning`
Expected: compile error `could not find manifest_input in p11scope`.

- [ ] **Step 3: Move the code**

Create `src/manifest_input.rs` with the module doc `//! Manifest input hygiene: bounded read
and structural validation of `p11scope-manifest/4` documents. Trusted operator input, validated
before use.` and move (cut, do not copy) from `src/verify.rs`: the constants at lines 20–26
(rename nothing), `read_manifest` (1329–1350) and the whole `validate_structure` block with its
helpers (1602–2062). Keep `use` lines minimal (`std::io::Read`, `std::path::Path`,
`p11scope_manifest::identity::open_regular`, `p11scope_manifest::manifest::*`). In
`src/verify.rs` add `use crate::manifest_input::{read_manifest, validate_structure,
MAX_MANIFEST_BYTES, MAX_TOTAL_OBJECT_BYTES};` and `pub use` re-exports so `main.rs` and
`discover_cmd.rs` keep compiling for now:

```rust
pub use crate::manifest_input::{read_manifest, MAX_MANIFEST_BYTES, MAX_TOTAL_OBJECT_BYTES};
```

Add `pub mod manifest_input;` to `src/lib.rs`.

- [ ] **Step 4: Run the checks**

Run: `cargo +1.88 test --locked --workspace --all-targets && cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings`
Expected: PASS (the moved code is unchanged; `manifest_pinning` input test passes; the
ignored test is skipped).

- [ ] **Step 5: Commit**

```bash
git add src/manifest_input.rs src/lib.rs src/verify.rs tests/manifest_pinning.rs
git commit -m "refactor: move manifest input hygiene into manifest_input.rs"
```

---

### Task 3: `discovery/identity.rs` — pinned objects without leases

**Files:**
- Create: `src/discovery/mod.rs`, `src/discovery/identity.rs`
- Modify: `src/lib.rs` (add `pub mod discovery;`)
- Test: `tests/manifest_pinning.rs`

**Interfaces:**
- Consumes: `manifest_input::{validate_structure, MAX_TOTAL_OBJECT_BYTES}`,
  `p11scope_manifest::identity::{open_object, inspect_file, ObjectIdentity, InspectedObject}`,
  `p11scope_manifest::manifest::{Manifest, Resolution}`.
- Produces:

```rust
pub struct PinnedObjects { /* private */ }
impl PinnedObjects {
    /// `/proc/self/fd/N` for aya to reopen the pinned inode (never the manifest path).
    pub fn attach_path(&self, original: &str) -> Result<PathBuf, String>;
    /// `Ok(true)` when every pinned object still has the (ino, size, ctime) seen at
    /// pinning; `Ok(false)` when any changed (the caller records `provider_changed`);
    /// `Err` only when `fstat` itself fails.
    pub fn check_unchanged(&self) -> Result<bool, String>;
    /// (path, identity) of every pinned object, for `capture.module` rendering.
    pub fn identities(&self) -> impl Iterator<Item = (&str, &ObjectIdentity)>;
}
/// Structural validation + open + size cap + identity match + executable-offset check.
pub fn pin_manifest_objects(m: &Manifest) -> Result<PinnedObjects, Vec<String>>;
```

- [ ] **Step 1: Write the failing tests**

In `tests/manifest_pinning.rs`, add (copied from `tests/reuse.rs`, with
`p11scope::verify::check_reuse` → `p11scope::discovery::identity::pin_manifest_objects` and
`VerifiedObjects` → `PinnedObjects`): `matching_identity_is_accepted`,
`changed_object_is_refused_naming_the_file`, `vanished_object_is_refused`,
`non_reusable_identity_is_refused_even_if_unchanged`,
`relative_and_duplicate_manifest_objects_are_refused`,
`symlink_is_pinned_and_non_executable_offsets_are_refused`,
`reordered_or_unknown_standard_function_names_are_refused`,
`every_supported_table_boundary_passes_structural_reuse_validation`,
`acquisition_evidence_cannot_be_omitted_or_invented`,
`manifest_v4_requires_a_whole_file_provenance_closure`; un-ignore
`aggregate_object_bytes_are_refused_before_parsing`. Then add two new tests:

```rust
#[test]
fn unchanged_objects_report_true_and_in_place_write_reports_false() {
    let dir = tmpdir();
    let so = cc_so(&dir, "provider", "int f(void){return 1;}");
    let m = manifest_for(&[&so]);
    let pinned = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap();
    assert_eq!(pinned.check_unchanged().unwrap(), true);
    // An in-place append changes size and ctime; the pinned fd sees it.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let mut f = std::fs::OpenOptions::new().append(true).open(&so).unwrap();
    std::io::Write::write_all(&mut f, b"\0").unwrap();
    assert_eq!(pinned.check_unchanged().unwrap(), false);
}

#[test]
fn replacing_the_file_by_rename_keeps_the_pinned_inode_unchanged() {
    let dir = tmpdir();
    let so = cc_so(&dir, "provider", "int f(void){return 1;}");
    let m = manifest_for(&[&so]);
    let pinned = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap();
    let other = cc_so(&dir, "other", "int g(void){return 2;}");
    std::fs::rename(&other, &so).unwrap(); // new inode at the old path
    assert_eq!(pinned.check_unchanged().unwrap(), true, "the old inode is what we hold");
    let path = pinned.attach_path(so.to_str().unwrap()).unwrap();
    assert!(path.starts_with("/proc/self/fd/"));
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo +1.88 test --locked --test manifest_pinning`
Expected: compile error `could not find discovery in p11scope`.

- [ ] **Step 3: Implement**

`src/discovery/mod.rs`:

```rust
//! Discovery: how the observer learns which objects/offsets to probe and pins their
//! identity. Slice 1a: manifest input only (`identity`). Slice 1b adds scan/live/pause.
pub mod identity;
```

`src/discovery/identity.rs` — take `check_reuse` (`src/verify.rs:2280-2410`) as the body of
`pin_manifest_objects` and make exactly these changes: delete every `lease` line
(`LeaseMonitor::new`, `lease.acquire`, `lease.ensure`); after opening and inspecting each
object, record its `fstat` pin; return `PinnedObjects`:

```rust
use std::collections::BTreeMap;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use p11scope_manifest::identity::{inspect_file, open_object, ObjectIdentity};
use p11scope_manifest::manifest::{Manifest, Resolution};

use crate::manifest_input::{validate_structure, MAX_TOTAL_OBJECT_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pin {
    ino: u64,
    size: u64,
    ctime: (i64, i64),
}

fn pin_of(file: &std::fs::File) -> Result<Pin, String> {
    let md = file
        .metadata()
        .map_err(|error| format!("fstat failed: {error}"))?;
    Ok(Pin {
        ino: md.ino(),
        size: md.len(),
        ctime: (md.ctime(), md.ctime_nsec()),
    })
}

#[derive(Debug)]
pub struct PinnedObjects {
    files: BTreeMap<String, std::fs::File>,
    identities: BTreeMap<String, ObjectIdentity>,
    pins: BTreeMap<String, Pin>,
}

impl PinnedObjects {
    pub fn attach_path(&self, original: &str) -> Result<PathBuf, String> {
        self.files
            .get(original)
            .map(|file| PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())))
            .ok_or_else(|| format!("object path {original:?} was not pinned"))
    }

    pub fn check_unchanged(&self) -> Result<bool, String> {
        for (path, file) in &self.files {
            let now = pin_of(file).map_err(|error| format!("{path}: {error}"))?;
            if now != self.pins[path] {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn identities(&self) -> impl Iterator<Item = (&str, &ObjectIdentity)> {
        self.identities.iter().map(|(p, i)| (p.as_str(), i))
    }
}

pub fn pin_manifest_objects(m: &Manifest) -> Result<PinnedObjects, Vec<String>> {
    // body of check_reuse with the lease calls removed and, in the final loop:
    //   let pin = pin_of(&file).map_err(|e| vec![format!("{path}: {e}")])?;
    //   pins.insert(path.clone(), pin);
    // ...
}
```

Keep the error strings of `check_reuse` verbatim (tests assert on them), except the
`re-run \`p11scope discover\`` hint which becomes `re-run \`p11scope-discover\``.

- [ ] **Step 4: Run the tests**

Run: `cargo +1.88 test --locked --test manifest_pinning`
Expected: PASS for all tests in the file (the `an_existing_writer_prevents_object_authorization`
lease test is *not* carried over).

- [ ] **Step 5: Full checks and commit**

Run: `cargo +1.88 fmt --all && cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings && cargo +1.88 test --locked --workspace --all-targets`

```bash
git add src/discovery tests/manifest_pinning.rs src/lib.rs
git commit -m "feat: hash-pinned object identity without leases (discovery::identity)"
```

---

### Task 4: `output.rs` — atomic profile publication

**Files:**
- Create: `src/output.rs`
- Modify: `src/lib.rs`
- Test: unit tests inside `src/output.rs`

**Interfaces:**
- Produces:

```rust
pub struct AtomicFile { /* temp path, final path, File */ }
impl AtomicFile {
    /// Creates `<dir>/.<name>.p11scope.<pid>.tmp` next to `path` (0o644 minus umask).
    pub fn create(path: &Path) -> std::io::Result<AtomicFile>;
    pub fn file(&mut self) -> &mut std::fs::File;
    /// fsync + rename over `path`. Consumes self.
    pub fn commit(self) -> std::io::Result<()>;
}
impl Drop for AtomicFile { /* removes the temp file if not committed */ }
```

- [ ] **Step 1: Write the failing tests** (in `src/output.rs`, `#[cfg(test)] mod tests`)

```rust
#[test]
fn commit_publishes_atomically_and_replaces_stale_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("observed.json");
    std::fs::write(&path, b"stale").unwrap();
    let mut a = AtomicFile::create(&path).unwrap();
    std::io::Write::write_all(a.file(), b"{\"ok\":true}").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"stale", "not visible before commit");
    a.commit().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"{\"ok\":true}");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "no temp left");
}

#[test]
fn drop_without_commit_leaves_no_temp_and_no_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("observed.json");
    {
        let mut a = AtomicFile::create(&path).unwrap();
        std::io::Write::write_all(a.file(), b"partial").unwrap();
    }
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
```

- [ ] **Step 2: Run to verify they fail** — `cargo +1.88 test --locked --lib output` → compile error.

- [ ] **Step 3: Implement**

```rust
//! Atomic publication of the `-o` profile document: write a sibling temp file, fsync,
//! rename. A capture that dies mid-write never leaves a half-written report.
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

pub struct AtomicFile {
    temp: PathBuf,
    target: PathBuf,
    file: Option<File>,
}

impl AtomicFile {
    pub fn create(path: &Path) -> std::io::Result<Self> {
        let target = std::path::absolute(path)?;
        let dir = target.parent().ok_or_else(|| std::io::Error::other("output path has no parent"))?;
        let name = target.file_name().ok_or_else(|| std::io::Error::other("output path has no file name"))?;
        let temp = dir.join(format!(".{}.p11scope.{}.tmp", name.to_string_lossy(), std::process::id()));
        let file = OpenOptions::new().write(true).create_new(true).open(&temp)?;
        Ok(Self { temp, target, file: Some(file) })
    }

    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("file present until commit")
    }

    pub fn commit(mut self) -> std::io::Result<()> {
        let file = self.file.take().expect("commit once");
        file.sync_all()?;
        drop(file);
        std::fs::rename(&self.temp, &self.target)?;
        Ok(())
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if self.file.is_some() {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}
```

Add `pub mod output;` to `src/lib.rs`.

- [ ] **Step 4: Run** — `cargo +1.88 test --locked --lib output` → PASS.
- [ ] **Step 5: Commit** — `git add src/output.rs src/lib.rs && git commit -m "feat: atomic profile publication (output::AtomicFile)"`

---

### Task 5: `cli.rs` — one argument parser, durations with suffixes, removed-flag hints

**Files:**
- Create: `src/cli.rs`
- Modify: `src/lib.rs`
- Test: unit tests inside `src/cli.rs`

**Interfaces:**
- Produces:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind { Profile, Trace }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeArg { Pid(u32), Cgroup(PathBuf) }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureArgs {
    pub kind: Kind,
    pub manifest: PathBuf,
    pub scope: ScopeArg,
    pub metrics: bool,               // --mode metrics (profile only)
    pub duration: Option<Duration>,
    pub out: Option<PathBuf>,
    pub unsafe_requested: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub enum CliError { Usage(String), Help }
pub const USAGE: &str = "...";      // moved from main.rs, updated
pub fn parse_capture(kind: Kind, args: impl Iterator<Item = String>) -> Result<CaptureArgs, CliError>;
pub fn parse_duration(s: &str) -> Result<Duration, String>;   // "30" | "30s" | "5m" | "1h"
```

Removed flags produce `CliError::Usage` with a specific hint:
`--provenance-module` / `--trusted-workload` → "removed in productization slice 1a: the
observer pins provider identity by SHA-256 and fstat; see docs/usage.md";
`--mode trace` → "trace is a subcommand: `p11scope trace …`".

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn args(v: &[&str]) -> impl Iterator<Item = String> { v.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter() }

    #[test]
    fn duration_accepts_bare_seconds_and_suffixes() {
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("-1").is_err());
    }

    #[test]
    fn profile_requires_manifest_and_exactly_one_scope() {
        let a = parse_capture(Kind::Profile, args(&["--manifest", "m.json", "--pid", "12", "--duration", "2m", "-o", "out.json"])).unwrap();
        assert_eq!(a.scope, ScopeArg::Pid(12));
        assert_eq!(a.duration, Some(Duration::from_secs(120)));
        assert!(matches!(parse_capture(Kind::Profile, args(&["--pid", "1"])), Err(CliError::Usage(m)) if m.contains("--manifest is required")));
        assert!(matches!(parse_capture(Kind::Profile, args(&["--manifest", "m", "--pid", "1", "--cgroup", "/sys/fs/cgroup/x"])), Err(CliError::Usage(m)) if m.contains("mutually exclusive")));
        assert!(matches!(parse_capture(Kind::Profile, args(&["--manifest", "m"])), Err(CliError::Usage(m)) if m.contains("exactly one of --pid or --cgroup")));
    }

    #[test]
    fn removed_flags_get_a_named_hint() {
        for flag in ["--provenance-module", "--trusted-workload"] {
            let err = parse_capture(Kind::Profile, args(&["--manifest", "m", "--pid", "1", flag, "x"])).unwrap_err();
            assert!(matches!(err, CliError::Usage(m) if m.contains("removed in productization slice 1a")), "{flag}");
        }
        assert!(matches!(parse_capture(Kind::Profile, args(&["--manifest", "m", "--pid", "1", "--mode", "trace"])), Err(CliError::Usage(m)) if m.contains("trace is a subcommand")));
    }

    #[test]
    fn trace_rejects_mode_and_accepts_the_rest() {
        assert!(matches!(parse_capture(Kind::Trace, args(&["--manifest", "m", "--pid", "1", "--mode", "metrics"])), Err(CliError::Usage(_))));
        let a = parse_capture(Kind::Trace, args(&["--manifest", "m", "--cgroup", "/sys/fs/cgroup/x", "--unsafe-unvalidated-metadata"])).unwrap();
        assert!(a.unsafe_requested);
        assert_eq!(a.scope, ScopeArg::Cgroup(PathBuf::from("/sys/fs/cgroup/x")));
    }

    #[test]
    fn help_is_not_an_error() {
        assert_eq!(parse_capture(Kind::Profile, args(&["--help"])).unwrap_err(), CliError::Help);
    }
}
```

- [ ] **Step 2: Run** — `cargo +1.88 test --locked --lib cli` → compile error.

- [ ] **Step 3: Implement** — a `while let Some(a) = args.next()` loop like today's
`cmd_profile`, producing `CliError::Usage(format!("{msg}\n{USAGE}"))` where main.rs used
`eprintln!(…); exit(2)`. `USAGE` text:

```
usage:
  p11scope profile --manifest <m.json> (--pid <n> | --cgroup <path>) [--mode profile|metrics] [--unsafe-unvalidated-metadata] [--duration <30|30s|5m|1h>] [-o <out.json>]
  p11scope trace   --manifest <m.json> (--pid <n> | --cgroup <path>) [--unsafe-unvalidated-metadata] [--duration <…>] [-o <out.file>]
  p11scope-discover --module <provider.so> [-o <manifest.json>]   (offline helper; executes provider code)

notes: --mode defaults to profile; --mode metrics is the lighter maps-only level.
Ctrl-C or SIGTERM ends a capture cleanly (final frame printed, -o written). --cgroup matches
that cgroup and every descendant (kernel >= 5.15). Provider identity is pinned by SHA-256 at
attach and checked for in-place change during capture (evidence.provider_changed).
```

`parse_duration`: split trailing `s|m|h`, parse `u64`, reject empty/negative/other.

- [ ] **Step 4: Run** — `cargo +1.88 test --locked --lib cli` → PASS.
- [ ] **Step 5: Commit** — `git add src/cli.rs src/lib.rs && git commit -m "feat: single CLI parser with duration suffixes and removed-flag hints"`

---

### Task 6: `render::Evidence.provider_changed`

**Files:**
- Modify: `src/render.rs` (struct at 10–93, `verdict` 109–152, `live` 182–365, JSON is via
  `Serialize`), `src/trace.rs` (test literals at 406–447), `src/main.rs:933-1004`
  (`evidence_for` literal — add the field with `false`; the real value is wired in Task 7)
- Test: `src/render.rs` tests

- [ ] **Step 1: Failing test** (in `render.rs` tests, next to `any_gap_forces_partial`):

```rust
#[test]
fn provider_change_forces_partial_and_is_shown_live() {
    let mut ev = clean_evidence();            // the existing all-zero fixture helper in this test module
    ev.verdict();
    assert_eq!(ev.completeness, "COMPLETE");
    ev.provider_changed = true;
    ev.verdict();
    assert_eq!(ev.completeness, "PARTIAL");
    let frame = live(&[], &ev, std::time::Duration::from_secs(1), "/x.so", "profile", CapturePolicy::Allowlisted);
    assert!(frame.contains("provider changed"), "{frame}");
    let json = serde_json::to_value(&ev).unwrap();
    assert_eq!(json["provider_changed"], serde_json::Value::Bool(true));
}
```

(If the test module names its fixture differently, use that name; do not add a second
fixture.)

- [ ] **Step 2: Run** — `cargo +1.88 test --locked --lib render::tests::provider_change` → compile error (no field).
- [ ] **Step 3: Implement** — add `pub provider_changed: bool` (doc: "A pinned provider
object changed (ino, size or ctime) after attach; probes may no longer describe the mapped
bytes.") to `Evidence`; `&& !self.provider_changed` in `verdict()`; in `live()` add
`" · provider changed"` to the gap line when true; add `provider_changed: false` to every
`Evidence { … }` literal the compiler points at (`main.rs`, `render.rs` tests, `trace.rs`
tests).
- [ ] **Step 4: Run** — full `cargo +1.88 test --locked --workspace --all-targets` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: evidence.provider_changed (in-place provider change forces PARTIAL)"`

---

### Task 7: `main.rs` — single-process capture on the new modules

**Files:**
- Modify: `src/main.rs` (rewrite), `src/attach.rs:5` (import), `src/attach.rs:185-191,674`
  (drop `_config`, `_cgroup_file` fields and their assignments — they are never read)
- Test: `src/main.rs` unit tests

**Interfaces:**
- Consumes: `cli::{parse_capture, Kind, ScopeArg, CaptureArgs, CliError, USAGE}`,
  `manifest_input::read_manifest`, `discovery::identity::{pin_manifest_objects, PinnedObjects}`,
  `output::AtomicFile`, `attach::{Session, Scope, CapturePolicy}` (Session::start now takes
  `&PinnedObjects`), `scope::cgroup_id`, and the unchanged
  `events/metrics/semantics/process/trace/render/plan/shapes` APIs.

- [ ] **Step 1: Write the failing tests** (replace the test module of `main.rs`; keep
`ebpf_object_is_a_real_bpf_elf`, `fmt_rfc3339_matches_a_known_instant`,
`should_stop_*`, `fork_only_traffic_does_not_consume_process_tracking_budget`,
`broken_stdout_closes_only_that_sink_and_file_continues`,
`trace_file_write_and_flush_errors_propagate`, `policy_output_unsafe_flag_is_refused_before_manifest_loading`
(now via `cli::parse_capture` + `CapturePolicy::from_cli`) and adapt these):

```rust
#[test]
fn manifest_v1_and_v2_are_rejected_with_rediscovery_instruction() {
    for schema in ["p11scope-manifest/1", "p11scope-manifest/2"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.json");
        std::fs::write(&path, format!(r#"{{"schema":"{schema}","module_path":"/opt/p.so","objects":[],"interface_list":{{"status":"absent"}},"surfaces":[],"vendor_interfaces":[],"alias_groups":[]}}"#)).unwrap();
        let err = load_plan(&path).unwrap_err().to_string();
        assert!(err.contains("rediscover"), "{err}");
    }
}

#[test]
fn stop_flag_is_shared_by_sigint_and_sigterm() {
    // install_stop_flag registers both; assert both consts are wired by reading the
    // function's registration list (kept as a const so the test can see it).
    assert_eq!(STOP_SIGNALS, [libc::SIGINT, libc::SIGTERM]);
}
```

Delete `terminal_detach_precedes_snapshot_and_unproven_drain_mark_precedes_output` (source-grep
test) and `policy_output_discover_rejects_unsafe_flag_before_helper_lookup` (subcommand gone).

- [ ] **Step 2: Run** — `cargo +1.88 test --locked --bin p11scope` → compile errors.

- [ ] **Step 3: Rewrite `main.rs`**

Structure (keep every helper not mentioned here verbatim: `report_attach_failures`,
`load_mech_shapes`, `warn_unsafe_policy`, `identify_tracked`, `retire_exited`, `observe_fork`,
`write_json_report` → now writes into `AtomicFile::file()`, `emit_trace_line`, `write_stdout`,
`flush_stdout`, `drain_trace_events`, `report_trace_loss`, `evidence_for` (+`provider_changed`
parameter), `fmt_rfc3339`):

```rust
use p11scope::cli::{self, CliError, Kind, ScopeArg};
use p11scope::discovery::identity::{pin_manifest_objects, PinnedObjects};
use p11scope::manifest_input::read_manifest;
use p11scope::output::AtomicFile;

const STOP_SIGNALS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGTERM];

fn install_stop_flag() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    for sig in STOP_SIGNALS {
        signal_hook::flag::register(sig, Arc::clone(&flag))
            .with_context(|| format!("installing handler for signal {sig}"))?;
    }
    Ok(flag)
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("profile") => cmd_capture(Kind::Profile, args),
        Some("trace") => cmd_capture(Kind::Trace, args),
        Some("discover") => {
            eprintln!("`p11scope discover` was removed: run `p11scope-discover --module <provider.so> -o <manifest.json>` (offline helper; executes provider code)\n{}", cli::USAGE);
            std::process::exit(2);
        }
        Some("--help") | Some("-h") => { eprintln!("{}", cli::USAGE); Ok(()) }
        other => { eprintln!("unknown or missing subcommand: {}\n{}", other.unwrap_or("(none)"), cli::USAGE); std::process::exit(2); }
    }
}

fn cmd_capture(kind: Kind, args: impl Iterator<Item = String>) -> Result<()> {
    let a = match cli::parse_capture(kind, args) {
        Ok(a) => a,
        Err(CliError::Help) => { eprintln!("{}", cli::USAGE); return Ok(()); }
        Err(CliError::Usage(msg)) => { eprintln!("{msg}"); std::process::exit(2); }
    };
    let mode = match (kind, a.metrics) { (Kind::Trace, _) => "trace", (Kind::Profile, true) => "metrics", (Kind::Profile, false) => "profile" };
    let policy = CapturePolicy::from_cli(mode, a.unsafe_requested, cfg!(feature = "unsafe-unvalidated-metadata"))?;
    let scope = match &a.scope {
        ScopeArg::Pid(p) => Scope::Pid(*p),
        ScopeArg::Cgroup(c) => Scope::Cgroup { id: scope::cgroup_id(c)?, path: c.clone() },
    };
    warn_unsafe_policy(policy);
    let (manifest, plan, pinned) = load_plan(&a.manifest)?;
    let stop = install_stop_flag()?;
    match kind {
        Kind::Profile => capture_profile(manifest, plan, scope, policy, a.duration, a.out.as_deref(), &pinned, &stop),
        Kind::Trace => capture_trace(plan, scope, policy, a.duration, a.out.as_deref(), &pinned, &stop),
    }
}

fn load_plan(manifest_path: &Path) -> Result<(Manifest, plan::AttachPlan, PinnedObjects)> {
    let text = read_manifest(manifest_path).map_err(|e| anyhow!("reading manifest {}: {e}", manifest_path.display()))?;
    let manifest: Manifest = serde_json::from_str(&text).with_context(|| format!("parsing manifest {}", manifest_path.display()))?;
    if manifest.schema != SCHEMA {
        bail!("manifest schema mismatch: got {:?}, this build expects {SCHEMA:?}; rerun `p11scope-discover` to rediscover the module", manifest.schema);
    }
    let pinned = pin_manifest_objects(&manifest).map_err(|problems| {
        for p in &problems { eprintln!("p11scope: {p}"); }
        anyhow!("manifest does not match the current files; refusing to attach")
    })?;
    let plan = plan::build(&manifest);
    if plan.slots.is_empty() { bail!("attach plan is empty: manifest {} has no attachable slots", manifest_path.display()); }
    plan::ensure_capacity(&plan).map_err(|e| anyhow!(e))?;
    Ok((manifest, plan, pinned))
}
```

`capture_profile`/`capture_trace`: today's bodies with these edits — no `worker`, `stdout` is
`std::io::stdout().lock()` (as `&mut dyn Write`), `-o` for profile is `AtomicFile::create(path)?`
committed after `write_json_report`, `-o` for trace is `File::create(path)?`; every
`objects.ensure_stable()…?` becomes
`if !pinned.check_unchanged().map_err(anyhow::Error::msg)? { provider_changed = true; }` (a
local `bool` passed into `evidence_for`); the `start_authorized_session` becomes
`Session::start(&plan, &scope, pinned, policy).context("starting attach session")?` followed
by `report_attach_failures(&session)`; the final `drop(oracle)` lines go; the interrupt flag is
the passed `stop`. `should_stop` keeps its signature (`Option<Duration>` now instead of
`Option<u64>` seconds).

`attach.rs`: `use crate::discovery::identity::PinnedObjects;` and rename the parameter type;
delete the two dead fields.

- [ ] **Step 4: Run** — `cargo +1.88 test --locked --workspace --all-targets` and clippy →
PASS (verify.rs/oracle.rs/discover_cmd.rs still compile but are now unused by main —
expect `dead_code` warnings? No: they are `pub mod`, so no warnings.)

- [ ] **Step 5: Commit** — `git commit -am "refactor: single-process capture on cli/manifest_input/identity/output; SIGTERM stops cleanly"`

---

### Task 8: Delete the authorization lane

**Files:**
- Delete: `src/verify.rs`, `src/oracle.rs`, `src/discover_cmd.rs`, `tests/lease_break.rs`,
  `tests/provenance_lease_break.rs`, `tests/cli_discover.rs`, `tests/reuse.rs`
- Modify: `src/lib.rs` (remove the three modules), `src/trace.rs` (delete
  `abort_evidence_line` and its tests), `crates/manifest/src/identity.rs` (delete
  `inspect_elf_loader`, `ProgramRange`, `set_once`, `dynamic_string`, `bounded_name_total` and
  everything only they use, lines 232–543), `crates/manifest/tests/identity.rs` (delete the
  loader-graph tests), `crates/manifest/Cargo.toml` (unchanged: `object` is still used by
  `inspect_file`)

- [ ] **Step 1: Delete and fix compilation**

```bash
git rm src/verify.rs src/oracle.rs src/discover_cmd.rs tests/lease_break.rs tests/provenance_lease_break.rs tests/cli_discover.rs tests/reuse.rs
```

Remove `pub mod discover_cmd; pub(crate) mod oracle; pub mod verify;` from `src/lib.rs`.
Run `cargo +1.88 check --locked --workspace --all-targets`; fix each error by deleting the
dead item it points at (`trace::abort_evidence_line`, the manifest-crate loader validator and
its tests, any `use` of removed items). Do not add code.

- [ ] **Step 2: Run everything**

Run: `cargo +1.88 fmt --all -- --check && cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings && cargo +1.88 test --locked --workspace --all-targets`
Expected: PASS. Record `git diff --stat HEAD~1 | tail -1` in the commit body.

- [ ] **Step 3: Commit with the history note**

```bash
git commit -am "remove: lease/provenance/hardened-oracle authorization lane

The lane built by docs/superpowers/plans/2026-08-13-manifest-provenance.md (closure read
leases, fresh rediscovery through a root-owned helper, hardened oracle with glibc staging,
lease supervisor fork, exit 78) existed and was reviewed; it is removed deliberately by
Productization Slice 1a so the observer runs with only BPF capabilities and never executes
provider code by default. Reasoning: docs/notes/2026-08-15-architecture-and-gap-analysis.md
(A5, A7) and docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md
(§4.11, §10.6). Restorable from history."
```

---

### Task 9: `p11scope-discover` — drop the control-fd handshake and the sysctl requirement

**Files:**
- Modify: `crates/discover/src/main.rs`
- Delete: `crates/discover/tests/control_protocol.rs`
- Test: `crates/discover/src/main.rs` unit test, `crates/discover/tests/cli.rs`

- [ ] **Step 1: Failing test** — in `crates/discover/tests/cli.rs` add:

```rust
#[test]
fn control_fd_flag_is_gone() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_p11scope-discover"))
        .args(["--control-fd", "3", "--module", "/nonexistent.so"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown argument: --control-fd"));
}
```

- [ ] **Step 2: Run** — `cargo +1.88 test --locked -p p11scope-discover --test cli control_fd` → FAIL (flag accepted).

- [ ] **Step 3: Implement** — delete `PREPARED/DROP/READY/GO`, `inherited_control`,
`send_control`, `expect_control`, the `--control-fd` arm and both handshake blocks in `main`;
in `prepare_drop` delete the `suid_dumpable` read and `validate_suid_dumpable` (and its unit
test); keep the credential drop exactly as is. `git rm crates/discover/tests/control_protocol.rs`.
Update `USAGE` (unchanged text; it never mentioned the flag).

- [ ] **Step 4: Run** — `cargo +1.88 test --locked -p p11scope-discover` and clippy → PASS.
- [ ] **Step 5: Commit** — `git commit -am "discover: standalone offline helper — drop control-fd handshake and suid_dumpable requirement"`

---

### Task 10: `tests/artifact_contracts.rs` — keep only artifact-executing tests

**Files:**
- Rename: `tests/release_contracts.rs` → `tests/artifact_contracts.rs`

- [ ] **Step 1: Rewrite** — keep, verbatim, only: the helpers `run_ok`,
`embedded_map_definitions`, `embedded_symbols`, and the tests
`task6_review_capture_evidence_checker_self_tests_exact_allowances` (rename
`capture_evidence_checker_self_test`), `task6_review_host_shell_syntax_is_checked_as_one_set`
(rename `every_script_parses_with_sh_n`; it globs `scripts/**/*.sh`), `immutable_policy_maps`,
`policy_specific_ebpf` (delete its text-reading half — keep only the embedded-object inventory
assertions). Delete every other test (they assert on script/Rust/doc text or on the removed
lane).

- [ ] **Step 2: Run** — `cargo +1.88 test --locked --test artifact_contracts` → PASS
(needs `llvm-readelf`, `llvm-objcopy`, `python3`, `sh` on the machine — same as before).
- [ ] **Step 3: Commit** — `git add -A tests && git commit -m "test: artifact contracts only (drop text-grep contract tests)"`

---

### Task 11: Scripts — `scripts/lib.sh`, gate scripts on the new CLI

**Files:**
- Rename: `scripts/trusted-p11scope.sh` → `scripts/lib.sh`
- Delete: `scripts/attach-pod.sh`, `scripts/container-authority.py`
- Modify: `scripts/verify-attach-e2e.sh`, `scripts/verify-induced-gaps.sh`,
  `scripts/verify-canaries.sh`, `scripts/bench-overhead.sh`, `scripts/build-release.sh`,
  `scripts/matrix/verify-docker.sh`, `scripts/matrix/verify-shared-layer.sh`,
  `scripts/matrix/verify-kind-pod.sh`, `scripts/matrix/verify-knative.sh`,
  `scripts/matrix/verify-fork-scope.sh`, `scripts/matrix/verify-oracle.sh`
- Create: `scripts/gates.sh`

- [ ] **Step 1: `scripts/lib.sh`** — from `trusted-p11scope.sh` delete: `set_suid_dumpable_zero`,
`restore_suid_dumpable`, `validate_protected_parent`, `is_immediate_child`,
`is_trusted_exec_destination`, `create_trusted_exec_dir`, `create_protected_output_dir`,
`stage_container_authority`, `stage_trusted_p11scope`, `remove_trusted_exec_root`,
`remove_trusted_p11scope`, `remove_protected_output_dir`, `require_rewritten_authority_refusal`,
`publish_protected_file`, `publish_protected_mapdump_lane`, `is_protected_output_file`. Keep:
`require_non_root_caller`, `cleanup_step`, `capped_container_tar`,
`launch_root_recorded_process`, `wait_root_process_record`, `process_starttime`,
`root_process_starttime`, `process_matches_starttime`, `root_process_matches_starttime`,
`signal_pinned_process`, `signal_verified_process`, `signal_verified_root_process`,
`wait_for_capture_ready`. Add:

```sh
# Binaries built by the calling script; no staging, no ownership rules.
P11SCOPE=${P11SCOPE:-target/release/p11scope}
P11SCOPE_DISCOVER=${P11SCOPE_DISCOVER:-target/release/p11scope-discover}
```

- [ ] **Step 2: Every script** — apply this mechanical rewrite and nothing else:
`. scripts/trusted-p11scope.sh` → `. scripts/lib.sh`; delete `TRUST_DIR=`/`RUN_DIR=` lines,
`create_trusted_exec_dir`/`create_protected_output_dir`/`stage_trusted_p11scope`,
`set_suid_dumpable_zero`/`restore_suid_dumpable`, `cleanup_step remove_trusted_p11scope …`,
`cleanup_step remove_protected_output_dir …`, `cleanup_step restore_suid_dumpable`;
`"$TRUST_DIR/p11scope"` → `"$WORK/build/release/p11scope"` (or the script's own build path);
`"$TRUST_DIR/p11scope-discover"` / `"$TRUST_DIR/p11scope" discover` → `"$WORK/build/release/p11scope-discover"`;
`-o "$RUN_DIR/x.json"` → `-o "$WORK/x.json"` and delete the following
`publish_protected_file "$RUN_DIR" x.json "$WORK" x.json`; delete `--provenance-module "$…"`
and `--trusted-workload` from every `p11scope profile|trace` invocation; where a script
asserted the exit-78 lease-abort or the "rewritten authority refusal", delete that check.
For the container matrix scripts, the manifest is still produced by copying
`p11scope-discover` into the container (`capped_container_tar` stays) and rewriting attach
paths to `/proc/<pid>/root/…` — keep that logic; delete only the `container-authority.py`
provenance steps.

- [ ] **Step 3: `scripts/gates.sh`**

```sh
#!/bin/sh
# One local entry point for the root gates (requires passwordless sudo, softhsm2, gcc, python3).
set -eu
cd "$(dirname "$0")/.."
for gate in scripts/verify-attach-e2e.sh scripts/verify-induced-gaps.sh scripts/verify-canaries.sh; do
    echo "=== $gate ==="
    "$gate"
done
echo "=== gates: ALL OK ==="
```

- [ ] **Step 4: Verify without privileges**

Run: `for f in scripts/*.sh scripts/matrix/*.sh; do sh -n "$f" || exit 1; done && python3 scripts/check-capture-evidence.py --self-test && grep -rn 'provenance-module\|trusted-workload\|TRUST_DIR\|RUN_DIR\|suid_dumpable\|trusted-p11scope' scripts/ ; echo "grep-exit=$?"`
Expected: all `sh -n` OK, self-test OK, and the grep finds nothing (exit 1).
Then `cargo +1.88 test --locked --test artifact_contracts` (script syntax test) → PASS.

- [ ] **Step 5: Commit** — `git add -A scripts && git commit -m "scripts: run binaries directly under sudo; drop trusted staging, sysctl and provenance steps"`

Note for the executor: running the gates needs `sudo`; do **not** run them without owner
approval (CLAUDE.md). CI (Task 12) runs `verify-attach-e2e.sh`.

---

### Task 12: CI skeleton

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

```yaml
name: ci
on: [push, pull_request]
jobs:
  checks:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: rustup toolchain install 1.88 --profile minimal --component rustfmt,clippy
      - run: rustup toolchain install nightly --profile minimal --component rust-src
      - uses: Swatinem/rust-cache@v2
      - run: cargo +1.88 install bpf-linker --locked
      - run: sudo apt-get update && sudo apt-get install -y gcc llvm python3
      - run: cargo +1.88 fmt --all -- --check
      - run: cargo +1.88 check --locked --workspace --all-targets
      - run: cargo +1.88 test --locked --workspace --all-targets
      - run: cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
  e2e:
    runs-on: ubuntu-24.04
    needs: checks
    steps:
      - uses: actions/checkout@v4
      - run: rustup toolchain install 1.88 --profile minimal
      - run: rustup toolchain install nightly --profile minimal --component rust-src
      - uses: Swatinem/rust-cache@v2
      - run: cargo +1.88 install bpf-linker --locked
      - run: sudo apt-get update && sudo apt-get install -y gcc softhsm2 python3
      - run: uname -r && cat /proc/sys/kernel/perf_event_paranoid && cat /proc/sys/kernel/yama/ptrace_scope
      - run: scripts/verify-attach-e2e.sh
```

- [ ] **Step 2: Local sanity** — `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` (or `ruby -ryaml`) → parses.
- [ ] **Step 3: Commit** — `git add .github && git commit -m "ci: unprivileged checks and sudo e2e gate on GitHub Actions"`

The first real run happens when the owner pushes; the executor cannot observe it. If the
e2e job fails on the runner, the fix belongs to this task (re-open).

---

### Task 13: Docs sync (minimal; the full rewrite is Slice 1b)

**Files:**
- Modify: `README.md`, `docs/usage.md`, `CHANGELOG.md`, `docs/schema/observed-profile-v1.md`,
  `docs/privacy/allowlist-v1.md`

- [ ] **Step 1: README** — Quickstart commands become
`p11scope-discover --module … -o manifest.json` and
`p11scope profile --manifest manifest.json --pid 12345 -o observed-profile.json`; delete the
"Containers and Kubernetes" paragraphs describing provenance/leases/exit 78 and replace with:
"Provider identity is pinned when probes attach (SHA-256 once, then `fstat` change detection
reported as `evidence.provider_changed`). Discovery without the offline helper, container
convenience (`run`, `inspect`, `doctor`) and minimum-privilege tiers land in Slice 1b — see
`docs/superpowers/plans/ROADMAP.md`." Delete the `CAP_LEASE` sentence in "Honest claims";
state the current requirement: BPF capabilities (`CAP_SYS_ADMIN` on `perf_event_paranoid=4`
hosts) plus `CAP_SYS_PTRACE` for cross-uid `/proc/<pid>/root`.
- [ ] **Step 2: usage.md** — same for the Quickstart, "Attaching to an existing Kubernetes pod"
(delete; note the wrapper returns in Slice 1b), the provenance paragraphs (delete), the
privileges table (drop the "Added file-stability requirement" column and the `CAP_LEASE`
sentence), "Related docs" (`v1.3` → `v1.4`).
- [ ] **Step 3: CHANGELOG** — new top section "Unreleased — productization slice 1a": lane
removed (with the reasoning pointer), CLI changes, `provider_changed`, SIGTERM, CI.
- [ ] **Step 4: schema doc** — add `provider_changed` row to the evidence table with "(v1.4
addendum, 2026-08-15)".
- [ ] **Step 5: allowlist** — replace the paragraph starting "A raw manifest never authorizes
code…" with "A manifest is trusted operator input, structurally validated and hash-matched
against the pinned object; the observer executes no provider code."
- [ ] **Step 6: Commit** — `git commit -am "docs: sync README/usage/CHANGELOG/schema/allowlist with slice 1a"`

---

### Task 14: Final verification

- [ ] **Step 1: The four checks** — all green (Global Constraints).
- [ ] **Step 2: Line count** — `git diff --stat f35c04e..HEAD -- src crates tests scripts | tail -1`
recorded in the ROADMAP slice 1a entry as "landed: −N lines".
- [ ] **Step 3: Ask the owner** whether to run `scripts/gates.sh` locally (sudo) now or rely on
CI; run only on approval and paste the tail of each gate log into the ROADMAP entry.
- [ ] **Step 4: Commit** the ROADMAP line.

---

## Self-review

- Spec coverage (Slice 1a items of §7): ROADMAP (T1) ✔; deletions §4.11 (T8, T9, T10, T11)
  ✔; identity pinning §4.5 with `fstat` (T3, T7) ✔; manifest as input with SHA-256 match (T3)
  ✔; CLI cleanup incl. `--duration` suffixes, SIGTERM, removed flags (T5, T7) ✔; scripts on
  the new CLI (T11) ✔; CI skeleton (T12) ✔; CHANGELOG/ROADMAP (T1, T13) ✔; `provider_changed`
  evidence (T6, T7) ✔. Not in 1a by design: `--module` optional, `run/inspect/doctor`, scan,
  hooks, pause, schema v2, `discovery[]` evidence, `--pause`, `--hook-symbol` (Slice 1b).
- Placeholder scan: none; every code step shows the code or the exact source range to move.
- Type consistency: `PinnedObjects::{attach_path, check_unchanged, identities}` (T3) used in
  T7 and `attach.rs`; `AtomicFile::{create, file, commit}` (T4) used in T7;
  `cli::{parse_capture, Kind, ScopeArg, CaptureArgs, CliError, USAGE, parse_duration}` (T5)
  used in T7; `STOP_SIGNALS` (T7) tested in T7; `manifest_input::{read_manifest,
  validate_structure, MAX_*}` (T2) used in T3/T7.
