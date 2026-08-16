# Productization Slice 1a — Trust Simplification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the lease/provenance/hardened-oracle authorization lane and its operational
requirements, replace it with hash-pinned object identity, simplify the CLI, and add a CI
skeleton — so that `p11scope profile|trace --manifest … --pid|--cgroup …` works with only the
BPF capabilities (plus `CAP_SYS_PTRACE` for cross-uid targets) and today's gates still pass.

**Architecture:** `verify.rs`, `oracle.rs`, `discover_cmd.rs` and the supervisor fork are
deleted (kept in git history). Three small modules keep what is still needed:
`manifest_input.rs` (bounded manifest read + structural validation, moved code),
`discovery/identity.rs` (`PinnedObjects`: open + size cap + SHA-256 once + executable-offset
check + `fstat` `(ino, size, ctime)` change detection) and `output.rs` (the existing
identity-safe temp+rename profile publication, moved and stripped of the output-directory
ownership policy). `cli.rs` is the single argument parser. `main.rs` becomes a single-process
capture loop. The `p11scope-discover` helper stays as a standalone offline tool (its
control-fd handshake and `suid_dumpable` requirement go). Every gate script drops the
trusted-staging/sysctl helpers and calls the binaries directly under `sudo`. A GitHub Actions
workflow runs the unprivileged checks and the e2e gate.

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
  script has one, its `--self-test`. Anything not run is recorded as UNRUN/PENDING, never as
  green.
- Privacy allowlist: the capture-field inventory (`docs/privacy/allowlist-v1.md` tables) is
  unchanged; only its trust-model prose is updated (Task 13). Capture policy code in
  `attach.rs`/`crates/ebpf` unchanged.
- No new dependencies. No `clap`.
- Manifest schema stays `p11scope-manifest/4`; profile schema stays
  `pkcs11-scope/observed-profile/v1.4` / `v1.1-metrics` in this slice (the additive evidence
  field `provider_changed` is documented as a v1.4 addendum; the v2 bump is Slice 1b).
- The deletion commit message must record that the lane existed and was removed
  deliberately (spec §4.11).
- Task order is load-bearing: text-grep contract tests are pruned (Task 2) before any source
  they read is changed; the lease/oracle/supervisor code stays compilable until Task 9.

---

## File map

| Path | Action | Responsibility after 1a |
| --- | --- | --- |
| `docs/superpowers/plans/ROADMAP.md` | modify | Productization slices recorded; old lane scheduled for removal (T1) → removed (T9) |
| `tests/release_contracts.rs` → `tests/artifact_contracts.rs` | rename+modify | eight artifact/behaviour tests only (T2), script references updated (T11) |
| `src/manifest_input.rs` | create | `read_manifest`, `validate_structure`, size caps (moved from `verify.rs`) |
| `src/discovery/mod.rs`, `src/discovery/identity.rs` | create | `PinnedObjects`, `pin_manifest_objects`, `check_unchanged`, `attach_path` |
| `src/output.rs` | create | `AtomicFile` (moved `PendingProfile`, minus directory ownership policy) |
| `src/cli.rs` | create | `CaptureArgs`, `parse_capture`, `parse_duration`, removed-flag hints |
| `src/main.rs` | rewrite | dispatch, single-process capture loops, SIGINT+SIGTERM flag |
| `src/attach.rs` | modify | `PinnedObjects`; `check_unchanged` before/after attach; drop dead fields |
| `src/render.rs` | modify | `Evidence.provider_changed` (verdict, live, JSON) |
| `src/trace.rs` | modify | delete `abort_evidence_line` (only the supervisor used it) |
| `src/lib.rs` | modify | module list |
| `src/verify.rs`, `src/oracle.rs`, `src/discover_cmd.rs` | delete (T9) | — |
| `crates/manifest/src/identity.rs` | modify | delete `inspect_elf_loader` + loader-graph validator (lines 232–543) |
| `crates/manifest/tests/identity.rs` | modify | delete loader-graph tests |
| `crates/discover/src/main.rs` | modify | delete `--control-fd` handshake and `suid_dumpable` requirement |
| `crates/discover/tests/control_protocol.rs` | delete | — |
| `tests/lease_break.rs`, `tests/provenance_lease_break.rs`, `tests/cli_discover.rs` | delete | — |
| `tests/reuse.rs` → `tests/manifest_pinning.rs` | rename+modify | pinning/structure tests on the new API |
| `scripts/trusted-p11scope.sh` → `scripts/lib.sh` | rename+modify | shared script helpers minus staging/sysctl |
| `scripts/attach-pod.sh`, `scripts/container-authority.py` | delete | rewritten/replaced in Slice 1b |
| `scripts/*.sh`, `scripts/matrix/*.sh` | modify | new CLI, no staging, no sysctl |
| `scripts/gates.sh` | create | one local entry point for the root gates |
| `.github/workflows/ci.yml` | create | unprivileged checks + `sudo` e2e job |
| `README.md`, `docs/usage.md`, `CHANGELOG.md`, `docs/schema/observed-profile-v1.md`, `docs/privacy/allowlist-v1.md` | modify | status block, CLI sync, lane removal, `provider_changed` addendum |

---

### Task 1: ROADMAP records the productization slices

**Files:**
- Modify: `docs/superpowers/plans/ROADMAP.md`, `docs/superpowers/plans/2026-08-13-manifest-provenance.md`

- [x] **Step 1: Add the productization section** — append after "Explicitly deferred":

```markdown
## Productization (2026-08-15 →)

Input: `docs/notes/2026-08-15-architecture-and-gap-analysis.md` (review + decisions A1–A7)
and `docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md`.

- **Slice 1a — trust simplification** ([plan](2026-08-15-productization-slice1a-trust-simplification.md)):
  the lease/provenance/hardened-oracle lane of `2026-08-13-manifest-provenance.md` is
  **scheduled for removal** (status flips to "removed" in the plan's deletion task; kept in
  git history; reasoning in the spec §4.11 and §10.6). Object identity becomes hash-pinned
  (SHA-256 once, `fstat` change detection). CLI drops `--provenance-module`,
  `--trusted-workload`, the `p11scope discover` subcommand and exit code 78. CI skeleton.
- **Slice 1b — discovery engine and commands**: memory-scan + loader/export-hook discovery,
  `run`, `inspect`, `doctor`, `--module` optional, schema v2. Plan written after 1a lands.
- **Slice 2 — capture quality**: ring/epoll, budgets, safe-policy params, per-module profile
  sections, filters, snapshots.
- **Slice 3 — structure**: module split, evidence plumbing, docs consolidation, multi-kernel CI.
- Then AArch64, 32-bit counting mode, `uprobe_multi`, freezer pause, manifest catalog.

**Gate for each slice:** the four cargo checks, the unprivileged suite, and the CI e2e job
green; root gates run locally only with owner approval and are otherwise recorded UNRUN.
```

- [x] **Step 2: Mark the provenance plan** — under its title add:

```markdown
> **Status (2026-08-15): scheduled for removal by Productization Slice 1a** (spec
> `docs/superpowers/specs/2026-08-15-productization-slice1-discovery-and-trust-design.md`
> §4.11/§10.6). This note is updated to "removed" by the slice's deletion task.
```

- [x] **Step 3: Commit**

```bash
git add docs/superpowers/plans/ROADMAP.md docs/superpowers/plans/2026-08-13-manifest-provenance.md
git commit -m "docs: ROADMAP — productization slices; provenance lane scheduled for removal"
```

---

### Task 2: `tests/artifact_contracts.rs` — prune text-grep tests before code moves

**Files:**
- Rename: `tests/release_contracts.rs` → `tests/artifact_contracts.rs`

The remaining tests must not read Rust source or documentation text (they would break as
later tasks move code); they may execute scripts, artifacts and self-tests. Script text
references they still contain are updated in Task 11 in the same commit that changes the
scripts.

- [x] **Step 1: Keep exactly these** (bodies verbatim unless noted; helpers `run_ok`,
`embedded_map_definitions`, `embedded_symbols`, `read`, `between` may stay if used):
  1. `immutable_policy_maps` — embedded eBPF object: RDONLY flags on control maps.
  2. `policy_specific_ebpf` → keep only the embedded-object inventory assertions (default
     object lacks unsafe-only programs/maps); delete its source-text reads.
  3. `task6_review_capture_evidence_checker_self_tests_exact_allowances` → rename
     `capture_evidence_checker_self_test`.
  4. `task6_review_host_shell_syntax_is_checked_as_one_set` → rename
     `every_script_parses_with_sh_n`.
  5. `container_provider_streams_are_byte_capped` — keep the `capped_container_tar`
     execution; keep the script list assertion (Task 11 removes `scripts/attach-pod.sh` from
     it and switches `. scripts/trusted-p11scope.sh` to `. scripts/lib.sh`).
  6. `task6_review_pidfd_signal_is_bound_to_the_recorded_identity` → rename
     `pidfd_signal_is_bound_to_recorded_identity`.
  7. `metadata_canary_matrix` → keep the lane-table, sentinel-fixture and `--self-test`
     assertions; delete assertions about trusted staging / `suid_dumpable` / provenance
     inside `verify-canaries.sh` (Task 11 removes that text).
  8. `task6_official_observer_build_is_isolated_and_safe_only` → rename
     `official_build_is_safe_only`; keep the `--no-default-features` / `OFFICIAL_TARGET`
     assertions on `scripts/build-release.sh`; delete assertions about staging.
- [x] **Step 2: Delete every other test** (they read `src/*.rs`, `crates/*/src/*.rs`,
docs, or assert on the removed lane's script text).
- [x] **Step 3: Run** — `cargo +1.88 test --locked --test artifact_contracts` → PASS
(needs `llvm-readelf`, `llvm-objcopy`, `python3`, `sh`, as before).
- [x] **Step 4: Commit** — `git add -A tests && git commit -m "test: artifact contracts only (drop text-grep contract tests before the lane moves)"`

---

### Task 3: `manifest_input.rs` — bounded read and structural validation (moved code)

**Files:**
- Create: `src/manifest_input.rs`
- Modify: `src/lib.rs`, `src/verify.rs`
- Test: `tests/manifest_pinning.rs` (new)

**Interfaces:**
- Produces: `pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;`,
  `pub const MAX_TOTAL_OBJECT_BYTES: u64 = 512 * 1024 * 1024;`,
  `pub fn read_manifest(path: &Path) -> Result<String, String>` (moved verbatim from
  `src/verify.rs:1329-1350`), `pub fn validate_structure(m: &Manifest) -> Vec<String>`
  (moved verbatim from `src/verify.rs:1602-2062` with every private helper/constant it uses:
  `MAX_OBJECTS`, `MAX_SURFACES`, `MAX_FUNCTIONS`, `MAX_PATH_BYTES`, `MAX_DETAIL_BYTES`).

- [x] **Step 1: Failing test** — create `tests/manifest_pinning.rs` with the helpers
`tmpdir`, `cc_so`, `cc_so_with_build_id`, `manifest_for`, `first_executable_offset`,
`walked_legacy_manifest` copied verbatim from `tests/reuse.rs:10-126`, and one test copied
from `tests/reuse.rs` with its import changed:

```rust
use p11scope::manifest_input::{read_manifest, MAX_MANIFEST_BYTES};
// body of `manifest_input_is_regular_utf8_and_bounded` verbatim, calling `read_manifest`
```

- [x] **Step 2: Run** — `cargo +1.88 test --locked --test manifest_pinning` → compile error
`could not find manifest_input in p11scope`.
- [x] **Step 3: Move** — create `src/manifest_input.rs` (module doc: "Manifest input hygiene:
bounded read and structural validation of `p11scope-manifest/4` documents. Trusted operator
input, validated before use.") and *cut* the ranges above from `src/verify.rs`. In
`src/verify.rs` add **only**:

```rust
pub use crate::manifest_input::{
    read_manifest, validate_structure, MAX_MANIFEST_BYTES, MAX_TOTAL_OBJECT_BYTES,
};
```

(a `pub use` also brings the names into `verify.rs`'s own scope; do not add a second `use`).
Add `pub mod manifest_input;` to `src/lib.rs`.
- [x] **Step 4: Run** — full test + clippy → PASS.
- [x] **Step 5: Commit** — `git add src/manifest_input.rs src/lib.rs src/verify.rs tests/manifest_pinning.rs && git commit -m "refactor: move manifest input hygiene into manifest_input.rs"`

---

### Task 4: `discovery/identity.rs` — pinned objects without leases

**Files:**
- Create: `src/discovery/mod.rs`, `src/discovery/identity.rs`
- Modify: `src/lib.rs`
- Test: `tests/manifest_pinning.rs`

**Interfaces:**
- Consumes: `manifest_input::{validate_structure, MAX_TOTAL_OBJECT_BYTES}`,
  `p11scope_manifest::identity::{open_object, inspect_file, ObjectIdentity}`,
  `p11scope_manifest::manifest::{Manifest, Resolution}`.
- Produces:

```rust
pub struct PinnedObjects { /* private */ }
impl PinnedObjects {
    /// `/proc/self/fd/N` for aya to reopen the pinned inode (never the manifest path).
    pub fn attach_path(&self, original: &str) -> Result<PathBuf, String>;
    /// `Ok(true)` when every pinned object still has the (ino, size, ctime) seen at pinning;
    /// `Ok(false)` when any changed; `Err` only when `fstat` itself fails.
    pub fn check_unchanged(&self) -> Result<bool, String>;
    /// (path, identity) of every pinned object, for `capture.module` rendering.
    pub fn identities(&self) -> impl Iterator<Item = (&str, &ObjectIdentity)>;
}
/// Structural validation + open + size cap + identity match + executable-offset check.
pub fn pin_manifest_objects(m: &Manifest) -> Result<PinnedObjects, Vec<String>>;
```

- [x] **Step 1: Failing tests** — in `tests/manifest_pinning.rs` add, copied from
`tests/reuse.rs` with `p11scope::verify::check_reuse` → `p11scope::discovery::identity::pin_manifest_objects`
and `VerifiedObjects` → `PinnedObjects`: `matching_identity_is_accepted`,
`changed_object_is_refused_naming_the_file`, `vanished_object_is_refused`,
`non_reusable_identity_is_refused_even_if_unchanged`,
`relative_and_duplicate_manifest_objects_are_refused`,
`symlink_is_pinned_and_non_executable_offsets_are_refused`,
`reordered_or_unknown_standard_function_names_are_refused`,
`every_supported_table_boundary_passes_structural_reuse_validation`,
`acquisition_evidence_cannot_be_omitted_or_invented`,
`manifest_v4_requires_a_whole_file_provenance_closure`,
`aggregate_object_bytes_are_refused_before_parsing`. Then add:

```rust
#[test]
fn same_size_overwrite_changes_ctime_and_is_detected() {
    let d = tmpdir("manifest_pinning_same_size_overwrite");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    let pinned = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap();
    assert!(pinned.check_unchanged().unwrap());
    std::thread::sleep(std::time::Duration::from_millis(20)); // ctime granularity margin
    // Overwrite the first byte with itself: size and content unchanged, ctime bumped.
    let first = std::fs::read(&so).unwrap()[0];
    let mut f = std::fs::OpenOptions::new().write(true).open(&so).unwrap();
    std::io::Write::write_all(&mut f, &[first]).unwrap();
    drop(f);
    assert!(!pinned.check_unchanged().unwrap(), "ctime change must be detected");
}

#[test]
fn replacing_the_file_by_rename_keeps_the_pinned_inode_but_reports_a_change() {
    let d = tmpdir("manifest_pinning_rename_over");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    let pinned = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap();
    let old_bytes = std::fs::read(&so).unwrap();
    let attach = pinned.attach_path(so.to_str().unwrap()).unwrap();
    assert!(attach.starts_with("/proc/self/fd/"));
    std::thread::sleep(std::time::Duration::from_millis(20)); // ctime granularity margin
    let other = cc_so(&d, "other", "int g(void){return 2;}\n");
    std::fs::rename(&other, &so).unwrap(); // new inode at the old path
    // The fd still pins the old inode (aya would attach to the old bytes) …
    assert_eq!(std::fs::read(&attach).unwrap(), old_bytes, "the old inode is what we hold");
    // … but unlinking the old inode bumped its ctime, so the change is reported
    // conservatively (a rename-over is indistinguishable from an in-place write
    // without relying on the settable mtime; the capture continues, PARTIAL).
    assert!(!pinned.check_unchanged().unwrap(), "rename-over is reported as a change");
}
```

Helper signatures are those of `tests/reuse.rs`: `tmpdir(name: &str)`, `cc_so(dir, name, body)`
(takes the `CC_LOCK` itself), `manifest_for(path: &Path)` (needs `provenance_for`); copy each
helper only when a test in the file uses it (unused helpers fail clippy `-D warnings`).

- [x] **Step 2: Run** — `cargo +1.88 test --locked --test manifest_pinning` → compile error.
- [x] **Step 3: Implement** — `src/discovery/mod.rs`:

```rust
//! Discovery: how the observer learns which objects/offsets to probe and pins their
//! identity. Slice 1a: manifest input only (`identity`). Slice 1b adds scan/live/pause.
pub mod identity;
```

`src/discovery/identity.rs`: take `check_reuse` (`src/verify.rs:2280-2410`) as the body of
`pin_manifest_objects`; delete every lease line (`LeaseMonitor::new`, `lease.acquire`,
`lease.ensure`); after `inspect_file` succeeds record the `fstat` pin:

```rust
use std::collections::BTreeMap;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use p11scope_manifest::identity::{inspect_file, open_object, ObjectIdentity};
use p11scope_manifest::manifest::{Manifest, Resolution};

use crate::manifest_input::{validate_structure, MAX_TOTAL_OBJECT_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pin { ino: u64, size: u64, ctime: (i64, i64) }

fn pin_of(file: &std::fs::File) -> Result<Pin, String> {
    let md = file.metadata().map_err(|error| format!("fstat failed: {error}"))?;
    Ok(Pin { ino: md.ino(), size: md.len(), ctime: (md.ctime(), md.ctime_nsec()) })
}

#[derive(Debug)]
pub struct PinnedObjects {
    files: BTreeMap<String, std::fs::File>,
    identities: BTreeMap<String, ObjectIdentity>,
    pins: BTreeMap<String, Pin>,
}

impl PinnedObjects {
    pub fn attach_path(&self, original: &str) -> Result<PathBuf, String> {
        self.files.get(original)
            .map(|file| PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())))
            .ok_or_else(|| format!("object path {original:?} was not pinned"))
    }
    pub fn check_unchanged(&self) -> Result<bool, String> {
        for (path, file) in &self.files {
            if pin_of(file).map_err(|e| format!("{path}: {e}"))? != self.pins[path] { return Ok(false); }
        }
        Ok(true)
    }
    pub fn identities(&self) -> impl Iterator<Item = (&str, &ObjectIdentity)> {
        self.identities.iter().map(|(p, i)| (p.as_str(), i))
    }
}

pub fn pin_manifest_objects(m: &Manifest) -> Result<PinnedObjects, Vec<String>> {
    // check_reuse body without leases; in the final loop:
    //   let pin = pin_of(&file).map_err(|e| vec![format!("{path}: {e}")])?;
    //   pins.insert(path.clone(), pin);
}
```

Keep the error strings of `check_reuse` verbatim (tests assert on them) except
`re-run \`p11scope discover\`` → `re-run \`p11scope-discover\``.
- [x] **Step 4: Run** — `cargo +1.88 test --locked --test manifest_pinning` → PASS (the
`an_existing_writer_prevents_object_authorization` lease test is not carried over).
- [x] **Step 5: Commit** — `git add src/discovery src/lib.rs tests/manifest_pinning.rs && git commit -m "feat: hash-pinned object identity without leases (discovery::identity)"`

---

### Task 5: `output.rs` — atomic profile publication (moved `PendingProfile`)

**Files:**
- Create: `src/output.rs`
- Modify: `src/lib.rs`, `src/verify.rs` (the moved code is cut; `SupervisorOutput::profile`
  keeps compiling by using `crate::output::AtomicFile` until Task 9 deletes it — or, simpler,
  leave `PendingProfile` in place in `verify.rs` and *copy* it now; Task 9 deletes the copy.
  Choose **copy now, delete in Task 9** to keep the diff reviewable.)
- Test: unit tests inside `src/output.rs`

**Interfaces:**
- Produces:

```rust
pub struct AtomicFile { /* directory fd, temp File, temp name, final name, identity, cleanup flag */ }
impl AtomicFile {
    /// Opens the parent directory (O_DIRECTORY|O_CLOEXEC), creates
    /// `.p11scope.<pid>.<seq>.tmp` beside `path` with openat(O_CREAT|O_EXCL|O_WRONLY|
    /// O_NOFOLLOW|O_CLOEXEC, 0o600), retrying seq 0..128; records the temp file's identity.
    pub fn create(path: &Path) -> Result<AtomicFile, String>;
    pub fn file(&mut self) -> &mut std::fs::File;
    /// Re-verifies the temp identity (regular file, same dev/ino, owner == euid, mode & 0o077 == 0),
    /// `sync_all`, then `renameat` over the final name. Consumes self. On any error the temp
    /// file is unlinked by Drop.
    pub fn commit(self) -> Result<(), String>;
}
impl Drop for AtomicFile { /* unlinkat(temp) unless committed */ }
```

Source to move: `PendingProfile` (`src/verify.rs:299-450` region: `create`, `publish`,
`verify_temp_identity`, `Drop`), `FileIdentity`, `normalize_output_path`, `c_name`,
`openat_profile`, `metadata_at`, `renameat`, `unlinkat` (`src/verify.rs:453-641`). Delete
only the directory policy: `open_protected_directory`/`validate_protected_directory` and
their callers become a plain `openat_directory` of the parent (O_DIRECTORY|O_CLOEXEC|
O_NOFOLLOW off — follow is fine for the parent). Add `sync_all()` before `renameat` (the
original did not fsync). Keep the `cleanup` flag so `Drop` unlinks the temp on every
non-committed path, including a failed `commit`.

- [x] **Step 1: Failing tests** — create `src/output.rs` containing only the module doc and
this test module, and add `pub mod output;` to `src/lib.rs` (so the red state is real):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

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
    fn temp_is_private_and_removed_when_not_committed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        {
            let mut a = AtomicFile::create(&path).unwrap();
            let temp = std::fs::read_dir(dir.path()).unwrap().next().unwrap().unwrap();
            assert_eq!(temp.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            std::io::Write::write_all(a.file(), b"partial").unwrap();
        }
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn commit_fails_and_cleans_up_when_the_temp_was_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        let mut a = AtomicFile::create(&path).unwrap();
        std::io::Write::write_all(a.file(), b"x").unwrap();
        let temp = std::fs::read_dir(dir.path()).unwrap().next().unwrap().unwrap().path();
        std::fs::remove_file(&temp).unwrap();
        std::fs::write(&temp, b"impostor").unwrap(); // different inode at the temp name
        assert!(a.commit().is_err());
        assert!(!path.exists());
    }
}
```

- [x] **Step 2: Run** — `cargo +1.88 test --locked --lib output` → compile error (`AtomicFile`).
- [x] **Step 3: Implement** by moving the listed code and applying the listed edits.
- [x] **Step 4: Run** — `cargo +1.88 test --locked --lib output` and full clippy → PASS.
- [x] **Step 5: Commit** — `git add src/output.rs src/lib.rs && git commit -m "feat: output::AtomicFile — identity-safe temp+rename publication without directory ownership policy"`

---

### Task 6: `cli.rs` — one argument parser, durations with suffixes, removed-flag hints

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
pub const USAGE: &str = "…";
pub fn parse_capture(kind: Kind, args: impl Iterator<Item = String>) -> Result<CaptureArgs, CliError>;
pub fn parse_duration(s: &str) -> Result<Duration, String>;   // "30" | "30s" | "5m" | "1h"
```

Removed flags → `CliError::Usage` with a hint: `--provenance-module` / `--trusted-workload`
→ "removed in productization slice 1a: the observer pins provider identity by SHA-256 and
fstat; see docs/usage.md"; `--mode trace` → "trace is a subcommand: `p11scope trace …`".

- [x] **Step 1: Failing tests** — create `src/cli.rs` with only the module doc and this test
module; add `pub mod cli;` to `src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn args(v: &[&str]) -> std::vec::IntoIter<String> { v.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter() }

    #[test]
    fn duration_accepts_bare_seconds_and_suffixes() {
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        for bad in ["", "5x", "-1", "s", "1.5m"] { assert!(parse_duration(bad).is_err(), "{bad}"); }
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

- [x] **Step 2: Run** — `cargo +1.88 test --locked --lib cli` → compile error.
- [x] **Step 3: Implement** — a `while let Some(a) = args.next()` loop like today's
`cmd_profile`, producing `CliError::Usage(format!("{msg}\n{USAGE}"))` where main.rs used
`eprintln!(…); exit(2)`. `USAGE`:

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

`parse_duration`: optional trailing `s|m|h`, digits only before it, `u64`, non-empty.
- [x] **Step 4: Run** — `cargo +1.88 test --locked --lib cli` → PASS.
- [x] **Step 5: Commit** — `git add src/cli.rs src/lib.rs && git commit -m "feat: single CLI parser with duration suffixes and removed-flag hints"`

---

### Task 7: `render::Evidence.provider_changed`

**Files:**
- Modify: `src/render.rs` (struct 10–93, `verdict` 109–152, `live` 182–365), `src/trace.rs`
  (test literals 406–447), `src/main.rs:933-1004` (`evidence_for` literal: add
  `provider_changed: false` for now)
- Test: `src/render.rs` tests

- [x] **Step 1: Failing test** — in the `render.rs` test module, using its existing all-zero
evidence fixture (whatever it is named there; do not add a second one):

```rust
#[test]
fn provider_change_forces_partial_and_is_shown_live() {
    let mut ev = /* existing clean fixture */;
    ev.verdict();
    assert_eq!(ev.completeness, "COMPLETE");
    ev.provider_changed = true;
    ev.verdict();
    assert_eq!(ev.completeness, "PARTIAL");
    let frame = live(&[], &ev, std::time::Duration::from_secs(1), "/x.so", "profile", CapturePolicy::Allowlisted);
    assert!(frame.contains("provider changed"), "{frame}");
    assert_eq!(serde_json::to_value(&ev).unwrap()["provider_changed"], serde_json::Value::Bool(true));
}
```

- [x] **Step 2: Run** — compile error (no field).
- [x] **Step 3: Implement** — `pub provider_changed: bool` (doc: "A pinned provider object
changed (ino, size or ctime) after attach; probes may no longer describe the mapped bytes.");
`&& !self.provider_changed` in `verdict()`; `" · provider changed"` on the live gap line;
`provider_changed: false` in every `Evidence { … }` literal the compiler points at.
- [x] **Step 4: Run** — full tests → PASS.
- [x] **Step 5: Commit** — `git commit -am "feat: evidence.provider_changed (in-place provider change forces PARTIAL)"`

---

### Task 8: `main.rs` + `attach.rs` — single-process capture on the new modules

**Files:**
- Modify: `src/main.rs` (rewrite), `src/attach.rs:5,185-191,494-512,674`
- Test: `src/main.rs` unit tests

**Interfaces:**
- Consumes: `cli::{parse_capture, Kind, ScopeArg, CaptureArgs, CliError, USAGE}`,
  `manifest_input::read_manifest`, `discovery::identity::{pin_manifest_objects, PinnedObjects}`,
  `output::AtomicFile`, `attach::{Session, Scope, CapturePolicy}`, `scope::cgroup_id`, and the
  unchanged `events/metrics/semantics/process/trace/render/plan/shapes` APIs.
- Produces: `Session::start(plan, scope, pinned: &PinnedObjects, policy)` semantics: refuses to
  attach if `pinned.check_unchanged()` is `false` before loading **or** immediately after
  attaching (error "a pinned provider object changed before/after attach; refusing to observe
  changed bytes"); during capture a change sets `provider_changed` (never aborts).

- [x] **Step 1: Failing tests** — replace the `main.rs` test module: keep
`ebpf_object_is_a_real_bpf_elf`, `fmt_rfc3339_matches_a_known_instant`, `should_stop_*`,
`fork_only_traffic_does_not_consume_process_tracking_budget`,
`broken_stdout_closes_only_that_sink_and_file_continues`,
`trace_file_write_and_flush_errors_propagate`,
`policy_output_unsafe_flag_is_refused_before_manifest_loading` (now `cli::parse_capture` +
`CapturePolicy::from_cli`); delete `terminal_detach_precedes_snapshot_and_unproven_drain_mark_precedes_output`
(source grep) and `policy_output_discover_rejects_unsafe_flag_before_helper_lookup`; adapt/add:

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

/// The finalization a stopped loop runs into: `-o` publication produces valid JSON and
/// replaces stale content atomically (adapted from the previous shutdown-path test).
#[test]
fn shutdown_path_publishes_valid_json_over_a_stale_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("observed.json");
    std::fs::write(&path, b"stale trailing bytes that must disappear").unwrap();
    let j = serde_json::json!({"schema": "pkcs11-scope/observed-profile/v1.4", "evidence": {}});
    let mut out = AtomicFile::create(&path).unwrap();
    write_json_report(out.file(), &j).expect("shutdown finalization must write the report");
    out.commit().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(parsed["schema"], "pkcs11-scope/observed-profile/v1.4");
}

/// A real SIGTERM (raised in-process after the handler is installed) sets the same stop
/// flag Ctrl-C sets, so `should_stop` returns true on the next tick.
#[test]
fn sigterm_sets_the_stop_flag() {
    let stop = install_stop_flag().unwrap();
    assert!(!should_stop(&stop, Duration::ZERO, None));
    // SAFETY: raise() with a handled signal; the handler only sets an AtomicBool.
    assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
    assert!(should_stop(&stop, Duration::ZERO, None));
}
```

- [x] **Step 2: Run** — `cargo +1.88 test --locked --bin p11scope` → compile errors.
- [x] **Step 3: Rewrite `main.rs`** — keep verbatim: `report_attach_failures`,
`load_mech_shapes`, `warn_unsafe_policy`, `identify_tracked`, `retire_exited`, `observe_fork`,
`write_json_report` (now called with `AtomicFile::file()`), `emit_trace_line`, `write_stdout`,
`flush_stdout`, `drain_trace_events`, `report_trace_loss`, `evidence_for` (add a
`provider_changed: bool` parameter), `fmt_rfc3339`. New skeleton:

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

`capture_profile`/`capture_trace`: today's bodies with these edits — no `worker`; `stdout` is
`std::io::stdout().lock()` as `&mut dyn Write`; profile `-o` is `AtomicFile::create(path)`
created **before** the loop (so a bad path fails early) and committed after
`write_json_report`; trace `-o` is `File::create(path)?` (append lines as today); every
`objects.ensure_stable()…?` becomes
`if !pinned.check_unchanged().map_err(anyhow::Error::msg)? { provider_changed = true; }` with a
local `bool` passed into `evidence_for`; `start_authorized_session` becomes
`Session::start(&plan, &scope, pinned, policy).context("starting attach session")?` +
`report_attach_failures(&session)`; the `drop(oracle)` lines go; the stop flag is the passed
`stop`; `should_stop(&stop, elapsed, duration: Option<Duration>)`.

`attach.rs`: `use crate::discovery::identity::PinnedObjects;` (parameter type in `start` and
`start_inner`); replace both `objects.ensure_stable()…` blocks in `Session::start` with

```rust
if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
    bail!("a pinned provider object changed before attach; refusing to observe changed bytes");
}
```
and after `start_inner`
```rust
if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
    bail!("a pinned provider object changed while attaching; refusing to observe changed bytes");
}
```
(the returned error drops `session`, which detaches). Delete the dead `_config` and
`_cgroup_file` fields and their assignments.

- [x] **Step 4: Run** — full tests + clippy → PASS (verify/oracle/discover_cmd still compile,
unused by main; they are `pub mod`, so no dead-code warnings).
- [x] **Step 5: Commit** — `git commit -am "refactor: single-process capture on cli/manifest_input/identity/output; SIGTERM stops cleanly; refuse attach on changed pinned bytes"`

---

### Task 9: Delete the authorization lane

**Files:**
- Delete: `src/verify.rs`, `src/oracle.rs`, `src/discover_cmd.rs`, `tests/lease_break.rs`,
  `tests/provenance_lease_break.rs`, `tests/cli_discover.rs`, `tests/reuse.rs`
- Modify: `src/lib.rs`, `src/trace.rs` (delete `abort_evidence_line` + its tests),
  `crates/manifest/src/identity.rs` (delete `inspect_elf_loader`, `ProgramRange`, `set_once`,
  `dynamic_string`, `bounded_name_total`, lines 232–543; keep `mapping_file_key`,
  `MappingFileKey`, `identify`, `inspect_file`, `open_object`, `open_regular`),
  `crates/manifest/tests/identity.rs` (delete the loader-graph tests),
  `docs/superpowers/plans/2026-08-13-manifest-provenance.md` (status note → "removed")

- [x] **Step 1: Delete and fix compilation**

```bash
git rm src/verify.rs src/oracle.rs src/discover_cmd.rs tests/lease_break.rs tests/provenance_lease_break.rs tests/cli_discover.rs tests/reuse.rs
```

Remove `pub mod discover_cmd; pub(crate) mod oracle; pub mod verify;` from `src/lib.rs`. Run
`cargo +1.88 check --locked --workspace --all-targets`; fix each error only by deleting the
dead item it points at. Flip the provenance plan's status note to "**removed** by
Productization Slice 1a (this commit)".
- [x] **Step 2: Run everything** — the four checks → PASS.
- [x] **Step 3: Commit with the history note**

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

### Task 10: `p11scope-discover` — drop the control-fd handshake and the sysctl requirement

**Files:**
- Modify: `crates/discover/src/main.rs`; Delete: `crates/discover/tests/control_protocol.rs`
- Test: `crates/discover/tests/cli.rs`

- [x] **Step 1: Failing test** — in `crates/discover/tests/cli.rs`:

```rust
#[test]
fn control_fd_flag_is_gone() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_p11scope-discover"))
        .args(["--control-fd", "3", "--module", "/nonexistent.so"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown argument: --control-fd"));
}
```

- [x] **Step 2: Run** — FAIL (flag accepted).
- [x] **Step 3: Implement** — delete `PREPARED/DROP/READY/GO`, `inherited_control`,
`send_control`, `expect_control`, the `--control-fd` arm and both handshake blocks in `main`;
in `prepare_drop` delete the `suid_dumpable` read and `validate_suid_dumpable` (and its unit
test); keep the credential drop exactly as is. `git rm crates/discover/tests/control_protocol.rs`.
- [x] **Step 4: Run** — `cargo +1.88 test --locked -p p11scope-discover` + clippy → PASS.
- [x] **Step 5: Commit** — `git commit -am "discover: standalone offline helper — drop control-fd handshake and suid_dumpable requirement"`

---

### Task 11: Scripts — `scripts/lib.sh`, gate scripts on the new CLI, artifact tests updated

**Files:**
- Rename: `scripts/trusted-p11scope.sh` → `scripts/lib.sh`
- Delete: `scripts/attach-pod.sh`, `scripts/container-authority.py`
- Modify: `scripts/verify-attach-e2e.sh`, `scripts/verify-induced-gaps.sh`,
  `scripts/verify-canaries.sh`, `scripts/bench-overhead.sh`, `scripts/build-release.sh`,
  `scripts/matrix/verify-docker.sh`, `scripts/matrix/verify-shared-layer.sh`,
  `scripts/matrix/verify-kind-pod.sh`, `scripts/matrix/verify-knative.sh`,
  `scripts/matrix/verify-fork-scope.sh`, `scripts/matrix/verify-oracle.sh`,
  `tests/artifact_contracts.rs` (script references)
- Create: `scripts/gates.sh`

- [x] **Step 1: `scripts/lib.sh`** — from `trusted-p11scope.sh` delete: `set_suid_dumpable_zero`,
`restore_suid_dumpable`, `validate_protected_parent`, `is_immediate_child`,
`is_trusted_exec_destination`, `create_trusted_exec_dir`, `create_protected_output_dir`,
`stage_container_authority`, `stage_trusted_p11scope`, `remove_trusted_exec_root`,
`remove_trusted_p11scope`, `remove_protected_output_dir`, `require_rewritten_authority_refusal`,
`publish_protected_file`, `publish_protected_mapdump_lane`, `is_protected_output_file`. Keep:
`require_non_root_caller`, `cleanup_step`, `capped_container_tar`,
`launch_root_recorded_process`, `wait_root_process_record`, `process_starttime`,
`root_process_starttime`, `process_matches_starttime`, `root_process_matches_starttime`,
`signal_pinned_process`, `signal_verified_process`, `signal_verified_root_process`,
`wait_for_capture_ready`.
- [x] **Step 2: Every script** — mechanical rewrite, nothing else: `. scripts/trusted-p11scope.sh`
→ `. scripts/lib.sh`; delete `TRUST_DIR=`/`RUN_DIR=` lines, `create_trusted_exec_dir`/
`create_protected_output_dir`/`stage_trusted_p11scope`, `set_suid_dumpable_zero`/
`restore_suid_dumpable`, `cleanup_step remove_trusted_p11scope …`,
`cleanup_step remove_protected_output_dir …`, `cleanup_step restore_suid_dumpable`;
`"$TRUST_DIR/p11scope"` → the script's own build path (e.g. `"$WORK/build/release/p11scope"`);
`"$TRUST_DIR/p11scope-discover"` and `"$TRUST_DIR/p11scope" discover` →
`"$WORK/build/release/p11scope-discover"`; `-o "$RUN_DIR/x.json"` → `-o "$WORK/x.json"` and
delete the following `publish_protected_file …`; delete `--provenance-module "$…"` and
`--trusted-workload` from every `p11scope profile|trace` invocation; delete any check that
asserted the exit-78 lease abort or the "rewritten authority refusal". Container matrix
scripts keep copying `p11scope-discover` into the container (`capped_container_tar`) and
rewriting attach paths to `/proc/<pid>/root/…`; delete only the `container-authority.py`
provenance steps.
- [x] **Step 3: `scripts/gates.sh`**

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

- [x] **Step 4: Update `tests/artifact_contracts.rs`** — `scripts/trusted-p11scope.sh` →
`scripts/lib.sh` in the two shell-executing tests; drop `scripts/attach-pod.sh` from the
byte-cap script list; trim `metadata_canary_matrix` / `official_build_is_safe_only` to the
assertions that remain true.
- [x] **Step 5: Verify without privileges**

```sh
for f in scripts/*.sh scripts/matrix/*.sh; do sh -n "$f" || exit 1; done
python3 scripts/check-capture-evidence.py --self-test
if grep -rn 'provenance-module\|trusted-workload\|TRUST_DIR\|RUN_DIR\|suid_dumpable\|trusted-p11scope\|container-authority' scripts/ tests/artifact_contracts.rs; then
    echo "stale terms remain"; exit 1
fi
cargo +1.88 test --locked --test artifact_contracts
```
Expected: all pass, grep finds nothing.
- [x] **Step 6: Commit** — `git add -A scripts tests/artifact_contracts.rs && git commit -m "scripts: run binaries directly under sudo; drop trusted staging, sysctl and provenance steps"`

Executor note: the gates need `sudo`; do **not** run them without owner approval
(CLAUDE.md). CI (Task 12) runs `verify-attach-e2e.sh`. Record their status as UNRUN in the
Task 14 note unless run.

---

### Task 12: CI skeleton

**Files:**
- Create: `.github/workflows/ci.yml`

- [x] **Step 1: Write the workflow**

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
      - run: cargo +1.88 install bpf-linker --version 0.10.4 --locked
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
      - run: cargo +1.88 install bpf-linker --version 0.10.4 --locked
      - run: sudo apt-get update && sudo apt-get install -y gcc softhsm2 python3
      - run: uname -r; cat /proc/sys/kernel/perf_event_paranoid; cat /proc/sys/kernel/yama/ptrace_scope
      - run: scripts/verify-attach-e2e.sh
```

- [x] **Step 2: Local sanity** — `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` → parses.
- [x] **Step 3: Commit** — `git add .github && git commit -m "ci: unprivileged checks and sudo e2e gate on GitHub Actions"`

The first real run happens when the owner pushes; the executor cannot observe it and must
record it as PENDING (Task 14).

---

### Task 13: Docs sync (minimal; the full rewrite is Slice 1b)

**Files:**
- Modify: `README.md`, `docs/usage.md`, `CHANGELOG.md`, `docs/schema/observed-profile-v1.md`,
  `docs/privacy/allowlist-v1.md`

- [x] **Step 1: README** — replace the status block (`README.md:13-21`) with: "**Status:
unreleased.** Productization slice 1a: the lease/provenance/hardened-oracle lane was
removed (see `docs/superpowers/plans/ROADMAP.md` → Productization); provider identity is
pinned by SHA-256 at attach and checked for in-place change during capture
(`evidence.provider_changed`). Discovery without the offline helper, `run`/`inspect`/`doctor`
and minimum-privilege tiers are Slice 1b." Quickstart: `p11scope-discover --module … -o
manifest.json` then `p11scope profile --manifest manifest.json --pid 12345 -o
observed-profile.json`. Delete the "Containers and Kubernetes" paragraphs on provenance/
leases/exit 78 (keep the inode-sharing paragraph). In "Honest claims" delete the `CAP_LEASE`
sentence; state the current requirement: BPF capabilities (`CAP_SYS_ADMIN` on
`perf_event_paranoid=4` hosts) plus `CAP_SYS_PTRACE` for cross-uid `/proc/<pid>/root`.
- [x] **Step 2: usage.md** — same for the status block, Quickstart, "Attaching to an existing
Kubernetes pod" (delete; wrapper returns in Slice 1b), the provenance paragraphs (delete),
the privileges table (drop the "Added file-stability requirement" column and the `CAP_LEASE`
text), "Related docs" (`v1.3` → `v1.4`).
- [x] **Step 3: CHANGELOG** — new top section "Unreleased — productization slice 1a": lane
removed (pointer to reasoning), CLI changes, `provider_changed`, SIGTERM, CI, helper is
offline-only.
- [x] **Step 4: schema doc** — add `provider_changed` row to the evidence table "(v1.4
addendum, 2026-08-15)".
- [x] **Step 5: allowlist** — replace the paragraph starting "A raw manifest never authorizes
code…" with "A manifest is trusted operator input, structurally validated and hash-matched
against the pinned object; the observer executes no provider code." (capture-field tables
unchanged).
- [x] **Step 6: Commit** — `git commit -am "docs: sync README/usage/CHANGELOG/schema/allowlist with slice 1a"`

---

### Task 14: Final verification and honest status

- [x] **Step 1: The four checks** — all green (Global Constraints).
- [x] **Step 2: Line count** — `git diff --stat f35c04e..HEAD -- src crates tests scripts | tail -1`.
- [x] **Step 3: Ask the owner** whether to run `scripts/gates.sh` locally (sudo). Run only on
approval.
- [x] **Step 4: Record in the ROADMAP Slice 1a entry**: "landed <commit>, −N lines; unprivileged
suite green; root gates: <PASS with log tail | UNRUN (not approved)>; CI e2e: <PASS |
PENDING first push>". Never write "green" for anything not run.
- [x] **Step 5: Commit** the ROADMAP line.

---

## Self-review

- Spec coverage (Slice 1a items of §7): ROADMAP (T1, T9 flip, T14) ✔; text-grep tests pruned
  before code moves (T2) ✔; deletions §4.11 (T9, T10, T11) ✔; identity pinning §4.5 with
  `fstat`, refuse-on-change before/after attach, `provider_changed` during capture (T4, T7,
  T8) ✔; manifest as input with SHA-256 match (T4) ✔; atomic output with the existing
  identity guarantees (T5) ✔; CLI cleanup incl. `--duration` suffixes, SIGTERM, removed
  flags (T6, T8) ✔; scripts on the new CLI (T11) ✔; CI skeleton with pinned bpf-linker (T12)
  ✔; docs incl. README status block, CHANGELOG (T13) ✔; honest UNRUN/PENDING recording (T14)
  ✔. Not in 1a by design: `--module` optional, `run/inspect/doctor`, scan, hooks, pause,
  schema v2, `discovery[]` evidence, `--pause`, `--hook-symbol` (Slice 1b).
- Placeholder scan: none; every code step shows the code or the exact source range to move.
- Red states are real: T5/T6 create the module file with tests and wire `pub mod` in Step 1.
- Compile-at-every-commit: T2 prunes source-reading tests first; T3 keeps `verify.rs`
  compiling with a single `pub use`; T5 copies `PendingProfile` (T9 deletes the original);
  T8 rewires main/attach while the lane still compiles; T9 deletes; T11 changes scripts and
  the tests that reference them in one commit.
- Type consistency: `PinnedObjects::{attach_path, check_unchanged, identities}` (T4) used in
  T8/`attach.rs`; `AtomicFile::{create, file, commit}` (T5) used in T8; `cli::{parse_capture,
  Kind, ScopeArg, CaptureArgs, CliError, USAGE, parse_duration}` (T6) used in T8;
  `STOP_SIGNALS`/`install_stop_flag` (T8) tested in T8; `manifest_input::{read_manifest,
  validate_structure, MAX_*}` (T3) used in T4/T8.
