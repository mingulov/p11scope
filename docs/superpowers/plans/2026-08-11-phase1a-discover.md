# Phase 1a — p11scope-discover + aya offset pin — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `p11scope-discover` — the unprivileged dlopen helper that turns a PKCS#11 provider into a probe-manifest JSON of `{object, file_offset}` targets — and pin aya's uprobe offset semantics as a regression fact (Gate G0 carry-over).

**Architecture:** New workspace member `crates/discover` (lib + bin). The lib is four focused modules: `maps` (/proc/self/maps → file offsets), `identity` (per-object build-ID / SHA-256), `manifest` (schema v1 types), `discover` (dlopen + table walk glue on `pkcs11-module`). The offset experiment is throwaway-adjacent code under `spike/aya-offset-pin/` producing a durable note in `docs/notes/`. Phase 1b (aya attach engine, `metrics` mode) gets its own plan after this lands.

**Tech Stack:** Rust edition 2024; `pkcs11-module` (proxy-ng shared crate, git+rev); `libloading` 0.8; `cryptoki-sys` 0.5; `object` 0.39 (read-only); `sha2`; `serde`/`serde_json`; aya 0.14.0 + aya-ebpf 0.2.1 (spike only); gcc fixtures; docker (ubuntu 24.04 / alpine).

Spec inputs: [design spec](../specs/2026-08-10-pkcs11-scope-design.md) (Architecture, v1 scope), [outputs spec](../specs/2026-08-10-pkcs11-scope-outputs.md) (CLI), [ROADMAP Phase 1](ROADMAP.md), [extraction design §10](../specs/2026-08-10-module-crate-extraction-design.md) (dependency contract), review corrections recorded in this plan's design session (2026-08-11).

## Global Constraints

- Edition 2024, `rust-version = "1.88"`, `license = "MIT OR Apache-2.0"`, `publish = false` — every crate.
- The helper NEVER calls `C_Initialize` and NEVER calls `C_GetInterface` (interface *selection* is proxy policy; the helper records what the module reports).
- Both surfaces are ALWAYS attempted — legacy `C_GetFunctionList` and the `C_GetInterfaceList` enumeration — regardless of module generation.
- Only standard-named (`"PKCS 11"`, via `RawInterface::is_standard()`) interfaces are walked. Vendor interfaces are recorded present-but-undecoded. NULL entries, non-file-backed pointers, unmapped pointers, and acquisition failures are recorded as evidence, never dropped.
- Dependency contract (extraction spec §10): `pkcs11-module = { git = "https://github.com/mingulov/pkcs11-proxy-ng", rev = "7c5c86043820eb3795f40c65a36ce961cdfd26c5" }`. **No path dependencies are ever committed.** Task 5 gates on that rev being reachable on the remote.
- `libloading = "0.8"` and `cryptoki-sys = "0.5"` must stay in lockstep with proxy-ng's workspace versions (types cross the `pkcs11-module` API boundary).
- Allowed `crates/discover` dependencies, exhaustively: `pkcs11-module`, `cryptoki-sys`, `libloading`, `object` (default-features off, `read`), `sha2`, `serde` (derive), `serde_json`. Nothing else.
- Manifest offsets are ELF **object-file byte offsets** — exactly what aya 0.14's `UProbeAttachLocation::AbsoluteOffset` consumes (Task 3 pins this).
- Commit style: short prefix + imperative, matching repo history (`discover:`, `spike:`, `plan:`, `docs:`).
- Do NOT run proxy-ng's provider-matrix gate (`scripts/run-pooled-proxy-tests.sh`) — that is the pkcs11-proxy-ng project's job.

## Verified environment facts (2026-08-11)

- SoftHSM2 at `/usr/lib/softhsm/libsofthsm2.so` (symlink into `/usr/lib/x86_64-linux-gnu/softhsm/`), 2.40-only provider.
- `sudo -n` works. `gcc`, `clang`, `readelf`, `docker` present; `alpine:3.24`/`alpine:latest` images cached; `ubuntu:24.04` and `rust:1-alpine` need `docker pull`.
- rustup: stable (default, 1.94), **nightly with rust-src installed**. `bpf-linker` NOT installed — Task 3 installs it.
- crates.io reachable. Cargo's built-in git fetch (libgit2/gitoxide) FAILS in this sandbox for https GitHub URLs, but `git` CLI https and ssh both work → machine-local `[net] git-fetch-with-cli = true` is required (Task 5, uncommitted).
- aya 0.14.0: `UProbeAttachLocation::AbsoluteOffset(u64)` is documented "The offset in the target object file, in bytes"; `attach(point: impl Into<UProbeAttachPoint>, target: AsRef<Path>, scope: UProbeScope)`; `UProbeScope::{AllProcesses, CallingProcess, OneProcess}` lives in `aya::programs::uprobe`. aya-ebpf is 0.2.1.
- `pkcs11-module` (rev `7c5c860…`) root re-exports: `function_list`, `interface_list`, `RawInterface` (+ `is_standard()`), `FnField`, `FUNCTION_LIST_FIELDS` (68), `FUNCTION_LIST_3_0_EXTRA_FIELDS` (24), `FUNCTION_LIST_3_2_EXTRA_FIELDS` (12), `Surface`, `TableSet`, `tables_for`, `read_fn_pointers`, `detect_null_functions`.
- `RawInterface { name: Option<Vec<u8>>, version: Option<CK_VERSION>, flags: CK_FLAGS, func_list: *mut c_void }`; `version` is `None` iff `func_list` is NULL.

---

### Task 1: Workspace conversion + `maps` resolver

**Files:**
- Modify: `Cargo.toml` (root — add workspace table)
- Create: `crates/discover/Cargo.toml`
- Create: `crates/discover/src/lib.rs`
- Create: `crates/discover/src/main.rs`
- Create: `crates/discover/src/maps.rs`

**Interfaces:**
- Produces: `maps::MapEntry { start: u64, end: u64, file_offset: u64, path: Option<PathBuf> }`; `maps::parse_maps(text: &str) -> Vec<MapEntry>`; `maps::Resolved { File { path: PathBuf, file_offset: u64 }, Anonymous, Unmapped }`; `maps::resolve(maps: &[MapEntry], vaddr: u64) -> Resolved`. Task 5 consumes all of these.

- [ ] **Step 1: Convert the root manifest to a workspace root**

Append to the existing `[package]` in root `Cargo.toml` (leave the package section untouched):

```toml
[workspace]
members = ["crates/discover"]
```

- [ ] **Step 2: Create the discover crate skeleton**

`crates/discover/Cargo.toml`:

```toml
[package]
name = "p11scope-discover"
version = "0.0.0"
edition = "2024"
rust-version = "1.88"
license = "MIT OR Apache-2.0"
repository = "https://github.com/mingulov/pkcs11-scope"
description = "PKCS#11 discovery helper: dlopen a provider, map its function tables to ELF file offsets"
publish = false

[dependencies]
```

`crates/discover/src/lib.rs`:

```rust
//! p11scope-discover library — split from the bin so tests call discovery
//! directly. Runs vendor code via dlopen; that is why the helper is a
//! separate unprivileged short-lived process (design spec, Architecture).

pub mod maps;
```

`crates/discover/src/main.rs`:

```rust
fn main() {
    eprintln!("p11scope-discover: not implemented yet");
    std::process::exit(1);
}
```

- [ ] **Step 3: Write the failing maps test**

In `crates/discover/src/maps.rs`, write the module doc, an empty body, and the tests first:

```rust
//! /proc/<pid>/maps parsing and vaddr → ELF-file-offset resolution.

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const FIXTURE: &str = "\
00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/dbus-daemon
7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0
7ffc55555000-7ffc55576000 rw-p 00000000 00:00 0 [stack]
7f2b40000000-7f2b40021000 r-xp 00021000 08:01 999 /opt/with space/lib.so
7f2b50000000-7f2b50001000 r--p 00002000 08:01 998 /usr/lib/gone.so (deleted)
not a maps line
";

    #[test]
    fn parses_entries_and_skips_garbage() {
        let m = parse_maps(FIXTURE);
        assert_eq!(m.len(), 5);
        assert_eq!(m[0].start, 0x400000);
        assert_eq!(m[0].end, 0x452000);
        assert_eq!(m[0].file_offset, 0);
        assert_eq!(m[0].path, Some(PathBuf::from("/usr/bin/dbus-daemon")));
        // Path with spaces survives; pseudo-paths and anonymous become None.
        assert_eq!(m[3].path, Some(PathBuf::from("/opt/with space/lib.so")));
        assert_eq!(m[1].path, None);
        assert_eq!(m[2].path, None);
        // Deleted-file suffix preserved verbatim — honest evidence.
        assert_eq!(m[4].path, Some(PathBuf::from("/usr/lib/gone.so (deleted)")));
    }

    #[test]
    fn resolves_with_segment_offset_arithmetic() {
        let m = parse_maps(FIXTURE);
        assert_eq!(
            resolve(&m, 0x7f2b40000abc),
            Resolved::File { path: PathBuf::from("/opt/with space/lib.so"), file_offset: 0x21abc }
        );
        assert_eq!(
            resolve(&m, 0x400010),
            Resolved::File { path: PathBuf::from("/usr/bin/dbus-daemon"), file_offset: 0x10 }
        );
    }

    #[test]
    fn classifies_anonymous_and_unmapped() {
        let m = parse_maps(FIXTURE);
        assert_eq!(resolve(&m, 0x7f8a1c000500), Resolved::Anonymous);
        assert_eq!(resolve(&m, 0x7ffc55555100), Resolved::Anonymous); // [stack]
        assert_eq!(resolve(&m, 0x1), Resolved::Unmapped);
        assert_eq!(resolve(&m, 0x00452000), Resolved::Unmapped); // end is exclusive
    }
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test -p p11scope-discover`
Expected: compile error — `parse_maps`, `Resolved`, `resolve` not found.

- [ ] **Step 5: Implement the resolver**

Above the tests in `maps.rs`:

```rust
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    /// `None` for anonymous mappings and `[heap]`-style pseudo-paths.
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    File { path: PathBuf, file_offset: u64 },
    Anonymous,
    Unmapped,
}

/// Parse /proc/<pid>/maps text. Unparseable lines are skipped — discovery
/// degrades to "unmapped" evidence rather than aborting.
pub fn parse_maps(text: &str) -> Vec<MapEntry> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<MapEntry> {
    // <start>-<end> <perms> <offset> <dev> <inode> [path with possible spaces]
    let mut it = line.splitn(6, ' ');
    let range = it.next()?;
    let _perms = it.next()?;
    let offset = it.next()?;
    let _dev = it.next()?;
    let _inode = it.next()?;
    let path = it.next().map(str::trim).filter(|p| !p.is_empty());

    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let file_offset = u64::from_str_radix(offset, 16).ok()?;
    // Only absolute paths are file-backed; `[stack]` etc. count as anonymous.
    let path = path.filter(|p| p.starts_with('/')).map(PathBuf::from);
    Some(MapEntry { start, end, file_offset, path })
}

pub fn resolve(maps: &[MapEntry], vaddr: u64) -> Resolved {
    match maps.iter().find(|m| m.start <= vaddr && vaddr < m.end) {
        None => Resolved::Unmapped,
        Some(m) => match &m.path {
            None => Resolved::Anonymous,
            Some(p) => Resolved::File {
                path: p.clone(),
                file_offset: m.file_offset + (vaddr - m.start),
            },
        },
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p p11scope-discover` — expected: 3 passed. Also `cargo check` (whole workspace still builds).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates/discover
git commit -m "discover: workspace member with /proc maps → file-offset resolver"
```

---

### Task 2: Per-object identity (build-ID, SHA-256 fallback)

**Files:**
- Modify: `crates/discover/Cargo.toml` (add object, sha2, serde)
- Create: `crates/discover/src/identity.rs`
- Modify: `crates/discover/src/lib.rs` (add `pub mod identity;`)
- Create: `crates/discover/tests/identity.rs`

**Interfaces:**
- Produces: `identity::IdentityKind { GnuBuildId, Sha256, Unavailable }`; `identity::ObjectIdentity { kind: IdentityKind, value: Option<String>, reusable: bool, note: Option<String> }` (serde-derived); `identity::identify(path: &Path) -> ObjectIdentity` (never panics, never errors — degrades to `Unavailable`/not-reusable); `pub(crate) identity::hex(bytes: &[u8]) -> String`. Tasks 4/5 consume these.

- [ ] **Step 1: Add dependencies**

In `crates/discover/Cargo.toml` under `[dependencies]`:

```toml
object = { version = "0.39", default-features = false, features = ["read"] }
serde = { version = "1", features = ["derive"] }
sha2 = "0.10"
```

- [ ] **Step 2: Write the failing tests**

`crates/discover/tests/identity.rs`:

```rust
use p11scope_discover::identity::{IdentityKind, identify};
use std::path::{Path, PathBuf};
use std::process::Command;

fn cc_shared(dir: &Path, out: &str, extra: &[&str]) -> PathBuf {
    let src = dir.join("stub.c");
    std::fs::write(&src, "int nothing(void) { return 42; }\n").unwrap();
    let so = dir.join(out);
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&src)
        .args(extra)
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc failed");
    so
}

fn tmpdir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn gnu_build_id_preferred() {
    let so = cc_shared(&tmpdir("id1"), "with_id.so", &["-Wl,--build-id=sha1"]);
    let id = identify(&so);
    assert_eq!(id.kind, IdentityKind::GnuBuildId);
    assert!(id.reusable);
    assert_eq!(id.value.unwrap().len(), 40); // sha1 note = 20 bytes hex
}

#[test]
fn sha256_fallback_without_build_id() {
    let so = cc_shared(&tmpdir("id2"), "no_id.so", &["-Wl,--build-id=none"]);
    let id = identify(&so);
    assert_eq!(id.kind, IdentityKind::Sha256);
    assert!(id.reusable);
    assert_eq!(id.value.unwrap().len(), 64);
}

#[test]
fn non_elf_still_hashes_bytes() {
    let d = tmpdir("id3");
    let f = d.join("not_elf.so");
    std::fs::write(&f, b"not an ELF at all").unwrap();
    let id = identify(&f);
    assert_eq!(id.kind, IdentityKind::Sha256);
    assert!(id.reusable);
    assert!(id.note.unwrap().contains("not parseable"));
}

#[test]
fn unreadable_is_explicitly_not_reusable() {
    let id = identify(Path::new("/nonexistent/x.so"));
    assert_eq!(id.kind, IdentityKind::Unavailable);
    assert!(!id.reusable);
    assert!(id.value.is_none());
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p p11scope-discover --test identity`
Expected: compile error — module `identity` does not exist.

- [ ] **Step 4: Implement**

`crates/discover/src/identity.rs`:

```rust
//! Per-object identity for manifest-reuse decisions. A manifest may only be
//! reused against a file whose identity matches (Gate G1: reuse refused on
//! build-ID mismatch). GNU build-ID is authoritative; whole-file SHA-256 is
//! the fallback; a file we cannot read gets an explicit not-reusable state.

use object::Object as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    GnuBuildId,
    Sha256,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectIdentity {
    pub kind: IdentityKind,
    /// Hex digest; `None` only when `kind == Unavailable`.
    pub value: Option<String>,
    /// Whether a manifest may be reused against a file with this identity.
    pub reusable: bool,
    pub note: Option<String>,
}

pub fn identify(path: &Path) -> ObjectIdentity {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            return ObjectIdentity {
                kind: IdentityKind::Unavailable,
                value: None,
                reusable: false,
                note: Some(format!("read failed: {e}")),
            };
        }
    };
    let mut note = None;
    // object reads the build-id from PT_NOTE program headers too, so a
    // stripped section table does not lose it (review finding, 2026-08-11).
    match object::File::parse(&*data) {
        Ok(f) => match f.build_id() {
            Ok(Some(id)) => {
                return ObjectIdentity {
                    kind: IdentityKind::GnuBuildId,
                    value: Some(hex(id)),
                    reusable: true,
                    note: None,
                };
            }
            Ok(None) => {}
            Err(e) => note = Some(format!("build-id read failed: {e}")),
        },
        Err(e) => note = Some(format!("not parseable as an object file: {e}")),
    }
    let digest = Sha256::digest(&data);
    ObjectIdentity {
        kind: IdentityKind::Sha256,
        value: Some(hex(&digest)),
        reusable: true,
        note,
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
```

Add `pub mod identity;` to `lib.rs`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p p11scope-discover` — expected: all pass (maps 3 + identity 4).

- [ ] **Step 6: Commit**

```bash
git add crates/discover Cargo.lock
git commit -m "discover: per-object identity — GNU build-ID, SHA-256 fallback, explicit not-reusable"
```

---

### Task 3: Aya offset-semantics regression pin (Gate G0 carry-over)

**Files:**
- Create: `spike/aya-offset-pin/Cargo.toml`, `spike/aya-offset-pin/src/main.rs`
- Create: `spike/aya-offset-pin/pin-ebpf/Cargo.toml`, `spike/aya-offset-pin/pin-ebpf/src/main.rs`
- Create: `spike/aya-offset-pin/target.c`, `spike/aya-offset-pin/run.sh`
- Create: `docs/notes/aya-offset-semantics.md`
- Modify: `.gitignore`, `docs/notes/spike-findings.md`

**Interfaces:**
- Consumes: nothing from other tasks (standalone; deliberately outside the workspace).
- Produces: the pinned fact "aya 0.14.0 `AbsoluteOffset` = ELF object-file byte offset", recorded in `docs/notes/aya-offset-semantics.md`. Task 4's schema comment and Phase 1b's attach code rely on it.

Claim under test (already confirmed in aya 0.14.0 source, `src/programs/uprobe.rs`: "The offset in the target object file, in bytes"): attaching at the *file offset* of a symbol observes calls; interpreting the same location as a *virtual address* does not. A non-PIE executable has `p_vaddr != p_offset` for `.text` (the case SoftHSM2 could not exercise in Phase 0 — there `p_offset == p_vaddr`).

- [ ] **Step 1: Install bpf-linker if missing (~5 min build)**

```bash
which bpf-linker || cargo install bpf-linker
```

- [ ] **Step 2: Ignore spike build artifacts**

Append to `.gitignore`:

```
target/
spike/aya-offset-pin/work/
```

(The existing `/target/` line only covers the workspace root; the spike crates have their own `target/` dirs.)

- [ ] **Step 3: Write the eBPF counter program**

`spike/aya-offset-pin/pin-ebpf/Cargo.toml`:

```toml
[package]
name = "pin-ebpf"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
aya-ebpf = "=0.2.1"

[profile.release]
panic = "abort"
lto = true
codegen-units = 1

[workspace]
```

`spike/aya-offset-pin/pin-ebpf/src/main.rs`:

```rust
#![no_std]
#![no_main]

use aya_ebpf::macros::{map, uprobe};
use aya_ebpf::maps::Array;
use aya_ebpf::programs::ProbeContext;

#[map]
static HITS: Array<u64> = Array::with_max_entries(1, 0);

#[uprobe]
pub fn pin(_ctx: ProbeContext) -> u32 {
    if let Some(v) = HITS.get_ptr_mut(0) {
        unsafe { *v += 1 };
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

- [ ] **Step 4: Write the userspace attacher**

`spike/aya-offset-pin/Cargo.toml`:

```toml
[package]
name = "aya-offset-pin"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
aya = "=0.14.0"

[workspace]
```

`spike/aya-offset-pin/src/main.rs`:

```rust
//! Attach the `pin` uprobe at a caller-supplied offset, run the target once,
//! print the hit count. Exit 0 iff hits == expected. Exit 3 on attach error.

use aya::maps::Array;
use aya::programs::UProbe;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeScope};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, obj, target, off_hex, expect] = &args[..] else {
        eprintln!("usage: aya-offset-pin <ebpf.o> <target-exe> <0xoffset> <expected-calls>");
        std::process::exit(2);
    };
    let offset = u64::from_str_radix(off_hex.trim_start_matches("0x"), 16).expect("hex offset");
    let mut ebpf = aya::Ebpf::load(&std::fs::read(obj).expect("read ebpf object")).expect("load ebpf");
    let prog: &mut UProbe = ebpf
        .program_mut("pin")
        .expect("program 'pin'")
        .try_into()
        .expect("uprobe program");
    prog.load().expect("kernel load");
    if let Err(e) = prog.attach(
        UProbeAttachLocation::AbsoluteOffset(offset),
        target,
        UProbeScope::AllProcesses,
    ) {
        println!("attach_error={e}");
        std::process::exit(3);
    }
    let status = std::process::Command::new(target).status().expect("run target");
    assert!(status.success(), "target exited nonzero");
    let hits: Array<_, u64> = Array::try_from(ebpf.map("HITS").expect("map HITS")).expect("array");
    let n = hits.get(&0, 0).expect("read map");
    println!("hits={n} expected={expect}");
    std::process::exit(if n.to_string() == *expect { 0 } else { 1 });
}
```

- [ ] **Step 5: Write the non-PIE target and driver script**

`spike/aya-offset-pin/target.c`:

```c
/* Built -no-pie so .text p_vaddr (0x40xxxx) != p_offset — the disagreement
 * case Phase 0 could not produce (SoftHSM2 has p_offset == p_vaddr). */
__attribute__((noinline)) void probe_me(void) { __asm__ volatile(""); }

int main(void) {
    for (int i = 0; i < 7; i++) probe_me();
    return 0;
}
```

`spike/aya-offset-pin/run.sh` (mark executable):

```sh
#!/bin/sh -eu
# Regression pin for aya's uprobe offset semantics (Gate G0 carry-over).
cd "$(dirname "$0")"
mkdir -p work
gcc -no-pie -O0 -o work/target target.c

VADDR=$(readelf -sW work/target | awk '$8=="probe_me" {print $2; exit}')
set -- $(readelf -SW work/target | sed 's/\[ *[0-9]*\]//' | awk '$1==".text" {print $3, $4}')
TEXT_ADDR=$1 TEXT_OFF=$2
FILE_OFF=$(printf '%x' $((0x$VADDR - 0x$TEXT_ADDR + 0x$TEXT_OFF)))
echo "probe_me: vaddr=0x$VADDR file_offset=0x$FILE_OFF (.text addr=0x$TEXT_ADDR off=0x$TEXT_OFF)"
# Numeric compare — readelf pads vaddr with leading zeros, printf does not.
[ $((0x$VADDR)) -ne $((0x$FILE_OFF)) ] || { echo "control invalid: vaddr == file offset"; exit 1; }

cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core \
    --manifest-path pin-ebpf/Cargo.toml
cargo build --release

EBPF=pin-ebpf/target/bpfel-unknown-none/release/pin-ebpf
sudo ./target/release/aya-offset-pin "$EBPF" "$PWD/work/target" "0x$FILE_OFF" 7
echo "PASS: file-offset attach observed exactly 7 calls"

if sudo ./target/release/aya-offset-pin "$EBPF" "$PWD/work/target" "0x$VADDR" 7; then
    echo "FAIL: vaddr interpretation also observed the calls — semantics ambiguous"
    exit 1
fi
echo "PASS: vaddr interpretation does not observe the calls"
```

- [ ] **Step 6: Run it**

Run: `sh spike/aya-offset-pin/run.sh`
Expected: both `PASS` lines. If the vaddr control *also* fires, STOP — the pinned assumption is wrong; escalate to the human before any schema work proceeds.

- [ ] **Step 7: Record the durable note**

`docs/notes/aya-offset-semantics.md` — write the observed numbers in, replacing the bracketed values with what run.sh printed:

```markdown
# Aya uprobe offset semantics — pinned (Phase 1a, Task 3)

**Fact:** aya 0.14.0 `UProbeAttachLocation::AbsoluteOffset(u64)` is an ELF
**object-file byte offset** — exactly what `p11scope-discover` records per
manifest entry. No vaddr translation happens at attach time; aya passes the
value through to the kernel, which expects file offsets for uprobes.

**Evidence** (spike/aya-offset-pin/run.sh, kernel [uname -r], aya =0.14.0,
aya-ebpf =0.2.1): non-PIE target, `probe_me` vaddr [0x…], file offset
[0x…]. Attach at file offset → hits=7/7. Attach at vaddr → [attach_error=… |
hits=0]. Source cross-reference: aya-0.14.0 `src/programs/uprobe.rs`
documents AbsoluteOffset as "The offset in the target object file, in
bytes" and provides `UProbeAttachLocation::from_virtual_address` for
callers holding vaddrs.

**Consequence for Phase 1b:** attach with
`UProbeAttachLocation::AbsoluteOffset(manifest_entry.file_offset)` directly.
Never re-derive offsets from symbol tables (providers are stripped).
```

Also append one line to the "carried into Phase 1" item in `docs/notes/spike-findings.md`: `Resolved 2026-08-11 — see aya-offset-semantics.md (file offsets; pinned by spike/aya-offset-pin).`

- [ ] **Step 8: Commit**

```bash
git add spike/aya-offset-pin .gitignore docs/notes/aya-offset-semantics.md docs/notes/spike-findings.md
git commit -m "spike: pin aya 0.14 uprobe AbsoluteOffset = ELF file offset"
```

---

### Task 4: Manifest schema v1

**Files:**
- Modify: `crates/discover/Cargo.toml` (add serde_json)
- Create: `crates/discover/src/manifest.rs`
- Modify: `crates/discover/src/lib.rs` (add `pub mod manifest;`)

**Interfaces:**
- Consumes: `identity::ObjectIdentity` (Task 2).
- Produces: every type below, exactly as named — Tasks 5–7 construct and assert on them. `manifest::SCHEMA = "p11scope-manifest/1"`.

- [ ] **Step 1: Add serde_json**

In `crates/discover/Cargo.toml` `[dependencies]`: `serde_json = "1"`.

- [ ] **Step 2: Write the schema types with a failing round-trip test**

`crates/discover/src/manifest.rs`:

```rust
//! Probe-manifest schema v1. Offsets are ELF object-file byte offsets —
//! aya 0.14 `UProbeAttachLocation::AbsoluteOffset` semantics, pinned in
//! docs/notes/aya-offset-semantics.md. Evidence (NULL entries, vendor
//! interfaces, non-file-backed pointers, acquisition failures) is recorded,
//! never dropped.

use crate::identity::ObjectIdentity;
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "p11scope-manifest/1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: String,
    /// The dlopen target as given on the command line.
    pub module_path: String,
    /// Every distinct object file some pointer resolved into. Identity is
    /// per object: a table entry may legally live outside the module .so.
    pub objects: Vec<ObjectRecord>,
    /// Outcome of the C_GetInterfaceList enumeration as a whole (the
    /// legacy surface records its own acquisition inside its record).
    pub interface_list: Acquisition,
    pub surfaces: Vec<SurfaceRecord>,
    /// Present-but-undecoded evidence; never walked.
    pub vendor_interfaces: Vec<VendorInterface>,
    /// ≥2 distinct logical names resolving to one {object, file_offset}.
    pub alias_groups: Vec<AliasGroup>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectRecord {
    pub id: u32,
    pub path: String,
    pub identity: ObjectIdentity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceRecord {
    pub source: SurfaceSource,
    pub acquisition: Acquisition,
    /// Reported CK_VERSION of this surface's function list, if any.
    pub version: Option<Version>,
    pub walk: WalkOutcome,
    pub functions: Vec<FunctionRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SurfaceSource {
    /// The legacy 2.40 table from C_GetFunctionList.
    LegacyFunctionList,
    /// One C_GetInterfaceList entry whose name is exactly "PKCS 11".
    Interface { index: usize, raw_name_hex: String, name_lossy: String, flags: u64 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Acquisition {
    Ok,
    /// Symbol not exported — the only proven fact; no generation inference.
    Absent,
    /// Export present, zero interfaces reported.
    Empty,
    Error { detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalkOutcome {
    /// Every field table for the reported version was walked.
    Full,
    /// 3.x minor > 2: walked tables are a safe prefix; excess exists.
    KnownPrefix,
    /// tables_for refused the layout; nothing walked.
    Refused,
    /// Surface present but unwalkable (NULL function list, failed acquisition).
    NotWalked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionRecord {
    pub name: String,
    pub resolution: Resolution,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Resolution {
    Resolved { object: u32, file_offset: u64 },
    NullPointer,
    /// Pointer lands in an anonymous mapping — evidence gap, not an entry.
    NonFileBacked,
    /// Pointer inside no mapping at all — evidence gap.
    Unmapped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VendorInterface {
    pub index: usize,
    /// Lossless raw bytes of pInterfaceName; None when the pointer was NULL.
    pub raw_name_hex: Option<String>,
    pub name_lossy: Option<String>,
    pub version: Option<Version>,
    pub flags: u64,
    pub func_list_null: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AliasGroup {
    pub object: u32,
    pub file_offset: u64,
    /// Every (surface, name) resolving here — includes same-name
    /// corroborations once the group qualifies (≥2 distinct names).
    pub entries: Vec<AliasEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AliasEntry {
    pub surface: usize,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityKind, ObjectIdentity};

    #[test]
    fn round_trips_through_json() {
        let m = Manifest {
            schema: SCHEMA.to_string(),
            module_path: "/opt/p11.so".into(),
            objects: vec![ObjectRecord {
                id: 0,
                path: "/opt/p11.so".into(),
                identity: ObjectIdentity {
                    kind: IdentityKind::GnuBuildId,
                    value: Some("aa".into()),
                    reusable: true,
                    note: None,
                },
            }],
            interface_list: Acquisition::Error { detail: "boom".into() },
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: Some(Version { major: 2, minor: 40 }),
                walk: WalkOutcome::Full,
                functions: vec![
                    FunctionRecord {
                        name: "C_Initialize".into(),
                        resolution: Resolution::Resolved { object: 0, file_offset: 0x1000 },
                    },
                    FunctionRecord {
                        name: "C_GetFunctionStatus".into(),
                        resolution: Resolution::NullPointer,
                    },
                ],
            }],
            vendor_interfaces: vec![VendorInterface {
                index: 1,
                raw_name_hex: Some("41".into()),
                name_lossy: Some("A".into()),
                version: None,
                flags: 0,
                func_list_null: false,
            }],
            alias_groups: vec![],
        };
        let json = serde_json::to_string_pretty(&m).unwrap();
        assert!(json.contains("\"schema\": \"p11scope-manifest/1\""));
        assert!(json.contains("\"status\": \"null_pointer\""));
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }
}
```

- [ ] **Step 3: Run — fails until `pub mod manifest;` is added**

Add `pub mod manifest;` to `lib.rs`, then run `cargo test -p p11scope-discover`.
Expected: all pass (maps 3, identity 4, manifest 1).

- [ ] **Step 4: Commit**

```bash
git add crates/discover Cargo.lock
git commit -m "discover: probe-manifest schema v1 (per-object identity, explicit evidence)"
```

---

### Task 5: Acquisition + walk glue, SoftHSM2 integration (GATED on pushed rev)

**Files:**
- Modify: `crates/discover/Cargo.toml` (add pkcs11-module git+rev, cryptoki-sys, libloading)
- Create: `crates/discover/src/discover.rs`
- Modify: `crates/discover/src/lib.rs` (add `pub mod discover;`)
- Create: `crates/discover/tests/softhsm.rs`

**Interfaces:**
- Consumes: `maps::{parse_maps, resolve, MapEntry, Resolved}`, `identity::{identify, hex}`, all `manifest::*` types; from `pkcs11_module`: `function_list`, `interface_list`, `RawInterface::is_standard`, `Surface`, `TableSet`, `FnField`, `tables_for`, `read_fn_pointers`, `FUNCTION_LIST_FIELDS`.
- Produces: `discover::discover(module_path: &Path) -> Result<Manifest, String>`. Tasks 6–8 consume it.

- [ ] **Step 1: GATE — verify the pinned rev is reachable**

```bash
git -C /home/user/src/m/pkcs11-proxy-ng-ws/pkcs11-proxy-ng fetch origin
git -C /home/user/src/m/pkcs11-proxy-ng-ws/pkcs11-proxy-ng branch -r --contains 7c5c86043820eb3795f40c65a36ce961cdfd26c5
```

Non-empty output → proceed. Empty → **STOP and ask the human** to publish the rev (their call which shape, e.g. `git push origin dev` or `git push origin 7c5c86043820eb3795f40c65a36ce961cdfd26c5:refs/heads/pkcs11-module`). Do NOT substitute a path dependency — no path deps are ever committed (Global Constraints).

- [ ] **Step 2: Machine-local cargo fetch fix (uncommitted)**

Cargo's built-in git fetch fails in this sandbox; the git CLI works:

```bash
grep -qs 'git-fetch-with-cli' ~/.cargo/config.toml || printf '\n[net]\ngit-fetch-with-cli = true\n' >> ~/.cargo/config.toml
```

- [ ] **Step 3: Add the pinned dependency**

In `crates/discover/Cargo.toml` `[dependencies]` (versions in lockstep with proxy-ng's workspace):

```toml
cryptoki-sys = "0.5"
libloading = "0.8"
pkcs11-module = { git = "https://github.com/mingulov/pkcs11-proxy-ng", rev = "7c5c86043820eb3795f40c65a36ce961cdfd26c5" }
```

Run: `cargo check -p p11scope-discover` — expected: fetches and builds cleanly.

- [ ] **Step 4: Write the failing SoftHSM2 integration test**

`crates/discover/tests/softhsm.rs`:

```rust
use p11scope_discover::discover::discover;
use p11scope_discover::identity::IdentityKind;
use p11scope_discover::manifest::*;
use std::path::Path;

const SOFTHSM: &str = "/usr/lib/softhsm/libsofthsm2.so";

#[test]
fn softhsm2_legacy_table_fully_resolved() {
    if !Path::new(SOFTHSM).exists() {
        eprintln!("SKIP: {SOFTHSM} not present");
        return;
    }
    let m = discover(Path::new(SOFTHSM)).unwrap();
    assert_eq!(m.schema, SCHEMA);

    // Legacy surface: 68/68, names exactly FUNCTION_LIST_FIELDS, in order.
    let legacy = &m.surfaces[0];
    assert!(matches!(legacy.source, SurfaceSource::LegacyFunctionList));
    assert!(matches!(legacy.acquisition, Acquisition::Ok));
    assert!(matches!(legacy.walk, WalkOutcome::Full));
    let expected: Vec<&str> = pkcs11_module::FUNCTION_LIST_FIELDS.iter().map(|f| f.name).collect();
    let got: Vec<&str> = legacy.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(got, expected);
    assert_eq!(legacy.functions.len(), 68);

    // Every entry resolves into a softhsm object file.
    for f in &legacy.functions {
        match f.resolution {
            Resolution::Resolved { object, .. } => {
                assert!(m.objects[object as usize].path.contains("softhsm"), "{}", f.name);
            }
            ref other => panic!("{} did not resolve: {other:?}", f.name),
        }
    }

    // SoftHSM2 2.6 is 2.40-only: no C_GetInterfaceList export.
    assert!(matches!(m.interface_list, Acquisition::Absent));
    assert!(m.surfaces.len() == 1);
    assert!(m.vendor_interfaces.is_empty());

    // Distro .so carries a GNU build-id.
    assert_eq!(m.objects[0].identity.kind, IdentityKind::GnuBuildId);
    assert!(m.objects[0].identity.reusable);
}
```

Add `pkcs11-module` is already a dependency, so the test's `pkcs11_module::` use resolves.
Run: `cargo test -p p11scope-discover --test softhsm` — expected: compile error, module `discover` missing.

- [ ] **Step 5: Implement the glue**

`crates/discover/src/discover.rs`:

```rust
//! dlopen + table-walk glue: pkcs11-module facts → manifest records.
//! This module runs vendor code (dlopen constructors) — the reason the
//! helper is a separate unprivileged short-lived process. It never calls
//! C_Initialize and never calls C_GetInterface.

use crate::identity;
use crate::manifest::*;
use crate::maps;
use libloading::Library;
use pkcs11_module::{FnField, Surface, TableSet, function_list, interface_list, read_fn_pointers, tables_for};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn discover(module_path: &Path) -> Result<Manifest, String> {
    let lib = unsafe { Library::new(module_path) }
        .map_err(|e| format!("cannot dlopen {}: {e}", module_path.display()))?;
    // Maps are read AFTER dlopen so the module's segments are present.
    let maps_text = std::fs::read_to_string("/proc/self/maps")
        .map_err(|e| format!("/proc/self/maps: {e}"))?;
    let maps = maps::parse_maps(&maps_text);

    let mut objects = ObjectTable::default();
    let legacy = legacy_surface(&lib, &maps, &mut objects);
    let (interface_list_acq, iface_surfaces, vendor_interfaces) =
        interface_records(&lib, &maps, &mut objects);

    let mut surfaces = vec![legacy];
    surfaces.extend(iface_surfaces);
    let alias_groups = alias_groups(&surfaces);

    Ok(Manifest {
        schema: SCHEMA.to_string(),
        module_path: module_path.display().to_string(),
        objects: objects.into_records(),
        interface_list: interface_list_acq,
        surfaces,
        vendor_interfaces,
        alias_groups,
    })
}

/// Dense object ids in first-seen order; identity computed once per object.
#[derive(Default)]
struct ObjectTable {
    ids: BTreeMap<PathBuf, u32>,
}

impl ObjectTable {
    fn id(&mut self, path: PathBuf) -> u32 {
        let next = self.ids.len() as u32;
        *self.ids.entry(path).or_insert(next)
    }

    fn into_records(self) -> Vec<ObjectRecord> {
        let mut v: Vec<ObjectRecord> = self
            .ids
            .into_iter()
            .map(|(path, id)| ObjectRecord {
                id,
                identity: identity::identify(&path),
                path: path.display().to_string(),
            })
            .collect();
        v.sort_by_key(|o| o.id);
        v
    }
}

fn legacy_surface(lib: &Library, maps: &[maps::MapEntry], objects: &mut ObjectTable) -> SurfaceRecord {
    // Distinguish "not exported" from "exported but failed".
    let exported = unsafe { lib.get::<unsafe extern "C" fn()>(b"C_GetFunctionList\0") }.is_ok();
    let source = SurfaceSource::LegacyFunctionList;
    if !exported {
        return SurfaceRecord {
            source,
            acquisition: Acquisition::Absent,
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        };
    }
    match function_list(lib) {
        Err(detail) => SurfaceRecord {
            source,
            acquisition: Acquisition::Error { detail },
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        },
        Ok(list) => {
            // Leading CK_VERSION is reported as evidence; the walk stays
            // base-size regardless (Surface::LegacyFunctionList contract).
            let v = unsafe { (list as *const cryptoki_sys::CK_VERSION).read_unaligned() };
            let (walk, functions) =
                walk_tables(list as *const u8, tables_for(Surface::LegacyFunctionList), maps, objects);
            SurfaceRecord {
                source,
                acquisition: Acquisition::Ok,
                version: Some(Version { major: v.major, minor: v.minor }),
                walk,
                functions,
            }
        }
    }
}

fn interface_records(
    lib: &Library,
    maps: &[maps::MapEntry],
    objects: &mut ObjectTable,
) -> (Acquisition, Vec<SurfaceRecord>, Vec<VendorInterface>) {
    let raw = match interface_list(lib) {
        Err(detail) => return (Acquisition::Error { detail }, vec![], vec![]),
        Ok(None) => return (Acquisition::Absent, vec![], vec![]),
        Ok(Some(v)) if v.is_empty() => return (Acquisition::Empty, vec![], vec![]),
        Ok(Some(v)) => v,
    };
    let mut surfaces = Vec::new();
    let mut vendor = Vec::new();
    for (index, i) in raw.iter().enumerate() {
        if i.is_standard() {
            let name = i.name.as_deref().expect("is_standard implies a name");
            let source = SurfaceSource::Interface {
                index,
                raw_name_hex: identity::hex(name),
                name_lossy: String::from_utf8_lossy(name).into_owned(),
                flags: i.flags,
            };
            match (i.version, i.func_list.is_null()) {
                (Some(v), false) => {
                    let (walk, functions) = walk_tables(
                        i.func_list as *const u8,
                        tables_for(Surface::StandardInterface { version: v }),
                        maps,
                        objects,
                    );
                    surfaces.push(SurfaceRecord {
                        source,
                        acquisition: Acquisition::Ok,
                        version: Some(Version { major: v.major, minor: v.minor }),
                        walk,
                        functions,
                    });
                }
                // NULL function list: recorded, never dereferenced.
                _ => surfaces.push(SurfaceRecord {
                    source,
                    acquisition: Acquisition::Ok,
                    version: None,
                    walk: WalkOutcome::NotWalked,
                    functions: vec![],
                }),
            }
        } else {
            vendor.push(VendorInterface {
                index,
                raw_name_hex: i.name.as_deref().map(identity::hex),
                name_lossy: i.name.as_deref().map(|b| String::from_utf8_lossy(b).into_owned()),
                version: i.version.map(|v| Version { major: v.major, minor: v.minor }),
                flags: i.flags,
                func_list_null: i.func_list.is_null(),
            });
        }
    }
    (Acquisition::Ok, surfaces, vendor)
}

fn walk_tables(
    base: *const u8,
    set: TableSet,
    maps: &[maps::MapEntry],
    objects: &mut ObjectTable,
) -> (WalkOutcome, Vec<FunctionRecord>) {
    let (outcome, tables): (WalkOutcome, &[&[FnField]]) = match set {
        TableSet::Walk(t) => (WalkOutcome::Full, t),
        TableSet::WalkKnownPrefix(t) => (WalkOutcome::KnownPrefix, t),
        TableSet::Refuse => return (WalkOutcome::Refused, vec![]),
    };
    let mut out = Vec::new();
    for table in tables {
        // SAFETY: base points at a live function-list struct the provider
        // returned for this surface; tables_for chose the matching layout.
        for (name, value) in unsafe { read_fn_pointers(base, table) } {
            let resolution = if value == 0 {
                Resolution::NullPointer
            } else {
                match maps::resolve(maps, value as u64) {
                    maps::Resolved::File { path, file_offset } => {
                        Resolution::Resolved { object: objects.id(path), file_offset }
                    }
                    maps::Resolved::Anonymous => Resolution::NonFileBacked,
                    maps::Resolved::Unmapped => Resolution::Unmapped,
                }
            };
            out.push(FunctionRecord { name: name.to_string(), resolution });
        }
    }
    (outcome, out)
}

/// Alias = one {object, file_offset} claimed by ≥2 DISTINCT names. Same
/// name from two surfaces is corroboration, not ambiguity — but once a
/// group qualifies, every entry is listed.
fn alias_groups(surfaces: &[SurfaceRecord]) -> Vec<AliasGroup> {
    let mut by_target: BTreeMap<(u32, u64), Vec<AliasEntry>> = BTreeMap::new();
    for (si, s) in surfaces.iter().enumerate() {
        for f in &s.functions {
            if let Resolution::Resolved { object, file_offset } = f.resolution {
                by_target
                    .entry((object, file_offset))
                    .or_default()
                    .push(AliasEntry { surface: si, name: f.name.clone() });
            }
        }
    }
    by_target
        .into_iter()
        .filter(|(_, entries)| {
            let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            names.sort_unstable();
            names.dedup();
            names.len() >= 2
        })
        .map(|((object, file_offset), entries)| AliasGroup { object, file_offset, entries })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface_with(functions: Vec<FunctionRecord>) -> SurfaceRecord {
        SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: None,
            walk: WalkOutcome::Full,
            functions,
        }
    }

    fn resolved(name: &str, off: u64) -> FunctionRecord {
        FunctionRecord {
            name: name.into(),
            resolution: Resolution::Resolved { object: 0, file_offset: off },
        }
    }

    #[test]
    fn alias_groups_require_two_distinct_names() {
        // Same name on two surfaces at one target: corroboration, no group.
        let s = vec![
            surface_with(vec![resolved("C_Sign", 0x10)]),
            surface_with(vec![resolved("C_Sign", 0x10)]),
        ];
        assert!(alias_groups(&s).is_empty());

        // Two names, one target: a group, listing all entries.
        let s = vec![surface_with(vec![
            resolved("C_GetFunctionStatus", 0x20),
            resolved("C_CancelFunction", 0x20),
        ])];
        let g = alias_groups(&s);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].entries.len(), 2);
    }
}
```

Add `pub mod discover;` to `lib.rs`.

- [ ] **Step 6: Run all tests**

Run: `cargo test -p p11scope-discover`
Expected: all pass, including `softhsm2_legacy_table_fully_resolved` (not skipped — the .so is present on this machine).

- [ ] **Step 7: Commit**

```bash
git add crates/discover Cargo.lock
git commit -m "discover: dlopen + table walk on pkcs11-module (pinned git dep); SoftHSM2 68/68"
```

---

### Task 6: Controlled fixture provider (3.x / vendor / NULL / alias / cross-object)

**Files:**
- Create: `crates/discover/tests/fixture/helper.c`
- Create: `crates/discover/tests/fixture/provider.c`
- Create: `crates/discover/tests/fixture_provider.rs`

**Interfaces:**
- Consumes: `discover::discover`, `manifest::*` (Tasks 4–5).
- Produces: nothing for later tasks — this is the coverage SoftHSM2 (2.40-only) cannot give.

- [ ] **Step 1: Write the fixture sources**

`crates/discover/tests/fixture/helper.c`:

```c
/* Second object file: the cross-object resolution target. */
typedef unsigned long CK_RV;
CK_RV helper_fn(void) { return 0UL; }
```

`crates/discover/tests/fixture/provider.c`:

```c
/* Controlled PKCS#11 provider fixture. Exercises what SoftHSM2 (2.40-only)
 * cannot: a 3.0 interface, a vendor interface, a "PKCS 11" interface with a
 * NULL function list, a NULL table entry, a cross-surface alias, and a
 * pointer into another object (helper.so).
 *
 * Struct layout matches cryptoki-sys on linux-x86-64 (natural alignment):
 * CK_VERSION{2 x uchar} + 6 bytes padding, then 8-byte function pointers.
 */
typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL
#define NBASE 68
#define N30 (68 + 24)

CK_RV helper_fn(void); /* lives in helper.so */

/* 92 distinct stubs s00..s91 — distinct so nothing aliases by accident. */
#define S(n) static CK_RV s##n(void) { return CKR_OK; }
#define S10(m) S(m##0) S(m##1) S(m##2) S(m##3) S(m##4) S(m##5) S(m##6) S(m##7) S(m##8) S(m##9)
S10(0) S10(1) S10(2) S10(3) S10(4) S10(5) S10(6) S10(7) S10(8) S(90) S(91)
#define L10(m) s##m##0, s##m##1, s##m##2, s##m##3, s##m##4, s##m##5, s##m##6, s##m##7, s##m##8, s##m##9

static void *stubs[N30] = { L10(0), L10(1), L10(2), L10(3), L10(4), L10(5), L10(6), L10(7), L10(8), s90, s91 };

static struct { CK_VERSION v; void *f[NBASE]; } legacy;
static struct { CK_VERSION v; void *f[N30]; } v30;

static void fill(void) {
    static int done;
    if (done) return;
    done = 1;
    legacy.v = (CK_VERSION){2, 40};
    for (int i = 0; i < NBASE; i++) legacy.f[i] = stubs[i];
    legacy.f[64] = (void *)helper_fn; /* C_GenerateRandom -> cross-object   */
    legacy.f[65] = 0;                 /* C_GetFunctionStatus -> NULL entry  */
    legacy.f[66] = legacy.f[67];      /* C_CancelFunction aliases C_WaitForSlotEvent */
    v30.v = (CK_VERSION){3, 0};
    /* Same base stubs (same names, same targets — corroboration, not an
     * alias) plus 24 distinct 3.0 entries. */
    for (int i = 0; i < N30; i++) v30.f[i] = stubs[i];
}

CK_RV C_GetFunctionList(void **pp) {
    fill();
    *pp = &legacy;
    return CKR_OK;
}

static char name_std[] = "PKCS 11";
static char name_vendor[] = "Vendor NetHSM-Ext";
static unsigned char vendor_blob[64]; /* opaque vendor "table": never walked */

CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    fill();
    if (!count) return CKR_ARGUMENTS_BAD;
    if (!out) { *count = 3; return CKR_OK; }
    if (*count < 3) { *count = 3; return CKR_BUFFER_TOO_SMALL; }
    out[0] = (CK_INTERFACE){ name_std, &v30, 0 };
    out[1] = (CK_INTERFACE){ name_vendor, vendor_blob, 0 };
    out[2] = (CK_INTERFACE){ name_std, 0, 0 };
    *count = 3;
    return CKR_OK;
}
```

- [ ] **Step 2: Write the failing test**

`crates/discover/tests/fixture_provider.rs`:

```rust
use p11scope_discover::discover::discover;
use p11scope_discover::manifest::*;
use std::path::{Path, PathBuf};
use std::process::Command;

fn build_fixture() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fixture");
    std::fs::create_dir_all(&dir).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let helper = dir.join("helper.so");
    let provider = dir.join("provider.so");
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-Wl,-soname,helper.so", "-o"])
        .arg(&helper)
        .arg(src.join("helper.c"))
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc helper.so failed");
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&provider)
        .arg(src.join("provider.c"))
        .arg(&helper)
        .arg(format!("-Wl,-rpath,{}", dir.display()))
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc provider.so failed");
    provider
}

fn resolution<'a>(s: &'a SurfaceRecord, name: &str) -> &'a Resolution {
    &s.functions.iter().find(|f| f.name == name).unwrap().resolution
}

#[test]
fn fixture_covers_3x_vendor_null_alias_cross_object() {
    let provider = build_fixture();
    let m = discover(&provider).unwrap();

    // Legacy surface walked in full; NULL entry preserved as evidence.
    let legacy = &m.surfaces[0];
    assert!(matches!(legacy.walk, WalkOutcome::Full));
    assert_eq!(legacy.functions.len(), 68);
    assert!(matches!(resolution(legacy, "C_GetFunctionStatus"), Resolution::NullPointer));

    // Cross-object: C_GenerateRandom resolves into helper.so, which gets
    // its own object record with its own identity.
    let Resolution::Resolved { object: helper_obj, .. } = *resolution(legacy, "C_GenerateRandom")
    else { panic!("C_GenerateRandom did not resolve") };
    let Resolution::Resolved { object: main_obj, .. } = *resolution(legacy, "C_Initialize")
    else { panic!("C_Initialize did not resolve") };
    assert_ne!(helper_obj, main_obj);
    assert!(m.objects[helper_obj as usize].path.ends_with("helper.so"));
    assert!(m.objects[helper_obj as usize].identity.reusable);

    // Interface enumeration succeeded; the standard 3.0 surface is walked
    // in full: 68 base + 24 extra entries.
    assert!(matches!(m.interface_list, Acquisition::Ok));
    let std30 = m
        .surfaces
        .iter()
        .find(|s| s.version == Some(Version { major: 3, minor: 0 }))
        .expect("3.0 standard surface");
    assert!(matches!(std30.walk, WalkOutcome::Full));
    assert_eq!(std30.functions.len(), 92);

    // "PKCS 11" with a NULL function list: recorded, never walked.
    let nullfl = m
        .surfaces
        .iter()
        .find(|s| matches!(s.source, SurfaceSource::Interface { index: 2, .. }))
        .expect("NULL-func-list surface");
    assert!(matches!(nullfl.walk, WalkOutcome::NotWalked));
    assert!(nullfl.functions.is_empty());

    // Vendor interface: present-but-undecoded, lossless name.
    assert_eq!(m.vendor_interfaces.len(), 1);
    assert_eq!(m.vendor_interfaces[0].name_lossy.as_deref(), Some("Vendor NetHSM-Ext"));
    assert!(!m.vendor_interfaces[0].func_list_null);

    // Alias: C_CancelFunction and C_WaitForSlotEvent share one target.
    let g = m
        .alias_groups
        .iter()
        .find(|g| g.entries.iter().any(|e| e.name == "C_CancelFunction"))
        .expect("alias group");
    assert!(g.entries.iter().any(|e| e.name == "C_WaitForSlotEvent"));
}
```

- [ ] **Step 3: Run — expect assertion failures or missing files first, then green**

Run: `cargo test -p p11scope-discover --test fixture_provider`
First run must fail only if the implementation has a real bug — the glue exists since Task 5. Investigate any failure; do not weaken assertions. Expected end state: PASS.

- [ ] **Step 4: Run the whole suite**

Run: `cargo test -p p11scope-discover` — expected: everything green.

- [ ] **Step 5: Commit**

```bash
git add crates/discover
git commit -m "discover: controlled fixture provider — 3.0 iface, vendor, NULL, alias, cross-object"
```

---

### Task 7: CLI binary + end-to-end test

**Files:**
- Modify: `crates/discover/src/main.rs`
- Create: `crates/discover/tests/cli.rs`

**Interfaces:**
- Consumes: `discover::discover`, `manifest::Manifest`.
- Produces: the `p11scope-discover` binary contract — `--module <path>` required, `-o <file>` optional (default: manifest JSON on stdout), exit 0 ok / 1 discovery failure / 2 usage. Task 8 and Phase 1b (`p11scope discover` subcommand exec) rely on exactly this.

- [ ] **Step 1: Write the failing CLI tests**

`crates/discover/tests/cli.rs`:

```rust
use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_p11scope-discover");
const SOFTHSM: &str = "/usr/lib/softhsm/libsofthsm2.so";

#[test]
fn manifest_json_on_stdout() {
    if !Path::new(SOFTHSM).exists() {
        eprintln!("SKIP: {SOFTHSM} not present");
        return;
    }
    let out = Command::new(BIN).args(["--module", SOFTHSM]).output().unwrap();
    assert!(out.status.success());
    let m: p11scope_discover::manifest::Manifest = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(m.schema, "p11scope-manifest/1");
    assert_eq!(m.surfaces[0].functions.len(), 68);
}

#[test]
fn missing_module_is_usage_error() {
    let out = Command::new(BIN).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}

#[test]
fn undlopenable_module_fails_loudly() {
    let out = Command::new(BIN).args(["--module", "/dev/null"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot dlopen"));
}
```

Run: `cargo test -p p11scope-discover --test cli` — expected: FAIL (stub main exits 1 for everything).

- [ ] **Step 2: Implement main**

`crates/discover/src/main.rs`:

```rust
//! p11scope-discover — unprivileged short-lived discovery helper.
//! Design: v1 behavior when discovery fails is report-and-exit-nonzero;
//! never silently proceed (design spec, Architecture).

use std::path::PathBuf;

const USAGE: &str = "usage: p11scope-discover --module <provider.so> [-o manifest.json]";

fn main() {
    let mut module: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--module" => module = args.next().map(PathBuf::from),
            "-o" => out = args.next().map(PathBuf::from),
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    let Some(module) = module else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };
    match p11scope_discover::discover::discover(&module) {
        Err(e) => {
            eprintln!("p11scope-discover: {e}");
            std::process::exit(1);
        }
        Ok(m) => {
            let json = serde_json::to_string_pretty(&m).expect("manifest serializes");
            match out {
                None => println!("{json}"),
                Some(p) => {
                    if let Err(e) = std::fs::write(&p, json) {
                        eprintln!("p11scope-discover: write {}: {e}", p.display());
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p p11scope-discover` — expected: everything green.
Sanity check by hand: `cargo run -p p11scope-discover -- --module /usr/lib/softhsm/libsofthsm2.so | head -30` — JSON starts with `"schema": "p11scope-manifest/1"`.

- [ ] **Step 4: Commit**

```bash
git add crates/discover
git commit -m "discover: CLI — manifest JSON to stdout/-o, loud failures"
```

---

### Task 8: Container verification — ubuntu (glibc) + alpine (musl *dynamic*)

**Files:**
- Create: `scripts/verify-discover-containers.sh`

**Interfaces:**
- Consumes: the Task 7 binary contract.
- Produces: the Gate G1 evidence "helper verified in ubuntu (glibc) and alpine (musl) containers". Note: `rustup target add x86_64-unknown-linux-musl` is NOT sufficient — that target defaults to `+crt-static` and a static helper cannot dlopen sanely; we build natively in Alpine with crt-static disabled (review finding, 2026-08-11).

- [ ] **Step 1: Write the script**

`scripts/verify-discover-containers.sh` (mark executable):

```sh
#!/bin/sh -eu
# Gate G1: p11scope-discover runs against SoftHSM2 in ubuntu (glibc) and
# alpine (musl), and both builds are DYNAMIC (a static helper cannot
# dlopen providers sanely). The glibc binary is built in rust:1-bookworm
# (glibc 2.36) so it runs on ubuntu 24.04 (2.39) — the host glibc may be
# newer than the container's, so a host build is not portable.
cd "$(dirname "$0")/.."

docker pull -q ubuntu:24.04
docker pull -q rust:1-bookworm
docker pull -q rust:1-alpine

# Vendored so container builds need no network (sandbox git quirks).
# The vendor config is rewritten with absolute /src paths because it is
# copied into $CARGO_HOME inside the containers.
mkdir -p target/vendor
cargo vendor target/vendor/src > target/vendor/config.toml
sed 's|directory = "|directory = "/src/|' target/vendor/config.toml > target/vendor/config.container.toml

echo "=== glibc: build in rust:1-bookworm, run in ubuntu:24.04 ==="
docker run --rm -v "$PWD:/src" -w /src rust:1-bookworm sh -ec '
  export CARGO_HOME=/tmp/cargo
  mkdir -p /tmp/cargo && cp target/vendor/config.container.toml /tmp/cargo/config.toml
  cargo build --release -p p11scope-discover --offline --target-dir /src/target/glibc-build'
docker run --rm -v "$PWD/target/glibc-build/release/p11scope-discover:/usr/local/bin/p11scope-discover:ro" \
    ubuntu:24.04 sh -ec '
  apt-get update -q >/dev/null && apt-get install -qy softhsm2 >/dev/null
  p11scope-discover --module /usr/lib/softhsm/libsofthsm2.so -o /tmp/m.json
  n=$(grep -c "\"name\": \"C_" /tmp/m.json)
  test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
  echo "ubuntu glibc: 68/68 OK"'

echo "=== musl-dynamic: build + run in rust:1-alpine ==="
docker run --rm -v "$PWD:/src" -w /src rust:1-alpine sh -ec '
  apk add -q musl-dev gcc softhsm file
  export CARGO_HOME=/tmp/cargo
  mkdir -p /tmp/cargo && cp target/vendor/config.container.toml /tmp/cargo/config.toml
  export RUSTFLAGS="-C target-feature=-crt-static"
  cargo build --release -p p11scope-discover --offline --target-dir /tmp/build
  file /tmp/build/release/p11scope-discover | grep -q "dynamically linked" \
      || { echo "helper is NOT dynamic"; exit 1; }
  ldd /tmp/build/release/p11scope-discover
  /tmp/build/release/p11scope-discover --module /usr/lib/softhsm/libsofthsm2.so -o /tmp/m.json
  n=$(grep -c "\"name\": \"C_" /tmp/m.json)
  test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
  echo "alpine musl-dynamic: 68/68 OK"'

echo "=== container verification: ALL OK ==="
```

- [ ] **Step 2: Run it**

Run: `sh scripts/verify-discover-containers.sh`
Expected final line: `=== container verification: ALL OK ===`. The `ldd` output must show `/lib/ld-musl-x86_64.so.1`. If the alpine `softhsm` package installs the module elsewhere, locate it with `apk info -L softhsm` and fix the script's path — do not skip the run.

- [ ] **Step 3: Commit**

```bash
git add scripts/verify-discover-containers.sh
git commit -m "discover: G1 container verification — ubuntu glibc + alpine musl-dynamic"
```

---

### Task 9: Bookkeeping — roadmap split, extraction-plan state

**Files:**
- Modify: `docs/superpowers/plans/ROADMAP.md`
- Modify: `docs/superpowers/plans/2026-08-10-pkcs11-module-extraction.md`

- [ ] **Step 1: Record the Phase 1a/1b split in the roadmap**

In `ROADMAP.md`, at the end of the Phase 1 section's bullet list (before "**Gate G1**"), add:

```markdown
Phase 1 is executed as two plans: **1a** — offset-semantics pin +
`p11scope-discover` ([plan](2026-08-11-phase1a-discover.md)); **1b** — aya
attach engine + `metrics` mode, plan written only after 1a lands (the
plan-after-inputs rule above). Gate G1 closes when both have landed.
The `pkcs11-proxy-ng-types` dependency is deferred until code actually
needs it (review, 2026-08-11) — the helper consumes only `pkcs11-module`.
```

- [ ] **Step 2: Record execution state in the extraction plan**

In `2026-08-10-pkcs11-module-extraction.md`: mark every checkbox in Tasks 1–6 and Task 8 as `[x]` (landed as submodule commits `cb37041..7c5c860`, umbrella `21e0988`, verified 2026-08-11: 18 module + 303 backend + 62 quality-gate tests green). Under Task 7 add, leaving its boxes unchecked:

```markdown
> Task 7 (provider-matrix gate) is owned by the pkcs11-proxy-ng project;
> not tracked in this repo.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/ROADMAP.md docs/superpowers/plans/2026-08-10-pkcs11-module-extraction.md
git commit -m "plan: phase 1 split (1a/1b); record module-extraction execution state"
```
