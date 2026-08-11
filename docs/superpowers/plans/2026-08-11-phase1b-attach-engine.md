# Phase 1b — aya attach engine + `metrics` mode — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `p11scope` a working eBPF observer — attach uprobe+uretprobe pairs at the file offsets Phase 1a discovered, aggregate calls/CK_RV/latency/in-flight in BPF maps under PID/cgroup scope, and report them live and as JSON.

**Architecture:** Three new workspace members plus the existing root binary. `crates/manifest` holds the schema types (extracted from `crates/discover` so the static observer doesn't inherit libloading/cryptoki-sys/object). `crates/ebpf-common` holds `#![no_std]` `repr(C)` map types shared by kernel and userspace. `crates/ebpf` holds two BPF programs — one uprobe, one uretprobe — attached once per unique `{object, file_offset}` with the **attach cookie** carrying the slot index, so 68+ attach points need only two programs. The root `p11scope` binary loads the embedded BPF object, builds the attach plan, applies filters, and renders.

**Tech Stack:** aya `=0.14.0`, aya-ebpf `=0.2.1`, aya-build `0.2`, aya-ebpf-bindings `0.2` (raw helpers), serde/serde_json, nightly + `rust-src` + `bpf-linker` for the BPF target.

## Global Constraints

- Edition 2024, `rust-version = "1.88"`, `license = "MIT OR Apache-2.0"`, `publish = false` for every crate except `crates/ebpf` and `crates/ebpf-common`, which are `edition = "2021"` (BPF target toolchain) and also `publish = false`.
- Kernel floor **5.15** — that is exactly what makes `bpf_get_attach_cookie` (added 5.15) usable; do not design around a lower floor.
- Manifest offsets are **ELF object-file byte offsets**, consumed via `UProbeAttachLocation::AbsoluteOffset` with no translation. This is the fact pinned in `docs/notes/aya-offset-semantics.md`; never re-derive offsets from symbol tables.
- `p11scope` **never dlopens a provider**. Discovery always runs in the separate `p11scope-discover` process. The observer must stay linkable as a fully static musl binary.
- Evidence is never dropped: attach failures, aliased targets, non-file-backed/unmapped/NULL manifest entries, and in-flight calls at capture end all appear in the output. A capture that lost information says so.
- Aliased targets (≥2 distinct names at one `{object, file_offset}`) are **never attributed to one name** — their counts are reported against the whole alias group.
- Latency percentiles from log2 buckets are approximations and must be labeled as such in both renderers. Exact `total_ns`/`max_ns` are also recorded.
- Commit style: short prefix + imperative (`manifest:`, `ebpf:`, `scope:`, `plan:`).
- Do not weaken any Phase 1a test. The full workspace suite stays green at every commit.

## Verified environment facts (2026-08-11)

- Phase 1a merged at `5d78b66`; workspace members: `crates/discover` only. Root `p11scope` is still the stub.
- aya `0.14.0` exposes `UProbeAttachPoint { location: UProbeAttachLocation, cookie: Option<u64> }` and `UProbe::attach(point, target, scope)` with `UProbeScope::{AllProcesses, OneProcess(NonZeroU32), CallingProcess}`.
- aya-ebpf `0.2.1` provides `#[uprobe]`/`#[uretprobe]` macros, `ProbeContext`, `RetProbeContext::ret::<T>()`, and maps `Array`, `HashMap`, `PerCpuArray`, `PerCpuHashMap`.
- `aya_ebpf::helpers::*` re-exports the generated bindings (`pub use aya_ebpf_bindings::helpers as generated; pub use generated::*;`), so `bpf_get_attach_cookie`, `bpf_ktime_get_ns`, `bpf_get_current_pid_tgid`, and `bpf_get_current_cgroup_id` are all reachable from that one path.
- Userspace `aya::maps::PerCpuArray::get(&index, flags) -> PerCpuValues<V>`; sum across CPUs in userspace.
- `aya-build 0.2.0` exposes `build_ebpf([Package { name, root_dir, .. }], Toolchain::…)` for build.rs, honouring `AYA_BUILD_SKIP`.
- Toolchain present: stable 1.94 default, **nightly with rust-src**, `bpf-linker` installed during Phase 1a Task 3. `sudo -n` works. Kernel 7.0.0-28-generic, BTF present.
- `spike/harness.c` is a deterministic PKCS#11 workload calling through the module's own `CK_FUNCTION_LIST`; `spike/expected.txt` is its exact ground truth (9 functions: `C_CloseSession 10`, `C_Digest 50`, `C_DigestInit 50`, `C_Finalize 1`, `C_GenerateRandom 100`, `C_GetInfo 3`, `C_GetSlotList 1`, `C_Initialize 1`, `C_OpenSession 10`). This is the Task 8 oracle.
- SoftHSM2 at `/usr/lib/softhsm/libsofthsm2.so`; `p11scope-discover` resolves all 68 legacy entries against it.

---

### Task 1: Extract `crates/manifest` (shared schema types)

**Files:**
- Create: `crates/manifest/Cargo.toml`, `crates/manifest/src/lib.rs`
- Modify: `Cargo.toml` (workspace members), `crates/discover/Cargo.toml`, `crates/discover/src/lib.rs`, `crates/discover/src/manifest.rs` (deleted), `crates/discover/src/identity.rs` (moved), `crates/discover/src/discover.rs` (imports)

**Interfaces:**
- Produces: crate `p11scope-manifest` exporting **exactly** the types Phase 1a defined, unchanged in name, field, and serde attribute: `SCHEMA`, `Manifest`, `ObjectRecord`, `SurfaceRecord`, `SurfaceSource`, `Acquisition`, `Version`, `WalkOutcome`, `FunctionRecord`, `Resolution`, `VendorInterface`, `AliasGroup`, `AliasEntry`, plus `IdentityKind` and `ObjectIdentity`. Tasks 4–8 and `crates/discover` consume these.

The observer must read manifests without linking libloading/cryptoki-sys/object. `identity` moves too, because `ObjectRecord` embeds `ObjectIdentity`; the *computation* (`identify()`) stays behind a feature so the lean consumer gets types only.

- [ ] **Step 1: Create the crate**

`crates/manifest/Cargo.toml`:

```toml
[package]
name = "p11scope-manifest"
version = "0.0.0"
edition = "2024"
rust-version = "1.88"
license = "MIT OR Apache-2.0"
repository = "https://github.com/mingulov/pkcs11-scope"
description = "Probe-manifest schema shared by p11scope-discover and p11scope"
publish = false

[features]
# Computing identity needs file/ELF access; readers of manifests do not.
identify = ["dep:object", "dep:sha2"]

[dependencies]
serde = { version = "1", features = ["derive"] }
object = { version = "0.39", default-features = false, features = ["read"], optional = true }
sha2 = { version = "0.10", optional = true }
```

- [ ] **Step 2: Move the modules**

```bash
git mv crates/discover/src/manifest.rs crates/manifest/src/manifest.rs
git mv crates/discover/src/identity.rs crates/manifest/src/identity.rs
```

`crates/manifest/src/lib.rs`:

```rust
//! Probe-manifest schema v1 — the contract between `p11scope-discover`
//! (writer) and `p11scope` (reader). Offsets are ELF object-file byte
//! offsets; see docs/notes/aya-offset-semantics.md.

pub mod identity;
pub mod manifest;

pub use identity::{IdentityKind, ObjectIdentity};
pub use manifest::*;
```

In `crates/manifest/src/identity.rs`, gate the computation but never the types:

```rust
#[cfg(feature = "identify")]
pub fn identify(path: &Path) -> ObjectIdentity {
```

…and gate its imports (`use object::Object as _;`, `use sha2::{Digest as _, Sha256};`, `use std::path::Path;`) and the `hex` helper the same way, changing `pub(crate) fn hex` to `pub fn hex` (it is now consumed across the crate boundary by `crates/discover`). Move the four identity integration tests from `crates/discover/tests/identity.rs` to `crates/manifest/tests/identity.rs` unchanged except the import path (`p11scope_manifest::identity::…`), and add `required-features`-style guarding by running them under the feature:

```toml
# crates/manifest/Cargo.toml, appended
[[test]]
name = "identity"
required-features = ["identify"]
```

In `crates/manifest/src/manifest.rs`, change `use crate::identity::ObjectIdentity;` to stay valid (it already is) and keep the round-trip test, adding `serde_json` as a dev-dependency:

```toml
[dev-dependencies]
serde_json = "1"
```

- [ ] **Step 3: Point discover at the new crate**

Root `Cargo.toml`:

```toml
[workspace]
members = ["crates/discover", "crates/manifest"]
```

`crates/discover/Cargo.toml` — drop `object` and `sha2` (they now live behind the manifest crate's feature), add:

```toml
p11scope-manifest = { path = "../manifest", features = ["identify"] }
```

`crates/discover/src/lib.rs`:

```rust
//! p11scope-discover library — split from the bin so tests call discovery
//! directly. Runs vendor code via dlopen; that is why the helper is a
//! separate unprivileged short-lived process.

pub mod discover;
pub mod maps;

pub use p11scope_manifest::{identity, manifest};
```

In `crates/discover/src/discover.rs` replace `use crate::identity;` / `use crate::manifest::*;` with:

```rust
use p11scope_manifest::identity;
use p11scope_manifest::manifest::*;
```

- [ ] **Step 4: Run the whole suite**

Run: `cargo test --workspace`
Expected: every Phase 1a test still passes (maps 3, identity 4, manifest 1, discover unit 1, softhsm 1, fixture 1, cli 6 = 17), zero warnings. The move must change no behavior.

- [ ] **Step 5: Verify the lean dependency tree**

Run: `cargo tree -p p11scope-manifest --no-default-features -e normal`
Expected: `serde` only — no `object`, no `sha2`, no `libloading`, no `cryptoki-sys`. This is the property the static observer depends on.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "manifest: extract schema types into p11scope-manifest crate"
```

---

### Task 2: `crates/ebpf-common` — shared kernel/userspace map types

**Files:**
- Create: `crates/ebpf-common/Cargo.toml`, `crates/ebpf-common/src/lib.rs`
- Modify: root `Cargo.toml` (workspace members)

**Interfaces:**
- Produces: `MAX_SLOTS`, `LATENCY_BUCKETS`, `CFG_*` constants; `SlotStats`, `StartKey`, `RvKey`; `bucket_of(ns: u64) -> u32`. Tasks 3–6 consume all of them. Every type is `#[repr(C)]` and POD so the identical bytes are read from both sides.

- [ ] **Step 1: Create the crate**

`crates/ebpf-common/Cargo.toml`:

```toml
[package]
name = "p11scope-ebpf-common"
version = "0.0.0"
edition = "2021"
rust-version = "1.88"
license = "MIT OR Apache-2.0"
publish = false

[features]
# Userspace side needs aya's Pod impls; the kernel side must stay no_std.
user = ["dep:aya"]

[dependencies]
aya = { version = "=0.14.0", optional = true }
```

- [ ] **Step 2: Write the shared types with their unit test**

`crates/ebpf-common/src/lib.rs`:

```rust
//! Types shared verbatim between the BPF programs and userspace. Every
//! type is `#[repr(C)]` with no padding surprises: both sides read the
//! same bytes out of the same map.
#![no_std]

/// Attach slots. One slot per unique {object, file_offset} target, not
/// per function name — aliased names share a slot by construction.
/// 256 covers the 92-entry 3.2 table several times over.
pub const MAX_SLOTS: u32 = 256;

/// Log2 latency buckets: bucket i holds durations in [2^(i-1), 2^i) ns,
/// bucket 0 holds 0ns, bucket 31 is a catch-all for >= 2^30 ns (~1.07s).
pub const LATENCY_BUCKETS: usize = 32;

/// CONFIG map indices.
pub const CFG_FLAGS: u32 = 0;
/// CONFIG flag bits.
pub const FLAG_PID_FILTER: u64 = 1 << 0;
pub const FLAG_CGROUP_FILTER: u64 = 1 << 1;

/// Per-slot aggregates. `entered - returned` is the in-flight count;
/// they are separate counters precisely so a call that never returns is
/// visible rather than silently absent.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SlotStats {
    pub entered: u64,
    pub returned: u64,
    pub errors: u64,
    pub total_ns: u64,
    pub max_ns: u64,
    pub buckets: [u64; LATENCY_BUCKETS],
}

impl SlotStats {
    pub const ZERO: Self = Self {
        entered: 0,
        returned: 0,
        errors: 0,
        total_ns: 0,
        max_ns: 0,
        buckets: [0; LATENCY_BUCKETS],
    };
}

/// Key for the in-flight start-timestamp map. `pid_tgid` is the raw
/// `bpf_get_current_pid_tgid()` value: distinct threads calling the same
/// function concurrently get distinct entries.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StartKey {
    pub pid_tgid: u64,
    pub slot: u32,
    pub _pad: u32,
}

/// Key for the CK_RV distribution map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RvKey {
    pub slot: u32,
    pub rv: u32,
}

/// Bucket index for a duration. Saturates into the last bucket so a
/// pathologically long call is still counted, never dropped.
pub const fn bucket_of(ns: u64) -> u32 {
    if ns == 0 {
        return 0;
    }
    let idx = 64 - ns.leading_zeros();
    if idx as usize >= LATENCY_BUCKETS {
        (LATENCY_BUCKETS - 1) as u32
    } else {
        idx
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SlotStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for StartKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RvKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_monotonic_and_saturating() {
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(1), 1);
        assert_eq!(bucket_of(2), 2);
        assert_eq!(bucket_of(3), 2);
        assert_eq!(bucket_of(4), 3);
        // Monotonic across the whole range.
        let mut prev = 0;
        let mut ns = 1u64;
        while ns < u64::MAX / 2 {
            let b = bucket_of(ns);
            assert!(b >= prev, "bucket went backwards at {ns}");
            prev = b;
            ns *= 2;
        }
        // Saturates, never indexes out of bounds.
        assert_eq!(bucket_of(u64::MAX), (LATENCY_BUCKETS - 1) as u32);
        assert!((bucket_of(u64::MAX) as usize) < LATENCY_BUCKETS);
    }
}
```

Note the `#![no_std]` + `#[cfg(test)]` combination: run the unit test with the `user` feature so `std` is available to the harness via the dev profile — if the test fails to build under `no_std`, add `extern crate std;` under `#[cfg(test)]` rather than dropping `no_std`.

- [ ] **Step 3: Register and test**

Root `Cargo.toml` members become `["crates/discover", "crates/manifest", "crates/ebpf-common"]`.

Run: `cargo test -p p11scope-ebpf-common --features user`
Expected: 1 passed.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "ebpf-common: shared repr(C) map types for kernel and userspace"
```

---

### Task 3: `crates/ebpf` — the uprobe/uretprobe programs

**Files:**
- Create: `crates/ebpf/Cargo.toml`, `crates/ebpf/src/main.rs`, `crates/ebpf/rust-toolchain.toml`
- Modify: `.gitignore`

**Interfaces:**
- Produces: a BPF object exporting programs named exactly `p11_entry` (uprobe) and `p11_return` (uretprobe), and maps named exactly `CONFIG`, `PID_FILTER`, `CGROUP_FILTER`, `STATS`, `START`, `RV_COUNTS`. Task 4 loads them by these names — any rename breaks it.

This crate is **not** a workspace member (its target triple and toolchain differ); it carries its own `[workspace]` table, exactly like `spike/aya-offset-pin/pin-ebpf`.

- [ ] **Step 1: Create the crate manifest**

`crates/ebpf/Cargo.toml`:

```toml
[package]
name = "p11scope-ebpf"
version = "0.0.0"
edition = "2021"
license = "MIT OR Apache-2.0"
publish = false

[dependencies]
aya-ebpf = "=0.2.1"
p11scope-ebpf-common = { path = "../ebpf-common" }

[[bin]]
name = "p11scope-ebpf"
path = "src/main.rs"

[profile.release]
panic = "abort"
lto = true
codegen-units = 1

[workspace]
```

`crates/ebpf/rust-toolchain.toml`:

```toml
[toolchain]
channel = "nightly"
components = ["rust-src"]
```

- [ ] **Step 2: Write the programs**

`crates/ebpf/src/main.rs`:

```rust
//! p11scope BPF programs. Two programs serve every attach point: the
//! attach cookie carries the slot index, so 68+ probes need two programs
//! rather than 68 copies. Cookies need kernel >= 5.15, which is the
//! project's floor.
#![no_std]
#![no_main]

use aya_ebpf::macros::{map, uprobe, uretprobe};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, PerCpuHashMap};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf::{EbpfContext as _, helpers};
use p11scope_ebpf_common::{
    CFG_FLAGS, FLAG_CGROUP_FILTER, FLAG_PID_FILTER, MAX_SLOTS, RvKey, SlotStats, StartKey,
    bucket_of,
};

#[map]
static CONFIG: Array<u64> = Array::with_max_entries(4, 0);

#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static CGROUP_FILTER: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static STATS: PerCpuArray<SlotStats> = PerCpuArray::with_max_entries(MAX_SLOTS, 0);

#[map]
static START: HashMap<StartKey, u64> = HashMap::with_max_entries(16384, 0);

#[map]
static RV_COUNTS: PerCpuHashMap<RvKey, u64> = PerCpuHashMap::with_max_entries(4096, 0);

/// Does this call belong to the capture scope? With no filter configured
/// nothing is observed — scope is always explicit (design spec: no
/// magical system-wide capture).
fn in_scope(ctx: &ProbeContext) -> bool {
    let flags = CONFIG.get(CFG_FLAGS).copied().unwrap_or(0);
    if flags & FLAG_PID_FILTER != 0 {
        let tgid = (ctx.pid()) as u32;
        if unsafe { PID_FILTER.get(&tgid) }.is_some() {
            return true;
        }
    }
    if flags & FLAG_CGROUP_FILTER != 0 {
        let cgid = unsafe { helpers::bpf_get_current_cgroup_id() };
        if unsafe { CGROUP_FILTER.get(&cgid) }.is_some() {
            return true;
        }
    }
    false
}

fn slot_of<C>(ctx: &C) -> u32
where
    C: aya_ebpf::EbpfContext,
{
    (unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) }) as u32
}

#[uprobe]
pub fn p11_entry(ctx: ProbeContext) -> u32 {
    let slot = slot_of(&ctx);
    if slot >= MAX_SLOTS || !in_scope(&ctx) {
        return 0;
    }
    if let Some(stats) = STATS.get_ptr_mut(slot) {
        // SAFETY: PerCpuArray gives this CPU exclusive access to its own
        // copy; there is no cross-CPU aliasing to race with.
        unsafe { (*stats).entered += 1 };
    }
    let key = StartKey { pid_tgid: helpers::bpf_get_current_pid_tgid(), slot, _pad: 0 };
    let now = unsafe { helpers::bpf_ktime_get_ns() };
    // A re-entrant call overwrites its own start: the outer call then
    // measures short. Recorded rather than dropped; PKCS#11 entry points
    // are not re-entrant in practice.
    let _ = START.insert(&key, &now, 0);
    0
}

#[uretprobe]
pub fn p11_return(ctx: RetProbeContext) -> u32 {
    let slot = slot_of(&ctx);
    if slot >= MAX_SLOTS {
        return 0;
    }
    let key = StartKey { pid_tgid: helpers::bpf_get_current_pid_tgid(), slot, _pad: 0 };
    // No start entry means the entry probe filtered this call out (or the
    // process was already inside the function at attach time). Either way
    // there is nothing to attribute.
    let Some(&start) = (unsafe { START.get(&key) }) else {
        return 0;
    };
    let _ = START.remove(&key);

    let now = unsafe { helpers::bpf_ktime_get_ns() };
    let delta = now.saturating_sub(start);
    let rv: u64 = ctx.ret().unwrap_or(0);

    if let Some(stats) = STATS.get_ptr_mut(slot) {
        // SAFETY: as in p11_entry — per-CPU storage, no aliasing.
        unsafe {
            (*stats).returned += 1;
            (*stats).total_ns += delta;
            if delta > (*stats).max_ns {
                (*stats).max_ns = delta;
            }
            let b = bucket_of(delta) as usize;
            if b < (*stats).buckets.len() {
                (*stats).buckets[b] += 1;
            }
            if rv != 0 {
                (*stats).errors += 1;
            }
        }
    }

    let rk = RvKey { slot, rv: rv as u32 };
    let prev = unsafe { RV_COUNTS.get(&rk) }.copied().unwrap_or(0);
    let _ = RV_COUNTS.insert(&rk, &(prev + 1), 0);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

If `ctx.pid()` is not the thread-group id on this aya version, derive it explicitly instead: `let tgid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;`. Prefer whichever compiles; the value must be the **tgid** (what userspace calls the PID), not the thread id.

- [ ] **Step 3: Ignore build artifacts**

Append to `.gitignore`:

```
crates/ebpf/target/
```

- [ ] **Step 4: Build it**

Run:

```bash
cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core \
    --manifest-path crates/ebpf/Cargo.toml
```

Expected: builds clean. Then confirm the object carries the expected symbols:

```bash
llvm-objdump -h crates/ebpf/target/bpfel-unknown-none/release/p11scope-ebpf | grep -E 'uprobe|uretprobe|maps'
```

Expected: sections for both programs and the maps. If the build fails on an API mismatch, fix the call against the vendored source at `~/.cargo/registry/src/*/aya-ebpf-0.2.1/` and note the deviation — do not change what is measured.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "ebpf: uprobe/uretprobe programs with cookie-carried slot index"
```

---

### Task 4: Attach engine — manifest → attach plan → live probes

**Files:**
- Modify: root `Cargo.toml` (dependencies, build-dependencies)
- Create: `build.rs`
- Create: `src/plan.rs`, `src/attach.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `p11scope_manifest::*` (Task 1), `p11scope_ebpf_common::*` (Task 2), the BPF object's program/map names (Task 3).
- Produces: `plan::AttachPlan`, `plan::Slot { index: u32, object: String, file_offset: u64, names: Vec<String>, aliased: bool }`, `plan::Skipped { name: String, reason: String }`, `plan::build(&Manifest) -> AttachPlan`; `attach::Session::start(plan, scope) -> Result<Session>` and `Session::attach_failures() -> &[(u32, String)]`. Tasks 5–8 consume these.

- [ ] **Step 1: Wire the build**

Root `Cargo.toml`:

```toml
[dependencies]
anyhow = "1"
aya = "=0.14.0"
p11scope-ebpf-common = { path = "crates/ebpf-common", features = ["user"] }
p11scope-manifest = { path = "crates/manifest" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[build-dependencies]
aya-build = "0.2"
```

`build.rs`:

```rust
//! Builds the BPF object with the nightly toolchain and hands cargo the
//! path via OUT_DIR, so `p11scope` ships one self-contained binary.
//! Set AYA_BUILD_SKIP=1 to skip (e.g. doc-only builds).
fn main() -> aya_build::Result<()> {
    aya_build::build_ebpf(
        [aya_build::Package { name: "p11scope-ebpf", root_dir: "crates/ebpf", ..Default::default() }],
        aya_build::Toolchain::default(),
    )
}
```

Consult `~/.cargo/registry/src/*/aya-build-0.2.0/src/lib.rs` for the exact `Toolchain` constructor and whether `build_ebpf` writes to `OUT_DIR` — adapt the call and the `include_bytes_aligned!` path in Step 3 to match what that source actually does, and record the resolved shape in your report.

- [ ] **Step 2: Write the plan builder with its tests**

`src/plan.rs`:

```rust
//! Manifest → attach plan. One slot per unique {object, file_offset};
//! everything the manifest could not resolve becomes a Skipped entry so
//! the capture's evidence section can report it.

use p11scope_manifest::manifest::{Manifest, Resolution};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    pub index: u32,
    pub object: String,
    pub file_offset: u64,
    /// Every distinct function name resolving here, sorted.
    pub names: Vec<String>,
    /// True when >= 2 distinct names share this target: counts belong to
    /// the group, never to one name.
    pub aliased: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttachPlan {
    pub slots: Vec<Slot>,
    pub skipped: Vec<Skipped>,
    /// Total function records seen across every walked surface.
    pub entries_seen: usize,
}

pub fn build(m: &Manifest) -> AttachPlan {
    let mut by_target: BTreeMap<(String, u64), Vec<String>> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut entries_seen = 0usize;

    for surface in &m.surfaces {
        for f in &surface.functions {
            entries_seen += 1;
            match &f.resolution {
                Resolution::Resolved { object, file_offset } => {
                    let path = m
                        .objects
                        .iter()
                        .find(|o| o.id == *object)
                        .map(|o| o.path.clone())
                        .unwrap_or_default();
                    if path.is_empty() {
                        skipped.push(Skipped {
                            name: f.name.clone(),
                            reason: format!("object id {object} missing from manifest"),
                        });
                        continue;
                    }
                    by_target.entry((path, *file_offset)).or_default().push(f.name.clone());
                }
                Resolution::NullPointer => skipped
                    .push(Skipped { name: f.name.clone(), reason: "null pointer".into() }),
                Resolution::NonFileBacked => skipped
                    .push(Skipped { name: f.name.clone(), reason: "non-file-backed".into() }),
                Resolution::Unmapped => {
                    skipped.push(Skipped { name: f.name.clone(), reason: "unmapped".into() })
                }
            }
        }
    }

    let slots = by_target
        .into_iter()
        .enumerate()
        .map(|(i, ((object, file_offset), mut names))| {
            names.sort();
            names.dedup();
            Slot {
                index: i as u32,
                object,
                file_offset,
                aliased: names.len() >= 2,
                names,
            }
        })
        .collect();

    AttachPlan { slots, skipped, entries_seen }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
    use p11scope_manifest::manifest::*;

    fn manifest_with(functions: Vec<FunctionRecord>) -> Manifest {
        Manifest {
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
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: None,
                walk: WalkOutcome::Full,
                functions,
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
        }
    }

    fn rec(name: &str, r: Resolution) -> FunctionRecord {
        FunctionRecord { name: name.into(), resolution: r }
    }

    #[test]
    fn one_slot_per_unique_target_and_aliases_flagged() {
        let m = manifest_with(vec![
            rec("C_Sign", Resolution::Resolved { object: 0, file_offset: 0x10 }),
            rec("C_Verify", Resolution::Resolved { object: 0, file_offset: 0x20 }),
            rec("C_CancelFunction", Resolution::Resolved { object: 0, file_offset: 0x30 }),
            rec("C_WaitForSlotEvent", Resolution::Resolved { object: 0, file_offset: 0x30 }),
        ]);
        let p = build(&m);
        assert_eq!(p.slots.len(), 3, "aliased pair collapses to one slot");
        assert_eq!(p.entries_seen, 4);
        let aliased: Vec<&Slot> = p.slots.iter().filter(|s| s.aliased).collect();
        assert_eq!(aliased.len(), 1);
        assert_eq!(aliased[0].names, vec!["C_CancelFunction", "C_WaitForSlotEvent"]);
        // Slot indices are dense and start at zero.
        let idx: Vec<u32> = p.slots.iter().map(|s| s.index).collect();
        assert_eq!(idx, vec![0, 1, 2]);
    }

    #[test]
    fn unresolvable_entries_become_skipped_evidence() {
        let m = manifest_with(vec![
            rec("C_Sign", Resolution::Resolved { object: 0, file_offset: 0x10 }),
            rec("C_GetFunctionStatus", Resolution::NullPointer),
            rec("C_Weird", Resolution::NonFileBacked),
            rec("C_Gone", Resolution::Unmapped),
        ]);
        let p = build(&m);
        assert_eq!(p.slots.len(), 1);
        assert_eq!(p.skipped.len(), 3);
        assert_eq!(p.entries_seen, 4);
        let reasons: Vec<&str> = p.skipped.iter().map(|s| s.reason.as_str()).collect();
        assert!(reasons.contains(&"null pointer"));
        assert!(reasons.contains(&"non-file-backed"));
        assert!(reasons.contains(&"unmapped"));
    }
}
```

- [ ] **Step 3: Write the attach session**

`src/attach.rs`:

```rust
//! Loading and attaching. One uprobe + one uretprobe program serve every
//! slot; the attach cookie carries the slot index.

use crate::plan::AttachPlan;
use anyhow::{Context as _, Result};
use aya::Ebpf;
use aya::programs::UProbe;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};

/// Which processes the capture covers. Scope is always explicit.
#[derive(Debug, Clone)]
pub enum Scope {
    Pid(u32),
    Cgroup(u64),
}

pub struct Session {
    pub ebpf: Ebpf,
    attach_failures: Vec<(u32, String)>,
    attached: usize,
}

impl Session {
    pub fn start(plan: &AttachPlan, scope: &Scope) -> Result<Self> {
        let mut ebpf = Ebpf::load(crate::EBPF_OBJECT).context("loading BPF object")?;
        let uprobe_scope = match scope {
            Scope::Pid(pid) => UProbeScope::OneProcess(
                std::num::NonZeroU32::new(*pid).context("pid must be non-zero")?,
            ),
            // Cgroup scoping is enforced in BPF, so the probe itself is
            // process-wide and the filter map decides.
            Scope::Cgroup(_) => UProbeScope::AllProcesses,
        };

        let mut attach_failures = Vec::new();
        let mut attached = 0usize;

        for prog_name in ["p11_entry", "p11_return"] {
            let prog: &mut UProbe = ebpf
                .program_mut(prog_name)
                .with_context(|| format!("program {prog_name} missing from object"))?
                .try_into()?;
            prog.load().with_context(|| format!("loading {prog_name}"))?;
            for slot in &plan.slots {
                let point = UProbeAttachPoint {
                    location: UProbeAttachLocation::AbsoluteOffset(slot.file_offset),
                    cookie: Some(slot.index as u64),
                };
                match prog.attach(point, &slot.object, uprobe_scope) {
                    Ok(_) => attached += 1,
                    Err(e) => attach_failures.push((
                        slot.index,
                        format!("{prog_name} at {}+{:#x}: {e}", slot.object, slot.file_offset),
                    )),
                }
            }
        }

        Ok(Self { ebpf, attach_failures, attached })
    }

    /// Attach points that failed — reported as an evidence gap, never
    /// silently treated as zero calls.
    pub fn attach_failures(&self) -> &[(u32, String)] {
        &self.attach_failures
    }

    /// Successful attachments across both programs (2 per fully-attached slot).
    pub fn attached_probes(&self) -> usize {
        self.attached
    }
}
```

- [ ] **Step 4: Embed the object and wire a minimal main**

In `src/main.rs`, replace the stub with the module wiring plus the embedded object; the CLI grows in Tasks 5–7:

```rust
//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes).

mod attach;
mod plan;

/// The BPF object, built by build.rs. Alignment matters: aya parses it
/// as ELF in place.
pub static EBPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf"));

fn main() {
    eprintln!("p11scope 0.0.0-dev — use `p11scope profile --manifest … --pid …`");
    std::process::exit(2);
}
```

Adjust the `include_bytes_aligned!` path to whatever `aya_build` actually emits (Step 1).

- [ ] **Step 5: Test**

Run: `cargo test --workspace`
Expected: the two new `plan` tests pass alongside all Phase 1a tests; `cargo build` produces the binary with the BPF object embedded (the build.rs invokes nightly — first build is slow).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "scope: attach plan and cookie-based uprobe attach session"
```

---

### Task 5: Scope filters (PID / cgroup) and CONFIG wiring

**Files:**
- Create: `src/scope.rs`
- Modify: `src/attach.rs` (apply filters after load), `src/main.rs` (module decl)

**Interfaces:**
- Consumes: `attach::Scope`, `p11scope_ebpf_common::{CFG_FLAGS, FLAG_PID_FILTER, FLAG_CGROUP_FILTER}`.
- Produces: `scope::cgroup_id(path: &Path) -> Result<u64>`; `scope::apply(&mut Ebpf, &Scope) -> Result<()>`. Tasks 6–8 rely on `apply` being called before any event can be counted.

- [ ] **Step 1: Write the filter application with its test**

`src/scope.rs`:

```rust
//! Capture scope. The BPF side observes nothing until a filter is
//! installed — there is no implicit system-wide capture.

use crate::attach::Scope;
use anyhow::{Context as _, Result};
use aya::Ebpf;
use aya::maps::{Array, HashMap};
use p11scope_ebpf_common::{CFG_FLAGS, FLAG_CGROUP_FILTER, FLAG_PID_FILTER};
use std::path::Path;

/// A cgroup's kernel id is its directory inode number — the same value
/// `bpf_get_current_cgroup_id()` returns for a task inside it.
pub fn cgroup_id(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::metadata(path)
        .with_context(|| format!("reading cgroup path {}", path.display()))?;
    Ok(md.ino())
}

pub fn apply(ebpf: &mut Ebpf, scope: &Scope) -> Result<()> {
    let mut flags: u64 = 0;
    match scope {
        Scope::Pid(pid) => {
            let mut m: HashMap<_, u32, u8> =
                HashMap::try_from(ebpf.map_mut("PID_FILTER").context("PID_FILTER map")?)?;
            m.insert(*pid, 1, 0)?;
            flags |= FLAG_PID_FILTER;
        }
        Scope::Cgroup(id) => {
            let mut m: HashMap<_, u64, u8> =
                HashMap::try_from(ebpf.map_mut("CGROUP_FILTER").context("CGROUP_FILTER map")?)?;
            m.insert(*id, 1, 0)?;
            flags |= FLAG_CGROUP_FILTER;
        }
    }
    let mut cfg: Array<_, u64> =
        Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map")?)?;
    cfg.set(CFG_FLAGS, flags, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_id_is_the_directory_inode() {
        // The unified hierarchy root always exists on a cgroup2 system;
        // if it does not, there is nothing meaningful to assert.
        let root = Path::new("/sys/fs/cgroup");
        if !root.exists() {
            eprintln!("SKIP: no /sys/fs/cgroup");
            return;
        }
        use std::os::unix::fs::MetadataExt as _;
        let expected = std::fs::metadata(root).unwrap().ino();
        assert_eq!(cgroup_id(root).unwrap(), expected);
    }

    #[test]
    fn missing_cgroup_path_errors_loudly() {
        let e = cgroup_id(Path::new("/sys/fs/cgroup/definitely-not-here")).unwrap_err();
        assert!(e.to_string().contains("reading cgroup path"));
    }
}
```

- [ ] **Step 2: Call it from the session**

In `src/attach.rs`, inside `Session::start`, immediately after `Ebpf::load(...)` and **before** any `prog.attach(...)`:

```rust
        crate::scope::apply(&mut ebpf, scope).context("installing scope filter")?;
```

Filters must exist before the first probe fires, otherwise early calls are dropped by an empty filter and the capture silently under-counts.

Add `mod scope;` to `src/main.rs`.

- [ ] **Step 3: Test**

Run: `cargo test --workspace`
Expected: the two scope tests pass; everything else stays green.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "scope: pid and cgroup filter maps installed before attach"
```

---

### Task 6: Metrics readout — live summary and JSON

**Files:**
- Create: `src/metrics.rs`, `src/render.rs`
- Modify: `src/main.rs` (CLI for `profile --mode metrics`)

**Interfaces:**
- Consumes: `plan::AttachPlan`, `attach::Session`, `p11scope_ebpf_common::{SlotStats, RvKey, LATENCY_BUCKETS}`.
- Produces: `metrics::SlotReport { names, aliased, calls, errors, in_flight, total_ns, max_ns, buckets, rv_counts }`; `metrics::read(&Session, &AttachPlan) -> Result<Vec<SlotReport>>`; `metrics::percentile_ns(buckets, q) -> Option<u64>`; `render::live(&[SlotReport], &Evidence, elapsed)`; `render::json(...) -> serde_json::Value`; `render::Evidence`. Tasks 7–8 consume `render::json`.

- [ ] **Step 1: Write the readout with its tests**

`src/metrics.rs`:

```rust
//! Reading the aggregate maps. PerCpu values are summed in userspace;
//! percentiles come from log2 buckets and are therefore approximations
//! (the lower bound of the containing bucket), which every renderer must
//! state.

use crate::attach::Session;
use crate::plan::AttachPlan;
use anyhow::{Context as _, Result};
use aya::maps::{PerCpuArray, PerCpuHashMap};
use p11scope_ebpf_common::{LATENCY_BUCKETS, RvKey, SlotStats};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct SlotReport {
    pub names: Vec<String>,
    pub aliased: bool,
    /// Completed calls (entry and return both observed).
    pub calls: u64,
    pub errors: u64,
    /// Entered but never returned by capture end — excluded from latency.
    pub in_flight: u64,
    pub total_ns: u64,
    pub max_ns: u64,
    pub buckets: [u64; LATENCY_BUCKETS],
    /// CK_RV → count.
    pub rv_counts: BTreeMap<u32, u64>,
}

pub fn read(session: &Session, plan: &AttachPlan) -> Result<Vec<SlotReport>> {
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS map")?)?;
    let rvs: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(session.ebpf.map("RV_COUNTS").context("RV_COUNTS map")?)?;

    let mut rv_by_slot: BTreeMap<u32, BTreeMap<u32, u64>> = BTreeMap::new();
    for entry in rvs.iter() {
        let (k, per_cpu) = entry?;
        let total: u64 = per_cpu.iter().copied().sum();
        if total > 0 {
            *rv_by_slot.entry(k.slot).or_default().entry(k.rv).or_default() += total;
        }
    }

    let mut out = Vec::with_capacity(plan.slots.len());
    for slot in &plan.slots {
        let per_cpu = stats.get(&slot.index, 0)?;
        let mut acc = SlotStats::ZERO;
        for cpu in per_cpu.iter() {
            acc.entered += cpu.entered;
            acc.returned += cpu.returned;
            acc.errors += cpu.errors;
            acc.total_ns += cpu.total_ns;
            acc.max_ns = acc.max_ns.max(cpu.max_ns);
            for (i, b) in cpu.buckets.iter().enumerate() {
                acc.buckets[i] += b;
            }
        }
        out.push(SlotReport {
            names: slot.names.clone(),
            aliased: slot.aliased,
            calls: acc.returned,
            errors: acc.errors,
            in_flight: acc.entered.saturating_sub(acc.returned),
            total_ns: acc.total_ns,
            max_ns: acc.max_ns,
            buckets: acc.buckets,
            rv_counts: rv_by_slot.remove(&slot.index).unwrap_or_default(),
        });
    }
    Ok(out)
}

/// Approximate quantile from log2 buckets: the lower bound of the bucket
/// containing the q-th observation. `q` is in (0.0, 1.0].
pub fn percentile_ns(buckets: &[u64; LATENCY_BUCKETS], q: f64) -> Option<u64> {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return None;
    }
    let target = ((total as f64) * q).ceil() as u64;
    let mut seen = 0u64;
    for (i, count) in buckets.iter().enumerate() {
        seen += count;
        if seen >= target {
            // Bucket i holds [2^(i-1), 2^i); bucket 0 holds exactly 0.
            return Some(if i == 0 { 0 } else { 1u64 << (i - 1) });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::bucket_of;

    #[test]
    fn percentiles_come_from_bucket_lower_bounds() {
        let mut b = [0u64; LATENCY_BUCKETS];
        // 100 observations at ~1µs, 10 at ~1ms.
        b[bucket_of(1_000) as usize] = 100;
        b[bucket_of(1_000_000) as usize] = 10;
        let p50 = percentile_ns(&b, 0.50).unwrap();
        let p99 = percentile_ns(&b, 0.99).unwrap();
        assert_eq!(p50, 512, "1_000ns falls in the [512,1024) bucket");
        assert_eq!(p99, 524_288, "1_000_000ns falls in the [524288,1048576) bucket");
        assert!(p99 > p50);
    }

    #[test]
    fn empty_buckets_have_no_percentile() {
        let b = [0u64; LATENCY_BUCKETS];
        assert_eq!(percentile_ns(&b, 0.5), None);
    }
}
```

- [ ] **Step 2: Write the renderers with their tests**

`src/render.rs`:

```rust
//! Rendering. Both renderers state the capture's completeness; a report
//! that lost information never reads as complete.

use crate::metrics::{SlotReport, percentile_ns};
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Evidence {
    /// Function records present in the manifest across walked surfaces.
    pub table_entries: usize,
    /// Unique {object, file_offset} targets planned.
    pub slots: usize,
    /// Probes successfully attached (2 per fully-attached slot).
    pub attached_probes: usize,
    pub attach_failures: Vec<String>,
    /// Slots whose counts belong to a name group, not a single name.
    pub aliased: Vec<Vec<String>>,
    /// Manifest entries with no attachable target, and why.
    pub skipped: Vec<SkippedOut>,
    pub in_flight_at_end: u64,
    pub completeness: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SkippedOut {
    pub name: String,
    pub reason: String,
}

impl Evidence {
    /// COMPLETE only when nothing was lost: every planned probe attached,
    /// nothing was skipped, no aliasing ambiguity, no call left in flight.
    pub fn verdict(&mut self) {
        self.completeness = if self.attach_failures.is_empty()
            && self.skipped.is_empty()
            && self.aliased.is_empty()
            && self.in_flight_at_end == 0
        {
            "COMPLETE"
        } else {
            "PARTIAL"
        };
    }
}

fn label(r: &SlotReport) -> String {
    if r.aliased { format!("{} (aliased)", r.names.join("|")) } else { r.names.join("|") }
}

fn fmt_ns(ns: Option<u64>) -> String {
    match ns {
        None => "—".into(),
        Some(v) if v < 1_000 => format!("{v}ns"),
        Some(v) if v < 1_000_000 => format!("{:.1}µs", v as f64 / 1e3),
        Some(v) if v < 1_000_000_000 => format!("{:.1}ms", v as f64 / 1e6),
        Some(v) => format!("{:.2}s", v as f64 / 1e9),
    }
}

/// One refreshing screen. Rows with no activity are omitted; the evidence
/// line is always present.
pub fn live(reports: &[SlotReport], ev: &Evidence, elapsed: Duration, module: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "p11scope — {module} — up {:02}:{:02}:{:02} — mode metrics\n",
        elapsed.as_secs() / 3600,
        (elapsed.as_secs() % 3600) / 60,
        elapsed.as_secs() % 60
    ));
    s.push_str(&format!(
        "{:<28} {:>8} {:>6} {:>9} {:>9} {:>9} {:>9}\n",
        "FUNCTION", "CALLS", "ERR", "p50~", "p95~", "p99~", "IN-FLIGHT"
    ));
    let mut rows: Vec<&SlotReport> =
        reports.iter().filter(|r| r.calls > 0 || r.in_flight > 0).collect();
    rows.sort_by(|a, b| b.calls.cmp(&a.calls).then(a.names.cmp(&b.names)));
    for r in rows {
        s.push_str(&format!(
            "{:<28} {:>8} {:>6} {:>9} {:>9} {:>9} {:>9}\n",
            label(r),
            r.calls,
            r.errors,
            fmt_ns(percentile_ns(&r.buckets, 0.50)),
            fmt_ns(percentile_ns(&r.buckets, 0.95)),
            fmt_ns(percentile_ns(&r.buckets, 0.99)),
            r.in_flight
        ));
    }
    s.push_str("(~ = log2-bucket approximation, lower bound)\n");
    s.push_str(&format!(
        "Evidence: {}/{} probes attached · {} slots · {} aliased · {} skipped · {} in-flight → {}\n",
        ev.attached_probes,
        ev.slots * 2,
        ev.slots,
        ev.aliased.len(),
        ev.skipped.len(),
        ev.in_flight_at_end,
        ev.completeness
    ));
    s
}

#[derive(Serialize)]
struct FunctionOut {
    names: Vec<String>,
    aliased: bool,
    calls: u64,
    errors: u64,
    in_flight: u64,
    latency_ns: LatencyOut,
    rv_counts: std::collections::BTreeMap<String, u64>,
}

#[derive(Serialize)]
struct LatencyOut {
    /// Bucket-approximated; exact values are total/max.
    approximate: bool,
    p50: Option<u64>,
    p95: Option<u64>,
    p99: Option<u64>,
    total: u64,
    max: u64,
}

pub fn json(
    reports: &[SlotReport],
    ev: &Evidence,
    module: &str,
    started: &str,
    ended: &str,
    kernel: &str,
) -> serde_json::Value {
    let functions: Vec<FunctionOut> = reports
        .iter()
        .map(|r| FunctionOut {
            names: r.names.clone(),
            aliased: r.aliased,
            calls: r.calls,
            errors: r.errors,
            in_flight: r.in_flight,
            latency_ns: LatencyOut {
                approximate: true,
                p50: percentile_ns(&r.buckets, 0.50),
                p95: percentile_ns(&r.buckets, 0.95),
                p99: percentile_ns(&r.buckets, 0.99),
                total: r.total_ns,
                max: r.max_ns,
            },
            rv_counts: r
                .rv_counts
                .iter()
                .map(|(rv, n)| (format!("0x{rv:08x}"), *n))
                .collect(),
        })
        .collect();
    serde_json::json!({
        "schema": "pkcs11-scope/observed-profile/v0-metrics",
        "capture": { "start": started, "end": ended, "mode": "metrics",
                     "kernel": kernel, "module": module },
        "evidence": ev,
        "functions": functions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::LATENCY_BUCKETS;

    fn report(name: &str, calls: u64, in_flight: u64, aliased: bool) -> SlotReport {
        SlotReport {
            names: vec![name.into()],
            aliased,
            calls,
            errors: 0,
            in_flight,
            total_ns: 0,
            max_ns: 0,
            buckets: [0; LATENCY_BUCKETS],
            rv_counts: Default::default(),
        }
    }

    fn evidence() -> Evidence {
        Evidence {
            table_entries: 68,
            slots: 68,
            attached_probes: 136,
            attach_failures: vec![],
            aliased: vec![],
            skipped: vec![],
            in_flight_at_end: 0,
            completeness: "UNKNOWN",
        }
    }

    #[test]
    fn clean_capture_is_complete() {
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
    }

    #[test]
    fn any_gap_forces_partial() {
        for mutate in [
            (|e: &mut Evidence| e.attach_failures.push("boom".into())) as fn(&mut Evidence),
            |e: &mut Evidence| e.skipped.push(SkippedOut { name: "C_X".into(), reason: "null pointer".into() }),
            |e: &mut Evidence| e.aliased.push(vec!["C_A".into(), "C_B".into()]),
            |e: &mut Evidence| e.in_flight_at_end = 1,
        ] {
            let mut ev = evidence();
            mutate(&mut ev);
            ev.verdict();
            assert_eq!(ev.completeness, "PARTIAL", "a gap must never read as COMPLETE");
        }
    }

    #[test]
    fn live_view_shows_inflight_rows_and_marks_aliases() {
        let mut ev = evidence();
        ev.verdict();
        let out = live(
            &[report("C_Sign", 10, 0, false), report("C_WaitForSlotEvent", 0, 1, true)],
            &ev,
            Duration::from_secs(65),
            "/opt/p11.so",
        );
        assert!(out.contains("C_Sign"));
        // Zero-call rows still appear when a call is in flight.
        assert!(out.contains("C_WaitForSlotEvent (aliased)"));
        assert!(out.contains("up 00:01:05"));
        assert!(out.contains("approximation"));
    }

    #[test]
    fn json_marks_latency_approximate_and_hex_rvs() {
        let mut ev = evidence();
        ev.verdict();
        let mut r = report("C_Sign", 1, 0, false);
        r.rv_counts.insert(0, 1);
        let v = json(&[r], &ev, "/opt/p11.so", "t0", "t1", "6.8.0");
        assert_eq!(v["functions"][0]["latency_ns"]["approximate"], true);
        assert_eq!(v["functions"][0]["rv_counts"]["0x00000000"], 1);
        assert_eq!(v["evidence"]["completeness"], "COMPLETE");
    }
}
```

- [ ] **Step 3: Wire the `profile` subcommand**

Replace `src/main.rs`'s `main` with the real CLI (keep the module declarations and `EBPF_OBJECT`):

```rust
const USAGE: &str = "usage:\n  \
p11scope profile --manifest <m.json> (--pid <n> | --cgroup <path>) [--mode metrics] [--duration <secs>] [-o <out.json>]\n  \
p11scope discover --module <provider.so> [-o <manifest.json>]";

fn main() {
    if let Err(e) = run() {
        eprintln!("p11scope: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("profile") => cmd_profile(args),
        Some("discover") => crate::discover_cmd::run(args),
        Some("--help") | Some("-h") => {
            eprintln!("{USAGE}");
            Ok(())
        }
        other => {
            eprintln!("unknown or missing subcommand: {}\n{USAGE}", other.unwrap_or("(none)"));
            std::process::exit(2);
        }
    }
}
```

`cmd_profile` (same file) parses `--manifest`, `--pid`, `--cgroup`, `--mode` (only `metrics` in this phase; anything else → exit 2 with "mode X not implemented in this phase"), `--duration` (seconds; default: run until SIGINT), `-o`; every flag missing its value exits 2 with `<flag> requires a value` (the convention Phase 1a settled). It then:

1. reads and deserializes the manifest (`p11scope_manifest::manifest::Manifest`), erroring if `schema != p11scope_manifest::manifest::SCHEMA`;
2. builds the plan, errors if `plan.slots.is_empty()`;
3. resolves `Scope` (`--pid` → `Scope::Pid`, `--cgroup` → `scope::cgroup_id(path)?` → `Scope::Cgroup`);
4. starts the `Session`, prints attach failures to stderr as they are found;
5. loops until the duration elapses or SIGINT arrives, redrawing `render::live` every second (clear with `\x1b[2J\x1b[H`);
6. on exit builds `Evidence` from the plan + session + final reports, calls `verdict()`, prints the final frame, and writes `render::json` to `-o` when given.

Read the kernel release for the JSON from `/proc/sys/kernel/osrelease` (trim). Timestamps: `SystemTime::now()` formatted as RFC3339-ish UTC — a small helper is fine, no chrono dependency.

Handle SIGINT without a signal-handling crate: install a flag via `std::sync::atomic::AtomicBool` and `unsafe { libc::signal(...) }` **only if** a libc dependency already exists — otherwise accept that Ctrl-C aborts and rely on `--duration` for clean output, and say so in `--help`. Prefer the no-new-dependency path.

- [ ] **Step 4: Test**

Run: `cargo test --workspace`
Expected: 4 render tests + 2 metrics tests + everything prior, all green.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "scope: metrics readout, live summary, and JSON output"
```

---

### Task 7: `p11scope discover` subcommand (execs the helper)

**Files:**
- Create: `src/discover_cmd.rs`
- Modify: `src/main.rs` (module decl)
- Create: `tests/cli_discover.rs`

**Interfaces:**
- Consumes: nothing from other tasks except the CLI conventions.
- Produces: `discover_cmd::run(args: impl Iterator<Item = String>) -> Result<()>`.

`p11scope` is static and must never dlopen a provider, so this subcommand **executes the `p11scope-discover` binary** rather than linking its logic. Resolution order: `--helper <path>` if given; else a sibling of the running executable (`std::env::current_exe()`'s directory); else `p11scope-discover` on `PATH`. A helper that cannot be found is a loud error naming all three places searched.

- [ ] **Step 1: Write the failing test**

`tests/cli_discover.rs`:

```rust
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_p11scope");

#[test]
fn missing_helper_names_every_place_searched() {
    let out = Command::new(BIN)
        .args(["discover", "--module", "/dev/null", "--helper", "/nonexistent/helper"])
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("/nonexistent/helper"), "stderr: {err}");
}

#[test]
fn discover_forwards_to_the_helper() {
    // The helper is built into the same target dir by the workspace.
    let helper = env!("CARGO_BIN_EXE_p11scope-discover");
    let softhsm = "/usr/lib/softhsm/libsofthsm2.so";
    if !std::path::Path::new(softhsm).exists() {
        eprintln!("SKIP: no SoftHSM2");
        return;
    }
    let out = Command::new(BIN)
        .args(["discover", "--module", softhsm, "--helper", helper])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "p11scope-manifest/1");
}

#[test]
fn missing_module_is_usage_error() {
    let out = Command::new(BIN).args(["discover"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
```

`CARGO_BIN_EXE_p11scope-discover` is only defined for tests in the package that owns that binary. If it is not available from the root package, resolve the helper in the test by walking up from `env!("CARGO_BIN_EXE_p11scope")`'s directory to a sibling named `p11scope-discover`, and skip with a message when it is absent.

Run: `cargo test --test cli_discover` → FAIL (subcommand not implemented).

- [ ] **Step 2: Implement**

`src/discover_cmd.rs`:

```rust
//! `p11scope discover` — locate and exec the unprivileged helper.
//! p11scope never dlopens a provider itself: it is privileged, static,
//! and must not run vendor constructors in its own address space.

use anyhow::{Result, anyhow};
use std::path::PathBuf;
use std::process::Command;

pub fn run(args: impl Iterator<Item = String>) -> Result<()> {
    let mut helper: Option<PathBuf> = None;
    let mut forwarded: Vec<String> = Vec::new();
    let mut it = args.peekable();
    while let Some(a) = it.next() {
        if a == "--helper" {
            let v = it.next().ok_or_else(|| anyhow!("--helper requires a value"))?;
            helper = Some(PathBuf::from(v));
        } else {
            forwarded.push(a);
        }
    }
    if !forwarded.iter().any(|a| a == "--module") {
        eprintln!("discover requires --module <provider.so>");
        std::process::exit(2);
    }

    let mut searched = Vec::new();
    let path = match helper {
        Some(p) => {
            searched.push(p.display().to_string());
            p.exists().then_some(p)
        }
        None => {
            let sibling = std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(|d| d.join("p11scope-discover")));
            match sibling {
                Some(p) => {
                    searched.push(p.display().to_string());
                    if p.exists() { Some(p) } else { None }
                }
                None => None,
            }
        }
    };
    let path = match path {
        Some(p) => p,
        None => {
            searched.push("p11scope-discover on PATH".into());
            PathBuf::from("p11scope-discover")
        }
    };

    let status = Command::new(&path).args(&forwarded).status().map_err(|e| {
        anyhow!("cannot execute discovery helper ({e}); searched: {}", searched.join(", "))
    })?;
    std::process::exit(status.code().unwrap_or(1));
}
```

Add `mod discover_cmd;` to `src/main.rs` and `serde_json` to dev-dependencies if the test needs it (it is already a normal dependency).

- [ ] **Step 3: Test**

Run: `cargo test --workspace`
Expected: all three discover CLI tests pass plus everything prior.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "scope: discover subcommand execs the unprivileged helper"
```

---

### Task 8: Manifest reuse verification (build-ID mismatch refusal)

**Files:**
- Create: `src/verify.rs`
- Modify: `Cargo.toml` (enable the manifest crate's `identify` feature), `src/main.rs` (module decl; call before attaching)
- Create: `tests/reuse.rs`

**Interfaces:**
- Consumes: `p11scope_manifest::{Manifest, ObjectRecord, IdentityKind, identity::identify}`.
- Produces: `verify::check_reuse(&Manifest) -> Result<(), Vec<String>>` — `Err` lists one human-readable reason per object that no longer matches.

A manifest records `{object, file_offset}` targets that are only valid for the exact file image they were derived from. Attaching stale offsets to an upgraded provider silently probes the wrong instructions — the failure mode this gate exists to prevent. This is the Gate G1 criterion "manifest reuse refused on build-ID mismatch (tested)".

- [ ] **Step 1: Enable identity computation in the observer**

In root `Cargo.toml`, change the manifest dependency to `p11scope-manifest = { path = "crates/manifest", features = ["identify"] }`. This adds `object` and `sha2` — both pure Rust with no dlopen and no C runtime requirement, so the static musl build is unaffected. Confirm with `cargo tree -p p11scope -e normal | grep -E 'libloading|cryptoki'` returning nothing.

- [ ] **Step 2: Write the failing tests**

`tests/reuse.rs`:

```rust
use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
use p11scope_manifest::manifest::*;
use std::path::PathBuf;
use std::process::Command;

fn tmpdir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Build a .so with a caller-chosen build-id so two builds differ.
fn cc_so(dir: &PathBuf, name: &str, body: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, body).unwrap();
    let so = dir.join(format!("{name}.so"));
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-Wl,--build-id=sha1", "-o"])
            .arg(&so)
            .arg(&src)
            .status()
            .unwrap()
            .success()
    );
    so
}

fn manifest_for(path: &PathBuf) -> Manifest {
    let id = p11scope_manifest::identity::identify(path);
    Manifest {
        schema: SCHEMA.to_string(),
        module_path: path.display().to_string(),
        objects: vec![ObjectRecord { id: 0, path: path.display().to_string(), identity: id }],
        interface_list: Acquisition::Absent,
        surfaces: vec![],
        vendor_interfaces: vec![],
        alias_groups: vec![],
    }
}

#[test]
fn matching_identity_is_accepted() {
    let d = tmpdir("reuse_ok");
    let so = cc_so(&d, "same", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    assert!(p11scope::verify::check_reuse(&m).is_ok());
}

#[test]
fn changed_object_is_refused_naming_the_file() {
    let d = tmpdir("reuse_bad");
    let so = cc_so(&d, "changed", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    // Rebuild with different content → different build-id, same path.
    let _ = cc_so(&d, "changed", "int f(void){return 2;} int g(void){return 3;}\n");
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("changed.so"), "{err:?}");
    assert!(err[0].contains("build") || err[0].contains("identity"), "{err:?}");
}

#[test]
fn vanished_object_is_refused() {
    let d = tmpdir("reuse_gone");
    let so = cc_so(&d, "gone", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    std::fs::remove_file(&so).unwrap();
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert_eq!(err.len(), 1);
}

#[test]
fn non_reusable_identity_is_refused_even_if_unchanged() {
    let d = tmpdir("reuse_unreusable");
    let so = cc_so(&d, "unreusable", "int f(void){return 1;}\n");
    let mut m = manifest_for(&so);
    m.objects[0].identity = ObjectIdentity {
        kind: IdentityKind::Unavailable,
        value: None,
        reusable: false,
        note: Some("read failed".into()),
    };
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("not reusable"), "{err:?}");
}
```

These tests call `p11scope::verify`, so the root package needs a library target. Add to root `Cargo.toml`:

```toml
[lib]
name = "p11scope"
path = "src/lib.rs"
```

and create `src/lib.rs` re-exporting the modules the binary uses (`pub mod attach; pub mod discover_cmd; pub mod metrics; pub mod plan; pub mod render; pub mod scope; pub mod verify;` plus the `EBPF_OBJECT` constant), with `src/main.rs` reduced to CLI parsing that calls into the library. Move `EBPF_OBJECT` and the existing `mod` declarations accordingly.

Run: `cargo test --test reuse` → FAIL (no `verify` module).

- [ ] **Step 3: Implement**

`src/verify.rs`:

```rust
//! Manifest reuse gate. A manifest's offsets are only meaningful for the
//! exact file image they came from; reusing one against a changed
//! provider would probe the wrong instructions silently. Refuse instead.

use p11scope_manifest::identity::identify;
use p11scope_manifest::manifest::Manifest;
use std::path::Path;

/// `Ok(())` when every recorded object still matches. `Err` lists one
/// reason per object that does not — the caller reports all of them
/// rather than stopping at the first.
pub fn check_reuse(m: &Manifest) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    for obj in &m.objects {
        if !obj.identity.reusable {
            problems.push(format!(
                "{}: manifest identity is not reusable ({})",
                obj.path,
                obj.identity.note.as_deref().unwrap_or("no identity recorded")
            ));
            continue;
        }
        let current = identify(Path::new(&obj.path));
        if !current.reusable {
            problems.push(format!(
                "{}: cannot identify the file now ({})",
                obj.path,
                current.note.as_deref().unwrap_or("unreadable")
            ));
            continue;
        }
        if current.kind != obj.identity.kind || current.value != obj.identity.value {
            problems.push(format!(
                "{}: identity changed since discovery (manifest {:?} {}, current {:?} {}) — \
                 re-run `p11scope discover`",
                obj.path,
                obj.identity.kind,
                obj.identity.value.as_deref().unwrap_or("-"),
                current.kind,
                current.value.as_deref().unwrap_or("-"),
            ));
        }
    }
    if problems.is_empty() { Ok(()) } else { Err(problems) }
}
```

- [ ] **Step 4: Refuse before attaching**

In `cmd_profile`, immediately after deserializing the manifest and before building the plan:

```rust
    if let Err(problems) = verify::check_reuse(&manifest) {
        for p in &problems {
            eprintln!("p11scope: {p}");
        }
        anyhow::bail!("manifest does not match the current files; refusing to attach");
    }
```

There is no `--force` flag: silently attaching stale offsets is the exact failure this gate prevents.

- [ ] **Step 5: Test**

Run: `cargo test --workspace`
Expected: 4 reuse tests pass plus everything prior.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "scope: refuse manifest reuse when object identity changed"
```

---

### Task 9: End-to-end proof against the deterministic workload + static musl build

**Files:**
- Create: `scripts/verify-attach-e2e.sh`
- Create: `docs/notes/phase1b-e2e.md`

**Interfaces:**
- Consumes: everything above.
- Produces: the Gate G1 evidence that probes attach and count correctly, and a static musl `p11scope`.

`spike/harness.c` performs an exact, known number of calls through the module's own function table; `spike/expected.txt` is its ground truth. Observed counts must match it exactly for every function the harness calls.

Note the ordering constraint this task inherits: the manifest is generated moments before the run, so `verify::check_reuse` (Task 8) must pass — if it refuses, the discovery helper and the observer disagree about the provider file, which is a real bug, not a reason to bypass the gate.

- [ ] **Step 1: Write the script**

`scripts/verify-attach-e2e.sh` (executable):

```sh
#!/bin/sh
# Gate G1: p11scope attaches at discovered offsets and counts a
# deterministic workload exactly. Oracle: spike/expected.txt, the ground
# truth for spike/harness.c.
set -eu
cd "$(dirname "$0")/.."

MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/e2e
mkdir -p "$WORK"

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

echo "=== build ==="
cargo build --release
gcc -O0 -o "$WORK/harness" spike/harness.c -ldl

echo "=== discover ==="
./target/release/p11scope-discover --module "$MODULE" -o "$WORK/manifest.json"

echo "=== observe ==="
# The workload waits for a go-file so probes are attached before it runs
# a single call — attach-before-run is the whole point.
rm -f "$WORK/go"
( while [ ! -f "$WORK/go" ]; do sleep 0.05; done; exec "$WORK/harness" "$MODULE" ) &
WPID=$!
sudo ./target/release/p11scope profile \
    --manifest "$WORK/manifest.json" --pid "$WPID" \
    --mode metrics --duration 20 -o "$WORK/observed.json" &
SPID=$!
sleep 3            # let attach complete
touch "$WORK/go"
wait "$WPID"
wait "$SPID"

echo "=== verify against spike/expected.txt ==="
python3 - "$WORK/observed.json" spike/expected.txt <<'PY'
import json, sys
obs = json.load(open(sys.argv[1]))
counts = {}
for f in obs["functions"]:
    for n in f["names"]:
        counts[n] = counts.get(n, 0) + f["calls"]
fail = 0
for line in open(sys.argv[2]):
    name, want = line.split()
    got = counts.get(name, 0)
    if got != int(want):
        print(f"MISMATCH {name}: want {want}, got {got}")
        fail = 1
    else:
        print(f"ok {name}: {got}")
ev = obs["evidence"]
print("evidence:", ev["attached_probes"], "probes,", ev["completeness"])
if ev["attached_probes"] == 0:
    print("no probes attached")
    fail = 1
sys.exit(fail)
PY

echo "=== static musl build ==="
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl --bin p11scope
file target/x86_64-unknown-linux-musl/release/p11scope | grep -q "statically linked" \
    || { echo "p11scope is NOT static"; exit 1; }
echo "p11scope: statically linked OK"

echo "=== e2e: ALL OK ==="
```

`set -eu` is on its own line in the body: a shebang's flags are inert under `sh script` (the trap this project hit twice already).

- [ ] **Step 2: Run it**

Run: `sh scripts/verify-attach-e2e.sh`
Expected: every `ok <name>: <count>` line matches `spike/expected.txt` exactly, `attached_probes` > 0, and the static build check passes.

Debugging guidance if counts mismatch:
- **All zero:** the filter is wrong (check `--pid` is the harness pid, not the subshell's) or attach happened after the workload ran (raise the sleep).
- **Roughly double:** the same target got two entry probes — check slot dedup in `plan::build`.
- **Off by a few on `C_Initialize`/`C_Finalize`:** the workload started before attach completed; raise the pre-`go` sleep.
- Do not "fix" a mismatch by loosening the oracle.

If the static musl link fails because aya needs a C toolchain, install `musl-tools` (or build that step in `rust:1-alpine` as Phase 1a's container script does) and record the deviation.

- [ ] **Step 3: Record the result**

`docs/notes/phase1b-e2e.md` — write the observed table (function, expected, observed), the `attached_probes`/`completeness` line, the kernel version, and the `file` output for the static binary. Real numbers only; no placeholders.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "scope: end-to-end attach verification against deterministic workload"
```

---

### Task 10: Roadmap bookkeeping — Gate G1 status

**Files:**
- Modify: `docs/superpowers/plans/ROADMAP.md`

- [ ] **Step 1: Record Phase 1b completion under the Phase 1 section**

Replace the Phase 1a/1b split note's last sentence ("Gate G1 closes when both have landed.") with a status line naming both plans and mapping each Gate G1 criterion to its evidence: proxy-ng suite green after the extraction (Phase 1a, verified 2026-08-11); helper verified in ubuntu (glibc) and alpine (musl) containers (Phase 1a Task 8, `scripts/verify-discover-containers.sh`); manifest reuse refused on build-ID mismatch, tested (Phase 1b Task 8, `tests/reuse.rs`); attach failures and aliased offsets surfaced in output rather than dropped (Phase 1b Tasks 4/6, `render::Evidence`); end-to-end counts verified against the deterministic oracle (Phase 1b Task 9, `scripts/verify-attach-e2e.sh`). The remaining criterion is `/code-review` on both repos' branches — a human-triggered step, so state it as outstanding rather than claiming it.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/ROADMAP.md
git commit -m "plan: record phase 1b status against gate G1 criteria"
```
