# Safe and Unvalidated Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make profile and trace safe by default against caller-controlled pointer aliasing while retaining all existing decoded metadata behind an off-by-default compile-time feature plus an explicit runtime flag.

**Architecture:** One `CapturePolicy` selects immutable eBPF behavior and every public label. The default object contains safe and aggregate paths only; the feature object additionally contains the existing unvalidated parameter/template decoders. Userspace publishes, verifies, and freezes policy maps before attachment, and tests prove both the useful finite mechanism/name equality oracles and the absence of a general pointer-content channel.

**Tech Stack:** Rust 1.88; root edition 2024; existing no_std eBPF/common crates remain edition 2021; Aya 0.14.0, aya-ebpf 0.2.1, Linux x86-64, and existing `libc`/`pkcs11-proxy-ng-types` dependencies.

## Global Constraints

- Complete Tasks 4–5 of `2026-08-13-manifest-provenance.md` before starting this plan. Complete Tasks 1–5 here before the consolidated Task 6, then finish provenance Task 7.
- `allowlisted` is the default for profile and trace; `aggregate-only` is the only metrics policy.
- `unsafe-unvalidated-metadata` requires both the off-by-default Cargo feature and `--unsafe-unvalidated-metadata`; no runtime flag can activate code absent from the object.
- Preserve the shared `Event` ABI and keep `CallStart` feature-independent across default, unsafe, small-ring, and unsafe+small-ring builds.
- Safe pointer-derived output is limited to exact membership in the finite published/configured mechanism registry and the exact 104-name function catalog.
- Do not decode or emit PINs, keys, labels, `CKA_ID`, messages, signatures, wrapped objects, arbitrary buffers, raw pointers, raw session handles, or async ids.
- Support remains cumulative across PKCS #11 2.0x, 2.40, 3.0, 3.1, and 3.2 surfaces.
- Keep `MAX_MECH_SHAPES = 1024`; overflow refuses before attachment rather than truncating.
- Add no dependency and no second embedded BPF object. Use the existing standard library, `libc`, Aya, and pinned proxy-ng types.
- Do not combine this security change with an edition migration of the eBPF/common crates.
- Keep Linux x86-64 and kernel 5.15 as the release floor.
- Privileged and container tests require explicit approval and an unrun gate is never reported as passed.
- Preserve unrelated working-tree changes and do not commit without explicit approval.

---

### Task 1: Feature matrix and one capture-policy authority

**Files:**
- Modify: `Cargo.toml`
- Modify: `build.rs`
- Modify: `crates/ebpf/Cargo.toml`
- Modify: `crates/ebpf-common/src/lib.rs`
- Modify: `src/attach.rs`
- Test: `crates/ebpf-common/src/lib.rs`
- Test: `tests/release_contracts.rs`

**Interfaces:**
- Produces: `attach::CapturePolicy::{Allowlisted, UnsafeUnvalidatedMetadata, AggregateOnly}`.
- Produces: `CapturePolicy::config_bit() -> u64`, `privacy_mode() -> &'static str`, `uses_events() -> bool`, and `uses_unsafe_decoders() -> bool`.
- Consumes: `P11SCOPE_SMALL_RING` and Cargo's `CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA` in `build.rs`.

- [x] **Step 1: Pin the feature and policy matrix with failing tests**

Add unit assertions under `#[cfg(test)] mod capture_policy` for the three distinct policy bits/labels and add `metadata_feature_matrix` to `tests/release_contracts.rs` for the root/eBPF feature declarations. Pin the shared ABI to `size_of::<CallStart>() == 272`, `size_of::<Event>() == 288`, and alignment 8 after adding `CallStart.mechanism_ptr: u64`.

```rust
assert_eq!(CapturePolicy::Allowlisted.privacy_mode(), "allowlisted");
assert_eq!(CapturePolicy::AggregateOnly.uses_events(), false);
assert!(CapturePolicy::UnsafeUnvalidatedMetadata.uses_unsafe_decoders());
assert_eq!(core::mem::size_of::<CallStart>(), 272);
assert_eq!(core::mem::size_of::<Event>(), 288);
```

- [x] **Step 2: Run the focused tests and confirm RED**

Run:

```sh
cargo +1.88 test --locked -p p11scope capture_policy -- --nocapture
cargo +1.88 test --locked -p p11scope-ebpf-common tests::event_and_callstart_have_no_implicit_padding -- --exact
```

Run: `cargo +1.88 test --locked --test release_contracts metadata_feature_matrix -- --exact`

Expected: FAIL because `CapturePolicy`, the feature declarations, and `mechanism_ptr` do not exist.

- [x] **Step 3: Add the minimum feature plumbing and policy type**

Declare an empty root feature and an eBPF feature of the same name. Keep `ebpf-common` feature-neutral. Add the pointer field to `CallStart`, not `Event`, so both eBPF artifacts share one ABI and public events never contain an address.

```toml
[features]
unsafe-unvalidated-metadata = []
```

```rust
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CapturePolicy {
    Allowlisted,
    UnsafeUnvalidatedMetadata,
    AggregateOnly,
}
```

In `build.rs`, emit `cargo:rerun-if-env-changed=CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA`, build one comma-separated list, and pass `--features` once. The four required combinations are default, unsafe, small-ring, and unsafe+small-ring.

```rust
let mut features = Vec::new();
if small_ring { features.push("small-ring"); }
if env::var_os("CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA").is_some() {
    features.push("unsafe-unvalidated-metadata");
}
if !features.is_empty() {
    cmd.arg("--features").arg(features.join(","));
}
```

- [x] **Step 4: Run the policy/ABI tests and all four build combinations**

Run:

```sh
cargo +1.88 test --locked -p p11scope capture_policy -- --nocapture
cargo +1.88 test --locked -p p11scope-ebpf-common tests::event_and_callstart_have_no_implicit_padding -- --exact
cargo +1.88 test --locked --test release_contracts metadata_feature_matrix -- --exact
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 check --locked -p p11scope --all-targets --features unsafe-unvalidated-metadata
P11SCOPE_SMALL_RING=1 cargo +1.88 check --locked --workspace --all-targets
P11SCOPE_SMALL_RING=1 cargo +1.88 check --locked -p p11scope --all-targets --features unsafe-unvalidated-metadata
```

Expected: PASS. Save the exact commands/output in the task report; do not commit without user approval.

---

### Task 2: Immutable map publication and freeze syscall

**Files:**
- Modify: `crates/ebpf-common/src/lib.rs`
- Modify: `crates/ebpf/src/main.rs`
- Modify: `src/scope.rs`
- Modify: `src/shapes.rs`
- Modify: `src/attach.rs`
- Test: `src/scope.rs`
- Test: `src/shapes.rs`
- Test: `src/attach.rs`
- Test: `tests/release_contracts.rs`

**Interfaces:**
- Consumes: `CapturePolicy` from Task 1.
- Produces: `scope::PublishedScope { config: u64, cgroup_file: Option<std::fs::File> }` from `scope::publish(&mut Ebpf, &Scope, CapturePolicy)`.
- Produces: `shapes::approved_mechanisms(&MechanismRegistry) -> BTreeMap<u64, u32>`.
- Produces: private `attach::freeze_map(name: &str, map: &aya::maps::Map) -> anyhow::Result<()>`.
- Produces: shared `valid_config(flags: u64) -> bool`, used identically by userspace publication tests and eBPF fail-closed scope checks.

- [x] **Step 1: Write RED publication tests**

Pin exactly one scope bit and one policy bit in every legal `CONFIG` word; reject zero or multiple bits. Pin the approved-mechanism union, deduplication, `shape::NONE` for official unshaped ids, the real `u64::MAX` id, and refusal when a synthetic union exceeds 1024. Name pinned proxy-ng revision `a2aab6cd67d21d140277a4584942e06c903f165b` next to the assertion that its official list has exactly 463 unique ids.

```rust
assert!(config_valid(FLAG_PID_FILTER | FLAG_POLICY_ALLOWLISTED));
assert!(!config_valid(FLAG_PID_FILTER));
assert!(!config_valid(FLAG_PID_FILTER | FLAG_POLICY_ALLOWLISTED | FLAG_POLICY_AGGREGATE));
assert_eq!(official.iter().map(|m| m.0).collect::<BTreeSet<_>>().len(), 463);
assert!(approved.contains_key(&u64::MAX));
```

Add `immutable_policy_maps` to `tests/release_contracts.rs`: ordinary immutable Array/Hash maps use `BPF_F_RDONLY_PROG`, while `CGROUP_FILTER` and `TEMPLATE_TAIL` use flags 0 because Linux rejects program-readonly flags on fd-array maps.

- [x] **Step 2: Run focused tests and confirm RED**

Run:

```sh
cargo +1.88 test --locked --lib shapes::tests -- --nocapture
cargo +1.88 test --locked --lib scope::tests -- --nocapture
cargo +1.88 test --locked --lib attach::tests -- --nocapture
```

Run: `cargo +1.88 test --locked --test release_contracts immutable_policy_maps -- --exact`

Expected: FAIL because policy bits, union publication, readback, and freezing are absent.

- [x] **Step 3: Refactor publication into one owner**

Make `Session::start_inner` call `scope::publish`, populate `SLOT_SEMANTICS`, the byte-exact async catalog, mechanism approvals, and feature-only boolean attributes, then compare every supported map entry with its expected `BTreeMap`/array before any program attach. `CGROUP_FILTER` is the only syscall-readback exception: verify type/max_entries=1, retain the source cgroup fd, require successful `set(0, fd)`, and cover effective membership in the live gate. Read `TEMPLATE_TAIL` back as the loaded program id.

```rust
pub struct PublishedScope {
    pub config: u64,
    pub cgroup_file: Option<std::fs::File>,
}

pub fn publish(ebpf: &mut Ebpf, scope: &Scope, policy: CapturePolicy)
    -> Result<PublishedScope>;
```

Build `MECH_SHAPE` from the deduplicated union of `PKCS11_3_2_OFFICIAL_MECHANISMS` and `MechanismRegistry::registered_mechanisms()`. The map value remains an optional decoder shape; map presence is approval.

- [x] **Step 4: Implement the private Linux freeze shim**

Match only `Map::Array`, `Map::HashMap`, `Map::CgroupArray`, and `Map::ProgramArray`; extract their public `MapData::fd()`. Call command 22 (`BPF_MAP_FREEZE`) using `libc::syscall(libc::SYS_bpf, ...)` and a zero-initialized map-fd attribute. Return an `anyhow` error containing the map name and `last_os_error`; never ignore an unexpected map variant.

```rust
#[repr(C)]
#[derive(Default)]
struct BpfMapFreezeAttr { map_fd: u32 }

fn freeze_map(name: &str, map: &aya::maps::Map) -> Result<()> {
    let data = match map {
        aya::maps::Map::Array(m)
        | aya::maps::Map::HashMap(m)
        | aya::maps::Map::CgroupArray(m)
        | aya::maps::Map::ProgramArray(m) => m,
        other => bail!("refusing to freeze unexpected {name} map variant {other:?}"),
    };
    let attr = BpfMapFreezeAttr { map_fd: data.fd().as_fd().as_raw_fd() as u32 };
    let rc = unsafe { libc::syscall(libc::SYS_bpf, 22u32, &attr, size_of_val(&attr)) };
    if rc == -1 { return Err(std::io::Error::last_os_error()).with_context(|| format!("freezing {name}")); }
    Ok(())
}
```

Freeze `CONFIG`, `PID_FILTER`, `CGROUP_FILTER`, `SLOT_SEMANTICS`, `ASYNC_FUNCTIONS`, and `MECH_SHAPE` after exact publication. In feature builds freeze `ATTR_BOOL_BITS` after publication and `TEMPLATE_TAIL` after its program id is installed; freeze unused optional maps empty. Reorder the existing fork tracepoint so neither it nor any uprobe attaches before all selected-policy freezes complete. Any failure aborts before attach.

- [x] **Step 5: Run unprivileged checks; leave the live mutation gate explicitly pending**

Run:

```sh
cargo +1.88 test --locked --lib shapes::tests -- --nocapture
cargo +1.88 test --locked --lib scope::tests -- --nocapture
cargo +1.88 test --locked --lib attach::tests -- --nocapture
cargo +1.88 test --locked --test release_contracts immutable_policy_maps -- --exact
cargo +1.88 check --locked --workspace --all-targets
```

Expected: PASS. Record the approval-gated live check as unrun until authorized: an otherwise-valid update/delete must succeed against an unfrozen matched control and return `EPERM` against every frozen policy map; invalid cgroup/program fds are not accepted as proof.

---

### Task 3: Policy-specific eBPF capture

**Files:**
- Modify: `crates/ebpf-common/src/lib.rs`
- Modify: `crates/ebpf/src/main.rs`
- Modify: `src/attach.rs`
- Modify: `src/metrics.rs`
- Test: `crates/ebpf-common/src/lib.rs`
- Test: `src/attach.rs`
- Test: `tests/release_contracts.rs`

**Interfaces:**
- Consumes: immutable policy bits and approved `MECH_SHAPE` from Task 2.
- Produces: `FunctionNameKey { len: u32, bytes: [u8; FUNCTION_NAME_MAX_BYTES + 1] }` for exact `ASYNC_FUNCTIONS` lookup. The extra zero byte makes the `repr(C)` key exactly 32 bytes with no uninitialized tail padding.
- Produces: `FunctionNameKey::from_bytes(&[u8]) -> Option<FunctionNameKey>` for the same bounded NUL/length rule in tests and publication.
- Produces: shared `return_allows_mechanism(rv: u64) -> bool` for exactly `CKR_OK` and `CKR_PENDING`.
- Produces: `EVIDENCE_UNREGISTERED_MECHANISMS` and its userspace sum.

- [x] **Step 1: Add RED structural and semantic contracts**

Under `#[cfg(test)] mod safe_capture`, pin that aggregate entry reads no `SlotSemantics` or argument and aggregate return emits no `Event`; the built default object has no template maps/programs or decoder symbols; unsafe fixed-offset additions use `checked_add`; async authorization cannot succeed on hash/length alone. Add pure helpers for return gating and exact name-key construction so the ordinary suite covers `CKR_OK`, `CKR_PENDING`, failure, null, unreadable, unknown, exact, overlong, and unknown-name cases. Include successful/unreadable `C_OpenSession.phSession` and `C_AsyncGetID` output-scalar cases and prove those internal correlation values never enter rendered output. Add the corresponding `policy_specific_ebpf` object/source contract to `tests/release_contracts.rs`.

```rust
assert!(return_allows_mechanism(CKR_OK));
assert!(return_allows_mechanism(CKR_PENDING));
assert!(!return_allows_mechanism(CKR_ARGUMENTS_BAD));
assert_eq!(FunctionNameKey::from_bytes(b"C_Encrypt\0"), Some(expected));
let unknown = FunctionNameKey::from_bytes(b"C_EncryptX\0").unwrap();
assert_eq!(catalog.get(&unknown), None);
```

- [x] **Step 2: Run focused tests and confirm RED**

Run: `cargo +1.88 test --locked --workspace safe_capture -- --nocapture`

Run: `cargo +1.88 test --locked --test release_contracts policy_specific_ebpf -- --exact`

Expected: FAIL because all current policies execute the entry-time unvalidated decoder and async authorization is hash-based.

- [x] **Step 3: Implement `aggregate-only` before all semantic reads**

After scope and CONFIG validation, aggregate entry records only timestamp/key and increments `STATS.entered`; it returns before reading `SLOT_SEMANTICS` or any argument. Aggregate return updates `STATS`/`RV_COUNTS`, removes `START`, and returns before cgroup/semantic state or ring reservation. Do not attach `sched_process_fork` for this policy.

```rust
if flags & FLAG_POLICY_AGGREGATE != 0 {
    return record_aggregate_start(slot, key);
}
```

- [x] **Step 4: Implement return-gated safe mechanism capture**

In safe entry, store only nullness and `mechanism_ptr`; do not dereference it. On return, only `CKR_OK`/`CKR_PENDING` may read the first `u64`. Persist the value only when `MECH_SHAPE.get(&id)` is present. A read fault increments semantic-capture failures; an absent id increments unregistered mechanisms; both withhold the value and force `PARTIAL`. Remove `START` on every terminal path.

```rust
if flags & FLAG_POLICY_ALLOWLISTED != 0
    && return_allows_mechanism(rv)
    && start.mechanism_ptr != 0
{
    match bpf_probe_read_user(start.mechanism_ptr as *const u64) {
        Ok(id) if MECH_SHAPE.get(&id).is_some() => event.mechanism = id,
        Ok(_) => bump_evidence(EVIDENCE_UNREGISTERED_MECHANISMS),
        Err(_) => bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES),
    }
}
```

Keep null-cancellation semantics distinct. Do not make a rejected init a mechanism request in safe mode.
Safe mode otherwise retains descriptor-approved scalar arguments, output
pointer nullness, and successful provider-written session/async id reads for
internal correlation only; it never dereferences ordinary output buffers.

- [x] **Step 5: Replace async hash authorization with exact bytes**

Snapshot at most 29 bytes on the BPF stack, require a NUL at length `0..=27`, zero-fill `FunctionNameKey.bytes`, and look up the complete key. A hash may be retained only as an untrusted candidate optimization followed by full byte comparison; the preferred implementation removes it.

```rust
#[repr(C)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct FunctionNameKey {
    pub len: u32,
    pub bytes: [u8; FUNCTION_NAME_MAX_BYTES + 1],
}
```

Add the existing feature-gated `aya::Pod` implementation for userspace map
publication and assert `size_of::<FunctionNameKey>() == 32`.

Null, unreadable, overlong, and unknown names increment async evidence when correlation is required. Only the numeric catalog id persists.

- [x] **Step 6: Compile unsafe-only code out of the default object**

Guard `decode_params`, `walk_template`, `ATTR_BOOL_BITS`, `TEMPLATE_TAIL`, and all template uprobe functions with `#[cfg(feature = "unsafe-unvalidated-metadata")]`. In the feature object, an allowlisted or aggregate invocation leaves the unsafe maps empty/frozen and never selects a template program; unsafe mode preserves the pre-design entry-time mechanism, parameter, template, and boolean behavior. Use `checked_add` before every fixed pointer offset; overflow records failure and reads nothing. Preserve a real `u64::MAX` mechanism through explicit capture bits rather than sentinel comparison.

- [x] **Step 7: Run focused tests and build both eBPF artifacts**

Run:

```sh
cargo +1.88 test --locked --workspace safe_capture -- --nocapture
cargo +1.88 test --locked --test release_contracts policy_specific_ebpf -- --exact
cargo +nightly build --locked --release --target bpfel-unknown-none -Z build-std=core --manifest-path crates/ebpf/Cargo.toml --target-dir target/plan-safe-ebpf
cargo +nightly build --locked --release --target bpfel-unknown-none -Z build-std=core --manifest-path crates/ebpf/Cargo.toml --target-dir target/plan-unsafe-ebpf --features unsafe-unvalidated-metadata
```

Expected: PASS. Inspect the two objects and record that unsafe-only maps/program symbols are absent from the default and present in the feature build.

---

### Task 4: CLI, state, rendering, and abnormal-output contract

**Files:**
- Modify: `src/main.rs`
- Modify: `src/attach.rs`
- Modify: `src/semantics.rs`
- Modify: `src/render.rs`
- Modify: `src/trace.rs`
- Modify: `src/metrics.rs`
- Test: `src/main.rs`
- Test: `src/semantics.rs`
- Test: `src/render.rs`
- Test: `src/trace.rs`

**Interfaces:**
- Consumes: `CapturePolicy` and kernel evidence from Tasks 1–3.
- Produces: `CapturePolicy::from_cli(mode: &str, unsafe_requested: bool, unsafe_compiled: bool) -> anyhow::Result<CapturePolicy>`; production passes `cfg!(feature = "unsafe-unvalidated-metadata")`.
- Produces: `trace::abort_evidence_line(CapturePolicy, "object_lease_break") -> String` for provenance Task 5.
- Produces: `write_json_report(&mut std::fs::File, &serde_json::Value) -> anyhow::Result<()>`, which writes and syncs only the supervisor-prepared temporary profile fd.

- [x] **Step 1: Add RED CLI/output/state tests**

Under `#[cfg(test)] mod policy_output`, pin early refusal before `load_plan` for the unsafe flag in a default build; safe default in feature builds; metrics+unsafe refusal; discover flag refusal; every live/JSON/trace policy label; v1.4/v1.1-metrics exact schemas; safe rejected-init omission; safe disabled parameter/template notes; unsafe legacy attribution; unregistered/fault evidence forcing `PARTIAL`; and `u64::MAX` rendering when capture bits say present.

```rust
assert_eq!(CapturePolicy::from_cli("profile", false, false)?, CapturePolicy::Allowlisted);
assert!(CapturePolicy::from_cli("metrics", true, true).is_err());
assert_eq!(value["schema"], "pkcs11-scope/observed-profile/v1.4");
assert_eq!(value["capture"]["privacy_mode"], "allowlisted");
```

Pin normal terminal evidence with `final_drain: true` and `counters_available: true`. Abort evidence is a discriminated minimal record with `completeness: "PARTIAL"`, `event_loss: null`, `capture_aborted: "object_lease_break"`, `final_drain: false`, and `counters_available: false`; ordinary per-capture counter fields are absent rather than fabricated.

- [x] **Step 2: Run focused tests and confirm RED**

Run: `cargo +1.88 test --locked policy_output -- --nocapture`

Expected: FAIL because CLI policy selection and new schema/evidence fields are absent.

- [x] **Step 3: Thread one policy value through attach and rendering**

Parse the flag in the existing manual command loops and validate it before discovery or privilege use. Change `Session::start` to accept `CapturePolicy`; use it for map bits, program selection, fork attachment, renderer labels, and the unsafe stderr warning. Do not infer output labels from a mutable map.

```rust
pub fn start(
    plan: &AttachPlan,
    scope: &Scope,
    objects: &VerifiedObjects,
    policy: CapturePolicy,
) -> Result<Self>;
```

Make safe semantics bind a mechanism only from successful/pending approved events. Render policy-disabled params/templates as explicit omissions, not decode failures. Unsafe semantics retain the pre-design request attribution.

- [x] **Step 4: Advance schemas and implement terminal evidence**

Use profile `pkcs11-scope/observed-profile/v1.4` and metrics `pkcs11-scope/observed-profile/v1.1-metrics`. Add `capture.privacy_mode`, `evidence.unregistered_mechanisms`, the policy to every live frame header, and `CAPTURE privacy=<mode>` before the first trace call. Normal terminal trace evidence carries `privacy_mode`, `capture_aborted: null`, `final_drain: true`, and `counters_available: true`. Implement the supervisor-safe abort serializer without BPF state:

```rust
pub fn abort_evidence_line(policy: CapturePolicy, reason: &'static str) -> String {
    format!(
        "EVIDENCE {}",
        serde_json::json!({
            "completeness": "PARTIAL",
            "privacy_mode": policy.privacy_mode(),
            "capture_aborted": reason,
            "final_drain": false,
            "counters_available": false,
            "event_loss": serde_json::Value::Null,
        })
    )
}
```

Provenance Task 5 owns sink duplication, worker reaping, bounded stdout, newline prefix, flush, and exit 78. A consumer treats exit 78 or no terminal record as truncated.

- [x] **Step 5: Separate profile serialization from publication**

Refactor the existing `write_json_report` to accept the already-open temporary file, truncate/seek it to zero, write the complete JSON, flush, and `sync_all`. Provenance Task 5 creates the same-directory file with `OpenOptions::create_new(true)` before fork and is the only code that renames it to the final path, after a valid completion record, pidfd-confirmed worker exit, and release of the last lease references. On lease break or abnormal exit it removes the temp. The worker never publishes the destination.

- [x] **Step 6: Run focused and ordinary tests**

Run:

```sh
cargo +1.88 test --locked policy_output -- --nocapture
cargo +1.88 test --locked --lib semantics::tests -- --nocapture
cargo +1.88 test --locked --lib render::tests -- --nocapture
cargo +1.88 test --locked --lib trace::tests -- --nocapture
cargo +1.88 test --locked --workspace --all-targets
```

Expected: PASS with exact schema/policy assertions and no fallback parsing of old schema ids.

---

### Task 5: Hostile-alias, map, and feature verification

**Files:**
- Modify: `scripts/fixtures/canary_workload.c`
- Modify: `scripts/verify-canaries.sh`
- Modify: `scripts/verify-induced-gaps.sh`
- Modify: `scripts/check-bpf-map-defs.py`
- Test: `tests/release_contracts.rs`

**Interfaces:**
- Consumes: both artifacts and all policy/output behavior from Tasks 1–4.
- Produces: ordinary unprivileged contracts plus approval-gated safe/unsafe live evidence used by Task 6.
- Produces: `scripts/check-bpf-map-defs.py --policy-inventory <default-elf> <unsafe-elf>` for exact map/program inventory comparison.

- [x] **Step 1: Add failing static/release contracts**

Add `metadata_canary_matrix` to `tests/release_contracts.rs`. Require canary lanes for default safe profile, default safe trace, feature-without-flag safe profile/trace, feature-plus-flag unsafe profile/trace, and aggregate-only metrics. Require exact observer map ids, a nonempty `START`, positive scanner control, standard-id usefulness, unknown-id containment, rejection of a test-injected noncatalog name with the same legacy hash candidate, and no unsafe map/program inventory in the default object.

- [x] **Step 2: Run the contract and confirm RED**

Run: `cargo +1.88 test --locked --test release_contracts metadata_canary_matrix -- --exact`

Expected: FAIL because the scripts do not yet exercise both policies and aggregate-only behavior.

- [x] **Step 3: Extend the workload with malicious aliases**

Route distinct benign sentinels through every existing pointer-derived decoder: mechanism id, RSA-PSS words, both GCM layouts, template type, each one-byte policy value, and async function name. Keep ordinary-placement sentinels for PIN, key, label, `CKA_ID`, plaintext/ciphertext, signature, wrapped object, random/output buffers, and stack arguments. Add a registered standard mechanism control and a readable unknown-id control whose provider returns `CKR_OK`.

- [x] **Step 4: Make the gate assert policy-specific outcomes**

Safe mode may expose only the registered mechanism control and exact catalog name; no alias sentinel may appear in maps/events/logs/output. Unsafe mode must reproduce all and only the pre-design decoded scalar metadata and print/serialize its warning and privacy label. Metrics must leave the ring empty and all semantic evidence zero while aggregate counts advance. Scan the exact live observer map ids, not names.

- [x] **Step 5: Add overflow, saturation, and immutability cases**

Exercise `u64::MAX`, unreadable/overflowing fixed offsets, a final-entry boolean fault, mechanism-registry capacity refusal, START/RV/ring saturation, and all control-map freeze mutations. The frozen mutation must return `EPERM` with a valid operation; its unfrozen matched control must succeed. Dynamic STATS/RV/EVIDENCE updates must still work.

- [x] **Step 6: Run unprivileged contracts and record live lanes accurately**

Run:

```sh
cargo +1.88 test --locked --test release_contracts metadata_canary_matrix -- --exact
python3 scripts/check-bpf-map-defs.py --self-test
python3 scripts/check-bpf-map-defs.py --policy-inventory target/plan-safe-ebpf/bpfel-unknown-none/release/p11scope-ebpf target/plan-unsafe-ebpf/bpfel-unknown-none/release/p11scope-ebpf
sh -n scripts/verify-canaries.sh scripts/verify-induced-gaps.sh
```

Expected: PASS. Run `scripts/verify-canaries.sh` and privileged induced-gap/freeze cases only after explicit approval; otherwise record each as UNRUN rather than PASS.

---

### Task 6: Consolidated public/release integration and final gates

**Files:**
- Modify: `README.md`
- Modify: `docs/usage.md`
- Modify: `docs/privacy/allowlist-v1.md`
- Modify: `docs/schema/observed-profile-v1.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/superpowers/plans/ROADMAP.md`
- Modify: `scripts/build-release.sh`
- Modify: `scripts/matrix/verify-docker.sh`
- Modify: `scripts/matrix/verify-shared-layer.sh`
- Modify: `scripts/matrix/verify-kind-pod.sh`
- Modify: `scripts/matrix/verify-knative.sh`
- Modify: `tests/release_contracts.rs`

**Interfaces:**
- Consumes: completed provenance Tasks 4–5, metadata Tasks 1–5, and every requirement listed in provenance Task 6.
- Produces: the only final public/release contract edit and the evidence handed to provenance Task 7.

- [x] **Step 1: Write the final release-contract assertions before public edits**

Pin the exact v1.4/v1.1-metrics ids, direct published migrations v1.2→v1.4 and v0-metrics→v1.1-metrics, safe-default/unsafe-feature CLI matrix, transient `START.pMechanism` allowlist row, manifest v4, mandatory provenance, lease-break exit 78/abort evidence, static official artifact, separate target directories, and absence of unsafe-only map/program inventory.

- [x] **Step 2: Run the release contract and confirm RED**

Run: `cargo +1.88 test --locked --test release_contracts`

Expected: FAIL on the public/release markers not yet updated by this integrated task.

- [x] **Step 3: Update the public contract once**

Document safe/unsafe trust boundaries without calling `bpf_probe_read_user` validation. State that v1.3/v1-metrics were internal waypoints if never published. Record `START.pMechanism` as transient privileged state: raw argument only, no safe entry dereference, return-gated finite lookup, removal on every terminal path, and no public output.

Integrate provenance Task 6: manifest v4, exact-inode closure, `$ORIGIN`, root-owned loader chain, `CAP_LEASE`, same-uid limitation, atomic profile publication, and terminal trace-abort semantics.

- [x] **Step 4: Update release and environment scripts**

Build the official observer with `--no-default-features` in a dedicated `CARGO_TARGET_DIR`; fail packaging if the unsafe flag works or unsafe-only inventory is present. Build diagnostic/canary artifacts in a different directory and never copy them into the archive. Preserve the root-owned sibling helper and safe-copy provenance staging.

For Docker, shared-layer, kind, and Knative, copy the resolved provider plus required adjacent dependency closure as regular files. Positively prove read-lease acquisition on every actual provider/attach/authorization-runtime object and record `statfs` filesystem type plus `/proc/sys/fs/lease-break-time`. Do not blacklist overlay by name; refuse only a lane that cannot establish the required lease.

- [x] **Step 5: Run all unprivileged release gates**

Run:

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
git diff --check
```

Expected: every command exits 0. Run modified shell files through `sh -n` and `scripts/check-bpf-map-defs.py` as part of the same gate.

- [ ] **Step 6: Run only authorized privileged/container gates and finish provenance review**

With explicit approval, run safe/unsafe canaries, freeze mutations, attach/induced-gap tests, release packaging, and the changed Docker/shared-layer/kind/Knative lanes. Require the captured filesystem and lease-timeout evidence. Otherwise list them as UNRUN and keep G3/G5 open.

**Partially complete (2026-08-14).** Run under explicit approval and passed:
the privileged host attach lane (136/136 probes, exact SoftHSM counts,
`PARTIAL` with zero concrete gap counters), the full canary matrix (seven
capture lanes and three START lanes), the induced-gap matrix G1–G5, and the
container matrix (Ubuntu/glibc and Alpine/musl discovery; Docker 68/68/136;
shared layer broad 2x plus both leaf 1x; kind pod 68/68/136; Knative
cold-start capture from a pod created after attach) with per-lane read-lease,
filesystem-type, and `lease-break-time` evidence recorded.

Still UNRUN, so G5 stays open:

- `scripts/matrix/verify-fork-scope.sh` and `scripts/matrix/verify-oracle.sh`.
  Both asserted the now-impossible terminal `COMPLETE` and were corrected to
  the shared `terminal_capture_is_clean` predicate on 2026-08-14; neither has
  been rerun since. The fork-scope lane carries the capability matrix, so the
  minimum capability set remains inherited rather than freshly measured.
- The container lanes have not been rerun since the provider-copy byte cap
  was added, and `scripts/attach-pod.sh` has never been executed against a
  live cluster — it is unprivileged-tested for argument refusal only.
- Release packaging, publication, push, and tag: NOT PERFORMED.
- Provenance Task 7's final cross-cutting re-review has not run.

Then execute provenance Task 7's fixed-class maximum review. Zero findings is required only in its explicitly named classes; a blocked or unrun security gate is not converted into release clearance. Do not commit, push, tag, or publish without separate user approval.
