# Shared PKCS#11 module-loading crate — extraction design

**Date:** 2026-08-10
**Status:** Proposed — pending review. No code has been written.
**Scope of this doc:** the Phase 1 *cross-repo precursor* from the
[ROADMAP](../plans/ROADMAP.md): extracting `pkcs11-proxy-ng`'s module-FFI
(dlopen + function-table discovery) into a lean crate that both the proxy and
`p11scope-discover` consume. It does **not** cover the eBPF observer, the
manifest schema, or anything else in Phase 1.
**Parent docs:** [pkcs11-scope design](2026-08-10-pkcs11-scope-design.md)
("Shared decode core" decision row), ROADMAP Phase 1,
`pkcs11-proxy-ng/doc/adr/ADR-0011` (ABI axes).

---

## 1. Problem

`p11scope-discover` must dlopen a PKCS#11 provider, obtain its function
table(s), and map the function pointers to ELF file offsets. pkcs11-proxy-ng
already has production-hardened code for the first two steps
(`crates/backend/src/ffi/loading.rs` + `ffi/function_field_tables.rs`),
including quirk handling for real providers that misreport their interfaces.
The settled decision (scope design spec) is to **reuse it, not duplicate it**.

Reuse is blocked by a dependency chain, verified in the tree:

```
pkcs11-proxy-ng-backend  →  pkcs11-proxy-ng-proto  →  tonic/prost
                                     └─ build.rs runs tonic-prost-build
                                        → requires protoc in every build env
```

(CI installs `protobuf-compiler`; `crates/proto/build.rs` compiles three
`.proto` files.) The discover helper ships as glibc **and** musl *dynamic*
binaries that get copied into arbitrary target containers — requiring
protoc + the tonic stack to build a dlopen helper is the concrete cost being
removed.

A second, proxy-side benefit: the loader becomes independently buildable and
testable, and `crates/backend` gets thinner.

## 2. Decision summary

| Decision | Choice | Rationale |
|---|---|---|
| New crate | `crates/module` in the `pkcs11-proxy-ng` workspace; package name **`pkcs11-module`** (subject to a crates.io availability check, see §9) | Repo-neutral name so a later relocation (own repo, crates.io) changes only the consumer's dependency *source* line, never `use` paths. Matches the family naming (`pkcs11-check`, `pkcs11-scope`, `pkcs11-lab`). Deliberately *not* `pkcs11-proxy-ng-module` (locks name to repo) and not `cryptoki-*` (that namespace on crates.io belongs to an unrelated project family; adjacency invites confusion) |
| Dependencies | `libloading`, `cryptoki-sys` — nothing else | No `types` dep: everything the loader needs from `types` turned out to be nothing (see §5). No tracing, no serde |
| What moves | `loading.rs` (verbatim, incl. version-fallback policy), `function_field_tables.rs`, `host_abi.rs` | §4 |
| What is new | `interface_list()` raw `C_GetInterfaceList` enumeration; `read_fn_pointers()`; `Abi` value type | §4, §6 |
| What stays in `backend` | `detect_interface_capabilities` (imports the moved tables), all 100+ `Pkcs11Backend` op implementations, `initialize_args`, session/mech caches | §5 |
| What stays in `types` | `width.rs` bridge, `is_ulong()`/`is_ulong_array()` classifier, mechanism registry, official name tables | §5 — scope consumes `types` as a second, independent git dep |
| Consumption model | git deps pinned to a rev/tag; all crates stay `publish = false` | Standalone repo / crates.io deferred until publishing pressure exists (settled in the parent spec) |
| Foreign ABIs | Detect and refuse; no cross-ABI layout computation in v1 | §6 |

## 3. Crate API surface (illustrative — exact signatures at implementation)

```rust
// package pkcs11-module, crates/module/src/

/// A dlopen'ed PKCS#11 module and its resolved function-list pointers.
/// Construction never calls C_Initialize; side effects are limited to the
/// module's own dlopen constructors.
pub struct LoadedModule {
    pub lib: libloading::Library,          // keeps the module mapped
    pub func_list: *mut CK_FUNCTION_LIST,
    pub func_list_3_0: Option<*const CK_FUNCTION_LIST_3_0>,
    pub func_list_3_2: Option<*const CK_FUNCTION_LIST_3_2>,
}

/// Proxy-semantics open: C_GetInterface preferred, C_GetFunctionList
/// fallback, plus the primary-interface version fallback (see §4).
/// Moved verbatim from backend's loading.rs.
pub fn open(path: &Path) -> Result<LoadedModule, String>;

/// Raw interface enumeration via C_GetInterfaceList (two-call pattern).
/// NEW code. Returns each interface exactly as the module reports it —
/// no version fallback, no de-duplication. Empty result for 2.40-only
/// modules (no C_GetInterfaceList export).
pub struct RawInterface {
    pub name: String,                      // copied from pInterfaceName
    pub version: CK_VERSION,               // leading field of pFunctionList
    pub flags: CK_FLAGS,
    pub func_list: *mut c_void,
}
pub fn interface_list(lib: &Library) -> Result<Vec<RawInterface>, String>;

/// (field name, byte offset) tables for the three function-list structs.
/// offset_of!-derived: valid for the COMPILATION TARGET's ABI only (§6).
pub static FUNCTION_LIST_FIELDS: &[FnField];          // 68 entries (v2.40)
pub static FUNCTION_LIST_3_0_EXTRA_FIELDS: &[FnField]; // +24
pub static FUNCTION_LIST_3_2_EXTRA_FIELDS: &[FnField]; // +12

/// Existing NULL-slot scan (moved) and its new sibling that returns the
/// pointer values themselves (for pointer→file-offset mapping in the
/// discover helper).
pub unsafe fn detect_null_functions(base: *const u8, fields: &[FnField]) -> Vec<String>;
pub unsafe fn read_fn_pointers(base: *const u8, fields: &[FnField])
    -> Vec<(&'static str, usize)>;

/// The build target's C-ABI properties relevant to PKCS#11 (moved from
/// backend/src/host_abi.rs, generalized from two free functions into a
/// value type so "detected but unsupported" is expressible).
pub struct Abi { pub ulong_width: u32, pub byte_order: ByteOrder }
impl Abi { pub fn host() -> Abi; }
```

Notes for reviewers:

- **No `unsafe impl Send/Sync` on `LoadedModule`.** `FfiBackend` keeps its
  own unsafe impls with the existing `CKF_OS_LOCKING_OK` justification —
  that argument is about how the *proxy* drives the module, and does not
  transfer to arbitrary consumers.
- Raw pointer fields are `pub` on purpose: the discover helper must hand
  them to `dladdr`/`dl_iterate_phdr`-based mapping code (scope-side; not
  this crate's business).
- ELF build-ID extraction, pointer→file-offset mapping, manifest JSON, and
  aliasing analysis all stay in `p11scope-discover`. This crate is
  deliberately only "dlopen + tables + self-ABI".

## 4. The two surfaces — why `open()` alone is not enough

`open()` carries the proxy's **version-fallback policy**: some real 3.x
modules answer an explicit versioned `C_GetInterface` query for `{3,0}` with
NULL even though their default 3.1+ interface implements the 3.0 functions.
The fallback reuses the *primary* table pointer for `func_list_3_0` in that
case. (Concrete provider: BouncyHSM; there is a regression test for it in
`loading.rs`. Without the fallback, 3.0-only dispatch such as
`C_SessionCancel` wrongly returns `CKR_FUNCTION_NOT_SUPPORTED` through the
proxy.)

For the proxy this is correct dispatch behavior. For the observer it is
**evidence poison**: if the discover helper read `func_list_3_0` off
`LoadedModule`, a fallback-resolved list is literally the same address as
the primary list, and the helper would report "aliased functions across
interfaces" — an artifact of proxy policy, not a property of the provider.
The scope design spec explicitly requires per-interface aliasing to be
reported as genuine ambiguity, so the input must be unprocessed.

Hence the split:

| Surface | Consumer | Semantics |
|---|---|---|
| `open()` | proxy backend | best-effort dispatch tables, quirk handling ON |
| `interface_list()` | discover helper | raw per-interface enumeration, no interpretation |

The discover helper uses `interface_list()` (plus `C_GetFunctionList` for
2.40-only modules) and **never** the fallback-resolved fields. This is the
one place where the extraction is more than a mechanical move, and it is the
main thing this document asks reviewers to sanity-check.

## 5. What deliberately does not move

- **`types/width.rs` (the CK_ULONG width/endianness bridge, ADR-0011).**
  Pure, zero-dep, runtime-parameterized by `(src_width, dst_width, order)`,
  ~15 call sites across shim and backend. It already lives in the
  dependency-lean `types` crate, which scope consumes anyway for the
  mechanism registry and official name tables. Moving it would churn call
  sites for zero benefit.
- **`types/attribute.rs` ulong classifier** — same reasoning.
- **`detect_interface_capabilities` / `InterfaceCapabilities`.** This is
  proxy *wire shape* (advertised to shims over gRPC). Moving it would drag
  a `types` dep into the crate for something the observer never emits. It
  stays in `backend` and imports the moved tables.
- **The `backend → proto` untangle.** `backend`'s only proto coupling is
  `proto::convert::message_params::MessageParameter` (used by the 3.x
  message-ops paths; proto's own comment already marks it as a future
  migration to `types`). None of that code is on the loading path; the
  cleanup is real but unrelated, and bundling it would grow this change's
  risk for no Phase 1 benefit.
- **A `types` split into "general PKCS#11" vs "proxy wire" crates, a
  standalone shared repo, crates.io publishing.** All deferred; the trigger
  for each is publishing pressure, which does not exist yet. The
  relocation-neutral crate name is what keeps these cheap later.

## 6. ABI analysis (the "compatibility layers" question)

ADR-0011 decomposes every C edge into two orthogonal axes:

1. **`CK_ULONG` width + byte order** — the only properties that cross a
   process/wire boundary. LP64 = (8, LE); ILP32 and LLP64/Windows-x64 are
   both (4, LE) for this axis.
2. **Pointer width + struct packing** — purely local to each edge's build;
   handled by cryptoki-sys's per-target pregenerated bindings (verified in
   cryptoki-sys 0.5.0: 13 targets; only `x86_64-pc-windows-msvc` and
   `generic` are `#[repr(C, packed)]`).

Consequences for this crate:

- **The `offset_of!` tables describe the compilation target's layout and
  nothing else.** They cannot be "keyed by ABI" to produce foreign layouts
  — `offset_of!` is a compile-time construct. An earlier draft of this
  proposal suggested an ABI-keyed `fields_for(abi)` API; that claim was
  wrong and is withdrawn. (A computed-layout generalization *is* possible
  for function lists specifically — every field after the leading
  `CK_VERSION` is a pointer, so `offset = base(abi) + i × ptr_width(abi)` —
  but it is real code with real tests, and no consumer needs it: v1 targets
  x86-64 Linux, and the first post-v1 target, AArch64 Linux, is also LP64.)
- **The tables are still sound for the discover helper by construction:**
  discovery dlopens the provider into the helper's own process, so helper
  ABI == provider ABI whenever dlopen succeeds. A class-mismatched provider
  (e.g. an i386 `.so` against the x86-64 helper) fails at `dlopen` with an
  ELF-class error and must be reported as *unsupported* — matching the
  parent spec's detect-and-refuse rule for 32-bit targets. Cross-machine
  manifest reuse is gated on ELF build-ID equality, and identical build-ID
  implies identical binary implies identical ABI, so the manifest schema
  needs no separate ABI field.
- **`Abi` ships as a value type, not machinery.** Its v1 job is to make
  "detected (4, LE), refusing" a first-class reportable state. `host()` is
  the moved `host_abi.rs` logic (`size_of::<CK_ULONG>()` +
  `cfg!(target_endian)`). The width *bridge* stays in `types/width.rs` and
  is not this crate's concern.

## 7. Migration mechanics in pkcs11-proxy-ng

Verified blast radius (grep evidence as of submodule `HEAD` at the time of
writing):

- Every private fn in `loading.rs` (`try_get_interface`,
  `resolve_get_interface`, `try_get_versioned_interface`,
  `primary_interface_fallback`, `get_interface_with_name`,
  `try_get_function_list`) has **zero call sites outside the file** and is
  already `self`-free (all take `&Library` or raw pointers). Only
  `load_with_init_args` constructs `FfiBackend`.
- `FfiBackend::load_with_init_args` external callers: `server/src/main.rs`,
  `server/tests/support/daemon.rs`. Signatures unchanged — it becomes a thin
  wrapper that calls `module::open()` and destructures `LoadedModule` into
  the existing fields. The ~217 `self.func_list*` references across the 12
  FFI op files are **untouched**.
- `detect_null_functions` users: `ffi/interface_caps.rs` only (import path
  change).
- `host_abi` users: `backend/src/traits.rs`, two call sites. Its module doc
  comment ("the only crate that links cryptoki-sys as a normal dependency")
  is stale — backend, server, and shim all do — and gets fixed in the move.

Same-commit checklist (proxy-ng contributor rules require refactors to land
whole, with scans updated):

1. Workspace `Cargo.toml` `members` += `crates/module`.
2. `scripts/oasis-coverage-inventory.py` — the function-field-table path
   (currently `crates/backend/src/ffi/function_field_tables.rs`) moves; the
   script and its generated evidence strings must follow.
3. `crates/server/tests/local_quality_gate_test.rs` — the XOF ABI-decision
   evidence assertion cites the same path; update in lockstep with (2).
4. `AGENTS.md` §13 architecture quick reference + `doc/architecture-overview.md`
   gain the new crate row (contributor rule: architectural changes ship with
   doc updates in the same change).
5. The BouncyHSM 3.0-fallback regression test moves with the code it tests
   (or stays in backend against the wrapper — implementer's choice; it must
   keep passing either way, env-gated as today).
6. New: an `interface_list()` test, env-gated on a 3.x module being present
   (SoftHSM2 2.6 is 2.40-only; kryoptic or BouncyHSM are suitable), plus a
   pure-Rust test that the two-call pattern handles count-only responses.
7. New crate inherits workspace lints/edition 2024/MSRV 1.88, is
   `publish = false`, and is added to the standalone-build verification
   (the submodule must keep passing `cargo fmt/check/test` from a fresh
   clone).

Commit order per the umbrella workspace rules: commit in the
`pkcs11-proxy-ng` submodule first, then bump the submodule pointer.

## 8. How `p11scope-discover` consumes it (context, not part of this change)

```toml
# pkcs11-scope/Cargo.toml (Phase 1, later change)
[dependencies]
pkcs11-module         = { git = "https://github.com/mingulov/pkcs11-proxy-ng", rev = "<pinned>" }
pkcs11-proxy-ng-types = { git = "https://github.com/mingulov/pkcs11-proxy-ng", rev = "<pinned>" }
```

Helper flow: `Library::new(path)` → `interface_list()` (3.x) and/or
`C_GetFunctionList` (2.40) → `read_fn_pointers()` per table →
`dladdr`/`dl_iterate_phdr` mapping to file offsets (scope-side) → manifest
JSON with build-ID (scope-side). Per-interface aliasing is *recorded*, never
resolved. The helper is built as glibc and musl **dynamic** binaries; the
crate must not assume glibc (libloading/dlopen is fine on musl-dynamic).

## 9. Open questions for review

1. **Crate name.** Is `pkcs11-module` acceptable, and is it free on
   crates.io? (Availability not yet checked — must be verified before the
   first commit that hardcodes the name. Alternative: `pkcs11-module-ffi`.)
2. **`interface_list()` error granularity.** Flat `Result<Vec<_>, String>`
   (matching `open()`'s current style) vs a small error enum. The proxy
   uses `String` errors throughout the loading path; the observer will want
   to record failures as evidence. Default: keep `String` for symmetry,
   revisit when the manifest schema lands.
3. **Where the BouncyHSM fallback test lives** (moved vs wrapper-level in
   backend). Cosmetic; see §7 item 5.

## 10. Risks

- **FFI move regression.** Mitigated by moving `loading.rs` verbatim (no
  logic edits), keeping `FfiBackend`'s public API identical, and the
  existing proxy test suite + BouncyHSM regression test.
- **Silent quality-gate drift** if the inventory script and gate test paths
  are not updated atomically — mitigated by the same-commit checklist and
  the gate test itself failing loudly on the stale path.
- **Name churn** if `pkcs11-module` proves unavailable — bounded by
  checking before the first commit (§9.1).
- **Scope creep** toward the `types` split / shared repo — explicitly
  deferred in §5; reviewers should push back on any implementation PR that
  drags those in.
