# Shared PKCS#11 module-loading crate — extraction design

**Date:** 2026-08-10
**Status:** Proposed — revision 2, incorporating external review round 1
(verdict: changes required; all five findings accepted, boundary narrowed per
the reviewer's counter-proposal). No code has been written.
**Scope of this doc:** the Phase 1 *cross-repo precursor* from the
[ROADMAP](../plans/ROADMAP.md): extracting the reusable module-FFI *facts*
(dlopen bootstrap + table enumeration + field-offset tables) from
`pkcs11-proxy-ng` into a lean crate that both the proxy and
`p11scope-discover` consume, plus two latent-bug fixes in the proxy's loading
path that the review surfaced. It does **not** cover the eBPF observer, the
manifest schema, or anything else in Phase 1.
**Parent docs:** [pkcs11-scope design](2026-08-10-pkcs11-scope-design.md)
("Shared decode core" decision row), ROADMAP Phase 1,
`pkcs11-proxy-ng/doc/adr/ADR-0011` (ABI axes).

---

## 1. Problem

`p11scope-discover` must dlopen a PKCS#11 provider, obtain **all** of its
function tables, and map the function pointers to ELF file offsets.
pkcs11-proxy-ng has production-hardened module-FFI code
(`crates/backend/src/ffi/loading.rs` + `ffi/function_field_tables.rs`). The
settled decision (scope design spec) is to reuse it, not duplicate it.

Reuse is blocked by a dependency chain, verified in the tree:

```
pkcs11-proxy-ng-backend  →  pkcs11-proxy-ng-proto  →  tonic/prost
                                     └─ build.rs runs tonic-prost-build
                                        → requires protoc in every build env
```

(CI installs `protobuf-compiler`; `crates/proto/build.rs` compiles three
`.proto` files.) The discover helper ships as glibc **and** musl *dynamic*
binaries copied into arbitrary target containers — requiring protoc + the
tonic stack to build a dlopen helper is the concrete cost being removed.

## 2. Decision summary

| Decision | Choice | Rationale |
|---|---|---|
| New crate | `crates/module` in the `pkcs11-proxy-ng` workspace; package name **`pkcs11-module`** (confirmed unregistered on crates.io at review time; availability is in any case non-blocking for a `publish = false` git dependency) | Repo-neutral name so a later relocation changes only the consumer's dependency *source* line. Matches family naming (`pkcs11-check`, `pkcs11-scope`, `pkcs11-lab`). Not `cryptoki-*` (unrelated project family owns that crates.io namespace) |
| Dependencies | `libloading`, `cryptoki-sys` — nothing else | No `types`, no tracing, no serde |
| Boundary principle | **Facts move; policy stays.** The crate holds only operations with two consumers or that are provider-fact extraction; the proxy's interface-selection *policy* (version fallback, quirk handling) stays in `backend` | Review round 1: the earlier "move `open()` verbatim" plan was invalidated by findings 1 and 4 — the loading path needs edits either way, so single-home-for-loading no longer justified exporting proxy policy |
| What moves | `try_get_function_list` (as public `function_list()`), the three field-offset tables, `detect_null_functions` + new `read_fn_pointers` (both switched to unaligned reads) | §3 |
| What is new | `interface_list()` — hardened raw `C_GetInterfaceList` enumeration with a deterministic test seam | §3, §5 |
| What stays in `backend` | `loading.rs` policy (`C_GetInterface` machinery, version fallback, `load_with_init_args`) with two fixes (§6); `host_abi.rs`; `detect_interface_capabilities`; all op implementations | §4 |
| What stays in `types` | `width.rs` bridge, ulong classifier, mechanism registry, official name tables | Scope consumes `types` as a second, independent git dep |
| Errors | `Result<_, String>`, matching the existing loading path | Revisit if/when the manifest schema wants structured evidence; not now |
| Foreign ABIs | Detect and refuse at `dlopen` (ELF-class mismatch fails there); **no `Abi`/`ByteOrder` abstraction in v1** | The earlier draft's `Abi` value type was speculative; v1 is x86-64-Linux-only and the dlopen error is the refusal evidence. `host_abi.rs` (proxy wire advertisement) stays in backend; its stale module comment gets fixed in place |

## 3. Crate API surface (illustrative — exact signatures at implementation)

```rust
// package pkcs11-module, crates/module/src/

/// Resolve the legacy 2.40 entry point and return its table.
/// Moved from backend's try_get_function_list, made a free fn.
/// Never calls C_Initialize (spec: C_GetFunctionList/C_GetInterfaceList/
/// C_GetInterface are the only pre-initialize calls).
pub fn function_list(lib: &Library) -> Result<*mut CK_FUNCTION_LIST, String>;

/// One interface exactly as the module reported it. Nothing is resolved,
/// deduplicated, or reinterpreted; NULL fields are preserved as evidence.
pub struct RawInterface {
    pub name: Option<Vec<u8>>,       // bytes of pInterfaceName; None if NULL
    pub version: Option<CK_VERSION>, // leading field of pFunctionList; None if that is NULL
    pub flags: CK_FLAGS,
    pub func_list: *mut c_void,      // may be NULL — preserved, never deref'd then
}

impl RawInterface {
    /// Exact-match test against the standard interface name b"PKCS 11".
    /// Callers MUST NOT walk the standard field tables over an interface
    /// for which this is false (vendor layouts are unrelated; only the
    /// leading CK_VERSION is guaranteed by the spec).
    pub fn is_standard(&self) -> bool;
}

/// Raw C_GetInterfaceList enumeration (two-call pattern), hardened per §5.
/// Empty Vec for modules that do not export C_GetInterfaceList.
pub fn interface_list(lib: &Library) -> Result<Vec<RawInterface>, String>;

// Deterministic-test seam: the public fn resolves the symbol and delegates
// to the pure driver, which is what the unit tests exercise.
fn interface_list_impl(
    get_list: impl FnMut(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV,
) -> Result<Vec<RawInterface>, String>;

/// (field name, byte offset) tables for the three function-list structs.
/// offset_of!-derived: valid for the COMPILATION TARGET's ABI only (§7).
pub static FUNCTION_LIST_FIELDS: &[FnField];           // 68 entries (v2.40)
pub static FUNCTION_LIST_3_0_EXTRA_FIELDS: &[FnField]; // +24
pub static FUNCTION_LIST_3_2_EXTRA_FIELDS: &[FnField]; // +12

/// NULL-slot scan (moved) and pointer-value reader (new sibling, for the
/// helper's pointer→file-offset mapping). BOTH use read_unaligned: on the
/// packed Windows-MSVC cryptoki-sys bindings, function-pointer fields start
/// at offset 2 (after CK_VERSION) and an aligned read is UB. (Fixes a
/// latent-UB bug in the current detect_null_functions; free on x86-64.)
pub unsafe fn detect_null_functions(base: *const u8, fields: &[FnField]) -> Vec<String>;
pub unsafe fn read_fn_pointers(base: *const u8, fields: &[FnField])
    -> Vec<(&'static str, usize)>;
```

Notes for reviewers:

- There is deliberately **no `open()`, no `LoadedModule`, no Send/Sync
  assertion, and no C_GetInterface wrapper** in the crate. Interface
  *selection* is proxy policy and stays in `backend` (§4). The crate never
  interprets what it enumerates.
- ELF build-ID extraction, pointer→file-offset mapping (`dladdr` /
  `dl_iterate_phdr`), manifest JSON, and aliasing analysis stay in
  `p11scope-discover`.
- Version read (`RawInterface.version`) dereferences the leading
  `CK_VERSION` of a non-NULL `func_list` only — guaranteed by the spec for
  vendor and standard interfaces alike; nothing beyond those two bytes is
  read unless `is_standard()`.

## 4. Boundary rationale: facts vs policy

The proxy's `loading.rs` contains a **version-fallback policy**: some real
3.x modules answer an explicit versioned `C_GetInterface` query for `{3,0}`
with NULL even though their default 3.1+ interface implements the 3.0
functions (concrete provider: BouncyHSM; regression test in `loading.rs`).
The fallback reuses the *primary* table pointer for `func_list_3_0`.

For proxy dispatch this is correct. For the observer it is **evidence
poison**: a fallback-resolved list is literally the same address as the
primary list, so consuming it would report "aliased functions across
interfaces" as provider fact when it is proxy policy. Keeping the policy in
`backend` makes the hazard unrepresentable: the crate's only enumeration
output is the module's own answers, and the discover helper cannot reach the
fallback at all.

This also keeps the BouncyHSM regression test where it lives today
(resolving an open question from revision 1).

## 5. `interface_list()` contract (review finding: must be deterministic-testable)

Two-call pattern with the following hardening, all exercised through the
`interface_list_impl` seam with closure-simulated providers — an optional
real-provider test alone is insufficient:

1. **Bounded retry.** First call (NULL buffer) yields a count; allocate;
   second call may return `CKR_BUFFER_TOO_SMALL` if the count grew. Retry
   the whole sequence, **3 attempts total**, then error.
2. **Checked count handling.** `CK_ULONG → usize` via checked conversion;
   allocation capped (256 interfaces — real providers report a handful; a
   garbage count must not drive allocation).
3. **Capacity overrun rejected.** If the second call returns
   `CKR_OK` with a count exceeding the supplied capacity, error out —
   never read past the allocation.
4. **NULL preservation.** NULL `pInterfaceName` → `name: None`; NULL
   `pFunctionList` → entry kept with `version: None`, pointer preserved,
   nothing dereferenced. Malformed entries are *evidence*, not panics.
5. **Zero interfaces** is a valid result (`Ok(vec![])`), distinct from
   "symbol absent" only in that both return an empty Vec — the helper
   records which case occurred via its own symbol probe if needed.

Deterministic test matrix (pure Rust, no provider): count growth converging
on attempt 2; count growth never converging (error after 3); absurd count
(cap → error); `CKR_OK` with count > capacity (error); NULL name; NULL
function list; zero interfaces; vendor-named interface passes through with
`is_standard() == false`.

## 6. Two latent bugs fixed in `backend` during extraction

Both were found by external review of this design; both are in the loading
path that stays behind, and both ship in the extraction change with tests.

**6a. Default-interface name validation (spec conformance).**
`C_GetInterface(NULL, NULL, …)` returns "a default interface of its choice"
(OASIS general-purpose functions, verified in the vendored spec) — nothing
restricts it to the standard interface, and a vendor interface's function
list has no guaranteed layout beyond the leading `CK_VERSION`. The current
`try_get_interface` makes exactly that unnamed request and discards
`pInterfaceName`, so a module whose default interface is vendor-defined
would be table-walked as if it were `CK_FUNCTION_LIST`. New selection order:

1. named query for the standard interface (`C_GetInterface(b"PKCS 11", NULL, …)`);
2. unnamed query, **accepted only if** the returned `pInterfaceName` is
   exactly `"PKCS 11"` (covers providers that only answer unnamed forms —
   the BouncyHSM class of quirk);
3. `C_GetFunctionList`.

This is a deliberate behavior change (a conformance bug fix). Gate: the
existing proxy test suite plus a pooled provider-matrix run (SoftHSM2
baseline at minimum) before merge; a pure unit test covers the name
comparison itself.

**6b. Fallback provenance (unsound flag derivation).**
`loading.rs` sets `primary_from_interface` from *symbol existence*
(`resolve_get_interface(&lib).is_some()`) **before** the query runs. If
`C_GetInterface` exists but its query fails and loading falls back to
`C_GetFunctionList`, the base-size table is still flagged interface-derived
— and `primary_interface_fallback` may then reuse it as a 3.0/3.2 list,
which the existing regression test
(`primary_fallback_ignores_c_get_function_list_version_3_x`) documents as
unsound but cannot reach (it passes the flag manually). Fix by deriving the
flag from the branch that produced the pointer:

```rust
let (func_list, primary_from_interface) = match Self::try_get_interface(&lib) {
    Ok(fl) => (fl, true),
    Err(_) => (Self::try_get_function_list(&lib)?, false),
};
```

Correct by construction; the existing test continues to cover the
downstream gating.

## 7. ABI analysis

ADR-0011 decomposes every C edge into two orthogonal axes: (1) `CK_ULONG`
width + byte order — the only properties that cross a boundary; (2) pointer
width + struct packing — purely local, handled by cryptoki-sys's per-target
pregenerated bindings (verified in 0.5.0: 13 targets; only
`x86_64-pc-windows-msvc` and `generic` are `#[repr(C, packed)]`).

Consequences:

- **The `offset_of!` tables describe the compilation target only.** They
  cannot be keyed by a foreign ABI (an earlier draft suggested that; the
  claim was wrong and is withdrawn). This is sound for the discover helper
  *by construction*: discovery dlopens the provider into the helper's own
  process, so helper ABI == provider ABI whenever dlopen succeeds. A
  class-mismatched provider fails at `dlopen` and is reported as
  unsupported — matching the parent spec's detect-and-refuse rule. No
  `Abi` value type is introduced for this; the dlopen failure is the
  refusal.
- **Manifest reuse needs no ABI field**: it is gated on ELF build-ID
  equality, and identical build-ID ⇒ identical binary ⇒ identical ABI.
- **Unaligned reads** (§3) are the one packed-target correctness item in
  the moved code; fixed in the move.

## 8. Migration mechanics in pkcs11-proxy-ng

Verified blast radius:

- `try_get_function_list`: no callers outside `loading.rs`; its body moves
  to the crate, `loading.rs` calls `pkcs11_module::function_list()`.
- Field tables / `detect_null_functions`: only consumer is
  `ffi/interface_caps.rs` (import-path change).
- `FfiBackend::load_with_init_args` external callers (`server/src/main.rs`,
  `server/tests/support/daemon.rs`): signature unchanged. The ~217
  `self.func_list*` references across the 12 FFI op files: untouched.
- `host_abi.rs`: does not move; its stale module comment ("the only crate
  that links cryptoki-sys as a normal dependency" — backend, server, and
  shim all do) is corrected in place.

Same-commit checklist (proxy contributor rules: refactors land whole, scans
updated):

1. Workspace `Cargo.toml` `members` += `crates/module`; crate inherits
   edition 2024 / MSRV 1.88 / lints; `publish = false`.
2. `scripts/oasis-coverage-inventory.py` — function-field-table path
   follows the move.
3. `crates/server/tests/local_quality_gate_test.rs` — XOF ABI-decision
   evidence path updated in lockstep with (2).
4. `AGENTS.md` §13 + `doc/architecture-overview.md` gain the new crate row.
   **Pre-existing condition:** the proxy tree currently carries an
   uncommitted, unrelated refresh of `doc/architecture-overview.md`; it
   must be committed or dropped before this change touches the same file.
5. §6a + §6b fixes with their tests (unit-level name comparison;
   existing BouncyHSM + fallback-gating regression tests stay in backend
   and keep passing; provider-matrix gate for §6a).
6. `interface_list()` deterministic test matrix (§5) + an env-gated
   real-provider test against a 3.x module (SoftHSM2 2.6 is 2.40-only;
   kryoptic or BouncyHSM are suitable).
7. Standalone-build verification: the submodule keeps passing
   `cargo fmt/check/test` from a fresh clone, now including the new crate.

Commit order per umbrella rules: submodule first, then pointer bump.

## 9. How `p11scope-discover` consumes it (context, not part of this change)

```toml
# pkcs11-scope/Cargo.toml (Phase 1, later change)
[dependencies]
pkcs11-module         = { git = "https://github.com/mingulov/pkcs11-proxy-ng", rev = "<pinned>" }
pkcs11-proxy-ng-types = { git = "https://github.com/mingulov/pkcs11-proxy-ng", rev = "<pinned>" }
```

Helper flow — **both surfaces, always, regardless of module generation**
(review finding: a third-party app may call through the legacy 2.40 table a
3.x provider also exports, and its pointers are not guaranteed identical to
any listed interface; collecting only interfaces can yield zero capture
reported as complete):

1. `Library::new(path)`;
2. `function_list()` → the legacy table (present on virtually every module);
3. `interface_list()` → every reported interface, standard or not;
4. table-walk (`read_fn_pointers`) **only** surfaces that are the legacy
   table or `is_standard()` interfaces; vendor interfaces are recorded in
   the manifest as *present-but-undecoded* evidence, never walked;
5. pointer→file-offset mapping via `dladdr`/`dl_iterate_phdr` (scope-side);
6. manifest records each probe target's **provenance** (legacy table vs
   named interface + version) and cross-surface pointer aliasing as
   observed — the union is probed; aliases are reported as ambiguity, never
   resolved to one name.

The helper builds as glibc and musl **dynamic** binaries; the crate must not
assume glibc (libloading/dlopen is fine on musl-dynamic).

## 10. Alternative evaluated: `cryptoki_sys::Pkcs11` (bindgen dynamic loader)

cryptoki-sys ships a generated `Pkcs11` struct (`Pkcs11::new(path)`) that
dlsym-loads every `C_*` symbol for symbol-based dispatch. Rejected:

- Symbol-based dispatch is exactly the surface **stripped providers do not
  export** — the tool's core premise (and the proxy's) is table-based
  discovery via the three bootstrap entry points;
- `from_library` consumes the `Library`, which the helper still needs for
  pointer→offset mapping, and attempts ~200 dlsym calls that are pure noise
  against a stripped module;
- The only thing it would replace is the ~10-line bootstrap dlsym that
  `function_list()` already is; it provides neither table walking nor the
  hardened `C_GetInterfaceList` enumeration.

## 11. Resolved questions (from revision 1 review)

1. **Crate name** — `pkcs11-module`; confirmed unregistered at review time;
   availability non-blocking for a git dep.
2. **Error granularity** — `String` for v1.
3. **BouncyHSM test placement** — stays in `backend`, where the fallback
   policy now stays.

## 12. Risks

- **§6a is a behavior change** in provider selection, mitigated by the
  named→validated-unnamed→legacy order (strictly widens conformance, keeps
  quirk tolerance) and gated on the provider-matrix run.
- **Silent quality-gate drift** if inventory script and gate test paths are
  not updated atomically — mitigated by the same-commit checklist and the
  gate test failing loudly.
- **Scope creep** toward moving policy, a `types` split, or a shared repo —
  all explicitly out; reviewers should push back on any implementation PR
  that drags them in.
- **The uncommitted `doc/architecture-overview.md` refresh** in the proxy
  tree must land or be dropped first (§8 item 4) or the extraction commit
  will entangle unrelated content.
