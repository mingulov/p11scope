# Shared PKCS#11 module-loading crate — extraction design

**Date:** 2026-08-10
**Status:** Proposed — revision 3, incorporating external review rounds 1–2
(round 2 verdict: changes required; all four findings accepted). No code has
been written.
**Scope of this doc:** the Phase 1 *cross-repo precursor* from the
[ROADMAP](../plans/ROADMAP.md): extracting the reusable module-FFI *facts*
(dlopen bootstrap + table enumeration + field-offset tables + layout
selection) from `pkcs11-proxy-ng` into a lean crate that both the proxy and
`p11scope-discover` consume, plus latent-bug fixes in the proxy's loading
path that the reviews surfaced. It does **not** cover the eBPF observer, the
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
settled decision (scope design spec) is to reuse it, not duplicate it —
FFI duplication looks cheap initially but creates two subtly different
implementations exactly where drift is most dangerous.

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
| New crate | `crates/module` in the `pkcs11-proxy-ng` workspace; package name **`pkcs11-module`** (confirmed unregistered on crates.io in both review rounds; availability is in any case non-blocking for a `publish = false` git dependency) | Repo-neutral name so a later relocation changes only the consumer's dependency *source* line. Matches family naming. Not `cryptoki-*` (unrelated project family owns that crates.io namespace) |
| Dependencies | `libloading`, `cryptoki-sys` — nothing else | No `types`, no tracing, no serde |
| Boundary principle | **Facts move; policy stays.** Crate = raw table acquisition + layout facts; `backend` = interface-selection policy (version fallback, quirks); `p11scope-discover` = evidence policy (pointer mapping, provenance/alias analysis, manifest) | Review round 1; reaffirmed round 2. Consumers genuinely need different semantics on top of the same facts |
| What moves | `try_get_function_list` (as public `function_list()`), the three field-offset tables, `detect_null_functions` + new `read_fn_pointers` (both unaligned-safe) | §3 |
| What is new | `interface_list()` (hardened, deterministic-testable); `tables_for()` — the single provenance/version → walkable-tables authority | §3, §5, §7 |
| What stays in `backend` | `loading.rs` policy (`C_GetInterface` machinery, version fallback, `load_with_init_args`) with the §6 fixes; `host_abi.rs`; `detect_interface_capabilities`; all op implementations | §4 |
| What stays in `types` | `width.rs` bridge, ulong classifier, mechanism registry, official name tables | Scope consumes `types` as a second, independent git dep |
| Errors | `Result<_, String>` | Revisit when the manifest schema wants structured evidence |
| Foreign ABIs | Detect and refuse at `dlopen` (ELF-class mismatch fails there); no `Abi` abstraction in v1 | v1 is x86-64-Linux-only; the dlopen error is the refusal evidence |
| Placement | **In the proxy workspace, indefinitely** — including if the two products stay separate. Revisit triggers in §13 | A pinned git rev already gives scope full release independence; the workspace groups crates without forcing consumers to build siblings — Cargo compiles only `pkcs11-module` + its two deps for scope, never backend/tonic/prost/protoc |

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
    pub fn is_standard(&self) -> bool;
}

/// Raw C_GetInterfaceList enumeration (two-call pattern), hardened per §5.
///   Ok(None)          — module does not export C_GetInterfaceList
///   Ok(Some(vec![]))  — export present, zero interfaces reported
/// These are distinct provider facts for an evidence tool and must not be
/// conflated (review round 2, finding 4); the helper never repeats the
/// symbol probe.
pub fn interface_list(lib: &Library) -> Result<Option<Vec<RawInterface>>, String>;

// Deterministic-test seam: the public fn resolves the symbol and delegates
// to the pure driver, which is what the unit tests exercise.
fn interface_list_impl(
    get_list: impl FnMut(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV,
) -> Result<Vec<RawInterface>, String>;

/// (field name, byte offset) tables for the three function-list structs.
/// offset_of!-derived: valid for the COMPILATION TARGET's ABI only (§8).
pub static FUNCTION_LIST_FIELDS: &[FnField];           // 68 entries (v2.40)
pub static FUNCTION_LIST_3_0_EXTRA_FIELDS: &[FnField]; // +24
pub static FUNCTION_LIST_3_2_EXTRA_FIELDS: &[FnField]; // +12

/// The single authority binding provenance + reported version to the set
/// of field tables that may be walked over that surface (§7). Pure;
/// exhaustively unit-tested; both consumers use it rather than selecting
/// tables ad hoc.
pub enum Surface {
    LegacyFunctionList,                      // from C_GetFunctionList
    StandardInterface { version: CK_VERSION }, // is_standard() == true only
}
pub enum TableSet {
    Walk(&'static [&'static [FnField]]),        // tables, in walk order
    WalkKnownPrefix(&'static [&'static [FnField]]), // 3.x minor > 2: prefix
                                                // is safe; excess recorded
    Refuse,                                     // unknown major — record, no walk
}
pub fn tables_for(surface: Surface) -> TableSet;

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
  assertion, and no `C_GetInterface` wrapper** in the crate. Interface
  *selection* is proxy policy and stays in `backend` (§4). The crate never
  interprets what it enumerates — except `tables_for()`, which encodes the
  one interpretation both consumers must share: what is safe to read.
- ELF build-ID extraction, pointer→file-offset mapping (`dladdr` /
  `dl_iterate_phdr`), provenance/alias analysis, and manifest JSON stay in
  `p11scope-discover`.
- `RawInterface.version` dereferences the leading `CK_VERSION` of a
  non-NULL `func_list` only — the spec guarantees that field for vendor and
  standard interfaces alike; nothing beyond those two bytes is read except
  through `tables_for()`.

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
output is the module's own answers, and the discover helper cannot reach
the fallback at all.

The resulting three-layer split:

```
pkcs11-module              shared facts
├── function_list()          raw C_GetFunctionList
├── interface_list()         raw C_GetInterfaceList
├── field tables             offset_of!-derived
├── tables_for()             provenance/version → walkable tables
└── unaligned-safe readers

pkcs11-proxy-ng/backend    proxy-only policy
├── interface selection      named → validated unnamed → legacy (§6a)
├── provider quirks          BouncyHSM-class fallbacks
└── version fallback         + provenance fix (§6b)

p11scope-discover          scope-only policy
├── ELF pointer mapping      dladdr / dl_iterate_phdr / build-ID
├── provenance/alias         evidence, never resolution
└── manifest generation      versioned JSON
```

## 5. `interface_list()` contract

Two-call pattern with the following hardening, all exercised through the
`interface_list_impl` seam with closure-simulated providers — an optional
real-provider test alone is insufficient:

1. **Bounded retry.** First call (NULL buffer) yields a count; allocate;
   second call may return `CKR_BUFFER_TOO_SMALL` if the count grew. Retry
   the whole sequence, **3 attempts total**, then error.
2. **Checked count handling.** `CK_ULONG → usize` via checked conversion;
   allocation capped (256 interfaces — real providers report a handful; a
   garbage count must not drive allocation).
3. **Capacity overrun rejected.** If the second call returns `CKR_OK` with
   a count exceeding the supplied capacity, error out — never read past
   the allocation.
4. **NULL preservation.** NULL `pInterfaceName` → `name: None`; NULL
   `pFunctionList` → entry kept with `version: None`, pointer preserved,
   nothing dereferenced. Malformed entries are *evidence*, not panics.
5. **Absent symbol vs zero interfaces are distinct facts:** `Ok(None)` vs
   `Ok(Some(vec![]))` (§3).

Deterministic test matrix (pure Rust, no provider): symbol absent (`None`);
zero interfaces (`Some(empty)`); count growth converging on attempt 2;
count growth never converging (error after 3); absurd count (cap → error);
`CKR_OK` with count > capacity (error); NULL name; NULL function list;
vendor-named interface passes through with `is_standard() == false`.

## 6. Proxy loading-path fixes landing with the extraction

Both reviews found latent bugs in the code that stays behind; the fixes
ship in the extraction change with deterministic tests. To make the tests
deterministic, the selection order is restructured as a pure driver over
closure-injected query primitives (the same seam pattern as
`interface_list_impl`); the FFI boundary resolves symbols and delegates.

**6a. Name validation for every unnamed `C_GetInterface` result.**
OASIS clause 1 applies to *any* unnamed query — primary **or versioned**:
"If pInterfaceName is NULL_PTR, the cryptoki library can return a default
interface of its choice" (subject to the version/flags filters). The
current code has two unvalidated unnamed paths:

- the primary default query (`try_get_interface`), and
- the **versioned unnamed fallback** (`get_interface_with_name` with
  `use_name = false` — the BouncyHSM path), whose returned pointer is cast
  to `CK_FUNCTION_LIST_3_0`/`_3_2` (round 2, finding 1).

A vendor interface of matching version could therefore be walked as a
standard 3.x table. Fix — one rule, no exceptions: **every `CK_INTERFACE`
obtained from an unnamed query is accepted only if its `pInterfaceName` is
exactly `"PKCS 11"`.** Selection order for the primary list becomes:

1. named standard query (`C_GetInterface(b"PKCS 11", NULL, …)`);
2. unnamed query, accepted only under the name rule;
3. `C_GetFunctionList`.

The versioned fallback keeps its named→unnamed order and applies the same
name rule to the unnamed result. If a provider's unnamed versioned response
were vendor-named, rejection is correct even though it may shrink dispatch
surface — soundness over coverage; the provider-matrix gate catches any
real-provider regression.

**6b. Fallback provenance derived from the producing branch.**
`loading.rs` sets `primary_from_interface` from *symbol existence* before
the query runs; a module whose `C_GetInterface` exists but fails the query
gets its `C_GetFunctionList` base pointer flagged interface-derived, which
`primary_interface_fallback` may then reuse as a 3.0/3.2 list — the exact
unsoundness the existing regression test documents but cannot reach. Fix:

```rust
let (func_list, primary_from_interface) = match Self::try_get_interface(&lib) {
    Ok(fl) => (fl, true),
    Err(_) => (Self::try_get_function_list(&lib)?, false),
};
```

**Deterministic selection tests (round 2, finding 3)** — via the driver
seam, covering the root branches, not only the downstream gating:

- `C_GetInterface` present but failing + `C_GetFunctionList` succeeding →
  `primary_from_interface == false`;
- named query fails → unnamed returns a **vendor** interface → rejected,
  falls through to legacy;
- named query fails → unnamed returns a **standard** interface → accepted;
- (existing) `primary_fallback_ignores_c_get_function_list_version_3_x`
  and the env-gated BouncyHSM regression test continue to pass in backend.

**6a is a deliberate behavior change** (a conformance bug fix), gated on
the proxy test suite plus a pooled provider-matrix run (SoftHSM2 baseline
at minimum) before merge.

## 7. Table-selection invariant (round 2, finding 2)

Which field tables may be walked over a surface is bound to **provenance
and validated version**, never to what a table's own bytes claim. Pinned:

| Surface (provenance) | Reported version | Tables walked |
|---|---|---|
| `C_GetFunctionList` (legacy) | *any* — including a 3.x or malformed claim | base `FUNCTION_LIST_FIELDS` **only** (a legacy pointer is only known to be base-size; same principle as the existing proxy regression test) |
| Standard interface (`is_standard()`) | 2.x | base |
| Standard interface | 3.0 / 3.1 | base + 3.0 extras |
| Standard interface | 3.2 | base + 3.0 + 3.2 extras |
| Standard interface | 3.minor > 2 | base + 3.0 + 3.2 as **known prefix**; the surface is recorded as beyond-known-layout evidence |
| Standard interface | major ∉ {2, 3} | **refuse** — recorded as unknown-version evidence, nothing walked |
| Vendor interface (`!is_standard()`) | any | **refuse** — present-but-undecoded evidence |
| NULL `func_list` | — | nothing (already unreachable via `tables_for`) |

`tables_for()` (§3) is the single implementation of this table, in the
shared crate, exhaustively unit-tested (every row plus boundary versions
2.40/3.0/3.1/3.2/3.3/4.0). Both consumers go through it: the discover
helper for every walked surface; `backend`'s `detect_interface_capabilities`
conforms today by construction (its 3.x lists come from validated versioned
queries after §6a) and adopts `tables_for()` in the move so the invariant
has one home.

Without this contract, the unsafe readers can be handed a base-size table
with an extended field list — reading past the end of the provider's
static data.

## 8. ABI analysis

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
  unsupported — matching the parent spec's detect-and-refuse rule.
- **Manifest reuse needs no ABI field**: it is gated on ELF build-ID
  equality, and identical build-ID ⇒ identical binary ⇒ identical ABI.
- **Unaligned reads** (§3) are the one packed-target correctness item in
  the moved code; fixed in the move.

## 9. Migration mechanics in pkcs11-proxy-ng

Verified blast radius:

- `try_get_function_list`: no callers outside `loading.rs`; its body moves
  to the crate, `loading.rs` calls `pkcs11_module::function_list()`.
- Field tables / `detect_null_functions`: only consumer is
  `ffi/interface_caps.rs` (import-path change + `tables_for()` adoption).
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
   **Precondition:** the proxy tree's pre-existing uncommitted
   `doc/architecture-overview.md` refresh is **committed separately first**
   (review round 2 verified its content against the dev tree: legitimate
   stale-doc cleanup, the proxy's only dirty file — commit, don't drop).
5. §6a + §6b fixes with the deterministic selection tests (§6) and the
   provider-matrix gate for §6a.
6. `interface_list()` deterministic test matrix (§5) + `tables_for()`
   exhaustive row tests (§7) + an env-gated real-provider test against a
   3.x module (SoftHSM2 2.6 is 2.40-only; kryoptic or BouncyHSM suit).
7. Standalone-build verification: the submodule keeps passing
   `cargo fmt/check/test` from a fresh clone, now including the new crate.

Commit order per umbrella rules: submodule first, then pointer bump.

## 10. How `p11scope-discover` consumes it (context, not part of this change)

```toml
# pkcs11-scope/Cargo.toml (Phase 1, later change)
[dependencies]
pkcs11-module         = { git = "https://github.com/mingulov/pkcs11-proxy-ng", rev = "<pinned>" }
pkcs11-proxy-ng-types = { git = "https://github.com/mingulov/pkcs11-proxy-ng", rev = "<pinned>" }
```

Helper flow — **both surfaces, always, regardless of module generation** (a
third-party app may call through the legacy 2.40 table a 3.x provider also
exports; its pointers are not guaranteed identical to any listed
interface):

1. `Library::new(path)`;
2. `function_list()` → the legacy table;
3. `interface_list()` → `None` (no export — recorded as a 2.40-only module
   fact) or every reported interface, standard or not;
4. for each surface, `tables_for(surface)` decides what is walked
   (`read_fn_pointers`) — legacy → base only; standard interfaces → per
   validated version; vendor / unknown-major / beyond-known-prefix →
   recorded evidence, not walked (§7);
5. pointer→file-offset mapping via `dladdr`/`dl_iterate_phdr` (scope-side);
6. manifest records each probe target's **provenance** (legacy table vs
   named interface + version) and cross-surface pointer aliasing as
   observed — the union is probed; aliases are reported as ambiguity,
   never resolved to one name.

The helper builds as glibc and musl **dynamic** binaries; the crate must
not assume glibc (libloading/dlopen is fine on musl-dynamic).

## 11. Alternative evaluated: `cryptoki_sys::Pkcs11` (bindgen dynamic loader)

cryptoki-sys ships a generated `Pkcs11` struct (`Pkcs11::new(path)`) that
performs **104 dlsym lookups** (one per declared `C_*` function, each
stored as a per-symbol `Result`) and **takes ownership of the `Library`**
(kept alive in a private field — the mapping survives, but the handle is no
longer separately usable). Rejected because: it changes ownership of the
handle the helper needs for its own resolution; the 104 lookups are
unnecessary for table-based discovery (against a stripped provider all but
the bootstrap entries are misses by design); and it provides neither
hardened enumeration nor table walking — the only thing it would replace is
the ~10-line bootstrap dlsym that `function_list()` already is.

## 12. Resolved questions

1. **Crate name** — `pkcs11-module`; confirmed unregistered in both review
   rounds; availability non-blocking for a git dep.
2. **Error granularity** — `String` for v1.
3. **BouncyHSM test placement** — stays in `backend`, where the fallback
   policy stays.
4. **Selection order** — named → validated unnamed → legacy, confirmed by
   review round 2.

## 13. Placement decision (products stay separate; crate stays in-workspace)

Recorded owner intent: `pkcs11-scope` and `pkcs11-proxy-ng` remain separate
products (internal for now), with a preference for keeping them separated.
This is **compatible with the crate living in the proxy workspace**: a
pinned git rev already gives scope full release independence — it upgrades
deliberately, and proxy releases never propagate implicitly. A workspace
groups crates for development; it does not force consumers to build
siblings (scope's build compiles `pkcs11-module` + libloading +
cryptoki-sys, nothing else).

Lift `pkcs11-module` (alone — not `types`, not a "core" bundle) into its
own repository only when one of these becomes real:

1. **crates.io publishing** of any consumer that depends on it (git deps
   cannot be published);
2. **scope-driven churn**: changes to `pkcs11-module` needed by scope start
   requiring frequent proxy-side commits/reviews that the proxy does not
   otherwise want (as a gauge: more than ~quarterly);
3. **a consumer outside the two products** appears (`pkcs11-lab` is Python
   and consumes JSON, so it does not count).

The repo-neutral crate name makes the lift a dependency-source-line change
for consumers, with no `use`-path churn.

## 14. Risks

- **§6a is a behavior change** in provider selection, mitigated by the
  named→validated-unnamed→legacy order (widens conformance, keeps quirk
  tolerance) and gated on the provider-matrix run.
- **Silent quality-gate drift** if inventory script and gate test paths are
  not updated atomically — mitigated by the same-commit checklist and the
  gate test failing loudly.
- **Scope creep** toward moving policy, a `types` split, or a shared repo —
  all explicitly out; reviewers should push back on any implementation PR
  that drags them in.
- **The uncommitted `doc/architecture-overview.md` refresh** must be
  committed separately before the extraction touches the same file (§9
  item 4; content verified legitimate by review round 2).
