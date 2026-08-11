# pkcs11-module Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the module-FFI *facts* from `pkcs11-proxy-ng/crates/backend`
into a new `pkcs11-module` crate (per the approved spec
`docs/superpowers/specs/2026-08-10-module-crate-extraction-design.md`), land
the two loading-path bug fixes (§6a name validation, §6b provenance), and
update every scan/doc that cites moved paths.

**Architecture:** Facts move, policy stays. New crate `crates/module` (package
`pkcs11-module`) holds raw `C_GetFunctionList`/`C_GetInterfaceList`
acquisition, the function-list field-offset tables, the `tables_for()`
layout-selection authority, and unaligned-safe readers. `backend/src/ffi/loading.rs`
keeps interface-selection policy, restructured as a pure driver over
closure-injected query primitives so its branches are deterministically
testable.

**Tech Stack:** Rust (edition 2024, MSRV 1.88), libloading 0.8, cryptoki-sys 0.5.

## Global Constraints

- Implementation repo: `/home/user/src/m/pkcs11-proxy-ng-ws/pkcs11-proxy-ng`
  (the submodule). **All cargo/git commands run there unless a step says
  otherwise.** The umbrella repo is `/home/user/src/m/pkcs11-proxy-ng-ws`.
- Commit order: commit in the submodule per task; bump the umbrella submodule
  pointer once, at the end (Task 8).
- New crate dependencies: `libloading` + `cryptoki-sys` **only** (workspace
  versions). `publish = false`. No proto/tonic/protoc anywhere near it.
- The crate never calls `C_Initialize`.
- All errors are `Result<_, String>`.
- Every raw pointer read of a function-list field uses `read_unaligned`
  (packed Windows-MSVC bindings put function pointers at offset 2).
- The standard interface name is the exact byte string `b"PKCS 11"`
  (no NUL in the comparison; NUL-terminated only at the FFI boundary).
- Per proxy contributor rules: run `cargo fmt --all` and `cargo check` for
  every touched crate before each commit; refactors must not leave the tree
  partially migrated; scans/tests citing moved paths update in the same
  commit as the move.
- Let-chains (`if cond && let X = e {}`) are allowed (MSRV 1.88).

---

### Task 1: Create the crate; move the field tables with unaligned-safe readers; repoint every consumer and scan

**Files:**
- Create: `crates/module/Cargo.toml`
- Create: `crates/module/src/lib.rs`
- Create: `crates/module/src/tables.rs` (content moved from
  `crates/backend/src/ffi/function_field_tables.rs`)
- Delete: `crates/backend/src/ffi/function_field_tables.rs`
- Modify: `Cargo.toml` (workspace members)
- Modify: `crates/backend/Cargo.toml` (add dep)
- Modify: `crates/backend/src/ffi.rs` (drop the `#[path] mod function_field_tables;` entry)
- Modify: `crates/backend/src/ffi/interface_caps.rs` (imports)
- Modify: `scripts/oasis-coverage-inventory.py` (moved path)
- Modify: `crates/server/tests/local_quality_gate_test.rs` (evidence-path assertion)

**Interfaces:**
- Produces (later tasks rely on these exact names):
  - `pkcs11_module::tables::{FnField, FUNCTION_LIST_FIELDS, FUNCTION_LIST_3_0_EXTRA_FIELDS, FUNCTION_LIST_3_2_EXTRA_FIELDS}`
  - `pub unsafe fn detect_null_functions(base: *const u8, fields: &[FnField]) -> Vec<String>`
  - `pub unsafe fn read_fn_pointers(base: *const u8, fields: &[FnField]) -> Vec<(&'static str, usize)>`
  - All re-exported at crate root (`pkcs11_module::FnField` etc.).

- [x] **Step 1: Create the crate skeleton**

`crates/module/Cargo.toml`:

```toml
[package]
name = "pkcs11-module"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish = false

[dependencies]
libloading.workspace = true
cryptoki-sys.workspace = true
```

`crates/module/src/lib.rs`:

```rust
//! Shared PKCS#11 module-FFI facts: raw function-table acquisition,
//! function-list field-offset tables, and layout selection.
//!
//! Facts only — interface-*selection* policy (version fallback, provider
//! quirks) lives in the proxy backend; evidence policy (pointer→offset
//! mapping, provenance/alias analysis) lives in p11scope-discover. This
//! crate never calls `C_Initialize`. Design of record: the extraction spec
//! in the pkcs11-scope repository
//! (`docs/superpowers/specs/2026-08-10-module-crate-extraction-design.md`).

pub mod tables;

pub use tables::{
    FnField, FUNCTION_LIST_3_0_EXTRA_FIELDS, FUNCTION_LIST_3_2_EXTRA_FIELDS,
    FUNCTION_LIST_FIELDS, detect_null_functions, read_fn_pointers,
};
```

Add `"crates/module",` to the workspace `members` list in the root
`Cargo.toml` (after `"crates/audit"`, keeping the existing order style).

- [x] **Step 2: Move the tables into `crates/module/src/tables.rs`**

Copy the entire contents of `crates/backend/src/ffi/function_field_tables.rs`
into `crates/module/src/tables.rs`, then make exactly these changes:

1. In `detect_null_functions`, change the read to unaligned:

```rust
// Each function pointer field is `Option<unsafe extern "C" fn(...)>`,
// which is pointer-sized. A None value is all-zero bytes. read_unaligned:
// on the packed Windows-MSVC cryptoki-sys bindings these fields start at
// offset 2 (after CK_VERSION), where an aligned read is UB.
let ptr_val = unsafe { (base.add(field.offset) as *const usize).read_unaligned() };
```

2. Append the pointer-value reader:

```rust
/// Read every function-pointer field's raw value (for pointer→file-offset
/// mapping in discovery tooling).
///
/// # Safety
/// Same contract as [`detect_null_functions`]: `base` must point to a
/// valid, live struct of the type `fields` was generated from.
pub unsafe fn read_fn_pointers(base: *const u8, fields: &[FnField]) -> Vec<(&'static str, usize)> {
    fields
        .iter()
        .map(|field| {
            let value = unsafe { (base.add(field.offset) as *const usize).read_unaligned() };
            (field.name, value)
        })
        .collect()
}
```

**Do not** reformat or reorder the `fn_fields!` macro or the three `static`
lists — `scripts/oasis-coverage-inventory.py` parses this file textually.
Delete `crates/backend/src/ffi/function_field_tables.rs` after copying.

- [x] **Step 3: Write the reader unit tests (in `tables.rs`)**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// A byte buffer standing in for a CK_FUNCTION_LIST: one non-NULL slot
    /// written at the C_Initialize offset, everything else zero.
    fn fake_base_table() -> Vec<u8> {
        let mut buf = vec![0u8; std::mem::size_of::<cryptoki_sys::CK_FUNCTION_LIST>()];
        let off = FUNCTION_LIST_FIELDS[0].offset; // C_Initialize
        buf[off..off + std::mem::size_of::<usize>()]
            .copy_from_slice(&0xDEAD_BEEFusize.to_ne_bytes());
        buf
    }

    #[test]
    fn detect_null_functions_reports_all_but_the_set_slot() {
        let buf = fake_base_table();
        let nulls = unsafe { detect_null_functions(buf.as_ptr(), FUNCTION_LIST_FIELDS) };
        assert!(!nulls.contains(&"C_Initialize".to_string()));
        assert_eq!(nulls.len(), FUNCTION_LIST_FIELDS.len() - 1);
    }

    #[test]
    fn read_fn_pointers_returns_names_with_values() {
        let buf = fake_base_table();
        let ptrs = unsafe { read_fn_pointers(buf.as_ptr(), FUNCTION_LIST_FIELDS) };
        assert_eq!(ptrs.len(), FUNCTION_LIST_FIELDS.len());
        assert_eq!(ptrs[0], ("C_Initialize", 0xDEAD_BEEF));
        assert!(ptrs[1..].iter().all(|(_, v)| *v == 0));
    }

    #[test]
    fn table_sizes_match_the_documented_counts() {
        assert_eq!(FUNCTION_LIST_FIELDS.len(), 68);
        assert_eq!(FUNCTION_LIST_3_0_EXTRA_FIELDS.len(), 24);
        assert_eq!(FUNCTION_LIST_3_2_EXTRA_FIELDS.len(), 12);
    }
}
```

- [x] **Step 4: Run the new crate's tests**

Run: `cargo test -p pkcs11-module`
Expected: PASS (3 tests).

- [x] **Step 5: Repoint backend**

In `crates/backend/Cargo.toml` add under `[dependencies]`:

```toml
pkcs11-module = { path = "../module" }
```

In `crates/backend/src/ffi.rs` delete the two lines:

```rust
#[path = "ffi/function_field_tables.rs"]
mod function_field_tables;
```

In `crates/backend/src/ffi/interface_caps.rs` replace

```rust
use super::function_field_tables::*;
```

with

```rust
use pkcs11_module::tables::*;
```

- [x] **Step 6: Repoint the OASIS scan and the quality gate**

Run: `grep -rn "function_field_tables" --include="*.py" --include="*.rs" --include="*.md" .`
For **every** hit (expected: `scripts/oasis-coverage-inventory.py` around
line 1443, `crates/server/tests/local_quality_gate_test.rs` around line 3323;
update any others the grep surfaces the same way), replace the path string
`crates/backend/src/ffi/function_field_tables.rs` with
`crates/module/src/tables.rs`.

- [x] **Step 7: Verify the whole workspace**

Run: `cargo fmt --all && cargo check`
Run: `cargo test -p pkcs11-proxy-ng-backend`
Run: `cargo test -p pkcs11-proxy-ng --test local_quality_gate_test`
Expected: all PASS. If the gate test fails on a path string, Step 6 missed a
citation — fix it there, not by weakening the test.

- [x] **Step 8: Commit (submodule)**

```bash
git add -A
git commit -m "refactor(module): extract function-list field tables into pkcs11-module

New facts-only crate (libloading + cryptoki-sys, publish = false) per the
extraction design spec. Readers switch to read_unaligned (packed MSVC
bindings put fn pointers at offset 2 — latent UB in the aligned read);
adds read_fn_pointers for discovery tooling. OASIS inventory script and
quality-gate evidence path follow the move."
```

---

### Task 2: `tables_for()` — the provenance/version → walkable-tables authority

**Files:**
- Modify: `crates/module/src/tables.rs`
- Modify: `crates/module/src/lib.rs` (re-exports)
- Modify: `crates/backend/src/ffi/interface_caps.rs` (adopt it)

**Interfaces:**
- Consumes: the three field-table statics from Task 1.
- Produces (exact shapes; Task 4's helper-facing docs and scope's Phase 1
  code rely on them):

```rust
pub enum Surface {
    LegacyFunctionList,
    StandardInterface { version: cryptoki_sys::CK_VERSION },
}
pub enum TableSet {
    Walk(&'static [&'static [FnField]]),
    WalkKnownPrefix(&'static [&'static [FnField]]),
    Refuse,
}
pub fn tables_for(surface: Surface) -> TableSet;
```

- [x] **Step 1: Write the failing tests (spec §7 rows + boundary versions)**

Append to the `tests` module in `tables.rs`:

```rust
fn std_iface(major: u8, minor: u8) -> Surface {
    Surface::StandardInterface { version: cryptoki_sys::CK_VERSION { major, minor } }
}

fn walked(set: TableSet) -> Vec<*const FnField> {
    match set {
        TableSet::Walk(s) | TableSet::WalkKnownPrefix(s) => {
            s.iter().map(|f| f.as_ptr()).collect()
        }
        TableSet::Refuse => Vec::new(),
    }
}

#[test]
fn legacy_walks_base_only_regardless_of_any_version_claim() {
    // Provenance, not the table's own bytes, decides: legacy is base-only.
    let set = tables_for(Surface::LegacyFunctionList);
    assert!(matches!(set, TableSet::Walk(_)));
    assert_eq!(walked(set), vec![FUNCTION_LIST_FIELDS.as_ptr()]);
}

#[test]
fn standard_240_walks_base_and_other_2x_is_refused() {
    let set = tables_for(std_iface(2, 40));
    assert!(matches!(set, TableSet::Walk(_)));
    assert_eq!(walked(set), vec![FUNCTION_LIST_FIELDS.as_ptr()]);
    // OASIS defines the structure only as 0x02/0x28 "2.40 compatible";
    // an older 2.x table is not guaranteed to contain the full 2.40 tail.
    assert!(matches!(tables_for(std_iface(2, 30)), TableSet::Refuse));
    assert!(matches!(tables_for(std_iface(2, 20)), TableSet::Refuse));
}

#[test]
fn standard_30_and_31_walk_base_plus_30() {
    for minor in [0, 1] {
        let set = tables_for(std_iface(3, minor));
        assert!(matches!(set, TableSet::Walk(_)));
        assert_eq!(
            walked(set),
            vec![FUNCTION_LIST_FIELDS.as_ptr(), FUNCTION_LIST_3_0_EXTRA_FIELDS.as_ptr()],
        );
    }
}

#[test]
fn standard_32_walks_all_three() {
    let set = tables_for(std_iface(3, 2));
    assert!(matches!(set, TableSet::Walk(_)));
    assert_eq!(
        walked(set),
        vec![
            FUNCTION_LIST_FIELDS.as_ptr(),
            FUNCTION_LIST_3_0_EXTRA_FIELDS.as_ptr(),
            FUNCTION_LIST_3_2_EXTRA_FIELDS.as_ptr(),
        ],
    );
}

#[test]
fn standard_3_minor_above_2_walks_known_prefix() {
    let set = tables_for(std_iface(3, 3));
    assert!(matches!(set, TableSet::WalkKnownPrefix(_)));
    assert_eq!(
        walked(set),
        vec![
            FUNCTION_LIST_FIELDS.as_ptr(),
            FUNCTION_LIST_3_0_EXTRA_FIELDS.as_ptr(),
            FUNCTION_LIST_3_2_EXTRA_FIELDS.as_ptr(),
        ],
    );
}

#[test]
fn unknown_majors_are_refused() {
    assert!(matches!(tables_for(std_iface(4, 0)), TableSet::Refuse));
    assert!(matches!(tables_for(std_iface(1, 0)), TableSet::Refuse));
    assert!(matches!(tables_for(std_iface(0, 0)), TableSet::Refuse));
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pkcs11-module tables_for`
Expected: FAIL to compile — `Surface`, `TableSet`, `tables_for` not defined.

- [x] **Step 3: Implement**

Add to `tables.rs` (above the tests):

```rust
/// Where a function table came from — the input that decides which field
/// tables may be walked over it (spec §7). Vendor interfaces and NULL
/// function lists are deliberately unrepresentable: only `is_standard()`
/// interfaces may be wrapped in `StandardInterface`, and callers never
/// construct a `Surface` for anything else.
#[derive(Debug, Clone, Copy)]
pub enum Surface {
    /// Obtained via `C_GetFunctionList`. Only known to be base-size,
    /// regardless of what its own version field claims.
    LegacyFunctionList,
    /// A `C_GetInterfaceList`/`C_GetInterface` interface whose reported
    /// name is exactly "PKCS 11", with its validated reported version.
    StandardInterface { version: cryptoki_sys::CK_VERSION },
}

/// The tables that may be walked over a surface, in walk order.
#[derive(Debug, Clone, Copy)]
pub enum TableSet {
    Walk(&'static [&'static [FnField]]),
    /// 3.x with minor > 2: the listed tables are a safe *prefix*; fields
    /// beyond the known 3.2 layout exist but must be recorded as excess,
    /// not walked.
    WalkKnownPrefix(&'static [&'static [FnField]]),
    /// Unknown layout (non-2.40 2.x, unknown major): record, walk nothing.
    Refuse,
}

static BASE: &[&[FnField]] = &[FUNCTION_LIST_FIELDS];
static V3_0: &[&[FnField]] = &[FUNCTION_LIST_FIELDS, FUNCTION_LIST_3_0_EXTRA_FIELDS];
static V3_2: &[&[FnField]] =
    &[FUNCTION_LIST_FIELDS, FUNCTION_LIST_3_0_EXTRA_FIELDS, FUNCTION_LIST_3_2_EXTRA_FIELDS];

/// The single authority binding provenance + validated version to the
/// walkable field tables (spec §7). Both the proxy's capability scan and
/// the discovery helper go through this, so the invariant has one home.
pub fn tables_for(surface: Surface) -> TableSet {
    match surface {
        Surface::LegacyFunctionList => TableSet::Walk(BASE),
        Surface::StandardInterface { version } => match (version.major, version.minor) {
            // OASIS mandates 0x02/0x28 ("a version 2.40 compatible
            // structure") — the only 2.x layout the base table describes.
            (2, 40) => TableSet::Walk(BASE),
            (2, _) => TableSet::Refuse,
            (3, 0) | (3, 1) => TableSet::Walk(V3_0),
            (3, 2) => TableSet::Walk(V3_2),
            (3, _) => TableSet::WalkKnownPrefix(V3_2),
            _ => TableSet::Refuse,
        },
    }
}
```

Add `Surface`, `TableSet`, `tables_for` to the re-export list in `lib.rs`.

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p pkcs11-module`
Expected: PASS (all, including Task 1's).

- [x] **Step 5: Adopt in `interface_caps.rs`**

Replace the body of `detect_interface_capabilities` so table selection goes
through `tables_for` (walked sets are unchanged — this is consolidation, not
behavior change):

```rust
use pkcs11_module::tables::{Surface, TableSet, detect_null_functions, tables_for};

fn nulls_for(list: *const u8, surface: Surface) -> Vec<String> {
    match tables_for(surface) {
        TableSet::Walk(sets) | TableSet::WalkKnownPrefix(sets) => sets
            .iter()
            .flat_map(|fields| unsafe { detect_null_functions(list, fields) })
            .collect(),
        TableSet::Refuse => Vec::new(),
    }
}
```

and in `detect_interface_capabilities`:

```rust
// v2.40 is always present. self.func_list may be legacy- or (validated)
// interface-derived; both walk base-only, so LegacyFunctionList is the
// conservative surface for it either way.
let null_2_40 = nulls_for(self.func_list as *const u8, Surface::LegacyFunctionList);
// ...
// v3.0 if available (list came from a validated versioned {3,0} query):
let nulls = nulls_for(
    fl3 as *const u8,
    Surface::StandardInterface { version: cryptoki_sys::CK_VERSION { major: 3, minor: 0 } },
);
// v3.2 if available:
let nulls = nulls_for(
    fl3_2 as *const u8,
    Surface::StandardInterface { version: cryptoki_sys::CK_VERSION { major: 3, minor: 2 } },
);
```

keeping the surrounding `InterfaceCapabilities { interfaces }` construction
exactly as it is.

- [x] **Step 6: Verify backend + gate**

Run: `cargo fmt --all && cargo check`
Run: `cargo test -p pkcs11-proxy-ng-backend`
Run: `cargo test -p pkcs11-proxy-ng --test local_quality_gate_test`
Expected: PASS.

- [x] **Step 7: Commit (submodule)**

```bash
git add -A
git commit -m "feat(module): tables_for() binds provenance + version to walkable tables

Single authority for the layout invariant (spec §7): legacy -> base only;
standard 2.40 exactly -> base (other 2.x refused -- OASIS defines the
structure only as 2.40-compatible); 3.0/3.1 -> +3.0 extras; 3.2 -> all;
3.minor>2 -> known prefix; unknown majors refused. interface_caps adopts
it; walked sets unchanged."
```

---

### Task 3: `function_list()` moves to the crate

**Files:**
- Create: `crates/module/src/acquire.rs`
- Modify: `crates/module/src/lib.rs`
- Modify: `crates/backend/src/ffi/loading.rs`

**Interfaces:**
- Produces: `pub fn pkcs11_module::function_list(lib: &libloading::Library) -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String>`
- Task 5 consumes it as the legacy branch of primary selection.

- [x] **Step 1: Create `crates/module/src/acquire.rs`**

Move the body of `FfiBackend::try_get_function_list` (in
`crates/backend/src/ffi/loading.rs`) into a free function:

```rust
//! Raw table acquisition — the three pre-initialize entry points.

use libloading::{Library, Symbol};

/// Resolve `C_GetFunctionList` and return the module's legacy 2.40 table.
///
/// Never calls `C_Initialize`. The returned pointer aliases the module's
/// static data and is valid while `lib` stays loaded.
pub fn function_list(lib: &Library) -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String> {
    let get_func_list: Symbol<
        unsafe extern "C" fn(*mut *mut cryptoki_sys::CK_FUNCTION_LIST) -> cryptoki_sys::CK_RV,
    > = unsafe {
        lib.get(b"C_GetFunctionList\0")
            .map_err(|e| format!("C_GetFunctionList not found: {e}"))?
    };

    let mut func_list: *mut cryptoki_sys::CK_FUNCTION_LIST = std::ptr::null_mut();
    let rv = unsafe { get_func_list(&mut func_list) };
    if rv != 0 {
        return Err(format!("C_GetFunctionList returned 0x{rv:08x}"));
    }
    if func_list.is_null() {
        return Err("C_GetFunctionList returned null".into());
    }
    Ok(func_list)
}
```

In `lib.rs` add:

```rust
pub mod acquire;
pub use acquire::function_list;
```

- [x] **Step 2: Repoint backend**

In `crates/backend/src/ffi/loading.rs`:
- delete the private `fn try_get_function_list`;
- replace its one call site (`.or_else(|_| Self::try_get_function_list(&lib))`)
  with `.or_else(|_| pkcs11_module::function_list(&lib))`.

(No deterministic unit test for the thin FFI wrapper itself; it is exercised
by every backend test that loads a real module, and by Task 4's env-gated
real-provider test alongside `interface_list`.)

- [x] **Step 3: Verify**

Run: `cargo fmt --all && cargo check`
Run: `cargo test -p pkcs11-module && cargo test -p pkcs11-proxy-ng-backend`
Expected: PASS.

- [x] **Step 4: Commit (submodule)**

```bash
git add -A
git commit -m "refactor(module): move C_GetFunctionList acquisition into pkcs11-module

try_get_function_list becomes pkcs11_module::function_list(); backend
loading calls it. Behavior unchanged."
```

---

### Task 4: `interface_list()` — hardened raw enumeration with resolver-level seam

**Files:**
- Modify: `crates/module/src/acquire.rs`
- Modify: `crates/module/src/lib.rs`

**Interfaces:**
- Produces (scope's Phase 1 helper consumes exactly these):

```rust
pub struct RawInterface {
    pub name: Option<Vec<u8>>,
    pub version: Option<cryptoki_sys::CK_VERSION>,
    pub flags: cryptoki_sys::CK_FLAGS,
    pub func_list: *mut std::ffi::c_void,
}
impl RawInterface { pub fn is_standard(&self) -> bool; }
pub fn interface_list(lib: &Library) -> Result<Option<Vec<RawInterface>>, String>;
```

- [x] **Step 1: Write the failing deterministic test matrix**

Append a `tests` module to `acquire.rs`. The seam is resolver-level:
`interface_list_impl(None)` models an absent export. Non-null test pointers
use `NonNull::dangling()`; entries with real name/version data point at
test-owned buffers.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki_sys::{CK_INTERFACE, CK_RV, CK_ULONG, CKR_BUFFER_TOO_SMALL, CKR_OK};

    type NoFn = fn(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV;

    /// A fake standard interface backed by test-owned static data.
    fn fake_iface(name: &'static [u8], func_list: *mut std::ffi::c_void) -> CK_INTERFACE {
        CK_INTERFACE {
            pInterfaceName: name.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR,
            pFunctionList: func_list,
            flags: 0,
        }
    }

    // A static 2-byte CK_VERSION {3, 0} the fake pFunctionList can point at.
    static FAKE_LIST_HEADER: cryptoki_sys::CK_VERSION =
        cryptoki_sys::CK_VERSION { major: 3, minor: 0 };
    fn fake_list_ptr() -> *mut std::ffi::c_void {
        &FAKE_LIST_HEADER as *const _ as *mut std::ffi::c_void
    }

    #[test]
    fn absent_symbol_is_ok_none() {
        assert_eq!(
            interface_list_impl(None::<NoFn>).map(|o| o.is_none()),
            Ok(true),
        );
    }

    #[test]
    fn zero_interfaces_is_ok_some_empty() {
        let result = interface_list_impl(Some(|_ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
            unsafe { *count = 0 };
            CKR_OK
        }))
        .unwrap();
        assert_eq!(result.map(|v| v.len()), Some(0));
    }

    #[test]
    fn count_growth_converges_on_retry() {
        let mut calls = 0u32;
        let result = interface_list_impl(Some(|ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
            calls += 1;
            match calls {
                1 => { unsafe { *count = 1 }; CKR_OK }               // count query
                2 => { unsafe { *count = 2 }; CKR_BUFFER_TOO_SMALL } // grew
                3 => { unsafe { *count = 2 }; CKR_OK }               // fresh count
                _ => {
                    unsafe {
                        *ifaces = fake_iface(b"PKCS 11\0", fake_list_ptr());
                        *ifaces.add(1) = fake_iface(b"Vendor X\0", fake_list_ptr());
                        *count = 2;
                    }
                    CKR_OK
                }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].is_standard());
        assert!(!result[1].is_standard());
    }

    #[test]
    fn count_growth_never_converging_errors_after_three_attempts() {
        let mut fills = 0u32;
        let err = interface_list_impl(Some(|ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
            if ifaces.is_null() {
                unsafe { *count = 1 };
                CKR_OK
            } else {
                fills += 1;
                unsafe { *count = 2 };
                CKR_BUFFER_TOO_SMALL
            }
        }))
        .unwrap_err();
        assert_eq!(fills, 3, "exactly three whole attempts");
        assert!(err.contains("attempts"), "unexpected error: {err}");
    }

    #[test]
    fn absurd_count_is_rejected_by_the_cap() {
        let err = interface_list_impl(Some(|_: *mut CK_INTERFACE, count: *mut CK_ULONG| {
            unsafe { *count = 10_000 };
            CKR_OK
        }))
        .unwrap_err();
        assert!(err.contains("cap"), "unexpected error: {err}");
    }

    #[test]
    fn capacity_overrun_is_rejected() {
        let err = interface_list_impl(Some(|ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
            if ifaces.is_null() {
                unsafe { *count = 1 };
            } else {
                unsafe { *count = 2 }; // claims more than the capacity it was given
            }
            CKR_OK
        }))
        .unwrap_err();
        assert!(err.contains("capacity"), "unexpected error: {err}");
    }

    #[test]
    fn null_name_and_null_func_list_are_preserved_not_dereferenced() {
        let result = interface_list_impl(Some(|ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| {
            if ifaces.is_null() {
                unsafe { *count = 2 };
            } else {
                unsafe {
                    *ifaces = CK_INTERFACE {
                        pInterfaceName: std::ptr::null_mut(),
                        pFunctionList: fake_list_ptr(),
                        flags: 0,
                    };
                    *ifaces.add(1) = fake_iface(b"PKCS 11\0", std::ptr::null_mut());
                    *count = 2;
                }
            }
            CKR_OK
        }))
        .unwrap()
        .unwrap();
        assert_eq!(result[0].name, None);
        assert_eq!(result[0].version.map(|v| (v.major, v.minor)), Some((3, 0)));
        assert!(!result[0].is_standard()); // no name -> not standard
        assert_eq!(result[1].name.as_deref(), Some(b"PKCS 11".as_slice()));
        assert_eq!(result[1].version, None); // NULL list: nothing dereferenced
        assert!(result[1].func_list.is_null());
    }

    #[test]
    fn is_standard_requires_exact_name() {
        let dangling = std::ptr::NonNull::<std::ffi::c_void>::dangling().as_ptr();
        let mk = |name: Option<&[u8]>| RawInterface {
            name: name.map(|n| n.to_vec()),
            version: None,
            flags: 0,
            func_list: dangling,
        };
        assert!(mk(Some(b"PKCS 11")).is_standard());
        assert!(!mk(Some(b"PKCS 11 X")).is_standard());
        assert!(!mk(Some(b"pkcs 11")).is_standard());
        assert!(!mk(None).is_standard());
    }
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pkcs11-module acquire`
Expected: FAIL to compile — `RawInterface`, `interface_list_impl` not defined.

- [x] **Step 3: Implement in `acquire.rs`**

```rust
use cryptoki_sys::{CK_INTERFACE, CK_RV, CK_ULONG, CKR_BUFFER_TOO_SMALL, CKR_OK};

/// One interface exactly as the module reported it. Nothing is resolved,
/// deduplicated, or reinterpreted; NULL fields are preserved as evidence.
#[derive(Debug)]
pub struct RawInterface {
    /// Bytes of `pInterfaceName` (no trailing NUL); `None` if NULL.
    pub name: Option<Vec<u8>>,
    /// Leading `CK_VERSION` of `pFunctionList`; `None` if that is NULL.
    pub version: Option<cryptoki_sys::CK_VERSION>,
    pub flags: cryptoki_sys::CK_FLAGS,
    /// May be NULL — preserved, never dereferenced then.
    pub func_list: *mut std::ffi::c_void,
}

impl RawInterface {
    /// Exact match against the standard interface name. Callers must not
    /// walk the standard field tables over an interface for which this is
    /// false (vendor layouts are unrelated; only the leading CK_VERSION is
    /// guaranteed by the spec).
    pub fn is_standard(&self) -> bool {
        self.name.as_deref() == Some(b"PKCS 11")
    }
}

/// Providers report a handful of interfaces; a garbage count must not
/// drive allocation.
const MAX_INTERFACES: usize = 256;
/// Whole two-call sequences attempted when the count keeps growing.
const MAX_ATTEMPTS: u32 = 3;

/// Raw `C_GetInterfaceList` enumeration (two-call pattern).
///
/// - `Ok(None)` — the module does not export `C_GetInterfaceList`. The
///   only proven fact is "symbol not exported"; callers must not infer
///   the module generation from it.
/// - `Ok(Some(vec![]))` — export present, zero interfaces reported.
pub fn interface_list(
    lib: &libloading::Library,
) -> Result<Option<Vec<RawInterface>>, String> {
    type GetInterfaceListFn =
        unsafe extern "C" fn(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV;
    let sym: Option<libloading::Symbol<GetInterfaceListFn>> =
        unsafe { lib.get(b"C_GetInterfaceList\0").ok() };
    match sym {
        None => Ok(None),
        Some(f) => interface_list_impl(Some(
            |ifaces: *mut CK_INTERFACE, count: *mut CK_ULONG| unsafe { f(ifaces, count) },
        )),
    }
}

/// Resolver-level seam: `None` models an absent export so `Ok(None)` is
/// reachable in deterministic tests; the driver below is pure Rust.
fn interface_list_impl<F>(mut get_list: Option<F>) -> Result<Option<Vec<RawInterface>>, String>
where
    F: FnMut(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV,
{
    let Some(get_list) = get_list.as_mut() else {
        return Ok(None);
    };

    for _ in 0..MAX_ATTEMPTS {
        // Call 1: count only.
        let mut count: CK_ULONG = 0;
        let rv = get_list(std::ptr::null_mut(), &mut count);
        if rv != CKR_OK {
            return Err(format!("C_GetInterfaceList (count) returned 0x{rv:08x}"));
        }
        let capacity: usize = count
            .try_into()
            .map_err(|_| format!("interface count {count} does not fit usize"))?;
        if capacity > MAX_INTERFACES {
            return Err(format!(
                "provider reports {capacity} interfaces; cap is {MAX_INTERFACES}"
            ));
        }
        if capacity == 0 {
            return Ok(Some(Vec::new()));
        }

        // Call 2: fill.
        let mut buf: Vec<CK_INTERFACE> = (0..capacity)
            .map(|_| CK_INTERFACE {
                pInterfaceName: std::ptr::null_mut(),
                pFunctionList: std::ptr::null_mut(),
                flags: 0,
            })
            .collect();
        let mut written: CK_ULONG = count;
        let rv = get_list(buf.as_mut_ptr(), &mut written);
        if rv == CKR_BUFFER_TOO_SMALL {
            continue; // the count grew between calls; retry the sequence
        }
        if rv != CKR_OK {
            return Err(format!("C_GetInterfaceList returned 0x{rv:08x}"));
        }
        let filled: usize = written
            .try_into()
            .map_err(|_| format!("written count {written} does not fit usize"))?;
        if filled > capacity {
            return Err(format!(
                "provider claims {filled} interfaces written into capacity {capacity}"
            ));
        }
        // SAFETY: entries were written by the provider (or are the zeroed
        // initializers); name/version reads below guard NULL pointers and
        // use read_unaligned for the version header.
        return Ok(Some(buf[..filled].iter().map(|i| unsafe { raw_interface(i) }).collect()));
    }
    Err(format!(
        "C_GetInterfaceList count kept growing after {MAX_ATTEMPTS} attempts"
    ))
}

/// # Safety
/// Non-NULL `pInterfaceName` must be a live NUL-terminated string and
/// non-NULL `pFunctionList` must point at readable memory of at least
/// `CK_VERSION` size — both guaranteed by the PKCS#11 contract for
/// interfaces a live module reports.
unsafe fn raw_interface(iface: &CK_INTERFACE) -> RawInterface {
    let name = if iface.pInterfaceName.is_null() {
        None
    } else {
        Some(
            unsafe {
                std::ffi::CStr::from_ptr(iface.pInterfaceName as *const std::os::raw::c_char)
            }
            .to_bytes()
            .to_vec(),
        )
    };
    let version = if iface.pFunctionList.is_null() {
        None
    } else {
        Some(unsafe {
            (iface.pFunctionList as *const cryptoki_sys::CK_VERSION).read_unaligned()
        })
    };
    RawInterface { name, version, flags: iface.flags, func_list: iface.pFunctionList }
}
```

Re-export in `lib.rs`: add `RawInterface`, `interface_list` to the
`pub use acquire::{...}` list.

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p pkcs11-module`
Expected: PASS (all).

- [x] **Step 5: Add the env-gated real-provider test**

Append to the same `tests` module (pattern follows backend's existing
BouncyHSM test — skip when the module is absent):

```rust
    /// Real 3.x provider check (SoftHSM2 2.6 is 2.40-only, so it cannot
    /// serve here). Point PKCS11_MODULE_TEST_3X_MODULE at a 3.x .so
    /// (kryoptic or BouncyHSM) to run; skipped otherwise.
    #[test]
    fn real_3x_module_reports_standard_interfaces() {
        let Ok(path) = std::env::var("PKCS11_MODULE_TEST_3X_MODULE") else {
            eprintln!("skipping: PKCS11_MODULE_TEST_3X_MODULE not set");
            return;
        };
        if !std::path::Path::new(&path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }
        let lib = unsafe { libloading::Library::new(&path) }.expect("dlopen");
        let listed = interface_list(&lib).expect("enumeration should succeed");
        let listed = listed.expect("a 3.x module exports C_GetInterfaceList");
        assert!(!listed.is_empty());
        assert!(
            listed.iter().any(|i| i.is_standard()),
            "a conforming 3.x module reports at least one \"PKCS 11\" interface"
        );
        // The legacy surface must be independently collectable too.
        super::function_list(&lib).expect("legacy 2.40 table");
    }
```

Run: `cargo test -p pkcs11-module` (expect skip locally unless env set; if a
3.x module path is known in this environment, run once with
`PKCS11_MODULE_TEST_3X_MODULE=<path>` and confirm PASS).

- [x] **Step 6: Verify + commit (submodule)**

Run: `cargo fmt --all && cargo check && cargo test -p pkcs11-module`

```bash
git add -A
git commit -m "feat(module): hardened raw C_GetInterfaceList enumeration

interface_list() with the spec §5 contract: bounded retry (3 attempts) on
count growth, checked count conversion with a 256-interface allocation
cap, capacity-overrun rejection, NULL name/function-list preservation.
Resolver-level seam makes Ok(None) (symbol absent) vs Ok(Some(empty))
(zero interfaces) deterministically testable; env-gated real-provider
test via PKCS11_MODULE_TEST_3X_MODULE."
```

---

### Task 5: Backend selection driver — §6a name validation + §6b provenance

**Files:**
- Modify: `crates/backend/src/ffi/loading.rs` (restructure)

**Interfaces:**
- Consumes: `pkcs11_module::function_list` (Task 3).
- Produces (backend-internal; named here so the tests and `load_with_init_args`
  agree):

```rust
pub(crate) struct InterfaceAnswer { pub name: Option<Vec<u8>>, pub func_list: *mut std::ffi::c_void }
fn select_primary(
    query: Option<&mut dyn FnMut(Option<&[u8]>, Option<cryptoki_sys::CK_VERSION>) -> Option<InterfaceAnswer>>,
    legacy: &mut dyn FnMut() -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String>,
) -> Result<(*mut cryptoki_sys::CK_FUNCTION_LIST, bool), String>;
fn select_versioned(
    q: &mut dyn FnMut(Option<&[u8]>, Option<cryptoki_sys::CK_VERSION>) -> Option<InterfaceAnswer>,
    major: u8, minor: u8,
) -> Option<*mut std::ffi::c_void>;
```

- `FfiBackend::load` / `load_with_init_args` signatures unchanged;
  `resolve_get_interface`, `primary_interface_fallback`, and all existing
  tests (including the env-gated BouncyHSM test) stay.

- [x] **Step 1: Write the failing driver tests**

Append to the existing `tests` module in `loading.rs`:

```rust
    use super::{select_primary, select_versioned, InterfaceAnswer};

    fn dangling_list() -> *mut cryptoki_sys::CK_FUNCTION_LIST {
        std::ptr::NonNull::dangling().as_ptr()
    }
    fn answer(name: &[u8]) -> InterfaceAnswer {
        InterfaceAnswer {
            name: Some(name.to_vec()),
            func_list: std::ptr::NonNull::<std::ffi::c_void>::dangling().as_ptr(),
        }
    }

    /// §6b: C_GetInterface exists but every query fails; the legacy table
    /// must carry provenance false (the current code derives the flag from
    /// symbol existence, which this test would catch).
    #[test]
    fn provenance_is_false_when_queries_fail_and_legacy_succeeds() {
        let mut q = |_: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| None;
        let expected = dangling_list();
        let mut legacy = || Ok(expected);
        let (list, from_interface) =
            select_primary(Some(&mut q), &mut legacy).expect("legacy succeeds");
        assert_eq!(list, expected);
        assert!(!from_interface, "a C_GetFunctionList pointer is never interface-derived");
    }

    /// §6a: an unnamed result is accepted only when named exactly "PKCS 11".
    #[test]
    fn unnamed_vendor_interface_is_rejected_and_falls_through_to_legacy() {
        let mut q = |name: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| match name {
            Some(_) => None,                    // named standard query fails
            None => Some(answer(b"ACME Vendor")), // unnamed returns a vendor interface
        };
        let expected = dangling_list();
        let mut legacy = || Ok(expected);
        let (list, from_interface) = select_primary(Some(&mut q), &mut legacy).unwrap();
        assert_eq!(list, expected);
        assert!(!from_interface);
    }

    #[test]
    fn unnamed_standard_interface_is_accepted() {
        let std_answer = answer(b"PKCS 11");
        let expected = std_answer.func_list as *mut cryptoki_sys::CK_FUNCTION_LIST;
        let mut q = |name: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| match name {
            Some(_) => None,
            None => Some(answer(b"PKCS 11")),
        };
        let mut legacy = || -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String> {
            panic!("legacy must not be consulted when the unnamed standard answer is valid")
        };
        let (list, from_interface) = select_primary(Some(&mut q), &mut legacy).unwrap();
        assert_eq!(list, expected);
        assert!(from_interface);
    }

    /// The versioned (BouncyHSM-class) unnamed fallback applies the same rule.
    #[test]
    fn versioned_unnamed_vendor_is_rejected_standard_is_accepted() {
        let mut vendor_q = |name: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| match name {
            Some(_) => None,
            None => Some(answer(b"ACME Vendor")),
        };
        assert!(select_versioned(&mut vendor_q, 3, 0).is_none());

        let mut std_q = |name: Option<&[u8]>, _: Option<cryptoki_sys::CK_VERSION>| match name {
            Some(_) => None,
            None => Some(answer(b"PKCS 11")),
        };
        assert!(select_versioned(&mut std_q, 3, 0).is_some());
    }
```

Note for the third test: build `expected` from the same `answer()` value the
closure returns — since `NonNull::dangling()` is deterministic for a given
type, constructing two `answer(b"PKCS 11")` values yields the same pointer;
asserting equality against a separately-constructed one is fine.

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pkcs11-proxy-ng-backend loading`
Expected: FAIL to compile — `select_primary`, `select_versioned`,
`InterfaceAnswer` not defined.

- [x] **Step 3: Implement the driver + FFI adapter; rewire `load_with_init_args`**

In `loading.rs`, **delete** `try_get_interface`,
`try_get_versioned_interface`, and `get_interface_with_name`. **Keep**
`GetInterfaceFn`, `resolve_get_interface`, `primary_interface_fallback` (and
its doc comments/tests) unchanged. Add:

```rust
/// One `C_GetInterface` answer as the module reported it.
pub(crate) struct InterfaceAnswer {
    pub name: Option<Vec<u8>>,
    pub func_list: *mut std::ffi::c_void,
}

const STANDARD_NAME: &[u8] = b"PKCS 11";

/// §6a acceptance rule, applied uniformly to named and unnamed answers:
/// only an interface named exactly "PKCS 11" with a non-NULL function
/// list may be treated as a standard table. OASIS lets any unnamed query
/// return "a default interface of its choice", and a vendor interface's
/// function list has no guaranteed layout beyond the leading CK_VERSION.
fn accepts_standard(ans: &InterfaceAnswer) -> bool {
    ans.name.as_deref() == Some(STANDARD_NAME) && !ans.func_list.is_null()
}

/// Primary-list selection (§6a order, §6b provenance): named standard →
/// validated unnamed → legacy. Provenance in the returned bool comes from
/// the branch that produced the pointer, never from symbol existence.
fn select_primary(
    query: Option<&mut dyn FnMut(Option<&[u8]>, Option<cryptoki_sys::CK_VERSION>) -> Option<InterfaceAnswer>>,
    legacy: &mut dyn FnMut() -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String>,
) -> Result<(*mut cryptoki_sys::CK_FUNCTION_LIST, bool), String> {
    if let Some(q) = query {
        for name in [Some(STANDARD_NAME), None] {
            if let Some(ans) = q(name, None)
                && accepts_standard(&ans)
            {
                return Ok((ans.func_list as *mut cryptoki_sys::CK_FUNCTION_LIST, true));
            }
        }
    }
    legacy().map(|func_list| (func_list, false))
}

/// Versioned-list selection: named first, then the unnamed fallback for
/// modules (e.g. BouncyHSM) that only respond to the unnamed form — with
/// the same §6a name rule on the unnamed result. Rejecting a hypothetical
/// vendor-named answer here is soundness over coverage.
fn select_versioned(
    q: &mut dyn FnMut(Option<&[u8]>, Option<cryptoki_sys::CK_VERSION>) -> Option<InterfaceAnswer>,
    major: u8,
    minor: u8,
) -> Option<*mut std::ffi::c_void> {
    let version = cryptoki_sys::CK_VERSION { major, minor };
    for name in [Some(STANDARD_NAME), None] {
        if let Some(ans) = q(name, Some(version))
            && accepts_standard(&ans)
        {
            return Some(ans.func_list);
        }
    }
    None
}

/// FFI adapter: performs one real `C_GetInterface` query and copies the
/// answer out of module-owned memory.
fn ffi_query(
    get_interface: GetInterfaceFn,
) -> impl FnMut(Option<&[u8]>, Option<cryptoki_sys::CK_VERSION>) -> Option<InterfaceAnswer> {
    move |name, version| {
        // NUL-terminated storage must outlive the call.
        let name_buf: Vec<u8>;
        let name_ptr = match name {
            Some(n) => {
                name_buf = [n, b"\0"].concat();
                name_buf.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR
            }
            None => std::ptr::null_mut(),
        };
        let mut version_val = version.unwrap_or(cryptoki_sys::CK_VERSION { major: 0, minor: 0 });
        let version_ptr: *mut cryptoki_sys::CK_VERSION = if version.is_some() {
            &mut version_val
        } else {
            std::ptr::null_mut()
        };
        let mut interface_ptr: *mut cryptoki_sys::CK_INTERFACE = std::ptr::null_mut();
        let rv = unsafe { get_interface(name_ptr, version_ptr, &mut interface_ptr, 0) };
        if rv != 0 || interface_ptr.is_null() {
            return None;
        }
        let iface = unsafe { &*interface_ptr };
        let name = if iface.pInterfaceName.is_null() {
            None
        } else {
            Some(
                unsafe {
                    std::ffi::CStr::from_ptr(iface.pInterfaceName as *const std::os::raw::c_char)
                }
                .to_bytes()
                .to_vec(),
            )
        };
        Some(InterfaceAnswer { name, func_list: iface.pFunctionList })
    }
}
```

Rewire `load_with_init_args` (replacing the current
`primary_from_interface` / `func_list` / `func_list_3_0` / `func_list_3_2`
derivation; everything after — `initialize_args`, the `Ok(Self { .. })` —
stays):

```rust
let get_iface_sym = Self::resolve_get_interface(&lib);
let mut legacy = || pkcs11_module::function_list(&lib);
let (func_list, primary_from_interface) = match get_iface_sym {
    Some(sym) => {
        let mut q = ffi_query(sym);
        select_primary(Some(&mut q), &mut legacy)?
    }
    None => select_primary(None, &mut legacy)?,
};

// 3.0/3.2 discovery keeps the primary-interface fallback (see its doc
// comment: some modules answer an explicit {3,0} query with NULL even
// though their >=3.0 primary implements the functions).
let func_list_3_0 = get_iface_sym
    .and_then(|sym| select_versioned(&mut ffi_query(sym), 3, 0))
    .or_else(|| Self::primary_interface_fallback(func_list, primary_from_interface, 3, 0))
    .map(|ptr| ptr as *const cryptoki_sys::CK_FUNCTION_LIST_3_0);
let func_list_3_2 = get_iface_sym
    .and_then(|sym| select_versioned(&mut ffi_query(sym), 3, 2))
    .or_else(|| Self::primary_interface_fallback(func_list, primary_from_interface, 3, 2))
    .map(|ptr| ptr as *const cryptoki_sys::CK_FUNCTION_LIST_3_2);
```

Preserve the existing block comment above the 3.0/3.2 discovery (the
BouncyHSM fallback rationale) — move it onto this rewired block.

- [x] **Step 4: Run the tests**

Run: `cargo test -p pkcs11-proxy-ng-backend loading`
Expected: PASS — the four new driver tests plus the existing
`primary_fallback_ignores_c_get_function_list_version_3_x`,
`has_interface_accessors_*`, and (if the module is present) the env-gated
BouncyHSM test.

- [x] **Step 5: Full backend + server suites**

Run: `cargo fmt --all && cargo check`
Run: `cargo test -p pkcs11-proxy-ng-backend && cargo test -p pkcs11-proxy-ng`
Expected: PASS. If SoftHSM2-backed integration tests exist in this
environment they must pass unchanged — §6a does not alter selection for any
conforming provider (SoftHSM2 answers the named standard query).

- [x] **Step 6: Commit (submodule)**

```bash
git add -A
git commit -m "fix(backend): validate every unnamed C_GetInterface result; derive fallback provenance from the producing branch

§6a: OASIS lets any unnamed query return a default interface of the
provider's choice, so an unvalidated unnamed answer (primary or the
versioned BouncyHSM-class fallback) could cast a vendor layout to a
standard 3.x table. Selection is now named-standard -> validated-unnamed
-> legacy, with the exact \"PKCS 11\" rule applied uniformly.

§6b: primary_from_interface was derived from symbol existence before the
query ran, so a module whose C_GetInterface exists but fails handed its
C_GetFunctionList base pointer to the 3.x fallback flagged as
interface-derived. The flag now comes from the branch that produced the
pointer.

Selection is a pure driver over closure-injected query primitives;
deterministic tests cover the failing-query, unnamed-vendor, and
unnamed-standard branches. Behavior change is gated on the provider
matrix (SoftHSM2 baseline) before merge."
```

---

### Task 6: Docs + workspace-wide verification

**Files:**
- Modify: `AGENTS.md` (§13 Architecture Quick Reference)
- Modify: `doc/architecture-overview.md` (crate table)

- [x] **Step 1: AGENTS.md §13**

Add one bullet after the **FFI backend** entry:

```markdown
- **Module loader** (`crates/module`, package `pkcs11-module`): shared
  module-FFI *facts* — raw `C_GetFunctionList`/`C_GetInterfaceList`
  acquisition, function-list field-offset tables, provenance/version →
  table selection (`tables_for`), unaligned-safe readers. No proto/tonic
  dependencies; also consumed externally (pkcs11-scope's discover helper)
  via git dependency. Interface-*selection* policy stays in the backend.
```

- [x] **Step 2: architecture-overview.md crate table**

Add a row to the "Current Crate Structure" table (after `backend`):

```markdown
| `module` | lib | Shared module-FFI facts: raw function-table acquisition, field-offset tables, layout selection (`pkcs11-module`; consumed by backend and externally) |
```

- [x] **Step 3: Verify the dependency claim and the whole tree**

Run: `cargo tree -p pkcs11-module --edges normal`
Expected: only `libloading` and `cryptoki-sys` subtrees — no tonic, prost,
or proto anywhere in the output.

Run: `cargo fmt --all && cargo check && cargo test`
Expected: full workspace suite PASS. (This approximates the spec's
fresh-clone standalone check; the real fresh-clone verification happens in
CI as it does today.)

- [x] **Step 4: Commit (submodule)**

```bash
git add -A
git commit -m "docs: add pkcs11-module to the architecture quick reference and overview"
```

---

### Task 7: Provider-matrix gate for §6a (spec requirement before merge)

> Task 7 (provider-matrix gate) is owned by the pkcs11-proxy-ng project;
> not tracked in this repo.

**Working directory: the umbrella repo** `/home/user/src/m/pkcs11-proxy-ng-ws`.

- [ ] **Step 1: Build release proxy binaries**

Run (in the submodule): `cargo build --release`
Expected: clean build.

- [ ] **Step 2: Run the representative pooled provider run**

Run (in the umbrella repo):

```bash
BASELINE_DIR=/home/user/src/m/pkcs11-check-ws/artifacts_base \
scripts/run-pooled-proxy-tests.sh \
  --testcases src/pkcs11_check/testcases/test_interface.py \
  softhsm2-main
```

Expected: run completes; the comparison against the baseline shows **no new
regressions** attributable to interface selection (§6a must not change
selection for any conforming provider).

If this environment lacks the pkcs11-check workspace or `BASELINE_DIR`
artifacts, **stop and say so explicitly** (proxy contributor rule 7) — the
gate then runs on the machine that has them before merge. Do not mark this
task complete on an unrun gate.

- [ ] **Step 3: (Owner's call, recommended before merge) wider matrix**

The full-matrix command is in the umbrella `CLAUDE.md` ("Full
`pkcs11-check` Proxy Matrix"). BouncyHSM (`bouncyhsm`) is the most valuable
addition here — it exercises the versioned unnamed fallback §6a touches.

---

### Task 8: Umbrella pointer bump

**Working directory: the umbrella repo** `/home/user/src/m/pkcs11-proxy-ng-ws`.

- [x] **Step 1: Confirm the submodule is clean and pushedable**

Run (in the submodule): `git status --short` → empty; `git log --oneline -7`
→ the Task 1–6 commits on top of the previous HEAD.

- [x] **Step 2: Bump the pointer**

```bash
git add pkcs11-proxy-ng
git commit -m "chore: advance proxy for the pkcs11-module extraction"
```

- [x] **Step 3: Mark the spec's status**

In the **pkcs11-scope repo**, edit
`docs/superpowers/specs/2026-08-10-module-crate-extraction-design.md`
status line from "Proposed — revision 4 …" to
"Implemented — revision 4 approved by external review; extraction landed
(see pkcs11-proxy-ng `crates/module`)", and commit:

```bash
git add docs/superpowers/specs/2026-08-10-module-crate-extraction-design.md
git commit -m "spec: mark module-crate extraction implemented"
```

---

## Self-review notes (spec → plan coverage)

- Spec §3 API surface → Tasks 1 (tables/readers), 2 (`tables_for`),
  3 (`function_list`), 4 (`RawInterface`/`interface_list`/seam).
- Spec §5 contract + test matrix → Task 4 Step 1 (all nine rows).
- Spec §6a/§6b + deterministic selection tests → Task 5.
- Spec §7 invariant + exhaustive rows (2.30 refuse / 2.40 base / boundary
  versions) + interface_caps adoption → Task 2.
- Spec §9 checklist: item 1 → Task 1 Step 1; items 2–3 → Task 1 Step 6;
  item 4 → Task 6 (precondition already landed as `866b307`); item 5 →
  Tasks 5 + 7; item 6 → Tasks 2/4/5 (incl. env-gated 3.x test); item 7 →
  Task 6 Step 3.
- Spec §8 (unaligned reads) → Task 1; §10/§13 are consumption/placement
  context with no implementation here; §11/§12 need no code.
