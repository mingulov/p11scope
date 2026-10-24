//! SPDX-License-Identifier: GPL-3.0-or-later
//! Hostile provider-table regression tests: modules whose `C_GetFunctionList`
//! or `C_GetInterfaceList` return null pointers, hostile versions, garbage
//! addresses or lying counts must be recorded as evidence, never walked as
//! valid tables. No hostile provider yields attributed (resolved) functions,
//! and no provider pointer is ever dereferenced unsafely.

use p11scope_discover::discover::discover;
use p11scope_manifest::manifest::{Acquisition, Resolution, SurfaceSource, WalkOutcome};
use std::path::{Path, PathBuf};
use std::process::Command;

fn workdir(name: &str) -> PathBuf {
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| {
        std::env::var("CARGO_TARGET_TMPDIR").expect("TMPDIR or CARGO_TARGET_TMPDIR")
    });
    let dir = PathBuf::from(base).join(format!("hostile-tables-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_provider(dir: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).unwrap();
    let so = dir.join(format!("{name}.so"));
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-O2", "-o"])
            .arg(&so)
            .arg(&src)
            .status()
            .unwrap()
            .success(),
        "gcc failed for {name}"
    );
    so
}

/// Every hostile provider module built by this file's tests, grouped by the
/// owning test. Each test builds its names from its slice and asserts it
/// built exactly that slice; `hostile_provider_corpus_is_pinned` pins the
/// exact membership, so the corpus cannot shrink silently.
/// `unusable_module_paths_are_refused` builds nothing (path-only refusals).
const HOSTILE_PROVIDERS: &[&str] = &[
    // null_and_failing_legacy_acquisitions_are_errors
    "null_table",
    "bad_rv",
    // module_without_pkcs11_exports_is_refused_not_attributed
    "plain",
    // hostile_versions_are_never_walked
    "version_9_9",
    "version_0_0",
    "version_4_0",
    "version_2_255",
    // unmapped_table_pointer_is_unreadable
    "unmapped_ptr",
    // garbage_slots_resolve_only_the_real_code_pointer
    "slots",
    // lying_interface_counts_are_capped
    "crowded",
    "growing",
    "overfill",
    // hostile_interface_names_and_lists_are_evidence_only
    "ifaces",
];

/// Builds `name` from `source`, recording the name so each test can assert it
/// built exactly its [`HOSTILE_PROVIDERS`] slice.
fn build_tracked<'a>(
    dir: &Path,
    built: &mut Vec<&'a str>,
    name: &'a str,
    source: &str,
) -> PathBuf {
    built.push(name);
    build_provider(dir, name, source)
}

/// Only the legacy slot exists and it records absence: no standard
/// interface surface was walked.
fn only_absent_legacy(manifest: &p11scope_manifest::manifest::Manifest) -> bool {
    manifest.surfaces.len() == 1
        && manifest.surfaces[0].source == SurfaceSource::LegacyFunctionList
        && manifest.surfaces[0].acquisition == Acquisition::Absent
}

/// No function in the manifest may resolve to an address: hostile tables
/// attribute nothing.
fn assert_nothing_resolved(manifest: &p11scope_manifest::manifest::Manifest, context: &str) {
    for surface in &manifest.surfaces {
        for function in &surface.functions {
            assert!(
                !matches!(function.resolution, Resolution::Resolved { .. }),
                "{context}: hostile table resolved {}",
                function.name
            );
        }
    }
    for table in &manifest.selection_evidence.tables {
        for function in &table.functions {
            assert!(
                !matches!(function.resolution, Resolution::Resolved { .. }),
                "{context}: hostile selection table resolved {}",
                function.name
            );
        }
    }
}

#[test]
fn null_and_failing_legacy_acquisitions_are_errors() {
    let dir = workdir("legacy-absent");
    let mut built = Vec::new();
    let null = build_tracked(
        &dir,
        &mut built,
        HOSTILE_PROVIDERS[0],
        r#"typedef unsigned long CK_RV;
unsigned long C_GetFunctionList(void **out){ *out = 0; return 0; }
"#,
    );
    let manifest = discover(&null).expect("null table must record evidence, not fail discovery");
    let surface = &manifest.surfaces[0];
    assert!(
        matches!(surface.acquisition, Acquisition::Error { ref detail } if detail.contains("null")),
        "null: {:?}",
        surface.acquisition
    );
    assert_eq!(surface.walk, WalkOutcome::NotWalked);
    assert!(surface.functions.is_empty());
    assert_nothing_resolved(&manifest, "null table");

    let bad_rv = build_tracked(
        &dir,
        &mut built,
        HOSTILE_PROVIDERS[1],
        r#"typedef unsigned long CK_RV;
unsigned long C_GetFunctionList(void **out){ (void)out; return 7; }
"#,
    );
    let manifest = discover(&bad_rv).expect("bad rv must record evidence, not fail discovery");
    let surface = &manifest.surfaces[0];
    assert!(
        matches!(surface.acquisition, Acquisition::Error { ref detail } if detail.contains("0x00000007")),
        "bad rv: {:?}",
        surface.acquisition
    );
    assert_nothing_resolved(&manifest, "bad rv");
    assert_eq!(built, HOSTILE_PROVIDERS[0..2]);
}

#[test]
fn module_without_pkcs11_exports_is_refused_not_attributed() {
    let dir = workdir("no-exports");
    let mut built = Vec::new();
    let plain = build_tracked(
        &dir,
        &mut built,
        HOSTILE_PROVIDERS[2],
        "int plain_symbol(void){return 1;}\n",
    );
    // No acquisition export exists, so discovery refuses outright with no
    // manifest at all — nothing is attributed to the module.
    let error = discover(&plain).unwrap_err();
    assert!(
        error.contains("no module acquisition export"),
        "export-less module must be refused as unacquirable: {error}"
    );
    assert_eq!(built, HOSTILE_PROVIDERS[2..3]);
}

#[test]
fn hostile_versions_are_never_walked() {
    let dir = workdir("versions");
    let mut built = Vec::new();
    let cases = [(9u8, 9u8), (0, 0), (4, 0), (2, 255)];
    assert_eq!(cases.len(), HOSTILE_PROVIDERS[3..7].len());
    for ((major, minor), name) in cases.into_iter().zip(&HOSTILE_PROVIDERS[3..7]) {
        assert_eq!(name, &format!("version_{major}_{minor}"));
        let provider = build_tracked(
            &dir,
            &mut built,
            name,
            &format!(
                r#"typedef unsigned char CK_BYTE;
typedef unsigned long CK_RV;
typedef struct {{ CK_BYTE major; CK_BYTE minor; }} CK_VERSION;
typedef struct {{ CK_VERSION version; void *functions[104]; }} Table;
static Table table;
__attribute__((constructor)) static void fill(void){{
    table.version.major = {major}; table.version.minor = {minor};
    for (int i = 0; i < 104; i++) table.functions[i] = (void *)0xdeadbeef;
}}
CK_RV C_GetFunctionList(void **out){{ *out = &table; return 0; }}
"#
            ),
        );
        let manifest = discover(&provider).expect("hostile version must record evidence");
        let surface = &manifest.surfaces[0];
        assert_eq!(surface.acquisition, Acquisition::Ok);
        let version = surface
            .version
            .as_ref()
            .expect("reported version is recorded");
        assert_eq!((version.major, version.minor), (major, minor));
        // 2.255 walks its known 2.40 prefix; every other hostile version
        // refuses the walk. Either way nothing resolves.
        assert!(
            matches!(
                surface.walk,
                WalkOutcome::Refused | WalkOutcome::KnownPrefix | WalkOutcome::Full
            ),
            "version {major}.{minor}: {:?}",
            surface.walk
        );
        assert_nothing_resolved(&manifest, &format!("version {major}.{minor}"));
        if (major, minor) != (2, 255) {
            assert_eq!(surface.walk, WalkOutcome::Refused);
            assert!(surface.functions.is_empty());
        }
    }
    assert_eq!(built, HOSTILE_PROVIDERS[3..7]);
}

#[test]
fn unmapped_table_pointer_is_unreadable() {
    let dir = workdir("unmapped");
    let mut built = Vec::new();
    let provider = build_tracked(
        &dir,
        &mut built,
        HOSTILE_PROVIDERS[7],
        r#"typedef unsigned long CK_RV;
CK_RV C_GetFunctionList(void **out){ *out = (void *)0xdeadbeefdeadbeefUL; return 0; }
"#,
    );
    let manifest = discover(&provider).expect("unmapped pointer must record evidence");
    let surface = &manifest.surfaces[0];
    assert_eq!(surface.acquisition, Acquisition::Ok);
    assert!(
        matches!(surface.walk, WalkOutcome::Unreadable { .. }),
        "unmapped: {:?}",
        surface.walk
    );
    assert!(surface.functions.is_empty());
    assert_nothing_resolved(&manifest, "unmapped pointer");
    assert_eq!(built, HOSTILE_PROVIDERS[7..8]);
}

#[test]
fn garbage_slots_resolve_only_the_real_code_pointer() {
    let dir = workdir("slots");
    let mut built = Vec::new();
    let provider = build_tracked(
        &dir,
        &mut built,
        HOSTILE_PROVIDERS[8],
        r#"typedef unsigned char CK_BYTE;
typedef unsigned long CK_RV;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { CK_VERSION version; void *functions[68]; } Table;
static Table table;
static int filler_data = 42;
static int real_target(void){ return filler_data; }
__attribute__((constructor)) static void fill(void){
    table.version.major = 2; table.version.minor = 40;
    for (int i = 0; i < 68; i++) table.functions[i] = 0;
    table.functions[0] = (void *)real_target;   // file-backed executable: resolves
    table.functions[1] = (void *)0x1;           // unmapped: evidence only
    table.functions[2] = (void *)0xdeadbeefUL;  // unmapped: evidence only
    table.functions[3] = (void *)&filler_data;  // file-backed data: not executable
}
CK_RV C_GetFunctionList(void **out){ *out = &table; return 0; }
"#,
    );
    let manifest = discover(&provider).expect("mixed slots must record evidence");
    let surface = &manifest.surfaces[0];
    assert_eq!(surface.walk, WalkOutcome::Full);
    let resolved: Vec<&str> = surface
        .functions
        .iter()
        .filter(|function| matches!(function.resolution, Resolution::Resolved { .. }))
        .map(|function| function.name.as_str())
        .collect();
    assert_eq!(
        resolved.len(),
        1,
        "exactly the code pointer resolves: {resolved:?}"
    );
    assert_eq!(resolved[0], "C_Initialize");
    // Every other published slot is present as explicit evidence, never
    // silently dropped and never resolved.
    assert_eq!(surface.functions.len(), 68);
    for function in &surface.functions {
        if let Resolution::Resolved { file_offset, .. } = &function.resolution {
            let len = std::fs::metadata(&provider).unwrap().len();
            assert!(*file_offset < len, "resolved offset out of range");
        }
    }
    assert_eq!(built, HOSTILE_PROVIDERS[8..9]);
}

#[test]
fn lying_interface_counts_are_capped() {
    let dir = workdir("iface-count");
    let mut built = Vec::new();
    // 300 interfaces over the 256 cap.
    let crowded = build_tracked(
        &dir,
        &mut built,
        HOSTILE_PROVIDERS[9],
        r#"typedef unsigned long CK_RV; typedef unsigned long CK_ULONG; typedef unsigned long CK_FLAGS;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;
CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count){
    if (!out) { *count = 300; return 0; }
    return 7;
}
"#,
    );
    let manifest = discover(&crowded).expect("lying count must record evidence");
    assert!(
        matches!(manifest.interface_list, Acquisition::Error { ref detail } if detail.contains("cap is 256")),
        "crowded: {:?}",
        manifest.interface_list
    );
    assert!(only_absent_legacy(&manifest));
    assert!(manifest.vendor_interfaces.is_empty());
    // A count that keeps growing exhausts the retry budget.
    let growing = build_tracked(
        &dir,
        &mut built,
        HOSTILE_PROVIDERS[10],
        r#"typedef unsigned long CK_RV; typedef unsigned long CK_ULONG; typedef unsigned long CK_FLAGS;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;
CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count){
    if (!out) { *count = 2; return 0; }
    return 0x150;
}
"#,
    );
    let manifest = discover(&growing).expect("growing count must record evidence");
    assert!(
        matches!(manifest.interface_list, Acquisition::Error { ref detail } if detail.contains("kept growing")),
        "growing: {:?}",
        manifest.interface_list
    );
    // A fill count larger than the reservation is refused.
    let overfill = build_tracked(
        &dir,
        &mut built,
        HOSTILE_PROVIDERS[11],
        r#"typedef unsigned long CK_RV; typedef unsigned long CK_ULONG; typedef unsigned long CK_FLAGS;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;
static CK_INTERFACE one[1];
CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count){
    if (!out) { *count = 1; return 0; }
    out[0] = one[0]; *count = 2; return 0;
}
"#,
    );
    let manifest = discover(&overfill).expect("overfill must record evidence");
    assert!(
        matches!(manifest.interface_list, Acquisition::Error { ref detail } if detail.contains("written into capacity")),
        "overfill: {:?}",
        manifest.interface_list
    );
    assert_eq!(built, HOSTILE_PROVIDERS[9..12]);
}

#[test]
fn hostile_interface_names_and_lists_are_evidence_only() {
    let dir = workdir("iface-names");
    let mut built = Vec::new();
    let provider = build_tracked(
        &dir,
        &mut built,
        HOSTILE_PROVIDERS[12],
        r#"typedef unsigned long CK_RV; typedef unsigned long CK_ULONG; typedef unsigned long CK_FLAGS;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;
static char vendor_name[] = "vendor-hostile-interface";
static CK_INTERFACE ifaces[4];
__attribute__((constructor)) static void fill(void){
    ifaces[0].pInterfaceName = 0;                    // NULL name
    ifaces[0].pFunctionList = 0;
    ifaces[1].pInterfaceName = (char *)0x12345;      // unreadable name
    ifaces[1].pFunctionList = 0;
    ifaces[2].pInterfaceName = vendor_name;          // vendor name, NULL list
    ifaces[2].pFunctionList = 0;
    ifaces[3].pInterfaceName = vendor_name;          // vendor name, garbage list
    ifaces[3].pFunctionList = (void *)0x54321;
}
CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count){
    if (!out) { *count = 4; return 0; }
    for (int i = 0; i < 4; i++) out[i] = ifaces[i];
    *count = 4; return 0;
}
"#,
    );
    let manifest = discover(&provider).expect("hostile interfaces must record evidence");
    assert_eq!(manifest.interface_list, Acquisition::Ok);
    // Vendor names are never walked as standard surfaces.
    assert!(
        only_absent_legacy(&manifest),
        "vendor names must not walk: {:?}",
        manifest.surfaces
    );
    assert_eq!(manifest.vendor_interfaces.len(), 4);
    for vendor in &manifest.vendor_interfaces {
        assert!(
            vendor.name_error.is_some() || vendor.raw_name_hex.is_some(),
            "each hostile name keeps evidence: {vendor:?}"
        );
    }
    assert_nothing_resolved(&manifest, "hostile interfaces");
    assert_eq!(built, HOSTILE_PROVIDERS[12..13]);
}

#[test]
fn hostile_provider_corpus_is_pinned() {
    // The hostile corpus is a fixed compiled-provider set (byte-mutating a
    // dlopened .so per iteration would blow the per-target time budget); pin
    // its exact membership so it cannot shrink silently.
    assert_eq!(
        HOSTILE_PROVIDERS,
        &[
            "null_table",
            "bad_rv",
            "plain",
            "version_9_9",
            "version_0_0",
            "version_4_0",
            "version_2_255",
            "unmapped_ptr",
            "slots",
            "crowded",
            "growing",
            "overfill",
            "ifaces",
        ]
    );
}

#[test]
fn unusable_module_paths_are_refused() {
    let dir = workdir("paths");
    assert!(
        discover(Path::new("relative/path.so"))
            .unwrap_err()
            .contains("absolute")
    );
    // Identity precedes dlopen, so a missing file fails the open.
    assert!(
        discover(&dir.join("missing.so"))
            .unwrap_err()
            .contains("cannot open")
    );
    let text = dir.join("not-an-object.txt");
    std::fs::write(&text, b"plain text, not an ELF\n").unwrap();
    assert!(discover(&text).is_err());
}
