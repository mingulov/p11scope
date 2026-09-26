//! SPDX-License-Identifier: GPL-3.0-or-later
//! Export linkage (GT-2): a provider loaded before attach has no interface,
//! live-return or manifest evidence, so its scan-decoded table used to be
//! named `unknown` throughout. Its own `.dynsym` is a second, independent
//! witness: when every standard name the object defines (non-IFUNC, in the
//! same object) sits exactly at the target its ordinal holds, the table's
//! ordinal names are presented. Presentation only — no slot gains semantic
//! authority, so argument decoding is unchanged.
//!
//! Each case compiles a real 2.40 provider, `dlopen`s it into this test
//! process, and drives the production scan → pin → reconcile → plan chain
//! over the process's own memory.

use super::{CaptureWorkBudget, ScanLimits, ScanRequest, scan_pid};
use crate::discovery::hooks::HookRegistry;
use crate::discovery::identity::{pin_scanned_objects, reconcile_scanned_modules};
use crate::plan::{AttachPlan, build_from_reconciled_modules};
use p11scope_ebpf_common::SlotSemantics;
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;

/// The 2.40 `CK_FUNCTION_LIST` ordinal count.
const LEGACY_ORDINALS: usize = 68;

#[derive(Clone, Copy)]
enum Variant {
    /// Every standard name exported, every ordinal pointing at its export.
    Agreeing,
    /// `C_Sign` and `C_Verify` trade places in the table: the exports
    /// contradict two ordinals.
    Swapped,
    /// `C_CancelFunction` is an alias of `C_GetFunctionStatus`: two ordinals
    /// share one exported stub.
    SharedStub,
    /// Every standard name (including `C_GetFunctionList`) is an IFUNC and
    /// the table holds the resolver addresses — exactly the `st_value` of
    /// each IFUNC symbol. A resolver is not the function.
    IfuncResolvers,
}

fn legacy_names() -> Vec<&'static str> {
    (0..LEGACY_ORDINALS)
        .map(|ordinal| pkcs11_module::function_name(ordinal).expect("2.40 ordinal name"))
        .collect()
}

fn source(variant: Variant) -> String {
    let names = legacy_names();
    let mut c = String::new();
    for (ordinal, name) in names.iter().enumerate() {
        let body = 0x1000 + ordinal;
        match variant {
            Variant::IfuncResolvers => {
                c.push_str(&format!(
                    "static unsigned long impl_{ordinal}(void) {{ return {body}; }}\n\
                     static unsigned long (*resolve_{ordinal}(void))(void) {{ return impl_{ordinal}; }}\n\
                     unsigned long {name}(void) __attribute__((ifunc(\"resolve_{ordinal}\")));\n"
                ));
            }
            Variant::SharedStub if *name == "C_CancelFunction" => {
                c.push_str(
                    "unsigned long C_CancelFunction(void) \
                     __attribute__((alias(\"C_GetFunctionStatus\")));\n",
                );
            }
            _ => c.push_str(&format!(
                "unsigned long {name}(void) {{ return {body}; }}\n"
            )),
        }
    }
    let entry = |ordinal: usize| -> String {
        let name = names[ordinal];
        match variant {
            Variant::IfuncResolvers => format!("(void *)resolve_{ordinal}"),
            Variant::Swapped if name == "C_Sign" => "(void *)C_Verify".into(),
            Variant::Swapped if name == "C_Verify" => "(void *)C_Sign".into(),
            _ => format!("(void *){name}"),
        }
    };
    let entries: Vec<String> = (0..LEGACY_ORDINALS).map(entry).collect();
    c.push_str(&format!(
        "struct p11scope_legacy_table {{ unsigned char major, minor; void *fns[{LEGACY_ORDINALS}]; }};\n\
         __attribute__((used)) static const struct p11scope_legacy_table p11scope_table = \
         {{ 2, 40, {{ {} }} }};\n",
        entries.join(", ")
    ));
    c
}

struct Loaded {
    _dir: tempfile::TempDir,
    path: PathBuf,
    handle: *mut std::ffi::c_void,
}

impl Loaded {
    fn build(variant: Variant) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("provider.c");
        let path = dir.path().join("provider.so");
        std::fs::write(&c, source(variant)).unwrap();
        let output = std::process::Command::new("gcc")
            .args(["-shared", "-fPIC", "-O0", "-o"])
            .arg(&path)
            .arg(&c)
            .output()
            .expect("spawn gcc");
        assert!(
            output.status.success(),
            "the export-linkage fixture must compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: an owned file just written by this test; RTLD_LOCAL keeps
        // its symbols out of every other test in this process, and nothing
        // in it runs at load time.
        let handle = unsafe { libc::dlopen(cpath.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        assert!(!handle.is_null(), "the export-linkage fixture must load");
        Self {
            _dir: dir,
            path,
            handle,
        }
    }

    /// The production chain over this process's own memory.
    fn plan(&self) -> AttachPlan {
        let pid = std::process::id();
        let hooks = HookRegistry::builtin();
        let hints = [self.path.clone()];
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: u64::MAX,
        });
        let outcome = scan_pid(
            &ScanRequest {
                pid,
                hints: &hints,
                hooks: &hooks,
            },
            &mut budget,
        )
        .expect("scan this process");
        let modules = outcome.modules().to_vec();
        assert_eq!(modules.len(), 1, "skipped: {:?}", outcome.skipped());
        assert_eq!(
            modules[0].tables.len(),
            1,
            "exactly the planted table decodes"
        );
        let (mut pinned, skipped) =
            pin_scanned_objects(pid, &modules, &mut budget).expect("pin the fixture");
        assert!(skipped.is_empty(), "{skipped:?}");
        let (reconciled, _, lost) = reconcile_scanned_modules(&modules, &mut pinned);
        assert!(lost.is_empty(), "{lost:?}");
        build_from_reconciled_modules(&reconciled)
    }

    /// `.dynsym` definitions of the standard names, by file offset.
    fn exports_by_offset(&self) -> BTreeMap<u64, Vec<String>> {
        let file = std::fs::File::open(&self.path).unwrap();
        let mut by_offset: BTreeMap<u64, Vec<String>> = BTreeMap::new();
        for (name, offset) in
            p11scope_manifest::elf::exports_matching(&file, &legacy_names()).unwrap()
        {
            by_offset.entry(offset).or_default().push(name);
        }
        for names in by_offset.values_mut() {
            names.sort();
        }
        by_offset
    }
}

impl Drop for Loaded {
    fn drop(&mut self) {
        // SAFETY: the handle came from `dlopen` above and is closed once.
        unsafe { libc::dlclose(self.handle) };
    }
}

fn assert_count_only(plan: &AttachPlan) {
    for slot in &plan.slots {
        assert!(
            !slot.semantic_authorized,
            "export linkage names only; it never authorizes semantics: {slot:?}"
        );
        assert_eq!(slot.semantics, SlotSemantics::COUNT_ONLY, "{slot:?}");
        assert_eq!(slot.descriptor_index, 0, "{slot:?}");
    }
}

/// RED (GT-2): the SoftHSM2 shape — every standard name exported, the table
/// found only heuristically — presents the standard names, publishes
/// `linkage: "exports"`, and stays count-only.
#[test]
fn exported_standard_names_that_agree_with_every_ordinal_name_the_table() {
    let loaded = Loaded::build(Variant::Agreeing);
    let exports = loaded.exports_by_offset();
    assert_eq!(exports.len(), LEGACY_ORDINALS, "every name is its own stub");
    let plan = loaded.plan();

    let tables = &plan.modules[0].tables;
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].linkage, "exports", "{tables:?}");
    assert_eq!(plan.slots.len(), LEGACY_ORDINALS);
    for slot in &plan.slots {
        assert_eq!(
            Some(&slot.names),
            exports.get(&slot.file_offset),
            "slot at {:#x} carries the name exported there",
            slot.file_offset
        );
        assert!(!slot.aliased, "{slot:?}");
    }
    assert_count_only(&plan);
}

/// A table that contradicts any exported name is refused as a whole: the
/// single table predicate never names a suspect layout by position.
#[test]
fn one_contradicted_export_leaves_every_ordinal_unknown() {
    let loaded = Loaded::build(Variant::Swapped);
    let plan = loaded.plan();

    assert_eq!(plan.modules[0].tables[0].linkage, "heuristic");
    assert_eq!(plan.slots.len(), LEGACY_ORDINALS);
    for slot in &plan.slots {
        assert_eq!(slot.names, ["unknown"], "{slot:?}");
    }
    assert_count_only(&plan);
}

/// Two ordinals on one exported stub are one target: one row, both names,
/// aliased — the grouping README promises to disclose.
#[test]
fn two_ordinals_on_one_exported_stub_are_one_aliased_row() {
    let loaded = Loaded::build(Variant::SharedStub);
    let exports = loaded.exports_by_offset();
    let shared = exports
        .iter()
        .find(|(_, names)| names.len() == 2)
        .map(|(offset, names)| (*offset, names.clone()))
        .expect("the alias shares one offset");
    assert_eq!(shared.1, ["C_CancelFunction", "C_GetFunctionStatus"]);
    let plan = loaded.plan();

    assert_eq!(plan.modules[0].tables[0].linkage, "exports");
    assert_eq!(plan.slots.len(), LEGACY_ORDINALS - 1);
    let slot = plan
        .slots
        .iter()
        .find(|slot| slot.file_offset == shared.0)
        .expect("the shared stub is one slot");
    assert_eq!(slot.names, shared.1);
    assert!(slot.aliased);
    assert_count_only(&plan);
}

/// An IFUNC symbol's value is its resolver, never the function. A table
/// pointing at every resolver lines up with every `st_value` and must still
/// not be named: IFUNC definitions are not export witnesses.
#[test]
fn ifunc_resolver_addresses_never_corroborate_a_table() {
    let loaded = Loaded::build(Variant::IfuncResolvers);
    assert!(
        loaded.exports_by_offset().is_empty(),
        "no standard name has a non-IFUNC definition"
    );
    let plan = loaded.plan();

    assert_eq!(plan.modules[0].tables[0].linkage, "heuristic");
    for slot in &plan.slots {
        assert_eq!(slot.names, ["unknown"], "{slot:?}");
    }
    assert_count_only(&plan);
}

#[test]
fn the_fixture_source_is_the_2_40_layout() {
    // Guard the fixture itself: 68 functions, the version bytes first.
    let text = source(Variant::Agreeing);
    assert_eq!(text.matches("unsigned long C_").count(), LEGACY_ORDINALS);
    assert!(text.contains("{ 2, 40, {"));
}
