//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Export linkage (GT-2): a provider loaded before attach has no interface,
//! live-return or manifest evidence, so its scan-decoded table used to be
//! named `unknown` throughout. Its own `.dynsym` is a second, independent
//! witness: when every standard name the object defines (non-IFUNC, in the
//! same object) sits exactly at the target its ordinal holds, the table's
//! ordinal names are presented. Presentation only — no slot gains semantic
//! authority, so argument decoding is unchanged.
//!
//! Each case compiles a real 2.40 provider, loads it into an owned stopped
//! child, and drives the production scan → pin → reconcile → plan chain
//! over that child's stable memory.

use super::{CaptureWorkBudget, ScanLimits, ScanRequest, Skipped, scan_pid};
use crate::discovery::hooks::HookRegistry;
use crate::discovery::identity::{
    PinnedObjects, ReconciledModule, pin_scanned_objects, reconcile_scanned_modules,
};
use crate::discovery::test_subject::OwnedMapper;
use crate::fixture_guard::DieWithParent as _;
use crate::plan::{AttachPlan, build_from_reconciled_modules};
use p11scope_ebpf_common::SlotSemantics;
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

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
    /// Like `Agreeing`, plus a 3.x interface getter exported as an IFUNC:
    /// no definition in the witness, but the presence bit must survive
    /// the pin → bind chain.
    IfuncGetter,
    /// The Fedora/Chromium shape: the table is stamped 3.2 (with a
    /// deterministic non-pointer tail refuting wider layouts), and the
    /// loader preloads a second provider exporting `C_GetFunctionList`,
    /// so the bootstrap slot forwards out of the module by ordinary
    /// dynamic-linker interposition.
    Interposed32,
    /// The hostile twin of [`Variant::Interposed32`]: the table is stamped
    /// 3.2 with the same deterministic tail, but its bootstrap slot points
    /// at the preload's *decoy* export instead of the preload's
    /// `C_GetFunctionList` — a forwarded bootstrap to a wrong offset.
    /// The forward must be refused and every ordinal must stay `unknown`.
    Misdirected32,
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
            Variant::Misdirected32 if name == "C_GetFunctionList" => {
                "(void *)p11scope_decoy".into()
            }
            _ => format!("(void *){name}"),
        }
    };
    let entries: Vec<String> = (0..LEGACY_ORDINALS).map(entry).collect();
    if matches!(variant, Variant::Misdirected32) {
        // The reference must link: the provider defines the decoy too, but
        // the globally preloaded decoy wins the relocation by load order,
        // so the bootstrap slot forwards out of the module to a wrong
        // offset. Distinct body, so the two decoys can never fold.
        c.push_str("unsigned long p11scope_decoy(void) { return 0xDEC07; }\n");
    }
    if matches!(variant, Variant::Interposed32 | Variant::Misdirected32) {
        // The 3.2 stamp walks the 68-slot known prefix; the embedded tail
        // of small non-pointer words refutes wider layouts at ordinal 68
        // deterministically (low addresses never resolve to executable
        // file mappings), proving the prefix complete.
        let tail: Vec<String> = (1..=24).map(|word| word.to_string()).collect();
        c.push_str(&format!(
            "struct p11scope_legacy_table {{ unsigned char major, minor; void *fns[{LEGACY_ORDINALS}]; unsigned long tail[24]; }};\n\
             __attribute__((used)) static const struct p11scope_legacy_table p11scope_table = \
             {{ 3, 2, {{ {} }}, {{ {} }} }};\n",
            entries.join(", "),
            tail.join(", ")
        ));
    } else {
        c.push_str(&format!(
            "struct p11scope_legacy_table {{ unsigned char major, minor; void *fns[{LEGACY_ORDINALS}]; }};\n\
             __attribute__((used)) static const struct p11scope_legacy_table p11scope_table = \
             {{ 2, 40, {{ {} }} }};\n",
            entries.join(", ")
        ));
    }
    if matches!(variant, Variant::IfuncGetter) {
        c.push_str(
            "static unsigned long get_interface_impl(void) { return 0; }\n\
             static void *get_interface_resolver(void) { return (void *)get_interface_impl; }\n\
             unsigned long C_GetInterface(void) __attribute__((ifunc(\"get_interface_resolver\")));\n",
        );
    }
    c
}

struct Loaded {
    // Declaration order drops the owned child before removing its executable
    // and provider. Keep it stopped through scan, pin, reconcile and plan.
    subject: OwnedMapper,
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn build_loader(dir: &Path) -> PathBuf {
    let source = dir.join("load-only.c");
    let driver = dir.join("load-only");
    std::fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 64;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        (void)write(STDERR_FILENO, "fixture dlopen failed\n", 22);
        return 65;
    }
    if (write(STDOUT_FILENO, "ready\n", 6) != 6) return 66;
    char input;
    ssize_t result;
    do { result = read(STDIN_FILENO, &input, 1); }
    while (result < 0 && errno == EINTR);
    dlclose(handle);
    return result < 0 ? 67 : 0;
}
"#,
    )
    .unwrap();
    let output = std::process::Command::new("gcc")
        .args(["-O0", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&driver)
        .arg(&source)
        .arg("-ldl")
        .output()
        .expect("spawn gcc for load-only fixture");
    assert!(
        output.status.success(),
        "the load-only fixture must compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    driver
}

/// A second provider exporting exactly `sources`, so a provider loaded
/// after it (globally visible) interposes the names it references.
fn build_preload_source(dir: &Path, stem: &str, sources: &str) -> PathBuf {
    let c = dir.join(format!("{stem}.c"));
    let path = dir.join(format!("{stem}.so"));
    std::fs::write(&c, sources).unwrap();
    let output = std::process::Command::new("gcc")
        .args(["-shared", "-fPIC", "-O0", "-o"])
        .arg(&path)
        .arg(&c)
        .output()
        .expect("spawn gcc for the preload fixture");
    assert!(
        output.status.success(),
        "the preload fixture must compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

/// A second provider exporting only the `C_GetFunctionList` bootstrap, so a
/// provider loaded after it (globally visible) interposes that one slot.
fn build_preload(dir: &Path) -> PathBuf {
    build_preload_source(
        dir,
        "preload",
        "unsigned long C_GetFunctionList(void) { return 0xC11CE5; }\n",
    )
}

/// The misdirected twin's preload: the genuine bootstrap plus a decoy
/// export at a different offset, so the bootstrap slot can forward to a
/// wrong offset while the rest of the table agrees.
fn build_decoy_preload(dir: &Path) -> PathBuf {
    build_preload_source(
        dir,
        "decoy-preload",
        "unsigned long C_GetFunctionList(void) { return 0xC11CE5; }\n\
         unsigned long p11scope_decoy(void) { return 0xDEC09; }\n",
    )
}

fn build_interposed_loader(dir: &Path) -> PathBuf {
    let source = dir.join("load-interposed.c");
    let driver = dir.join("load-interposed");
    std::fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    void *pre = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (!pre) {
        (void)write(STDERR_FILENO, "fixture preload failed\n", 23);
        return 65;
    }
    void *handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        (void)write(STDERR_FILENO, "fixture dlopen failed\n", 22);
        return 65;
    }
    if (write(STDOUT_FILENO, "ready\n", 6) != 6) return 66;
    char input;
    ssize_t result;
    do { result = read(STDIN_FILENO, &input, 1); }
    while (result < 0 && errno == EINTR);
    dlclose(handle);
    dlclose(pre);
    return result < 0 ? 67 : 0;
}
"#,
    )
    .unwrap();
    let output = std::process::Command::new("gcc")
        .args(["-O0", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&driver)
        .arg(&source)
        .arg("-ldl")
        .output()
        .expect("spawn gcc for load-interposed fixture");
    assert!(
        output.status.success(),
        "the load-interposed fixture must compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    driver
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
        let child = std::process::Command::new(build_loader(dir.path()))
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .die_with_parent()
            .spawn()
            .expect("spawn owned load-only subject");
        let subject = OwnedMapper::from_child(child, std::time::Duration::from_secs(5))
            .expect("the loaded subject must acknowledge readiness and stop");
        Self {
            subject,
            _dir: dir,
            path,
        }
    }

    /// The interposed twin: the preload lands first and globally visible,
    /// so the provider's bootstrap relocation binds to the preload's
    /// `C_GetFunctionList`. Returns the loaded subject and the preload path.
    fn build_interposed() -> (Self, PathBuf) {
        Self::build_interposed_like(Variant::Interposed32, build_preload)
    }

    /// The misdirected twin: the decoy preload lands first and globally
    /// visible, so the provider's bootstrap slot binds to the preload's
    /// decoy export — a forwarded bootstrap to a wrong offset — while the
    /// other 67 slots bind to the provider's own definitions.
    fn build_misdirected() -> (Self, PathBuf) {
        Self::build_interposed_like(Variant::Misdirected32, build_decoy_preload)
    }

    fn build_interposed_like(
        variant: Variant,
        build_preload: fn(&Path) -> PathBuf,
    ) -> (Self, PathBuf) {
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
        let preload = build_preload(dir.path());
        let child = std::process::Command::new(build_interposed_loader(dir.path()))
            .arg(&preload)
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .die_with_parent()
            .spawn()
            .expect("spawn owned load-interposed subject");
        let subject = OwnedMapper::from_child(child, std::time::Duration::from_secs(5))
            .expect("the loaded subject must acknowledge readiness and stop");
        let loaded = Self {
            subject,
            _dir: dir,
            path,
        };
        (loaded, preload)
    }

    /// The production scan → pin → reconcile chain over the retained
    /// stopped child's memory.
    fn reconciled(&self) -> (Vec<ReconciledModule>, PinnedObjects) {
        let pid = self.subject.pid();
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
        .expect("scan the owned stopped subject");
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
        (reconciled, pinned)
    }

    /// The production chain without the no-loss assertion, for twins whose
    /// shape must refuse an entry: returns the refused records too.
    fn reconciled_with_loss(&self) -> (Vec<ReconciledModule>, PinnedObjects, Vec<Skipped>) {
        let pid = self.subject.pid();
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
        .expect("scan the owned stopped subject");
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
        (reconciled, pinned, lost)
    }

    /// The production chain over the retained stopped child's memory.
    fn plan(&self) -> AttachPlan {
        let (reconciled, _) = self.reconciled();
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

#[test]
fn export_fixture_keeps_provider_out_of_parent_mappings() {
    let loaded = Loaded::build(Variant::Agreeing);
    let maps = std::fs::read("/proc/self/maps").unwrap();
    assert!(
        !maps
            .windows(loaded.path.as_os_str().as_bytes().len())
            .any(|bytes| bytes == loaded.path.as_os_str().as_bytes()),
        "the export fixture must load into its owned subject, outside the test process"
    );
}

fn assert_reaped(pid: u32) {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: a non-signaling, non-consuming check of our former child.
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn export_subject_stays_stopped_and_stable_through_parent_changes_and_plan() {
    struct Mapping(*mut libc::c_void, usize);
    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: this guard owns exactly this successful anonymous map.
            assert_eq!(unsafe { libc::munmap(self.0, self.1) }, 0);
        }
    }

    let loaded = Loaded::build(Variant::Agreeing);
    let pid = loaded.subject.pid();
    assert_ne!(pid, std::process::id());
    assert_eq!(
        std::fs::read_link(format!("/proc/{pid}/exe")).unwrap(),
        loaded._dir.path().join("load-only")
    );
    let snapshot = || {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: observe the retained child's stop without consuming custody.
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid,
                    info.as_mut_ptr(),
                    libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            0
        );
        // SAFETY: valid zero-initialized output from successful waitid.
        let info = unsafe { info.assume_init() };
        assert_eq!(unsafe { info.si_pid() }, pid as i32);
        assert_eq!(info.si_code, libc::CLD_STOPPED);
        assert_eq!(unsafe { info.si_status() }, libc::SIGSTOP);
        std::fs::read(format!("/proc/{pid}/maps")).unwrap()
    };
    let before = snapshot();
    assert!(
        before
            .windows(loaded.path.as_os_str().as_bytes().len())
            .any(|bytes| bytes == loaded.path.as_os_str().as_bytes())
    );

    // Change only a new kernel-chosen range owned by this parent, after exec
    // and acknowledged stop established the subject's separate mapping space.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    assert!(page > 0);
    let size = page.checked_mul(3).unwrap();
    // SAFETY: anonymous mapping, no fixed address or borrowed range.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(address, libc::MAP_FAILED);
    let mapping = Mapping(address, size);
    // SAFETY: the page-aligned middle page is within our retained mapping.
    assert_eq!(
        unsafe { libc::mprotect(address.byte_add(page), page, libc::PROT_READ) },
        0
    );
    assert_eq!(snapshot(), before);
    let plan = loaded.plan();
    assert_eq!(plan.modules.len(), 1);
    assert_eq!(plan.modules[0].tables[0].linkage, "exports");
    assert_eq!(plan.slots.len(), LEGACY_ORDINALS);
    assert_count_only(&plan);
    assert_eq!(snapshot(), before);
    drop(mapping);
    assert_eq!(snapshot(), before);
    let directory = loaded._dir.path().to_path_buf();
    drop(loaded);
    assert_reaped(pid);
    assert!(!directory.exists());
}

#[test]
fn export_loader_failure_reaps_the_owned_child() {
    let dir = tempfile::tempdir().unwrap();
    let stderr = dir.path().join("stderr");
    let child = std::process::Command::new(build_loader(dir.path()))
        .arg(dir.path().join("absent-provider.so"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .die_with_parent()
        .spawn()
        .unwrap();
    let pid = child.id();
    assert!(OwnedMapper::from_child(child, std::time::Duration::from_secs(5)).is_err());
    assert_eq!(std::fs::read(stderr).unwrap(), b"fixture dlopen failed\n");
    assert_reaped(pid);
}

#[test]
fn export_early_exit_reaps_the_owned_child() {
    let child = std::process::Command::new("sh")
        .args(["-c", "exit 0"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    assert!(OwnedMapper::from_child(child, std::time::Duration::from_secs(5)).is_err());
    assert_reaped(pid);
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

/// RED (live triage): the Fedora/Chromium shape — a 3.2-stamped table whose
/// bootstrap slot forwards to a preloaded provider's same-named export by
/// ordinary linker interposition — still names every ordinal (linkage
/// `exports`) and publishes the proven-complete prefix as a full walk.
/// The unanimous 67 same-object agreements prove the layout; the forwarded
/// bootstrap keeps its ABI-definitional name instead of poisoning the table.
#[test]
fn interposed_bootstrap_names_the_table_and_publishes_full_walk() {
    let (loaded, preload) = Loaded::build_interposed();
    let exports = loaded.exports_by_offset();
    assert_eq!(exports.len(), LEGACY_ORDINALS, "every name is its own stub");
    let preload_file = std::fs::File::open(&preload).unwrap();
    let preload_offsets =
        p11scope_manifest::elf::exports_matching(&preload_file, &["C_GetFunctionList"]).unwrap();
    assert_eq!(
        preload_offsets.len(),
        1,
        "the preload exports the bootstrap"
    );
    let (_, preload_offset) = &preload_offsets[0];
    let plan = loaded.plan();

    let tables = &plan.modules[0].tables;
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].version, (3, 2), "{tables:?}");
    assert_eq!(tables[0].linkage, "exports", "{tables:?}");
    assert_eq!(plan.slots.len(), LEGACY_ORDINALS);
    let (forwarded, local): (Vec<_>, Vec<_>) = plan
        .slots
        .iter()
        .partition(|slot| slot.names == ["C_GetFunctionList"]);
    assert_eq!(forwarded.len(), 1, "one bootstrap slot: {:?}", plan.slots);
    assert_eq!(
        forwarded[0].file_offset, *preload_offset,
        "the bootstrap slot targets the preload's export: {:?}",
        forwarded[0]
    );
    for slot in local {
        assert_eq!(
            Some(&slot.names),
            exports.get(&slot.file_offset),
            "slot at {:#x} carries the name exported there",
            slot.file_offset
        );
    }
    for slot in &plan.slots {
        assert!(!slot.aliased, "{slot:?}");
    }
    let surface = plan
        .surfaces
        .iter()
        .find(|surface| surface.source.contains("table 3.2"))
        .expect("the 3.2 table surface is published");
    assert_eq!(surface.walk, "full", "{surface:?}");
    assert_eq!(surface.acquisition, "ok", "{surface:?}");
    assert_eq!(surface.functions, LEGACY_ORDINALS, "{surface:?}");
    assert_count_only(&plan);
}

/// RED (fix round): a bootstrap slot forwarded to a *wrong* offset —
/// the preload's decoy export, not its `C_GetFunctionList` — must not
/// name the table, even though the other 67 entries agree in-object.
/// The forward is refused at bind time (unpinned with a reason) and every
/// ordinal stays `unknown` (linkage `heuristic`, no full walk): the
/// bootstrap exemption trusts only a forward the pinned target's own
/// `.dynsym` resolves by name.
#[test]
fn forwarded_bootstrap_to_a_wrong_offset_stays_unnamed() {
    let (loaded, preload) = Loaded::build_misdirected();
    let preload_file = std::fs::File::open(&preload).unwrap();
    let mut preload_offsets = p11scope_manifest::elf::exports_matching(
        &preload_file,
        &["C_GetFunctionList", "p11scope_decoy"],
    )
    .unwrap();
    preload_offsets.sort();
    assert_eq!(
        preload_offsets.len(),
        2,
        "the preload exports the bootstrap and the decoy"
    );
    let bootstrap = preload_offsets
        .iter()
        .find(|(name, _)| name == "C_GetFunctionList")
        .map(|(_, offset)| *offset)
        .expect("the preload exports the bootstrap");
    let decoy = preload_offsets
        .iter()
        .find(|(name, _)| name == "p11scope_decoy")
        .map(|(_, offset)| *offset)
        .expect("the preload exports the decoy");
    assert_ne!(
        bootstrap, decoy,
        "the decoy must sit at a different offset than the bootstrap"
    );
    let (reconciled, _pinned, lost) = loaded.reconciled_with_loss();
    assert_eq!(reconciled.len(), 1);
    assert_eq!(
        lost.len(),
        1,
        "exactly the misdirected bootstrap is refused: {lost:?}"
    );
    assert_eq!(lost[0].subject, "C_GetFunctionList");
    assert!(
        lost[0].reason.contains("C_GetFunctionList") && lost[0].reason.contains("not attached"),
        "the refusal names the check and the outcome: {}",
        lost[0].reason
    );
    let plan = build_from_reconciled_modules(&reconciled);
    let tables = &plan.modules[0].tables;
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].version, (3, 2), "{tables:?}");
    assert_eq!(tables[0].linkage, "heuristic", "{tables:?}");
    assert_eq!(plan.slots.len(), LEGACY_ORDINALS - 1);
    for slot in &plan.slots {
        assert_eq!(slot.names, ["unknown"], "{slot:?}");
    }
    let surface = plan
        .surfaces
        .iter()
        .find(|surface| surface.source.contains("table 3.2"))
        .expect("the 3.2 table surface is published");
    assert_eq!(surface.walk, "known_prefix", "{surface:?}");
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

/// The witness flags ride the production pin → bind chain: the compiled
/// fixture exports its 3.x getter as an IFUNC (no definition in the
/// witness), yet the pinned entry and the bound module both record the
/// presence bit. Stubbing `export_witness_flags_for` to `(false, false)`
/// turns this red.
#[test]
fn an_ifunc_getter_presence_bit_survives_pin_and_bind() {
    let loaded = Loaded::build(Variant::IfuncGetter);
    let (reconciled, pinned) = loaded.reconciled();
    assert_eq!(reconciled.len(), 1);
    let module = &reconciled[0];
    assert!(
        !module
            .exports
            .iter()
            .any(|(name, _)| name == "C_GetInterface"),
        "an IFUNC getter leaves no definition in the witness"
    );
    assert_eq!(
        pinned.export_witness_flags_for(module.object),
        (true, false),
        "the pinned entry records the IFUNC getter presence"
    );
    assert!(
        module.getter_present,
        "binding carries the pinned presence bit onto the module"
    );
    assert!(
        !module.witness_fault,
        "a healthy image binds without a witness fault"
    );
}

#[test]
fn the_fixture_source_is_the_2_40_layout() {
    // Guard the fixture itself: 68 functions, the version bytes first.
    let text = source(Variant::Agreeing);
    assert_eq!(text.matches("unsigned long C_").count(), LEGACY_ORDINALS);
    assert!(text.contains("{ 2, 40, {"));
}

/// An entry reconciliation could not pin (for example one forwarded into an
/// object it could not open) is moved from `entries` to `unpinned`, never
/// dropped from the evidence. If its standard name is exported by this
/// object, the table points somewhere else for that name: a contradiction,
/// not a neutral hole.
#[test]
fn an_unpinned_entry_whose_name_is_exported_contradicts_the_table() {
    use super::{
        ExportAgreement, ObjectExports, ScannedEntry, ScannedTable, Skipped, export_agreement,
    };
    use p11scope_manifest::maps::{Device, ObjectKey};

    let object = ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode: 42,
    };
    let table = ScannedTable {
        version: (2, 40),
        walk: "full",
        entries: vec![ScannedEntry {
            name: "C_Initialize",
            object,
            object_path: "/opt/p11.so".into(),
            file_offset: 0x10,
        }],
        null_entries: vec!["C_GetFunctionStatus"],
        unpinned: vec![Skipped {
            subject: "C_Sign".into(),
            reason: "/opt/dep.so could not be reconciled to a comparable pinned object; \
                     entry was not attached"
                .into(),
        }],
        address: 0x7000,
        file_offset: Some(0x100),
        live_return: false,
        manifest_supported: false,
        extension_impossible: false,
    };
    let symbols = vec![
        ("C_Initialize".to_string(), 0x10),
        ("C_Sign".to_string(), 0x40),
        ("C_GetFunctionStatus".to_string(), 0x50),
    ];
    let agreement = export_agreement(
        &table,
        &ObjectExports {
            object,
            symbols: &symbols,
            getter_present: false,
            witness_fault: false,
        },
    );
    assert_eq!(
        agreement,
        ExportAgreement {
            agreeing: 1,
            disagreeing: 1,
        },
        "the unpinned C_Sign contradicts; the NULL entry stays neutral"
    );
    assert!(!agreement.corroborates());
}

/// RED (live triage): the interposed bootstrap — `C_GetFunctionList`
/// forwarded to another object while the rest of the table agrees —
/// keeps its ABI-definitional name instead of contradicting the table.
/// The dynamic linker resolves that relocation by name, so the target is
/// a `C_GetFunctionList` definition by construction; the unanimous rest
/// proves the layout is a real function list. Isolation check for the
/// scoring arm only: production tables reach this score after bind
/// verifies the forward against the pinned target's own exports, and a
/// forward to a wrong offset is refused before scoring (see the
/// `forwarded_bootstrap_to_a_wrong_offset` twin).
#[test]
fn forwarded_bootstrap_with_agreeing_rest_keeps_its_name() {
    use super::{ExportAgreement, ObjectExports, ScannedEntry, ScannedTable, export_agreement};
    use p11scope_manifest::maps::{Device, ObjectKey};

    let object = ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode: 42,
    };
    let forwarded = ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode: 43,
    };
    let table = ScannedTable {
        version: (3, 2),
        walk: "known_prefix",
        entries: vec![
            ScannedEntry {
                name: "C_Initialize",
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            },
            ScannedEntry {
                name: "C_GetFunctionList",
                object: forwarded,
                object_path: "/opt/dep.so".into(),
                file_offset: 0xebe0,
            },
        ],
        null_entries: Vec::new(),
        unpinned: Vec::new(),
        address: 0x7000,
        file_offset: Some(0x100),
        live_return: false,
        manifest_supported: false,
        extension_impossible: true,
    };
    let symbols = vec![
        ("C_Initialize".to_string(), 0x10),
        ("C_GetFunctionList".to_string(), 0x20),
    ];
    let agreement = export_agreement(
        &table,
        &ObjectExports {
            object,
            symbols: &symbols,
            getter_present: false,
            witness_fault: false,
        },
    );
    assert_eq!(
        agreement,
        ExportAgreement {
            agreeing: 2,
            disagreeing: 0,
        },
        "the forwarded bootstrap agrees once the rest proves the layout"
    );
    assert!(agreement.corroborates());
}

/// The bootstrap exemption needs the layout proof: a forwarded
/// `C_GetFunctionList` with no agreeing entry anywhere is a contradiction,
/// exactly as before — a lone forward proves nothing.
#[test]
fn forwarded_bootstrap_without_agreeing_rest_still_contradicts() {
    use super::{ExportAgreement, ObjectExports, ScannedEntry, ScannedTable, export_agreement};
    use p11scope_manifest::maps::{Device, ObjectKey};

    let object = ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode: 42,
    };
    let forwarded = ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode: 43,
    };
    let table = ScannedTable {
        version: (3, 2),
        walk: "known_prefix",
        entries: vec![ScannedEntry {
            name: "C_GetFunctionList",
            object: forwarded,
            object_path: "/opt/dep.so".into(),
            file_offset: 0xebe0,
        }],
        null_entries: Vec::new(),
        unpinned: Vec::new(),
        address: 0x7000,
        file_offset: Some(0x100),
        live_return: false,
        manifest_supported: false,
        extension_impossible: true,
    };
    let symbols = vec![("C_GetFunctionList".to_string(), 0x20)];
    let agreement = export_agreement(
        &table,
        &ObjectExports {
            object,
            symbols: &symbols,
            getter_present: false,
            witness_fault: false,
        },
    );
    assert_eq!(
        agreement,
        ExportAgreement {
            agreeing: 0,
            disagreeing: 1,
        },
        "a lone forwarded bootstrap contradicts"
    );
    assert!(!agreement.corroborates());
}

/// The bootstrap exemption is narrow: a forwarded ordinary entry still
/// contradicts even when the rest of the table agrees.
#[test]
fn forwarded_non_bootstrap_with_agreeing_rest_still_contradicts() {
    use super::{ExportAgreement, ObjectExports, ScannedEntry, ScannedTable, export_agreement};
    use p11scope_manifest::maps::{Device, ObjectKey};

    let object = ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode: 42,
    };
    let forwarded = ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode: 43,
    };
    let table = ScannedTable {
        version: (2, 40),
        walk: "full",
        entries: vec![
            ScannedEntry {
                name: "C_Initialize",
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            },
            ScannedEntry {
                name: "C_Login",
                object: forwarded,
                object_path: "/opt/dep.so".into(),
                file_offset: 0x30,
            },
        ],
        null_entries: Vec::new(),
        unpinned: Vec::new(),
        address: 0x7000,
        file_offset: Some(0x100),
        live_return: false,
        manifest_supported: false,
        extension_impossible: false,
    };
    let symbols = vec![
        ("C_Initialize".to_string(), 0x10),
        ("C_Login".to_string(), 0x70),
    ];
    let agreement = export_agreement(
        &table,
        &ObjectExports {
            object,
            symbols: &symbols,
            getter_present: false,
            witness_fault: false,
        },
    );
    assert_eq!(
        agreement,
        ExportAgreement {
            agreeing: 1,
            disagreeing: 1,
        },
        "only the bootstrap forward is exempt"
    );
    assert!(!agreement.corroborates());
}
