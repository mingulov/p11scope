//! The scan's oracle is the offline helper: for the same provider loaded in this
//! process, every table entry the scan finds must have the offset
//! `p11scope-discover` computes. Both run in-process here; the helper dlopens the
//! fixture (test-only — the observer itself never does).
//!
//! Run with `--test-threads=1`: every test dlopens a fixture into the shared
//! process image and then scans that image.

use p11scope::discovery::hooks::HookRegistry;
use p11scope::discovery::scan::{
    CaptureWorkBudget, ScanLimits, ScanOutcome, ScanRequest, scan_pid,
};
use p11scope_manifest::manifest::{Resolution, SurfaceSource};
use std::collections::BTreeMap;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

fn serial_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn compile(dir: &Path, name: &str, source: &Path, defines: &[&str]) -> PathBuf {
    let so = dir.join(format!("{name}.so"));
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(source)
        .args(defines)
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc failed for {name}");
    so
}

fn build_fixture(dir: &Path, name: &str, defines: &[&str]) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/discover/tests/fixture/version_matrix.c");
    compile(dir, name, &source, defines)
}

/// dlopen + call C_GetFunctionList so the fixture's static tables are filled,
/// exactly as a real application would before the observer scans it.
fn load_and_populate(so: &Path) {
    let c = std::ffi::CString::new(so.to_str().unwrap()).unwrap();
    let handle = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen {}", so.display());
    let symbol = std::ffi::CString::new("C_GetFunctionList").unwrap();
    let entry = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    assert!(!entry.is_null(), "C_GetFunctionList missing");
    let entry: extern "C" fn(*mut *mut std::ffi::c_void) -> u64 =
        unsafe { std::mem::transmute(entry) };
    let mut table: *mut std::ffi::c_void = std::ptr::null_mut();
    assert_eq!(
        entry(&mut table),
        0,
        "fixture C_GetFunctionList must succeed"
    );
}

fn scan_self(hints: &[PathBuf]) -> ScanOutcome {
    let hooks = HookRegistry::builtin();
    let mut budget = CaptureWorkBudget::default();
    scan_pid(
        &ScanRequest {
            pid: std::process::id(),
            hints,
            hooks: &hooks,
        },
        &mut budget,
    )
    .expect("scanning our own process must not fail")
}

fn helper_offsets(so: &Path) -> BTreeMap<String, u64> {
    let manifest = p11scope_discover::discover::discover(so).expect("helper discovery");
    let mut out = BTreeMap::new();
    for surface in &manifest.surfaces {
        if !matches!(surface.source, SurfaceSource::LegacyFunctionList) {
            continue;
        }
        for function in &surface.functions {
            if let Resolution::Resolved { file_offset, .. } = function.resolution {
                out.insert(function.name.clone(), file_offset);
            }
        }
    }
    out
}

#[test]
fn scanned_offsets_equal_the_helpers_for_the_legacy_table() {
    let _guard = serial_guard();
    let dir = tmp("scan-oracle");
    let so = build_fixture(&dir, "oracle", &["-DMATRIX_INTERFACES=0"]);
    load_and_populate(&so);

    let ScanOutcome::Scanned { modules, .. } = scan_self(&[so.clone()]) else {
        panic!("/proc/self/mem must always be readable");
    };
    let module = modules
        .iter()
        .find(|m| m.path.ends_with("oracle.so"))
        .expect("the fixture must be discovered");

    let legacy = module
        .tables
        .iter()
        .find(|t| t.version == (2, 40))
        .expect("the 2.40 legacy table must be found");
    let scanned: BTreeMap<String, u64> = legacy
        .entries
        .iter()
        .map(|e| (e.name.to_string(), e.file_offset))
        .collect();

    let expected = helper_offsets(&so);
    assert!(!expected.is_empty(), "the helper must produce an oracle");
    assert_eq!(
        scanned, expected,
        "scanned offsets must equal the helper's exactly"
    );
    assert!(
        legacy.entries.len() >= 60,
        "a 2.40 table has 68 slots: {}",
        legacy.entries.len()
    );
}

#[test]
fn every_supported_version_layout_is_found_with_its_documented_entry_count() {
    let _guard = serial_guard();
    // (major, minor, expected entry+null count) — the N of spec §4.1 step 4.
    for (major, minor, expected) in [(2u8, 0u8, 67usize), (2, 40, 68), (3, 0, 92), (3, 2, 104)] {
        let dir = tmp(&format!("scan-v{major}-{minor}"));
        let so = build_fixture(
            &dir,
            "versioned",
            &[
                &format!("-DLEGACY_MAJOR={major}"),
                &format!("-DLEGACY_MINOR={minor}"),
                "-DMATRIX_INTERFACES=0",
            ],
        );
        load_and_populate(&so);
        let ScanOutcome::Scanned { modules, .. } = scan_self(&[so.clone()]) else {
            panic!("scan must be available");
        };
        let module = modules
            .iter()
            .find(|m| m.path.ends_with("versioned.so"))
            .unwrap();
        let table = module
            .tables
            .iter()
            .find(|t| t.version == (major, minor))
            .unwrap_or_else(|| panic!("{major}.{minor} table not found"));
        assert_eq!(
            table.entries.len() + table.null_entries.len(),
            expected,
            "{major}.{minor} must decode {expected} slots"
        );
    }
}

/// A provider-owned, statically initialised `CK_FUNCTION_LIST` plus the
/// `CK_INTERFACE` array that names it — the shape a PKCS#11 v3 provider publishes
/// and hands back by pointer from `C_GetInterface`. `version_matrix.c` cannot serve
/// here: it builds its interface list in the *caller's* buffer, so the triples live
/// on the application heap and never appear in any mapping of the provider object
/// that the scan reads (measured: see the task report).
const INTERFACE_ARRAY_FIXTURE: &str = r#"
typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;
typedef struct { CK_VERSION version; void *functions[68]; } Table;

#define CKR_OK 0UL
#define S(n) static CK_RV s##n(void) { return CKR_OK; }
#define S10(m) S(m##0) S(m##1) S(m##2) S(m##3) S(m##4) S(m##5) S(m##6) S(m##7) S(m##8) S(m##9)
S10(0) S10(1) S10(2) S10(3) S10(4) S10(5)
S(60) S(61) S(62) S(63) S(64) S(65) S(66) S(67)
#define L10(m) s##m##0, s##m##1, s##m##2, s##m##3, s##m##4, s##m##5, s##m##6, s##m##7, s##m##8, s##m##9

static Table published_table = {
    {2, 40},
    {L10(0), L10(1), L10(2), L10(3), L10(4), L10(5),
     s60, s61, s62, s63, s64, s65, s66, s67}
};

static char standard_name[] = "PKCS 11";
static char vendor_name[] = "Acme Vendor ABI";

static CK_INTERFACE published[] = {
    {standard_name, &published_table, 0},
    {vendor_name, &published_table, 0x55},
};

void p11scope_set_vendor_name(char *name) { published[1].pInterfaceName = name; }

CK_RV C_GetFunctionList(void **out) {
    if (!out) return 1;
    *out = &published_table;
    return CKR_OK;
}

CK_RV C_GetInterface(void *name, void *version, void **out, CK_FLAGS flags) {
    (void)name; (void)version; (void)flags;
    if (!out) return 1;
    *out = &published[0];
    return CKR_OK;
}
"#;

#[test]
fn interfaces_are_recorded_with_their_name_class() {
    let _guard = serial_guard();
    let dir = tmp("scan-interfaces");
    let source = dir.join("interface_array.c");
    std::fs::write(&source, INTERFACE_ARRAY_FIXTURE).unwrap();
    let so = compile(&dir, "ifaces", &source, &[]);
    load_and_populate(&so);

    let ScanOutcome::Scanned { modules, .. } = scan_self(&[so.clone()]) else {
        panic!("scan must be available")
    };
    let module = modules
        .iter()
        .find(|m| m.path.ends_with("ifaces.so"))
        .unwrap();
    assert!(
        !module.tables.is_empty(),
        "the published 2.40 table must be found first: {module:?}"
    );
    assert!(
        module
            .interfaces
            .iter()
            .any(|i| i.name_class == "exact_standard"
                && i.name_lossy.as_deref() == Some("PKCS 11")),
        "the fixture publishes a \"PKCS 11\" interface: {:?}",
        module.interfaces
    );
    assert!(
        module
            .interfaces
            .iter()
            .any(|i| i.name_class == "other" && i.name_lossy.as_deref() == Some("Acme Vendor ABI")),
        "the fixture publishes a vendor-named interface too: {:?}",
        module.interfaces
    );
    // Every accepted triple must name a table this scan actually decoded.
    assert!(
        module
            .interfaces
            .iter()
            .all(|i| i.table.is_some_and(|index| index < module.tables.len())),
        "{:?}",
        module.interfaces
    );
}

#[test]
fn interface_names_do_not_cross_readable_vmas() {
    let _guard = serial_guard();
    const PREFIX: &[u8] = b"EDGE";
    const ADJACENT: &[u8] = b"ADJACENT_SECRET\0";

    let dir = tmp("scan-interface-vma-boundary");
    let source = dir.join("interface_array.c");
    std::fs::write(&source, INTERFACE_ARRAY_FIXTURE).unwrap();
    let so = compile(&dir, "vma-ifaces", &source, &[]);
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    assert!(page.is_power_of_two());

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&so)
        .unwrap();
    let first_offset = file.metadata().unwrap().len().next_multiple_of(page as u64);
    file.set_len(first_offset + 3 * page as u64).unwrap();
    file.write_all_at(PREFIX, first_offset + page as u64 - PREFIX.len() as u64)
        .unwrap();
    file.write_all_at(ADJACENT, first_offset + 2 * page as u64)
        .unwrap();

    let reserved = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            2 * page,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(reserved, libc::MAP_FAILED);
    let first = unsafe {
        libc::mmap(
            reserved,
            page,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            file.as_raw_fd(),
            first_offset as libc::off_t,
        )
    };
    assert_eq!(first, reserved);
    let second_address = unsafe { reserved.cast::<u8>().add(page).cast() };
    let second = unsafe {
        libc::mmap(
            second_address,
            page,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            file.as_raw_fd(),
            (first_offset + 2 * page as u64) as libc::off_t,
        )
    };
    assert_eq!(second, second_address);
    let name = unsafe { reserved.cast::<u8>().add(page - PREFIX.len()) };

    load_and_populate(&so);
    let path = std::ffi::CString::new(so.to_str().unwrap()).unwrap();
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null());
    let symbol = std::ffi::CString::new("p11scope_set_vendor_name").unwrap();
    let setter = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    assert!(!setter.is_null());
    let setter: extern "C" fn(*mut libc::c_char) = unsafe { std::mem::transmute(setter) };
    setter(name.cast());

    let maps = p11scope_manifest::maps::parse_maps(
        &std::fs::read(format!("/proc/{}/maps", std::process::id())).unwrap(),
    )
    .unwrap();
    let name_address = name as u64;
    let containing = maps
        .iter()
        .find(|entry| entry.start <= name_address && name_address < entry.end)
        .unwrap();
    assert_eq!(containing.end, name_address + PREFIX.len() as u64);
    let adjacent = maps
        .iter()
        .find(|entry| entry.start == containing.end)
        .unwrap();
    assert_eq!(
        (adjacent.device, adjacent.inode),
        (containing.device, containing.inode)
    );

    let outcome = scan_self(&[so.clone()]);
    assert_eq!(unsafe { libc::munmap(reserved, 2 * page) }, 0);
    let module = outcome
        .modules()
        .iter()
        .find(|module| module.path.ends_with("vma-ifaces.so"))
        .unwrap();
    let boundary = module
        .interfaces
        .iter()
        .find(|interface| interface.flags == 0x55)
        .unwrap();
    assert_eq!(boundary.name_class, "unreadable");
    assert_eq!(boundary.name_lossy, None);

    let text = p11scope::inspect::render_text(
        std::process::id(),
        &outcome,
        &p11scope::discovery::identity::PinnedObjects::empty(),
    );
    assert!(
        !text.contains("EDGE"),
        "unterminated prefix became a name: {text}"
    );
    assert!(
        !text.contains("ADJACENT_SECRET"),
        "adjacent VMA bytes became a name: {text}"
    );
}

#[test]
fn a_table_less_object_and_a_non_elf_hint_produce_no_module_and_no_panic() {
    let _guard = serial_guard();
    let dir = tmp("scan-negative");
    let plain = dir.join("plain.so");
    let c = dir.join("plain.c");
    std::fs::write(&c, "int unrelated(void){return 1;}\n").unwrap();
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&plain)
            .arg(&c)
            .status()
            .unwrap()
            .success()
    );
    load_and_populate_ignoring_missing_entry(&plain);

    let ScanOutcome::Scanned { modules, .. } = scan_self(&[plain.clone()]) else {
        panic!("scan must be available")
    };
    // The hint is honoured, so the object is identified; it just has nothing in it.
    let module = modules
        .iter()
        .find(|m| m.path.ends_with("plain.so"))
        .expect("a hinted object that is mapped must be identified");
    assert!(
        module.tables.is_empty() && module.interfaces.is_empty() && module.exports.is_empty(),
        "an object with no table must yield no tables: {module:?}"
    );

    let text = dir.join("not-elf.so");
    std::fs::write(&text, b"not an elf at all\n").unwrap();
    let ScanOutcome::Scanned { skipped, .. } = scan_self(&[text.clone()]) else {
        panic!("scan must be available")
    };
    // The hint names a file that is not mapped at all: recorded, never fatal.
    assert!(
        skipped.iter().any(|s| s.subject.contains("not-elf.so")),
        "{skipped:?}"
    );
}

fn load_and_populate_ignoring_missing_entry(so: &Path) {
    let c = std::ffi::CString::new(so.to_str().unwrap()).unwrap();
    let handle = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen {}", so.display());
}

/// A version word at the end of file-backed data does not satisfy the detector's
/// complete-body clause and therefore is not evidence of a truncated table.
#[test]
fn a_table_header_running_past_file_backed_data_is_silently_ignored() {
    let _guard = serial_guard();
    let dir = tmp("scan-truncated");
    let so = build_fixture(&dir, "truncated", &["-DMATRIX_INTERFACES=0"]);
    load_and_populate(&so);
    let ScanOutcome::Scanned {
        modules, skipped, ..
    } = scan_self(&[so.clone()])
    else {
        panic!("scan must be available")
    };
    // The tables that do fit are still found, so this is not a wholesale failure.
    let module = modules
        .iter()
        .find(|m| m.path.ends_with("truncated.so"))
        .unwrap();
    assert!(!module.tables.is_empty(), "{module:?}");
    assert!(
        !skipped.iter().any(|s| s.reason.contains("extends past")),
        "a version word without its complete pointer body is not a candidate: {skipped:?}"
    );
}

/// The same obligation with no hint in sight. An object that exports a registry
/// entry point is one the *tool itself* classified as a provider: it reaches
/// `discovery[]` and `capture.modules[]` as a module this capture observed. If
/// its table is built at run time, nothing was ever probed in it — and with no
/// entry to skip, no attach to fail and no counter to raise, a capture that
/// found any other provider publishes COMPLETE over the gap.
#[test]
fn an_unhinted_object_the_tool_called_a_provider_says_when_it_yielded_no_table() {
    let _guard = serial_guard();
    let dir = tmp("scan-unhinted-empty");
    let so = dir.join("tableless.so");
    let c = dir.join("tableless.c");
    std::fs::write(
        &c,
        "unsigned long C_GetFunctionList(void **out){ (void)out; return 5; }\n",
    )
    .unwrap();
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&so)
            .arg(&c)
            .status()
            .unwrap()
            .success()
    );
    load_and_populate_ignoring_missing_entry(&so);
    let ScanOutcome::Scanned {
        modules, skipped, ..
    } = scan_self(&[])
    else {
        panic!("scan must be available")
    };
    assert!(
        modules
            .iter()
            .any(|m| m.path.ends_with("tableless.so") && m.tables.is_empty()),
        "the export makes it a module this capture reports: {modules:?}"
    );
    let reasons: Vec<&str> = skipped
        .iter()
        .filter(|s| s.subject.ends_with("tableless.so"))
        .map(|s| s.reason.as_str())
        .collect();
    assert!(
        reasons.iter().any(|r| r.contains("no function table")),
        "a provider that yielded no table must say so: {skipped:?}"
    );
    assert!(
        !reasons.iter().any(|r| r.contains("hint")),
        "nobody hinted this module; no reason may claim one: {reasons:?}"
    );
}

#[test]
fn a_hinted_object_with_no_table_says_so() {
    let _guard = serial_guard();
    let dir = tmp("scan-hinted-empty");
    let plain = dir.join("empty.so");
    let c = dir.join("empty.c");
    std::fs::write(&c, "int unrelated(void){return 1;}\n").unwrap();
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&plain)
            .arg(&c)
            .status()
            .unwrap()
            .success()
    );
    load_and_populate_ignoring_missing_entry(&plain);
    let ScanOutcome::Scanned { skipped, .. } = scan_self(&[plain.clone()]) else {
        panic!("scan must be available")
    };
    assert!(
        skipped
            .iter()
            .any(|s| s.subject.ends_with("empty.so") && s.reason.contains("--module hint")),
        "an explicitly named module that yielded nothing must be explained: {skipped:?}"
    );
}

/// The readable non-executable bytes the scan would snapshot for `so`, as the scan
/// itself counts them — used to size a budget that admits exactly one object.
fn readable_data_bytes(so: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    let inode = std::fs::metadata(so).unwrap().ino();
    let maps =
        p11scope_manifest::maps::parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    maps.iter()
        .filter(|m| m.inode == inode && m.permissions[0] == b'r' && m.permissions[2] != b'x')
        .map(|m| m.end - m.start)
        .sum()
}

fn maps_snapshot_bytes() -> u64 {
    u64::try_from(std::fs::read("/proc/self/maps").unwrap().len())
        .expect("/proc/self/maps length fits in u64")
}

#[test]
fn the_per_capture_byte_cap_accumulates_across_objects() {
    let _guard = serial_guard();
    let dir = tmp("scan-capture-cap");
    let first = build_fixture(&dir, "budget-a", &["-DMATRIX_INTERFACES=0"]);
    let second = build_fixture(&dir, "budget-b", &["-DMATRIX_INTERFACES=0"]);
    load_and_populate(&first);
    load_and_populate(&second);
    // Room for exactly one of the two: the second object must trip the running total,
    // not the per-object cap.
    let total_bytes = maps_snapshot_bytes()
        .checked_add(readable_data_bytes(&first))
        .expect("capture byte budget fits in u64");
    assert_eq!(
        readable_data_bytes(&first),
        readable_data_bytes(&second),
        "fixtures must match"
    );
    let hooks = HookRegistry::builtin();
    let mut budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: 64 * 1024 * 1024,
        total_bytes,
    });
    let ScanOutcome::Scanned {
        modules, skipped, ..
    } = scan_pid(
        &ScanRequest {
            pid: std::process::id(),
            hints: &[first.clone(), second.clone()],
            hooks: &hooks,
        },
        &mut budget,
    )
    .unwrap()
    else {
        panic!("scan must be available")
    };
    assert_eq!(modules.len(), 2, "both objects are identified: {modules:?}");
    assert_eq!(
        modules.iter().filter(|m| !m.tables.is_empty()).count(),
        1,
        "the budget admits exactly one object: {modules:?}"
    );
    assert_eq!(
        skipped
            .iter()
            .filter(|s| s.reason.contains("capture attempted-I/O ceiling"))
            .count(),
        1,
        "the object over the running total must be reported: {skipped:?}"
    );
}

#[test]
fn separate_process_scans_cannot_renew_the_capture_byte_budget() {
    let _guard = serial_guard();
    let dir = tmp("scan-shared-capture-cap");
    let first = build_fixture(&dir, "shared-a", &["-DMATRIX_INTERFACES=0"]);
    let second = build_fixture(&dir, "shared-b", &["-DMATRIX_INTERFACES=0"]);
    load_and_populate(&first);
    load_and_populate(&second);
    let object_bytes = readable_data_bytes(&first);
    assert_eq!(object_bytes, readable_data_bytes(&second));
    let total_bytes = maps_snapshot_bytes()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(object_bytes))
        .expect("capture byte budget fits in u64");
    let hooks = HookRegistry::builtin();
    let limits = ScanLimits {
        per_object_bytes: 64 * 1024 * 1024,
        total_bytes,
    };
    let mut budget = CaptureWorkBudget::new(limits);
    let first_outcome = scan_pid(
        &ScanRequest {
            pid: std::process::id(),
            hints: &[first],
            hooks: &hooks,
        },
        &mut budget,
    )
    .unwrap();
    let second_outcome = scan_pid(
        &ScanRequest {
            pid: std::process::id(),
            hints: &[second],
            hooks: &hooks,
        },
        &mut budget,
    )
    .unwrap();
    assert!(first_outcome.modules().iter().any(|m| !m.tables.is_empty()));
    assert!(
        second_outcome.modules().iter().all(|m| m.tables.is_empty())
            && second_outcome
                .skipped()
                .iter()
                .any(|skip| skip.reason.contains("capture attempted-I/O ceiling")),
        "a later process scan must not receive a fresh capture allowance: {second_outcome:?}"
    );
}

#[test]
fn the_per_object_byte_cap_is_enforced_as_a_skip_not_a_truncation() {
    let _guard = serial_guard();
    let dir = tmp("scan-cap");
    let so = build_fixture(&dir, "capped", &["-DMATRIX_INTERFACES=0"]);
    load_and_populate(&so);
    let hooks = HookRegistry::builtin();
    let mut budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: 1,
        total_bytes: 512 * 1024 * 1024,
    });
    let outcome = scan_pid(
        &ScanRequest {
            pid: std::process::id(),
            hints: &[so.clone()],
            hooks: &hooks,
        },
        &mut budget,
    )
    .unwrap();
    let ScanOutcome::Scanned {
        modules, skipped, ..
    } = outcome
    else {
        panic!("scan must be available")
    };
    // The object is still identified — it is the *decode* that the cap refuses — so
    // the emptiness assertion below is about a module that really exists.
    assert!(
        modules.iter().any(|m| m.path.ends_with("capped.so")),
        "a capped object must be reported, not dropped: {modules:?}"
    );
    assert!(
        modules.iter().all(|m| m.tables.is_empty()),
        "nothing may be decoded from a capped object"
    );
    assert!(
        skipped.iter().any(|s| s.reason.contains("too_large")),
        "the cap must be reported as too_large: {skipped:?}"
    );
}

#[test]
fn scan_budget_charges_only_the_prefix_read_before_aggregate_exhaustion() {
    let _guard = serial_guard();
    let dir = tmp("scan-prefix-budget");
    let so = build_fixture(&dir, "prefix-capped", &["-DMATRIX_INTERFACES=0"]);
    load_and_populate(&so);
    let total_bytes = readable_data_bytes(&so) - 1;
    let hooks = HookRegistry::builtin();
    let mut budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: 64 * 1024 * 1024,
        total_bytes,
    });
    let outcome = scan_pid(
        &ScanRequest {
            pid: std::process::id(),
            hints: &[so],
            hooks: &hooks,
        },
        &mut budget,
    )
    .unwrap();
    assert_eq!(
        budget.attempted_io_bytes(),
        total_bytes,
        "only the bytes actually read before the next refused read are charged"
    );
    assert!(
        outcome
            .skipped()
            .iter()
            .any(|skip| skip.reason.contains("capture") && skip.reason.contains("ceiling")),
        "the unread remainder must be explicit: {:?}",
        outcome.skipped()
    );
}

/// An unreadable `/proc/<pid>/mem` costs the tables, never the object inventory and
/// never the call (spec §4.1 step 3, §4.9). The target is a same-uid *non-descendant*,
/// which `ptrace_scope >= 1` refuses; the expected outcome is derived from the live
/// configuration rather than assumed, exactly as `proc_access.rs` does.
#[test]
fn an_unreadable_proc_mem_is_reported_as_unavailable_not_as_an_error() {
    let _guard = serial_guard();
    let mut child = Command::new("setsid")
        .args(["--fork", "sleep", "27.1828"])
        .spawn()
        .expect("spawn setsid sleep");
    // `setsid --fork` exits as soon as it has forked; reap it so it is not left a zombie.
    child.wait().expect("reap setsid");
    std::thread::sleep(std::time::Duration::from_millis(200));
    let out = Command::new("pgrep")
        .args(["-f", "sleep 27.1828"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // A leftover from an earlier run would match too: use one and clean up all of them,
    // rather than failing on a condition that says nothing about the code under test.
    let pids: Vec<u32> = stdout
        .split_whitespace()
        .filter_map(|pid| pid.parse().ok())
        .collect();
    let Some(&pid) = pids.first() else {
        panic!("expected a reparented sleep, pgrep found none")
    };

    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).expect("target exe link");
    let hooks = HookRegistry::builtin();
    let mut budget = CaptureWorkBudget::default();
    let outcome = scan_pid(
        &ScanRequest {
            pid,
            hints: &[exe.clone()],
            hooks: &hooks,
        },
        &mut budget,
    );
    for pid in &pids {
        let _ = Command::new("kill").arg(pid.to_string()).status();
    }

    let outcome = outcome.expect("an unreadable /proc/<pid>/mem is never fatal");
    let scope: i32 = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse().unwrap_or(0))
        .unwrap_or(0);
    let is_root = unsafe { libc::geteuid() } == 0;
    let refused = if is_root { scope > 2 } else { scope > 0 };
    eprintln!(
        "MEASURED: euid_root={is_root}, ptrace_scope={scope}, outcome={:?}",
        outcome.unavailable_reason()
    );
    assert_eq!(
        outcome.unavailable_reason(),
        refused.then_some("ptrace"),
        "ptrace_scope={scope}, euid_root={is_root}"
    );
    // Either way the hinted object is identified from maps + .dynsym alone.
    let module = outcome
        .modules()
        .iter()
        .find(|m| m.path == exe.display().to_string())
        .unwrap_or_else(|| panic!("{} must still be identified", exe.display()));
    if refused {
        assert!(
            module.tables.is_empty() && module.interfaces.is_empty(),
            "no memory was read, so nothing may be claimed: {module:?}"
        );
        assert!(
            outcome
                .skipped()
                .iter()
                .any(|s| s.subject == format!("/proc/{pid}/mem")),
            "the refusal itself must be recorded: {:?}",
            outcome.skipped()
        );
    }
}

#[test]
fn softhsm_if_installed_is_discovered_without_false_positives() {
    let _guard = serial_guard();
    let module = Path::new("/usr/lib/softhsm/libsofthsm2.so");
    if !module.exists() {
        eprintln!("SKIP: SoftHSM2 not installed");
        return;
    }
    load_and_populate(module);
    let ScanOutcome::Scanned { modules, .. } = scan_self(&[module.to_path_buf()]) else {
        panic!("scan must be available")
    };
    let found = modules
        .iter()
        .find(|m| m.path.contains("libsofthsm2.so"))
        .expect("SoftHSM2 must be discovered");
    assert!(
        !found.tables.is_empty(),
        "SoftHSM2 must expose at least one table"
    );
    let expected = helper_offsets(module);
    let mut checked = 0usize;
    for table in &found.tables {
        for entry in &table.entries {
            if let Some(want) = expected.get(entry.name) {
                assert_eq!(
                    entry.file_offset, *want,
                    "{} offset disagrees with the helper",
                    entry.name
                );
                checked += 1;
            }
        }
    }
    eprintln!(
        "softhsm: {} tables, {checked} entries cross-checked against the helper",
        found.tables.len()
    );
    // Without this the loop above could agree with the helper vacuously.
    assert!(
        checked >= 60,
        "a 2.40 table has 68 slots; only {checked} were cross-checked"
    );
}

#[test]
fn inspect_renders_a_scanned_fixture_end_to_end() {
    let _guard = serial_guard();
    let dir = tmp("inspect-e2e");
    let so = build_fixture(&dir, "inspected", &["-DMATRIX_INTERFACES=0"]);
    load_and_populate(&so);
    let hooks = HookRegistry::builtin();
    let mut budget = CaptureWorkBudget::default();
    let outcome = scan_pid(
        &ScanRequest {
            pid: std::process::id(),
            hints: &[so.clone()],
            hooks: &hooks,
        },
        &mut budget,
    )
    .unwrap();
    let (pinned, _) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        outcome.modules(),
        &mut budget,
    )
    .unwrap();
    let text = p11scope::inspect::render_text(std::process::id(), &outcome, &pinned);
    assert!(text.contains("inspected.so"), "{text}");
    assert!(text.contains("2.40"), "{text}");
    let json = p11scope::inspect::render_json(std::process::id(), &outcome, &pinned);
    assert_eq!(json["schema"], "pkcs11-scope/inspect/v1");
    assert!(
        json["modules"][0]["identity"]["sha256"]
            .as_str()
            .unwrap()
            .len()
            == 64
    );
}
