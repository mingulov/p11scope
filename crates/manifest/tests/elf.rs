//! SPDX-License-Identifier: GPL-3.0-or-later
use object::elf;
use p11scope_manifest::elf::{
    ElfAbi, ElfSnapshot, entry_file_offset, exports_matching, read_export_facts, symbol_file_offset,
};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

fn cc_so(dir: &Path, name: &str, source: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let c = dir.join(format!("{name}.c"));
    let so = dir.join(format!("{name}.so"));
    std::fs::write(&c, source).unwrap();
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&c)
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc failed for {name}");
    so
}

fn cc_exe(dir: &Path, name: &str, source: &str) -> PathBuf {
    cc_exe_width(dir, name, source, 64)
}

fn cc_exe_width(dir: &Path, name: &str, source: &str, bits: u8) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let c = dir.join(format!("{name}.c"));
    let exe = dir.join(name);
    std::fs::write(&c, source).unwrap();
    let ok = Command::new("gcc")
        .arg(format!("-m{bits}"))
        .args(["-rdynamic", "-o"])
        .arg(&exe)
        .arg(&c)
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc failed for {name}");
    exe
}

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Hermetic executable with a custom entry point: `-nostdlib` means no libc
/// is needed at all, so the static variant also builds without a static
/// toolchain — the shape a statically linked observer has.
fn cc_entry_exe(dir: &Path, name: &str, extra: &[&str]) -> PathBuf {
    let c = dir.join(format!("{name}.c"));
    let exe = dir.join(name);
    std::fs::write(&c, "void entry_point(void) {}\n").unwrap();
    let mut cmd = Command::new("gcc");
    cmd.args(["-nostdlib", "-e", "entry_point", "-o"]);
    cmd.arg(&exe).arg(&c).args(extra);
    let ok = cmd.status().unwrap().success();
    assert!(ok, "gcc failed for {name}");
    exe
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn program_header(bytes: &[u8], kind: u32, executable: bool) -> std::ops::Range<usize> {
    assert_eq!(&bytes[..4], b"\x7fELF");
    assert_eq!(bytes[4], 2, "fixture must be ELF64");
    assert_eq!(bytes[5], 1, "fixture must be little-endian");
    let start: usize = le_u64(bytes, 0x20).try_into().unwrap();
    let size = usize::from(le_u16(bytes, 0x36));
    let count = usize::from(le_u16(bytes, 0x38));
    (0..count)
        .map(|index| start + index * size)
        .find(|offset| {
            u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().unwrap()) == kind
                && (!executable
                    || u32::from_le_bytes(bytes[*offset + 4..*offset + 8].try_into().unwrap())
                        & elf::PF_X
                        != 0)
        })
        .map(|offset| offset..offset + size)
        .unwrap()
}

const REGISTRY: &[&str] = &[
    "C_GetFunctionList",
    "C_GetInterfaceList",
    "C_GetInterface",
    "NSC_GetFunctionList",
    "FC_GetFunctionList",
];

#[test]
fn snapshot_reads_once_and_separates_data_from_attachable_hook() {
    let d = tmp("elf-snapshot-once");
    let exe = cc_exe(
        &d,
        "loader-fixture",
        "unsigned long loader_state = 7;\n\
         void loader_hook(void) {}\n\
         int main(void) { loader_hook(); return (int)loader_state; }\n",
    );
    let file = p11scope_manifest::identity::open_object(&exe).unwrap();
    let snapshot = ElfSnapshot::read(&file).unwrap();

    // Destroy the backing bytes after the snapshot. Every fact below must still
    // come from the one retained read, never from reopening or rereading the ELF.
    std::fs::write(&exe, b"not an ELF any more").unwrap();

    let interpreter = snapshot.interpreter().unwrap();
    assert!(interpreter.starts_with(b"/"), "{interpreter:?}");

    let state = snapshot.defined_symbol("loader_state").unwrap().unwrap();
    assert_ne!(state.virtual_address, 0);
    assert!(!snapshot.is_executable_offset(state.file_offset));

    let hook = snapshot.defined_symbol("loader_hook").unwrap().unwrap();
    assert_ne!(hook.virtual_address, 0);
    assert!(snapshot.is_executable_offset(hook.file_offset));
}

#[test]
fn interpreter_absence_and_malformed_nul_are_explicit() {
    let d = tmp("elf-interpreter-refusals");
    let shared = cc_so(&d, "no-interpreter", "int hook(void) { return 0; }\n");
    let file = p11scope_manifest::identity::open_object(&shared).unwrap();
    assert_eq!(ElfSnapshot::read(&file).unwrap().interpreter(), None);

    let exe = cc_exe(&d, "bad-interpreter", "int main(void) { return 0; }\n");
    let mut bytes = std::fs::read(&exe).unwrap();
    let header = program_header(&bytes, elf::PT_INTERP, false);
    let offset: usize = le_u64(&bytes, header.start + 8).try_into().unwrap();
    let size: usize = le_u64(&bytes, header.start + 32).try_into().unwrap();
    bytes[offset + size - 1] = b'X';
    std::fs::write(&exe, bytes).unwrap();
    let file = p11scope_manifest::identity::open_object(&exe).unwrap();
    let error = ElfSnapshot::read(&file).unwrap_err();
    assert!(error.contains("NUL"), "{error}");

    let exe = cc_exe(&d, "embedded-nul", "int main(void) { return 0; }\n");
    let mut bytes = std::fs::read(&exe).unwrap();
    let header = program_header(&bytes, elf::PT_INTERP, false);
    let offset: usize = le_u64(&bytes, header.start + 8).try_into().unwrap();
    bytes[offset + 1] = 0;
    std::fs::write(&exe, bytes).unwrap();
    let file = p11scope_manifest::identity::open_object(&exe).unwrap();
    let error = ElfSnapshot::read(&file).unwrap_err();
    assert!(error.contains("embedded NUL"), "{error}");
}

#[test]
fn defined_symbol_refuses_undefined_duplicates_and_missing_names() {
    let d = tmp("elf-symbol-refusals");
    let shared = cc_so(
        &d,
        "undefined",
        "extern void never_defined(void);\n\
         void *keep_undefined = (void *)never_defined;\n\
         void defined_hook(void) {}\n",
    );
    let file = p11scope_manifest::identity::open_object(&shared).unwrap();
    let snapshot = ElfSnapshot::read(&file).unwrap();
    assert_eq!(snapshot.defined_symbol("never_defined").unwrap(), None);
    assert_eq!(snapshot.defined_symbol("missing_name").unwrap(), None);
    assert!(snapshot.defined_symbol("defined_hook").unwrap().is_some());

    let exe = cc_exe(
        &d,
        "duplicate",
        "void dupe_one(void) {}\n\
         void dupe_two(void) {}\n\
         int main(void) { dupe_one(); dupe_two(); return 0; }\n",
    );
    let mut bytes = std::fs::read(&exe).unwrap();
    let mut replacements = 0;
    for offset in 0..=bytes.len() - b"dupe_two\0".len() {
        if &bytes[offset..offset + b"dupe_two\0".len()] == b"dupe_two\0" {
            bytes[offset..offset + b"dupe_one\0".len()].copy_from_slice(b"dupe_one\0");
            replacements += 1;
        }
    }
    assert!(replacements >= 2, "both symbol tables must be patched");
    std::fs::write(&exe, bytes).unwrap();
    let file = p11scope_manifest::identity::open_object(&exe).unwrap();
    let error = ElfSnapshot::read(&file)
        .unwrap()
        .defined_symbol("dupe_one")
        .unwrap_err();
    assert!(error.contains("duplicate"), "{error}");
}

#[test]
fn malformed_and_overflowing_program_header_ranges_are_refused() {
    let d = tmp("elf-range-refusals");
    let exe = cc_exe(&d, "malformed-range", "int main(void) { return 0; }\n");
    let mut bytes = std::fs::read(&exe).unwrap();
    let header = program_header(&bytes, elf::PT_INTERP, false);
    bytes[header.start + 8..header.start + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    std::fs::write(&exe, bytes).unwrap();
    let file = p11scope_manifest::identity::open_object(&exe).unwrap();
    assert!(ElfSnapshot::read(&file).is_err());

    let exe = cc_exe(&d, "overflow-range", "int main(void) { return 0; }\n");
    let mut bytes = std::fs::read(&exe).unwrap();
    let header = program_header(&bytes, elf::PT_LOAD, true);
    bytes[header.start + 8..header.start + 16].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    bytes[header.start + 32..header.start + 40].copy_from_slice(&4_u64.to_le_bytes());
    std::fs::write(&exe, bytes).unwrap();
    let file = p11scope_manifest::identity::open_object(&exe).unwrap();
    assert!(ElfSnapshot::read(&file).is_err());

    let exe = cc_exe(&d, "past-eof-range", "int main(void) { return 0; }\n");
    let mut bytes = std::fs::read(&exe).unwrap();
    let header = program_header(&bytes, elf::PT_LOAD, true);
    let past_end_size = bytes.len() as u64 + 1;
    bytes[header.start + 32..header.start + 40].copy_from_slice(&past_end_size.to_le_bytes());
    std::fs::write(&exe, bytes).unwrap();
    let file = p11scope_manifest::identity::open_object(&exe).unwrap();
    assert!(
        ElfSnapshot::read(&file).is_err(),
        "a non-overflowing PT_LOAD range past EOF must be refused"
    );
}

#[test]
fn only_registry_exports_are_reported_with_usable_offsets() {
    let d = tmp("elf-exports");
    let so = cc_so(
        &d,
        "provider",
        "unsigned long C_GetFunctionList(void **p){(void)p;return 0;}\n\
         unsigned long NSC_GetFunctionList(void **p){(void)p;return 0;}\n\
         unsigned long some_other_symbol(void){return 7;}\n",
    );
    let file = p11scope_manifest::identity::open_object(&so).unwrap();
    let mut found = exports_matching(&file, REGISTRY).unwrap();
    found.sort();
    let names: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["C_GetFunctionList", "NSC_GetFunctionList"]);

    // Every reported offset must land inside an executable segment — the same
    // property manifest offsets must satisfy.
    let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
    for (name, offset) in &found {
        assert!(
            inspected.contains_executable_offset(*offset),
            "{name} offset {offset:#x} is outside every executable segment"
        );
    }
    assert!(
        symbol_file_offset(&file, "some_other_symbol")
            .unwrap()
            .is_some()
    );
    assert_eq!(symbol_file_offset(&file, "C_NotThere").unwrap(), None);
}

#[test]
fn entry_offset_is_the_custom_entry_symbol_in_both_linkages() {
    // The doctor's static-build fallback anchors its self-probe here; the
    // entry symbol route (symtab) and the entry header route must agree.
    for (case, extra) in [("dynamic", &[] as &[&str]), ("static", &["-static"])] {
        let d = tmp(&format!("elf-entry-{case}"));
        let exe = cc_entry_exe(&d, "anchored", extra);
        let file = p11scope_manifest::identity::open_object(&exe).unwrap();
        let entry = entry_file_offset(&file)
            .unwrap_or_else(|e| panic!("{case}: entry unreadable: {e}"))
            .unwrap_or_else(|| panic!("{case}: entry outside every loaded segment"));
        let symbol = symbol_file_offset(&file, "entry_point")
            .unwrap()
            .unwrap_or_else(|| panic!("{case}: entry symbol missing"));
        assert_eq!(
            entry, symbol,
            "{case}: header route and symtab route disagree"
        );
        let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
        assert!(
            inspected.contains_executable_offset(entry),
            "{case}: entry offset {entry:#x} is outside every executable segment"
        );
    }
}

#[test]
fn a_table_less_object_reports_no_registry_exports() {
    let d = tmp("elf-empty");
    let so = cc_so(&d, "plain", "int unrelated(void){return 1;}\n");
    let file = p11scope_manifest::identity::open_object(&so).unwrap();
    assert!(exports_matching(&file, REGISTRY).unwrap().is_empty());
}

#[test]
fn conventional_lp64_and_ilp32_are_classified_and_mismatches_refused() {
    let d = tmp("elf-abi");
    let lp64 = cc_so(&d, "lp64", "int hook(void) { return 0; }\n");
    let file = p11scope_manifest::identity::open_object(&lp64).unwrap();
    assert_eq!(ElfSnapshot::read(&file).unwrap().abi(), ElfAbi::Lp64);
    assert_eq!(
        ElfSnapshot::read_with_reader(&file, |file, bytes, offset| { file.read_at(bytes, offset) })
            .unwrap()
            .abi(),
        ElfAbi::Lp64
    );

    let ilp32 = d.join("ilp32.so");
    let status = Command::new("gcc")
        .args(["-m32", "-shared", "-fPIC", "-o"])
        .arg(&ilp32)
        .arg("-x")
        .arg("c")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"int hook(void) { return 0; }\n")?;
            child.wait()
        })
        .unwrap();
    assert!(
        status.success(),
        "the W7 test environment requires gcc -m32"
    );
    let file = p11scope_manifest::identity::open_object(&ilp32).unwrap();
    assert_eq!(ElfSnapshot::read(&file).unwrap().abi(), ElfAbi::Ilp32);
    assert_eq!(
        ElfSnapshot::read_with_reader(&file, |file, bytes, offset| { file.read_at(bytes, offset) })
            .unwrap()
            .abi(),
        ElfAbi::Ilp32
    );

    for (name, class, machine) in [("x32", 1, elf::EM_X86_64), ("elf64-i386", 2, elf::EM_386)] {
        let path = d.join(name);
        let mut bytes = std::fs::read(if class == 1 { &ilp32 } else { &lp64 }).unwrap();
        bytes[4] = class;
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();
        let file = p11scope_manifest::identity::open_object(&path).unwrap();
        assert!(ElfSnapshot::read(&file).is_err(), "{name} must be refused");
    }

    let path = d.join("big-endian");
    let mut bytes = std::fs::read(&lp64).unwrap();
    bytes[5] = 2;
    std::fs::write(&path, bytes).unwrap();
    let file = p11scope_manifest::identity::open_object(&path).unwrap();
    assert!(ElfSnapshot::read(&file).is_err());
}

#[test]
fn virtual_symbol_accepts_bss_but_requires_complete_load_memory_span() {
    let d = tmp("elf-bss-symbol");
    for (bits, abi) in [(32, ElfAbi::Ilp32), (64, ElfAbi::Lp64)] {
        let exe = cc_exe_width(
            &d,
            &format!("bss-state-{bits}"),
            "unsigned int loader_state;\nint main(void) { return (int)loader_state; }\n",
            bits,
        );
        let file = p11scope_manifest::identity::open_object(&exe).unwrap();
        let snapshot = ElfSnapshot::read(&file).unwrap();
        assert_eq!(snapshot.abi(), abi);
        let address = snapshot
            .defined_symbol_virtual_address("loader_state", 4)
            .unwrap()
            .unwrap();
        assert_ne!(address, 0);
        assert_eq!(snapshot.defined_symbol("loader_state").unwrap(), None);
        assert!(
            snapshot
                .defined_symbol_virtual_address("loader_state", usize::MAX)
                .is_err()
        );

        // Keep the symbol and section metadata intact while shortening only
        // its PT_LOAD memory boundary to one byte short of the requested word.
        let mut bytes = std::fs::read(&exe).unwrap();
        let (phoff, phsize, phnum) = if bits == 32 {
            (
                u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize,
                le_u16(&bytes, 42) as usize,
                le_u16(&bytes, 44) as usize,
            )
        } else {
            (
                le_u64(&bytes, 32) as usize,
                le_u16(&bytes, 54) as usize,
                le_u16(&bytes, 56) as usize,
            )
        };
        let mut shortened = false;
        for header in (0..phnum).map(|index| phoff + index * phsize) {
            if u32::from_le_bytes(bytes[header..header + 4].try_into().unwrap()) != elf::PT_LOAD {
                continue;
            }
            let (vaddr, memsz) = if bits == 32 {
                (
                    u32::from_le_bytes(bytes[header + 8..header + 12].try_into().unwrap()) as u64,
                    u32::from_le_bytes(bytes[header + 20..header + 24].try_into().unwrap()) as u64,
                )
            } else {
                (le_u64(&bytes, header + 16), le_u64(&bytes, header + 40))
            };
            if vaddr <= address && address + 4 <= vaddr + memsz {
                let size = address + 3 - vaddr;
                if bits == 32 {
                    bytes[header + 20..header + 24].copy_from_slice(&(size as u32).to_le_bytes());
                } else {
                    bytes[header + 40..header + 48].copy_from_slice(&size.to_le_bytes());
                }
                shortened = true;
            }
        }
        assert!(shortened);
        std::fs::write(&exe, bytes).unwrap();
        let file = p11scope_manifest::identity::open_object(&exe).unwrap();
        assert_eq!(
            ElfSnapshot::read(&file)
                .unwrap()
                .defined_symbol_virtual_address("loader_state", 4),
            Ok(None)
        );
    }
}

#[test]
fn ilp32_interpreter_rejects_malformed_paths_and_program_headers() {
    let d = tmp("elf32-interpreter-refusals");
    let exe = cc_exe_width(&d, "interpreter", "int main(void) { return 0; }\n", 32);
    let original = std::fs::read(&exe).unwrap();
    let phoff = u32::from_le_bytes(original[28..32].try_into().unwrap()) as usize;
    let phsize = le_u16(&original, 42) as usize;
    let phnum = le_u16(&original, 44) as usize;
    let headers: Vec<_> = (0..phnum).map(|i| phoff + i * phsize).collect();
    let header = *headers
        .iter()
        .find(|&&h| u32::from_le_bytes(original[h..h + 4].try_into().unwrap()) == elf::PT_INTERP)
        .unwrap();
    let offset = u32::from_le_bytes(original[header + 4..header + 8].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(original[header + 16..header + 20].try_into().unwrap()) as usize;
    let file = p11scope_manifest::identity::open_object(&exe).unwrap();
    let snapshot = ElfSnapshot::read(&file).unwrap();
    assert_eq!(snapshot.abi(), ElfAbi::Ilp32);
    assert_eq!(
        snapshot.interpreter(),
        Some(&original[offset..offset + size - 1])
    );

    for case in [
        "missing-nul",
        "embedded-nul",
        "empty",
        "past-eof",
        "duplicate",
    ] {
        let mut bytes = original.clone();
        match case {
            "missing-nul" => bytes[offset + size - 1] = b'X',
            "embedded-nul" => bytes[offset + 1] = 0,
            "empty" => bytes[header + 16..header + 20].copy_from_slice(&0_u32.to_le_bytes()),
            "past-eof" => bytes[header + 4..header + 8].copy_from_slice(&u32::MAX.to_le_bytes()),
            "duplicate" => {
                let other = *headers.iter().find(|&&h| h != header).unwrap();
                bytes.copy_within(header..header + phsize, other);
            }
            _ => unreachable!(),
        }
        assert_ne!(bytes, original);
        let path = d.join(case);
        std::fs::write(&path, bytes).unwrap();
        let file = p11scope_manifest::identity::open_object(&path).unwrap();
        assert!(ElfSnapshot::read(&file).is_err(), "accepted {case}");
    }
}

#[test]
fn non_elf_and_foreign_class_are_refused_with_a_named_reason() {
    let d = tmp("elf-refuse");
    let text = d.join("not-an-elf.so");
    std::fs::write(&text, b"#!/bin/sh\necho hi\n").unwrap();
    let file = p11scope_manifest::identity::open_object(&text).unwrap();
    let error = exports_matching(&file, REGISTRY).unwrap_err();
    assert!(error.contains("ELF"), "{error}");

    // Conventional ia32 is an admitted W7 target and must use the same export path.
    let ok = Command::new("gcc")
        .args(["-m32", "-shared", "-fPIC", "-o"])
        .arg(d.join("m32.so"))
        .arg("-x")
        .arg("c")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write as _;
            c.stdin
                .as_mut()
                .unwrap()
                .write_all(b"unsigned long C_GetFunctionList(void**p){(void)p;return 0;}\n")?;
            c.wait()
        })
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "the W7 test environment requires gcc -m32");
    let file = p11scope_manifest::identity::open_object(&d.join("m32.so")).unwrap();
    assert_eq!(
        exports_matching(&file, REGISTRY).unwrap()[0].0,
        "C_GetFunctionList"
    );
}

// --- A5: demand-paged export facts (mmap + the existing object parser) ---

/// Whole-file oracle: `(abi, exports)` from a retained snapshot.
fn oracle_facts(path: &Path, wanted: &[&str]) -> Result<(ElfAbi, Vec<(String, u64)>), String> {
    let file = p11scope_manifest::identity::open_object(path).unwrap();
    let snapshot = ElfSnapshot::read(&file)?;
    Ok((snapshot.abi(), snapshot.exports_matching(wanted)?))
}

// Mirrors the frozen `read_export_facts` return shape.
#[allow(clippy::type_complexity)]
fn sparse_result(
    path: &Path,
    wanted: &[&str],
) -> Result<(ElfAbi, Vec<(String, u64)>, u64), String> {
    let file = p11scope_manifest::identity::open_object(path).unwrap();
    read_export_facts(&file, wanted)
}

/// The sparse facts must equal the whole-file oracle exactly — same ABI, same
/// exports in the same order with the same offsets, or byte-identical errors.
/// Returns the charged bytes on success.
fn assert_sparse_matches_oracle(path: &Path, wanted: &[&str]) -> u64 {
    match (oracle_facts(path, wanted), sparse_result(path, wanted)) {
        (Ok((abi, exports)), Ok((sparse_abi, sparse_exports, charged))) => {
            assert_eq!(
                (sparse_abi, sparse_exports),
                (abi, exports),
                "facts for {}",
                path.display()
            );
            assert!(charged > 0, "charge must be nonzero for {}", path.display());
            charged
        }
        (Err(expected), Err(actual)) => {
            assert_eq!(actual, expected, "error for {}", path.display());
            0
        }
        (oracle, sparse) => panic!(
            "oracle/sparse disposition differs for {}: {oracle:?} vs {sparse:?}",
            path.display()
        ),
    }
}

fn assert_bounded_charge(path: &Path, charged: u64) {
    let file_len = std::fs::metadata(path).unwrap().len();
    assert!(
        charged < 1024 * 1024,
        "charge for {} must be tables, not the file: {charged} of {file_len}",
        path.display()
    );
    assert!(
        charged < file_len,
        "charge for {} must be below the whole file: {charged} of {file_len}",
        path.display()
    );
}

fn provider_source() -> &'static str {
    "unsigned long C_GetFunctionList(void **p){(void)p;return 0;}\n\
     unsigned long NSC_GetFunctionList(void **p){(void)p;return 0;}\n"
}

#[test]
fn export_facts_match_snapshot_on_provider_and_system_objects() {
    let d = tmp("elf-export-facts-oracle");
    let provider = cc_so(&d, "provider", provider_source());
    let charged = assert_sparse_matches_oracle(&provider, REGISTRY);
    assert_bounded_charge(&provider, charged);
    let (_, exports) = oracle_facts(&provider, REGISTRY).unwrap();
    assert!(
        !exports.is_empty(),
        "the provider fixture must export hooks, or the offsets are unpinned"
    );

    // A real shell: table-less for the registry, but the ABI and the (empty)
    // export list must still agree exactly.
    let sh = Path::new("/bin/sh");
    let charged = assert_sparse_matches_oracle(sh, REGISTRY);
    assert_bounded_charge(sh, charged);

    // The system libc exports no registry hooks, so pin it with its own names.
    let mut saw_libc = false;
    for candidate in [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/libc.so.6",
    ] {
        if !Path::new(candidate).exists() {
            continue;
        }
        saw_libc = true;
        let wanted = ["malloc", "printf", "calloc"];
        let charged = assert_sparse_matches_oracle(Path::new(candidate), &wanted);
        assert_bounded_charge(Path::new(candidate), charged);
        let (_, exports) = oracle_facts(Path::new(candidate), &wanted).unwrap();
        assert!(!exports.is_empty(), "libc must export malloc/printf");
    }
    assert!(saw_libc, "the test environment must provide a libc");

    // Installed providers exercise real-world table shapes (GNU_HASH-only
    // softhsm, p11-kit-trust); absent ones are skipped, never failed.
    for optional in [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so",
    ] {
        if !Path::new(optional).exists() {
            eprintln!("SKIP: {optional} not installed");
            continue;
        }
        let charged = assert_sparse_matches_oracle(Path::new(optional), REGISTRY);
        assert_bounded_charge(Path::new(optional), charged);
    }
}

#[test]
fn export_facts_match_snapshot_on_ilp32_provider() {
    let d = tmp("elf-export-facts-ilp32");
    let ilp32 = d.join("provider32.so");
    let ok = Command::new("gcc")
        .args(["-m32", "-shared", "-fPIC", "-o"])
        .arg(&ilp32)
        .arg("-x")
        .arg("c")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(provider_source().as_bytes())?;
            child.wait()
        })
        .map(|status| status.success())
        .unwrap_or(false);
    assert!(ok, "the W7 test environment requires gcc -m32");
    let charged = assert_sparse_matches_oracle(&ilp32, REGISTRY);
    assert_bounded_charge(&ilp32, charged);
    let (abi, exports) = oracle_facts(&ilp32, REGISTRY).unwrap();
    assert_eq!(abi, ElfAbi::Ilp32);
    assert!(!exports.is_empty(), "the ilp32 provider must export hooks");
}

/// `(shoff, entsize, count)` of the ELF64 section-header table.
fn section_table(bytes: &[u8]) -> (usize, usize, usize) {
    assert_eq!(&bytes[..4], b"\x7fELF");
    assert_eq!(bytes[4], 2, "fixture must be ELF64");
    (
        le_u64(bytes, 0x28).try_into().unwrap(),
        usize::from(le_u16(bytes, 0x3A)),
        usize::from(le_u16(bytes, 0x3C)),
    )
}

fn section_offset_mut(bytes: &mut [u8], kind: u32) -> Option<(usize, u32)> {
    let (start, size, count) = section_table(bytes);
    (0..count)
        .map(|index| start + index * size)
        .find(|offset| {
            u32::from_le_bytes(bytes[*offset + 4..*offset + 8].try_into().unwrap()) == kind
        })
        .map(|offset| {
            let link = u32::from_le_bytes(bytes[offset + 40..offset + 44].try_into().unwrap());
            (offset, link)
        })
}

#[test]
fn export_facts_refuse_corrupt_tables_exactly_like_snapshot() {
    let d = tmp("elf-export-facts-corrupt");
    let provider = cc_so(&d, "provider", provider_source());
    let original = std::fs::read(&provider).unwrap();

    // Every corruption below fails inside `classified_object` (the shared
    // parse core), so the sparse error must be byte-identical to the oracle.
    let mut bad_magic = original.clone();
    bad_magic[0..4].copy_from_slice(b"NOPE");
    let mut big_endian = original.clone();
    big_endian[5] = 2;
    // (0xFFFF is PN_XNUM — extended numbering, not a huge count — so a
    // truncated header table is pinned via e_phoff past EOF instead.)
    let mut phoff_past_eof = original.clone();
    phoff_past_eof[0x20..0x28].copy_from_slice(&(original.len() as u64 + 0x1000).to_le_bytes());
    let mut bad_dynsym = original.clone();
    let (dynsym, _) = section_offset_mut(&mut bad_dynsym, elf::SHT_DYNSYM).unwrap();
    bad_dynsym[dynsym + 24..dynsym + 32]
        .copy_from_slice(&(original.len() as u64 + 0x1000).to_le_bytes());
    let mut dynsym_overflow = original.clone();
    let (dynsym, _) = section_offset_mut(&mut dynsym_overflow, elf::SHT_DYNSYM).unwrap();
    dynsym_overflow[dynsym + 24..dynsym + 32].copy_from_slice(&u64::MAX.to_le_bytes());

    for (case, bytes) in [
        ("bad-magic", bad_magic),
        ("short", original[..32].to_vec()),
        ("text", b"#!/bin/sh\necho hi\n".to_vec()),
        ("big-endian", big_endian),
        ("phoff-past-eof", phoff_past_eof),
        ("dynsym-past-eof", bad_dynsym),
        ("dynsym-offset-overflow", dynsym_overflow),
    ] {
        let path = d.join(case);
        std::fs::write(&path, bytes).unwrap();
        assert!(
            sparse_result(&path, REGISTRY).is_err(),
            "{case} must error, never answer or panic"
        );
        assert_sparse_matches_oracle(&path, REGISTRY);
    }
}

#[test]
fn export_facts_tolerate_an_unreadable_dynstr_exactly_like_snapshot() {
    // The dynamic-strings table is read lazily per symbol: a past-EOF offset
    // (non-overflowing, so the eager range check passes) skips names rather
    // than refusing the file — whatever the oracle does, sparse must match.
    let d = tmp("elf-export-facts-dynstr");
    let provider = cc_so(&d, "provider", provider_source());
    let original = std::fs::read(&provider).unwrap();
    let mut bytes = original.clone();
    let (_, link) = section_offset_mut(&mut bytes, elf::SHT_DYNSYM).unwrap();
    let (start, size, _) = section_table(&bytes);
    let dynstr = start + link as usize * size;
    bytes[dynstr + 24..dynstr + 32]
        .copy_from_slice(&(original.len() as u64 + 0x1000).to_le_bytes());
    let path = d.join("dynstr-past-eof.so");
    std::fs::write(&path, &bytes).unwrap();
    assert_sparse_matches_oracle(&path, REGISTRY);
}

#[test]
fn export_facts_clamp_a_lying_dynstr_size_to_the_file() {
    // I-1 regression: the dynstr charge term must not trust the raw `sh_size`
    // u64. A corrupt file claiming a ~281 TB string table still parses (the
    // lazy walk skips unreadable names), so without a clamp one 15 KB file
    // would saturate the whole capture budget. Facts must stay correct —
    // success with empty exports, exactly like the snapshot oracle — while
    // the charge stays within the bytes that could physically have moved.
    let d = tmp("elf-export-facts-lying-dynstr");
    let provider = cc_so(&d, "provider", provider_source());
    let original = std::fs::read(&provider).unwrap();
    let mut bytes = original.clone();
    let (_, link) = section_offset_mut(&mut bytes, elf::SHT_DYNSYM).unwrap();
    let (start, size, _) = section_table(&bytes);
    let dynstr = start + link as usize * size;
    bytes[dynstr + 32..dynstr + 40].copy_from_slice(&0xFFFF_FFFF_FFFF_u64.to_le_bytes());
    assert_ne!(bytes, original);
    let path = d.join("lying-dynstr.so");
    std::fs::write(&path, &bytes).unwrap();

    let file_len = std::fs::metadata(&path).unwrap().len();
    let (abi, exports, charged) = sparse_result(&path, REGISTRY)
        .unwrap_or_else(|error| panic!("a lying dynstr size must skip names, not refuse: {error}"));
    assert!(
        exports.is_empty(),
        "unreadable names must skip: {exports:?}"
    );
    assert!(
        charged <= file_len,
        "charge must be bounded by the file: {charged} of {file_len}"
    );
    let (oracle_abi, oracle_exports) = oracle_facts(&path, REGISTRY).unwrap();
    assert_eq!(
        (abi, exports),
        (oracle_abi, oracle_exports),
        "facts must equal the snapshot oracle"
    );
}

#[test]
fn export_facts_refuse_an_empty_file_exactly_like_snapshot() {
    // Mapping a 0-length file derefs to an empty slice (memmap2 documents
    // this), so the shared parser refuses it with today's exact snapshot
    // string — a skip, never a panic and never facts.
    let d = tmp("elf-export-facts-empty");
    let empty = d.join("empty.so");
    std::fs::write(&empty, b"").unwrap();
    assert!(
        sparse_result(&empty, REGISTRY).is_err(),
        "an empty file must error, never answer or panic"
    );
    assert_sparse_matches_oracle(&empty, REGISTRY);
}
