use object::elf;
use p11scope_manifest::elf::{ElfSnapshot, exports_matching, symbol_file_offset};
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
    std::fs::create_dir_all(dir).unwrap();
    let c = dir.join(format!("{name}.c"));
    let exe = dir.join(name);
    std::fs::write(&c, source).unwrap();
    let ok = Command::new("gcc")
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
fn a_table_less_object_reports_no_registry_exports() {
    let d = tmp("elf-empty");
    let so = cc_so(&d, "plain", "int unrelated(void){return 1;}\n");
    let file = p11scope_manifest::identity::open_object(&so).unwrap();
    assert!(exports_matching(&file, REGISTRY).unwrap().is_empty());
}

#[test]
fn non_elf_and_foreign_class_are_refused_with_a_named_reason() {
    let d = tmp("elf-refuse");
    let text = d.join("not-an-elf.so");
    std::fs::write(&text, b"#!/bin/sh\necho hi\n").unwrap();
    let file = p11scope_manifest::identity::open_object(&text).unwrap();
    let error = exports_matching(&file, REGISTRY).unwrap_err();
    assert!(error.contains("ELF"), "{error}");

    // 32-bit is a named refusal, not a misread (spec §4.2): build one if the
    // multilib compiler is available, otherwise state that it was not covered.
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
    if !ok {
        eprintln!("SKIP: no -m32 toolchain; ELFCLASS32 refusal not covered on this host");
        return;
    }
    let file = p11scope_manifest::identity::open_object(&d.join("m32.so")).unwrap();
    let error = exports_matching(&file, REGISTRY).unwrap_err();
    assert!(
        error.contains("x86-64") || error.contains("64-bit"),
        "{error}"
    );
}
