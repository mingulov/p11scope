use p11scope_manifest::elf::{exports_matching, symbol_file_offset};
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

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const REGISTRY: &[&str] = &[
    "C_GetFunctionList",
    "C_GetInterfaceList",
    "C_GetInterface",
    "NSC_GetFunctionList",
    "FC_GetFunctionList",
];

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
