//! SPDX-License-Identifier: GPL-3.0-or-later
//! Selected observations remain useful independently of stronger authority.

#[allow(dead_code)]
#[path = "../../../src/manifest_input.rs"]
mod manifest_input;

use p11scope_discover::manifest::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn observe(defines: &[&str]) -> Manifest {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "selection-recovery-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let provider = directory.join("provider.so");
    let mut compiler = Command::new("gcc");
    compiler
        .arg(format!("-m{}", usize::BITS))
        .args(["-shared", "-fPIC", "-o"])
        .arg(&provider)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture/selection_recovery.c"))
        .args(defines);
    if defines.contains(&"-DSELECT_BAD=3") {
        let source = directory.join("backend.c");
        let backend = directory.join("backend.so");
        std::fs::write(
            &source,
            "unsigned long selection_backend(void) { return 0; }\n",
        )
        .unwrap();
        assert!(
            Command::new("gcc")
                .arg(format!("-m{}", usize::BITS))
                .args(["-shared", "-fPIC", "-Wl,-soname,backend.so", "-o"])
                .arg(&backend)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        compiler
            .arg(&backend)
            .arg(format!("-Wl,-rpath,{}", directory.display()));
    }
    assert!(compiler.status().unwrap().success());
    let output = Command::new(env!("CARGO_BIN_EXE_p11scope-discover"))
        .arg("--module")
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn only_table(manifest: &Manifest, words: usize) -> &SelectionTable {
    let evidence = &manifest.selection_evidence;
    assert_eq!(evidence.queries.len(), 10);
    assert_eq!(evidence.tables.len(), 1, "{evidence:?}");
    let table = &evidence.tables[0];
    assert_eq!(table.functions.len(), words);
    assert!(!table.semantic_authorized);
    assert_eq!(
        table.functions.first().map(|f| f.name.as_str()),
        (words > 0).then_some("C_Initialize")
    );
    assert!(evidence.queries.iter().filter(|q| q.rv == 0).all(|query| {
        query.selection_table == Some(table.id)
            && query.authority == SelectionAuthority::SelectionCountOnly
            && query.inventory_matches.is_empty()
    }));
    let problems = manifest_input::validate_structure(manifest);
    assert!(problems.is_empty(), "{problems:?}");
    table
}

#[test]
fn selected_versions_preserve_source_bounded_ordinals() {
    for (major, minor, words) in [
        (2, 0, 68),
        (2, 40, 68),
        (3, 0, 92),
        (3, 1, 92),
        (3, 2, 104),
        (3, 9, 104),
        (4, 19, 68),
    ] {
        let major_define = format!("-DSELECT_MAJOR={major}");
        let minor_define = format!("-DSELECT_MINOR={minor}");
        let manifest = observe(&[&major_define, &minor_define]);
        let table = only_table(&manifest, words);
        assert_eq!(table.version, Version { major, minor });
        assert!(matches!(
            table.functions[67].resolution,
            Resolution::Resolved { .. }
        ));
        assert!(!manifest.selection_evidence.selection_truncated);
    }
}

#[test]
fn selected_unknown_metadata_and_default_request_keep_count_only_targets() {
    for defines in [
        vec!["-DSELECT_FLAGS=64"],
        vec!["-DSELECT_NAME=1"],
        vec!["-DSELECT_NAME=2"],
        vec!["-DSELECT_NAME=3"],
        vec!["-DSELECT_DEFAULT_ONLY=1"],
        vec!["-DSELECT_LEGACY=1", "-DSELECT_LIST=1"],
        vec!["-DSELECT_LEGACY=1", "-DSELECT_LIST=2"],
    ] {
        let manifest = observe(&defines);
        let table = only_table(&manifest, 92);
        assert!(matches!(
            table.functions[43].resolution,
            Resolution::Resolved { .. }
        ));
    }
}

#[test]
fn selected_sparse_and_empty_tables_are_observations() {
    for (sparse, populated) in [(-1, 0), (67, 1)] {
        let define = format!("-DSELECT_SPARSE={sparse}");
        let manifest = observe(&[&define]);
        let table = only_table(&manifest, 92);
        assert_eq!(
            table
                .functions
                .iter()
                .filter(|f| matches!(f.resolution, Resolution::Resolved { .. }))
                .count(),
            populated
        );
        assert!(!manifest.selection_evidence.selection_truncated);
    }
}

#[test]
fn selected_missing_tail_and_heap_keep_only_completed_words() {
    for words in [0, 1, 3, 67, 68, 92, 104] {
        let define = format!("-DSELECT_WORDS={words}");
        let manifest = observe(&["-DSELECT_MINOR=2", &define]);
        let table = only_table(&manifest, words);
        assert_eq!(manifest.selection_evidence.selection_truncated, words < 104);
        assert_eq!(
            matches!(table.walk, WalkOutcome::Unreadable { .. }),
            words < 104
        );
    }
    only_table(&observe(&["-DSELECT_HEAP=1"]), 92);
    let partial = observe(&[
        "-DSELECT_MINOR=2",
        "-DSELECT_WORDS=67",
        "-DSELECT_PARTIAL_WORD=1",
    ]);
    only_table(&partial, 67);
    assert!(partial.selection_evidence.selection_truncated);
}

#[test]
fn selected_bad_words_do_not_erase_later_targets_or_become_null() {
    for bad in [1, 2, 4] {
        let define = format!("-DSELECT_BAD={bad}");
        let manifest = observe(&[&define]);
        let table = only_table(&manifest, 92);
        assert!(!matches!(
            table.functions[20].resolution,
            Resolution::Resolved { .. } | Resolution::NullPointer
        ));
        assert!(matches!(
            table.functions[67].resolution,
            Resolution::Resolved { .. }
        ));
        assert!(manifest.selection_evidence.selection_truncated);
    }
}

#[test]
fn selected_dependency_uses_ordinary_exact_object_provenance() {
    let manifest = observe(&["-DSELECT_BAD=3"]);
    let table = only_table(&manifest, 92);
    let Resolution::Resolved { object, .. } = table.functions[20].resolution else {
        panic!("dependency observation lost")
    };
    assert_ne!(object, 0);
    assert!(
        manifest.objects[object as usize]
            .path
            .ends_with("backend.so")
    );
    assert!(!manifest.selection_evidence.selection_truncated);
}

#[test]
fn conflicting_selected_observations_retain_both_target_sets() {
    let manifest = observe(&["-DSELECT_CONFLICT=1"]);
    let evidence = &manifest.selection_evidence;
    assert_eq!(evidence.tables.len(), 2);
    assert!(evidence.selection_truncated);
    assert_ne!(
        evidence.tables[0].functions[67].resolution,
        evidence.tables[1].functions[67].resolution
    );
    assert!(
        evidence
            .queries
            .iter()
            .all(|q| q.authority == SelectionAuthority::SelectionCountOnly)
    );
    assert!(manifest_input::validate_structure(&manifest).is_empty());
}

#[test]
fn failed_or_null_selection_has_no_observed_table() {
    for define in ["-DSELECT_ERROR=1", "-DSELECT_NULL_OUTPUT=1"] {
        let manifest = observe(&[define]);
        assert!(manifest.selection_evidence.tables.is_empty());
        assert!(
            manifest
                .selection_evidence
                .queries
                .iter()
                .all(|q| q.authority == SelectionAuthority::None)
        );
        assert!(manifest_input::validate_structure(&manifest).is_empty());
    }
}
