//! SPDX-License-Identifier: GPL-3.0-or-later
use p11scope::discovery::identity::pin_manifest_objects;
use p11scope::manifest_input::validate_structure;
use p11scope::plan::build_from_sources;
use p11scope_discover::discover::discover;
use p11scope_manifest::manifest::*;
use std::path::PathBuf;
use std::process::Command;

fn provider(name: &str, defines: &[&str]) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("metadata-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("provider.so");
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .arg("-DMETA_RECLAIM_GUARDS=1")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&path)
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("crates/discover/tests/fixture/metadata_provider.c")
            )
            .args(defines)
            .status()
            .unwrap()
            .success()
    );
    path
}

#[test]
fn historical_canonical_full_prefixes_remain_useful_without_claiming_a_complete_walk() {
    for (major, minor) in [(2, 0), (2, 40), (3, 2), (4, 19)] {
        let major_define = format!("-DMETA_MAJOR={major}");
        let minor_define = format!("-DMETA_MINOR={minor}");
        let provider = provider(
            &format!("old-{major}-{minor}"),
            &[&major_define, &minor_define],
        );
        let complete = discover(&provider).unwrap();
        for (words, expected_slots) in [(0, 0), (1, 1), (3, 1), (67, 2)] {
            let mut manifest = complete.clone();
            manifest.surfaces[0].walk = WalkOutcome::Full;
            manifest.surfaces[0].functions.truncate(words);
            let problems = validate_structure(&manifest);
            assert!(problems.is_empty(), "{major}.{minor}/{words}: {problems:?}");
            let pins = pin_manifest_objects(&manifest).unwrap();
            let plan = build_from_sources(&[], &[manifest], &pins);
            assert_eq!(plan.entries_seen, words);
            assert_eq!(plan.slots.len(), expected_slots);
            assert_eq!(plan.surfaces[0].walk, "known_prefix");
            assert!(plan.slots.iter().all(|slot| slot.semantic_authorized));
            assert!(
                !plan
                    .skipped
                    .iter()
                    .any(|entry| entry.subject == "C_WaitForSlotEvent")
            );
        }
    }
}

fn assert_header_recovery(interface: usize) {
    let interface_define = format!("-DMETA_INTERFACE={interface}");
    let provider = provider(
        &format!("unreadable-header-{interface}"),
        &["-DMETA_HEADER_UNREADABLE=1", &interface_define],
    );
    let manifest = discover(&provider).unwrap();
    let surface = &manifest.surfaces[interface];
    assert_eq!(surface.version, None);
    assert!(matches!(&surface.walk, WalkOutcome::Unreadable { detail } if !detail.is_empty()));
    assert_eq!(surface.functions.len(), 68);
    assert_eq!(surface.functions[43].name, "C_Sign");
    assert_eq!(surface.functions[67].name, "C_WaitForSlotEvent");
    assert!(matches!(
        surface.functions[67].resolution,
        Resolution::NullPointer
    ));
    let problems = validate_structure(&manifest);
    assert!(problems.is_empty(), "{problems:?}");
    let pins = pin_manifest_objects(&manifest).unwrap();
    let plan = build_from_sources(&[], &[manifest], &pins);
    assert_eq!(plan.entries_seen, 68);
    assert_eq!(plan.slots.len(), 2);
    assert_eq!(
        plan.modules[0].tables[0].version,
        (0, 0),
        "existing public placeholder; the manifest version remains None"
    );
    assert!(
        plan.surfaces[interface]
            .walk
            .contains("version header unreadable")
    );
    assert_eq!(plan.surfaces[interface].functions, 68);
    let sign = plan
        .slots
        .iter()
        .find(|slot| slot.names == ["C_Sign"])
        .unwrap();
    assert!(sign.semantic_authorized);
    assert_ne!(sign.descriptor_index, 0);
}

#[test]
fn unreadable_legacy_header_preserves_all_readable_function_words_and_s1() {
    assert_header_recovery(0);
}

#[test]
fn unreadable_interface_header_preserves_all_readable_function_words_and_s1() {
    assert_header_recovery(1);
}

#[test]
fn reported_zero_version_stays_distinct_from_the_public_unknown_placeholder() {
    let provider = provider("reported-zero", &["-DMETA_MAJOR=0", "-DMETA_MINOR=0"]);
    let manifest = discover(&provider).unwrap();
    assert_eq!(
        manifest.surfaces[0].version,
        Some(Version { major: 0, minor: 0 })
    );
    let pins = pin_manifest_objects(&manifest).unwrap();
    let plan = build_from_sources(&[], &[manifest], &pins);
    assert_eq!(plan.modules[0].tables[0].version, (0, 0));
    assert_eq!(plan.surfaces[0].walk, "known_prefix");
    assert_eq!(plan.entries_seen, 68);
    assert_eq!(plan.slots.len(), 2);
}

#[test]
fn imported_missing_version_is_explicit_without_changing_function_authority() {
    let provider = provider("imported-missing-version", &[]);
    let complete = discover(&provider).unwrap();
    for walk in [WalkOutcome::Full, WalkOutcome::KnownPrefix] {
        for words in [67, 68] {
            for version in [None, Some(Version { major: 0, minor: 0 })] {
                let mut manifest = complete.clone();
                manifest.surfaces[0].version = version;
                manifest.surfaces[0].walk = walk.clone();
                manifest.surfaces[0].functions.truncate(words);
                assert!(validate_structure(&manifest).is_empty());
                let pins = pin_manifest_objects(&manifest).unwrap();
                let plan = build_from_sources(&[], &[manifest], &pins);
                assert_eq!(plan.modules[0].tables[0].version, (0, 0));
                assert_eq!(plan.entries_seen, words);
                assert_eq!(plan.slots.len(), 2);
                assert!(plan.slots.iter().all(|slot| slot.semantic_authorized));
                assert_eq!(
                    plan.surfaces[0]
                        .walk
                        .contains("version metadata unavailable"),
                    version.is_none(),
                    "walk={walk:?}, words={words}, version={version:?}"
                );
                assert_eq!(
                    plan.surfaces[0].walk.starts_with("known_prefix"),
                    words < 68 || matches!(walk, WalkOutcome::KnownPrefix)
                );
            }
        }
    }
}

#[test]
fn unreadable_header_and_missing_word_controls_keep_only_observed_rows() {
    for (name, defines, observed) in [
        ("healthy", vec![], 68),
        ("missing-last", vec!["-DMETA_WORDS=67"], 67),
        ("no-readable-words", vec!["-DMETA_HEADER_UNREADABLE=2"], 0),
    ] {
        let provider = provider(name, &defines);
        let manifest = discover(&provider).unwrap();
        assert_eq!(manifest.surfaces[0].functions.len(), observed, "{name}");
        assert!(validate_structure(&manifest).is_empty(), "{name}");
    }
}
