//! SPDX-License-Identifier: GPL-3.0-or-later
use p11scope_discover::discover::discover;
use p11scope_discover::manifest::*;
use std::path::{Path, PathBuf};
use std::process::Command;

fn build(name: &str, defines: &[&str]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("version-matrix");
    std::fs::create_dir_all(&dir).unwrap();
    let output = dir.join(format!("{name}.so"));
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture/version_matrix.c");
    let mut command = Command::new("gcc");
    command
        .arg(format!("-m{}", usize::BITS))
        .args(["-shared", "-fPIC", "-o"])
        .arg(&output)
        .arg(source);
    command.args(defines);
    let status = command.status().unwrap();
    assert!(status.success(), "gcc failed for {name}");
    output
}

fn legacy(manifest: &Manifest) -> &SurfaceRecord {
    manifest
        .surfaces
        .iter()
        .find(|surface| matches!(surface.source, SurfaceSource::LegacyFunctionList))
        .unwrap()
}

fn interface(manifest: &Manifest, index: usize) -> &SurfaceRecord {
    manifest
        .surfaces
        .iter()
        .find(|surface| matches!(surface.source, SurfaceSource::Interface { index: i, .. } if i == index))
        .unwrap_or_else(|| panic!("missing interface {index}"))
}

#[test]
fn legacy_layout_matrix_covers_200_through_32() {
    let cases = [
        (2, 0, 68, "full"),
        (2, 1, 68, "full"),
        (2, 10, 68, "full"),
        (2, 11, 68, "full"),
        (2, 20, 68, "full"),
        (2, 30, 68, "full"),
        (2, 40, 68, "full"),
        (2, 41, 68, "known_prefix"),
        (3, 0, 68, "known_prefix"),
        (3, 1, 68, "known_prefix"),
        (3, 2, 68, "known_prefix"),
        (4, 0, 68, "known_prefix"),
        (0, 255, 68, "known_prefix"),
    ];
    for (major, minor, count, expected_walk) in cases {
        let name = format!("legacy-{major}-{minor}");
        let major_define = format!("-DLEGACY_MAJOR={major}");
        let minor_define = format!("-DLEGACY_MINOR={minor}");
        let provider = build(
            &name,
            &[&major_define, &minor_define, "-DMATRIX_INTERFACES=0"],
        );
        let manifest = discover(&provider).unwrap();
        let surface = legacy(&manifest);
        assert_eq!(surface.version, Some(Version { major, minor }), "{name}");
        assert_eq!(surface.functions.len(), count, "{name}");
        let walk = match &surface.walk {
            WalkOutcome::Full => "full",
            WalkOutcome::KnownPrefix => "known_prefix",
            WalkOutcome::Refused => "refused",
            other => panic!("unexpected {name} walk: {other:?}"),
        };
        assert_eq!(walk, expected_walk, "{name}");
        if count > 0 {
            assert_eq!(surface.functions[0].name, "C_Initialize");
            assert_eq!(
                surface.functions.last().unwrap().name,
                pkcs11_module::FUNCTION_LIST_FIELDS[count - 1].name,
                "{name} boundary"
            );
        }
    }
}

#[test]
fn standard_and_corroborated_interfaces_cover_every_published_boundary() {
    let provider = build(
        "interfaces",
        &[
            "-DLEGACY_MAJOR=2",
            "-DLEGACY_MINOR=40",
            "-DMATRIX_INTERFACES=1",
        ],
    );
    let manifest = discover(&provider).unwrap();

    for (index, version, count, prefix) in [
        (
            0,
            Version {
                major: 2,
                minor: 40,
            },
            68,
            false,
        ),
        (1, Version { major: 3, minor: 0 }, 92, false),
        (2, Version { major: 3, minor: 1 }, 92, false),
        (3, Version { major: 3, minor: 2 }, 104, false),
        (4, Version { major: 3, minor: 9 }, 104, true),
    ] {
        let surface = interface(&manifest, index);
        assert_eq!(surface.version, Some(version));
        assert_eq!(surface.functions.len(), count, "interface {index}");
        assert_eq!(matches!(&surface.walk, WalkOutcome::KnownPrefix), prefix);
    }
    assert!(matches!(
        &interface(&manifest, 5).walk,
        WalkOutcome::KnownPrefix
    ));
    assert_eq!(interface(&manifest, 5).functions.len(), 68);

    let all_names: Vec<&str> = pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS)
        .map(|field| field.name)
        .collect();
    let v32 = interface(&manifest, 3);
    for boundary in [0, 66, 67, 68, 91, 92, 103] {
        assert_eq!(v32.functions[boundary].name, all_names[boundary]);
    }

    for index in [6, 7, 8, 10] {
        let surface = interface(&manifest, index);
        assert!(matches!(&surface.walk, WalkOutcome::KnownPrefix));
        assert!(matches!(
            surface.source,
            SurfaceSource::Interface {
                classification: InterfaceClassification::CorroboratedStandardPrefix,
                ..
            }
        ));
    }
    assert!(matches!(
        &interface(&manifest, 11).walk,
        WalkOutcome::NotWalked
    ));
    assert_eq!(interface(&manifest, 12).functions.len(), 104);
    assert!(matches!(&interface(&manifest, 12).walk, WalkOutcome::Full));
    assert!(
        manifest
            .vendor_interfaces
            .iter()
            .any(|vendor| vendor.index == 9)
    );
    assert!(
        !manifest
            .surfaces
            .iter()
            .any(|surface| { matches!(surface.source, SurfaceSource::Interface { index: 9, .. }) })
    );
}

#[test]
fn page_boundary_short_table_retains_only_complete_pointer_words() {
    let provider = build(
        "short-table",
        &[
            "-DLEGACY_MAJOR=2",
            "-DLEGACY_MINOR=1",
            "-DMATRIX_INTERFACES=0",
            "-DSHORT_LEGACY=1",
        ],
    );
    let manifest = discover(&provider).unwrap();
    let surface = legacy(&manifest);
    assert!(matches!(&surface.walk, WalkOutcome::Unreadable { .. }));
    assert_eq!(surface.functions.len(), 67);
    assert_eq!(surface.functions[66].name, "C_CancelFunction");
    assert!(
        surface
            .functions
            .iter()
            .all(|function| matches!(function.resolution, Resolution::Resolved { .. }))
    );
}

#[test]
fn bounded_legacy_tables_preserve_sparse_and_empty_observations() {
    for ((major, minor, populated), words) in [
        (2, 40, 67),
        (3, 0, 67),
        (3, 1, 67),
        (3, 2, 67),
        (4, 19, 27),
        (0, 255, -1),
        (2, 0, 67),
    ]
    .into_iter()
    .flat_map(|case| [68, 92, 104].map(|words| (case, words)))
    {
        let name = format!("bounded-{major}-{minor}-{populated}-{words}");
        let major_define = format!("-DLEGACY_MAJOR={major}");
        let minor_define = format!("-DLEGACY_MINOR={minor}");
        let sparse_define = format!("-DSPARSE_LEGACY={populated}");
        let words_define = format!("-DMAPPED_LEGACY_WORDS={words}");
        let provider = build(
            &name,
            &[
                &major_define,
                &minor_define,
                &sparse_define,
                "-DMATRIX_INTERFACES=0",
                &words_define,
                "-DLEGACY_PADDING=1",
            ],
        );
        let manifest = discover(&provider).unwrap();
        let surface = legacy(&manifest);
        assert_eq!(surface.version, Some(Version { major, minor }), "{name}");
        assert_eq!(surface.functions.len(), 68, "{name}");
        assert!(
            matches!(surface.walk, WalkOutcome::Full | WalkOutcome::KnownPrefix),
            "{name}"
        );
        assert_eq!(surface.functions[27].name, "C_FindObjects");
        assert_eq!(surface.functions[67].name, "C_WaitForSlotEvent");
        for (ordinal, function) in surface.functions.iter().enumerate() {
            assert_eq!(
                matches!(function.resolution, Resolution::Resolved { .. }),
                ordinal as i32 == populated,
                "{name} slot {ordinal}"
            );
            assert_eq!(
                matches!(function.resolution, Resolution::NullPointer),
                ordinal as i32 != populated,
                "{name} slot {ordinal}"
            );
        }
    }
}

#[test]
fn interface_version_does_not_erase_observed_common_or_extend_a_shorter_layout() {
    for ((major, minor, bound), words) in [
        (2, 40, 68),
        (3, 0, 92),
        (3, 1, 92),
        (3, 2, 104),
        (4, 19, 68),
    ]
    .into_iter()
    .flat_map(|case| [68, 92, 104].map(|words| (case, words)))
    {
        let name = format!("interface-{major}-{minor}-with-{words}");
        let major_define = format!("-DINTERFACE_MAJOR={major}");
        let minor_define = format!("-DINTERFACE_MINOR={minor}");
        let words_define = format!("-DMAPPED_V32_WORDS={words}");
        let provider = build(&name, &[&major_define, &minor_define, &words_define]);
        let manifest = discover(&provider).unwrap();
        let surface = interface(&manifest, 3);
        assert_eq!(surface.version, Some(Version { major, minor }), "{name}");
        assert_eq!(
            matches!(surface.walk, WalkOutcome::Unreadable { .. }),
            words < bound,
            "{name}"
        );
        assert_eq!(surface.functions.len(), words.min(bound), "{name}");
        assert_eq!(surface.functions[67].name, "C_WaitForSlotEvent");
        if words.min(bound) >= 92 {
            assert_eq!(surface.functions[91].name, "C_MessageVerifyFinal");
        }
        assert_eq!(
            interface(&manifest, 0).functions.len(),
            68,
            "a 2.40 label on 104-word storage does not claim extension ordinals"
        );
        assert_eq!(interface(&manifest, 1).functions.len(), 92);
    }
}

#[test]
fn legacy_read_failure_distinguishes_unread_words_from_null() {
    for words in [0, 1, 3, 67] {
        let name = format!("short-{words}-words");
        let words_define = format!("-DMAPPED_LEGACY_WORDS={words}");
        let provider = build(
            &name,
            &[
                "-DLEGACY_MAJOR=2",
                "-DLEGACY_MINOR=0",
                "-DMATRIX_INTERFACES=0",
                "-DSPARSE_LEGACY=0",
                &words_define,
            ],
        );
        let manifest = discover(&provider).unwrap();
        let surface = legacy(&manifest);
        assert!(
            matches!(&surface.walk, WalkOutcome::Unreadable { detail } if !detail.is_empty()),
            "{name}"
        );
        assert_eq!(surface.functions.len(), words, "{name}");
        if words > 0 {
            assert!(matches!(
                surface.functions[0].resolution,
                Resolution::Resolved { .. }
            ));
            assert!(
                surface.functions[1..]
                    .iter()
                    .all(|function| matches!(function.resolution, Resolution::NullPointer))
            );
        }
    }
}

#[test]
fn preloaded_and_non_executable_targets_are_evidence_not_probe_targets() {
    let provider = build(
        "untrusted-targets",
        &[
            "-DLEGACY_MAJOR=2",
            "-DLEGACY_MINOR=40",
            "-DMATRIX_INTERFACES=0",
            "-DUNTRUSTED_TARGETS=1",
        ],
    );
    let manifest = discover(&provider).unwrap();
    let surface = legacy(&manifest);
    for (index, expected) in [(0, "not loaded for this provider"), (1, "not executable")] {
        let Resolution::UnusableFile { reason, .. } = &surface.functions[index].resolution else {
            panic!(
                "slot {index} unexpectedly attachable: {:?}",
                surface.functions[index]
            );
        };
        assert!(reason.contains(expected), "slot {index}: {reason}");
    }
    for ordinal in [2, 67] {
        assert!(
            matches!(
                surface.functions[ordinal].resolution,
                Resolution::Resolved { .. }
            ),
            "valid slot {ordinal} survives unusable targets"
        );
    }
}
