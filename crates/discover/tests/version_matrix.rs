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
        (2, 0, 67, "full"),
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
        (4, 0, 0, "refused"),
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
        WalkOutcome::Refused
    ));

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
fn page_boundary_short_table_becomes_unreadable_evidence() {
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
    assert!(surface.functions.is_empty());
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
}
