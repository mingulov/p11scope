use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
use p11scope_manifest::manifest::*;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

fn tmpdir(name: &str) -> PathBuf {
    let d =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Build a .so with a caller-chosen build-id so two builds differ.
fn cc_so(dir: &Path, name: &str, body: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, body).unwrap();
    let so = dir.join(format!("{name}.so"));
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-Wl,--build-id=sha1", "-o"])
            .arg(&so)
            .arg(&src)
            .status()
            .unwrap()
            .success()
    );
    so
}

fn cc_so_with_build_id(dir: &Path, name: &str, body: &str, build_id: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, body).unwrap();
    let so = dir.join(format!("{name}.so"));
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC"])
            .arg(format!("-Wl,--build-id=0x{build_id}"))
            .args(["-o"])
            .arg(&so)
            .arg(&src)
            .status()
            .unwrap()
            .success()
    );
    so
}

fn manifest_for(path: &Path) -> Manifest {
    let id = p11scope_manifest::identity::identify(path);
    Manifest {
        schema: SCHEMA.to_string(),
        module_path: path.display().to_string(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.display().to_string(),
            identity: id,
        }],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Absent,
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        }],
        vendor_interfaces: vec![],
        alias_groups: vec![],
    }
}

fn first_executable_offset(path: &Path) -> u64 {
    let file = p11scope_manifest::identity::open_object(path).unwrap();
    p11scope_manifest::identity::inspect_file(&file)
        .unwrap()
        .executable_ranges[0]
        .0
}

fn walked_legacy_manifest(path: &Path) -> Manifest {
    let mut manifest = manifest_for(path);
    let offset = first_executable_offset(path);
    manifest.surfaces[0] = SurfaceRecord {
        source: SurfaceSource::LegacyFunctionList,
        acquisition: Acquisition::Ok,
        version: Some(Version {
            major: 2,
            minor: 40,
        }),
        walk: WalkOutcome::Full,
        functions: pkcs11_module::FUNCTION_LIST_FIELDS
            .iter()
            .map(|field| FunctionRecord {
                name: field.name.into(),
                resolution: Resolution::Resolved {
                    object: 0,
                    file_offset: offset,
                },
            })
            .collect(),
    };
    manifest
}

#[test]
fn forged_function_role_is_refused_by_fresh_provenance() {
    let d = tmpdir("reuse_forged_role");
    let provider = cc_so(&d, "provider", "int provider(void){return 1;}\n");
    let dependency = cc_so(&d, "dependency", "int dependency(void){return 2;}\n");
    let dependency_offset = first_executable_offset(&dependency);

    let mut discovered = walked_legacy_manifest(&provider);
    discovered.objects.push(ObjectRecord {
        id: 1,
        path: dependency.display().to_string(),
        identity: p11scope_manifest::identity::identify(&dependency),
    });
    discovered.surfaces[0]
        .functions
        .iter_mut()
        .find(|function| function.name == "C_Initialize")
        .unwrap()
        .resolution = Resolution::Resolved {
        object: 1,
        file_offset: dependency_offset,
    };

    let mut forged = discovered.clone();
    forged.surfaces[0]
        .functions
        .iter_mut()
        .find(|function| function.name == "C_EncryptInit")
        .unwrap()
        .resolution = Resolution::Resolved {
        object: 1,
        file_offset: dependency_offset,
    };

    assert!(
        p11scope::verify::check_reuse(&forged).is_ok(),
        "the existing identity/range gate deliberately cannot prove function roles"
    );
    let errors = p11scope::verify::check_provenance(&forged, &discovered).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("C_EncryptInit") && error.contains("provenance")),
        "{errors:?}"
    );
}

#[test]
fn provenance_accepts_an_identity_equal_copy_and_ignores_diagnostic_text() {
    let d = tmpdir("reuse_provenance_copy");
    let original = cc_so(&d, "original", "int provider(void){return 1;}\n");
    let copy = d.join("safe-copy.so");
    std::fs::copy(&original, &copy).unwrap();

    let mut discovered = walked_legacy_manifest(&original);
    discovered.interface_list = Acquisition::Error {
        detail: "unreadable pointer 0x1111".into(),
    };
    discovered.objects[0].identity.note = Some("discovery diagnostic".into());

    let mut candidate = walked_legacy_manifest(&copy);
    candidate.interface_list = Acquisition::Error {
        detail: "unreadable pointer 0x9999".into(),
    };
    candidate.objects[0].identity.note = Some("attach diagnostic".into());

    assert!(p11scope::verify::check_reuse(&candidate).is_ok());
    p11scope::verify::check_provenance(&candidate, &discovered).unwrap();
}

#[test]
fn provenance_rejects_different_bytes_with_a_spoofed_build_id() {
    let d = tmpdir("reuse_provenance_spoofed_build_id");
    let build_id = "1111111111111111111111111111111111111111";
    let discovered_so = cc_so_with_build_id(
        &d,
        "discovered",
        "int provider(void){return 1;}\n",
        build_id,
    );
    let candidate_so =
        cc_so_with_build_id(&d, "candidate", "int provider(void){return 2;}\n", build_id);
    let discovered = walked_legacy_manifest(&discovered_so);
    let candidate = walked_legacy_manifest(&candidate_so);

    assert_eq!(
        candidate.objects[0].identity.value, discovered.objects[0].identity.value,
        "fixture must reproduce a build-id collision"
    );
    let errors = p11scope::verify::check_provenance(&candidate, &discovered).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("module provenance"))
    );
}

#[test]
fn provenance_normalizes_dependency_object_ids() {
    let d = tmpdir("reuse_provenance_object_ids");
    let provider = cc_so(&d, "id-provider", "int provider(void){return 1;}\n");
    let dependency_a = cc_so(&d, "id-dependency-a", "int a(void){return 2;}\n");
    let dependency_b = cc_so(&d, "id-dependency-b", "int b(void){return 3;}\n");
    let mut discovered = walked_legacy_manifest(&provider);
    for (id, path) in [(1, &dependency_a), (2, &dependency_b)] {
        discovered.objects.push(ObjectRecord {
            id,
            path: path.display().to_string(),
            identity: p11scope_manifest::identity::identify(path),
        });
    }
    for (name, object, file_offset) in [
        ("C_Initialize", 1, first_executable_offset(&dependency_a)),
        ("C_Finalize", 2, first_executable_offset(&dependency_b)),
    ] {
        discovered.surfaces[0]
            .functions
            .iter_mut()
            .find(|function| function.name == name)
            .unwrap()
            .resolution = Resolution::Resolved {
            object,
            file_offset,
        };
    }

    let mut candidate = discovered.clone();
    candidate.objects.swap(1, 2);
    candidate.objects[1].id = 1;
    candidate.objects[2].id = 2;
    for function in &mut candidate.surfaces[0].functions {
        if let Resolution::Resolved { object, .. } = &mut function.resolution {
            *object = match *object {
                1 => 2,
                2 => 1,
                other => other,
            };
        }
    }

    p11scope::verify::check_provenance(&candidate, &discovered).unwrap();
}

#[test]
fn matching_identity_is_accepted() {
    let d = tmpdir("reuse_ok");
    let so = cc_so(&d, "same", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    assert!(p11scope::verify::check_reuse(&m).is_ok());
}

#[test]
fn an_existing_writer_prevents_object_authorization() {
    let d = tmpdir("reuse_existing_writer");
    let so = cc_so(&d, "writer", "int f(void){return 1;}\n");
    let manifest = manifest_for(&so);
    let _writer = std::fs::OpenOptions::new().write(true).open(&so).unwrap();

    let errors = p11scope::verify::check_reuse(&manifest).unwrap_err();
    assert!(
        errors.iter().any(|error| error.contains("read lease")),
        "{errors:?}"
    );
}

#[test]
fn changed_object_is_refused_naming_the_file() {
    let d = tmpdir("reuse_bad");
    let so = cc_so(&d, "changed", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    // Rebuild with different content → different build-id, same path.
    let _ = cc_so(
        &d,
        "changed",
        "int f(void){return 2;} int g(void){return 3;}\n",
    );
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("changed.so"), "{err:?}");
    assert!(
        err[0].contains("build") || err[0].contains("identity"),
        "{err:?}"
    );
}

#[test]
fn vanished_object_is_refused() {
    let d = tmpdir("reuse_gone");
    let so = cc_so(&d, "gone", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    std::fs::remove_file(&so).unwrap();
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert_eq!(err.len(), 1);
}

#[test]
fn non_reusable_identity_is_refused_even_if_unchanged() {
    let d = tmpdir("reuse_unreusable");
    let so = cc_so(&d, "unreusable", "int f(void){return 1;}\n");
    let mut m = manifest_for(&so);
    m.objects[0].identity = ObjectIdentity {
        kind: IdentityKind::Unavailable,
        value: None,
        sha256: None,
        reusable: false,
        note: Some("read failed".into()),
    };
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("not reusable"), "{err:?}");
}

#[test]
fn relative_and_duplicate_manifest_objects_are_refused() {
    let d = tmpdir("reuse_structure");
    let so = cc_so(&d, "structure", "int f(void){return 1;}\n");
    let mut m = manifest_for(&so);
    m.module_path = "structure.so".into();
    m.objects[0].path = "structure.so".into();
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert!(
        err.iter().any(|problem| problem.contains("absolute")),
        "{err:?}"
    );

    let mut m = manifest_for(&so);
    m.objects.push(m.objects[0].clone());
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("duplicate object id")),
        "{err:?}"
    );
}

#[test]
fn symlink_is_pinned_and_non_executable_offsets_are_refused() {
    let d = tmpdir("reuse_target_shape");
    let so = cc_so(&d, "target", "int f(void){return 1;}\n");
    let link = d.join("target-link.so");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&so, &link).unwrap();
    let mut symlink_manifest = manifest_for(&so);
    symlink_manifest.module_path = link.display().to_string();
    symlink_manifest.objects[0].path = link.display().to_string();
    let verified = p11scope::verify::check_reuse(&symlink_manifest).unwrap();
    let pinned = verified
        .attach_path(&symlink_manifest.objects[0].path)
        .unwrap();
    let replacement = cc_so(&d, "replacement", "int f(void){return 2;}\n");
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&replacement, &link).unwrap();
    let pinned_metadata = std::fs::metadata(&pinned).unwrap();
    let original_metadata = std::fs::metadata(&so).unwrap();
    let replacement_metadata = std::fs::metadata(&replacement).unwrap();
    assert_eq!(
        (pinned_metadata.dev(), pinned_metadata.ino()),
        (original_metadata.dev(), original_metadata.ino())
    );
    assert_ne!(
        (pinned_metadata.dev(), pinned_metadata.ino()),
        (replacement_metadata.dev(), replacement_metadata.ino())
    );

    let mut offset_manifest = manifest_for(&so);
    offset_manifest.surfaces[0] = SurfaceRecord {
        source: SurfaceSource::LegacyFunctionList,
        acquisition: Acquisition::Ok,
        version: Some(Version { major: 2, minor: 0 }),
        walk: WalkOutcome::Full,
        functions: pkcs11_module::FUNCTION_LIST_FIELDS[..67]
            .iter()
            .map(|field| FunctionRecord {
                name: field.name.into(),
                resolution: Resolution::Resolved {
                    object: 0,
                    file_offset: if field.name == "C_Initialize" {
                        0
                    } else {
                        first_executable_offset(&so)
                    },
                },
            })
            .collect(),
    };
    let err = p11scope::verify::check_reuse(&offset_manifest).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("executable ELF segment")),
        "{err:?}"
    );
}

#[test]
fn reordered_or_unknown_standard_function_names_are_refused() {
    let d = tmpdir("reuse_names");
    let so = cc_so(&d, "names", "int f(void){return 1;}\n");
    let mut m = manifest_for(&so);
    m.surfaces[0] = SurfaceRecord {
        source: SurfaceSource::LegacyFunctionList,
        acquisition: Acquisition::Ok,
        version: Some(Version { major: 2, minor: 0 }),
        walk: WalkOutcome::Full,
        functions: pkcs11_module::FUNCTION_LIST_FIELDS[..67]
            .iter()
            .enumerate()
            .map(|(index, field)| FunctionRecord {
                name: field.name.into(),
                resolution: Resolution::Resolved {
                    object: 0,
                    file_offset: first_executable_offset(&so) + index as u64,
                },
            })
            .collect(),
    };
    m.surfaces[0].functions.swap(0, 1);
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("canonical function order")),
        "{err:?}"
    );

    m.surfaces[0].functions.swap(0, 1);
    m.surfaces[0].functions[0].name = "C_Evil".into();
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("canonical function order")),
        "{err:?}"
    );
}

#[test]
fn every_supported_table_boundary_passes_structural_reuse_validation() {
    let d = tmpdir("reuse_versions");
    let so = cc_so(&d, "versions", "int f(void){return 1;}\n");
    let offset = first_executable_offset(&so);
    let all: Vec<&str> = pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS)
        .map(|field| field.name)
        .collect();
    let mut m = manifest_for(&so);
    m.interface_list = Acquisition::Ok;
    for (index, (major, minor, count, prefix, alternate)) in [
        (2, 40, 68, false, false),
        (3, 0, 92, false, false),
        (3, 1, 92, false, false),
        (3, 2, 104, false, false),
        (3, 9, 104, true, false),
        (3, 2, 104, true, true),
    ]
    .into_iter()
    .enumerate()
    {
        m.surfaces.push(SurfaceRecord {
            source: SurfaceSource::Interface {
                index,
                raw_name_hex: Some(
                    if alternate {
                        "416c7465726e617465"
                    } else {
                        "504b4353203131"
                    }
                    .into(),
                ),
                name_lossy: Some(if alternate { "Alternate" } else { "PKCS 11" }.into()),
                name_error: None,
                flags: 0,
                classification: if alternate {
                    InterfaceClassification::CorroboratedStandardPrefix
                } else {
                    InterfaceClassification::ExactStandard
                },
            },
            acquisition: Acquisition::Ok,
            version: Some(Version { major, minor }),
            walk: if prefix {
                WalkOutcome::KnownPrefix
            } else {
                WalkOutcome::Full
            },
            functions: all[..count]
                .iter()
                .map(|name| FunctionRecord {
                    name: (*name).into(),
                    resolution: Resolution::Resolved {
                        object: 0,
                        file_offset: offset,
                    },
                })
                .collect(),
        });
    }
    m.surfaces[0] = SurfaceRecord {
        source: SurfaceSource::LegacyFunctionList,
        acquisition: Acquisition::Ok,
        version: Some(Version { major: 2, minor: 0 }),
        walk: WalkOutcome::Full,
        functions: all[..67]
            .iter()
            .map(|name| FunctionRecord {
                name: (*name).into(),
                resolution: Resolution::Resolved {
                    object: 0,
                    file_offset: offset,
                },
            })
            .collect(),
    };
    assert!(p11scope::verify::check_reuse(&m).is_ok());

    let mut mislabeled = m;
    let SurfaceSource::Interface { raw_name_hex, .. } = &mut mislabeled.surfaces[1].source else {
        unreachable!()
    };
    *raw_name_hex = Some("416c7465726e617465".into());
    let err = p11scope::verify::check_reuse(&mislabeled).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("exact_standard classification")),
        "{err:?}"
    );
}

#[test]
fn acquisition_evidence_cannot_be_omitted_or_invented() {
    let d = tmpdir("reuse_acquisition_evidence");
    let so = cc_so(&d, "evidence", "int f(void){return 1;}\n");

    let mut missing_legacy = manifest_for(&so);
    missing_legacy.surfaces.clear();
    let err = p11scope::verify::check_reuse(&missing_legacy).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("exactly one legacy")),
        "{err:?}"
    );

    let mut missing_interfaces = manifest_for(&so);
    missing_interfaces.interface_list = Acquisition::Ok;
    let err = p11scope::verify::check_reuse(&missing_interfaces).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("interface indices")),
        "{err:?}"
    );
}

#[test]
fn manifest_input_is_regular_utf8_and_bounded() {
    let d = tmpdir("reuse_manifest_input");
    let directory = d.join("directory");
    std::fs::create_dir_all(&directory).unwrap();
    assert!(
        p11scope::verify::read_manifest(&directory)
            .unwrap_err()
            .contains("regular file")
    );

    let oversized = d.join("oversized.json");
    let file = std::fs::File::create(&oversized).unwrap();
    file.set_len(p11scope::verify::MAX_MANIFEST_BYTES + 1)
        .unwrap();
    assert!(
        p11scope::verify::read_manifest(&oversized)
            .unwrap_err()
            .contains("limit")
    );

    let invalid = d.join("invalid.json");
    std::fs::write(&invalid, [0xff]).unwrap();
    assert!(
        p11scope::verify::read_manifest(&invalid)
            .unwrap_err()
            .contains("UTF-8")
    );
}

#[test]
fn aggregate_object_bytes_are_refused_before_parsing() {
    let d = tmpdir("reuse_aggregate_object_bytes");
    let so = cc_so(&d, "small", "int f(void){return 1;}\n");
    let mut m = manifest_for(&so);
    for id in 1..=2 {
        let path = d.join(format!("large-{id}.so"));
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(p11scope_manifest::identity::MAX_OBJECT_BYTES)
            .unwrap();
        m.objects.push(ObjectRecord {
            id,
            path: path.display().to_string(),
            identity: ObjectIdentity {
                kind: IdentityKind::Sha256,
                value: Some("00".repeat(32)),
                sha256: Some("00".repeat(32)),
                reusable: true,
                note: None,
            },
        });
    }
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert!(
        err.iter().any(|problem| problem.contains("objects total")),
        "{err:?}"
    );
}
