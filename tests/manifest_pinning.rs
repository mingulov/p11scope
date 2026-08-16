use p11scope::manifest_input::{MAX_MANIFEST_BYTES, read_manifest};
use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
use p11scope_manifest::manifest::*;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

static CC_LOCK: Mutex<()> = Mutex::new(());

fn tmpdir(name: &str) -> PathBuf {
    let d =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Build a .so with a caller-chosen build-id so two builds differ.
fn cc_so(dir: &Path, name: &str, body: &str) -> PathBuf {
    let _guard = CC_LOCK.lock().unwrap();
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

fn manifest_for(path: &Path) -> Manifest {
    let provenance = provenance_for(path);
    let id = provenance.identity.clone();
    Manifest {
        schema: SCHEMA.to_string(),
        module_path: path.display().to_string(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.display().to_string(),
            identity: id,
        }],
        provenance_objects: vec![provenance],
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

fn provenance_for(path: &Path) -> ProvenanceObject {
    let file = p11scope_manifest::identity::open_object(path).unwrap();
    let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
    ProvenanceObject {
        path: path.display().to_string(),
        device_major: key.device_major,
        device_minor: key.device_minor,
        inode: key.inode,
        identity: p11scope_manifest::identity::inspect_file(&file)
            .unwrap()
            .identity,
    }
}

/// The `(device, inode)` a mapping of this file would show — the key every pin is
/// stored under.
fn manifest_key(path: &Path) -> p11scope_manifest::maps::ObjectKey {
    let file = p11scope_manifest::identity::open_object(path).unwrap();
    let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
    p11scope_manifest::maps::ObjectKey {
        device: p11scope_manifest::maps::Device {
            major: key.device_major,
            minor: key.device_minor,
        },
        inode: key.inode,
    }
}

fn first_executable_offset(path: &Path) -> u64 {
    let file = p11scope_manifest::identity::open_object(path).unwrap();
    p11scope_manifest::identity::inspect_file(&file)
        .unwrap()
        .executable_ranges[0]
        .0
}

#[test]
fn manifest_input_is_regular_utf8_and_bounded() {
    let d = tmpdir("manifest_pinning_input");
    let directory = d.join("directory");
    std::fs::create_dir_all(&directory).unwrap();
    assert!(
        read_manifest(&directory)
            .unwrap_err()
            .contains("regular file")
    );

    let oversized = d.join("oversized.json");
    let file = std::fs::File::create(&oversized).unwrap();
    file.set_len(MAX_MANIFEST_BYTES + 1).unwrap();
    assert!(read_manifest(&oversized).unwrap_err().contains("limit"));

    let invalid = d.join("invalid.json");
    std::fs::write(&invalid, [0xff]).unwrap();
    assert!(read_manifest(&invalid).unwrap_err().contains("UTF-8"));
}

#[test]
fn matching_identity_is_accepted() {
    let d = tmpdir("manifest_pinning_ok");
    let so = cc_so(&d, "same", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    assert!(p11scope::discovery::identity::pin_manifest_objects(&m).is_ok());
}

/// A capture pins objects from the scan *and* from every `--manifest`, but
/// `Session::start` takes one set: both must survive the merge, each still
/// reachable the way its own slots are attached (by key for a scanned object,
/// by the recorded path for a manifest one).
#[test]
fn scan_and_manifest_pins_merge_into_one_set() {
    use p11scope::discovery::scan::ScanLimits;

    let d = tmpdir("manifest_pinning_absorb");
    let so = cc_so(&d, "absorbed", "int f(void){return 1;}\n");
    let manifest_pins =
        p11scope::discovery::identity::pin_manifest_objects(&manifest_for(&so)).unwrap();

    let (exe, modules) = scan_self();
    let (mut pinned, _) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &modules,
        ScanLimits::default(),
    )
    .unwrap();
    pinned.absorb(manifest_pins);

    assert!(
        pinned.pinned().any(|s| s.path == exe.display().to_string()),
        "the scanned object survives the merge"
    );
    let key = manifest_key(&so);
    let attach = pinned
        .attach_path_for(key)
        .expect("the manifest's object still resolves after the merge");
    assert!(attach.starts_with("/proc/self/fd/"), "{attach:?}");
    assert!(pinned.check_unchanged().unwrap());
}

#[test]
fn changed_object_is_refused_naming_the_file() {
    let d = tmpdir("manifest_pinning_bad");
    let so = cc_so(&d, "changed", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    // Rebuild with different content → different build-id, same path.
    let _ = cc_so(
        &d,
        "changed",
        "int f(void){return 2;} int g(void){return 3;}\n",
    );
    let err = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("changed.so"), "{err:?}");
    assert!(
        err[0].contains("build") || err[0].contains("identity"),
        "{err:?}"
    );
}

#[test]
fn vanished_object_is_refused() {
    let d = tmpdir("manifest_pinning_gone");
    let so = cc_so(&d, "gone", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    std::fs::remove_file(&so).unwrap();
    let err = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap_err();
    assert_eq!(err.len(), 1);
}

#[test]
fn non_reusable_identity_is_refused_even_if_unchanged() {
    let d = tmpdir("manifest_pinning_unreusable");
    let so = cc_so(&d, "unreusable", "int f(void){return 1;}\n");
    let mut m = manifest_for(&so);
    m.objects[0].identity = ObjectIdentity {
        kind: IdentityKind::Unavailable,
        value: None,
        sha256: None,
        reusable: false,
        note: Some("read failed".into()),
    };
    let err = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("not reusable"), "{err:?}");
}

#[test]
fn relative_and_duplicate_manifest_objects_are_refused() {
    let d = tmpdir("manifest_pinning_structure");
    let so = cc_so(&d, "structure", "int f(void){return 1;}\n");
    let mut m = manifest_for(&so);
    m.module_path = "structure.so".into();
    m.objects[0].path = "structure.so".into();
    let err = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap_err();
    assert!(
        err.iter().any(|problem| problem.contains("absolute")),
        "{err:?}"
    );

    let mut m = manifest_for(&so);
    m.objects.push(m.objects[0].clone());
    let err = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("duplicate object id")),
        "{err:?}"
    );
}

#[test]
fn symlink_is_pinned_and_non_executable_offsets_are_refused() {
    let d = tmpdir("manifest_pinning_target_shape");
    let so = cc_so(&d, "target", "int f(void){return 1;}\n");
    let link = d.join("target-link.so");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&so, &link).unwrap();
    let mut symlink_manifest = manifest_for(&so);
    symlink_manifest.module_path = link.display().to_string();
    symlink_manifest.objects[0].path = link.display().to_string();
    let pinned = p11scope::discovery::identity::pin_manifest_objects(&symlink_manifest).unwrap();
    let attach = pinned
        .attach_path_for(manifest_key(&link))
        .expect("a symlinked object is pinned by the identity it resolves to");
    let replacement = cc_so(&d, "replacement", "int f(void){return 2;}\n");
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&replacement, &link).unwrap();
    let pinned_metadata = std::fs::metadata(&attach).unwrap();
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
    let err = p11scope::discovery::identity::pin_manifest_objects(&offset_manifest).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("executable ELF segment")),
        "{err:?}"
    );
}

#[test]
fn reordered_or_unknown_standard_function_names_are_refused() {
    let d = tmpdir("manifest_pinning_names");
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
    let err = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("canonical function order")),
        "{err:?}"
    );

    m.surfaces[0].functions.swap(0, 1);
    m.surfaces[0].functions[0].name = "C_Evil".into();
    let err = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("canonical function order")),
        "{err:?}"
    );
}

#[test]
fn every_supported_table_boundary_passes_structural_reuse_validation() {
    let d = tmpdir("manifest_pinning_versions");
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
    assert!(p11scope::discovery::identity::pin_manifest_objects(&m).is_ok());

    let mut mislabeled = m;
    let SurfaceSource::Interface { raw_name_hex, .. } = &mut mislabeled.surfaces[1].source else {
        unreachable!()
    };
    *raw_name_hex = Some("416c7465726e617465".into());
    let err = p11scope::discovery::identity::pin_manifest_objects(&mislabeled).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("exact_standard classification")),
        "{err:?}"
    );
}

#[test]
fn acquisition_evidence_cannot_be_omitted_or_invented() {
    let d = tmpdir("manifest_pinning_acquisition_evidence");
    let so = cc_so(&d, "evidence", "int f(void){return 1;}\n");

    let mut missing_legacy = manifest_for(&so);
    missing_legacy.surfaces.clear();
    let err = p11scope::discovery::identity::pin_manifest_objects(&missing_legacy).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("exactly one legacy")),
        "{err:?}"
    );

    let mut missing_interfaces = manifest_for(&so);
    missing_interfaces.interface_list = Acquisition::Ok;
    let err = p11scope::discovery::identity::pin_manifest_objects(&missing_interfaces).unwrap_err();
    assert!(
        err.iter()
            .any(|problem| problem.contains("interface indices")),
        "{err:?}"
    );
}

#[test]
fn manifest_v4_requires_a_whole_file_provenance_closure() {
    let d = tmpdir("manifest_pinning_missing_provenance_closure");
    let so = cc_so(&d, "missing-closure", "int f(void){return 1;}\n");
    let mut manifest = manifest_for(&so);
    manifest.provenance_objects.clear();

    let errors = p11scope::discovery::identity::pin_manifest_objects(&manifest).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("provenance objects")),
        "{errors:?}"
    );
}

#[test]
fn aggregate_object_bytes_are_refused_before_parsing() {
    let d = tmpdir("manifest_pinning_aggregate_object_bytes");
    let so = cc_so(&d, "small", "int f(void){return 1;}\n");
    let _guard = CC_LOCK.lock().unwrap();
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
        let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        m.provenance_objects.push(ProvenanceObject {
            path: path.display().to_string(),
            device_major: key.device_major,
            device_minor: key.device_minor,
            inode: key.inode,
            identity: ObjectIdentity {
                kind: IdentityKind::Sha256,
                value: Some("00".repeat(32)),
                sha256: Some("00".repeat(32)),
                reusable: true,
                note: None,
            },
        });
    }
    let err = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap_err();
    assert!(
        err.iter().any(|problem| problem.contains("objects total")),
        "{err:?}"
    );
}

#[test]
fn same_size_overwrite_changes_ctime_and_is_detected() {
    let d = tmpdir("manifest_pinning_same_size_overwrite");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    let pinned = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap();
    assert!(pinned.check_unchanged().unwrap());
    std::thread::sleep(std::time::Duration::from_millis(20)); // ctime granularity margin
    // Overwrite the first byte with itself: size and content unchanged, ctime bumped.
    let first = std::fs::read(&so).unwrap()[0];
    let mut f = std::fs::OpenOptions::new().write(true).open(&so).unwrap();
    std::io::Write::write_all(&mut f, &[first]).unwrap();
    drop(f);
    assert!(
        !pinned.check_unchanged().unwrap(),
        "ctime change must be detected"
    );
}

#[test]
fn replacing_the_file_by_rename_keeps_the_pinned_inode_but_reports_a_change() {
    let d = tmpdir("manifest_pinning_rename_over");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    let pinned = p11scope::discovery::identity::pin_manifest_objects(&m).unwrap();
    let old_bytes = std::fs::read(&so).unwrap();
    let attach = pinned.attach_path_for(manifest_key(&so)).unwrap();
    assert!(attach.starts_with("/proc/self/fd/"));
    std::thread::sleep(std::time::Duration::from_millis(20)); // ctime granularity margin
    let other = cc_so(&d, "other", "int g(void){return 2;}\n");
    std::fs::rename(&other, &so).unwrap(); // new inode at the old path
    // The fd still pins the old inode (aya would attach to the old bytes) …
    assert_eq!(
        std::fs::read(&attach).unwrap(),
        old_bytes,
        "the old inode is what we hold"
    );
    // … but unlinking the old inode bumped its ctime, so the change is reported
    // conservatively (a rename-over is indistinguishable from an in-place write
    // without relying on the settable mtime; the capture continues, PARTIAL).
    assert!(
        !pinned.check_unchanged().unwrap(),
        "rename-over is reported as a change"
    );
}

#[test]
fn a_pid_pin_detects_process_exit() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pin = p11scope::process::PidPin::open(child.id()).expect("pin a live child");
    assert!(pin.still_the_same());
    child.kill().unwrap();
    child.wait().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while pin.still_the_same() {
        assert!(
            std::time::Instant::now() < deadline,
            "exit must become visible"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Our own executable is a file-backed mapping with a stable identity; scan our
/// process with it as the hint, so the modules are the scan's real view of us.
fn scan_self() -> (PathBuf, Vec<p11scope::discovery::scan::ScannedModule>) {
    use p11scope::discovery::hooks::HookRegistry;
    use p11scope::discovery::scan::{ScanLimits, ScanOutcome, ScanRequest, scan_pid};

    let hooks = HookRegistry::builtin();
    let exe = std::env::current_exe().unwrap();
    let outcome = scan_pid(&ScanRequest {
        pid: std::process::id(),
        hints: &[exe.clone()],
        hooks: &hooks,
        limits: ScanLimits::default(),
    })
    .unwrap();
    let ScanOutcome::Scanned { modules, .. } = outcome else {
        panic!("/proc/self/mem is always readable")
    };
    (exe, modules)
}

#[test]
fn scanned_objects_are_pinned_hashed_and_attachable() {
    use p11scope::discovery::scan::ScanLimits;

    let (exe, modules) = scan_self();
    let (pinned, skipped) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &modules,
        ScanLimits::default(),
    )
    .unwrap();
    assert!(
        skipped.is_empty(),
        "nothing about our own process should be unpinnable: {skipped:?}"
    );
    // The hint is our own executable, so the scan always names at least that object.
    // (Measured: it is the only one — the test binary maps no PKCS#11 table, so no
    // table entry names a second object. Its identity resolves via "mountinfo".)
    assert!(
        pinned.pinned().any(|s| s.path == exe.display().to_string()),
        "the hinted executable must be pinned"
    );
    for summary in pinned.pinned() {
        assert_eq!(summary.sha256.len(), 64, "sha256 must be a full digest");
        let attach = pinned.attach_path_for(summary.key).unwrap();
        assert!(attach.starts_with("/proc/self/fd/"), "{attach:?}");
        assert!(
            std::fs::metadata(&attach).is_ok(),
            "the pinned fd must still be open"
        );
    }
    assert!(pinned.check_unchanged().unwrap());
}

#[test]
fn a_retargeted_path_is_skipped_as_an_identity_mismatch() {
    use p11scope::discovery::scan::{ScanLimits, ScannedModule};
    use p11scope_manifest::maps::{Device, ObjectKey};

    // The path the scan named still resolves — to a different inode than the mapping
    // reported. That is what a retargeted path looks like, and it must never be pinned.
    let exe = std::env::current_exe().unwrap();
    let module = ScannedModule {
        key: ObjectKey {
            device: Device { major: 0, minor: 0 },
            inode: std::fs::metadata(&exe).unwrap().ino() + 1,
        },
        path: exe.display().to_string(),
        exports: vec![],
        tables: vec![],
        interfaces: vec![],
    };
    let (pinned, skipped) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &[module],
        ScanLimits::default(),
    )
    .unwrap();
    assert_eq!(pinned.pinned().count(), 0, "a mismatch must not be pinned");
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert!(
        skipped[0].reason.starts_with("identity_mismatch"),
        "{:?}",
        skipped[0]
    );
    assert_eq!(skipped[0].subject, exe.display().to_string());

    // Right inode, wrong device: only the "mountinfo" comparison can catch this, so
    // this is what a silent downgrade of the check to inode-only would break. On a
    // host where mountinfo cannot resolve, the weaker check is legitimate — but it
    // then has to say so rather than pass itself off as the strong one.
    let module = ScannedModule {
        key: ObjectKey {
            device: Device {
                major: 0xffff,
                minor: 0xffff,
            },
            inode: std::fs::metadata(&exe).unwrap().ino(),
        },
        path: exe.display().to_string(),
        exports: vec![],
        tables: vec![],
        interfaces: vec![],
    };
    let (pinned, skipped) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &[module],
        ScanLimits::default(),
    )
    .unwrap();
    match pinned.pinned().next() {
        None => assert!(
            skipped[0].reason.starts_with("identity_mismatch"),
            "{:?}",
            skipped[0]
        ),
        Some(summary) => assert_eq!(
            summary.identity_source, "stat",
            "a device mismatch may only be accepted when mountinfo was unavailable, \
             and the report must record why: {:?}",
            summary.note
        ),
    }
}

#[test]
fn an_object_over_the_byte_budget_is_skipped_naming_the_cap() {
    use p11scope::discovery::scan::ScanLimits;

    let (exe, modules) = scan_self();
    // Sized from live data: one byte under the object the scan actually reported.
    let len = std::fs::metadata(&exe).unwrap().len();
    for limits in [
        ScanLimits {
            per_object_bytes: len - 1,
            total_bytes: u64::MAX,
        },
        ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: len - 1,
        },
    ] {
        let (pinned, skipped) = p11scope::discovery::identity::pin_scanned_objects(
            std::process::id(),
            &modules,
            limits,
        )
        .unwrap();
        assert_eq!(
            pinned.pinned().count(),
            0,
            "an object over budget is never hashed"
        );
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        let reason = &skipped[0].reason;
        assert!(
            reason.starts_with("too_large")
                && reason.contains(&format!("{len} bytes"))
                && reason.contains(&(len - 1).to_string()),
            "the reason must name the object's size and the cap it broke: {reason}"
        );
    }
}
