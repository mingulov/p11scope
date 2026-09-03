use p11scope::discovery::scan::{CaptureWorkBudget, ScanLimits};
use p11scope::manifest_input::{MAX_MANIFEST_BYTES, read_manifest};
use p11scope::process::{MountNamespaceId, ProcessView, ProcessViewId};
use p11scope_discover::discover::discover as discover_provider;
use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
use p11scope_manifest::manifest::*;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

static CC_LOCK: Mutex<()> = Mutex::new(());
static DISCOVER_FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);

fn current_mount_namespace() -> MountNamespaceId {
    let metadata = std::fs::metadata("/proc/self/ns/mnt").unwrap();
    MountNamespaceId {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn tmpdir(name: &str) -> PathBuf {
    let d =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn self_binary_budget() -> CaptureWorkBudget {
    CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    })
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

fn discover_fixture(mode: &str) -> PathBuf {
    let _guard = CC_LOCK.lock().unwrap();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "manifest-discover-{mode}-{}-{}",
        std::process::id(),
        DISCOVER_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/discover/tests/fixture");
    let helper = dir.join("helper.so");
    let provider = dir.join("provider.so");
    let mut helper_command = Command::new("gcc");
    helper_command
        .args(["-shared", "-fPIC", "-Wl,-soname,helper.so", "-o"])
        .arg(&helper)
        .arg(fixture.join("helper.c"));
    if mode == "outside" {
        let outside = dir.join("outside.c");
        std::fs::write(
            &outside,
            "typedef unsigned long CK_RV; CK_RV C_GetInterface(void*a,void*b,void**c,unsigned long d){(void)a;(void)b;(void)c;(void)d;__builtin_trap();}\n",
        )
        .unwrap();
        helper_command.arg(outside);
    }
    assert!(helper_command.status().unwrap().success());
    let mut provider_command = Command::new("gcc");
    provider_command
        .args(["-shared", "-fPIC", "-o"])
        .arg(&provider)
        .arg(fixture.join("provider.c"))
        .arg(&helper);
    match mode {
        "conflict" => {
            provider_command.arg("-DCONFLICT_FIXTURE=1");
        }
        "post-failure" => {
            provider_command.arg("-DPOST_FAILURE_FIXTURE=1");
        }
        "absent" | "outside" => {
            provider_command.arg("-DNO_GET_INTERFACE=1");
        }
        "unknown-flags" => {
            provider_command.arg("-DUNKNOWN_FLAGS_FIXTURE=1");
        }
        "short-table" => {
            provider_command.arg("-DSHORT_TABLE_FIXTURE=1");
        }
        "normal" => {}
        other => panic!("unknown fixture mode {other}"),
    }
    assert!(
        provider_command
            .arg(format!("-Wl,-rpath,{}", dir.display()))
            .status()
            .unwrap()
            .success()
    );
    provider
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
        selection_evidence: SelectionEvidence::default(),
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

fn queried_selection_matrix() -> SelectionEvidence {
    let queries = (0..5)
        .flat_map(|selector| {
            (0..2).map(move |flags| SelectionQuery {
                selector,
                request: SelectionRequest {
                    name: match selector {
                        0 => SelectionNameClass::Null,
                        _ => SelectionNameClass::ExactStandard,
                    },
                    version: match selector {
                        0 | 1 => SelectionVersionClass::Null,
                        2 => SelectionVersionClass::V3_0,
                        3 => SelectionVersionClass::V3_1,
                        _ => SelectionVersionClass::V3_2,
                    },
                    flags,
                },
                rv: 7,
                result: None,
                inventory_matches: vec![],
                selection_table: None,
                authority: SelectionAuthority::None,
                helper_failure: None,
            })
        })
        .collect();
    SelectionEvidence {
        acquisition: SelectionAcquisition::Queried,
        queries,
        tables: vec![],
        selection_truncated: false,
    }
}

#[test]
fn manifest_v5_selection_matrix_is_exact() {
    let path = Path::new("/bin/true");
    let mut manifest = manifest_for(path);
    manifest.schema = "p11scope-manifest/5".into();
    manifest.selection_evidence = queried_selection_matrix();
    assert!(
        p11scope::manifest_input::validate_structure(&manifest).is_empty(),
        "a v5 manifest with the fixed selection matrix should validate"
    );
}

#[test]
fn emitted_selection_fixtures_validate_as_v5_manifests() {
    for mode in [
        "normal",
        "conflict",
        "post-failure",
        "absent",
        "unknown-flags",
        "outside",
        "short-table",
    ] {
        let provider = discover_fixture(mode);
        let manifest = discover_provider(&provider).unwrap();
        let problems = p11scope::manifest_input::validate_structure(&manifest);
        assert!(problems.is_empty(), "{mode} fixture: {problems:?}");
    }
}

#[test]
fn selection_agreement_requires_readable_fields() {
    let path = Path::new("/bin/true");
    let mut manifest = manifest_for(path);
    manifest.schema = "p11scope-manifest/5".into();
    manifest.selection_evidence = queried_selection_matrix();
    manifest.selection_evidence.queries[0].rv = 0;
    manifest.selection_evidence.queries[0].result = Some(SelectionResult {
        name: SelectionNameClass::Unreadable,
        version: SelectionVersionClass::V3_0,
        flags: 0,
    });
    manifest.selection_evidence.queries[0].inventory_matches = vec![SelectionInventoryMatch {
        surface: 0,
        name_agrees: true,
        version_agrees: false,
    }];
    assert!(
        p11scope::manifest_input::validate_structure(&manifest)
            .iter()
            .any(|problem| problem.contains("agreement")),
        "v5 agreement must be false for an unreadable result field"
    );
}

#[test]
fn selection_validation_rejects_review_mutations() {
    let path = Path::new("/bin/true");

    let mut unknown = serde_json::to_value(manifest_for(path)).unwrap();
    unknown["selection_evidence"]["unknown"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<Manifest>(unknown).is_err());

    let mut bounds = manifest_for(path);
    bounds.selection_evidence = queried_selection_matrix();
    bounds.selection_evidence.queries[0].inventory_matches = (0..17)
        .map(|surface| SelectionInventoryMatch {
            surface,
            name_agrees: false,
            version_agrees: false,
        })
        .collect();
    assert!(
        p11scope::manifest_input::validate_structure(&bounds)
            .iter()
            .any(|problem| problem.contains("more than 16"))
    );

    let mut null_fields = manifest_for(path);
    null_fields.selection_evidence = queried_selection_matrix();
    null_fields.selection_evidence.queries[0].rv = 0;
    null_fields.selection_evidence.queries[0].authority = SelectionAuthority::Inventory;
    null_fields.selection_evidence.queries[0].helper_failure = Some(SelectionFailure::NullOutput);
    assert!(
        p11scope::manifest_input::validate_structure(&null_fields)
            .iter()
            .any(|problem| problem.contains("null result cross-fields"))
    );

    let mut changed_result = manifest_for(path);
    changed_result.selection_evidence = queried_selection_matrix();
    changed_result.selection_evidence.queries[0].rv = 0;
    changed_result.selection_evidence.queries[0].helper_failure =
        Some(SelectionFailure::ProviderChanged);
    assert!(
        p11scope::manifest_input::validate_structure(&changed_result).is_empty(),
        "provider-change may explain a safely unreadable result"
    );

    let mut unsorted = manifest_for(path);
    unsorted.selection_evidence = queried_selection_matrix();
    unsorted.selection_evidence.queries[0].inventory_matches = vec![
        SelectionInventoryMatch {
            surface: 1,
            name_agrees: false,
            version_agrees: false,
        },
        SelectionInventoryMatch {
            surface: 0,
            name_agrees: false,
            version_agrees: false,
        },
    ];
    assert!(
        p11scope::manifest_input::validate_structure(&unsorted)
            .iter()
            .any(|problem| problem.contains("unsorted"))
    );

    let malformed_table = SelectionTable {
        id: 0,
        version: Version {
            major: 2,
            minor: 40,
        },
        walk: WalkOutcome::Refused,
        functions: vec![FunctionRecord {
            name: "C_Initialize".into(),
            resolution: Resolution::Resolved {
                object: 1,
                file_offset: 0,
            },
        }],
        semantic_authorized: true,
    };
    let mut table_fields = manifest_for(path);
    table_fields.selection_evidence = queried_selection_matrix();
    table_fields.selection_evidence.tables = vec![malformed_table];
    let query = &mut table_fields.selection_evidence.queries[4];
    query.rv = 0;
    query.result = Some(SelectionResult {
        name: SelectionNameClass::ExactStandard,
        version: SelectionVersionClass::V3_0,
        flags: 0,
    });
    query.selection_table = Some(0);
    query.authority = SelectionAuthority::SelectionCountOnly;
    let problems = p11scope::manifest_input::validate_structure(&table_fields);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("unsupported version"))
    );
    assert!(problems.iter().any(|problem| problem.contains("full walk")));
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("dependency object"))
    );
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("semantic decoding"))
    );
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("table version disagrees"))
    );

    let mut orphan = manifest_for(path);
    orphan.selection_evidence = queried_selection_matrix();
    orphan.selection_evidence.tables = vec![SelectionTable {
        id: 0,
        version: Version { major: 3, minor: 0 },
        walk: WalkOutcome::Full,
        functions: vec![],
        semantic_authorized: false,
    }];
    assert!(
        p11scope::manifest_input::validate_structure(&orphan)
            .iter()
            .any(|problem| problem.contains("orphaned"))
    );

    let mut unexplained = manifest_for(path);
    unexplained.selection_evidence = queried_selection_matrix();
    unexplained.selection_evidence.selection_truncated = true;
    unexplained.selection_evidence.queries[4].rv = 0;
    unexplained.selection_evidence.queries[4].result = Some(SelectionResult {
        name: SelectionNameClass::ExactStandard,
        version: SelectionVersionClass::V3_0,
        flags: 0,
    });
    assert!(
        p11scope::manifest_input::validate_structure(&unexplained)
            .iter()
            .any(|problem| problem.contains("unexplained selection truncation"))
    );
}

#[test]
fn helper_failure_cross_fields_are_exact() {
    let result = |name, version| {
        Some(SelectionResult {
            name,
            version,
            flags: 0,
        })
    };
    let check = |failure, query_result, authority, selection_table, diagnostic: Option<&str>| {
        let mut manifest = manifest_for(Path::new("/bin/true"));
        manifest.schema = "p11scope-manifest/5".into();
        manifest.selection_evidence = queried_selection_matrix();
        if let Some(table_id) = selection_table {
            manifest.selection_evidence.tables = vec![SelectionTable {
                id: table_id,
                version: Version { major: 3, minor: 0 },
                walk: WalkOutcome::Full,
                functions: pkcs11_module::FUNCTION_LIST_FIELDS
                    .iter()
                    .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS.iter())
                    .map(|field| FunctionRecord {
                        name: field.name.into(),
                        resolution: Resolution::NullPointer,
                    })
                    .collect(),
                semantic_authorized: false,
            }];
            let reference = &mut manifest.selection_evidence.queries[4];
            reference.rv = 0;
            reference.result = result(
                SelectionNameClass::ExactStandard,
                SelectionVersionClass::V3_0,
            );
            reference.selection_table = Some(table_id);
            reference.authority = SelectionAuthority::SelectionCountOnly;
        }
        let query = &mut manifest.selection_evidence.queries[0];
        query.rv = 0;
        query.result = query_result;
        query.authority = authority;
        query.selection_table = selection_table;
        query.helper_failure = Some(failure);
        let problems = p11scope::manifest_input::validate_structure(&manifest);
        assert_eq!(problems.is_empty(), diagnostic.is_none(), "{problems:?}");
        if let Some(diagnostic) = diagnostic {
            assert!(
                problems.iter().any(|problem| problem.contains(diagnostic)),
                "{problems:?}"
            );
        }
    };
    let none = SelectionAuthority::None;
    let null = result(SelectionNameClass::Null, SelectionVersionClass::Null);

    for failure in [
        SelectionFailure::NullOutput,
        SelectionFailure::UnreadableInterface,
    ] {
        check(failure, None, none, None, None);
        check(
            failure,
            null,
            none,
            None,
            Some("invalid helper failure for a result"),
        );
    }
    check(SelectionFailure::ProviderChanged, None, none, None, None);
    for failure in [
        SelectionFailure::UnreadableName,
        SelectionFailure::UnreadableVersion,
        SelectionFailure::UnreadableTable,
        SelectionFailure::OutsideProvider,
        SelectionFailure::UnresolvedFunction,
    ] {
        check(
            failure,
            None,
            none,
            None,
            Some("successful selection query 0 has no result"),
        );
    }
    for failure in [
        SelectionFailure::NullOutput,
        SelectionFailure::UnreadableInterface,
    ] {
        check(
            failure,
            None,
            none,
            Some(0),
            Some("successful selection query 0 has null result cross-fields"),
        );
    }
    for name in [
        SelectionNameClass::Null,
        SelectionNameClass::ExactStandard,
        SelectionNameClass::Other,
        SelectionNameClass::Unreadable,
    ] {
        check(
            SelectionFailure::UnreadableName,
            result(name, SelectionVersionClass::Null),
            none,
            None,
            (!matches!(
                name,
                SelectionNameClass::Null | SelectionNameClass::Unreadable
            ))
            .then_some("unreadable-name failure disagrees with result"),
        );
    }
    for version in [
        SelectionVersionClass::Null,
        SelectionVersionClass::Unreadable,
        SelectionVersionClass::V2_40,
        SelectionVersionClass::V3_0,
        SelectionVersionClass::V3_1,
        SelectionVersionClass::V3_2,
        SelectionVersionClass::Other,
    ] {
        check(
            SelectionFailure::UnreadableVersion,
            result(SelectionNameClass::Null, version),
            none,
            None,
            (version != SelectionVersionClass::Unreadable)
                .then_some("unreadable-version failure disagrees with result"),
        );
        check(
            SelectionFailure::UnreadableTable,
            result(SelectionNameClass::Null, version),
            none,
            None,
            (!matches!(
                version,
                SelectionVersionClass::Null
                    | SelectionVersionClass::V3_0
                    | SelectionVersionClass::V3_1
                    | SelectionVersionClass::V3_2
            ))
            .then_some("unreadable-table failure disagrees with result"),
        );
    }
    for failure in [
        SelectionFailure::OutsideProvider,
        SelectionFailure::UnresolvedFunction,
        SelectionFailure::ProviderChanged,
    ] {
        check(failure, null, none, None, None);
    }
    for failure in [
        SelectionFailure::UnreadableTable,
        SelectionFailure::OutsideProvider,
        SelectionFailure::UnresolvedFunction,
        SelectionFailure::ProviderChanged,
    ] {
        check(
            failure,
            null,
            none,
            Some(0),
            Some("helper failure has a selection table"),
        );
    }
    for (failure, valid_result) in [
        (SelectionFailure::NullOutput, None),
        (SelectionFailure::UnreadableInterface, None),
        (SelectionFailure::UnreadableName, null),
        (
            SelectionFailure::UnreadableVersion,
            result(SelectionNameClass::Null, SelectionVersionClass::Unreadable),
        ),
        (SelectionFailure::UnreadableTable, null),
        (SelectionFailure::OutsideProvider, null),
        (SelectionFailure::UnresolvedFunction, null),
        (SelectionFailure::ProviderChanged, null),
    ] {
        check(
            failure,
            valid_result,
            SelectionAuthority::Inventory,
            None,
            Some(if valid_result.is_none() {
                "null result cross-fields"
            } else {
                "with helper failure has authority"
            }),
        );
    }
}

#[test]
fn manifest_v4_is_rejected_precisely() {
    let mut manifest = manifest_for(Path::new("/bin/true"));
    manifest.schema = "p11scope-manifest/4".into();
    let problems = p11scope::manifest_input::validate_structure(&manifest);
    assert_eq!(problems.len(), 1);
    assert!(problems[0].contains("p11scope-manifest/5"));
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

fn first_non_executable_offset(path: &Path) -> u64 {
    let file = p11scope_manifest::identity::open_object(path).unwrap();
    let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
    (0..file.metadata().unwrap().len())
        .find(|offset| !inspected.contains_executable_offset(*offset))
        .expect("fixture has a non-executable file byte")
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
/// reachable by its capture-local pinned ID.
#[test]
fn scan_and_manifest_pins_merge_into_one_set() {
    let d = tmpdir("manifest_pinning_absorb");
    let so = cc_so(&d, "absorbed", "int f(void){return 1;}\n");
    let manifest_pins =
        p11scope::discovery::identity::pin_manifest_objects(&manifest_for(&so)).unwrap();

    let (exe, modules) = scan_self();
    let (mut pinned, _) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &modules,
        &mut self_binary_budget(),
    )
    .unwrap();
    pinned.absorb(manifest_pins);

    assert!(
        pinned.pinned().any(|s| s.path == exe.display().to_string()),
        "the scanned object survives the merge"
    );
    let key = manifest_key(&so);
    let id = pinned.pinned().find(|pin| pin.key == key).unwrap().id;
    let attach = pinned
        .attach_path_for(id)
        .expect("the manifest's object still resolves after the merge");
    assert!(attach.starts_with("/proc/self/fd/"), "{attach:?}");
    assert!(pinned.check_unchanged().unwrap());
}

/// Mutation caught: namespace/provider coalescing must never make one process
/// generation own another generation's private table target or retained fd.
#[test]
fn retiring_one_shared_namespace_view_keeps_only_the_stable_views_claims() {
    use p11scope::discovery::identity::{pin_scanned_view_objects, reconcile_scanned_modules};
    use p11scope::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
    use p11scope::process::ProcessView;

    let d = tmpdir("manifest_pinning_view_retirement");
    let provider = cc_so(&d, "provider", "int provider(void){return 1;}\n");
    let target_a = cc_so(&d, "target_a", "int target_a(void){return 2;}\n");
    let target_b = cc_so(&d, "target_b", "int target_b(void){return 3;}\n");
    let namespace = current_mount_namespace();
    let module = |view, name, target: &Path| ScannedModule {
        view,
        mount_namespace: namespace,
        key: manifest_key(&provider),
        path: provider.display().to_string(),
        exports: vec!["C_GetFunctionList".into()],
        tables: vec![ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![ScannedEntry {
                name,
                object: manifest_key(target),
                object_path: target.display().to_string(),
                file_offset: first_executable_offset(target),
            }],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x1000,
            file_offset: Some(0),
        }],
        interfaces: vec![],
    };
    let a = module(ProcessViewId(10), "C_Sign", &target_a);
    let b = module(ProcessViewId(11), "C_Verify", &target_b);
    let mut pinned = p11scope::discovery::identity::PinnedObjects::empty();
    for scanned in [&a, &b] {
        let view = ProcessView::open(scanned.view, std::process::id()).unwrap();
        let (local, skipped) = pin_scanned_view_objects(
            &view,
            std::slice::from_ref(scanned),
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(pinned.absorb(local).is_empty());
    }
    let modules = vec![a, b];
    let (mut reconciled, _, skipped) = reconcile_scanned_modules(&modules, &mut pinned);
    assert!(skipped.is_empty(), "{skipped:?}");
    let stale_target = pinned.view_claims(ProcessViewId(10)).unwrap().targets[0].0;
    let stable_target = pinned.view_claims(ProcessViewId(11)).unwrap().targets[0].0;
    assert_ne!(stale_target, stable_target);

    let removed = pinned
        .remove_view(ProcessViewId(10))
        .expect("the stale view owns precise claims");
    reconciled.retain(|module| module.scanned.view != ProcessViewId(10));
    let plan = p11scope::plan::build_from_reconciled_modules(&reconciled);

    assert_eq!(
        removed.targets,
        vec![(stale_target, first_executable_offset(&target_a))]
    );
    assert!(pinned.view_claims(ProcessViewId(10)).is_none());
    assert!(pinned.attach_path_for(stale_target).is_err());
    assert!(pinned.attach_path_for(stable_target).is_ok());
    assert_eq!(plan.slots.len(), 1, "the stable view remains eligible");
    assert_eq!(plan.slots[0].names, ["C_Verify"]);
    assert_eq!(plan.slots[0].object, stable_target);
}

/// Mutation caught: recording ownership only after provider reconciliation leaks
/// target pins opened for a view whose provider was rejected.
#[test]
fn retiring_a_rejected_provider_view_removes_its_unplanned_pins_and_raw_aliases() {
    use p11scope::discovery::identity::{pin_scanned_view_objects, reconcile_scanned_modules};
    use p11scope::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
    use p11scope::process::ProcessView;

    let d = tmpdir("manifest_pinning_rejected_provider_retirement");
    let provider = cc_so(&d, "rejected_provider", "int provider(void){return 1;}\n");
    let unique = cc_so(&d, "unique_target", "int unique(void){return 2;}\n");
    let shared = cc_so(&d, "shared_target", "int shared(void){return 3;}\n");
    let view_id = ProcessViewId(23);
    let mut rejected_provider = manifest_key(&provider);
    rejected_provider.inode = rejected_provider.inode.wrapping_add(1);
    let module = ScannedModule {
        view: view_id,
        mount_namespace: current_mount_namespace(),
        key: rejected_provider,
        path: provider.display().to_string(),
        exports: vec!["C_GetFunctionList".into()],
        tables: vec![ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![
                ScannedEntry {
                    name: "C_Sign",
                    object: manifest_key(&unique),
                    object_path: unique.display().to_string(),
                    file_offset: first_executable_offset(&unique),
                },
                ScannedEntry {
                    name: "C_Verify",
                    object: manifest_key(&shared),
                    object_path: shared.display().to_string(),
                    file_offset: first_executable_offset(&shared),
                },
            ],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x1000,
            file_offset: Some(0),
        }],
        interfaces: vec![],
    };
    let view = ProcessView::open(view_id, std::process::id()).unwrap();
    let (local, skipped) = pin_scanned_view_objects(
        &view,
        std::slice::from_ref(&module),
        &mut CaptureWorkBudget::default(),
    )
    .unwrap();
    assert!(
        skipped
            .iter()
            .any(|skip| skip.reason.contains("identity_mismatch")),
        "the provider must be rejected while its targets pin: {skipped:?}"
    );
    let mut pinned = p11scope::discovery::identity::PinnedObjects::empty();
    pinned.absorb(local);
    pinned.absorb(
        p11scope::discovery::identity::pin_manifest_objects(&manifest_for(&shared)).unwrap(),
    );
    let unique_id = pinned
        .id_for_scanned(
            &module,
            manifest_key(&unique),
            &unique.display().to_string(),
        )
        .expect("the rejected provider's unique target was opened");
    let shared_scan_id = pinned
        .id_for_scanned(
            &module,
            manifest_key(&shared),
            &shared.display().to_string(),
        )
        .expect("the rejected provider's shared target was opened");
    let shared_manifest_id = pinned
        .id_for_manifest(manifest_key(&shared), &shared.display().to_string())
        .expect("the manifest independently owns the shared target");
    assert_eq!(shared_scan_id, shared_manifest_id);
    let (reconciled, _, _) = reconcile_scanned_modules(std::slice::from_ref(&module), &mut pinned);
    assert!(reconciled.is_empty(), "the provider itself was rejected");

    pinned
        .remove_view(view_id)
        .expect("every scan-opened pin is owned before reconciliation");

    assert!(pinned.attach_path_for(unique_id).is_err());
    assert!(
        pinned
            .id_for_scanned(
                &module,
                manifest_key(&shared),
                &shared.display().to_string()
            )
            .is_none(),
        "the retired view's raw alias must be removed even when its fd is shared"
    );
    assert!(pinned.attach_path_for(shared_manifest_id).is_ok());
    assert_eq!(
        pinned.id_for_manifest(manifest_key(&shared), &shared.display().to_string()),
        Some(shared_manifest_id),
        "the retained manifest keeps its exact pin and alias"
    );
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
fn stale_manifest_objects_are_typed_individually_for_scan_fallback() {
    use p11scope::discovery::identity::{ManifestStaleReason, pin_manifest_objects_deferred};

    let d = tmpdir("manifest_pinning_typed_stale");
    let so = cc_so(&d, "changed", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    let _ = cc_so(
        &d,
        "changed",
        "int f(void){return 2;} int g(void){return 3;}\n",
    );

    let pinned = pin_manifest_objects_deferred(&m).expect("staleness is deferred, not fatal");
    assert_eq!(pinned.pins.pinned().count(), 0);
    assert_eq!(pinned.stale.len(), 1);
    assert_eq!(pinned.stale[0].object, 0);
    assert_eq!(
        pinned.stale[0].reason,
        ManifestStaleReason::IdentityMismatch
    );
}

#[test]
fn proc_root_manifest_without_its_retained_process_view_fails_closed() {
    let d = tmpdir("manifest_pinning_proc_root_unbound");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let locator = PathBuf::from(format!("/proc/{}/root{}", std::process::id(), so.display()));
    let manifest = manifest_for(&locator);

    let errors = p11scope::discovery::identity::pin_manifest_objects(&manifest)
        .expect_err("a proc-root locator without its retained process view is not authoritative");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("no exact retained process view")),
        "{errors:?}"
    );
}

fn retarget_manifest(manifest: &mut Manifest, path: String) {
    manifest.module_path.clone_from(&path);
    manifest.objects[0].path.clone_from(&path);
    manifest.provenance_objects[0].path = path;
}

#[test]
fn proc_root_manifest_uses_its_exact_retained_process_view() {
    use p11scope::discovery::identity::pin_manifest_objects_deferred_in_views;

    let d = tmpdir("manifest_pinning_proc_root_retained");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let pid = std::process::id();
    let locator = PathBuf::from(format!("/proc/{pid}/root{}", so.display()));
    let manifest = manifest_for(&locator);
    let view = ProcessView::open(ProcessViewId(17), pid).unwrap();

    let pinning = pin_manifest_objects_deferred_in_views(&manifest, &[view]).unwrap();
    assert!(pinning.stale.is_empty());
    assert_eq!(pinning.pins.pinned().count(), 1);
}

#[test]
fn proc_root_manifest_rejects_ambiguous_spellings() {
    use p11scope::discovery::identity::{ManifestPinError, pin_manifest_objects_deferred_in_views};

    let d = tmpdir("manifest_pinning_proc_root_ambiguous");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let pid = std::process::id();
    let canonical = PathBuf::from(format!("/proc/{pid}/root{}", so.display()));
    let base = manifest_for(&canonical);
    let view = ProcessView::open(ProcessViewId(18), pid).unwrap();
    let directory = so.parent().unwrap();
    let file = so.file_name().unwrap().to_str().unwrap();
    let spellings = [
        format!("/proc/self/root{}", so.display()),
        format!("/proc/thread-self/root{}", so.display()),
        format!("/proc/0{pid}/root{}", so.display()),
        format!("//proc/{pid}/root{}", so.display()),
        format!("/proc/{pid}//root{}", so.display()),
        format!("/proc/{pid}/root/{}", so.display()),
        format!("/proc/{pid}/task/{pid}/root{}", so.display()),
        format!("/proc/{pid}/root/proc/self/root{}", so.display()),
        format!("/proc/{pid}/root{}/./{file}", directory.display()),
        format!("/proc/{pid}/root{}/{file}/../{file}", directory.display()),
    ];

    for path in spellings {
        let mut manifest = base.clone();
        retarget_manifest(&mut manifest, path.clone());
        let error = pin_manifest_objects_deferred_in_views(&manifest, std::slice::from_ref(&view))
            .expect_err("ambiguous proc-root spelling must fail closed");
        assert!(
            matches!(error, ManifestPinError::Fatal(ref errors)
                if errors.iter().any(|error| error.contains("canonical /proc/<pid>/root"))),
            "{path}: {error:?}"
        );
    }
}

#[test]
fn proc_root_parent_alias_cannot_erase_the_retained_view_boundary() {
    let pid = std::process::id();
    let mut manifest = manifest_for(Path::new("/bin/sh"));
    retarget_manifest(&mut manifest, format!("/proc/{pid}/root/../bin/sh"));

    let errors = p11scope::discovery::identity::pin_manifest_objects(&manifest)
        .expect_err("normalization must not turn a proc-root alias into a host locator");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("canonical /proc/<pid>/root")),
        "{errors:?}"
    );
}

#[test]
fn proc_root_prefix_alias_cannot_hide_an_erased_view_boundary() {
    let pid = std::process::id();
    let base = manifest_for(Path::new("/bin/sh"));
    for path in [
        format!("/./proc/{pid}/root/../bin/sh"),
        format!("/tmp/../proc/{pid}/root/../bin/sh"),
        format!("/../proc/{pid}/root/../bin/sh"),
        format!("/./proc/{pid}/root/../../../bin/sh"),
    ] {
        let mut manifest = base.clone();
        retarget_manifest(&mut manifest, path.clone());
        let errors = p11scope::discovery::identity::pin_manifest_objects(&manifest)
            .expect_err("a prefixed proc-root alias must not become a host locator");
        assert!(
            errors
                .iter()
                .any(|error| error.contains("canonical /proc/<pid>/root")),
            "{path}: {errors:?}"
        );
    }
}

#[test]
fn proc_root_manifest_rejects_a_pid_not_in_the_retained_views() {
    use p11scope::discovery::identity::{ManifestPinError, pin_manifest_objects_deferred_in_views};

    let d = tmpdir("manifest_pinning_proc_root_wrong_view");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let locator = PathBuf::from(format!("/proc/{}/root{}", child.id(), so.display()));
    let manifest = manifest_for(&locator);
    let observer = ProcessView::open(ProcessViewId(19), std::process::id()).unwrap();

    let error = pin_manifest_objects_deferred_in_views(&manifest, &[observer])
        .expect_err("a different retained pid cannot authorize this locator");
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        matches!(error, ManifestPinError::Fatal(ref errors)
            if errors.iter().any(|error| error.contains("no exact retained process view"))),
        "{error:?}"
    );
}

#[test]
fn proc_root_manifest_rejects_a_stale_retained_process_view() {
    use p11scope::discovery::identity::{ManifestPinError, pin_manifest_objects_deferred_in_views};

    let d = tmpdir("manifest_pinning_proc_root_stale_view");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let locator = PathBuf::from(format!("/proc/{}/root{}", child.id(), so.display()));
    let manifest = manifest_for(&locator);
    let view = ProcessView::open(ProcessViewId(20), child.id()).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();

    let error = pin_manifest_objects_deferred_in_views(&manifest, &[view])
        .expect_err("a stale retained process generation must fail closed");
    assert!(
        matches!(error, ManifestPinError::Fatal(ref errors)
            if errors.iter().any(|error| error.contains("exited"))),
        "{error:?}"
    );
}

#[test]
fn ordinary_host_manifest_behavior_is_unchanged_with_retained_views() {
    use p11scope::discovery::identity::pin_manifest_objects_deferred_in_views;

    let d = tmpdir("manifest_pinning_host_with_views");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let manifest = manifest_for(&so);
    let view = ProcessView::open(ProcessViewId(21), std::process::id()).unwrap();

    let pinning = pin_manifest_objects_deferred_in_views(&manifest, &[view]).unwrap();
    assert!(pinning.stale.is_empty());
    assert_eq!(pinning.pins.pinned().count(), 1);
}

#[test]
fn a_missing_locator_is_stale_but_malformed_and_other_open_failures_are_fatal() {
    use p11scope::discovery::identity::{
        ManifestPinError, ManifestStaleReason, pin_manifest_objects_deferred,
    };

    let d = tmpdir("manifest_pinning_typed_open_stale");
    let so = cc_so(&d, "gone", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    std::fs::remove_file(&so).unwrap();
    let pinned = pin_manifest_objects_deferred(&m).expect("ENOENT is decided after scanning");
    assert_eq!(pinned.stale.len(), 1);
    assert_eq!(pinned.stale[0].reason, ManifestStaleReason::OpenStale);

    let mut malformed = m.clone();
    malformed.module_path = "relative.so".into();
    assert!(matches!(
        pin_manifest_objects_deferred(&malformed),
        Err(ManifestPinError::Invalid(_))
    ));

    let directory = d.join("not-a-file");
    std::fs::create_dir_all(&directory).unwrap();
    let mut non_regular = manifest_for(&PathBuf::from("/bin/sh"));
    non_regular.module_path = directory.display().to_string();
    non_regular.objects[0].path = directory.display().to_string();
    non_regular.provenance_objects[0].path = directory.display().to_string();
    assert!(matches!(
        pin_manifest_objects_deferred(&non_regular),
        Err(ManifestPinError::Fatal(_))
    ));
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
    // Note the shape: `objects[0].path` is the symlink the operator named, while
    // `provenance_objects[0].path` is what a mapping of it shows — the two pathnames
    // in one manifest that `p11scope-discover` produces for any provider named
    // through a symlink. A pin is filed under the *object's* path and keyed by the
    // identity that path resolves to; `main.rs::retarget_to_pins` relies on exactly
    // that pairing to replace a stale recorded identity with the live one.
    let summary = pinned.pinned().next().expect("one object is pinned");
    assert_eq!(pinned.pinned().count(), 1);
    assert_eq!(summary.path, symlink_manifest.objects[0].path);
    assert_ne!(summary.path, symlink_manifest.provenance_objects[0].path);
    assert_eq!(summary.key, manifest_key(&link));
    let attach = pinned
        .attach_path_for(summary.id)
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
    let non_executable_offset = first_non_executable_offset(&so);
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
                        non_executable_offset
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

    let mut selection_offset_manifest = manifest_for(&so);
    selection_offset_manifest.selection_evidence = queried_selection_matrix();
    selection_offset_manifest.selection_evidence.tables = vec![SelectionTable {
        id: 0,
        version: Version { major: 3, minor: 0 },
        walk: WalkOutcome::Full,
        functions: pkcs11_module::FUNCTION_LIST_FIELDS
            .iter()
            .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS.iter())
            .map(|field| FunctionRecord {
                name: field.name.into(),
                resolution: Resolution::Resolved {
                    object: 0,
                    file_offset: if field.name == "C_Initialize" {
                        non_executable_offset
                    } else {
                        first_executable_offset(&so)
                    },
                },
            })
            .collect(),
        semantic_authorized: false,
    }];
    let query = &mut selection_offset_manifest.selection_evidence.queries[4];
    query.rv = 0;
    query.result = Some(SelectionResult {
        name: SelectionNameClass::ExactStandard,
        version: SelectionVersionClass::V3_0,
        flags: 0,
    });
    query.selection_table = Some(0);
    query.authority = SelectionAuthority::SelectionCountOnly;
    let err = p11scope::discovery::identity::pin_manifest_objects(&selection_offset_manifest)
        .unwrap_err();
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
fn byte_identical_aliases_require_an_unambiguous_provenance_relation() {
    let d = tmpdir("manifest_pinning_ambiguous_provenance");
    let so = cc_so(&d, "provider", "int f(void){return 1;}\n");
    let identity = p11scope_manifest::identity::inspect_file(
        &p11scope_manifest::identity::open_object(&so).unwrap(),
    )
    .unwrap()
    .identity;
    let mut m = manifest_for(&so);
    m.module_path = "/aliases/a.so".into();
    m.objects = vec![
        ObjectRecord {
            id: 0,
            path: "/aliases/a.so".into(),
            identity: identity.clone(),
        },
        ObjectRecord {
            id: 1,
            path: "/aliases/b.so".into(),
            identity: identity.clone(),
        },
    ];
    m.provenance_objects = vec![
        ProvenanceObject {
            path: "/real/a.so".into(),
            device_major: 8,
            device_minor: 1,
            inode: 101,
            identity: identity.clone(),
        },
        ProvenanceObject {
            path: "/real/b.so".into(),
            device_major: 8,
            device_minor: 1,
            inode: 102,
            identity,
        },
    ];

    let problems = p11scope::manifest_input::validate_structure(&m);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("matches multiple provenance objects")),
        "first-digest provenance remained authoritative: {problems:?}"
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
    let key = manifest_key(&so);
    let id = pinned.pinned().find(|pin| pin.key == key).unwrap().id;
    let attach = pinned.attach_path_for(id).unwrap();
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
    use p11scope::discovery::scan::{ScanOutcome, ScanRequest, scan_pid};

    let hooks = HookRegistry::builtin();
    let exe = std::env::current_exe().unwrap();
    let outcome = scan_pid(
        &ScanRequest {
            pid: std::process::id(),
            hints: &[exe.clone()],
            hooks: &hooks,
        },
        &mut self_binary_budget(),
    )
    .unwrap();
    let ScanOutcome::Scanned { modules, .. } = outcome else {
        panic!("/proc/self/mem is always readable")
    };
    (exe, modules)
}

#[test]
fn scanned_objects_are_pinned_hashed_and_attachable() {
    let (exe, modules) = scan_self();
    let (pinned, skipped) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &modules,
        &mut self_binary_budget(),
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
        let attach = pinned.attach_path_for(summary.id).unwrap();
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
    use p11scope::discovery::scan::ScannedModule;
    use p11scope_manifest::maps::{Device, ObjectKey};

    // The path the scan named still resolves — to a different inode than the mapping
    // reported. That is what a retargeted path looks like, and it must never be pinned.
    let exe = std::env::current_exe().unwrap();
    let module = ScannedModule {
        view: ProcessViewId(0),
        mount_namespace: current_mount_namespace(),
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
        &mut CaptureWorkBudget::default(),
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

    // Force `mapping_file_key` to be unavailable: memfd's internal mount does not
    // appear in /proc/self/mountinfo. The inode still agrees, while the mapping device
    // deliberately does not. Incomparable identity must fail closed, never fall back
    // to accepting the inode by itself.
    use std::ffi::CString;
    use std::io::{Seek as _, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let name = CString::new("p11scope-identity-unavailable").unwrap();
    // SAFETY: valid NUL-terminated name and supported memfd flags; success returns a
    // uniquely owned descriptor transferred immediately into `File`.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
    let mut memfd = unsafe { std::fs::File::from_raw_fd(fd) };
    memfd.write_all(&std::fs::read(&exe).unwrap()).unwrap();
    memfd.rewind().unwrap();
    let memfd_path = format!("/proc/self/fd/{}", memfd.as_raw_fd());
    let opened = p11scope_manifest::identity::open_object(Path::new(&memfd_path)).unwrap();
    let mapping_error = p11scope_manifest::identity::mapping_file_key(&opened)
        .expect_err("memfd mount identity must be absent from mountinfo");
    assert!(
        mapping_error.contains("missing from the mount table"),
        "{mapping_error}"
    );
    let metadata = memfd.metadata().unwrap();
    let module = ScannedModule {
        view: ProcessViewId(0),
        mount_namespace: current_mount_namespace(),
        key: ObjectKey {
            device: Device {
                major: 0xffff,
                minor: 0xffff,
            },
            inode: metadata.ino(),
        },
        path: memfd_path.clone(),
        exports: vec![],
        tables: vec![],
        interfaces: vec![],
    };
    let (pinned, skipped) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &[module],
        &mut CaptureWorkBudget::default(),
    )
    .unwrap();
    assert_eq!(
        pinned.pinned().count(),
        0,
        "inode-only identity was accepted"
    );
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert_eq!(skipped[0].subject, memfd_path);
    assert!(
        skipped[0].reason.contains("mapping identity") && skipped[0].reason.contains("unavailable"),
        "{:?}",
        skipped[0]
    );
}

#[test]
fn an_object_over_the_byte_budget_is_skipped_naming_the_cap() {
    use p11scope::discovery::scan::ScanLimits;

    let (exe, modules) = scan_self();
    // Sized from live data: one byte under the object the scan actually reported.
    let len = std::fs::metadata(&exe).unwrap().len();
    let limits = ScanLimits {
        per_object_bytes: len - 1,
        total_bytes: u64::MAX,
    };
    let (pinned, skipped) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &modules,
        &mut CaptureWorkBudget::new(limits),
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

#[test]
fn hash_budget_charges_the_prefix_read_before_aggregate_exhaustion() {
    use p11scope::discovery::scan::ScanLimits;

    let (exe, modules) = scan_self();
    let len = std::fs::metadata(exe).unwrap().len();
    let total_bytes = len - 1;
    let mut budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: len,
        total_bytes,
    });
    let (pinned, skipped) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &modules,
        &mut budget,
    )
    .unwrap();
    assert_eq!(
        pinned.pinned().count(),
        0,
        "a partial digest is never trusted"
    );
    assert_eq!(
        budget.attempted_io_bytes(),
        total_bytes,
        "the completed prefix remains charged"
    );
    assert!(
        skipped
            .iter()
            .any(|skip| skip.reason.contains("capture") && skip.reason.contains("ceiling")),
        "the unread hash remainder must be explicit: {skipped:?}"
    );
}

#[test]
fn a_failed_hash_attempt_still_consumes_the_capture_budget() {
    use p11scope::discovery::scan::{ScanLimits, ScannedModule};

    let dir = tmpdir("failed-hash-budget");
    let valid = cc_so(&dir, "valid-budget", "int exported(void) { return 0; }");
    let invalid = dir.join("invalid-budget.so");
    let mut bytes = std::fs::read(&valid).unwrap();
    bytes[..4].copy_from_slice(b"NOPE");
    std::fs::write(&invalid, bytes).unwrap();
    let len = std::fs::metadata(&valid).unwrap().len();
    assert_eq!(len, std::fs::metadata(&invalid).unwrap().len());
    let module = |path: &Path| ScannedModule {
        view: ProcessViewId(0),
        mount_namespace: current_mount_namespace(),
        key: manifest_key(path),
        path: path.display().to_string(),
        exports: vec![],
        tables: vec![],
        interfaces: vec![],
    };
    let limits = ScanLimits {
        per_object_bytes: len,
        total_bytes: len,
    };
    let mut budget = CaptureWorkBudget::new(limits);
    let (_, failed) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &[module(&invalid)],
        &mut budget,
    )
    .unwrap();
    assert_eq!(failed.len(), 1, "the invalid ELF must fail after its read");
    let (retry, skipped) = p11scope::discovery::identity::pin_scanned_objects(
        std::process::id(),
        &[module(&valid)],
        &mut budget,
    )
    .unwrap();
    assert_eq!(
        retry.pinned().count(),
        0,
        "a retry cannot regain spent bytes"
    );
    assert!(
        skipped
            .iter()
            .any(|skip| skip.reason.contains("capture attempted-I/O ceiling")),
        "the shared budget exhaustion must be explicit: {skipped:?}"
    );
}
