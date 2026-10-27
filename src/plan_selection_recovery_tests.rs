//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use p11scope_manifest::manifest::{SelectionAuthority, SelectionTable};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) fn acquire_manifest(provider: &Path) -> Manifest {
    let manifest_path = provider.with_extension("manifest.json");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "discovery::engine::tests::lifecycle_manifest_helper_entrypoint",
            "--ignored",
            "--nocapture",
        ])
        .env("P11SCOPE_TEST_DISCOVERY_PROVIDER", provider)
        .env("P11SCOPE_TEST_DISCOVERY_MANIFEST", &manifest_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap()
}

struct Fixture {
    directory: tempfile::TempDir,
    path: PathBuf,
}

impl Fixture {
    fn build(defines: &[&str]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.so");
        let mut compiler = Command::new("gcc");
        compiler
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-o"])
            .arg(&path)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("crates/discover/tests/fixture/selection_recovery.c"),
            )
            .args(defines);
        if defines.contains(&"-DSELECT_BAD=3") {
            let source = directory.path().join("backend.c");
            let backend = directory.path().join("backend.so");
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
                .arg(format!("-Wl,-rpath,{}", directory.path().display()));
        }
        assert!(compiler.status().unwrap().success());
        Self { directory, path }
    }

    fn manifest(&self) -> Manifest {
        let manifest = acquire_manifest(&self.path);
        let problems = crate::manifest_input::validate_structure(&manifest);
        assert!(problems.is_empty(), "{problems:?}");
        manifest
    }
}

fn policies(endpoints: u64) -> [AdmissionPolicy; 3] {
    [
        AdmissionPolicy::detailed(),
        AdmissionPolicy::inventory(
            crate::capacity::InventoryBudget::new(
                endpoints,
                endpoints * crate::capacity::INVENTORY_ENDPOINT_BYTES,
            )
            .unwrap(),
        ),
        AdmissionPolicy::counters(crate::capacity::CounterBudget::new(endpoints).unwrap()),
    ]
}

fn resolved_keys(
    table: &SelectionTable,
    manifest: &Manifest,
    pins: &PinnedObjects,
) -> BTreeSet<AttachKey> {
    table
        .functions
        .iter()
        .filter_map(|function| {
            let Resolution::Resolved {
                object,
                file_offset,
            } = function.resolution
            else {
                return None;
            };
            let record = manifest
                .objects
                .iter()
                .find(|record| record.id == object)
                .unwrap();
            let key = object_key(manifest, record).unwrap();
            Some(AttachKey {
                object: pins.id_for_manifest(key, &record.path).unwrap(),
                file_offset,
            })
        })
        .collect()
}

#[test]
fn helper_selected_targets_reach_detailed_inventory_and_counter_consumers() {
    let cases: &[&[&str]] = &[
        &[],
        &["-DSELECT_MAJOR=2", "-DSELECT_MINOR=0"],
        &["-DSELECT_MAJOR=2", "-DSELECT_MINOR=40"],
        &["-DSELECT_MINOR=1"],
        &["-DSELECT_MINOR=2"],
        &["-DSELECT_MINOR=9"],
        &["-DSELECT_MAJOR=4", "-DSELECT_MINOR=19"],
        &["-DSELECT_FLAGS=64"],
        &["-DSELECT_NAME=1"],
        &["-DSELECT_NAME=2"],
        &["-DSELECT_NAME=3"],
        &["-DSELECT_DEFAULT_ONLY=1"],
        &["-DSELECT_LEGACY=1", "-DSELECT_LIST=1"],
        &["-DSELECT_LEGACY=1", "-DSELECT_LIST=2"],
        &["-DSELECT_SPARSE=-1"],
        &["-DSELECT_SPARSE=67"],
        &["-DSELECT_BAD=1"],
        &["-DSELECT_BAD=2"],
        &["-DSELECT_BAD=3"],
        &["-DSELECT_BAD=4"],
        &["-DSELECT_HEAP=1"],
        &["-DSELECT_CONFLICT=1"],
        &["-DSELECT_HEADER_UNREADABLE=1"],
        &["-DSELECT_HEADER_UNREADABLE=1", "-DSELECT_BAD=1"],
        &["-DSELECT_MAJOR=0", "-DSELECT_MINOR=0"],
        &["-DSELECT_MINOR=2", "-DSELECT_WORDS=0"],
        &["-DSELECT_MINOR=2", "-DSELECT_WORDS=1"],
        &["-DSELECT_MINOR=2", "-DSELECT_WORDS=3"],
        &["-DSELECT_MINOR=2", "-DSELECT_WORDS=67"],
        &[
            "-DSELECT_MINOR=2",
            "-DSELECT_WORDS=67",
            "-DSELECT_PARTIAL_WORD=1",
        ],
        &["-DSELECT_MINOR=2", "-DSELECT_WORDS=68"],
        &["-DSELECT_MINOR=2", "-DSELECT_WORDS=92"],
        &["-DSELECT_MINOR=2", "-DSELECT_WORDS=104"],
    ];
    for defines in cases {
        let fixture = Fixture::build(defines);
        let manifest = fixture.manifest();
        let pins = crate::discovery::identity::pin_manifest_objects(&manifest).unwrap();
        let expected: BTreeSet<_> = manifest
            .selection_evidence
            .tables
            .iter()
            .flat_map(|table| resolved_keys(table, &manifest, &pins))
            .collect();
        let incomplete = manifest.selection_evidence.tables.iter().any(|table| {
            crate::manifest_input::selection_table_inventory_incomplete(
                &manifest.selection_evidence,
                table,
            )
        });
        assert!(
            manifest
                .selection_evidence
                .queries
                .iter()
                .all(|query| query.authority != SelectionAuthority::Inventory)
        );
        let claims = semantic_source_claims(&[], std::slice::from_ref(&manifest), &pins);
        assert_eq!(!claims.incomplete.is_empty(), incomplete, "{defines:?}");
        for policy in policies(16) {
            let mut plan =
                build_from_sources_for_policy(&[], std::slice::from_ref(&manifest), &pins, policy);
            assert_eq!(plan.modules.len(), 1, "{defines:?}");
            let module = plan.modules[0].id;
            let provider = plan.modules[0].object;
            let allocated = plan.clone();
            for (table_id, targets) in
                crate::discovery::engine::manifest_selection_targets(&manifest, &pins)
            {
                let table = manifest
                    .selection_evidence
                    .tables
                    .iter()
                    .find(|table| table.id == table_id)
                    .unwrap();
                let named =
                    crate::manifest_input::selection_table_name_authorized(&manifest, table_id);
                for target in &targets {
                    let ordinal = target.ordinal.unwrap();
                    assert_eq!(target.name == "unknown", !named, "{defines:?}");
                    assert!(matches!(
                        table.functions[usize::from(ordinal)].resolution,
                        Resolution::Resolved { .. }
                    ));
                }
                plan.add_selection_table(&allocated, module, targets)
                    .unwrap();
            }
            assert_eq!(
                plan.slots
                    .iter()
                    .map(AttachKey::of)
                    .collect::<BTreeSet<_>>(),
                expected,
                "{defines:?}"
            );
            if incomplete {
                assert!(
                    plan.skipped
                        .iter()
                        .any(|skip| skip.subject.starts_with("selection table")),
                    "{defines:?}"
                );
            }
            if !expected.is_empty() {
                assert_eq!(
                    claims.providers.get(&provider),
                    Some(&expected),
                    "{defines:?}"
                );
            }
            for slot in &plan.slots {
                assert_eq!(slot.descriptor_index, 0);
                assert_eq!(slot.semantics, SlotSemantics::COUNT_ONLY);
                assert!(!slot.semantic_authorized);
                assert!(claims.degraded.contains(&AttachKey::of(slot)));
                let ordinals = plan.slot_ordinals.get(&AttachKey::of(slot)).unwrap();
                for ordinal in ordinals {
                    assert_eq!(ordinal.table_file_offset, None);
                    assert!(manifest.selection_evidence.tables.iter().any(|table| {
                        table
                            .functions
                            .get(usize::from(ordinal.ordinal))
                            .is_some_and(|function| {
                                let Resolution::Resolved {
                                    object,
                                    file_offset,
                                } = function.resolution
                                else {
                                    return false;
                                };
                                let record = &manifest.objects[object as usize];
                                pins.id_for_manifest(
                                    object_key(&manifest, record).unwrap(),
                                    &record.path,
                                ) == Some(slot.object)
                                    && file_offset == slot.file_offset
                            })
                    }));
                }
            }
            if defines.contains(&"-DSELECT_SPARSE=67") {
                assert_eq!(plan.slots.len(), 1);
                assert_eq!(
                    plan.slot_ordinals[&AttachKey::of(&plan.slots[0])]
                        .iter()
                        .map(|o| o.ordinal)
                        .collect::<Vec<_>>(),
                    [67]
                );
            }
        }
    }
}

#[test]
fn selected_table_capacity_and_provider_proof_refusals_are_atomic() {
    let fixture = Fixture::build(&[]);
    let manifest = fixture.manifest();
    let pins = crate::discovery::identity::pin_manifest_objects(&manifest).unwrap();
    let targets = crate::discovery::engine::manifest_selection_targets(&manifest, &pins)
        .next()
        .unwrap()
        .1;
    assert_eq!(targets.len(), 4);
    let policy = AdmissionPolicy::counters(crate::capacity::CounterBudget::new(3).unwrap());
    let mut plan = build_from_sources_for_policy(&[], &[manifest], &pins, policy);
    let allocated = plan.clone();
    let error = plan
        .add_selection_table(&allocated, plan.modules[0].id, targets.clone())
        .unwrap_err();
    assert!(error.contains("refusing to attach a prefix"), "{error}");
    assert!(plan.slots.is_empty() && plan.slot_ordinals.is_empty());
    let unpinned = PinnedObjects::empty();
    assert!(
        SelectionTableTarget::from_pinned(
            targets[0].object,
            targets[0].object,
            targets[0].object_path.clone(),
            targets[0].file_offset,
            "unknown",
            0,
            &unpinned
        )
        .is_none()
    );
    plan.modules[0].object = PinnedObjectId(u32::MAX);
    let before = plan.clone();
    assert!(
        plan.add_selection_table(&allocated, plan.modules[0].id, targets)
            .is_err()
    );
    assert_eq!(plan.slots, before.slots);
    assert_eq!(plan.slot_ordinals, before.slot_ordinals);
}

#[test]
fn selected_dependency_abi_mismatch_keeps_local_targets_and_an_explicit_gap() {
    let fixture = Fixture::build(&["-DSELECT_BAD=3"]);
    let mut manifest = fixture.manifest();
    let source = fixture.directory.path().join("other-abi.c");
    let library = fixture.directory.path().join("other-abi.so");
    std::fs::write(
        &source,
        "unsigned long selected_other_abi(void) { return 0; }\n",
    )
    .unwrap();
    let opposite = if usize::BITS == 64 { "-m32" } else { "-m64" };
    assert!(
        Command::new("gcc")
            .args([opposite, "-nostdlib", "-shared", "-fPIC", "-o"])
            .arg(&library)
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    let file = p11scope_manifest::identity::open_object(&library).unwrap();
    let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
    let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
    let Resolution::Resolved { object, .. } =
        manifest.selection_evidence.tables[0].functions[20].resolution
    else {
        panic!("missing dependency")
    };
    let old_path = manifest.objects[object as usize].path.clone();
    manifest.objects[object as usize].path = library.display().to_string();
    manifest.objects[object as usize].identity = inspected.identity.clone();
    let provenance = manifest
        .provenance_objects
        .iter_mut()
        .find(|provenance| provenance.path == old_path)
        .unwrap();
    provenance.path = library.display().to_string();
    provenance.identity = inspected.identity;
    provenance.device_major = mapping.device_major;
    provenance.device_minor = mapping.device_minor;
    provenance.inode = mapping.inode;
    for table in &mut manifest.selection_evidence.tables {
        table.functions[20].resolution = Resolution::Resolved {
            object,
            file_offset: inspected.executable_ranges[0].0,
        };
    }
    assert!(crate::manifest_input::validate_structure(&manifest).is_empty());
    let pins = crate::discovery::identity::pin_manifest_objects(&manifest).unwrap();
    let targets = crate::discovery::engine::manifest_selection_targets(&manifest, &pins)
        .next()
        .unwrap()
        .1;
    assert_eq!(
        targets.len(),
        4,
        "only the opposite-ABI dependency is unavailable"
    );
    assert!(targets.iter().all(|target| target.ordinal != Some(20)));
    let claims = semantic_source_claims(&[], std::slice::from_ref(&manifest), &pins);
    assert_eq!(claims.incomplete.len(), 1);
    let mut plan = build_from_sources(&[], &[manifest], &pins);
    assert!(
        plan.skipped
            .iter()
            .any(|skip| skip.subject.ends_with("ordinal 20")
                && skip.reason.contains("different target ABI"))
    );
    let allocated = plan.clone();
    plan.add_selection_table(&allocated, plan.modules[0].id, targets)
        .unwrap();
    assert_eq!(plan.slots.len(), 4);
    assert!(plan.slots.iter().all(|slot| !slot.semantic_authorized));
}

#[test]
fn imported_selected_metadata_drift_keeps_extended_targets_count_only() {
    let fixture = Fixture::build(&["-DSELECT_MINOR=2"]);
    let mut manifest = fixture.manifest();
    manifest.selection_evidence.tables[0].walk = WalkOutcome::Unreadable {
        detail: "version metadata changed: 104 complete function words retained".into(),
    };
    for query in &mut manifest.selection_evidence.queries {
        query.helper_failure =
            Some(p11scope_manifest::manifest::SelectionFailure::UnreadableVersion);
    }
    assert!(crate::manifest_input::validate_structure(&manifest).is_empty());
    let pins = crate::discovery::identity::pin_manifest_objects(&manifest).unwrap();
    let claims = semantic_source_claims(&[], std::slice::from_ref(&manifest), &pins);
    assert!(
        claims.incomplete.is_empty(),
        "only metadata changed; all104 words were observed"
    );
    for policy in policies(16) {
        let mut plan =
            build_from_sources_for_policy(&[], std::slice::from_ref(&manifest), &pins, policy);
        let allocated = plan.clone();
        for (_, targets) in crate::discovery::engine::manifest_selection_targets(&manifest, &pins) {
            assert_eq!(targets.len(), 5);
            assert!(targets.iter().all(|target| target.name == "unknown"));
            assert!(targets.iter().any(|target| target.ordinal == Some(103)));
            plan.add_selection_table(&allocated, plan.modules[0].id, targets)
                .unwrap();
        }
        assert_eq!(plan.slots.len(), 5);
        assert!(
            plan.slots
                .iter()
                .all(|slot| !slot.semantic_authorized && slot.descriptor_index == 0)
        );
    }
}

#[test]
fn two_selected_providers_share_one_dependency_slot_without_sole_owner_s1() {
    let fixture = Fixture::build(&["-DSELECT_BAD=3"]);
    let mut first = fixture.manifest();
    let path = fixture.directory.path().join("second-provider.so");
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-DSELECT_BAD=3", "-o"])
            .arg(&path)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("crates/discover/tests/fixture/selection_recovery.c")
            )
            .arg(fixture.directory.path().join("backend.so"))
            .arg(format!("-Wl,-rpath,{}", fixture.directory.path().display()))
            .status()
            .unwrap()
            .success()
    );
    let second = acquire_manifest(&path);
    // The trusted ordinary input grants its existing per-function permission;
    // a second provider sharing the physical target must remove sole ownership.
    first.surfaces[0].acquisition = Acquisition::Ok;
    first.surfaces[0].version = Some(p11scope_manifest::manifest::Version {
        major: 2,
        minor: 40,
    });
    first.surfaces[0].walk = WalkOutcome::Full;
    first.surfaces[0].functions = pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .map(|field| p11scope_manifest::manifest::FunctionRecord {
            name: field.name.into(),
            resolution: Resolution::NullPointer,
        })
        .collect();
    first.surfaces[0].functions[20] = first.selection_evidence.tables[0].functions[20].clone();
    assert!(crate::manifest_input::validate_structure(&first).is_empty());
    assert!(crate::manifest_input::validate_structure(&second).is_empty());
    let mut pins = crate::discovery::identity::pin_manifest_objects(&first).unwrap();
    assert!(
        pins.absorb(crate::discovery::identity::pin_manifest_objects(&second).unwrap())
            .is_empty()
    );
    let manifests = [first, second];
    let mut plan = build_from_sources(&[], &manifests, &pins);
    assert_eq!(plan.slots.len(), 1);
    let backend_key = AttachKey::of(&plan.slots[0]);
    assert!(plan.slots[0].semantic_authorized);
    let allocated = plan.clone();
    for (index, manifest) in manifests.iter().enumerate() {
        let object = pins.id_for_path(&manifest.module_path).unwrap();
        let module = plan
            .modules
            .iter()
            .find(|module| module.object == object)
            .unwrap()
            .id;
        for (_, targets) in crate::discovery::engine::manifest_selection_targets(manifest, &pins) {
            plan.add_selection_table(&allocated, module, targets)
                .unwrap();
        }
        if index == 0 {
            let slot = &plan.slots[plan.slot_by_key[&backend_key]];
            assert!(
                slot.semantic_authorized,
                "same-provider count-only observation preserves existing S1"
            );
        }
    }
    let shared = &plan.slots[plan.slot_by_key[&backend_key]];
    assert_eq!(shared.module_ids.len(), 2);
    assert_eq!(shared.semantics, SlotSemantics::COUNT_ONLY);
    assert_eq!(shared.descriptor_index, 0);
    assert!(!shared.semantic_authorized);
    assert!(shared.semantic_ambiguous);
    assert_eq!(plan.module_of_slot(shared.index), None);
    assert_eq!(plan.active_module_of_slot(shared.index), None);
    assert_eq!(plan.module_ambiguous, 1);
    plan.validate_slot_index().unwrap();
}
