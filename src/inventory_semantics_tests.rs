//! SPDX-License-Identifier: GPL-3.0-or-later
//! Uses the retained-source planner and the Session's attachment/readback seam.

use super::*;
use crate::discovery::engine::inventory_coordinator::semantics::{
    SemanticInputs, engine_for_test, prepare_attested_subset,
};
use crate::discovery::identity::{PinnedObjectId, PinnedObjects, ReconciledModule};
use crate::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
use crate::inventory_semantics::{AttestedSubset, SemanticRefusal};
use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
use p11scope_manifest::manifest::*;

struct ProviderFixture {
    dir: tempfile::TempDir,
    manifest: Manifest,
    pins: PinnedObjects,
    offsets: [u64; 2],
}

impl ProviderFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.so");
        std::fs::copy("/bin/true", &path).unwrap();
        let file = open_object(&path).unwrap();
        let inspected = inspect_file(&file).unwrap();
        let mapping = mapping_file_key(&file).unwrap();
        let start = inspected
            .executable_ranges
            .iter()
            .find(|(a, b)| b - a > 2)
            .unwrap()
            .0;
        let offsets = [start, start + 1];
        let functions =
            match pkcs11_module::tables_for(pkcs11_module::Surface::LegacyFunctionList {
                version: cryptoki_sys::CK_VERSION {
                    major: 2,
                    minor: 40,
                },
            }) {
                pkcs11_module::TableSet::Walk(spans) => spans
                    .iter()
                    .flat_map(|span| span.fields())
                    .map(|field| {
                        let resolution = match field.name {
                            "C_SignInit" => Resolution::Resolved {
                                object: 0,
                                file_offset: offsets[0],
                            },
                            "C_Sign" => Resolution::Resolved {
                                object: 0,
                                file_offset: offsets[1],
                            },
                            _ => Resolution::NullPointer,
                        };
                        FunctionRecord {
                            name: field.name.into(),
                            resolution,
                        }
                    })
                    .collect(),
                _ => panic!("2.40 is a full standard table"),
            };
        let path = path.to_str().unwrap().to_string();
        let manifest = Manifest {
            schema: SCHEMA.into(),
            module_path: path.clone(),
            objects: vec![ObjectRecord {
                id: 0,
                path: path.clone(),
                identity: inspected.identity.clone(),
            }],
            provenance_objects: vec![ProvenanceObject {
                path,
                device_major: mapping.device_major,
                device_minor: mapping.device_minor,
                inode: mapping.inode,
                identity: inspected.identity,
            }],
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: Some(Version {
                    major: 2,
                    minor: 40,
                }),
                walk: WalkOutcome::Full,
                functions,
            }],
            vendor_interfaces: Vec::new(),
            alias_groups: Vec::new(),
            selection_evidence: Default::default(),
        };
        assert!(crate::manifest_input::validate_structure(&manifest).is_empty());
        let pinning = crate::discovery::identity::pin_manifest_objects_deferred(&manifest).unwrap();
        assert!(pinning.stale.is_empty());
        assert_eq!(pinning.pins.pinned().count(), 1);
        Self {
            dir,
            manifest,
            pins: pinning.pins,
            offsets,
        }
    }

    fn source(&self, names: [&'static str; 2]) -> ReconciledModule {
        let object = self.pins.pinned().next().unwrap().id;
        let key = self.pins.raw_keys_for(object)[0];
        let view =
            crate::process::ProcessView::open(crate::process::ProcessViewId(0), std::process::id())
                .unwrap();
        ReconciledModule {
            scanned: ScannedModule {
                mapped_identity: None,
                view: view.id(),
                mount_namespace: view.mount_namespace(),
                key,
                double_loaded: false,
                path: self.manifest.module_path.clone(),
                decoder_abi: None,
                exports: Vec::new(),
                interfaces: Vec::new(),
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: names
                        .into_iter()
                        .zip(self.offsets)
                        .map(|(name, file_offset)| ScannedEntry {
                            name,
                            object: key,
                            object_path: self.manifest.module_path.clone(),
                            file_offset,
                        })
                        .collect(),
                    null_entries: Vec::new(),
                    unpinned: Vec::new(),
                    address: 0,
                    file_offset: Some(0x40),
                    live_return: true,
                    manifest_supported: false,
                }],
            },
            object,
            entry_objects: vec![vec![object; 2]],
            exports: std::sync::Arc::from(Vec::new()),
        }
    }

    fn subset(&self) -> AttestedSubset {
        let path = self.write_manifest();
        let engine = engine_for_test(Vec::new(), Vec::new(), self.pins.clone());
        let prepared = prepare_attested_subset(&engine, &[path]);
        let subset = prepared.subset.expect("nonempty validated operator subset");
        assert_eq!(subset.plan().slots.len(), 2);
        assert!(
            subset
                .plan()
                .slots
                .iter()
                .all(|slot| slot.descriptor_index != 0)
        );
        subset
    }

    fn write_manifest(&self) -> PathBuf {
        let path = self.dir.path().join("operator-input.json");
        std::fs::write(&path, serde_json::to_vec(&self.manifest).unwrap()).unwrap();
        path
    }

    fn with_dependency() -> Self {
        let mut fixture = Self::new();
        let dependency = fixture.dir.path().join("dependency.so");
        std::fs::copy(&fixture.manifest.module_path, &dependency).unwrap();
        let file = open_object(&dependency).unwrap();
        let inspected = inspect_file(&file).unwrap();
        let mapping = mapping_file_key(&file).unwrap();
        let path = dependency.to_str().unwrap().to_string();
        fixture.manifest.objects.push(ObjectRecord {
            id: 1,
            path: path.clone(),
            identity: inspected.identity.clone(),
        });
        fixture.manifest.provenance_objects.push(ProvenanceObject {
            path,
            device_major: mapping.device_major,
            device_minor: mapping.device_minor,
            inode: mapping.inode,
            identity: inspected.identity,
        });
        let sign = fixture.manifest.surfaces[0]
            .functions
            .iter_mut()
            .find(|f| f.name == "C_Sign")
            .unwrap();
        sign.resolution = Resolution::Resolved {
            object: 1,
            file_offset: fixture.offsets[1],
        };
        assert!(crate::manifest_input::validate_structure(&fixture.manifest).is_empty());
        let pinned =
            crate::discovery::identity::pin_manifest_objects_deferred(&fixture.manifest).unwrap();
        assert!(pinned.stale.is_empty());
        assert_eq!(pinned.pins.pinned().count(), 2);
        fixture.pins = pinned.pins;
        fixture
    }

    fn over_capacity_inputs(&self) -> (crate::discovery::engine::Engine, PathBuf, u64) {
        let mut manifest = self.manifest.clone();
        manifest.interface_list = Acquisition::Ok;
        let fields = match pkcs11_module::tables_for(pkcs11_module::Surface::StandardInterface {
            version: cryptoki_sys::CK_VERSION { major: 3, minor: 2 },
        }) {
            pkcs11_module::TableSet::Walk(spans) => spans
                .iter()
                .flat_map(|span| span.fields())
                .map(|field| field.name)
                .collect::<Vec<_>>(),
            _ => panic!("3.2 is a full standard interface"),
        };
        let mut offset = self.offsets[0] + 200;
        for index in 0..6 {
            let functions = fields
                .iter()
                .map(|name| {
                    let function = FunctionRecord {
                        name: (*name).into(),
                        resolution: Resolution::Resolved {
                            object: 0,
                            file_offset: offset,
                        },
                    };
                    offset += 1;
                    function
                })
                .collect();
            manifest.surfaces.push(SurfaceRecord {
                source: SurfaceSource::Interface {
                    index,
                    raw_name_hex: Some("504b4353203131".into()),
                    name_lossy: Some("PKCS 11".into()),
                    name_error: None,
                    flags: 0,
                    classification: InterfaceClassification::ExactStandard,
                },
                acquisition: Acquisition::Ok,
                version: Some(Version { major: 3, minor: 2 }),
                walk: WalkOutcome::Full,
                functions,
            });
        }
        assert!(crate::manifest_input::validate_structure(&manifest).is_empty());
        let path = self.dir.path().join("large-operator-input.json");
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let mut source = self.source(["C_SignInit", "C_Sign"]);
        let key = source.scanned.key;
        for (index, surface) in manifest.surfaces.iter().skip(1).enumerate() {
            let entries = surface
                .functions
                .iter()
                .map(|function| {
                    let Resolution::Resolved { file_offset, .. } = function.resolution else {
                        unreachable!()
                    };
                    let name = fields.iter().find(|name| **name == function.name).unwrap();
                    ScannedEntry {
                        name,
                        object: key,
                        object_path: self.manifest.module_path.clone(),
                        file_offset,
                    }
                })
                .collect::<Vec<_>>();
            source
                .entry_objects
                .push(vec![source.object; entries.len()]);
            source.scanned.tables.push(ScannedTable {
                version: (3, 2),
                walk: "full",
                entries,
                null_entries: Vec::new(),
                unpinned: Vec::new(),
                address: 0,
                file_offset: Some(0x80 + index as u64 * 0x400),
                live_return: false,
                manifest_supported: false,
            });
        }
        // A published affecting endpoint without an operator claim is required
        // too. It cannot vanish merely because the selected plan hit capacity.
        let count_only = offset + 100;
        source.entry_objects.push(vec![source.object]);
        source.scanned.tables.push(ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![ScannedEntry {
                name: "C_SignUpdate",
                object: key,
                object_path: self.manifest.module_path.clone(),
                file_offset: count_only,
            }],
            null_entries: Vec::new(),
            unpinned: Vec::new(),
            address: 0,
            file_offset: Some(0x2400),
            live_return: false,
            manifest_supported: false,
        });
        (
            engine_for_test(Vec::new(), vec![source], self.pins.clone()),
            path,
            count_only,
        )
    }

    fn inputs(
        &self,
        subset: &AttestedSubset,
    ) -> (
        BTreeMap<u32, RetainedStaticTarget>,
        BTreeSet<StaticEndpoint>,
    ) {
        // Actual return-first attach scheduling and retention; only link I/O is scripted.
        let outcome = attach_targets_with(
            subset.plan().slots.as_slice(),
            CapturePolicy::Allowlisted,
            false,
            |slot| Ok(subset.pins().abi_for(slot.object).unwrap()),
            |_, _, _| Ok(()),
            |_| Some(1),
        )
        .unwrap();
        let targets = subset
            .plan()
            .slots
            .iter()
            .map(|slot| {
                (
                    slot.index,
                    (
                        subset.pins().attach_path_for(slot.object).unwrap(),
                        subset.pins().abi_for(slot.object).unwrap(),
                    ),
                )
            })
            .collect();
        let mut retained = BTreeMap::new();
        retain_from_successful(
            &mut retained,
            &subset.plan().slots,
            &targets,
            &outcome.successful,
        );
        assert_eq!(outcome.completed.len(), 2);
        (retained, outcome.successful)
    }

    fn watched(
        &self,
        object: PinnedObjectId,
    ) -> Option<crate::discovery::identity::RetainedInventoryTarget> {
        self.pins.retain_inventory_target(object).ok()
    }
}

#[test]
fn native_semantic_manifest_repeatable_and_mixed_refusal_preserves_counts() {
    let fixture = ProviderFixture::new();
    let valid = fixture.dir.path().join("accepted.json");
    std::fs::write(&valid, serde_json::to_vec(&fixture.manifest).unwrap()).unwrap();
    let invalid = fixture.dir.path().join("invalid.json");
    std::fs::write(&invalid, b"{\"schema\":\"wrong\"}").unwrap();
    let args = [
        "inventory",
        "--pid",
        "42",
        "--manifest",
        valid.to_str().unwrap(),
        "--manifest",
        invalid.to_str().unwrap(),
    ];
    let parsed = crate::cli::parse(args.into_iter().map(std::ffi::OsString::from));
    let Ok(crate::cli::Command::Inventory(args)) = parsed else {
        panic!("repeatable manifests: {parsed:?}");
    };
    assert_eq!(args.manifests, vec![valid.clone(), invalid.clone()]);
    let engine = engine_for_test(
        Vec::new(),
        vec![fixture.source(["C_SignInit", "C_Sign"])],
        fixture.pins.clone(),
    );
    let before = engine.plan().clone();
    assert_eq!(
        before.slots.len(),
        2,
        "broad physical endpoints are nonempty"
    );
    let without_input = prepare_attested_subset(&engine, &[]);
    let refused_input = prepare_attested_subset(&engine, std::slice::from_ref(&invalid));
    let prepared = prepare_attested_subset(&engine, &[valid, invalid]);
    assert!(
        prepared.subset.is_some(),
        "valid provider survives another input's refusal"
    );
    assert_eq!(prepared.refusals, vec![SemanticRefusal::ManifestInput]);
    assert!(
        without_input.subset.is_none(),
        "same retained scan without explicit input cannot attest"
    );
    assert!(
        refused_input.subset.is_none(),
        "refused input cannot attest the retained scan"
    );
    assert_eq!(
        engine.plan(),
        &before,
        "semantic refusal cannot rewrite physical counts/admission"
    );
}

#[test]
fn native_semantic_manifest_input_retains_original_after_replacement() {
    let fixture = ProviderFixture::new();
    let path = fixture.write_manifest();
    let engine = engine_for_test(
        Vec::new(),
        vec![fixture.source(["C_SignInit", "C_Sign"])],
        fixture.pins.clone(),
    );
    let before = engine.plan().clone();
    let mut inputs = SemanticInputs::new(vec![path.clone()]);
    let original = inputs
        .prepare(&engine)
        .subset
        .expect("actual explicit input produces a nonempty subset");
    assert_eq!(original.plan().slots.len(), 2);
    let removed = fixture.dir.path().join("original-input.json");
    std::fs::rename(&path, &removed).unwrap();
    std::fs::write(&path, b"{\"schema\":\"replacement-is-not-attestation\"}").unwrap();
    let replaced = inputs.prepare(&engine);
    assert!(
        replaced.subset.is_some(),
        "pathname replacement cannot replace the retained explicit source"
    );
    assert_eq!(replaced.subset.unwrap().plan(), original.plan());
    std::fs::remove_file(&removed).unwrap();
    std::fs::remove_file(&path).unwrap();
    let unlinked = inputs.prepare(&engine);
    assert!(
        unlinked.subset.is_some(),
        "unlink does not erase accepted immutable input and held provider pins"
    );
    assert_eq!(unlinked.subset.unwrap().plan(), original.plan());
    assert_eq!(engine.plan(), &before);
}

#[test]
fn native_semantic_unreadable_acquired_surface_refuses_whole_provider() {
    let mut fixture = ProviderFixture::new();
    let interface = SurfaceRecord {
        source: SurfaceSource::Interface {
            index: 0,
            raw_name_hex: Some("504b4353203131".into()),
            name_lossy: Some("PKCS 11".into()),
            name_error: None,
            flags: 0,
            classification: InterfaceClassification::ExactStandard,
        },
        acquisition: Acquisition::Ok,
        version: Some(Version { major: 3, minor: 0 }),
        walk: WalkOutcome::Full,
        functions: pkcs11_module::FUNCTION_LIST_FIELDS
            .iter()
            .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
            .map(|field| FunctionRecord {
                name: field.name.into(),
                resolution: Resolution::NullPointer,
            })
            .collect(),
    };
    fixture.manifest.interface_list = Acquisition::Ok;
    fixture.manifest.surfaces.push(interface);
    let engine = engine_for_test(
        Vec::new(),
        vec![fixture.source(["C_SignInit", "C_Sign"])],
        fixture.pins.clone(),
    );
    let before = engine.plan().clone();
    assert!(crate::manifest_input::validate_structure(&fixture.manifest).is_empty());
    let positive = prepare_attested_subset(&engine, &[fixture.write_manifest()]);
    assert_eq!(positive.subset.unwrap().plan().slots.len(), 2);
    let mut admitted = Vec::new();
    for (label, walk, version) in [
        (
            "unreadable",
            WalkOutcome::Unreadable {
                detail: "acquired standard table could not be read".into(),
            },
            None,
        ),
        ("not_walked", WalkOutcome::NotWalked, None),
        (
            "refused_layout",
            WalkOutcome::Refused,
            Some(Version {
                major: 2,
                minor: 30,
            }),
        ),
    ] {
        let surface = &mut fixture.manifest.surfaces[1];
        surface.walk = walk;
        surface.version = version;
        surface.functions.clear();
        assert!(
            crate::manifest_input::validate_structure(&fixture.manifest).is_empty(),
            "{label} is a valid retained input, not a parser rejection"
        );
        let prepared = prepare_attested_subset(&engine, &[fixture.write_manifest()]);
        if prepared.subset.is_some() {
            admitted.push(label);
        } else {
            assert_eq!(prepared.refusals, vec![SemanticRefusal::IncompleteProvider]);
        }
        assert_eq!(engine.plan(), &before);
    }
    assert!(
        admitted.is_empty(),
        "acquired missing tables cannot vanish from whole-provider requirements: {admitted:?}"
    );
}

fn selection_only_evidence(name: &str, offset: u64) -> SelectionEvidence {
    let functions = pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .map(|field| FunctionRecord {
            name: field.name.into(),
            resolution: if field.name == name {
                Resolution::Resolved {
                    object: 0,
                    file_offset: offset,
                }
            } else {
                Resolution::NullPointer
            },
        })
        .collect();
    let mut queries = Vec::new();
    for selector in 0..5 {
        for flags in 0..=1 {
            let (name, version) = match selector {
                0 => (SelectionNameClass::Null, SelectionVersionClass::Null),
                1 => (
                    SelectionNameClass::ExactStandard,
                    SelectionVersionClass::Null,
                ),
                2 => (
                    SelectionNameClass::ExactStandard,
                    SelectionVersionClass::V3_0,
                ),
                3 => (
                    SelectionNameClass::ExactStandard,
                    SelectionVersionClass::V3_1,
                ),
                _ => (
                    SelectionNameClass::ExactStandard,
                    SelectionVersionClass::V3_2,
                ),
            };
            let request = SelectionRequest {
                name,
                version,
                flags,
            };
            let reachable = selector == 2 && flags == 0;
            queries.push(SelectionQuery {
                selector,
                request,
                rv: if reachable { 0 } else { 1 },
                result: reachable.then_some(request),
                inventory_matches: Vec::new(),
                selection_table: reachable.then_some(0),
                authority: if reachable {
                    SelectionAuthority::SelectionCountOnly
                } else {
                    SelectionAuthority::None
                },
                helper_failure: None,
            });
        }
    }
    SelectionEvidence {
        acquisition: SelectionAcquisition::Queried,
        queries,
        tables: vec![SelectionTable {
            id: 0,
            version: Version { major: 3, minor: 0 },
            walk: WalkOutcome::Full,
            functions,
            semantic_authorized: false,
        }],
        selection_truncated: false,
    }
}

#[test]
fn native_semantic_reachable_selection_preserves_demand_and_rivals() {
    let mut fixture = ProviderFixture::new();
    let engine = engine_for_test(
        Vec::new(),
        vec![fixture.source(["C_SignInit", "C_Sign"])],
        fixture.pins.clone(),
    );
    let before = engine.plan().clone();
    let positive = prepare_attested_subset(&engine, &[fixture.write_manifest()]);
    assert_eq!(positive.subset.unwrap().plan().slots.len(), 2);
    let mut omitted = Vec::new();
    for (label, offset) in [
        ("additional_endpoint", fixture.offsets[1] + 1),
        ("unattested_alias", fixture.offsets[1]),
    ] {
        fixture.manifest.selection_evidence = selection_only_evidence("C_SignUpdate", offset);
        assert!(
            crate::manifest_input::validate_structure(&fixture.manifest).is_empty(),
            "reachable selection-only table uses the accepted full canonical layout"
        );
        let prepared = prepare_attested_subset(&engine, &[fixture.write_manifest()]);
        if let Some(subset) = prepared.subset {
            if !subset.plan().slots.iter().any(|slot| {
                slot.file_offset == offset
                    && slot.descriptor_index == 0
                    && !slot.semantic_authorized
            }) {
                omitted.push(label);
            }
        } else {
            assert_eq!(prepared.refusals, vec![SemanticRefusal::IncompleteProvider]);
        }
        assert_eq!(engine.plan(), &before);
    }
    assert!(
        omitted.is_empty(),
        "reachable selection endpoints and negative alias claims cannot disappear: {omitted:?}"
    );
}

#[test]
fn native_semantic_names_never_attest() {
    let fixture = ProviderFixture::new();
    let positive = fixture.subset();
    assert_eq!(positive.required().len(), 1);
    let scan = fixture.source(["C_SignInit", "C_Sign"]);
    let engine = engine_for_test(Vec::new(), vec![scan], fixture.pins.clone());
    assert_eq!(engine.plan().slots.len(), 2);
    let prepared = prepare_attested_subset(&engine, &[]);
    assert!(
        prepared.subset.is_none(),
        "published scan names are count authority only"
    );
    assert_eq!(prepared.refusals, vec![SemanticRefusal::Unattested]);
}

#[test]
fn native_semantic_attached_receipt_rejects_foreign_or_forged_slot() {
    let fixture = ProviderFixture::new();
    let subset = fixture.subset();
    let (retained, sides) = fixture.inputs(&subset);
    let domain = crate::attach::capture::NativeDomainId::mint();
    let receipt = seal_attached_subset_with(
        subset,
        domain,
        CapturePolicy::Allowlisted,
        Ok(crate::kinds::DESCRIPTORS.to_vec()),
        &retained,
        &sides,
        |id| fixture.watched(id),
    )
    .unwrap();
    assert!(
        receipt
            .validate_with(
                domain,
                CapturePolicy::Allowlisted,
                Ok(crate::kinds::DESCRIPTORS.to_vec()),
                &retained,
                &sides,
                |id| fixture.watched(id)
            )
            .is_ok()
    );
    let foreign = crate::attach::capture::NativeDomainId::mint();
    let mut refused = vec![(
        "foreign Session",
        receipt
            .validate_with(
                foreign,
                CapturePolicy::Allowlisted,
                Ok(crate::kinds::DESCRIPTORS.to_vec()),
                &retained,
                &sides,
                |id| fixture.watched(id),
            )
            .is_err(),
    )];
    for mutation in 0..3 {
        let mut forged = retained.clone();
        let target = forged.values_mut().next().unwrap();
        match mutation {
            0 => target.slot.file_offset += 1,
            1 => target.slot.descriptor_index = 0,
            _ => target.slot.object = PinnedObjectId(u32::MAX),
        }
        refused.push((
            "forged retained target",
            receipt
                .validate_with(
                    domain,
                    CapturePolicy::Allowlisted,
                    Ok(crate::kinds::DESCRIPTORS.to_vec()),
                    &forged,
                    &sides,
                    |id| fixture.watched(id),
                )
                .is_err(),
        ));
    }
    for fault in 0..3 {
        let bad_readback = || {
            if fault == 0 {
                return Err(anyhow!("injected descriptor readback failure"));
            }
            let mut values = crate::kinds::DESCRIPTORS.to_vec();
            if fault == 1 {
                values.pop();
            } else {
                values[retained.values().next().unwrap().slot.descriptor_index as usize] =
                    SlotSemantics::COUNT_ONLY;
            }
            Ok(values)
        };
        refused.push((
            "failed/short/changed initial readback",
            seal_attached_subset_with(
                fixture.subset(),
                domain,
                CapturePolicy::Allowlisted,
                bad_readback(),
                &retained,
                &sides,
                |id| fixture.watched(id),
            )
            .is_err(),
        ));
        refused.push((
            "failed/short/changed final readback",
            receipt
                .validate_with(
                    domain,
                    CapturePolicy::Allowlisted,
                    bad_readback(),
                    &retained,
                    &sides,
                    |id| fixture.watched(id),
                )
                .is_err(),
        ));
    }
    for policy in [
        CapturePolicy::AggregateOnly,
        CapturePolicy::UnsafeUnvalidatedMetadata,
    ] {
        refused.push((
            "initial nonallowlisted policy",
            seal_attached_subset_with(
                fixture.subset(),
                domain,
                policy,
                Ok(crate::kinds::DESCRIPTORS.to_vec()),
                &retained,
                &sides,
                |id| fixture.watched(id),
            )
            .is_err(),
        ));
        refused.push((
            "final nonallowlisted policy",
            receipt
                .validate_with(
                    domain,
                    policy,
                    Ok(crate::kinds::DESCRIPTORS.to_vec()),
                    &retained,
                    &sides,
                    |id| fixture.watched(id),
                )
                .is_err(),
        ));
    }
    assert!(
        refused.iter().all(|(_, refused)| *refused),
        "refusal controls: {refused:?}"
    );
}

#[test]
fn native_semantic_partial_affecting_set_refuses() {
    let fixture = ProviderFixture::new();
    let complete = fixture.subset();
    let (retained, sides) = fixture.inputs(&complete);
    let domain = crate::attach::capture::NativeDomainId::mint();
    assert!(
        seal_attached_subset_with(
            complete,
            domain,
            CapturePolicy::Allowlisted,
            Ok(crate::kinds::DESCRIPTORS.to_vec()),
            &retained,
            &sides,
            |id| fixture.watched(id)
        )
        .is_ok()
    );
    let (engine, path, count_only) = fixture.over_capacity_inputs();
    let before = engine.plan().clone();
    assert!(
        before.slots.len() > p11scope_ebpf_common::MAX_SLOTS as usize,
        "complete provider claims exceed the actual Detailed capacity"
    );
    assert!(
        before
            .slots
            .iter()
            .any(|slot| slot.file_offset == count_only && slot.descriptor_index == 0),
        "the pre-admission population contains the required count-only affecting endpoint"
    );
    let too_large_manifest = prepare_attested_subset(&engine, &[path]);
    assert!(
        too_large_manifest.subset.is_none(),
        "existing planner already refuses an operator manifest that itself exceeds capacity whole"
    );
    let prepared = prepare_attested_subset(&engine, &[fixture.write_manifest()]);
    if let Some(subset) = &prepared.subset {
        assert!(
            !subset.plan().slots.is_empty(),
            "actual planner admitted a nonempty operator prefix"
        );
        assert!(subset.plan().slots.len() < before.slots.len());
        assert!(
            !subset
                .plan()
                .slots
                .iter()
                .any(|slot| slot.file_offset == count_only),
            "actual prefix omitted the independently required count-only endpoint"
        );
    }
    assert!(
        prepared.subset.is_none(),
        "required claims must be preserved before admission; plan.slots cannot certify its own truncated prefix"
    );
    assert_eq!(
        engine.plan(),
        &before,
        "Detailed refusal cannot change broad physical claims"
    );
    for missing in 0..2 {
        let subset = fixture.subset();
        let (mut partial, mut sides) = fixture.inputs(&subset);
        if missing == 0 {
            partial.pop_last();
        } else {
            sides.pop_last();
        }
        assert!(
            seal_attached_subset_with(
                subset,
                domain,
                CapturePolicy::Allowlisted,
                Ok(crate::kinds::DESCRIPTORS.to_vec()),
                &partial,
                &sides,
                |id| fixture.watched(id)
            )
            .is_err(),
            "one retained endpoint/side missing must refuse the whole affecting set"
        );
    }
    for missing in 0..3 {
        let mut unresolved = ProviderFixture::new();
        let mut source = unresolved.source(["C_SignInit", "C_Sign"]);
        if missing < 2 {
            for function in &mut unresolved.manifest.surfaces[0].functions {
                if function.name == "C_SignUpdate" {
                    function.resolution = if missing == 0 {
                        Resolution::Unmapped
                    } else {
                        Resolution::UnusableFile {
                            reason: "null pointer".into(),
                            path_hex: String::new(),
                        }
                    };
                }
            }
        } else {
            source.scanned.tables[0]
                .unpinned
                .push(crate::plan::Skipped {
                    subject: "C_SignUpdate".into(),
                    reason: "no retained file identity for non-null affecting target".into(),
                });
        }
        assert!(crate::manifest_input::validate_structure(&unresolved.manifest).is_empty());
        let engine = engine_for_test(Vec::new(), vec![source], unresolved.pins.clone());
        let before = engine.plan().clone();
        assert_eq!(before.slots.len(), 2, "known endpoints remain nonempty");
        let prepared = prepare_attested_subset(&engine, &[unresolved.write_manifest()]);
        assert!(
            prepared.subset.is_none(),
            "a non-null affecting manifest/scan entry without a retained target cannot silently disappear"
        );
        assert_eq!(prepared.refusals, vec![SemanticRefusal::IncompleteProvider]);
        assert_eq!(engine.plan(), &before);
    }
}

#[test]
fn native_semantic_unattested_overlap_stays_count_only() {
    let fixture = ProviderFixture::new();
    assert_eq!(fixture.subset().plan().slots.len(), 2);
    // A second physical provider publishes the same two targets. Selecting the
    // operator-attested first provider must not erase this unattested rival.
    let other = ProviderFixture::new();
    let mut pins = fixture.pins.clone();
    assert!(pins.absorb(other.pins.clone()).is_empty());
    assert_eq!(pins.pinned().count(), 2);
    let first_object = fixture.pins.pinned().next().unwrap().id;
    let target_key = pins.raw_keys_for(first_object)[0];
    let mut rival = other.source(["C_SignInit", "C_Sign"]);
    rival.object = pins
        .id_for_manifest(rival.scanned.key, &rival.scanned.path)
        .unwrap();
    assert_ne!(rival.object, first_object);
    rival.entry_objects = vec![vec![first_object; 2]];
    for entry in &mut rival.scanned.tables[0].entries {
        entry.object = target_key;
        entry.object_path = fixture.manifest.module_path.clone();
    }
    let path = fixture.write_manifest();
    let engine = engine_for_test(
        Vec::new(),
        vec![fixture.source(["C_SignInit", "C_Sign"]), rival],
        pins,
    );
    let before = engine.plan().clone();
    let prepared = prepare_attested_subset(&engine, &[path]);
    assert!(
        prepared.subset.is_none(),
        "attested selection cannot erase a rival or claim a complete affecting set"
    );
    assert_eq!(prepared.refusals, vec![SemanticRefusal::IncompleteProvider]);
    assert_eq!(engine.plan(), &before);
    assert_eq!(before.slots.len(), 2);
    assert_eq!(before.modules.len(), 2);
    assert!(before.slots.iter().all(|slot| slot.module_ids.len() == 2));
}

#[test]
fn native_semantic_provider_pin_must_equal_watched_pin() {
    let fixture = ProviderFixture::new();
    let domain = crate::attach::capture::NativeDomainId::mint();
    let subset = fixture.subset();
    let (retained, sides) = fixture.inputs(&subset);
    assert!(
        seal_attached_subset_with(
            subset,
            domain,
            CapturePolicy::Allowlisted,
            Ok(crate::kinds::DESCRIPTORS.to_vec()),
            &retained,
            &sides,
            |id| fixture.watched(id)
        )
        .is_ok()
    );
    let dependency = ProviderFixture::with_dependency();
    let subset = dependency.subset();
    let (retained, sides) = dependency.inputs(&subset);
    assert!(
        seal_attached_subset_with(
            subset,
            domain,
            CapturePolicy::Allowlisted,
            Ok(crate::kinds::DESCRIPTORS.to_vec()),
            &retained,
            &sides,
            |id| dependency.watched(id)
        )
        .is_err(),
        "a provider's table entry in a dependency cannot prove its own load instance"
    );
    // Byte-identical ELF and reused capture-local ID are not the held provider.
    let other = ProviderFixture::new();
    assert_eq!(
        fixture.pins.pinned().next().unwrap().id,
        other.pins.pinned().next().unwrap().id
    );
    assert_eq!(
        fixture.manifest.objects[0].identity,
        other.manifest.objects[0].identity
    );
    let subset = fixture.subset();
    let (retained, sides) = fixture.inputs(&subset);
    assert!(
        seal_attached_subset_with(
            subset,
            domain,
            CapturePolicy::Allowlisted,
            Ok(crate::kinds::DESCRIPTORS.to_vec()),
            &retained,
            &sides,
            |id| other.watched(id)
        )
        .is_err(),
        "equal bytes/different inode and equal local ID cannot supply provider identity"
    );
    let subset = fixture.subset();
    let (retained, sides) = fixture.inputs(&subset);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&fixture.manifest.module_path)
        .unwrap()
        .set_len(1)
        .unwrap();
    assert!(
        seal_attached_subset_with(
            subset,
            domain,
            CapturePolicy::Allowlisted,
            Ok(crate::kinds::DESCRIPTORS.to_vec()),
            &retained,
            &sides,
            |id| fixture.watched(id)
        )
        .is_err(),
        "stale held pin"
    );
}
