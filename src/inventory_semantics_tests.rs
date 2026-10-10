//! SPDX-License-Identifier: GPL-3.0-or-later
//! Uses the retained-source planner and the Session's attachment/readback seam.

use super::*;
use crate::discovery::engine::inventory_coordinator::semantics::{
    SemanticInputs, engine_for_test, prepare_attested_subset,
};
use crate::discovery::identity::{PinnedObjectId, PinnedObjects, ReconciledModule};
use crate::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
use crate::inventory_semantics::{
    AttestedSubset, LaneDrainOutcome, SemanticCaptureStatus, SemanticCaptureSummary,
    SemanticRefusal, SemanticStopIo, SemanticStopQuiescence,
};
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

// ---- H3 Task 3: retained-custody caller bindings ----

use crate::attach::Scope;
use crate::attach::capture::{
    CaptureHealth, CapturePhase, CookieQuery, DiscoveryBatch, DomainCookie, ExecCoverage,
    ExtendReceipt, NativeDomainId, ScopeCustody, WitnessBatch, WitnessRow,
};
use crate::discovery::caller_registry::{
    AdmissionState, CallerId, ImageAuthority, MappingState, ModuleInfo, ModuleKey, OsProcessSource,
    RegistryLimits,
};
use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;
use crate::discovery::engine::inventory_coordinator::NativeBatch;
use crate::discovery::engine::inventory_coordinator::semantics::SemanticBindingRefusal;
use crate::discovery::hooks::HookRegistry;
use crate::discovery::instances::{MAX_INSTANCES, MAX_PENDING};
use crate::discovery::inventory_attach_set::{AttachObjectId, EndpointId};
use crate::discovery::native_binding::{NativeIdentity, UnboundReason};
use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
use crate::process::PidPin;
use p11scope_ebpf_common::ImageIdentity;
use std::collections::HashMap;

/// Scripted cookie answers keyed by pid: the query travels through the
/// retained pin, the answer is programmed per domain. Queries are logged
/// so tests prove which domain's evidence actually decided.
#[derive(Default)]
struct ScriptedPidIdentity {
    answers: HashMap<(u32, NativeDomainId), CookieQuery>,
    queries: Vec<(u32, NativeDomainId)>,
}

impl NativeIdentity<PidPin> for ScriptedPidIdentity {
    fn owner_image(&mut self, _pid: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        self.queries.push((pin.pid(), domain));
        self.answers
            .get(&(pin.pid(), domain))
            .cloned()
            .unwrap_or(CookieQuery::NoCookie)
    }
}

std::thread_local! {
    static SIGHT_NS: std::cell::Cell<u64> = const { std::cell::Cell::new(1_005) };
}

fn sight_clock() -> Option<u64> {
    SIGHT_NS.with(|clock| Some(clock.get()))
}

fn set_sight(ns: u64) {
    SIGHT_NS.with(|clock| clock.set(ns));
}

struct BindingScene {
    coordinator: InventoryCoordinator<OsProcessSource>,
    identity: ScriptedPidIdentity,
    detailed: NativeDomainId,
    inventory: NativeDomainId,
    foreign: NativeDomainId,
    module: ModuleKey,
}

fn stage_witness_read(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    identity: &mut ScriptedPidIdentity,
    domain: NativeDomainId,
    rows: Vec<WitnessRow>,
    at_ns: u64,
) {
    let batch = WitnessBatch {
        domain,
        phase: CapturePhase::Active,
        rows,
        integrity: Vec::new(),
        integrity_total: 0,
        visited: 0,
        sweep_completed: true,
        sweeps_completed: 1,
        row_bound_reached: false,
        deadline_reached: false,
        read_failures: Vec::new(),
        unrecorded_rows: 0,
        sweep_gaps: false,
        counts: Vec::new(),
        refresh_sweep_completed: true,
        refresh_sweep_gaps: false,
        refresh_deadline_reached: false,
        refresh_sweeps_completed: 1,
        seen_rows: 0,
        pair_limit: 65_536,
        health: CaptureHealth {
            discovery_counters: Some([0; 5]),
            ..CaptureHealth::default()
        },
        health_regression: None,
        health_unproven: None,
        health_baseline_ns: 0,
        health_read_ns: at_ns,
        rows_anchor_ns: at_ns + 1,
        rows_read_ns: at_ns + 1,
        counts_read_ns: at_ns + 1,
        changed_objects: Vec::new(),
        custody: ScopeCustody::System,
        custody_proven_ns: None,
        lifecycle_proven_ns: u64::MAX,
        lifecycle_loss: None,
        unsettled: false,
    };
    coordinator.stage_native(NativeBatch::Witness(Box::new(batch)), identity, at_ns + 2);
}

fn stage_lifecycle_drain(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    identity: &mut ScriptedPidIdentity,
    domain: NativeDomainId,
    at_ns: u64,
) {
    let batch = DiscoveryBatch::scripted(domain, Vec::new(), at_ns);
    coordinator.stage_native(NativeBatch::Lifecycle(batch), identity, at_ns + 1);
}

impl BindingScene {
    fn new() -> Self {
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let detailed = NativeDomainId::mint();
        let inventory = NativeDomainId::mint();
        let foreign = NativeDomainId::mint();
        for domain in [detailed, inventory, foreign] {
            coordinator.note_extend_receipt(&ExtendReceipt {
                activated_roots: true,
                exec_coverage: Some(ExecCoverage::scripted(domain, 0)),
                ..ExtendReceipt::default()
            });
        }
        coordinator.set_semantic_binding_clock(sight_clock);
        Self {
            coordinator,
            identity: ScriptedPidIdentity::default(),
            detailed,
            inventory,
            foreign,
            // Mapping-key consistency is what matters here, not the
            // filesystem: nonzero so the key is identifiable.
            module: ModuleKey::physical(7, 7, 777, None, "/task3/provider.so"),
        }
    }

    fn admit(&mut self, pid: u32, at_ns: u64) -> CallerId {
        self.coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, at_ns)
            .unwrap()
    }

    fn map(&mut self, caller: CallerId, pid: u32, at_ns: u64) {
        let info = ModuleInfo {
            path: "/task3/provider.so".into(),
            key: self.module.clone(),
            double_loaded: false,
            build_id: None,
            identity_source: Some("task3".into()),
            admission: AdmissionState::Admitted,
            admission_class: Some("exact".into()),
            admission_endpoints: Some(1),
            admission_reasons: Vec::new(),
        };
        self.coordinator
            .registry_mut()
            .note_mapping(caller, pid, info, at_ns);
        self.coordinator.commit_batch(false).unwrap();
    }

    fn answer(&mut self, pid: u32, domain: NativeDomainId, ticket: u64) {
        self.identity.answers.insert(
            (pid, domain),
            CookieQuery::Cookie(DomainCookie::scripted(domain, ticket)),
        );
    }

    fn witness_read(&mut self, domain: NativeDomainId, rows: Vec<WitnessRow>, at_ns: u64) {
        let Self {
            coordinator,
            identity,
            ..
        } = self;
        stage_witness_read(coordinator, identity, domain, rows, at_ns);
    }

    fn drain(&mut self, domain: NativeDomainId, at_ns: u64) {
        let Self {
            coordinator,
            identity,
            ..
        } = self;
        stage_lifecycle_drain(coordinator, identity, domain, at_ns);
    }

    /// Rows, then both horizons, then publish: decided by return.
    fn bind_image(&mut self, domain: NativeDomainId, rows: Vec<(u64, u64, u32, u64)>, at_ns: u64) {
        let rows = rows
            .into_iter()
            .map(|(ticket, exec, tgid, t0)| {
                WitnessRow::scripted(
                    domain,
                    ticket,
                    exec,
                    AttachObjectId::scripted(0),
                    EndpointId(0),
                    tgid,
                    t0,
                )
            })
            .collect();
        self.witness_read(domain, rows, at_ns);
        self.drain(domain, at_ns + 10);
        self.witness_read(domain, Vec::new(), at_ns + 20);
        self.coordinator.commit_batch(false).unwrap();
    }

    fn bind(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        domain: NativeDomainId,
        image: ImageIdentity,
    ) -> Result<(), SemanticBindingRefusal> {
        let Self {
            coordinator,
            identity,
            ..
        } = self;
        coordinator.bind_semantic_caller(caller, module.clone(), domain, image, identity)
    }

    fn detailed_queries(&self) -> usize {
        self.identity
            .queries
            .iter()
            .filter(|(_, domain)| *domain == self.detailed)
            .count()
    }
}

#[test]
fn native_semantic_domain_binding_uses_retained_custody() {
    assert_eq!(MAX_PENDING, 1_024, "one tick serves at most 1,024 targets");
    assert_eq!(
        MAX_INSTANCES, 4_096,
        "the default binding cap holds 4,096 callers"
    );
    set_sight(1_005);
    let mut scene = BindingScene::new();
    let pid = std::process::id();
    let module = scene.module.clone();
    let (detailed, inventory, foreign) = (scene.detailed, scene.inventory, scene.foreign);
    let caller = scene.admit(pid, 50);
    scene.map(caller, pid, 60);
    let mid = scene.coordinator.registry().module_id_for(&module).unwrap();
    assert_eq!(
        scene
            .coordinator
            .registry()
            .edge(caller, mid)
            .unwrap()
            .mapping,
        MappingState::Mapped,
        "complete mapping transaction first"
    );
    let image = ImageIdentity {
        task_cookie: 7,
        exec_id: 1,
    };

    // Equal numeric cookies in the Inventory producer never bridge: the
    // Detailed binding refuses with no Detailed image bound and no query.
    scene.answer(pid, inventory, 7);
    scene.bind_image(inventory, vec![(7, 1, pid, 100)], 1_000);
    assert_eq!(
        scene.bind(caller, &module, detailed, image),
        Err(SemanticBindingRefusal::ImageUnproven(
            UnboundReason::ExecAmbiguous
        )),
        "Inventory-bound cookie 7 cannot satisfy a Detailed binding"
    );
    assert_eq!(
        scene.detailed_queries(),
        0,
        "no Detailed evidence was even consulted"
    );

    // An undecided Detailed row is not proof either: pending rows wait.
    scene.answer(pid, detailed, 7);
    let row = WitnessRow::scripted(
        detailed,
        7,
        1,
        AttachObjectId::scripted(0),
        EndpointId(0),
        pid,
        100,
    );
    scene.witness_read(detailed, vec![row], 2_000);
    assert_eq!(
        scene.bind(caller, &module, detailed, image),
        Err(SemanticBindingRefusal::ImageUnproven(
            UnboundReason::ExecAmbiguous
        )),
        "pending Detailed rows are not a bound image"
    );

    // A foreign producer binding the same numeric cookie changes nothing.
    scene.answer(pid, foreign, 7);
    scene.bind_image(foreign, vec![(7, 1, pid, 100)], 3_000);
    assert_eq!(
        scene.bind(caller, &module, detailed, image),
        Err(SemanticBindingRefusal::ImageUnproven(
            UnboundReason::ExecAmbiguous
        )),
        "foreign-bound cookie 7 cannot satisfy a Detailed binding"
    );

    // The Detailed domain's own decided image binds the correct caller.
    scene.drain(detailed, 2_010);
    scene.witness_read(detailed, Vec::new(), 2_020);
    scene.coordinator.commit_batch(false).unwrap();
    let before = scene.detailed_queries();
    assert_eq!(scene.bind(caller, &module, detailed, image), Ok(()));
    assert_eq!(
        scene.detailed_queries() - before,
        2,
        "sight, mapping read, re-sight: the mapping is bracketed by two fresh queries"
    );
    let bound = scene
        .coordinator
        .semantic_bindings()
        .get(caller)
        .expect("accepted binding is retained");
    assert_eq!(bound.caller(), caller);
    assert_eq!(bound.module(), &module);
    assert_eq!(bound.domain(), detailed);
    assert_eq!(bound.image(), image);

    // Re-proving reuses the one stable Arc: no second duplication.
    let stable = bound.pin();
    let before = scene.detailed_queries();
    assert_eq!(scene.bind(caller, &module, detailed, image), Ok(()));
    assert_eq!(
        scene.detailed_queries() - before,
        2,
        "reuse still requires fresh same-custody evidence"
    );
    assert!(
        Arc::ptr_eq(
            &stable,
            &scene
                .coordinator
                .semantic_bindings()
                .get(caller)
                .unwrap()
                .pin()
        ),
        "one stable Arc per accepted caller"
    );

    // A wrong physical target refuses: a fresh caller without a complete
    // mapping cannot bind at all, while the established binding wins over
    // a contradictory second module rather than misattributing its calls.
    let unmapped_child = OwnedStoppedChild::new();
    let unmapped = scene.admit(unmapped_child.id(), 70);
    scene.answer(unmapped_child.id(), detailed, 31);
    scene.bind_image(detailed, vec![(31, 1, unmapped_child.id(), 80)], 900);
    // Sight between admission and horizons so the mapping check decides.
    set_sight(905);
    assert_eq!(
        scene.bind(
            unmapped,
            &module,
            detailed,
            ImageIdentity {
                task_cookie: 31,
                exec_id: 1
            }
        ),
        Err(SemanticBindingRefusal::MappingIncomplete)
    );
    assert_eq!(
        scene.bind(
            unmapped,
            &ModuleKey::Unidentified {
                path: "/task3/unknown.so".into()
            },
            detailed,
            ImageIdentity {
                task_cookie: 31,
                exec_id: 1
            }
        ),
        Err(SemanticBindingRefusal::MappingIncomplete)
    );
    set_sight(1_005);
    let other = ModuleKey::physical(7, 7, 778, None, "/task3/other.so");
    assert_eq!(
        scene.bind(caller, &other, detailed, image),
        Err(SemanticBindingRefusal::ModuleConflict)
    );
    assert_eq!(
        scene.bind(
            caller,
            &ModuleKey::Unidentified {
                path: "/task3/unknown.so".into()
            },
            detailed,
            image
        ),
        Err(SemanticBindingRefusal::ModuleConflict)
    );

    // Uncertainty refuses until the remap completes; the Arc survives.
    scene
        .coordinator
        .registry_mut()
        .note_member_unscanned(caller);
    scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(
        scene.bind(caller, &module, detailed, image),
        Err(SemanticBindingRefusal::MappingIncomplete)
    );
    scene.map(caller, pid, 4_000);
    assert_eq!(scene.bind(caller, &module, detailed, image), Ok(()));
    assert!(
        Arc::ptr_eq(
            &stable,
            &scene
                .coordinator
                .semantic_bindings()
                .get(caller)
                .unwrap()
                .pin()
        ),
        "remap recovery keeps the stable Arc"
    );

    // A stale caller refuses: the pid no longer names its incarnation, so
    // a reused pid number can never inherit the binding.
    let child = OwnedStoppedChild::new();
    let retired = scene.admit(child.id(), 200);
    scene.map(retired, child.id(), 210);
    scene.answer(child.id(), detailed, 21);
    scene.bind_image(detailed, vec![(21, 1, child.id(), 300)], 3_000);
    assert_eq!(
        scene.bind(
            retired,
            &module,
            detailed,
            ImageIdentity {
                task_cookie: 21,
                exec_id: 1
            }
        ),
        Ok(())
    );
    drop(child);
    scene.coordinator.adapter_mut().reconcile(
        &std::collections::BTreeSet::new(),
        &mut |_| ImageAuthority::ScanPinned,
        4_000,
    );
    scene.coordinator.commit_batch(false).unwrap();
    assert!(
        scene.coordinator.adapter().record(retired).unwrap().retired,
        "the reaped child retires"
    );
    assert_eq!(
        scene.bind(
            retired,
            &module,
            detailed,
            ImageIdentity {
                task_cookie: 21,
                exec_id: 1
            }
        ),
        Err(SemanticBindingRefusal::NoLiveCaller)
    );

    // A new exec ends the old incarnation: the old caller refuses, the
    // successor binds only its own fresh image with a distinct Arc.
    scene.bind_image(detailed, vec![(7, 2, pid, 400)], 5_000);
    assert!(
        scene.coordinator.adapter().record(caller).unwrap().retired,
        "the later exec sequence retires the old incarnation"
    );
    let successor = scene.coordinator.adapter().live_id(pid).unwrap();
    assert_ne!(successor, caller);
    assert_eq!(
        scene.bind(caller, &module, detailed, image),
        Err(SemanticBindingRefusal::NoLiveCaller)
    );
    let image2 = ImageIdentity {
        task_cookie: 7,
        exec_id: 2,
    };
    scene.bind_image(detailed, vec![(7, 2, pid, 6_100)], 6_000);
    scene.map(successor, pid, 6_100);
    // The sighting must postdate the successor's admission but predate
    // its horizons, exactly like a production re-poll.
    set_sight(5_500);
    assert_eq!(scene.bind(successor, &module, detailed, image2), Ok(()));
    assert!(
        !Arc::ptr_eq(
            &stable,
            &scene
                .coordinator
                .semantic_bindings()
                .get(successor)
                .unwrap()
                .pin()
        ),
        "the successor incarnation holds distinct custody"
    );
    assert_eq!(
        scene.bind(successor, &module, detailed, image),
        Err(SemanticBindingRefusal::ImageUnproven(
            UnboundReason::ExecAmbiguous
        )),
        "a contradictory image cannot attach to the successor"
    );

    // The persistent cursor rotates fairly: five siblings plus the three
    // retained slots take turns, never a fixed prefix.
    let mut children = Vec::new();
    let mut siblings = Vec::new();
    for index in 0u64..5 {
        let child = OwnedStoppedChild::new();
        let sibling = scene.admit(child.id(), 7_000 + index);
        scene.map(sibling, child.id(), 7_100 + index);
        scene.answer(child.id(), detailed, 100 + index);
        children.push(child);
        siblings.push(sibling);
    }
    let rows = siblings
        .iter()
        .enumerate()
        .map(|(index, sibling)| {
            let pid = scene.coordinator.adapter().record(*sibling).unwrap().pid;
            (100 + index as u64, 1, pid, 7_200 + index as u64)
        })
        .collect();
    scene.bind_image(detailed, rows, 7_300);
    set_sight(7_100);
    for (index, sibling) in siblings.iter().enumerate() {
        assert_eq!(
            scene.bind(
                *sibling,
                &module,
                detailed,
                ImageIdentity {
                    task_cookie: 100 + index as u64,
                    exec_id: 1
                }
            ),
            Ok(())
        );
    }
    assert_eq!(scene.coordinator.semantic_bindings().len(), 8);
    let first: Vec<CallerId> = scene
        .coordinator
        .semantic_bindings_mut()
        .windowed(2)
        .iter()
        .map(|binding| binding.caller())
        .collect();
    let second: Vec<CallerId> = scene
        .coordinator
        .semantic_bindings_mut()
        .windowed(2)
        .iter()
        .map(|binding| binding.caller())
        .collect();
    let third: Vec<CallerId> = scene
        .coordinator
        .semantic_bindings_mut()
        .windowed(2)
        .iter()
        .map(|binding| binding.caller())
        .collect();
    assert_eq!(first, vec![caller, retired]);
    assert_eq!(third.len(), 2);
    assert_ne!(first, second, "the cursor advances past the first window");
    assert_ne!(second, third, "every window serves a fresh slice");
    for sibling in siblings.iter().copied() {
        assert!(
            scene.coordinator.semantic_bindings().get(sibling).is_some(),
            "rotation keeps the caller index exact"
        );
    }
    assert_eq!(
        scene
            .coordinator
            .semantic_bindings_mut()
            .bindings_for_tick()
            .len(),
        8,
        "one tick serves every accepted binding under the cap"
    );

    // The binding capacity refuses visibly without disturbing siblings.
    scene.coordinator.semantic_bindings_mut().reference_limit(8);
    let child = OwnedStoppedChild::new();
    let extra = scene.admit(child.id(), 8_000);
    scene.map(extra, child.id(), 8_100);
    scene.answer(child.id(), detailed, 200);
    scene.bind_image(detailed, vec![(200, 1, child.id(), 8_200)], 8_300);
    set_sight(8_100);
    assert_eq!(
        scene.bind(
            extra,
            &module,
            detailed,
            ImageIdentity {
                task_cookie: 200,
                exec_id: 1
            }
        ),
        Err(SemanticBindingRefusal::Capacity)
    );
    assert_eq!(scene.coordinator.semantic_bindings().len(), 8);
    children.push(child);

    // Refusal codes render for the audited path; pin every variant.
    let codes = [
        (SemanticBindingRefusal::NoLiveCaller, "no_live_caller"),
        (
            SemanticBindingRefusal::MappingIncomplete,
            "mapping_incomplete",
        ),
        (SemanticBindingRefusal::DomainConflict, "domain_conflict"),
        (SemanticBindingRefusal::ModuleConflict, "module_conflict"),
        (
            SemanticBindingRefusal::ImageUnproven(UnboundReason::ExecAmbiguous),
            UnboundReason::ExecAmbiguous.code(),
        ),
        (SemanticBindingRefusal::Capacity, "capacity"),
    ];
    for (refusal, code) in codes {
        assert_eq!(refusal.code(), code);
    }

    // Stale custody never refreshes on an old answer: flipping the
    // Detailed cookie refuses until the true proof returns, and the
    // recovered binding keeps its original Arc.
    let sibling = siblings[0];
    let sibling_pid = scene.coordinator.adapter().record(sibling).unwrap().pid;
    let sibling_stable = scene
        .coordinator
        .semantic_bindings()
        .get(sibling)
        .unwrap()
        .pin();
    set_sight(7_100);
    scene.answer(sibling_pid, detailed, 555);
    assert_eq!(
        scene.bind(
            sibling,
            &module,
            detailed,
            ImageIdentity {
                task_cookie: 100,
                exec_id: 1
            }
        ),
        Err(SemanticBindingRefusal::ImageUnproven(
            UnboundReason::CookieMismatch
        ))
    );
    scene.answer(sibling_pid, detailed, 100);
    assert_eq!(
        scene.bind(
            sibling,
            &module,
            detailed,
            ImageIdentity {
                task_cookie: 100,
                exec_id: 1
            }
        ),
        Ok(())
    );
    assert!(
        Arc::ptr_eq(
            &sibling_stable,
            &scene
                .coordinator
                .semantic_bindings()
                .get(sibling)
                .unwrap()
                .pin()
        ),
        "refresh reuses the stable Arc"
    );
}

// ---- H3 Task 3: bounded pending ownership and lane shells ----

use crate::attach::BackendSelection;
use crate::inventory_semantics::{AttestedSemanticLane, LaneNegative, SemanticBatch};
use crate::semantic_capture::TickReport;

fn gap_subjects(scene: &BindingScene) -> Vec<String> {
    scene
        .coordinator
        .registry()
        .gaps()
        .iter()
        .map(|gap| gap.subject.clone())
        .collect()
}

#[test]
fn native_semantic_pending_batch_bounds_and_refuses() {
    set_sight(1_005);
    let mut scene = BindingScene::new();
    let pid = std::process::id();
    let caller = scene.admit(pid, 50);
    scene.map(caller, pid, 60);
    let mid = scene
        .coordinator
        .registry()
        .module_id_for(&scene.module.clone())
        .unwrap();

    // An empty commit without a lane is a no-op: no gaps, no disturbance.
    scene.coordinator.commit_batch(false).unwrap();
    assert!(gap_subjects(&scene).is_empty());

    // One staged quantum without a lane cannot validate: it is refused
    // loudly through the audited path, never silently kept or published.
    let batch = SemanticBatch::scripted(scene.detailed, Vec::new(), 100);
    {
        let scene_ref = &mut scene;
        scene_ref.coordinator.stage_native(
            NativeBatch::Semantic(batch),
            &mut scene_ref.identity,
            200,
        );
    }
    scene.coordinator.commit_batch(false).unwrap();
    assert!(
        gap_subjects(&scene)
            .iter()
            .any(|subject| subject == "semantic batch dropped without lane authority"),
        "unvalidated batches refuse loudly, got {:?}",
        gap_subjects(&scene)
    );

    // A second quantum while one is still unpublished refuses at staging.
    let first = SemanticBatch::scripted(scene.detailed, Vec::new(), 300);
    let second = SemanticBatch::scripted(scene.detailed, Vec::new(), 400);
    {
        let scene_ref = &mut scene;
        scene_ref.coordinator.stage_native(
            NativeBatch::Semantic(first),
            &mut scene_ref.identity,
            500,
        );
        scene_ref.coordinator.stage_native(
            NativeBatch::Semantic(second),
            &mut scene_ref.identity,
            600,
        );
    }
    scene.coordinator.commit_batch(false).unwrap();
    let subjects = gap_subjects(&scene);
    assert!(
        subjects
            .iter()
            .any(|subject| subject == "semantic collection backpressure"),
        "backpressured collections refuse at staging, got {subjects:?}"
    );

    // Broad Inventory is preserved through every refusal.
    assert_eq!(
        scene
            .coordinator
            .registry()
            .edge(caller, mid)
            .unwrap()
            .mapping,
        MappingState::Mapped
    );
    // `commit_batch_with_semantics` with `None` delegates identically.
    let batch = SemanticBatch::scripted(scene.detailed, Vec::new(), 700);
    {
        let scene_ref = &mut scene;
        scene_ref.coordinator.stage_native(
            NativeBatch::Semantic(batch),
            &mut scene_ref.identity,
            800,
        );
    }
    // `commit_batch_with_semantics` with `None` delegates identically:
    // identical gaps coalesce with a repeat count.
    let dropped = |scene: &BindingScene| {
        let index = gap_subjects(scene)
            .iter()
            .position(|subject| subject == "semantic batch dropped without lane authority")
            .unwrap();
        scene.coordinator.registry().gap_repeats()[index]
    };
    let before = dropped(&scene);
    scene
        .coordinator
        .commit_batch_with_semantics(false, None)
        .unwrap();
    assert_eq!(dropped(&scene), before + 1);
}

#[test]
fn native_semantic_lane_shell_documents_task5_wiring() {
    let fixture = ProviderFixture::new();
    let subset = fixture.subset();
    let mut lane = AttestedSemanticLane::start(
        subset,
        &Scope::Pid(std::process::id()),
        BackendSelection::Auto,
    )
    .expect("an attested subset starts the shell lane");
    assert_eq!(lane.subset().plan().slots.len(), 2);
    assert!(
        matches!(lane.tick(&[]), Err(SemanticRefusal::Unavailable)),
        "Task 5 owns H0 driving; the shell never invents calls"
    );
    // The shell consumes cuts and serves scripted barriers in tests;
    // production runs the H0 atomic fault cut here instead.
    let cut = lane.apply_physical_gaps(Vec::new()).unwrap();
    assert!(cut.into_parts().2.is_empty());
    assert!(lane.recorded_gaps().is_empty());
    lane.script_cut_barrier(41);
    let cut = lane.apply_physical_gaps(Vec::new()).unwrap();
    assert_eq!(
        cut.into_parts().2,
        vec![LaneNegative::CutBarrier { ordinal: 41 }]
    );
    lane.fail_cut_once();
    assert!(
        matches!(
            lane.apply_physical_gaps(Vec::new()),
            Err(SemanticRefusal::Unavailable)
        ),
        "a failed cut refuses"
    );
    assert!(
        matches!(
            SemanticBatch::from_tick_report(
                lane.domain(),
                TickReport::default(),
                vec![LaneNegative::CutBarrier { ordinal: 1 }; 65],
                0,
            ),
            Err(SemanticRefusal::Unavailable)
        ),
        "lane negatives stay bounded"
    );
}

// ---- H3 Task 3: evidence-adapter conversion ----

use crate::discovery::caller_registry::instance_input::{
    AdmittedInstanceCall, CallEvidence, CallStanding, ConversionRefusal, InstanceLifecycle,
    InstanceReason, admit_call_from_evidence, admit_registration_from_coverage,
    finalize_invalidation, tail_loss_from_negative,
};
use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
use crate::discovery::instances::{
    CallFacts, EntryIp, EpochReading, InstanceId, InstanceRouter, MapRange, Route, RouterLimits,
    StableObservation,
};
use crate::inventory_semantics::{LaneCollectionRefusal, LaneCoverage};
use crate::semantic_capture::{Endpoint, InvalidationScope};
use p11scope_ebpf_common::capture;
use p11scope_ebpf_common::{Event, InstanceStamp, instance::STAMP_VALID};

fn refusal<T>(result: Result<T, ConversionRefusal>) -> Result<(), ConversionRefusal> {
    result.map(|_| ())
}

fn real_router_ids(domain: NativeDomainId, count: usize) -> Vec<InstanceId> {
    let mut router = InstanceRouter::new(domain, RouterLimits::default());
    let ranges = (0..count)
        .map(|n| {
            let base = 0x7000_0000 + n as u64 * 0x10000;
            MapRange::new(base, base + 0x3000, 0, true)
        })
        .collect();
    router.observe_legacy(StableObservation {
        file_slot: 0,
        reading: EpochReading {
            cookie: 71,
            local: 1,
            global: 0,
            fault: 0,
            record_flags: 0,
            sticky: 0,
        },
        ranges,
        fence: 0,
    });
    (0..count)
        .map(|n| {
            let stamp = InstanceStamp {
                epoch: 1,
                file_slot_plus1: 1,
                flags: STAMP_VALID,
                ..InstanceStamp::default()
            };
            match router.route(CallFacts {
                token: n as u64 + 1,
                domain,
                image: ImageIdentity {
                    task_cookie: 71,
                    exec_id: 0,
                },
                entry: stamp,
                ret: stamp,
                ip: EntryIp::new(0x7000_0000 + n as u64 * 0x10000 + 0x1000),
                attached_offset: Some(0x1000),
            }) {
                Route::Joined(id) => id,
                other => panic!("fixture must route a real instance: {other:?}"),
            }
        })
        .collect()
}

struct ConversionScene {
    scene: BindingScene,
    // Live TempDir guard: the lane's attested subset pins files under
    // it, so the fixture must outlive the scene.
    #[allow(dead_code)]
    fixture: ProviderFixture,
    lane: AttestedSemanticLane,
    caller: CallerId,
    image: ImageIdentity,
    init_slot: u32,
    sign_slot: u32,
    ids: Vec<InstanceId>,
}

impl ConversionScene {
    fn new() -> Self {
        set_sight(1_005);
        let mut scene = BindingScene::new();
        let pid = std::process::id();
        let caller = scene.admit(pid, 50);
        scene.map(caller, pid, 60);
        let image = ImageIdentity {
            task_cookie: 7,
            exec_id: 1,
        };
        // The lane starts first: bindings, coverages and batches all
        // carry the lane's own domain.
        let fixture = ProviderFixture::new();
        let lane =
            AttestedSemanticLane::start(fixture.subset(), &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let detailed = lane.domain();
        scene.coordinator.note_extend_receipt(&ExtendReceipt {
            activated_roots: true,
            exec_coverage: Some(ExecCoverage::scripted(detailed, 0)),
            ..ExtendReceipt::default()
        });
        scene.answer(pid, detailed, 7);
        scene.bind_image(detailed, vec![(7, 1, pid, 100)], 1_000);
        let module = scene.module.clone();
        assert_eq!(scene.bind(caller, &module, detailed, image), Ok(()));
        let mut init_slot = None;
        let mut sign_slot = None;
        for slot in &lane.subset().plan().slots {
            if slot.names.len() == 1 && slot.names[0] == "C_SignInit" {
                init_slot = Some(slot.index);
            }
            if slot.names.len() == 1 && slot.names[0] == "C_Sign" {
                sign_slot = Some(slot.index);
            }
        }
        Self {
            scene,
            fixture,
            lane,
            caller,
            image,
            init_slot: init_slot.expect("attested C_SignInit slot"),
            sign_slot: sign_slot.expect("attested C_Sign slot"),
            ids: real_router_ids(detailed, 10),
        }
    }

    fn detailed(&self) -> NativeDomainId {
        self.lane.domain()
    }

    fn binding(&self) -> &SemanticCallerBinding {
        self.scene
            .coordinator
            .semantic_bindings()
            .get(self.caller)
            .unwrap()
    }

    fn endpoint(&self, slot_index: u32) -> Endpoint {
        let slot = self
            .lane
            .subset()
            .plan()
            .slots
            .iter()
            .find(|slot| slot.index == slot_index)
            .unwrap();
        Endpoint {
            object: slot.object,
            file_slot: 0,
            offset: slot.file_offset,
        }
    }

    fn coverage(&self, ids: Vec<InstanceId>) -> LaneCoverage {
        LaneCoverage::scripted(
            self.detailed(),
            self.image,
            self.endpoint(self.init_slot),
            ids,
        )
    }

    fn event(
        &self,
        slot_index: u32,
        session: u64,
        mechanism: u64,
        capture: u32,
        ts_ns: u64,
    ) -> Event {
        Event {
            slot: slot_index,
            session,
            mechanism,
            capture,
            rv: 0,
            ts_ns,
            ..Default::default()
        }
    }

    fn init_event(&self, ts_ns: u64) -> Event {
        self.event(
            self.init_slot,
            7,
            0x000d,
            capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
            ts_ns,
        )
    }

    fn sign_event(&self, ts_ns: u64) -> Event {
        self.event(
            self.sign_slot,
            7,
            0,
            capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL,
            ts_ns,
        )
    }

    fn evidence(
        &self,
        token: u64,
        router: InstanceId,
        slot_index: u32,
        event: Event,
    ) -> CallEvidence {
        CallEvidence::scripted(
            self.detailed(),
            self.image,
            token,
            router,
            Some(self.endpoint(slot_index)),
            event,
        )
    }

    fn register(
        &mut self,
        coverage: &LaneCoverage,
        router: InstanceId,
        observed_ns: u64,
        boundary: Option<u64>,
    ) {
        let input = {
            let binding = self.binding();
            admit_registration_from_coverage(coverage, binding, router, observed_ns, boundary)
                .expect("scripted coverage registers")
        };
        self.scene.coordinator.registry_mut().note_instance(input);
    }

    fn convert(
        &self,
        evidence: CallEvidence,
        standing: CallStanding<'_>,
        barrier: Option<u64>,
    ) -> AdmittedInstanceCall {
        admit_call_from_evidence(
            evidence,
            self.binding(),
            self.lane.subset(),
            standing,
            barrier,
        )
        .expect("scripted evidence converts")
    }

    fn feed(&mut self, evidence: CallEvidence, standing: CallStanding<'_>, barrier: Option<u64>) {
        let input = {
            let binding = self.binding();
            admit_call_from_evidence(evidence, binding, self.lane.subset(), standing, barrier)
                .expect("scripted evidence converts")
        };
        self.scene
            .coordinator
            .registry_mut()
            .observe_instance_semantic(input);
    }

    fn commit(&mut self) {
        self.scene.coordinator.commit_batch(false).unwrap();
    }

    fn commit_with_lane(&mut self) {
        let Self { scene, lane, .. } = self;
        scene
            .coordinator
            .commit_batch_with_semantics(false, Some(lane))
            .unwrap();
    }

    fn edge_rows(&self) -> Vec<(Option<u64>, u64, bool, u64, u64)> {
        self.scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .map(|row| {
                let started = row.semantics.as_ref().map(|s| s.started()).unwrap_or(0);
                let completed = row.semantics.as_ref().map(|s| s.completed()).unwrap_or(0);
                (
                    row.api_returns,
                    row.historical_only_returns,
                    row.lossy,
                    started,
                    completed,
                )
            })
            .collect()
    }

    fn edge_reasons(&self, index: usize) -> Vec<InstanceReason> {
        self.scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .nth(index)
            .expect("published edge")
            .reasons
            .iter()
            .copied()
            .collect()
    }

    fn instance_states(&self) -> Vec<InstanceLifecycle> {
        self.scene
            .coordinator
            .registry()
            .instances()
            .map(|record| record.state)
            .collect()
    }

    fn gap_pairs(&self) -> Vec<(String, String)> {
        self.scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect()
    }

    fn prove_and_mark_tail(&mut self) {
        let detailed = self.detailed();
        let image = self.image;
        let caller = self.caller;
        self.scene
            .coordinator
            .reference_prove_image(detailed, image);
        self.scene.coordinator.reference_mark_tail(caller);
    }
}

#[test]
fn native_semantic_convert_admits_registered_call() {
    let mut conv = ConversionScene::new();
    let (r0, r1, r2) = (conv.ids[0], conv.ids[1], conv.ids[2]);

    // A registered Init/Sign pair reduces to one completed operation, and
    // nothing is visible before publication.
    let coverage = conv.coverage(vec![r0]);
    conv.register(&coverage, r0, 100, None);
    assert_eq!(
        conv.scene.coordinator.registry().instances().count(),
        0,
        "staged registrations stay invisible until publish"
    );
    let init = conv.evidence(1, r0, conv.init_slot, conv.init_event(110));
    conv.feed(init, CallStanding::Current(&coverage), None);
    let sign = conv.evidence(2, r0, conv.sign_slot, conv.sign_event(120));
    conv.feed(sign, CallStanding::Current(&coverage), None);
    conv.commit();
    assert_eq!(conv.edge_rows(), vec![(Some(2), 0, false, 1, 1)]);
    assert_eq!(
        conv.scene
            .coordinator
            .registry()
            .instances()
            .next()
            .unwrap()
            .state,
        InstanceLifecycle::Observed
    );
    // No duplicate legacy reduction: the physical edge keeps no reducer.
    let mid = conv
        .scene
        .coordinator
        .registry()
        .module_id_for(&conv.scene.module.clone())
        .unwrap();
    let edge = conv
        .scene
        .coordinator
        .registry()
        .edge(conv.caller, mid)
        .unwrap();
    assert_eq!(edge.mapping, MappingState::Mapped);
    assert!(
        edge.semantics.is_none(),
        "instance calls never feed the legacy physical reducer"
    );

    // An inherited registration boundary fences without a fresh loss: the
    // calls arrive with current standing yet stay historical-only, and the
    // inherited boundary discloses loss on the new record.
    let coverage1 = conv.coverage(vec![r1]);
    conv.register(&coverage1, r1, 200, Some(4));
    let init = conv.evidence(3, r1, conv.init_slot, conv.init_event(210));
    conv.feed(init, CallStanding::Current(&coverage1), None);
    let sign = conv.evidence(4, r1, conv.sign_slot, conv.sign_event(220));
    conv.feed(sign, CallStanding::Current(&coverage1), None);
    conv.commit();
    assert_eq!(
        conv.edge_rows()[1],
        (Some(2), 2, true, 0, 0),
        "inherited boundary keeps the pair historical-only"
    );

    // A same-publication barrier converts directly to historical-only;
    // history-only reduction discloses loss on the record.
    let coverage2 = conv.coverage(vec![r2]);
    conv.register(&coverage2, r2, 300, None);
    let init = conv.evidence(5, r2, conv.init_slot, conv.init_event(310));
    conv.feed(init, CallStanding::Current(&coverage2), Some(6));
    let sign = conv.evidence(6, r2, conv.sign_slot, conv.sign_event(320));
    conv.feed(sign, CallStanding::Current(&coverage2), Some(6));
    conv.commit();
    assert_eq!(
        conv.edge_rows()[2],
        (Some(2), 2, true, 0, 0),
        "a call at or before the barrier is historical even when current"
    );

    // A late Init after the completed Final cannot restart the machine:
    // conversion admits what it cannot know, the registry's ordering
    // guard keeps it history-only and discloses the loss.
    let late = conv.evidence(1, r0, conv.init_slot, conv.init_event(410));
    conv.feed(late, CallStanding::Current(&coverage), None);
    conv.commit();
    assert_eq!(
        conv.edge_rows()[0],
        (Some(3), 1, true, 1, 1),
        "late Init counts but never restarts"
    );
}

#[test]
fn native_semantic_convert_refuses_unproven_call() {
    let conv = ConversionScene::new();
    let r0 = conv.ids[0];
    let coverage = conv.coverage(vec![r0]);
    let binding = conv.binding();
    let subset = conv.lane.subset();
    let good = conv.evidence(1, r0, conv.init_slot, conv.init_event(110));

    // Identity mismatches refuse before any descriptor work.
    let mut event = conv.init_event(110);
    let foreign_domain = NativeDomainId::mint();
    let foreign = CallEvidence::scripted(
        foreign_domain,
        conv.image,
        1,
        r0,
        Some(conv.endpoint(conv.init_slot)),
        event,
    );
    assert_eq!(
        refusal(admit_call_from_evidence(
            foreign,
            binding,
            subset,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Domain)
    );
    let rival_image = ImageIdentity {
        task_cookie: 7,
        exec_id: 99,
    };
    let rival = CallEvidence::scripted(
        conv.detailed(),
        rival_image,
        1,
        r0,
        Some(conv.endpoint(conv.init_slot)),
        event,
    );
    assert_eq!(
        refusal(admit_call_from_evidence(
            rival,
            binding,
            subset,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Custody)
    );
    let unpositioned = CallEvidence::scripted(
        conv.detailed(),
        conv.image,
        0,
        r0,
        Some(conv.endpoint(conv.init_slot)),
        event,
    );
    assert_eq!(
        refusal(admit_call_from_evidence(
            unpositioned,
            binding,
            subset,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Position)
    );

    // Endpoint and slot proofs must agree exactly.
    let no_endpoint = CallEvidence::scripted(conv.detailed(), conv.image, 1, r0, None, event);
    assert_eq!(
        refusal(admit_call_from_evidence(
            no_endpoint,
            binding,
            subset,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Slot)
    );
    event = conv.init_event(110);
    event.slot = 99;
    let unknown_slot = CallEvidence::scripted(
        conv.detailed(),
        conv.image,
        1,
        r0,
        Some(conv.endpoint(conv.init_slot)),
        event,
    );
    assert_eq!(
        refusal(admit_call_from_evidence(
            unknown_slot,
            binding,
            subset,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Slot)
    );
    let mut endpoint = conv.endpoint(conv.init_slot);
    endpoint.object = PinnedObjectId(4_242);
    let wrong_object = CallEvidence::scripted(
        conv.detailed(),
        conv.image,
        1,
        r0,
        Some(endpoint),
        conv.init_event(110),
    );
    assert_eq!(
        refusal(admit_call_from_evidence(
            wrong_object,
            binding,
            subset,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Slot)
    );
    endpoint = conv.endpoint(conv.init_slot);
    endpoint.offset += 1;
    let wrong_offset = CallEvidence::scripted(
        conv.detailed(),
        conv.image,
        1,
        r0,
        Some(endpoint),
        conv.init_event(110),
    );
    assert_eq!(
        refusal(admit_call_from_evidence(
            wrong_offset,
            binding,
            subset,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Slot)
    );

    // Coverage must name this partition: image, file and id all match.
    let wrong_image = LaneCoverage::scripted(
        conv.detailed(),
        rival_image,
        conv.endpoint(conv.init_slot),
        vec![r0],
    );
    assert_eq!(
        refusal(admit_call_from_evidence(
            conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
            binding,
            subset,
            CallStanding::Current(&wrong_image),
            None
        )),
        Err(ConversionRefusal::Coverage)
    );
    let mut wrong_file = conv.endpoint(conv.init_slot);
    wrong_file.file_slot = 9;
    let wrong_file = LaneCoverage::scripted(conv.detailed(), conv.image, wrong_file, vec![r0]);
    assert_eq!(
        refusal(admit_call_from_evidence(
            conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
            binding,
            subset,
            CallStanding::Current(&wrong_file),
            None
        )),
        Err(ConversionRefusal::Coverage)
    );
    let missing_id = conv.coverage(vec![conv.ids[1]]);
    assert_eq!(
        refusal(admit_call_from_evidence(
            good,
            binding,
            subset,
            CallStanding::Current(&missing_id),
            None
        )),
        Err(ConversionRefusal::Coverage)
    );
    assert_eq!(
        refusal(admit_registration_from_coverage(
            &coverage,
            binding,
            conv.ids[1],
            100,
            None
        )),
        Err(ConversionRefusal::Coverage),
        "only ids the coverage carries can register"
    );
    assert_eq!(
        refusal(admit_registration_from_coverage(
            &coverage,
            binding,
            r0,
            100,
            Some(0)
        )),
        Err(ConversionRefusal::Position)
    );

    // Historical standing converts without coverage: old facts stay
    // admissible as history with a finite reason.
    let historical = conv.evidence(1, r0, conv.init_slot, conv.init_event(110));
    assert!(
        admit_call_from_evidence(
            historical,
            binding,
            subset,
            CallStanding::Historical(InstanceReason::SemanticLoss),
            None
        )
        .is_ok()
    );

    // `prepare` admits no unauthorized slots in reachable shapes (it
    // refuses the subset instead): no endpoint, unknown slot index, and
    // object/offset mismatch all refuse above. The conversion's
    // authorized/unambiguous/count-only checks are defense-in-depth above
    // those proven Slot paths, pinned by scripted descriptor shapes in
    // `native_semantic_convert_refuses_unauthorized_descriptor_shapes`.
}

#[test]
fn native_semantic_convert_maps_invalidations_and_tail_losses() {
    // A fault-era cut ends live operations unknown while history stays.
    let mut conv = ConversionScene::new();
    let (p0, s0) = (conv.ids[0], conv.ids[2]);
    let coverage = conv.coverage(vec![p0, s0]);
    conv.register(&coverage, p0, 100, None);
    conv.register(&coverage, s0, 100, None);
    let init = conv.evidence(1, p0, conv.init_slot, conv.init_event(110));
    conv.feed(init, CallStanding::Current(&coverage), None);
    conv.commit();
    assert_eq!(conv.edge_rows()[0], (Some(1), 0, false, 1, 0));
    let (losses, retirements) = finalize_invalidation(
        &InvalidationScope::FaultEra,
        Some(5),
        conv.detailed(),
        None,
        &[],
    )
    .unwrap();
    assert!(retirements.is_empty());
    assert_eq!(losses.len(), 1);
    for loss in losses {
        conv.scene
            .coordinator
            .registry_mut()
            .note_instance_semantic_loss(loss);
    }
    conv.commit();
    let rows = conv.edge_rows();
    assert_eq!(rows[0], (Some(1), 0, true, 1, 0));
    assert!(rows[1].2, "the domain cut is deliberately wide");
    assert!(
        conv.scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .next()
            .unwrap()
            .reasons
            .contains(&InstanceReason::SemanticLoss)
    );

    // Image retirement names its scope; a missing position dominates
    // every scope into permanent domain authority refusal.
    let mut conv = ConversionScene::new();
    let p0 = conv.ids[0];
    let coverage = conv.coverage(vec![p0]);
    conv.register(&coverage, p0, 100, None);
    conv.commit();
    let (losses, retirements) = finalize_invalidation(
        &InvalidationScope::ImageRetired(conv.image),
        Some(6),
        conv.detailed(),
        None,
        &[],
    )
    .unwrap();
    assert!(retirements.is_empty());
    assert_eq!(losses.len(), 1);
    for loss in losses {
        conv.scene
            .coordinator
            .registry_mut()
            .note_instance_semantic_loss(loss);
    }
    conv.commit();
    assert!(
        conv.scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .next()
            .unwrap()
            .reasons
            .contains(&InstanceReason::ImageRetired)
    );
    let rows = conv.scene.coordinator.registry().instances().count();
    let (losses, _) = finalize_invalidation(
        &InvalidationScope::File {
            image: conv.image,
            file_slot: 0,
        },
        None,
        conv.detailed(),
        None,
        &[],
    )
    .unwrap();
    assert_eq!(losses.len(), 1);
    for loss in losses {
        conv.scene
            .coordinator
            .registry_mut()
            .note_instance_semantic_loss(loss);
    }
    conv.commit();
    let fresh = conv.coverage(vec![conv.ids[1]]);
    conv.register(&fresh, conv.ids[1], 200, None);
    conv.commit();
    assert_eq!(
        conv.scene.coordinator.registry().instances().count(),
        rows,
        "exhaustion refuses new registration"
    );
    assert!(
        conv.scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .any(|gap| gap.subject == "instance semantics refused"
                && gap.reason == "authority_exhausted"),
        "exhaustion refusal is disclosed, got {:?}",
        conv.scene.coordinator.registry().gaps()
    );
    assert_eq!(
        refusal(finalize_invalidation(
            &InvalidationScope::FaultEra,
            Some(0),
            conv.detailed(),
            None,
            &[]
        )),
        Err(ConversionRefusal::Position)
    );

    // A fresh disjoint partition retires exactly the superseded ids: the
    // sibling stays observed with no fake retirement.
    let mut conv = ConversionScene::new();
    let (p0, p1, s0, f0) = (conv.ids[0], conv.ids[1], conv.ids[2], conv.ids[3]);
    let old = conv.coverage(vec![p0, p1]);
    conv.register(&old, p0, 100, None);
    conv.register(&old, p1, 100, None);
    let sibling = conv.coverage(vec![s0]);
    conv.register(&sibling, s0, 100, None);
    conv.commit();
    let fresh = conv.coverage(vec![f0]);
    let binding_image = conv.image;
    let (losses, retirements) = {
        let binding = conv.binding();
        assert_eq!(binding.image(), binding_image);
        finalize_invalidation(
            &InvalidationScope::InstancesRetired {
                image: conv.image,
                file_slot: 0,
                ids: vec![p0, p1],
            },
            Some(7),
            conv.detailed(),
            Some(binding),
            std::slice::from_ref(&fresh),
        )
        .unwrap()
    };
    assert!(losses.is_empty());
    assert_eq!(retirements.len(), 2);
    for retirement in retirements {
        conv.scene
            .coordinator
            .registry_mut()
            .retire_instance(retirement);
    }
    conv.commit();
    let states: Vec<InstanceLifecycle> = conv
        .scene
        .coordinator
        .registry()
        .instances()
        .map(|row| row.state)
        .collect();
    assert_eq!(
        states,
        vec![
            InstanceLifecycle::Retired,
            InstanceLifecycle::Retired,
            InstanceLifecycle::Observed
        ]
    );

    // Without a fresh partition the same observation is exact loss, not
    // retirement: the sibling is untouched.
    let mut conv = ConversionScene::new();
    let (p0, s0) = (conv.ids[0], conv.ids[2]);
    let old = conv.coverage(vec![p0]);
    conv.register(&old, p0, 100, None);
    let sibling = conv.coverage(vec![s0]);
    conv.register(&sibling, s0, 100, None);
    conv.commit();
    let (losses, retirements) = {
        let binding = conv.binding();
        finalize_invalidation(
            &InvalidationScope::InstancesRetired {
                image: conv.image,
                file_slot: 0,
                ids: vec![p0],
            },
            Some(7),
            conv.detailed(),
            Some(binding),
            &[],
        )
        .unwrap()
    };
    assert!(retirements.is_empty());
    assert_eq!(losses.len(), 1);
    for loss in losses {
        conv.scene
            .coordinator
            .registry_mut()
            .note_instance_semantic_loss(loss);
    }
    conv.commit();
    let rows = conv.edge_rows();
    assert!(rows[0].2);
    assert!(!rows[1].2, "exact loss spares the sibling");

    // Lane negatives: a cut barrier stages domain loss, a refused
    // collection is no H2 loss at all.
    assert!(matches!(
        tail_loss_from_negative(conv.detailed(), &LaneNegative::CutBarrier { ordinal: 0 }),
        Some(Err(ConversionRefusal::Position))
    ));
    for (reason, code) in [
        (LaneCollectionRefusal::Backpressure, "backpressure"),
        (LaneCollectionRefusal::CollectionFailed, "collection_failed"),
    ] {
        assert_eq!(reason.code(), code);
        assert!(
            tail_loss_from_negative(conv.detailed(), &LaneNegative::CollectionRefused { reason })
                .is_none(),
            "collection refusals never mint instance losses"
        );
    }
    let loss = tail_loss_from_negative(conv.detailed(), &LaneNegative::CutBarrier { ordinal: 9 })
        .unwrap()
        .unwrap();
    conv.scene
        .coordinator
        .registry_mut()
        .note_instance_semantic_loss(loss);
    conv.commit();
    assert!(
        conv.scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .all(|row| row.lossy),
        "the tail barrier fences every unpublished instance"
    );
}

// ---- H3 Task 3: physical-gap finalization fencing ----

#[test]
fn native_semantic_physical_gap_finalization_fences_unpublished_calls() {
    let mut conv = ConversionScene::new();
    let (r0, r1) = (conv.ids[0], conv.ids[1]);

    // A published pair reduces cleanly before any physical cut.
    let coverage = conv.coverage(vec![r0]);
    conv.register(&coverage, r0, 100, None);
    conv.feed(
        conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.feed(
        conv.evidence(2, r0, conv.sign_slot, conv.sign_event(120)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.commit();
    assert_eq!(conv.edge_rows(), vec![(Some(2), 0, false, 1, 1)]);
    assert_eq!(conv.instance_states(), vec![InstanceLifecycle::Observed]);

    // Conversion admits the call pre-cut (admission evidence only): the
    // converted input drops without staging, so this leg cannot evidence
    // finalizer fencing of a pre-minted call.
    // TASK5-CARRYOVER: preminted-through-finalizer fencing needs the
    // H0-driven batch test once the lane loop stages queued calls.
    let preminted = conv.convert(
        conv.evidence(3, r0, conv.init_slot, conv.init_event(130)),
        CallStanding::Current(&coverage),
        None,
    );
    drop(preminted);
    conv.prove_and_mark_tail();
    conv.lane.script_cut_barrier(2);
    conv.commit_with_lane();
    assert_eq!(
        conv.lane.take_recorded_gaps().len(),
        1,
        "one proven bound caller mints exactly one gap"
    );
    assert_eq!(
        conv.scene.coordinator.registry().instances().count(),
        1,
        "an unstaged input stages no record"
    );
    assert_eq!(conv.edge_rows(), vec![(Some(2), 0, true, 1, 1)]);
    assert_eq!(conv.edge_reasons(0), vec![InstanceReason::SemanticLoss]);
    assert_eq!(
        conv.instance_states(),
        vec![InstanceLifecycle::Uncertain],
        "the cut invalidates with the flesh intact"
    );

    // Replaying the same cut never re-invalidates: the fence is sticky
    // and the disclosure stays exactly once.
    conv.prove_and_mark_tail();
    conv.lane.script_cut_barrier(2);
    conv.commit_with_lane();
    assert_eq!(conv.lane.take_recorded_gaps().len(), 1);
    assert_eq!(conv.edge_rows(), vec![(Some(2), 0, true, 1, 1)]);
    assert_eq!(conv.edge_reasons(0), vec![InstanceReason::SemanticLoss]);

    // A fresh pair above the barrier recovers: it reduces through the
    // fence while the inherited loss stays disclosed.
    let coverage1 = conv.coverage(vec![r1]);
    conv.register(&coverage1, r1, 500, None);
    conv.feed(
        conv.evidence(5, r1, conv.init_slot, conv.init_event(510)),
        CallStanding::Current(&coverage1),
        None,
    );
    conv.feed(
        conv.evidence(6, r1, conv.sign_slot, conv.sign_event(520)),
        CallStanding::Current(&coverage1),
        None,
    );
    conv.commit_with_lane();
    assert!(conv.lane.take_recorded_gaps().is_empty());
    assert_eq!(
        conv.edge_rows()[1],
        (Some(2), 0, true, 1, 1),
        "fresh calls reduce; the inherited cut stays disclosed"
    );
    assert_eq!(
        conv.instance_states(),
        vec![InstanceLifecycle::Uncertain, InstanceLifecycle::Observed],
        "reducing flesh revives the record; the edge keeps the disclosure"
    );
    assert_eq!(conv.edge_reasons(1), vec![InstanceReason::SemanticLoss]);

    // A late Init after the completed Final counts but never restarts:
    // the cut fence keeps it historical-only.
    conv.feed(
        conv.evidence(1, r0, conv.init_slot, conv.init_event(610)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.commit_with_lane();
    assert_eq!(
        conv.edge_rows()[0],
        (Some(3), 1, true, 1, 1),
        "late Init counts but never restarts"
    );
    assert_eq!(
        conv.edge_reasons(0),
        vec![
            InstanceReason::SemanticLoss,
            InstanceReason::BeforeSemanticBoundary
        ]
    );

    // An unknown instance never fences its way in: no record, honest
    // refusal through the audited path.
    let r9 = conv.ids[9];
    let coverage9 = conv.coverage(vec![r9]);
    let gaps_before = conv.gap_pairs().len();
    conv.feed(
        conv.evidence(9, r9, conv.init_slot, conv.init_event(710)),
        CallStanding::Current(&coverage9),
        None,
    );
    conv.commit_with_lane();
    assert_eq!(
        conv.scene.coordinator.registry().instances().count(),
        2,
        "unknown calls never mint records"
    );
    assert!(
        conv.gap_pairs()[gaps_before..].contains(&(
            "instance semantics refused".into(),
            "instance_unproven".into()
        )),
        "unknown calls refuse honestly, got {:?}",
        conv.gap_pairs()
    );

    // An empty tick stages nothing: no gaps, no cuts, no disturbance.
    let gaps_before = conv.gap_pairs().len();
    conv.commit_with_lane();
    assert_eq!(conv.gap_pairs().len(), gaps_before);
    assert!(conv.lane.take_recorded_gaps().is_empty());

    // A tail mark for an unbound caller mints nothing and refuses
    // nothing: only bound callers carry gaps.
    conv.scene
        .coordinator
        .reference_mark_tail(crate::discovery::caller_registry::CallerId(999_999));
    conv.commit_with_lane();
    assert_eq!(conv.gap_pairs().len(), gaps_before);
    assert!(conv.lane.take_recorded_gaps().is_empty());
}

#[test]
fn native_semantic_physical_gap_refuses_before_first_scan() {
    // No accepted H0 scan proves the image yet: no mint, no cut, only
    // conservative audited disclosure, while broad Inventory continues.
    let mut conv = ConversionScene::new();
    conv.scene.coordinator.reference_mark_tail(conv.caller);
    conv.commit_with_lane();
    assert!(conv.lane.take_recorded_gaps().is_empty());
    assert!(
        conv.gap_pairs().contains(&(
            "semantic gap refused before first scan".into(),
            "no accepted H0 scan proves this image yet; the physical uncertainty stands \
             without a semantic cut"
                .into()
        )),
        "pre-first-scan gaps refuse conservatively, got {:?}",
        conv.gap_pairs()
    );
    let mid = conv
        .scene
        .coordinator
        .registry()
        .module_id_for(&conv.scene.module.clone())
        .unwrap();
    assert_eq!(
        conv.scene
            .coordinator
            .registry()
            .edge(conv.caller, mid)
            .unwrap()
            .mapping,
        MappingState::Mapped
    );

    // A superseded exec proves nothing either: the proof must name the
    // binding's exact current image.
    let gaps_before = conv.gap_pairs().len();
    conv.scene.coordinator.reference_prove_image(
        conv.detailed(),
        ImageIdentity {
            task_cookie: 7,
            exec_id: 99,
        },
    );
    conv.scene.coordinator.reference_mark_tail(conv.caller);
    conv.commit_with_lane();
    assert!(conv.lane.take_recorded_gaps().is_empty());
    assert_eq!(conv.gap_pairs().len(), gaps_before);
}

#[test]
fn native_semantic_physical_gap_cut_failure_ends_domain_authority() {
    // A failed cut ends semantic authority in the domain permanently:
    // later quanta refuse loudly while broad Inventory continues.
    let mut conv = ConversionScene::new();
    conv.prove_and_mark_tail();
    conv.lane.fail_cut_once();
    conv.commit_with_lane();
    assert!(
        conv.gap_pairs().contains(&(
            "semantic authority ended for domain".into(),
            "the physical cut failed; new semantic authority in this domain refuses permanently"
                .into()
        )),
        "cut failure ends the domain loudly, got {:?}",
        conv.gap_pairs()
    );
    let batch = SemanticBatch::scripted(conv.detailed(), Vec::new(), 700);
    {
        let scene = &mut conv.scene;
        scene
            .coordinator
            .stage_native(NativeBatch::Semantic(batch), &mut scene.identity, 800);
    }
    conv.commit_with_lane();
    assert!(
        conv.gap_pairs().contains(&(
            "semantic batch refused for an ended domain".into(),
            "the domain's semantic authority ended permanently; the batch was refused through \
             the audited path"
                .into()
        )),
        "ended domains refuse later quanta, got {:?}",
        conv.gap_pairs()
    );
    let mid = conv
        .scene
        .coordinator
        .registry()
        .module_id_for(&conv.scene.module.clone())
        .unwrap();
    assert_eq!(
        conv.scene
            .coordinator
            .registry()
            .edge(conv.caller, mid)
            .unwrap()
            .mapping,
        MappingState::Mapped
    );
}

// ---- H3 Task 3: cgroup provisional remap ----

use crate::discovery::engine::inventory_coordinator::tests::cgroup_provider_scene;
use crate::inspect_system::inventory_cgroup::ScopedCollectionOutcome;
use crate::scope::inventory_cgroup::{CgroupWalkLimits, CgroupWalkState, CollectionControl};

struct CgroupScene {
    dir: tempfile::TempDir,
    child: OwnedStoppedChild,
    coordinator: InventoryCoordinator<OsProcessSource>,
    // Live TempDir guard: the lane's attested subset pins files under
    // it, so the fixture must outlive the scene.
    #[allow(dead_code)]
    fixture: ProviderFixture,
    lane: AttestedSemanticLane,
    caller: CallerId,
    module: ModuleKey,
}

impl CgroupScene {
    fn new() -> Self {
        set_sight(2_005);
        let (dir, child, mut coordinator) = cgroup_provider_scene();
        let pid = child.id();
        coordinator.set_semantic_binding_clock(sight_clock);
        let fixture = ProviderFixture::new();
        // The shell ignores scope/backend; Task 5 starts the Session.
        let mut lane =
            AttestedSemanticLane::start(fixture.subset(), &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let detailed = lane.domain();
        // Pass 1: admit, deep-scan and map the held provider child.
        Self::run_pass(
            &mut coordinator,
            &mut lane,
            CgroupWalkLimits::default(),
            1_000,
        );
        let caller = coordinator
            .adapter()
            .live_id(pid)
            .expect("pass 1 admits the held child");
        let mid = coordinator
            .registry()
            .edges_of(caller)
            .find(|edge| edge.mapping == MappingState::Mapped)
            .map(|edge| edge.module)
            .expect("pass 1 maps the provider module");
        let module = coordinator
            .registry()
            .module(mid)
            .expect("retained module")
            .key
            .clone();
        // Detailed binder proof for the semantic binding.
        coordinator.note_extend_receipt(&ExtendReceipt {
            activated_roots: true,
            exec_coverage: Some(ExecCoverage::scripted(detailed, 0)),
            ..ExtendReceipt::default()
        });
        let mut identity = ScriptedPidIdentity::default();
        identity.answers.insert(
            (pid, detailed),
            CookieQuery::Cookie(DomainCookie::scripted(detailed, 7)),
        );
        // The row's t0 must not predate the caller's pass-1 admission.
        let rows = vec![WitnessRow::scripted(
            detailed,
            7,
            1,
            AttachObjectId::scripted(0),
            EndpointId(0),
            pid,
            1_500,
        )];
        stage_witness_read(&mut coordinator, &mut identity, detailed, rows, 2_000);
        stage_lifecycle_drain(&mut coordinator, &mut identity, detailed, 2_010);
        stage_witness_read(&mut coordinator, &mut identity, detailed, Vec::new(), 2_020);
        coordinator.commit_batch(false).unwrap();
        let image = ImageIdentity {
            task_cookie: 7,
            exec_id: 1,
        };
        coordinator
            .bind_semantic_caller(caller, module.clone(), detailed, image, &mut identity)
            .expect("bound caller with a mapped provider module");
        coordinator.reference_prove_image(detailed, image);
        Self {
            dir,
            child,
            coordinator,
            fixture,
            lane,
            caller,
            module,
        }
    }

    fn run_pass(
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        lane: &mut AttestedSemanticLane,
        limits: CgroupWalkLimits,
        now_ns: u64,
    ) -> ScopedCollectionOutcome {
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                limits,
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        coordinator
            .apply_cgroup_collection(collection, now_ns)
            .unwrap();
        coordinator
            .commit_batch_with_semantics(false, Some(lane))
            .unwrap();
        coordinator
            .take_cgroup_completion()
            .expect("committed pass completes")
            .outcome
    }

    fn pass(&mut self, limits: CgroupWalkLimits, now_ns: u64) -> ScopedCollectionOutcome {
        let Self {
            coordinator, lane, ..
        } = self;
        Self::run_pass(coordinator, lane, limits, now_ns)
    }

    fn set_procs(&self, pid: Option<u32>) {
        let contents = pid.map_or(String::new(), |pid| format!("{pid}\n"));
        std::fs::write(self.dir.path().join("cgroup.procs"), contents).unwrap();
    }

    fn mapping(&self) -> MappingState {
        let mid = self
            .coordinator
            .registry()
            .module_id_for(&self.module)
            .unwrap();
        self.coordinator
            .registry()
            .edge(self.caller, mid)
            .unwrap()
            .mapping
    }

    fn mapping_reason(&self) -> Option<String> {
        let mid = self
            .coordinator
            .registry()
            .module_id_for(&self.module)
            .unwrap();
        self.coordinator
            .registry()
            .edge(self.caller, mid)
            .unwrap()
            .mapping_reason
            .clone()
    }

    fn gap_pairs(&self) -> Vec<(String, String)> {
        self.coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect()
    }
}

#[test]
fn native_semantic_cgroup_provisional_unscanned_remap_recovers_without_erasing_gaps() {
    let mut scene = CgroupScene::new();
    let pid = scene.child.id();

    // A complete same-custody pass suppresses the provisional marker:
    // the edge stays mapped and no tail gap mints.
    let outcome = scene.pass(CgroupWalkLimits::default(), 3_000);
    assert_eq!(outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(scene.mapping(), MappingState::Mapped);
    assert!(scene.lane.recorded_gaps().is_empty());
    assert!(
        !scene
            .gap_pairs()
            .iter()
            .any(|(subject, _)| subject == "semantic gap refused before first scan"),
        "a proven image never refuses, got {:?}",
        scene.gap_pairs()
    );

    // A mapped edge alone never suppresses: an empty census stages the
    // genuine uncertainty even though the publication completes.
    scene.lane.script_cut_barrier(50);
    scene.set_procs(None);
    let outcome = scene.pass(CgroupWalkLimits::default(), 4_000);
    assert_eq!(outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(
        scene.mapping(),
        MappingState::Uncertain,
        "the unscanned member demotes despite a complete publication"
    );
    assert_eq!(
        scene.mapping_reason().as_deref(),
        Some("member was not scanned this pass; the mapping is neither confirmed nor refuted")
    );
    assert_eq!(
        scene.lane.recorded_gaps().len(),
        1,
        "the unresolved marker mints exactly one tail cut"
    );
    assert_eq!(
        scene.coordinator.registry().instance_negative_occupied(),
        1,
        "the tail cut fences the semantic domain"
    );

    // Remap recovers without erasing gaps: the edge maps again, the
    // marker suppresses, and the earlier cut stands untouched.
    scene.set_procs(Some(pid));
    let outcome = scene.pass(CgroupWalkLimits::default(), 5_000);
    assert_eq!(outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(scene.mapping(), MappingState::Mapped);
    assert_eq!(
        scene.lane.recorded_gaps().len(),
        1,
        "recovery mints no new cut and erases none"
    );
    assert_eq!(
        scene.coordinator.registry().instance_negative_occupied(),
        1,
        "the earlier cut fence persists through recovery"
    );

    // Scope loss stages again: a second empty census mints a second cut.
    scene.set_procs(None);
    let outcome = scene.pass(CgroupWalkLimits::default(), 6_000);
    assert_eq!(outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(scene.mapping(), MappingState::Uncertain);
    assert_eq!(scene.lane.recorded_gaps().len(), 2);

    // Recovery again: mapped, suppressed, both cuts intact.
    scene.set_procs(Some(pid));
    let outcome = scene.pass(CgroupWalkLimits::default(), 7_000);
    assert_eq!(outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(scene.mapping(), MappingState::Mapped);
    assert_eq!(scene.lane.recorded_gaps().len(), 2);

    // A failed publication stages through the other branch: the
    // transaction gap discloses the failure and the marker stands.
    let failed = CgroupWalkLimits {
        work_units: 0,
        ..CgroupWalkLimits::default()
    };
    let outcome = scene.pass(failed, 8_000);
    assert!(
        matches!(outcome, ScopedCollectionOutcome::Incomplete(_)),
        "an exhausted walk cannot complete, got {outcome:?}"
    );
    assert!(
        scene.gap_pairs().contains(&(
            "cgroup scope transaction incomplete".into(),
            outcome.reason().into()
        )),
        "failed publications disclose loudly, got {:?}",
        scene.gap_pairs()
    );
    assert_eq!(scene.mapping(), MappingState::Uncertain);
    assert_eq!(scene.lane.recorded_gaps().len(), 3);

    // Markers stay bounded across passes: repeated complete passes
    // suppress every time without multiplying gaps or cuts.
    let gaps_before = scene.gap_pairs().len();
    for now_ns in [9_000, 10_000] {
        let outcome = scene.pass(CgroupWalkLimits::default(), now_ns);
        assert_eq!(outcome, ScopedCollectionOutcome::Complete);
        assert_eq!(scene.mapping(), MappingState::Mapped);
    }
    assert_eq!(scene.lane.recorded_gaps().len(), 3);
    assert_eq!(
        scene.gap_pairs().len(),
        gaps_before,
        "complete passes add no gaps once suppressed"
    );
}

// ---- H3 Task 3 fix loop: bounded retention and adjudication arms ----

#[test]
fn native_semantic_proven_images_bounded_by_live_bindings() {
    let mut conv = ConversionScene::new();
    let detailed = conv.detailed();
    let module = conv.scene.module.clone();

    // Bind/retire churn: a second caller binds and proves, then its
    // process exits and the incarnation retires (the binding persists).
    let child = OwnedStoppedChild::new();
    let churned = conv.scene.admit(child.id(), 200);
    conv.scene.map(churned, child.id(), 210);
    conv.scene.answer(child.id(), detailed, 21);
    conv.scene
        .bind_image(detailed, vec![(21, 1, child.id(), 300)], 3_000);
    let churned_image = ImageIdentity {
        task_cookie: 21,
        exec_id: 1,
    };
    assert_eq!(
        conv.scene.bind(churned, &module, detailed, churned_image),
        Ok(())
    );
    conv.scene
        .coordinator
        .reference_prove_image(detailed, churned_image);
    drop(child);
    conv.scene.coordinator.adapter_mut().reconcile(
        &std::collections::BTreeSet::new(),
        &mut |_| ImageAuthority::ScanPinned,
        4_000,
    );
    conv.scene.coordinator.commit_batch(false).unwrap();
    assert!(
        conv.scene
            .coordinator
            .adapter()
            .record(churned)
            .unwrap()
            .retired,
        "the reaped child retires"
    );
    assert_eq!(conv.scene.coordinator.semantic_bindings().len(), 2);

    // Fill far beyond the binding cap with unbound tickets: none persist.
    for ticket in 1_000..1_000 + MAX_INSTANCES as u64 + 64 {
        conv.scene.coordinator.reference_prove_image(
            detailed,
            ImageIdentity {
                task_cookie: ticket,
                exec_id: 1,
            },
        );
    }
    assert!(
        conv.scene.coordinator.proven_image_count()
            <= conv.scene.coordinator.semantic_bindings().len(),
        "proven images stay bounded by live bindings, got {} over {}",
        conv.scene.coordinator.proven_image_count(),
        conv.scene.coordinator.semantic_bindings().len()
    );

    // Gap minting still works for the bound survivor.
    conv.prove_and_mark_tail();
    conv.lane.script_cut_barrier(2);
    conv.commit_with_lane();
    assert_eq!(
        conv.lane.take_recorded_gaps().len(),
        1,
        "one proven bound caller mints exactly one gap"
    );
    assert!(
        conv.scene.coordinator.proven_image_count()
            <= conv.scene.coordinator.semantic_bindings().len(),
        "minting keeps the bound"
    );
}

#[test]
fn native_semantic_adjudicator_stages_genuine_unscanned() {
    let mut conv = ConversionScene::new();
    let pid = std::process::id();
    let detailed = conv.detailed();
    let image = conv.image;
    let mid = conv
        .scene
        .coordinator
        .registry()
        .module_id_for(&conv.scene.module.clone())
        .unwrap();
    let mapping = |conv: &ConversionScene| {
        conv.scene
            .coordinator
            .registry()
            .edge(conv.caller, mid)
            .unwrap()
            .mapping
    };

    // Control: with no marker the adjudicator stages nothing.
    conv.scene
        .coordinator
        .adjudicate_provisional_unscanned(false);
    conv.commit();
    assert_eq!(mapping(&conv), MappingState::Mapped);

    // A live marker in an incomplete publication stages the genuine
    // uncertainty itself: the edge demotes with its reason.
    conv.scene
        .coordinator
        .reference_stage_adjudication(conv.caller, pid);
    conv.scene
        .coordinator
        .adjudicate_provisional_unscanned(false);
    conv.commit();
    assert_eq!(
        mapping(&conv),
        MappingState::Uncertain,
        "the genuine arm demotes the unscanned member"
    );
    assert_eq!(
        conv.scene
            .coordinator
            .registry()
            .edge(conv.caller, mid)
            .unwrap()
            .mapping_reason
            .as_deref(),
        Some("member was not scanned this pass; the mapping is neither confirmed nor refuted")
    );

    // The same arm stages the tail too: adjudicating twice still mints
    // exactly one gap (markers drain; the tail never duplicates).
    conv.scene
        .coordinator
        .reference_stage_adjudication(conv.caller, pid);
    conv.scene
        .coordinator
        .adjudicate_provisional_unscanned(false);
    conv.scene
        .coordinator
        .adjudicate_provisional_unscanned(false);
    conv.scene
        .coordinator
        .reference_prove_image(detailed, image);
    conv.lane.script_cut_barrier(2);
    conv.commit_with_lane();
    assert_eq!(
        conv.lane.take_recorded_gaps().len(),
        1,
        "the adjudicated tail mints exactly one gap"
    );
}

#[test]
fn native_semantic_finalize_invalidation_covers_domain_reasons() {
    // Each positioned domain scope stages one domain loss with its own
    // reason and retires nothing: no fake retirement, no silent revival.
    let scopes: Vec<(InvalidationScope, Vec<InstanceReason>, Vec<InstanceReason>)> = vec![
        (
            InvalidationScope::CoverageFailed,
            vec![InstanceReason::SemanticLoss],
            vec![
                InstanceReason::CaptureStopped,
                InstanceReason::TaskRetired,
                InstanceReason::AuthorityExhausted,
            ],
        ),
        (
            InvalidationScope::AuthorityExhausted,
            vec![InstanceReason::AuthorityExhausted],
            vec![InstanceReason::SemanticLoss],
        ),
        (
            InvalidationScope::Stopped,
            vec![InstanceReason::SemanticLoss, InstanceReason::CaptureStopped],
            vec![
                InstanceReason::TaskRetired,
                InstanceReason::AuthorityExhausted,
            ],
        ),
        (
            InvalidationScope::TaskRetired(7),
            vec![InstanceReason::SemanticLoss, InstanceReason::TaskRetired],
            vec![
                InstanceReason::CaptureStopped,
                InstanceReason::AuthorityExhausted,
            ],
        ),
    ];
    for (scope, present, absent) in scopes {
        let name = match scope {
            InvalidationScope::CoverageFailed => "coverage_failed",
            InvalidationScope::AuthorityExhausted => "authority_exhausted",
            InvalidationScope::Stopped => "stopped",
            InvalidationScope::TaskRetired(_) => "task_retired",
            _ => unreachable!("domain-scope legs only"),
        };
        let mut conv = ConversionScene::new();
        let r0 = conv.ids[0];
        let coverage = conv.coverage(vec![r0]);
        conv.register(&coverage, r0, 100, None);
        conv.commit();
        let (losses, retirements) =
            finalize_invalidation(&scope, Some(5), conv.detailed(), None, &[]).unwrap();
        assert!(retirements.is_empty(), "{name} never retires");
        assert_eq!(losses.len(), 1, "{name} stages one domain loss");
        for loss in losses {
            conv.scene
                .coordinator
                .registry_mut()
                .note_instance_semantic_loss(loss);
        }
        conv.commit();
        let reasons = conv.edge_reasons(0);
        for reason in &present {
            assert!(
                reasons.contains(reason),
                "{name} discloses {reason:?}, got {reasons:?}"
            );
        }
        for reason in &absent {
            assert!(
                !reasons.contains(reason),
                "{name} discloses no {reason:?}, got {reasons:?}"
            );
        }
        assert_eq!(
            conv.instance_states(),
            vec![InstanceLifecycle::Uncertain],
            "{name} ends the operation unknown"
        );
    }
}

/// Map one more provider module for the same caller, so partition-scope
/// legs can tell module-narrow losses from image-wide ones.
fn map_sibling_module(conv: &mut ConversionScene, key: &ModuleKey, path: &str, at_ns: u64) {
    let info = ModuleInfo {
        path: path.into(),
        key: key.clone(),
        double_loaded: false,
        build_id: None,
        identity_source: Some("task3".into()),
        admission: AdmissionState::Admitted,
        admission_class: Some("exact".into()),
        admission_endpoints: Some(1),
        admission_reasons: Vec::new(),
    };
    conv.scene.coordinator.registry_mut().note_mapping(
        conv.caller,
        std::process::id(),
        info,
        at_ns,
    );
    conv.scene.coordinator.commit_batch(false).unwrap();
}

#[test]
fn native_semantic_finalize_invalidation_narrows_partition_scopes() {
    let other = ModuleKey::physical(7, 7, 778, None, "/task3/other.so");

    // File invalidation with a position narrows to the bound module:
    // only that module's edge fences, the sibling module stays clean.
    let mut conv = ConversionScene::new();
    let (r0, r1) = (conv.ids[0], conv.ids[1]);
    map_sibling_module(&mut conv, &other, "/task3/other.so", 70);
    let coverage = conv.coverage(vec![r0]);
    conv.register(&coverage, r0, 100, None);
    let sibling_binding = SemanticCallerBinding::scripted(
        conv.caller,
        other.clone(),
        conv.detailed(),
        conv.image,
        conv.binding().pin(),
    );
    let sibling_coverage = LaneCoverage::scripted(
        conv.detailed(),
        conv.image,
        conv.endpoint(conv.init_slot),
        vec![r1],
    );
    let input =
        admit_registration_from_coverage(&sibling_coverage, &sibling_binding, r1, 100, None)
            .expect("sibling module registers");
    conv.scene.coordinator.registry_mut().note_instance(input);
    conv.commit();
    let (losses, retirements) = {
        let binding = conv.binding();
        finalize_invalidation(
            &InvalidationScope::File {
                image: conv.image,
                file_slot: 0,
            },
            Some(5),
            conv.detailed(),
            Some(binding),
            &[],
        )
        .unwrap()
    };
    assert!(retirements.is_empty());
    assert_eq!(losses.len(), 1);
    for loss in losses {
        conv.scene
            .coordinator
            .registry_mut()
            .note_instance_semantic_loss(loss);
    }
    conv.commit();
    assert_eq!(
        conv.edge_rows().iter().map(|row| row.2).collect::<Vec<_>>(),
        vec![true, false],
        "module narrowing fences only the bound module"
    );
    assert_eq!(
        conv.instance_states(),
        vec![InstanceLifecycle::Uncertain, InstanceLifecycle::Observed]
    );

    // Without a binding the same file scope widens to the image: both
    // modules fence.
    let mut conv = ConversionScene::new();
    let (r0, r1) = (conv.ids[0], conv.ids[1]);
    map_sibling_module(&mut conv, &other, "/task3/other.so", 70);
    let coverage = conv.coverage(vec![r0]);
    conv.register(&coverage, r0, 100, None);
    let sibling_binding = SemanticCallerBinding::scripted(
        conv.caller,
        other.clone(),
        conv.detailed(),
        conv.image,
        conv.binding().pin(),
    );
    let sibling_coverage = LaneCoverage::scripted(
        conv.detailed(),
        conv.image,
        conv.endpoint(conv.init_slot),
        vec![r1],
    );
    let input =
        admit_registration_from_coverage(&sibling_coverage, &sibling_binding, r1, 100, None)
            .expect("sibling module registers");
    conv.scene.coordinator.registry_mut().note_instance(input);
    conv.commit();
    let (losses, retirements) = finalize_invalidation(
        &InvalidationScope::File {
            image: conv.image,
            file_slot: 0,
        },
        Some(5),
        conv.detailed(),
        None,
        &[],
    )
    .unwrap();
    assert!(retirements.is_empty());
    assert_eq!(losses.len(), 1);
    for loss in losses {
        conv.scene
            .coordinator
            .registry_mut()
            .note_instance_semantic_loss(loss);
    }
    conv.commit();
    assert_eq!(
        conv.edge_rows().iter().map(|row| row.2).collect::<Vec<_>>(),
        vec![true, true],
        "imageless file scope fences the whole image"
    );
    assert_eq!(
        conv.instance_states(),
        vec![InstanceLifecycle::Uncertain, InstanceLifecycle::Uncertain]
    );

    // A superseded partition without fresh proof is exact loss per id,
    // never retirement: listed ids fence, the sibling stays clean.
    let mut conv = ConversionScene::new();
    let (p0, p1, s0) = (conv.ids[0], conv.ids[1], conv.ids[2]);
    let coverage = conv.coverage(vec![p0, p1, s0]);
    conv.register(&coverage, p0, 100, None);
    conv.register(&coverage, p1, 100, None);
    conv.register(&coverage, s0, 100, None);
    conv.commit();
    let (losses, retirements) = {
        let binding = conv.binding();
        finalize_invalidation(
            &InvalidationScope::InstancesRetired {
                image: conv.image,
                file_slot: 0,
                ids: vec![p0, p1],
            },
            Some(7),
            conv.detailed(),
            Some(binding),
            &[],
        )
        .unwrap()
    };
    assert!(retirements.is_empty(), "no fresh proof retires nothing");
    assert_eq!(losses.len(), 2, "one exact loss per superseded id");
    for loss in losses {
        conv.scene
            .coordinator
            .registry_mut()
            .note_instance_semantic_loss(loss);
    }
    conv.commit();
    assert_eq!(
        conv.edge_rows().iter().map(|row| row.2).collect::<Vec<_>>(),
        vec![true, true, false],
        "exact loss spares the sibling"
    );
    assert_eq!(
        conv.instance_states(),
        vec![
            InstanceLifecycle::Uncertain,
            InstanceLifecycle::Uncertain,
            InstanceLifecycle::Observed
        ]
    );

    // Without a binding even a fresh partition cannot retire: the
    // fallback is one wide image loss, never exact retirement.
    let mut conv = ConversionScene::new();
    let (r0, r1) = (conv.ids[0], conv.ids[1]);
    let coverage = conv.coverage(vec![r0, r1]);
    conv.register(&coverage, r0, 100, None);
    conv.register(&coverage, r1, 100, None);
    conv.commit();
    let fresh = conv.coverage(vec![conv.ids[9]]);
    let (losses, retirements) = finalize_invalidation(
        &InvalidationScope::InstancesRetired {
            image: conv.image,
            file_slot: 0,
            ids: vec![r0],
        },
        Some(7),
        conv.detailed(),
        None,
        std::slice::from_ref(&fresh),
    )
    .unwrap();
    assert!(
        retirements.is_empty(),
        "no binding mints no exact retirement"
    );
    assert_eq!(losses.len(), 1, "the fallback is one image loss");
    for loss in losses {
        conv.scene
            .coordinator
            .registry_mut()
            .note_instance_semantic_loss(loss);
    }
    conv.commit();
    assert_eq!(
        conv.edge_rows().iter().map(|row| row.2).collect::<Vec<_>>(),
        vec![true, true],
        "the image fallback is deliberately wide"
    );
}

#[test]
fn native_semantic_convert_refuses_unbound_module_and_foreign_coverage() {
    let conv = ConversionScene::new();
    let r0 = conv.ids[0];
    let coverage = conv.coverage(vec![r0]);
    let subset = conv.lane.subset();
    let binding = conv.binding();
    let good = conv.evidence(1, r0, conv.init_slot, conv.init_event(110));

    // A binding without an identified module refuses before any
    // descriptor work: production proof never accepts such bindings,
    // so conversion must not either.
    let unidentified = SemanticCallerBinding::scripted(
        conv.caller,
        ModuleKey::Unidentified {
            path: "/task3/unknown.so".into(),
        },
        conv.detailed(),
        conv.image,
        conv.binding().pin(),
    );
    assert_eq!(
        refusal(admit_call_from_evidence(
            good,
            &unidentified,
            subset,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Module)
    );

    // A coverage from another domain proves nothing here.
    let foreign = NativeDomainId::mint();
    let foreign_coverage =
        LaneCoverage::scripted(foreign, conv.image, conv.endpoint(conv.init_slot), vec![r0]);
    assert_eq!(
        refusal(admit_call_from_evidence(
            conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
            binding,
            subset,
            CallStanding::Current(&foreign_coverage),
            None
        )),
        Err(ConversionRefusal::Coverage)
    );
}

/// The attested plan with one scripted init-slot shape: descriptor
/// degradations `prepare` never admits, for the defense-in-depth arms.
fn subset_with_init_shape(
    conv: &ConversionScene,
    shape: impl FnOnce(&mut crate::plan::Slot),
) -> AttestedSubset {
    let lane_subset = conv.lane.subset();
    let mut plan = lane_subset.plan().clone();
    let slot = plan
        .slots
        .iter_mut()
        .find(|slot| slot.index == conv.init_slot)
        .expect("attested init slot");
    shape(slot);
    AttestedSubset::scripted(
        plan,
        lane_subset.pins().clone(),
        lane_subset.required().clone(),
    )
}

#[test]
fn native_semantic_convert_refuses_unauthorized_descriptor_shapes() {
    let conv = ConversionScene::new();
    let r0 = conv.ids[0];
    let coverage = conv.coverage(vec![r0]);
    let binding = conv.binding();

    // Control: the unmodified attested plan converts.
    let proven = subset_with_init_shape(&conv, |_| {});
    assert!(
        admit_call_from_evidence(
            conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
            binding,
            &proven,
            CallStanding::Current(&coverage),
            None
        )
        .is_ok()
    );

    // Each degraded shape refuses through the slot arm.
    let unauthorized = subset_with_init_shape(&conv, |slot| slot.semantic_authorized = false);
    assert_eq!(
        refusal(admit_call_from_evidence(
            conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
            binding,
            &unauthorized,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Slot),
        "an unauthorized descriptor refuses"
    );
    let aliased = subset_with_init_shape(&conv, |slot| slot.aliased = true);
    assert_eq!(
        refusal(admit_call_from_evidence(
            conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
            binding,
            &aliased,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Slot),
        "an aliased descriptor refuses"
    );
    let ambiguous = subset_with_init_shape(&conv, |slot| slot.semantic_ambiguous = true);
    assert_eq!(
        refusal(admit_call_from_evidence(
            conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
            binding,
            &ambiguous,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Slot),
        "an ambiguous descriptor refuses"
    );
    let nameless = subset_with_init_shape(&conv, |slot| slot.names.clear());
    assert_eq!(
        refusal(admit_call_from_evidence(
            conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
            binding,
            &nameless,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Slot),
        "a nameless descriptor refuses"
    );
    let count_only =
        subset_with_init_shape(&conv, |slot| slot.semantics = SlotSemantics::COUNT_ONLY);
    assert_eq!(
        refusal(admit_call_from_evidence(
            conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
            binding,
            &count_only,
            CallStanding::Current(&coverage),
            None
        )),
        Err(ConversionRefusal::Slot),
        "a count-only descriptor refuses"
    );
}

#[test]
fn native_semantic_register_refuses_domain_and_custody_mismatch() {
    let conv = ConversionScene::new();
    let r0 = conv.ids[0];
    let binding = conv.binding();

    // A foreign domain's coverage never registers here.
    let foreign = NativeDomainId::mint();
    let foreign_coverage =
        LaneCoverage::scripted(foreign, conv.image, conv.endpoint(conv.init_slot), vec![r0]);
    assert_eq!(
        refusal(admit_registration_from_coverage(
            &foreign_coverage,
            binding,
            r0,
            100,
            None
        )),
        Err(ConversionRefusal::Domain)
    );

    // A superseded exec proves nothing for this binding either.
    let stale = LaneCoverage::scripted(
        conv.detailed(),
        ImageIdentity {
            task_cookie: 7,
            exec_id: 99,
        },
        conv.endpoint(conv.init_slot),
        vec![r0],
    );
    assert_eq!(
        refusal(admit_registration_from_coverage(
            &stale, binding, r0, 100, None
        )),
        Err(ConversionRefusal::Custody)
    );
}

#[test]
fn native_semantic_binding_refuses_domain_conflict() {
    set_sight(1_005);
    let mut scene = BindingScene::new();
    let pid = std::process::id();
    let module = scene.module.clone();
    let (detailed, inventory) = (scene.detailed, scene.inventory);
    let caller = scene.admit(pid, 50);
    scene.map(caller, pid, 60);
    let image = ImageIdentity {
        task_cookie: 7,
        exec_id: 1,
    };
    scene.answer(pid, detailed, 7);
    scene.bind_image(detailed, vec![(7, 1, pid, 100)], 1_000);
    assert_eq!(scene.bind(caller, &module, detailed, image), Ok(()));

    // The same caller under a second domain refuses: one binding per
    // caller mirrors H0's per-cookie association.
    assert_eq!(
        scene.bind(caller, &module, inventory, image),
        Err(SemanticBindingRefusal::DomainConflict)
    );
    assert_eq!(
        scene
            .coordinator
            .semantic_bindings()
            .get(caller)
            .unwrap()
            .domain(),
        detailed,
        "the refused rebind keeps the original domain"
    );
    assert_eq!(scene.bind(caller, &module, detailed, image), Ok(()));
}

/// A scripted [`SemanticStopIo`]: the same orchestration the live lane
/// runs, driven without a Session. Drain batches carry ascending
/// `observed_ns` markers; the Finish batch carries `u64::MAX`, so batch
/// order is observable without forging H0 outcomes.
struct ScriptedStopIo {
    domain: crate::attach::capture::NativeDomainId,
    gated: std::cell::Cell<bool>,
    quiesce_after: usize,
    services: usize,
    quiesce_failures: usize,
    positions: [(usize, usize); 2],
    advance_per_service: [(usize, usize); 2],
    fail_positions: bool,
    position_reads: usize,
    drain_markers: Vec<u64>,
    events_drain: LaneDrainOutcome,
    discovery_drain: LaneDrainOutcome,
    events_stops: Vec<usize>,
    discovery_stops: Vec<usize>,
    finish_calls: usize,
    cuts: u64,
    next_marker: u64,
}

impl ScriptedStopIo {
    fn new(domain: crate::attach::capture::NativeDomainId) -> Self {
        Self {
            domain,
            gated: std::cell::Cell::new(false),
            quiesce_after: 0,
            services: 0,
            quiesce_failures: 0,
            positions: [(0, 0), (0, 0)],
            advance_per_service: [(0, 0), (0, 0)],
            fail_positions: false,
            position_reads: 0,
            drain_markers: Vec::new(),
            events_drain: LaneDrainOutcome::default(),
            discovery_drain: LaneDrainOutcome::default(),
            events_stops: Vec::new(),
            discovery_stops: Vec::new(),
            finish_calls: 0,
            cuts: 0,
            next_marker: 1,
        }
    }

    fn batch(&mut self, marker: u64) -> crate::inventory_semantics::SemanticBatch {
        crate::inventory_semantics::SemanticBatch::scripted(self.domain, Vec::new(), marker)
    }
}

impl SemanticStopIo for ScriptedStopIo {
    fn request_stop(&self) {
        self.gated.set(true);
    }

    fn quiescent(&self) -> bool {
        self.services >= self.quiesce_after
    }

    fn service_quantum(
        &mut self,
    ) -> Result<Option<crate::inventory_semantics::SemanticBatch>, SemanticRefusal> {
        self.services += 1;
        self.positions[0].0 = self.positions[0]
            .0
            .saturating_add(self.advance_per_service[0].0)
            .min(self.positions[0].1 + self.advance_per_service[0].1);
        self.positions[1].0 = self.positions[1]
            .0
            .saturating_add(self.advance_per_service[1].0)
            .min(self.positions[1].1 + self.advance_per_service[1].1);
        if self.services <= self.quiesce_failures {
            return Err(SemanticRefusal::Unavailable);
        }
        if self.drain_markers.is_empty() {
            return Ok(None);
        }
        let marker = self.drain_markers.remove(0);
        self.next_marker = self.next_marker.max(marker + 1);
        Ok(Some(self.batch(marker)))
    }

    fn positions(&mut self) -> Option<[(usize, usize); 2]> {
        self.position_reads += 1;
        if self.fail_positions {
            return None;
        }
        Some(self.positions)
    }

    fn drain_events_to(&mut self, stop: usize, _quantum: usize) -> LaneDrainOutcome {
        self.events_stops.push(stop);
        self.events_drain
    }

    fn drain_discovery_to(&mut self, stop: usize, _quantum: usize) -> LaneDrainOutcome {
        self.discovery_stops.push(stop);
        self.discovery_drain
    }

    fn finish_h0(&mut self) -> crate::inventory_semantics::SemanticBatch {
        self.finish_calls += 1;
        self.batch(u64::MAX)
    }

    fn continuity_cuts(&self) -> u64 {
        self.cuts
    }
}

#[test]
fn native_semantic_stop_orders_gate_drain_finish_output() {
    use crate::inventory_semantics::run_semantic_stop;
    use std::time::{Duration, Instant};
    let domain = crate::attach::capture::NativeDomainId::mint();
    let clock = |ticks: Vec<Duration>| {
        let start = Instant::now();
        let mut at = 0;
        move || {
            let step = ticks
                .get(at)
                .copied()
                .unwrap_or(Duration::from_secs(3600 * 24 * 365));
            at += 1;
            start + step
        }
    };

    // Clean quiesced drain: the gate is requested immediately, bounded
    // audited quanta run while waiting, both producer positions are
    // captured at Q, the same owned cursors drain exactly to Q, and H0
    // stops once after every drained batch.
    let mut io = ScriptedStopIo::new(domain);
    io.quiesce_after = 2;
    io.positions = [(0, 16), (0, 8)];
    io.advance_per_service = [(8, 0), (4, 0)];
    io.drain_markers = vec![1, 2];
    io.cuts = 3;
    let mut markers = Vec::new();
    let summary = run_semantic_stop(
        &mut io,
        Duration::from_secs(5),
        16,
        1024,
        clock(vec![
            Duration::ZERO,
            Duration::from_millis(1),
            Duration::from_millis(2),
        ]),
        |batch| markers.push(batch.observed_ns()),
    );
    assert!(io.gated.get(), "the stop request gates immediately");
    assert!(summary.quiesced);
    assert_eq!(
        summary.q,
        Some(crate::run::TerminalQuiescence {
            events_q: 16,
            discovery_q: 8,
        }),
        "Q captures both producer positions"
    );
    assert_eq!(
        markers,
        vec![1, 2, u64::MAX],
        "drained batches finalize before Finish"
    );
    assert_eq!(io.finish_calls, 1, "H0 stops exactly once");
    assert_eq!(summary.drain_batches, 2);
    assert_eq!(summary.continuity_cuts, 3);
    assert!(!summary.semantic_loss);
    assert!(summary.final_drain);
    assert_eq!(io.events_stops, vec![16]);
    assert_eq!(io.discovery_stops, vec![8]);

    // A delayed last return drained after Q still finalizes before the
    // Finish batch: the stop request is not Finish.
    let mut io = ScriptedStopIo::new(domain);
    io.quiesce_after = 0;
    io.positions = [(0, 16), (0, 0)];
    io.advance_per_service = [(16, 0), (0, 0)];
    io.drain_markers = vec![7];
    let mut markers = Vec::new();
    let summary = run_semantic_stop(
        &mut io,
        Duration::from_secs(5),
        16,
        1024,
        clock(vec![Duration::ZERO]),
        |batch| markers.push(batch.observed_ns()),
    );
    assert_eq!(markers, vec![7, u64::MAX]);
    assert!(summary.final_drain);

    // Quiesce refusals (pending H0 work that will not route) never stall
    // the wait: they count, and the Finish batch still expires joins.
    let mut io = ScriptedStopIo::new(domain);
    io.quiesce_after = 3;
    io.quiesce_failures = 2;
    io.positions = [(0, 0), (0, 0)];
    let mut markers = Vec::new();
    let summary = run_semantic_stop(
        &mut io,
        Duration::from_secs(5),
        16,
        1024,
        clock(vec![Duration::ZERO; 8]),
        |batch| markers.push(batch.observed_ns()),
    );
    assert_eq!(summary.quiesce_refusals, 2);
    assert_eq!(markers, vec![u64::MAX]);
    assert_eq!(io.finish_calls, 1);
    assert!(summary.final_drain);

    // Pending-expiry below the scripted refusals: the refusals above
    // count H0 quanta that will not route, but join expiry is a router
    // transition, not a count. Drive the production router directly:
    // unobserved calls pend real joins, and `expire_image` — the exact
    // call `SemanticCapture::stop` makes per awaiting image — resolves
    // that image's joins as unknown while other images stay pending.
    use crate::discovery::instances::UnknownReason;
    let mut router = InstanceRouter::new(domain, RouterLimits::default());
    let stamp = InstanceStamp {
        epoch: 1,
        global: 0,
        fault: 0,
        file_slot_plus1: 1,
        flags: STAMP_VALID,
    };
    let facts = |token: u64, cookie: u64| CallFacts {
        token,
        domain,
        image: ImageIdentity {
            task_cookie: cookie,
            exec_id: 0,
        },
        entry: stamp,
        ret: stamp,
        ip: EntryIp::new(0x7000_1000),
        attached_offset: Some(0x1000),
    };
    assert_eq!(router.route(facts(11, 71)), Route::Pending);
    assert_eq!(router.route(facts(12, 72)), Route::Pending);
    assert_eq!(router.pending_len(), 2, "unobserved calls pend joins");
    let resolved = router.expire_image(ImageIdentity {
        task_cookie: 71,
        exec_id: 0,
    });
    assert_eq!(
        resolved,
        vec![(11, Route::Unknown(UnknownReason::Unobserved))]
    );
    assert_eq!(router.pending_len(), 1, "expiry is image-scoped");
    // TASK6-LIVE: live H0 `SemanticCapture::stop()` expiring a real
    // awaiting join, with the expiry resolution observed in the Finish
    // batch of an installed loss-recovery cell.

    // Quiescence timeout: the 5 s budget ends the wait unproven, only
    // one bounded poll drains each cursor under the terminal bound, and
    // semantic loss is declared with positive history preserved.
    let mut io = ScriptedStopIo::new(domain);
    io.quiesce_after = usize::MAX;
    io.positions = [(4, 40), (2, 20)];
    io.events_drain = LaneDrainOutcome {
        records: 3,
        post_q: false,
        backlog: true,
        failed: false,
    };
    let mut markers = Vec::new();
    let summary = run_semantic_stop(
        &mut io,
        Duration::from_secs(5),
        16,
        1024,
        clock(vec![
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(3),
            Duration::from_secs(4),
            Duration::from_secs(5),
            Duration::from_secs(6),
        ]),
        |batch| markers.push(batch.observed_ns()),
    );
    assert!(!summary.quiesced);
    assert_eq!(summary.q, None);
    assert!(summary.semantic_loss);
    assert!(!summary.final_drain);
    assert_eq!(io.services, 4, "bounded audited work while waiting");
    assert_eq!(io.events_stops, vec![40], "one terminal-bound poll");
    assert_eq!(io.discovery_stops, vec![20]);
    assert_eq!(summary.unrouted_returns, 3);
    assert_eq!(markers, vec![u64::MAX], "the Finish batch still finalizes");

    // An unreadable ring at Q capture declares loss without hanging or
    // certifying a drain; the Finish batch still runs once.
    let mut io = ScriptedStopIo::new(domain);
    io.quiesce_after = 0;
    io.fail_positions = true;
    let mut markers = Vec::new();
    let summary = run_semantic_stop(
        &mut io,
        Duration::from_secs(5),
        16,
        1024,
        clock(vec![Duration::ZERO]),
        |batch| markers.push(batch.observed_ns()),
    );
    assert!(summary.quiesced);
    assert!(summary.semantic_loss);
    assert!(!summary.final_drain);
    assert!(io.events_stops.is_empty());
    assert_eq!(markers, vec![u64::MAX]);
    assert_eq!(io.finish_calls, 1);

    // A post-Q writer is detected and reported, and the drain is not
    // certified; the violation is disclosure, not silent loss.
    let mut io = ScriptedStopIo::new(domain);
    io.quiesce_after = 0;
    io.positions = [(16, 16), (8, 8)];
    io.events_drain = LaneDrainOutcome {
        records: 0,
        post_q: true,
        backlog: false,
        failed: false,
    };
    let summary = run_semantic_stop(
        &mut io,
        Duration::from_secs(5),
        16,
        1024,
        clock(vec![Duration::ZERO]),
        |_| {},
    );
    assert!(summary.post_q_events);
    assert!(!summary.post_q_discovery);
    assert!(!summary.final_drain);
    assert!(!summary.semantic_loss);

    // A failed drain read declares loss and refuses certification.
    let mut io = ScriptedStopIo::new(domain);
    io.quiesce_after = 0;
    io.positions = [(16, 16), (8, 8)];
    io.discovery_drain = LaneDrainOutcome {
        records: 0,
        post_q: false,
        backlog: true,
        failed: true,
    };
    let summary = run_semantic_stop(
        &mut io,
        Duration::from_secs(5),
        16,
        1024,
        clock(vec![Duration::ZERO]),
        |_| {},
    );
    assert!(summary.semantic_loss);
    assert!(!summary.final_drain);

    // Failed startup finishes nothing: no gate, no drain, no Finish
    // batch, and no disturbance to positive history elsewhere.
    let mut conv = ConversionScene::new();
    conv.lane.mark_startup_failed();
    assert!(!conv.lane.is_live());
    let mut batches = 0;
    let summary = conv
        .lane
        .run_semantic_stop(&[], clock(vec![Duration::ZERO]), |_| {
            batches += 1;
        });
    assert_eq!(batches, 0);
    assert!(!summary.quiesced);
    assert!(!summary.final_drain);
    assert_eq!(
        conv.lane.semantic_summary().status,
        SemanticCaptureStatus::Unavailable
    );
    // A shell lane without any startup attempt reports disabled with a
    // null final drain: no manifests, no Detailed anything.
    let quiet = ConversionScene::new();
    let summary = quiet.lane.semantic_summary();
    assert_eq!(summary.status, SemanticCaptureStatus::Disabled);
    assert_eq!(
        summary.stop_quiescence,
        SemanticStopQuiescence::NotRequested
    );
    assert_eq!(summary.final_drain, None);
    assert_eq!(
        summary.json(),
        serde_json::json!({
            "status": "disabled",
            "admitted_endpoints": 0,
            "refused_endpoints": 0,
            "continuity_cuts": 0,
            "unrouted_returns": 0,
            "stop_quiescence": "not_requested",
            "final_drain": null,
        })
    );
    let stopped = SemanticCaptureSummary {
        status: SemanticCaptureStatus::Stopped,
        admitted_endpoints: 4,
        refused_endpoints: 1,
        continuity_cuts: 2,
        unrouted_returns: 3,
        stop_quiescence: SemanticStopQuiescence::Quiesced,
        final_drain: Some(true),
    };
    assert_eq!(stopped.json()["status"], "stopped");
    assert_eq!(stopped.json()["stop_quiescence"], "quiesced");
    assert_eq!(stopped.json()["final_drain"], true);

    // Finish certifies nothing about Inventory: the terminal batches
    // commit beside the registry without mutating it, and a repeat
    // commit stays quiet. One producer's stop never settles the other.
    let mut conv = ConversionScene::new();
    let r0 = conv.ids[0];
    let coverage = conv.coverage(vec![r0]);
    conv.register(&coverage, r0, 100, None);
    conv.feed(
        conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.feed(
        conv.evidence(2, r0, conv.sign_slot, conv.sign_event(120)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.commit_with_lane();
    let before = (conv.edge_rows(), conv.instance_states(), conv.gap_pairs());
    let lane_domain = conv.lane.domain();
    let mut io = ScriptedStopIo::new(lane_domain);
    io.quiesce_after = 0;
    io.positions = [(0, 0), (0, 0)];
    let mut terminal = Vec::new();
    let summary = run_semantic_stop(
        &mut io,
        Duration::from_secs(5),
        16,
        1024,
        clock(vec![Duration::ZERO]),
        |batch| terminal.push(batch),
    );
    assert!(summary.final_drain);
    for batch in terminal {
        conv.scene.coordinator.stage_semantic_batch(batch);
        conv.commit_with_lane();
    }
    conv.commit_with_lane();
    assert_eq!(
        (conv.edge_rows(), conv.instance_states(), conv.gap_pairs()),
        before,
        "the semantic Finish mutates no reducer and settles nothing else"
    );

    // The reverse direction: Inventory-side terminal work never
    // certifies the semantic lane. Pure-Inventory commits and a
    // retirement disclosure leave the lane's stop accounting
    // untouched, and the Inventory-side gap discloses verbatim beside
    // semantic rows through the shared audited path.
    let lane_before = conv.lane.semantic_summary();
    assert_eq!(lane_before.status, SemanticCaptureStatus::Disabled);
    conv.commit();
    conv.scene.coordinator.note_scope_gap(
        "native capture retirement unsettled".into(),
        "budget passed".into(),
    );
    conv.commit();
    let lane_after = conv.lane.semantic_summary();
    assert_eq!(lane_after.status, SemanticCaptureStatus::Disabled);
    assert_eq!(
        lane_after.stop_quiescence,
        SemanticStopQuiescence::NotRequested,
        "Inventory commits never certify semantic quiescence"
    );
    assert_eq!(lane_after.final_drain, None);
    assert!(
        conv.gap_pairs().contains(&(
            "native capture retirement unsettled".to_string(),
            "budget passed".to_string()
        )),
        "the Inventory-side disclosure survives, got {:?}",
        conv.gap_pairs()
    );
    let gaps_after_inventory = conv.gap_pairs();
    conv.commit();
    assert_eq!(
        conv.gap_pairs(),
        gaps_after_inventory,
        "a repeat Inventory commit stays quiet"
    );
    // TASK6-LIVE: one live loop with a quiesced H0 lane and an
    // unsettled native retirement, asserting the observation shows
    // semantic_capture.stop_quiescence=quiesced beside
    // settlement=unsettled.

    // Output legs: a slow, broken or signal-cancelled stdout records
    // its failure while the event stream still completes with the
    // semantic summary; a broken event sink likewise never suppresses
    // the document. Both owners stay preserved through every attempt.
    use crate::inventory::{EventLogState, StreamState, finish_output};
    use crate::inventory_events::EventWriter;
    use crate::inventory_output::{FinalStdout, StdoutFailure, StdoutFailureReason, StdoutResult};
    struct FailingStdout {
        reason: Option<StdoutFailureReason>,
        pub written: Vec<u8>,
    }
    impl FinalStdout for FailingStdout {
        fn begin_finalization(&mut self) {}
        fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
            self.written.extend_from_slice(bytes);
            match self.reason.take() {
                None => Ok(bytes.len()),
                Some(StdoutFailureReason::Io(error)) => Err(StdoutFailure {
                    accepted: 0,
                    total: bytes.len(),
                    reason: StdoutFailureReason::Io(error),
                }),
                Some(reason) => Err(StdoutFailure {
                    accepted: 0,
                    total: bytes.len(),
                    reason,
                }),
            }
        }
    }
    let output_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        output_dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    for (name, reason, expect) in [
        (
            "broken",
            StdoutFailureReason::Io(std::io::Error::other("EPIPE")),
            "I/O error: EPIPE",
        ),
        (
            "slow",
            StdoutFailureReason::NoProgress,
            "no progress for 5 seconds",
        ),
        (
            "second-signal",
            StdoutFailureReason::Cancelled,
            "cancelled by a later signal",
        ),
    ] {
        let path = output_dir.path().join(format!("{name}.jsonl"));
        let writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
        let mut stdout = FailingStdout {
            reason: Some(reason),
            written: Vec::new(),
        };
        let mut presentation = crate::inventory_present::Presentation::capture(
            &conv.scene.coordinator,
            "test",
            0,
            500,
            6,
        );
        presentation.semantic_capture = conv.lane.semantic_summary();
        let outcome = finish_output(
            None,
            &mut EventLogState::new(Some(writer)),
            &mut StreamState::new(),
            &presentation,
            true,
            false,
            &mut stdout,
            None,
        );
        assert_eq!(outcome.exit_code(), 1, "{name} stdout fails the run");
        assert_eq!(outcome.event_log_confirmed(), Some(true));
        assert!(
            outcome.failures().iter().any(|line| line.contains(expect)),
            "{name} stdout discloses its reason, got {:?}",
            outcome.failures()
        );
        if name == "second-signal" {
            assert!(outcome.stdout_cancelled());
        }
        let document: serde_json::Value = serde_json::from_slice(&stdout.written).unwrap();
        assert_eq!(
            document["observation"]["semantic_capture"]["status"], "disabled",
            "{name} stdout still attempted the full document"
        );
    }
    // A broken event sink (a planted rotation link) fails the stream
    // while the document still completes with its semantic summary.
    let events = output_dir.path().join("broken.jsonl");
    let writer = EventWriter::create(&events, 64, 2).unwrap();
    let victim = output_dir.path().join("victim.txt");
    std::fs::write(&victim, b"do not touch").unwrap();
    std::os::unix::fs::symlink(&victim, output_dir.path().join("broken.jsonl.1")).unwrap();
    let mut document_bytes = Vec::new();
    let presentation =
        crate::inventory_present::Presentation::capture(&conv.scene.coordinator, "test", 0, 500, 6);
    let outcome = finish_output(
        None,
        &mut EventLogState::new(Some(writer)),
        &mut StreamState::new(),
        &presentation,
        true,
        false,
        &mut crate::inventory_output::WriterStdout(&mut document_bytes),
        None,
    );
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(outcome.event_log_confirmed(), Some(false));
    assert!(!document_bytes.is_empty());
    let document: serde_json::Value = serde_json::from_slice(&document_bytes).unwrap();
    assert_eq!(
        document["observation"]["semantic_capture"]["status"],
        "disabled"
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
}

#[test]
fn native_semantic_stop_bounds_noisy_terminal_staging() {
    use crate::inventory_semantics::{
        TERMINAL_STAGED_BATCH_CAP, TerminalBatchStage, run_semantic_stop,
    };
    use std::time::{Duration, Instant};
    let domain = crate::attach::capture::NativeDomainId::mint();
    // A noisy producer: several caps of quiesce-wait batches before Q.
    // Phase 1 proves the bound matters; phase 2 proves it holds.
    const NOISE: usize = 4 * TERMINAL_STAGED_BATCH_CAP;
    let scripted = || {
        let mut io = ScriptedStopIo::new(domain);
        io.quiesce_after = NOISE;
        io.positions = [(0, 0), (0, 0)];
        io.drain_markers = (1..=(NOISE as u64)).collect();
        io
    };
    let clock = || {
        let start = Instant::now();
        let mut at = 0;
        move || {
            at += 1;
            start + Duration::from_millis(at)
        }
    };

    // Phase 1 (noise control): unbounded staging would hold every
    // quiesce-wait batch plus Finish — far beyond the cap. If the fake
    // ever goes quiet this fails instead of a vacuous GREEN.
    let mut io = scripted();
    let mut unbounded = Vec::new();
    let summary = run_semantic_stop(
        &mut io,
        Duration::from_secs(5),
        16,
        1024,
        clock(),
        |batch| unbounded.push(batch.observed_ns()),
    );
    assert!(summary.quiesced);
    assert_eq!(summary.drain_batches, NOISE);
    assert_eq!(unbounded.len(), NOISE + 1);
    assert!(
        unbounded.len() > TERMINAL_STAGED_BATCH_CAP,
        "the producer must be noisy enough to overflow the cap"
    );

    // Phase 2 (bound): the stage sheds oldest-first, discloses the
    // shed count, and preserves delivery order with Finish last.
    let mut io = scripted();
    let mut stage = TerminalBatchStage::new();
    let summary = run_semantic_stop(
        &mut io,
        Duration::from_secs(5),
        16,
        1024,
        clock(),
        |batch| stage.push(batch),
    );
    assert!(summary.quiesced);
    assert!(summary.final_drain);
    assert_eq!(summary.drain_batches, NOISE);
    assert_eq!(stage.len(), TERMINAL_STAGED_BATCH_CAP);
    assert!(!stage.is_empty());
    let shed = NOISE + 1 - TERMINAL_STAGED_BATCH_CAP;
    assert_eq!(stage.shed(), shed, "every over-cap batch discloses");
    let markers: Vec<u64> = stage
        .into_batches()
        .map(|batch| batch.observed_ns())
        .collect();
    let mut expected: Vec<u64> = ((shed as u64 + 1)..=(NOISE as u64)).collect();
    expected.push(u64::MAX);
    assert_eq!(markers, expected, "oldest shed, order kept, Finish last");
}

#[test]
fn native_semantic_one_cursor_and_independent_producers() {
    // No manifests means no Detailed anything: subset preparation
    // refuses, no lane starts, and broad Inventory is untouched.
    set_sight(1_005);
    let mut scene = BindingScene::new();
    let pid = std::process::id();
    let caller = scene.admit(pid, 50);
    scene.map(caller, pid, 60);
    let engine = engine_for_test(
        Vec::new(),
        Vec::new(),
        crate::discovery::identity::PinnedObjects::empty(),
    );
    let preparation = prepare_attested_subset(&engine, &[]);
    assert!(preparation.subset.is_none());
    assert!(
        preparation.refusals.contains(&SemanticRefusal::Unattested),
        "no manifests refuses without attesting, got {:?}",
        preparation.refusals
    );

    // A shell lane drives no H0 work: ticks and refreshes refuse
    // instead of inventing calls, and nothing stages behind them.
    let mut conv = ConversionScene::new();
    assert!(!conv.lane.is_live());
    let bindings: Vec<SemanticCallerBinding> = Vec::new();
    assert!(
        matches!(conv.lane.tick(&bindings), Err(SemanticRefusal::Unavailable)),
        "a shell lane refuses ticks instead of inventing calls"
    );
    let pin = conv.binding().pin();
    assert_eq!(
        conv.lane.refresh_candidate(pin, conv.init_slot),
        Err(SemanticRefusal::Unavailable)
    );

    // Interleaved counts and calls commit together: a staged semantic
    // quantum publishes beside physical staging with exact totals.
    let (r0, r1) = (conv.ids[0], conv.ids[1]);
    let coverage = conv.coverage(vec![r0]);
    conv.register(&coverage, r0, 100, None);
    conv.feed(
        conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.feed(
        conv.evidence(2, r0, conv.sign_slot, conv.sign_event(120)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.scene
        .coordinator
        .stage_semantic_batch(SemanticBatch::scripted(conv.detailed(), Vec::new(), 130));
    conv.commit_with_lane();
    assert_eq!(conv.edge_rows(), vec![(Some(2), 0, false, 1, 1)]);
    let mid = conv
        .scene
        .coordinator
        .registry()
        .module_id_for(&conv.scene.module.clone())
        .unwrap();
    let edge = conv
        .scene
        .coordinator
        .registry()
        .edge(conv.caller, mid)
        .unwrap();
    assert_eq!(edge.mapping, MappingState::Mapped);
    assert!(
        edge.semantics.is_none(),
        "instance calls never feed the legacy physical reducer"
    );

    // A foreign batch refuses loudly through the audited path: no
    // positives, no disturbance, broad counts intact.
    let foreign = crate::attach::capture::NativeDomainId::mint();
    conv.scene
        .coordinator
        .stage_semantic_batch(SemanticBatch::scripted(foreign, Vec::new(), 140));
    conv.commit_with_lane();
    assert!(
        conv.gap_pairs().contains(&(
            "semantic batch refused for a foreign domain".into(),
            "the batch names another lane domain; it was dropped through the audited path \
             without staging"
                .into()
        )),
        "foreign batches refuse loudly, got {:?}",
        conv.gap_pairs()
    );
    assert_eq!(
        conv.scene.coordinator.registry().instances().count(),
        1,
        "a foreign batch stages no records"
    );
    assert_eq!(conv.edge_rows(), vec![(Some(2), 0, false, 1, 1)]);

    // Subset failure preserves broad counts: a manifest whose
    // provider the retained pins never saw cannot attest a lane.
    let fixture = ProviderFixture::new();
    let mut bad = fixture.manifest.clone();
    bad.module_path = "/nonexistent/provider.so".to_string();
    let bad_path = fixture.dir.path().join("bad-input.json");
    std::fs::write(&bad_path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let engine = engine_for_test(Vec::new(), Vec::new(), fixture.pins.clone());
    let preparation = prepare_attested_subset(&engine, &[bad_path]);
    assert!(preparation.subset.is_none());
    assert!(
        preparation
            .refusals
            .contains(&SemanticRefusal::ManifestInput),
        "unresolvable manifests refuse at the input, got {:?}",
        preparation.refusals
    );

    // A no-call registration rows unknown: null returns, no operation
    // claims, never observed zeros.
    let coverage1 = conv.coverage(vec![r1]);
    conv.register(&coverage1, r1, 200, None);
    conv.commit_with_lane();
    assert_eq!(
        conv.edge_rows()[1],
        (None, 0, false, 0, 0),
        "no-call rows stay unknown"
    );

    // Per-edge refusal and unknown stay independent of the global
    // usage feed: semantic gaps never flip physical coverage.
    let presentation =
        crate::inventory_present::Presentation::capture(&conv.scene.coordinator, "test", 0, 300, 3);
    assert!(
        !presentation.usage_feed,
        "semantic-only activity never feeds the physical usage signal"
    );
    assert_eq!(presentation.semantic_edges.len(), 2);
    assert!(presentation.edges.iter().all(|edge| edge.entry_count == 0));
}

#[test]
fn native_semantic_finalizer_orchestrates_cut_and_queued_batch_through_commit() {
    use crate::discovery::caller_registry::instance_input::{
        self as instance, Retirement as RefRetirement,
    };
    // TASK3 CARRYOVER (a): end-to-end finalizer orchestration through
    // commit_with_lane with H0-timeline batch inputs. A published pair
    // reduces cleanly before any physical cut.
    let mut conv = ConversionScene::new();
    let (r0, r1) = (conv.ids[0], conv.ids[1]);
    let coverage = conv.coverage(vec![r0]);
    conv.register(&coverage, r0, 100, None);
    conv.feed(
        conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.feed(
        conv.evidence(2, r0, conv.sign_slot, conv.sign_event(120)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.commit_with_lane();
    assert_eq!(conv.edge_rows(), vec![(Some(2), 0, false, 1, 1)]);
    assert_eq!(conv.lane.take_last_conversion_barrier(), None);

    // A retired sibling stays exactly retired: the finalizer invents
    // no retirements and revives none.
    let coverage1 = conv.coverage(vec![r1]);
    conv.register(&coverage1, r1, 150, None);
    conv.commit_with_lane();
    let module = conv.scene.module.clone();
    let detailed = conv.detailed();
    let key = instance::key(detailed, conv.image, r1, module);
    let position = instance::position(detailed, 3);
    conv.scene
        .coordinator
        .registry_mut()
        .retire_instance(instance::retirement(
            RefRetirement::Exact(key),
            position,
            InstanceReason::InstanceRetired,
        ));
    conv.commit_with_lane();
    assert_eq!(
        conv.instance_states(),
        vec![InstanceLifecycle::Observed, InstanceLifecycle::Retired]
    );

    // A staged ordinary quantum plus a tail cut co-finalize in one
    // publication: the cut joins first and its floor fences the queued
    // quantum's conversion barrier.
    conv.scene
        .coordinator
        .stage_semantic_batch(SemanticBatch::scripted(conv.detailed(), Vec::new(), 200));
    conv.prove_and_mark_tail();
    conv.lane.script_cut_barrier(5);
    conv.commit_with_lane();
    assert_eq!(conv.lane.take_recorded_gaps().len(), 1);
    assert_eq!(
        conv.lane.take_last_conversion_barrier(),
        Some(5),
        "the cut floor fences the queued quantum"
    );
    assert_eq!(
        conv.instance_states(),
        vec![InstanceLifecycle::Uncertain, InstanceLifecycle::Retired],
        "the cut invalidates live flesh; the retired sibling is untouched"
    );
    assert_eq!(conv.edge_rows()[0], (Some(2), 0, true, 1, 1));

    // A pending batch's own barrier fences its own calls without any
    // tail cut: the conversion barrier is the batch's own negative.
    conv.scene
        .coordinator
        .stage_semantic_batch(SemanticBatch::scripted(
            conv.detailed(),
            vec![crate::inventory_semantics::LaneNegative::CutBarrier { ordinal: 7 }],
            300,
        ));
    conv.commit_with_lane();
    assert_eq!(conv.lane.take_last_conversion_barrier(), Some(7));
    assert!(conv.lane.take_recorded_gaps().is_empty());

    // Both batches were consumed exactly once: a second commit stages
    // nothing, records nothing, and disturbs nothing.
    let gaps_before = conv.gap_pairs().len();
    conv.commit_with_lane();
    assert_eq!(conv.lane.take_last_conversion_barrier(), None);
    assert_eq!(conv.gap_pairs().len(), gaps_before);
    assert_eq!(
        conv.instance_states(),
        vec![InstanceLifecycle::Uncertain, InstanceLifecycle::Retired]
    );
}

#[test]
fn native_semantic_preminted_call_fenced_by_carried_floor() {
    // TASK3 CARRYOVER (b): a call minted before the cut meets the cut's
    // floor through the finalizer. Conversion admits the call pre-cut
    // (admission evidence only); the converted input drops unstaged.
    let mut conv = ConversionScene::new();
    let r0 = conv.ids[0];
    let coverage = conv.coverage(vec![r0]);
    conv.register(&coverage, r0, 100, None);
    let preminted = conv.evidence(3, r0, conv.init_slot, conv.init_event(130));
    let admitted = conv.convert(preminted, CallStanding::Current(&coverage), None);
    drop(admitted);
    conv.commit_with_lane();
    assert_eq!(conv.edge_rows(), vec![(None, 0, false, 0, 0)]);

    // The tail cut commits through the lane: the finalizer carries the
    // H0-timeline barrier into the publication.
    conv.prove_and_mark_tail();
    conv.lane.script_cut_barrier(5);
    conv.commit_with_lane();
    assert_eq!(conv.lane.take_recorded_gaps().len(), 1);
    let floor = conv.lane.take_last_conversion_barrier();
    assert_eq!(floor, Some(5));

    // The preminted call fenced by the carried floor counts as history
    // only: no machine starts behind the cut.
    conv.feed(
        conv.evidence(3, r0, conv.init_slot, conv.init_event(130)),
        CallStanding::Current(&coverage),
        floor,
    );
    conv.commit_with_lane();
    assert_eq!(
        conv.edge_rows(),
        vec![(Some(1), 1, true, 0, 0)],
        "a preminted call below the carried floor is history-only"
    );

    // A fresh pair above the floor still reduces: fencing is precise,
    // not a blanket refusal.
    conv.feed(
        conv.evidence(6, r0, conv.init_slot, conv.init_event(610)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.feed(
        conv.evidence(7, r0, conv.sign_slot, conv.sign_event(620)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.commit_with_lane();
    assert_eq!(
        conv.edge_rows(),
        vec![(Some(3), 1, true, 1, 1)],
        "fresh calls above the floor reduce with loss disclosed"
    );
}

#[test]
fn native_semantic_live_stream_retention_matches_snapshot() {
    use crate::discovery::caller_registry::instance_input::{self as instance};
    use crate::inventory::{EventLogState, StreamState, finish_output};
    use crate::inventory_events::{EventWriter, InstanceEmitter};
    use crate::inventory_output::WriterStdout;
    fn event_records(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn last_by_kind<'a>(
        records: &'a [serde_json::Value],
        kind: &str,
    ) -> Vec<&'a serde_json::Value> {
        records
            .iter()
            .filter(|record| record["kind"] == kind)
            .map(|record| &record["event"])
            .collect()
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();

    // Three instances: a completed pair, a no-call row, and a retired
    // sibling, beside one physical edge and a repeated refusal gap.
    let mut conv = ConversionScene::new();
    let (r0, r1, r2) = (conv.ids[0], conv.ids[1], conv.ids[2]);
    let coverage = conv.coverage(vec![r0]);
    conv.register(&coverage, r0, 100, None);
    conv.feed(
        conv.evidence(1, r0, conv.init_slot, conv.init_event(110)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.feed(
        conv.evidence(2, r0, conv.sign_slot, conv.sign_event(120)),
        CallStanding::Current(&coverage),
        None,
    );
    let coverage1 = conv.coverage(vec![r1]);
    conv.register(&coverage1, r1, 140, None);
    conv.commit_with_lane();
    let coverage2 = conv.coverage(vec![r2]);
    conv.register(&coverage2, r2, 150, None);
    conv.commit_with_lane();
    let module = conv.scene.module.clone();
    let detailed = conv.detailed();
    conv.scene
        .coordinator
        .registry_mut()
        .retire_instance(instance::retirement(
            instance::Retirement::Exact(instance::key(detailed, conv.image, r2, module)),
            instance::position(detailed, 3),
            InstanceReason::InstanceRetired,
        ));
    // One refusal recorded twice: the stream must carry the exact
    // repeat count, and the sweep must not disturb it.
    let foreign = crate::attach::capture::NativeDomainId::mint();
    conv.scene
        .coordinator
        .stage_semantic_batch(SemanticBatch::scripted(foreign, Vec::new(), 160));
    conv.commit_with_lane();
    conv.scene
        .coordinator
        .stage_semantic_batch(SemanticBatch::scripted(foreign, Vec::new(), 170));
    conv.commit_with_lane();
    let presentation =
        crate::inventory_present::Presentation::capture(&conv.scene.coordinator, "test", 0, 200, 4);
    assert_eq!(presentation.instances.len(), 3);
    assert_eq!(presentation.semantic_edges.len(), 3);
    assert_eq!(presentation.edges.len(), 1);

    // Tiny per-pass quota: four rows wait behind two served, FIFO, with
    // exact per-kind deferred counts.
    let path = dir.path().join("live.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    let mut emitter = InstanceEmitter::with_cap(2);
    let first = emitter
        .emit(
            &mut writer,
            &presentation.instances,
            &presentation.semantic_edges,
            presentation.budgets.instances_limit,
            200,
        )
        .unwrap();
    assert_eq!(first.instance_emitted, 2);
    assert_eq!(first.instance_deferred, 1);
    assert_eq!(first.edge_emitted, 0);
    assert_eq!(first.edge_deferred, 3);
    assert_eq!(emitter.tracked(), 3, "one tracked record per instance");
    let records = event_records(&path);
    assert_eq!(last_by_kind(&records, "instance_observed").len(), 2);
    assert_eq!(
        last_by_kind(&records, "instance_observed")[0],
        &crate::inventory::instance_json(&presentation.instances[0]),
        "instance rows serialize verbatim"
    );

    // A deferred row that changes again keeps its single queue place
    // and emits its current payload: no lost updates, no duplicates.
    conv.feed(
        conv.evidence(4, r0, conv.init_slot, conv.init_event(210)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.feed(
        conv.evidence(5, r0, conv.sign_slot, conv.sign_event(220)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.commit_with_lane();
    let presentation =
        crate::inventory_present::Presentation::capture(&conv.scene.coordinator, "test", 0, 300, 5);
    let second = emitter
        .emit(
            &mut writer,
            &presentation.instances,
            &presentation.semantic_edges,
            presentation.budgets.instances_limit,
            300,
        )
        .unwrap();
    assert_eq!(second.instance_emitted + second.edge_emitted, 2);
    assert_eq!(second.instance_emitted, 1);
    assert_eq!(second.edge_emitted, 1);
    assert_eq!(
        second.instance_deferred + second.edge_deferred,
        3,
        "a row that changes while queued rejoins nothing twice; the \
         call-advanced instance row re-dirties exactly once"
    );
    drop(writer);
    let live_records = event_records(&path);
    let edges = last_by_kind(&live_records, "semantic_edge_observed");
    assert_eq!(
        edges.len(),
        1,
        "the shared quota serves FIFO across both kinds"
    );
    assert_eq!(edges[0]["instance"], "i0");
    assert_eq!(
        edges[0]["api_returns"]["count"], 4,
        "a deferred row emits its current payload, exactly once"
    );

    // The exact sweep before ended settles all three kinds together:
    // every last retained record equals its snapshot row verbatim.
    let path = dir.path().join("swept.jsonl");
    let writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    let mut stream = EventLogState::new(Some(writer));
    let mut state = StreamState::new();
    assert_eq!(
        finish_output(
            None,
            &mut stream,
            &mut state,
            &presentation,
            false,
            true,
            &mut WriterStdout(&mut Vec::new()),
            None,
        )
        .exit_code(),
        0
    );
    let records = event_records(&path);
    let instances = last_by_kind(&records, "instance_observed");
    let edges = last_by_kind(&records, "semantic_edge_observed");
    assert_eq!(instances.len(), 3);
    assert_eq!(edges.len(), 3);
    for (row, carried) in presentation.instances.iter().zip(instances.iter().copied()) {
        assert_eq!(
            carried,
            &crate::inventory::instance_json(row),
            "the live instance row equals its snapshot row"
        );
    }
    for (row, carried) in presentation
        .semantic_edges
        .iter()
        .zip(edges.iter().copied())
    {
        assert_eq!(
            carried,
            &crate::inventory::instance_semantic_json(row),
            "the live semantic row equals its snapshot row"
        );
    }
    // The no-call row carries nulls, never zeros; the retired row
    // carries its retirement; the completed row carries both pairs.
    assert_eq!(instances[1]["state"], "observed");
    assert_eq!(edges[1]["api_returns"]["count"], serde_json::Value::Null);
    assert_eq!(instances[2]["state"], "retired");
    assert_eq!(edges[0]["api_returns"]["count"], 4);
    let physical = last_by_kind(&records, "edge_observed");
    assert_eq!(physical.len(), 1);
    let ended = records.last().unwrap();
    assert_eq!(ended["kind"], "ended");
    assert_eq!(ended["event"]["edges_unretained"], 0);
    assert_eq!(ended["event"]["instances_unretained"], 0);
    assert_eq!(ended["event"]["semantic_edges_unretained"], 0);
    assert_eq!(ended["event"]["instance_events"], 3);
    assert_eq!(ended["event"]["semantic_edge_events"], 3);
    let repeats: Vec<u64> = records
        .iter()
        .filter(|record| record["kind"] == "gap_repeated")
        .map(|record| record["event"]["repeats"].as_u64().unwrap())
        .collect();
    assert_eq!(repeats.last(), Some(&2), "exact repeat counts survive");

    // Tiny rotation budgets disclose unavoidable loss exactly per kind:
    // nothing retained reads as zero, and no physical final row is
    // silently evicted by appended semantic rows.
    let path = dir.path().join("tiny.jsonl");
    let writer = EventWriter::create(&path, 1, 1).unwrap();
    let mut stream = EventLogState::new(Some(writer));
    let mut state = StreamState::new();
    assert_eq!(
        finish_output(
            None,
            &mut stream,
            &mut state,
            &presentation,
            false,
            true,
            &mut WriterStdout(&mut Vec::new()),
            None,
        )
        .exit_code(),
        0
    );
    let records = event_records(&path);
    let ended = records.last().unwrap();
    assert_eq!(ended["kind"], "ended");
    assert_eq!(ended["event"]["edges_unretained"], 1);
    assert_eq!(ended["event"]["instances_unretained"], 3);
    assert_eq!(ended["event"]["semantic_edges_unretained"], 3);
}
