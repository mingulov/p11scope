//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Boundary regression tests for structural validation: the object,
//! path and detail limits accept at the bound and refuse past it.

use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
use p11scope_manifest::manifest::*;
use p11scope_manifest::validate::validate_structure;

fn sha_identity(seed: u8) -> ObjectIdentity {
    let hex = format!("{seed:02x}").repeat(32);
    ObjectIdentity {
        kind: IdentityKind::Sha256,
        value: Some(hex.clone()),
        sha256: Some(hex),
        reusable: true,
        note: None,
    }
}

fn minimal_valid_manifest() -> Manifest {
    let identity = sha_identity(1);
    Manifest {
        schema: SCHEMA.to_string(),
        module_path: "/obj/mod.so".into(),
        objects: vec![ObjectRecord {
            id: 0,
            path: "/obj/mod.so".into(),
            identity: identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path: "/obj/mod.so".into(),
            device_major: 8,
            device_minor: 1,
            inode: 7,
            identity,
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
        selection_evidence: SelectionEvidence::default(),
        getters: vec![],
    }
}

fn object_at(index: usize) -> (ObjectRecord, ProvenanceObject) {
    let path = format!("/obj/{index}.so");
    let identity = sha_identity(index as u8);
    (
        ObjectRecord {
            id: index as u32,
            path: path.clone(),
            identity: identity.clone(),
        },
        ProvenanceObject {
            path,
            device_major: 8,
            device_minor: 1,
            inode: index as u64 + 1,
            identity,
        },
    )
}

#[test]
fn minimal_manifest_passes() {
    let manifest = minimal_valid_manifest();
    assert_eq!(validate_structure(&manifest), Vec::<String>::new());
}

#[test]
fn object_limit_accepts_512_and_refuses_513() {
    for count in [512, 513] {
        let mut manifest = minimal_valid_manifest();
        manifest.module_path = "/obj/0.so".into();
        manifest.objects.clear();
        manifest.provenance_objects.clear();
        for index in 0..count {
            let (object, provenance) = object_at(index);
            manifest.objects.push(object);
            manifest.provenance_objects.push(provenance);
        }
        let problems = validate_structure(&manifest);
        if count == 512 {
            assert!(problems.is_empty(), "{problems:?}");
        } else {
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.contains("513 objects")),
                "{problems:?}"
            );
        }
    }
}

#[test]
fn path_limit_accepts_4096_and_refuses_4097() {
    for len in [4096, 4097] {
        let mut manifest = minimal_valid_manifest();
        let long = format!("/{}", "a".repeat(len - 1));
        manifest.module_path = long.clone();
        manifest.objects[0].path = long.clone();
        manifest.provenance_objects[0].path = long;
        let problems = validate_structure(&manifest);
        if len == 4096 {
            assert!(problems.is_empty(), "{problems:?}");
        } else {
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.contains("4097 bytes")),
                "{problems:?}"
            );
        }
    }
}

#[test]
fn detail_limit_accepts_4096_and_refuses_4097() {
    for len in [4096, 4097] {
        let mut manifest = minimal_valid_manifest();
        manifest.interface_list = Acquisition::Ok;
        manifest.vendor_interfaces.push(VendorInterface {
            index: 0,
            raw_name_hex: None,
            name_lossy: None,
            name_error: Some("e".repeat(len)),
            version: None,
            version_error: None,
            flags: 0,
            func_list_null: true,
        });
        let problems = validate_structure(&manifest);
        if len == 4096 {
            assert!(problems.is_empty(), "{problems:?}");
        } else {
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.contains("4097 bytes")),
                "{problems:?}"
            );
        }
    }
}
