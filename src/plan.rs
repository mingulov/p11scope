//! Manifest → attach plan. One slot per unique {object, file_offset};
//! everything the manifest could not resolve becomes a Skipped entry so
//! the capture's evidence section can report it.

use p11scope_manifest::manifest::{Manifest, Resolution};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    pub index: u32,
    pub object: String,
    pub file_offset: u64,
    /// Every distinct function name resolving here, sorted.
    pub names: Vec<String>,
    /// True when >= 2 distinct names share this target: counts belong to
    /// the group, never to one name.
    pub aliased: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttachPlan {
    pub slots: Vec<Slot>,
    pub skipped: Vec<Skipped>,
    /// Total function records seen across every walked surface.
    pub entries_seen: usize,
}

pub fn build(m: &Manifest) -> AttachPlan {
    let mut by_target: BTreeMap<(String, u64), Vec<String>> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut entries_seen = 0usize;

    for surface in &m.surfaces {
        for f in &surface.functions {
            entries_seen += 1;
            match &f.resolution {
                Resolution::Resolved { object, file_offset } => {
                    let path = m
                        .objects
                        .iter()
                        .find(|o| o.id == *object)
                        .map(|o| o.path.clone())
                        .unwrap_or_default();
                    if path.is_empty() {
                        skipped.push(Skipped {
                            name: f.name.clone(),
                            reason: format!("object id {object} missing from manifest"),
                        });
                        continue;
                    }
                    by_target.entry((path, *file_offset)).or_default().push(f.name.clone());
                }
                Resolution::NullPointer => skipped
                    .push(Skipped { name: f.name.clone(), reason: "null pointer".into() }),
                Resolution::NonFileBacked => skipped
                    .push(Skipped { name: f.name.clone(), reason: "non-file-backed".into() }),
                Resolution::Unmapped => {
                    skipped.push(Skipped { name: f.name.clone(), reason: "unmapped".into() })
                }
            }
        }
    }

    let slots = by_target
        .into_iter()
        .enumerate()
        .map(|(i, ((object, file_offset), mut names))| {
            names.sort();
            names.dedup();
            Slot {
                index: i as u32,
                object,
                file_offset,
                aliased: names.len() >= 2,
                names,
            }
        })
        .collect();

    AttachPlan { slots, skipped, entries_seen }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
    use p11scope_manifest::manifest::*;

    fn manifest_with(functions: Vec<FunctionRecord>) -> Manifest {
        Manifest {
            schema: SCHEMA.to_string(),
            module_path: "/opt/p11.so".into(),
            objects: vec![ObjectRecord {
                id: 0,
                path: "/opt/p11.so".into(),
                identity: ObjectIdentity {
                    kind: IdentityKind::GnuBuildId,
                    value: Some("aa".into()),
                    reusable: true,
                    note: None,
                },
            }],
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: None,
                walk: WalkOutcome::Full,
                functions,
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
        }
    }

    fn rec(name: &str, r: Resolution) -> FunctionRecord {
        FunctionRecord { name: name.into(), resolution: r }
    }

    #[test]
    fn one_slot_per_unique_target_and_aliases_flagged() {
        let m = manifest_with(vec![
            rec("C_Sign", Resolution::Resolved { object: 0, file_offset: 0x10 }),
            rec("C_Verify", Resolution::Resolved { object: 0, file_offset: 0x20 }),
            rec("C_CancelFunction", Resolution::Resolved { object: 0, file_offset: 0x30 }),
            rec("C_WaitForSlotEvent", Resolution::Resolved { object: 0, file_offset: 0x30 }),
        ]);
        let p = build(&m);
        assert_eq!(p.slots.len(), 3, "aliased pair collapses to one slot");
        assert_eq!(p.entries_seen, 4);
        let aliased: Vec<&Slot> = p.slots.iter().filter(|s| s.aliased).collect();
        assert_eq!(aliased.len(), 1);
        assert_eq!(aliased[0].names, vec!["C_CancelFunction", "C_WaitForSlotEvent"]);
        // Slot indices are dense and start at zero.
        let idx: Vec<u32> = p.slots.iter().map(|s| s.index).collect();
        assert_eq!(idx, vec![0, 1, 2]);
    }

    #[test]
    fn unresolvable_entries_become_skipped_evidence() {
        let m = manifest_with(vec![
            rec("C_Sign", Resolution::Resolved { object: 0, file_offset: 0x10 }),
            rec("C_GetFunctionStatus", Resolution::NullPointer),
            rec("C_Weird", Resolution::NonFileBacked),
            rec("C_Gone", Resolution::Unmapped),
        ]);
        let p = build(&m);
        assert_eq!(p.slots.len(), 1);
        assert_eq!(p.skipped.len(), 3);
        assert_eq!(p.entries_seen, 4);
        let reasons: Vec<&str> = p.skipped.iter().map(|s| s.reason.as_str()).collect();
        assert!(reasons.contains(&"null pointer"));
        assert!(reasons.contains(&"non-file-backed"));
        assert!(reasons.contains(&"unmapped"));
    }
}
