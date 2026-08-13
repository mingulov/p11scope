//! Manifest → attach plan. One slot per unique {object, file_offset};
//! everything the manifest could not resolve becomes a Skipped entry so
//! the capture's evidence section can report it.

use p11scope_ebpf_common::SlotSemantics;
use p11scope_manifest::manifest::{Acquisition, Manifest, Resolution, SurfaceSource, WalkOutcome};
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
    pub semantics: SlotSemantics,
    /// At least one name was unknown or the aliased names disagreed.
    pub semantic_ambiguous: bool,
    /// True only when every surface exposing this exact target is a
    /// standard interface carrying CKF_INTERFACE_FORK_SAFE.
    pub fork_safe: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

/// Per-surface discovery provenance, carried through to evidence so a
/// manifest that never finished walking a surface can't be reported as a
/// complete capture just because its (empty) function list produced no
/// skips or aliases.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SurfaceSummary {
    /// Short human label for the surface (legacy table or interface name).
    pub source: String,
    pub walk: String,
    pub acquisition: String,
    pub functions: usize,
}

fn source_label(s: &SurfaceSource) -> String {
    match s {
        SurfaceSource::LegacyFunctionList => "legacy_function_list".into(),
        SurfaceSource::Interface {
            index,
            name_lossy,
            name_error,
            ..
        } => {
            let name = name_lossy
                .as_deref()
                .or(name_error.as_deref())
                .unwrap_or("unnamed");
            format!("interface[{index}] {name}")
        }
    }
}

fn walk_label(w: &WalkOutcome) -> String {
    match w {
        WalkOutcome::Full => "full".into(),
        WalkOutcome::KnownPrefix => "known_prefix".into(),
        WalkOutcome::Refused => "refused".into(),
        WalkOutcome::NotWalked => "not_walked".into(),
        WalkOutcome::Unreadable { detail } => format!("unreadable: {detail}"),
    }
}

fn acquisition_label(a: &Acquisition) -> String {
    match a {
        Acquisition::Ok => "ok".into(),
        Acquisition::Absent => "absent".into(),
        Acquisition::Empty => "empty".into(),
        Acquisition::Error { detail } => format!("error: {detail}"),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttachPlan {
    pub slots: Vec<Slot>,
    pub skipped: Vec<Skipped>,
    /// Total function records seen across every walked surface.
    pub entries_seen: usize,
    /// One entry per manifest surface, so evidence can see discovery gaps
    /// (partial walks, failed acquisitions) even when they produced no
    /// skipped/aliased function records of their own.
    pub surfaces: Vec<SurfaceSummary>,
    /// Present-but-undecoded vendor interfaces (never walked).
    pub vendor_interfaces: usize,
    /// Outcome of the manifest-level C_GetInterfaceList enumeration.
    pub interface_list: String,
}

pub fn ensure_capacity(plan: &AttachPlan) -> Result<(), String> {
    let required = plan.slots.len();
    let available = p11scope_ebpf_common::MAX_SLOTS as usize;
    if required > available {
        Err(format!(
            "attach plan requires {required} slots but only {available} are available; refusing to attach a prefix"
        ))
    } else {
        Ok(())
    }
}

pub fn build(m: &Manifest) -> AttachPlan {
    let mut by_target: BTreeMap<(String, u64), Vec<String>> = BTreeMap::new();
    let mut fork_safe_by_target: BTreeMap<(String, u64), bool> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut entries_seen = 0usize;
    let mut surfaces = Vec::new();

    for surface in &m.surfaces {
        surfaces.push(SurfaceSummary {
            source: source_label(&surface.source),
            walk: walk_label(&surface.walk),
            acquisition: acquisition_label(&surface.acquisition),
            functions: surface.functions.len(),
        });
        for f in &surface.functions {
            entries_seen += 1;
            match &f.resolution {
                Resolution::Resolved {
                    object,
                    file_offset,
                } => {
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
                    let target = (path, *file_offset);
                    let surface_fork_safe = matches!(
                        &surface.source,
                        SurfaceSource::Interface { flags, .. } if flags & 1 != 0
                    );
                    fork_safe_by_target
                        .entry(target.clone())
                        .and_modify(|safe| *safe &= surface_fork_safe)
                        .or_insert(surface_fork_safe);
                    by_target.entry(target).or_default().push(f.name.clone());
                }
                Resolution::NullPointer => skipped.push(Skipped {
                    name: f.name.clone(),
                    reason: "null pointer".into(),
                }),
                Resolution::NonFileBacked => skipped.push(Skipped {
                    name: f.name.clone(),
                    reason: "non-file-backed".into(),
                }),
                Resolution::Unmapped => skipped.push(Skipped {
                    name: f.name.clone(),
                    reason: "unmapped".into(),
                }),
                Resolution::UnusableFile { reason, .. } => skipped.push(Skipped {
                    name: f.name.clone(),
                    reason: reason.clone(),
                }),
            }
        }
    }

    let slots = by_target
        .into_iter()
        .enumerate()
        .map(|(i, ((object, file_offset), mut names))| {
            names.sort();
            names.dedup();
            let (semantics, semantic_ambiguous) = crate::kinds::descriptor_slot(&names);
            let fork_safe = fork_safe_by_target
                .get(&(object.clone(), file_offset))
                .copied()
                .unwrap_or(false);
            Slot {
                index: i as u32,
                object,
                file_offset,
                aliased: names.len() >= 2,
                names,
                semantics,
                semantic_ambiguous,
                fork_safe,
            }
        })
        .collect();

    AttachPlan {
        slots,
        skipped,
        entries_seen,
        surfaces,
        vendor_interfaces: m.vendor_interfaces.len(),
        interface_list: acquisition_label(&m.interface_list),
    }
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
                    sha256: Some("11".repeat(32)),
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
        FunctionRecord {
            name: name.into(),
            resolution: r,
        }
    }

    #[test]
    fn one_slot_per_unique_target_and_aliases_flagged() {
        let m = manifest_with(vec![
            rec(
                "C_Sign",
                Resolution::Resolved {
                    object: 0,
                    file_offset: 0x10,
                },
            ),
            rec(
                "C_Verify",
                Resolution::Resolved {
                    object: 0,
                    file_offset: 0x20,
                },
            ),
            rec(
                "C_OpenSession",
                Resolution::Resolved {
                    object: 0,
                    file_offset: 0x40,
                },
            ),
            rec(
                "C_CancelFunction",
                Resolution::Resolved {
                    object: 0,
                    file_offset: 0x30,
                },
            ),
            rec(
                "C_WaitForSlotEvent",
                Resolution::Resolved {
                    object: 0,
                    file_offset: 0x30,
                },
            ),
        ]);
        let p = build(&m);
        assert_eq!(p.slots.len(), 4, "aliased pair collapses to one slot");
        assert_eq!(p.entries_seen, 5);
        let aliased: Vec<&Slot> = p.slots.iter().filter(|s| s.aliased).collect();
        assert_eq!(aliased.len(), 1);
        assert_eq!(
            aliased[0].names,
            vec!["C_CancelFunction", "C_WaitForSlotEvent"]
        );
        assert!(aliased[0].semantic_ambiguous);
        assert_eq!(aliased[0].semantics, SlotSemantics::COUNT_ONLY);
        // Slot indices are dense and start at zero.
        let idx: Vec<u32> = p.slots.iter().map(|s| s.index).collect();
        assert_eq!(idx, vec![0, 1, 2, 3]);
        // Assert C_OpenSession slot gets the exact descriptor.
        let open_session_slot = p
            .slots
            .iter()
            .find(|s| s.names == vec!["C_OpenSession"])
            .unwrap();
        assert_eq!(
            open_session_slot.semantics,
            crate::kinds::descriptor("C_OpenSession").unwrap()
        );
    }

    #[test]
    fn unresolvable_entries_become_skipped_evidence() {
        let m = manifest_with(vec![
            rec(
                "C_Sign",
                Resolution::Resolved {
                    object: 0,
                    file_offset: 0x10,
                },
            ),
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

    #[test]
    fn surface_summaries_are_populated_from_the_manifest() {
        let m = manifest_with(vec![rec(
            "C_Sign",
            Resolution::Resolved {
                object: 0,
                file_offset: 0x10,
            },
        )]);
        let p = build(&m);
        assert_eq!(p.surfaces.len(), 1);
        assert_eq!(p.surfaces[0].source, "legacy_function_list");
        assert_eq!(p.surfaces[0].walk, "full");
        assert_eq!(p.surfaces[0].acquisition, "ok");
        assert_eq!(p.surfaces[0].functions, 1);
        assert_eq!(p.vendor_interfaces, 0);
        assert_eq!(p.interface_list, "absent");
    }

    #[test]
    fn surface_summaries_carry_gap_provenance() {
        let mut m = manifest_with(vec![rec(
            "C_Sign",
            Resolution::Resolved {
                object: 0,
                file_offset: 0x10,
            },
        )]);
        m.interface_list = Acquisition::Error {
            detail: "boom".into(),
        };
        m.surfaces[0].walk = WalkOutcome::KnownPrefix;
        m.surfaces[0].acquisition = Acquisition::Error {
            detail: "partial read".into(),
        };
        m.vendor_interfaces = vec![VendorInterface {
            index: 1,
            raw_name_hex: None,
            name_lossy: None,
            name_error: Some("null name pointer".into()),
            version: None,
            version_error: Some("null function-list pointer".into()),
            flags: 0,
            func_list_null: true,
        }];
        let p = build(&m);
        assert_eq!(p.surfaces[0].walk, "known_prefix");
        assert_eq!(p.surfaces[0].acquisition, "error: partial read");
        assert_eq!(p.vendor_interfaces, 1);
        assert_eq!(p.interface_list, "error: boom");
    }

    #[test]
    fn known_matrix_fits_and_overflow_is_refused_whole() {
        let make = |count| AttachPlan {
            slots: (0..count)
                .map(|index| Slot {
                    index: index as u32,
                    object: "/opt/p11.so".into(),
                    file_offset: index as u64 * 8,
                    names: vec!["C_Initialize".into()],
                    aliased: false,
                    semantics: SlotSemantics::COUNT_ONLY,
                    semantic_ambiguous: false,
                    fork_safe: false,
                })
                .collect(),
            skipped: vec![],
            entries_seen: count,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
        };
        assert!(ensure_capacity(&make(424)).is_ok());
        let error = ensure_capacity(&make(513)).unwrap_err();
        assert!(error.contains("requires 513"));
        assert!(error.contains("only 512"));
        assert!(error.contains("refusing to attach a prefix"));
    }
}
