//! dlopen + table-walk glue: pkcs11-module facts → manifest records.
//! This module runs vendor code (dlopen constructors) — the reason the
//! helper is a separate unprivileged short-lived process. It never calls
//! C_Initialize and never calls C_GetInterface.

use crate::maps;
use libloading::Library;
use p11scope_manifest::identity;
use p11scope_manifest::manifest::*;
use pkcs11_module::{FnField, Surface, TableSet, function_list, interface_list, read_fn_pointers, tables_for};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn discover(module_path: &Path) -> Result<Manifest, String> {
    let lib = unsafe { Library::new(module_path) }
        .map_err(|e| format!("cannot dlopen {}: {e}", module_path.display()))?;
    // Maps are read AFTER dlopen so the module's segments are present.
    let maps_text = std::fs::read_to_string("/proc/self/maps")
        .map_err(|e| format!("/proc/self/maps: {e}"))?;
    let maps = maps::parse_maps(&maps_text);

    let mut objects = ObjectTable::default();
    let legacy = legacy_surface(&lib, &maps, &mut objects);
    let (interface_list_acq, iface_surfaces, vendor_interfaces) =
        interface_records(&lib, &maps, &mut objects);

    let mut surfaces = vec![legacy];
    surfaces.extend(iface_surfaces);
    let alias_groups = alias_groups(&surfaces);

    Ok(Manifest {
        schema: SCHEMA.to_string(),
        module_path: module_path.display().to_string(),
        objects: objects.into_records(),
        interface_list: interface_list_acq,
        surfaces,
        vendor_interfaces,
        alias_groups,
    })
}

/// Dense object ids in first-seen order; identity computed once per object.
#[derive(Default)]
struct ObjectTable {
    ids: BTreeMap<PathBuf, u32>,
}

impl ObjectTable {
    fn id(&mut self, path: PathBuf) -> u32 {
        let next = self.ids.len() as u32;
        *self.ids.entry(path).or_insert(next)
    }

    fn into_records(self) -> Vec<ObjectRecord> {
        let mut v: Vec<ObjectRecord> = self
            .ids
            .into_iter()
            .map(|(path, id)| ObjectRecord {
                id,
                identity: identity::identify(&path),
                path: path.display().to_string(),
            })
            .collect();
        v.sort_by_key(|o| o.id);
        v
    }
}

fn legacy_surface(lib: &Library, maps: &[maps::MapEntry], objects: &mut ObjectTable) -> SurfaceRecord {
    // Distinguish "not exported" from "exported but failed".
    let exported = unsafe { lib.get::<unsafe extern "C" fn()>(b"C_GetFunctionList\0") }.is_ok();
    let source = SurfaceSource::LegacyFunctionList;
    if !exported {
        return SurfaceRecord {
            source,
            acquisition: Acquisition::Absent,
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        };
    }
    match function_list(lib) {
        Err(detail) => SurfaceRecord {
            source,
            acquisition: Acquisition::Error { detail },
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        },
        Ok(list) => {
            // Leading CK_VERSION is reported as evidence; the walk stays
            // base-size regardless (Surface::LegacyFunctionList contract).
            let v = unsafe { (list as *const cryptoki_sys::CK_VERSION).read_unaligned() };
            let (walk, functions) =
                walk_tables(list as *const u8, tables_for(Surface::LegacyFunctionList), maps, objects);
            SurfaceRecord {
                source,
                acquisition: Acquisition::Ok,
                version: Some(Version { major: v.major, minor: v.minor }),
                walk,
                functions,
            }
        }
    }
}

fn interface_records(
    lib: &Library,
    maps: &[maps::MapEntry],
    objects: &mut ObjectTable,
) -> (Acquisition, Vec<SurfaceRecord>, Vec<VendorInterface>) {
    let raw = match interface_list(lib) {
        Err(detail) => return (Acquisition::Error { detail }, vec![], vec![]),
        Ok(None) => return (Acquisition::Absent, vec![], vec![]),
        Ok(Some(v)) if v.is_empty() => return (Acquisition::Empty, vec![], vec![]),
        Ok(Some(v)) => v,
    };
    let mut surfaces = Vec::new();
    let mut vendor = Vec::new();
    for (index, i) in raw.iter().enumerate() {
        if i.is_standard() {
            let name = i.name.as_deref().expect("is_standard implies a name");
            let source = SurfaceSource::Interface {
                index,
                raw_name_hex: identity::hex(name),
                name_lossy: String::from_utf8_lossy(name).into_owned(),
                flags: i.flags,
            };
            match (i.version, i.func_list.is_null()) {
                (Some(v), false) => {
                    let (walk, functions) = walk_tables(
                        i.func_list as *const u8,
                        tables_for(Surface::StandardInterface { version: v }),
                        maps,
                        objects,
                    );
                    surfaces.push(SurfaceRecord {
                        source,
                        acquisition: Acquisition::Ok,
                        version: Some(Version { major: v.major, minor: v.minor }),
                        walk,
                        functions,
                    });
                }
                // NULL function list: recorded, never dereferenced.
                _ => surfaces.push(SurfaceRecord {
                    source,
                    acquisition: Acquisition::Ok,
                    version: None,
                    walk: WalkOutcome::NotWalked,
                    functions: vec![],
                }),
            }
        } else {
            vendor.push(VendorInterface {
                index,
                raw_name_hex: i.name.as_deref().map(identity::hex),
                name_lossy: i.name.as_deref().map(|b| String::from_utf8_lossy(b).into_owned()),
                version: i.version.map(|v| Version { major: v.major, minor: v.minor }),
                flags: i.flags,
                func_list_null: i.func_list.is_null(),
            });
        }
    }
    (Acquisition::Ok, surfaces, vendor)
}

fn walk_tables(
    base: *const u8,
    set: TableSet,
    maps: &[maps::MapEntry],
    objects: &mut ObjectTable,
) -> (WalkOutcome, Vec<FunctionRecord>) {
    let (outcome, tables): (WalkOutcome, &[&[FnField]]) = match set {
        TableSet::Walk(t) => (WalkOutcome::Full, t),
        TableSet::WalkKnownPrefix(t) => (WalkOutcome::KnownPrefix, t),
        TableSet::Refuse => return (WalkOutcome::Refused, vec![]),
    };
    let mut out = Vec::new();
    for table in tables {
        // SAFETY: base points at a live function-list struct the provider
        // returned for this surface; tables_for chose the matching layout.
        for (name, value) in unsafe { read_fn_pointers(base, table) } {
            let resolution = if value == 0 {
                Resolution::NullPointer
            } else {
                match maps::resolve(maps, value as u64) {
                    maps::Resolved::File { path, file_offset } => {
                        Resolution::Resolved { object: objects.id(path), file_offset }
                    }
                    maps::Resolved::Anonymous => Resolution::NonFileBacked,
                    maps::Resolved::Unmapped => Resolution::Unmapped,
                }
            };
            out.push(FunctionRecord { name: name.to_string(), resolution });
        }
    }
    (outcome, out)
}

/// Alias = one {object, file_offset} claimed by ≥2 DISTINCT names. Same
/// name from two surfaces is corroboration, not ambiguity — but once a
/// group qualifies, every entry is listed.
fn alias_groups(surfaces: &[SurfaceRecord]) -> Vec<AliasGroup> {
    let mut by_target: BTreeMap<(u32, u64), Vec<AliasEntry>> = BTreeMap::new();
    for (si, s) in surfaces.iter().enumerate() {
        for f in &s.functions {
            if let Resolution::Resolved { object, file_offset } = f.resolution {
                by_target
                    .entry((object, file_offset))
                    .or_default()
                    .push(AliasEntry { surface: si, name: f.name.clone() });
            }
        }
    }
    by_target
        .into_iter()
        .filter(|(_, entries)| {
            let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            names.sort_unstable();
            names.dedup();
            names.len() >= 2
        })
        .map(|((object, file_offset), entries)| AliasGroup { object, file_offset, entries })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface_with(functions: Vec<FunctionRecord>) -> SurfaceRecord {
        SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: None,
            walk: WalkOutcome::Full,
            functions,
        }
    }

    fn resolved(name: &str, off: u64) -> FunctionRecord {
        FunctionRecord {
            name: name.into(),
            resolution: Resolution::Resolved { object: 0, file_offset: off },
        }
    }

    #[test]
    fn alias_groups_require_two_distinct_names() {
        // Same name on two surfaces at one target: corroboration, no group.
        let s = vec![
            surface_with(vec![resolved("C_Sign", 0x10)]),
            surface_with(vec![resolved("C_Sign", 0x10)]),
        ];
        assert!(alias_groups(&s).is_empty());

        // Two names, one target: a group, listing all entries.
        let s = vec![surface_with(vec![
            resolved("C_GetFunctionStatus", 0x20),
            resolved("C_CancelFunction", 0x20),
        ])];
        let g = alias_groups(&s);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].entries.len(), 2);
    }
}
