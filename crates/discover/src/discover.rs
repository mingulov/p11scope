//! SPDX-License-Identifier: GPL-3.0-or-later
//! dlopen + table-walk glue: raw provider facts become bounded manifest evidence.
//! The helper never calls C_Initialize and performs only the fixed v5
//! C_GetInterface compatibility matrix.

use crate::maps::{self, Device, MappedPath, ObjectKey};
use libloading::Library;
use p11scope_manifest::identity::{
    self, KernelSelfMappingProbe, ObjectIdentity, ProbeBudget, SelfMappingProbe,
    UnboundedProbeBudget, opened_file_matches_maps, self_mapped_fallback_key,
};
use p11scope_manifest::manifest::*;
use pkcs11_module::{
    RawInterface, Surface, TableSet, function_list, interface_list, read_fn_pointers, tables_for,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::raw::c_void;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

const INTERFACE_NAME_CAP: usize = 256;
const MAX_OBJECTS: usize = 512;
const MAX_TOTAL_OBJECT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
struct ExportAddresses {
    get_function_list: Option<usize>,
    get_interface_list: Option<usize>,
    get_interface: Option<usize>,
}

pub fn discover(module_path: &Path) -> Result<Manifest, String> {
    if !module_path.is_absolute() {
        return Err("--module must be an absolute path".into());
    }
    discover_with_self_memory(module_path, ProcessMemory::open()?.0)
}

/// Discover with a retained descriptor for the helper's post-exec address
/// space. The helper hardens itself before releasing the provider-load barrier.
pub fn discover_with_self_memory(
    module_path: &Path,
    self_memory: File,
) -> Result<Manifest, String> {
    if !module_path.is_absolute() {
        return Err("--module must be an absolute path".into());
    }
    let module_path_text = module_path
        .to_str()
        .ok_or_else(|| "--module path must be valid UTF-8 for the manifest".to_string())?;
    let memory = ProcessMemory(self_memory);
    let (module_file_key, module_identity) = identity_and_key(module_path)?;
    let before_maps = read_self_maps()?;
    let before_index = validated_map_index(&before_maps)?;
    let before_keys: BTreeSet<ObjectKey> =
        before_index.entries().iter().map(ObjectKey::of).collect();

    let lib = unsafe { Library::new(module_path) }
        .map_err(|e| format!("cannot dlopen {}: {e}", module_path.display()))?;
    let raw_exports = ExportAddresses {
        get_function_list: symbol_address(&lib, b"C_GetFunctionList\0"),
        get_interface_list: symbol_address(&lib, b"C_GetInterfaceList\0"),
        get_interface: symbol_address(&lib, b"C_GetInterface\0"),
    };

    // Acquisition can lazily load dependencies, so both calls precede maps.
    let legacy_acquisition = raw_exports.get_function_list.map(|_| function_list(&lib));
    let interfaces_acquisition = interface_list(&lib);

    let maps = read_self_maps()?;
    let map_index = validated_map_index(&maps)?;
    let module_file = identity::open_object(module_path)
        .map_err(|e| format!("cannot open {} for reuse: {e}", module_path.display()))?;
    let module_map_key = loaded_module_key(
        raw_exports,
        &map_index,
        module_file_key,
        &module_identity,
        &module_file,
    )?;
    let initial_module_mappings: Vec<maps::MapEntry> = map_index
        .entries()
        .iter()
        .filter(|mapping| ObjectKey::of(mapping) == module_map_key)
        .cloned()
        .collect();
    let mut approved_keys: BTreeSet<ObjectKey> = map_index
        .entries()
        .iter()
        .map(ObjectKey::of)
        .filter(|key| !before_keys.contains(key))
        .collect();
    approved_keys.insert(module_map_key);
    let current_identity = validated_identity(module_path, module_file_key)?;
    if current_identity != module_identity {
        return Err(format!(
            "module {} changed while discovery was running",
            module_path.display()
        ));
    }

    let exports = ExportAddresses {
        get_function_list: module_export(raw_exports.get_function_list, &map_index, module_map_key),
        get_interface_list: module_export(
            raw_exports.get_interface_list,
            &map_index,
            module_map_key,
        ),
        get_interface: module_export(raw_exports.get_interface, &map_index, module_map_key),
    };
    let mut objects = ObjectTable::new(
        module_path.to_path_buf(),
        module_map_key,
        module_identity.clone(),
        approved_keys,
    );

    let (legacy, legacy_240, legacy_ptr) = legacy_surface(
        legacy_acquisition,
        raw_exports.get_function_list,
        exports.get_function_list,
        &memory,
        &map_index,
        &mut objects,
    );
    let (interface_list, interface_surfaces, vendor_interfaces, interface_ptrs) = interface_records(
        interfaces_acquisition,
        raw_exports.get_interface_list,
        exports,
        legacy_240.as_deref(),
        &memory,
        &map_index,
        &mut objects,
    );

    let mut surfaces = vec![legacy];
    surfaces.extend(interface_surfaces);
    let mut inventory_tables = Vec::with_capacity(1 + interface_ptrs.len());
    inventory_tables.push(legacy_ptr);
    inventory_tables.extend(interface_ptrs);
    let selection_raw = selection_acquisition(
        &lib,
        raw_exports.get_interface,
        exports.get_interface,
        &memory,
        &inventory_tables,
        module_path,
        module_file_key,
        &module_identity,
        &objects,
    );
    let selection_evidence = selection_records(selection_raw, &surfaces);
    let alias_groups = alias_groups(&surfaces);
    let final_maps = read_self_maps()?;
    let final_map_index = validated_map_index(&final_maps)?;
    let (final_file_key, final_identity) = identity_and_key(module_path)?;
    if final_file_key != module_file_key
        || final_identity != module_identity
        || !initial_module_mappings
            .iter()
            .all(|mapping| final_map_index.entries().contains(mapping))
    {
        return Err(format!(
            "module {} changed while discovery was running",
            module_path.display()
        ));
    }
    let provenance_objects = provenance_objects(&final_map_index)?;

    Ok(Manifest {
        schema: SCHEMA.to_string(),
        module_path: module_path_text.to_string(),
        objects: objects.into_records(),
        provenance_objects,
        interface_list,
        surfaces,
        vendor_interfaces,
        alias_groups,
        selection_evidence,
    })
}

/// Reads before giving up on a torn snapshot of this process's own maps.
const SELF_MAPS_ATTEMPTS: usize = 4;

/// One consistent snapshot of this process's own maps. The kernel serves
/// `/proc/self/maps` over several `read` calls and drops the mmap lock
/// between them, so another thread's `mmap` (a provider's worker, or a
/// parallel test) can tear the snapshot. A torn snapshot fails the
/// `MapIndex` order check and is read again, up to [`SELF_MAPS_ATTEMPTS`]
/// times; a parse error is never retried.
fn read_self_maps() -> Result<Vec<maps::MapEntry>, String> {
    read_self_maps_with(|| std::fs::read("/proc/self/maps"))
}

fn read_self_maps_with(
    mut read: impl FnMut() -> std::io::Result<Vec<u8>>,
) -> Result<Vec<maps::MapEntry>, String> {
    let mut torn = String::new();
    for _ in 0..SELF_MAPS_ATTEMPTS {
        let bytes = read().map_err(|e| format!("/proc/self/maps: {e}"))?;
        let entries = maps::parse_maps(&bytes)?;
        match maps::MapIndex::new(&entries) {
            Ok(_) => return Ok(entries),
            Err(error) => torn = format!("invalid /proc maps snapshot: {error}"),
        }
    }
    Err(torn)
}

fn validated_map_index(entries: &[maps::MapEntry]) -> Result<maps::MapIndex<'_>, String> {
    maps::MapIndex::new(entries).map_err(|error| format!("invalid /proc maps snapshot: {error}"))
}

fn provenance_objects(index: &maps::MapIndex<'_>) -> Result<Vec<ProvenanceObject>, String> {
    let mut by_key: BTreeMap<ObjectKey, ProvenanceObject> = BTreeMap::new();
    let mut opened_paths = BTreeMap::new();
    let mut total_bytes = 0u64;

    for mapping in index
        .entries()
        .iter()
        .filter(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
    {
        let raw_path = mapping
            .raw_path
            .as_deref()
            .ok_or_else(|| "file-backed executable mapping has no pathname".to_string())?;
        let path = match index.resolve(mapping.start) {
            maps::Resolved::File {
                path: MappedPath::Usable(path),
                ..
            } => path,
            maps::Resolved::File {
                path: MappedPath::Unusable { reason },
                ..
            } => {
                return Err(format!(
                    "executable mapping {} is unusable: {reason}",
                    identity::hex(raw_path)
                ));
            }
            _ => {
                return Err(format!(
                    "file-backed executable mapping {} has no usable absolute path",
                    identity::hex(raw_path)
                ));
            }
        };
        let key = ObjectKey::of(mapping);
        if let Some(previous) = opened_paths.insert(path.clone(), key) {
            if previous != key {
                return Err(format!(
                    "executable mapping path {} changed device/inode within one pass",
                    path.display()
                ));
            }
            continue;
        }

        let file = identity::open_object(&path).map_err(|error| {
            format!("cannot open executable mapping {}: {error}", path.display())
        })?;
        let object_identity = validated_file_identity(&path, &file, key)?;
        if let Some(previous) = by_key.get(&key) {
            if previous.identity != object_identity {
                return Err(format!(
                    "executable mapping aliases for {key:?} disagree on whole-file identity"
                ));
            }
            continue;
        }
        if by_key.len() >= MAX_OBJECTS {
            return Err(format!(
                "executable provenance object cap {MAX_OBJECTS} reached"
            ));
        }
        let len = file
            .metadata()
            .map_err(|error| format!("metadata for {} failed: {error}", path.display()))?
            .len();
        total_bytes = total_bytes
            .checked_add(len)
            .ok_or_else(|| "executable provenance size overflowed u64".to_string())?;
        if total_bytes > MAX_TOTAL_OBJECT_BYTES {
            return Err(format!(
                "executable provenance objects total more than the {MAX_TOTAL_OBJECT_BYTES}-byte limit"
            ));
        }
        by_key.insert(
            key,
            ProvenanceObject {
                path: path.display().to_string(),
                device_major: key.device.major,
                device_minor: key.device.minor,
                inode: key.inode,
                identity: object_identity,
            },
        );
    }

    if by_key.is_empty() {
        return Err("discovery found no file-backed executable mappings".into());
    }
    Ok(by_key.into_values().collect())
}

fn symbol_address(lib: &Library, name: &[u8]) -> Option<usize> {
    unsafe {
        lib.get::<unsafe extern "C" fn()>(name)
            .ok()
            .map(|symbol| *symbol as usize)
    }
}

fn module_export(
    address: Option<usize>,
    maps: &maps::MapIndex<'_>,
    module_key: ObjectKey,
) -> Option<usize> {
    address.filter(|address| match maps.resolve(*address as u64) {
        maps::Resolved::File { device, inode, .. } => ObjectKey { device, inode } == module_key,
        _ => false,
    })
}

fn loaded_module_key(
    exports: ExportAddresses,
    maps: &maps::MapIndex<'_>,
    module_file_key: ObjectKey,
    module_identity: &ObjectIdentity,
    module_file: &File,
) -> Result<ObjectKey, String> {
    let mut budget = UnboundedProbeBudget;
    loaded_module_key_with_probe(
        exports,
        maps,
        module_file_key,
        module_identity,
        module_file,
        &KernelSelfMappingProbe,
        &mut budget,
    )
}

fn loaded_module_key_with_probe(
    exports: ExportAddresses,
    maps: &maps::MapIndex<'_>,
    module_file_key: ObjectKey,
    module_identity: &ObjectIdentity,
    module_file: &File,
    probe: &impl SelfMappingProbe,
    budget: &mut dyn ProbeBudget,
) -> Result<ObjectKey, String> {
    for address in [exports.get_function_list, exports.get_interface_list]
        .into_iter()
        .flatten()
    {
        if let maps::Resolved::File {
            path,
            device,
            inode,
            ..
        } = maps.resolve(address as u64)
        {
            let maps_key = ObjectKey { device, inode };
            // On pre-6.8 kernels an overlayfs fd and its mappings
            // legitimately carry different keys (overlay vs backing
            // device); the self-mapping probe asks the kernel how it
            // renders this exact fd before refusing.
            if opened_file_matches_maps(module_file, module_file_key, maps_key, budget, probe) {
                if let MappedPath::Usable(path) = path {
                    // When the kernel-reported path is reachable, require the
                    // same exact fd identity and whole-file identity too.
                    if std::fs::metadata(&path).is_ok()
                        && validated_identity_with_probe(&path, module_file_key, probe, budget)
                            .as_ref()
                            != Ok(module_identity)
                    {
                        continue;
                    }
                }
                return Ok(maps_key);
            }
        }
    }
    Err("no module acquisition export maps to the requested file identity".into())
}

fn file_key(file: &File) -> Result<ObjectKey, String> {
    let key = identity::mapping_file_key(file)?;
    Ok(ObjectKey {
        device: Device {
            major: key.device_major,
            minor: key.device_minor,
        },
        inode: key.inode,
    })
}

fn validated_identity(path: &Path, expected: ObjectKey) -> Result<ObjectIdentity, String> {
    let mut budget = UnboundedProbeBudget;
    validated_identity_with_probe(path, expected, &KernelSelfMappingProbe, &mut budget)
}

fn validated_identity_with_probe(
    path: &Path,
    expected: ObjectKey,
    probe: &impl SelfMappingProbe,
    budget: &mut dyn ProbeBudget,
) -> Result<ObjectIdentity, String> {
    let file = identity::open_object(path)
        .map_err(|e| format!("cannot open {} for reuse: {e}", path.display()))?;
    validated_file_identity_with_probe(path, &file, expected, probe, budget)
}

fn identity_and_key(path: &Path) -> Result<(ObjectKey, ObjectIdentity), String> {
    let file = identity::open_object(path)
        .map_err(|e| format!("cannot open {} for reuse: {e}", path.display()))?;
    let key = file_key(&file)?;
    let identity = validated_file_identity(path, &file, key)?;
    Ok((key, identity))
}

fn validated_file_identity(
    path: &Path,
    file: &File,
    expected: ObjectKey,
) -> Result<ObjectIdentity, String> {
    let mut budget = UnboundedProbeBudget;
    validated_file_identity_with_probe(path, file, expected, &KernelSelfMappingProbe, &mut budget)
}

fn validated_file_identity_with_probe(
    path: &Path,
    file: &File,
    expected: ObjectKey,
    probe: &impl SelfMappingProbe,
    budget: &mut dyn ProbeBudget,
) -> Result<ObjectIdentity, String> {
    let actual = file_key(file)?;
    // On pre-6.8 kernels an overlayfs fd and its mappings legitimately
    // carry different keys (overlay vs backing device); the self-mapping
    // probe asks the kernel how it renders this exact fd before refusing.
    // A same-file revalidation (`actual == expected`) never probes.
    if !opened_file_matches_maps(file, actual, expected, budget, probe) {
        return Err(format!(
            "device/inode mismatch for {}: mapped {:?}, path {:?}",
            path.display(),
            expected,
            actual
        ));
    }
    let value = identity::inspect_file(file)
        .map_err(|e| format!("cannot identify {} for reuse: {e}", path.display()))?
        .identity;
    if !value.reusable {
        return Err(format!(
            "cannot identify {} for reuse: {}",
            path.display(),
            value.note.as_deref().unwrap_or("identity unavailable")
        ));
    }
    Ok(value)
}

struct ProcessMemory(File);

impl ProcessMemory {
    fn open() -> Result<Self, String> {
        File::open("/proc/self/mem")
            .map(Self)
            .map_err(|e| format!("/proc/self/mem: {e}"))
    }

    fn read_exact(&self, address: usize, len: usize) -> Result<Vec<u8>, String> {
        let mut bytes = vec![0; len];
        let mut done = 0;
        while done < len {
            let at = address
                .checked_add(done)
                .ok_or_else(|| "provider pointer arithmetic overflow".to_string())?;
            let read = self
                .0
                .read_at(&mut bytes[done..], at as u64)
                .map_err(|e| format!("pread at 0x{at:x}: {e}"))?;
            if read == 0 {
                return Err(format!(
                    "short pread at 0x{address:x}: read {done} of {len} bytes"
                ));
            }
            done += read;
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone)]
struct NameRead {
    raw: Option<Vec<u8>>,
    lossy: Option<String>,
    error: Option<String>,
}

fn read_name(memory: &ProcessMemory, address: usize) -> NameRead {
    if address == 0 {
        return NameRead {
            raw: None,
            lossy: None,
            error: Some("null name pointer".into()),
        };
    }

    let mut raw = Vec::with_capacity(INTERFACE_NAME_CAP);
    while raw.len() < INTERFACE_NAME_CAP {
        let mut chunk = [0u8; 32];
        let want = chunk.len().min(INTERFACE_NAME_CAP - raw.len());
        let Some(at) = address.checked_add(raw.len()) else {
            return NameRead {
                raw: (!raw.is_empty()).then_some(raw),
                lossy: None,
                error: Some("name pointer arithmetic overflow".into()),
            };
        };
        let read = match memory.0.read_at(&mut chunk[..want], at as u64) {
            Ok(0) => {
                return NameRead {
                    raw: (!raw.is_empty()).then_some(raw),
                    lossy: None,
                    error: Some(format!("short name pread at 0x{at:x}")),
                };
            }
            Ok(read) => read,
            Err(error) => {
                return NameRead {
                    raw: (!raw.is_empty()).then_some(raw),
                    lossy: None,
                    error: Some(format!("name pread at 0x{at:x}: {error}")),
                };
            }
        };
        if let Some(nul) = chunk[..read].iter().position(|byte| *byte == 0) {
            raw.extend_from_slice(&chunk[..nul]);
            let lossy = String::from_utf8_lossy(&raw).into_owned();
            return NameRead {
                raw: Some(raw),
                lossy: Some(lossy),
                error: None,
            };
        }
        raw.extend_from_slice(&chunk[..read]);
    }

    NameRead {
        raw: Some(raw),
        lossy: None,
        error: Some(format!(
            "overlong interface name (cap {INTERFACE_NAME_CAP} bytes)"
        )),
    }
}

fn read_version(
    memory: &ProcessMemory,
    address: usize,
) -> Result<cryptoki_sys::CK_VERSION, String> {
    if address == 0 {
        return Err("null function-list pointer".into());
    }
    let bytes = memory.read_exact(address, 2)?;
    Ok(cryptoki_sys::CK_VERSION {
        major: bytes[0],
        minor: bytes[1],
    })
}

struct TableSnapshot {
    walk: WalkOutcome,
    values: Vec<(&'static str, usize)>,
}

fn snapshot_table(memory: &ProcessMemory, base: usize, set: TableSet) -> TableSnapshot {
    let (walk, spans) = match set {
        TableSet::Walk(spans) => (WalkOutcome::Full, spans),
        TableSet::WalkKnownPrefix(spans) => (WalkOutcome::KnownPrefix, spans),
        TableSet::Refuse => {
            return TableSnapshot {
                walk: WalkOutcome::Refused,
                values: vec![],
            };
        }
    };
    let width = std::mem::size_of::<usize>();
    let Some(len) = spans
        .iter()
        .flat_map(|span| span.fields())
        .filter_map(|field| field.offset.checked_add(width))
        .max()
    else {
        return TableSnapshot {
            walk: WalkOutcome::Unreadable {
                detail: "selected table has no fields".into(),
            },
            values: vec![],
        };
    };
    let bytes = match memory.read_exact(base, len) {
        Ok(bytes) => bytes,
        Err(detail) => {
            return TableSnapshot {
                walk: WalkOutcome::Unreadable { detail },
                values: vec![],
            };
        }
    };
    let mut values = Vec::new();
    for span in spans {
        match read_fn_pointers(&bytes, span.fields()) {
            Ok(mut span_values) => values.append(&mut span_values),
            Err(detail) => {
                return TableSnapshot {
                    walk: WalkOutcome::Unreadable { detail },
                    values: vec![],
                };
            }
        }
    }
    TableSnapshot { walk, values }
}

fn legacy_surface(
    acquisition: Option<Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String>>,
    raw_export: Option<usize>,
    module_export: Option<usize>,
    memory: &ProcessMemory,
    maps: &maps::MapIndex<'_>,
    objects: &mut ObjectTable,
) -> (SurfaceRecord, Option<Vec<usize>>, Option<usize>) {
    let source = SurfaceSource::LegacyFunctionList;
    let Some(acquisition) = acquisition else {
        return (
            SurfaceRecord {
                source,
                acquisition: Acquisition::Absent,
                version: None,
                walk: WalkOutcome::NotWalked,
                functions: vec![],
            },
            None,
            None,
        );
    };
    if raw_export.is_some() && module_export.is_none() {
        return (
            SurfaceRecord {
                source,
                acquisition: Acquisition::Error {
                    detail: "C_GetFunctionList resolved outside the requested module".into(),
                },
                version: None,
                walk: WalkOutcome::NotWalked,
                functions: vec![],
            },
            None,
            None,
        );
    }
    let base = match acquisition {
        Ok(base) => base as usize,
        Err(detail) => {
            return (
                SurfaceRecord {
                    source,
                    acquisition: Acquisition::Error { detail },
                    version: None,
                    walk: WalkOutcome::NotWalked,
                    functions: vec![],
                },
                None,
                None,
            );
        }
    };
    let version = match read_version(memory, base) {
        Ok(version) => version,
        Err(detail) => {
            return (
                SurfaceRecord {
                    source,
                    acquisition: Acquisition::Ok,
                    version: None,
                    walk: WalkOutcome::Unreadable { detail },
                    functions: vec![],
                },
                None,
                None,
            );
        }
    };
    let snapshot = snapshot_table(
        memory,
        base,
        tables_for(Surface::LegacyFunctionList { version }),
    );
    let legacy_240 = (version.major == 2
        && version.minor == 40
        && matches!(&snapshot.walk, WalkOutcome::Full)
        && snapshot.values.len() == 68)
        .then(|| snapshot.values.iter().map(|(_, value)| *value).collect());
    let inventory_pointer =
        matches!(snapshot.walk, WalkOutcome::Full | WalkOutcome::KnownPrefix).then_some(base);
    let functions = resolve_values(snapshot.values, maps, objects);
    (
        SurfaceRecord {
            source,
            acquisition: Acquisition::Ok,
            version: Some(manifest_version(version)),
            walk: snapshot.walk,
            functions,
        },
        legacy_240,
        inventory_pointer,
    )
}

fn interface_records(
    acquisition: Result<Option<Vec<RawInterface>>, String>,
    raw_export: Option<usize>,
    exports: ExportAddresses,
    legacy_240: Option<&[usize]>,
    memory: &ProcessMemory,
    maps: &maps::MapIndex<'_>,
    objects: &mut ObjectTable,
) -> (
    Acquisition,
    Vec<SurfaceRecord>,
    Vec<VendorInterface>,
    Vec<Option<usize>>,
) {
    if raw_export.is_some() && exports.get_interface_list.is_none() {
        return (
            Acquisition::Error {
                detail: "C_GetInterfaceList resolved outside the requested module".into(),
            },
            vec![],
            vec![],
            vec![],
        );
    }
    let raw = match acquisition {
        Err(detail) => return (Acquisition::Error { detail }, vec![], vec![], vec![]),
        Ok(None) => return (Acquisition::Absent, vec![], vec![], vec![]),
        Ok(Some(entries)) if entries.is_empty() => {
            return (Acquisition::Empty, vec![], vec![], vec![]);
        }
        Ok(Some(entries)) => entries,
    };

    let mut surfaces = Vec::new();
    let mut vendor = Vec::new();
    let mut table_ptrs = Vec::new();
    for (index, entry) in raw.into_iter().enumerate() {
        let name = read_name(memory, entry.name_ptr as usize);
        let exact = name.raw.as_deref() == Some(b"PKCS 11".as_slice()) && name.error.is_none();
        let version = read_version(memory, entry.func_list as usize);

        if exact {
            let surface = interface_surface(
                index,
                &entry,
                name,
                version,
                InterfaceClassification::ExactStandard,
                false,
                memory,
                maps,
                objects,
            );
            table_ptrs.push(
                matches!(surface.walk, WalkOutcome::Full | WalkOutcome::KnownPrefix)
                    .then_some(entry.func_list as usize),
            );
            surfaces.push(surface);
            continue;
        }

        if let Ok(version_value) = version {
            let snapshot = snapshot_table(
                memory,
                entry.func_list as usize,
                tables_for(Surface::StandardInterface {
                    version: version_value,
                }),
            );
            if corroborates_standard(version_value, &snapshot, exports, legacy_240) {
                let surface = interface_surface_from_snapshot(
                    index,
                    &entry,
                    name,
                    version_value,
                    InterfaceClassification::CorroboratedStandardPrefix,
                    snapshot,
                    true,
                    maps,
                    objects,
                );
                table_ptrs.push(
                    matches!(surface.walk, WalkOutcome::Full | WalkOutcome::KnownPrefix)
                        .then_some(entry.func_list as usize),
                );
                surfaces.push(surface);
                continue;
            }
            vendor.push(vendor_interface(
                index,
                &entry,
                name,
                Some(version_value),
                None,
            ));
        } else {
            vendor.push(vendor_interface(index, &entry, name, None, version.err()));
        }
    }
    (Acquisition::Ok, surfaces, vendor, table_ptrs)
}

type GetInterfaceFn = unsafe extern "C" fn(
    *mut cryptoki_sys::CK_UTF8CHAR,
    *mut cryptoki_sys::CK_VERSION,
    *mut *mut c_void,
    cryptoki_sys::CK_FLAGS,
) -> cryptoki_sys::CK_RV;

#[allow(clippy::unnecessary_cast)]
fn native_ulong_u64(value: cryptoki_sys::CK_ULONG) -> u64 {
    value as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TableOrigin {
    object: ObjectKey,
    file_offset: u64,
}

struct RawSelectionResult {
    name: SelectionNameClass,
    version: SelectionVersionClass,
    flags: u64,
    table: Option<(SelectionTable, TableOrigin)>,
    inventory_matches: Vec<usize>,
}

struct RawSelectionQuery {
    selector: u8,
    request: SelectionRequest,
    rv: u64,
    result: Option<RawSelectionResult>,
    helper_failure: Option<SelectionFailure>,
}

fn selection_request(selector: u8, flags: u64) -> SelectionRequest {
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
        4 => (
            SelectionNameClass::ExactStandard,
            SelectionVersionClass::V3_2,
        ),
        _ => unreachable!("fixed selection selector"),
    };
    SelectionRequest {
        name,
        version,
        flags,
    }
}

fn selection_maps_unchanged(first: &[maps::MapEntry], second: &[maps::MapEntry]) -> bool {
    let file_backed = |entry: &&maps::MapEntry| {
        entry
            .raw_path
            .as_deref()
            .is_some_and(|path| path.starts_with(b"/"))
    };
    first
        .iter()
        .filter(file_backed)
        .eq(second.iter().filter(file_backed))
}

fn selection_bracket<T, SnapshotA, Resolve, SnapshotB>(
    snapshot_a: SnapshotA,
    resolve: Resolve,
    snapshot_b: SnapshotB,
) -> Result<T, SelectionFailure>
where
    SnapshotA: FnOnce() -> Result<Vec<maps::MapEntry>, ()>,
    Resolve: FnOnce(&maps::MapIndex<'_>) -> Result<T, SelectionFailure>,
    SnapshotB: FnOnce() -> Result<Vec<maps::MapEntry>, ()>,
{
    let maps_a = snapshot_a().map_err(|_| SelectionFailure::ProviderChanged)?;
    let index_a = maps::MapIndex::new(&maps_a).map_err(|_| SelectionFailure::ProviderChanged)?;
    let resolved = resolve(&index_a);
    let maps_b = snapshot_b().map_err(|_| SelectionFailure::ProviderChanged)?;
    let index_b = maps::MapIndex::new(&maps_b).map_err(|_| SelectionFailure::ProviderChanged)?;
    if !selection_maps_unchanged(index_a.entries(), index_b.entries()) {
        return Err(SelectionFailure::ProviderChanged);
    }
    resolved
}

fn selection_inventory_indices(inventory_tables: &[Option<usize>], pointer: usize) -> Vec<usize> {
    inventory_tables
        .iter()
        .enumerate()
        .filter_map(|(surface, candidate)| (*candidate == Some(pointer)).then_some(surface))
        .collect()
}

fn selection_table_incomplete(
    version: SelectionVersionClass,
    snapshot: Option<&TableSnapshot>,
) -> bool {
    matches!(
        version,
        SelectionVersionClass::V3_0 | SelectionVersionClass::V3_1 | SelectionVersionClass::V3_2
    ) && !snapshot.is_some_and(|snapshot| matches!(snapshot.walk, WalkOutcome::Full))
}

#[allow(clippy::too_many_arguments)]
fn selection_acquisition(
    lib: &Library,
    raw_export: Option<usize>,
    module_export: Option<usize>,
    memory: &ProcessMemory,
    inventory_tables: &[Option<usize>],
    module_path: &Path,
    module_file_key: ObjectKey,
    module_identity: &ObjectIdentity,
    objects: &ObjectTable,
) -> (SelectionAcquisition, Vec<RawSelectionQuery>) {
    if raw_export.is_none() {
        return (SelectionAcquisition::ExportAbsent, Vec::new());
    }
    if module_export.is_none() {
        return (SelectionAcquisition::ExportOutsideModule, Vec::new());
    }
    let get_interface: libloading::Symbol<'_, GetInterfaceFn> = unsafe {
        match lib.get(b"C_GetInterface\0") {
            Ok(symbol) => symbol,
            Err(_) => return (SelectionAcquisition::ExportOutsideModule, Vec::new()),
        }
    };
    let mut queries = Vec::with_capacity(10);
    for selector in 0..5u8 {
        for flag in [0u8, 1] {
            let flags: cryptoki_sys::CK_FLAGS = flag.into();
            let request = selection_request(selector, native_ulong_u64(flags));
            let mut version = match request.version {
                SelectionVersionClass::V3_0 => cryptoki_sys::CK_VERSION { major: 3, minor: 0 },
                SelectionVersionClass::V3_1 => cryptoki_sys::CK_VERSION { major: 3, minor: 1 },
                SelectionVersionClass::V3_2 => cryptoki_sys::CK_VERSION { major: 3, minor: 2 },
                _ => cryptoki_sys::CK_VERSION { major: 0, minor: 0 },
            };
            let mut output = std::ptr::null_mut();
            let name = b"PKCS 11\0";
            let name_ptr = if request.name == SelectionNameClass::ExactStandard {
                name.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR
            } else {
                std::ptr::null_mut()
            };
            let version_ptr = matches!(
                request.version,
                SelectionVersionClass::V3_0
                    | SelectionVersionClass::V3_1
                    | SelectionVersionClass::V3_2
            )
            .then_some(&mut version as *mut cryptoki_sys::CK_VERSION)
            .unwrap_or(std::ptr::null_mut());
            let rv = unsafe { get_interface(name_ptr, version_ptr, &mut output, flags) };
            let (result, helper_failure) = if rv != cryptoki_sys::CKR_OK {
                (None, None)
            } else if output.is_null() {
                (None, Some(SelectionFailure::NullOutput))
            } else {
                let mut captured = None;
                let bracket = selection_bracket(
                    || stable_selection_maps(module_path, module_file_key, module_identity),
                    |maps_a| {
                        let (name_pointer, table_pointer, returned_flags) =
                            read_interface(memory, output as usize)
                                .map_err(|_| SelectionFailure::UnreadableInterface)?;
                        let inventory_matches =
                            selection_inventory_indices(inventory_tables, table_pointer);
                        let name = read_name(memory, name_pointer);
                        let version_read = read_version(memory, table_pointer);
                        let name_class = selection_name_class(&name, name_pointer);
                        let version_class = selection_version_class(&version_read, table_pointer);
                        let table_snapshot = match version_class {
                            SelectionVersionClass::V3_0
                            | SelectionVersionClass::V3_1
                            | SelectionVersionClass::V3_2 => Some(snapshot_table(
                                memory,
                                table_pointer,
                                tables_for(Surface::StandardInterface {
                                    version: cryptoki_sys::CK_VERSION {
                                        major: 3,
                                        minor: match version_class {
                                            SelectionVersionClass::V3_0 => 0,
                                            SelectionVersionClass::V3_1 => 1,
                                            SelectionVersionClass::V3_2 => 2,
                                            _ => unreachable!(),
                                        },
                                    },
                                }),
                            )),
                            _ => None,
                        };
                        let mut helper_failure = if name_pointer == 0 || name.error.is_some() {
                            Some(SelectionFailure::UnreadableName)
                        } else if table_pointer == 0 {
                            Some(SelectionFailure::UnreadableTable)
                        } else if version_read.is_err() {
                            Some(SelectionFailure::UnreadableVersion)
                        } else if selection_table_incomplete(version_class, table_snapshot.as_ref())
                        {
                            Some(SelectionFailure::UnreadableTable)
                        } else {
                            None
                        };
                        let mut selection_table = None;
                        if helper_failure.is_none()
                            && request.name == SelectionNameClass::ExactStandard
                            && inventory_matches.is_empty()
                            && name_class == SelectionNameClass::ExactStandard
                            && matches!(
                                version_class,
                                SelectionVersionClass::V3_0
                                    | SelectionVersionClass::V3_1
                                    | SelectionVersionClass::V3_2
                            )
                            && matches!(returned_flags, 0 | 1)
                        {
                            match selection_table_for(
                                table_pointer,
                                version_class,
                                table_snapshot.as_ref(),
                                maps_a,
                                objects,
                            ) {
                                Ok((table, origin)) => {
                                    selection_table = Some((table, origin));
                                }
                                Err(failure) => {
                                    helper_failure = Some(failure);
                                }
                            }
                        }
                        captured = Some((
                            RawSelectionResult {
                                name: name_class,
                                version: version_class,
                                flags: returned_flags,
                                table: selection_table,
                                inventory_matches,
                            },
                            helper_failure,
                        ));
                        Ok(())
                    },
                    || stable_selection_maps(module_path, module_file_key, module_identity),
                );
                match bracket {
                    Ok(()) => captured
                        .map(|(result, helper_failure)| (Some(result), helper_failure))
                        .unwrap_or((None, Some(SelectionFailure::UnreadableInterface))),
                    Err(SelectionFailure::ProviderChanged) => captured
                        .map(|(mut result, _)| {
                            result.table = None;
                            (Some(result), Some(SelectionFailure::ProviderChanged))
                        })
                        .unwrap_or((None, Some(SelectionFailure::ProviderChanged))),
                    Err(failure) => (None, Some(failure)),
                }
            };
            queries.push(RawSelectionQuery {
                selector,
                request,
                rv: native_ulong_u64(rv),
                result,
                helper_failure,
            });
        }
    }
    (SelectionAcquisition::Queried, queries)
}

fn ptr_bytes(bytes: &[u8], offset: usize) -> Result<usize, String> {
    let width = std::mem::size_of::<usize>();
    let end = offset
        .checked_add(width)
        .ok_or_else(|| "interface pointer offset overflow".to_string())?;
    let bytes = bytes
        .get(offset..end)
        .ok_or_else(|| "short CK_INTERFACE read".to_string())?;
    match width {
        8 => Ok(u64::from_ne_bytes(bytes.try_into().unwrap()) as usize),
        4 => Ok(u32::from_ne_bytes(bytes.try_into().unwrap()) as usize),
        _ => Err("unsupported provider pointer width".into()),
    }
}

fn read_interface(memory: &ProcessMemory, address: usize) -> Result<(usize, usize, u64), String> {
    let width = std::mem::size_of::<usize>();
    let bytes = memory.read_exact(address, width * 3)?;
    Ok((
        ptr_bytes(&bytes, 0)?,
        ptr_bytes(&bytes, width)?,
        ptr_bytes(&bytes, width * 2)? as u64,
    ))
}

fn selection_name_class(name: &NameRead, pointer: usize) -> SelectionNameClass {
    if pointer == 0 {
        SelectionNameClass::Null
    } else if name.error.is_some() {
        SelectionNameClass::Unreadable
    } else if name.raw.as_deref() == Some(b"PKCS 11".as_slice()) {
        SelectionNameClass::ExactStandard
    } else {
        SelectionNameClass::Other
    }
}

fn selection_version_class(
    version: &Result<cryptoki_sys::CK_VERSION, String>,
    pointer: usize,
) -> SelectionVersionClass {
    if pointer == 0 {
        SelectionVersionClass::Null
    } else {
        match version {
            Ok(version) => match (version.major, version.minor) {
                (2, 40) => SelectionVersionClass::V2_40,
                (3, 0) => SelectionVersionClass::V3_0,
                (3, 1) => SelectionVersionClass::V3_1,
                (3, 2) => SelectionVersionClass::V3_2,
                _ => SelectionVersionClass::Other,
            },
            Err(_) => SelectionVersionClass::Unreadable,
        }
    }
}

fn selection_result_readable(result: &SelectionRequest) -> bool {
    !matches!(
        (result.name, result.version),
        (SelectionNameClass::Null | SelectionNameClass::Unreadable, _)
            | (
                _,
                SelectionVersionClass::Null | SelectionVersionClass::Unreadable
            )
    )
}

fn inventory_name_class(source: &SurfaceSource) -> SelectionNameClass {
    let SurfaceSource::Interface {
        raw_name_hex,
        name_error,
        ..
    } = source
    else {
        return SelectionNameClass::Null;
    };
    if name_error.is_some() {
        SelectionNameClass::Unreadable
    } else if raw_name_hex.as_deref() == Some("504b4353203131") {
        SelectionNameClass::ExactStandard
    } else if raw_name_hex.is_some() {
        SelectionNameClass::Other
    } else {
        SelectionNameClass::Null
    }
}

fn inventory_version_class(surface: &SurfaceRecord) -> SelectionVersionClass {
    match surface.version {
        Some(version) => match (version.major, version.minor) {
            (2, 40) => SelectionVersionClass::V2_40,
            (3, 0) => SelectionVersionClass::V3_0,
            (3, 1) => SelectionVersionClass::V3_1,
            (3, 2) => SelectionVersionClass::V3_2,
            _ => SelectionVersionClass::Other,
        },
        None if matches!(surface.walk, WalkOutcome::Unreadable { .. }) => {
            SelectionVersionClass::Unreadable
        }
        None => SelectionVersionClass::Null,
    }
}

fn selection_resolve_values(
    values: Vec<(&'static str, usize)>,
    maps: &maps::MapIndex<'_>,
    objects: &ObjectTable,
) -> Result<Vec<FunctionRecord>, SelectionFailure> {
    values
        .into_iter()
        .map(|(name, value)| {
            let resolution = if value == 0 {
                Resolution::NullPointer
            } else {
                match maps.resolve(value as u64) {
                    maps::Resolved::File {
                        file_offset,
                        device,
                        inode,
                        permissions,
                        ..
                    } if ObjectKey { device, inode } == objects.module_key
                        && permissions[2] == b'x' =>
                    {
                        Resolution::Resolved {
                            object: 0,
                            file_offset,
                        }
                    }
                    maps::Resolved::File { .. } => {
                        return Err(SelectionFailure::UnresolvedFunction);
                    }
                    maps::Resolved::Anonymous | maps::Resolved::Unmapped => {
                        return Err(SelectionFailure::UnresolvedFunction);
                    }
                }
            };
            Ok(FunctionRecord {
                name: name.to_string(),
                resolution,
            })
        })
        .collect()
}

fn selection_table_for(
    pointer: usize,
    version: SelectionVersionClass,
    snapshot: Option<&TableSnapshot>,
    maps: &maps::MapIndex<'_>,
    objects: &ObjectTable,
) -> Result<(SelectionTable, TableOrigin), SelectionFailure> {
    let version = match version {
        SelectionVersionClass::V3_0 => Version { major: 3, minor: 0 },
        SelectionVersionClass::V3_1 => Version { major: 3, minor: 1 },
        SelectionVersionClass::V3_2 => Version { major: 3, minor: 2 },
        _ => return Err(SelectionFailure::UnreadableTable),
    };
    let maps::Resolved::File {
        device,
        inode,
        file_offset,
        ..
    } = maps.resolve(pointer as u64)
    else {
        return Err(SelectionFailure::OutsideProvider);
    };
    if (ObjectKey { device, inode }) != objects.module_key {
        return Err(SelectionFailure::OutsideProvider);
    }
    let Some(snapshot) = snapshot else {
        return Err(SelectionFailure::UnreadableTable);
    };
    if !matches!(snapshot.walk, WalkOutcome::Full) {
        return Err(SelectionFailure::UnreadableTable);
    }
    let functions = selection_resolve_values(snapshot.values.clone(), maps, objects)?;
    Ok((
        SelectionTable {
            id: 0,
            version,
            walk: WalkOutcome::Full,
            functions,
            semantic_authorized: false,
        },
        TableOrigin {
            object: ObjectKey { device, inode },
            file_offset,
        },
    ))
}

fn stable_selection_maps(
    module_path: &Path,
    expected_key: ObjectKey,
    expected_identity: &ObjectIdentity,
) -> Result<Vec<maps::MapEntry>, ()> {
    let mut budget = UnboundedProbeBudget;
    stable_selection_maps_with_probe(
        module_path,
        expected_key,
        expected_identity,
        &KernelSelfMappingProbe,
        &mut budget,
    )
}

fn stable_selection_maps_with_probe(
    module_path: &Path,
    expected_key: ObjectKey,
    expected_identity: &ObjectIdentity,
    probe: &impl SelfMappingProbe,
    budget: &mut dyn ProbeBudget,
) -> Result<Vec<maps::MapEntry>, ()> {
    let bytes = std::fs::read("/proc/self/maps").map_err(|_| ())?;
    let current_maps = maps::parse_maps(&bytes).map_err(|_| ())?;
    let file = identity::open_object(module_path).map_err(|_| ())?;
    let current_key = file_key(&file).map_err(|_| ())?;
    let current_identity =
        validated_file_identity_with_probe(module_path, &file, current_key, probe, budget)
            .map_err(|_| ())?;
    if current_key != expected_key || current_identity != *expected_identity {
        return Err(());
    }
    if current_maps
        .iter()
        .any(|mapping| ObjectKey::of(mapping) == expected_key)
    {
        return Ok(current_maps);
    }
    // On pre-6.8 kernels the overlay fd key never appears in maps; accept
    // only when the kernel renders this exact fd at a key the snapshot
    // contains.
    if let Some(probed) = self_mapped_fallback_key(&file, current_key, budget, probe)
        && current_maps
            .iter()
            .any(|mapping| ObjectKey::of(mapping) == probed)
    {
        return Ok(current_maps);
    }
    Err(())
}

fn selection_records(
    acquisition: (SelectionAcquisition, Vec<RawSelectionQuery>),
    surfaces: &[SurfaceRecord],
) -> SelectionEvidence {
    let (acquisition, raw_queries) = acquisition;
    if !matches!(acquisition, SelectionAcquisition::Queried) {
        return SelectionEvidence {
            acquisition,
            ..SelectionEvidence::default()
        };
    }
    let mut tables = Vec::<SelectionTable>::new();
    let mut pair_tables = BTreeMap::<(SelectionVersionClass, u64), (TableOrigin, u8)>::new();
    let mut table_pointers = BTreeMap::<(TableOrigin, SelectionVersionClass), u8>::new();
    let mut selection_truncated = false;
    let mut queries = Vec::with_capacity(raw_queries.len());
    for raw in raw_queries {
        if raw.rv != 0 {
            queries.push(SelectionQuery {
                selector: raw.selector,
                request: raw.request,
                rv: raw.rv,
                result: None,
                inventory_matches: Vec::new(),
                selection_table: None,
                authority: SelectionAuthority::None,
                helper_failure: None,
            });
            continue;
        }
        let Some(raw_result) = raw.result else {
            queries.push(SelectionQuery {
                selector: raw.selector,
                request: raw.request,
                rv: raw.rv,
                result: None,
                inventory_matches: Vec::new(),
                selection_table: None,
                authority: SelectionAuthority::None,
                helper_failure: raw.helper_failure,
            });
            continue;
        };
        let result = SelectionRequest {
            name: raw_result.name,
            version: raw_result.version,
            flags: raw_result.flags,
        };
        let mut matches = raw_result
            .inventory_matches
            .into_iter()
            .filter(|surface| *surface < surfaces.len())
            .map(|surface| {
                let surface_name = inventory_name_class(&surfaces[surface].source);
                let surface_version = inventory_version_class(&surfaces[surface]);
                SelectionInventoryMatch {
                    surface,
                    name_agrees: !matches!(
                        (result.name, surface_name),
                        (SelectionNameClass::Null | SelectionNameClass::Unreadable, _)
                            | (_, SelectionNameClass::Null | SelectionNameClass::Unreadable)
                    ) && matches!(
                        surfaces[surface].source,
                        SurfaceSource::Interface { .. }
                    ) && result.name == surface_name,
                    version_agrees: !matches!(
                        (result.version, surface_version),
                        (
                            SelectionVersionClass::Null | SelectionVersionClass::Unreadable,
                            _
                        ) | (
                            _,
                            SelectionVersionClass::Null | SelectionVersionClass::Unreadable
                        )
                    ) && result.version == surface_version,
                }
            })
            .collect::<Vec<_>>();
        if matches.len() > 16 {
            matches.truncate(16);
            selection_truncated = true;
        }
        let mut selection_table = None;
        let mut authority = SelectionAuthority::None;
        if raw.helper_failure.is_none()
            && raw.request.name == SelectionNameClass::ExactStandard
            && let Some((mut table, origin)) = raw_result.table
            && matches.is_empty()
            && result.name == SelectionNameClass::ExactStandard
            && matches!(
                result.version,
                SelectionVersionClass::V3_0
                    | SelectionVersionClass::V3_1
                    | SelectionVersionClass::V3_2
            )
            && matches!(result.flags, 0 | 1)
        {
            let key = (origin, result.version);
            let pair = (result.version, result.flags);
            if let Some((known_origin, table_id)) = pair_tables.get(&pair).copied() {
                if known_origin != origin {
                    selection_truncated = true;
                } else {
                    selection_table = Some(table_id);
                    authority = SelectionAuthority::SelectionCountOnly;
                }
            } else {
                let table_id = if let Some(table_id) = table_pointers.get(&key).copied() {
                    table_id
                } else {
                    let table_id = tables.len() as u8;
                    table.id = table_id;
                    tables.push(table);
                    table_pointers.insert(key, table_id);
                    table_id
                };
                pair_tables.insert(pair, (origin, table_id));
                selection_table = Some(table_id);
                authority = SelectionAuthority::SelectionCountOnly;
            }
        }
        if !matches.is_empty() && raw.helper_failure.is_none() && selection_result_readable(&result)
        {
            authority = SelectionAuthority::Inventory;
        }
        queries.push(SelectionQuery {
            selector: raw.selector,
            request: raw.request,
            rv: raw.rv,
            result: Some(result),
            inventory_matches: matches,
            selection_table,
            authority,
            helper_failure: raw.helper_failure,
        });
    }
    SelectionEvidence {
        acquisition,
        queries,
        tables,
        selection_truncated,
    }
}

#[allow(clippy::too_many_arguments)]
fn interface_surface(
    index: usize,
    entry: &RawInterface,
    name: NameRead,
    version: Result<cryptoki_sys::CK_VERSION, String>,
    classification: InterfaceClassification,
    force_prefix: bool,
    memory: &ProcessMemory,
    maps: &maps::MapIndex<'_>,
    objects: &mut ObjectTable,
) -> SurfaceRecord {
    let Ok(version) = version else {
        return SurfaceRecord {
            source: interface_source(index, native_ulong_u64(entry.flags), name, classification),
            acquisition: Acquisition::Ok,
            version: None,
            walk: if entry.func_list.is_null() {
                WalkOutcome::NotWalked
            } else {
                WalkOutcome::Unreadable {
                    detail: version.unwrap_err(),
                }
            },
            functions: vec![],
        };
    };
    let snapshot = snapshot_table(
        memory,
        entry.func_list as usize,
        tables_for(Surface::StandardInterface { version }),
    );
    interface_surface_from_snapshot(
        index,
        entry,
        name,
        version,
        classification,
        snapshot,
        force_prefix,
        maps,
        objects,
    )
}

#[allow(clippy::too_many_arguments)]
fn interface_surface_from_snapshot(
    index: usize,
    entry: &RawInterface,
    name: NameRead,
    version: cryptoki_sys::CK_VERSION,
    classification: InterfaceClassification,
    snapshot: TableSnapshot,
    force_prefix: bool,
    maps: &maps::MapIndex<'_>,
    objects: &mut ObjectTable,
) -> SurfaceRecord {
    let walk = if force_prefix && matches!(&snapshot.walk, WalkOutcome::Full) {
        WalkOutcome::KnownPrefix
    } else {
        snapshot.walk
    };
    SurfaceRecord {
        source: interface_source(index, native_ulong_u64(entry.flags), name, classification),
        acquisition: Acquisition::Ok,
        version: Some(manifest_version(version)),
        walk,
        functions: resolve_values(snapshot.values, maps, objects),
    }
}

fn interface_source(
    index: usize,
    flags: u64,
    name: NameRead,
    classification: InterfaceClassification,
) -> SurfaceSource {
    SurfaceSource::Interface {
        index,
        raw_name_hex: name.raw.as_deref().map(identity::hex),
        name_lossy: name.lossy,
        name_error: name.error,
        flags,
        classification,
    }
}

fn vendor_interface(
    index: usize,
    entry: &RawInterface,
    name: NameRead,
    version: Option<cryptoki_sys::CK_VERSION>,
    version_error: Option<String>,
) -> VendorInterface {
    VendorInterface {
        index,
        raw_name_hex: name.raw.as_deref().map(identity::hex),
        name_lossy: name.lossy,
        name_error: name.error,
        version: version.map(manifest_version),
        version_error,
        flags: native_ulong_u64(entry.flags),
        func_list_null: entry.func_list.is_null(),
    }
}

fn corroborates_standard(
    version: cryptoki_sys::CK_VERSION,
    snapshot: &TableSnapshot,
    exports: ExportAddresses,
    legacy_240: Option<&[usize]>,
) -> bool {
    if matches!(
        &snapshot.walk,
        WalkOutcome::Refused | WalkOutcome::Unreadable { .. } | WalkOutcome::NotWalked
    ) {
        return false;
    }
    match (version.major, version.minor) {
        (2, 40) => {
            let values: Vec<usize> = snapshot.values.iter().map(|(_, value)| *value).collect();
            legacy_240.is_some_and(|legacy| legacy == values)
        }
        (3, _) => {
            table_value(&snapshot.values, "C_GetFunctionList") == exports.get_function_list
                && table_value(&snapshot.values, "C_GetInterfaceList") == exports.get_interface_list
                && table_value(&snapshot.values, "C_GetInterface") == exports.get_interface
                && exports.get_function_list.is_some()
                && exports.get_interface_list.is_some()
                && exports.get_interface.is_some()
        }
        _ => false,
    }
}

fn table_value(values: &[(&'static str, usize)], name: &str) -> Option<usize> {
    values
        .iter()
        .find(|(field, _)| *field == name)
        .map(|(_, value)| *value)
}

fn resolve_values(
    values: Vec<(&'static str, usize)>,
    maps: &maps::MapIndex<'_>,
    objects: &mut ObjectTable,
) -> Vec<FunctionRecord> {
    values
        .into_iter()
        .map(|(name, value)| FunctionRecord {
            name: name.to_string(),
            resolution: if value == 0 {
                Resolution::NullPointer
            } else {
                match maps.resolve(value as u64) {
                    maps::Resolved::File {
                        path,
                        raw_path,
                        file_offset,
                        device,
                        inode,
                        permissions,
                    } => {
                        if permissions[2] != b'x' {
                            unusable_file("mapping is not executable".into(), &raw_path)
                        } else {
                            objects.resolve(
                                path,
                                raw_path,
                                file_offset,
                                ObjectKey { device, inode },
                            )
                        }
                    }
                    maps::Resolved::Anonymous => Resolution::NonFileBacked,
                    maps::Resolved::Unmapped => Resolution::Unmapped,
                }
            },
        })
        .collect()
}

struct ObjectTable {
    module_key: ObjectKey,
    approved: BTreeSet<ObjectKey>,
    ids: BTreeMap<ObjectKey, u32>,
    records: Vec<ObjectRecord>,
}

impl ObjectTable {
    fn new(
        module_path: PathBuf,
        module_key: ObjectKey,
        identity: ObjectIdentity,
        approved: BTreeSet<ObjectKey>,
    ) -> Self {
        let mut ids = BTreeMap::new();
        ids.insert(module_key, 0);
        Self {
            module_key,
            approved,
            ids,
            records: vec![ObjectRecord {
                id: 0,
                path: module_path.display().to_string(),
                identity,
            }],
        }
    }

    fn resolve(
        &mut self,
        path: MappedPath,
        raw_path: Vec<u8>,
        file_offset: u64,
        key: ObjectKey,
    ) -> Resolution {
        if !self.approved.contains(&key) {
            return unusable_file(
                "target object was not loaded for this provider".into(),
                &raw_path,
            );
        }
        if key == self.module_key {
            return Resolution::Resolved {
                object: 0,
                file_offset,
            };
        }
        let path = match path {
            MappedPath::Usable(path) => path,
            MappedPath::Unusable { reason } => {
                return unusable_file(reason, &raw_path);
            }
        };
        if let Some(id) = self.ids.get(&key) {
            return Resolution::Resolved {
                object: *id,
                file_offset,
            };
        }
        if self.records.len() >= MAX_OBJECTS {
            return unusable_file(
                format!("provider object cap {MAX_OBJECTS} reached"),
                &raw_path,
            );
        }
        let object_identity = match validated_identity(&path, key) {
            Ok(identity) => identity,
            Err(reason) => return unusable_file(reason, &raw_path),
        };
        let id = self.records.len() as u32;
        self.ids.insert(key, id);
        self.records.push(ObjectRecord {
            id,
            path: path.display().to_string(),
            identity: object_identity,
        });
        Resolution::Resolved {
            object: id,
            file_offset,
        }
    }

    fn into_records(self) -> Vec<ObjectRecord> {
        self.records
    }
}

fn unusable_file(reason: String, raw_path: &[u8]) -> Resolution {
    Resolution::UnusableFile {
        reason,
        path_hex: identity::hex(raw_path),
    }
}

fn manifest_version(version: cryptoki_sys::CK_VERSION) -> Version {
    Version {
        major: version.major,
        minor: version.minor,
    }
}

/// Alias = one {object, file_offset} claimed by at least two distinct names.
fn alias_groups(surfaces: &[SurfaceRecord]) -> Vec<AliasGroup> {
    let mut by_target: BTreeMap<(u32, u64), Vec<AliasEntry>> = BTreeMap::new();
    for (surface, record) in surfaces.iter().enumerate() {
        for function in &record.functions {
            if let Resolution::Resolved {
                object,
                file_offset,
            } = function.resolution
            {
                by_target
                    .entry((object, file_offset))
                    .or_default()
                    .push(AliasEntry {
                        surface,
                        name: function.name.clone(),
                    });
            }
        }
    }
    by_target
        .into_iter()
        .filter(|(_, entries)| {
            let mut names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
            names.sort_unstable();
            names.dedup();
            names.len() >= 2
        })
        .map(|((object, file_offset), entries)| AliasGroup {
            object,
            file_offset,
            entries,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_MAPS: &[u8] = b"00400000-00401000 r-xp 00000000 08:01 11 /usr/lib/a.so\n\
00401000-00402000 r--p 00001000 08:01 11 /usr/lib/a.so\n";
    // What a torn read looks like: a line served after another thread's
    // mmap moved the cursor, so ranges arrive out of order.
    const TORN_MAPS: &[u8] = b"00401000-00402000 r--p 00001000 08:01 11 /usr/lib/a.so\n\
00400000-00401000 r-xp 00000000 08:01 11 /usr/lib/a.so\n";

    fn scripted(reads: Vec<&'static [u8]>) -> impl FnMut() -> std::io::Result<Vec<u8>> {
        let mut reads = reads.into_iter();
        move || Ok(reads.next().expect("no more scripted reads").to_vec())
    }

    #[test]
    fn a_torn_self_maps_snapshot_is_read_again() {
        let entries = read_self_maps_with(scripted(vec![TORN_MAPS, TORN_MAPS, GOOD_MAPS])).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(maps::MapIndex::new(&entries).is_ok());
    }

    #[test]
    fn a_self_maps_snapshot_torn_on_every_attempt_is_refused() {
        let err = read_self_maps_with(scripted(vec![TORN_MAPS; SELF_MAPS_ATTEMPTS])).unwrap_err();
        assert!(err.contains("unsorted or overlapping"), "{err}");
    }

    #[test]
    fn a_self_maps_parse_error_is_not_retried() {
        let mut calls = 0;
        let err = read_self_maps_with(|| {
            calls += 1;
            Ok(b"not a maps line\n".to_vec())
        })
        .unwrap_err();
        assert_eq!(calls, 1, "{err}");
    }

    #[test]
    fn self_maps_stay_readable_while_another_thread_maps_and_unmaps() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let held: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 1 << 20]).collect();
                    drop(held);
                }
            });
            // Stop the mapper before asserting, so a failure cannot leave
            // the scope waiting on it forever.
            let failures: Vec<String> = (0..200).filter_map(|_| read_self_maps().err()).collect();
            stop.store(true, Ordering::Relaxed);
            assert!(failures.is_empty(), "torn snapshots surfaced: {failures:?}");
        });
    }

    #[test]
    fn relative_module_is_rejected_before_loading() {
        let err = discover(Path::new("provider.so")).unwrap_err();
        assert!(err.contains("absolute path"), "{err}");
    }

    #[test]
    fn provider_names_are_read_through_a_bounded_snapshot() {
        let memory = ProcessMemory::open().unwrap();
        let exact = b"PKCS 11\0ignored";
        let name = read_name(&memory, exact.as_ptr() as usize);
        assert_eq!(name.raw.as_deref(), Some(b"PKCS 11".as_slice()));
        assert_eq!(name.lossy.as_deref(), Some("PKCS 11"));
        assert_eq!(name.error, None);

        let overlong = [b'x'; INTERFACE_NAME_CAP];
        let name = read_name(&memory, overlong.as_ptr() as usize);
        assert!(name.error.as_deref().unwrap().contains("overlong"));
        assert_eq!(name.raw.as_deref(), Some(overlong.as_slice()));

        assert!(memory.read_exact(usize::MAX, 2).is_err());
    }

    #[test]
    fn mapped_path_identity_requires_device_and_inode() {
        let exe = std::env::current_exe().unwrap();
        let key = identity_and_key(&exe).unwrap().0;
        assert!(validated_identity(&exe, key).unwrap().reusable);

        let wrong = ObjectKey {
            inode: key.inode.wrapping_add(1),
            ..key
        };
        let err = validated_identity(&exe, wrong).unwrap_err();
        assert!(err.contains("device/inode mismatch"), "{err}");
    }

    #[test]
    fn loaded_module_key_reports_invalid_snapshot_before_export_absence() {
        let module_key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 7,
        };
        let module_identity = identity_and_key(&std::env::current_exe().unwrap())
            .unwrap()
            .1;
        let provider = maps::MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: module_key.device,
            inode: module_key.inode,
            raw_path: Some(b"/definitely-not-reachable/provider.so".to_vec()),
        };
        let module_file = identity::open_object(&std::env::current_exe().unwrap()).unwrap();
        let valid = vec![provider];
        let load = |exports, entries: &[maps::MapEntry]| {
            let index = validated_map_index(entries)?;
            loaded_module_key(exports, &index, module_key, &module_identity, &module_file)
        };

        assert_eq!(
            load(
                ExportAddresses {
                    get_function_list: Some(0x1000),
                    ..ExportAddresses::default()
                },
                &valid,
            ),
            Ok(module_key)
        );

        let absent = load(
            ExportAddresses {
                get_function_list: Some(0x9000),
                ..ExportAddresses::default()
            },
            &valid,
        )
        .unwrap_err();
        assert_eq!(
            absent,
            "no module acquisition export maps to the requested file identity"
        );

        let mut invalid = valid;
        invalid.extend([
            maps::MapEntry {
                start: 0x3000,
                end: 0x4000,
                file_offset: 0,
                permissions: *b"rw-p",
                device: Device { major: 0, minor: 0 },
                inode: 0,
                raw_path: None,
            },
            maps::MapEntry {
                start: 0x3800,
                end: 0x4800,
                file_offset: 0,
                permissions: *b"rw-p",
                device: Device { major: 0, minor: 0 },
                inode: 0,
                raw_path: None,
            },
        ]);
        let invalid = load(
            ExportAddresses {
                get_function_list: Some(0x1000),
                ..ExportAddresses::default()
            },
            &invalid,
        )
        .unwrap_err();
        assert!(invalid.contains("invalid /proc maps snapshot"), "{invalid}");
        assert!(
            !invalid.contains("no module acquisition export"),
            "{invalid}"
        );

        let no_exports = load(
            ExportAddresses::default(),
            &[
                maps::MapEntry {
                    start: 0x1000,
                    end: 0x3000,
                    file_offset: 0,
                    permissions: *b"rw-p",
                    device: Device { major: 0, minor: 0 },
                    inode: 0,
                    raw_path: None,
                },
                maps::MapEntry {
                    start: 0x2000,
                    end: 0x4000,
                    file_offset: 0,
                    permissions: *b"rw-p",
                    device: Device { major: 0, minor: 0 },
                    inode: 0,
                    raw_path: None,
                },
            ],
        )
        .unwrap_err();
        assert!(
            no_exports.contains("invalid /proc maps snapshot"),
            "{no_exports}"
        );
    }

    /// A scripted self-mapping probe (see `p11scope_manifest::identity`):
    /// `overlay` answers the overlayfs question and `key` answers the
    /// kernel-rendered maps key, counting both consultations. Real
    /// overlayfs is unmountable without privileges, so unit tests script
    /// the kernel side of the pre-6.8 split.
    struct FakeSelfMappingProbe {
        overlay: bool,
        key: Option<ObjectKey>,
        overlay_checks: std::cell::Cell<usize>,
        probes: std::cell::Cell<usize>,
    }

    impl FakeSelfMappingProbe {
        fn new(overlay: bool, key: Option<ObjectKey>) -> Self {
            Self {
                overlay,
                key,
                overlay_checks: std::cell::Cell::new(0),
                probes: std::cell::Cell::new(0),
            }
        }
    }

    impl SelfMappingProbe for FakeSelfMappingProbe {
        fn fd_is_on_overlayfs(&self, _file: &File) -> bool {
            self.overlay_checks.set(self.overlay_checks.get() + 1);
            self.overlay
        }

        fn kernel_maps_key(
            &self,
            _file: &File,
            _budget: &mut dyn ProbeBudget,
        ) -> Option<ObjectKey> {
            self.probes.set(self.probes.get() + 1);
            self.key
        }
    }

    /// The inode a two-container docker run really produced for one shared
    /// image-layer object.
    const SPLIT_INODE: u64 = 56_317_450;

    /// The fd identity mountinfo gives an overlay file (observed 0:41).
    fn split_fd_key() -> ObjectKey {
        ObjectKey {
            device: Device {
                major: 0,
                minor: 41,
            },
            inode: SPLIT_INODE,
        }
    }

    /// The backing identity a pre-6.8 kernel prints for that fd's mappings:
    /// `00:15` is 0:21, the measured 6.1 rendering.
    fn split_maps_key() -> ObjectKey {
        ObjectKey {
            device: Device {
                major: 0,
                minor: 21,
            },
            inode: SPLIT_INODE,
        }
    }

    fn wrong_key() -> ObjectKey {
        ObjectKey {
            device: Device {
                major: 0,
                minor: 43,
            },
            inode: SPLIT_INODE,
        }
    }

    /// A real non-empty file for probe fixtures. Uses the process temp dir
    /// so the repo's `TMPDIR` lane override applies.
    fn probe_tempfile(name: &str) -> (PathBuf, File) {
        let dir = std::env::temp_dir().join(format!(
            "p11scope-discover-probe-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probed.so");
        std::fs::write(&path, "p11scope-discover-probe:page-one").unwrap();
        let file = File::open(&path).unwrap();
        (dir, file)
    }

    /// One executable mapping carrying `key` at 0x1000 with an unreachable
    /// path, so the reachable-path revalidation never runs and the tests
    /// stay hermetic.
    fn provider_entry(key: ObjectKey) -> maps::MapEntry {
        maps::MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: key.device,
            inode: key.inode,
            raw_path: Some(b"/definitely-not-reachable/provider.so".to_vec()),
        }
    }

    fn export_at_1000() -> ExportAddresses {
        ExportAddresses {
            get_function_list: Some(0x1000),
            ..ExportAddresses::default()
        }
    }

    #[test]
    fn loaded_split_probe_equal_keys_accept_without_probing() {
        let (_dir, module_file) = probe_tempfile("loaded-equal");
        let module_identity = identity_and_key(&std::env::current_exe().unwrap())
            .unwrap()
            .1;
        let entries = vec![provider_entry(split_fd_key())];
        let index = validated_map_index(&entries).unwrap();
        let probe = FakeSelfMappingProbe::new(true, None);
        let mut budget = UnboundedProbeBudget;
        assert_eq!(
            loaded_module_key_with_probe(
                export_at_1000(),
                &index,
                split_fd_key(),
                &module_identity,
                &module_file,
                &probe,
                &mut budget,
            ),
            Ok(split_fd_key())
        );
        assert_eq!(probe.overlay_checks.get(), 0);
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn loaded_split_probe_overlay_match_accepts_the_maps_key() {
        let (_dir, module_file) = probe_tempfile("loaded-match");
        let module_identity = identity_and_key(&std::env::current_exe().unwrap())
            .unwrap()
            .1;
        let entries = vec![provider_entry(split_maps_key())];
        let index = validated_map_index(&entries).unwrap();
        let probe = FakeSelfMappingProbe::new(true, Some(split_maps_key()));
        let mut budget = UnboundedProbeBudget;
        assert_eq!(
            loaded_module_key_with_probe(
                export_at_1000(),
                &index,
                split_fd_key(),
                &module_identity,
                &module_file,
                &probe,
                &mut budget,
            ),
            Ok(split_maps_key())
        );
        assert_eq!(probe.probes.get(), 1);
    }

    #[test]
    fn loaded_split_probe_overlay_mismatch_refuses_with_todays_message() {
        let (_dir, module_file) = probe_tempfile("loaded-mismatch");
        let module_identity = identity_and_key(&std::env::current_exe().unwrap())
            .unwrap()
            .1;
        let entries = vec![provider_entry(split_maps_key())];
        let index = validated_map_index(&entries).unwrap();
        let probe = FakeSelfMappingProbe::new(true, Some(wrong_key()));
        let mut budget = UnboundedProbeBudget;
        assert_eq!(
            loaded_module_key_with_probe(
                export_at_1000(),
                &index,
                split_fd_key(),
                &module_identity,
                &module_file,
                &probe,
                &mut budget,
            )
            .unwrap_err(),
            "no module acquisition export maps to the requested file identity"
        );
    }

    #[test]
    fn loaded_split_probe_non_overlay_mismatch_refuses_without_probing() {
        let (_dir, module_file) = probe_tempfile("loaded-non-overlay");
        let module_identity = identity_and_key(&std::env::current_exe().unwrap())
            .unwrap()
            .1;
        let entries = vec![provider_entry(split_maps_key())];
        let index = validated_map_index(&entries).unwrap();
        let probe = FakeSelfMappingProbe::new(false, Some(split_maps_key()));
        let mut budget = UnboundedProbeBudget;
        assert_eq!(
            loaded_module_key_with_probe(
                export_at_1000(),
                &index,
                split_fd_key(),
                &module_identity,
                &module_file,
                &probe,
                &mut budget,
            )
            .unwrap_err(),
            "no module acquisition export maps to the requested file identity"
        );
        assert_eq!(probe.overlay_checks.get(), 1);
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn loaded_split_probe_error_refuses() {
        let (_dir, module_file) = probe_tempfile("loaded-error");
        let module_identity = identity_and_key(&std::env::current_exe().unwrap())
            .unwrap()
            .1;
        let entries = vec![provider_entry(split_maps_key())];
        let index = validated_map_index(&entries).unwrap();
        let probe = FakeSelfMappingProbe::new(true, None);
        let mut budget = UnboundedProbeBudget;
        assert_eq!(
            loaded_module_key_with_probe(
                export_at_1000(),
                &index,
                split_fd_key(),
                &module_identity,
                &module_file,
                &probe,
                &mut budget,
            )
            .unwrap_err(),
            "no module acquisition export maps to the requested file identity"
        );
    }

    #[test]
    fn validated_split_probe_equal_keys_accept_without_probing() {
        let exe = std::env::current_exe().unwrap();
        let file = identity::open_object(&exe).unwrap();
        let key = file_key(&file).unwrap();
        let probe = FakeSelfMappingProbe::new(true, None);
        let mut budget = UnboundedProbeBudget;
        assert!(
            validated_file_identity_with_probe(&exe, &file, key, &probe, &mut budget)
                .unwrap()
                .reusable
        );
        assert_eq!(probe.overlay_checks.get(), 0);
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn validated_split_probe_overlay_match_accepts_a_split_maps_key() {
        let exe = std::env::current_exe().unwrap();
        let file = identity::open_object(&exe).unwrap();
        let probe = FakeSelfMappingProbe::new(true, Some(split_maps_key()));
        let mut budget = UnboundedProbeBudget;
        // `expected` is the maps rendering (backing) while the fd resolves
        // to the overlay device, so only the probe bridges them.
        assert!(
            validated_file_identity_with_probe(&exe, &file, split_maps_key(), &probe, &mut budget,)
                .unwrap()
                .reusable
        );
        assert_eq!(probe.probes.get(), 1);
    }

    #[test]
    fn validated_split_probe_mismatch_keeps_todays_message() {
        let exe = std::env::current_exe().unwrap();
        let file = identity::open_object(&exe).unwrap();
        for probe in [
            FakeSelfMappingProbe::new(true, Some(wrong_key())),
            FakeSelfMappingProbe::new(false, Some(split_maps_key())),
            FakeSelfMappingProbe::new(true, None),
        ] {
            let mut budget = UnboundedProbeBudget;
            let err = validated_file_identity_with_probe(
                &exe,
                &file,
                split_maps_key(),
                &probe,
                &mut budget,
            )
            .unwrap_err();
            assert!(err.contains("device/inode mismatch"), "{err}");
        }
    }

    #[test]
    fn stable_maps_live_module_accepts_without_probing() {
        let exe = std::env::current_exe().unwrap();
        let (key, identity) = identity_and_key(&exe).unwrap();
        let probe = FakeSelfMappingProbe::new(true, None);
        let mut budget = UnboundedProbeBudget;
        let maps =
            stable_selection_maps_with_probe(&exe, key, &identity, &probe, &mut budget).unwrap();
        assert!(maps.iter().any(|mapping| ObjectKey::of(mapping) == key));
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn stable_maps_changed_key_refuses() {
        let exe = std::env::current_exe().unwrap();
        let (key, identity) = identity_and_key(&exe).unwrap();
        let wrong = ObjectKey {
            inode: key.inode.wrapping_add(1),
            ..key
        };
        let probe = FakeSelfMappingProbe::new(true, Some(wrong));
        let mut budget = UnboundedProbeBudget;
        stable_selection_maps_with_probe(&exe, wrong, &identity, &probe, &mut budget).unwrap_err();
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn identity_inspection_stays_on_the_opened_inode_after_retarget() {
        let dir = std::env::temp_dir().join(format!(
            "p11scope-discover-retarget-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let link = dir.join("provider.so");
        let original = std::env::current_exe().unwrap();
        let replacement = Path::new("/bin/true");
        std::os::unix::fs::symlink(&original, &link).unwrap();
        let file = identity::open_object(&link).unwrap();
        let key = file_key(&file).unwrap();
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(replacement, &link).unwrap();

        let actual = validated_file_identity(&link, &file, key).unwrap();
        assert_eq!(actual, identity::identify(&original));
        assert_ne!(actual, identity::identify(replacement));

        std::fs::remove_dir_all(dir).unwrap();
    }

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
            resolution: Resolution::Resolved {
                object: 0,
                file_offset: off,
            },
        }
    }

    #[test]
    fn selection_bracket_rejects_synthetic_remap() {
        let first = maps::MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: Device { major: 1, minor: 2 },
            inode: 3,
            raw_path: Some(b"/provider.so".to_vec()),
        };
        let mut remapped = first.clone();
        remapped.start = 0x3000;
        remapped.end = 0x4000;
        let result = selection_bracket(|| Ok(vec![first]), |_| Ok(7u8), || Ok(vec![remapped]));
        assert_eq!(result, Err(SelectionFailure::ProviderChanged));
    }

    #[test]
    fn selection_bracket_refuses_invalid_snapshots() {
        let provider = maps::MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: Device { major: 1, minor: 2 },
            inode: 3,
            raw_path: Some(b"/provider.so".to_vec()),
        };
        let anonymous = maps::MapEntry {
            start: 0x3000,
            end: 0x4000,
            file_offset: 0,
            permissions: *b"rw-p",
            device: Device { major: 0, minor: 0 },
            inode: 0,
            raw_path: None,
        };
        let overlap = maps::MapEntry {
            start: 0x3800,
            end: 0x4800,
            ..anonymous.clone()
        };
        let valid = vec![provider, anonymous];
        let invalid = vec![valid[0].clone(), valid[1].clone(), overlap];

        let reads = std::cell::Cell::new(0);
        let invalid_a = selection_bracket(
            || Ok(invalid.clone()),
            |_| {
                reads.set(reads.get() + 1);
                Ok(7u8)
            },
            || Ok(valid.clone()),
        );
        assert_eq!(invalid_a, Err(SelectionFailure::ProviderChanged));
        assert_eq!(reads.get(), 0, "invalid A must prevent dependent reads");

        let invalid_b =
            selection_bracket(|| Ok(valid.clone()), |_| Ok(7u8), || Ok(invalid.clone()));
        assert_eq!(invalid_b, Err(SelectionFailure::ProviderChanged));

        let both_invalid =
            selection_bracket(|| Ok(invalid.clone()), |_| Ok(7u8), || Ok(invalid.clone()));
        assert_eq!(both_invalid, Err(SelectionFailure::ProviderChanged));

        let stable = selection_bracket(|| Ok(valid.clone()), |_| Ok(7u8), || Ok(valid.clone()));
        assert_eq!(stable, Ok(7));
    }

    #[test]
    fn selection_bracket_validation_overrides_absence_classifications() {
        let module_key = ObjectKey {
            device: Device { major: 1, minor: 2 },
            inode: 3,
        };
        let provider = maps::MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: module_key.device,
            inode: module_key.inode,
            raw_path: Some(b"/provider.so".to_vec()),
        };
        let anonymous = maps::MapEntry {
            start: 0x3000,
            end: 0x4000,
            file_offset: 0,
            permissions: *b"rw-p",
            device: Device { major: 0, minor: 0 },
            inode: 0,
            raw_path: None,
        };
        let valid = vec![provider, anonymous.clone()];
        let invalid = vec![
            valid[0].clone(),
            anonymous.clone(),
            maps::MapEntry {
                start: 0x3800,
                end: 0x4800,
                ..anonymous
            },
        ];
        let objects = ObjectTable {
            module_key,
            approved: BTreeSet::new(),
            ids: BTreeMap::new(),
            records: Vec::new(),
        };

        let valid_table_absence = selection_bracket(
            || Ok(valid.clone()),
            |index| {
                selection_table_for(0x9000, SelectionVersionClass::V3_0, None, index, &objects)
                    .map(|_| ())
            },
            || Ok(valid.clone()),
        );
        assert_eq!(valid_table_absence, Err(SelectionFailure::OutsideProvider));

        let invalid_b_table = selection_bracket(
            || Ok(valid.clone()),
            |index| {
                selection_table_for(0x9000, SelectionVersionClass::V3_0, None, index, &objects)
                    .map(|_| ())
            },
            || Ok(invalid.clone()),
        );
        assert_eq!(invalid_b_table, Err(SelectionFailure::ProviderChanged));

        let valid_function_absence = selection_bracket(
            || Ok(valid.clone()),
            |index| selection_resolve_values(vec![("C_Test", 0x9000)], index, &objects).map(|_| ()),
            || Ok(valid.clone()),
        );
        assert_eq!(
            valid_function_absence,
            Err(SelectionFailure::UnresolvedFunction)
        );

        let invalid_b_function = selection_bracket(
            || Ok(valid.clone()),
            |index| selection_resolve_values(vec![("C_Test", 0x9000)], index, &objects).map(|_| ()),
            || Ok(invalid.clone()),
        );
        assert_eq!(invalid_b_function, Err(SelectionFailure::ProviderChanged));
    }

    #[test]
    fn selection_bracket_ignores_unrelated_anonymous_mapping_churn() {
        let provider = maps::MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: Device { major: 1, minor: 2 },
            inode: 3,
            raw_path: Some(b"/provider.so".to_vec()),
        };
        let worker_stack = maps::MapEntry {
            start: 0x3000,
            end: 0x4000,
            file_offset: 0,
            permissions: *b"rw-p",
            device: Device { major: 0, minor: 0 },
            inode: 0,
            raw_path: None,
        };
        let result = selection_bracket(
            || Ok(vec![provider.clone(), worker_stack]),
            |_| Ok(7u8),
            || Ok(vec![provider.clone()]),
        );
        assert_eq!(result, Ok(7));
    }

    #[test]
    fn selection_bracket_orders_snapshots_around_resolution() {
        let events = std::cell::RefCell::new(Vec::new());
        let result = selection_bracket(
            || {
                events.borrow_mut().push("a");
                Ok(Vec::new())
            },
            |_| {
                events.borrow_mut().push("read");
                Ok(7u8)
            },
            || {
                events.borrow_mut().push("b");
                Ok(Vec::new())
            },
        );
        assert_eq!(result.unwrap(), 7);
        assert_eq!(*events.borrow(), vec!["a", "read", "b"]);
    }

    #[test]
    fn selection_inventory_indices_require_literal_pointer_equality() {
        let indices =
            selection_inventory_indices(&[Some(0x1000), Some(0x2000), Some(0x1000)], 0x3000);
        assert!(indices.is_empty());
        assert_eq!(
            selection_inventory_indices(&[Some(0x1000), Some(0x2000)], 0x2000),
            vec![1]
        );
    }

    #[test]
    fn known_incomplete_selection_table_is_unreadable() {
        let snapshot = TableSnapshot {
            walk: WalkOutcome::Unreadable {
                detail: "short table".into(),
            },
            values: vec![],
        };
        assert!(selection_table_incomplete(
            SelectionVersionClass::V3_0,
            Some(&snapshot)
        ));
    }

    #[test]
    fn selector_zero_never_gets_selection_count_only_authority() {
        let evidence = selection_records(
            (
                SelectionAcquisition::Queried,
                vec![RawSelectionQuery {
                    selector: 0,
                    request: selection_request(0, 0),
                    rv: 0,
                    result: Some(RawSelectionResult {
                        name: SelectionNameClass::ExactStandard,
                        version: SelectionVersionClass::V3_0,
                        flags: 0,
                        table: Some((
                            SelectionTable {
                                id: 0,
                                version: Version { major: 3, minor: 0 },
                                walk: WalkOutcome::Full,
                                functions: vec![],
                                semantic_authorized: false,
                            },
                            TableOrigin {
                                object: ObjectKey {
                                    device: Device { major: 1, minor: 1 },
                                    inode: 1,
                                },
                                file_offset: 0,
                            },
                        )),
                        inventory_matches: vec![],
                    }),
                    helper_failure: None,
                }],
            ),
            &[],
        );
        assert_eq!(evidence.queries[0].authority, SelectionAuthority::None);
        assert!(evidence.queries[0].selection_table.is_none());
        assert!(evidence.tables.is_empty());
    }

    #[test]
    fn selection_inventory_matches_are_bounded_at_sixteen() {
        let surfaces = (0..17)
            .map(|_| surface_with(Vec::new()))
            .collect::<Vec<_>>();
        let evidence_for = |count| {
            selection_records(
                (
                    SelectionAcquisition::Queried,
                    vec![RawSelectionQuery {
                        selector: 0,
                        request: selection_request(0, 0),
                        rv: 0,
                        result: Some(RawSelectionResult {
                            name: SelectionNameClass::ExactStandard,
                            version: SelectionVersionClass::V3_0,
                            flags: 0,
                            table: None,
                            inventory_matches: (0..count).collect(),
                        }),
                        helper_failure: None,
                    }],
                ),
                &surfaces,
            )
        };

        let boundary = evidence_for(16);
        assert_eq!(boundary.queries[0].inventory_matches.len(), 16);
        assert!(!boundary.selection_truncated);

        let evidence = evidence_for(17);

        assert_eq!(
            evidence.queries[0]
                .inventory_matches
                .iter()
                .map(|matched| matched.surface)
                .collect::<Vec<_>>(),
            (0..16).collect::<Vec<_>>()
        );
        assert!(evidence.selection_truncated);
    }

    #[test]
    fn alias_groups_require_two_distinct_names() {
        let surfaces = vec![
            surface_with(vec![resolved("C_Sign", 0x10)]),
            surface_with(vec![resolved("C_Sign", 0x10)]),
        ];
        assert!(alias_groups(&surfaces).is_empty());

        let surfaces = vec![surface_with(vec![
            resolved("C_GetFunctionStatus", 0x20),
            resolved("C_CancelFunction", 0x20),
        ])];
        let groups = alias_groups(&surfaces);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].entries.len(), 2);
    }
}
