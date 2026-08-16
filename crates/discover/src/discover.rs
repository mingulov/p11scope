//! dlopen + table-walk glue: raw provider facts become bounded manifest evidence.
//! The helper never calls C_Initialize or C_GetInterface.

use crate::maps::{self, Device, MappedPath, ObjectKey};
use libloading::Library;
use p11scope_manifest::identity::{self, ObjectIdentity};
use p11scope_manifest::manifest::*;
use pkcs11_module::{
    RawInterface, Surface, TableSet, function_list, interface_list, read_fn_pointers, tables_for,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
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
    let before_maps = maps::parse_maps(
        &std::fs::read("/proc/self/maps").map_err(|e| format!("/proc/self/maps: {e}"))?,
    )?;
    let before_keys: BTreeSet<ObjectKey> = before_maps.iter().map(ObjectKey::of).collect();

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

    let maps_bytes =
        std::fs::read("/proc/self/maps").map_err(|e| format!("/proc/self/maps: {e}"))?;
    let maps = maps::parse_maps(&maps_bytes)?;
    let module_map_key = loaded_module_key(raw_exports, &maps, module_file_key, &module_identity)?;
    let mut approved_keys: BTreeSet<ObjectKey> = maps
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
        get_function_list: module_export(raw_exports.get_function_list, &maps, module_map_key),
        get_interface_list: module_export(raw_exports.get_interface_list, &maps, module_map_key),
        get_interface: module_export(raw_exports.get_interface, &maps, module_map_key),
    };
    let mut objects = ObjectTable::new(
        module_path.to_path_buf(),
        module_map_key,
        module_identity,
        approved_keys,
    );

    let (legacy, legacy_240) = legacy_surface(
        legacy_acquisition,
        raw_exports.get_function_list,
        exports.get_function_list,
        &memory,
        &maps,
        &mut objects,
    );
    let (interface_list, interface_surfaces, vendor_interfaces) = interface_records(
        interfaces_acquisition,
        raw_exports.get_interface_list,
        exports,
        legacy_240.as_deref(),
        &memory,
        &maps,
        &mut objects,
    );

    let mut surfaces = vec![legacy];
    surfaces.extend(interface_surfaces);
    let alias_groups = alias_groups(&surfaces);
    let provenance_objects = provenance_objects(&maps)?;

    Ok(Manifest {
        schema: SCHEMA.to_string(),
        module_path: module_path_text.to_string(),
        objects: objects.into_records(),
        provenance_objects,
        interface_list,
        surfaces,
        vendor_interfaces,
        alias_groups,
    })
}

fn provenance_objects(mappings: &[maps::MapEntry]) -> Result<Vec<ProvenanceObject>, String> {
    let mut by_key: BTreeMap<ObjectKey, ProvenanceObject> = BTreeMap::new();
    let mut opened_paths = BTreeMap::new();
    let mut total_bytes = 0u64;

    for mapping in mappings
        .iter()
        .filter(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
    {
        let raw_path = mapping
            .raw_path
            .as_deref()
            .ok_or_else(|| "file-backed executable mapping has no pathname".to_string())?;
        let path = match maps::resolve(mappings, mapping.start) {
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
    maps: &[maps::MapEntry],
    module_key: ObjectKey,
) -> Option<usize> {
    address.filter(|address| match maps::resolve(maps, *address as u64) {
        maps::Resolved::File { device, inode, .. } => ObjectKey { device, inode } == module_key,
        _ => false,
    })
}

fn loaded_module_key(
    exports: ExportAddresses,
    maps: &[maps::MapEntry],
    module_file_key: ObjectKey,
    module_identity: &ObjectIdentity,
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
        } = maps::resolve(maps, address as u64)
        {
            if (ObjectKey { device, inode }) == module_file_key {
                if let MappedPath::Usable(path) = path {
                    // When the kernel-reported path is reachable, require the
                    // same exact fd identity and whole-file identity too.
                    if std::fs::metadata(&path).is_ok()
                        && validated_identity(&path, module_file_key).as_ref()
                            != Ok(module_identity)
                    {
                        continue;
                    }
                }
                return Ok(ObjectKey { device, inode });
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
    let file = identity::open_object(path)
        .map_err(|e| format!("cannot open {} for reuse: {e}", path.display()))?;
    validated_file_identity(path, &file, expected)
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
    let actual = file_key(file)?;
    if actual != expected {
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
    maps: &[maps::MapEntry],
    objects: &mut ObjectTable,
) -> (SurfaceRecord, Option<Vec<usize>>) {
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
    )
}

fn interface_records(
    acquisition: Result<Option<Vec<RawInterface>>, String>,
    raw_export: Option<usize>,
    exports: ExportAddresses,
    legacy_240: Option<&[usize]>,
    memory: &ProcessMemory,
    maps: &[maps::MapEntry],
    objects: &mut ObjectTable,
) -> (Acquisition, Vec<SurfaceRecord>, Vec<VendorInterface>) {
    if raw_export.is_some() && exports.get_interface_list.is_none() {
        return (
            Acquisition::Error {
                detail: "C_GetInterfaceList resolved outside the requested module".into(),
            },
            vec![],
            vec![],
        );
    }
    let raw = match acquisition {
        Err(detail) => return (Acquisition::Error { detail }, vec![], vec![]),
        Ok(None) => return (Acquisition::Absent, vec![], vec![]),
        Ok(Some(entries)) if entries.is_empty() => {
            return (Acquisition::Empty, vec![], vec![]);
        }
        Ok(Some(entries)) => entries,
    };

    let mut surfaces = Vec::new();
    let mut vendor = Vec::new();
    for (index, entry) in raw.into_iter().enumerate() {
        let name = read_name(memory, entry.name_ptr as usize);
        let exact = name.raw.as_deref() == Some(b"PKCS 11".as_slice()) && name.error.is_none();
        let version = read_version(memory, entry.func_list as usize);

        if exact {
            surfaces.push(interface_surface(
                index,
                &entry,
                name,
                version,
                InterfaceClassification::ExactStandard,
                false,
                memory,
                maps,
                objects,
            ));
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
                surfaces.push(interface_surface_from_snapshot(
                    index,
                    &entry,
                    name,
                    version_value,
                    InterfaceClassification::CorroboratedStandardPrefix,
                    snapshot,
                    true,
                    maps,
                    objects,
                ));
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
    (Acquisition::Ok, surfaces, vendor)
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
    maps: &[maps::MapEntry],
    objects: &mut ObjectTable,
) -> SurfaceRecord {
    let Ok(version) = version else {
        return SurfaceRecord {
            source: interface_source(index, entry.flags, name, classification),
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
    maps: &[maps::MapEntry],
    objects: &mut ObjectTable,
) -> SurfaceRecord {
    let walk = if force_prefix && matches!(&snapshot.walk, WalkOutcome::Full) {
        WalkOutcome::KnownPrefix
    } else {
        snapshot.walk
    };
    SurfaceRecord {
        source: interface_source(index, entry.flags, name, classification),
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
        flags: entry.flags,
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
    maps: &[maps::MapEntry],
    objects: &mut ObjectTable,
) -> Vec<FunctionRecord> {
    values
        .into_iter()
        .map(|(name, value)| FunctionRecord {
            name: name.to_string(),
            resolution: if value == 0 {
                Resolution::NullPointer
            } else {
                match maps::resolve(maps, value as u64) {
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
