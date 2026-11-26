//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
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
use pkcs11_module::{RawInterface, Surface, TableSet, function_list, interface_list, tables_for};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::raw::c_void;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const INTERFACE_NAME_CAP: usize = 64;
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

/// Upper bound on provider-directory siblings preloaded for one discovery.
/// The Firefox snap needs five; the bound keeps a hostile DT_NEEDED closure
/// finite. Past it the fallback gives up and the original loader diagnosis
/// stands.
const MAX_SIBLING_PRELOADS: usize = 64;

/// A DT_NEEDED name the sibling fallback may resolve: a bare file name with
/// no path separator, so the candidate can only name the provider's own
/// directory. Names with a separator (absolute or relative paths the loader
/// resolves itself), `.`/`..` and empty names are never preloaded.
fn is_bare_library_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

/// Whether the sibling fallback may `dlopen` `candidate`: a regular file
/// beside the provider, or a symlink whose fully-resolved target is a
/// regular file staying inside the provider's canonical directory
/// (SONAME links like `libfoo.so.1 -> libfoo.so.1.2.3`). Anything else —
/// directories, outside links, unresolvable names — stays for the normal
/// loader search. A swap between this check and the load is outside the
/// model: a writer in the provider's own directory already owns it.
fn sibling_is_usable(dir_canonical: Option<&Path>, candidate: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(candidate) else {
        return false;
    };
    if meta.is_file() {
        return true;
    }
    if !meta.file_type().is_symlink() {
        return false;
    }
    let Some(dir) = dir_canonical else {
        return false;
    };
    std::fs::canonicalize(candidate).is_ok_and(|target| target.starts_with(dir) && target.is_file())
}

/// Preload this provider's own-directory dependencies: for every DT_NEEDED
/// bare name — transitively, the provider's needs plus every discovered
/// sibling's needs, whether or not that sibling loaded yet — `dlopen` the
/// same-directory file by absolute path, keeping each handle alive in the
/// returned vector. Loads retry to a fixpoint after every success, so
/// dependency order never matters (P → A → B loads B, then A on retry,
/// then the provider retry). Only regular files and in-directory symlinks
/// resolving inside the directory are loaded (see `sibling_is_usable`);
/// directories, outside links and anything else are skipped, and names
/// absent from the directory stay for the normal loader search. No
/// environment is read or set: the loader environment stays sanitized. One
/// unloadable file never aborts the whole fallback: an open, parse, or
/// `dlopen` failure skips that sibling (its own needs are still parsed, so
/// a dependency it names can load first), while a genuinely missing library
/// still fails the retry with an accurate diagnosis. Only the preload cap
/// below aborts the fallback; the caller then keeps the original loader
/// diagnosis.
fn preload_sibling_dependencies(module_path: &Path) -> Result<Vec<Library>, String> {
    let dir = module_path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or_else(|| "--module names no directory".to_string())?;
    let dir_canonical = std::fs::canonicalize(dir).ok();
    let mut preloads = Vec::new();
    // Needs are parsed once per file; loads retry until a full round
    // loads nothing new.
    let mut parsed: BTreeSet<PathBuf> = BTreeSet::new();
    let mut loaded: BTreeSet<PathBuf> = BTreeSet::new();
    let mut failed: BTreeSet<PathBuf> = BTreeSet::new();
    let mut to_parse = vec![module_path.to_path_buf()];
    loop {
        while let Some(next) = to_parse.pop() {
            if !parsed.insert(next.clone()) {
                continue;
            }
            let Ok(file) = std::fs::File::open(&next) else {
                continue;
            };
            let Ok(needed) = p11scope_manifest::elf::needed_libraries(&file) else {
                continue;
            };
            for name in needed {
                if !is_bare_library_name(&name) {
                    continue;
                }
                let candidate = dir.join(&name);
                if candidate == *module_path || loaded.contains(&candidate) {
                    continue;
                }
                if !sibling_is_usable(dir_canonical.as_deref(), &candidate) {
                    continue;
                }
                failed.insert(candidate.clone());
                to_parse.push(candidate);
            }
        }
        // Retry every failure: a sibling unloadable for a missing
        // same-directory dependency may load now that its dependency did.
        // Each round that continues loads at least one new sibling, and
        // loads are capped below, so this terminates.
        let mut progress = false;
        let retry: Vec<PathBuf> = failed.iter().cloned().collect();
        failed.clear();
        for candidate in retry {
            if preloads.len() >= MAX_SIBLING_PRELOADS {
                return Err(format!(
                    "provider directory holds more than {MAX_SIBLING_PRELOADS} needed siblings"
                ));
            }
            match unsafe { Library::new(&candidate) } {
                Ok(sibling) => {
                    preloads.push(sibling);
                    loaded.insert(candidate);
                    progress = true;
                }
                Err(_) => {
                    failed.insert(candidate);
                }
            }
        }
        if !progress {
            break;
        }
    }
    Ok(preloads)
}

/// `dlopen` the provider, resolving its own-directory siblings on failure.
/// The first attempt is exactly today's load: when every dependency
/// resolves through the normal search, nothing else runs and no behavior
/// changes. Only when that fails, the sibling fallback preloads validated
/// same-directory dependencies (see `preload_sibling_dependencies`) and
/// retries once. With no usable sibling the original loader diagnosis is
/// returned unchanged; after a retry the retry's diagnosis names what is
/// still missing. Returned sibling handles must stay alive while `lib` is
/// used.
fn dlopen_with_sibling_fallback(module_path: &Path) -> Result<(Library, Vec<Library>), String> {
    match unsafe { Library::new(module_path) } {
        Ok(lib) => Ok((lib, Vec::new())),
        Err(first) => {
            let first = format!("cannot dlopen {}: {first}", module_path.display());
            let preloads = match preload_sibling_dependencies(module_path) {
                Ok(preloads) if !preloads.is_empty() => preloads,
                _ => return Err(first),
            };
            match unsafe { Library::new(module_path) } {
                Ok(lib) => Ok((lib, preloads)),
                Err(retry) => Err(format!("cannot dlopen {}: {retry}", module_path.display())),
            }
        }
    }
}

/// Discover with a retained descriptor for the helper's post-exec address
/// space. The helper hardens itself before releasing the provider-load barrier.
pub fn discover_with_self_memory(
    module_path: &Path,
    self_memory: File,
) -> Result<Manifest, String> {
    discover_with_budget(module_path, self_memory, Rc::new(IdentifyBudget::default()))
}

/// Discovery-wide identify budget: each distinct object's bytes are
/// charged once, on first identification; rechecks of an already
/// charged key stream without a debit. Rechecks are bounded by the
/// fixed pipeline below (initial, loaded-key, revalidation, twenty
/// selection snapshots, final, required provenance), so the total
/// stays bounded while no file is ever refused for its own size.
/// Shared (not threaded) so cloned candidate tables still charge the
/// bytes they read.
#[derive(Debug, Default)]
struct IdentifyBudget {
    spent: Cell<u64>,
    charged: RefCell<BTreeSet<ObjectKey>>,
}

impl IdentifyBudget {
    /// False while `key` never contributed a byte. Single-threaded use
    /// only: each call borrows briefly and never nests.
    fn is_charged(&self, key: &ObjectKey) -> bool {
        self.charged.borrow().contains(key)
    }

    /// A budget with no allowance left, for tests that must fail closed.
    #[cfg(test)]
    fn exhausted_for_test() -> Self {
        Self {
            spent: Cell::new(MAX_TOTAL_OBJECT_BYTES),
            charged: RefCell::new(BTreeSet::new()),
        }
    }
}

/// [`discover_with_self_memory`] with an injected identify budget: every
/// identify read in the pipeline debits `identify_spent`, shared by the
/// module, every dependency, the selection revalidations and the
/// provenance loop. The budget is observable after the call, which is
/// what proves the production pipeline uses one counter.
fn discover_with_budget(
    module_path: &Path,
    self_memory: File,
    identify_spent: Rc<IdentifyBudget>,
) -> Result<Manifest, String> {
    if !module_path.is_absolute() {
        return Err("--module must be an absolute path".into());
    }
    let module_path_text = module_path
        .to_str()
        .ok_or_else(|| "--module path must be valid UTF-8 for the manifest".to_string())?;
    let memory = ProcessMemory(self_memory);
    let (module_file_key, module_identity) = identity_and_key(module_path, &identify_spent)?;
    let before_maps = read_self_maps()?;
    let before_index = validated_map_index(&before_maps)?;
    let before_keys: BTreeSet<ObjectKey> =
        before_index.entries().iter().map(ObjectKey::of).collect();

    // Sibling handles stay alive for the whole discovery: dropping one
    // would unload a library the provider is bound to.
    let (lib, _sibling_preloads) = dlopen_with_sibling_fallback(module_path)?;
    let raw_exports = ExportAddresses {
        get_function_list: symbol_address(&lib, b"C_GetFunctionList\0"),
        get_interface_list: symbol_address(&lib, b"C_GetInterfaceList\0"),
        get_interface: symbol_address(&lib, b"C_GetInterface\0"),
    };

    // Acquisition can lazily load dependencies, so both calls precede maps.
    // The interface enumeration mints before the legacy table: stub-pool
    // providers (p11-kit proxy/client) hand every getter call a heap table
    // with fresh stub addresses from one shared pool, and a workload's
    // first C_GetInterface call uses pool mint 0. Minting legacy first
    // would spend mint 0 on the 68-slot table, leaving the first-mint v3
    // slots (C_GetInterfaceList/C_GetInterface) unrecorded and their
    // calls unattached. Static providers return the same tables whatever
    // the order, so their manifests are unchanged.
    let interfaces_acquisition = interface_list(&lib);
    let legacy_acquisition = raw_exports.get_function_list.map(|_| function_list(&lib));

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
        &identify_spent,
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
    let current_identity = validated_identity(module_path, module_file_key, &identify_spent)?;
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
        Rc::clone(&identify_spent),
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
        module_map_key,
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
        module_map_key,
        &module_identity,
        &mut objects,
        &identify_spent,
        &|| std::fs::read("/proc/self/maps"),
    );
    let selection_evidence = selection_records(selection_raw, &surfaces);
    let alias_groups = alias_groups(&surfaces);
    let final_maps = read_self_maps()?;
    let final_map_index = validated_map_index(&final_maps)?;
    let (final_file_key, final_identity) = identity_and_key(module_path, &identify_spent)?;
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
    let provenance_objects = provenance_objects(&final_map_index, &objects, &identify_spent)?;

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
        getters: Vec::new(),
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

/// Provider and resolved-target provenance is required. Other executable
/// mappings are useful context, retained best effort within the same bounds.
fn provenance_objects(
    index: &maps::MapIndex<'_>,
    objects: &ObjectTable,
    identify_spent: &IdentifyBudget,
) -> Result<Vec<ProvenanceObject>, String> {
    const MAX_OPTIONAL_DIAGNOSTICS: u64 = 8;
    const MAX_DIAGNOSTIC_CHARS: usize = 256;
    let mut required = BTreeMap::new();
    for (key, id) in &objects.ids {
        let record = objects
            .records
            .get(*id as usize)
            .filter(|record| record.id == *id)
            .ok_or_else(|| "resolved object has no identity record".to_string())?;
        required.insert(*key, &record.identity);
    }
    let mut by_key: BTreeMap<ObjectKey, ProvenanceObject> = BTreeMap::new();
    let mut opened_paths = BTreeMap::new();
    let mut omitted = 0u64;

    // Optional runtime mappings cannot consume the object/byte budget before
    // the provider and every individually resolved target have been checked.
    for required_pass in [true, false] {
        for mapping in index.entries().iter().filter(|mapping| {
            mapping.permissions[2] == b'x'
                && mapping.inode != 0
                && required.contains_key(&ObjectKey::of(mapping)) == required_pass
        }) {
            let result = (|| -> Result<(), String> {
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
                    return Ok(());
                }
                if !by_key.contains_key(&key) && by_key.len() >= MAX_OBJECTS {
                    return Err(format!(
                        "executable provenance object cap {MAX_OBJECTS} reached"
                    ));
                }
                let file = identity::open_object(&path).map_err(|error| {
                    format!("cannot open executable mapping {}: {error}", path.display())
                })?;
                // The discovery-wide byte allowance debits what identify
                // reads actually move (cumulative in `identify_spent`,
                // shared with the module, dependency and revalidation
                // reads; a failed inspection keeps its partial debit),
                // so best effort stays bounded without refusing any
                // object for its own size.
                let object_identity =
                    validated_provenance_identity(&path, &file, key, identify_spent)?;
                if required
                    .get(&key)
                    .is_some_and(|expected| **expected != object_identity)
                {
                    return Err(format!(
                        "required executable provenance identity changed for {}",
                        path.display()
                    ));
                }
                if let Some(previous) = by_key.get(&key) {
                    if previous.identity != object_identity {
                        return Err(format!(
                            "executable mapping aliases for {key:?} disagree on whole-file identity"
                        ));
                    }
                    return Ok(());
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
                Ok(())
            })();
            if let Err(error) = result {
                if required_pass {
                    return Err(error);
                }
                omitted = omitted.saturating_add(1);
                if omitted <= MAX_OPTIONAL_DIAGNOSTICS {
                    let detail: String = error.chars().take(MAX_DIAGNOSTIC_CHARS).collect();
                    eprintln!(
                        "p11scope-discover: optional executable provenance omitted: {detail}"
                    );
                }
            }
        }
        if required_pass && required.keys().any(|key| !by_key.contains_key(key)) {
            return Err("required executable provenance has no validated mapping".into());
        }
    }
    if omitted > MAX_OPTIONAL_DIAGNOSTICS {
        eprintln!(
            "p11scope-discover: optional executable provenance: {} further omissions",
            omitted - MAX_OPTIONAL_DIAGNOSTICS
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
    identify_spent: &IdentifyBudget,
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
        identify_spent,
    )
}

#[allow(clippy::too_many_arguments)]
fn loaded_module_key_with_probe(
    exports: ExportAddresses,
    maps: &maps::MapIndex<'_>,
    module_file_key: ObjectKey,
    module_identity: &ObjectIdentity,
    module_file: &File,
    probe: &impl SelfMappingProbe,
    budget: &mut dyn ProbeBudget,
    identify_spent: &IdentifyBudget,
) -> Result<ObjectKey, String> {
    for address in [
        exports.get_function_list,
        exports.get_interface_list,
        exports.get_interface,
    ]
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
                        && validated_identity_with_probe(
                            &path,
                            module_file_key,
                            probe,
                            budget,
                            identify_spent,
                        )
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

fn validated_identity(
    path: &Path,
    expected: ObjectKey,
    identify_spent: &IdentifyBudget,
) -> Result<ObjectIdentity, String> {
    let mut budget = UnboundedProbeBudget;
    validated_identity_with_probe(
        path,
        expected,
        &KernelSelfMappingProbe,
        &mut budget,
        identify_spent,
    )
}

fn validated_identity_with_probe(
    path: &Path,
    expected: ObjectKey,
    probe: &impl SelfMappingProbe,
    budget: &mut dyn ProbeBudget,
    identify_spent: &IdentifyBudget,
) -> Result<ObjectIdentity, String> {
    let file = identity::open_object(path)
        .map_err(|e| format!("cannot open {} for reuse: {e}", path.display()))?;
    validated_file_identity_with_probe(path, &file, expected, probe, budget, identify_spent)
}

fn identity_and_key(
    path: &Path,
    identify_spent: &IdentifyBudget,
) -> Result<(ObjectKey, ObjectIdentity), String> {
    let file = identity::open_object(path)
        .map_err(|e| format!("cannot open {} for reuse: {e}", path.display()))?;
    let key = file_key(&file)?;
    let identity = validated_file_identity(path, &file, key, identify_spent)?;
    Ok((key, identity))
}

fn validated_file_identity(
    path: &Path,
    file: &File,
    expected: ObjectKey,
    identify_spent: &IdentifyBudget,
) -> Result<ObjectIdentity, String> {
    let mut budget = UnboundedProbeBudget;
    validated_file_identity_with_probe(
        path,
        file,
        expected,
        &KernelSelfMappingProbe,
        &mut budget,
        identify_spent,
    )
}

/// The identify-read wrapper every object read in one discovery goes
/// through for `key`: the key's bytes debit the shared budget on first
/// identification, while rechecks of an already-charged key stream
/// without a debit. Reads fail incrementally once the cumulative
/// allowance is gone. A file is never refused for its own size: what
/// fits is read and hashed, and a failed inspection keeps its partial
/// debit.
fn budgeted_reader_for(
    budget: &IdentifyBudget,
    key: ObjectKey,
) -> impl FnMut(&File, &mut [u8], u64) -> std::io::Result<usize> + '_ {
    // Decided on first read, not at construction: a key counts as
    // charged only once it actually debits a byte, so an exhausted
    // budget keeps refusing a fresh key instead of marking it charged
    // for free rechecks later.
    let mut charging: Option<bool> = None;
    move |file, bytes, offset| {
        let charging = *charging.get_or_insert_with(|| !budget.is_charged(&key));
        if !charging {
            return file.read_at(bytes, offset);
        }
        let left = MAX_TOTAL_OBJECT_BYTES.saturating_sub(budget.spent.get());
        let allowed = left.min(bytes.len() as u64) as usize;
        if allowed == 0 && !bytes.is_empty() {
            return Err(std::io::Error::other(format!(
                "identified objects total more than the {MAX_TOTAL_OBJECT_BYTES}-byte limit"
            )));
        }
        let read = file.read_at(&mut bytes[..allowed], offset)?;
        budget
            .spent
            .set(budget.spent.get().saturating_add(read as u64));
        if read > 0 {
            budget.charged.borrow_mut().insert(key);
        }
        Ok(read)
    }
}

fn validated_file_identity_with_probe(
    path: &Path,
    file: &File,
    expected: ObjectKey,
    probe: &impl SelfMappingProbe,
    budget: &mut dyn ProbeBudget,
    identify_spent: &IdentifyBudget,
) -> Result<ObjectIdentity, String> {
    validated_file_identity_with_probe_and_reader(
        path,
        file,
        expected,
        probe,
        budget,
        budgeted_reader_for(identify_spent, expected),
    )
}

fn validated_file_identity_with_probe_and_reader(
    path: &Path,
    file: &File,
    expected: ObjectKey,
    probe: &impl SelfMappingProbe,
    budget: &mut dyn ProbeBudget,
    reader: impl FnMut(&File, &mut [u8], u64) -> std::io::Result<usize>,
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
    let value = identity::inspect_file_with_reader_exporting(file, reader, &[])
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

/// Provenance-loop identity with the discovery-wide byte allowance
/// enforced incrementally as identify reads stream (never an upfront
/// size refusal). `identify_spent` carries the cumulative hashed bytes.
fn validated_provenance_identity(
    path: &Path,
    file: &File,
    expected: ObjectKey,
    identify_spent: &IdentifyBudget,
) -> Result<ObjectIdentity, String> {
    let mut budget = UnboundedProbeBudget;
    validated_file_identity_with_probe_and_reader(
        path,
        file,
        expected,
        &KernelSelfMappingProbe,
        &mut budget,
        budgeted_reader_for(identify_spent, expected),
    )
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

/// A NUL-terminated name of at most [`INTERFACE_NAME_CAP`] bytes, read only
/// inside the readable provider mapping that contains `address`. A pointer
/// outside a readable mapping, or inside a readable mapping that is not the
/// provider's own, is refused without a read, and a name without an
/// in-mapping NUL is unreadable. The provider key is the validated loaded
/// module key, so a hostile name pointer cannot cause a read from stack,
/// environment or unrelated mappings. Bytes the provider itself placed in
/// its own file mapping, writable segments included, are provider data:
/// the scope rule is where the observer reads, not what the provider wrote.
fn read_name(
    memory: &ProcessMemory,
    maps: &maps::MapIndex<'_>,
    module_key: ObjectKey,
    address: usize,
) -> NameRead {
    if address == 0 {
        return NameRead {
            raw: None,
            lossy: None,
            error: Some("null name pointer".into()),
        };
    }

    let Some(mapping) = maps.containing(address as u64) else {
        return NameRead {
            raw: None,
            lossy: None,
            error: Some("name pointer outside any mapping".into()),
        };
    };
    if mapping.permissions[0] != b'r' {
        return NameRead {
            raw: None,
            lossy: None,
            error: Some("name pointer in a non-readable mapping".into()),
        };
    }
    let provider = match maps.resolve(address as u64) {
        maps::Resolved::File { device, inode, .. } => ObjectKey { device, inode } == module_key,
        _ => false,
    };
    if !provider {
        return NameRead {
            raw: None,
            lossy: None,
            error: Some("name pointer outside the provider mappings".into()),
        };
    }
    let mapping_bytes = mapping.end - address as u64;
    let limit = mapping_bytes.min(INTERFACE_NAME_CAP as u64) as usize;

    let mut raw = Vec::with_capacity(limit);
    while raw.len() < limit {
        let mut chunk = [0u8; 32];
        let want = chunk.len().min(limit - raw.len());
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
                    error: Some("short name pread".into()),
                };
            }
            Ok(read) => read,
            Err(error) => {
                return NameRead {
                    raw: (!raw.is_empty()).then_some(raw),
                    lossy: None,
                    error: Some(format!("name pread failed: {error}")),
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
        raw: (!raw.is_empty()).then_some(raw),
        lossy: None,
        error: Some(if limit < INTERFACE_NAME_CAP {
            "unterminated interface name at readable mapping end".into()
        } else {
            format!("overlong interface name (cap {INTERFACE_NAME_CAP} bytes)")
        }),
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
    let mut values = Vec::new();
    for field in spans.iter().flat_map(|span| span.fields()) {
        // A failed word ends the contiguous inventory. Earlier complete words,
        // including observed NULLs and unusable targets, retain their ordinals.
        let bytes = base
            .checked_add(field.offset)
            .ok_or_else(|| "provider pointer arithmetic overflow".to_string())
            .and_then(|address| memory.read_exact(address, width));
        match bytes {
            Ok(bytes) => {
                let mut raw = [0u8; std::mem::size_of::<usize>()];
                raw.copy_from_slice(&bytes);
                values.push((field.name, usize::from_ne_bytes(raw)));
            }
            Err(_) => {
                // The read error carries the helper's raw address and errno;
                // the diagnostic keeps only fixed text, the failed field and
                // the retained ordinal count, like the selection tables.
                return TableSnapshot {
                    walk: WalkOutcome::Unreadable {
                        detail: format!(
                            "{} unreadable after {} complete function words",
                            field.name,
                            values.len()
                        ),
                    },
                    values,
                };
            }
        }
    }
    TableSnapshot { walk, values }
}

fn inventory_tables(source: Surface) -> TableSet {
    // The typed getter supplies all 68 bounded legacy positions independently
    // of its label. An unrecognized interface label retains this common ABI.
    let TableSet::Walk(spans) = tables_for(Surface::LegacyFunctionList {
        version: cryptoki_sys::CK_VERSION {
            major: 2,
            minor: 40,
        },
    }) else {
        unreachable!("the legacy ABI has a bounded field catalogue");
    };
    match (source, tables_for(source)) {
        (Surface::LegacyFunctionList { .. }, TableSet::Walk(_)) => TableSet::Walk(spans),
        (Surface::LegacyFunctionList { .. }, _) | (_, TableSet::Refuse) => {
            TableSet::WalkKnownPrefix(spans)
        }
        (_, selected) => selected,
    }
}

fn inventory_snapshot(
    memory: &ProcessMemory,
    base: usize,
    source: Result<Surface, &str>,
) -> TableSnapshot {
    match source {
        Ok(source) => snapshot_table(memory, base, inventory_tables(source)),
        Err(_header_error) => {
            // An unavailable header gives no extension evidence, but does not
            // prevent bounded reads of the independently acquired common ABI.
            // The header error carries the helper's raw address; the
            // diagnostic keeps only the fixed prefix, like the selection
            // tables.
            let mut snapshot = snapshot_table(
                memory,
                base,
                inventory_tables(Surface::LegacyFunctionList {
                    version: cryptoki_sys::CK_VERSION {
                        major: 2,
                        minor: 40,
                    },
                }),
            );
            let detail = match &snapshot.walk {
                WalkOutcome::Unreadable { detail } => {
                    format!("version header unreadable: metadata unavailable; functions: {detail}")
                }
                _ => "version header unreadable: metadata unavailable".into(),
            };
            snapshot.walk = WalkOutcome::Unreadable { detail };
            snapshot
        }
    }
}

fn selection_inventory_usable(source: Surface, walk: &WalkOutcome) -> bool {
    // Common-prefix recovery does not widen the fixed selection contract.
    !matches!(tables_for(source), TableSet::Refuse)
        && matches!(walk, WalkOutcome::Full | WalkOutcome::KnownPrefix)
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
    let version = read_version(memory, base);
    let snapshot = inventory_snapshot(
        memory,
        base,
        version
            .as_ref()
            .map(|version| Surface::LegacyFunctionList { version: *version })
            .map_err(String::as_str),
    );
    let legacy_240 = (version
        .as_ref()
        .is_ok_and(|version| version.major == 2 && version.minor == 40)
        && matches!(&snapshot.walk, WalkOutcome::Full)
        && snapshot.values.len() == 68)
        .then(|| snapshot.values.iter().map(|(_, value)| *value).collect());
    let inventory_pointer = version
        .as_ref()
        .is_ok_and(|version| {
            selection_inventory_usable(
                Surface::LegacyFunctionList { version: *version },
                &snapshot.walk,
            )
        })
        .then_some(base);
    let functions = resolve_values(snapshot.values, maps, objects);
    (
        SurfaceRecord {
            source,
            acquisition: Acquisition::Ok,
            version: version.ok().map(manifest_version),
            walk: snapshot.walk,
            functions,
        },
        legacy_240,
        inventory_pointer,
    )
}

#[allow(clippy::too_many_arguments)]
fn interface_records(
    acquisition: Result<Option<Vec<RawInterface>>, String>,
    raw_export: Option<usize>,
    exports: ExportAddresses,
    legacy_240: Option<&[usize]>,
    memory: &ProcessMemory,
    maps: &maps::MapIndex<'_>,
    module_key: ObjectKey,
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
        let name = read_name(memory, maps, module_key, entry.name_ptr as usize);
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
                surface
                    .version
                    .is_some_and(|version| {
                        selection_inventory_usable(
                            Surface::StandardInterface {
                                version: cryptoki_sys::CK_VERSION {
                                    major: version.major,
                                    minor: version.minor,
                                },
                            },
                            &surface.walk,
                        )
                    })
                    .then_some(entry.func_list as usize),
            );
            surfaces.push(surface);
            continue;
        }

        if let Ok(version_value) = version {
            let snapshot = snapshot_table(
                memory,
                entry.func_list as usize,
                inventory_tables(Surface::StandardInterface {
                    version: version_value,
                }),
            );
            if corroborates_standard(version_value, &snapshot, exports, legacy_240) {
                let surface = interface_surface_from_snapshot(
                    index,
                    &entry,
                    name,
                    Some(version_value),
                    InterfaceClassification::CorroboratedStandardPrefix,
                    snapshot,
                    true,
                    maps,
                    objects,
                );
                table_ptrs.push(
                    selection_inventory_usable(
                        Surface::StandardInterface {
                            version: version_value,
                        },
                        &surface.walk,
                    )
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
            // The read failure carries the helper's raw address; the
            // manifest keeps fixed text, branched on the null pointer
            // (already recorded in `func_list_null`), never on the
            // error string.
            let version_error = if entry.func_list.is_null() {
                "null function-list pointer"
            } else {
                "function-list version header unreadable"
            };
            vendor.push(vendor_interface(
                index,
                &entry,
                name,
                None,
                Some(version_error.to_string()),
            ));
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
enum TableOrigin {
    File { object: ObjectKey, file_offset: u64 },
    // Used only within this helper invocation; never serialized.
    ProcessLocal(usize),
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

fn selection_table_incomplete(table: &SelectionTable, metadata_uncertain: bool) -> bool {
    let expected = match inventory_tables(Surface::StandardInterface {
        version: cryptoki_sys::CK_VERSION {
            major: table.version.major,
            minor: table.version.minor,
        },
    }) {
        TableSet::Walk(spans) | TableSet::WalkKnownPrefix(spans) => {
            spans.iter().map(|span| span.fields().len()).sum()
        }
        TableSet::Refuse => unreachable!("inventory always retains the common ABI"),
    };
    table.functions.len() != expected
        || (matches!(table.walk, WalkOutcome::Unreadable { .. }) && !metadata_uncertain)
        || table.functions.iter().any(|function| {
            !matches!(
                function.resolution,
                Resolution::Resolved { .. } | Resolution::NullPointer
            )
        })
}

fn confirm_selection_snapshot(
    memory: &ProcessMemory,
    pointer: usize,
    snapshot: &TableSnapshot,
    version: Option<(u8, u8)>,
) -> Result<Option<String>, SelectionFailure> {
    let width = std::mem::size_of::<usize>();
    let start = pointer
        .checked_add(pkcs11_module::FUNCTION_LIST_FIELDS[0].offset)
        .ok_or(SelectionFailure::ProviderChanged)?;
    let bytes = snapshot
        .values
        .len()
        .checked_mul(width)
        .and_then(|length| memory.read_exact(start, length).ok())
        .ok_or(SelectionFailure::ProviderChanged)?;
    if !bytes
        .chunks_exact(width)
        .zip(&snapshot.values)
        .all(|(word, (_, expected))| usize::from_ne_bytes(word.try_into().unwrap()) == *expected)
    {
        return Err(SelectionFailure::ProviderChanged);
    }
    let confirmed_version = read_version(memory, pointer)
        .ok()
        .map(|version| (version.major, version.minor));
    Ok((confirmed_version != version).then(|| {
        format!(
            "version metadata changed: {} complete function words retained",
            snapshot.values.len()
        )
    }))
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
    module_key: ObjectKey,
    module_identity: &ObjectIdentity,
    objects: &mut ObjectTable,
    identify_spent: &IdentifyBudget,
    read_maps: &impl Fn() -> std::io::Result<Vec<u8>>,
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
                let mut candidate_objects = objects.clone();
                let bracket = selection_bracket(
                    || {
                        stable_selection_maps(
                            module_path,
                            module_file_key,
                            module_identity,
                            identify_spent,
                            read_maps,
                        )
                    },
                    |maps_a| {
                        let (name_pointer, table_pointer, returned_flags) =
                            read_interface(memory, output as usize)
                                .map_err(|_| SelectionFailure::UnreadableInterface)?;
                        let inventory_matches =
                            selection_inventory_indices(inventory_tables, table_pointer);
                        let name = read_name(memory, maps_a, module_key, name_pointer);
                        let version_read = read_version(memory, table_pointer);
                        let name_class = selection_name_class(&name, name_pointer);
                        let mut version_class =
                            selection_version_class(&version_read, table_pointer);
                        let source = version_read
                            .as_ref()
                            .map(|version| Surface::StandardInterface { version: *version })
                            .map_err(String::as_str);
                        let table_snapshot = (table_pointer != 0)
                            .then(|| inventory_snapshot(memory, table_pointer, source));
                        let mut helper_failure = if table_pointer == 0 {
                            Some(SelectionFailure::UnreadableTable)
                        } else if version_read.is_err() {
                            Some(SelectionFailure::UnreadableVersion)
                        } else if name_pointer == 0 || name.error.is_some() {
                            Some(SelectionFailure::UnreadableName)
                        } else if table_snapshot.as_ref().is_some_and(|snapshot| {
                            matches!(snapshot.walk, WalkOutcome::Unreadable { .. })
                        }) {
                            Some(SelectionFailure::UnreadableTable)
                        } else {
                            None
                        };
                        let mut selection_table = None;
                        if inventory_matches.is_empty()
                            && let Some(snapshot) = &table_snapshot
                        {
                            let (table, origin) = selection_table_for(
                                table_pointer,
                                version_read
                                    .as_ref()
                                    .ok()
                                    .map_or(Version { major: 0, minor: 0 }, |version| {
                                        manifest_version(*version)
                                    }),
                                snapshot,
                                maps_a,
                                &mut candidate_objects,
                            );
                            if helper_failure.is_none()
                                && selection_table_incomplete(&table, version_read.is_err())
                            {
                                helper_failure = Some(SelectionFailure::UnresolvedFunction);
                            }
                            selection_table = Some((table, origin));
                        }
                        // Compare every captured word, including invalid targets,
                        // and metadata again before accepting a heap or file view.
                        let confirmed_interface = read_interface(memory, output as usize)
                            .map_err(|_| SelectionFailure::ProviderChanged)?;
                        let confirmed_name = read_name(memory, maps_a, module_key, name_pointer);
                        if confirmed_interface != (name_pointer, table_pointer, returned_flags)
                            || confirmed_name.raw != name.raw
                            || confirmed_name.error != name.error
                        {
                            return Err(SelectionFailure::ProviderChanged);
                        }
                        if let Some(snapshot) = &table_snapshot
                            && let Some(diagnostic) = confirm_selection_snapshot(
                                memory,
                                table_pointer,
                                snapshot,
                                version_read
                                    .as_ref()
                                    .ok()
                                    .map(|version| (version.major, version.minor)),
                            )?
                        {
                            helper_failure = Some(SelectionFailure::UnreadableVersion);
                            if let Some((table, _)) = &mut selection_table {
                                table.walk = WalkOutcome::Unreadable {
                                    detail: match &snapshot.walk {
                                        WalkOutcome::Unreadable { .. } if version_read.is_err() => {
                                            format!(
                                                "version header unreadable: metadata unavailable; {diagnostic}"
                                            )
                                        }
                                        WalkOutcome::Unreadable { .. } => {
                                            format!("{diagnostic}; function tail unavailable")
                                        }
                                        _ => diagnostic,
                                    },
                                };
                            } else {
                                // Ordinary inventory retains its observed version;
                                // the unstable query gets no agreement authority.
                                version_class = SelectionVersionClass::Unreadable;
                                eprintln!("warning: {diagnostic}");
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
                    || {
                        stable_selection_maps(
                            module_path,
                            module_file_key,
                            module_identity,
                            identify_spent,
                            read_maps,
                        )
                    },
                );
                match bracket {
                    Ok(()) => {
                        *objects = candidate_objects;
                        captured
                            .map(|(result, helper_failure)| (Some(result), helper_failure))
                            .unwrap_or((None, Some(SelectionFailure::UnreadableInterface)))
                    }
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

fn selection_table_for(
    pointer: usize,
    version: Version,
    snapshot: &TableSnapshot,
    maps: &maps::MapIndex<'_>,
    objects: &mut ObjectTable,
) -> (SelectionTable, TableOrigin) {
    let origin = match maps.resolve(pointer as u64) {
        maps::Resolved::File {
            device,
            inode,
            file_offset,
            ..
        } => TableOrigin::File {
            object: ObjectKey { device, inode },
            file_offset,
        },
        maps::Resolved::Anonymous | maps::Resolved::Unmapped => TableOrigin::ProcessLocal(pointer),
    };
    let functions = resolve_values(snapshot.values.clone(), maps, objects);
    (
        SelectionTable {
            id: 0,
            version,
            walk: match &snapshot.walk {
                WalkOutcome::Unreadable { detail } => WalkOutcome::Unreadable {
                    detail: if detail.starts_with("version header unreadable:") {
                        format!(
                            "version header unreadable: metadata unavailable; {} complete function words",
                            snapshot.values.len()
                        )
                    } else {
                        format!(
                            "function word {} unreadable after {} complete function words",
                            snapshot.values.len(),
                            snapshot.values.len()
                        )
                    },
                },
                walk => walk.clone(),
            },
            functions,
            semantic_authorized: false,
        },
        origin,
    )
}

fn stable_selection_maps(
    module_path: &Path,
    expected_key: ObjectKey,
    expected_identity: &ObjectIdentity,
    identify_spent: &IdentifyBudget,
    read_maps: &impl Fn() -> std::io::Result<Vec<u8>>,
) -> Result<Vec<maps::MapEntry>, ()> {
    let mut budget = UnboundedProbeBudget;
    // A torn snapshot is read again like every other maps read here,
    // instead of failing the revalidation spuriously.
    let current_maps = read_self_maps_with(read_maps).map_err(|_| ())?;
    stable_selection_maps_with_probe(
        module_path,
        expected_key,
        expected_identity,
        &KernelSelfMappingProbe,
        &mut budget,
        identify_spent,
        current_maps,
    )
}

fn stable_selection_maps_with_probe(
    module_path: &Path,
    expected_key: ObjectKey,
    expected_identity: &ObjectIdentity,
    probe: &impl SelfMappingProbe,
    budget: &mut dyn ProbeBudget,
    identify_spent: &IdentifyBudget,
    current_maps: Vec<maps::MapEntry>,
) -> Result<Vec<maps::MapEntry>, ()> {
    let file = identity::open_object(module_path).map_err(|_| ())?;
    let current_key = file_key(&file).map_err(|_| ())?;
    let current_identity = validated_file_identity_with_probe(
        module_path,
        &file,
        current_key,
        probe,
        budget,
        identify_spent,
    )
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
    let mut pair_tables = BTreeMap::<(SelectionVersionClass, u64), u8>::new();
    let mut table_observations = Vec::<(TableOrigin, SelectionTable)>::new();
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
        if let Some((mut table, origin)) = raw_result.table
            && matches.is_empty()
        {
            selection_truncated |= selection_table_incomplete(
                &table,
                raw.helper_failure == Some(SelectionFailure::UnreadableVersion),
            );
            let pair = (result.version, result.flags);
            let table_id = if let Some((_, known)) =
                table_observations.iter().find(|(known_origin, known)| {
                    *known_origin == origin
                        && known.version == table.version
                        && known.walk == table.walk
                        && known.functions == table.functions
                }) {
                known.id
            } else {
                let table_id = tables.len() as u8;
                table.id = table_id;
                table_observations.push((origin, table.clone()));
                tables.push(table);
                table_id
            };
            if let Some(known_id) = pair_tables.insert(pair, table_id)
                && known_id != table_id
            {
                selection_truncated = true;
            }
            selection_table = Some(table_id);
            authority = SelectionAuthority::SelectionCountOnly;
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
    if entry.func_list.is_null() {
        return SurfaceRecord {
            source: interface_source(index, native_ulong_u64(entry.flags), name, classification),
            acquisition: Acquisition::Ok,
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        };
    }
    let snapshot = inventory_snapshot(
        memory,
        entry.func_list as usize,
        version
            .as_ref()
            .map(|version| Surface::StandardInterface { version: *version })
            .map_err(String::as_str),
    );
    interface_surface_from_snapshot(
        index,
        entry,
        name,
        version.ok(),
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
    version: Option<cryptoki_sys::CK_VERSION>,
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
        version: version.map(manifest_version),
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

#[derive(Clone)]
struct ObjectTable {
    module_key: ObjectKey,
    approved: BTreeSet<ObjectKey>,
    ids: BTreeMap<ObjectKey, u32>,
    records: Vec<ObjectRecord>,
    identify_spent: Rc<IdentifyBudget>,
}

impl ObjectTable {
    fn new(
        module_path: PathBuf,
        module_key: ObjectKey,
        identity: ObjectIdentity,
        approved: BTreeSet<ObjectKey>,
        identify_spent: Rc<IdentifyBudget>,
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
            identify_spent,
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
        let object_identity = match validated_identity(&path, key, &self.identify_spent) {
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

    /// Reads one provider name the way discovery does: against this
    /// process's live maps, scoped to `module_key`.
    fn read_name_at(memory: &ProcessMemory, module_key: ObjectKey, address: usize) -> NameRead {
        let entries = read_self_maps().unwrap();
        let index = validated_map_index(&entries).unwrap();
        read_name(memory, &index, module_key, address)
    }

    const TEST_PROVIDER_KEY: ObjectKey = ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode: 7,
    };

    /// Clone the live mappings containing `addrs`, re-keyed as provider
    /// mappings: the bounds stay exactly what the kernel reported, only
    /// provenance is scripted, so the 64-byte cap and the in-mapping bound
    /// stay testable now that foreign mappings are refused.
    fn provider_view(
        entries: &[maps::MapEntry],
        addrs: &[u64],
        module_key: ObjectKey,
    ) -> Vec<maps::MapEntry> {
        let index = validated_map_index(entries).unwrap();
        let mut view = Vec::new();
        for addr in addrs {
            let containing = index.containing(*addr).expect("test buffer is mapped");
            if view
                .iter()
                .all(|entry: &maps::MapEntry| entry.start != containing.start)
            {
                let mut entry = containing.clone();
                entry.device = module_key.device;
                entry.inode = module_key.inode;
                entry.raw_path = Some(b"/provider.so".to_vec());
                view.push(entry);
            }
        }
        view.sort_by_key(|entry| entry.start);
        view
    }

    #[test]
    fn provider_names_are_read_through_a_bounded_snapshot() {
        let memory = ProcessMemory::open().unwrap();
        let exact = b"PKCS 11\0ignored";
        let overlong = [b'x'; INTERFACE_NAME_CAP];
        let entries = read_self_maps().unwrap();
        let view = provider_view(
            &entries,
            &[exact.as_ptr() as u64, overlong.as_ptr() as u64],
            TEST_PROVIDER_KEY,
        );
        let index = validated_map_index(&view).unwrap();
        let name = read_name(&memory, &index, TEST_PROVIDER_KEY, exact.as_ptr() as usize);
        assert_eq!(name.raw.as_deref(), Some(b"PKCS 11".as_slice()));
        assert_eq!(name.lossy.as_deref(), Some("PKCS 11"));
        assert_eq!(name.error, None);

        let name = read_name(
            &memory,
            &index,
            TEST_PROVIDER_KEY,
            overlong.as_ptr() as usize,
        );
        let expected = format!("overlong interface name (cap {INTERFACE_NAME_CAP} bytes)");
        assert_eq!(name.error.as_deref(), Some(expected.as_str()));
        assert_eq!(name.raw.as_deref(), Some(overlong.as_slice()));

        assert!(memory.read_exact(usize::MAX, 2).is_err());
    }

    #[test]
    fn interface_name_read_stops_at_the_readable_mapping_end() {
        let memory = ProcessMemory::open().unwrap();
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        const PREFIX: &[u8] = b"EDGE!";
        const ADJACENT: &[u8] = b"ADJACENT_SECRET\0";
        let address = unsafe { (base as *mut u8).add(page - PREFIX.len()) };
        let second = unsafe { (base as *mut u8).add(page) };
        unsafe {
            std::ptr::copy_nonoverlapping(PREFIX.as_ptr(), address, PREFIX.len());
            std::ptr::copy_nonoverlapping(ADJACENT.as_ptr(), second, ADJACENT.len());
        }
        assert_eq!(
            unsafe { libc::mprotect(second.cast(), page, libc::PROT_READ) },
            0
        );
        let entries = read_self_maps().unwrap();
        let containing = entries
            .iter()
            .find(|entry| entry.start <= address as u64 && (address as u64) < entry.end)
            .expect("the name pointer is mapped");
        assert_eq!(containing.permissions[0], b'r');
        assert_eq!(containing.end, address as u64 + PREFIX.len() as u64);

        let view = provider_view(&entries, &[address as u64], TEST_PROVIDER_KEY);
        let provider_index = validated_map_index(&view).unwrap();
        let name = read_name(
            &memory,
            &provider_index,
            TEST_PROVIDER_KEY,
            address as usize,
        );
        assert_eq!(unsafe { libc::munmap(base, page * 2) }, 0);

        let error = name.error.as_deref().expect("an in-VMA NUL is required");
        assert_eq!(error, "unterminated interface name at readable mapping end");
        assert!(
            name.raw
                .as_deref()
                .is_none_or(|raw| raw.len() <= PREFIX.len()),
            "the read crossed into the adjacent mapping: {:?}",
            name.raw
        );
    }

    #[test]
    fn name_read_reports_a_short_pread_without_an_address() {
        // A regular file shorter than the read offset answers Ok(0):
        // the helper's address never enters the diagnostic.
        let dir = std::env::temp_dir().join(format!("name-short-pread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("short");
        std::fs::write(&path, b"01234567").unwrap();
        let memory = ProcessMemory(File::open(&path).unwrap());
        let probe = b"unread\0";
        let entries = read_self_maps().unwrap();
        let view = provider_view(&entries, &[probe.as_ptr() as u64], TEST_PROVIDER_KEY);
        let index = validated_map_index(&view).unwrap();
        let name = read_name(&memory, &index, TEST_PROVIDER_KEY, probe.as_ptr() as usize);
        assert!(name.raw.is_none());
        assert!(name.lossy.is_none());
        assert_eq!(name.error.as_deref(), Some("short name pread"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn name_read_reports_a_failed_pread_without_an_address() {
        // A write-only descriptor fails the read: only the fixed prefix
        // plus the OS error are recorded, never the address.
        let dir = std::env::temp_dir().join(format!("name-failed-pread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("write-only");
        std::fs::write(&path, b"01234567").unwrap();
        let memory = ProcessMemory(File::options().write(true).open(&path).unwrap());
        let probe = b"unread\0";
        let entries = read_self_maps().unwrap();
        let view = provider_view(&entries, &[probe.as_ptr() as u64], TEST_PROVIDER_KEY);
        let index = validated_map_index(&view).unwrap();
        let name = read_name(&memory, &index, TEST_PROVIDER_KEY, probe.as_ptr() as usize);
        assert!(name.raw.is_none());
        assert!(name.lossy.is_none());
        let error = name.error.as_deref().expect("a failed read is refused");
        // Exact on this Linux target: any inserted address, before or
        // after the OS error, fails here.
        assert_eq!(error, "name pread failed: Bad file descriptor (os error 9)");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn interface_name_outside_readable_mappings_is_refused() {
        let memory = ProcessMemory::open().unwrap();

        let unmapped = read_name_at(&memory, TEST_PROVIDER_KEY, usize::MAX);
        assert!(unmapped.raw.is_none());
        let error = unmapped
            .error
            .as_deref()
            .expect("an unmapped pointer is refused");
        assert!(error.contains("outside any mapping"), "{error}");

        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        let secret = b"PROTECTED\0";
        unsafe {
            std::ptr::copy_nonoverlapping(secret.as_ptr(), base.cast::<u8>(), secret.len());
        }
        assert_eq!(unsafe { libc::mprotect(base, page, libc::PROT_NONE) }, 0);

        let unreadable = read_name_at(&memory, TEST_PROVIDER_KEY, base as usize);
        assert_eq!(unsafe { libc::munmap(base, page) }, 0);

        assert!(unreadable.raw.is_none());
        let error = unreadable
            .error
            .as_deref()
            .expect("a non-readable mapping is refused");
        assert!(error.contains("non-readable"), "{error}");
    }

    /// One out-of-provider pointer must publish nothing: the address
    /// has to be readable (so the refusal comes from the provider-scope
    /// check, not an earlier arm) and the refusal stays recorded.
    fn assert_name_outside_provider_is_refused(
        memory: &ProcessMemory,
        index: &maps::MapIndex<'_>,
        address: usize,
        label: &str,
    ) {
        let containing = index
            .containing(address as u64)
            .unwrap_or_else(|| panic!("{label}: the probe address must be mapped"));
        assert_eq!(
            containing.permissions[0], b'r',
            "{label}: the probe address must stay readable"
        );
        let name = read_name(memory, index, TEST_PROVIDER_KEY, address);
        assert!(
            name.raw.is_none(),
            "{label}: out-of-provider bytes were published: {name:?}"
        );
        let error = name.error.as_deref().unwrap_or_else(|| {
            panic!("{label}: an out-of-provider pointer needs a recorded refusal: {name:?}")
        });
        assert!(error.contains("provider mappings"), "{label}: {error}");
    }

    #[test]
    fn interface_name_outside_provider_mappings_is_refused() {
        let memory = ProcessMemory::open().unwrap();
        let entries = read_self_maps().unwrap();
        let index = validated_map_index(&entries).unwrap();
        // A hostile provider can point pInterfaceName at any readable
        // mapping; readable with an in-mapping NUL is not enough: only
        // provider bytes may publish. Each buffer below pins a different
        // refusal arm while staying live, readable and NUL-terminated.
        // The .rodata literal is file-backed with the wrong key: the
        // foreign-File arm.
        let rodata_name = b"HOSTILE_RODATA_NAME\0";
        let rodata_addr = rodata_name.as_ptr() as usize;
        let file_key = match index.resolve(rodata_addr as u64) {
            maps::Resolved::File { device, inode, .. } => ObjectKey { device, inode },
            resolved => panic!("the literal must stay file-backed: {resolved:?}"),
        };
        assert_ne!(
            file_key, TEST_PROVIDER_KEY,
            "the literal must keep the wrong key"
        );
        assert_name_outside_provider_is_refused(&memory, &index, rodata_addr, "rodata");
        // Real heap and stack buffers are Anonymous mappings: the
        // stack/environment arm, where heap and environment secrets live
        // (the helper retains its environment).
        let heap_name: Box<[u8]> = b"HOSTILE_HEAP_NAME\0".to_vec().into_boxed_slice();
        let heap_addr = heap_name.as_ptr() as usize;
        assert!(
            matches!(index.resolve(heap_addr as u64), maps::Resolved::Anonymous),
            "the heap buffer must stay anonymous"
        );
        assert_name_outside_provider_is_refused(&memory, &index, heap_addr, "heap");
        let stack_name = *b"HOSTILE_STACK_NAME\0";
        let stack_addr = stack_name.as_ptr() as usize;
        assert!(
            matches!(index.resolve(stack_addr as u64), maps::Resolved::Anonymous),
            "the stack buffer must stay anonymous"
        );
        assert_name_outside_provider_is_refused(&memory, &index, stack_addr, "stack");
    }

    /// A real address-bearing header failure, proving the probes below
    /// strip something genuine rather than passing on an empty echo.
    fn address_bearing_header_error(memory: &ProcessMemory) -> String {
        let header = read_version(memory, 0x1000).unwrap_err();
        assert!(
            header.contains("0x"),
            "the probe needs a real address-bearing failure: {header}"
        );
        header
    }

    fn assert_walk_detail_has_no_address(detail: &str) {
        assert!(
            !detail.contains("0x") && !detail.contains("pread"),
            "walk detail leaks a read address: {detail}"
        );
    }

    #[test]
    fn surface_walk_function_detail_carries_no_address() {
        let memory = ProcessMemory::open().unwrap();
        // An unmapped table base reads like a torn provider table: every
        // word fails. The diagnostic must keep fixed text plus the ordinal
        // count, never the helper's raw pread address.
        let legacy = Surface::LegacyFunctionList {
            version: cryptoki_sys::CK_VERSION {
                major: 2,
                minor: 40,
            },
        };
        let snapshot = snapshot_table(&memory, 0x1000, inventory_tables(legacy));
        assert!(
            snapshot.values.is_empty(),
            "the unmapped base must read nothing"
        );
        let WalkOutcome::Unreadable { detail } = &snapshot.walk else {
            panic!(
                "an unreadable table must stay unreadable: {:?}",
                snapshot.walk
            );
        };
        assert_walk_detail_has_no_address(detail);
    }

    #[test]
    fn surface_walk_header_detail_carries_no_address() {
        let memory = ProcessMemory::open().unwrap();
        // The version-header arm echoes a real header read failure.
        let header = address_bearing_header_error(&memory);
        let snapshot = inventory_snapshot(&memory, 0x1000, Err(header.as_str()));
        let WalkOutcome::Unreadable { detail } = &snapshot.walk else {
            panic!(
                "an unreadable header must stay unreadable: {:?}",
                snapshot.walk
            );
        };
        assert_walk_detail_has_no_address(detail);
    }

    #[test]
    fn walked_table_header_detail_carries_no_address() {
        let memory = ProcessMemory::open().unwrap();
        // A readable table with an unreadable header keeps its words; only
        // the header echo can carry an address.
        let header = address_bearing_header_error(&memory);
        let words = [0usize; 104];
        let snapshot = inventory_snapshot(&memory, words.as_ptr() as usize, Err(header.as_str()));
        assert_eq!(
            snapshot.values.len(),
            68,
            "the legacy walk keeps its complete words"
        );
        let WalkOutcome::Unreadable { detail } = &snapshot.walk else {
            panic!(
                "an unreadable header must stay unreadable: {:?}",
                snapshot.walk
            );
        };
        assert_walk_detail_has_no_address(detail);
    }

    #[test]
    fn interface_name_read_is_capped_at_64_bytes() {
        let memory = ProcessMemory::open().unwrap();
        let overlong = vec![b'x'; 256];
        let entries = read_self_maps().unwrap();
        let view = provider_view(&entries, &[overlong.as_ptr() as u64], TEST_PROVIDER_KEY);
        let index = validated_map_index(&view).unwrap();
        let name = read_name(
            &memory,
            &index,
            TEST_PROVIDER_KEY,
            overlong.as_ptr() as usize,
        );
        assert_eq!(name.raw.as_deref().map(<[u8]>::len), Some(64));
        let error = name
            .error
            .as_deref()
            .expect("a name without a NUL is refused");
        let expected = format!("overlong interface name (cap {INTERFACE_NAME_CAP} bytes)");
        assert_eq!(error, expected.as_str());
    }

    #[test]
    fn mapped_path_identity_requires_device_and_inode() {
        let exe = small_owned_elf();
        let key = identity_and_key(&exe, &IdentifyBudget::default())
            .unwrap()
            .0;
        assert!(
            validated_identity(&exe, key, &IdentifyBudget::default())
                .unwrap()
                .reusable
        );

        let wrong = ObjectKey {
            inode: key.inode.wrapping_add(1),
            ..key
        };
        let err = validated_identity(&exe, wrong, &IdentifyBudget::default()).unwrap_err();
        assert!(err.contains("device/inode mismatch"), "{err}");
    }

    /// A distinct-key copy of the small fixture: same bytes, fresh
    /// inode, so charge-once tests can tell rechecks from new objects.
    fn copied_owned_elf(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "p11scope-discover-copy-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("copy.so");
        std::fs::copy(small_owned_elf(), &path).unwrap();
        path
    }

    #[test]
    fn identify_reads_share_one_cumulative_byte_budget() {
        let exe = small_owned_elf();
        let len = std::fs::metadata(&exe).unwrap().len();
        let other = selection_spend_fixture();
        let other_len = std::fs::metadata(&other).unwrap().len();
        let budget = IdentifyBudget::default();
        let key = identity_and_key(&exe, &budget).unwrap().0;
        assert_eq!(budget.spent.get(), len, "the first read charges its bytes");
        validated_identity(&exe, key, &budget).unwrap();
        assert_eq!(
            budget.spent.get(),
            len,
            "a recheck of a charged key streams free"
        );
        identity_and_key(&other, &budget).unwrap();
        assert_eq!(
            budget.spent.get(),
            len + other_len,
            "a distinct key charges again"
        );
        // Near the cap the next fresh key debits its partial head, then
        // fails: never an upfront size refusal, and a failed inspection
        // keeps its partial debit.
        budget.spent.set(MAX_TOTAL_OBJECT_BYTES - 10);
        let third = copied_owned_elf("identify-third");
        let third_file = identity::open_object(&third).unwrap();
        let third_key = file_key(&third_file).unwrap();
        let error = validated_identity(&third, third_key, &budget).unwrap_err();
        assert_eq!(
            error,
            format!(
                "cannot identify {} for reuse: read failed: identified objects total more than the {MAX_TOTAL_OBJECT_BYTES}-byte limit",
                third.display()
            )
        );
        assert_eq!(
            budget.spent.get(),
            MAX_TOTAL_OBJECT_BYTES,
            "the partial head stays debited"
        );
    }

    #[test]
    fn provenance_reads_share_the_identify_budget() {
        let exe = small_owned_elf();
        let len = std::fs::metadata(&exe).unwrap().len();
        let file = identity::open_object(&exe).unwrap();
        let key = file_key(&file).unwrap();
        let other = copied_owned_elf("prov-other");
        let other_len = std::fs::metadata(&other).unwrap().len();
        let other_file = identity::open_object(&other).unwrap();
        let other_key = file_key(&other_file).unwrap();
        let budget = IdentifyBudget::default();
        validated_identity(&exe, key, &budget).unwrap();
        validated_provenance_identity(&exe, &file, key, &budget).unwrap();
        assert_eq!(
            budget.spent.get(),
            len,
            "a recheck of a charged key streams free"
        );
        validated_provenance_identity(&other, &other_file, other_key, &budget).unwrap();
        assert_eq!(
            budget.spent.get(),
            len + other_len,
            "module and provenance reads share one counter"
        );
        budget.spent.set(MAX_TOTAL_OBJECT_BYTES - 10);
        let third = copied_owned_elf("prov-third");
        let third_file = identity::open_object(&third).unwrap();
        let third_key = file_key(&third_file).unwrap();
        let error =
            validated_provenance_identity(&third, &third_file, third_key, &budget).unwrap_err();
        assert_eq!(
            error,
            format!(
                "cannot identify {} for reuse: read failed: identified objects total more than the {MAX_TOTAL_OBJECT_BYTES}-byte limit",
                third.display()
            )
        );
        assert_eq!(budget.spent.get(), MAX_TOTAL_OBJECT_BYTES);
    }

    /// One synthetic maps line carrying `key`, for tests that must not
    /// depend on a live (tearing) maps read. Addresses are fixed: only
    /// device/inode feed the key under test.
    fn scripted_maps_bytes(key: &ObjectKey) -> Vec<u8> {
        format!(
            "10000000-10001000 r-xp 00000000 {:02x}:{:02x} {} /synthetic/probe-target\n",
            key.device.major, key.device.minor, key.inode
        )
        .into_bytes()
    }

    /// A minimal provider whose C_GetInterface answers CKR_OK with a
    /// garbage table pointer: every selection query runs both maps
    /// snapshots, then fails reading the interface. Shape-only; the
    /// table is never walked.
    fn selection_spend_fixture() -> PathBuf {
        static FIXTURE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        FIXTURE
            .get_or_init(|| {
                let dir = std::env::temp_dir().join(format!(
                    "p11scope-discover-spend-{}",
                    std::process::id()
                ));
                std::fs::create_dir_all(&dir).unwrap();
                let source = dir.join("selection-spend.c");
                let path = dir.join("selection-spend.so");
                std::fs::write(
                    &source,
                    "typedef unsigned long CK_RV;\n\
                     typedef unsigned long CK_FLAGS;\n\
                     CK_RV C_GetInterface(void *name, void *version, void **output, CK_FLAGS flags) {\n\
                         (void)name; (void)version; (void)flags;\n\
                         *output = (void *)0x12345;\n\
                         return 0;\n\
                     }\n",
                )
                .unwrap();
                assert!(
                    std::process::Command::new("gcc")
                        .args(["-shared", "-fPIC", "-o"])
                        .arg(&path)
                        .arg(&source)
                        .status()
                        .unwrap()
                        .success(),
                    "the selection-spend fixture must compile"
                );
                path
            })
            .clone()
    }

    /// Selection snapshots share the budget: one selection run over the
    /// garbage-output fixture charges exactly one module read however
    /// many snapshots recheck it. Per-closure counter threading is
    /// pinned by the wiring shape test below: spend alone cannot
    /// attribute free rechecks. The snapshots parse scripted maps
    /// bytes, so no live (tearing) read can skip a debit: single
    /// attempt.
    #[test]
    fn selection_snapshots_charge_the_shared_identify_budget() {
        let provider = selection_spend_fixture();
        let lib = unsafe { Library::new(&provider) }.unwrap();
        let memory = ProcessMemory::open().unwrap();
        let len = std::fs::metadata(&provider).unwrap().len();
        let module_file = identity::open_object(&provider).unwrap();
        let module_file_key = file_key(&module_file).unwrap();
        let module_identity = identity_and_key(&provider, &IdentifyBudget::default())
            .unwrap()
            .1;
        let maps_bytes = scripted_maps_bytes(&module_file_key);
        let spent = Rc::new(IdentifyBudget::default());
        let mut objects = ObjectTable::new(
            provider.clone(),
            module_file_key,
            module_identity.clone(),
            BTreeSet::from([module_file_key]),
            Rc::clone(&spent),
        );
        let (acquisition, queries) = selection_acquisition(
            &lib,
            Some(1),
            Some(1),
            &memory,
            &[],
            &provider,
            module_file_key,
            module_file_key,
            &module_identity,
            &mut objects,
            &spent,
            &|| Ok(maps_bytes.clone()),
        );
        assert_eq!(acquisition, SelectionAcquisition::Queried);
        assert_eq!(queries.len(), 10);
        assert_eq!(
            spent.spent.get(),
            len,
            "the first snapshot charges the module; its rechecks stream free"
        );
    }

    /// The production pipeline honors the injected budget end to end: a
    /// fresh counter yields a valid manifest with debited bytes, while an
    /// exhausted counter fails the discovery at the first identify read.
    /// Driven on the selection-spend fixture through `discover_with_budget`.
    #[test]
    fn discovery_pipeline_honors_the_injected_budget() {
        let provider = selection_spend_fixture();
        let open_memory = || ProcessMemory::open().unwrap().0;
        let spent = Rc::new(IdentifyBudget::default());
        let manifest = discover_with_budget(&provider, open_memory(), Rc::clone(&spent)).unwrap();
        assert!(spent.spent.get() > 0, "a discovery debits its budget");
        assert!(
            p11scope_manifest::validate::validate_structure(&manifest).is_empty(),
            "the budgeted discovery stays structurally valid"
        );
        let spent = Rc::new(IdentifyBudget::exhausted_for_test());
        let error = discover_with_budget(&provider, open_memory(), spent).unwrap_err();
        assert_eq!(
            error,
            format!(
                "cannot identify {} for reuse: read failed: identified objects total more than the {MAX_TOTAL_OBJECT_BYTES}-byte limit",
                provider.display()
            )
        );
    }

    /// The public entry delegates to the budgeted pipeline: full
    /// discovery through `discover_with_self_memory` succeeds with a
    /// valid manifest. Behavioral backstop for the wiring pin below: a
    /// deleted delegation panics here instead of passing silently.
    #[test]
    fn public_entry_discovers_through_the_budgeted_pipeline() {
        let provider = selection_spend_fixture();
        let manifest =
            discover_with_self_memory(&provider, ProcessMemory::open().unwrap().0).unwrap();
        assert!(
            p11scope_manifest::validate::validate_structure(&manifest).is_empty(),
            "public-entry discovery stays structurally valid"
        );
    }

    /// Structural pin (not a behavioral guarantee): every production
    /// call edge into the identify machinery spells the shared counter
    /// at its call site, one assertion per edge. The haystack is the
    /// production region of this file only (everything before the test
    /// module), so no assertion can match its own literal: a vacuous
    /// whole-file search would pass even with the wiring deleted.
    /// Behavioral pass/fail cannot attribute edges — every exhausted
    /// read fails identically and the pipeline short-circuits — so the
    /// wiring shape is pinned here while the callees' counter use is
    /// pinned behaviorally by the spend tests above.
    #[test]
    fn discovery_call_edges_pin_the_shared_counter_wiring() {
        let source = include_str!("discover.rs");
        let production = source
            .find("mod tests {")
            .map(|at| &source[..at])
            .expect("test module marker");
        let lines: Vec<&str> = production.lines().collect();
        let window_has_counter = |anchor: &str, window: usize| {
            let at = lines
                .iter()
                .position(|line| line.contains(anchor))
                .unwrap_or_else(|| panic!("edge anchor gone: {anchor}"));
            lines[at..(at + window).min(lines.len())]
                .join("\n")
                .contains("&identify_spent")
        };
        for (edge, anchor, window) in [
            (
                "initial module identity",
                "let (module_file_key, module_identity) = identity_and_key(module_path,",
                3,
            ),
            (
                "loaded module key",
                "let module_map_key = loaded_module_key(",
                9,
            ),
            (
                "module revalidation",
                "let current_identity = validated_identity(module_path, module_file_key,",
                3,
            ),
            ("object table", "let mut objects = ObjectTable::new(", 9),
            (
                "selection acquisition",
                "let selection_raw = selection_acquisition(",
                15,
            ),
            (
                "final module identity",
                "let (final_file_key, final_identity) = identity_and_key(module_path,",
                3,
            ),
            (
                "provenance objects",
                "provenance_objects(&final_map_index,",
                4,
            ),
        ] {
            assert!(
                window_has_counter(anchor, window),
                "{edge} must pass the shared counter"
            );
        }
        let entry_at = lines
            .iter()
            .position(|line| line.contains("pub fn discover_with_self_memory("))
            .expect("public entry anchor");
        assert!(
            lines[entry_at..(entry_at + 8).min(lines.len())]
                .join("\n")
                .contains("discover_with_budget(module_path, self_memory,"),
            "the public entry must delegate to the budgeted pipeline"
        );
        // Both selection snapshot closures forward the shared counter:
        // spend alone cannot attribute free rechecks, so each closure
        // is pinned separately.
        let snapshots: Vec<&str> = production
            .split("|| {\n                        stable_selection_maps(")
            .collect();
        assert_eq!(snapshots.len(), 3, "two snapshot closures expected");
        for (n, tail) in snapshots[1..].iter().enumerate() {
            assert!(
                tail.lines()
                    .take(8)
                    .any(|line| line.contains("identify_spent,")),
                "snapshot closure {} must pass the shared counter",
                n + 1
            );
        }
    }

    /// `ObjectTable::resolve` identifies dependencies against the table's
    /// shared counter, not a fresh one: an exhausted budget turns the
    /// target unusable with the limit reason instead of resolving it.
    #[test]
    fn object_resolve_charges_the_shared_identify_budget() {
        use std::os::unix::ffi::OsStrExt as _;
        let exe = small_owned_elf();
        let len = std::fs::metadata(&exe).unwrap().len();
        let file = identity::open_object(&exe).unwrap();
        let key = file_key(&file).unwrap();
        let module_key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 7,
        };
        assert_ne!(key, module_key);
        let identity = identity_and_key(&exe, &IdentifyBudget::default())
            .unwrap()
            .1;
        let resolve = |spent: Rc<IdentifyBudget>| {
            let mut objects = ObjectTable::new(
                exe.clone(),
                module_key,
                identity.clone(),
                BTreeSet::from([module_key, key]),
                spent,
            );
            objects.resolve(
                MappedPath::Usable(exe.clone()),
                exe.as_os_str().as_bytes().to_vec(),
                0,
                key,
            )
        };
        let spent = Rc::new(IdentifyBudget::default());
        assert_eq!(
            resolve(Rc::clone(&spent)),
            Resolution::Resolved {
                object: 1,
                file_offset: 0
            }
        );
        assert_eq!(spent.spent.get(), len);
        let spent = Rc::new(IdentifyBudget::exhausted_for_test());
        let resolution = resolve(spent);
        let Resolution::UnusableFile { reason, .. } = resolution else {
            panic!("an exhausted budget must not resolve: {resolution:?}");
        };
        assert_eq!(
            reason,
            format!(
                "cannot identify {} for reuse: read failed: identified objects total more than the {MAX_TOTAL_OBJECT_BYTES}-byte limit",
                exe.display()
            )
        );
    }

    /// `stable_selection_maps` revalidates the module against the passed
    /// counter: an exhausted budget refuses the snapshot. Driven on the
    /// owned fixture with scripted maps carrying its key, so no live
    /// (tearing) read stands between the test and the exact debit:
    /// single attempt.
    #[test]
    fn stable_selection_maps_charges_the_shared_identify_budget() {
        let exe = small_owned_elf();
        let len = std::fs::metadata(&exe).unwrap().len();
        let file = identity::open_object(&exe).unwrap();
        let key = file_key(&file).unwrap();
        let identity = identity_and_key(&exe, &IdentifyBudget::default())
            .unwrap()
            .1;
        let maps_bytes = scripted_maps_bytes(&key);
        let spent = IdentifyBudget::default();
        let maps = stable_selection_maps(&exe, key, &identity, &spent, &|| Ok(maps_bytes.clone()))
            .unwrap();
        assert!(!maps.is_empty());
        assert_eq!(spent.spent.get(), len);
        let spent = IdentifyBudget::exhausted_for_test();
        assert!(
            stable_selection_maps(&exe, key, &identity, &spent, &|| Ok(maps_bytes.clone()))
                .is_err()
        );
    }

    /// A torn maps snapshot is read again instead of failing the
    /// revalidation: the first scripted read arrives out of order, the
    /// second carries the key, and the reader runs exactly twice.
    #[test]
    fn stable_selection_maps_retries_a_torn_snapshot() {
        let exe = small_owned_elf();
        let file = identity::open_object(&exe).unwrap();
        let key = file_key(&file).unwrap();
        let identity = identity_and_key(&exe, &IdentifyBudget::default())
            .unwrap()
            .1;
        let valid = scripted_maps_bytes(&key);
        let calls = Cell::new(0u32);
        let maps = stable_selection_maps(&exe, key, &identity, &IdentifyBudget::default(), &|| {
            let n = calls.get();
            calls.set(n + 1);
            Ok(if n == 0 {
                TORN_MAPS.to_vec()
            } else {
                valid.clone()
            })
        })
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert!(!maps.is_empty());
    }

    /// `provenance_objects` debits the passed counter for every mapping
    /// it identifies: with an exhausted budget nothing validates, so the
    /// loop ends with no file-backed executable mappings.
    #[test]
    fn provenance_objects_charges_the_shared_identify_budget() {
        let entries = read_self_maps().unwrap();
        let index = validated_map_index(&entries).unwrap();
        let table = |spent: Rc<IdentifyBudget>| ObjectTable {
            module_key: ObjectKey {
                device: Device { major: 8, minor: 1 },
                inode: 7,
            },
            approved: BTreeSet::new(),
            ids: BTreeMap::new(),
            records: Vec::new(),
            identify_spent: spent,
        };
        let spent = Rc::new(IdentifyBudget::default());
        let objects = provenance_objects(&index, &table(Rc::clone(&spent)), &spent).unwrap();
        assert!(!objects.is_empty());
        assert!(spent.spent.get() > 0, "provenance reads charge the counter");
        let spent = Rc::new(IdentifyBudget::exhausted_for_test());
        let error = provenance_objects(&index, &table(Rc::clone(&spent)), &spent).unwrap_err();
        assert!(
            error.contains("no file-backed executable mappings"),
            "{error}"
        );
        assert_eq!(spent.spent.get(), MAX_TOTAL_OBJECT_BYTES);
    }

    /// `loaded_module_key` rechecks the resolved module against the
    /// passed counter: an exhausted budget skips every export instead of
    /// confirming one. Driven on the dlopened owned fixture at its
    /// exported entry address.
    #[test]
    fn loaded_module_key_recheck_uses_the_shared_budget() {
        let exe = small_owned_elf();
        let lib = unsafe { Library::new(&exe) }.expect("dlopen the owned fixture");
        let entry: libloading::Symbol<unsafe extern "C" fn()> =
            unsafe { lib.get(b"p11scope_discover_small_owned_entry\0") }
                .expect("owned entry symbol");
        let len = std::fs::metadata(&exe).unwrap().len();
        let module_file = identity::open_object(&exe).unwrap();
        let module_file_key = file_key(&module_file).unwrap();
        let module_identity = identity_and_key(&exe, &IdentifyBudget::default())
            .unwrap()
            .1;
        let maps = read_self_maps().unwrap();
        let index = validated_map_index(&maps).unwrap();
        let exports = ExportAddresses {
            get_function_list: Some(*entry as usize),
            get_interface_list: None,
            get_interface: None,
        };
        let mut budget = UnboundedProbeBudget;
        let spent = IdentifyBudget::default();
        let found = loaded_module_key_with_probe(
            exports,
            &index,
            module_file_key,
            &module_identity,
            &module_file,
            &KernelSelfMappingProbe,
            &mut budget,
            &spent,
        )
        .unwrap();
        assert_eq!(found, module_file_key);
        assert_eq!(spent.spent.get(), len);
        let spent = IdentifyBudget::exhausted_for_test();
        let error = loaded_module_key_with_probe(
            exports,
            &index,
            module_file_key,
            &module_identity,
            &module_file,
            &KernelSelfMappingProbe,
            &mut budget,
            &spent,
        )
        .unwrap_err();
        assert!(error.contains("no module acquisition export"), "{error}");
    }

    #[test]
    fn loaded_module_key_reports_invalid_snapshot_before_export_absence() {
        let module_key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 7,
        };
        let module_identity = identity_and_key(&small_owned_elf(), &IdentifyBudget::default())
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
        let module_file = identity::open_object(&small_owned_elf()).unwrap();
        let valid = vec![provider];
        let load = |exports, entries: &[maps::MapEntry]| {
            let index = validated_map_index(entries)?;
            loaded_module_key(
                exports,
                &index,
                module_key,
                &module_identity,
                &module_file,
                &IdentifyBudget::default(),
            )
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
    /// `overlay`/`btrfs` answer the filesystem questions and `key` answers
    /// the kernel-rendered maps key, counting consultations. Real
    /// overlayfs/btrfs splits are unmountable without privileges, so unit
    /// tests script the kernel side.
    struct FakeSelfMappingProbe {
        overlay: bool,
        btrfs: bool,
        key: Option<ObjectKey>,
        overlay_checks: std::cell::Cell<usize>,
        btrfs_checks: std::cell::Cell<usize>,
        probes: std::cell::Cell<usize>,
    }

    impl FakeSelfMappingProbe {
        fn new(overlay: bool, key: Option<ObjectKey>) -> Self {
            Self {
                overlay,
                btrfs: false,
                key,
                overlay_checks: std::cell::Cell::new(0),
                btrfs_checks: std::cell::Cell::new(0),
                probes: std::cell::Cell::new(0),
            }
        }
    }

    impl SelfMappingProbe for FakeSelfMappingProbe {
        fn fd_is_on_overlayfs(&self, _file: &File) -> bool {
            self.overlay_checks.set(self.overlay_checks.get() + 1);
            self.overlay
        }

        fn fd_is_on_btrfs(&self, _file: &File) -> bool {
            self.btrfs_checks.set(self.btrfs_checks.get() + 1);
            self.btrfs
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

    /// A small owned ELF for tests that need a real pinnable object.
    /// The test binary itself pins only while thin, and pinning it trips
    /// the coverage self-pin guard, so these tests pin this instead: a
    /// gcc-built shared object that is never instrumented, built once per
    /// process and shared, and asserted far below the object limit so it
    /// stays pinnable under any test profile. Uses the process temp dir
    /// so the repo's `TMPDIR` lane override applies.
    fn small_owned_elf() -> PathBuf {
        static ELF: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        ELF.get_or_init(|| {
            let dir = std::env::temp_dir()
                .join(format!("p11scope-discover-owned-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let source = dir.join("small-owned-elf.c");
            let path = dir.join("small-owned-elf.so");
            std::fs::write(
                &source,
                "const char p11scope_discover_small_owned_marker[] = \"SMALL-OWNED-0001\";\n\
                 int p11scope_discover_small_owned_entry(void) { return 0; }\n",
            )
            .unwrap();
            assert!(
                std::process::Command::new("gcc")
                    .args(["-shared", "-fPIC", "-o"])
                    .arg(&path)
                    .arg(&source)
                    .status()
                    .unwrap()
                    .success(),
                "the small owned fixture must compile"
            );
            let len = std::fs::metadata(&path).unwrap().len();
            assert!(
                len < 64 * 1024 * 1024,
                "the small owned fixture must stay small: {len} bytes"
            );
            path
        })
        .clone()
    }

    #[test]
    fn small_owned_elf_stays_pinnable() {
        let path = small_owned_elf();
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(
            len < 64 * 1024 * 1024,
            "the fixture must stay small under any profile: {len} bytes"
        );
        assert_eq!(path, small_owned_elf());
        let file = identity::open_object(&path).unwrap();
        let inspected = identity::inspect_file(&file).unwrap();
        assert!(inspected.identity.reusable);
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
        let module_identity = identity_and_key(&small_owned_elf(), &IdentifyBudget::default())
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
                &IdentifyBudget::default(),
            ),
            Ok(split_fd_key())
        );
        assert_eq!(probe.overlay_checks.get(), 0);
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn loaded_split_probe_overlay_match_accepts_the_maps_key() {
        let (_dir, module_file) = probe_tempfile("loaded-match");
        let module_identity = identity_and_key(&small_owned_elf(), &IdentifyBudget::default())
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
                &IdentifyBudget::default(),
            ),
            Ok(split_maps_key())
        );
        assert_eq!(probe.probes.get(), 1);
    }

    #[test]
    fn loaded_split_probe_overlay_mismatch_refuses_with_todays_message() {
        let (_dir, module_file) = probe_tempfile("loaded-mismatch");
        let module_identity = identity_and_key(&small_owned_elf(), &IdentifyBudget::default())
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
                &IdentifyBudget::default(),
            )
            .unwrap_err(),
            "no module acquisition export maps to the requested file identity"
        );
    }

    #[test]
    fn loaded_split_probe_non_overlay_mismatch_refuses_without_probing() {
        let (_dir, module_file) = probe_tempfile("loaded-non-overlay");
        let module_identity = identity_and_key(&small_owned_elf(), &IdentifyBudget::default())
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
                &IdentifyBudget::default(),
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
        let module_identity = identity_and_key(&small_owned_elf(), &IdentifyBudget::default())
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
                &IdentifyBudget::default(),
            )
            .unwrap_err(),
            "no module acquisition export maps to the requested file identity"
        );
    }

    #[test]
    fn validated_split_probe_equal_keys_accept_without_probing() {
        let exe = small_owned_elf();
        let file = identity::open_object(&exe).unwrap();
        let key = file_key(&file).unwrap();
        let probe = FakeSelfMappingProbe::new(true, None);
        let mut budget = UnboundedProbeBudget;
        assert!(
            validated_file_identity_with_probe(
                &exe,
                &file,
                key,
                &probe,
                &mut budget,
                &IdentifyBudget::default(),
            )
            .unwrap()
            .reusable
        );
        assert_eq!(probe.overlay_checks.get(), 0);
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn validated_split_probe_overlay_match_accepts_a_split_maps_key() {
        let exe = small_owned_elf();
        let file = identity::open_object(&exe).unwrap();
        let probe = FakeSelfMappingProbe::new(true, Some(split_maps_key()));
        let mut budget = UnboundedProbeBudget;
        // `expected` is the maps rendering (backing) while the fd resolves
        // to the overlay device, so only the probe bridges them.
        assert!(
            validated_file_identity_with_probe(
                &exe,
                &file,
                split_maps_key(),
                &probe,
                &mut budget,
                &IdentifyBudget::default(),
            )
            .unwrap()
            .reusable
        );
        assert_eq!(probe.probes.get(), 1);
    }

    #[test]
    fn validated_split_probe_mismatch_keeps_todays_message() {
        let exe = small_owned_elf();
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
                &IdentifyBudget::default(),
            )
            .unwrap_err();
            assert!(err.contains("device/inode mismatch"), "{err}");
        }
    }

    #[test]
    fn stable_maps_matching_module_accepts_without_probing() {
        let exe = small_owned_elf();
        let (key, identity) = identity_and_key(&exe, &IdentifyBudget::default()).unwrap();
        let probe = FakeSelfMappingProbe::new(true, None);
        let mut budget = UnboundedProbeBudget;
        let maps = stable_selection_maps_with_probe(
            &exe,
            key,
            &identity,
            &probe,
            &mut budget,
            &IdentifyBudget::default(),
            maps::parse_maps(&scripted_maps_bytes(&key)).unwrap(),
        )
        .unwrap();
        assert!(maps.iter().any(|mapping| ObjectKey::of(mapping) == key));
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn stable_maps_changed_key_refuses() {
        let exe = small_owned_elf();
        let (key, identity) = identity_and_key(&exe, &IdentifyBudget::default()).unwrap();
        let wrong = ObjectKey {
            inode: key.inode.wrapping_add(1),
            ..key
        };
        let probe = FakeSelfMappingProbe::new(true, Some(wrong));
        let mut budget = UnboundedProbeBudget;
        stable_selection_maps_with_probe(
            &exe,
            wrong,
            &identity,
            &probe,
            &mut budget,
            &IdentifyBudget::default(),
            maps::parse_maps(&scripted_maps_bytes(&key)).unwrap(),
        )
        .unwrap_err();
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
        let original = small_owned_elf();
        let replacement = Path::new("/bin/true");
        std::os::unix::fs::symlink(&original, &link).unwrap();
        let file = identity::open_object(&link).unwrap();
        let key = file_key(&file).unwrap();
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(replacement, &link).unwrap();

        let actual =
            validated_file_identity(&link, &file, key, &IdentifyBudget::default()).unwrap();
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
        let mut objects = ObjectTable {
            module_key,
            approved: BTreeSet::new(),
            ids: BTreeMap::new(),
            records: Vec::new(),
            identify_spent: Rc::new(IdentifyBudget::default()),
        };

        let valid_table_absence = selection_bracket(
            || Ok(valid.clone()),
            |_| Err::<(), _>(SelectionFailure::UnreadableTable),
            || Ok(valid.clone()),
        );
        assert_eq!(valid_table_absence, Err(SelectionFailure::UnreadableTable));

        let invalid_b_table = selection_bracket(
            || Ok(valid.clone()),
            |_| Err::<(), _>(SelectionFailure::UnreadableTable),
            || Ok(invalid.clone()),
        );
        assert_eq!(invalid_b_table, Err(SelectionFailure::ProviderChanged));

        let valid_function_absence = selection_bracket(
            || Ok(valid.clone()),
            |index| {
                Ok(resolve_values(
                    vec![("C_Test", 0x9000)],
                    index,
                    &mut objects,
                ))
            },
            || Ok(valid.clone()),
        );
        assert!(matches!(
            valid_function_absence.unwrap()[0].resolution,
            Resolution::Unmapped
        ));

        let invalid_b_function = selection_bracket(
            || Ok(valid.clone()),
            |index| {
                Ok(resolve_values(
                    vec![("C_Test", 0x9000)],
                    index,
                    &mut objects,
                ))
            },
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
        let table = SelectionTable {
            id: 0,
            version: Version { major: 3, minor: 0 },
            walk: WalkOutcome::Unreadable {
                detail: "short table".into(),
            },
            functions: vec![],
            semantic_authorized: false,
        };
        assert!(selection_table_incomplete(&table, false));
    }

    #[test]
    fn selection_metadata_drift_preserves_real_words_but_changed_word_refuses() {
        #[repr(C)]
        struct Table {
            version: cryptoki_sys::CK_VERSION,
            functions: [usize; 104],
        }
        let mut table = Box::new(Table {
            version: cryptoki_sys::CK_VERSION { major: 3, minor: 2 },
            functions: [0; 104],
        });
        table.functions[0] = selection_metadata_drift_preserves_real_words_but_changed_word_refuses
            as *const () as usize;
        table.functions[103] = table.functions[0];
        let pointer = (&*table) as *const Table as usize;
        let memory = ProcessMemory::open().unwrap();
        let source = Ok(Surface::StandardInterface {
            version: table.version,
        });
        let snapshot = inventory_snapshot(&memory, pointer, source);
        assert_eq!(snapshot.values.len(), 104);
        table.version = cryptoki_sys::CK_VERSION {
            major: 2,
            minor: 40,
        };
        let diagnostic = confirm_selection_snapshot(&memory, pointer, &snapshot, Some((3, 2)))
            .expect("metadata drift does not invalidate identical function words")
            .unwrap();
        assert!(diagnostic.starts_with("version metadata changed:"));
        let mapping_entries = read_self_maps().unwrap();
        let mappings = validated_map_index(&mapping_entries).unwrap();
        let maps::Resolved::File { device, inode, .. } =
            mappings.resolve(table.functions[0] as u64)
        else {
            panic!("test code must be file-backed");
        };
        let module_key = ObjectKey { device, inode };
        let executable = small_owned_elf();
        let identity = identity_and_key(&executable, &IdentifyBudget::default())
            .unwrap()
            .1;
        let mut objects = ObjectTable::new(
            executable,
            module_key,
            identity,
            BTreeSet::from([module_key]),
            Rc::new(IdentifyBudget::default()),
        );
        let (observed, _) = selection_table_for(
            pointer,
            Version { major: 3, minor: 2 },
            &snapshot,
            &mappings,
            &mut objects,
        );
        assert_eq!(observed.functions.len(), 104);
        assert!(matches!(
            observed.functions[103].resolution,
            Resolution::Resolved { .. }
        ));
        table.functions[5] = 1;
        assert_eq!(
            confirm_selection_snapshot(&memory, pointer, &snapshot, Some((3, 2))),
            Err(SelectionFailure::ProviderChanged)
        );
        let invalid_snapshot = inventory_snapshot(&memory, pointer, source);
        table.functions[5] = 2;
        assert_eq!(
            confirm_selection_snapshot(&memory, pointer, &invalid_snapshot, Some((2, 40))),
            Err(SelectionFailure::ProviderChanged),
            "invalid observed words participate in coherence too"
        );
    }

    #[test]
    fn selector_zero_retains_a_selected_count_only_observation() {
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
                            TableOrigin::File {
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
        assert_eq!(
            evidence.queries[0].authority,
            SelectionAuthority::SelectionCountOnly
        );
        assert_eq!(evidence.queries[0].selection_table, Some(0));
        assert_eq!(evidence.tables.len(), 1);
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
    fn only_bare_names_resolve_inside_the_provider_directory() {
        for name in ["libmozsqlite3.so", "libnspr4.so", "a", "x.y"] {
            assert!(is_bare_library_name(name), "{name}");
        }
        for name in [
            "",
            ".",
            "..",
            "sub/dir.so",
            "/lib/x86_64-linux-gnu/libc.so.6",
            "a\0b",
        ] {
            assert!(!is_bare_library_name(name), "{name:?}");
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
