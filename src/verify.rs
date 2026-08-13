//! Manifest trust boundary. Validate the recorded table shape, identify every
//! target through one open file descriptor, and keep those leased descriptors
//! alive through the complete capture while Aya attaches via `/proc/self/fd/*`.

use p11scope_manifest::identity::{
    IdentityKind, ObjectIdentity, inspect_file, open_object, open_regular,
};
use p11scope_manifest::manifest::*;
use pkcs11_module::{Surface, TableSet, tables_for};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TOTAL_OBJECT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OBJECTS: usize = p11scope_ebpf_common::MAX_SLOTS as usize;
const MAX_SURFACES: usize = 257; // legacy + the shared acquisition cap
const MAX_FUNCTIONS: usize = 32_768;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DETAIL_BYTES: usize = 4096;
pub const OBJECT_CHANGED_EXIT: i32 = 78;

/// Reads one regular, bounded UTF-8 manifest. The descriptor is opened before
/// metadata and content are inspected, so replacing its pathname cannot mix
/// two files in one parse.
pub fn read_manifest(path: &Path) -> Result<String, String> {
    let file = open_regular(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(format!(
            "manifest is {} bytes; limit is {MAX_MANIFEST_BYTES}",
            metadata.len()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read failed: {error}"))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(format!(
            "manifest grew beyond the {MAX_MANIFEST_BYTES}-byte limit"
        ));
    }
    String::from_utf8(bytes).map_err(|error| format!("manifest is not UTF-8: {error}"))
}

#[derive(Debug)]
pub struct VerifiedObjects {
    files: BTreeMap<String, std::fs::File>,
    identities: BTreeMap<String, ObjectIdentity>,
    lease: LeaseMonitor,
}

impl VerifiedObjects {
    /// Path Aya may reopen without re-resolving the untrusted manifest path.
    pub fn attach_path(&self, original: &str) -> Result<PathBuf, String> {
        self.files
            .get(original)
            .map(|file| PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())))
            .ok_or_else(|| format!("object path {original:?} was not verified"))
    }

    /// Fails closed if any writer attempted to change an authorized object.
    /// The leases are held until this value is dropped, so an intact lease
    /// also proves that the bytes hashed at authorization are still current.
    pub fn ensure_stable(&self) -> Result<(), String> {
        self.lease.ensure(self.files.values())
    }

    /// Re-hashes every pinned object after attachment. The held lease is the
    /// continuity guarantee; this second identity check also catches a
    /// filesystem that reported a lease but did not preserve the bytes.
    pub fn verify_stable(&self) -> Result<(), String> {
        self.ensure_stable()?;
        for (path, file) in &self.files {
            let current = inspect_file(file)
                .map_err(|error| format!("rechecking authorized object {path}: {error}"))?
                .identity;
            let expected = &self.identities[path];
            if current.kind != expected.kind
                || current.value != expected.value
                || current.sha256 != expected.sha256
            {
                return Err(format!(
                    "authorized object {path} changed while capture was starting"
                ));
            }
        }
        self.ensure_stable()
    }
}

#[derive(Debug)]
pub(crate) struct LeaseMonitor {
    broken: Arc<AtomicBool>,
    signal_id: signal_hook::SigId,
}

impl LeaseMonitor {
    pub(crate) fn new() -> Result<Self, String> {
        let broken = Arc::new(AtomicBool::new(false));
        let signal_flag = Arc::clone(&broken);
        // SAFETY: the handler performs only an atomic store and `_exit`, both
        // async-signal-safe. Exiting immediately ensures probes disappear
        // before a writer waiting on the broken lease can modify the object.
        let signal_id = unsafe {
            signal_hook::low_level::register(libc::SIGIO, move || {
                signal_flag.store(true, Ordering::SeqCst);
                libc::_exit(OBJECT_CHANGED_EXIT);
            })
        }
        .map_err(|error| format!("installing object-lease signal handler failed: {error}"))?;
        Ok(Self { broken, signal_id })
    }

    pub(crate) fn acquire(&self, file: &std::fs::File) -> Result<(), String> {
        // SAFETY: fcntl receives a live descriptor and the integer lease type
        // required by Linux F_SETLEASE.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) } == -1 {
            return Err(format!(
                "cannot acquire required read lease: {}; the observer needs file ownership or CAP_LEASE, and the object must have no writer",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(crate) fn ensure<'a>(
        &self,
        files: impl IntoIterator<Item = &'a std::fs::File>,
    ) -> Result<(), String> {
        if self.broken.load(Ordering::SeqCst) {
            return Err("an authorized object changed while capture was active".into());
        }
        for file in files {
            // SAFETY: F_GETLEASE only queries the lease on this live fd.
            let lease = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLEASE) };
            if lease == -1 {
                return Err(format!(
                    "checking object read lease failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if lease != libc::F_RDLCK {
                return Err("an authorized object changed while capture was active".into());
            }
        }
        if self.broken.load(Ordering::SeqCst) {
            return Err("an authorized object changed while capture was active".into());
        }
        Ok(())
    }
}

impl Drop for LeaseMonitor {
    fn drop(&mut self) {
        signal_hook::low_level::unregister(self.signal_id);
    }
}

fn bounded(label: &str, value: &str, limit: usize, problems: &mut Vec<String>) {
    if value.len() > limit {
        problems.push(format!(
            "{label} is {} bytes; limit is {limit}",
            value.len()
        ));
    }
}

fn valid_hex(value: &str) -> bool {
    value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn expected_surface(surface: &SurfaceRecord) -> Result<(Vec<&'static str>, &'static str), String> {
    let version = surface
        .version
        .ok_or_else(|| "walked surface has no version".to_string())?;
    let version = cryptoki_sys::CK_VERSION {
        major: version.major,
        minor: version.minor,
    };
    let source = match surface.source {
        SurfaceSource::LegacyFunctionList => Surface::LegacyFunctionList { version },
        SurfaceSource::Interface { .. } => Surface::StandardInterface { version },
    };
    let (spans, normal_walk) = match tables_for(source) {
        TableSet::Walk(spans) => (spans, "full"),
        TableSet::WalkKnownPrefix(spans) => (spans, "known_prefix"),
        TableSet::Refuse => return Ok((Vec::new(), "refused")),
    };
    let forced_prefix = matches!(
        surface.source,
        SurfaceSource::Interface {
            classification: InterfaceClassification::CorroboratedStandardPrefix,
            ..
        }
    );
    Ok((
        spans
            .iter()
            .flat_map(|span| span.fields().iter().map(|field| field.name))
            .collect(),
        if forced_prefix {
            "known_prefix"
        } else {
            normal_walk
        },
    ))
}

fn walk_name(walk: &WalkOutcome) -> &'static str {
    match walk {
        WalkOutcome::Full => "full",
        WalkOutcome::KnownPrefix => "known_prefix",
        WalkOutcome::Refused => "refused",
        WalkOutcome::NotWalked => "not_walked",
        WalkOutcome::Unreadable { .. } => "unreadable",
    }
}

fn validate_structure(m: &Manifest) -> Vec<String> {
    let mut problems = Vec::new();
    if m.schema != SCHEMA {
        problems.push(format!("manifest schema {:?} is not {SCHEMA:?}", m.schema));
    }
    bounded("module path", &m.module_path, MAX_PATH_BYTES, &mut problems);
    if !Path::new(&m.module_path).is_absolute() {
        problems.push("module path must be absolute".into());
    }
    if m.objects.is_empty() || m.objects.len() > MAX_OBJECTS {
        problems.push(format!(
            "manifest has {} objects; expected 1..={MAX_OBJECTS}",
            m.objects.len()
        ));
    }
    if m.surfaces.len() > MAX_SURFACES {
        problems.push(format!(
            "manifest has {} surfaces; limit is {MAX_SURFACES}",
            m.surfaces.len()
        ));
    }
    if m.vendor_interfaces.len() > 256 {
        problems.push(format!(
            "manifest has {} vendor interfaces; limit is 256",
            m.vendor_interfaces.len()
        ));
    }
    if m.alias_groups.len() > p11scope_ebpf_common::MAX_SLOTS as usize {
        problems.push(format!(
            "manifest has too many alias groups: {}",
            m.alias_groups.len()
        ));
    }

    let mut object_ids = BTreeSet::new();
    let mut object_paths = BTreeSet::new();
    for (position, object) in m.objects.iter().enumerate() {
        bounded("object path", &object.path, MAX_PATH_BYTES, &mut problems);
        if !Path::new(&object.path).is_absolute() {
            problems.push(format!("object {} path must be absolute", object.id));
        }
        if object.id as usize != position {
            problems.push(format!(
                "object ids must be dense: position {position} has id {}",
                object.id
            ));
        }
        if !object_ids.insert(object.id) {
            problems.push(format!("duplicate object id {}", object.id));
        }
        if !object_paths.insert(object.path.as_str()) {
            problems.push(format!("duplicate object path {:?}", object.path));
        }
        match (
            &object.identity.kind,
            &object.identity.value,
            &object.identity.sha256,
            object.identity.reusable,
        ) {
            (IdentityKind::GnuBuildId, Some(value), Some(sha256), true) => {
                if value.is_empty() || value.len() > 128 || !valid_hex(value) {
                    problems.push(format!("object {} has an invalid GNU build-id", object.id));
                }
                if sha256.len() != 64 || !valid_hex(sha256) {
                    problems.push(format!(
                        "object {} has an invalid content SHA-256",
                        object.id
                    ));
                }
            }
            (IdentityKind::Sha256, Some(value), Some(sha256), true) => {
                if value.len() != 64 || !valid_hex(value) || value != sha256 {
                    problems.push(format!(
                        "object {} has an invalid SHA-256 identity",
                        object.id
                    ));
                }
            }
            (IdentityKind::Unavailable, None, None, false) => {}
            _ => problems.push(format!(
                "object {} has an inconsistent identity record",
                object.id
            )),
        }
        if let Some(note) = &object.identity.note {
            bounded("identity note", note, MAX_DETAIL_BYTES, &mut problems);
        }
    }
    if m.objects
        .first()
        .is_some_and(|object| object.path != m.module_path)
    {
        problems.push("object id 0 path must equal module_path".into());
    }

    let mut legacy_seen = false;
    let mut interface_indices = BTreeSet::new();
    let mut total_functions = 0usize;
    for (surface_index, surface) in m.surfaces.iter().enumerate() {
        if let Acquisition::Error { detail } = &surface.acquisition {
            bounded(
                "surface acquisition error",
                detail,
                MAX_DETAIL_BYTES,
                &mut problems,
            );
        }
        if let WalkOutcome::Unreadable { detail } = &surface.walk {
            bounded(
                "surface walk error",
                detail,
                MAX_DETAIL_BYTES,
                &mut problems,
            );
        }
        match &surface.source {
            SurfaceSource::LegacyFunctionList => {
                if legacy_seen {
                    problems.push(
                        "manifest contains more than one legacy function-list surface".into(),
                    );
                }
                legacy_seen = true;
                if matches!(surface.acquisition, Acquisition::Empty) {
                    problems.push("legacy acquisition cannot be empty".into());
                }
            }
            SurfaceSource::Interface {
                index,
                raw_name_hex,
                name_lossy,
                name_error,
                classification,
                ..
            } => {
                if *index >= 256 || !interface_indices.insert(*index) {
                    problems.push(format!("invalid or duplicate interface index {index}"));
                }
                if !matches!(surface.acquisition, Acquisition::Ok) {
                    problems.push(format!("interface {index} acquisition must be ok"));
                }
                if let Some(raw) = raw_name_hex {
                    if raw.len() > 512 || !valid_hex(raw) {
                        problems.push(format!("interface {index} has invalid raw_name_hex"));
                    }
                }
                if let Some(name) = name_lossy {
                    bounded("interface name", name, 768, &mut problems);
                }
                if let Some(error) = name_error {
                    bounded(
                        "interface name error",
                        error,
                        MAX_DETAIL_BYTES,
                        &mut problems,
                    );
                }
                let exact_raw = raw_name_hex
                    .as_deref()
                    .is_some_and(|raw| raw.eq_ignore_ascii_case("504b4353203131"));
                match classification {
                    InterfaceClassification::ExactStandard
                        if !exact_raw
                            || name_lossy.as_deref() != Some("PKCS 11")
                            || name_error.is_some() =>
                    {
                        problems.push(format!(
                            "interface {index} exact_standard classification disagrees with its recorded name"
                        ));
                    }
                    InterfaceClassification::CorroboratedStandardPrefix if exact_raw => {
                        problems.push(format!(
                            "interface {index} corroborated classification is invalid for an exact standard name"
                        ));
                    }
                    InterfaceClassification::CorroboratedStandardPrefix
                        if !matches!(surface.walk, WalkOutcome::KnownPrefix) =>
                    {
                        problems.push(format!(
                            "corroborated interface {index} must record a known-prefix walk"
                        ));
                    }
                    _ => {}
                }
            }
        }
        total_functions = total_functions.saturating_add(surface.functions.len());
        if total_functions > MAX_FUNCTIONS {
            problems.push(format!(
                "manifest has more than {MAX_FUNCTIONS} function records"
            ));
            break;
        }
        for function in &surface.functions {
            bounded("function name", &function.name, 128, &mut problems);
            if let Resolution::Resolved { object, .. } = function.resolution
                && !object_ids.contains(&object)
            {
                problems.push(format!(
                    "{} refers to missing object id {object}",
                    function.name
                ));
            }
            if let Resolution::UnusableFile { reason, path_hex } = &function.resolution {
                bounded(
                    "unusable-file reason",
                    reason,
                    MAX_DETAIL_BYTES,
                    &mut problems,
                );
                if path_hex.len() > MAX_PATH_BYTES * 2 || !valid_hex(path_hex) {
                    problems.push(format!("{} has invalid unusable path hex", function.name));
                }
            }
        }

        if !matches!(surface.acquisition, Acquisition::Ok) {
            if !surface.functions.is_empty() || !matches!(surface.walk, WalkOutcome::NotWalked) {
                problems.push(format!(
                    "surface {surface_index} acquired as non-ok must be not_walked and empty"
                ));
            }
            continue;
        }
        if matches!(surface.walk, WalkOutcome::Unreadable { .. }) {
            if !surface.functions.is_empty() {
                problems.push(format!("unreadable surface {surface_index} must be empty"));
            }
            continue;
        }
        if matches!(surface.walk, WalkOutcome::NotWalked) {
            if surface.version.is_some() || !surface.functions.is_empty() {
                problems.push(format!(
                    "not-walked surface {surface_index} must have no version or functions"
                ));
            }
            continue;
        }
        match expected_surface(surface) {
            Ok((expected, expected_walk)) => {
                if walk_name(&surface.walk) != expected_walk {
                    problems.push(format!(
                        "surface {surface_index} walk {:?} disagrees with its source/version; expected {expected_walk}",
                        surface.walk
                    ));
                }
                let actual: Vec<&str> = surface
                    .functions
                    .iter()
                    .map(|function| function.name.as_str())
                    .collect();
                if actual != expected {
                    problems.push(format!(
                        "surface {surface_index} does not match canonical function order (got {}, expected {})",
                        actual.len(),
                        expected.len()
                    ));
                }
            }
            Err(error) => problems.push(format!("surface {surface_index}: {error}")),
        }
    }

    if !legacy_seen {
        problems.push("manifest must contain exactly one legacy acquisition surface".into());
    }

    for vendor in &m.vendor_interfaces {
        if vendor.index >= 256 || !interface_indices.insert(vendor.index) {
            problems.push(format!(
                "invalid or duplicate interface index {}",
                vendor.index
            ));
        }
        if let Some(raw) = &vendor.raw_name_hex
            && (raw.len() > 512 || !valid_hex(raw))
        {
            problems.push(format!(
                "vendor interface {} has invalid raw_name_hex",
                vendor.index
            ));
        }
        for (label, value) in [
            ("vendor interface name", vendor.name_lossy.as_deref()),
            ("vendor interface name error", vendor.name_error.as_deref()),
            (
                "vendor interface version error",
                vendor.version_error.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                bounded(label, value, MAX_DETAIL_BYTES, &mut problems);
            }
        }
    }
    if let Acquisition::Error { detail } = &m.interface_list {
        bounded(
            "interface-list acquisition error",
            detail,
            MAX_DETAIL_BYTES,
            &mut problems,
        );
    }
    let dense_interface_indices = interface_indices
        .iter()
        .copied()
        .eq(0..interface_indices.len());
    match m.interface_list {
        Acquisition::Ok if interface_indices.is_empty() || !dense_interface_indices => problems
            .push("successful interface-list acquisition requires dense interface indices".into()),
        Acquisition::Ok => {}
        _ if !interface_indices.is_empty() => problems.push(
            "non-successful interface-list acquisition cannot contain interface indices".into(),
        ),
        _ => {}
    }
    let alias_entries: usize = m.alias_groups.iter().map(|group| group.entries.len()).sum();
    if alias_entries > MAX_FUNCTIONS {
        problems.push(format!(
            "manifest has too many alias entries: {alias_entries}"
        ));
    }
    for group in &m.alias_groups {
        if !object_ids.contains(&group.object) {
            problems.push(format!(
                "alias group refers to missing object id {}",
                group.object
            ));
        }
        for entry in &group.entries {
            bounded("alias function name", &entry.name, 128, &mut problems);
            if entry.surface >= m.surfaces.len() {
                problems.push(format!(
                    "alias entry refers to missing surface {}",
                    entry.surface
                ));
            }
        }
    }
    problems
}

#[derive(Debug, PartialEq, Eq)]
struct Provenance {
    module: String,
    objects: Vec<String>,
    interface_list: &'static str,
    surfaces: Vec<ProvenanceSurface>,
    vendor_interfaces: Vec<Vec<String>>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProvenanceSurface {
    source: Vec<String>,
    acquisition: &'static str,
    version: Option<(u8, u8)>,
    walk: &'static str,
    functions: Vec<(String, String)>,
}

fn acquisition_name(acquisition: &Acquisition) -> &'static str {
    match acquisition {
        Acquisition::Ok => "ok",
        Acquisition::Absent => "absent",
        Acquisition::Empty => "empty",
        Acquisition::Error { .. } => "error",
    }
}

fn identity_name(object: &ObjectRecord) -> String {
    format!(
        "sha256:{}:{}",
        object.identity.reusable,
        object.identity.sha256.as_deref().unwrap_or("")
    )
}

fn provenance(m: &Manifest) -> Result<Provenance, Vec<String>> {
    let problems = validate_structure(m);
    if !problems.is_empty() {
        return Err(problems);
    }

    let identities: BTreeMap<u32, String> = m
        .objects
        .iter()
        .map(|object| (object.id, identity_name(object)))
        .collect();
    let mut objects: Vec<String> = identities.values().cloned().collect();
    objects.sort();

    let mut surfaces = Vec::with_capacity(m.surfaces.len());
    for surface in &m.surfaces {
        let source = match &surface.source {
            SurfaceSource::LegacyFunctionList => vec!["legacy".into()],
            SurfaceSource::Interface {
                raw_name_hex,
                flags,
                classification,
                ..
            } => vec![
                "interface".into(),
                raw_name_hex.as_deref().unwrap_or("").to_ascii_lowercase(),
                flags.to_string(),
                match classification {
                    InterfaceClassification::ExactStandard => "exact",
                    InterfaceClassification::CorroboratedStandardPrefix => "corroborated",
                }
                .into(),
            ],
        };
        let functions = surface
            .functions
            .iter()
            .map(|function| {
                let resolution = match &function.resolution {
                    Resolution::Resolved {
                        object,
                        file_offset,
                    } => format!(
                        "resolved:{}:{file_offset}",
                        identities
                            .get(object)
                            .expect("structure validation checked object ids")
                    ),
                    Resolution::NullPointer => "null".into(),
                    Resolution::NonFileBacked => "non-file-backed".into(),
                    Resolution::Unmapped => "unmapped".into(),
                    Resolution::UnusableFile { .. } => "unusable-file".into(),
                };
                (function.name.clone(), resolution)
            })
            .collect();
        surfaces.push(ProvenanceSurface {
            source,
            acquisition: acquisition_name(&surface.acquisition),
            version: surface
                .version
                .map(|version| (version.major, version.minor)),
            walk: walk_name(&surface.walk),
            functions,
        });
    }
    surfaces.sort();

    let mut vendor_interfaces: Vec<Vec<String>> = m
        .vendor_interfaces
        .iter()
        .map(|interface| {
            vec![
                interface
                    .raw_name_hex
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase(),
                interface
                    .version
                    .map(|version| format!("{}.{}", version.major, version.minor))
                    .unwrap_or_default(),
                interface.flags.to_string(),
                interface.func_list_null.to_string(),
            ]
        })
        .collect();
    vendor_interfaces.sort();

    Ok(Provenance {
        module: identities
            .get(&0)
            .expect("structure validation requires object zero")
            .clone(),
        objects,
        interface_list: acquisition_name(&m.interface_list),
        surfaces,
        vendor_interfaces,
    })
}

/// Proves that a stored manifest's attach semantics were freshly reported by
/// the selected provider. Paths, object ids, and diagnostics are deliberately
/// normalized; object identity, table provenance, and every name-to-offset
/// mapping are not.
pub fn check_provenance(candidate: &Manifest, discovered: &Manifest) -> Result<(), Vec<String>> {
    let candidate = provenance(candidate)?;
    let discovered = provenance(discovered)?;
    if candidate.module != discovered.module {
        return Err(vec![
            "module provenance differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    if candidate.objects != discovered.objects {
        return Err(vec![
            "object provenance differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    if candidate.interface_list != discovered.interface_list {
        return Err(vec![
            "interface-list provenance differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    if candidate.surfaces.len() != discovered.surfaces.len() {
        return Err(vec![
            "surface provenance differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    for (candidate, discovered) in candidate.surfaces.iter().zip(&discovered.surfaces) {
        if candidate.source != discovered.source
            || candidate.acquisition != discovered.acquisition
            || candidate.version != discovered.version
            || candidate.walk != discovered.walk
        {
            return Err(vec![
                "surface provenance differs from fresh discovery; refusing to attach".into(),
            ]);
        }
        if candidate.functions != discovered.functions {
            let name = candidate
                .functions
                .iter()
                .zip(&discovered.functions)
                .find(|(candidate, discovered)| candidate != discovered)
                .map(|(candidate, _)| candidate.0.as_str())
                .unwrap_or("function table");
            return Err(vec![format!(
                "{name} provenance differs from fresh discovery; refusing to attach"
            )]);
        }
    }
    if candidate.vendor_interfaces != discovered.vendor_interfaces {
        return Err(vec![
            "vendor-interface provenance differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    Ok(())
}

/// Opens, identifies, and pins every object. Errors are aggregated so an
/// operator sees every stale or malformed target in one run.
pub fn check_reuse(m: &Manifest) -> Result<VerifiedObjects, Vec<String>> {
    let mut problems = validate_structure(m);
    if !problems.is_empty() {
        return Err(problems);
    }

    let lease = match LeaseMonitor::new() {
        Ok(lease) => lease,
        Err(error) => return Err(vec![error]),
    };
    let mut pinned = Vec::new();
    let mut total_object_bytes = 0u64;
    for object in &m.objects {
        if !object.identity.reusable {
            problems.push(format!(
                "{}: manifest identity is not reusable ({})",
                object.path,
                object
                    .identity
                    .note
                    .as_deref()
                    .unwrap_or("no identity recorded")
            ));
            continue;
        }
        let file = match open_object(Path::new(&object.path)) {
            Ok(file) => file,
            Err(error) => {
                problems.push(format!(
                    "{}: cannot open the file now ({error})",
                    object.path
                ));
                continue;
            }
        };
        if let Err(error) = lease.acquire(&file) {
            problems.push(format!("{}: {error}", object.path));
            continue;
        }
        let len = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                problems.push(format!("{}: metadata failed ({error})", object.path));
                continue;
            }
        };
        let Some(total) = total_object_bytes.checked_add(len) else {
            problems.push("total object size overflowed u64".into());
            continue;
        };
        if total > MAX_TOTAL_OBJECT_BYTES {
            problems.push(format!(
                "manifest objects total more than the {MAX_TOTAL_OBJECT_BYTES}-byte limit"
            ));
            continue;
        }
        total_object_bytes = total;
        pinned.push((object, file));
    }
    if !problems.is_empty() {
        return Err(problems);
    }

    let mut opened = BTreeMap::new();
    for (object, file) in pinned {
        let inspected = match inspect_file(&file) {
            Ok(inspected) => inspected,
            Err(error) => {
                problems.push(format!(
                    "{}: cannot identify the file now ({error})",
                    object.path
                ));
                continue;
            }
        };
        if inspected.identity.kind != object.identity.kind
            || inspected.identity.value != object.identity.value
            || inspected.identity.sha256 != object.identity.sha256
        {
            problems.push(format!(
                "{}: identity changed since discovery (manifest {:?} {} sha256 {}, current {:?} {} sha256 {}) — re-run `p11scope discover`",
                object.path,
                object.identity.kind,
                object.identity.value.as_deref().unwrap_or("-"),
                object.identity.sha256.as_deref().unwrap_or("-"),
                inspected.identity.kind,
                inspected.identity.value.as_deref().unwrap_or("-"),
                inspected.identity.sha256.as_deref().unwrap_or("-"),
            ));
            continue;
        }
        opened.insert(object.id, (object.path.clone(), file, inspected));
    }

    for surface in &m.surfaces {
        for function in &surface.functions {
            let Resolution::Resolved {
                object,
                file_offset,
            } = function.resolution
            else {
                continue;
            };
            if let Some((path, _, inspected)) = opened.get(&object)
                && !inspected.contains_executable_offset(file_offset)
            {
                problems.push(format!(
                    "{}: {}+{file_offset:#x} is outside every executable ELF segment",
                    function.name, path
                ));
            }
        }
    }

    if !problems.is_empty() {
        return Err(problems);
    }
    if let Err(error) = lease.ensure(opened.values().map(|(_, file, _)| file)) {
        return Err(vec![error]);
    }
    let mut files = BTreeMap::new();
    let mut identities = BTreeMap::new();
    for (path, file, inspected) in opened.into_values() {
        identities.insert(path.clone(), inspected.identity);
        files.insert(path, file);
    }
    Ok(VerifiedObjects {
        files,
        identities,
        lease,
    })
}
