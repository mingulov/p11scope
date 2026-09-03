//! Manifest input hygiene: bounded read and structural validation of
//! `p11scope-manifest/5` documents. Trusted operator input, validated before use.

use p11scope_manifest::identity::{IdentityKind, ObjectIdentity, open_regular};
use p11scope_manifest::manifest::*;
use pkcs11_module::{Surface, TableSet, tables_for};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::Path;

pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TOTAL_OBJECT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OBJECTS: usize = p11scope_ebpf_common::MAX_SLOTS as usize;
const MAX_SURFACES: usize = 257; // legacy + the shared acquisition cap
const MAX_FUNCTIONS: usize = 32_768;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DETAIL_BYTES: usize = 4096;
const MAX_SELECTION_TABLES: usize = 10;
const MAX_SELECTION_MATCHES: usize = 16;
const SELECTION_QUERIES: usize = 10;

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

fn validate_identity(label: &str, identity: &ObjectIdentity, problems: &mut Vec<String>) {
    match (
        &identity.kind,
        &identity.value,
        &identity.sha256,
        identity.reusable,
    ) {
        (IdentityKind::GnuBuildId, Some(value), Some(sha256), true) => {
            if value.is_empty() || value.len() > 128 || !valid_hex(value) {
                problems.push(format!("{label} has an invalid GNU build-id"));
            }
            if sha256.len() != 64 || !valid_hex(sha256) {
                problems.push(format!("{label} has an invalid content SHA-256"));
            }
        }
        (IdentityKind::Sha256, Some(value), Some(sha256), true) => {
            if value.len() != 64 || !valid_hex(value) || value != sha256 {
                problems.push(format!("{label} has an invalid SHA-256 identity"));
            }
        }
        _ => problems.push(format!(
            "{label} identity is not reusable and has no mandatory whole-file SHA-256"
        )),
    }
    if let Some(note) = &identity.note {
        bounded("identity note", note, MAX_DETAIL_BYTES, problems);
    }
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

fn selection_request(selector: u8, flags: u64) -> Option<SelectionRequest> {
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
        _ => return None,
    };
    Some(SelectionRequest {
        name,
        version,
        flags,
    })
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

fn selection_table_names(version: Version) -> Option<Vec<&'static str>> {
    let cryptoki_version = cryptoki_sys::CK_VERSION {
        major: version.major,
        minor: version.minor,
    };
    match tables_for(Surface::StandardInterface {
        version: cryptoki_version,
    }) {
        TableSet::Walk(spans) => Some(
            spans
                .iter()
                .flat_map(|span| span.fields().iter().map(|field| field.name))
                .collect(),
        ),
        TableSet::WalkKnownPrefix(_) | TableSet::Refuse => None,
    }
}

fn selection_name_agrees(result: &SelectionResult, surface: &SurfaceRecord) -> bool {
    let SurfaceSource::Interface {
        raw_name_hex,
        name_error,
        ..
    } = &surface.source
    else {
        return false;
    };
    let surface_name = if name_error.is_some() {
        SelectionNameClass::Unreadable
    } else if raw_name_hex.as_deref() == Some("504b4353203131") {
        SelectionNameClass::ExactStandard
    } else if raw_name_hex.is_some() {
        SelectionNameClass::Other
    } else {
        SelectionNameClass::Null
    };
    !matches!(
        result.name,
        SelectionNameClass::Null | SelectionNameClass::Unreadable
    ) && result.name == surface_name
}

fn selection_version_agrees(result: &SelectionResult, surface: &SurfaceRecord) -> bool {
    let surface_version = match surface.version {
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
    };
    !matches!(
        result.version,
        SelectionVersionClass::Null | SelectionVersionClass::Unreadable
    ) && result.version == surface_version
}

pub(crate) fn selection_surface_usable(surface: &SurfaceRecord) -> bool {
    if !matches!(surface.acquisition, Acquisition::Ok) {
        return false;
    }
    let Ok((_, expected_walk)) = expected_surface(surface) else {
        return false;
    };
    matches!(
        (&surface.walk, expected_walk),
        (WalkOutcome::Full, "full") | (WalkOutcome::KnownPrefix, "known_prefix")
    )
}

fn validate_selection_table(
    table: &SelectionTable,
    object_ids: &BTreeSet<u32>,
    problems: &mut Vec<String>,
) {
    if table.id as usize >= MAX_SELECTION_TABLES {
        problems.push(format!("selection table id {} is out of range", table.id));
    }
    if table.version.major != 3 || table.version.minor > 2 {
        problems.push(format!(
            "selection table {} has unsupported version {}.{}",
            table.id, table.version.major, table.version.minor
        ));
    }
    if !matches!(table.walk, WalkOutcome::Full) {
        problems.push(format!(
            "selection table {} must have a full walk outcome",
            table.id
        ));
    }
    if table.semantic_authorized {
        problems.push(format!(
            "selection table {} cannot authorize semantic decoding",
            table.id
        ));
    }
    if let Some(expected) = selection_table_names(table.version) {
        let actual: Vec<&str> = table
            .functions
            .iter()
            .map(|function| function.name.as_str())
            .collect();
        if actual != expected {
            problems.push(format!(
                "selection table {} does not match its canonical function layout",
                table.id
            ));
        }
    }
    if table.functions.len() > 104 {
        problems.push(format!(
            "selection table {} has too many functions",
            table.id
        ));
    }
    for function in &table.functions {
        bounded("selection function name", &function.name, 128, problems);
        match function.resolution {
            Resolution::NullPointer => {}
            Resolution::Resolved { object, .. } if object_ids.contains(&object) && object == 0 => {}
            Resolution::Resolved { object, .. } => problems.push(format!(
                "selection function {} refers to dependency object {}",
                function.name, object
            )),
            Resolution::NonFileBacked | Resolution::Unmapped | Resolution::UnusableFile { .. } => {
                problems.push(format!(
                    "selection function {} has an unresolved resolution",
                    function.name
                ));
            }
        }
    }
}

fn validate_selection_evidence(
    evidence: &SelectionEvidence,
    surfaces: &[SurfaceRecord],
    object_ids: &BTreeSet<u32>,
    problems: &mut Vec<String>,
) {
    if evidence.tables.len() > MAX_SELECTION_TABLES {
        problems.push(format!(
            "manifest has {} selection tables; limit is {MAX_SELECTION_TABLES}",
            evidence.tables.len()
        ));
    }
    let mut table_ids = BTreeSet::new();
    for table in &evidence.tables {
        if !table_ids.insert(table.id) {
            problems.push(format!("duplicate selection table id {}", table.id));
        }
        validate_selection_table(table, object_ids, problems);
    }

    match evidence.acquisition {
        SelectionAcquisition::ExportAbsent | SelectionAcquisition::ExportOutsideModule => {
            if !evidence.queries.is_empty() {
                problems.push("zero-call selection acquisition has queries".into());
            }
            if !evidence.tables.is_empty() {
                problems.push("zero-call selection acquisition has tables".into());
            }
            if evidence.selection_truncated {
                problems.push("zero-call selection acquisition is truncated".into());
            }
            return;
        }
        SelectionAcquisition::Queried if evidence.queries.len() != SELECTION_QUERIES => {
            problems.push(format!(
                "queried selection acquisition requires exactly {SELECTION_QUERIES} queries"
            ));
        }
        SelectionAcquisition::Queried => {}
    }

    let mut referenced_tables = BTreeSet::new();
    let mut pair_authority = BTreeMap::<(SelectionVersionClass, u64), u8>::new();
    let mut conflict_pair = false;
    for (position, query) in evidence.queries.iter().enumerate() {
        let expected_selector = (position / 2) as u8;
        let expected_flags = (position % 2) as u64;
        if query.selector != expected_selector {
            problems.push(format!(
                "selection query {position} has selector {}; expected {expected_selector}",
                query.selector
            ));
        }
        if query.request
            != selection_request(query.selector, query.request.flags).unwrap_or(SelectionRequest {
                name: SelectionNameClass::Unreadable,
                version: SelectionVersionClass::Unreadable,
                flags: query.request.flags,
            })
        {
            problems.push(format!(
                "selection query {position} has an invalid selector"
            ));
        }
        if query.request.flags != expected_flags {
            problems.push(format!(
                "selection query {position} has flags {}; expected {expected_flags}",
                query.request.flags
            ));
        }
        let mut previous_surface = None;
        for found in &query.inventory_matches {
            let Some(surface) = surfaces.get(found.surface) else {
                problems.push(format!(
                    "selection query {position} refers to missing surface {}",
                    found.surface
                ));
                previous_surface = Some(found.surface);
                continue;
            };
            if !selection_surface_usable(surface) {
                problems.push(format!(
                    "selection query {position} refers to unavailable inventory surface {}",
                    found.surface
                ));
            }
            if previous_surface.is_some_and(|previous| found.surface <= previous) {
                problems.push(format!(
                    "selection query {position} contains duplicate or unsorted surfaces"
                ));
            }
            previous_surface = Some(found.surface);
            if let Some(result) = query.result.as_ref() {
                if found.name_agrees != selection_name_agrees(result, surface) {
                    problems.push(format!(
                        "selection query {position} has incorrect name agreement"
                    ));
                }
                if found.version_agrees != selection_version_agrees(result, surface) {
                    problems.push(format!(
                        "selection query {position} has incorrect version agreement"
                    ));
                }
            }
        }
        if query.inventory_matches.len() > MAX_SELECTION_MATCHES {
            problems.push(format!(
                "selection query {position} has more than {MAX_SELECTION_MATCHES} inventory matches"
            ));
        }
        match query.rv {
            0 => {
                let Some(result) = query.result else {
                    if !matches!(
                        query.helper_failure,
                        Some(
                            SelectionFailure::NullOutput
                                | SelectionFailure::UnreadableInterface
                                | SelectionFailure::ProviderChanged,
                        )
                    ) {
                        problems.push(format!(
                            "successful selection query {position} has no result"
                        ));
                    }
                    if !query.inventory_matches.is_empty()
                        || query.selection_table.is_some()
                        || !matches!(query.authority, SelectionAuthority::None)
                    {
                        problems.push(format!(
                            "successful selection query {position} has null result cross-fields"
                        ));
                    }
                    continue;
                };
                if query.helper_failure.is_some()
                    && !matches!(query.authority, SelectionAuthority::None)
                {
                    problems.push(format!(
                        "selection query {position} with helper failure has authority"
                    ));
                }
                match query.helper_failure {
                    Some(SelectionFailure::NullOutput | SelectionFailure::UnreadableInterface) => {
                        problems.push(format!(
                            "selection query {position} has an invalid helper failure for a result"
                        ));
                    }
                    Some(SelectionFailure::UnreadableName)
                        if !matches!(
                            result.name,
                            SelectionNameClass::Null | SelectionNameClass::Unreadable
                        ) =>
                    {
                        problems.push(format!(
                            "selection query {position} unreadable-name failure disagrees with result"
                        ));
                    }
                    Some(SelectionFailure::UnreadableVersion)
                        if result.version != SelectionVersionClass::Unreadable =>
                    {
                        problems.push(format!(
                            "selection query {position} unreadable-version failure disagrees with result"
                        ));
                    }
                    Some(SelectionFailure::UnreadableTable)
                        if !matches!(
                            result.version,
                            SelectionVersionClass::Null
                                | SelectionVersionClass::V3_0
                                | SelectionVersionClass::V3_1
                                | SelectionVersionClass::V3_2
                        ) =>
                    {
                        problems.push(format!(
                            "selection query {position} unreadable-table failure disagrees with result"
                        ));
                    }
                    Some(
                        SelectionFailure::UnreadableTable
                        | SelectionFailure::OutsideProvider
                        | SelectionFailure::UnresolvedFunction
                        | SelectionFailure::ProviderChanged,
                    ) if query.selection_table.is_some() => {
                        problems.push(format!(
                            "selection query {position} helper failure has a selection table"
                        ));
                    }
                    _ => {}
                }
                if let Some(table_id) = query.selection_table {
                    let Some(table) = evidence.tables.iter().find(|table| table.id == table_id)
                    else {
                        problems.push(format!(
                            "selection query {position} refers to missing table {table_id}"
                        ));
                        continue;
                    };
                    if !query.inventory_matches.is_empty()
                        || query.helper_failure.is_some()
                        || query.request.name != SelectionNameClass::ExactStandard
                        || !matches!(query.authority, SelectionAuthority::SelectionCountOnly)
                        || result.name != SelectionNameClass::ExactStandard
                        || !matches!(
                            result.version,
                            SelectionVersionClass::V3_0
                                | SelectionVersionClass::V3_1
                                | SelectionVersionClass::V3_2
                        )
                        || !matches!(result.flags, 0 | 1)
                    {
                        problems.push(format!(
                            "selection query {position} has invalid selection-table authority"
                        ));
                    }
                    let result_version = match result.version {
                        SelectionVersionClass::V3_0 => Some(Version { major: 3, minor: 0 }),
                        SelectionVersionClass::V3_1 => Some(Version { major: 3, minor: 1 }),
                        SelectionVersionClass::V3_2 => Some(Version { major: 3, minor: 2 }),
                        _ => None,
                    };
                    if result_version != Some(table.version) {
                        problems.push(format!(
                            "selection query {position} table version disagrees with result"
                        ));
                    }
                    referenced_tables.insert(table_id);
                    let pair = (result.version, result.flags);
                    if let Some(previous) = pair_authority.insert(pair, table_id)
                        && previous != table_id
                    {
                        conflict_pair = true;
                        problems.push(format!(
                            "selection query {position} conflicts for version/flags pair"
                        ));
                    }
                } else if matches!(query.authority, SelectionAuthority::Inventory)
                    && (query.inventory_matches.is_empty()
                        || query.helper_failure.is_some()
                        || !selection_result_readable(&result))
                {
                    problems.push(format!(
                        "selection query {position} has invalid inventory authority"
                    ));
                } else if !query.inventory_matches.is_empty()
                    && query.helper_failure.is_none()
                    && selection_result_readable(&result)
                    && !matches!(query.authority, SelectionAuthority::Inventory)
                {
                    problems.push(format!(
                        "selection query {position} has matches without inventory authority"
                    ));
                } else if matches!(query.authority, SelectionAuthority::SelectionCountOnly) {
                    problems.push(format!(
                        "selection query {position} has count-only authority without a table"
                    ));
                } else if query.helper_failure.is_none()
                    && query.inventory_matches.is_empty()
                    && query.request.name == SelectionNameClass::ExactStandard
                    && result.name == SelectionNameClass::ExactStandard
                    && matches!(
                        result.version,
                        SelectionVersionClass::V3_0
                            | SelectionVersionClass::V3_1
                            | SelectionVersionClass::V3_2
                    )
                    && matches!(result.flags, 0 | 1)
                {
                    let pair = (result.version, result.flags);
                    if pair_authority.contains_key(&pair) {
                        conflict_pair = true;
                    } else {
                        problems.push(format!(
                            "selection query {position} has unexplained selection truncation or conflict"
                        ));
                    }
                }
            }
            _ => {
                if query.result.is_some()
                    || !query.inventory_matches.is_empty()
                    || query.selection_table.is_some()
                    || query.helper_failure.is_some()
                    || !matches!(query.authority, SelectionAuthority::None)
                {
                    problems.push(format!(
                        "nonzero selection query {position} has success-only fields"
                    ));
                }
            }
        }
    }
    for table in &evidence.tables {
        if !referenced_tables.contains(&table.id) {
            problems.push(format!("selection table {} is orphaned", table.id));
        }
    }
    if conflict_pair && !evidence.selection_truncated {
        problems.push("selection semantic-pair conflict is not truncated".into());
    }
    if evidence.selection_truncated
        && !conflict_pair
        && !evidence
            .queries
            .iter()
            .any(|query| query.inventory_matches.len() == MAX_SELECTION_MATCHES)
    {
        problems
            .push("selection truncation has no bounded alias or semantic conflict evidence".into());
    }
}

pub fn validate_structure(m: &Manifest) -> Vec<String> {
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
        validate_identity(
            &format!("object {}", object.id),
            &object.identity,
            &mut problems,
        );
    }
    if m.objects
        .first()
        .is_some_and(|object| object.path != m.module_path)
    {
        problems.push("object id 0 path must equal module_path".into());
    }

    if m.provenance_objects.is_empty() || m.provenance_objects.len() > MAX_OBJECTS {
        problems.push(format!(
            "manifest has {} provenance objects; expected 1..={MAX_OBJECTS}",
            m.provenance_objects.len()
        ));
    }
    let mut provenance_keys = BTreeSet::new();
    let mut provenance_paths = BTreeSet::new();
    for object in &m.provenance_objects {
        bounded(
            "provenance object path",
            &object.path,
            MAX_PATH_BYTES,
            &mut problems,
        );
        if !Path::new(&object.path).is_absolute() {
            problems.push(format!(
                "provenance object path must be absolute: {:?}",
                object.path
            ));
        }
        if object.inode == 0 {
            problems.push(format!(
                "provenance object {:?} has a zero inode",
                object.path
            ));
        }
        if !provenance_keys.insert((object.device_major, object.device_minor, object.inode)) {
            problems.push("duplicate provenance device/inode".into());
        }
        if !provenance_paths.insert(object.path.as_str()) {
            problems.push(format!(
                "duplicate provenance object path {:?}",
                object.path
            ));
        }
        validate_identity(
            &format!("provenance object {:?}", object.path),
            &object.identity,
            &mut problems,
        );
    }
    for object in &m.objects {
        let Some(sha256) = object.identity.sha256.as_deref() else {
            // `validate_identity` already gives the precise unusable-identity
            // diagnostic. Provenance relation is meaningful only for a digest.
            continue;
        };
        if let Some(provenance) = m
            .provenance_objects
            .iter()
            .find(|provenance| provenance.path == object.path)
        {
            if provenance.identity.sha256.as_deref() != Some(sha256) {
                problems.push(format!(
                    "object {} and its path-matched provenance object have different identities",
                    object.id
                ));
            }
            continue;
        }
        let matches = m
            .provenance_objects
            .iter()
            .filter(|provenance| provenance.identity.sha256.as_deref() == Some(sha256))
            .count();
        match matches {
            0 => problems.push(format!(
                "object {} identity is absent from the executable provenance closure",
                object.id
            )),
            1 => {}
            _ => problems.push(format!(
                "object {} identity matches multiple provenance objects without an exact path",
                object.id
            )),
        }
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
    validate_selection_evidence(
        &m.selection_evidence,
        &m.surfaces,
        &object_ids,
        &mut problems,
    );
    problems
}
