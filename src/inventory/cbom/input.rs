//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Bounded CBOM input: one saved inventory or profile document.
//!
//! The byte, depth, string and node bounds are exactly the offline
//! `inventory diff` reader's; unknown additive input is bounded and
//! ignored, never copied through. Malformed rows degrade to counted,
//! named unknowns; only a missing or unsupported top-level schema
//! fails the conversion.

use anyhow::{Context as _, Result, ensure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;

#[cfg(test)]
use crate::inventory_diff::input::parse_bounded_value;
use crate::inventory_diff::input::{InputLimits, read_bounded_value};

pub(super) const SCHEMA_INVENTORY_V1: &str = "p11scope/inventory/v1";
pub(super) const SCHEMA_PROFILE_V3: &str = "p11scope/observed-profile/v3";
pub(super) const SCHEMA_PROFILE_V2: &str = "p11scope/observed-profile/v2";

/// Joined display lists keep this many entries before a `+N more` tail;
/// counts stay exact either way.
pub(super) const JOIN_LIMIT: usize = 32;
/// Text views name this many applications/providers before a `+N more` line.
pub(super) const TEXT_LIST_LIMIT: usize = 8;

pub(super) struct LoadedInput {
    pub projection: Projection,
    pub source: File,
}

pub(super) fn read_input(path: &Path) -> Result<LoadedInput> {
    let limits = InputLimits::default();
    let (value, source) = read_bounded_value(path, limits)?;
    let projection = convert_value(&value, limits)?;
    Ok(LoadedInput { projection, source })
}

#[cfg(test)]
pub(super) fn parse_input(bytes: &[u8]) -> Result<Projection> {
    let limits = InputLimits::default();
    let value = parse_bounded_value(bytes, limits)?;
    convert_value(&value, limits)
}

#[cfg(test)]
pub(super) fn parse_input_with_limits(bytes: &[u8], limits: InputLimits) -> Result<Projection> {
    let value = parse_bounded_value(bytes, limits)?;
    convert_value(&value, limits)
}

#[derive(Debug, Default)]
pub(super) struct Unknowns {
    pub callers_unknown_exe: u64,
    pub callers_skipped: u64,
    pub modules_skipped: u64,
    pub modules_invalid_digest: u64,
    pub dangling_edge_refs: u64,
    pub edges_without_mechanisms: u64,
    pub mechanisms_unnamed: u64,
    pub mechanisms_unknown_primitive: u64,
    pub keys_unknown_size: u64,
    pub keys_unknown_type: u64,
    pub keys_unjoinable: u64,
    pub objects_skipped_non_key: u64,
    /// Folded identities past the per-module/run-wide bounds, summed.
    pub departed_identities_dropped: u64,
    /// Modules whose folded identity list saturated, counted.
    pub departed_identities_saturated: u64,
    /// Folded mechanism rows past the bounds, with their calls/errors.
    pub departed_mechs_overflow: u64,
    pub departed_mechs_overflow_calls: u64,
    pub departed_mechs_overflow_errors: u64,
    /// Modules whose folded app-to-mechanism pairs stay unlinked: the
    /// fold keeps per-module totals, not caller x mechanism pairs.
    pub departed_links_withheld: u64,
}

#[derive(Debug)]
pub(super) struct Application {
    pub path: String,
    pub incarnations: u64,
    /// Incarnations rejoined from `departed_use` aggregates (0 for
    /// live-only applications); part of `incarnations`.
    pub departed_incarnations: u64,
    pub lifecycles: Vec<String>,
    pub bom_ref: String,
}

#[derive(Debug)]
pub(super) struct Provider {
    pub name: String,
    pub sha256: Option<String>,
    pub build_id: Option<String>,
    pub admission: Option<String>,
    pub lifecycle: Option<String>,
    pub device: Option<String>,
    pub inode: Option<u64>,
    pub endpoints: Option<u64>,
    /// Task 7 `CK_INFO.manufacturerID`: `None` without a completed
    /// `C_GetInfo` or when the field was refused (non-UTF8).
    pub supplier: Option<String>,
    /// Task 7 `<library major>.<library minor>`, when published.
    pub library_version: Option<String>,
    pub bom_ref: String,
}

/// Dedup key for Task 7 token devices: one device per (module,
/// slot, token identity).
type TokenIdentityKey = (
    String,
    u64,
    Option<String>,
    Option<String>,
    String,
    String,
    u64,
    u64,
    u64,
);

/// One Task 7 per-(module, caller, slot) token row: manufacturer,
/// model, versions, flags and PIN lengths. Serials, labels, session
/// counts, memory sizes and clock readings never reach this struct
/// (no such key exists in the section contract).
#[derive(Debug)]
pub(super) struct TokenDevice {
    pub name: String,
    pub hardware: String,
    pub firmware: String,
    pub flags: u64,
    pub pin_min_len: u64,
    pub pin_max_len: u64,
    pub slot: u64,
    pub bom_ref: String,
}

/// One Task 7 per-(module, caller, slot) mechanism-limit reporter.
#[derive(Debug, Clone)]
pub(super) struct MechanismLimit {
    pub module: String,
    pub caller: String,
    pub slot: u64,
    pub min_key_size: u64,
    pub max_key_size: u64,
    pub flags: u64,
}

#[derive(Debug)]
pub(super) struct Mechanism {
    pub id: u64,
    pub name: Option<String>,
    pub calls: u64,
    pub errors: u64,
    pub operations: Vec<String>,
    pub functions: Vec<String>,
    pub returns: Vec<String>,
    pub rows: u64,
    /// Task 7 per-reporter limits for this mechanism id.
    pub limits: Vec<MechanismLimit>,
    /// True when no edge/profile row claimed this id: the component
    /// is minted from provider-reported limits alone.
    pub limit_only: bool,
    pub bom_ref: String,
}

#[derive(Debug)]
pub(super) struct KeyObject {
    pub object: u64,
    pub label: Option<String>,
    pub key_type: Option<u64>,
    pub class: Option<u64>,
    pub size_bits: Option<u64>,
    pub curve: Option<String>,
    pub token: Option<u64>,
    pub creation: Option<String>,
    pub references: u64,
    pub bom_ref: String,
}

#[derive(Debug, Default)]
pub(super) struct Projection {
    pub source_schema: String,
    pub scope_note: Option<String>,
    pub window_note: Option<String>,
    pub passes: Option<u64>,
    pub gap_count: u64,
    pub gaps_suppressed: u64,
    pub gap_subjects: Vec<String>,
    pub object_observations: String,
    pub profile_note: Option<String>,
    pub completeness: Option<String>,
    pub applications: Vec<Application>,
    pub providers: Vec<Provider>,
    pub mechanisms: Vec<Mechanism>,
    pub keys: Vec<KeyObject>,
    /// Task 7 token devices, in input row order.
    pub tokens: Vec<TokenDevice>,
    /// Proven joins only: (from `bom_ref`, to `bom_ref`).
    pub dependencies: Vec<(String, String)>,
    pub unknowns: Unknowns,
}

fn str_of(value: &Value) -> Option<&str> {
    value.as_str()
}

fn u64_of(value: &Value) -> Option<u64> {
    value.as_u64()
}

/// `<major>.<minor>` dotted version from two numeric keys.
fn dotted_version(row: &Value, major: &str, minor: &str) -> Option<String> {
    let major = row.get(major).and_then(u64_of)?;
    let minor = row.get(minor).and_then(u64_of)?;
    Some(format!("{major}.{minor}"))
}

/// Combined converted-row count, under the shared per-input row bound.
/// Top-level row arrays plus nested mechanism and key rows; unknown
/// additive subtrees are bounded by the parse, never converted.
fn count_rows(value: &Value, limits: InputLimits) -> Result<()> {
    let mut rows = 0usize;
    let mut add = |count: usize| -> Result<()> {
        rows = rows
            .checked_add(count)
            .context("inventory row limit overflow")?;
        Ok(())
    };
    for key in [
        "callers",
        "modules",
        "edges",
        "semantic_edges",
        "instances",
        "mechanisms",
        "gaps",
        "functions",
    ] {
        add(value
            .get(key)
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0))?;
    }
    for edge in arr_of(value, "edges")
        .into_iter()
        .chain(arr_of(value, "semantic_edges"))
    {
        add(edge
            .get("mechanisms")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0))?;
    }
    // Folded rows convert like live rows, so they count the same way.
    for module in arr_of(value, "modules") {
        let Some(departed) = module.get("departed_use") else {
            continue;
        };
        for key in ["identities", "mechanisms"] {
            add(departed
                .get(key)
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0))?;
        }
    }
    if let Some(section) = value.get("object_observations") {
        for key in [
            "sessions",
            "objects",
            "key_operations",
            "unknown_key_operations",
        ] {
            add(section
                .get(key)
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0))?;
        }
    }
    if let Some(section) = value.get("provider_observations") {
        for key in ["tokens", "mechanisms"] {
            add(section
                .get(key)
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0))?;
        }
    }
    ensure!(
        rows <= limits.rows,
        "inventory row limit exceeded ({})",
        limits.rows
    );
    Ok(())
}

fn arr_of<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

pub(super) fn join_bounded(items: &BTreeSet<String>, limit: usize) -> String {
    let mut parts: Vec<String> = items.iter().take(limit).cloned().collect();
    if items.len() > limit {
        parts.push(format!("+{} more", items.len() - limit));
    }
    parts.join(",")
}

fn convert_value(value: &Value, limits: InputLimits) -> Result<Projection> {
    let schema = value
        .get("schema")
        .and_then(str_of)
        .context("CBOM input has no schema string")?;
    count_rows(value, limits)?;
    match schema {
        SCHEMA_INVENTORY_V1 => convert_inventory(value),
        SCHEMA_PROFILE_V3 | SCHEMA_PROFILE_V2 => convert_profile(value, schema),
        other => anyhow::bail!("unsupported CBOM input schema: {other}"),
    }
}

fn convert_inventory(value: &Value) -> Result<Projection> {
    let mut out = Projection {
        source_schema: SCHEMA_INVENTORY_V1.to_string(),
        ..Projection::default()
    };
    out.scope_note = value.get("scope").and_then(str_of).map(str::to_string);
    if let Some(observation) = value.get("observation") {
        let started = observation.get("started_ns").and_then(u64_of);
        let ended = observation.get("ended_ns").and_then(u64_of);
        if let (Some(started), Some(ended)) = (started, ended) {
            out.window_note = Some(format!("{started}..{ended} (CLOCK_MONOTONIC ns)"));
        }
        out.passes = observation.get("passes").and_then(u64_of);
    }
    let gaps = arr_of(value, "gaps");
    out.gap_count = gaps.len() as u64;
    out.gaps_suppressed = value.get("gaps_suppressed").and_then(u64_of).unwrap_or(0);
    let mut subjects = BTreeSet::new();
    for gap in gaps {
        if let Some(subject) = gap.get("subject").and_then(str_of) {
            subjects.insert(subject.to_string());
        }
    }
    out.gap_subjects = subjects.into_iter().collect();

    // Callers group by executable path; pathless incarnations stay counted.
    let mut caller_known: BTreeSet<String> = BTreeSet::new();
    let mut app_order: Vec<String> = Vec::new();
    let mut app_incarnations: BTreeMap<String, u64> = BTreeMap::new();
    let mut app_lifecycles: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut caller_app: BTreeMap<String, String> = BTreeMap::new();
    for caller in arr_of(value, "callers") {
        let Some(id) = caller.get("id").and_then(str_of) else {
            out.unknowns.callers_skipped += 1;
            continue;
        };
        caller_known.insert(id.to_string());
        let path = caller
            .get("image")
            .and_then(|image| image.get("exe"))
            .and_then(|exe| exe.get("path"))
            .and_then(str_of)
            .filter(|path| !path.is_empty());
        let Some(path) = path else {
            out.unknowns.callers_unknown_exe += 1;
            continue;
        };
        caller_app.insert(id.to_string(), path.to_string());
        if !app_incarnations.contains_key(path) {
            app_order.push(path.to_string());
        }
        *app_incarnations.entry(path.to_string()).or_insert(0) += 1;
        if let Some(lifecycle) = caller.get("lifecycle").and_then(str_of) {
            app_lifecycles
                .entry(path.to_string())
                .or_default()
                .insert(lifecycle.to_string());
        }
    }
    // Folded callers rejoin the same grouping: one component per
    // distinct executable path, incarnations counted, lifecycles
    // unioned. A present-but-unreadable aggregate stays unread, like
    // any unknown additive subtree.
    let mut app_departed: BTreeMap<String, u64> = BTreeMap::new();
    for module in arr_of(value, "modules") {
        let Some(departed) = module.get("departed_use").and_then(Value::as_object) else {
            continue;
        };
        out.unknowns.departed_identities_dropped =
            out.unknowns.departed_identities_dropped.saturating_add(
                departed
                    .get("identities_dropped")
                    .and_then(u64_of)
                    .unwrap_or(0),
            );
        if departed
            .get("identities_saturated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            out.unknowns.departed_identities_saturated += 1;
        }
        let Some(identities) = departed.get("identities").and_then(Value::as_array) else {
            continue;
        };
        for identity in identities {
            if identity.get("caller").and_then(str_of).is_none() {
                out.unknowns.callers_skipped += 1;
                continue;
            }
            let path = identity
                .get("exe")
                .and_then(|exe| exe.get("path"))
                .and_then(str_of)
                .filter(|path| !path.is_empty());
            let Some(path) = path else {
                out.unknowns.callers_unknown_exe += 1;
                continue;
            };
            if !app_incarnations.contains_key(path) {
                app_order.push(path.to_string());
            }
            *app_incarnations.entry(path.to_string()).or_insert(0) += 1;
            *app_departed.entry(path.to_string()).or_insert(0) += 1;
            if let Some(lifecycle) = identity.get("lifecycle").and_then(str_of) {
                app_lifecycles
                    .entry(path.to_string())
                    .or_default()
                    .insert(lifecycle.to_string());
            }
        }
    }
    for (index, path) in app_order.iter().enumerate() {
        out.applications.push(Application {
            path: path.clone(),
            incarnations: app_incarnations.get(path).copied().unwrap_or(0),
            departed_incarnations: app_departed.get(path).copied().unwrap_or(0),
            lifecycles: app_lifecycles
                .get(path)
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default(),
            bom_ref: format!("p11scope:caller:{index}"),
        });
    }
    let app_ref_of = |path: &str| -> Option<String> {
        app_order
            .iter()
            .position(|known| known == path)
            .map(|index| format!("p11scope:caller:{index}"))
    };

    // Modules keep input order; identity fields stay verbatim.
    let mut module_ref: BTreeMap<String, String> = BTreeMap::new();
    for (index, module) in arr_of(value, "modules").iter().enumerate() {
        let Some(id) = module.get("id").and_then(str_of) else {
            out.unknowns.modules_skipped += 1;
            continue;
        };
        let bom_ref = format!("p11scope:module:{index}");
        module_ref.insert(id.to_string(), bom_ref.clone());
        let name = module
            .get("paths")
            .and_then(Value::as_array)
            .and_then(|paths| paths.iter().filter_map(str_of).next())
            .map(str::to_string)
            .unwrap_or_else(|| format!("module {id}"));
        let identity = module.get("identity");
        let sha256 = identity
            .and_then(|identity| identity.get("sha256"))
            .and_then(str_of)
            .map(str::to_string);
        if let Some(digest) = &sha256
            && !(digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            out.unknowns.modules_invalid_digest += 1;
        }
        let sha256 = sha256.filter(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
        let build_id = identity
            .and_then(|identity| identity.get("build_id"))
            .and_then(str_of)
            .map(str::to_string);
        let admission = module.get("admission").map(|admission| {
            let state = admission.get("state").and_then(str_of).unwrap_or("unknown");
            let class = admission.get("class").and_then(str_of).unwrap_or("unknown");
            format!("{state}/{class}")
        });
        let lifecycle = module.get("lifecycle").and_then(str_of).map(str::to_string);
        let device = identity
            .and_then(|identity| identity.get("device"))
            .and_then(|device| {
                let major = device.get("major").and_then(u64_of)?;
                let minor = device.get("minor").and_then(u64_of)?;
                Some(format!("{major}:{minor}"))
            });
        let inode = identity
            .and_then(|identity| identity.get("inode"))
            .and_then(u64_of);
        let endpoints = module
            .get("admission")
            .and_then(|admission| admission.get("endpoints"))
            .and_then(u64_of);
        // Task 7: a refused (null) manufacturer omits the supplier;
        // malformed provider_info degrades to no supplier/version
        // while the component itself still renders.
        let provider_info = module.get("provider_info");
        let supplier = provider_info
            .and_then(|info| info.get("manufacturer"))
            .and_then(str_of)
            .map(str::to_string);
        let library_version = provider_info.and_then(|info| {
            let major = info.get("library_major").and_then(u64_of)?;
            let minor = info.get("library_minor").and_then(u64_of)?;
            Some(format!("{major}.{minor}"))
        });
        out.providers.push(Provider {
            name,
            sha256,
            build_id,
            admission,
            lifecycle,
            device,
            inode,
            endpoints,
            supplier,
            library_version,
            bom_ref,
        });
    }

    // Mechanisms union by id across physical and semantic edges.
    #[derive(Default)]
    struct MechAccum {
        name: Option<String>,
        calls: u64,
        errors: u64,
        operations: BTreeSet<String>,
        functions: BTreeSet<String>,
        returns: BTreeSet<String>,
        rows: u64,
        callers: BTreeSet<String>,
        modules: BTreeSet<String>,
    }
    let mut mechs: BTreeMap<u64, MechAccum> = BTreeMap::new();
    let mut edges_seen = 0u64;
    let mut edges_with_mechanisms = 0u64;
    // One mechanism row in the edge-row shape, live or folded: counts
    // sum, categories and provenance union. Attribution stays with the
    // caller: live rows join their edge, folded rows their aggregate.
    let fold_mech_row = |row: &Value, entry: &mut MechAccum| {
        entry.rows += 1;
        if entry.name.is_none() {
            entry.name = row.get("name").and_then(str_of).map(str::to_string);
        }
        entry.calls = entry
            .calls
            .saturating_add(row.get("calls").and_then(u64_of).unwrap_or(0));
        entry.errors = entry
            .errors
            .saturating_add(row.get("errors").and_then(u64_of).unwrap_or(0));
        for op in arr_of(row, "operations") {
            if let Some(op) = str_of(op) {
                entry.operations.insert(op.to_string());
            }
        }
        if let Some(evidence) = row.get("evidence") {
            for function in arr_of(evidence, "functions") {
                if let Some(function) = str_of(function) {
                    entry.functions.insert(function.to_string());
                }
            }
            for ret in arr_of(evidence, "returns") {
                let label = ret
                    .get("name")
                    .and_then(str_of)
                    .map(str::to_string)
                    .or_else(|| ret.get("rv_hex").and_then(str_of).map(str::to_string))
                    .or_else(|| ret.get("rv").and_then(u64_of).map(|rv| format!("rv {rv}")));
                if let Some(label) = label {
                    entry.returns.insert(label);
                }
            }
        }
    };
    let mut fold_edge = |edge: &Value, out: &mut Projection| {
        let caller = edge.get("caller").and_then(str_of);
        let module = edge.get("module").and_then(str_of);
        let (Some(caller), Some(module)) = (caller, module) else {
            out.unknowns.dangling_edge_refs += 1;
            return;
        };
        if !caller_known.contains(caller) || !module_ref.contains_key(module) {
            out.unknowns.dangling_edge_refs += 1;
            return;
        }
        edges_seen += 1;
        // The observed mapping itself joins application and provider,
        // even when this edge carries no mechanism claims.
        if let (Some(app_path), Some(provider)) = (caller_app.get(caller), module_ref.get(module))
            && let Some(app) = app_ref_of(app_path)
        {
            add_dependency(&mut out.dependencies, &app, provider);
        }
        let rows = edge
            .get("mechanisms")
            .and_then(Value::as_array)
            .map(|items| items.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        if rows.is_empty() {
            return;
        }
        edges_with_mechanisms += 1;
        let app = caller_app.get(caller).cloned();
        let provider = module_ref.get(module).cloned();
        for row in rows {
            let Some(id) = row.get("mechanism").and_then(u64_of) else {
                continue;
            };
            let entry = mechs.entry(id).or_default();
            fold_mech_row(row, entry);
            if let Some(app) = &app {
                entry.callers.insert(app.clone());
            }
            if let Some(provider) = &provider {
                entry.modules.insert(provider.clone());
            }
        }
    };
    for edge in arr_of(value, "edges") {
        fold_edge(edge, &mut out);
    }
    for edge in arr_of(value, "semantic_edges") {
        fold_edge(edge, &mut out);
    }
    // Folded mechanism rows merge into the same per-id totals: the
    // fold preserves the edge-row shape. Overflow rows past the
    // bounds have no id to merge under, so their sums stay named
    // unknowns instead.
    for module in arr_of(value, "modules") {
        let Some(id) = module.get("id").and_then(str_of) else {
            continue;
        };
        let Some(provider) = module_ref.get(id).cloned() else {
            continue;
        };
        let Some(departed) = module.get("departed_use").and_then(Value::as_object) else {
            continue;
        };
        if let Some(overflow) = departed
            .get("mechanisms_overflow")
            .and_then(Value::as_object)
        {
            out.unknowns.departed_mechs_overflow = out
                .unknowns
                .departed_mechs_overflow
                .saturating_add(overflow.get("mechs").and_then(u64_of).unwrap_or(0));
            out.unknowns.departed_mechs_overflow_calls = out
                .unknowns
                .departed_mechs_overflow_calls
                .saturating_add(overflow.get("calls").and_then(u64_of).unwrap_or(0));
            out.unknowns.departed_mechs_overflow_errors = out
                .unknowns
                .departed_mechs_overflow_errors
                .saturating_add(overflow.get("errors").and_then(u64_of).unwrap_or(0));
        }
        let identities = departed
            .get("identities")
            .and_then(Value::as_array)
            .map(|items| items.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut named = 0u64;
        let mut paths = BTreeSet::new();
        let mut all_named_have_paths = true;
        for identity in &identities {
            if identity.get("caller").and_then(str_of).is_none() {
                continue;
            }
            named += 1;
            match identity
                .get("exe")
                .and_then(|exe| exe.get("path"))
                .and_then(str_of)
                .filter(|path| !path.is_empty())
            {
                Some(path) => {
                    paths.insert(path.to_string());
                }
                None => {
                    all_named_have_paths = false;
                }
            }
        }
        // The folded mapping joins each departed application to this
        // provider, exactly like a live edge with no mechanism claims.
        for path in &paths {
            if let Some(app) = app_ref_of(path) {
                add_dependency(&mut out.dependencies, &app, &provider);
            }
        }
        let rows = departed
            .get("mechanisms")
            .and_then(Value::as_array)
            .map(|items| items.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        if rows.is_empty() {
            continue;
        }
        // Per-app mechanism pairs survive the fold only when every
        // folded caller is named and all share one executable path;
        // otherwise the pairs are withheld, never guessed.
        let callers = departed.get("callers").and_then(u64_of).unwrap_or(0);
        let dropped = departed
            .get("identities_dropped")
            .and_then(u64_of)
            .unwrap_or(0);
        let saturated = departed
            .get("identities_saturated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let complete = !saturated && dropped == 0 && named > 0 && named == callers;
        let single_app = if complete && all_named_have_paths && paths.len() == 1 {
            paths.iter().next().cloned()
        } else {
            None
        };
        if paths.len() > 1 {
            out.unknowns.departed_links_withheld += 1;
        }
        for row in rows {
            let Some(id) = row.get("mechanism").and_then(u64_of) else {
                continue;
            };
            let entry = mechs.entry(id).or_default();
            fold_mech_row(row, entry);
            if let Some(app) = &single_app {
                entry.callers.insert(app.clone());
            }
            entry.modules.insert(provider.clone());
        }
    }
    out.unknowns.edges_without_mechanisms = edges_seen.saturating_sub(edges_with_mechanisms);
    for (id, accum) in &mechs {
        let bom_ref = format!("p11scope:mechanism:0x{id:x}");
        if accum.name.is_none() {
            out.unknowns.mechanisms_unnamed += 1;
        }
        let operations: Vec<String> = accum.operations.iter().cloned().collect();
        out.mechanisms.push(Mechanism {
            id: *id,
            name: accum.name.clone(),
            calls: accum.calls,
            errors: accum.errors,
            operations,
            functions: accum.functions.iter().cloned().collect(),
            returns: accum.returns.iter().cloned().collect(),
            rows: accum.rows,
            limits: Vec::new(),
            limit_only: false,
            bom_ref: bom_ref.clone(),
        });
        for app_path in &accum.callers {
            if let Some(app) = app_ref_of(app_path) {
                add_dependency(&mut out.dependencies, &app, &bom_ref);
            }
        }
        for provider in &accum.modules {
            add_dependency(&mut out.dependencies, provider, &bom_ref);
        }
    }

    // Task 7 provider/token/mechanism rows (section version 8).
    // Unknown section versions refuse the conversion, never guess.
    if let Some(section) = value.get("provider_observations") {
        let version = section.get("version").and_then(u64_of);
        ensure!(
            version == Some(8),
            "unsupported provider_observations section version: {}",
            version
                .map(|version| version.to_string())
                .unwrap_or_else(|| "missing".to_string())
        );
        // One device per (module, slot, token identity): callers
        // reporting the same token share it, while a conflicting
        // identity on the same slot keeps its own device (slot ids
        // are per-process).
        let mut seen_tokens: BTreeSet<TokenIdentityKey> = BTreeSet::new();
        for row in arr_of(section, "tokens") {
            let (Some(module), Some(caller)) = (
                row.get("module").and_then(str_of),
                row.get("caller").and_then(str_of),
            ) else {
                continue;
            };
            let (Some(provider), true) = (module_ref.get(module), caller_known.contains(caller))
            else {
                out.unknowns.dangling_edge_refs += 1;
                continue;
            };
            let (
                Some(slot),
                Some(hardware),
                Some(firmware),
                Some(flags),
                Some(pin_min),
                Some(pin_max),
            ) = (
                row.get("slot").and_then(u64_of),
                dotted_version(row, "hardware_major", "hardware_minor"),
                dotted_version(row, "firmware_major", "firmware_minor"),
                row.get("flags").and_then(u64_of),
                row.get("pin_min_len").and_then(u64_of),
                row.get("pin_max_len").and_then(u64_of),
            )
            else {
                continue;
            };
            let manufacturer = row.get("manufacturer").and_then(str_of).map(str::to_string);
            let model = row.get("model").and_then(str_of).map(str::to_string);
            if !seen_tokens.insert((
                module.to_string(),
                slot,
                manufacturer.clone(),
                model.clone(),
                hardware.clone(),
                firmware.clone(),
                flags,
                pin_min,
                pin_max,
            )) {
                continue;
            }
            let mut parts = Vec::new();
            if let Some(manufacturer) = &manufacturer {
                parts.push(manufacturer.clone());
            }
            if let Some(model) = &model {
                parts.push(model.clone());
            }
            let name = if parts.is_empty() {
                format!("token slot {slot}")
            } else {
                parts.join(" ")
            };
            let bom_ref = format!("p11scope:token:{}", out.tokens.len());
            add_dependency(&mut out.dependencies, &bom_ref, provider);
            out.tokens.push(TokenDevice {
                name,
                hardware,
                firmware,
                flags,
                pin_min_len: pin_min,
                pin_max_len: pin_max,
                slot,
                bom_ref,
            });
        }
        // Mechanism limits group by id; reporters keep input order
        // here and the renderer sorts them deterministically.
        let mut limits: BTreeMap<u64, Vec<MechanismLimit>> = BTreeMap::new();
        for row in arr_of(section, "mechanisms") {
            let (Some(module), Some(caller), Some(id)) = (
                row.get("module").and_then(str_of),
                row.get("caller").and_then(str_of),
                row.get("mechanism").and_then(u64_of),
            ) else {
                continue;
            };
            if !caller_known.contains(caller) || !module_ref.contains_key(module) {
                out.unknowns.dangling_edge_refs += 1;
                continue;
            }
            let (Some(min), Some(max), Some(flags)) = (
                row.get("min_key_size").and_then(u64_of),
                row.get("max_key_size").and_then(u64_of),
                row.get("flags").and_then(u64_of),
            ) else {
                continue;
            };
            let Some(slot) = row.get("slot").and_then(u64_of) else {
                continue;
            };
            limits.entry(id).or_default().push(MechanismLimit {
                module: module.to_string(),
                caller: caller.to_string(),
                slot,
                min_key_size: min,
                max_key_size: max,
                flags,
            });
        }
        for (id, reporters) in &limits {
            if let Some(mechanism) = out.mechanisms.iter_mut().find(|row| row.id == *id) {
                mechanism.limits.clone_from(reporters);
            } else {
                out.mechanisms.push(Mechanism {
                    id: *id,
                    name: None,
                    calls: 0,
                    errors: 0,
                    operations: Vec::new(),
                    functions: Vec::new(),
                    returns: Vec::new(),
                    rows: 0,
                    limits: reporters.clone(),
                    limit_only: true,
                    bom_ref: format!("p11scope:mechanism:0x{id:x}"),
                });
            }
        }
        out.mechanisms.sort_by_key(|mechanism| mechanism.id);
    }

    // Instances join key operations to their caller and module.
    let mut instance_module: BTreeMap<String, String> = BTreeMap::new();
    let mut instance_caller: BTreeMap<String, String> = BTreeMap::new();
    for instance in arr_of(value, "instances") {
        let (Some(id), Some(caller), Some(module)) = (
            instance.get("id").and_then(str_of),
            instance.get("caller").and_then(str_of),
            instance.get("module").and_then(str_of),
        ) else {
            continue;
        };
        if let Some(provider) = module_ref.get(module) {
            instance_module.insert(id.to_string(), provider.clone());
        }
        if let Some(app_path) = caller_app.get(caller)
            && let Some(app) = app_ref_of(app_path)
        {
            instance_caller.insert(id.to_string(), app);
        }
    }

    // Key objects: established facts only; requested values never qualify.
    let observations = value.get("object_observations");
    out.object_observations = match observations {
        None => "absent".to_string(),
        Some(section) => {
            let status = section.get("status").and_then(str_of).unwrap_or("unknown");
            let reason = section.get("reason").and_then(str_of).unwrap_or("unknown");
            if status == "populated" {
                "populated".to_string()
            } else {
                format!("{status} ({reason})")
            }
        }
    };
    let mut key_use: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    if let Some(section) = observations {
        for row in arr_of(section, "key_operations") {
            let (Some(object), Some(instance)) = (
                row.get("object").and_then(u64_of),
                row.get("instance").and_then(str_of),
            ) else {
                continue;
            };
            key_use
                .entry(object)
                .or_default()
                .push(instance.to_string());
        }
    }
    if let Some(section) = observations {
        for object in arr_of(section, "objects") {
            let Some(id) = object.get("object").and_then(u64_of) else {
                continue;
            };
            let established = object.get("established");
            let class = established_value(established, "class");
            let key_type = established_value(established, "key_type");
            let label = object.get("label").and_then(str_of).map(str::to_string);
            let used_as_key = key_use.contains_key(&id);
            let is_key_class = matches!(class, Some(2) | Some(3) | Some(4));
            if !is_key_class && label.is_none() && !used_as_key {
                out.unknowns.objects_skipped_non_key += 1;
                continue;
            }
            let size_bits = established_value(established, "modulus_bits").or_else(|| {
                established_value(established, "value_len").and_then(|len| len.checked_mul(8))
            });
            if size_bits.is_none() {
                out.unknowns.keys_unknown_size += 1;
            }
            if !matches!(class, Some(2) | Some(3) | Some(4)) {
                out.unknowns.keys_unknown_type += 1;
            }
            let curve = established
                .and_then(|block| block.get("ec_params"))
                .and_then(|slot| {
                    if slot.get("status").and_then(str_of) == Some("value") {
                        slot.get("value").and_then(str_of).map(str::to_string)
                    } else {
                        None
                    }
                });
            let token = established_value(established, "token");
            let creation = object.get("creation").and_then(str_of).map(str::to_string);
            let references = object
                .get("successful_key_references")
                .and_then(u64_of)
                .unwrap_or(0);
            let bom_ref = format!("p11scope:key:{id}");
            let mut joined = false;
            if let Some(instances) = key_use.get(&id) {
                for instance in instances {
                    if let Some(provider) = instance_module.get(instance) {
                        add_dependency(&mut out.dependencies, &bom_ref, provider);
                        joined = true;
                    }
                    if let Some(app) = instance_caller.get(instance) {
                        add_dependency(&mut out.dependencies, &bom_ref, app);
                        joined = true;
                    }
                }
            }
            if !joined {
                out.unknowns.keys_unjoinable += 1;
            }
            out.keys.push(KeyObject {
                object: id,
                label,
                key_type,
                class,
                size_bits,
                curve,
                token,
                creation,
                references,
                bom_ref,
            });
        }
    }

    // Count unknown primitives after the classifier ran.
    // Limit-only mechanisms are provider-reported support, not
    // observed uses without a name, so they stay out of this count.
    for mechanism in &out.mechanisms {
        if mechanism.limit_only {
            continue;
        }
        let operations = mechanism.operations.clone();
        let classified =
            super::classify::classify(mechanism.name.as_deref().unwrap_or(""), &operations);
        if classified
            .primitive
            .is_none_or(|primitive| primitive == "unknown")
        {
            out.unknowns.mechanisms_unknown_primitive += 1;
        }
    }

    out.dependencies.sort();
    out.dependencies.dedup();
    Ok(out)
}

/// Established metadata slot: `status == "value"` with a numeric code.
/// Requested, conflicting and invalidated slots never qualify.
fn established_value(block: Option<&Value>, slot: &str) -> Option<u64> {
    let slot = block?.get(slot)?;
    if slot.get("status").and_then(str_of) != Some("value") {
        return None;
    }
    slot.get("value").and_then(u64_of)
}

fn add_dependency(dependencies: &mut Vec<(String, String)>, from: &str, to: &str) {
    if from != to {
        dependencies.push((from.to_string(), to.to_string()));
    }
}

fn convert_profile(value: &Value, schema: &str) -> Result<Projection> {
    let mut out = Projection {
        source_schema: schema.to_string(),
        ..Projection::default()
    };
    out.profile_note = Some(
        "profile input: mechanisms are capture-global, without caller, usage-edge or key linkage"
            .to_string(),
    );
    out.object_observations = "absent".to_string();
    let capture = value.get("capture");
    if let Some(capture) = capture {
        let start = capture.get("start").and_then(str_of);
        let end = capture.get("end").and_then(str_of);
        if let (Some(start), Some(end)) = (start, end) {
            out.window_note = Some(format!("{start}..{end} (capture wall clock)"));
        }
        for (index, module) in arr_of(capture, "modules").iter().enumerate() {
            let name = module
                .get("path")
                .and_then(str_of)
                .map(str::to_string)
                .unwrap_or_else(|| format!("module {index}"));
            let sha256 = module
                .get("sha256")
                .and_then(str_of)
                .map(str::to_string)
                .filter(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
            if module.get("sha256").and_then(str_of).is_some() && sha256.is_none() {
                out.unknowns.modules_invalid_digest += 1;
            }
            let build_id = module.get("build_id").and_then(str_of).map(str::to_string);
            let device = module.get("dev").and_then(Value::as_array).and_then(|dev| {
                let major = dev.first().and_then(u64_of)?;
                let minor = dev.get(1).and_then(u64_of)?;
                Some(format!("{major}:{minor}"))
            });
            let inode = module.get("ino").and_then(u64_of);
            out.providers.push(Provider {
                name,
                sha256,
                build_id,
                admission: None,
                lifecycle: None,
                device,
                inode,
                endpoints: None,
                supplier: None,
                library_version: None,
                bom_ref: format!("p11scope:module:{index}"),
            });
        }
    }
    if let Some(evidence) = value.get("evidence") {
        out.completeness = evidence
            .get("completeness")
            .and_then(str_of)
            .map(str::to_string);
    }
    let mut mechs: BTreeMap<u64, (u64, u64, BTreeSet<String>, u64)> = BTreeMap::new();
    for row in arr_of(value, "mechanisms") {
        let Some(id) = row.get("mechanism").and_then(u64_of) else {
            continue;
        };
        let entry = mechs.entry(id).or_insert((0, 0, BTreeSet::new(), 0));
        entry.0 = entry
            .0
            .saturating_add(row.get("calls").and_then(u64_of).unwrap_or(0));
        entry.1 = entry
            .1
            .saturating_add(row.get("errors").and_then(u64_of).unwrap_or(0));
        for op in arr_of(row, "ops") {
            if let Some(op) = str_of(op) {
                entry.2.insert(op.to_string());
            }
        }
        entry.3 += 1;
    }
    for (id, (calls, errors, operations, rows)) in &mechs {
        out.unknowns.mechanisms_unnamed += 1;
        out.unknowns.mechanisms_unknown_primitive += 1;
        out.mechanisms.push(Mechanism {
            id: *id,
            name: None,
            calls: *calls,
            errors: *errors,
            operations: operations.iter().cloned().collect(),
            functions: Vec::new(),
            returns: Vec::new(),
            rows: *rows,
            limits: Vec::new(),
            limit_only: false,
            bom_ref: format!("p11scope:mechanism:0x{id:x}"),
        });
    }
    Ok(out)
}
