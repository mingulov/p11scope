//! SPDX-License-Identifier: GPL-3.0-or-later
//! CycloneDX 1.6 document and text views for a CBOM projection.
//!
//! The JSON document is complete; text views cap their named lists and
//! degrade unknown details to named notes instead of stopping.

use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::fmt::Write as _;

use super::classify::classify;
use super::input::{JOIN_LIMIT, Projection, TEXT_LIST_LIMIT, join_bounded};
use crate::render::escape_controls;

pub(super) fn render_json(projection: &Projection) -> Value {
    let mut document = Map::new();
    document.insert(
        "bomFormat".to_string(),
        Value::String("CycloneDX".to_string()),
    );
    document.insert("specVersion".to_string(), Value::String("1.6".to_string()));
    document.insert("metadata".to_string(), render_metadata(projection));
    document.insert(
        "components".to_string(),
        Value::Array(render_components(projection)),
    );
    document.insert(
        "dependencies".to_string(),
        Value::Array(render_dependencies(projection)),
    );
    Value::Object(document)
}

fn prop(name: &str, value: String) -> Value {
    Value::Object(Map::from_iter([
        ("name".to_string(), Value::String(name.to_string())),
        ("value".to_string(), Value::String(value)),
    ]))
}

fn render_metadata(projection: &Projection) -> Value {
    let tool = Value::Object(Map::from_iter([
        ("type".to_string(), Value::String("application".to_string())),
        ("name".to_string(), Value::String("p11scope".to_string())),
        (
            "version".to_string(),
            Value::String(env!("CARGO_PKG_VERSION").to_string()),
        ),
    ]));
    let mut properties = vec![prop(
        "p11scope:source_schema",
        projection.source_schema.clone(),
    )];
    if let Some(scope) = &projection.scope_note {
        properties.push(prop("p11scope:scope", scope.clone()));
    }
    if let Some(window) = &projection.window_note {
        properties.push(prop("p11scope:window", window.clone()));
    }
    if let Some(passes) = projection.passes {
        properties.push(prop("p11scope:passes", passes.to_string()));
    }
    if let Some(completeness) = &projection.completeness {
        properties.push(prop("p11scope:completeness", completeness.clone()));
    }
    properties.push(prop(
        "p11scope:source_gaps",
        projection.gap_count.to_string(),
    ));
    if projection.gaps_suppressed > 0 {
        properties.push(prop(
            "p11scope:gaps_suppressed",
            projection.gaps_suppressed.to_string(),
        ));
    }
    if !projection.gap_subjects.is_empty() {
        let subjects: BTreeSet<String> = projection.gap_subjects.iter().cloned().collect();
        properties.push(prop(
            "p11scope:gap_subjects",
            join_bounded(&subjects, JOIN_LIMIT),
        ));
    }
    properties.push(prop(
        "p11scope:object_observations",
        projection.object_observations.clone(),
    ));
    if let Some(note) = &projection.profile_note {
        properties.push(prop("p11scope:profile_note", note.clone()));
    }
    let unknowns = &projection.unknowns;
    for (name, count) in [
        (
            "p11scope:applications",
            projection.applications.len() as u64,
        ),
        ("p11scope:providers", projection.providers.len() as u64),
        ("p11scope:algorithms", projection.mechanisms.len() as u64),
        ("p11scope:keys", projection.keys.len() as u64),
        ("p11scope:callers_unknown_exe", unknowns.callers_unknown_exe),
        ("p11scope:mechanisms_unnamed", unknowns.mechanisms_unnamed),
        (
            "p11scope:mechanisms_unknown_primitive",
            unknowns.mechanisms_unknown_primitive,
        ),
        ("p11scope:keys_unknown_size", unknowns.keys_unknown_size),
        ("p11scope:keys_unknown_type", unknowns.keys_unknown_type),
    ] {
        properties.push(prop(name, count.to_string()));
    }
    Value::Object(Map::from_iter([
        (
            "tools".to_string(),
            Value::Object(Map::from_iter([(
                "components".to_string(),
                Value::Array(vec![tool]),
            )])),
        ),
        ("properties".to_string(), Value::Array(properties)),
    ]))
}

fn render_components(projection: &Projection) -> Vec<Value> {
    let mut components = Vec::new();
    for app in &projection.applications {
        let mut properties = vec![prop("p11scope:incarnations", app.incarnations.to_string())];
        if !app.lifecycles.is_empty() {
            properties.push(prop("p11scope:lifecycle", app.lifecycles.join(",")));
        }
        components.push(Value::Object(Map::from_iter([
            ("bom-ref".to_string(), Value::String(app.bom_ref.clone())),
            ("type".to_string(), Value::String("application".to_string())),
            ("name".to_string(), Value::String(app.path.clone())),
            (
                "description".to_string(),
                Value::String(
                    "Application observed with provider mappings in this capture; one component per distinct executable path."
                        .to_string(),
                ),
            ),
            ("properties".to_string(), Value::Array(properties)),
        ])));
    }
    for provider in &projection.providers {
        let mut properties = Vec::new();
        if let Some(admission) = &provider.admission {
            properties.push(prop("p11scope:admission", admission.clone()));
        }
        if let Some(lifecycle) = &provider.lifecycle {
            properties.push(prop("p11scope:lifecycle", lifecycle.clone()));
        }
        if let Some(device) = &provider.device {
            properties.push(prop("p11scope:device", device.clone()));
        }
        if let Some(inode) = provider.inode {
            properties.push(prop("p11scope:inode", inode.to_string()));
        }
        if let Some(endpoints) = provider.endpoints {
            properties.push(prop("p11scope:endpoints", endpoints.to_string()));
        }
        if let Some(build_id) = &provider.build_id {
            properties.push(prop("p11scope:build_id", build_id.clone()));
        }
        let mut component = Map::from_iter([
            (
                "bom-ref".to_string(),
                Value::String(provider.bom_ref.clone()),
            ),
            ("type".to_string(), Value::String("library".to_string())),
            ("name".to_string(), Value::String(provider.name.clone())),
            (
                "description".to_string(),
                Value::String(
                    "Provider module file observed mapped in this capture; mapping is not evidence of calls."
                        .to_string(),
                ),
            ),
            ("properties".to_string(), Value::Array(properties)),
        ]);
        if let Some(sha256) = &provider.sha256 {
            component.insert(
                "hashes".to_string(),
                Value::Array(vec![Value::Object(Map::from_iter([
                    ("alg".to_string(), Value::String("SHA-256".to_string())),
                    ("content".to_string(), Value::String(sha256.clone())),
                ]))]),
            );
        }
        components.push(Value::Object(component));
    }
    for mechanism in &projection.mechanisms {
        let classified = classify(
            mechanism.name.as_deref().unwrap_or(""),
            &mechanism.operations,
        );
        let mut algorithm = Map::new();
        if let Some(primitive) = classified.primitive {
            algorithm.insert(
                "primitive".to_string(),
                Value::String(primitive.to_string()),
            );
        }
        if let Some(mode) = classified.mode {
            algorithm.insert("mode".to_string(), Value::String(mode.to_string()));
        }
        if let Some(padding) = classified.padding {
            algorithm.insert("padding".to_string(), Value::String(padding.to_string()));
        }
        if !classified.functions.is_empty() {
            algorithm.insert(
                "cryptoFunctions".to_string(),
                Value::Array(
                    classified
                        .functions
                        .iter()
                        .map(|function| Value::String((*function).to_string()))
                        .collect(),
                ),
            );
        }
        let operations: BTreeSet<String> = mechanism.operations.iter().cloned().collect();
        let functions: BTreeSet<String> = mechanism.functions.iter().cloned().collect();
        let returns: BTreeSet<String> = mechanism.returns.iter().cloned().collect();
        let properties = vec![
            prop("p11scope:mechanism_id", mechanism.id.to_string()),
            prop("p11scope:mechanism_hex", format!("0x{:x}", mechanism.id)),
            prop("p11scope:calls", mechanism.calls.to_string()),
            prop("p11scope:errors", mechanism.errors.to_string()),
            prop("p11scope:operations", join_bounded(&operations, JOIN_LIMIT)),
            prop("p11scope:functions", join_bounded(&functions, JOIN_LIMIT)),
            prop("p11scope:returns", join_bounded(&returns, JOIN_LIMIT)),
            prop("p11scope:rows", mechanism.rows.to_string()),
        ];
        let name = mechanism
            .name
            .clone()
            .unwrap_or_else(|| format!("PKCS#11 mechanism 0x{:x}", mechanism.id));
        components.push(Value::Object(Map::from_iter([
            (
                "bom-ref".to_string(),
                Value::String(mechanism.bom_ref.clone()),
            ),
            (
                "type".to_string(),
                Value::String("cryptographic-asset".to_string()),
            ),
            ("name".to_string(), Value::String(name)),
            (
                "description".to_string(),
                Value::String(
                    "Mechanism observed initializing operations; carries no key size, curve or parameters."
                        .to_string(),
                ),
            ),
            (
                "cryptoProperties".to_string(),
                Value::Object(Map::from_iter([
                    (
                        "assetType".to_string(),
                        Value::String("algorithm".to_string()),
                    ),
                    (
                        "algorithmProperties".to_string(),
                        Value::Object(algorithm),
                    ),
                ])),
            ),
            ("properties".to_string(), Value::Array(properties)),
        ])));
    }
    for key in &projection.keys {
        let material = match key.class {
            Some(2) => "public-key",
            Some(3) => "private-key",
            Some(4) => "secret-key",
            _ => "unknown",
        };
        let mut related =
            Map::from_iter([("type".to_string(), Value::String(material.to_string()))]);
        if let Some(size) = key.size_bits {
            related.insert(
                "size".to_string(),
                Value::Number(serde_json::Number::from(size)),
            );
        }
        let mut properties = vec![
            prop("p11scope:object", key.object.to_string()),
            prop("p11scope:references", key.references.to_string()),
        ];
        if let Some(label) = &key.label {
            properties.push(prop("p11scope:label", label.clone()));
        }
        properties.push(prop(
            "p11scope:class",
            match key.class {
                Some(code) => format!("{code} ({})", class_name(code)),
                None => "unknown".to_string(),
            },
        ));
        properties.push(prop(
            "p11scope:key_type",
            match key.key_type {
                Some(code) => format!("{code} ({})", key_type_name(code)),
                None => "unknown".to_string(),
            },
        ));
        if let Some(curve) = &key.curve {
            properties.push(prop("p11scope:curve", curve.clone()));
        }
        if let Some(token) = key.token {
            properties.push(prop("p11scope:token", token.to_string()));
        }
        if let Some(creation) = &key.creation {
            properties.push(prop("p11scope:creation", creation.clone()));
        }
        let name = key
            .label
            .clone()
            .unwrap_or_else(|| format!("key object {}", key.object));
        components.push(Value::Object(Map::from_iter([
            ("bom-ref".to_string(), Value::String(key.bom_ref.clone())),
            (
                "type".to_string(),
                Value::String("cryptographic-asset".to_string()),
            ),
            ("name".to_string(), Value::String(name)),
            (
                "description".to_string(),
                Value::String(
                    "Key object observed in application calls; values, CKA labels/IDs and PINs are never captured."
                        .to_string(),
                ),
            ),
            (
                "cryptoProperties".to_string(),
                Value::Object(Map::from_iter([
                    (
                        "assetType".to_string(),
                        Value::String("related-crypto-material".to_string()),
                    ),
                    (
                        "relatedCryptoMaterialProperties".to_string(),
                        Value::Object(related),
                    ),
                ])),
            ),
            ("properties".to_string(), Value::Array(properties)),
        ])));
    }
    components
}

/// Presentation names from the object-observations contract; unknown
/// codes stay numeric, never guessed.
fn class_name(code: u64) -> &'static str {
    match code {
        0 => "data",
        1 => "certificate",
        2 => "public_key",
        3 => "private_key",
        4 => "secret_key",
        _ => "unknown",
    }
}

fn key_type_name(code: u64) -> &'static str {
    match code {
        0 => "rsa",
        1 => "dsa",
        2 => "dh",
        3 => "ec",
        4 => "x9_42_dh",
        16 => "generic_secret",
        31 => "aes",
        64 => "ec_edwards",
        65 => "ec_montgomery",
        _ => "unknown",
    }
}

fn render_dependencies(projection: &Projection) -> Vec<Value> {
    let mut grouped: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (from, to) in &projection.dependencies {
        grouped.insert((from.as_str(), to.as_str()));
    }
    let mut refs: BTreeSet<&str> = BTreeSet::new();
    for (from, _) in &grouped {
        refs.insert(from);
    }
    refs.iter()
        .map(|from| {
            let depends: Vec<Value> = grouped
                .iter()
                .filter(|(candidate, _)| candidate == from)
                .map(|(_, to)| Value::String((*to).to_string()))
                .collect();
            Value::Object(Map::from_iter([
                ("ref".to_string(), Value::String((*from).to_string())),
                ("dependsOn".to_string(), Value::Array(depends)),
            ]))
        })
        .collect()
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

fn head_line(projection: &Projection) -> String {
    let scope = projection.scope_note.as_deref().unwrap_or("unknown scope");
    format!(
        "CBOM from {} (scope {scope}): {}, {}, {}, {}",
        escape_controls(&projection.source_schema),
        counted(projection.applications.len(), "application", "applications"),
        counted(projection.providers.len(), "provider", "providers"),
        counted(
            projection.mechanisms.len(),
            "cryptographic algorithm",
            "cryptographic algorithms"
        ),
        counted(projection.keys.len(), "key object", "key objects"),
    )
}

fn capped_list(items: &[String], limit: usize) -> String {
    let mut parts: Vec<String> = items
        .iter()
        .take(limit)
        .map(|item| escape_controls(item).into_owned())
        .collect();
    if items.len() > limit {
        parts.push(format!("+{} more", items.len() - limit));
    }
    parts.join(", ")
}

fn unknown_parts(projection: &Projection) -> Vec<String> {
    let unknowns = &projection.unknowns;
    let mut parts = Vec::new();
    if unknowns.mechanisms_unnamed > 0 {
        parts.push(counted(
            unknowns.mechanisms_unnamed as usize,
            "unnamed mechanism id",
            "unnamed mechanism ids",
        ));
    }
    let named_unknown = unknowns
        .mechanisms_unknown_primitive
        .saturating_sub(unknowns.mechanisms_unnamed);
    if named_unknown > 0 {
        parts.push(counted(
            named_unknown as usize,
            "named mechanism with unknown primitive",
            "named mechanisms with unknown primitive",
        ));
    }
    if unknowns.keys_unknown_size > 0 {
        parts.push(counted(
            unknowns.keys_unknown_size as usize,
            "key without established size",
            "keys without established size",
        ));
    }
    if unknowns.keys_unknown_type > 0 {
        parts.push(counted(
            unknowns.keys_unknown_type as usize,
            "key of unknown type",
            "keys of unknown type",
        ));
    }
    if unknowns.callers_unknown_exe > 0 {
        parts.push(counted(
            unknowns.callers_unknown_exe as usize,
            "caller without an executable path",
            "callers without an executable path",
        ));
    }
    parts
}

fn coverage_parts(projection: &Projection) -> Vec<String> {
    let unknowns = &projection.unknowns;
    let mut parts = vec![format!(
        "source {}",
        counted(projection.gap_count as usize, "gap", "gaps")
    )];
    if !projection.gap_subjects.is_empty() {
        parts.push(format!(
            "subjects: {}",
            capped_list(&projection.gap_subjects, TEXT_LIST_LIMIT)
        ));
    }
    if projection.gaps_suppressed > 0 {
        parts.push(format!(
            "{} suppressed",
            counted(projection.gaps_suppressed as usize, "gap", "gaps")
        ));
    }
    parts.push(format!(
        "object observations {}",
        escape_controls(&projection.object_observations)
    ));
    if let Some(completeness) = &projection.completeness {
        parts.push(format!("completeness {}", escape_controls(completeness)));
    }
    if unknowns.edges_without_mechanisms > 0 {
        parts.push(counted(
            unknowns.edges_without_mechanisms as usize,
            "edge without mechanism claims",
            "edges without mechanism claims",
        ));
    }
    if unknowns.keys_unjoinable > 0 {
        parts.push(counted(
            unknowns.keys_unjoinable as usize,
            "key without provider linkage",
            "keys without provider linkage",
        ));
    }
    if unknowns.objects_skipped_non_key > 0 {
        parts.push(counted(
            unknowns.objects_skipped_non_key as usize,
            "non-key object skipped",
            "non-key objects skipped",
        ));
    }
    if unknowns.modules_invalid_digest > 0 {
        parts.push(counted(
            unknowns.modules_invalid_digest as usize,
            "invalid digest omitted",
            "invalid digests omitted",
        ));
    }
    if unknowns.dangling_edge_refs > 0 {
        parts.push(counted(
            unknowns.dangling_edge_refs as usize,
            "dangling edge reference",
            "dangling edge references",
        ));
    }
    if unknowns.callers_skipped + unknowns.modules_skipped > 0 {
        parts.push(counted(
            (unknowns.callers_skipped + unknowns.modules_skipped) as usize,
            "malformed caller/module row skipped",
            "malformed caller/module rows skipped",
        ));
    }
    if let Some(note) = &projection.profile_note {
        parts.push(escape_controls(note).into_owned());
    }
    parts
}

fn quiet() -> bool {
    crate::cli::text_verbosity() == crate::cli::TextVerbosity::Quiet
}

pub(super) fn render_concise(projection: &Projection, out: &mut Vec<u8>) -> std::io::Result<()> {
    let mut text = String::new();
    let _ = writeln!(text, "{}", head_line(projection));
    let apps: Vec<String> = projection
        .applications
        .iter()
        .map(|app| app.path.clone())
        .collect();
    let providers: Vec<String> = projection
        .providers
        .iter()
        .map(|provider| provider.name.clone())
        .collect();
    let _ = writeln!(
        text,
        "applications: {}",
        capped_list(&apps, TEXT_LIST_LIMIT)
    );
    let _ = writeln!(
        text,
        "providers: {}",
        capped_list(&providers, TEXT_LIST_LIMIT)
    );
    let unknowns = unknown_parts(projection);
    if unknowns.is_empty() {
        let _ = writeln!(text, "unknowns: none");
    } else {
        let _ = writeln!(text, "unknowns: {}", unknowns.join(", "));
    }
    let _ = writeln!(text, "coverage: {}", coverage_parts(projection).join("; "));
    if !quiet() {
        let _ = writeln!(text, "{}", crate::cli::VERBOSE_HINT);
    }
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

pub(super) fn render_verbose(projection: &Projection, out: &mut Vec<u8>) -> std::io::Result<()> {
    let mut text = String::new();
    let _ = writeln!(text, "{}", head_line(projection));
    let _ = writeln!(
        text,
        "{} ({}):",
        plural(projection.applications.len(), "application", "applications"),
        projection.applications.len()
    );
    for app in &projection.applications {
        let _ = writeln!(
            text,
            "  {} ({}, {})",
            escape_controls(&app.path),
            counted(app.incarnations as usize, "incarnation", "incarnations"),
            if app.lifecycles.is_empty() {
                "lifecycle unknown".to_string()
            } else {
                app.lifecycles.join(",")
            },
        );
    }
    let _ = writeln!(
        text,
        "{} ({}):",
        plural(projection.providers.len(), "provider", "providers"),
        projection.providers.len()
    );
    for provider in &projection.providers {
        let mut detail = Vec::new();
        if let Some(sha256) = &provider.sha256 {
            detail.push(format!("sha256 {}…", &sha256[..8.min(sha256.len())]));
        }
        if let Some(admission) = &provider.admission {
            detail.push(escape_controls(admission).into_owned());
        }
        if let Some(lifecycle) = &provider.lifecycle {
            detail.push(escape_controls(lifecycle).into_owned());
        }
        let _ = writeln!(
            text,
            "  {} ({})",
            escape_controls(&provider.name),
            if detail.is_empty() {
                "no details".to_string()
            } else {
                detail.join(", ")
            },
        );
    }
    let _ = writeln!(
        text,
        "{} ({}):",
        plural(projection.mechanisms.len(), "algorithm", "algorithms"),
        projection.mechanisms.len()
    );
    for mechanism in &projection.mechanisms {
        let classified = classify(
            mechanism.name.as_deref().unwrap_or(""),
            &mechanism.operations,
        );
        let name = mechanism
            .name
            .clone()
            .unwrap_or_else(|| format!("PKCS#11 mechanism 0x{:x}", mechanism.id));
        let mut detail = classified.primitive.unwrap_or("unknown").to_string();
        if let Some(mode) = classified.mode {
            let _ = write!(detail, "/{mode}");
        }
        if let Some(padding) = classified.padding {
            let _ = write!(detail, "+{padding}");
        }
        if !classified.functions.is_empty() {
            let _ = write!(detail, ", {}", classified.functions.join("+"));
        }
        let _ = writeln!(
            text,
            "  {} (0x{:x}): {}, {}, {}",
            escape_controls(&name),
            mechanism.id,
            detail,
            counted(mechanism.calls as usize, "call", "calls"),
            counted(mechanism.errors as usize, "error", "errors"),
        );
    }
    let _ = writeln!(
        text,
        "{} ({}):",
        plural(projection.keys.len(), "key", "keys"),
        projection.keys.len()
    );
    for key in &projection.keys {
        let kind = match key.class {
            Some(2) => "public-key",
            Some(3) => "private-key",
            Some(4) => "secret-key",
            _ => "unknown type",
        };
        let size = key
            .size_bits
            .map(|size| format!("{size} bits"))
            .unwrap_or_else(|| "unknown size".to_string());
        let name = key
            .label
            .clone()
            .unwrap_or_else(|| format!("key object {}", key.object));
        let _ = writeln!(
            text,
            "  {}: {}, {}, {}",
            escape_controls(&name),
            kind,
            size,
            counted(key.references as usize, "reference", "references"),
        );
    }
    let unknowns = unknown_parts(projection);
    if unknowns.is_empty() {
        let _ = writeln!(text, "unknowns: none");
    } else {
        let _ = writeln!(text, "unknowns: {}", unknowns.join(", "));
    }
    let _ = writeln!(text, "coverage: {}", coverage_parts(projection).join("; "));
    out.extend_from_slice(text.as_bytes());
    Ok(())
}
