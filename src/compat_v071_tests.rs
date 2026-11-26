//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Profile schema compatibility matrix: real v0.7.1 and current
//! captures validated against the v0.7.1-tag schema and the current
//! schema. See `tests/fixtures/upgrade/README.md` for provenance.

use serde_json::{Value, json};

const SCHEMA071: &[u8] =
    include_bytes!("../tests/fixtures/upgrade/v071-observed-profile-v3.schema.json");
const PROFILE071: &[u8] =
    include_bytes!("../tests/fixtures/upgrade/v071-observed-profile-signer.json");
const METRICS071: &[u8] = include_bytes!("../tests/fixtures/upgrade/v071-observed-metrics.json");
const PROFILE072: &[u8] = include_bytes!("../tests/fixtures/upgrade/v072-observed-profile.json");
const METRICS072: &[u8] = include_bytes!("../tests/fixtures/upgrade/v072-observed-metrics.json");

fn schema_071() -> Value {
    serde_json::from_slice(SCHEMA071).unwrap()
}

fn schema_head() -> Value {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("docs/schema/observed-profile-v3.schema.json"))
        .expect("the shipped schema reads");
    serde_json::from_str(&text).expect("the shipped schema parses")
}

fn valid(schema: &Value, document: &Value) -> bool {
    jsonschema::options()
        .build(schema)
        .expect("the schema builds")
        .is_valid(document)
}

fn document(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

/// Real v0.7.1 documents validate against their own schema and
/// against the current schema (the four newer evidence fields are
/// optional there).
#[test]
fn v071_documents_validate_against_both_schemas() {
    let old = schema_071();
    let new = schema_head();
    for (name, bytes) in [("profile", PROFILE071), ("metrics", METRICS071)] {
        let document = document(bytes);
        assert!(
            valid(&old, &document),
            "{name} validates against its own schema"
        );
        assert!(
            valid(&new, &document),
            "{name} validates against the current schema"
        );
    }
}

/// Real current documents validate against the current schema and
/// fail the v0.7.1 schema with exactly the new-fields error: the old
/// closed evidence object rejects the four newer fields on profiles
/// and `coverage_retired_slots` on metrics. One-way break,
/// documented in the changelog.
#[test]
fn v072_documents_fail_the_old_schema() {
    use jsonschema::error::ValidationErrorKind;
    use std::collections::BTreeSet;
    let old = schema_071();
    let new = schema_head();
    let validator = jsonschema::options()
        .build(&old)
        .expect("the old schema builds");
    for (name, bytes, unexpected) in [
        (
            "profile",
            PROFILE072,
            BTreeSet::from([
                "coverage_retired_slots",
                "member_stop_attached",
                "member_stop_unattached",
                "pid_descendant_gaps_admitted",
            ]),
        ),
        (
            "metrics",
            METRICS072,
            BTreeSet::from(["coverage_retired_slots"]),
        ),
    ] {
        let document = document(bytes);
        assert!(
            valid(&new, &document),
            "{name} validates against the current schema"
        );
        let errors: Vec<_> = validator.iter_errors(&document).collect();
        assert_eq!(errors.len(), 1, "{name} fails with one error");
        let error = &errors[0];
        assert_eq!(error.instance_path().to_string(), "/evidence", "{name}");
        match error.kind() {
            ValidationErrorKind::AdditionalProperties { unexpected: got } => {
                assert_eq!(
                    got.iter().map(String::as_str).collect::<BTreeSet<_>>(),
                    unexpected,
                    "{name} unexpected set"
                );
            }
            other => panic!("{name}: expected additionalProperties, got {other:?}"),
        }
    }
}

/// The version-tolerant fields are all-or-none in the profile
/// lane: v0.7.1 documents carry none, current documents carry all
/// four, and any partial set is malformed.
#[test]
fn profile_version_tolerant_fields_are_all_or_none() {
    const FIELDS: [&str; 4] = [
        "coverage_retired_slots",
        "member_stop_attached",
        "member_stop_unattached",
        "pid_descendant_gaps_admitted",
    ];
    let new = schema_head();
    for held in 0..FIELDS.len() {
        let mut singleton = document(PROFILE071);
        singleton["evidence"][FIELDS[held]] = json!(0);
        assert!(
            !valid(&new, &singleton),
            "a lone {} is malformed",
            FIELDS[held]
        );
        let mut all_but_one = document(PROFILE071);
        for (index, field) in FIELDS.iter().enumerate() {
            if index != held {
                all_but_one["evidence"][field] = json!(0);
            }
        }
        assert!(
            !valid(&new, &all_but_one),
            "missing only {} is malformed",
            FIELDS[held]
        );
    }
    let mut full = document(PROFILE071);
    for field in FIELDS {
        full["evidence"][field] = json!(0);
    }
    assert!(
        valid(&new, &full),
        "all four fields validate (the v0.7.2 shape)"
    );
}

/// The matrix is not vacuous: a document missing a
/// universally-required key fails both schemas.
#[test]
fn schema_matrix_rejects_a_broken_document() {
    let old = schema_071();
    let new = schema_head();
    let mut document = document(PROFILE071);
    document["evidence"]
        .as_object_mut()
        .unwrap()
        .remove("completeness");
    assert!(!valid(&old, &document));
    assert!(!valid(&new, &document));
}
