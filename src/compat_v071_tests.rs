//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Profile schema compatibility matrix: real v0.7.1 and current
//! captures validated against the v0.7.1-tag schema and the current
//! schema. See `tests/fixtures/upgrade/README.md` for provenance.

use serde_json::Value;

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
/// fail the v0.7.1 schema: the old closed evidence object rejects
/// the newer fields. One-way break, documented in the changelog.
#[test]
fn v072_documents_fail_the_old_schema() {
    let old = schema_071();
    let new = schema_head();
    for (name, bytes) in [("profile", PROFILE072), ("metrics", METRICS072)] {
        let document = document(bytes);
        assert!(
            valid(&new, &document),
            "{name} validates against the current schema"
        );
        assert!(
            !valid(&old, &document),
            "{name} fails the v0.7.1 schema (one-way break)"
        );
    }
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
