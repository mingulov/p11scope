//! SPDX-License-Identifier: GPL-3.0-or-later
//! Hostile manifest regression tests: oversize, truncated, extreme-valued
//! and mutated `p11scope-manifest/5` documents must be refused before or
//! during parsing, or validate only when structurally sound. Untrusted
//! counts, ids and string lengths never drive unbounded work, and a
//! malformed document never validates clean with invented structure.

use p11scope::manifest_input::{MAX_MANIFEST_BYTES, read_manifest, validate_structure};
use p11scope_manifest::manifest::*;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Fixed seed for the mutation loop below; recorded so a failure reproduces.
const MUTATION_SEED: u64 = 0xC2E1_F00D_0000_0006;
const MUTATIONS: usize = 2000;

fn workdir(name: &str) -> PathBuf {
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| {
        std::env::var("CARGO_TARGET_TMPDIR").expect("TMPDIR or CARGO_TARGET_TMPDIR")
    });
    let dir = PathBuf::from(base).join(format!("hostile-manifest-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_module(dir: &Path) -> PathBuf {
    let src = dir.join("module.c");
    std::fs::write(&src, "int provider_entry(void){return 1;}\n").unwrap();
    let so = dir.join("module.so");
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-O2", "-o"])
            .arg(&so)
            .arg(&src)
            .status()
            .unwrap()
            .success()
    );
    so
}

fn provenance_for(path: &Path) -> ProvenanceObject {
    let file = p11scope_manifest::identity::open_object(path).unwrap();
    let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
    ProvenanceObject {
        path: path.display().to_string(),
        device_major: key.device_major,
        device_minor: key.device_minor,
        inode: key.inode,
        identity: p11scope_manifest::identity::inspect_file(&file)
            .unwrap()
            .identity,
    }
}

fn minimal_manifest(path: &Path) -> Manifest {
    let provenance = provenance_for(path);
    Manifest {
        schema: SCHEMA.to_string(),
        module_path: path.display().to_string(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.display().to_string(),
            identity: provenance.identity.clone(),
        }],
        provenance_objects: vec![provenance],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Absent,
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        }],
        vendor_interfaces: vec![],
        alias_groups: vec![],
        selection_evidence: SelectionEvidence::default(),
    }
}

/// A valid seed document plus the directory holding its module file.
fn seed(dir: &Path) -> String {
    let module = build_module(dir);
    let manifest = minimal_manifest(&module);
    assert!(
        validate_structure(&manifest).is_empty(),
        "seed must validate clean: {:?}",
        validate_structure(&manifest)
    );
    serde_json::to_string(&manifest).unwrap()
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn manifest_file_read_is_regular_utf8_and_bounded() {
    let dir = workdir("file");
    let text = seed(&dir);
    let path = dir.join("manifest.json");
    std::fs::write(&path, &text).unwrap();
    assert_eq!(read_manifest(&path).unwrap(), text);

    // Oversize files are refused before parsing.
    let big = dir.join("big.json");
    std::fs::write(&big, vec![b' '; MAX_MANIFEST_BYTES as usize + 1]).unwrap();
    let error = read_manifest(&big).unwrap_err();
    assert!(
        error.contains("limit"),
        "oversize refusal must name the limit: {error}"
    );
    // Exactly at the cap the read proceeds (content then fails as JSON).
    let edge = dir.join("edge.json");
    std::fs::write(&edge, vec![b' '; MAX_MANIFEST_BYTES as usize]).unwrap();
    assert!(read_manifest(&edge).is_ok(), "at-cap read must proceed");

    // Non-UTF-8, directories, FIFOs and missing files are refused.
    let bad_utf8 = dir.join("bad.json");
    std::fs::write(&bad_utf8, b"{\xff}").unwrap();
    assert!(read_manifest(&bad_utf8).unwrap_err().contains("UTF-8"));
    assert!(read_manifest(&dir).unwrap_err().contains("regular file"));
    assert!(read_manifest(&dir.join("missing.json")).is_err());
    let empty = dir.join("empty.json");
    std::fs::write(&empty, b"").unwrap();
    assert_eq!(read_manifest(&empty).unwrap(), "");
    assert!(serde_json::from_str::<Manifest>("").is_err());
}

#[test]
fn truncation_at_every_byte_boundary_never_validates_clean() {
    let dir = workdir("trunc");
    let text = seed(&dir);
    assert!(text.len() > 128, "seed must be nontrivially long");
    let mut refused = 0usize;
    for len in 0..text.len() {
        let head = &text.as_bytes()[..len];
        let clean = std::str::from_utf8(head)
            .ok()
            .and_then(|text| serde_json::from_str::<Manifest>(text).ok())
            .is_some_and(|manifest| validate_structure(&manifest).is_empty());
        assert!(!clean, "truncation at {len} validated clean");
        refused += 1;
    }
    assert_eq!(refused, text.len());
    let full: Manifest = serde_json::from_str(&text).unwrap();
    assert!(
        validate_structure(&full).is_empty(),
        "the complete seed must validate clean"
    );
}

#[test]
fn wrong_schema_and_counts_are_named_problems() {
    let dir = workdir("schema");
    let text = seed(&dir);
    let base: Value = serde_json::from_str(&text).unwrap();
    let object_template = base["objects"][0].clone();
    let surface_template = base["surfaces"][0].clone();

    // Schema mismatches never validate.
    for schema in [
        json!("bogus"),
        json!(""),
        json!("p11scope-manifest/4"),
        json!(5),
    ] {
        let mut value = base.clone();
        value["schema"] = schema;
        if let Ok(manifest) = serde_json::from_value::<Manifest>(value) {
            assert!(
                validate_structure(&manifest)
                    .iter()
                    .any(|problem| problem.contains("schema")),
                "wrong schema must be a named problem"
            );
        }
    }
    // Count extremes refuse with a named bound.
    for (field, count, fragment) in [
        ("objects", 513usize, "objects"),
        ("surfaces", 258, "surfaces"),
        ("vendor_interfaces", 257, "vendor interfaces"),
        ("alias_groups", 513, "alias groups"),
        ("provenance_objects", 513, "provenance"),
    ] {
        let mut value = base.clone();
        let filler = match field {
            "objects" => object_template.clone(),
            "surfaces" => surface_template.clone(),
            "vendor_interfaces" => json!({"index": 0, "flags": 0, "func_list_null": true}),
            "alias_groups" => json!({"object": 0, "file_offset": 0, "entries": []}),
            _ => value["provenance_objects"][0].clone(),
        };
        value[field] = Value::Array(vec![filler; count]);
        if let Ok(manifest) = serde_json::from_value::<Manifest>(value) {
            assert!(
                validate_structure(&manifest)
                    .iter()
                    .any(|problem| problem.contains(fragment)),
                "{field} x {count} must be a named problem"
            );
        }
    }
    // Empty collections refuse where the contract requires presence.
    for field in ["objects", "provenance_objects"] {
        let mut value = base.clone();
        value[field] = Value::Array(vec![]);
        let manifest: Manifest = serde_json::from_value(value).unwrap();
        assert!(
            !validate_structure(&manifest).is_empty(),
            "empty {field} must be a problem"
        );
    }
}

#[test]
fn duplicate_reordered_and_relative_ids_are_problems() {
    let dir = workdir("ids");
    let text = seed(&dir);
    let base: Value = serde_json::from_str(&text).unwrap();
    let object_template = base["objects"][0].clone();
    let problems_of = |value: &Value| -> Vec<String> {
        match serde_json::from_value::<Manifest>(value.clone()) {
            Ok(manifest) => validate_structure(&manifest),
            Err(error) => vec![format!("serde: {error}")],
        }
    };
    // Duplicate object ids.
    let mut dup = base.clone();
    dup["objects"] = Value::Array(vec![object_template.clone(), object_template.clone()]);
    assert!(
        problems_of(&dup)
            .iter()
            .any(|problem| problem.contains("duplicate")),
        "duplicate ids: {:?}",
        problems_of(&dup)
    );
    // Non-dense ids (0, 2): the gap is refused.
    let mut gap = base.clone();
    let mut second = object_template.clone();
    second["id"] = json!(2);
    second["path"] = json!("/tmp/hostile-second.so");
    gap["objects"] = Value::Array(vec![object_template.clone(), second]);
    assert!(
        problems_of(&gap)
            .iter()
            .any(|problem| problem.contains("dense")),
        "id gap: {:?}",
        problems_of(&gap)
    );
    // Reordered ids (1, 0).
    let mut reordered = base.clone();
    let mut first = object_template.clone();
    first["id"] = json!(1);
    let mut zero = object_template.clone();
    zero["id"] = json!(0);
    zero["path"] = json!("/tmp/hostile-zero.so");
    reordered["objects"] = Value::Array(vec![first, zero]);
    assert!(
        !problems_of(&reordered).is_empty(),
        "reordered ids must be a problem"
    );
    // Relative and overlong paths.
    for (path, fragment) in [
        ("relative/path.so", "absolute"),
        ("", "absolute"),
        (&"a".repeat(5000), "limit is 4096"),
    ] {
        let mut value = base.clone();
        value["module_path"] = json!(path);
        assert!(
            problems_of(&value)
                .iter()
                .any(|problem| problem.contains(fragment)),
            "module path {path:?} must be a named problem"
        );
    }
    // Object 0 must name the module path.
    let mut retargeted = base.clone();
    retargeted["objects"][0]["path"] = json!("/tmp/hostile-other.so");
    assert!(
        problems_of(&retargeted)
            .iter()
            .any(|problem| problem.contains("module_path")),
        "retargeted object 0 must be a problem"
    );
    // Identity extremes.
    for (case, fragment) in [
        (0, "invalid"),
        (1, "invalid"),
        (2, "reusable"),
        (3, "limit is 4096"),
    ] {
        let mut value = base.clone();
        let identity = &mut value["objects"][0]["identity"];
        match case {
            0 => identity["value"] = json!("zz"),
            1 => identity["sha256"] = json!("abc"),
            2 => identity["reusable"] = json!(false),
            _ => identity["note"] = json!("n".repeat(5000)),
        }
        assert!(
            problems_of(&value)
                .iter()
                .any(|problem| problem.contains(fragment)),
            "hostile identity case {case} must be a named problem"
        );
    }
    // Numeric extremes: out-of-range ids fail deserialization, in-range
    // extremes fail the dense check; neither validates clean.
    for id in [json!(1u64), json!(u32::MAX as u64)] {
        let mut value = base.clone();
        value["objects"][0]["id"] = id;
        assert!(
            !problems_of(&value).is_empty(),
            "extreme id must be a problem"
        );
    }
    let mut value = base.clone();
    value["objects"][0]["id"] = json!(u64::from(u32::MAX) + 1);
    assert!(serde_json::from_value::<Manifest>(value).is_err());
    // Unknown top-level fields are denied; unknown record fields are
    // tolerated (serde default on the record structs) but must not
    // smuggle structure past validation: the verdict is unchanged.
    let mut unknown = base.clone();
    unknown["bogus"] = json!(true);
    assert!(
        serde_json::from_value::<Manifest>(unknown)
            .unwrap_err()
            .to_string()
            .contains("unknown field")
    );
    let mut unknown_nested = base.clone();
    unknown_nested["objects"][0]["bogus"] = json!(true);
    let tolerated: Manifest = serde_json::from_value(unknown_nested).unwrap();
    assert_eq!(
        validate_structure(&tolerated),
        validate_structure(&serde_json::from_value::<Manifest>(base.clone()).unwrap()),
        "an unknown nested field must not change the validation verdict"
    );
}

#[test]
fn oversize_and_deeply_nested_documents_stay_bounded() {
    let dir = workdir("huge");
    let text = seed(&dir);
    let base: Value = serde_json::from_str(&text).unwrap();
    // 100k objects parse (input-proportional) but refuse on the count bound.
    let mut value = base.clone();
    value["objects"] = Value::Array(vec![base["objects"][0].clone(); 100_000]);
    let manifest: Manifest = serde_json::from_value(value).expect("100k objects must parse");
    assert_eq!(manifest.objects.len(), 100_000);
    assert!(
        validate_structure(&manifest)
            .iter()
            .any(|problem| problem.contains("objects")),
        "100k objects must be a named problem"
    );
    // Deep nesting refuses at the deserializer recursion limit, without a
    // stack overflow, at depths both sides of it.
    for depth in [129, 200, 10_000] {
        let mut nested = String::from("{\"schema\":\"p11scope-manifest/5\",\"a\":");
        for _ in 0..depth {
            nested.push_str("{\"a\":");
        }
        nested.push('0');
        for _ in 0..depth {
            nested.push('}');
        }
        nested.push('}');
        assert!(
            serde_json::from_str::<Manifest>(&nested).is_err(),
            "depth {depth} must be refused"
        );
        assert!(
            serde_json::from_str::<Value>(&nested).is_err(),
            "depth {depth} must be refused even as untyped JSON"
        );
    }
    // A 5 MB unknown string field is denied without copying it anywhere.
    let mut value = base.clone();
    value["objects"][0]["identity"]["note"] = Value::String("n".repeat(5 * 1024 * 1024));
    let manifest: Manifest = serde_json::from_value(value).unwrap();
    assert!(
        validate_structure(&manifest)
            .iter()
            .any(|problem| problem.contains("limit is 4096")),
        "oversize note must be a named problem"
    );
}

#[test]
fn seeded_mutations_never_validate_clean_with_invented_structure() {
    let dir = workdir("mutate");
    let text = seed(&dir);
    let bytes = text.as_bytes();
    let mut rng = MUTATION_SEED;
    let mut refused = 0usize;
    let mut accepted = 0usize;
    for iteration in 0..MUTATIONS {
        let flips = 1 + (xorshift64(&mut rng) % 8) as usize;
        let mut candidate = bytes.to_vec();
        for _ in 0..flips {
            let offset = (xorshift64(&mut rng) % candidate.len() as u64) as usize;
            candidate[offset] = (xorshift64(&mut rng) % 256) as u8;
        }
        let outcome = std::str::from_utf8(&candidate)
            .ok()
            .and_then(|text| serde_json::from_str::<Manifest>(text).ok());
        match outcome {
            Some(manifest) => {
                let problems = validate_structure(&manifest);
                if problems.is_empty() {
                    accepted += 1;
                    // A mutation that still validates must keep the core
                    // invariants: schema, dense ids, absolute module path.
                    assert_eq!(manifest.schema, SCHEMA, "mutation {iteration}");
                    assert!(
                        Path::new(&manifest.module_path).is_absolute(),
                        "mutation {iteration}"
                    );
                    for (position, object) in manifest.objects.iter().enumerate() {
                        assert_eq!(object.id as usize, position, "mutation {iteration}");
                    }
                    assert_eq!(
                        manifest.objects.first().map(|object| object.path.as_str()),
                        Some(manifest.module_path.as_str()),
                        "mutation {iteration}"
                    );
                } else {
                    refused += 1;
                }
            }
            None => refused += 1,
        }
    }
    assert_eq!(refused + accepted, MUTATIONS);
    assert!(
        refused > accepted,
        "mutations must usually break the document (refused {refused}, accepted {accepted})"
    );
}

#[test]
fn control_characters_in_paths_round_trip_exactly() {
    let dir = workdir("controls");
    let text = seed(&dir);
    let base: Value = serde_json::from_str(&text).unwrap();
    for hostile in [
        "/tmp/a\nb.so",
        "/tmp/a\x01b.so",
        "/tmp/a\x7fb.so",
        "/tmp/\u{202e}evil.so",
    ] {
        let mut value = base.clone();
        value["module_path"] = json!(hostile);
        value["objects"][0]["path"] = json!(hostile);
        value["provenance_objects"][0]["path"] = json!(hostile);
        let manifest: Manifest = serde_json::from_value(value).unwrap();
        // Whatever the verdict, the path is never silently truncated or
        // rewritten: it round-trips byte-exact.
        assert_eq!(manifest.module_path, hostile);
        assert_eq!(manifest.objects[0].path, hostile);
    }
}
