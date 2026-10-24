//! SPDX-License-Identifier: GPL-3.0-or-later
//! Hostile saved-snapshot regression tests: malformed, truncated, oversize
//! and mutated `p11scope/inventory/v1` documents fed to the offline diff
//! must be refused with a side-naming error, never compared as valid
//! evidence. Untrusted document sizes and nesting never drive unbounded
//! work, hostile paths never reach text output raw, and an output alias of
//! either input is refused before any report is written.

use p11scope::cli::InventoryDiffArgs;
use p11scope::inventory_diff::run_with_writer;
use std::path::{Path, PathBuf};

/// Fixed seed for the mutation loop below; recorded so a failure reproduces.
const MUTATION_SEED: u64 = 0xC2E1_F00D_0000_0007;
const MUTATIONS: usize = 2000;

fn workdir(name: &str) -> PathBuf {
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| {
        std::env::var("CARGO_TARGET_TMPDIR").expect("TMPDIR or CARGO_TARGET_TMPDIR")
    });
    let dir = PathBuf::from(base).join(format!("hostile-diff-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn seed() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/inventory-diff/scan-current.json");
    std::fs::read(&path).expect("diff seed fixture must exist")
}

fn run(
    before: &Path,
    after: &Path,
    json: bool,
    out: Option<PathBuf>,
) -> (Result<i32, String>, Vec<u8>) {
    let args = InventoryDiffArgs {
        before: before.to_path_buf(),
        after: after.to_path_buf(),
        json,
        out,
    };
    let mut output = Vec::new();
    let result = run_with_writer(&args, &mut output).map_err(|error| format!("{error:#}"));
    (result, output)
}

fn above_below<'a>(
    hostile: &'a Path,
    valid: &'a Path,
) -> [(&'static str, (&'a Path, &'a Path)); 2] {
    [("before", (hostile, valid)), ("after", (valid, hostile))]
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
fn identical_valid_snapshots_compare_clean() {
    let dir = workdir("baseline");
    let bytes = seed();
    let before = dir.join("before.json");
    let after = dir.join("after.json");
    std::fs::write(&before, &bytes).unwrap();
    std::fs::write(&after, &bytes).unwrap();
    let (result, output) = run(&before, &after, false, None);
    assert_eq!(result.unwrap(), 0);
    let text = String::from_utf8(output).expect("text output must be UTF-8");
    assert!(
        text.starts_with("Inventory comparison: 0 application groups changed"),
        "identical snapshots must compare unchanged: {text:?}"
    );
    let (result, output) = run(&before, &after, true, None);
    assert_eq!(result.unwrap(), 0);
    let report: serde_json::Value =
        serde_json::from_slice(&output).expect("JSON report must parse");
    assert_eq!(report["schema"], "p11scope/inventory-diff/v1");
    assert_eq!(report["summary"]["application_groups_changed"], 0);
    assert_eq!(report["summary"]["module_paths_changed"], 0);
}

#[test]
fn hostile_snapshot_files_are_refused_naming_the_side() {
    let dir = workdir("files");
    let bytes = seed();
    let valid = dir.join("valid.json");
    std::fs::write(&valid, &bytes).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("garbage", b"not json at all\x00\x01\x02".to_vec()),
        ("truncated", bytes[..bytes.len() / 2].to_vec()),
        ("one byte", bytes[..1].to_vec()),
        ("wrong schema", {
            String::from_utf8(bytes.clone())
                .unwrap()
                .replace("p11scope/inventory/v1", "p11scope/inventory/v9")
                .into_bytes()
        }),
        ("null bytes", vec![0u8; 1024]),
        ("deep nesting", {
            let mut nested = String::from("{\"schema\":\"p11scope/inventory/v1\",\"a\":");
            for _ in 0..10_000 {
                nested.push_str("{\"a\":");
            }
            nested.push('0');
            for _ in 0..10_000 {
                nested.push('}');
            }
            nested.push('}');
            nested.into_bytes()
        }),
        ("huge line", {
            let mut huge = b"{\"schema\":\"p11scope/inventory/v1\",\"pad\":\"".to_vec();
            huge.extend(std::iter::repeat_n(b'x', 4 * 1024 * 1024));
            huge.extend_from_slice(b"\"}");
            huge
        }),
    ];
    for (index, (label, hostile)) in cases.iter().enumerate() {
        let path = dir.join(format!("hostile-{index}.json"));
        std::fs::write(&path, hostile).unwrap();
        for (side, (before, after)) in [("before", (&path, &valid)), ("after", (&valid, &path))] {
            let (result, _) = run(before, after, true, None);
            let error = result.unwrap_err();
            assert!(
                error.contains(&format!("{side} snapshot")),
                "{label} on the {side} side must name it: {error}"
            );
        }
    }
    // One input past the 64 MiB reader bound is refused without parsing.
    let oversize = dir.join("oversize.json");
    std::fs::write(&oversize, vec![b'x'; 67_108_864 + 1]).unwrap();
    for (side, (before, after)) in above_below(&oversize, &valid) {
        let error = run(before, after, true, None).0.unwrap_err();
        assert!(
            error.contains(&format!("{side} snapshot")) && error.contains("byte limit"),
            "oversize on the {side} side: {error}"
        );
    }
    // Non-regular and missing inputs are refused, never read.
    let missing = dir.join("absent.json");
    assert!(run(&missing, &valid, true, None).0.is_err());
    assert!(run(&valid, &missing, true, None).0.is_err());
    assert!(
        run(&dir, &valid, true, None)
            .0
            .unwrap_err()
            .contains("regular file")
    );
    assert!(
        run(&valid, &dir, true, None)
            .0
            .unwrap_err()
            .contains("regular file")
    );
    assert!(run(Path::new("/dev/null"), &valid, true, None).0.is_err());
}

#[test]
fn seeded_mutations_are_refused_or_reported_without_raw_controls() {
    let dir = workdir("mutate");
    let bytes = seed();
    let fixed = dir.join("fixed.json");
    std::fs::write(&fixed, &bytes).unwrap();
    let moving = dir.join("moving.json");
    let mut rng = MUTATION_SEED;
    let mut refused = 0usize;
    let mut compared = 0usize;
    for iteration in 0..MUTATIONS {
        let flips = 1 + (xorshift64(&mut rng) % 8) as usize;
        let mut candidate = bytes.clone();
        for _ in 0..flips {
            let offset = (xorshift64(&mut rng) % candidate.len() as u64) as usize;
            candidate[offset] = (xorshift64(&mut rng) % 256) as u8;
        }
        // Alternate the mutated side so both error contexts are exercised.
        let mutate_before = iteration.is_multiple_of(2);
        std::fs::write(&moving, &candidate).unwrap();
        let (before, after, side) = if mutate_before {
            (moving.as_path(), fixed.as_path(), "before")
        } else {
            (fixed.as_path(), moving.as_path(), "after")
        };
        // Alternate JSON and text rendering; both must stay well-formed.
        let json = iteration % 3 != 0;
        let (result, output) = run(before, after, json, None);
        match result {
            Ok(code) => {
                compared += 1;
                assert_eq!(code, 0, "mutation {iteration} exit code");
                if json {
                    let report: serde_json::Value =
                        serde_json::from_slice(&output).expect("JSON report must parse");
                    assert_eq!(report["schema"], "p11scope/inventory-diff/v1");
                } else {
                    let text = String::from_utf8(output).expect("text must be UTF-8");
                    assert!(
                        text.bytes().all(|byte| byte == b'\n'
                            || (byte >= 0x20 && byte != 0x7f)
                            || byte >= 0x80),
                        "mutation {iteration}: raw control byte in text output"
                    );
                }
            }
            Err(error) => {
                refused += 1;
                assert!(
                    error.contains(&format!("{side} snapshot")),
                    "mutation {iteration} must name the {side} side: {error}"
                );
                // Errors sanitize controls too: no raw C0 byte may leak.
                assert!(
                    error.bytes().all(|byte| byte == b'\n'
                        || (byte >= 0x20 && byte != 0x7f)
                        || byte >= 0x80),
                    "mutation {iteration}: raw control byte in error: {error:?}"
                );
            }
        }
    }
    assert_eq!(refused + compared, MUTATIONS);
    assert!(
        refused > compared,
        "mutations must usually break the document (refused {refused}, compared {compared})"
    );
}

#[test]
fn hostile_paths_never_reach_text_output_raw() {
    let dir = workdir("paths");
    let bytes = seed();
    let mut document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let hostile = "/tmp/\x1b[1;31mred\x1b[0m/\x01\x02\x7f/so with spaces\nnewline.so";
    document["modules"][0]["paths"] = serde_json::json!([hostile]);
    if document
        .get("gaps")
        .and_then(|gaps| gaps.as_array())
        .is_some_and(|gaps| !gaps.is_empty())
    {
        document["gaps"][0]["subject"] = serde_json::json!(hostile);
        document["gaps"][0]["reason"] = serde_json::json!(format!("{hostile} failed"));
    }
    let before = dir.join("before.json");
    let after = dir.join("after.json");
    std::fs::write(&before, serde_json::to_vec(&document).unwrap()).unwrap();
    std::fs::write(&after, &bytes).unwrap();
    let (result, output) = run(&before, &after, false, None);
    assert_eq!(result.unwrap(), 0);
    let text = String::from_utf8(output).expect("text must be UTF-8");
    assert!(
        !text.contains('\x1b') && !text.contains('\x01') && !text.contains('\x7f'),
        "hostile path bytes reached text output: {text:?}"
    );
    let (result, output) = run(&before, &after, true, None);
    assert_eq!(result.unwrap(), 0);
    let report: serde_json::Value = serde_json::from_slice(&output).expect("JSON must parse");
    assert_eq!(report["schema"], "p11scope/inventory-diff/v1");
}

#[test]
fn output_alias_of_either_input_is_refused_before_writing() {
    let dir = workdir("alias");
    let bytes = seed();
    let before = dir.join("before.json");
    let after = dir.join("after.json");
    std::fs::write(&before, &bytes).unwrap();
    std::fs::write(&after, &bytes).unwrap();
    // The output may not be either input, by spelling or by hardlink.
    for out in [before.clone(), after.clone()] {
        let error = run(&before, &after, true, Some(out)).0.unwrap_err();
        assert!(
            error.contains("alias"),
            "output alias must be refused: {error}"
        );
    }
    let linked = dir.join("linked.json");
    std::fs::hard_link(&before, &linked).unwrap();
    let error = run(&before, &after, true, Some(linked.clone()))
        .0
        .unwrap_err();
    assert!(
        error.contains("alias"),
        "hardlink alias must be refused: {error}"
    );
    assert_eq!(
        std::fs::read(&before).unwrap(),
        bytes,
        "input must be untouched"
    );
    // A fresh output path receives a parseable report.
    let out = dir.join("report.json");
    let (result, _) = run(&before, &after, true, Some(out.clone()));
    assert_eq!(result.unwrap(), 0);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).unwrap()).expect("report must parse");
    assert_eq!(report["schema"], "p11scope/inventory-diff/v1");
}
