//! SPDX-License-Identifier: GPL-3.0-or-later
//! Paired default/unsafe driver for tests/python/test_entry_object.py.
//!
//! Lane procedure: build the workspace twice in separate target dirs,
//! once default and once with `--features
//! p11scope/unsafe-unvalidated-metadata`; set
//! P11SCOPE_ENTRY_PAIRED_DEFAULT_TARGET_DIR and
//! P11SCOPE_ENTRY_PAIRED_UNSAFE_TARGET_DIR to those target dirs; run
//! this test with `--ignored --exact --nocapture`. The suite takes about
//! 2 hours (measured 6,915 s on the current objects), so it never joins
//! the ordinary gate; its progress streams while it runs. Every input fails
//! closed: an unset variable, a missing or ambiguous object, a non-ELF
//! file, or two identical objects refuses instead of running a partial
//! suite.

use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The suite's test count; update with the suite (it proves selection).
const EXPECTED_TESTS: u32 = 45;

fn target_dir(var: &str, kind: &str) -> PathBuf {
    let dir = std::env::var_os(var)
        .unwrap_or_else(|| panic!("{kind}: set {var} to a built target dir (see the test docs)"));
    PathBuf::from(dir)
}

fn is_root_out_dir(name: &str) -> bool {
    name.len() == "p11scope-".len() + 16
        && name.starts_with("p11scope-")
        && name["p11scope-".len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
}

fn paired_object(target_dir: &Path, kind: &str, var: &str) -> PathBuf {
    assert!(
        target_dir.is_dir(),
        "{kind}: {} is not a directory; set {var} to a built target dir",
        target_dir.display()
    );
    let mut hits = Vec::new();
    for profile in ["debug", "release"] {
        let build = target_dir.join(profile).join("build");
        let entries = match std::fs::read_dir(&build) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            let entry = entry.expect("read build dir entry");
            if !entry.file_type().expect("entry type").is_dir()
                || !is_root_out_dir(&entry.file_name().to_string_lossy())
            {
                continue;
            }
            let object = entry.path().join("out").join("p11scope-ebpf");
            if object.is_file() {
                hits.push(object);
            }
        }
    }
    assert!(
        !hits.is_empty(),
        "{kind}: no p11scope-ebpf under {}; build the target dir first",
        target_dir.display()
    );
    // A target dir used for both `build` and `test` holds one object per
    // profile unit; they must agree byte-for-byte, else the dir is
    // ambiguous and refuses.
    let first = std::fs::read(&hits[0]).expect("read candidate object");
    for hit in &hits[1..] {
        let bytes = std::fs::read(hit).expect("read candidate object");
        assert!(
            bytes == first,
            "{kind}: {} p11scope-ebpf files under {} differ; clean the \
             target dir and rebuild",
            hits.len(),
            target_dir.display()
        );
    }
    hits.into_iter().next().expect("at least one hit")
}

#[test]
#[ignore = "needs default and unsafe-unvalidated-metadata target dirs from the paired-build lane"]
fn paired_default_and_unsafe_objects_satisfy_the_entry_contract() {
    let default_dir = target_dir("P11SCOPE_ENTRY_PAIRED_DEFAULT_TARGET_DIR", "default");
    let unsafe_dir = target_dir("P11SCOPE_ENTRY_PAIRED_UNSAFE_TARGET_DIR", "unsafe");
    let default_object = paired_object(
        &default_dir,
        "default",
        "P11SCOPE_ENTRY_PAIRED_DEFAULT_TARGET_DIR",
    );
    let unsafe_object = paired_object(
        &unsafe_dir,
        "unsafe",
        "P11SCOPE_ENTRY_PAIRED_UNSAFE_TARGET_DIR",
    );
    let default_bytes = std::fs::read(&default_object).expect("read default object");
    let unsafe_bytes = std::fs::read(&unsafe_object).expect("read unsafe object");
    for (kind, bytes) in [("default", &default_bytes), ("unsafe", &unsafe_bytes)] {
        assert!(
            bytes.starts_with(b"\x7fELF"),
            "{kind} object is not an ELF file"
        );
    }
    assert_ne!(
        default_bytes, unsafe_bytes,
        "the two objects are byte-identical; pass two different builds"
    );
    println!(
        "default object: {} ({} bytes)",
        default_object.display(),
        default_bytes.len()
    );
    println!(
        "unsafe object: {} ({} bytes)",
        unsafe_object.display(),
        unsafe_bytes.len()
    );
    let mut child = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            "tests/python/test_entry_object.py",
            "--default-object",
        ])
        .arg(&default_object)
        .args(["--unsafe-object"])
        .arg(&unsafe_object)
        .arg("-v")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run actual paired entry-object suite");
    let reader = std::io::BufReader::new(child.stderr.take().expect("suite stderr"));
    let mut stderr = String::new();
    for line in reader.lines() {
        let line = line.expect("read suite line");
        println!("{line}");
        std::io::stdout().flush().expect("stream suite line");
        stderr.push_str(&line);
        stderr.push('\n');
    }
    let status = child.wait().expect("wait for suite");
    assert!(status.success(), "paired entry suite failed: {stderr}");
    assert!(
        stderr.contains(&format!("Ran {EXPECTED_TESTS} tests")),
        "expected {EXPECTED_TESTS} tests: {stderr}"
    );
    assert!(!stderr.contains("(skipped="), "skipped proof: {stderr}");
}
