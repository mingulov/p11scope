//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Architecture guards (v0.8.0 P0): the allowlist-v1 byte-identity pin.
//!
//! Golden renderer snapshots land in this file after the port, mem-b2,
//! handle-table and keyrow-yield lanes land; Wave 0 carries only the sha pin.

use sha2::{Digest as _, Sha256};

/// Pinned sha256 of `docs/privacy/allowlist-v1.md` (Global Constraints).
const ALLOWLIST_V1_SHA256: &str =
    "26940546a4962008778650f66550d93e62f6228decc166fe8fba845a70b0df6e";

#[test]
fn allowlist_v1_sha256_pin() {
    let bytes =
        std::fs::read("docs/privacy/allowlist-v1.md").expect("read docs/privacy/allowlist-v1.md");
    let digest = Sha256::digest(&bytes);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex, ALLOWLIST_V1_SHA256,
        "docs/privacy/allowlist-v1.md changed: got {hex}, want {ALLOWLIST_V1_SHA256}"
    );
}

use std::collections::BTreeSet;

/// Files allowed to keep a raw test-side `RLIMIT_NOFILE` change or the
/// production raise sites reserved for their own lane.
const SETRLIMIT_ALLOWED: &[&str] = &[
    "src/test_support/isolation.rs",
    "src/fd_budget.rs",
    "src/process.rs",
    "tests/capture_stderr_delivery.rs",
];

/// Every remaining specialized re-exec child gate that is not a plain
/// isolated test body (readiness protocols, watchdogs, PTY fixtures), so a
/// new gate must use `src/test_support/isolation.rs` instead.
const CHILD_GATES_ALLOWED: &[(&str, &str)] = &[
    (
        "src/discovery/noise.rs",
        "P11SCOPE_DISCOVERY_NOISE_REPORT_CHILD",
    ),
    ("src/inventory/capture_tests.rs", "P11SCOPE_COUNT_CHILD"),
    ("src/inventory/capture_tests.rs", "P11SCOPE_STOPFLAG_CHILD"),
    (
        "src/inventory/dashboard_tests.rs",
        "P11SCOPE_DASHBOARD_STDIO_CHILD",
    ),
    (
        "src/inventory/diff/input_tests.rs",
        "P11SCOPE_DIFF_FIFO_CHILD",
    ),
    ("src/inventory/mod.rs", "P11SCOPE_CGROUP_STOP_TEST_CHILD"),
    ("src/inventory/mod.rs", "P11SCOPE_DASHBOARD_CANCEL_CHILD"),
    ("src/inventory/mod.rs", "P11SCOPE_NAMESPACE_OUTPUT_CHILD"),
    (
        "src/inventory/output_tests.rs",
        "P11SCOPE_INVENTORY_OUTPUT_FD_COUNT_CHILD",
    ),
    (
        "src/metrics/counter_reader.rs",
        "P11SCOPE_A27_SOFT1024_CHILD",
    ),
    (
        "src/metrics/counter_reader.rs",
        "P11SCOPE_SOFT1024_CHILD_DONE",
    ),
    (
        "src/run/cancellation_tests.rs",
        "P11SCOPE_CANCEL_MARKER_CHILD",
    ),
    (
        "src/run/diagnostics.rs",
        "P11SCOPE_CLEANUP_DIAGNOSTIC_CHILD",
    ),
    (
        "src/test_support/isolation.rs",
        "P11SCOPE_TEST_ISOLATED_CHILD",
    ),
    (
        "tests/identity_iter_standalone.rs",
        "P11SCOPE_PROBE_SHADOW_CHILD",
    ),
];

fn rust_sources(root: &str) -> Vec<(String, String)> {
    fn visit(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("read source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                visit(&path, out);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let relative = path
                    .strip_prefix(std::env::current_dir().expect("workspace root"))
                    .expect("source path under the workspace")
                    .to_string_lossy()
                    .into_owned();
                if relative != "tests/architecture_guards.rs" {
                    let text = std::fs::read_to_string(&path).expect("read Rust source");
                    out.push((relative, text));
                }
            }
        }
    }
    let mut out = Vec::new();
    visit(
        &std::path::Path::new(root)
            .canonicalize()
            .expect("canonical source root"),
        &mut out,
    );
    out.sort();
    out
}

fn setrlimit_violations(sources: &[(String, String)]) -> Vec<String> {
    let needle = concat!("libc::setrlimit(", "libc::RLIMIT_NOFILE");
    let mut violations = Vec::new();
    for (path, text) in sources {
        if SETRLIMIT_ALLOWED.contains(&path.as_str()) {
            continue;
        }
        for (line_number, line) in text.lines().enumerate() {
            if !line.trim_start().starts_with("//") && line.contains(needle) {
                violations.push(format!("{path}:{}", line_number + 1));
            }
        }
    }
    violations
}

fn child_gate_violations(sources: &[(String, String)]) -> Vec<String> {
    let allowed: BTreeSet<(&str, &str)> = CHILD_GATES_ALLOWED.iter().copied().collect();
    let mut violations = Vec::new();
    for (path, text) in sources {
        for (line_number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let mut rest = line;
            while let Some(quote) = rest.find('"') {
                rest = &rest[quote + 1..];
                if let Some(name) = rest.strip_prefix("P11SCOPE_") {
                    let end = name
                        .find(|character: char| {
                            !(character.is_ascii_uppercase()
                                || character.is_ascii_digit()
                                || character == '_')
                        })
                        .unwrap_or(name.len());
                    let name = format!("P11SCOPE_{}", &name[..end]);
                    if name.contains("CHILD") && !allowed.contains(&(path.as_str(), name.as_str()))
                    {
                        violations.push(format!("{path}:{} {name}", line_number + 1));
                    }
                }
            }
        }
    }
    violations
}

#[test]
fn raw_fd_limit_guards_stay_in_the_shared_helper() {
    let sources = rust_sources("src");
    let mut sources = sources;
    sources.extend(rust_sources("tests"));
    assert_eq!(
        setrlimit_violations(&sources),
        Vec::<String>::new(),
        "setrlimit(RLIMIT_NOFILE) outside src/test_support/isolation.rs"
    );
}

#[test]
fn reexec_child_gates_stay_in_the_shared_helper() {
    let mut sources = rust_sources("src");
    sources.extend(rust_sources("tests"));
    assert_eq!(
        child_gate_violations(&sources),
        Vec::<String>::new(),
        "a new re-exec child gate must use src/test_support/isolation.rs"
    );
}

#[test]
fn isolation_architecture_guard_detects_planted_violations() {
    let planted = vec![(
        "src/planted.rs".to_string(),
        "let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };\n\
         const CHILD: &str = \"P11SCOPE_PLANTED_CHILD\";"
            .to_string(),
    )];
    assert_eq!(
        setrlimit_violations(&planted),
        vec!["src/planted.rs:1".to_string()]
    );
    assert_eq!(
        child_gate_violations(&planted),
        vec!["src/planted.rs:2 P11SCOPE_PLANTED_CHILD".to_string()]
    );
    let allowed = vec![(
        "src/test_support/isolation.rs".to_string(),
        "libc::setrlimit(libc::RLIMIT_NOFILE, &next);\n\
         const CHILD_ENV: &str = \"P11SCOPE_TEST_ISOLATED_CHILD\";"
            .to_string(),
    )];
    assert!(setrlimit_violations(&allowed).is_empty());
    assert!(child_gate_violations(&allowed).is_empty());
}
