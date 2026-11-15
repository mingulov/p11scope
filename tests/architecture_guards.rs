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

/// Files that may change `RLIMIT_NOFILE` anywhere: the shared helper is
/// the only test-side owner, and the integration-test crate cannot link a
/// `cfg(test)` lib module.
const SETRLIMIT_ALLOWED_FILES: &[&str] = &[
    "src/test_support/isolation.rs",
    "tests/capture_stderr_delivery.rs",
];

/// Exact whitespace-normalized statements after
/// `libc::setrlimit(libc::RLIMIT_NOFILE` for the production raise sites
/// reserved for their own lane. Matching the whole statement keeps a new
/// raw change in a test module of the same file from hiding behind the
/// file-level allowance.
const SETRLIMIT_ALLOWED_SITES: &[(&str, &str)] = &[
    (
        "src/fd_budget.rs",
        ",&next)}!=0{returnErr(std::io::Error::last_os_error().to_string());}Ok(())",
    ),
    (
        "src/process.rs",
        ",&raised)}==0{Ok(limit.rlim_max.min(usize::MAXaslibc::rlim_t)asusize)}else{Ok(limit.rlim_cur.min(usize::MAXaslibc::rlim_t)asusize)}",
    ),
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
        if SETRLIMIT_ALLOWED_FILES.contains(&path.as_str()) {
            continue;
        }
        // Whitespace-normalized copy (comment-only lines dropped) so a call
        // split across lines is matched too. `line_starts` maps compact
        // offsets back to source lines for the report.
        let mut compact = String::new();
        let mut line_starts = vec![(0usize, 1usize)];
        for (index, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            line_starts.push((compact.len(), index + 1));
            compact.extend(line.chars().filter(|character| !character.is_whitespace()));
        }
        let mut search = 0;
        while let Some(offset) = compact[search..].find(needle) {
            let at = search + offset;
            let allowed = SETRLIMIT_ALLOWED_SITES.iter().any(|(site, suffix)| {
                *site == path.as_str() && compact[at + needle.len()..].starts_with(suffix)
            });
            if !allowed {
                let line = line_starts
                    .iter()
                    .rev()
                    .find(|(start, _)| *start <= at)
                    .map(|(_, line)| *line)
                    .unwrap_or(1);
                violations.push(format!("{path}:{line}"));
            }
            search = at + needle.len();
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
    // A production-file allowance is per statement, so a test module in
    // that file cannot add a raw limit change under its cover.
    let planted_in_production_file = vec![(
        "src/fd_budget.rs".to_string(),
        "mod tests {\n    fn raw() {\n        let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &saved) };\n    }\n}"
            .to_string(),
    )];
    assert_eq!(
        setrlimit_violations(&planted_in_production_file),
        vec!["src/fd_budget.rs:3".to_string()]
    );
    // A call split across lines is still one statement to the scanner.
    let planted_multiline = vec![(
        "src/planted.rs".to_string(),
        "let _ = unsafe {\n    libc::setrlimit(\n        libc::RLIMIT_NOFILE,\n        &saved,\n    )\n};"
            .to_string(),
    )];
    assert_eq!(
        setrlimit_violations(&planted_multiline),
        vec!["src/planted.rs:2".to_string()]
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

/// The collectors whose deep-scan cap decision must go through the one
/// census rule, with the marker that starts each file's inline test
/// module (production text is everything before it).
const CENSUS_COLLECTORS: &[(&str, &str)] = &[
    ("src/inspect_system.rs", "#[cfg(test)]\nmod tests {"),
    (
        "src/inspect_system/inventory_cgroup.rs",
        "#[cfg(test)]\nmod tests {",
    ),
];

/// One owner for the census cap rule: `census_over_cap` is defined once,
/// counts user processes through `user_process_pids`, and every collector
/// calls it instead of comparing a raw pid count with its cap.
fn census_cap_violations(sources: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    let owners: Vec<&(String, String)> = sources
        .iter()
        .filter(|(_, text)| text.contains("fn census_over_cap("))
        .collect();
    if owners.len() != 1 {
        violations.push(format!(
            "census_over_cap defined {} times (want exactly once)",
            owners.len()
        ));
    }
    for (path, text) in &owners {
        let body = &text[text.find("fn census_over_cap(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
        if !body.contains("user_process_pids(") {
            violations.push(format!(
                "{path}: census_over_cap does not count user processes"
            ));
        }
    }
    for (collector, test_marker) in CENSUS_COLLECTORS {
        let Some((_, text)) = sources.iter().find(|(path, _)| path == collector) else {
            violations.push(format!("{collector}: missing"));
            continue;
        };
        let production = text.split(test_marker).next().unwrap_or(text);
        // The owner's own body is the rule itself, not a bypass of it.
        let production = match production.find("fn census_over_cap(") {
            Some(start) => {
                let end = production[start..]
                    .find("\n}\n")
                    .map_or(production.len(), |end| start + end);
                format!("{}{}", &production[..start], &production[end..])
            }
            None => production.to_string(),
        };
        let compact: String = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(|line| line.chars().filter(|character| !character.is_whitespace()))
            .collect();
        if !compact.contains("census_over_cap(") {
            violations.push(format!(
                "{collector}: cap decision bypasses census_over_cap"
            ));
        }
        for raw in [".len()>cap", ".len()>max_scan_pids"] {
            if compact.contains(raw) {
                violations.push(format!("{collector}: raw census comparison `{raw}`"));
            }
        }
    }
    violations
}

#[test]
fn census_cap_rule_has_one_owner() {
    let sources = rust_sources("src");
    assert_eq!(
        census_cap_violations(&sources),
        Vec::<String>::new(),
        "every collector's deep-scan cap must go through census_over_cap"
    );
}

#[test]
fn census_cap_guard_detects_planted_violations() {
    let owner = (
        "src/inspect_system.rs".to_string(),
        "pub(crate) fn census_over_cap(pids: &[u32], proc_root: &Path, cap: usize) -> bool {\n    \
         user_process_pids(pids, proc_root).len() > cap\n}\n\
         fn collect() { let cap_hit = census_over_cap(&pids, root, cap); }\n\
         #[cfg(test)]\nmod tests {\n    fn twin() { assert!(pids.len() > cap); }\n}\n"
            .to_string(),
    );
    let cgroup = (
        "src/inspect_system/inventory_cgroup.rs".to_string(),
        "fn collect() { let cap_hit = census_over_cap(&pids, root, cap); }\n".to_string(),
    );
    assert!(census_cap_violations(&[owner.clone(), cgroup.clone()]).is_empty());
    // A collector comparing its raw pid count with the cap.
    let raw = (
        "src/inspect_system/inventory_cgroup.rs".to_string(),
        "fn collect() {\n    let cap_hit = pids.len()\n        > cap;\n}\n".to_string(),
    );
    assert_eq!(
        census_cap_violations(&[owner.clone(), raw]),
        vec![
            "src/inspect_system/inventory_cgroup.rs: cap decision bypasses census_over_cap"
                .to_string(),
            "src/inspect_system/inventory_cgroup.rs: raw census comparison `.len()>cap`"
                .to_string(),
        ]
    );
    // A second owner, and an owner that counts every pid.
    let second = (
        "src/discovery/census.rs".to_string(),
        "fn census_over_cap(pids: &[u32], cap: usize) -> bool {\n    pids.len() > cap\n}\n"
            .to_string(),
    );
    assert_eq!(
        census_cap_violations(&[owner, cgroup, second]),
        vec![
            "census_over_cap defined 2 times (want exactly once)".to_string(),
            "src/discovery/census.rs: census_over_cap does not count user processes".to_string(),
        ]
    );
}
