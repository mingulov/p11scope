use std::fs;
use std::path::Path;
use std::process::Command;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("reading {path}: {error}"))
}

#[test]
fn privacy_gate_uses_observer_owned_live_maps() {
    let script = read("scripts/verify-canaries.sh");
    assert!(script.contains("dump-owned-bpf-maps.py"));
    assert!(script.contains("mapdump_START_live.json"));
    assert!(!script.contains("bpftool prog show"));
    assert!(!script.contains("progs_before.json"));
}

#[test]
fn release_packages_and_smokes_the_documented_helper_path() {
    let script = read("scripts/build-release.sh");
    assert!(script.contains("verify-canaries.sh"));
    assert!(script.contains("$DIST/p11scope-discover\""));
    assert!(script.contains("$DIST/p11scope\" discover"));
}

#[test]
fn induced_gaps_pin_embedded_map_capacities() {
    let script = read("scripts/verify-induced-gaps.sh");
    assert!(script.contains("check-bpf-map-defs.py"));
    assert!(script.contains("START=1"));
    assert!(script.contains("RV_COUNTS=1"));
}

#[test]
fn spike_count_check_refuses_missing_inputs() {
    let script = read("spike/check.sh");
    assert!(script.contains("[ \"$#\" -ne 2 ]"));
}

#[test]
fn container_discovery_covers_all_table_sizes_and_nonstandard_names() {
    let script = read("scripts/verify-discover-containers.sh");
    assert!(script.contains("version_matrix.c"));
    for marker in ["68", "92", "104", "corroborated_standard_prefix"] {
        assert!(script.contains(marker), "container gate misses {marker}");
    }
}

#[test]
fn public_docs_pin_current_schema_support_and_stable_privacy_symbols() {
    let readme = read("README.md");
    for marker in ["observed-profile/v1.3", "2.00", "2.40", "3.2", "Alternate"] {
        assert!(readme.contains(marker), "README misses {marker}");
    }

    let schema = read("docs/schema/observed-profile-v1.md");
    for marker in [
        "p11scope-manifest/3",
        "observed-profile/v1.3",
        "observed-profile/v1-metrics",
        "v1.2 → v1.3",
        "process_tracking_failures",
        "sessions.closed",
    ] {
        assert!(schema.contains(marker), "schema doc misses {marker}");
    }

    let allowlist = read("docs/privacy/allowlist-v1.md");
    for symbol in [
        "arg_u64",
        "walk_template",
        "capture_async_target",
        "p11_entry_template",
    ] {
        assert!(
            allowlist.contains(symbol),
            "privacy contract misses {symbol}"
        );
    }
    assert!(
        !allowlist.contains(".rs:"),
        "privacy contract uses unstable source line citations"
    );

    let usage = read("docs/usage.md");
    let main = read("src/main.rs");
    for source in [&usage, &main] {
        assert!(source.contains("due to attach cookies"));
        assert!(!source.contains("5.15 native cgroup"));
    }
}

#[test]
fn privileged_and_namespace_gates_preserve_manifest_provenance() {
    for path in [
        "scripts/bench-overhead.sh",
        "scripts/build-release.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
        "scripts/matrix/verify-docker.sh",
        "scripts/matrix/verify-fork-scope.sh",
        "scripts/matrix/verify-kind-pod.sh",
        "scripts/matrix/verify-knative.sh",
        "scripts/matrix/verify-oracle.sh",
        "scripts/matrix/verify-shared-layer.sh",
    ] {
        assert!(
            read(path).contains("stage_trusted_p11scope"),
            "{path} does not stage the root-owned discovery oracle"
        );
    }
    for path in [
        "scripts/matrix/verify-docker.sh",
        "scripts/matrix/verify-kind-pod.sh",
        "scripts/matrix/verify-knative.sh",
        "scripts/matrix/verify-shared-layer.sh",
    ] {
        assert!(
            read(path).contains("--provenance-module"),
            "{path} does not authenticate its rewritten attach path"
        );
    }
    for path in [
        "scripts/matrix/verify-docker.sh",
        "scripts/matrix/verify-shared-layer.sh",
    ] {
        let script = read(path);
        assert!(
            script.contains("docker cp -L"),
            "{path} can stage a dangling provider symlink"
        );
        assert!(script.contains("[ ! -L \"$PROVENANCE_MODULE\" ]"));
    }
    for path in ["src/main.rs", "src/discover_cmd.rs"] {
        assert!(
            !read(path).contains("--trust-manifest"),
            "unsafe bypass in {path}"
        );
    }
}

#[test]
fn privileged_matrix_waits_are_set_e_safe() {
    for path in [
        "scripts/matrix/verify-fork-scope.sh",
        "scripts/matrix/verify-oracle.sh",
    ] {
        let script = read(path);
        assert!(
            script.contains("if wait \"$LAUNCHER_PID\"; then"),
            "{path} has a dead wait status path"
        );
        assert!(
            script.contains("if wait \"$PROFILE_PID\"; then"),
            "{path} can orphan the observer"
        );
        assert!(!script.contains("wait \"$LAUNCHER_PID\"\nLAUNCHER_RC=$?"));
    }
}

#[test]
fn oracle_compares_full_width_ck_rv_keys() {
    let script = read("scripts/matrix/verify-oracle.sh");
    assert!(script.contains("0xffffffffffffffff:016x"));
    assert!(!script.contains("0xffffffff:08x"));
}

#[test]
fn every_shell_wait_is_set_e_safe() {
    fn check_tree(path: &Path) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                check_tree(&path);
            } else if path.extension().is_some_and(|extension| extension == "sh") {
                for (line_number, line) in fs::read_to_string(&path).unwrap().lines().enumerate() {
                    let line = line.trim_start();
                    assert!(
                        !line.starts_with("wait \"$") || line.contains("|| true"),
                        "{}:{} uses raw wait under set -e; use `if wait` so cleanup and status reporting run",
                        path.display(),
                        line_number + 1
                    );
                }
            }
        }
    }

    check_tree(Path::new("scripts"));
}

#[test]
fn every_reaped_pid_is_cleared_on_both_wait_paths() {
    fn check_tree(path: &Path) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                check_tree(&path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "sh") {
                continue;
            }

            let source = fs::read_to_string(&path).unwrap();
            let lines = source.lines().collect::<Vec<_>>();
            for (line_number, line) in lines.iter().enumerate() {
                let Some(rest) = line.trim_start().strip_prefix("if wait \"$") else {
                    continue;
                };
                let pid = rest.split_once('"').unwrap().0;
                let end = lines[line_number..]
                    .iter()
                    .position(|line| line.contains("; fi") || line.trim() == "fi")
                    .unwrap();
                let block = lines[line_number..=line_number + end].join("\n");
                let (success, failure) = block.split_once("else").unwrap();
                let cleared = format!("{pid}=");
                assert!(
                    success.contains(&cleared) && failure.contains(&cleared),
                    "{}:{} leaves reaped {pid} live in an EXIT trap",
                    path.display(),
                    line_number + 1
                );
            }
        }
    }

    check_tree(Path::new("scripts"));

    let canaries = read("scripts/verify-canaries.sh");
    for line in canaries
        .lines()
        .filter(|line| line.contains("wait \"$SPID\""))
    {
        if line.trim_start().starts_with("if wait") {
            assert_eq!(line.matches("OBSERVER_PID=").count(), 2);
        }
    }
}

#[test]
fn release_script_cleanup_terminates_on_signals_and_preserves_status() {
    let helper = fs::canonicalize("scripts/cleanup-traps.sh").unwrap();
    for (action, expected) in [
        ("kill -INT $$", 130),
        ("kill -TERM $$", 143),
        ("exit 23", 23),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("cleanup-status");
        let script = format!(
            r#"cleanup() {{
    status=$?
    trap - EXIT INT TERM
    printf '%s' "$status" > "$TRAP_TEST_MARKER"
    exit "$status"
}}
. "$TRAP_HELPER"
{action}
exit 99
"#
        );
        let status = Command::new("sh")
            .args(["-c", &script])
            .env("TRAP_TEST_MARKER", &marker)
            .env("TRAP_HELPER", &helper)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(expected), "action: {action}");
        assert_eq!(read(marker.to_str().unwrap()), expected.to_string());
    }

    for path in [
        "scripts/build-release.sh",
        "scripts/bench-overhead.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-induced-gaps.sh",
        "scripts/verify-canaries.sh",
        "scripts/matrix/verify-oracle.sh",
        "scripts/matrix/verify-fork-scope.sh",
    ] {
        assert!(
            read(path).contains(". scripts/cleanup-traps.sh"),
            "{path} does not install the tested cleanup policy"
        );
    }
}

#[test]
fn ebpf_capture_does_not_assume_unwritten_stack_bytes_or_wrap_template_counts() {
    let source = read("crates/ebpf/src/main.rs");
    assert!(!source.contains("assume_init()"));
    assert!(source.contains("count.min(u32::MAX as u64) as u32"));
    assert!(source.contains("static ATTR_BOOL_BITS: HashMap<u32, u32>"));
    assert!(source.contains("if attr_type > u32::MAX as u64"));
    assert!(!source.contains("let attr_type = t as u32"));
}

#[test]
fn ebpf_user_addresses_and_pair_cleanup_fail_closed() {
    let source = read("crates/ebpf/src/main.rs");
    assert!(source.matches("checked_add(").count() >= 7);
    assert!(!source.contains("(pmech + 16) as *const"));
    assert!(!source.contains("(pmech + 8) as *const"));
    assert!(!source.contains("(pparam + o"));
    assert!(!source.contains("(base + 8) as *const"));
    assert!(!source.contains("(rsp + 8) as *const"));
    assert!(source.contains("START.remove(&key)"));
    assert!(source.contains("ambiguous nested call"));
}

#[test]
fn ebpf_boolean_reads_and_cgroup_migration_emit_gap_evidence() {
    let source = read("crates/ebpf/src/main.rs");
    let template = source
        .split_once("fn walk_template")
        .unwrap()
        .1
        .split_once("fn arg_u64")
        .unwrap()
        .0;
    assert!(template.contains("bpf_probe_read_user(value_addr as *const [u64; 2])"));
    assert!(template.contains("bpf_probe_read_user(pvalue as *const u8)"));
    assert!(
        template.matches("capture_failure(start);").count() >= 4,
        "every template metadata/value failure must become evidence"
    );

    let ret = source.split_once("pub fn p11_return").unwrap().1;
    let key = ret.find("let key = StartKey").unwrap();
    let scope = ret.find("if !in_scope()").unwrap();
    let cleanup = ret.find("START.remove(&key)").unwrap();
    assert!(key < scope && scope < cleanup);
    assert!(ret[cleanup..].contains("EVIDENCE_UNMATCHED_RETURNS"));
}

#[test]
fn pre_attach_returns_are_ignored_without_false_gap_evidence() {
    let source = read("crates/ebpf/src/main.rs");
    let ret = source.split_once("pub fn p11_return").unwrap().1;
    let missing = ret
        .split_once("let Some(&start)")
        .unwrap()
        .1
        .split_once("if START.remove(&key).is_err()")
        .unwrap()
        .0;
    assert!(missing.contains("else {\n        return 0;"));
    assert!(!missing.contains("EVIDENCE_UNMATCHED_RETURNS"));
}

#[test]
fn trace_reuses_the_complete_evidence_contract() {
    let main = read("src/main.rs");
    let trace = read("src/trace.rs");
    assert!(main.contains("trace::evidence_line"));
    assert!(trace.contains("EVIDENCE "));
    assert!(trace.contains("serde_json::to_string(ev)"));
}

#[test]
fn discovery_privilege_and_provider_target_boundaries_are_enforced() {
    let dispatcher = read("src/discover_cmd.rs");
    let helper = read("crates/discover/src/main.rs");
    let discover = read("crates/discover/src/discover.rs");
    assert!(dispatcher.contains("setresuid"));
    assert!(dispatcher.contains("PR_SET_NO_NEW_PRIVS"));
    assert!(helper.contains("drop_privileges"));
    assert!(helper.contains("PR_SET_DUMPABLE"));
    assert!(discover.contains("permissions[2] != b'x'"));
    assert!(discover.contains("loaded for this provider"));
}
