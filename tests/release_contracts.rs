use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("reading {path}: {error}"))
}

fn run_ok(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("running {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("command stdout is UTF-8")
}

fn embedded_map_definitions() -> BTreeMap<String, [u32; 7]> {
    let directory = tempfile::tempdir().expect("temporary map-inspection directory");
    let object = directory.path().join("p11scope-ebpf");
    let maps = directory.path().join("maps.bin");
    fs::write(&object, p11scope::EBPF_OBJECT).expect("write embedded eBPF object");

    let symbols = Command::new("llvm-readelf")
        .args(["-sW", object.to_str().unwrap()])
        .output()
        .expect("run llvm-readelf");
    assert!(
        symbols.status.success(),
        "{}",
        String::from_utf8_lossy(&symbols.stderr)
    );
    let dump = format!("maps={}", maps.display());
    let sections = Command::new("llvm-objcopy")
        .args(["--dump-section", &dump, object.to_str().unwrap()])
        .output()
        .expect("run llvm-objcopy");
    assert!(
        sections.status.success(),
        "{}",
        String::from_utf8_lossy(&sections.stderr)
    );
    let data = fs::read(maps).expect("read legacy map definitions");

    String::from_utf8(symbols.stdout)
        .expect("UTF-8 symbol table")
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 8 || fields[3] != "OBJECT" || fields[6].parse::<u32>().is_err() {
                return None;
            }
            let offset = usize::from_str_radix(fields[1], 16).ok()?;
            let bytes = data.get(offset..offset + 28)?;
            let mut definition = [0; 7];
            for (value, chunk) in definition.iter_mut().zip(bytes.chunks_exact(4)) {
                *value = u32::from_le_bytes(chunk.try_into().unwrap());
            }
            Some((fields[7].to_string(), definition))
        })
        .collect()
}

fn embedded_symbols() -> String {
    let directory = tempfile::tempdir().expect("temporary symbol-inspection directory");
    let object = directory.path().join("p11scope-ebpf");
    fs::write(&object, p11scope::EBPF_OBJECT).expect("write embedded eBPF object");
    let output = Command::new("llvm-readelf")
        .args(["-sW", object.to_str().unwrap()])
        .output()
        .expect("run llvm-readelf");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 symbol table")
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
fn metadata_feature_matrix() {
    for path in ["Cargo.toml", "crates/ebpf/Cargo.toml"] {
        assert!(
            read(path).contains("unsafe-unvalidated-metadata = []"),
            "{path} does not declare the diagnostic metadata feature"
        );
    }

    let build = read("build.rs");
    assert!(build.contains("CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA"));
    assert!(build.contains("features.join(\",\")"));
}

#[test]
fn immutable_policy_maps() {
    const BPF_F_RDONLY_PROG: u32 = 1 << 7;
    const FLAGS: usize = 4;
    let definitions = embedded_map_definitions();

    for name in [
        "CONFIG",
        "PID_FILTER",
        "SLOT_SEMANTICS",
        "ASYNC_FUNCTIONS",
        "MECH_SHAPE",
    ] {
        assert_eq!(definitions[name][FLAGS], BPF_F_RDONLY_PROG, "{name}");
    }
    assert_eq!(definitions["CGROUP_FILTER"][FLAGS], 0);
    assert!(!definitions.contains_key("ATTR_BOOL_BITS"));
    assert!(!definitions.contains_key("TEMPLATE_TAIL"));
    for name in ["STATS", "START", "RV_COUNTS", "EVENTS", "EVIDENCE"] {
        assert_eq!(definitions[name][FLAGS], 0, "dynamic map {name}");
    }
}

#[test]
fn policy_specific_ebpf() {
    const KEY_SIZE: usize = 1;
    let definitions = embedded_map_definitions();
    let symbols = embedded_symbols();

    assert_eq!(definitions["ASYNC_FUNCTIONS"][KEY_SIZE], 32);
    for unsafe_map in ["ATTR_BOOL_BITS", "TEMPLATE_TAIL"] {
        assert!(
            !definitions.contains_key(unsafe_map),
            "default object contains unsafe-only map {unsafe_map}"
        );
    }
    for unsafe_symbol in [
        "p11_entry_template",
        "p11_entry_template_types",
        "p11_entry_template_pair",
        "p11_entry_template_second",
        "walk_template",
        "decode_params",
    ] {
        assert!(
            !symbols.contains(unsafe_symbol),
            "default object contains unsafe-only symbol {unsafe_symbol}"
        );
    }

    let source = read("crates/ebpf/src/main.rs");
    let entry = source.split_once("fn p11_entry_impl").unwrap().1;
    let aggregate = entry.find("FLAG_POLICY_AGGREGATE").unwrap();
    let semantics = entry.find("SLOT_SEMANTICS").unwrap();
    let first_argument = entry.find("capture_scalar").unwrap();
    let async_name = entry.find("capture_async_target").unwrap();
    assert!(
        aggregate < semantics && aggregate < first_argument && aggregate < async_name,
        "aggregate entry must precede semantic and argument reads"
    );

    let ret = source.split_once("pub fn p11_return").unwrap().1;
    let aggregate = ret.find("FLAG_POLICY_AGGREGATE").unwrap();
    let semantics = ret.find("SLOT_SEMANTICS").unwrap();
    let event = ret.find("EVENTS.reserve").unwrap();
    assert!(aggregate < semantics && aggregate < event);
    let cleanup = ret.rfind("START.remove(&key)").unwrap();
    let safe_read = ret.find("return_allows_mechanism(rv)").unwrap();
    assert!(cleanup < safe_read);
    assert!(ret.contains("MECH_SHAPE.get(&value)"));
    assert!(ret.contains("EVIDENCE_UNREGISTERED_MECHANISMS"));
    assert!(ret.contains("EVIDENCE_SEMANTIC_CAPTURE_FAILURES"));

    let open_session = ret
        .split_once("let mut session = start.session;")
        .unwrap()
        .1
        .split_once("let mut async_value = start.async_value;")
        .unwrap()
        .0;
    assert!(open_session.contains("lifecycle::OPEN_SESSION"));
    assert!(open_session.contains("rv == 0 || rv == 0x204"));
    assert!(open_session.contains("bpf_probe_read_user(start.out_ptr as *const u64)"));
    assert!(open_session.contains("Ok(value) => session = value"));
    assert!(open_session.contains("Err(_) => bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES)"));

    let async_id = ret
        .split_once("let mut async_value = start.async_value;")
        .unwrap()
        .1
        .split_once("let ev = Event")
        .unwrap()
        .0;
    assert!(async_id.contains("rv == 0"));
    assert!(async_id.contains("lifecycle::ASYNC_GET_ID"));
    assert!(async_id.contains("bpf_probe_read_user(start.out_ptr as *const u64)"));
    assert!(async_id.contains("Ok(value) => async_value = value"));
    assert!(async_id.contains("capture::ASYNC_VALUE_UNREADABLE"));
    assert!(async_id.contains("bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES)"));
    assert_eq!(
        ret.matches("bpf_probe_read_user(start.out_ptr as *const u64)")
            .count(),
        2,
        "only C_OpenSession and C_AsyncGetID may dereference an output pointer"
    );

    let async_target = source
        .split_once("fn capture_async_target")
        .unwrap()
        .1
        .split_once("pub fn p11_entry")
        .unwrap()
        .0;
    assert!(async_target.contains("if pointer == 0"));
    assert!(async_target.contains("bpf_probe_read_user_str"));
    assert!(async_target.contains("read <= 0"));
    assert!(async_target.contains("FUNCTION_NAME_MAX_BYTES + 1"));
    assert!(async_target.contains("FunctionNameKey::default()"));
    assert!(async_target.contains("ASYNC_FUNCTIONS.get(&key)"));
    assert!(!source.contains("FUNCTION_HASH_OFFSET"));
    assert!(!source.contains("function_hash_step"));
    assert!(source.matches("checked_add(").count() >= 7);
}

#[test]
fn metadata_canary_matrix() {
    let canaries = read("scripts/verify-canaries.sh");
    let lane_block = canaries
        .split_once("done <<'LANES'\n")
        .expect("canary lane table")
        .1
        .split_once("\nLANES")
        .unwrap()
        .0;
    assert_eq!(
        lane_block,
        "default-safe-profile default profile\n\
default-safe-trace default trace\n\
feature-safe-profile feature profile\n\
feature-safe-trace feature trace\n\
feature-unsafe-profile feature-unsafe profile\n\
feature-unsafe-trace feature-unsafe trace\n\
aggregate-only-metrics default metrics"
    );
    for marker in [
        "assert_exact_owned_map_inventory",
        "assert_nonempty_start",
        "assert_ring_empty \"$WORK/mapdump_manifest_$lane.json\"",
        "--unsafe-unvalidated-metadata",
    ] {
        assert!(canaries.contains(marker), "canary gate misses {marker}");
    }

    let induced = read("scripts/verify-induced-gaps.sh");
    for marker in [
        "freeze_policy_maps \"$WPID\" \"$CGROUP_PATH\"",
        "/children",
        "wait_for_privacy_frame",
        "BPF_MAP_GET_FD_BY_ID",
        "BPF_OBJ_GET_INFO_BY_FD",
        "BPF_MAP_CREATE",
        "BPF_MAP_UPDATE_ELEM",
        "BPF_MAP_DELETE_ELEM",
        "BPF_PROG_GET_FD_BY_ID",
        "matched_result(control_rc, target_rc, target_errno)",
        "assert_dynamic_maps_advanced",
        "approval_capacity_refuses_the_whole_oversized_union",
        "START insertion loss",
        "RV update loss",
        "event loss",
    ] {
        assert!(induced.contains(marker), "induced-gap gate misses {marker}");
    }
    for name in [
        "CONFIG",
        "PID_FILTER",
        "CGROUP_FILTER",
        "SLOT_SEMANTICS",
        "ASYNC_FUNCTIONS",
        "MECH_SHAPE",
        "ATTR_BOOL_BITS",
        "TEMPLATE_TAIL",
        "STATS",
        "RV_COUNTS",
        "EVIDENCE",
    ] {
        assert!(induced.contains(name), "induced-gap gate misses map {name}");
    }

    for path in [
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
    ] {
        run_ok("sh", &["-n", path]);
    }
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("matrix-provider.so");
    let workload = directory.path().join("canary-workload");
    run_ok(
        "cc",
        &[
            "-shared",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-DPRIVACY_FIXTURE=1",
            "-o",
            provider.to_str().unwrap(),
            "crates/discover/tests/fixture/version_matrix.c",
        ],
    );
    run_ok(
        "cc",
        &[
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            workload.to_str().unwrap(),
            "scripts/fixtures/canary_workload.c",
            "-ldl",
        ],
    );
    let matrix = run_ok(
        workload.to_str().unwrap(),
        &[provider.to_str().unwrap(), "matrix"],
    );
    assert_eq!(
        matrix
            .lines()
            .filter(|line| line.ends_with(" -> 0x0"))
            .count(),
        24
    );
    assert!(matrix.contains("canary_workload matrix: all calls CKR_OK"));

    let lanes = run_ok("sh", &["scripts/verify-canaries.sh", "--self-test"]);
    assert!(lanes.contains("canary lane assertion self-test: OK"));

    let harness = induced
        .split_once("#define _GNU_SOURCE\n")
        .unwrap()
        .1
        .split_once("\nEOF\n")
        .unwrap()
        .0;
    assert!(!harness.contains("BPF_MAP_FREEZE"));
    let source = directory.path().join("freeze-policy-maps.c");
    let binary = directory.path().join("freeze-policy-maps");
    fs::write(&source, format!("#define _GNU_SOURCE\n{harness}")).unwrap();
    let compiled = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&binary)
        .arg(source)
        .output()
        .expect("compile freeze harness");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let harness_test = Command::new(binary)
        .arg("--self-test")
        .output()
        .expect("run freeze predicate self-test");
    assert!(harness_test.status.success());
    assert!(
        String::from_utf8_lossy(&harness_test.stdout)
            .contains("freeze matched-result self-test: OK")
    );

    let inspector = run_ok("python3", &["scripts/check-bpf-map-defs.py", "--self-test"]);
    assert!(inspector.contains("policy inventory self-test: OK"));

    let exact = p11scope_ebpf_common::FunctionNameKey::from_bytes(b"C_Encrypt\0").unwrap();
    let noncatalog = p11scope_ebpf_common::FunctionNameKey::from_bytes(b"C_Encrypu\0").unwrap();
    let injected_legacy_candidate = 30u32;
    let catalog = BTreeMap::from([(exact, injected_legacy_candidate)]);
    assert_eq!(catalog.get(&exact), Some(&injected_legacy_candidate));
    assert_eq!(
        catalog.get(&noncatalog),
        None,
        "a test-injected shared legacy candidate must not authorize a noncatalog exact name"
    );
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
    let scope = ret.find("let Some(flags) = scope_flags() else").unwrap();
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
