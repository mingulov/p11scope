use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("reading {path}: {error}"))
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing section end: {end}"))
        .0
}

fn canary_literals(source: &str) -> std::collections::BTreeSet<String> {
    source
        .split('"')
        .filter(|value| value.starts_with("CANARY_"))
        .map(str::to_owned)
        .collect()
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

fn cleanup_function(path: &str) -> String {
    let source = read(path);
    format!(
        "cleanup() {{{}\n}}",
        between(&source, "cleanup() {", "\n}\n. scripts/cleanup-traps.sh")
    )
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
fn task6_protected_staging_allocators_separate_exec_and_output_mounts() {
    let helper = read("scripts/trusted-p11scope.sh");
    assert!(helper.contains("create_trusted_exec_dir"));
    assert!(helper.contains("sudo mktemp -d /usr/local/bin/.p11scope.XXXXXXXX"));
    assert!(helper.contains("create_protected_output_dir"));
    assert!(helper.contains("sudo mktemp -d /run/p11scope-output.XXXXXXXX"));
    assert!(helper.contains("noexec"));
    assert!(helper.contains("remove_trusted_exec_root"));
    assert!(helper.contains("remove_protected_output_dir"));
}

#[test]
fn task6_host_staging_separates_executables_from_protected_output() {
    for path in [
        "scripts/build-release.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
    ] {
        let script = read(path);
        assert!(
            script.contains("create_trusted_exec_dir"),
            "{path} does not allocate protected executable staging"
        );
        assert!(
            script.contains("create_protected_output_dir"),
            "{path} does not allocate protected output staging"
        );
        assert!(
            !script.contains("TRUST_DIR=\"$PWD"),
            "{path} executes a root observer below a user-writable ancestor"
        );
        assert!(
            script.contains("-o \"$RUN_DIR/"),
            "{path} does not give root a protected output path"
        );
    }

    let induced = read("scripts/verify-induced-gaps.sh");
    assert!(induced.contains("$TRUST_ROOT/freeze-policy-maps"));
    assert!(
        !induced.contains("\"$RUN_DIR/freeze-policy-maps\""),
        "the noexec output mount still hosts an executed helper"
    );
    assert!(
        read("src/oracle.rs").contains("const GLIBC_STAGING_DIRECTORY: &str = \"/run/p11scope\";")
    );
}

#[test]
fn task6_host_capture_lanes_pin_the_intended_oracle_mode() {
    let attach = read("scripts/verify-attach-e2e.sh");
    let attach_observe = between(&attach, "=== observe ===", "=== verify against");
    assert_eq!(attach_observe.matches("--trusted-workload").count(), 1);

    let canaries = read("scripts/verify-canaries.sh");
    assert!(!canaries.contains("sudo python3 scripts/dump-owned-bpf-maps.py"));
    assert!(canaries.contains("$TRUST_ROOT/dump-owned-bpf-maps.py"));
    let normal_canary = between(
        &canaries,
        "run_lane() {",
        "=== discover deterministic matrix providers ===",
    );
    let start_canary = between(
        &canaries,
        "run_start_lane() {",
        "=== live safe START policy",
    );
    assert_eq!(normal_canary.matches("--trusted-workload").count(), 1);
    assert_eq!(start_canary.matches("--trusted-workload").count(), 1);

    let induced = read("scripts/verify-induced-gaps.sh");
    assert!(!induced.contains("sudo python3 scripts/dump-owned-bpf-maps.py"));
    assert!(induced.contains("$TRUST_ROOT/dump-owned-bpf-maps.py"));
    for (start, end) in [
        ("=== policy-map immutability", "=== private softhsm token"),
        ("=== gap 1/5:", "=== gap 2/5:"),
        ("=== gap 2/5:", "=== gap 3/5:"),
        ("=== gap 3/5:", "=== gap 4/5:"),
        ("=== gap 4/5:", "=== gap 5/5:"),
        ("=== gap 5/5:", "=== induced gaps: ALL OK ==="),
    ] {
        let lane = between(&induced, start, end);
        assert_eq!(
            lane.matches("--trusted-workload").count(),
            1,
            "induced command section {start}"
        );
    }

    let release = read("scripts/build-release.sh");
    let hardened = release
        .split_once("=== official static hostile-target smoke ===")
        .expect("official Hardened smoke section")
        .1
        .split_once("=== dist/ ===")
        .unwrap()
        .0;
    assert!(hardened.contains("setpriv --no-new-privs"));
    assert!(hardened.contains("wait_for_hardened_target"));
    for field in [
        "State:",
        "Uid:",
        "CapInh:",
        "CapPrm:",
        "CapEff:",
        "CapAmb:",
        "NoNewPrivs:",
    ] {
        assert!(
            hardened.contains(field),
            "Hardened target check misses {field}"
        );
    }
    assert!(hardened.contains("--pid \"$WPID\""));
    assert!(!hardened.contains("--cgroup"));
    assert!(!hardened.contains("--trusted-workload"));
}

#[test]
fn task6_official_observer_build_is_isolated_and_safe_only() {
    let release = read("scripts/build-release.sh");
    assert!(release.contains("OFFICIAL_TARGET=target/release-official"));
    let official = between(
        &release,
        "=== p11scope: isolated safe-only official static build ===",
        "=== p11scope-discover: dynamic glibc + dynamic musl builds ===",
    );
    let command = [
        "CARGO_TARGET_DIR=\"$OFFICIAL_TARGET\" \\",
        "RUSTFLAGS=\"-C target-feature=+crt-static\" \\",
        "    cargo +1.88 build --locked --release --no-default-features \\",
        "        --target x86_64-unknown-linux-musl --bin p11scope",
    ]
    .join("\n");
    assert!(official.contains(&command));
    for marker in [
        "--policy-inventory \"$OFFICIAL_BPF\" \"$DIAGNOSTIC_BPF\"",
        "--unsafe-unvalidated-metadata requires a build with",
    ] {
        assert!(official.contains(marker), "official build misses {marker}");
    }

    let attach = read("scripts/verify-attach-e2e.sh");
    assert!(attach.contains("--target-dir \"$WORK/build\""));
    assert!(!attach.contains("x86_64-unknown-linux-musl"));
}

#[test]
fn task6_review_staging_paths_are_exact_and_publication_is_shared() {
    let status = Command::new("sh")
        .args([
            "-c",
            ". scripts/trusted-p11scope.sh; \
             is_immediate_child /run/p11scope-output.abc /run p11scope-output. && \
             ! is_immediate_child /run/p11scope-output.abc/child /run p11scope-output. && \
             ! is_immediate_child /run/p11scope-output.abc/../other /run p11scope-output. && \
             is_trusted_exec_destination /usr/local/bin/.p11scope.abc/default && \
             ! is_trusted_exec_destination /usr/local/bin/.p11scope.abc/default/child && \
             ! is_trusted_exec_destination /tmp/.p11scope.abc",
        ])
        .status()
        .expect("exercise staging path guard");
    assert!(status.success(), "staging path guard rejected its contract");

    let helper = read("scripts/trusted-p11scope.sh");
    assert!(helper.contains("require_non_root_caller"));
    assert!(helper.contains("publish_protected_file"));
    assert!(helper.contains("mktemp \"$work_dir/.${destination}.XXXXXXXX\""));
    assert!(helper.contains("validate_protected_parent /run"));
    assert!(helper.contains("sudo rmdir \"$destination\""));

    for path in [
        "scripts/build-release.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
    ] {
        let script = read(path);
        assert!(script.contains("require_non_root_caller"), "{path}");
        assert!(script.contains("publish_protected_file"), "{path}");
        assert!(!script.contains("publish_protected() {"), "{path}");
        assert!(!script.contains("copy_gap_output() {"), "{path}");
    }
}

#[test]
fn task6_review_hostile_lane_pins_sysctl_toolchain_and_target_identity() {
    let release = read("scripts/build-release.sh");
    assert!(release.contains("rustup target add --toolchain 1.88 x86_64-unknown-linux-musl"));

    let hostile = between(
        &release,
        "=== official static hostile-target smoke ===",
        "=== dist/ ===",
    );
    for marker in [
        "set_suid_dumpable_zero",
        "TARGET_STARTTIME",
        "signal_verified_process CONT \"$WPID\" \"$TARGET_STARTTIME\"",
    ] {
        assert!(hostile.contains(marker), "hostile lane misses {marker}");
    }
    assert!(!hostile.contains("sudo kill -CONT \"$WPID\""));

    let cleanup = between(&release, "cleanup() {", "\n}\n");
    assert!(cleanup.contains("restore_suid_dumpable"));
    assert!(cleanup.contains("TARGET_STARTTIME"));
    assert!(!cleanup.contains("sudo kill -KILL \"$WPID\""));
}

#[test]
fn task6_review_every_privileged_discovery_lane_pins_suid_dumpable() {
    let helper = read("scripts/trusted-p11scope.sh");
    for marker in [
        "set_suid_dumpable_zero()",
        "restore_suid_dumpable()",
        "/proc/sys/fs/suid_dumpable",
    ] {
        assert!(
            helper.contains(marker),
            "shared sysctl helper misses {marker}"
        );
    }

    for path in [
        "scripts/build-release.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
    ] {
        let script = read(path);
        assert!(
            script.contains("set_suid_dumpable_zero"),
            "{path} does not pin suid_dumpable before privileged discovery"
        );
        assert!(
            cleanup_function(path).contains("restore_suid_dumpable"),
            "{path} does not restore suid_dumpable during cleanup"
        );
    }
}

#[test]
fn task6_review_privileged_intermediates_never_use_user_work() {
    let canaries = read("scripts/verify-canaries.sh");
    for forbidden in [
        "sh \"$WORK/$lane.observer.pid\"",
        "sh \"$WORK/$start_lane.observer.pid\"",
        "--manifest \"$WORK/matrix-manifest.json\"",
        "--manifest \"$WORK/privacy-manifest.json\"",
        "\"$OBSERVER_PID\" \"$WORK\" \"$lane\"",
        "\"$OBSERVER_PID\" \"$WORK\" \"$start_lane\"",
    ] {
        assert!(
            !canaries.contains(forbidden),
            "canary root sink under WORK: {forbidden}"
        );
    }
    for required in [
        "\"$RUN_DIR/$lane.observer.pid\"",
        "\"$RUN_DIR/$start_lane.observer.pid\"",
        "--manifest \"$RUN_DIR/matrix-manifest.json\"",
        "--manifest \"$RUN_DIR/privacy-manifest.json\"",
    ] {
        assert!(
            canaries.contains(required),
            "canary protected artifact missing: {required}"
        );
    }

    let induced = read("scripts/verify-induced-gaps.sh");
    for forbidden in [
        "\"$WORK/freeze-supervisor.pid\"",
        "\"$WORK/freeze-policy-map-ids\"",
        "\"$OBSERVER_PID\" \"$WORK\" freeze-before",
        "\"$OBSERVER_PID\" \"$WORK\" freeze-after",
        "--manifest \"$WORK/freeze-manifest.json\"",
        "--manifest \"$WORK/g1_manifest.json\"",
        "--manifest \"$WORK/g2_manifest.json\"",
        "--manifest \"$WORK/g3_manifest.json\"",
        "--manifest \"$WORK/g4_manifest.json\"",
        "--manifest \"$WORK/g5_manifest.json\"",
    ] {
        assert!(
            !induced.contains(forbidden),
            "induced root sink under WORK: {forbidden}"
        );
    }
    for required in [
        "\"$RUN_DIR/freeze-supervisor.pid\"",
        "\"$RUN_DIR/freeze-policy-map-ids\"",
        "--manifest \"$RUN_DIR/freeze-manifest.json\"",
        "--manifest \"$RUN_DIR/g1_manifest.json\"",
    ] {
        assert!(
            induced.contains(required),
            "induced protected artifact missing: {required}"
        );
    }
}

#[test]
fn task6_review_root_signals_verify_process_starttime() {
    let helper = read("scripts/trusted-p11scope.sh");
    for marker in [
        "process_starttime",
        "signal_verified_process",
        "signal_verified_root_process",
        "os.pidfd_open",
        "signal.pidfd_send_signal",
        "raw.rsplit(b\") \", 1)",
    ] {
        assert!(
            helper.contains(marker),
            "PID identity helper missing: {marker}"
        );
    }

    let canaries = read("scripts/verify-canaries.sh");
    assert!(canaries.contains("OBSERVER_STARTTIME"));
    assert!(canaries.contains("signal_verified_root_process STOP"));
    assert!(canaries.contains("signal_verified_root_process CONT"));
    assert!(!canaries.contains("sudo kill -TERM \"$OBSERVER_PID\""));
    assert!(!canaries.contains("sudo kill -CONT \"$OBSERVER_PID\""));

    let induced = read("scripts/verify-induced-gaps.sh");
    assert!(induced.contains("SUPERVISOR_STARTTIME"));
    assert!(induced.contains("signal_verified_root_process INT"));
    assert!(!induced.contains("sudo kill -TERM \"$OBSERVER_PID\""));
    assert!(!induced.contains("sudo kill -TERM \"$SUPERVISOR_PID\""));
    assert!(!induced.contains("sudo kill -INT \"$SUPERVISOR_PID\""));
}

#[test]
fn task6_review_pidfd_signal_is_bound_to_the_recorded_identity() {
    let output = Command::new("sh")
        .args([
            "-c",
            r#"
set -eu
. scripts/trusted-p11scope.sh
sleep 30 & pinned_pid=$!
trap 'kill -KILL "$pinned_pid" 2>/dev/null || true; wait "$pinned_pid" 2>/dev/null || true' EXIT
pinned_start=$(process_starttime "$pinned_pid")
if signal_verified_process TERM "$pinned_pid" "$((pinned_start + 1))" 2>/dev/null; then
    exit 1
fi
kill -0 "$pinned_pid"
signal_verified_process STOP "$pinned_pid" "$pinned_start"
attempt=0
while [ "$attempt" -lt 100 ]; do
    state=$(awk '$1 == "State:" { print $2; exit }' "/proc/$pinned_pid/status")
    [ "$state" = T ] && break
    attempt=$((attempt + 1))
    sleep 0.01
done
[ "$state" = T ]
signal_verified_process CONT "$pinned_pid" "$pinned_start"
signal_verified_process TERM "$pinned_pid" "$pinned_start"
if wait "$pinned_pid"; then exit 1; else status=$?; fi
[ "$status" -eq 143 ]
pinned_pid=
trap - EXIT
"#,
        ])
        .output()
        .expect("exercise pidfd identity signal helper");
    assert!(
        output.status.success(),
        "pidfd helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn task6_review_capture_start_uses_bounded_exact_readiness() {
    for (path, log, privacy, kind) in [
        (
            "scripts/build-release.sh",
            "$WORK/profile-static-smoke.log",
            "aggregate-only",
            "metrics",
        ),
        (
            "scripts/verify-attach-e2e.sh",
            "$WORK/profile.log",
            "aggregate-only",
            "metrics",
        ),
    ] {
        let script = read(path);
        let call = format!("wait_for_capture_ready \"{log}\" {privacy} {kind}");
        assert!(script.contains(&call), "{path} misses exact readiness call");
        assert!(
            !script.contains("sleep 3"),
            "{path} retains fixed attach sleep"
        );
    }

    let induced = read("scripts/verify-induced-gaps.sh");
    assert!(!induced.contains("sleep 3"));
    assert!(induced.contains("wait_for_capture_ready"));
    assert!(induced.contains("aggregate-only") || induced.contains("allowlisted"));
    assert!(read("scripts/trusted-p11scope.sh").contains("kill -0 \"$SPID\""));
}

#[test]
fn task6_review_fixture_evidence_requires_full_exact_shape() {
    for path in ["scripts/build-release.sh", "scripts/verify-attach-e2e.sh"] {
        let script = read(path);
        assert!(script.contains("scripts/check-capture-evidence.py clean-metrics"));
    }

    let canaries = read("scripts/verify-canaries.sh");
    assert!(canaries.contains("scripts/check-capture-evidence.py canary \"$lane\""));
    assert!(!canaries.contains("ev[\"attached_probes\"] == 136"));
    let checker = read("scripts/check-capture-evidence.py");
    for marker in [
        "68, 68, 136",
        "988, 104, 208",
        "VERSION_SURFACES",
        "COUNTERS",
    ] {
        assert!(
            checker.contains(marker),
            "shared evidence oracle misses {marker}"
        );
    }
}

#[test]
fn task6_review_capture_evidence_checker_self_tests_exact_allowances() {
    let output = Command::new("python3")
        .args(["scripts/check-capture-evidence.py", "--self-test"])
        .output()
        .expect("run capture-evidence checker self-test");
    assert!(
        output.status.success(),
        "capture-evidence checker self-test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 checker output");
    for marker in [
        "unexpected positive function rejected: OK",
        "bootstrap function exact count required: OK",
        "canary matrix 988/104/208 with 13 mixed surfaces: OK",
        "canary safe exact allowances: OK",
        "canary unsafe exact allowances: OK",
        "canary aggregate exact baseline: OK",
        "induced G1 exact allowances: OK",
        "induced G2 exact allowances: OK",
        "induced G3 exact allowances: OK",
        "induced G4 exact allowances: OK",
        "induced G5 exact allowances: OK",
        "induced G5 exact 11 calls and 9 RV failures: OK",
        "unrelated evidence gap rejected: OK",
    ] {
        assert!(stdout.contains(marker), "checker self-test misses {marker}");
    }
}

#[test]
fn task6_review_cleanup_preserves_primary_status_and_attempts_every_root() {
    for path in [
        "scripts/build-release.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
    ] {
        let directory = tempfile::tempdir().expect("cleanup harness directory");
        let harness = directory.path().join("cleanup-harness.sh");
        fs::write(
            &harness,
            format!(
                r#"set -eu
. scripts/trusted-p11scope.sh
MARKER=$1
PRIMARY=$2
WPID= TARGET_STARTTIME= LPID= SPID= PUBLISH_TMP=
OBSERVER_PID= OBSERVER_STARTTIME= SUPERVISOR_PID= SUPERVISOR_STARTTIME= WORKER_STOPPED=
TRUST_DIR=default TRUST_UNSAFE_DIR=unsafe TRUST_ROOT=root
TRUST_DEFAULT_DIR=default TRUST_SMALL_DIR=small TRUST_FREEZE_DIR=freeze RUN_DIR=run
restore_suid_dumpable() {{ return 0; }}
signal_verified_process() {{ return 0; }}
signal_verified_root_process() {{ return 0; }}
sudo() {{ printf '%s\n' sudo >> "$MARKER"; return 7; }}
remove_trusted_p11scope() {{ printf '%s\n' trusted >> "$MARKER"; return 7; }}
remove_trusted_exec_root() {{ printf '%s\n' exec >> "$MARKER"; return 7; }}
remove_protected_output_dir() {{ printf '%s\n' output >> "$MARKER"; return 7; }}
{}
trap cleanup EXIT
exit "$PRIMARY"
"#,
                cleanup_function(path)
            ),
        )
        .expect("write cleanup harness");

        for primary in [23, 0] {
            let marker = directory.path().join(format!("cleanup-{primary}.log"));
            let output = Command::new("sh")
                .arg(&harness)
                .arg(&marker)
                .arg(primary.to_string())
                .output()
                .expect("run cleanup harness");
            if primary == 0 {
                assert!(!output.status.success(), "{path}: cleanup failure was lost");
            } else {
                assert_eq!(
                    output.status.code(),
                    Some(primary),
                    "{path}: cleanup masked primary status: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let markers = fs::read_to_string(&marker).unwrap_or_default();
            assert_eq!(
                markers.lines().last(),
                Some("output"),
                "{path}: cleanup skipped a later root: {markers:?}"
            );
        }
    }
}

#[test]
fn task6_review_observer_diagnostics_preserve_child_status() {
    for (path, diagnostic) in [
        ("scripts/build-release.sh", "cat"),
        ("scripts/verify-attach-e2e.sh", "tail"),
    ] {
        let source = read(path);
        let wait_branch = source
            .lines()
            .find(|line| line.contains("if wait \"$SPID\"") && line.contains(diagnostic))
            .unwrap_or_else(|| panic!("{path}: observer diagnostic branch missing"));
        let directory = tempfile::tempdir().expect("diagnostic harness directory");
        let harness = directory.path().join("diagnostic-harness.sh");
        fs::write(
            &harness,
            format!(
                r#"set -eu
SPID=1
WORK=missing
wait() {{ return 37; }}
cat() {{ return 41; }}
tail() {{ return 42; }}
{wait_branch}
"#
            ),
        )
        .expect("write diagnostic harness");
        let output = Command::new("sh")
            .arg(&harness)
            .output()
            .expect("run observer diagnostic harness");
        assert_eq!(
            output.status.code(),
            Some(37),
            "{path}: {diagnostic} masked observer status: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn task6_host_terminal_assertions_match_unproven_drain_and_lease_abort() {
    for path in ["scripts/build-release.sh", "scripts/verify-attach-e2e.sh"] {
        let script = read(path);
        assert!(script.contains("scripts/check-capture-evidence.py clean-metrics"));
    }

    let canaries = read("scripts/verify-canaries.sh");
    for marker in [
        "pkcs11-scope/observed-profile/v1.4",
        "pkcs11-scope/observed-profile/v1.1-metrics",
        "trace_abort_terminal",
        "capture_aborted",
        "object_lease_break",
        "counters_available",
        "final_drain",
    ] {
        assert!(
            canaries.contains(marker),
            "canary terminal oracle misses {marker}"
        );
    }
    let checker = read("scripts/check-capture-evidence.py");
    assert!(checker.contains("COUNTERS"));
    assert!(checker.contains("\"completeness\"] == \"PARTIAL\""));
    assert_eq!(p11scope::verify::OBJECT_CHANGED_EXIT, 78);
}

#[test]
fn task6_review_host_shell_syntax_is_checked_as_one_set() {
    for path in [
        "scripts/trusted-p11scope.sh",
        "scripts/build-release.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
    ] {
        let status = Command::new("sh")
            .args(["-n", path])
            .status()
            .unwrap_or_else(|error| panic!("sh -n {path}: {error}"));
        assert!(status.success(), "sh -n failed for {path}");
    }
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
        "assert_hostile_starts",
        "assert_raw_events",
        "signal_verified_root_process STOP \"$OBSERVER_PID\"",
        "wait_for_stopped \"$OBSERVER_PID\"",
        "signal_verified_root_process CONT \"$OBSERVER_PID\"",
        "--unsafe-unvalidated-metadata",
    ] {
        assert!(canaries.contains(marker), "canary gate misses {marker}");
    }
    assert!(!canaries.contains("assert_ring_empty"));
    let normal_lane = canaries
        .split_once("run_lane() {")
        .unwrap()
        .1
        .split_once("\n}\n\necho \"=== discover deterministic matrix providers ===\"")
        .unwrap()
        .0;
    let stop = normal_lane
        .find("signal_verified_root_process STOP \"$OBSERVER_PID\"")
        .unwrap();
    let stopped = normal_lane
        .find("wait_for_stopped \"$OBSERVER_PID\"")
        .unwrap();
    let release = normal_lane.find("touch \"$WORK/$lane.go\"").unwrap();
    assert!(stop < stopped && stopped < release);

    let start_lane = canaries.split_once("run_start_lane() {").unwrap().1;
    for marker in [
        "kill -0 \"$WPID\"",
        "kill -TERM \"$WPID\"",
        "[ \"$start_status\" -eq 143 ]",
    ] {
        assert!(start_lane.contains(marker), "START lane misses {marker}");
    }

    let blocked_lanes = canaries
        .split_once("done <<'BLOCKED_LANES'\n")
        .expect("blocked safe-policy lane table")
        .1
        .split_once("\nBLOCKED_LANES")
        .unwrap()
        .0;
    assert_eq!(
        blocked_lanes,
        "default-safe-start default\nfeature-safe-start feature"
    );

    let induced = read("scripts/verify-induced-gaps.sh");
    for marker in [
        "freeze_policy_maps \"$WPID\" \"$CGROUP_PATH\"",
        "/children",
        "wait_for_capture_ready",
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
        for line in read(path).lines().map(str::trim_start) {
            if !line.starts_with('#')
                && (line.starts_with("cargo ") || line.contains(" cargo build"))
            {
                assert!(
                    line.contains("cargo +1.88"),
                    "unpinned cargo command in {path}: {line}"
                );
            }
        }
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
            "-pthread",
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
        25
    );
    assert!(matrix.contains("canary_workload matrix: all calls CKR_OK"));

    let blocked = run_ok(
        workload.to_str().unwrap(),
        &[provider.to_str().unwrap(), "blocked"],
    );
    assert!(blocked.contains("blocked hostile subset: all calls CKR_OK"));
    let faults = run_ok(
        workload.to_str().unwrap(),
        &[provider.to_str().unwrap(), "faults"],
    );
    assert!(faults.contains("blocked template faults: all calls CKR_OK"));

    let lanes = run_ok("sh", &["scripts/verify-canaries.sh", "--self-test"]);
    assert!(lanes.contains("canary lane assertion self-test: OK"));
    assert!(lanes.contains("raw binary alias scanner self-test: OK"));
    assert!(lanes.contains("unsafe raw template oracle self-test: OK"));
    assert!(lanes.contains("raw policy oracle self-test: OK"));
    assert!(lanes.contains("full CallStart safe defaults self-test: OK"));
    assert!(lanes.contains("canary matrix 988/104/208 with 13 mixed surfaces: OK"));
    let mut sentinels = canary_literals(&read("scripts/fixtures/canary_workload.c"));
    sentinels.extend(canary_literals(&read(
        "scripts/fixtures/privacy-stack-workload.c",
    )));
    assert_eq!(sentinels.len(), 18, "unexpected fixture sentinel inventory");
    for sentinel in sentinels {
        assert!(
            lanes.contains(&sentinel),
            "scanner self-test omitted fixture sentinel {sentinel}"
        );
    }

    let dumper = run_ok(
        "python3",
        &["scripts/dump-owned-bpf-maps.py", "--self-test"],
    );
    assert!(dumper.contains("nonzero valid JSON rejected: OK"));
    assert!(dumper.contains("ordinary dump list validation: OK"));

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
    assert!(inspector.contains("malformed map definitions rejected: OK"));
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
