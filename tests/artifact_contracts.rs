use std::collections::BTreeMap;
use std::fs;
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
fn official_build_is_safe_only() {
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
}

#[test]
fn container_provider_streams_are_byte_capped() {
    // A hostile image controls how many bytes the copy step reads. Under the
    // cap succeeds; reaching the cap and an empty stream both refuse, so a
    // truncated archive can never become an attach plan.
    let status = Command::new("sh")
        .args([
            "-c",
            ". scripts/lib.sh; \
             out=$(mktemp) || exit 1; \
             MAX_CONTAINER_TAR_BYTES=64; \
             capped_container_tar \"$out\" printf 'small' 2>/dev/null && \
             ! capped_container_tar \"$out\" sh -c 'head -c 4096 /dev/zero' 2>/dev/null && \
             ! capped_container_tar \"$out\" true 2>/dev/null; \
             result=$?; rm -f \"$out\"; exit $result",
        ])
        .status()
        .expect("exercise the container stream cap");
    assert!(status.success(), "container tar cap rejected its contract");

    // Only the knative lane still copies anything out of a container, because
    // it attaches before the pod exists and the memory scan has nothing to
    // read. Every other container lane discovers by scanning the container's
    // own mapped bytes, so it must not copy a provider at all.
    let path = "scripts/matrix/verify-knative.sh";
    let script = read(path);
    assert!(script.contains("capped_container_tar"), "{path}");
    assert!(!script.contains(". > \"$WORK/provider.tar\""), "{path}");
    for path in [
        "scripts/matrix/verify-docker.sh",
        "scripts/matrix/verify-shared-layer.sh",
        "scripts/matrix/verify-kind-pod.sh",
        "scripts/attach-pod.sh",
    ] {
        let script = read(path);
        for banned in [
            "capped_container_tar",
            "discover_copied_provider",
            "--manifest",
        ] {
            assert!(
                !script.contains(banned),
                "{path} still uses {banned}: the scan reads the container's own memory"
            );
        }
    }
}

#[test]
fn container_manifest_rewrite_refuses_escapes_and_rewrites_paths() {
    // Discovery runs on a host copy of the container's provider directory, so
    // every attach path must be rewritten into the container's mount view --
    // and a path that escapes the copy must never become an attach plan.
    let status = Command::new("sh")
        .args([
            "-c",
            r#"
set -eu
. scripts/lib.sh
root=$(mktemp -d) || exit 1
trap 'rm -rf "$root"' EXIT
mkdir "$root/copy"
: > "$root/copy/provider.so"
: > "$root/copy/dep.so"
: > "$root/escape.so"
manifest() {
    printf '{"schema":"p11scope-manifest/4","module_path":"%s","objects":[{"id":0,"path":"%s"},{"id":1,"path":"%s"}]}\n' \
        "$root/copy/provider.so" "$root/copy/provider.so" "$1" > "$root/in.json"
}
manifest "$root/copy/dep.so"
rewrite_container_manifest "$root/in.json" "$root/out.json" "$root/copy" /proc/42/root/usr/lib
grep -Fq '"module_path": "/proc/42/root/usr/lib/provider.so"' "$root/out.json"
grep -Fq '"path": "/proc/42/root/usr/lib/dep.so"' "$root/out.json"
# set -e ignores a `!`-negated command, so every refusal is an explicit branch.
if grep -Fq "$root/copy" "$root/out.json"; then echo "copy path leaked"; exit 1; fi
manifest "$root/copy/../escape.so"
if rewrite_container_manifest "$root/in.json" "$root/bad.json" "$root/copy" /proc/42/root/usr/lib 2>/dev/null; then echo "escape accepted"; exit 1; fi
printf '{"schema":"p11scope-manifest/3","module_path":"x","objects":[]}\n' > "$root/in.json"
if rewrite_container_manifest "$root/in.json" "$root/bad.json" "$root/copy" /proc/42/root/usr/lib 2>/dev/null; then echo "schema v3 accepted"; exit 1; fi
"#,
        ])
        .status()
        .expect("exercise the container manifest rewrite");
    assert!(
        status.success(),
        "container manifest rewrite broke its contract"
    );
}

#[test]
fn pidfd_signal_is_bound_to_recorded_identity() {
    let output = Command::new("sh")
        .args([
            "-c",
            r#"
set -eu
. scripts/lib.sh
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
fn capture_evidence_checker_self_test() {
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
        "clean metrics multiplier is exact: OK",
        "clean metrics discovery source is exact in all three lanes: OK",
        // The scan now contributes to the same capture as the manifest: the
        // version-matrix numbers are re-derived from a rooted run, not the
        // helper's alone. 988 -> 1216 entries and 13 -> 16 surfaces because
        // three of the provider's tables are also readable from its mapped
        // bytes; 104 slots and 208 probes are unchanged, because a slot is one
        // {object, offset} however many sources named it.
        "canary matrix 1216/104/208 with 16 mixed surfaces: OK",
        "canary scan contribution is required: OK",
        "canary freeze lane is manifest-only 988/104/208 with 13 surfaces: OK",
        "canary safe exact allowances: OK",
        "canary unsafe exact allowances: OK",
        "canary aggregate exact baseline: OK",
        "induced G1 exact allowances: OK",
        "induced G2 exact allowances: OK",
        "induced G3 exact allowances: OK",
        "induced G3 rejects state-map contamination: OK",
        "induced G3 exact function counts required: OK",
        "induced G4 exact allowances: OK",
        "induced G5 exact allowances: OK",
        "induced G5 exact 11 calls and 9 RV failures: OK",
        "unrelated evidence gap rejected: OK",
    ] {
        assert!(stdout.contains(marker), "checker self-test misses {marker}");
    }
}

#[test]
fn every_script_parses_with_sh_n() {
    for path in [
        "scripts/lib.sh",
        "scripts/gates.sh",
        "scripts/cleanup-traps.sh",
        "scripts/bench-overhead.sh",
        "scripts/build-release.sh",
        "scripts/attach-pod.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-inspect-doctor.sh",
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
        "scripts/verify-discover-containers.sh",
        "scripts/matrix/verify-docker.sh",
        "scripts/matrix/verify-fork-scope.sh",
        "scripts/matrix/verify-oracle.sh",
        "scripts/matrix/verify-shared-layer.sh",
        "scripts/matrix/verify-kind-pod.sh",
        "scripts/matrix/verify-knative.sh",
        "scripts/matrix/verify-proxy-stack.sh",
    ] {
        let status = Command::new("sh")
            .args(["-n", path])
            .status()
            .unwrap_or_else(|error| panic!("sh -n {path}: {error}"));
        assert!(status.success(), "sh -n failed for {path}");
    }
}

/// `scripts/attach-pod.sh` runs `p11scope profile --cgroup` against a pod the
/// operator names, so every name it accepts reaches a kubectl JSONPath filter
/// and a cgroup search. Its refusals are the contract, and they must hold with
/// no cluster, no sudo and no privileges.
#[test]
fn attach_pod_refuses_bad_arguments() {
    let output = Command::new("sh")
        .args(["scripts/attach-pod.sh", "--self-test"])
        .output()
        .expect("run attach-pod self-test");
    assert!(
        output.status.success(),
        "attach-pod self-test failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("attach-pod argument self-test: OK"));

    let script = read("scripts/attach-pod.sh");
    // The rewritten script attaches by cgroup and copies nothing: no provider
    // directory leaves the pod, and no manifest is rewritten into its mount view.
    assert!(
        script.contains("profile --cgroup"),
        "attach-pod must attach by cgroup"
    );
    for gone in [
        "rewrite_container_manifest",
        "provider-safe",
        "--trusted-workload",
    ] {
        assert!(!script.contains(gone), "attach-pod still references {gone}");
    }
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
    assert!(lanes.contains("canary matrix 1216/104/208 with 16 mixed surfaces: OK"));
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

/// The usage text is the contract for the manifest-free CLI, and the binary must
/// keep the exit codes that contract implies: 2 for a usage error, 0 for `--help`,
/// 1 with a single line for a target that cannot be read at all.
#[test]
fn usage_documents_every_subcommand_and_capture_needs_no_manifest() {
    for line in [
        "p11scope profile",
        "p11scope trace",
        "p11scope inspect --pid",
        "p11scope doctor",
        "p11scope-discover --module",
    ] {
        assert!(
            p11scope::cli::USAGE.contains(line),
            "{line} missing from usage"
        );
    }
    assert!(
        p11scope::cli::USAGE
            .contains("discovery scans the target's mapped memory — no manifest and no helper")
    );

    let bin = env!("CARGO_BIN_EXE_p11scope");
    let help = Command::new(bin)
        .arg("--help")
        .output()
        .expect("run --help");
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stderr).contains("p11scope inspect"));

    let no_pid = Command::new(bin)
        .arg("inspect")
        .output()
        .expect("run inspect");
    let stderr = String::from_utf8_lossy(&no_pid.stderr);
    assert_eq!(no_pid.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--pid"), "{stderr}");

    // A pid that names nothing: one line, exit 1, never a panic or a backtrace.
    let gone = Command::new(bin)
        .args(["inspect", "--pid", "2147483632"])
        .output()
        .expect("run inspect on a dead pid");
    let stderr = String::from_utf8_lossy(&gone.stderr);
    assert_eq!(gone.status.code(), Some(1), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn gate_scripts_pin_the_toolchain() {
    for path in [
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
        "scripts/verify-inspect-doctor.sh",
        "scripts/matrix/verify-fork-scope.sh",
        "scripts/matrix/verify-proxy-stack.sh",
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
}
