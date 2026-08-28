use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CASES: &[&str] = &[
    "ledger-missing-final-lf",
    "ledger-duplicate-row",
    "ledger-unsorted-row",
    "ledger-noncontiguous-seq",
    "ledger-4097th-row",
    "ledger-bad-field",
    "directory-listing-mutation",
    "undeclared-directory-entry",
    "unsafe-file-kind-or-identity",
    "trace-truncated",
    "trace-unparseable",
    "trace-lost-child",
    "trace-unaccounted-fd",
    "trace-missing-transitive-input",
    "trace-unknown-class",
    "production-undeclared-open",
    "production-input-mutation",
    "landlock-undeclared-read",
    "landlock-outside-write",
    "production-network-denied",
    "staging-collision",
    "staging-partial-pending",
    "staging-unexpected-entry",
    "staging-subject-drift",
    "lane09-mutable-base",
    "lane09-live-package-network",
    "lane09-broad-context",
    "lane09-missing-package",
    "authority-report-opaque",
    "tip-product-input-mutation",
    "tip-unrelated-report-accepted",
    "copy-source-replacement",
    "copy-destination-collision",
    "subject-replace-after-check",
    "subject-close-before-use",
    "subject-path-reopen",
    "subject-same-fd-check-use",
];

const INPUT_LEDGER_GOLDEN: &str = concat!(
    "input-v1\t0\tdynamic\tread\tpresent\t0644\t4\t",
    "0eb9e3089dc8479fdc76d897a20c1555c51505d9f13cc97a868af3ef5988dc87",
    "\texternal:/opt/rust/lib/libstd-abc.so\n",
    "input-v1\t1\tsymlink\tprobe\tpresent\t0777\t13\t",
    "730e2269528728efaabfdf0c18dd9a8326657e93b7a6e6af6bada4f5ffa8c405",
    "\texternal:/opt/rust/lib/libstd.so\n",
    "input-v1\t2\tdirectory\tenumerate\tpresent\t0755\t41\t",
    "d08775a2943728a4c3148c1a8262ae8ccb22c59789ef3f1efb1bc52e9fae8027",
    "\trepo:/\n",
    "input-v1\t3\trepo\tread\tpresent\t0644\t5\t",
    "d8c9f2728aa278ebcd33ccedf3ad309a866870ad5fb93a03526b4b7655c9e911",
    "\trepo:/Cargo.lock\n",
    "input-v1\t4\trepo\tread\tpresent\t0644\t10\t",
    "8a3cd5a81b3f9a621aa493d90c45f42ab571d4e42b8ae5aff351cb0a02d06d82",
    "\trepo:/Cargo.toml\n",
    "input-v1\t5\tabsent\tprobe\tENOENT\t-\t-\t-\trepo:/missing.cfg\n",
    "input-v1\t6\tvendor\tread\tpresent\t0644\t14\t",
    "16c2fca9e371936458d01576b4ca311c22d166a45539ccbc9104823d0b10db47",
    "\tvendor:/serde/src/lib.rs\n",
);

const INPUT_LEDGER_LARGE_SIZE: &str = concat!(
    "input-v1\t0\ttool\tread\tpresent\t0644\t2159017984\t",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "\texternal:/opt/rust/bin/rustc\n",
);

const INPUT_V1_RECONCILIATION_EXPECTED: &str = concat!(
    "input-v1\t0\trepo\tprobe\tpresent\t0600\t1\t",
    "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
    "\trepo:/blocker\n",
    "input-v1\t1\tabsent\tprobe\tENOTDIR\t-\t-\t-\trepo:/blocker/child\n",
    "input-v1\t2\tdirectory\tenumerate\tpresent\t0700\t4\t",
    "27a4f844873b98b62676cf72fa49841676f4b63221ae7afd85fdad5bbf4d85de",
    "\trepo:/enum\n",
    "input-v1\t3\tsymlink\tprobe\tpresent\t0777\t5\t",
    "4437e55da8273b6a2a433c93548a08cdab55f3e2cba9e08cc080dfdd67d04959",
    "\trepo:/link1\n",
    "input-v1\t4\tsymlink\tprobe\tpresent\t0777\t19\t",
    "21eec616add1a571e58aba55d5f1b9504205384b72a6b40976a4749a3e840b80",
    "\trepo:/link2\n",
    "input-v1\t5\tdirectory\tprobe\tpresent\t0700\t0\t",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "\trepo:/probe\n",
    "input-v1\t6\tabsent\tprobe\tENOENT\t-\t-\t-\trepo:/probe/missing\n",
    "input-v1\t7\tvendor\tread\tpresent\t0700\t4\t",
    "0eb9e3089dc8479fdc76d897a20c1555c51505d9f13cc97a868af3ef5988dc87",
    "\tvendor:/pkg/tool.bin\n",
);

const INPUT_LEDGER_INVALID: &[(&str, &str)] = &[
    (
        "eight-fields",
        "input-v1\t0\trepo\tread\tpresent\t0644\t1\trepo:/Cargo.lock\n",
    ),
    (
        "missing-final-lf",
        "input-v1\t0\ttool\tread\tpresent\t0644\t1\t1111111111111111111111111111111111111111111111111111111111111111\texternal:/opt/tool",
    ),
    (
        "duplicate-locator",
        "input-v1\t0\trepo\tread\tpresent\t0644\t1\t1111111111111111111111111111111111111111111111111111111111111111\trepo:/a\ninput-v1\t1\trepo\tread\tpresent\t0644\t1\t2222222222222222222222222222222222222222222222222222222222222222\trepo:/a\n",
    ),
    (
        "unsorted-locator",
        "input-v1\t0\trepo\tread\tpresent\t0644\t1\t1111111111111111111111111111111111111111111111111111111111111111\trepo:/z\ninput-v1\t1\trepo\tread\tpresent\t0644\t1\t2222222222222222222222222222222222222222222222222222222222222222\trepo:/a\n",
    ),
    (
        "leading-zero-seq",
        "input-v1\t00\trepo\tread\tpresent\t0644\t1\t1111111111111111111111111111111111111111111111111111111111111111\trepo:/a\n",
    ),
    (
        "noncontiguous-seq",
        "input-v1\t0\trepo\tread\tpresent\t0644\t1\t1111111111111111111111111111111111111111111111111111111111111111\trepo:/a\ninput-v1\t2\trepo\tread\tpresent\t0644\t1\t2222222222222222222222222222222222222222222222222222222222222222\trepo:/b\n",
    ),
    (
        "illegal-matrix-pair",
        "input-v1\t0\tdynamic\tprobe\tENOENT\t-\t-\t-\texternal:/x\n",
    ),
    (
        "absent-with-values",
        "input-v1\t0\tabsent\tprobe\tENOENT\t0644\t1\t1111111111111111111111111111111111111111111111111111111111111111\trepo:/x\n",
    ),
    (
        "namespace-class-mismatch",
        "input-v1\t0\trepo\tread\tpresent\t0644\t1\t1111111111111111111111111111111111111111111111111111111111111111\texternal:/x\n",
    ),
    (
        "dotdot-component",
        "input-v1\t0\trepo\tread\tpresent\t0644\t1\t1111111111111111111111111111111111111111111111111111111111111111\trepo:/src/../Cargo.toml\n",
    ),
];

fn snapshot_tree(root: &Path) -> BTreeSet<(PathBuf, &'static str)> {
    fn visit(root: &Path, current: &Path, entries: &mut BTreeSet<(PathBuf, &'static str)>) {
        for entry in fs::read_dir(current)
            .expect("read fixture directory")
            .map(|entry| entry.expect("read fixture entry"))
        {
            let path = entry.path();
            let file_type = fs::symlink_metadata(&path)
                .expect("read fixture entry metadata")
                .file_type();
            let kind = if file_type.is_dir() {
                "directory"
            } else if file_type.is_file() {
                "regular"
            } else if file_type.is_symlink() {
                "symlink"
            } else {
                "other"
            };
            entries.insert((
                path.strip_prefix(root)
                    .expect("fixture entry is below root")
                    .to_path_buf(),
                kind,
            ));
            if file_type.is_dir() {
                visit(root, &path, entries);
            }
        }
    }

    let mut entries = BTreeSet::new();
    visit(root, root, &mut entries);
    entries
}

#[test]
fn task4_build_subject_self_test_is_rootless_and_complete() {
    struct Cleanup(std::path::PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "p11scope-task4-build-subjects-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create private Task 4 fixture");
    let _cleanup = Cleanup(root.clone());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("chmod private Task 4 fixture");

    let fake_bin = root.join("tripwire-bin");
    let work = root.join("work");
    let staging = root.join("staging");
    let runtime = root.join("runtime");
    let report = root.join("report.tsv");
    let tripwire_log = root.join("tripwire.log");
    fs::create_dir(&fake_bin).expect("create private tripwire directory");
    fs::create_dir(&work).expect("create private self-test work directory");
    fs::set_permissions(&fake_bin, fs::Permissions::from_mode(0o700))
        .expect("chmod private tripwire directory");
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700))
        .expect("chmod private self-test work directory");

    let tripwire_names = [
        "bash",
        "bpftool",
        "bpftrace",
        "cargo",
        "cc",
        "clang",
        "clang++",
        "curl",
        "docker",
        "file",
        "gcc",
        "g++",
        "ip",
        "ld",
        "ld.lld",
        "make",
        "ninja",
        "p11scope",
        "p11scope-discover",
        "podman",
        "python",
        "python3",
        "rust-lld",
        "rustc",
        "rustdoc",
        "rustup",
        "setpriv",
        "sh",
        "strace",
        "sudo",
        "systemctl",
        "systemd-run",
        "wget",
    ];
    let tripwire =
        b"#!/bin/sh\nprintf '%s\\n' \"${0##*/}\" >> \"$P11SCOPE_TASK4_TRIPWIRE_LOG\"\nexit 97\n";
    for name in tripwire_names {
        let path = fake_bin.join(name);
        fs::write(&path, tripwire).expect("write tripwire");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod tripwire");
    }

    let repo_before = snapshot_tree(repo);
    let fake_bin_before = snapshot_tree(&fake_bin);
    let root_before = snapshot_tree(&root);

    let mut command = Command::new("/usr/bin/python3");
    command
        .args(["scripts/task4-build-subject.py", "--self-test"])
        .current_dir(repo)
        .env_clear()
        .env("PATH", &fake_bin)
        .env("TMPDIR", &root)
        .env("P11SCOPE_TASK4_SELF_TEST_WORK", &work)
        .env("P11SCOPE_TASK4_WORK", &work)
        .env("P11SCOPE_TASK4_SELF_TEST_REPORT", &report)
        .env("P11SCOPE_TASK4_SELF_TEST_STAGING", &staging)
        .env("P11SCOPE_TASK4_SELF_TEST_RUNTIME", &runtime)
        .env("P11SCOPE_TASK4_TRIPWIRE_LOG", &tripwire_log);
    for (variable, command_name) in [
        ("BPFTOOL", "bpftool"),
        ("CARGO", "cargo"),
        ("CC", "gcc"),
        ("CXX", "g++"),
        ("DOCKER", "docker"),
        ("LD", "ld"),
        ("PODMAN", "podman"),
        ("RUSTC", "rustc"),
        ("RUSTUP", "rustup"),
        ("STRACE", "strace"),
        ("SUDO", "sudo"),
        ("SYSTEMD_RUN", "systemd-run"),
    ] {
        command.env(variable, fake_bin.join(command_name));
    }

    let output = command
        .output()
        .expect("run /usr/bin/python3 scripts/task4-build-subject.py --self-test");
    assert!(
        output.status.success(),
        "Task 4 build-subject self-test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "self-test wrote to stdout");
    assert!(
        output.stderr.len() <= 64 * 1024,
        "self-test stderr is unbounded"
    );

    let report_bytes = fs::read(&report).expect("read private self-test report");
    assert!(
        report_bytes.len() <= 4 * 1024 * 1024,
        "self-test report is unbounded"
    );
    let report_text = String::from_utf8(report_bytes).expect("self-test report is UTF-8");
    let mut expected_report = String::new();
    for case in CASES {
        expected_report.push_str("selftest-v1\tcase\t");
        expected_report.push_str(case);
        expected_report.push_str("\tOK\tOK\n");
    }
    expected_report.push_str("selftest-v1\tcomplete\n");
    assert_eq!(report_text, expected_report);

    assert!(!tripwire_log.exists(), "a self-test tripwire command ran");
    assert_eq!(
        snapshot_tree(&fake_bin),
        fake_bin_before,
        "tripwire was modified"
    );
    assert!(
        snapshot_tree(&work).is_empty(),
        "self-test wrote runtime work output"
    );
    assert!(!staging.exists(), "self-test created staging output");
    assert!(!runtime.exists(), "self-test created runtime output");

    let mut expected_root = root_before;
    expected_root.insert((
        PathBuf::from(report.file_name().expect("report filename")),
        "regular",
    ));
    assert_eq!(
        snapshot_tree(&root),
        expected_root,
        "fixture gained unexpected output"
    );
    assert_eq!(
        snapshot_tree(repo),
        repo_before,
        "self-test changed repository output"
    );
}

#[test]
fn input_v1_ledger_round_trip_and_rejects_invalid_vectors() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-build-subject.py");
    let mut invalid = String::new();
    for (index, (name, vector)) in INPUT_LEDGER_INVALID.iter().enumerate() {
        if index != 0 {
            invalid.push('\x1e');
        }
        invalid.push_str(name);
        invalid.push('\x1f');
        invalid.push_str(vector);
    }
    let driver = r#"
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

golden = os.environ["TASK4_GOLDEN"].encode("ascii")
records = module.parse_ledger(golden)
if module.encode_ledger(records) != golden:
    raise SystemExit("input-v1 parse/encode changed the golden bytes")
large = os.environ["TASK4_LARGE_SIZE"].encode("ascii")
large_records = module.parse_ledger(large)
if module.encode_ledger(large_records) != large:
    raise SystemExit("input-v1 parse/encode changed the large-size bytes")
for item in os.environ["TASK4_INVALID"].split("\x1e"):
    name, raw = item.split("\x1f", 1)
    try:
        module.parse_ledger(raw.encode("ascii"))
    except module.FormatError:
        continue
    raise SystemExit(f"{name}: input-v1 parser accepted an invalid vector")
generated_invalid = {
    "4097-rows": b"".join(
        (
            f"input-v1\t{index}\ttool\tread\tpresent\t0644\t0\t"
            f"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\t"
            f"external:/tool/{index:04d}\n"
        ).encode("ascii")
        for index in range(4097)
    ),
    "bom": b"\xef\xbb\xbf" + golden,
    "cr": golden.replace(b"\n", b"\r\n", 1),
    "locator-unicode-cf": golden.replace(
        b"repo:/Cargo.toml", b"repo:/Cargo.\xe2\x80\x8btoml", 1
    ),
}
component = "a" * 250
oversized = b"".join(
    (
        f"input-v1\t{index}\ttool\tread\tpresent\t0644\t0\t"
        f"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\t"
        f"external:/oversized/{index:04d}/{component}/{component}/{component}/{component}\n"
    ).encode("ascii")
    for index in range(4096)
)
if len(oversized) <= 4 * 1024 * 1024:
    raise SystemExit("oversized input-v1 negative is not larger than 4 MiB")
generated_invalid["oversized"] = oversized
for name, raw in generated_invalid.items():
    try:
        module.parse_ledger(raw)
    except module.FormatError:
        continue
    raise SystemExit(f"{name}: input-v1 parser accepted an invalid vector")
print("input-v1-ok")
"#;
    let output = Command::new("/usr/bin/python3")
        .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("TASK4_GOLDEN", INPUT_LEDGER_GOLDEN)
        .env("TASK4_LARGE_SIZE", INPUT_LEDGER_LARGE_SIZE)
        .env("TASK4_INVALID", invalid)
        .output()
        .expect("import task4 build-subject script through /usr/bin/python3");
    assert!(
        output.status.success(),
        "input-v1 parse_ledger rejected the nine-field golden ledger: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "successful ledger driver wrote to stderr"
    );
    assert_eq!(
        output.stdout, b"input-v1-ok\n",
        "input-v1 parse/encode driver did not complete"
    );
}

#[test]
fn input_v1_reconciliation_uses_live_filesystem_and_complete_trace() {
    struct Cleanup(std::path::PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    let project = Path::new(env!("CARGO_MANIFEST_DIR"));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "p11scope-task4-reconcile-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create reconciliation fixture");
    let _cleanup = Cleanup(root.clone());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("chmod reconciliation fixture");

    let repo = root.join("repo");
    let vendor = repo.join("vendor");
    let vendor_pkg = vendor.join("pkg");
    let build = root.join("build");
    fs::create_dir(&repo).expect("create repo fixture");
    fs::create_dir(&build).expect("create build fixture");
    fs::create_dir(&vendor).expect("create vendor fixture");
    fs::create_dir(&vendor_pkg).expect("create vendor package fixture");
    for directory in [&repo, &build, &vendor, &vendor_pkg] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("chmod fixture directory");
    }
    let write_mode = |path: &Path, bytes: &[u8], mode: u32| {
        fs::write(path, bytes).expect("write fixture file");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod fixture file");
    };
    write_mode(&repo.join("blocker"), b"x", 0o600);
    fs::create_dir(repo.join("enum")).expect("create enum fixture");
    fs::set_permissions(repo.join("enum"), fs::Permissions::from_mode(0o700))
        .expect("chmod enum fixture");
    write_mode(&repo.join("enum/a"), b"a", 0o600);
    std::os::unix::fs::symlink("link2", repo.join("link1")).expect("create link1 fixture");
    std::os::unix::fs::symlink("vendor/pkg/tool.bin", repo.join("link2"))
        .expect("create link2 fixture");
    fs::create_dir(repo.join("probe")).expect("create probe fixture");
    fs::set_permissions(repo.join("probe"), fs::Permissions::from_mode(0o700))
        .expect("chmod probe fixture");
    write_mode(&vendor_pkg.join("tool.bin"), b"ELF\n", 0o700);

    let trace = format!(
        concat!(
            "100 openat(AT_FDCWD, \"{0}/enum\", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3\n",
            "100 getdents64(3, 0x7f, 32768) = 24\n",
            "100 getdents64(3, 0x7f, 32768) = 0\n",
            "100 close(3) = 0\n",
            "100 newfstatat(AT_FDCWD, \"{0}/probe/missing\", 0x7f, 0) = -1 ENOENT (No such file or directory)\n",
            "100 newfstatat(AT_FDCWD, \"{0}/blocker/child\", 0x7f, 0) = -1 ENOTDIR (Not a directory)\n",
            "100 openat(AT_FDCWD, \"{0}/link1\", O_RDONLY|O_CLOEXEC) = 4\n",
            "100 close(4) = 0\n",
            "100 +++ exited with 0 +++\n",
        ),
        repo.display()
    );
    let driver = r#"
import importlib.util
import os
import stat
import sys

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
reconcile = module.reconcile_input_v1

trace = os.environ["TASK4_TRACE"].encode("ascii")
repo_root = os.environ["TASK4_REPO_ROOT"]
vendor_root = os.environ["TASK4_VENDOR_ROOT"]
build_root = os.environ["TASK4_BUILD_ROOT"]
expected = os.environ["TASK4_EXPECTED"].encode("ascii")
blocker = os.path.join(repo_root, "blocker")
enum = os.path.join(repo_root, "enum")
link1 = os.path.join(repo_root, "link1")
link2 = os.path.join(repo_root, "link2")
probe = os.path.join(repo_root, "probe")
vendor_tool = os.path.join(vendor_root, "pkg", "tool.bin")

def snapshot(root):
    entries = []

    def visit(current):
        with os.scandir(current) as iterator:
            children = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in children:
            path = entry.path
            value = os.lstat(path)
            relative = os.fsencode(os.path.relpath(path, root))
            mode = stat.S_IMODE(value.st_mode)
            if stat.S_ISDIR(value.st_mode):
                kind, content = "directory", None
            elif stat.S_ISREG(value.st_mode):
                kind, content = "regular", open(path, "rb").read()
            elif stat.S_ISLNK(value.st_mode):
                kind, content = "symlink", os.readlink(path)
            else:
                kind, content = "other", None
            entries.append((relative, kind, mode, content))
            if kind == "directory":
                visit(path)

    visit(root)
    return sorted(entries)

def facts():
    return (
        open(blocker, "rb").read(),
        stat.S_IMODE(os.lstat(blocker).st_mode),
        open(os.path.join(enum, "a"), "rb").read(),
        stat.S_IMODE(os.lstat(os.path.join(enum, "a")).st_mode),
        os.readlink(link1),
        os.readlink(link2),
        open(vendor_tool, "rb").read(),
        stat.S_IMODE(os.lstat(vendor_tool).st_mode),
    )

expected_facts = (b"x", 0o600, b"a", 0o600, "link2", "vendor/pkg/tool.bin", b"ELF\n", 0o700)
if facts() != expected_facts:
    raise SystemExit("reconciliation fixture literals or modes are wrong")
repo_before = snapshot(repo_root)
if snapshot(build_root):
    raise SystemExit("reconciliation build root is not empty")

discovered = reconcile(
    trace,
    repo_root=repo_root,
    vendor_root=vendor_root,
    build_root=build_root,
    expected=None,
)
if discovered != expected:
    raise SystemExit("reconciliation discovery ledger differs from the verified rows")
reconcile(
    trace,
    repo_root=repo_root,
    vendor_root=vendor_root,
    build_root=build_root,
    expected=expected,
)
if snapshot(repo_root) != repo_before or snapshot(build_root):
    raise SystemExit("reconciliation emitted output during discovery or verification")

def assert_restored(name):
    if facts() != expected_facts or snapshot(repo_root) != repo_before or snapshot(build_root):
        raise SystemExit(f"{name}: reconciliation fixture was not restored")

def expect_mutation(name, operation):
    try:
        operation()
    except module.MutationError:
        return
    except Exception as exc:
        raise SystemExit(f"{name}: expected module.MutationError, got {type(exc).__name__}: {exc}")
    raise SystemExit(f"{name}: mutation was accepted")

enum_extra = os.path.join(enum, "b")
open(enum_extra, "wb").write(b"b")
os.chmod(enum_extra, 0o600)
expect_mutation("enum-entry-added", lambda: reconcile(trace, repo_root=repo_root, vendor_root=vendor_root, build_root=build_root, expected=expected))
os.unlink(enum_extra)
assert_restored("enum-entry-added")

other = os.path.join(vendor_root, "pkg", "other.bin")
open(other, "wb").write(b"other")
os.chmod(other, 0o700)
os.unlink(link2)
os.symlink("vendor/pkg/other.bin", link2)
expect_mutation("link2-retargeted", lambda: reconcile(trace, repo_root=repo_root, vendor_root=vendor_root, build_root=build_root, expected=expected))
os.unlink(link2)
os.symlink("vendor/pkg/tool.bin", link2)
os.unlink(other)
assert_restored("link2-retargeted")

missing = os.path.join(probe, "missing")
open(missing, "wb").write(b"missing")
os.chmod(missing, 0o600)
expect_mutation("probe-created", lambda: reconcile(trace, repo_root=repo_root, vendor_root=vendor_root, build_root=build_root, expected=expected))
os.unlink(missing)
assert_restored("probe-created")

os.unlink(blocker)
os.mkdir(blocker, 0o700)
expect_mutation("blocker-became-directory", lambda: reconcile(trace, repo_root=repo_root, vendor_root=vendor_root, build_root=build_root, expected=expected))
os.rmdir(blocker)
open(blocker, "wb").write(b"x")
os.chmod(blocker, 0o600)
assert_restored("blocker-became-directory")

extra = os.path.join(repo_root, "extra")
open(extra, "wb").write(b"extra")
os.chmod(extra, 0o600)
trace_extra = trace.replace(
    b"100 +++ exited with 0 +++\n",
    (
        f'100 openat(AT_FDCWD, "{extra}", O_RDONLY|O_CLOEXEC) = 5\n'
        "100 close(5) = 0\n100 +++ exited with 0 +++\n"
    ).encode("ascii"),
    1,
)
expect_mutation("trace-open-extra", lambda: reconcile(trace_extra, repo_root=repo_root, vendor_root=vendor_root, build_root=build_root, expected=expected))
os.unlink(extra)
assert_restored("trace-open-extra")

if facts() != expected_facts or snapshot(repo_root) != repo_before or snapshot(build_root):
    raise SystemExit("reconciliation fixture was not restored exactly")
print("input-v1-reconcile-ok")
"#;
    let project_before = snapshot_tree(project);
    let output = Command::new("/usr/bin/python3")
        .args([
            "-c",
            driver,
            project
                .join("scripts/task4-build-subject.py")
                .to_str()
                .expect("script path is UTF-8"),
        ])
        .current_dir(project)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("TASK4_TRACE", trace)
        .env("TASK4_REPO_ROOT", &repo)
        .env("TASK4_VENDOR_ROOT", &vendor)
        .env("TASK4_BUILD_ROOT", &build)
        .env("TASK4_EXPECTED", INPUT_V1_RECONCILIATION_EXPECTED)
        .output()
        .expect("import task4 build-subject script through /usr/bin/python3");
    assert!(
        output.status.success(),
        "input-v1 reconciliation contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "reconciliation driver wrote to stderr"
    );
    assert_eq!(
        output.stdout, b"input-v1-reconcile-ok\n",
        "reconciliation driver did not complete"
    );
    assert_eq!(
        snapshot_tree(project),
        project_before,
        "reconciliation changed the real repository"
    );
}
