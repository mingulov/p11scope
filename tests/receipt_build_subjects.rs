use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

const INPUT_LEDGER_GOLDEN: &str = include_str!("fixtures/task4/input-ledger-golden.tsv");

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

type ExactTreeEntry = (PathBuf, &'static str, u32, u64, u64, Vec<u8>);

fn snapshot_exact_tree(root: &Path) -> BTreeSet<ExactTreeEntry> {
    fn visit(root: &Path, current: &Path, entries: &mut BTreeSet<ExactTreeEntry>) {
        let metadata = fs::symlink_metadata(current).expect("read isolated project metadata");
        let file_type = metadata.file_type();
        let kind = if file_type.is_dir() {
            "directory"
        } else if file_type.is_file() {
            "regular"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };
        let content = if file_type.is_file() {
            fs::read(current).expect("read isolated project file")
        } else if file_type.is_symlink() {
            fs::read_link(current)
                .expect("read isolated project symlink")
                .into_os_string()
                .into_vec()
        } else {
            Vec::new()
        };
        entries.insert((
            current
                .strip_prefix(root)
                .expect("isolated project entry is below root")
                .to_path_buf(),
            kind,
            metadata.permissions().mode() & 0o7777,
            metadata.dev(),
            metadata.ino(),
            content,
        ));
        if file_type.is_dir() {
            for entry in fs::read_dir(current)
                .expect("read isolated project directory")
                .map(|entry| entry.expect("read isolated project entry"))
            {
                visit(root, &entry.path(), entries);
            }
        }
    }

    let mut entries = BTreeSet::new();
    visit(root, root, &mut entries);
    entries
}

#[test]
fn input_v1_ledger_round_trip_and_encoder_rejects_invalid_vectors() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let test = repo.join("tests/python/test_task4_ledger.py");
    let output = Command::new("/usr/bin/python3")
        .args([
            "-I",
            test.to_str().expect("ledger test path is UTF-8"),
            "InputLedgerTests.test_round_trip_fixed_vectors_and_boundary_locator",
            "InputLedgerTests.test_parser_rejects_invalid_vectors",
            "InputLedgerTests.test_encoder_rejects_invalid_records",
        ])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run task4 ledger tests through /usr/bin/python3");
    assert!(
        output.status.success(),
        "input-v1 ledger contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn input_v1_discovery_api_is_candidate_only() {
    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-build-subject.py");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let project = std::env::temp_dir().join(format!(
        "p11scope-task4-produce-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&project).expect("create isolated project");
    let _cleanup = Cleanup(project.clone());
    let scripts = project.join("scripts");
    fs::create_dir(&scripts).expect("create isolated project scripts directory");
    let isolated_script = scripts.join("task4-build-subject.py");
    fs::copy(&script, &isolated_script).expect("copy task4 build-subject script");
    let script_mode = fs::symlink_metadata(&script)
        .expect("read task4 build-subject script metadata")
        .permissions()
        .mode();
    fs::set_permissions(&isolated_script, fs::Permissions::from_mode(script_mode))
        .expect("copy task4 build-subject script mode");
    let project_before = snapshot_exact_tree(&project);
    for argv in [None, Some("produce"), Some("arbitrary")] {
        let mut command = Command::new("/usr/bin/python3");
        command
            .current_dir(&project)
            .env_clear()
            .env("PYTHONDONTWRITEBYTECODE", "1");
        match argv {
            None => {
                command.args(["scripts/task4-build-subject.py"]);
            }
            Some(value) => {
                command.args(["scripts/task4-build-subject.py", value]);
            }
        }
        let output = command
            .output()
            .expect("run deferred task4 build-subject argv");
        assert_eq!(output.status.code(), Some(77), "argv must remain deferred");
        assert!(output.stdout.is_empty(), "deferred argv wrote to stdout");
        assert!(output.stderr.is_empty(), "deferred argv wrote to stderr");
        assert_eq!(
            snapshot_exact_tree(&project),
            project_before,
            "deferred argv changed the isolated project tree"
        );
    }
    let api_test = repo.join("tests/python/test_task4_discovery_api.py");
    let api_output = Command::new("/usr/bin/python3")
        .args([
            "-I",
            api_test.to_str().expect("discovery API test path is UTF-8"),
            "DiscoveryApiTests.test_candidate_only_api_contract",
        ])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run task4 discovery API test through /usr/bin/python3");
    assert!(
        api_output.status.success(),
        "input-v1 discovery API contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&api_output.stdout),
        String::from_utf8_lossy(&api_output.stderr)
    );
    let borrowed_test = repo.join("tests/python/test_task4_borrowed_descriptor_admission.py");
    let borrowed_output = Command::new("/usr/bin/python3")
        .args([
            "-I",
            borrowed_test
                .to_str()
                .expect("borrowed descriptor test path is UTF-8"),
            "BorrowedDescriptorAdmissionTests.test_expected_ledger_fd_bool_true",
            "BorrowedDescriptorAdmissionTests.test_expected_ledger_fd_bool_false",
            "BorrowedDescriptorAdmissionTests.test_expected_ledger_fd_none",
            "BorrowedDescriptorAdmissionTests.test_expected_ledger_fd_string",
            "BorrowedDescriptorAdmissionTests.test_expected_ledger_fd_int_subclass",
            "BorrowedDescriptorAdmissionTests.test_expected_ledger_fd_negative",
            "BorrowedDescriptorAdmissionTests.test_expected_ledger_fd_invalid",
            "BorrowedDescriptorAdmissionTests.test_expected_ledger_fd_closed",
            "BorrowedDescriptorAdmissionTests.test_private_parent_fd_bool_true",
            "BorrowedDescriptorAdmissionTests.test_private_parent_fd_bool_false",
            "BorrowedDescriptorAdmissionTests.test_private_parent_fd_none",
            "BorrowedDescriptorAdmissionTests.test_private_parent_fd_string",
            "BorrowedDescriptorAdmissionTests.test_private_parent_fd_int_subclass",
            "BorrowedDescriptorAdmissionTests.test_private_parent_fd_negative",
            "BorrowedDescriptorAdmissionTests.test_private_parent_fd_invalid",
            "BorrowedDescriptorAdmissionTests.test_private_parent_fd_closed",
            "BorrowedDescriptorAdmissionTests.test_ledger_writable",
            "BorrowedDescriptorAdmissionTests.test_ledger_o_path",
            "BorrowedDescriptorAdmissionTests.test_ledger_wrong_kind",
            "BorrowedDescriptorAdmissionTests.test_ledger_wrong_mode",
            "BorrowedDescriptorAdmissionTests.test_ledger_nlink",
            "BorrowedDescriptorAdmissionTests.test_ledger_empty",
            "BorrowedDescriptorAdmissionTests.test_ledger_sparse_oversize",
            "BorrowedDescriptorAdmissionTests.test_ledger_malformed",
            "BorrowedDescriptorAdmissionTests.test_parent_o_path",
            "BorrowedDescriptorAdmissionTests.test_parent_wrong_kind",
            "BorrowedDescriptorAdmissionTests.test_parent_wrong_mode",
            "BorrowedDescriptorAdmissionTests.test_parent_no_cloexec",
        ])
        .current_dir(std::env::temp_dir())
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run task4 borrowed descriptor tests through /usr/bin/python3");
    assert!(
        borrowed_output.status.success(),
        "borrowed descriptor admission contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&borrowed_output.stdout),
        String::from_utf8_lossy(&borrowed_output.stderr)
    );
    let contract_test = repo.join("tests/python/test_task4_input_v1_contract.py");
    let output = Command::new("/usr/bin/python3")
        .args([
            "-I",
            contract_test
                .to_str()
                .expect("input-v1 contract test path is UTF-8"),
            "InputV1ContractTests.test_complete_candidate_only_contract",
        ])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("TASK4_GOLDEN", INPUT_LEDGER_GOLDEN)
        .output()
        .expect("run task4 input-v1 contract through /usr/bin/python3");
    assert!(
        output.status.success(),
        "input-v1 discovery API contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn discover_input_v1_candidate_only_discovers_complete_live_input() {
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
        "p11scope-task4-discover-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create discovery fixture");
    let _cleanup = Cleanup(root.clone());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod discovery fixture");

    let repo = root.join("repo");
    let vendor = repo.join("vendor");
    let vendor_pkg = vendor.join("pkg");
    let build = root.join("build");
    let stable = root.join("stable");
    let nightly = root.join("nightly");
    let tool = root.join("tool");
    fs::create_dir(&repo).expect("create repo fixture");
    fs::create_dir(&build).expect("create build fixture");
    fs::create_dir(&vendor).expect("create vendor fixture");
    fs::create_dir(&vendor_pkg).expect("create vendor package fixture");
    fs::create_dir(&stable).expect("create stable sysroot fixture");
    fs::create_dir(&nightly).expect("create nightly sysroot fixture");
    fs::create_dir(&tool).expect("create tool fixture");
    fs::set_permissions(&repo, fs::Permissions::from_mode(0o755)).expect("chmod repo fixture");
    fs::set_permissions(&vendor, fs::Permissions::from_mode(0o755)).expect("chmod vendor fixture");
    fs::set_permissions(&vendor_pkg, fs::Permissions::from_mode(0o755))
        .expect("chmod vendor package fixture");
    for directory in [&stable, &nightly, &tool] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
            .expect("chmod external fixture directory");
    }
    fs::set_permissions(&build, fs::Permissions::from_mode(0o700)).expect("chmod build fixture");
    let write_mode = |path: &Path, bytes: &[u8], mode: u32| {
        fs::write(path, bytes).expect("write fixture file");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod fixture file");
    };
    write_mode(&repo.join("blocker"), b"x", 0o600);
    let hard_a = repo.join("hard-a");
    let hard_b = repo.join("hard-b");
    write_mode(&hard_a, b"x", 0o600);
    fs::hard_link(&hard_a, &hard_b).expect("create hard-link fixture");
    fs::create_dir(repo.join("enum")).expect("create enum fixture");
    fs::set_permissions(repo.join("enum"), fs::Permissions::from_mode(0o700))
        .expect("chmod enum fixture");
    write_mode(&repo.join("enum/a"), b"a", 0o600);
    let sub = repo.join("sub");
    fs::create_dir(&sub).expect("create sub fixture");
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).expect("chmod sub fixture");
    write_mode(&sub.join("café.rs"), b"a", 0o644);
    std::os::unix::fs::symlink("link2", repo.join("link1")).expect("create link1 fixture");
    std::os::unix::fs::symlink("vendor/pkg/tool.bin", repo.join("link2"))
        .expect("create link2 fixture");
    fs::create_dir(repo.join("probe")).expect("create probe fixture");
    fs::set_permissions(repo.join("probe"), fs::Permissions::from_mode(0o700))
        .expect("chmod probe fixture");
    write_mode(&vendor_pkg.join("tool.bin"), b"ELF\n", 0o700);
    write_mode(&stable.join("stable.bin"), b"a", 0o644);
    write_mode(&nightly.join("nightly.bin"), b"x", 0o644);
    write_mode(&tool.join("rustc"), b"#!/bin/sh\nexit 0\n", 0o755);

    let trace = format!(
        concat!(
            "100 openat(AT_FDCWD, \"{0}/sub\", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3\n",
            "100 dup(3) = 9\n",
            "100 clone(child_stack=NULL, flags=SIGCHLD, child_tidptr=NULL) = 101\n",
            "100 openat(AT_FDCWD, \"{0}/enum\", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 4\n",
            "101 openat(9, \"caf\\xc3\\xa9.rs\", O_RDONLY|O_CLOEXEC) = 4\n",
            "100 getdents64(4, 0x7f, 32768) = 24\n",
            "100 getdents64(4, 0x7f, 32768) = 0\n",
            "100 close(4) = 0\n",
            "100 openat(AT_FDCWD, \"{0}/hard-a\", O_RDONLY|O_CLOEXEC) = 5\n",
            "100 close(5) = 0\n",
            "100 openat(AT_FDCWD, \"{0}/hard-b\", O_RDONLY|O_CLOEXEC) = 6\n",
            "100 close(6) = 0\n",
            "100 open(\"{1}/stable.bin\", O_RDONLY|O_CLOEXEC) = 7\n",
            "100 mmap(NULL, 1, PROT_READ, MAP_PRIVATE, 7, 0) = 0\n",
            "100 munmap(0, 1) = 0\n",
            "100 close(7) = 0\n",
            "100 openat2(AT_FDCWD, \"{2}/nightly.bin\", {{ flags=O_RDONLY|O_CLOEXEC, resolve=0 }}, 24) = 8\n",
            "100 read(8, \"x\", 1) = 1\n",
            "100 close(8) = 0\n",
            "100 openat(AT_FDCWD, \"{4}/generated.o\", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 4\n",
            "100 write(4, \"o\", 1) = 1\n",
            "100 close(4) = 0\n",
            "100 openat(AT_FDCWD, \"{4}/generated.o\", O_RDONLY|O_CLOEXEC) = 4\n",
            "100 read(4, \"o\", 1) = 1\n",
            "100 close(4) = 0\n",
            "100 openat(AT_FDCWD, \"{0}/link1\", O_RDONLY|O_CLOEXEC) = 10\n",
            "100 close(10) = 0\n",
            "100 newfstatat(AT_FDCWD, \"{0}/probe/missing\", 0x7f, 0) = -1 ENOENT (No such file or directory)\n",
            "100 newfstatat(AT_FDCWD, \"{0}/blocker/child\", 0x7f, 0) = -1 ENOTDIR (Not a directory)\n",
            "101 execve(\"{3}/rustc\", [\"rustc\"], [\"LC_ALL=C\"]) = 0\n",
            "101 fchdir(9) = 0\n",
            "101 openat(9, \"caf\\xc3\\xa9.rs\", O_RDONLY|O_CLOEXEC) = 3\n",
            "101 close(3) = 0\n",
            "101 +++ exited with 0 +++\n",
            "100 close(3) = 0\n",
            "100 close(9) = 0\n",
            "100 +++ exited with 0 +++\n",
        ),
        repo.display(),
        stable.display(),
        nightly.display(),
        tool.display(),
        build.display(),
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

trace = os.environ["TASK4_TRACE"].encode("ascii")
fixture_root = os.environ["TASK4_ROOT"]
repo_root = os.environ["TASK4_REPO_ROOT"]
build_root = os.environ["TASK4_BUILD_ROOT"]
stable_root = os.environ["TASK4_STABLE_ROOT"]
nightly_root = os.environ["TASK4_NIGHTLY_ROOT"]
tool_root = os.environ["TASK4_TOOL_ROOT"]

def snapshot(root):
    entries = []
    anchor = os.lstat(root)
    anchor_identity = (
        anchor.st_dev,
        anchor.st_ino,
        anchor.st_uid,
        anchor.st_gid,
        stat.S_IMODE(anchor.st_mode),
        anchor.st_nlink,
        anchor.st_size,
        anchor.st_mtime_ns,
        anchor.st_ctime_ns,
    )

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
    return anchor_identity, tuple(sorted(entries))

if stat.S_IMODE(os.lstat(fixture_root).st_mode) != 0o700 or os.lstat(fixture_root).st_uid != os.getuid():
    raise SystemExit("temp parent is not owner-only")
if stat.S_IMODE(os.lstat(repo_root).st_mode) != 0o755:
    raise SystemExit("repo fixture is unexpectedly private")
vendor_root = os.path.join(repo_root, "vendor")
if stat.S_IMODE(os.lstat(vendor_root).st_mode) != 0o755:
    raise SystemExit("vendor fixture is unexpectedly private")
if stat.S_IMODE(os.lstat(build_root).st_mode) != 0o700:
    raise SystemExit("build fixture is not private")
for outside_root in (stable_root, nightly_root, tool_root):
    if stat.S_IMODE(os.lstat(outside_root).st_mode) != 0o755:
        raise SystemExit("external fixture root is unexpectedly private")
for outside_root in (stable_root, nightly_root, tool_root):
    if os.path.commonpath((repo_root, outside_root)) == repo_root:
        raise SystemExit("outside input root is under the repo")
hard_a = os.path.join(repo_root, "hard-a")
hard_b = os.path.join(repo_root, "hard-b")
if os.stat(hard_a).st_ino != os.stat(hard_b).st_ino:
    raise SystemExit("hard-link fixture does not share one inode")
repo_before = snapshot(repo_root)
parent_before = snapshot(fixture_root)
stable_before = snapshot(stable_root)
nightly_before = snapshot(nightly_root)
tool_before = snapshot(tool_root)
build_before = snapshot(build_root)
if build_before[1]:
    raise SystemExit("build root is not empty")

discovered = module.discover_input_v1(
    trace,
    root_pid=100,
    initial_cwd=repo_root,
    repo_root=repo_root,
    vendor_relative="vendor",
    build_root=build_root,
    stable_sysroot_root=stable_root,
    nightly_sysroot_root=nightly_root,
)
rows = [
    ("stable-sysroot", "read", "present", "0644", "1", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", f"external:{stable_root}/stable.bin"),
    ("nightly-sysroot", "read", "present", "0644", "1", "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", f"external:{nightly_root}/nightly.bin"),
    ("tool", "execute", "present", "0755", "17", "306c6ca7407560340797866e077e053627ad409277d1b9da58106fce4cf717cb", f"external:{tool_root}/rustc"),
    ("repo", "probe", "present", "0600", "1", "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", "repo:/blocker"),
    ("absent", "probe", "ENOTDIR", "-", "-", "-", "repo:/blocker/child"),
    ("directory", "enumerate", "present", "0700", "4", "27a4f844873b98b62676cf72fa49841676f4b63221ae7afd85fdad5bbf4d85de", "repo:/enum"),
    ("repo", "probe", "present", "0600", "1", "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", "repo:/hard-a"),
    ("repo", "probe", "present", "0600", "1", "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", "repo:/hard-b"),
    ("symlink", "probe", "present", "0777", "5", "4437e55da8273b6a2a433c93548a08cdab55f3e2cba9e08cc080dfdd67d04959", "repo:/link1"),
    ("symlink", "probe", "present", "0777", "19", "21eec616add1a571e58aba55d5f1b9504205384b72a6b40976a4749a3e840b80", "repo:/link2"),
    ("directory", "probe", "present", "0700", "0", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "repo:/probe"),
    ("absent", "probe", "ENOENT", "-", "-", "-", "repo:/probe/missing"),
    ("directory", "probe", "present", "0755", "11", "69342b35fbb91e72cda5d95b052b88fad5f0b111afd2dbb718f45e5778641aa3", "repo:/sub"),
    ("repo", "probe", "present", "0644", "1", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "repo:/sub/café.rs"),
    ("vendor", "probe", "present", "0700", "4", "0eb9e3089dc8479fdc76d897a20c1555c51505d9f13cc97a868af3ef5988dc87", "vendor:/pkg/tool.bin"),
]
rows.sort(key=lambda row: row[-1].encode("utf-8"))
ledger = b"".join(
    ("\t".join(("input-v1", str(index), *row)) + "\n").encode("utf-8")
    for index, row in enumerate(rows)
)
if discovered != ledger:
    raise SystemExit("discovery ledger differs from the literal live rows")
if (
    snapshot(fixture_root) != parent_before
    or snapshot(repo_root) != repo_before
    or snapshot(stable_root) != stable_before
    or snapshot(nightly_root) != nightly_before
    or snapshot(tool_root) != tool_before
    or snapshot(build_root) != build_before
):
    raise SystemExit("discovery changed the fixture or build root")
print("input-v1-discover-ok")

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
        .env("TASK4_ROOT", &root)
        .env("TASK4_TRACE", trace)
        .env("TASK4_REPO_ROOT", &repo)
        .env("TASK4_BUILD_ROOT", &build)
        .env("TASK4_STABLE_ROOT", &stable)
        .env("TASK4_NIGHTLY_ROOT", &nightly)
        .env("TASK4_TOOL_ROOT", &tool)
        .output()
        .expect("import task4 build-subject script through /usr/bin/python3");
    assert!(
        output.status.success(),
        "input-v1 discovery contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "discovery driver wrote to stderr");
    assert_eq!(
        output.stdout, b"input-v1-discover-ok\n",
        "discovery driver did not complete"
    );
    assert_eq!(
        snapshot_tree(project),
        project_before,
        "discovery changed the real repository"
    );
}

#[test]
fn discover_input_v1_candidate_only_rejects_relation_and_trace_mutation() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-build-subject.py");
    let driver = r#"
import importlib.util
import os
import stat
import sys
import tempfile

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def metadata(path):
    value = os.lstat(path)
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def snapshot(root):
    root = os.fspath(root)
    entries = []

    def record(path):
        value = os.lstat(path)
        if stat.S_ISREG(value.st_mode):
            content = open(path, "rb").read()
        elif stat.S_ISLNK(value.st_mode):
            content = os.readlink(path)
        else:
            content = None
        return metadata(path), content

    def visit(current):
        children = sorted(os.scandir(current), key=lambda entry: os.fsencode(entry.name))
        for entry in children:
            path = entry.path
            entries.append((os.fsencode(os.path.relpath(path, root)), record(path)))
            if stat.S_ISDIR(os.lstat(path).st_mode):
                visit(path)

    anchor = record(root)
    if stat.S_ISDIR(os.lstat(root).st_mode):
        visit(root)
    return anchor, tuple(entries)


def fixture(root):
    os.chmod(root, 0o700)
    repo = os.path.join(root, "repo")
    vendor = os.path.join(repo, "vendor")
    build = os.path.join(root, "build")
    stable = os.path.join(root, "stable")
    nightly = os.path.join(root, "nightly")
    outside = os.path.join(root, "outside")
    outside_vendor = os.path.join(outside, "vendor")
    for path in (repo, vendor, stable, nightly, outside, outside_vendor):
        os.mkdir(path)
        os.chmod(path, 0o755)
    os.mkdir(build)
    os.chmod(build, 0o700)
    blocker = os.path.join(repo, "blocker")
    source = os.path.join(repo, "input.txt")
    with open(blocker, "wb") as handle:
        handle.write(b"blocker")
    os.chmod(blocker, 0o600)
    with open(source, "wb") as handle:
        handle.write(b"input\n")
    os.chmod(source, 0o644)
    return {
        "root": root,
        "repo": repo,
        "vendor": vendor,
        "build": build,
        "stable": stable,
        "nightly": nightly,
        "outside_vendor": outside_vendor,
        "source": source,
    }


def trace_for(paths):
    repo = paths["repo"]
    source = paths["source"]
    build = paths["build"]
    return (
        f'100 clone(child_stack=NULL, flags=SIGCHLD, child_tidptr=NULL) = 101\n'
        f'101 getpid() = 101\n'
        f'101 +++ exited with 0 +++\n'
        f'100 openat(AT_FDCWD, "{source}", O_RDONLY|O_CLOEXEC) = 3\n'
        f'100 mmap(NULL, 6, PROT_READ, MAP_PRIVATE, 3, 0) = 0\n'
        f'100 munmap(0, 6) = 0\n'
        f'100 read(3, "input\\n", 6) = 6\n'
        f'100 close(3) = 0\n'
        f'100 newfstatat(AT_FDCWD, "{repo}/blocker/child", 0x7f, 0) = -1 ENOTDIR (Not a directory)\n'
        f'100 openat(AT_FDCWD, "{build}/generated.o", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 4\n'
        f'100 write(4, "o", 1) = 1\n'
        f'100 close(4) = 0\n'
        f'100 openat(AT_FDCWD, "{build}/generated.o", O_RDONLY|O_CLOEXEC) = 4\n'
        f'100 read(4, "o", 1) = 1\n'
        f'100 close(4) = 0\n'
        f'100 +++ exited with 0 +++\n'
    ).encode("ascii")


def discover(module, paths, trace, *, vendor_relative="vendor", root_pid=100):
    return module.discover_input_v1(
        trace,
        root_pid=root_pid,
        initial_cwd=paths["repo"],
        repo_root=paths["repo"],
        vendor_relative=vendor_relative,
        build_root=paths["build"],
        stable_sysroot_root=paths["stable"],
        nightly_sysroot_root=paths["nightly"],
    )


def anchors(paths):
    return {
        name: snapshot(paths[name])
        for name in ("root", "repo", "vendor", "build", "stable", "nightly")
    }


def assert_unchanged(paths, before):
    after = anchors(paths)
    if after != before:
        raise SystemExit("discovery changed repo/build/sysroot or anchor identity/content")
    if snapshot(paths["build"])[1]:
        raise SystemExit("build root is not empty after rejected discovery")


def baseline():
    with tempfile.TemporaryDirectory(prefix="task4-bs2a-c1-") as root:
        paths = fixture(root)
        before = anchors(paths)
        result = discover(module, paths, trace_for(paths))
        expected = (
            "input-v1\t0\trepo\tprobe\tpresent\t0600\t7\t"
            "1a48940a9383be191a715f95a09c7c253b725555cf61f72272482836e8710eef\t"
            "repo:/blocker\n"
            "input-v1\t1\tabsent\tprobe\tENOTDIR\t-\t-\t-\t"
            "repo:/blocker/child\n"
            "input-v1\t2\trepo\tread\tpresent\t0644\t6\t"
            "7d3f9b6284c6f36e77b425cac882e8fbbcc97a4727ec20790853076d0f463453\t"
            "repo:/input.txt\n"
        ).encode("ascii")
        if result != expected:
            raise SystemExit("baseline candidate differs from the literal expected ledger")
        assert_unchanged(paths, before)


def rejected(
    name,
    *,
    mutate_trace=None,
    vendor_relative="vendor",
    root_pid=100,
    escape_vendor=False,
    absolute_vendor=False,
):
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-c1-{name}-") as root:
        paths = fixture(root)
        if escape_vendor:
            os.rmdir(paths["vendor"])
            os.symlink(paths["outside_vendor"], paths["vendor"])
        if absolute_vendor:
            vendor_relative = os.path.abspath(paths["vendor"])
        trace = trace_for(paths)
        if mutate_trace is not None:
            trace = mutate_trace(trace)
        before = anchors(paths)
        try:
            discover(
                module,
                paths,
                trace,
                vendor_relative=vendor_relative,
                root_pid=root_pid,
            )
        except (module.FormatError, module.MutationError):
            pass
        except BaseException as exc:
            raise SystemExit(f"{name}: unexpected exception {type(exc).__name__}: {exc}") from exc
        else:
            raise SystemExit(f"{name}: mutation was accepted")
        assert_unchanged(paths, before)


def output_read_before_create(raw):
    lines = raw.splitlines(keepends=True)
    create = next(index for index, line in enumerate(lines) if b"O_WRONLY|O_CREAT|O_EXCL" in line)
    read = next(index for index, line in enumerate(lines) if b'generated.o", O_RDONLY' in line)
    create_block = lines[create : create + 3]
    read_block = lines[read : read + 3]
    remaining = lines[:create] + lines[create + 3 : read] + lines[read + 3 :]
    return b"".join(remaining[:create] + read_block + create_block + remaining[create:])


baseline()
rejected("vendor-dot", vendor_relative=".")
rejected("vendor-absolute", absolute_vendor=True)
rejected("vendor-parent", vendor_relative="../outside")
rejected("vendor-dotdot", vendor_relative="vendor/../vendor")
rejected("vendor-trailing", vendor_relative="vendor/")
rejected("vendor-symlink-escape", escape_vendor=True)
rejected(
    "errno-mismatch",
    mutate_trace=lambda raw: raw.replace(
        b"= -1 ENOTDIR (Not a directory)",
        b"= -1 ENOENT (No such file or directory)",
    ),
)
rejected("output-read-before-create", mutate_trace=output_read_before_create)
rejected(
    "clone-missing",
    mutate_trace=lambda raw: raw.replace(
        b"100 clone(child_stack=NULL, flags=SIGCHLD, child_tidptr=NULL) = 101\n", b""
    ),
)
rejected(
    "child-exit-missing",
    mutate_trace=lambda raw: raw.replace(b"101 +++ exited with 0 +++\n", b""),
)
rejected("wrong-root-pid", root_pid=101)
rejected(
    "mmap-unaccounted-fd",
    mutate_trace=lambda raw: raw.replace(b"MAP_PRIVATE, 3, 0", b"MAP_PRIVATE, 99, 0"),
)
print("bs2a-c1-ok")
"#;
    let output = Command::new("/usr/bin/python3")
        .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("import task4 build-subject script through /usr/bin/python3");
    assert!(
        output.status.success(),
        "candidate mutation contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "mutation driver wrote to stderr");
    assert_eq!(
        output.stdout, b"bs2a-c1-ok\n",
        "mutation driver did not complete"
    );
}

#[test]
fn discover_input_v1_candidate_only_detects_two_pass_collection_mutation() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-build-subject.py");
    let driver = r#"
import importlib.util
import os
import stat
import sys
import tempfile

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def identity(path):
    value = os.lstat(path)
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_size,
    )


def snapshot(root):
    root = os.fspath(root)
    entries = []

    def visit(current):
        children = sorted(os.scandir(current), key=lambda entry: os.fsencode(entry.name))
        for entry in children:
            path = entry.path
            value = os.lstat(path)
            if stat.S_ISREG(value.st_mode):
                content = open(path, "rb").read()
            elif stat.S_ISLNK(value.st_mode):
                content = os.readlink(path)
            else:
                content = None
            entries.append(
                (
                    os.fsencode(os.path.relpath(path, root)),
                    identity(path),
                    content,
                )
            )
            if stat.S_ISDIR(value.st_mode):
                visit(path)

    anchor = identity(root)
    visit(root)
    return anchor, tuple(entries)


def fixture(root):
    os.chmod(root, 0o700)
    repo = os.path.join(root, "repo")
    vendor = os.path.join(repo, "vendor")
    build = os.path.join(root, "build")
    stable = os.path.join(root, "stable")
    nightly = os.path.join(root, "nightly")
    enum = os.path.join(repo, "enum")
    target = os.path.join(repo, "target")
    link = os.path.join(repo, "link")
    for path in (repo, vendor, stable, nightly):
        os.mkdir(path)
        os.chmod(path, 0o755)
    os.mkdir(build)
    os.chmod(build, 0o700)
    os.mkdir(enum)
    os.chmod(enum, 0o755)
    with open(os.path.join(enum, "a"), "wb") as handle:
        handle.write(b"a")
    os.chmod(os.path.join(enum, "a"), 0o644)
    with open(os.path.join(enum, "b"), "wb") as handle:
        handle.write(b"b")
    os.chmod(os.path.join(enum, "b"), 0o644)
    with open(target, "wb") as handle:
        handle.write(b"data")
    os.chmod(target, 0o644)
    os.symlink("target", link)
    if stat.S_IMODE(os.lstat(root).st_mode) != 0o700:
        raise SystemExit("temporary parent is not private")
    return {
        "root": root,
        "repo": repo,
        "vendor": vendor,
        "build": build,
        "stable": stable,
        "nightly": nightly,
        "enum": enum,
        "target": target,
        "link": link,
    }


def anchors(paths):
    return {
        name: snapshot(paths[name])
        for name in ("root", "repo", "build", "stable", "nightly")
    }


def assert_unchanged(paths, before):
    if anchors(paths) != before:
        raise SystemExit("discovery did not restore root/repo/build/sysroot fixtures")
    if snapshot(paths["build"])[1]:
        raise SystemExit("build root is not empty after rejected discovery")


def discover(paths, trace):
    return module.discover_input_v1(
        trace,
        root_pid=100,
        initial_cwd=paths["repo"],
        repo_root=paths["repo"],
        vendor_relative="vendor",
        build_root=paths["build"],
        stable_sysroot_root=paths["stable"],
        nightly_sysroot_root=paths["nightly"],
    )


def trace_for(paths):
    return (
        f'100 openat(AT_FDCWD, "{paths["repo"]}/enum", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3\n'
        f'100 getdents64(3, 0x7f, 32768) = 24\n'
        f'100 getdents64(3, 0x7f, 32768) = 0\n'
        f'100 close(3) = 0\n'
        f'100 openat(AT_FDCWD, "{paths["repo"]}/link", O_RDONLY|O_CLOEXEC) = 4\n'
        f'100 close(4) = 0\n'
        f'100 +++ exited with 0 +++\n'
    ).encode("ascii")


expected = (
    "input-v1\t0\tdirectory\tenumerate\tpresent\t0755\t8\t"
    "15746dfb2feb256226f09dd7194d1e4906cf72bc293b6e8b651d3bcca496fa37\t"
    "repo:/enum\n"
    "input-v1\t1\tsymlink\tprobe\tpresent\t0777\t6\t"
    "34a04005bcaf206eec990bd9637d9fdb6725e0a0c0d4aebf003f17f4c956eb5c\t"
    "repo:/link\n"
    "input-v1\t2\trepo\tprobe\tpresent\t0644\t4\t"
    "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7\t"
    "repo:/target\n"
).encode("ascii")


with tempfile.TemporaryDirectory(prefix="task4-bs2a-c2-baseline-") as root:
    paths = fixture(root)
    before = anchors(paths)
    if discover(paths, trace_for(paths)) != expected:
        raise SystemExit("baseline candidate differs from the literal expected ledger")
    assert_unchanged(paths, before)


with tempfile.TemporaryDirectory(prefix="task4-bs2a-c2-collection-") as root:
    paths = fixture(root)
    before = anchors(paths)
    real_scandir = os.scandir
    real_listdir = os.listdir
    real_fstat = os.fstat
    real_close = os.close
    enum_identity = identity(paths["enum"])[0:2]
    frozen_stat = [None]
    passes = []
    target_active = [False]
    violations = []
    outstanding_proxies = []

    def violation(reason):
        violations.append(reason)
        raise AssertionError(reason)

    def enum_path(target):
        if isinstance(target, int):
            return False
        try:
            candidate = os.path.realpath(os.path.abspath(os.fsdecode(target)))
        except (TypeError, ValueError):
            return False
        return candidate == paths["enum"]

    def begin_target(target):
        if enum_path(target):
            violation("enum collection must use a held directory fd")
        if not isinstance(target, int):
            return None
        try:
            value = real_fstat(target)
        except OSError:
            return None
        if (value.st_dev, value.st_ino) != enum_identity:
            return None
        if target_active[0] or len(passes) >= 2:
            violation("enum collection must have exactly two target passes")
        target_active[0] = True
        if frozen_stat[0] is None:
            frozen_stat[0] = value
        return len(passes)

    def complete_target(names):
        actual = set(names)
        expected_names = {b"a"} if not passes else {b"a", b"b"}
        if actual != expected_names:
            violation(
                f"enum target pass differs from expected {expected_names!r}: {actual!r}"
            )
        passes.append(actual)
        target_active[0] = False

    class ScandirProxy:
        def __init__(self, iterator, scan_fd, pass_index):
            self.iterator = iterator
            self.scan_fd = scan_fd
            self.pass_index = pass_index
            self.names = []
            self.exhausted = False
            self.closed = False

        def close(self):
            if not self.closed:
                self.closed = True
                try:
                    self.iterator.close()
                finally:
                    real_close(self.scan_fd)

        def __iter__(self):
            return self

        def __next__(self):
            try:
                while True:
                    entry = next(self.iterator)
                    name = os.fsencode(entry.name)
                    if self.pass_index == 0 and name == b"b":
                        continue
                    self.names.append(name)
                    return entry
            except StopIteration:
                if not self.exhausted:
                    self.exhausted = True
                    self.close()
                    complete_target(self.names)
                raise
            except BaseException:
                self.close()
                raise

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()
            return False

    def scandir(target):
        index = begin_target(target)
        if index is None:
            return real_scandir(target)
        scan_fd = os.open(
            ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=target
        )
        try:
            proxy = ScandirProxy(real_scandir(scan_fd), scan_fd, index)
            outstanding_proxies.append(proxy)
            return proxy
        except BaseException:
            real_close(scan_fd)
            raise

    def listdir(target):
        index = begin_target(target)
        if index is None:
            return real_listdir(target)
        scan_fd = os.open(
            ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=target
        )
        try:
            names = real_listdir(scan_fd)
            normalized = [os.fsencode(name) for name in names]
            if index == 0:
                names = [name for name in names if os.fsencode(name) != b"b"]
                normalized = [name for name in normalized if name != b"b"]
            complete_target(normalized)
            return names
        finally:
            real_close(scan_fd)

    def fstat(target):
        value = real_fstat(target)
        if (value.st_dev, value.st_ino) == enum_identity:
            if frozen_stat[0] is None:
                frozen_stat[0] = value
            return frozen_stat[0]
        return value

    module.os.scandir = scandir
    module.os.listdir = listdir
    module.os.fstat = fstat
    mutation = [False]
    accepted = [False]
    unexpected = [None]
    try:
        try:
            discover(paths, trace_for(paths))
        except module.MutationError:
            mutation[0] = True
        except BaseException as exc:
            unexpected[0] = f"{type(exc).__name__}: {exc}"
        else:
            accepted[0] = True
    finally:
        module.os.scandir = real_scandir
        module.os.listdir = real_listdir
        module.os.fstat = real_fstat
        for proxy in outstanding_proxies:
            proxy.close()
    if violations:
        raise SystemExit(f"collection seam violation: {violations!r}")
    if unexpected[0] is not None:
        raise SystemExit(f"collection mutation: unexpected {unexpected[0]}")
    if accepted[0]:
        raise SystemExit("collection mutation was accepted")
    if not mutation[0]:
        raise SystemExit("collection mutation did not raise MutationError")
    if module.os is not os:
        raise SystemExit("module.os identity changed during collection seam")
    if (
        module.os.scandir is not real_scandir
        or module.os.listdir is not real_listdir
        or module.os.fstat is not real_fstat
    ):
        raise SystemExit("collection seam did not restore os function identities")
    if passes != [{b"a"}, {b"a", b"b"}] or target_active[0]:
        raise SystemExit(f"collection passes were not exactly A then A+B: {passes!r}")
    assert_unchanged(paths, before)


with tempfile.TemporaryDirectory(prefix="task4-bs2a-c2-symlink-") as root:
    paths = fixture(root)
    before = anchors(paths)
    real_readlink = os.readlink
    real_fstat = os.fstat
    repo_identity = identity(paths["repo"])[0:2]
    returned = []
    symlink_violations = []

    def symlink_violation(reason):
        symlink_violations.append(reason)
        raise AssertionError(reason)

    def readlink(target, *, dir_fd=None):
        if os.fsdecode(target) != "link" or not isinstance(dir_fd, int):
            symlink_violation("link probe must use a descriptor-relative component")
        value = real_fstat(dir_fd)
        if (value.st_dev, value.st_ino) != repo_identity:
            symlink_violation("link probe dir_fd is not the held repo directory")
        actual = real_readlink(target, dir_fd=dir_fd)
        if len(returned) >= 2:
            symlink_violation("link target was read more than twice")
        value = actual if not returned else b"other" if isinstance(actual, bytes) else "other"
        returned.append(value)
        return value

    module.os.readlink = readlink
    mutation = [False]
    accepted = [False]
    unexpected = [None]
    try:
        try:
            discover(paths, trace_for(paths))
        except module.MutationError:
            mutation[0] = True
        except BaseException as exc:
            unexpected[0] = f"{type(exc).__name__}: {exc}"
        else:
            accepted[0] = True
    finally:
        module.os.readlink = real_readlink
    if symlink_violations:
        raise SystemExit(f"symlink seam violation: {symlink_violations!r}")
    if module.os is not os or module.os.readlink is not real_readlink:
        raise SystemExit("symlink seam did not restore os/readlink identity")
    if unexpected[0] is not None:
        raise SystemExit(f"symlink mutation: unexpected {unexpected[0]}")
    if accepted[0]:
        raise SystemExit("symlink mutation was accepted")
    if not mutation[0]:
        raise SystemExit("symlink mutation did not raise MutationError")
    if len(returned) != 2:
        raise SystemExit(f"symlink probe did not read the raw target twice: {returned!r}")
    expected_returns = ("target", "other") if isinstance(returned[0], str) else (b"target", b"other")
    if tuple(returned) != expected_returns:
        raise SystemExit(f"symlink probe returned unexpected values: {returned!r}")
    assert_unchanged(paths, before)

print("bs2a-c2-ok")
"#;
    let output = Command::new("/usr/bin/python3")
        .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("import task4 build-subject script through /usr/bin/python3");
    assert!(
        output.status.success(),
        "candidate two-pass mutation contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "two-pass mutation driver wrote to stderr"
    );
    assert_eq!(
        output.stdout, b"bs2a-c2-ok\n",
        "two-pass mutation driver did not complete"
    );
}

#[test]
fn discover_input_v1_candidate_only_rejects_confirmed_green_gaps() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-build-subject.py");
    let driver = r##"
import importlib.util
import os
import shutil
import stat
import sys
import tempfile

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

failures = []


def state(root):
    root = os.fspath(root)
    entries = []

    def visit(path):
        value = os.lstat(path)
        mode = stat.S_IMODE(value.st_mode)
        if stat.S_ISDIR(value.st_mode):
            kind, content = "directory", None
        elif stat.S_ISREG(value.st_mode):
            kind, content = "regular", open(path, "rb").read()
        elif stat.S_ISLNK(value.st_mode):
            kind, content = "symlink", os.fsencode(os.readlink(path))
        else:
            kind, content = "other", None
        relative = os.fsencode(os.path.relpath(path, root))
        entries.append((relative, kind, mode, value.st_dev, value.st_ino, content))
        if kind == "directory":
            for child in sorted(os.scandir(path), key=lambda entry: os.fsencode(entry.name)):
                visit(child.path)

    visit(root)
    return tuple(entries)


def fixture(root, *, many=False):
    os.chmod(root, 0o700)
    repo = os.path.join(root, "repo")
    vendor = os.path.join(repo, "vendor")
    build = os.path.join(root, "build")
    stable = os.path.join(root, "stable")
    nightly = os.path.join(root, "nightly")
    tool = os.path.join(root, "tool")
    for path in (repo, vendor, build, stable, nightly):
        os.mkdir(path)
        os.chmod(path, 0o700 if path == build else 0o755)
    with open(os.path.join(repo, "blocker"), "wb") as handle:
        handle.write(b"blocker")
    os.chmod(os.path.join(repo, "blocker"), 0o600)
    with open(os.path.join(repo, "input.txt"), "wb") as handle:
        handle.write(b"input\n")
    os.chmod(os.path.join(repo, "input.txt"), 0o644)
    with open(os.path.join(repo, "exec"), "wb") as handle:
        handle.write(b"#!/bin/sh\n")
    os.chmod(os.path.join(repo, "exec"), 0o755)
    with open(os.path.join(repo, "target"), "wb") as handle:
        handle.write(b"data")
    os.chmod(os.path.join(repo, "target"), 0o644)
    os.symlink("target", os.path.join(repo, "link"))
    with open(os.path.join(stable, "stable.bin"), "wb") as handle:
        handle.write(b"stable\n")
    os.chmod(os.path.join(stable, "stable.bin"), 0o644)
    with open(os.path.join(nightly, "nightly.bin"), "wb") as handle:
        handle.write(b"nightly\n")
    os.chmod(os.path.join(nightly, "nightly.bin"), 0o644)
    with open(tool, "wb") as handle:
        handle.write(b"stable\n")
    os.chmod(tool, 0o755)
    if many:
        enum = os.path.join(repo, "enum")
        os.mkdir(enum)
        os.chmod(enum, 0o755)
        for index in range(4097):
            with open(os.path.join(enum, f"e{index:04d}"), "wb"):
                pass
    return {
        "root": root,
        "repo": repo,
        "vendor": vendor,
        "build": build,
        "stable": stable,
        "nightly": nightly,
        "tool": tool,
        "input": os.path.join(repo, "input.txt"),
        "exec": os.path.join(repo, "exec"),
        "target": os.path.join(repo, "target"),
        "link": os.path.join(repo, "link"),
    }


def discover(paths, trace, **overrides):
    values = dict(
        root_pid=100,
        initial_cwd=paths["repo"],
        repo_root=paths["repo"],
        vendor_relative="vendor",
        build_root=paths["build"],
        stable_sysroot_root=paths["stable"],
        nightly_sysroot_root=paths["nightly"],
    )
    values.update(overrides)
    return module.discover_input_v1(trace, **values)


def exit_trace(pid=100):
    return f"{pid} +++ exited with 0 +++\n".encode("ascii")


def valid_read_exit_trace(paths):
    return (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"input\\n\", 6) = 6\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")


def expect_exception(name, expected, operation):
    try:
        operation()
    except BaseException as exc:
        if type(exc) is not expected:
            failures.append(
                f"{name}: expected {expected.__name__}, got {type(exc).__name__}: {exc}"
            )
    else:
        failures.append(f"{name}: accepted invalid input")


def expect_success(name, operation):
    try:
        value = operation()
    except BaseException as exc:
        failures.append(f"{name}: expected success, got {type(exc).__name__}: {exc}")
        return None
    return value


def replace_directory(path):
    backup = path + ".held"
    os.rename(path, backup)
    shutil.copytree(backup, path, symlinks=True)
    return backup


def restore_directory(path, backup):
    shutil.rmtree(path)
    os.rename(backup, path)


def path_is_beneath(path, root):
    if isinstance(path, int):
        return False
    try:
        candidate = os.path.abspath(os.fsdecode(path))
        return os.path.commonpath((candidate, root)) == root
    except (TypeError, ValueError):
        return False


def anchor_replacement_case(anchor):
    name = f"held-{anchor}-replacement"
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-{name}-") as root:
        paths = fixture(root)
        before = state(root)
        target = paths[anchor]
        target_id = (os.lstat(target).st_dev, os.lstat(target).st_ino)
        real_open = os.open
        real_close = os.close
        real_fstat = os.fstat
        real_scandir = os.scandir
        replacement = [False]
        violations = []
        opened = []
        replacement_fds = set()
        replacement_opened = set()
        replacement_closed = set()
        replacement_ids = set()
        backup = [None]

        def violation(reason):
            violations.append(reason)
            raise AssertionError(reason)

        def record_violation(reason):
            violations.append(reason)

        def tree_ids(path):
            value = os.lstat(path)
            ids = {(value.st_dev, value.st_ino)}
            if stat.S_ISDIR(value.st_mode):
                for entry in real_scandir(path):
                    ids.update(tree_ids(entry.path))
            return ids

        def swap():
            if replacement[0]:
                return
            replacement[0] = True
            backup[0] = replace_directory(target)
            replacement_ids.update(tree_ids(target))

        def open_hook(path, flags, mode=0o777, *, dir_fd=None):
            is_target = dir_fd is None and path_is_beneath(path, target)
            if is_target and replacement[0]:
                violation("replacement directory/object was opened by pathname")
            if dir_fd is None:
                fd = real_open(path, flags, mode)
            else:
                fd = real_open(path, flags, mode, dir_fd=dir_fd)
            opened.append(fd)
            if replacement_ids:
                value = real_fstat(fd)
                if (value.st_dev, value.st_ino) in replacement_ids:
                    replacement_fds.add(fd)
                    replacement_opened.add(fd)
                    record_violation("replacement tree object was opened")
            if dir_fd is None and not replacement[0] and os.path.abspath(os.fsdecode(path)) == target:
                swap()
            return fd

        def fstat_hook(fd):
            value = real_fstat(fd)
            if not replacement[0] and (value.st_dev, value.st_ino) == target_id:
                swap()
            return value

        def close_hook(fd):
            if fd in opened:
                opened.remove(fd)
            if fd in replacement_fds:
                replacement_fds.remove(fd)
                replacement_closed.add(fd)
            return real_close(fd)

        def scandir_hook(path):
            if not isinstance(path, int) and path_is_beneath(path, target):
                violation("anchor was enumerated by pathname")
            if isinstance(path, int) and replacement_ids:
                value = real_fstat(path)
                if (value.st_dev, value.st_ino) in replacement_ids:
                    record_violation("replacement tree object was enumerated")
            return real_scandir(path)

        module.os.open = open_hook
        module.os.close = close_hook
        module.os.fstat = fstat_hook
        module.os.scandir = scandir_hook
        try:
            try:
                requested = paths["input"] if anchor == "repo" else paths["stable"] + "/stable.bin"
                payload = "input\\n" if anchor == "repo" else "stable\\n"
                size = 6 if anchor == "repo" else 7
                trace = (
                    f'100 openat(AT_FDCWD, "{requested}", O_RDONLY|O_CLOEXEC) = 3\n'
                    f'100 read(3, "{payload}", {size}) = {size}\n'
                    "100 close(3) = 0\n"
                    "100 +++ exited with 0 +++\n"
                ).encode("ascii")
                discover(paths, trace)
            except BaseException as exc:
                if type(exc) is not module.MutationError:
                    failures.append(
                        f"{name}: expected MutationError, got {type(exc).__name__}: {exc}"
                    )
            else:
                failures.append(f"{name}: replacement was accepted")
        finally:
            module.os.open = real_open
            module.os.close = real_close
            module.os.fstat = real_fstat
            module.os.scandir = real_scandir
            if backup[0] is not None:
                restore_directory(target, backup[0])
            for fd in tuple(opened):
                try:
                    real_close(fd)
                except OSError:
                    pass
                if fd in opened:
                    opened.remove(fd)
                if fd in replacement_fds:
                    replacement_fds.remove(fd)
                    replacement_closed.add(fd)
            if opened:
                failures.append(f"{name}: replacement descriptors leaked: {tuple(opened)!r}")
        if not replacement[0]:
            failures.append(f"{name}: replacement seam was never reached")
        if violations:
            failures.append(f"{name}: hook violations {violations!r}")
        if replacement_fds or replacement_opened != replacement_closed:
            failures.append(
                f"{name}: replacement descriptor close mismatch: "
                f"opened={replacement_opened!r}, closed={replacement_closed!r}, "
                f"live={replacement_fds!r}"
            )
        if state(root) != before:
            failures.append(f"{name}: fixture identity/content was not restored")


def symlink_replacement_case():
    name = "held-symlink-replacement"
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-{name}-") as root:
        paths = fixture(root)
        before = state(root)
        repo_id = (os.lstat(paths["repo"]).st_dev, os.lstat(paths["repo"]).st_ino)
        real_readlink = os.readlink
        real_fstat = os.fstat
        returned = []
        violations = []
        replacement = [False]
        backup = [None]

        def violation(reason):
            violations.append(reason)
            raise AssertionError(reason)

        def record_violation(reason):
            violations.append(reason)

        def readlink_hook(path, *, dir_fd=None):
            if os.fsdecode(path) != "link" or not isinstance(dir_fd, int):
                violation("symlink target was not read descriptor-relatively")
            value = real_fstat(dir_fd)
            if (value.st_dev, value.st_ino) != repo_id:
                violation("symlink target used the wrong held directory")
            if replacement[0]:
                record_violation("forbidden replacement-target-byte consumption")
                return returned[0]
            actual = real_readlink(path, dir_fd=dir_fd)
            if returned:
                violation("symlink target was read more than once")
            returned.append(actual)
            if len(returned) == 1:
                backup[0] = paths["link"] + ".held"
                os.rename(paths["link"], backup[0])
                os.symlink("target", paths["link"])
                replacement[0] = True
            return actual

        module.os.readlink = readlink_hook
        try:
            trace = (
                f'100 openat(AT_FDCWD, "{paths["link"]}", O_RDONLY|O_CLOEXEC) = 3\n'
                "100 close(3) = 0\n"
                "100 +++ exited with 0 +++\n"
            ).encode("ascii")
            try:
                discover(paths, trace)
            except BaseException as exc:
                if type(exc) is not module.MutationError:
                    failures.append(
                        f"{name}: expected MutationError, got {type(exc).__name__}: {exc}"
                    )
            else:
                failures.append(f"{name}: replacement was accepted")
        finally:
            module.os.readlink = real_readlink
            if backup[0] is not None:
                os.unlink(paths["link"])
                os.rename(backup[0], paths["link"])
        if not replacement[0] or returned != [b"target"]:
            failures.append(f"{name}: target observations were {returned!r}")
        if violations:
            failures.append(f"{name}: hook violations {violations!r}")
        if state(root) != before:
            failures.append(f"{name}: fixture identity/content was not restored")


def regular_replacement_case():
    name = "held-regular-replacement"
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-{name}-") as root:
        paths = fixture(root)
        before = state(root)
        target = paths["input"]
        target_id = (os.lstat(target).st_dev, os.lstat(target).st_ino)
        repo_id = (os.lstat(paths["repo"]).st_dev, os.lstat(paths["repo"]).st_ino)
        real_lstat = os.lstat
        real_stat = os.stat
        real_fstat = os.fstat
        real_open = os.open
        real_close = os.close
        real_read = os.read
        replacement = [False]
        replacement_fds = set()
        replacement_opened = set()
        replacement_closed = set()
        opened = []
        replacement_reads = []
        violations = []
        backup = [None]

        def violation(reason):
            violations.append(reason)
            raise AssertionError(reason)

        def swap():
            if replacement[0]:
                return
            replacement[0] = True
            backup[0] = target + ".held"
            os.rename(target, backup[0])
            with open(target, "wb") as handle:
                handle.write(b"input\n")
            os.chmod(target, 0o644)

        def maybe_swap(value):
            if not replacement[0] and (value.st_dev, value.st_ino) == target_id:
                swap()

        def lstat_hook(path, *, dir_fd=None):
            value = real_lstat(path, dir_fd=dir_fd) if dir_fd is not None else real_lstat(path)
            if dir_fd is None and not isinstance(path, int) and os.path.abspath(os.fsdecode(path)) == target:
                maybe_swap(value)
            return value

        def stat_hook(path, *, dir_fd=None, follow_symlinks=True):
            if dir_fd is None:
                value = real_stat(path, follow_symlinks=follow_symlinks)
            else:
                value = real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
            if dir_fd is None and not isinstance(path, int) and os.path.abspath(os.fsdecode(path)) == target:
                maybe_swap(value)
            return value

        def fstat_hook(fd):
            value = real_fstat(fd)
            maybe_swap(value)
            return value

        def open_hook(path, flags, mode=0o777, *, dir_fd=None):
            if dir_fd is None:
                fd = real_open(path, flags, mode)
            else:
                fd = real_open(path, flags, mode, dir_fd=dir_fd)
            opened.append(fd)
            if replacement[0]:
                is_replacement = dir_fd is None and not isinstance(path, int) and os.path.abspath(os.fsdecode(path)) == target
                if dir_fd is not None and not isinstance(path, int) and os.fsdecode(path) == "input.txt":
                    try:
                        parent = real_fstat(dir_fd)
                    except OSError:
                        parent = None
                    is_replacement = parent is not None and (parent.st_dev, parent.st_ino) == repo_id
                if is_replacement:
                    replacement_fds.add(fd)
                    replacement_opened.add(fd)
            return fd

        def close_hook(fd):
            if fd in opened:
                opened.remove(fd)
            if fd in replacement_fds:
                replacement_fds.remove(fd)
                replacement_closed.add(fd)
            return real_close(fd)

        def read_hook(fd, size):
            if fd in replacement_fds:
                replacement_reads.append(fd)
                violations.append("replacement regular bytes were consumed")
            return real_read(fd, size)

        module.os.lstat = lstat_hook
        module.os.stat = stat_hook
        module.os.fstat = fstat_hook
        module.os.open = open_hook
        module.os.close = close_hook
        module.os.read = read_hook
        try:
            trace = (
                f'100 newfstatat(AT_FDCWD, "{target}", 0x7f, 0) = 0\n'
                f'100 openat(AT_FDCWD, "{target}", O_RDONLY|O_CLOEXEC) = 3\n'
                "100 read(3, \"input\\n\", 6) = 6\n"
                "100 close(3) = 0\n"
                "100 +++ exited with 0 +++\n"
            ).encode("ascii")
            try:
                discover(paths, trace)
            except BaseException as exc:
                if type(exc) is not module.MutationError:
                    failures.append(
                        f"{name}: expected MutationError, got {type(exc).__name__}: {exc}"
                    )
            else:
                failures.append(f"{name}: replacement was accepted")
        finally:
            module.os.lstat = real_lstat
            module.os.stat = real_stat
            module.os.fstat = real_fstat
            module.os.open = real_open
            module.os.close = real_close
            module.os.read = real_read
            leaked = tuple(opened)
            if backup[0] is not None:
                os.unlink(target)
                os.rename(backup[0], target)
            for fd in opened:
                try:
                    real_close(fd)
                except OSError:
                    pass
            if leaked:
                failures.append(f"{name}: replacement descriptors leaked: {leaked!r}")
            if replacement_fds or replacement_opened != replacement_closed:
                failures.append(
                    f"{name}: replacement descriptor close mismatch: "
                    f"opened={replacement_opened!r}, closed={replacement_closed!r}, "
                    f"live={replacement_fds!r}"
                )
        if not replacement[0]:
            failures.append(f"{name}: replacement seam was never reached")
        if replacement_reads or violations:
            failures.append(f"{name}: hook violations {violations!r}")
        if state(root) != before:
            failures.append(f"{name}: fixture identity/content was not restored")


anchor_replacement_case("repo")
anchor_replacement_case("stable")
symlink_replacement_case()
regular_replacement_case()


for name, link_count in (("self-cycle", 1), ("long-chain", 41)):
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-{name}-") as root:
        paths = fixture(root)
        if name == "self-cycle":
            os.symlink("cycle", os.path.join(paths["repo"], "cycle"))
            requested = os.path.join(paths["repo"], "cycle")
        else:
            for index in range(link_count):
                target = f"chain{index + 1}" if index + 1 < link_count else "input.txt"
                os.symlink(target, os.path.join(paths["repo"], f"chain{index}"))
            requested = os.path.join(paths["repo"], "chain0")
        before = state(root)
        trace = (
            f'100 openat(AT_FDCWD, "{requested}", O_RDONLY|O_CLOEXEC) = 3\n'
            "100 close(3) = 0\n"
            "100 +++ exited with 0 +++\n"
        ).encode("ascii")
        real_open = os.open
        real_close = os.close
        opened = []

        def open_tracking(path, flags, mode=0o777, *, dir_fd=None):
            if dir_fd is None:
                fd = real_open(path, flags, mode)
            else:
                fd = real_open(path, flags, mode, dir_fd=dir_fd)
            opened.append(fd)
            return fd

        def close_tracking(fd):
            if fd in opened:
                opened.remove(fd)
            return real_close(fd)

        module.os.open = open_tracking
        module.os.close = close_tracking
        try:
            expect_exception(name, module.FormatError, lambda: discover(paths, trace))
        finally:
            module.os.open = real_open
            module.os.close = real_close
            for fd in opened:
                try:
                    real_close(fd)
                except OSError:
                    pass
        if state(root) != before:
            failures.append(f"{name}: fixture changed")


with tempfile.TemporaryDirectory(prefix="task4-bs2a-access-") as root:
    paths = fixture(root)
    nested = os.path.join(paths["stable"], "nested")
    os.mkdir(nested)
    os.chmod(nested, 0o755)
    access_before = state(root)
    read_trace = (
        f'100 newfstatat(AT_FDCWD, "{paths["input"]}", 0x7f, 0) = 0\n'
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"input\\n\", 6) = 6\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    execute_trace = (
        f'100 newfstatat(AT_FDCWD, "{paths["exec"]}", 0x7f, 0) = 0\n'
        f'100 execve("{paths["exec"]}", ["exec"], ["LC_ALL=C"]) = 0\n'
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    stable_trace = (
        f'100 execve("{paths["stable"]}/stable.bin", ["stable.bin"], ["LC_ALL=C"]) = 0\n'
        f'100 execve("{paths["nightly"]}/nightly.bin", ["nightly.bin"], ["LC_ALL=C"]) = 0\n'
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    read_expected = (
        "input-v1\t0\trepo\tread\tpresent\t0644\t6\t"
        "7d3f9b6284c6f36e77b425cac882e8fbbcc97a4727ec20790853076d0f463453\t"
        "repo:/input.txt\n"
    ).encode("ascii")
    execute_expected = (
        "input-v1\t0\trepo\texecute\tpresent\t0755\t10\t"
        "a8076d3d28d21e02012b20eaf7dbf75409a6277134439025f282e368e3305abf\t"
        "repo:/exec\n"
    ).encode("ascii")
    stable_rows = [
        (
            f"input-v1\t0\tnightly-sysroot\texecute\tpresent\t0644\t8\t"
            f"58bea07cb6d97f9cfcd5c8f98b1feca0fb81cce5b0bf29a8e70ed2641956e9a6\t"
            f"external:{paths['nightly']}/nightly.bin\n"
        ).encode("ascii"),
        (
            f"input-v1\t1\tstable-sysroot\texecute\tpresent\t0644\t7\t"
            f"2b92ea252be0fbc26f70317cdaa7b6411ea634b50d55338cd8c495e4dbf25d1d\t"
            f"external:{paths['stable']}/stable.bin\n"
        ).encode("ascii"),
    ]
    stable_expected = b"".join(sorted(stable_rows, key=lambda row: row.split(b"\t")[-1]))
    for name, trace, expected in (
        ("probe-plus-read", read_trace, read_expected),
        ("probe-plus-execute", execute_trace, execute_expected),
        ("stable-nightly-execute", stable_trace, stable_expected),
    ):
        value = expect_success(name, lambda trace=trace: discover(paths, trace))
        if value is not None and value != expected:
            failures.append(f"{name}: literal ledger mismatch: {value!r}")

    for name, stable_root, nightly_root in (
        ("sysroot-equal", paths["stable"], paths["stable"]),
        ("sysroot-nested", paths["stable"], nested),
        ("sysroot-reverse-nested", nested, paths["stable"]),
    ):
        overlap_trace = (
            f'100 openat(AT_FDCWD, "{paths["stable"]}/stable.bin", O_RDONLY|O_CLOEXEC) = 3\n'
            "100 read(3, \"stable\\n\", 7) = 7\n"
            "100 close(3) = 0\n"
            "100 +++ exited with 0 +++\n"
        ).encode("ascii")
        expect_exception(
            name,
            module.MutationError,
            lambda stable_root=stable_root, nightly_root=nightly_root: discover(
                paths,
                overlap_trace,
                stable_sysroot_root=stable_root,
                nightly_sysroot_root=nightly_root,
            ),
        )
    if state(root) != access_before:
        failures.append("access fixture changed")


with tempfile.TemporaryDirectory(prefix="task4-bs2a-state-") as root:
    paths = fixture(root)
    trace_before = state(root)
    valid = (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        f'100 openat(AT_FDCWD, "{paths["exec"]}", O_RDONLY|O_CLOEXEC) = 4\n'
        "100 close(4) = 0\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception("trace-vt-separator", module.FormatError, lambda: discover(paths, valid.replace(b"\n", b"\v", 1)))
    expect_exception("trace-ff-separator", module.FormatError, lambda: discover(paths, valid.replace(b"\n", b"\f", 1)))
    control = (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"input\\n\", 6) = 6\n"
        "100 close(3) = 0\n"
    ).encode("ascii") + (
        b'100 openat(AT_FDCWD, "'
        + os.fsencode(paths["build"])
        + b'/owned\x01.o", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 4\n'
        + b"100 close(4) = 0\n100 +++ exited with 0 +++\n"
    )
    expect_exception("trace-unescaped-control", module.FormatError, lambda: discover(paths, control))
    overwrite = (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        f'100 openat(AT_FDCWD, "{paths["exec"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception("live-fd-overwrite", module.FormatError, lambda: discover(paths, overwrite))
    clone_zero = (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"input\\n\", 6) = 6\n"
        "100 close(3) = 0\n"
        "100 clone(child_stack=NULL, flags=SIGCHLD, child_tidptr=NULL) = 0\n"
        "0 +++ exited with 0 +++\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception(
        "clone-pid-zero",
        module.FormatError,
        lambda: discover(paths, clone_zero),
    )
    duplicate_output = (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"input\\n\", 6) = 6\n"
        "100 close(3) = 0\n"
        f'100 openat(AT_FDCWD, "{paths["build"]}/generated.o", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3\n'
        "100 close(3) = 0\n"
        f'100 openat(AT_FDCWD, "{paths["build"]}/generated.o", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 4\n'
        "100 close(4) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception("duplicate-exclusive-output", module.FormatError, lambda: discover(paths, duplicate_output))
    duplicate_mapping = (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 mmap(NULL, 6, PROT_READ, MAP_PRIVATE, 3, 0) = 4096\n"
        "100 mmap(NULL, 6, PROT_READ, MAP_PRIVATE, 3, 0) = 4096\n"
        "100 munmap(4096, 6) = 0\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception("duplicate-live-mapping", module.FormatError, lambda: discover(paths, duplicate_mapping))
    exec_reuse = (
        f'100 openat(AT_FDCWD, "{paths["exec"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 mmap(NULL, 10, PROT_READ, MAP_PRIVATE, 3, 0) = 4096\n"
        f'100 execve("{paths["tool"]}", ["tool"], ["LC_ALL=C"]) = 0\n'
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    exec_expected = (
        f"input-v1\t0\ttool\texecute\tpresent\t0755\t7\t"
        "2b92ea252be0fbc26f70317cdaa7b6411ea634b50d55338cd8c495e4dbf25d1d\t"
        f"external:{paths['tool']}\n"
        "input-v1\t1\trepo\tread\tpresent\t0755\t10\t"
        "a8076d3d28d21e02012b20eaf7dbf75409a6277134439025f282e368e3305abf\t"
        "repo:/exec\n"
    ).encode("ascii")
    value = expect_success("mapping-retired-on-exec", lambda: discover(paths, exec_reuse))
    if value is not None and value != exec_expected:
        failures.append(f"mapping-retired-on-exec: literal ledger mismatch: {value!r}")
    exit_reuse = (
        f'100 clone(child_stack=NULL, flags=SIGCHLD, child_tidptr=NULL) = 101\n'
        "101 getpid() = 101\n"
        f'101 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "101 mmap(NULL, 6, PROT_READ, MAP_PRIVATE, 3, 0) = 8192\n"
        "101 close(3) = 0\n"
        "101 +++ exited with 0 +++\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    value = expect_success("mapping-retired-on-exit", lambda: discover(paths, exit_reuse))
    exit_expected = (
        "input-v1\t0\trepo\tread\tpresent\t0644\t6\t"
        "7d3f9b6284c6f36e77b425cac882e8fbbcc97a4727ec20790853076d0f463453\t"
        "repo:/input.txt\n"
    ).encode("ascii")
    if value is not None and value != exit_expected:
        failures.append(f"mapping-retired-on-exit: literal ledger mismatch: {value!r}")
    read_only_create = (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"input\\n\", 6) = 6\n"
        "100 close(3) = 0\n"
        f'100 openat(AT_FDCWD, "{paths["build"]}/readonly.o", O_RDONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3\n'
        "100 write(3, \"x\", 1) = 1\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception("readonly-create-write", module.FormatError, lambda: discover(paths, read_only_create))
    write_only_read = (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_WRONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"input\\n\", 6) = 6\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception("write-only-read", module.FormatError, lambda: discover(paths, write_only_read))
    if state(root) != trace_before:
        failures.append("trace-state: fixture snapshot comparison failed")


with tempfile.TemporaryDirectory(prefix="task4-bs2a-relations-") as root:
    paths = fixture(root, many=True)
    before_absent = state(root)
    absent_trace = (
        f'100 newfstatat(AT_FDCWD, "{paths["repo"]}/blocker/child/grand", 0x7f, 0) = -1 ENOTDIR (Not a directory)\n'
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    absent_expected = (
        "input-v1\t0\trepo\tprobe\tpresent\t0600\t7\t"
        "1a48940a9383be191a715f95a09c7c253b725555cf61f72272482836e8710eef\t"
        "repo:/blocker\n"
        "input-v1\t1\tabsent\tprobe\tENOTDIR\t-\t-\t-\trepo:/blocker/child/grand\n"
    ).encode("ascii")
    value = expect_success("complete-enotdir-locator", lambda: discover(paths, absent_trace))
    if value is not None and value != absent_expected:
        failures.append(f"complete-enotdir-locator: literal ledger mismatch: {value!r}")
    if state(root) != before_absent:
        failures.append("complete-enotdir-locator: fixture changed")
    before_cardinality = state(root)
    many_trace = (
        f'100 openat(AT_FDCWD, "{paths["repo"]}/enum", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3\n'
        "100 getdents64(3, 0x7f, 32768) = 32768\n"
        "100 getdents64(3, 0x7f, 32768) = 0\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    enum = os.path.join(paths["repo"], "enum")
    enum_id = (os.lstat(enum).st_dev, os.lstat(enum).st_ino)
    real_listdir = os.listdir
    real_scandir = os.scandir
    real_fstat = os.fstat
    cardinality_inputs = []

    class BoundedEntries(list):
        def __iter__(self):
            for index, entry in enumerate(super().__iter__()):
                if index >= 4097:
                    raise AssertionError("directory enumeration exceeded 4097 entries")
                yield entry

    class BoundedScandir:
        def __init__(self, iterator):
            self.iterator = iterator
            self.count = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.close()
            return False

        def __iter__(self):
            return self

        def __next__(self):
            if self.count >= 4097:
                raise AssertionError("directory enumeration exceeded 4097 entries")
            entry = next(self.iterator)
            self.count += 1
            return entry

        def close(self):
            self.iterator.close()

    def listdir_cardinality(target):
        if isinstance(target, int):
            value = real_fstat(target)
            if (value.st_dev, value.st_ino) == enum_id:
                entries = real_listdir(target)
                cardinality_inputs.append(len(entries))
                return BoundedEntries(entries)
        return real_listdir(target)

    def scandir_cardinality(target):
        if isinstance(target, int):
            value = real_fstat(target)
            if (value.st_dev, value.st_ino) == enum_id:
                bounded = BoundedScandir(real_scandir(target))
                cardinality_inputs.append(bounded)
                return bounded
        return real_scandir(target)

    module.os.listdir = listdir_cardinality
    module.os.scandir = scandir_cardinality
    try:
        expect_exception("directory-cardinality-4097", module.FormatError, lambda: discover(paths, many_trace))
    finally:
        module.os.listdir = real_listdir
        module.os.scandir = real_scandir
    if not cardinality_inputs:
        failures.append("directory-cardinality-4097: seam was not reached")
    elif any(
        (value if isinstance(value, int) else value.count) != 4097
        for value in cardinality_inputs
    ):
        failures.append(f"directory-cardinality-4097: seam observed {cardinality_inputs!r}")
    if state(root) != before_cardinality:
        failures.append("directory-cardinality-4097: fixture changed")
    controlled = os.path.join(root, "controlled")
    os.mkdir(controlled)
    os.chmod(controlled, 0o755)
    with open(os.path.join(controlled, "entry"), "wb") as handle:
        handle.write(b"x")
    os.chmod(os.path.join(controlled, "entry"), 0o644)
    before_root = state(root)
    real_scandir = os.scandir
    real_listdir = os.listdir
    real_close = os.close
    real_fstat = os.fstat
    root_stat = os.lstat("/")
    root_id = (root_stat.st_dev, root_stat.st_ino)
    controlled_fd = os.open(controlled, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    violations = []

    def root_path(value):
        return not isinstance(value, int) and os.fsdecode(value) == "/"

    def scandir_root(target):
        if root_path(target):
            violations.append("root directory was scanned by pathname")
            return real_scandir(controlled_fd)
        if isinstance(target, int):
            value = real_fstat(target)
            if (value.st_dev, value.st_ino) == root_id:
                return real_scandir(controlled_fd)
        return real_scandir(target)

    def listdir_root(target):
        if root_path(target):
            violations.append("root directory was listed by pathname")
            return real_listdir(controlled_fd)
        if isinstance(target, int):
            value = real_fstat(target)
            if (value.st_dev, value.st_ino) == root_id:
                return real_listdir(controlled_fd)
        return real_listdir(target)

    module.os.scandir = scandir_root
    module.os.listdir = listdir_root
    try:
        root_trace = b'100 newfstatat(AT_FDCWD, "/", 0x7f, 0) = 0\n100 +++ exited with 0 +++\n'
        root_mode = stat.S_IMODE(root_stat.st_mode)
        root_expected = (
            f"input-v1\t0\tdirectory\tprobe\tpresent\t{root_mode:04o}\t8\t"
            "1228cb53fde462d88e7bd04d6076c13df410e3f2c0358d0f5d133b9f6ed84c47\t"
            "external:/\n"
        ).encode("ascii")
        value = expect_success("external-root-probe", lambda: discover(paths, root_trace, initial_cwd="/"))
        if value is not None and value != root_expected:
            failures.append(f"external-root-probe: literal ledger mismatch: {value!r}")
    finally:
        module.os.scandir = real_scandir
        module.os.listdir = real_listdir
        os.close(controlled_fd)
    if violations:
        failures.append(f"external-root-probe: hook violations {violations!r}")
    if state(root) != before_root:
        failures.append("relation fixture changed")

    before_root_spelling = state(root)
    for name, override in (
        ("noncanonical-repo-root", {"repo_root": "//" + paths["repo"].lstrip("/")}),
        ("trailing-build-root", {"build_root": paths["build"] + "/"}),
        ("noncanonical-stable-root", {"stable_sysroot_root": "//" + paths["stable"].lstrip("/")}),
        ("trailing-nightly-root", {"nightly_sysroot_root": paths["nightly"] + "/"}),
    ):
        expect_exception(
            name,
            module.FormatError,
            lambda override=override: discover(paths, valid_read_exit_trace(paths), **override),
        )
    if state(root) != before_root_spelling:
        failures.append("root-spelling fixtures changed")


if failures:
    raise SystemExit("\n".join(failures))
print("bs2a-confirmed-gaps-red-ok")
"##;
    let mut outputs = Vec::new();
    for seed in ["1", "2"] {
        outputs.push(
            Command::new("/usr/bin/python3")
                .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
                .current_dir(repo)
                .env_clear()
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .env("PYTHONHASHSEED", seed)
                .output()
                .expect("run BS2a confirmed-gap regression driver"),
        );
    }
    let diagnostics = outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            format!(
                "seed={} status={:?} stdout={:?} stderr={:?}",
                index + 1,
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .collect::<Vec<_>>();
    let same_diagnostics = outputs.windows(2).all(|pair| {
        pair[0].status.code() == pair[1].status.code()
            && pair[0].stdout == pair[1].stdout
            && pair[0].stderr == pair[1].stderr
    });
    assert!(
        same_diagnostics
            && outputs.iter().all(|output| {
                output.status.success()
                    && output.stderr.is_empty()
                    && output.stdout == b"bs2a-confirmed-gaps-red-ok\n"
            }),
        "BS2a confirmed-gap regression matrix diagnostics:\n{}",
        diagnostics.join("\n")
    );
}

#[test]
fn discover_input_v1_candidate_only_rejects_reset_gaps() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-build-subject.py");
    let driver = r##"
import importlib.util
import ctypes
import json
import os
import shutil
import signal
import stat
import struct
import sys
import tempfile
import time
import types

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

diagnostics = {f"R{index}": [] for index in range(14)}
diagnostics.update(
    {
        "R6/write-only-mmap": [],
        "R6/zero-length-mmap": [],
        "R6/munmap-length": [],
        **{
            f"R13/{field}/{kind}": []
            for field in ("seq", "klass", "access", "result", "mode", "size", "sha256", "locator")
            for kind in ("list", "dict")
        },
        "R13/non-record": [],
    }
)


def failure(label, reason):
    diagnostics.setdefault(label, []).append(reason)


def tree(root, *, include_times=True):
    entries = []

    def visit(path):
        value = os.lstat(path)
        mode = stat.S_IMODE(value.st_mode)
        if stat.S_ISDIR(value.st_mode):
            kind, content = "directory", None
        elif stat.S_ISREG(value.st_mode):
            kind, content = "regular", open(path, "rb").read()
        elif stat.S_ISLNK(value.st_mode):
            kind, content = "symlink", os.fsencode(os.readlink(path))
        else:
            kind, content = "other", None
        entry = [
            os.fsencode(os.path.relpath(path, root)),
            kind,
            mode,
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            content,
        ]
        if include_times:
            entry.extend((value.st_mtime_ns, value.st_ctime_ns))
        entries.append(tuple(entry))
        if kind == "directory":
            for child in sorted(os.scandir(path), key=lambda entry: os.fsencode(entry.name)):
                visit(child.path)

    visit(root)
    return tuple(entries)


def fixture(root, *, many=False):
    os.chmod(root, 0o700)
    repo = os.path.join(root, "repo")
    vendor = os.path.join(repo, "vendor")
    vendor_pkg = os.path.join(vendor, "pkg")
    build = os.path.join(root, "build")
    stable = os.path.join(root, "stable")
    nightly = os.path.join(root, "nightly")
    outside = os.path.join(root, "outside.bin")
    enum = os.path.join(repo, "enum")
    empty_dir = os.path.join(repo, "empty")
    for path in (repo, vendor, vendor_pkg, build, stable, nightly, enum, empty_dir):
        os.mkdir(path)
        os.chmod(path, 0o700 if path == build else 0o755)
    if many:
        for index in range(4097):
            with open(os.path.join(enum, f"e{index:04d}"), "wb"):
                pass
    else:
        with open(os.path.join(enum, "a"), "wb") as handle:
            handle.write(b"a")
        os.chmod(os.path.join(enum, "a"), 0o644)

    def write(path, data=b"abc", mode=0o644):
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, mode)

    write(os.path.join(repo, "input"))
    write(os.path.join(vendor_pkg, "tool"))
    write(os.path.join(stable, "stable.bin"))
    write(os.path.join(nightly, "nightly.bin"))
    write(outside)
    return {
        "root": root,
        "repo": repo,
        "vendor": vendor,
        "vendor_file": os.path.join(vendor_pkg, "tool"),
        "build": build,
        "stable": stable,
        "nightly": nightly,
        "outside": outside,
        "enum": enum,
        "empty": empty_dir,
        "input": os.path.join(repo, "input"),
    }


def values(paths, **overrides):
    result = dict(
        root_pid=100,
        initial_cwd=paths["repo"],
        repo_root=paths["repo"],
        vendor_relative="vendor",
        build_root=paths["build"],
        stable_sysroot_root=paths["stable"],
        nightly_sysroot_root=paths["nightly"],
    )
    result.update(overrides)
    return result


def discover(paths, trace, **overrides):
    return module.discover_input_v1(trace, **values(paths, **overrides))


def exit_trace(pid=100):
    return f"{pid} +++ exited with 0 +++\n".encode("ascii")


def expect_exception(label, expected, operation):
    try:
        operation()
    except BaseException as exc:
        if type(exc) is not expected:
            failure(label, f"expected {expected.__name__}, got {type(exc).__name__}")
    else:
        failure(label, f"accepted invalid input, expected {expected.__name__}")


def expect_success(label, operation):
    try:
        return operation()
    except BaseException as exc:
        failure(label, f"expected success, got {type(exc).__name__}")
        return None


IN_ACCESS = 0x00000001
IN_OPEN = 0x00000020
IN_NONBLOCK = 0x00000800
IN_DONT_FOLLOW = 0x02000000
IN_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
libc = ctypes.CDLL(None, use_errno=True)
libc.inotify_init1.argtypes = [ctypes.c_int]
libc.inotify_init1.restype = ctypes.c_int
libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
libc.inotify_add_watch.restype = ctypes.c_int
libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
libc.inotify_rm_watch.restype = ctypes.c_int


def native_watches(paths, *, nofollow=()):
    requested = tuple(dict.fromkeys(paths))
    fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
    if fd < 0:
        return None, {}
    watches = {}
    for path in requested:
        flags = IN_ACCESS | IN_OPEN | (IN_DONT_FOLLOW if path in nofollow else 0)
        watch = libc.inotify_add_watch(fd, os.fsencode(path), flags)
        if watch < 0 or watch in watches:
            os.close(fd)
            return None, {}
        watches[watch] = path
    if len(watches) != len(requested):
        os.close(fd)
        return None, {}
    return fd, watches


def native_events(fd, watches):
    events = []
    if fd is None:
        return events
    while True:
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            return events
        if not data:
            return events
        offset = 0
        while offset + 16 <= len(data):
            watch, mask, _cookie, length = struct.unpack_from("iIII", data, offset)
            offset += 16 + length
            if watch in watches:
                events.append((watches[watch], mask))


def wait_child(pid, timeout=5.0):
    deadline = time.monotonic() + timeout
    while True:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
        except ChildProcessError:
            return None, True
        if waited == pid:
            return status, os.WIFEXITED(status) or os.WIFSIGNALED(status)
        if time.monotonic() >= deadline:
            return None, False
        time.sleep(0.01)


# R0: compile both wrappers before forking, then install the audit hook in an
# isolated child immediately before the exact public calls. The hook and its
# evidence die with that child, and the parent receives only public outcomes.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    target = os.path.join(paths["repo"], "target")
    with open(target, "wb") as handle:
        handle.write(b"abc")
    os.chmod(target, 0o644)
    alias = os.path.join(paths["repo"], "alias")
    os.symlink("target", alias)
    trace = (
        f'100 openat(AT_FDCWD, "{alias}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expected = (
        "input-v1\t0\tsymlink\tprobe\tpresent\t0777\t6\t"
        "34a04005bcaf206eec990bd9637d9fdb6725e0a0c0d4aebf003f17f4c956eb5c\t"
        "repo:/alias\n"
        "input-v1\t1\trepo\tprobe\tpresent\t0644\t3\t"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\t"
        "repo:/target\n"
    ).encode("ascii")
    watched_paths = {
        os.path.realpath(sys.argv[1]),
        os.path.realpath(os.path.join(os.getcwd(), "tests", "task4_build_subjects.rs")),
    }
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            token = os.urandom(12).hex()
            first_name = "u" + token[:10]
            second_name = "v" + token[10:]
            deep_one = "w" + os.urandom(6).hex()
            deep_two = "z" + os.urandom(6).hex()
            first_source = (
                f"def {first_name}(call, payload, options):\n"
                "    return call(payload, **options)\n"
            )
            second_source = (
                f"def {second_name}(call, payload, options):\n"
                f"    def {deep_one}(value):\n"
                f"        def {deep_two}(nested):\n"
                "            return call(nested, **options)\n"
                f"        return {deep_two}(value)\n"
                f"    return {deep_one}(payload)\n"
            )
            first_namespace = {}
            second_namespace = {}
            exec(compile(first_source, "<x>", "exec"), {"__builtins__": __builtins__}, first_namespace)
            exec(compile(second_source, "<x>", "exec"), {"__builtins__": __builtins__}, second_namespace)
            sensitive = []
            watched_reads = []

            def audit_observer(event, args):
                lowered = event.lower()
                if event in {"sys._getframe", "sys.settrace", "sys.setprofile"} or any(
                    token in lowered for token in ("frame", "trace", "profile", "code")
                ):
                    sensitive.append(event)
                if any(isinstance(arg, (types.FrameType, types.CodeType)) for arg in args):
                    sensitive.append("sensitive-object")
                if event == "open":
                    for arg in args[:1]:
                        try:
                            path = os.path.realpath(os.fsdecode(arg))
                        except (TypeError, ValueError):
                            continue
                        if path in watched_paths:
                            watched_reads.append(path)

            sys.addaudithook(audit_observer)
            outcomes = []
            for namespace, name in ((first_namespace, first_name), (second_namespace, second_name)):
                try:
                    outcomes.append(("ok", namespace[name](module.discover_input_v1, trace, values(paths)).decode("ascii")))
                except BaseException as exc:
                    outcomes.append(("error", type(exc).__name__, str(exc)))
            payload = {"outcomes": outcomes, "sensitive": sensitive, "watched": watched_reads}
            os.write(write_fd, json.dumps(payload).encode("utf-8"))
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    child_status, child_reaped = wait_child(child)
    if child_status is None and not child_reaped:
        failure("R0", "isolated wrapper child wait timed out")
    if not child_reaped:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        cleanup_status, child_reaped = wait_child(child)
        if cleanup_status is not None:
            child_status = cleanup_status
    raw = os.read(read_fd, 65536) if child_reaped else b""
    os.close(read_fd)
    payload = json.loads(raw.decode("utf-8")) if raw else {}
    outcomes = payload.get("outcomes", [])
    if child_status is None or not os.WIFEXITED(child_status) or os.WEXITSTATUS(child_status) != 0:
        failure("R0", "isolated wrapper child did not exit normally")
    if payload.get("sensitive"):
        failure("R0", "introspection audit event observed")
    if payload.get("watched"):
        failure("R0", "test or candidate source path read after import")
    if len(outcomes) < 2 or outcomes[0] != ["ok", expected.decode("ascii")]:
        failure("R0", "first wrapper missed literal ledger")
    if len(outcomes) < 2 or outcomes[1] != ["ok", expected.decode("ascii")]:
        failure("R0", "second wrapper missed literal ledger")
    if len(outcomes) == 2 and outcomes[0] != outcomes[1]:
        failure("R0", "wrapper outcomes differ")


# R1: a real directory with 4097 ordinary entries must be rejected before the
# result can be materialized as an unbounded directory record.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root, many=True)
    before = tree(root)
    trace = (
        f'100 openat(AT_FDCWD, "{paths["enum"]}", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3\n'
        "100 getdents64(3, 0x7f, 32768) = 24\n"
        "100 getdents64(3, 0x7f, 32768) = 0\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception("R1", module.FormatError, lambda: discover(paths, trace))
    if tree(root) != before:
        failure("R1", "fixture changed")


# R2: prebuild both same-shaped trees, then stop the isolated child before its
# audited input open. The parent verifies a retained original b FD through
# /proc, swaps only the prebuilt directories, resumes, and uses inotify for
# original/replacement provenance. No parent audit hook survives this case.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    nested = os.path.join(paths["repo"], "a", "b")
    replacement = nested + "." + os.urandom(8).hex()
    held_nested = nested + "." + os.urandom(8).hex()
    os.mkdir(os.path.join(paths["repo"], "a"))
    os.mkdir(nested)
    os.mkdir(replacement)
    os.chmod(os.path.join(paths["repo"], "a"), 0o755)
    os.chmod(nested, 0o755)
    os.chmod(replacement, 0o755)
    target = os.path.join(nested, "input")
    replacement_target = os.path.join(replacement, "input")
    with open(target, "wb") as handle:
        handle.write(b"abc")
    with open(replacement_target, "wb") as handle:
        handle.write(b"xyz")
    os.chmod(target, 0o644)
    os.chmod(replacement_target, 0o644)
    before = tree(root, include_times=False)
    original_paths = {nested, target}
    replacement_paths = {replacement, replacement_target}
    watch_fd, all_watches = native_watches(tuple(original_paths | replacement_paths))
    watches = {
        watch: path for watch, path in all_watches.items() if path in original_paths
    }
    replacement_watches = {
        watch: ("replacement", path)
        for watch, path in all_watches.items()
        if path in replacement_paths
    }
    if watch_fd is None:
        failure("R2", "native inotify unavailable")
    trace = (
        f'100 openat(AT_FDCWD, "{target}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"abc\", 3) = 3\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        b_acquisitions = [0]
        stopped = [False]

        def audit_relation(event, args):
            if event != "open" or not args:
                return
            path = os.fsdecode(args[0])
            if path == "b":
                b_acquisitions[0] += 1
            elif not stopped[0] and b_acquisitions[0] and path == "input":
                stopped[0] = True
                os.kill(os.getpid(), signal.SIGSTOP)

        sys.addaudithook(audit_relation)
        try:
            try:
                result = ("ok", discover(paths, trace).decode("ascii"))
            except BaseException as exc:
                result = ("error", type(exc).__name__, str(exc))
            result += (b_acquisitions[0],)
            os.write(write_fd, json.dumps(result).encode("utf-8"))
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    child_status = None
    swapped = False
    original_renamed = False
    child_reaped = False
    original_identity = os.stat(nested, follow_symlinks=False)
    try:
        child_status, child_reaped = wait_child(child)
        if child_status is None:
            failure("R2", "isolated child wait timed out")
        if child_status is None or not os.WIFSTOPPED(child_status):
            failure("R2", "isolated child did not stop before input open")
        else:
            held = 0
            try:
                for entry in os.listdir(f"/proc/{child}/fd"):
                    try:
                        value = os.stat(f"/proc/{child}/fd/{entry}")
                    except OSError:
                        continue
                    if (value.st_dev, value.st_ino) == (original_identity.st_dev, original_identity.st_ino):
                        held += 1
            except OSError:
                held = -1
            if held < 1:
                failure("R2", "no held original b FD was observed")
            os.rename(nested, held_nested)
            original_renamed = True
            os.rename(replacement, nested)
            swapped = True
            if not child_reaped:
                os.kill(child, signal.SIGCONT)
                child_status, child_reaped = wait_child(child)
                if child_status is None:
                    failure("R2", "resumed child wait timed out")
    finally:
        if not child_reaped:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            cleanup_status, child_reaped = wait_child(child)
            if cleanup_status is not None:
                child_status = cleanup_status
        events = native_events(watch_fd, watches | replacement_watches)
        if watch_fd is not None:
            os.close(watch_fd)
        if swapped:
            os.rename(nested, replacement)
            os.rename(held_nested, nested)
        elif original_renamed:
            os.rename(held_nested, nested)
    raw = os.read(read_fd, 65536) if child_reaped else b""
    os.close(read_fd)
    result = json.loads(raw.decode("utf-8")) if raw else None
    if child_status is None or not os.WIFEXITED(child_status) or os.WEXITSTATUS(child_status) != 0:
        failure("R2", "isolated child did not exit normally")
    if not isinstance(result, list) or len(result) < 3 or result[-1] != 1:
        failure("R2", "original b path acquisition count was not one")
    if not (isinstance(result, list) and len(result) >= 2 and result[0] == "error" and result[1] == "MutationError"):
        failure("R2", "expected MutationError after replacement")
    original_target_activity = sum(
        path == target and bool(mask & (IN_OPEN | IN_ACCESS))
        for path, mask in events
    )
    replacement_activity = sum(
        isinstance(path, tuple)
        and path[0] == "replacement"
        and bool(mask & (IN_OPEN | IN_ACCESS))
        for path, mask in events
    )
    if not original_target_activity:
        failure("R2", "original input open/access provenance was not observed")
    if replacement_activity:
        failure("R2", "replacement tree was opened or read")
    if tree(root, include_times=False) != before:
        failure("R2", "fixture changed")


# R3: prebuild a replacement repo, then stop the isolated child at the vendor
# open after initial-cwd observation and exactly one repo acquisition. The
# parent verifies a retained original repo FD through /proc, performs two
# renames, resumes, and requires original-vendor/no-replacement inotify use.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    replacement_repo = paths["repo"] + "." + os.urandom(8).hex()
    held_repo = paths["repo"] + "." + os.urandom(8).hex()
    shutil.copytree(paths["repo"], replacement_repo, symlinks=True)
    replacement_vendor_file = os.path.join(replacement_repo, "vendor", "pkg", "tool")
    with open(replacement_vendor_file, "wb") as handle:
        handle.write(b"xyz")
    os.chmod(replacement_vendor_file, 0o644)
    before = tree(root, include_times=False)
    original_vendor_paths = {
        paths["vendor"],
        os.path.join(paths["vendor"], "pkg"),
        paths["vendor_file"],
    }
    replacement_vendor_paths = {
        os.path.join(replacement_repo, "vendor"),
        os.path.join(replacement_repo, "vendor", "pkg"),
        replacement_vendor_file,
    }
    watch_fd, all_watches = native_watches(tuple(original_vendor_paths | replacement_vendor_paths))
    watches = {
        watch: path for watch, path in all_watches.items() if path in original_vendor_paths
    }
    replacement_watches = {
        watch: ("replacement", path)
        for watch, path in all_watches.items()
        if path in replacement_vendor_paths
    }
    if watch_fd is None:
        failure("R3", "native inotify unavailable")
    trace = (
        f'100 openat(AT_FDCWD, "{paths["vendor_file"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"abc\", 3) = 3\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        cwd_seen = [False]
        repo_acquisitions = [0]
        stopped = [False]

        def audit_relation(event, args):
            if event != "open" or not args or stopped[0]:
                return
            path = os.fsdecode(args[0])
            if not cwd_seen[0] and path == os.path.basename(paths["root"]):
                cwd_seen[0] = True
            elif cwd_seen[0] and path == "repo":
                repo_acquisitions[0] += 1
            elif cwd_seen[0] and repo_acquisitions[0] == 1 and path == "vendor":
                stopped[0] = True
                os.kill(os.getpid(), signal.SIGSTOP)

        sys.addaudithook(audit_relation)
        try:
            try:
                result = ("ok", discover(paths, trace, initial_cwd=paths["root"]).decode("ascii"))
            except BaseException as exc:
                result = ("error", type(exc).__name__, str(exc))
            os.write(write_fd, json.dumps(result).encode("utf-8"))
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    child_status = None
    swapped = False
    original_renamed = False
    child_reaped = False
    original_identity = os.stat(paths["repo"], follow_symlinks=False)
    try:
        child_status, child_reaped = wait_child(child)
        if child_status is None:
            failure("R3", "isolated child wait timed out")
        if child_status is None or not os.WIFSTOPPED(child_status):
            failure("R3", "isolated child did not stop before vendor acquisition")
        else:
            held = 0
            try:
                for entry in os.listdir(f"/proc/{child}/fd"):
                    try:
                        value = os.stat(f"/proc/{child}/fd/{entry}")
                    except OSError:
                        continue
                    if (value.st_dev, value.st_ino) == (original_identity.st_dev, original_identity.st_ino):
                        held += 1
            except OSError:
                held = -1
            if held < 1:
                failure("R3", "no held original repo FD was observed")
            os.rename(paths["repo"], held_repo)
            original_renamed = True
            os.rename(replacement_repo, paths["repo"])
            swapped = True
            if not child_reaped:
                os.kill(child, signal.SIGCONT)
                child_status, child_reaped = wait_child(child)
                if child_status is None:
                    failure("R3", "resumed child wait timed out")
    finally:
        if not child_reaped:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            cleanup_status, child_reaped = wait_child(child)
            if cleanup_status is not None:
                child_status = cleanup_status
        events = native_events(watch_fd, watches | replacement_watches)
        if watch_fd is not None:
            os.close(watch_fd)
        if swapped:
            os.rename(paths["repo"], replacement_repo)
            os.rename(held_repo, paths["repo"])
        elif original_renamed:
            os.rename(held_repo, paths["repo"])
    raw = os.read(read_fd, 65536) if child_reaped else b""
    os.close(read_fd)
    result = json.loads(raw.decode("utf-8")) if raw else None
    if child_status is None or not os.WIFEXITED(child_status) or os.WEXITSTATUS(child_status) != 0:
        failure("R3", "isolated child did not exit normally")
    if not (isinstance(result, list) and len(result) >= 2 and result[0] == "error" and result[1] == "MutationError"):
        failure("R3", "expected MutationError after repo replacement")
    original_vendor_opened = sum(
        path in original_vendor_paths and bool(mask & (IN_OPEN | IN_ACCESS))
        for path, mask in events
    )
    replacement_vendor_opened = sum(
        isinstance(path, tuple)
        and path[0] == "replacement"
        and bool(mask & (IN_OPEN | IN_ACCESS))
        for path, mask in events
    )
    if not original_vendor_opened:
        failure("R3", "original vendor open was not observed")
    if replacement_vendor_opened:
        failure("R3", "replacement vendor object was opened or read")
    if tree(root, include_times=False) != before:
        failure("R3", "fixture changed")


# R4: deterministic public success control for one regular target acquisition.
# Native inotify proves exactly one target IN_OPEN while the resolved regular
# target is read. The full same-FD S0/H0/S1/rewind/H1/S2 mutation invariant is
# review-only here, as required by the architecture decision; this control
# does not claim to dynamically prove a race-free between-pass mutation.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    target = paths["outside"]
    before = tree(root)
    watch_fd, watches = native_watches((target,))
    if watch_fd is None:
        failure("R4", "native inotify unavailable")
    trace = (
        f'100 openat(AT_FDCWD, "{target}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"abc\", 3) = 3\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expected = (
        "input-v1\t0\ttool\tread\tpresent\t0644\t3\t"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\t"
        f"external:{target}\n"
    ).encode("ascii")
    value = expect_success("R4", lambda: discover(paths, trace))
    events = native_events(watch_fd, watches)
    if watch_fd is not None:
        os.close(watch_fd)
    if value != expected:
        failure("R4", "literal ledger mismatch")
    open_count = sum(path == target and bool(mask & IN_OPEN) for path, mask in events)
    if open_count != 1:
        failure("R4", f"target was opened {open_count} times")
    if tree(root) != before:
        failure("R4", "fixture changed")


# R5: ordinary external openat/read is a tool input, with no mmap or exec.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    trace = (
        f'100 openat(AT_FDCWD, "{paths["outside"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 read(3, \"abc\", 3) = 3\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expected = (
        "input-v1\t0\ttool\tread\tpresent\t0644\t3\t"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\t"
        f"external:{paths['outside']}\n"
    ).encode("ascii")
    value = expect_success("R5", lambda: discover(paths, trace))
    if value is not None and value != expected:
        failure("R5", "literal ledger mismatch")


# R6: mmap and munmap boundaries are exact public trace errors.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    cases = {
        "write-only-mmap": (
            f'100 openat(AT_FDCWD, "{paths["build"]}/generated.o", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3\n'
            "100 write(3, \"abc\", 3) = 3\n"
            "100 close(3) = 0\n"
            f'100 openat(AT_FDCWD, "{paths["build"]}/generated.o", O_WRONLY|O_CLOEXEC) = 4\n'
            "100 mmap(NULL, 3, PROT_READ, MAP_PRIVATE, 4, 0) = 0\n"
            "100 munmap(0, 3) = 0\n"
            "100 close(4) = 0\n"
            f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 5\n'
            "100 read(5, \"abc\", 3) = 3\n"
            "100 close(5) = 0\n"
            "100 +++ exited with 0 +++\n"
        ),
        "zero-length-mmap": (
            f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
            "100 mmap(NULL, 0, PROT_READ, MAP_PRIVATE, 3, 0) = 0\n"
            "100 close(3) = 0\n"
            f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'
            "100 read(4, \"abc\", 3) = 3\n"
            "100 close(4) = 0\n"
            "100 +++ exited with 0 +++\n"
        ),
        "munmap-length": (
            f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
            "100 mmap(NULL, 3, PROT_READ, MAP_PRIVATE, 3, 0) = 0\n"
            "100 munmap(0, 2) = 0\n"
            "100 close(3) = 0\n"
            f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'
            "100 read(4, \"abc\", 3) = 3\n"
            "100 close(4) = 0\n"
            "100 +++ exited with 0 +++\n"
        ),
    }
    for name, raw in cases.items():
        expect_exception(f"R6/{name}", module.FormatError, lambda raw=raw: discover(paths, raw.encode("ascii")))


# R7: dup aliases share a directory description, including its EOF state.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    trace = (
        f'100 openat(AT_FDCWD, "{paths["enum"]}", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3\n'
        "100 dup(3) = 9\n"
        "100 getdents64(3, 0x7f, 32768) = 24\n"
        "100 getdents64(3, 0x7f, 32768) = 0\n"
        "100 getdents64(9, 0x7f, 32768) = 24\n"
        "100 close(3) = 0\n"
        "100 close(9) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception("R7", module.FormatError, lambda: discover(paths, trace))


# R8: clone aliases share directory EOF, while a positive-through-one/EOF-
# through-the-other control trace is a successful single directory row.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    reject = (
        f'100 openat(AT_FDCWD, "{paths["enum"]}", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3\n'
        "100 clone(child_stack=NULL, flags=SIGCHLD, child_tidptr=NULL) = 101\n"
        "100 getdents64(3, 0x7f, 32768) = 24\n"
        "100 getdents64(3, 0x7f, 32768) = 0\n"
        "101 getdents64(3, 0x7f, 32768) = 24\n"
        "100 close(3) = 0\n"
        "101 close(3) = 0\n"
        "101 +++ exited with 0 +++\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception("R8", module.FormatError, lambda: discover(paths, reject))
    control = (
        f'100 openat(AT_FDCWD, "{paths["enum"]}", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3\n'
        "100 clone(child_stack=NULL, flags=SIGCHLD, child_tidptr=NULL) = 101\n"
        "100 getdents64(3, 0x7f, 32768) = 24\n"
        "101 getdents64(3, 0x7f, 32768) = 0\n"
        "100 close(3) = 0\n"
        "101 close(3) = 0\n"
        "101 +++ exited with 0 +++\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expected = (
        "input-v1\t0\tdirectory\tenumerate\tpresent\t0755\t4\t"
        "27a4f844873b98b62676cf72fa49841676f4b63221ae7afd85fdad5bbf4d85de\t"
        "repo:/enum\n"
    ).encode("ascii")
    value = expect_success("R8", lambda: discover(paths, control))
    if value is not None and value != expected:
        failure("R8", "control ledger mismatch")


# R9: cloning an address space copies a live mapping, but each process retires
# its own inherited copy independently.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    trace = (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 mmap(NULL, 3, PROT_READ, MAP_PRIVATE, 3, 0) = 0\n"
        "100 clone(child_stack=NULL, flags=SIGCHLD, child_tidptr=NULL) = 101\n"
        "101 munmap(0, 3) = 0\n"
        "101 close(3) = 0\n"
        "101 +++ exited with 0 +++\n"
        "100 munmap(0, 3) = 0\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expected = (
        "input-v1\t0\trepo\tread\tpresent\t0644\t3\t"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\t"
        "repo:/input\n"
    ).encode("ascii")
    value = expect_success("R9", lambda: discover(paths, trace))
    if value is not None and value != expected:
        failure("R9", "literal ledger mismatch")


# R10: immediate EOF is valid for an empty directory; a result larger than the
# requested getdents buffer is not.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    empty_trace = (
        f'100 openat(AT_FDCWD, "{paths["empty"]}", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3\n'
        "100 getdents64(3, 0x7f, 32768) = 0\n"
        "100 close(3) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expected = (
        "input-v1\t0\tdirectory\tenumerate\tpresent\t0755\t0\t"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\t"
        "repo:/empty\n"
    ).encode("ascii")
    value = expect_success("R10", lambda: discover(paths, empty_trace))
    if value is not None and value != expected:
        failure("R10", "empty-directory ledger mismatch")
    oversized = empty_trace.replace(b") = 0\n", b") = 32769\n", 1)
    expect_exception("R10", module.FormatError, lambda: discover(paths, oversized))


# R11: an exclusive output whose immediate parent is absent is not a claimed
# successful build output, and the real build directory remains empty.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    before = tree(paths["build"])
    trace = (
        f'100 openat(AT_FDCWD, "{paths["build"]}/missing/generated.o", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3\n'
        "100 write(3, \"o\", 1) = 1\n"
        "100 close(3) = 0\n"
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'
        "100 read(4, \"abc\", 3) = 3\n"
        "100 close(4) = 0\n"
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")
    expect_exception("R11", module.MutationError, lambda: discover(paths, trace))
    if tree(paths["build"]) != before:
        failure("R11", "build directory changed")


# R12: an already-green no-follow symlink control rejects a supplied root
# symlink before replay; this does not claim general identity-alias coverage.
with tempfile.TemporaryDirectory(prefix="x-") as root:
    paths = fixture(root)
    os.unlink(os.path.join(paths["nightly"], "nightly.bin"))
    os.rmdir(paths["nightly"])
    os.symlink(paths["stable"], paths["nightly"])
    before = tree(root)
    expect_exception("R12", module.MutationError, lambda: discover(paths, exit_trace()))
    if tree(root) != before:
        failure("R12", "symlink-alias fixture changed")


# R13: public encoder validation rejects every malformed field shape and a
# non-record element with FormatError, never leaking a Python TypeError.
digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
fields = ["seq", "klass", "access", "result", "mode", "size", "sha256", "locator"]
valid = [0, "tool", "read", "present", 0o644, 3, digest, "external:/x"]
for index, name in enumerate(fields):
    for replacement in (["x"], {"x": 1}):
        record = list(valid)
        record[index] = replacement
        label = f"R13/{name}/{type(replacement).__name__}"
        expect_exception(
            label,
            module.FormatError,
            lambda record=record: module.encode_ledger([module.InputRecord(*record)]),
        )
expect_exception("R13/non-record", module.FormatError, lambda: module.encode_ledger([[]]))

if any(diagnostics.values()):
    for label in sorted(diagnostics):
        print(f"{label}: {'PASS' if not diagnostics[label] else 'FAIL'}")
    for label in sorted(diagnostics):
        for reason in diagnostics[label]:
            print(f"{label}: {reason}")
    raise SystemExit(1)
print("bs2a-reset-red-ok")
"##;
    let output = Command::new("/usr/bin/python3")
        .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONHASHSEED", "1")
        .output()
        .expect("run BS2a reset RED regression driver");
    assert!(
        output.status.success()
            && output.stderr.is_empty()
            && output.stdout == b"bs2a-reset-red-ok\n",
        "BS2a reset RED diagnostics:\n{}\nstderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn discover_input_v1_candidate_only_rejects_final_review_gaps() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-build-subject.py");
    let driver = r##"
import hashlib
import importlib.util
import os
import stat
import sys
import tempfile

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

labels = [
    "alias-map-direct-read",
    "alias-read-direct-exec",
    "odirectory-regular",
    "odirectory-rdwr",
    "getdents-nonreadable-directory",
    "mmap-directory",
    "trace-separator-fs",
    "trace-separator-gs",
    "trace-separator-rs",
    "trace-separator-us",
    "read-malformed-escape",
    "read-raw-control",
    "read-empty-payload",
    "read-valid-escape-control",
    "write-malformed-escape",
    "write-raw-control",
    "write-empty-payload",
    "write-valid-escape-control",
    "surrogate-encoder",
    "surrogate-root",
    "surrogate-vendor",
    "open-create-mode",
    "openat-create-mode",
    "openat2-create-mode",
    "open-create-missing-mode",
    "openat-create-missing-mode",
    "openat2-create-missing-mode",
    "open-no-create-mode",
    "openat-no-create-mode",
    "openat2-no-create-mode",
    "structural-ancestor-sibling-churn",
    "vendor-anchor-pre-evidence-churn",
    "unobserved-anchor-sibling-churn",
    "build-root-ephemeral-churn",
    "build-provisional-enoent-ephemeral-churn",
    "build-root-final-nonempty",
    "cached-enotdir-blocker-replacement",
    "cached-enoent-parent-replacement",
    "absent-symlink-two-reads",
    "absent-symlink-final-metadata",
    "build-enoent-before-create",
    "build-enoent-after-create",
    "present-regular-final-metadata",
    "created-output-probe",
    "build-success-probe-unowned",
    "hardlinked-symlink-chain",
    "symlink-dotdot-decoy",
    "dirfd-fchdir-held-target",
    "open-only-probe-read-control",
    "same-locator-symlink-repetition",
    "symlink-depth-40-success",
    "absent-enoent-dotdot-floor",
    "absent-enoent-dotdot-above-floor",
    "absent-enotdir-dotdot-floor",
    "absent-enotdir-dotdot-above-floor",
    "event-time-evidence-baseline",
    "ledger-symlink-size-zero",
    "ledger-symlink-size-4097",
    "ledger-directory-size-4194305",
    "root-enoent-parent-full-identity",
    "absent-final-boundary",
    "absent-final-boundary-replaced",
    "relation-open-replacement",
    "external-post-s2-full-identity",
]
failures = {label: [] for label in labels}
deferred = {"external-post-s2-full-identity": "formal-review-only: no deterministic public seam without ptrace"}


def failure(label, reason):
    failures[label].append(reason)


def tree(root):
    entries = []

    def visit(path):
        value = os.lstat(path)
        mode = stat.S_IMODE(value.st_mode)
        if stat.S_ISDIR(value.st_mode):
            kind, content = "directory", None
        elif stat.S_ISREG(value.st_mode):
            kind, content = "regular", open(path, "rb").read()
        elif stat.S_ISLNK(value.st_mode):
            kind, content = "symlink", os.fsencode(os.readlink(path))
        else:
            kind, content = "other", None
        entries.append((
            os.fsencode(os.path.relpath(path, root)),
            kind,
            mode,
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
            content,
        ))
        if kind == "directory":
            for child in sorted(os.scandir(path), key=lambda entry: os.fsencode(entry.name)):
                visit(child.path)

    visit(root)
    return tuple(entries)


def fixture(root):
    os.chmod(root, 0o700)
    repo = os.path.join(root, "repo")
    vendor = os.path.join(repo, "vendor")
    build = os.path.join(root, "build")
    stable = os.path.join(root, "stable")
    nightly = os.path.join(root, "nightly")
    for path in (repo, vendor, build, stable, nightly):
        os.mkdir(path)
        os.chmod(path, 0o700 if path == build else 0o755)
    directory = os.path.join(repo, "directory")
    os.mkdir(directory)
    os.chmod(directory, 0o755)

    def write(path, data, mode=0o644):
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, mode)

    write(os.path.join(repo, "input"), b"data")
    write(os.path.join(directory, "entry"), b"entry")
    dynamic = os.path.join(root, "dynamic")
    tool = os.path.join(root, "tool")
    write(dynamic, b"data")
    write(tool, b"data", 0o755)
    write(os.path.join(stable, "stable"), b"data")
    write(os.path.join(nightly, "nightly"), b"data")
    return {
        "root": root,
        "repo": repo,
        "vendor": vendor,
        "build": build,
        "stable": stable,
        "nightly": nightly,
        "directory": directory,
        "input": os.path.join(repo, "input"),
        "dynamic": dynamic,
        "tool": tool,
    }


def values(paths, **overrides):
    result = dict(
        root_pid=100,
        initial_cwd=paths["repo"],
        repo_root=paths["repo"],
        vendor_relative="vendor",
        build_root=paths["build"],
        stable_sysroot_root=paths["stable"],
        nightly_sysroot_root=paths["nightly"],
    )
    result.update(overrides)
    return result


def discover(paths, trace, **overrides):
    return module.discover_input_v1(trace, **values(paths, **overrides))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def locator(path, namespace):
    if namespace == "external":
        return f"external:{path}"
    return f"{namespace}:/{os.path.basename(path)}"


def regular_row(path, klass, access, namespace):
    value = os.stat(path, follow_symlinks=False)
    data = open(path, "rb").read()
    return (klass, access, "present", f"{stat.S_IMODE(value.st_mode):04o}", str(len(data)), digest(data), locator(path, namespace))


def symlink_row(path, namespace):
    value = os.lstat(path)
    data = os.fsencode(os.readlink(path))
    return ("symlink", "probe", "present", f"{stat.S_IMODE(value.st_mode):04o}", str(len(data)), digest(data), locator(path, namespace))


def ledger(rows):
    rows = sorted(rows, key=lambda row: row[-1].encode("utf-8"))
    return b"".join(
        ("\t".join(("input-v1", str(index), *row)) + "\n").encode("utf-8")
        for index, row in enumerate(rows)
    )


def exit_trace(pid=100):
    return f"{pid} +++ exited with 0 +++\n".encode("ascii")


def read_trace(paths, payload, count, result=None):
    if result is None:
        result = count
    return (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'.encode("ascii")
        + b'100 read(3, "' + payload + f'", {count}) = {result}\n'.encode("ascii")
        + b"100 close(3) = 0\n100 +++ exited with 0 +++\n"
    )


def write_trace(paths, payload, count, result=None):
    if result is None:
        result = count
    return (
        f'100 openat(AT_FDCWD, "{paths["build"]}/generated", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3\n'.encode("ascii")
        + b'100 write(3, "' + payload + f'", {count}) = {result}\n'.encode("ascii")
        + b"100 close(3) = 0\n"
        + f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'.encode("ascii")
        + b'100 read(4, "data", 4) = 4\n100 close(4) = 0\n100 +++ exited with 0 +++\n'
    )


def run_trace(label, build_trace, *, expected=None, expected_error=None, **overrides):
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-final-{label}-") as root:
        paths = fixture(root)
        before = tree(root)
        try:
            actual = discover(paths, build_trace(paths), **overrides)
        except BaseException as exc:
            if expected_error is None:
                failure(label, f"expected success, got {type(exc).__name__}: {exc}")
            elif type(exc) is not expected_error:
                failure(label, f"expected {expected_error.__name__}, got {type(exc).__name__}: {exc}")
        else:
            if expected_error is not None:
                failure(label, f"accepted invalid input, expected {expected_error.__name__}")
            elif actual != expected:
                failure(label, f"ledger mismatch: {actual!r}")
        if tree(root) != before:
            failure(label, "fixture changed")


def run_operation(label, operation, *, expected_error):
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-final-{label}-") as root:
        paths = fixture(root)
        before = tree(root)
        try:
            operation(paths)
        except BaseException as exc:
            if type(exc) is not expected_error:
                failure(label, f"expected {expected_error.__name__}, got {type(exc).__name__}: {exc}")
        else:
            failure(label, f"accepted invalid input, expected {expected_error.__name__}")
        if tree(root) != before:
            failure(label, "fixture changed")


# Resolved aliases combine access by the resolved target, while retaining one
# symlink probe row per alias.
def map_alias_trace(paths):
    alias = os.path.join(paths["repo"], "map-link")
    return (
        f'100 openat(AT_FDCWD, "{alias}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 mmap(NULL, 4, PROT_READ, MAP_PRIVATE, 3, 0) = 0\n"
        "100 munmap(0, 4) = 0\n"
        "100 close(3) = 0\n"
        f'100 openat(AT_FDCWD, "{paths["dynamic"]}", O_RDONLY|O_CLOEXEC) = 4\n'
        '100 read(4, "data", 4) = 4\n'
        "100 close(4) = 0\n100 +++ exited with 0 +++\n"
    ).encode("ascii")


def map_alias_expected(paths):
    alias = os.path.join(paths["repo"], "map-link")
    return ledger([
        regular_row(paths["dynamic"], "dynamic", "read", "external"),
        symlink_row(alias, "repo"),
    ])


with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-alias-map-") as root:
    paths = fixture(root)
    alias = os.path.join(paths["repo"], "map-link")
    os.symlink(paths["dynamic"], alias)
    before = tree(root)
    try:
        actual = discover(paths, map_alias_trace(paths))
    except BaseException as exc:
        failure("alias-map-direct-read", f"expected success, got {type(exc).__name__}: {exc}")
    else:
        expected = map_alias_expected(paths)
        if actual != expected:
            failure("alias-map-direct-read", f"ledger mismatch: {actual!r}")
        try:
            records = module.parse_ledger(actual)
        except BaseException as exc:
            failure("alias-map-direct-read", f"public ledger parse failed: {type(exc).__name__}: {exc}")
        else:
            if len(records) != 2 or sum(record.klass == "symlink" for record in records) != 1:
                failure("alias-map-direct-read", "resolved alias emitted duplicate or missing rows")
    if tree(root) != before:
        failure("alias-map-direct-read", "fixture changed")


def exec_alias_trace(paths):
    alias = os.path.join(paths["repo"], "exec-link")
    return (
        f'100 openat(AT_FDCWD, "{alias}", O_RDONLY|O_CLOEXEC) = 3\n'
        '100 read(3, "data", 4) = 4\n'
        "100 close(3) = 0\n"
        f'100 execve("{paths["tool"]}", ["tool"], []) = 0\n'
        "100 +++ exited with 0 +++\n"
    ).encode("ascii")


with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-alias-exec-") as root:
    paths = fixture(root)
    alias = os.path.join(paths["repo"], "exec-link")
    os.symlink(paths["tool"], alias)
    before = tree(root)
    try:
        actual = discover(paths, exec_alias_trace(paths))
    except BaseException as exc:
        failure("alias-read-direct-exec", f"expected success, got {type(exc).__name__}: {exc}")
    else:
        expected = ledger([
            regular_row(paths["tool"], "tool", "read-execute", "external"),
            symlink_row(alias, "repo"),
        ])
        if actual != expected:
            failure("alias-read-direct-exec", f"ledger mismatch: {actual!r}")
        try:
            records = module.parse_ledger(actual)
        except BaseException as exc:
            failure("alias-read-direct-exec", f"public ledger parse failed: {type(exc).__name__}: {exc}")
        else:
            if len(records) != 2 or sum(record.klass == "symlink" for record in records) != 1:
                failure("alias-read-direct-exec", "resolved alias emitted duplicate or missing rows")
    if tree(root) != before:
        failure("alias-read-direct-exec", "fixture changed")


# Classification and descriptor state errors are public errors, not successful
# ledger rows.
run_trace(
    "odirectory-regular",
    lambda p: (
        f'100 openat(AT_FDCWD, "{p["input"]}", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 3\n'
        "100 close(3) = 0\n"
        f'100 openat(AT_FDCWD, "{p["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'
        '100 read(4, "data", 4) = 4\n'
        "100 close(4) = 0\n100 +++ exited with 0 +++\n"
    ).encode("ascii"),
    expected_error=module.MutationError,
)
run_trace(
    "getdents-nonreadable-directory",
    lambda p: (
        f'100 openat(AT_FDCWD, "{p["directory"]}", O_WRONLY|O_DIRECTORY|O_CLOEXEC) = 3\n'
        "100 getdents64(3, 0x7f, 32768) = 0\n100 close(3) = 0\n"
        f'100 openat(AT_FDCWD, "{p["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'
        '100 read(4, "data", 4) = 4\n'
        "100 close(4) = 0\n100 +++ exited with 0 +++\n"
    ).encode("ascii"),
    expected_error=module.FormatError,
)
run_trace(
    "odirectory-rdwr",
    lambda p: (
        f'100 openat(AT_FDCWD, "{p["directory"]}", O_RDWR|O_DIRECTORY|O_CLOEXEC) = 3\n'
        "100 getdents64(3, 0x7f, 32768) = 0\n100 close(3) = 0\n"
        f'100 openat(AT_FDCWD, "{p["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'
        '100 read(4, "data", 4) = 4\n100 close(4) = 0\n100 +++ exited with 0 +++\n'
    ).encode("ascii"),
    expected_error=module.FormatError,
)
run_trace(
    "mmap-directory",
    lambda p: (
        f'100 openat(AT_FDCWD, "{p["directory"]}", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 3\n'
        "100 mmap(NULL, 1, PROT_READ, MAP_PRIVATE, 3, 0) = 0\n"
        "100 munmap(0, 1) = 0\n100 close(3) = 0\n"
        f'100 openat(AT_FDCWD, "{p["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'
        '100 read(4, "data", 4) = 4\n'
        "100 close(4) = 0\n100 +++ exited with 0 +++\n"
    ).encode("ascii"),
    expected_error=module.FormatError,
)


base_read_trace = lambda p: read_trace(p, b"data", 4)
for name, separator in (("fs", 0x1C), ("gs", 0x1D), ("rs", 0x1E), ("us", 0x1F)):
    run_trace(
        f"trace-separator-{name}",
        lambda p, separator=separator: base_read_trace(p).replace(b"\n", bytes((separator,)), 1),
        expected_error=module.FormatError,
    )


run_trace("read-malformed-escape", lambda p: read_trace(p, b"bad\\q", 4), expected_error=module.FormatError)
run_trace("read-raw-control", lambda p: read_trace(p, b"bad\x01", 4), expected_error=module.FormatError)


def read_expected_for(paths):
    return ledger([regular_row(paths["input"], "repo", "read", "repo")])


def run_read_success(label, payload, count):
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-final-{label}-") as root:
        paths = fixture(root)
        before = tree(root)
        try:
            actual = discover(paths, read_trace(paths, payload, count))
        except BaseException as exc:
            failure(label, f"expected success, got {type(exc).__name__}: {exc}")
        else:
            expected = read_expected_for(paths)
            if actual != expected:
                failure(label, f"ledger mismatch: {actual!r}")
        if tree(root) != before:
            failure(label, "fixture changed")


run_read_success("read-empty-payload", b"", 0)
run_read_success("read-valid-escape-control", b"\\x01\\x1f", 2)
run_trace("write-malformed-escape", lambda p: write_trace(p, b"\\q", 1), expected_error=module.FormatError)
run_trace("write-raw-control", lambda p: write_trace(p, b"bad\x01", 4), expected_error=module.FormatError)


def write_expected_for(paths):
    return ledger([regular_row(paths["input"], "repo", "read", "repo")])


for label, payload, count in (
    ("write-empty-payload", b"", 0),
    ("write-valid-escape-control", b"\\x01\\x1f", 2),
):
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-final-{label}-") as root:
        paths = fixture(root)
        before = tree(root)
        try:
            actual = discover(paths, write_trace(paths, payload, count))
        except BaseException as exc:
            failure(label, f"expected success, got {type(exc).__name__}: {exc}")
        else:
            expected = write_expected_for(paths)
            if actual != expected:
                failure(label, f"ledger mismatch: {actual!r}")
        if tree(root) != before:
            failure(label, "fixture changed")


def surrogate_encoder(paths):
    module.encode_ledger([
        module.InputRecord(0, "repo", "read", "present", 0o644, 4, digest(b"data"), "repo:/\ud800")
    ])


run_operation("surrogate-encoder", surrogate_encoder, expected_error=module.FormatError)
run_operation(
    "surrogate-root",
    lambda p: discover(p, exit_trace(), repo_root=os.path.join(p["root"], "\ud800")),
    expected_error=module.FormatError,
)
run_operation("surrogate-vendor", lambda p: discover(p, exit_trace(), vendor_relative="\ud800"), expected_error=module.FormatError)


def input_tail(paths, fd=4):
    return (
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = {fd}\n'
        f'100 read({fd}, "data", 4) = 4\n'
        f"100 close({fd}) = 0\n100 +++ exited with 0 +++\n"
    )


def mode_trace(paths, syscall, *, create, mode_present):
    flags = "O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC" if create else "O_RDONLY|O_CLOEXEC"
    if create:
        path = os.path.join(paths["build"], "mode-output")
    else:
        path = paths["input"]
    mode = ", 0600" if mode_present and syscall != "openat2" else ""
    if syscall == "open":
        call = f'100 open("{path}", {flags}{mode}) = 3\n'
    elif syscall == "openat":
        call = f'100 openat(AT_FDCWD, "{path}", {flags}{mode}) = 3\n'
    else:
        struct_mode = ", mode=0600" if mode_present else ""
        call = f'100 openat2(AT_FDCWD, "{path}", {{ flags={flags}{struct_mode}, resolve=0 }}, 24) = 3\n'
    if create:
        return (call + "100 close(3) = 0\n" + input_tail(paths)).encode("ascii")
    return (call + '100 read(3, "data", 4) = 4\n100 close(3) = 0\n100 +++ exited with 0 +++\n').encode("ascii")


def mode_expected(paths):
    return ledger([regular_row(paths["input"], "repo", "read", "repo")])


def run_mode_success(label, syscall):
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-final-{label}-") as root:
        paths = fixture(root)
        before = tree(root)
        try:
            actual = discover(paths, mode_trace(paths, syscall, create=True, mode_present=True))
        except BaseException as exc:
            failure(label, f"expected success, got {type(exc).__name__}: {exc}")
        else:
            if actual != mode_expected(paths):
                failure(label, f"ledger mismatch: {actual!r}")
        if tree(root) != before:
            failure(label, "fixture changed")


for syscall in ("open", "openat", "openat2"):
    run_mode_success(f"{syscall}-create-mode", syscall)

for syscall in ("open", "openat", "openat2"):
    run_trace(
        f"{syscall}-create-missing-mode",
        lambda p, syscall=syscall: mode_trace(p, syscall, create=True, mode_present=False),
        expected_error=module.FormatError,
    )
    run_trace(
        f"{syscall}-no-create-mode",
        lambda p, syscall=syscall: mode_trace(p, syscall, create=False, mode_present=True),
        expected_error=module.FormatError,
    )


# Sibling churn changes structural-directory metadata without replacing its
# edge. Exercise it once between lstat and open, and once before the final edge
# walk; a valid external read still has a literal one-row ledger.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-structural-ancestor-sibling-churn-") as root:
    paths = fixture(root)
    expected = ledger([regular_row(paths["dynamic"], "tool", "read", "external")])
    markers = [
        os.path.join(root, "structural-churn-during-custody"),
        os.path.join(root, "structural-churn-after-custody"),
    ]
    seams = {"acquire": False, "post_custody": False}
    active = [True]

    def churn(path):
        os.mkdir(path)
        os.rmdir(path)

    def audit_structural(event, args):
        if not active[0] or event != "open" or not args:
            return
        try:
            path = os.fsdecode(args[0])
        except (TypeError, ValueError):
            return
        if not seams["acquire"] and path == os.path.basename(root):
            seams["acquire"] = True
            churn(markers[0])
        elif seams["acquire"] and not seams["post_custody"] and path == "dynamic":
            seams["post_custody"] = True
            churn(markers[1])

    sys.addaudithook(audit_structural)
    try:
        try:
            actual = discover(paths, (
                f'100 openat(AT_FDCWD, "{paths["dynamic"]}", O_RDONLY|O_CLOEXEC) = 3\n'
                '100 read(3, "data", 4) = 4\n'
                "100 close(3) = 0\n100 +++ exited with 0 +++\n"
            ).encode("ascii"))
        except BaseException as exc:
            failure("structural-ancestor-sibling-churn", f"expected success, got {type(exc).__name__}: {exc}")
        else:
            if actual != expected:
                failure("structural-ancestor-sibling-churn", f"ledger mismatch: {actual!r}")
    finally:
        active[0] = False
        for marker in markers:
            if os.path.isdir(marker):
                os.rmdir(marker)
    if not seams["acquire"]:
        failure("structural-ancestor-sibling-churn", "acquisition churn seam was not reached")
    if not seams["post_custody"]:
        failure("structural-ancestor-sibling-churn", "post-custody churn seam was not reached")
    if any(os.path.exists(marker) for marker in markers):
        failure("structural-ancestor-sibling-churn", "churn marker was not cleaned up")


# The vendor anchor is structural-only until its exact directory probe. A
# create/remove cycle after anchor custody but before trace evidence must not
# make that valid empty-directory probe fail.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-vendor-anchor-pre-evidence-churn-") as root:
    paths = fixture(root)
    expected = ledger([("directory", "probe", "present", "0755", "0", digest(b""), "vendor:/")])
    marker = os.path.join(paths["vendor"], "pre-evidence-churn")
    seam = [False]
    real_listdir = os.listdir
    build_identity = os.stat(paths["build"], follow_symlinks=False)
    before = tuple((*entry[:9], entry[11]) for entry in tree(root))

    def listdir_vendor_anchor(target):
        result = real_listdir(target)
        if not seam[0] and isinstance(target, int):
            value = os.fstat(target)
            if (value.st_dev, value.st_ino) == (build_identity.st_dev, build_identity.st_ino):
                if result:
                    raise AssertionError("build root was not initially empty")
                os.mkdir(marker)
                os.rmdir(marker)
                seam[0] = True
        return result

    module.os.listdir = listdir_vendor_anchor
    try:
        try:
            actual = discover(paths, (
                f'100 openat(AT_FDCWD, "{paths["vendor"]}", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 3\n'
                "100 close(3) = 0\n100 +++ exited with 0 +++\n"
            ).encode("ascii"))
        except BaseException as exc:
            failure("vendor-anchor-pre-evidence-churn", f"expected success, got {type(exc).__name__}: {exc}")
        else:
            if actual != expected:
                failure("vendor-anchor-pre-evidence-churn", f"ledger mismatch: {actual!r}")
    finally:
        module.os.listdir = real_listdir
        if os.path.isdir(marker):
            os.rmdir(marker)
    if not seam[0]:
        failure("vendor-anchor-pre-evidence-churn", "vendor pre-evidence churn seam was not reached")
    if module.os.listdir is not real_listdir:
        failure("vendor-anchor-pre-evidence-churn", "vendor churn seam was not restored")
    if os.path.exists(marker):
        failure("vendor-anchor-pre-evidence-churn", "vendor churn marker was not cleaned up")
    if tuple((*entry[:9], entry[11]) for entry in tree(root)) != before:
        failure("vendor-anchor-pre-evidence-churn", "fixture content or mode changed")


# An unobserved repo sibling must not become an input row. The audit hook fires
# while the observed input is being acquired, after all named anchors are held.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-unobserved-anchor-sibling-churn-") as root:
    paths = fixture(root)
    expected = ledger([regular_row(paths["input"], "repo", "read", "repo")])
    marker = os.path.join(paths["repo"], "unobserved-sibling")
    seam = [False]
    active = [True]

    def audit_unobserved(event, args):
        if not active[0]:
            return
        try:
            path = os.fsdecode(args[0]) if args else None
        except (TypeError, ValueError):
            return
        if event == "open" and not seam[0] and path == "input":
            seam[0] = True
            os.mkdir(marker)
            os.rmdir(marker)

    sys.addaudithook(audit_unobserved)
    try:
        try:
            actual = discover(paths, (
                f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
                '100 read(3, "data", 4) = 4\n'
                "100 close(3) = 0\n100 +++ exited with 0 +++\n"
            ).encode("ascii"))
        except BaseException as exc:
            failure("unobserved-anchor-sibling-churn", f"expected success, got {type(exc).__name__}: {exc}")
        else:
            if actual != expected:
                failure("unobserved-anchor-sibling-churn", f"ledger mismatch: {actual!r}")
    finally:
        active[0] = False
        if os.path.isdir(marker):
            os.rmdir(marker)
    if not seam[0]:
        failure("unobserved-anchor-sibling-churn", "unobserved sibling seam was not reached")
    if os.path.exists(marker):
        failure("unobserved-anchor-sibling-churn", "unobserved sibling marker was not cleaned up")


# A create/remove cycle leaves the build root empty and must not be rejected by
# directory timestamp changes used as an emptiness proxy.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-build-root-ephemeral-churn-") as root:
    paths = fixture(root)
    expected = ledger([regular_row(paths["dynamic"], "tool", "read", "external")])
    marker = os.path.join(paths["build"], "ephemeral-entry")
    seam = [False]
    real_listdir = os.listdir
    build_identity = os.stat(paths["build"], follow_symlinks=False)

    def listdir_ephemeral(target):
        result = real_listdir(target)
        if not seam[0] and isinstance(target, int):
            value = os.fstat(target)
            if (value.st_dev, value.st_ino) == (build_identity.st_dev, build_identity.st_ino):
                if result:
                    raise AssertionError("build root was not initially empty")
                seam[0] = True
                os.mkdir(marker)
                os.rmdir(marker)
        return result

    module.os.listdir = listdir_ephemeral
    try:
        try:
            actual = discover(paths, (
                f'100 openat(AT_FDCWD, "{paths["dynamic"]}", O_RDONLY|O_CLOEXEC) = 3\n'
                '100 read(3, "data", 4) = 4\n'
                "100 close(3) = 0\n100 +++ exited with 0 +++\n"
            ).encode("ascii"))
        except BaseException as exc:
            failure("build-root-ephemeral-churn", f"expected success, got {type(exc).__name__}: {exc}")
        else:
            if actual != expected:
                failure("build-root-ephemeral-churn", f"ledger mismatch: {actual!r}")
    finally:
        module.os.listdir = real_listdir
        if os.path.isdir(marker):
            os.rmdir(marker)
    if not seam[0]:
        failure("build-root-ephemeral-churn", "ephemeral build-root seam was not reached")
    if module.os.listdir is not real_listdir:
        failure("build-root-ephemeral-churn", "listdir seam was not restored")
    if os.path.exists(marker):
        failure("build-root-ephemeral-churn", "ephemeral build-root marker was not cleaned up")


# A provisional build-root ENOENT is suppressed by the later exact output
# create. Churn immediately before the semantic final listdir must not reject
# the otherwise empty build root.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-build-provisional-enoent-ephemeral-churn-") as root:
    paths = fixture(root)
    expected = ledger([regular_row(paths["input"], "repo", "read", "repo")])
    marker = os.path.join(paths["build"], "provisional-ephemeral-entry")
    seam = [False]
    absent_seen = [False]
    real_stat = os.stat
    real_listdir = os.listdir
    build_identity = real_stat(paths["build"], follow_symlinks=False)
    before = tuple((*entry[:9], entry[11]) for entry in tree(root))

    def is_build_output(target, dir_fd):
        if not isinstance(dir_fd, int) or os.fsdecode(target) != "generated.o":
            return False
        value = os.fstat(dir_fd)
        return (value.st_dev, value.st_ino) == (build_identity.st_dev, build_identity.st_ino)

    def stat_provisional(target, *, dir_fd=None, follow_symlinks=True):
        try:
            return real_stat(target, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        except FileNotFoundError:
            if is_build_output(target, dir_fd):
                absent_seen[0] = True
            raise

    def listdir_provisional(target):
        result = real_listdir(target)
        if not seam[0] and absent_seen[0] and isinstance(target, int):
            value = os.fstat(target)
            if (value.st_dev, value.st_ino) == (build_identity.st_dev, build_identity.st_ino):
                if result:
                    raise AssertionError("build root was not initially empty")
                os.mkdir(marker)
                os.rmdir(marker)
                seam[0] = True
        return result

    module.os.stat = stat_provisional
    module.os.listdir = listdir_provisional
    try:
        try:
            missing = f'{paths["build"]}/generated.o'
            trace = (
                f'100 newfstatat(AT_FDCWD, "{missing}", 0x7f, 0) = -1 ENOENT (No such file or directory)\n'
                f'100 openat(AT_FDCWD, "{missing}", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3\n'
                '100 write(3, "object", 6) = 6\n'
                '100 close(3) = 0\n'
                f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'
                '100 read(4, "data", 4) = 4\n'
                '100 close(4) = 0\n100 +++ exited with 0 +++\n'
            ).encode("ascii")
            actual = discover(paths, trace)
        except BaseException as exc:
            failure("build-provisional-enoent-ephemeral-churn", f"expected success, got {type(exc).__name__}: {exc}")
        else:
            if actual != expected:
                failure("build-provisional-enoent-ephemeral-churn", f"ledger mismatch: {actual!r}")
    finally:
        module.os.stat = real_stat
        module.os.listdir = real_listdir
        if os.path.isdir(marker):
            os.rmdir(marker)
    if not absent_seen[0]:
        failure("build-provisional-enoent-ephemeral-churn", "provisional build ENOENT seam was not reached")
    if not seam[0]:
        failure("build-provisional-enoent-ephemeral-churn", "final build-root listdir seam was not reached")
    if module.os.stat is not real_stat or module.os.listdir is not real_listdir:
        failure("build-provisional-enoent-ephemeral-churn", "provisional churn seams were not restored")
    if os.path.exists(marker):
        failure("build-provisional-enoent-ephemeral-churn", "provisional churn marker was not cleaned up")
    if tuple((*entry[:9], entry[11]) for entry in tree(root)) != before:
        failure("build-provisional-enoent-ephemeral-churn", "fixture content or mode changed")


# The build root is checked empty once, then an unrelated late entry must be
# rejected by a direct final emptiness check and cleaned up by this test.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-build-root-final-nonempty-") as root:
    paths = fixture(root)
    marker = os.path.join(paths["build"], "late-entry")
    seam = [False]
    real_listdir = os.listdir
    build_identity = os.stat(paths["build"], follow_symlinks=False)

    def listdir_build(target):
        result = real_listdir(target)
        if not seam[0] and isinstance(target, int):
            value = os.fstat(target)
            if (value.st_dev, value.st_ino) == (build_identity.st_dev, build_identity.st_ino):
                if result:
                    raise AssertionError("build root was not initially empty")
                seam[0] = True
                os.mkdir(marker)
        return result

    module.os.listdir = listdir_build
    try:
        try:
            discover(paths, (
                f'100 openat(AT_FDCWD, "{paths["dynamic"]}", O_RDONLY|O_CLOEXEC) = 3\n'
                '100 read(3, "data", 4) = 4\n'
                "100 close(3) = 0\n100 +++ exited with 0 +++\n"
            ).encode("ascii"))
        except BaseException as exc:
            if type(exc) is not module.MutationError:
                failure("build-root-final-nonempty", f"expected MutationError, got {type(exc).__name__}: {exc}")
        else:
            failure("build-root-final-nonempty", "accepted late build-root entry")
    finally:
        module.os.listdir = real_listdir
        if os.path.isdir(marker):
            os.rmdir(marker)
    if not seam[0]:
        failure("build-root-final-nonempty", "late build-root seam was not reached")
    if module.os.listdir is not real_listdir:
        failure("build-root-final-nonempty", "listdir seam was not restored")
    if os.path.exists(marker):
        failure("build-root-final-nonempty", "late build-root marker was not cleaned up")


# After the parent evidence and final edge/fstat comparison both succeed,
# create either the exact missing leaf or only its missing prefix. The latter
# preserves ENOENT and the canonical locator, so boundary identity must also
# be reproduced by the final absent replay.
def absent_final_case(label, requested_tail, first_missing):
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-final-{label}-") as root:
        paths = fixture(root)
        marker = os.path.join(paths["repo"], first_missing)
        state = {
            "absent": False,
            "repo_fstats": 0,
            "final_edge": False,
            "repo_final_observed": False,
            "created": False,
        }
        real_stat = os.stat
        real_fstat = os.fstat
        repo_identity = real_stat(paths["repo"], follow_symlinks=False)

        def stat_absent(target, *, dir_fd=None, follow_symlinks=True):
            if state["repo_final_observed"] and not state["created"]:
                state["created"] = True
                os.mkdir(marker)
            try:
                value = real_stat(target, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
            except FileNotFoundError:
                if not state["absent"] and os.fsdecode(target) == first_missing:
                    state["absent"] = True
                raise
            if (
                state["absent"]
                and state["repo_fstats"] >= 3
                and os.fsdecode(target) == "repo"
                and isinstance(dir_fd, int)
            ):
                state["final_edge"] = True
            return value

        def fstat_absent(fd):
            value = real_fstat(fd)
            if (value.st_dev, value.st_ino) == (repo_identity.st_dev, repo_identity.st_ino) and state["absent"]:
                state["repo_fstats"] += 1
                if state["final_edge"]:
                    state["repo_final_observed"] = True
            return value

        module.os.stat = stat_absent
        module.os.fstat = fstat_absent
        try:
            try:
                discover(paths, (
                    f'100 newfstatat(AT_FDCWD, "{paths["repo"]}/{requested_tail}", 0x7f, 0) = -1 ENOENT (No such file or directory)\n'
                    f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
                    '100 read(3, "data", 4) = 4\n'
                    "100 close(3) = 0\n100 +++ exited with 0 +++\n"
                ).encode("ascii"))
            except BaseException as exc:
                if type(exc) is not module.MutationError:
                    failure(label, f"expected MutationError, got {type(exc).__name__}: {exc}")
            else:
                failure(label, "accepted changed final absent boundary")
        finally:
            module.os.stat = real_stat
            module.os.fstat = real_fstat
            if os.path.isdir(marker):
                os.rmdir(marker)
        if not state["absent"]:
            failure(label, "initial absent seam was not reached")
        if (
            state["repo_fstats"] < 4
            or not state["final_edge"]
            or not state["repo_final_observed"]
            or not state["created"]
        ):
            failure(label, f"final boundary seam was incomplete: {state!r}")
        if module.os.stat is not real_stat or module.os.fstat is not real_fstat:
            failure(label, "stat/fstat seams were not restored")
        if os.path.exists(marker):
            failure(label, "absent-final marker was not cleaned up")


absent_final_case("absent-final-boundary", "absent-final-leaf", "absent-final-leaf")
absent_final_case(
    "absent-final-boundary-replaced",
    "absent-final-prefix/leaf",
    "absent-final-prefix",
)


# Mutation caught: replacing the cached ENOTDIR blocker after the production
# final-edge loop must invalidate the final absent replay.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-cached-enotdir-") as root:
    paths = fixture(root)
    blocker = os.path.join(paths["repo"], "blocker")
    backup = blocker + ".held"
    with open(blocker, "wb") as handle:
        handle.write(b"blocker")
    os.chmod(blocker, 0o644)
    original = os.lstat(blocker)
    repo_identity = os.stat(paths["repo"], follow_symlinks=False)
    real_stat = os.stat
    real_fstat = os.fstat
    real_read = os.read
    stat_calls = [0]
    fstat_calls = [0]
    collection_read = [False]
    pending_final_edge = [False]
    final_edge_observed = [False]
    replaced = [False]

    def stat_cached_enotdir(target, *, dir_fd=None, follow_symlinks=True):
        result = real_stat(target, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        if isinstance(dir_fd, int) and os.fsdecode(target) == "blocker" and (
            real_fstat(dir_fd).st_dev,
            real_fstat(dir_fd).st_ino,
        ) == (repo_identity.st_dev, repo_identity.st_ino):
            stat_calls[0] += 1
            if collection_read[0]:
                pending_final_edge[0] = True
        return result

    def fstat_cached_enotdir(target):
        result = real_fstat(target)
        if (result.st_dev, result.st_ino) == (original.st_dev, original.st_ino):
            fstat_calls[0] += 1
            if pending_final_edge[0] and collection_read[0] and not replaced[0]:
                final_edge_observed[0] = True
                os.rename(blocker, backup)
                with open(blocker, "wb") as handle:
                    handle.write(b"replacement")
                os.chmod(blocker, 0o644)
                replaced[0] = True
            pending_final_edge[0] = False
        return result

    def read_cached_enotdir(fd, size):
        result = real_read(fd, size)
        try:
            value = real_fstat(fd)
        except OSError:
            return result
        if (value.st_dev, value.st_ino) == (original.st_dev, original.st_ino):
            collection_read[0] = True
        return result

    module.os.stat = stat_cached_enotdir
    module.os.fstat = fstat_cached_enotdir
    module.os.read = read_cached_enotdir
    try:
        trace = (
            f'100 newfstatat(AT_FDCWD, "{paths["repo"]}/blocker/child", 0x7f, 0) = -1 ENOTDIR (Not a directory)\n'
            f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
            '100 read(3, "data", 4) = 4\n'
            "100 close(3) = 0\n100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            discover(paths, trace)
        except BaseException as exc:
            if type(exc) is not module.MutationError:
                failure("cached-enotdir-blocker-replacement", f"expected MutationError, got {type(exc).__name__}: {exc}")
        else:
            failure("cached-enotdir-blocker-replacement", "accepted replaced cached ENOTDIR blocker")
    finally:
        module.os.stat = real_stat
        module.os.fstat = real_fstat
        module.os.read = real_read
        if os.path.exists(backup):
            if os.path.exists(blocker):
                os.unlink(blocker)
            os.rename(backup, blocker)
    if stat_calls[0] == 0 or fstat_calls[0] == 0 or not final_edge_observed[0]:
        failure("cached-enotdir-blocker-replacement", f"blocker final edge observations were stat={stat_calls[0]}, fstat={fstat_calls[0]}, final={final_edge_observed[0]}")
    if not replaced[0]:
        failure("cached-enotdir-blocker-replacement", "cached ENOTDIR replacement seam was not reached")
    if module.os.stat is not real_stat or module.os.fstat is not real_fstat or module.os.read is not real_read:
        failure("cached-enotdir-blocker-replacement", "stat/fstat seams were not restored")
    if not os.path.exists(blocker) or os.lstat(blocker).st_ino != original.st_ino:
        failure("cached-enotdir-blocker-replacement", "original blocker was not restored")
    with open(blocker, "rb") as handle:
        if handle.read() != b"blocker":
            failure("cached-enotdir-blocker-replacement", "restored blocker content changed")
    if os.path.exists(backup):
        failure("cached-enotdir-blocker-replacement", "cached ENOTDIR backup was not cleaned up")


# Mutation caught: replacing the cached nearest existing ENOENT parent after
# its final edge stat/fstat observation must invalidate absent replay.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-cached-enoent-") as root:
    paths = fixture(root)
    parent = os.path.join(paths["repo"], "missing-parent")
    backup = parent + ".held"
    os.mkdir(parent)
    os.chmod(parent, 0o755)
    original = os.lstat(parent)
    repo_identity = os.stat(paths["repo"], follow_symlinks=False)
    real_stat = os.stat
    real_fstat = os.fstat
    real_open = os.open
    stat_calls = [0]
    fstat_calls = [0]
    collection_scan = [False]
    pending_final_edge = [False]
    final_edge_observed = [False]
    replaced = [False]

    def stat_cached_enoent(target, *, dir_fd=None, follow_symlinks=True):
        result = real_stat(target, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        if isinstance(dir_fd, int) and os.fsdecode(target) == "missing-parent" and (
            real_fstat(dir_fd).st_dev,
            real_fstat(dir_fd).st_ino,
        ) == (repo_identity.st_dev, repo_identity.st_ino):
            stat_calls[0] += 1
            if collection_scan[0]:
                pending_final_edge[0] = True
        return result

    def fstat_cached_enoent(target):
        result = real_fstat(target)
        if (result.st_dev, result.st_ino) == (original.st_dev, original.st_ino):
            fstat_calls[0] += 1
            if pending_final_edge[0] and collection_scan[0] and not replaced[0]:
                final_edge_observed[0] = True
                os.rename(parent, backup)
                os.mkdir(parent)
                os.chmod(parent, 0o755)
                replaced[0] = True
            pending_final_edge[0] = False
        return result

    def open_cached_enoent(path, flags, mode=0o777, *, dir_fd=None):
        fd = real_open(path, flags, mode, dir_fd=dir_fd) if dir_fd is not None else real_open(path, flags, mode)
        if os.fsdecode(path) == "." and isinstance(dir_fd, int):
            value = real_fstat(dir_fd)
            if (value.st_dev, value.st_ino) == (original.st_dev, original.st_ino):
                collection_scan[0] = True
        return fd

    module.os.stat = stat_cached_enoent
    module.os.fstat = fstat_cached_enoent
    module.os.open = open_cached_enoent
    try:
        trace = (
            f'100 newfstatat(AT_FDCWD, "{paths["repo"]}/missing-parent/missing-leaf", 0x7f, 0) = -1 ENOENT (No such file or directory)\n'
            f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
            '100 read(3, "data", 4) = 4\n'
            "100 close(3) = 0\n100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            discover(paths, trace)
        except BaseException as exc:
            if type(exc) is not module.MutationError:
                failure("cached-enoent-parent-replacement", f"expected MutationError, got {type(exc).__name__}: {exc}")
        else:
            failure("cached-enoent-parent-replacement", "accepted replaced cached ENOENT parent")
    finally:
        module.os.stat = real_stat
        module.os.fstat = real_fstat
        module.os.open = real_open
        if os.path.exists(backup):
            if os.path.exists(parent):
                os.rmdir(parent)
            os.rename(backup, parent)
    if stat_calls[0] == 0 or fstat_calls[0] == 0 or not final_edge_observed[0]:
        failure("cached-enoent-parent-replacement", f"parent final edge observations were stat={stat_calls[0]}, fstat={fstat_calls[0]}, final={final_edge_observed[0]}")
    if not replaced[0]:
        failure("cached-enoent-parent-replacement", "cached ENOENT replacement seam was not reached")
    if module.os.stat is not real_stat or module.os.fstat is not real_fstat or module.os.open is not real_open:
        failure("cached-enoent-parent-replacement", "stat/fstat seams were not restored")
    if not os.path.exists(parent) or os.lstat(parent).st_ino != original.st_ino:
        failure("cached-enoent-parent-replacement", "original ENOENT parent was not restored")
    if os.path.exists(backup):
        failure("cached-enoent-parent-replacement", "cached ENOENT backup was not cleaned up")


# Mutation caught: replaying an absent path through one symlink must reuse its
# first target observation, producing exactly two total target reads.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-absent-symlink-") as root:
    paths = fixture(root)
    link = os.path.join(paths["repo"], "absent-link")
    os.symlink("missing-target", link)
    before = tree(root)
    real_readlink = os.readlink
    reads = []

    def readlink_absent(target, *, dir_fd=None):
        reads.append((target, dir_fd))
        return real_readlink(target, dir_fd=dir_fd)

    module.os.readlink = readlink_absent
    actual = None
    try:
        trace = (
            f'100 newfstatat(AT_FDCWD, "{paths["repo"]}/absent-link/missing-leaf", 0x7f, 0) = -1 ENOENT (No such file or directory)\n'
            "100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            actual = discover(paths, trace)
        except BaseException as exc:
            failure("absent-symlink-two-reads", f"expected success, got {type(exc).__name__}: {exc}")
    finally:
        module.os.readlink = real_readlink
    if len(reads) != 2:
        failure("absent-symlink-two-reads", f"symlink target was read {len(reads)} times, expected 2")
    if any(os.fsdecode(target) != "absent-link" or not isinstance(dir_fd, int) for target, dir_fd in reads):
        failure("absent-symlink-two-reads", f"symlink reads were not descriptor-relative: {reads!r}")
    if actual is not None:
        try:
            records = module.parse_ledger(actual)
        except BaseException as exc:
            failure("absent-symlink-two-reads", f"public ledger parse failed: {type(exc).__name__}: {exc}")
        else:
            keys = {(record.klass, record.locator) for record in records}
            expected = {
                ("directory", "repo:/"),
                ("symlink", "repo:/absent-link"),
                ("absent", "repo:/missing-target/missing-leaf"),
            }
            if keys != expected:
                failure("absent-symlink-two-reads", f"absent symlink ledger keys were {keys!r}")
    if module.os.readlink is not real_readlink:
        failure("absent-symlink-two-reads", "readlink seam was not restored")
    if tree(root) != before:
        failure("absent-symlink-two-reads", "absent symlink fixture was not cleaned up")


# Mutation caught: a symlink metadata-only change at final listdir must fail
# before final replay reads the cached target again.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-absent-symlink-metadata-") as root:
    paths = fixture(root)
    link = os.path.join(paths["repo"], "absent-link")
    os.symlink("missing-target", link)
    original = os.lstat(link)
    real_readlink = os.readlink
    real_listdir = os.listdir
    real_fstat = os.fstat
    build_identity = os.stat(paths["build"], follow_symlinks=False)
    reads = []
    listdir_calls = [0]
    mutated = [False]
    reads_at_mutation = [None]

    def readlink_metadata(target, *, dir_fd=None):
        reads.append((target, dir_fd))
        return real_readlink(target, dir_fd=dir_fd)

    def listdir_metadata(target):
        result = real_listdir(target)
        if isinstance(target, int):
            value = real_fstat(target)
            if (value.st_dev, value.st_ino) == (build_identity.st_dev, build_identity.st_ino):
                listdir_calls[0] += 1
                if listdir_calls[0] == 2:
                    reads_at_mutation[0] = len(reads)
                    current = os.lstat(link)
                    os.utime(
                        link,
                        ns=(current.st_atime_ns, current.st_mtime_ns + 1),
                        follow_symlinks=False,
                    )
                    mutated[0] = True
        return result

    module.os.readlink = readlink_metadata
    module.os.listdir = listdir_metadata
    try:
        trace = (
            f'100 newfstatat(AT_FDCWD, "{paths["repo"]}/absent-link/missing-leaf", 0x7f, 0) = -1 ENOENT (No such file or directory)\n'
            "100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            discover(paths, trace)
        except BaseException as exc:
            if type(exc) is not module.MutationError:
                failure("absent-symlink-final-metadata", f"expected MutationError, got {type(exc).__name__}: {exc}")
        else:
            failure("absent-symlink-final-metadata", "accepted symlink metadata change")
    finally:
        module.os.readlink = real_readlink
        module.os.listdir = real_listdir
        try:
            os.utime(
                link,
                ns=(original.st_atime_ns, original.st_mtime_ns),
                follow_symlinks=False,
            )
        except OSError as exc:
            failure("absent-symlink-final-metadata", f"could not restore symlink metadata: {exc}")
    if listdir_calls[0] != 2:
        failure("absent-symlink-final-metadata", f"held build-root listdir calls were {listdir_calls[0]}, expected 2")
    if not mutated[0]:
        failure("absent-symlink-final-metadata", "symlink metadata seam was not reached")
    if reads_at_mutation[0] != 2:
        failure("absent-symlink-final-metadata", f"initial symlink reads before final listdir were {reads_at_mutation[0]}, expected 2")
    if len(reads) != 2:
        failure("absent-symlink-final-metadata", f"symlink target was read {len(reads)} times, expected no reads after metadata mutation")
    if module.os.readlink is not real_readlink or module.os.listdir is not real_listdir:
        failure("absent-symlink-final-metadata", "symlink metadata seams were not restored")
    if not os.path.islink(link) or os.readlink(link) != "missing-target":
        failure("absent-symlink-final-metadata", "symlink target was not cleaned up")


# Mutation caught: an ENOENT observation of exact build/generated is ignored
# only when the later exclusive create proves it was a logical output.
def build_enoent_case(label, *, after_create):
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-final-{label}-") as root:
        paths = fixture(root)
        before = tree(root)
        missing = f'{paths["build"]}/generated'
        absent = f'100 newfstatat(AT_FDCWD, "{missing}", 0x7f, 0) = -1 ENOENT (No such file or directory)\n'
        create = f'100 openat(AT_FDCWD, "{missing}", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3\n100 close(3) = 0\n'
        input_trace = (
            f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'
            '100 read(4, "data", 4) = 4\n'
            "100 close(4) = 0\n100 +++ exited with 0 +++\n"
        )
        trace = (create + absent if after_create else absent + create) + input_trace
        try:
            actual = discover(paths, trace.encode("ascii"))
        except BaseException as exc:
            if after_create:
                if type(exc) is not module.FormatError:
                    failure(label, f"expected FormatError, got {type(exc).__name__}: {exc}")
            else:
                failure(label, f"expected repo-only success, got {type(exc).__name__}: {exc}")
        else:
            if after_create:
                failure(label, "accepted ENOENT after logical creation")
            else:
                expected = ledger([regular_row(paths["input"], "repo", "read", "repo")])
                if actual != expected:
                    failure(label, f"build ENOENT before create emitted more than repo input: {actual!r}")
                try:
                    records = module.parse_ledger(actual)
                except BaseException as exc:
                    failure(label, f"public ledger parse failed: {type(exc).__name__}: {exc}")
                else:
                    if len(records) != 1 or records[0].locator != "repo:/input":
                        failure(label, f"build ENOENT before create records were {records!r}")
        if tree(root) != before:
            failure(label, "build ENOENT fixture was not cleaned up")


build_enoent_case("build-enoent-before-create", after_create=False)
build_enoent_case("build-enoent-after-create", after_create=True)


# Mutation caught: present-regular metadata changed at the second held
# build-root listdir must be rejected by final binding validation.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-present-regular-metadata-") as root:
    paths = fixture(root)
    target = paths["dynamic"]
    original = os.stat(target, follow_symlinks=False)
    with open(target, "rb") as handle:
        original_data = handle.read()
    real_listdir = os.listdir
    real_fstat = os.fstat
    build_identity = os.stat(paths["build"], follow_symlinks=False)
    listdir_calls = [0]
    mutated = [False]

    def listdir_present_metadata(target_fd):
        result = real_listdir(target_fd)
        if isinstance(target_fd, int):
            value = real_fstat(target_fd)
            if (value.st_dev, value.st_ino) == (build_identity.st_dev, build_identity.st_ino):
                listdir_calls[0] += 1
                if listdir_calls[0] == 2:
                    os.chmod(target, 0o600)
                    mutated[0] = True
        return result

    module.os.listdir = listdir_present_metadata
    try:
        trace = (
            f'100 openat(AT_FDCWD, "{target}", O_RDONLY|O_CLOEXEC) = 3\n'
            '100 read(3, "data", 4) = 4\n'
            "100 close(3) = 0\n100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            discover(paths, trace)
        except BaseException as exc:
            if type(exc) is not module.MutationError:
                failure("present-regular-final-metadata", f"expected MutationError, got {type(exc).__name__}: {exc}")
        else:
            failure("present-regular-final-metadata", "accepted present-regular metadata change")
    finally:
        module.os.listdir = real_listdir
        os.chmod(target, original.st_mode & 0o7777)
        os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns), follow_symlinks=False)
    if listdir_calls[0] != 2:
        failure("present-regular-final-metadata", f"held build-root listdir calls were {listdir_calls[0]}, expected 2")
    if not mutated[0]:
        failure("present-regular-final-metadata", "present-regular metadata seam was not reached")
    if module.os.listdir is not real_listdir:
        failure("present-regular-final-metadata", "listdir seam was not restored")
    restored = os.stat(target, follow_symlinks=False)
    if (
        (restored.st_dev, restored.st_ino, restored.st_mode & 0o7777, restored.st_size, restored.st_mtime_ns)
        != (original.st_dev, original.st_ino, original.st_mode & 0o7777, original.st_size, original.st_mtime_ns)
    ):
        failure("present-regular-final-metadata", "present-regular metadata was not restored")
    with open(target, "rb") as handle:
        if handle.read() != original_data:
            failure("present-regular-final-metadata", "present-regular content was not restored")


# Mutation caught: a successful probe of a physically present but unowned
# build-root input must be rejected before it can become a ledger row.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-build-success-probe-") as root:
    paths = fixture(root)
    target = os.path.join(paths["build"], "unowned")
    build_identity = os.stat(paths["build"], follow_symlinks=False)
    real_listdir = os.listdir
    real_fstat = os.fstat
    listdir_calls = [0]
    created = [False]

    def listdir_unowned_probe(target_fd):
        if isinstance(target_fd, int):
            value = real_fstat(target_fd)
            if (value.st_dev, value.st_ino) == (build_identity.st_dev, build_identity.st_ino):
                listdir_calls[0] += 1
                if listdir_calls[0] == 2 and os.path.exists(target):
                    os.unlink(target)
        result = real_listdir(target_fd)
        if listdir_calls[0] == 1:
            with open(target, "wb") as handle:
                handle.write(b"data")
            os.chmod(target, 0o600)
            created[0] = True
        return result

    module.os.listdir = listdir_unowned_probe
    try:
        trace = (
            f'100 newfstatat(AT_FDCWD, "{target}", 0x7f, 0) = 0\n'
            f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 3\n'
            '100 read(3, "data", 4) = 4\n'
            "100 close(3) = 0\n100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            discover(paths, trace)
        except BaseException as exc:
            if type(exc) is not module.FormatError:
                failure("build-success-probe-unowned", f"expected FormatError, got {type(exc).__name__}: {exc}")
        else:
            failure("build-success-probe-unowned", "accepted successful unowned build probe")
    finally:
        module.os.listdir = real_listdir
        if os.path.exists(target):
            os.unlink(target)
    if listdir_calls[0] != 1:
        failure("build-success-probe-unowned", f"held build-root listdir calls were {listdir_calls[0]}, expected trace-time rejection after first call")
    if not created[0]:
        failure("build-success-probe-unowned", "unowned build probe fixture was not activated")
    if module.os.listdir is not real_listdir:
        failure("build-success-probe-unowned", "listdir seam was not restored")
    if os.path.exists(target):
        failure("build-success-probe-unowned", "unowned build probe file was not cleaned up")


# Mutation caught: a successful probe of a logically created build output is
# evidence of the output event, not an emitted absent or build-root row.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-created-output-probe-") as root:
    paths = fixture(root)
    before = tree(root)
    target = os.path.join(paths["build"], "generated")
    trace = (
        f'100 openat(AT_FDCWD, "{target}", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3\n'
        "100 close(3) = 0\n"
        f'100 newfstatat(AT_FDCWD, "{target}", 0x7f, 0) = 0\n'
        f'100 openat(AT_FDCWD, "{paths["input"]}", O_RDONLY|O_CLOEXEC) = 4\n'
        '100 read(4, "data", 4) = 4\n'
        "100 close(4) = 0\n100 +++ exited with 0 +++\n"
    ).encode("ascii")
    try:
        actual = discover(paths, trace)
    except BaseException as exc:
        failure("created-output-probe", f"created output probe was not omitted: {type(exc).__name__}: {exc}")
    else:
        expected = ledger([regular_row(paths["input"], "repo", "read", "repo")])
        if actual != expected:
            failure("created-output-probe", f"created output probe emitted non-repo rows: {actual!r}")
        try:
            records = module.parse_ledger(actual)
        except BaseException as exc:
            failure("created-output-probe", f"public ledger parse failed: {type(exc).__name__}: {exc}")
        else:
            if len(records) != 1 or records[0].locator != "repo:/input":
                failure("created-output-probe", f"created output probe records were {records!r}")
    if tree(root) != before:
        failure("created-output-probe", "created output probe fixture was not cleaned up")


# Mutation caught: distinct hardlinked symlink locators in one resolution
# chain must not be mistaken for an inode cycle.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-hardlinked-symlink-") as root:
    paths = fixture(root)
    directory_a = os.path.join(paths["repo"], "a")
    directory_b = os.path.join(directory_a, "b")
    target = os.path.join(paths["repo"], "link")
    link_a = os.path.join(directory_a, "link")
    link_b = os.path.join(directory_b, "link")
    os.mkdir(directory_a)
    os.mkdir(directory_b)
    os.chmod(directory_a, 0o755)
    os.chmod(directory_b, 0o755)
    with open(target, "wb") as handle:
        handle.write(b"target")
    os.chmod(target, 0o644)
    os.symlink("../link", link_a)
    os.link(link_a, link_b, follow_symlinks=False)
    before = tree(root)
    original_a = os.lstat(link_a)
    original_b = os.lstat(link_b)
    if original_a.st_ino != original_b.st_ino:
        failure("hardlinked-symlink-chain", "hardlinked symlink setup did not share an inode")
    real_readlink = os.readlink
    real_fstat = os.fstat
    parent_labels = {
        (os.stat(directory_a, follow_symlinks=False).st_dev, os.stat(directory_a, follow_symlinks=False).st_ino): "repo/a",
        (os.stat(directory_b, follow_symlinks=False).st_dev, os.stat(directory_b, follow_symlinks=False).st_ino): "repo/a/b",
    }
    reads = []
    violations = []

    def readlink_chain(target_name, *, dir_fd=None):
        if not isinstance(dir_fd, int) or os.fsdecode(target_name) != "link":
            violations.append("symlink read was not descriptor-relative to link")
        else:
            parent = real_fstat(dir_fd)
            label = parent_labels.get((parent.st_dev, parent.st_ino))
            if label is None:
                violations.append("symlink read used an unexpected parent")
            else:
                reads.append(label)
        return real_readlink(target_name, dir_fd=dir_fd)

    module.os.readlink = readlink_chain
    actual = None
    try:
        trace = (
            f'100 newfstatat(AT_FDCWD, "{link_b}", 0x7f, 0) = 0\n'
            "100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            actual = discover(paths, trace)
        except BaseException as exc:
            failure("hardlinked-symlink-chain", f"hardlinked symlink chain was not accepted: {type(exc).__name__}: {exc}")
    finally:
        module.os.readlink = real_readlink
    if violations:
        failure("hardlinked-symlink-chain", f"symlink chain seam violations: {violations!r}")
    if reads.count("repo/a") != 2 or reads.count("repo/a/b") != 2 or len(reads) != 4:
        failure("hardlinked-symlink-chain", f"symlink reads were {reads!r}, expected two per locator")
    if actual is not None:
        try:
            records = module.parse_ledger(actual)
        except BaseException as exc:
            failure("hardlinked-symlink-chain", f"public ledger parse failed: {type(exc).__name__}: {exc}")
        else:
            keys = {(record.klass, record.locator) for record in records}
            expected = {
                ("symlink", "repo:/a/link"),
                ("symlink", "repo:/a/b/link"),
                ("repo", "repo:/link"),
            }
            if keys != expected:
                failure("hardlinked-symlink-chain", f"hardlinked symlink ledger keys were {keys!r}")
    if module.os.readlink is not real_readlink:
        failure("hardlinked-symlink-chain", "readlink seam was not restored")
    if tree(root) != before:
        failure("hardlinked-symlink-chain", "hardlinked symlink fixture was not cleaned up")


# Mutation caught: repeated traversal of one symlink locator is not an inode
# cycle; the target may be read again while the symlink row stays singular.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-same-locator-") as root:
    paths = fixture(root)
    link = os.path.join(paths["repo"], "again")
    os.symlink(".", link)
    before = tree(root)
    real_readlink = os.readlink
    reads = []

    def readlink_same_locator(target, *, dir_fd=None):
        if os.fsdecode(target) != "again" or not isinstance(dir_fd, int):
            failure("same-locator-symlink-repetition", f"symlink read was not repo-relative: {target!r}, {dir_fd!r}")
        reads.append((target, dir_fd))
        return real_readlink(target, dir_fd=dir_fd)

    module.os.readlink = readlink_same_locator
    actual = None
    try:
        trace = (
            f'100 openat(AT_FDCWD, "{paths["repo"]}/again/again/input", O_RDONLY|O_CLOEXEC) = 3\n'
            '100 read(3, "data", 4) = 4\n'
            "100 close(3) = 0\n100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            actual = discover(paths, trace)
        except BaseException as exc:
            failure("same-locator-symlink-repetition", f"expected success, got {type(exc).__name__}: {exc}")
    finally:
        module.os.readlink = real_readlink
    if len(reads) != 2:
        failure("same-locator-symlink-repetition", f"same symlink target was read {len(reads)} times, expected 2")
    if actual is not None:
        expected = ledger([
            symlink_row(link, "repo"),
            regular_row(paths["input"], "repo", "read", "repo"),
        ])
        if actual != expected:
            failure("same-locator-symlink-repetition", f"same-locator ledger mismatch: {actual!r}")
        try:
            records = module.parse_ledger(actual)
        except BaseException as exc:
            failure("same-locator-symlink-repetition", f"public ledger parse failed: {type(exc).__name__}: {exc}")
        else:
            if sum(record.klass == "symlink" for record in records) != 1:
                failure("same-locator-symlink-repetition", "same locator emitted more than one symlink row")
    if module.os.readlink is not real_readlink:
        failure("same-locator-symlink-repetition", "same-locator readlink seam was not restored")
    if tree(root) != before:
        failure("same-locator-symlink-repetition", "same-locator fixture changed")


# Mutation caught: the depth boundary permits exactly forty distinct symlink
# links, while the existing forty-one-link case remains a rejection.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-depth-40-") as root:
    paths = fixture(root)
    names = [f"chain{index}" for index in range(40)]
    for index, name in enumerate(names):
        target = names[index + 1] if index + 1 < len(names) else "input"
        os.symlink(target, os.path.join(paths["repo"], name))
    before = tree(root)
    real_readlink = os.readlink
    reads = []

    def readlink_depth_40(target, *, dir_fd=None):
        if os.fsdecode(target) not in names or not isinstance(dir_fd, int):
            failure("symlink-depth-40-success", f"depth read was not repo-relative: {target!r}, {dir_fd!r}")
        reads.append(os.fsdecode(target))
        return real_readlink(target, dir_fd=dir_fd)

    module.os.readlink = readlink_depth_40
    actual = None
    try:
        requested = os.path.join(paths["repo"], names[0])
        trace = (
            f'100 openat(AT_FDCWD, "{requested}", O_RDONLY|O_CLOEXEC) = 3\n'
            '100 read(3, "data", 4) = 4\n'
            "100 close(3) = 0\n100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            actual = discover(paths, trace)
        except BaseException as exc:
            failure("symlink-depth-40-success", f"expected forty-link success, got {type(exc).__name__}: {exc}")
    finally:
        module.os.readlink = real_readlink
    if len(reads) != 80:
        failure("symlink-depth-40-success", f"forty-link target reads were {len(reads)}, expected 80 total link-follow reads")
    if actual is not None:
        try:
            records = module.parse_ledger(actual)
        except BaseException as exc:
            failure("symlink-depth-40-success", f"public ledger parse failed: {type(exc).__name__}: {exc}")
        else:
            symlink_records = [record for record in records if record.klass == "symlink"]
            expected_locators = {f"repo:/{name}" for name in names}
            if {record.locator for record in symlink_records} != expected_locators:
                failure("symlink-depth-40-success", "forty-link success did not emit exactly the chain rows")
            if not any(record.locator == "repo:/input" and record.access == "read" for record in records):
                failure("symlink-depth-40-success", "forty-link success omitted the resolved input read")
    if module.os.readlink is not real_readlink:
        failure("symlink-depth-40-success", "forty-link readlink seam was not restored")
    if tree(root) != before:
        failure("symlink-depth-40-success", "forty-link fixture changed")


# Mutation caught: an ENOENT suffix must remain below its missing floor;
# missing/.. must not be normalized into the existing repo anchor.
def absent_dotdot_case(label, requested_tail, errno, setup, expected_rows=None, expect_error=None):
    with tempfile.TemporaryDirectory(prefix=f"task4-bs2a-final-{label}-") as root:
        paths = fixture(root)
        setup(paths)
        before = tree(root)
        trace = (
            f'100 newfstatat(AT_FDCWD, "{paths["repo"]}/{requested_tail}", 0x7f, 0) = -1 {errno} ({"No such file or directory" if errno == "ENOENT" else "Not a directory"})\n'
            "100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            actual = discover(paths, trace)
        except BaseException as exc:
            if expect_error is None:
                failure(label, f"expected success, got {type(exc).__name__}: {exc}")
            elif type(exc) is not expect_error:
                failure(label, f"expected {expect_error.__name__}, got {type(exc).__name__}: {exc}")
        else:
            if expect_error is not None:
                failure(label, f"accepted invalid suffix, expected {expect_error.__name__}")
            else:
                ordered = sorted(expected_rows, key=lambda row: row[-1].encode("utf-8"))
                expected = b"".join(
                    (
                        "\t".join((
                            "input-v1",
                            str(index),
                            row[0],
                            row[1],
                            errno if row[0] == "absent" else row[2],
                            row[3] if row[3] is not None else "-",
                            row[4] if row[4] is not None else "-",
                            row[5] if row[5] is not None else "-",
                            row[6],
                        )) + "\n"
                    ).encode("utf-8")
                    for index, row in enumerate(ordered)
                )
                if actual != expected:
                    failure(label, f"absent suffix ledger mismatch: {actual!r}")
        if tree(root) != before:
            failure(label, "absent suffix fixture changed")


absent_dotdot_case(
    "absent-enoent-dotdot-floor",
    "missing/a/../b",
    "ENOENT",
    lambda paths: None,
    expected_rows=[
        ("directory", "probe", "present", "0755", "29", digest(b"D\x00\tdirectoryF\x00\x05inputD\x00\x06vendor"), "repo:/"),
        ("absent", "probe", None, None, None, None, "repo:/missing/b"),
    ],
)
absent_dotdot_case(
    "absent-enoent-dotdot-above-floor",
    "missing/..",
    "ENOENT",
    lambda paths: None,
    expect_error=module.FormatError,
)


def setup_blocker(paths):
    blocker = os.path.join(paths["repo"], "blocker")
    with open(blocker, "wb") as handle:
        handle.write(b"blocker")
    os.chmod(blocker, 0o644)


absent_dotdot_case(
    "absent-enotdir-dotdot-floor",
    "blocker/a/../b",
    "ENOTDIR",
    setup_blocker,
    expected_rows=[
        ("repo", "probe", "present", "0644", "7", digest(b"blocker"), "repo:/blocker"),
        ("absent", "probe", None, None, None, None, "repo:/blocker/b"),
    ],
)
absent_dotdot_case(
    "absent-enotdir-dotdot-above-floor",
    "blocker/child/..",
    "ENOTDIR",
    setup_blocker,
    expect_error=module.FormatError,
)


# Mutation caught: mutating a resolved regular object's full identity after
# its first held-fd observation must be rejected, not baseline-captured later.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-event-time-baseline-") as root:
    paths = fixture(root)
    target = paths["dynamic"]
    original = os.stat(target, follow_symlinks=False)
    target_identity = (original.st_dev, original.st_ino)
    real_open = os.open
    real_fstat = os.fstat
    target_fd = [None]
    resolved = [False]
    mutated = [False]

    def open_event(path, flags, mode=0o777, *, dir_fd=None):
        fd = real_open(path, flags, mode, dir_fd=dir_fd) if dir_fd is not None else real_open(path, flags, mode)
        value = real_fstat(fd)
        if (value.st_dev, value.st_ino) == target_identity:
            target_fd[0] = fd
        return fd

    def fstat_event(fd):
        value = real_fstat(fd)
        if fd == target_fd[0] and not resolved[0]:
            resolved[0] = True
            os.chmod(target, 0o600)
            mutated[0] = True
        return value

    module.os.open = open_event
    module.os.fstat = fstat_event
    try:
        trace = (
            f'100 openat(AT_FDCWD, "{target}", O_RDONLY|O_CLOEXEC) = 3\n'
            '100 read(3, "data", 4) = 4\n'
            "100 close(3) = 0\n100 +++ exited with 0 +++\n"
        ).encode("ascii")
        try:
            discover(paths, trace)
        except BaseException as exc:
            if type(exc) is not module.MutationError:
                failure("event-time-evidence-baseline", f"expected MutationError, got {type(exc).__name__}: {exc}")
        else:
            failure("event-time-evidence-baseline", "accepted post-resolution identity mutation")
    finally:
        module.os.open = real_open
        module.os.fstat = real_fstat
        os.chmod(target, original.st_mode & 0o7777)
        os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns), follow_symlinks=False)
    if not resolved[0] or not mutated[0]:
        failure("event-time-evidence-baseline", "event-time identity seam was not activated")
    if module.os.open is not real_open or module.os.fstat is not real_fstat:
        failure("event-time-evidence-baseline", "event-time seams were not restored")
    restored = os.stat(target, follow_symlinks=False)
    if (
        restored.st_dev,
        restored.st_ino,
        restored.st_mode & 0o7777,
        restored.st_size,
        restored.st_mtime_ns,
    ) != (
        original.st_dev,
        original.st_ino,
        original.st_mode & 0o7777,
        original.st_size,
        original.st_mtime_ns,
    ):
        failure("event-time-evidence-baseline", "event-time identity metadata was not restored")


# Mutation caught: public ledger validation must reject class-specific size
# bounds even when every other field is a literal valid record.
def ledger_size_case(label, klass, size, mode, locator_value, digest_value):
    record = module.InputRecord(0, klass, "probe", "present", mode, size, digest_value, locator_value)
    try:
        module.encode_ledger([record])
    except module.FormatError:
        pass
    else:
        failure(label, "encoder accepted invalid class-specific size")
    literal = (
        f"input-v1\\t0\\t{klass}\\tprobe\\tpresent\\t{mode:04o}\\t{size}\\t{digest_value}\\t{locator_value}\\n"
    ).encode("ascii")
    try:
        module.parse_ledger(literal)
    except module.FormatError:
        pass
    else:
        failure(label, "parser accepted invalid class-specific size")


ledger_size_case("ledger-symlink-size-zero", "symlink", 0, 0o777, "repo:/size-link", digest(b"target"))
ledger_size_case("ledger-symlink-size-4097", "symlink", 4097, 0o777, "repo:/size-link-4097", digest(b"target"))
ledger_size_case("ledger-directory-size-4194305", "directory", 4194305, 0o755, "repo:/size-directory", digest(b""))


# Mutation caught: a final root full-identity-only change must invalidate an
# emitted external:/ ENOENT-parent directory evidence row.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-root-identity-") as root:
    paths = fixture(root)
    before = tree(root)
    real_fstat = os.fstat
    root_stat = os.stat("/", follow_symlinks=False)
    root_identity = (root_stat.st_dev, root_stat.st_ino)
    fake_root = os.stat_result(
        (
            root_stat.st_mode,
            root_stat.st_ino,
            root_stat.st_dev,
            root_stat.st_nlink,
            root_stat.st_uid,
            root_stat.st_gid,
            root_stat.st_size,
            root_stat.st_atime,
            root_stat.st_mtime + 1.0,
            root_stat.st_ctime,
        )
    )
    root_fstat_calls = [0]
    mutated = [False]
    mocked = [0]

    def fstat_root_identity(target):
        value = real_fstat(target)
        if (value.st_dev, value.st_ino) == root_identity:
            root_fstat_calls[0] += 1
            if root_fstat_calls[0] == 6:
                mutated[0] = True
                mocked[0] += 1
                return fake_root
        return value

    module.os.fstat = fstat_root_identity
    actual = None
    try:
        trace = b'100 newfstatat(AT_FDCWD, "/missing", 0x7f, 0) = -1 ENOENT (No such file or directory)\n100 +++ exited with 0 +++\n'
        try:
            actual = discover(paths, trace)
        except BaseException as exc:
            if type(exc) is not module.MutationError:
                failure("root-enoent-parent-full-identity", f"expected MutationError, got {type(exc).__name__}: {exc}")
        else:
            failure("root-enoent-parent-full-identity", "accepted root evidence full-identity change")
            try:
                records = module.parse_ledger(actual)
            except BaseException as exc:
                failure("root-enoent-parent-full-identity", f"public ledger parse failed: {type(exc).__name__}: {exc}")
            else:
                keys = {(record.klass, record.locator) for record in records}
                expected = {("directory", "external:/"), ("absent", "external:/missing")}
                if keys != expected:
                    failure("root-enoent-parent-full-identity", f"root ENOENT ledger keys were {keys!r}")
    finally:
        module.os.fstat = real_fstat
    if root_fstat_calls[0] != 6 or not mutated[0] or mocked[0] != 1:
        failure("root-enoent-parent-full-identity", f"required root fstat call6 was not activated: calls={root_fstat_calls[0]}, mock_calls={mocked[0]}")
    if module.os.fstat is not real_fstat:
        failure("root-enoent-parent-full-identity", "root identity seams were not restored")
    if tree(root) != before:
        failure("root-enoent-parent-full-identity", "root identity fixture was not cleaned up")


# Mutation caught: a symlink must resolve before a later dotdot component;
# lexically collapsing hop/.. would consume the repo decoy instead.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-symlink-dotdot-") as root:
    paths = fixture(root)
    outside = os.path.join(root, "outside")
    outside_dir = os.path.join(outside, "dir")
    os.mkdir(outside)
    os.mkdir(outside_dir)
    secret = os.path.join(outside, "secret")
    with open(secret, "wb") as handle:
        handle.write(b"actual")
    os.chmod(secret, 0o644)
    decoy = os.path.join(paths["repo"], "secret")
    with open(decoy, "wb") as handle:
        handle.write(b"decoy")
    os.chmod(decoy, 0o644)
    hop = os.path.join(paths["repo"], "hop")
    os.symlink("../outside/dir", hop)
    before = tree(root)
    trace = (
        f'100 openat(AT_FDCWD, "{paths["repo"]}/hop/../secret", O_RDONLY|O_CLOEXEC) = 3\n'
        '100 read(3, "actual", 6) = 6\n'
        "100 close(3) = 0\n100 +++ exited with 0 +++\n"
    ).encode("ascii")
    try:
        actual = discover(paths, trace)
    except BaseException as exc:
        failure("symlink-dotdot-decoy", f"expected success, got {type(exc).__name__}: {exc}")
    else:
        expected = ledger([
            symlink_row(hop, "repo"),
            regular_row(secret, "tool", "read", "external"),
        ])
        if actual != expected:
            failure("symlink-dotdot-decoy", f"symlink-before-dotdot ledger mismatch: {actual!r}")
        try:
            records = module.parse_ledger(actual)
        except BaseException as exc:
            failure("symlink-dotdot-decoy", f"public ledger parse failed: {type(exc).__name__}: {exc}")
        else:
            if "repo:/secret" in {record.locator for record in records}:
                failure("symlink-dotdot-decoy", "resolved repo decoy instead of external secret")
    if tree(root) != before:
        failure("symlink-dotdot-decoy", "symlink-before-dotdot fixture changed")


# Mutation caught: a directory symlink held as a dirfd must anchor both
# relative openat and post-fchdir AT_FDCWD paths at its resolved target.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-dirfd-fchdir-") as root:
    paths = fixture(root)
    left = os.path.join(paths["repo"], "left")
    right = os.path.join(paths["repo"], "right")
    right_inner = os.path.join(right, "inner")
    os.mkdir(left)
    os.mkdir(right)
    os.mkdir(right_inner)
    for directory in (left, right, right_inner):
        os.chmod(directory, 0o755)
    left_decoy = os.path.join(left, "sibling")
    right_sibling = os.path.join(right, "sibling")
    for path, data in ((left_decoy, b"left"), (right_sibling, b"right")):
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, 0o644)
    directory_link = os.path.join(left, "dir")
    os.symlink("../right/inner", directory_link)
    before = tree(root)
    trace = (
        f'100 openat(AT_FDCWD, "{directory_link}", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 3\n'
        '100 openat(3, "../sibling", O_RDONLY|O_CLOEXEC) = 4\n'
        '100 read(4, "right", 5) = 5\n'
        "100 close(4) = 0\n"
        '100 fchdir(3) = 0\n'
        '100 openat(AT_FDCWD, "../sibling", O_RDONLY|O_CLOEXEC) = 5\n'
        '100 read(5, "right", 5) = 5\n'
        "100 close(5) = 0\n100 +++ exited with 0 +++\n"
    ).encode("ascii")
    try:
        actual = discover(paths, trace)
    except BaseException as exc:
        failure("dirfd-fchdir-held-target", f"expected success, got {type(exc).__name__}: {exc}")
    else:
        expected = ledger([
            ("directory", "probe", "present", "0755", "0", digest(b""), "repo:/right/inner"),
            ("repo", "read", "present", "0644", "5", digest(b"right"), "repo:/right/sibling"),
            (*symlink_row(directory_link, "repo")[:-1], "repo:/left/dir"),
        ])
        if actual != expected:
            failure("dirfd-fchdir-held-target", f"dirfd/fchdir ledger mismatch: {actual!r}")
        try:
            records = module.parse_ledger(actual)
        except BaseException as exc:
            failure("dirfd-fchdir-held-target", f"public ledger parse failed: {type(exc).__name__}: {exc}")
        else:
            by_locator = {record.locator: record for record in records}
            if by_locator.get("repo:/right/sibling") is None or by_locator["repo:/right/sibling"].sha256 != digest(b"right"):
                failure("dirfd-fchdir-held-target", "resolved right sibling was not combined")
            if "repo:/left/sibling" in by_locator:
                failure("dirfd-fchdir-held-target", "resolved left decoy through stale dirfd path")
    if tree(root) != before:
        failure("dirfd-fchdir-held-target", "dirfd/fchdir fixture changed")


# Mutation caught: an open/close-only descriptor is a probe, while a positive
# read is read access; open-time readability must not invent a read event.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-open-only-probe-") as root:
    paths = fixture(root)
    probe = os.path.join(paths["repo"], "probe")
    readable = os.path.join(paths["repo"], "read")
    for path, data in ((probe, b"probe"), (readable, b"read")):
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, 0o644)
    before = tree(root)
    trace = (
        f'100 openat(AT_FDCWD, "{probe}", O_RDONLY|O_CLOEXEC) = 3\n'
        "100 close(3) = 0\n"
        f'100 openat(AT_FDCWD, "{readable}", O_RDONLY|O_CLOEXEC) = 4\n'
        '100 read(4, "read", 4) = 4\n'
        "100 close(4) = 0\n100 +++ exited with 0 +++\n"
    ).encode("ascii")
    try:
        actual = discover(paths, trace)
    except BaseException as exc:
        failure("open-only-probe-read-control", f"expected success, got {type(exc).__name__}: {exc}")
    else:
        expected = ledger([
            regular_row(probe, "repo", "probe", "repo"),
            regular_row(readable, "repo", "read", "repo"),
        ])
        if actual != expected:
            failure("open-only-probe-read-control", f"probe/read access ledger mismatch: {actual!r}")
        try:
            records = module.parse_ledger(actual)
        except BaseException as exc:
            failure("open-only-probe-read-control", f"public ledger parse failed: {type(exc).__name__}: {exc}")
        else:
            access = {record.locator: record.access for record in records}
            if access.get("repo:/probe") != "probe" or access.get("repo:/read") != "read":
                failure("open-only-probe-read-control", f"probe/read access was {access!r}")
    if tree(root) != before:
        failure("open-only-probe-read-control", "probe/read fixture changed")


# A relation that changes between the initial lstat and the one authorized
# open must be rejected; a stable replacement must not become a retry target.
with tempfile.TemporaryDirectory(prefix="task4-bs2a-final-relation-open-") as root:
    paths = fixture(root)
    original = paths["dynamic"]
    held = original + ".original"
    replacement = original + ".replacement"
    with open(replacement, "wb") as handle:
        handle.write(b"replacement")
    os.chmod(replacement, 0o644)
    armed = [True]

    def replace_before_open(event, args):
        if event != "open" or not armed[0] or args[0] not in ("dynamic", b"dynamic"):
            return
        armed[0] = False
        os.rename(original, held)
        os.rename(replacement, original)

    sys.addaudithook(replace_before_open)
    try:
        trace = (
            f'100 openat(AT_FDCWD, "{paths["dynamic"]}", O_RDONLY|O_CLOEXEC) = 3\n'
            '100 read(3, "data", 4) = 4\n100 close(3) = 0\n100 +++ exited with 0 +++\n'
        ).encode("ascii")
        discover(paths, trace)
    except BaseException as exc:
        if type(exc) is not module.MutationError:
            failure("relation-open-replacement", f"expected MutationError, got {type(exc).__name__}: {exc}")
    else:
        failure("relation-open-replacement", "accepted stable replacement after open-time mismatch")
    finally:
        if os.path.exists(held):
            if os.path.exists(original):
                os.rename(original, replacement)
            os.rename(held, original)
    if armed[0]:
        failure("relation-open-replacement", "open-time replacement seam was not reached")


if deferred:
    # No racy post-S2 oracle is installed: a public discovery call has no
    # deterministic pause between its second hash and final edge check.
    pass

if any(failures[label] for label in labels if label not in deferred):
    for label in labels:
        if label in deferred:
            print(f"{label}: FORMAL_REVIEW_ONLY ({deferred[label]})")
        else:
            print(f"{label}: {'PASS' if not failures[label] else 'FAIL'}")
    for label in labels:
        for reason in failures[label]:
            print(f"{label}: {reason}")
    raise SystemExit(1)
print("bs2a-final-gap-red-ok")
"##;
    let output = Command::new("/usr/bin/python3")
        .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run BS2a final review-gap regression driver");
    assert!(
        output.status.success()
            && output.stderr.is_empty()
            && output.stdout == b"bs2a-final-gap-red-ok\n",
        "BS2a final review-gap RED diagnostics:\n{}\nstderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn semantic_trace_v1_private_state_topology_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let test = repo.join("tests/python/test_task4_semantic_topology.py");
    let output = Command::new("/usr/bin/python3")
        .args([
            "-I",
            test.to_str().expect("semantic topology test path is UTF-8"),
            "SemanticTraceTopologyTests.test_initial_copied_and_shared_state",
            "SemanticTraceTopologyTests.test_shared_mutations_follow_ownership_topology",
            "SemanticTraceTopologyTests.test_fork_and_dup2_semantics",
            "SemanticTraceTopologyTests.test_invalid_operations_are_atomic",
        ])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run task4 semantic topology tests through /usr/bin/python3");
    assert!(
        output.status.success(),
        "BS2b semantic state topology contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn semantic_trace_v1_private_exec_event_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let test = repo.join("tests/python/test_task4_semantic_exec.py");
    let output = Command::new("/usr/bin/python3")
        .args([
            "-I",
            test.to_str().expect("semantic exec test path is UTF-8"),
            "SemanticTraceExecTests.test_exec_replaces_private_state_and_preserves_identity",
            "SemanticTraceExecTests.test_post_exec_fd_and_vm_mutations_follow_new_ownership",
            "SemanticTraceExecTests.test_post_exec_fs_mutations_follow_existing_shared_ownership",
            "SemanticTraceExecTests.test_post_exec_closes_do_not_cross_fd_tables",
            "SemanticTraceExecTests.test_mapping_boundaries_are_accepted",
            "SemanticTraceExecTests.test_task_and_thread_group_rejections_are_atomic",
            "SemanticTraceExecTests.test_fd_table_rejections_are_atomic",
            "SemanticTraceExecTests.test_mapping_rejections_are_atomic",
        ])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run task4 semantic exec tests through /usr/bin/python3");
    assert!(
        output.status.success(),
        "BS2b semantic exec-event contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn semantic_trace_v1_private_syscall_lifecycle_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let test = repo.join("tests/python/test_task4_semantic_syscall.py");
    let output = Command::new("/usr/bin/python3")
        .args([
            "-I",
            test.to_str()
                .expect("semantic syscall lifecycle test path is UTF-8"),
            "SemanticTraceSyscallTests.test_invalid_begin_tid",
            "SemanticTraceSyscallTests.test_invalid_finish_tid",
            "SemanticTraceSyscallTests.test_operation_shape_name_category_and_arguments_validation",
            "SemanticTraceSyscallTests.test_u64_argument_boundaries",
            "SemanticTraceSyscallTests.test_duplicate_begin_is_atomic",
            "SemanticTraceSyscallTests.test_category_restart_preserves_pending_and_topology",
            "SemanticTraceSyscallTests.test_pure_completion_clears_only_matching_pending",
            "SemanticTraceSyscallTests.test_product_completion_is_refused",
            "SemanticTraceSyscallTests.test_invalid_orphan_and_duplicate_finish",
        ])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run task4 semantic syscall lifecycle tests through /usr/bin/python3");
    assert!(
        output.status.success(),
        "BS2b semantic syscall lifecycle contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn semantic_trace_v1_private_open_description_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let test = repo.join("tests/python/test_task4_semantic_open_description.py");
    let selectors = [
        "SemanticTraceOpenDescriptionTests.test_open_alias_exec_close_identity",
        "SemanticTraceOpenDescriptionTests.test_local_pair_topology_and_io",
        "SemanticTraceOpenDescriptionTests.test_malformed_pair_descriptions",
        "SemanticTraceOpenDescriptionTests.test_pair_io_malformed_table",
        "SemanticTraceOpenDescriptionTests.test_offset_boundaries",
        "SemanticTraceOpenDescriptionTests.test_directory_io_rejection",
        "SemanticTraceOpenDescriptionTests.test_open_argument_validation",
        "SemanticTraceOpenDescriptionTests.test_pair_argument_validation",
        "SemanticTraceOpenDescriptionTests.test_malformed_tables_and_unrelated_entries",
        "SemanticTraceOpenDescriptionTests.test_io_tid_fd_validation",
        "SemanticTraceOpenDescriptionTests.test_io_direction_validation",
        "SemanticTraceOpenDescriptionTests.test_io_count_validation",
        "SemanticTraceOpenDescriptionTests.test_io_position_validation",
        "SemanticTraceOpenDescriptionTests.test_malformed_regular_description",
        "SemanticTraceOpenDescriptionTests.test_regular_access_mismatch",
        "SemanticTraceOpenDescriptionTests.test_legacy_opaque_io_rejection",
        "SemanticTraceOpenDescriptionTests.test_dup2_same_fd_and_close",
        "SemanticTraceOpenDescriptionTests.test_dup2_fd_validation",
        "SemanticTraceOpenDescriptionTests.test_dup2_tid_validation",
        "SemanticTraceOpenDescriptionTests.test_close_tid_fd_validation",
        "SemanticTraceOpenDescriptionTests.test_legacy_opaque_topology",
    ];
    let output = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg(&test)
        .args(selectors)
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run task4 semantic open-description tests through /usr/bin/python3");
    assert!(
        output.status.success(),
        "BS2b semantic open-description contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Ran 21 tests"),
        "BS2b semantic open-description runner did not execute exactly 21 tests: {stderr}"
    );
    assert_eq!(
        output.stdout, b"open-description-families=21 rejections=207\n",
        "BS2b semantic open-description inventory did not complete"
    );
}

#[test]
fn semantic_trace_v1_private_dup2_outcome_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let test = repo.join("tests/python/test_task4_semantic_dup2.py");
    let output = Command::new("/usr/bin/python3")
        .args([
            "-I",
            test.to_str()
                .expect("semantic dup2 outcome test path is UTF-8"),
            "SemanticTraceDup2Tests.test_success_failure_and_restart_outcomes",
            "SemanticTraceDup2Tests.test_operation_and_argument_validation",
            "SemanticTraceDup2Tests.test_result_errno_and_source_validation",
            "SemanticTraceDup2Tests.test_malformed_tables_and_invalid_tids",
            "SemanticTraceDup2Tests.test_orphan_and_duplicate_completion",
            "SemanticTraceDup2Tests.test_legacy_opaque_descriptions",
        ])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run task4 semantic dup2 outcome tests through /usr/bin/python3");
    assert!(
        output.status.success(),
        "BS2b semantic dup2 outcome contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn semantic_trace_v1_private_dup_outcome_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let test = repo.join("tests/python/test_task4_semantic_dup.py");
    let selectors = [
        "SemanticTraceDupTests.test_success_failure_and_restart_outcomes",
        "SemanticTraceDupTests.test_result_and_pending_validation",
        "SemanticTraceDupTests.test_argument_boundaries_and_validation",
        "SemanticTraceDupTests.test_malformed_tables_and_legacy_topology",
        "SemanticTraceDupTests.test_invalid_tids_and_completion_lifecycle",
        "SemanticTraceDupTests.test_private_slice_exports_no_runner",
    ];
    for selector in selectors {
        let output = Command::new("/usr/bin/python3")
            .args([
                "-I",
                test.to_str().expect("test path is UTF-8"),
                "-v",
                selector,
            ])
            .current_dir(repo)
            .env_clear()
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("run BS2b semantic dup-outcome contract");
        assert!(
            output.status.success(),
            "BS2b semantic dup-outcome selector {selector} failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn semantic_trace_v1_private_fd_table_mutator_admission_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let test = repo.join("tests/python/test_task4_semantic_fd_table_mutator.py");
    let selectors = [
        "SemanticTraceFdTableMutatorTests.test_first_valid_admission",
        "SemanticTraceFdTableMutatorTests.test_retry_contention_and_copied_table",
        "SemanticTraceFdTableMutatorTests.test_invalid_admission_tids",
        "SemanticTraceFdTableMutatorTests.test_malformed_owner_collection_and_entry",
        "SemanticTraceFdTableMutatorTests.test_malformed_owner_tids",
        "SemanticTraceFdTableMutatorTests.test_malformed_owner_table_types",
        "SemanticTraceFdTableMutatorTests.test_malformed_unrelated_owner_tables",
        "SemanticTraceFdTableMutatorTests.test_duplicate_and_stale_owner_identities",
        "SemanticTraceFdTableMutatorTests.test_malformed_stored_dup_operations",
        "SemanticTraceFdTableMutatorTests.test_malformed_stored_dup2_operations",
        "SemanticTraceFdTableMutatorTests.test_malformed_unowned_pending_shape",
        "SemanticTraceFdTableMutatorTests.test_pending_endpoint_validation",
        "SemanticTraceFdTableMutatorTests.test_pending_raw_argument_validation",
        "SemanticTraceFdTableMutatorTests.test_canonical_endpoint_boundaries",
        "SemanticTraceFdTableMutatorTests.test_terminal_requires_owner",
        "SemanticTraceFdTableMutatorTests.test_malformed_terminal_and_stale_topology",
        "SemanticTraceFdTableMutatorTests.test_terminal_release_and_alias_admission",
        "SemanticTraceFdTableMutatorTests.test_restart_then_terminal_release",
        "SemanticTraceFdTableMutatorTests.test_distinct_owner_completion_isolation",
        "SemanticTraceFdTableMutatorTests.test_later_index_dup2_cleanup",
        "SemanticTraceFdTableMutatorTests.test_later_index_dup_cleanup",
        "SemanticTraceFdTableMutatorTests.test_private_slice_exports_no_runner",
    ];
    let output = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg(&test)
        .args(selectors)
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run task4 FD-table-mutator tests through /usr/bin/python3");
    assert!(
        output.status.success(),
        "BS2b FD-table-mutator contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Ran 22 tests"),
        "FD-table-mutator runner did not execute exactly 22 tests: {stderr}"
    );
    assert_eq!(
        output.stdout, b"fd-mutator-families=22 rejections=265\n",
        "FD-table-mutator inventory did not complete"
    );
}

#[test]
fn semantic_trace_v1_private_close_outcome_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let test = repo.join("tests/python/test_task4_semantic_close.py");
    let output = Command::new("/usr/bin/python3")
        .args([
            "-I",
            test.to_str()
                .expect("semantic close outcome test path is UTF-8"),
            "SemanticTraceCloseTests.test_admission_contracts",
            "SemanticTraceCloseTests.test_stored_malformed_close_blocks_existing_handlers",
            "SemanticTraceCloseTests.test_terminal_outcomes_and_invalid_pairs",
            "SemanticTraceCloseTests.test_close_effects_preserve_aliases_mappings_and_restart",
            "SemanticTraceCloseTests.test_unrelated_owner_validation",
            "SemanticTraceCloseTests.test_later_owner_index_cleanup",
            "SemanticTraceCloseTests.test_private_slice_exports_no_runner",
        ])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run task4 semantic close outcome tests through /usr/bin/python3");
    assert!(
        output.status.success(),
        "BS2b semantic close outcome contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn bs2b_s9_fcntl_experiment_normalization_privacy_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-fcntl-experiment.py");
    assert!(
        script.is_file(),
        "RED1 missing scripts/task4-fcntl-experiment.py"
    );

    fn record(seq: u64, kind: u16) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        bytes[..8].copy_from_slice(b"P11S9R1\0");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&kind.to_le_bytes());
        bytes[12..16].copy_from_slice(&0u32.to_le_bytes());
        bytes[16..24].copy_from_slice(&seq.to_le_bytes());
        bytes
    }

    fn put_u16(bytes: &mut [u8; 128], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8; 128], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8; 128], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_raw_u16(bytes: &mut [u8], record_index: usize, offset: usize, value: u16) {
        let start = record_index * 128 + offset;
        bytes[start..start + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_raw_u32(bytes: &mut [u8], record_index: usize, offset: usize, value: u32) {
        let start = record_index * 128 + offset;
        bytes[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_raw_u64(bytes: &mut [u8], record_index: usize, offset: usize, value: u64) {
        let start = record_index * 128 + offset;
        bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn hex(data: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(data.len() * 2);
        for byte in data {
            result.push(char::from(DIGITS[(byte >> 4) as usize]));
            result.push(char::from(DIGITS[(byte & 0x0f) as usize]));
        }
        result
    }

    let mut records = Vec::<[u8; 128]>::new();
    let mut bytes = record(0, 1);
    put_u32(&mut bytes, 24, 128);
    put_u32(&mut bytes, 28, 0x0102_0304);
    records.push(bytes);
    let mut bytes = record(1, 0x10);
    put_u64(&mut bytes, 24, 1);
    records.push(bytes);
    let mut bytes = record(2, 0x16);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 0);
    put_u64(&mut bytes, 40, 1);
    put_u16(&mut bytes, 48, 1);
    records.push(bytes);

    let mut bytes = record(3, 0x11);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 1);
    records.push(bytes);
    let mut bytes = record(4, 0x12);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 1);
    records.push(bytes);
    let mut bytes = record(5, 0x14);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u64(&mut bytes, 40, 2);
    put_u64(&mut bytes, 48, 2);
    put_u16(&mut bytes, 56, 1);
    records.push(bytes);
    let mut bytes = record(6, 0x13);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 1);
    put_u16(&mut bytes, 42, 0);
    records.push(bytes);
    let mut bytes = record(7, 0x16);
    put_u64(&mut bytes, 24, 2);
    put_u64(&mut bytes, 32, 0);
    put_u64(&mut bytes, 40, 2);
    put_u16(&mut bytes, 48, 1);
    records.push(bytes);

    let mut bytes = record(8, 0x11);
    put_u64(&mut bytes, 24, 2);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 3);
    records.push(bytes);
    let mut bytes = record(9, 0x12);
    put_u64(&mut bytes, 24, 2);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 3);
    records.push(bytes);
    let mut bytes = record(10, 0x13);
    put_u64(&mut bytes, 24, 2);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 1);
    put_u16(&mut bytes, 42, 0);
    records.push(bytes);
    let mut bytes = record(11, 0x14);
    put_u64(&mut bytes, 24, 2);
    put_u64(&mut bytes, 32, 1);
    put_u64(&mut bytes, 40, 3);
    put_u64(&mut bytes, 48, 1);
    put_u16(&mut bytes, 56, 3);
    records.push(bytes);

    let mut bytes = record(12, 0x11);
    put_u64(&mut bytes, 24, 3);
    put_u64(&mut bytes, 32, 2);
    put_u16(&mut bytes, 40, 2);
    records.push(bytes);
    let mut bytes = record(13, 0x12);
    put_u64(&mut bytes, 24, 3);
    put_u64(&mut bytes, 32, 2);
    put_u16(&mut bytes, 40, 2);
    records.push(bytes);
    let mut bytes = record(14, 0x14);
    put_u64(&mut bytes, 24, 3);
    put_u64(&mut bytes, 32, 2);
    put_u64(&mut bytes, 40, 4);
    put_u64(&mut bytes, 48, 3);
    put_u16(&mut bytes, 56, 2);
    records.push(bytes);
    let mut bytes = record(15, 0x15);
    put_u64(&mut bytes, 24, 3);
    put_u64(&mut bytes, 32, 2);
    put_u64(&mut bytes, 40, 4);
    records.push(bytes);
    let mut bytes = record(16, 0x13);
    put_u64(&mut bytes, 24, 3);
    put_u64(&mut bytes, 32, 2);
    put_u16(&mut bytes, 40, 1);
    put_u16(&mut bytes, 42, 0);
    records.push(bytes);

    let mut bytes = record(17, 0x17);
    put_u64(&mut bytes, 24, 1);
    put_u32(&mut bytes, 32, 0);
    records.push(bytes);
    let mut bytes = record(18, 0x16);
    put_u64(&mut bytes, 24, 3);
    put_u64(&mut bytes, 32, 1);
    put_u64(&mut bytes, 40, 1);
    put_u16(&mut bytes, 48, 2);
    records.push(bytes);
    let mut bytes = record(19, 0x16);
    put_u64(&mut bytes, 24, 4);
    put_u64(&mut bytes, 32, 0);
    put_u64(&mut bytes, 40, 3);
    put_u16(&mut bytes, 48, 1);
    records.push(bytes);

    let mut bytes = record(20, 0x11);
    put_u64(&mut bytes, 24, 4);
    put_u64(&mut bytes, 32, 2);
    put_u16(&mut bytes, 40, 4);
    records.push(bytes);
    let mut bytes = record(21, 0x1a);
    put_u64(&mut bytes, 24, 2);
    put_u64(&mut bytes, 32, 435);
    records.push(bytes);
    let mut bytes = record(22, 0x11);
    put_u64(&mut bytes, 24, 5);
    put_u64(&mut bytes, 32, 4);
    put_u16(&mut bytes, 40, 1);
    records.push(bytes);
    let mut bytes = record(23, 0x13);
    put_u64(&mut bytes, 24, 5);
    put_u64(&mut bytes, 32, 4);
    put_u16(&mut bytes, 40, 0);
    put_u16(&mut bytes, 42, 1);
    records.push(bytes);
    let mut bytes = record(24, 0x19);
    put_u64(&mut bytes, 24, 2);
    put_u32(&mut bytes, 32, 15);
    records.push(bytes);

    let fcntl_args = |command: u64, argument: u64| {
        [
            5,
            command,
            argument,
            0x1111_2222_3333_4444,
            0x5555_6666_7777_8888,
            u64::MAX,
        ]
    };
    for (seq, invocation, generation, command, argument) in [
        (25, 1, 2, 0, 0),
        (27, 2, 3, 1, 0),
        (29, 3, 4, 2, 1),
        (31, 4, 4, 3, 0x200),
    ] {
        let mut bytes = record(seq, 0x20);
        put_u64(&mut bytes, 24, invocation);
        put_u64(&mut bytes, 32, generation);
        for (index, argument) in fcntl_args(command, argument).into_iter().enumerate() {
            put_u64(&mut bytes, 40 + index * 8, argument);
        }
        records.push(bytes);
        let mut bytes = record(seq + 1, 0x21);
        put_u64(&mut bytes, 24, invocation);
        put_u64(&mut bytes, 32, generation);
        put_u64(&mut bytes, 40, if invocation == 2 { 1 } else { 0 });
        records.push(bytes);
    }

    let mut bytes = record(33, 0x17);
    put_u64(&mut bytes, 24, 2);
    put_u32(&mut bytes, 32, 7 << 8);
    records.push(bytes);
    let mut bytes = record(34, 0x18);
    put_u64(&mut bytes, 24, 2);
    put_u32(&mut bytes, 32, 7 << 8);
    records.push(bytes);
    let mut bytes = record(35, 0x17);
    put_u64(&mut bytes, 24, 3);
    put_u32(&mut bytes, 32, 0x80 | 9);
    records.push(bytes);
    let mut bytes = record(36, 0x18);
    put_u64(&mut bytes, 24, 3);
    put_u32(&mut bytes, 32, 0x80 | 9);
    records.push(bytes);
    let mut bytes = record(37, 0x17);
    put_u64(&mut bytes, 24, 4);
    put_u32(&mut bytes, 32, 0);
    records.push(bytes);
    let mut bytes = record(38, 0x18);
    put_u64(&mut bytes, 24, 4);
    put_u32(&mut bytes, 32, 0);
    records.push(bytes);

    assert_eq!(records.len(), 39);
    let mut raw_golden = Vec::with_capacity(records.len() * 128);
    for bytes in &records {
        raw_golden.extend_from_slice(bytes);
    }

    let clone_exitless_raw = |syscall_kind: u16,
                              event_kind: u16,
                              child_group: u64,
                              child_status: u32,
                              active_fcntl: bool| {
        let mut raw = Vec::with_capacity(if active_fcntl { 11 } else { 10 } * 128);
        let mut push = |mut bytes: [u8; 128]| {
            put_u64(&mut bytes, 16, (raw.len() / 128) as u64);
            raw.extend_from_slice(&bytes);
        };

        let mut bytes = record(0, 1);
        put_u32(&mut bytes, 24, 128);
        put_u32(&mut bytes, 28, 0x0102_0304);
        push(bytes);
        let mut bytes = record(1, 0x10);
        put_u64(&mut bytes, 24, 1);
        push(bytes);
        let mut bytes = record(2, 0x16);
        put_u64(&mut bytes, 24, 1);
        put_u64(&mut bytes, 40, 1);
        put_u16(&mut bytes, 48, 1);
        push(bytes);
        let mut bytes = record(3, 0x11);
        put_u64(&mut bytes, 24, 1);
        put_u64(&mut bytes, 32, 1);
        put_u16(&mut bytes, 40, syscall_kind);
        push(bytes);
        let mut bytes = record(4, 0x12);
        put_u64(&mut bytes, 24, 1);
        put_u64(&mut bytes, 32, 1);
        put_u16(&mut bytes, 40, event_kind);
        push(bytes);
        let mut bytes = record(5, 0x14);
        put_u64(&mut bytes, 24, 1);
        put_u64(&mut bytes, 32, 1);
        put_u64(&mut bytes, 40, 2);
        put_u64(&mut bytes, 48, child_group);
        put_u16(&mut bytes, 56, event_kind);
        push(bytes);
        if event_kind == 2 {
            let mut bytes = record(6, 0x15);
            put_u64(&mut bytes, 24, 1);
            put_u64(&mut bytes, 32, 1);
            put_u64(&mut bytes, 40, 2);
            push(bytes);
        }
        let mut bytes = record(6, 0x13);
        put_u64(&mut bytes, 24, 1);
        put_u64(&mut bytes, 32, 1);
        put_u16(&mut bytes, 40, 1);
        push(bytes);
        let mut bytes = record(7, 0x17);
        put_u64(&mut bytes, 24, 1);
        put_u32(&mut bytes, 32, 0);
        push(bytes);
        let mut bytes = record(8, 0x18);
        put_u64(&mut bytes, 24, 1);
        put_u32(&mut bytes, 32, 0);
        push(bytes);
        if active_fcntl {
            let mut bytes = record(9, 0x20);
            put_u64(&mut bytes, 24, 1);
            put_u64(&mut bytes, 32, 2);
            push(bytes);
        }
        let mut bytes = record(if active_fcntl { 10 } else { 9 }, 0x18);
        put_u64(&mut bytes, 24, 2);
        put_u32(&mut bytes, 32, child_status);
        push(bytes);
        raw
    };
    let clone_exitless_positive = clone_exitless_raw(3, 3, 1, 9, false);
    let clone_exitless_negative_cases = [
        ("clone-exitless-fork", clone_exitless_raw(1, 1, 2, 9, false)),
        (
            "clone-exitless-vfork",
            clone_exitless_raw(2, 2, 2, 9, false),
        ),
        ("clone-exitless-non9", clone_exitless_raw(3, 3, 1, 0, false)),
        (
            "clone-exitless-active-fcntl",
            clone_exitless_raw(3, 3, 1, 9, true),
        ),
    ];
    let clone_exitless_negative_cases = clone_exitless_negative_cases
        .iter()
        .map(|(name, bytes)| format!("{name}\x1f{}", hex(bytes)))
        .collect::<Vec<_>>()
        .join("\x1e");

    let expected_json = concat!(
        "{\"authority\":\"non-production-experiment-only\",\"rows\":[",
        "{\"argument\":\"zero\",\"command\":\"dupfd\",\"count\":1,",
        "\"errno\":\"none\",\"result\":\"equal-floor\"},",
        "{\"argument\":\"none\",\"command\":\"getfd\",\"count\":1,",
        "\"errno\":\"none\",\"result\":\"cloexec\"},",
        "{\"argument\":\"file-status-flags\",\"command\":\"getfl\",\"count\":1,",
        "\"errno\":\"none\",\"result\":\"success\"},",
        "{\"argument\":\"cloexec\",\"command\":\"setfd\",\"count\":1,",
        "\"errno\":\"none\",\"result\":\"success-zero\"}],",
        "\"schema\":\"bs2b-s9-fcntl-experiment-aggregate-v1\",",
        "\"trace_v1_input\":false}\n"
    );
    let empty_json = concat!(
        "{\"authority\":\"non-production-experiment-only\",\"rows\":[],",
        "\"schema\":\"bs2b-s9-fcntl-experiment-aggregate-v1\",",
        "\"trace_v1_input\":false}\n"
    );

    let mut duplicate_raw = raw_golden.clone();
    put_raw_u64(&mut duplicate_raw, 31, 40, 0);
    put_raw_u64(&mut duplicate_raw, 31, 48, 0);
    put_raw_u64(&mut duplicate_raw, 31, 56, 0);
    let duplicate_json = concat!(
        "{\"authority\":\"non-production-experiment-only\",\"rows\":[",
        "{\"argument\":\"zero\",\"command\":\"dupfd\",\"count\":2,",
        "\"errno\":\"none\",\"result\":\"equal-floor\"},",
        "{\"argument\":\"none\",\"command\":\"getfd\",\"count\":1,",
        "\"errno\":\"none\",\"result\":\"cloexec\"},",
        "{\"argument\":\"cloexec\",\"command\":\"setfd\",\"count\":1,",
        "\"errno\":\"none\",\"result\":\"success-zero\"}],",
        "\"schema\":\"bs2b-s9-fcntl-experiment-aggregate-v1\",",
        "\"trace_v1_input\":false}\n"
    );

    let mut raw_rejections = Vec::<(String, Vec<u8>)>::new();
    let mut add_rejection = |name: &str, bytes: Vec<u8>| {
        raw_rejections.push((name.to_owned(), bytes));
    };
    add_rejection("envelope-empty", Vec::new());
    add_rejection(
        "envelope-nonaligned",
        raw_golden[..raw_golden.len() - 1].to_vec(),
    );
    let mut bytes = raw_golden.clone();
    put_raw_u32(&mut bytes, 3, 12, 1);
    add_rejection("reserved-flags", bytes);
    let mut bytes = raw_golden.clone();
    bytes[3 * 128 + 127] = 1;
    add_rejection("reserved-padding", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u32(&mut bytes, 0, 24, 129);
    add_rejection("envelope-header-size", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u32(&mut bytes, 0, 28, 0x0403_0201);
    add_rejection("envelope-endian", bytes);
    let mut bytes = raw_golden.clone();
    bytes[0] = b'Q';
    add_rejection("envelope-magic", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u16(&mut bytes, 0, 8, 2);
    add_rejection("envelope-version", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u64(&mut bytes, 3, 16, 2);
    add_rejection("sequence-duplicate", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u64(&mut bytes, 4, 16, 99);
    add_rejection("sequence-gap", bytes);
    for (name, value) in [
        ("ordinal-generation-zero", 0),
        ("ordinal-generation-cap", 4097),
    ] {
        let mut bytes = raw_golden.clone();
        put_raw_u64(&mut bytes, 25, 32, value);
        add_rejection(name, bytes);
    }
    for (name, value) in [
        ("ordinal-invocation-zero", 0),
        ("ordinal-invocation-cap", 65_537),
    ] {
        let mut bytes = raw_golden.clone();
        put_raw_u64(&mut bytes, 25, 24, value);
        add_rejection(name, bytes);
    }
    let mut bytes = raw_golden.clone();
    put_raw_u64(&mut bytes, 3, 24, 0);
    add_rejection("ordinal-creation-zero", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u64(&mut bytes, 4, 24, 99);
    add_rejection("creation-event-ordinal", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u16(&mut bytes, 4, 40, 3);
    add_rejection("creation-event-kind", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u16(&mut bytes, 9, 40, 1);
    put_raw_u16(&mut bytes, 11, 56, 1);
    add_rejection("creation2-fork-event-same-group", bytes);
    let mut clone3_vfork = Vec::new();
    let mut push_clone3_vfork = |mut bytes: [u8; 128]| {
        put_u64(&mut bytes, 16, (clone3_vfork.len() / 128) as u64);
        clone3_vfork.extend_from_slice(&bytes);
    };
    let mut bytes = record(0, 1);
    put_u32(&mut bytes, 24, 128);
    put_u32(&mut bytes, 28, 0x0102_0304);
    push_clone3_vfork(bytes);
    let mut bytes = record(1, 0x10);
    put_u64(&mut bytes, 24, 1);
    push_clone3_vfork(bytes);
    let mut bytes = record(2, 0x16);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 40, 1);
    put_u16(&mut bytes, 48, 1);
    push_clone3_vfork(bytes);
    let mut bytes = record(3, 0x11);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 4);
    push_clone3_vfork(bytes);
    let mut bytes = record(4, 0x12);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 2);
    push_clone3_vfork(bytes);
    let mut bytes = record(5, 0x14);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u64(&mut bytes, 40, 2);
    put_u64(&mut bytes, 48, 2);
    put_u16(&mut bytes, 56, 2);
    push_clone3_vfork(bytes);
    let mut bytes = record(6, 0x13);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 1);
    push_clone3_vfork(bytes);
    let mut bytes = record(7, 0x17);
    put_u64(&mut bytes, 24, 1);
    put_u32(&mut bytes, 32, 0);
    push_clone3_vfork(bytes);
    let mut bytes = record(8, 0x18);
    put_u64(&mut bytes, 24, 1);
    put_u32(&mut bytes, 32, 0);
    push_clone3_vfork(bytes);
    let mut bytes = record(9, 0x17);
    put_u64(&mut bytes, 24, 2);
    put_u32(&mut bytes, 32, 0);
    push_clone3_vfork(bytes);
    let mut bytes = record(10, 0x18);
    put_u64(&mut bytes, 24, 2);
    put_u32(&mut bytes, 32, 0);
    push_clone3_vfork(bytes);
    add_rejection("creation2-clone3-vfork-without-done", clone3_vfork);
    let mut bytes = raw_golden.clone();
    put_raw_u16(&mut bytes, 6, 40, 2);
    add_rejection("creation-outcome", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u16(&mut bytes, 6, 42, 1);
    add_rejection("creation-success-errno", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u64(&mut bytes, 5, 40, 4);
    add_rejection("creation-join-gap", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u64(&mut bytes, 15, 40, 3);
    add_rejection("vfork-done-child", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u16(&mut bytes, 18, 48, 3);
    add_rejection("exec-class", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u64(&mut bytes, 18, 32, 0);
    add_rejection("exec-displaced", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u64(&mut bytes, 18, 40, 2);
    add_rejection("exec-thread-group", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u32(&mut bytes, 35, 32, 0x7f);
    put_raw_u32(&mut bytes, 36, 32, 0x7f);
    add_rejection("terminal-stopped-status", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u32(&mut bytes, 35, 32, 0x0109);
    put_raw_u32(&mut bytes, 36, 32, 0x0109);
    add_rejection("terminal-noncanonical-signal-status", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u32(&mut bytes, 36, 32, 0);
    add_rejection("terminal-wif-mismatch", bytes);
    add_rejection(
        "terminal-missing-wif",
        raw_golden[..raw_golden.len() - 128].to_vec(),
    );
    let mut bytes = raw_golden.clone();
    let mut extra = record(39, 0x18);
    put_u64(&mut extra, 24, 4);
    put_u32(&mut extra, 32, 0);
    bytes.extend_from_slice(&extra);
    add_rejection("equation-duplicate-wif", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u16(&mut bytes, 4, 10, 0x19);
    for byte in &mut bytes[4 * 128 + 24..5 * 128] {
        *byte = 0;
    }
    put_raw_u64(&mut bytes, 4, 24, 1);
    put_raw_u32(&mut bytes, 4, 32, 1);
    add_rejection("equation-missing-event", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u64(&mut bytes, 28, 24, 3);
    add_rejection("equation-fcntl-ordinal", bytes);
    let mut bytes = raw_golden.clone();
    put_raw_u64(&mut bytes, 21, 32, 57);
    add_rejection("equation-cancel-mapping", bytes);
    let mut bytes = raw_golden.clone();
    let mut extra = record(39, 0x19);
    put_u64(&mut extra, 24, 4);
    put_u32(&mut extra, 32, 9);
    bytes.extend_from_slice(&extra);
    add_rejection("equation-post-terminal-reference", bytes);
    let mut bytes = raw_golden.clone();
    bytes.extend_from_slice(&record(39, 0x22));
    add_rejection("envelope-unknown-kind", bytes);
    let mut bytes = raw_golden.clone();
    let mut extra = record(39, 0x18);
    put_u64(&mut extra, 24, 1);
    put_u32(&mut extra, 32, 0);
    bytes.extend_from_slice(&extra);
    add_rejection("equation-superseded-wif", bytes);

    let mut join_after_exit = Vec::new();
    let mut append_join_after_exit = |mut bytes: [u8; 128]| {
        put_u64(&mut bytes, 16, (join_after_exit.len() / 128) as u64);
        join_after_exit.extend_from_slice(&bytes);
    };
    let mut bytes = record(0, 1);
    put_u32(&mut bytes, 24, 128);
    put_u32(&mut bytes, 28, 0x0102_0304);
    append_join_after_exit(bytes);
    let mut bytes = record(1, 0x10);
    put_u64(&mut bytes, 24, 1);
    append_join_after_exit(bytes);
    let mut bytes = record(2, 0x16);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 40, 1);
    put_u16(&mut bytes, 48, 1);
    append_join_after_exit(bytes);
    let mut bytes = record(3, 0x11);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 1);
    append_join_after_exit(bytes);
    let mut bytes = record(4, 0x12);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 1);
    append_join_after_exit(bytes);
    let mut bytes = record(5, 0x13);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 1);
    append_join_after_exit(bytes);
    let mut bytes = record(6, 0x17);
    put_u64(&mut bytes, 24, 1);
    put_u32(&mut bytes, 32, 0);
    append_join_after_exit(bytes);
    let mut bytes = record(7, 0x14);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u64(&mut bytes, 40, 2);
    put_u64(&mut bytes, 48, 2);
    put_u16(&mut bytes, 56, 1);
    append_join_after_exit(bytes);
    let mut bytes = record(8, 0x18);
    put_u64(&mut bytes, 24, 1);
    put_u32(&mut bytes, 32, 0);
    append_join_after_exit(bytes);
    let mut bytes = record(9, 0x17);
    put_u64(&mut bytes, 24, 2);
    put_u32(&mut bytes, 32, 0);
    append_join_after_exit(bytes);
    let mut bytes = record(10, 0x18);
    put_u64(&mut bytes, 24, 2);
    put_u32(&mut bytes, 32, 0);
    append_join_after_exit(bytes);
    add_rejection("creation-join-after-parent-exit", join_after_exit);

    let mut terminal_vfork = Vec::new();
    let mut push_terminal_vfork = |mut bytes: [u8; 128]| {
        put_u64(&mut bytes, 16, (terminal_vfork.len() / 128) as u64);
        terminal_vfork.extend_from_slice(&bytes);
    };
    let mut bytes = record(0, 1);
    put_u32(&mut bytes, 24, 128);
    put_u32(&mut bytes, 28, 0x0102_0304);
    push_terminal_vfork(bytes);
    let mut bytes = record(1, 0x10);
    put_u64(&mut bytes, 24, 1);
    push_terminal_vfork(bytes);
    let mut bytes = record(2, 0x16);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 40, 1);
    put_u16(&mut bytes, 48, 1);
    push_terminal_vfork(bytes);
    let mut bytes = record(3, 0x11);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 2);
    push_terminal_vfork(bytes);
    let mut bytes = record(4, 0x12);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 2);
    push_terminal_vfork(bytes);
    let mut bytes = record(5, 0x14);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u64(&mut bytes, 40, 2);
    put_u64(&mut bytes, 48, 2);
    put_u16(&mut bytes, 56, 2);
    push_terminal_vfork(bytes);
    let mut bytes = record(6, 0x17);
    put_u64(&mut bytes, 24, 2);
    push_terminal_vfork(bytes);
    let mut bytes = record(7, 0x15);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u64(&mut bytes, 40, 2);
    push_terminal_vfork(bytes);
    let mut bytes = record(8, 0x13);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u16(&mut bytes, 40, 1);
    push_terminal_vfork(bytes);
    let mut bytes = record(9, 0x17);
    put_u64(&mut bytes, 24, 1);
    push_terminal_vfork(bytes);
    let mut bytes = record(10, 0x18);
    put_u64(&mut bytes, 24, 1);
    push_terminal_vfork(bytes);
    let mut bytes = record(11, 0x18);
    put_u64(&mut bytes, 24, 2);
    push_terminal_vfork(bytes);
    add_rejection("vfork-done-after-child-terminal", terminal_vfork);

    let mut sparse_generation = Vec::new();
    for bytes in records.iter().take(3) {
        sparse_generation.extend_from_slice(bytes);
    }
    let mut bytes = record(3, 0x20);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 4097);
    for (index, argument) in fcntl_args(0, 0).into_iter().enumerate() {
        put_u64(&mut bytes, 40 + index * 8, argument);
    }
    sparse_generation.extend_from_slice(&bytes);
    add_rejection("sparse-generation-bound", sparse_generation);
    let mut sparse_invocation = Vec::new();
    for bytes in records.iter().take(3) {
        sparse_invocation.extend_from_slice(bytes);
    }
    let mut bytes = record(3, 0x20);
    put_u64(&mut bytes, 24, 65_537);
    put_u64(&mut bytes, 32, 1);
    for (index, argument) in fcntl_args(0, 0).into_iter().enumerate() {
        put_u64(&mut bytes, 40 + index * 8, argument);
    }
    sparse_invocation.extend_from_slice(&bytes);
    add_rejection("sparse-invocation-bound", sparse_invocation);

    let serialize_cases = |cases: &[(String, Vec<u8>)]| {
        cases
            .iter()
            .map(|(name, bytes)| format!("{name}\x1f{}", hex(bytes)))
            .collect::<Vec<_>>()
            .join("\x1e")
    };
    let mut creation_scale_raw = Vec::with_capacity(8199 * 128);
    let mut append_creation_scale = |mut bytes: [u8; 128]| {
        put_u64(&mut bytes, 16, (creation_scale_raw.len() / 128) as u64);
        creation_scale_raw.extend_from_slice(&bytes);
    };
    let mut bytes = record(0, 1);
    put_u32(&mut bytes, 24, 128);
    put_u32(&mut bytes, 28, 0x0102_0304);
    append_creation_scale(bytes);
    let mut bytes = record(1, 0x10);
    put_u64(&mut bytes, 24, 1);
    append_creation_scale(bytes);
    let mut bytes = record(2, 0x16);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 40, 1);
    put_u16(&mut bytes, 48, 1);
    append_creation_scale(bytes);
    for creation in 1..=4097 {
        let mut bytes = record(0, 0x11);
        put_u64(&mut bytes, 24, creation);
        put_u64(&mut bytes, 32, 1);
        put_u16(&mut bytes, 40, 1);
        append_creation_scale(bytes);
        let mut bytes = record(0, 0x13);
        put_u64(&mut bytes, 24, creation);
        put_u64(&mut bytes, 32, 1);
        put_u16(&mut bytes, 40, 0);
        put_u16(&mut bytes, 42, 1);
        append_creation_scale(bytes);
    }
    let mut bytes = record(0, 0x17);
    put_u64(&mut bytes, 24, 1);
    put_u32(&mut bytes, 32, 0);
    append_creation_scale(bytes);
    let mut bytes = record(0, 0x18);
    put_u64(&mut bytes, 24, 1);
    put_u32(&mut bytes, 32, 0);
    append_creation_scale(bytes);
    assert_eq!(creation_scale_raw.len(), 8199 * 128);

    let mut normalizations = Vec::<String>::new();
    let mut add_norm = |name: &str, command: u64, argument: u64, result: u64, expected: &str| {
        normalizations.push(format!(
            "{name}\x1f{command}\x1f{argument}\x1f{result}\x1f{expected}"
        ));
    };
    for (argument, result, expected) in [
        (0, 0, "zero,equal-floor,none"),
        (1, 1, "stdio,equal-floor,none"),
        (2, 3, "stdio,above-floor,none"),
        (3, 3, "low-3-31,equal-floor,none"),
        (31, 32, "low-3-31,above-floor,none"),
        (32, 32, "medium-32-1023,equal-floor,none"),
        (1023, 1024, "medium-32-1023,above-floor,none"),
        (1024, 1024, "high-1024-int-max,equal-floor,none"),
        (
            2_147_483_647,
            2_147_483_647,
            "high-1024-int-max,equal-floor,none",
        ),
    ] {
        add_norm(
            &format!("dupfd-{argument}-{result}"),
            0,
            argument,
            result,
            &format!("dupfd,{expected}"),
        );
    }
    add_norm(
        "dupfd-cloexec-above",
        1030,
        32,
        33,
        "dupfd-cloexec,medium-32-1023,above-floor,none",
    );
    add_norm(
        "dupfd-argument-over-int-max",
        0,
        2_147_483_648,
        2_147_483_648,
        "invalid",
    );
    add_norm("dupfd-result-over-int-max", 0, 0, 2_147_483_648, "invalid");
    add_norm("dupfd-result-below-floor", 0, 32, 31, "invalid");
    add_norm(
        "dupfd-negative-failure",
        0,
        0,
        u64::MAX - 1,
        "dupfd,zero,failure,other",
    );
    for (command, name) in [(0, "dupfd"), (1030, "dupfd-cloexec")] {
        add_norm(
            &format!("{name}-bad-fd"),
            command,
            0,
            u64::MAX - 8,
            &format!("{name},zero,failure,bad-fd"),
        );
        add_norm(
            &format!("{name}-invalid"),
            command,
            0,
            u64::MAX - 21,
            &format!("{name},zero,failure,invalid"),
        );
    }
    add_norm("getfd-none", 1, 0, 0, "getfd,none,none,none");
    add_norm("getfd-cloexec", 1, 0, 1, "getfd,none,cloexec,none");
    add_norm("getfd-mask-other", 1, 0, 2, "getfd,none,fd-mask-other,none");
    add_norm(
        "getfd-failure",
        1,
        0,
        u64::MAX - 8,
        "getfd,none,failure,bad-fd",
    );
    add_norm("setfd-none", 2, 0, 0, "setfd,none,success-zero,none");
    add_norm("setfd-cloexec", 2, 1, 0, "setfd,cloexec,success-zero,none");
    add_norm(
        "setfd-mask-other",
        2,
        2,
        0,
        "setfd,fd-mask-other,success-zero,none",
    );
    add_norm("setfd-nonzero-result", 2, 0, 1, "invalid");
    for (command, name) in [(3, "getfl"), (4, "setfl")] {
        add_norm(
            &format!("{name}-flags"),
            command,
            0x800,
            0,
            &format!("{name},file-status-flags,success,none"),
        );
        add_norm(
            &format!("{name}-failure"),
            command,
            0x800,
            u64::MAX - 21,
            &format!("{name},file-status-flags,failure,invalid"),
        );
    }
    for command in [5, 6, 7, 36, 37, 38, 1029] {
        add_norm(
            &format!("lock-{command}"),
            command,
            0x1234,
            0,
            "lock,pointer,success,none",
        );
    }
    for command in [8, 10, 11, 15, 16, 17] {
        add_norm(
            &format!("owner-{command}"),
            command,
            0x1234,
            0,
            "owner-signal,owner-signal,success,none",
        );
    }
    add_norm(
        "owner-getown-signed",
        9,
        0x1234,
        u64::MAX,
        "owner-signal,owner-signal,signed-ambiguous,none",
    );
    for (command, name) in [(1024, "lease"), (1025, "lease")] {
        add_norm(
            &format!("lease-{command}"),
            command,
            0x1234,
            0,
            &format!("{name},lease,success,none"),
        );
    }
    for (command, name) in [
        (1026, "notify"),
        (1031, "pipe"),
        (1032, "pipe"),
        (1033, "seal"),
        (1034, "seal"),
    ] {
        add_norm(
            &format!("{name}-{command}"),
            command,
            0x1234,
            0,
            &format!("{name},{name},success,none"),
        );
    }
    for command in 1035..=1038 {
        add_norm(
            &format!("hint-{command}"),
            command,
            0x1234,
            0,
            "hint,hint,success,none",
        );
    }
    add_norm(
        "unknown-success",
        12,
        0x1234,
        0,
        "unknown,unknown,success,none",
    );
    add_norm(
        "unknown-failure",
        u64::MAX,
        0x1234,
        u64::MAX - 1,
        "unknown,unknown,failure,other",
    );
    for (result, errno) in [
        (u64::MAX - 8, "bad-fd"),
        (u64::MAX - 21, "invalid"),
        (u64::MAX - 23, "process-fd-limit"),
        (u64::MAX - 22, "system-fd-limit"),
        (u64::MAX - 3, "interrupted"),
        (u64::MAX - 12, "contended"),
        (u64::MAX - 10, "contended"),
        (u64::MAX - 34, "deadlock"),
        (u64::MAX - 36, "no-locks"),
        (u64::MAX - 13, "bad-pointer"),
        (u64::MAX - 1, "other"),
        (u64::MAX, "denied"),
        (u64::MAX - 37, "unsupported"),
        (u64::MAX - 94, "unsupported"),
    ] {
        add_norm(
            &format!("errno-{errno}-{result}"),
            12,
            0x1234,
            result,
            &format!("unknown,unknown,failure,{errno}"),
        );
    }
    for result in [
        u64::MAX - 511,
        u64::MAX - 512,
        u64::MAX - 513,
        u64::MAX - 515,
    ] {
        add_norm(&format!("restart-{result}"), 12, 0, result, "invalid");
    }
    add_norm("getown-restart", 9, 0, u64::MAX - 511, "invalid");
    add_norm(
        "getown-signed-bad-fd",
        9,
        0,
        u64::MAX - 8,
        "owner-signal,owner-signal,signed-ambiguous,none",
    );
    add_norm(
        "generic-minimum-failure",
        12,
        0,
        u64::MAX - 4094,
        "unknown,unknown,failure,other",
    );
    add_norm("generic-below-minimum", 12, 0, u64::MAX - 4095, "invalid");
    let normalization_cases = normalizations.join("\x1e");

    let mut aggregate_mutations = vec![
        (
            "duplicate-key",
            expected_json.replace(
                "{\"authority\":",
                "{\"authority\":\"non-production-experiment-only\",\"authority\":",
            ),
        ),
        (
            "forbidden-key",
            expected_json.replace("\"rows\":", "\"path\":\"/forbidden\",\"rows\":"),
        ),
        (
            "forbidden-token",
            expected_json.replace("\"file-status-flags\"", "\"forbidden\""),
        ),
        (
            "order",
            format!(
                "{{\"rows\":{},\"authority\":\"non-production-experiment-only\",\"schema\":\"bs2b-s9-fcntl-experiment-aggregate-v1\",\"trace_v1_input\":false}}\n",
                &expected_json[expected_json.find("\"rows\":").unwrap() + "\"rows\":".len()
                    ..expected_json.find(",\"schema\":").unwrap()]
            ),
        ),
        (
            "whitespace",
            expected_json.replace(",\"rows\":", ", \"rows\":"),
        ),
        (
            "missing-final-lf",
            expected_json.trim_end_matches('\n').to_owned(),
        ),
        ("extra-final-lf", format!("{expected_json}\n")),
        (
            "count-type",
            expected_json.replacen("\"count\":1", "\"count\":true", 1),
        ),
    ];
    let duplicate_row_json = expected_json.replacen(
        "{\"argument\":\"none\"",
        "{\"argument\":\"zero\",\"command\":\"dupfd\",\"count\":1,\"errno\":\"none\",\"result\":\"equal-floor\"},{\"argument\":\"none\"",
        1,
    );
    aggregate_mutations.push(("duplicate-row", duplicate_row_json));
    let aggregate_cases = aggregate_mutations
        .iter()
        .map(|(name, json)| format!("{name}\x1f{json}"))
        .collect::<Vec<_>>()
        .join("\x1e");

    let driver = r#"
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile

spec = importlib.util.spec_from_file_location("task4_s9_fcntl_experiment", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 fcntl experiment")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

if any(callable(getattr(module, name, None)) for name in ("run", "produce", "capture")):
    raise SystemExit("experiment exposed a production callable")

def fail(label, message):
    raise SystemExit(f"{label}: {message}")

def expect_invalid(label, invoke):
    try:
        invoke()
    except module.ContractError as exc:
        if type(exc) is not module.ContractError or exc.code != "invalid" or str(exc) != "invalid":
            fail(label, f"wrong ContractError {type(exc).__name__}: {exc}")
    else:
        fail(label, "accepted invalid input")

def with_raw(raw, invoke):
    fd, path = tempfile.mkstemp(prefix="task4-s9-", dir=os.environ.get("TMPDIR"))
    try:
        os.fchmod(fd, 0o600)
        os.ftruncate(fd, len(raw))
        if raw and os.pwrite(fd, raw, 0) != len(raw):
            fail("raw fixture", "short fixture write")
        os.lseek(fd, 7, os.SEEK_SET)
        return invoke(fd)
    finally:
        os.close(fd)
        os.unlink(path)

expected_bytes = os.environ["TASK4_EXPECTED_JSON"].encode("ascii")
expected = json.loads(expected_bytes)
expected_rows = {
    (row["command"], row["argument"], row["result"], row["errno"]): row["count"]
    for row in expected["rows"]
}
if module._encode_aggregate({}) != os.environ["TASK4_EMPTY_JSON"].encode("ascii"):
    fail("empty aggregate", "canonical empty bytes differ")
module._privacy_scan_aggregate(os.environ["TASK4_EMPTY_JSON"].encode("ascii"))
golden = bytes.fromhex(os.environ["TASK4_RAW_GOLDEN"])

def parse_golden(fd):
    before = os.lseek(fd, 0, os.SEEK_CUR)
    rows = module._parse_raw(fd)
    if rows != expected_rows:
        fail("all-kinds golden", f"rows differ: {rows!r}")
    if os.lseek(fd, 0, os.SEEK_CUR) != before:
        fail("all-kinds golden", "raw offset changed")

with_raw(golden, parse_golden)
if module._encode_aggregate(expected_rows) != expected_bytes:
    fail("all-kinds golden", "canonical bytes differ")
module._privacy_scan_aggregate(expected_bytes)

duplicate_raw = bytes.fromhex(os.environ["TASK4_DUPLICATE_RAW"])
duplicate_expected = json.loads(os.environ["TASK4_DUPLICATE_JSON"])
duplicate_rows = {
    (row["command"], row["argument"], row["result"], row["errno"]): row["count"]
    for row in duplicate_expected["rows"]
}
def parse_duplicate(fd):
    if module._parse_raw(fd) != duplicate_rows:
        fail("duplicate raw", "rows did not merge")
with_raw(duplicate_raw, parse_duplicate)

clone_exitless = bytes.fromhex(os.environ["TASK4_CLONE_EXITLESS_RAW"])
def parse_clone_exitless(fd):
    try:
        rows = module._parse_raw(fd)
    except module.ContractError as exc:
        fail("clone-exitless-positive", f"parser rejected positive journal: {exc}")
    if rows != {}:
        fail("clone-exitless-positive", f"expected empty rows, got {rows!r}")
with_raw(clone_exitless, parse_clone_exitless)

for item in filter(None, os.environ["TASK4_CLONE_EXITLESS_NEGATIVE_CASES"].split("\x1e")):
    label, encoded = item.split("\x1f", 1)
    expect_invalid(label, lambda encoded=encoded: with_raw(bytes.fromhex(encoded), module._parse_raw))

for item in filter(None, os.environ["TASK4_RAW_CASES"].split("\x1e")):
    label, encoded = item.split("\x1f", 1)
    expect_invalid(label, lambda encoded=encoded: with_raw(bytes.fromhex(encoded), module._parse_raw))

fd, path = tempfile.mkstemp(prefix="task4-s9-cap-", dir=os.environ.get("TMPDIR"))
try:
    os.fchmod(fd, 0o600)
    os.ftruncate(fd, 128 * 1024 * 1024 + 128)
    real_pread = os.pread
    def pread_bomb(*args):
        fail("raw cap", "pread happened before cap rejection")
    os.pread = pread_bomb
    expect_invalid("raw-cap-plus-one", lambda: module._parse_raw(fd))
    os.pread = real_pread
finally:
    os.close(fd)
    os.unlink(path)

for item in os.environ["TASK4_NORMALIZATION_CASES"].split("\x1e"):
    label, command, argument, result, wanted = item.split("\x1f")
    values = (int(command), int(argument), int(result))
    if wanted == "invalid":
        expect_invalid(label, lambda values=values: module._normalize(*values))
    else:
        try:
            actual = module._normalize(*values)
        except BaseException as exc:
            fail(label, f"unexpected exception {type(exc).__name__}: {exc}")
        if actual != tuple(wanted.split(",")):
            fail(label, f"expected {wanted!r}, got {actual!r}")

class IntSubclass(int):
    pass

for label, values in (
    ("normalize-bool-command", (True, 0, 0)),
    ("normalize-int-subclass", (IntSubclass(0), 0, 0)),
    ("normalize-bool-argument", (0, True, 0)),
    ("normalize-int-subclass-argument", (0, IntSubclass(0), 0)),
    ("normalize-float-argument", (0, 0.0, 0)),
    ("normalize-negative-argument", (0, -1, 0)),
    ("normalize-overflow-argument", (0, 2**64, 0)),
    ("normalize-float", (0.0, 0, 0)),
    ("normalize-negative-command", (-1, 0, 0)),
    ("normalize-overflow-command", (2**64, 0, 0)),
    ("normalize-bool-result", (0, 0, True)),
    ("normalize-int-subclass-result", (0, 0, IntSubclass(0))),
    ("normalize-float-result", (0, 0, 0.0)),
    ("normalize-negative-result", (0, 0, -1)),
    ("normalize-overflow-result", (0, 0, 2**64)),
):
    expect_invalid(label, lambda values=values: module._normalize(*values))

for item in os.environ["TASK4_AGGREGATE_CASES"].split("\x1e"):
    label, encoded = item.split("\x1f", 1)
    expect_invalid(label, lambda encoded=encoded: module._privacy_scan_aggregate(encoded.encode("ascii")))
expect_invalid(
    "aggregate-count-sum",
    lambda: module._encode_aggregate({
        ("dupfd", "zero", "equal-floor", "none"): 65536,
        ("getfd", "none", "none", "none"): 1,
    }),
)
expect_invalid(
    "aggregate-count-zero",
    lambda: module._encode_aggregate({("dupfd", "zero", "equal-floor", "none"): 0}),
)
expect_invalid("aggregate-cap", lambda: module._privacy_scan_aggregate(b"x" * (1 << 20) + b"x"))

def invoke_main(argv):
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = module.main(argv)
    return code, out.getvalue(), err.getvalue()

code, out, err = invoke_main(["self-test"])
if code != 0 or out != "bs2b-s9-fcntl-experiment-self-test-ok\n" or err:
    fail("self-test", f"unexpected result {code!r}, {out!r}, {err!r}")
for argv in ([], ["produce"], ["capture"], ["check"], ["--help"], ["unknown"]):
    code, out, err = invoke_main(argv)
    if code != 77 or out or err:
        fail("refusal-" + "-".join(argv or ["empty"]), f"unexpected result {code!r}, {out!r}, {err!r}")

held_case = os.environ.get("TASK4_HELD_CASE")
if held_case is None:
    print("bs2b-s9-fcntl-experiment-normalization-privacy-ok")
    raise SystemExit(0)

def held_invalid(label):
    before = os.pread(1, 1 << 20, 0)
    try:
        module._check_raw(0, 1)
    except module.ContractError as exc:
        if type(exc) is not module.ContractError or exc.code != "invalid" or str(exc) != "invalid":
            fail(label, f"wrong error {type(exc).__name__}: {exc}")
    else:
        fail(label, "accepted invalid held-FD input")
    after = os.pread(1, 1 << 20, 0)
    if after != before:
        fail(label, "pre-write rejection changed output")
    if os.fstat(1).st_size != 0 and held_case not in ("alias", "link"):
        fail(label, "pre-write rejection left output bytes")

if held_case in ("alias", "kind", "mode", "link", "uid", "pre-invalid"):
    if held_case == "uid":
        real_fstat = os.fstat
        called = [False]
        def wrong_uid(fd):
            if fd == 0 and not called[0]:
                called[0] = True
                stat_result = real_fstat(fd)
                values = list(stat_result)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return real_fstat(fd)
        os.fstat = wrong_uid
        try:
            held_invalid("held-wrong-uid")
        finally:
            os.fstat = real_fstat
        if not called[0]:
            fail("held-wrong-uid", "metadata shim was not used")
    else:
        held_invalid("held-" + held_case)
    raise SystemExit(64)
elif held_case == "creation-scale":
    if module._parse_raw(0) != {}:
        fail("held-creation-scale", "failed creations produced aggregate rows")
    if os.fstat(1).st_size != 0:
        fail("held-creation-scale", "positive parse changed output")
    raise SystemExit(0)
elif held_case == "changed-during-read":
    raw_before = os.pread(0, 1 << 20, 0)
    real_pread = os.pread
    calls = [0]
    def changing_pread(fd, size, offset):
        data = real_pread(fd, size, offset)
        if fd == 0 and calls[0] == 0:
            calls[0] = 1
            os.fchmod(fd, 0o644)
        return data
    os.pread = changing_pread
    try:
        try:
            module._check_raw(0, 1)
        except module.ContractError as exc:
            if type(exc) is not module.ContractError or exc.code != "invalid" or str(exc) != "invalid":
                fail("held-changed-during-read", f"wrong error {type(exc).__name__}: {exc}")
        else:
            fail("held-changed-during-read", "metadata mutation was accepted")
    finally:
        os.pread = real_pread
    if calls[0] != 1:
        fail("held-changed-during-read", "raw-read shim did not run")
    if os.pread(0, 1 << 20, 0) != raw_before:
        fail("held-changed-during-read", "raw bytes changed")
    if os.fstat(1).st_size != 0:
        fail("held-changed-during-read", "changed input left output bytes")
    raise SystemExit(64)
elif held_case == "output-race":
    real_sha256 = hashlib.sha256
    calls = [0]
    def racing_sha256(*args, **kwargs):
        digest = real_sha256(*args, **kwargs)
        if calls[0] == 0:
            calls[0] = 1
            os.pwrite(1, b"x", 0)
        return digest
    hashlib.sha256 = racing_sha256
    try:
        try:
            module._check_raw(0, 1)
        except module.ContractError as exc:
            if type(exc) is not module.ContractError or exc.code != "invalid" or str(exc) != "invalid":
                fail("held-output-race", f"wrong error {type(exc).__name__}: {exc}")
        else:
            fail("held-output-race", "output race was accepted")
    finally:
        hashlib.sha256 = real_sha256
    if calls[0] != 1:
        fail("held-output-race", "digest shim did not run")
    if os.pread(1, 1 << 20, 0) != b"x":
        fail("held-output-race", "output race did not preserve the marker")
    raise SystemExit(64)
elif held_case == "offset":
    os.lseek(0, 19, os.SEEK_SET)
    os.lseek(1, 7, os.SEEK_SET)
    digest = module._check_raw(0, 1)
    if digest != hashlib.sha256(expected_bytes).hexdigest():
        fail("held-offset", "digest mismatch")
    if os.lseek(0, 0, os.SEEK_CUR) != 19 or os.lseek(1, 0, os.SEEK_CUR) != 7:
        fail("held-offset", "caller offsets changed")
elif held_case == "taint":
    real_pwrite = os.pwrite
    calls = []
    def short_pwrite(fd, data, offset):
        prefix = data[:max(1, len(data) // 2)]
        written = real_pwrite(fd, prefix, offset)
        calls.append((fd, len(data), written))
        return written
    os.pwrite = short_pwrite
    try:
        try:
            module._check_raw(0, 1)
        except module.ContractError as exc:
            if type(exc) is not module.ContractError or exc.code != "tainted-output" or str(exc) != "tainted-output":
                fail("held-taint", f"wrong error {type(exc).__name__}: {exc}")
        else:
            fail("held-taint", "short write was accepted")
    finally:
        os.pwrite = real_pwrite
    if len(calls) != 1 or calls[0][0] != 1 or calls[0][2] <= 0 or calls[0][2] >= calls[0][1]:
        fail("held-taint", f"unexpected pwrite calls {calls!r}")
    if os.fstat(1).st_size == 0:
        fail("held-taint", "tainted output was empty")
    raise SystemExit(65)
elif held_case == "success":
    digest = module._check_raw(0, 1)
    if digest != hashlib.sha256(expected_bytes).hexdigest():
        fail("held-success", "digest mismatch")
    if os.pread(1, 1 << 20, 0) != expected_bytes:
        fail("held-success", "readback bytes differ")
else:
    fail("held", "unknown held case")
raise SystemExit(0)
"#;

    for chunk in raw_rejections.chunks(6) {
        let output = Command::new("/usr/bin/python3")
            .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
            .current_dir(repo)
            .env_clear()
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("TASK4_RAW_GOLDEN", hex(&raw_golden))
            .env("TASK4_EMPTY_JSON", empty_json)
            .env("TASK4_EXPECTED_JSON", expected_json)
            .env("TASK4_DUPLICATE_RAW", hex(&duplicate_raw))
            .env("TASK4_DUPLICATE_JSON", duplicate_json)
            .env("TASK4_CLONE_EXITLESS_RAW", hex(&clone_exitless_positive))
            .env(
                "TASK4_CLONE_EXITLESS_NEGATIVE_CASES",
                &clone_exitless_negative_cases,
            )
            .env("TASK4_RAW_CASES", serialize_cases(chunk))
            .env("TASK4_NORMALIZATION_CASES", &normalization_cases)
            .env("TASK4_AGGREGATE_CASES", &aggregate_cases)
            .output()
            .expect("run BS2b-S9 normalization/privacy contract");
        assert!(
            output.status.success(),
            "BS2b-S9 normalization/privacy contract failed:\nstdout={:?}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "BS2b-S9 base driver wrote to stderr"
        );
        assert_eq!(
            output.stdout,
            b"bs2b-s9-fcntl-experiment-normalization-privacy-ok\n"
        );
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after epoch")
        .as_nanos();
    let temp_root = std::env::temp_dir().join(format!(
        "pkcs11-scope-bs2b-s9-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&temp_root).expect("create BS2b-S9 temporary directory");
    fs::set_permissions(&temp_root, fs::Permissions::from_mode(0o700))
        .expect("set BS2b-S9 temporary directory mode");
    let create_regular = |name: &str, contents: &[u8]| {
        let path = temp_root.join(name);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create BS2b-S9 regular fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set BS2b-S9 regular fixture mode");
        std::io::Write::write_all(&mut file, contents).expect("write BS2b-S9 regular fixture");
        file.sync_all().expect("sync BS2b-S9 regular fixture");
        file.seek(SeekFrom::Start(0))
            .expect("rewind BS2b-S9 regular fixture");
        (path, file)
    };
    let run_held = |case: &str, expected_status: i32, raw: Stdio, output: std::fs::File| {
        let child = Command::new("/usr/bin/python3")
            .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
            .current_dir(repo)
            .env_clear()
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("TASK4_RAW_GOLDEN", hex(&raw_golden))
            .env("TASK4_EMPTY_JSON", empty_json)
            .env("TASK4_EXPECTED_JSON", expected_json)
            .env("TASK4_DUPLICATE_RAW", hex(&duplicate_raw))
            .env("TASK4_DUPLICATE_JSON", duplicate_json)
            .env("TASK4_CLONE_EXITLESS_RAW", hex(&clone_exitless_positive))
            .env(
                "TASK4_CLONE_EXITLESS_NEGATIVE_CASES",
                &clone_exitless_negative_cases,
            )
            .env("TASK4_RAW_CASES", "")
            .env("TASK4_NORMALIZATION_CASES", &normalization_cases)
            .env("TASK4_AGGREGATE_CASES", &aggregate_cases)
            .env("TASK4_HELD_CASE", case)
            .stdin(raw)
            .stdout(Stdio::from(output))
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn BS2b-S9 held-FD contract");
        let result = child
            .wait_with_output()
            .expect("wait for BS2b-S9 held-FD contract");
        assert_eq!(
            result.status.code(),
            Some(expected_status),
            "BS2b-S9 held-FD {case} returned unexpected status: stderr={:?}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            result.stderr.is_empty(),
            "BS2b-S9 held-FD {case} wrote to stderr"
        );
    };
    let assert_regular = |path: &Path| {
        let metadata = fs::symlink_metadata(path).expect("read BS2b-S9 output metadata");
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    };

    let (raw_path, raw_file) = create_regular("success-raw", &raw_golden);
    let (output_path, output_file) = create_regular("success-output", &[]);
    run_held("success", 0, Stdio::from(raw_file), output_file);
    assert_regular(&output_path);
    assert_eq!(
        fs::read(&output_path).expect("read successful aggregate"),
        expected_json.as_bytes()
    );
    fs::remove_file(raw_path).expect("remove successful raw fixture");
    fs::remove_file(output_path).expect("remove successful output fixture");

    let (raw_path, raw_file) = create_regular("creation-scale-raw", &creation_scale_raw);
    let (output_path, output_file) = create_regular("creation-scale-output", &[]);
    run_held("creation-scale", 0, Stdio::from(raw_file), output_file);
    assert_eq!(
        fs::read(&raw_path).expect("read creation-scale raw fixture"),
        creation_scale_raw
    );
    assert_regular(&output_path);
    assert!(
        fs::read(&output_path)
            .expect("read creation-scale output")
            .is_empty()
    );
    fs::remove_file(raw_path).expect("remove creation-scale raw fixture");
    fs::remove_file(output_path).expect("remove creation-scale output fixture");

    let (raw_path, raw_file) = create_regular("offset-raw", &raw_golden);
    let (output_path, output_file) = create_regular("offset-output", &[]);
    let mut raw_probe = raw_file.try_clone().expect("clone offset raw probe");
    let mut output_probe = output_file.try_clone().expect("clone offset output probe");
    run_held("offset", 0, Stdio::from(raw_file), output_file);
    assert_eq!(
        raw_probe.stream_position().expect("seek offset raw probe"),
        19
    );
    assert_eq!(
        output_probe
            .stream_position()
            .expect("seek offset output probe"),
        7
    );
    assert_regular(&output_path);
    assert_eq!(
        fs::read(&output_path).expect("read offset aggregate"),
        expected_json.as_bytes()
    );
    fs::remove_file(raw_path).expect("remove offset raw fixture");
    fs::remove_file(output_path).expect("remove offset output fixture");

    let (raw_path, raw_file) = create_regular("taint-raw", &raw_golden);
    let (output_path, output_file) = create_regular("taint-output", &[]);
    run_held("taint", 65, Stdio::from(raw_file), output_file);
    assert_regular(&output_path);
    assert!(
        fs::metadata(&output_path)
            .expect("stat tainted output")
            .len()
            > 0
    );
    fs::remove_file(raw_path).expect("remove taint raw fixture");
    fs::remove_file(output_path).expect("remove taint output fixture");

    let (raw_path, raw_file) = create_regular("invalid-raw", &raw_golden[..raw_golden.len() - 128]);
    let (output_path, output_file) = create_regular("invalid-output", &[]);
    run_held("pre-invalid", 64, Stdio::from(raw_file), output_file);
    assert_regular(&output_path);
    assert!(
        fs::read(&output_path)
            .expect("read invalid output")
            .is_empty()
    );
    fs::remove_file(raw_path).expect("remove invalid raw fixture");
    fs::remove_file(output_path).expect("remove invalid output fixture");

    let (raw_path, raw_file) = create_regular("changed-raw", &raw_golden);
    let (output_path, output_file) = create_regular("changed-output", &[]);
    run_held(
        "changed-during-read",
        64,
        Stdio::from(raw_file),
        output_file,
    );
    assert_eq!(
        fs::read(&raw_path).expect("read changed raw fixture"),
        raw_golden
    );
    assert_regular(&output_path);
    assert!(
        fs::read(&output_path)
            .expect("read changed output")
            .is_empty()
    );
    fs::remove_file(raw_path).expect("remove changed raw fixture");
    fs::remove_file(output_path).expect("remove changed output fixture");

    let (raw_path, raw_file) = create_regular("output-race-raw", &raw_golden);
    let (output_path, output_file) = create_regular("output-race-output", &[]);
    run_held("output-race", 64, Stdio::from(raw_file), output_file);
    assert_regular(&output_path);
    assert_eq!(
        fs::read(&output_path).expect("read output-race output"),
        b"x"
    );
    fs::remove_file(raw_path).expect("remove output-race raw fixture");
    fs::remove_file(output_path).expect("remove output-race output fixture");

    let (raw_path, raw_file) = create_regular("mode-raw", &raw_golden);
    fs::set_permissions(&raw_path, fs::Permissions::from_mode(0o644))
        .expect("set wrong BS2b-S9 raw mode");
    let (output_path, output_file) = create_regular("mode-output", &[]);
    run_held("mode", 64, Stdio::from(raw_file), output_file);
    assert_regular(&output_path);
    assert!(fs::read(&output_path).expect("read mode output").is_empty());
    fs::remove_file(raw_path).expect("remove mode raw fixture");
    fs::remove_file(output_path).expect("remove mode output fixture");

    let (raw_path, raw_file) = create_regular("link-raw", &raw_golden);
    let link_path = temp_root.join("link-alias");
    fs::hard_link(&raw_path, &link_path).expect("create BS2b-S9 hard link");
    let (output_path, output_file) = create_regular("link-output", &[]);
    run_held("link", 64, Stdio::from(raw_file), output_file);
    assert_eq!(
        fs::read(&raw_path).expect("read linked raw fixture"),
        raw_golden
    );
    fs::remove_file(raw_path).expect("remove link raw fixture");
    fs::remove_file(link_path).expect("remove link raw hard link");
    assert_regular(&output_path);
    assert!(fs::read(&output_path).expect("read link output").is_empty());
    fs::remove_file(output_path).expect("remove link output fixture");

    let (raw_path, raw_file) = create_regular("alias-raw", &raw_golden);
    let alias_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&raw_path)
        .expect("open BS2b-S9 alias raw fixture");
    run_held("alias", 64, Stdio::from(raw_file), alias_file);
    assert_eq!(
        fs::read(&raw_path).expect("read alias raw fixture"),
        raw_golden
    );
    fs::remove_file(raw_path).expect("remove alias raw fixture");

    let (output_path, output_file) = create_regular("kind-output", &[]);
    run_held("kind", 64, Stdio::piped(), output_file);
    assert_regular(&output_path);
    assert!(fs::read(&output_path).expect("read kind output").is_empty());
    fs::remove_file(output_path).expect("remove kind output fixture");

    let (raw_path, raw_file) = create_regular("uid-raw", &raw_golden);
    let (output_path, output_file) = create_regular("uid-output", &[]);
    run_held("uid", 64, Stdio::from(raw_file), output_file);
    assert_regular(&output_path);
    assert!(fs::read(&output_path).expect("read uid output").is_empty());
    fs::remove_file(raw_path).expect("remove uid raw fixture");
    fs::remove_file(output_path).expect("remove uid output fixture");

    assert!(
        fs::read_dir(&temp_root)
            .expect("read BS2b-S9 temporary directory")
            .next()
            .is_none()
    );
    fs::remove_dir(&temp_root).expect("remove BS2b-S9 temporary directory");
}

#[test]
fn bs2b_s9_native_ptrace_lifecycle_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let collector = repo.join("scripts/fixtures/task4-fcntl-trace.c");
    assert!(
        collector.is_file(),
        "RED2 missing scripts/fixtures/task4-fcntl-trace.c"
    );
    const HEADER: u16 = 0x01;
    const ROOT: u16 = 0x10;
    const CREATE_ENTRY: u16 = 0x11;
    const CREATE_EVENT: u16 = 0x12;
    const CREATE_EXIT: u16 = 0x13;
    const CHILD_JOIN: u16 = 0x14;
    const VFORK_DONE: u16 = 0x15;
    const EXEC_EVENT: u16 = 0x16;
    const EXIT_EVENT: u16 = 0x17;
    const FINAL_WIF: u16 = 0x18;
    const SIGNAL_DELIVERY: u16 = 0x19;
    const SYSCALL_CANCEL: u16 = 0x1a;
    const FCNTL_ENTRY: u16 = 0x20;
    const FCNTL_EXIT: u16 = 0x21;

    let experiment = repo.join("scripts/task4-fcntl-experiment.py");
    assert!(experiment.is_file(), "RED2 missing Python parser");
    let test_file = repo.join("tests/task4_build_subjects.rs");
    let input_paths = [&test_file, &experiment, &collector];
    let snapshot_input = |path: &Path| {
        let metadata = fs::metadata(path).expect("snapshot RED2 input metadata");
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.size(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
            fs::read(path).expect("snapshot RED2 input bytes"),
        )
    };
    let input_before = input_paths
        .iter()
        .map(|path| snapshot_input(path))
        .collect::<Vec<_>>();
    let assert_inputs_unchanged = || {
        for (path, before) in input_paths.iter().zip(input_before.iter()) {
            assert_eq!(&snapshot_input(path), before, "RED2 owned input changed");
        }
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after epoch")
        .as_nanos();
    let temp_root = std::env::temp_dir().join(format!(
        "pkcs11-scope-bs2b-s9-red2-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&temp_root).expect("create RED2 temporary directory");
    struct TempGuard(PathBuf);
    impl Drop for TempGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _temp_guard = TempGuard(temp_root.clone());
    fs::set_permissions(&temp_root, fs::Permissions::from_mode(0o700))
        .expect("set RED2 temporary directory mode");
    let binary = temp_root.join("task4-fcntl-trace");
    let compile = Command::new("/usr/bin/cc")
        .args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            binary.to_str().expect("binary path is UTF-8"),
            collector.to_str().expect("collector path is UTF-8"),
            "-lseccomp",
            "-pthread",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .output()
        .expect("compile RED2 collector");
    assert_inputs_unchanged();
    assert!(
        compile.status.success(),
        "RED2 collector compile failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&compile.stdout),
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(compile.stdout.is_empty(), "RED2 compiler wrote to stdout");
    assert!(compile.stderr.is_empty(), "RED2 compiler wrote to stderr");

    let evidence = temp_root.join("evidence");
    fs::create_dir(&evidence).expect("create RED2 evidence directory");
    let driver = r#"
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import os
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time

binary, experiment, evidence = sys.argv[1:]

spec = importlib.util.spec_from_file_location("task4_s9_experiment", experiment)
if spec is None or spec.loader is None:
    raise SystemExit("RED2 could not import Python parser")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
if any(callable(getattr(module, name, None)) for name in ("run", "produce", "capture", "check")):
    raise SystemExit("RED2 production callable became reachable")
if not callable(getattr(module, "_parse_raw", None)):
    raise SystemExit("RED2 missing _parse_raw bridge")

libc = ctypes.CDLL(None, use_errno=True)
PR_SET_CHILD_SUBREAPER = 36
if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    raise SystemExit("RED2 collector containment unavailable")
driver_pid = os.getpid()
driver_tid = str(driver_pid)
proc_fd = os.open("/proc", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
task_fd = os.open(f"self/task/{driver_tid}", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=proc_fd)
children_fd = os.open("children", os.O_RDONLY | os.O_CLOEXEC, dir_fd=task_fd)
try:
    if os.pread(children_fd, 65536, 0) not in (b"", b"\n"):
        raise SystemExit("RED2 collector containment unavailable")
except OSError:
    raise SystemExit("RED2 collector containment unavailable")
if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit("RED2 collector containment unavailable")
try:
    own_pidfd = os.pidfd_open(driver_pid)
    signal.pidfd_send_signal(own_pidfd, 0)
    os.close(own_pidfd)
except OSError:
    raise SystemExit("RED2 collector containment unavailable")

CASES = (
    "sim-event-first", "sim-stop-first", "sim-tid-reuse", "sim-restart",
    "review-policy-bpf", "kernel-bootstrap", "kernel-fork", "kernel-clone",
    "kernel-vfork", "kernel-nonleader-exec", "kernel-signal-ignored",
    "kernel-signal-caught", "kernel-restart-reject", "kernel-group-stop-reject",
    "kernel-cleanup-signal-int", "kernel-cleanup-signal-hup",
    "kernel-cleanup-signal-term", "kernel-cleanup-failure",
)
KERNEL_CASES = set(CASES[5:])
UNRUN = {
    "bs2b-s9-native-unrun:linux-x86-64-required",
    "bs2b-s9-native-unrun:ptrace-seize-unsupported",
    "bs2b-s9-native-unrun:ptrace-seize-denied",
}
EXPECTED_ROWS = {
    "kernel-bootstrap": {},
    "kernel-fork": {("getfd", "none", "none", "none"): 2},
    "kernel-clone": {("getfd", "none", "none", "none"): 2},
    "kernel-vfork": {("getfd", "none", "none", "none"): 2},
    "kernel-nonleader-exec": {("getfd", "none", "none", "none"): 1},
    "kernel-signal-ignored": {("getfd", "none", "none", "none"): 1},
    "kernel-signal-caught": {("getfd", "none", "none", "none"): 2},
}
SIMULATION_NEGATIVE = {"sim-restart", "kernel-restart-reject", "kernel-group-stop-reject",
                       "kernel-cleanup-signal-int", "kernel-cleanup-signal-hup",
                       "kernel-cleanup-signal-term", "kernel-cleanup-failure"}

BPF_LD_W_ABS = 0x20
BPF_JA = 0x05
BPF_JEQ_K = 0x15
BPF_JGT_K = 0x25
BPF_JGE_K = 0x35
BPF_JSET_K = 0x45
BPF_AND_K = 0x54
BPF_RET_K = 0x06
SECCOMP_RET_KILL_THREAD = 0x00000000
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_TRACE = 0x7FF00000
SECCOMP_RET_LOG = 0x7FFC0000
SECCOMP_RET_ALLOW = 0x7FFF0000
AUDIT_ARCH_X86_64 = 0xC000003E
SOCK_SEQPACKET = 5
SOCK_CLOEXEC = 0x80000

def decode_bpf(program):
    if not program or len(program) % 8 != 0 or len(program) // 8 > 4096:
        fail("review-policy-bpf", "BPF export has invalid size")
    instructions = [struct.unpack_from("<HBBI", program, offset)
                    for offset in range(0, len(program), 8)]
    count = len(instructions)
    for pc, (code, jt, jf, k) in enumerate(instructions):
        if code == BPF_LD_W_ABS:
            if jt != 0 or jf != 0 or k >= 64 or k % 4 != 0:
                fail("review-policy-bpf", "unrecognized BPF load")
        elif code == BPF_JA:
            if jt != 0 or jf != 0 or pc + 1 + k >= count:
                fail("review-policy-bpf", "BPF jump is out of bounds")
        elif code in (BPF_JEQ_K, BPF_JGT_K, BPF_JGE_K, BPF_JSET_K):
            if pc + 1 + jt >= count or pc + 1 + jf >= count:
                fail("review-policy-bpf", "BPF conditional jump is out of bounds")
        elif code == BPF_AND_K:
            if jt != 0 or jf != 0:
                fail("review-policy-bpf", "unrecognized BPF ALU instruction")
        elif code == BPF_RET_K:
            if jt != 0 or jf != 0 or (k & 0xFFFF0000) not in (
                    SECCOMP_RET_KILL_THREAD, SECCOMP_RET_KILL_PROCESS,
                    SECCOMP_RET_TRAP, SECCOMP_RET_ERRNO, SECCOMP_RET_TRACE,
                    SECCOMP_RET_LOG, SECCOMP_RET_ALLOW):
                fail("review-policy-bpf", "unrecognized BPF terminal action")
        else:
            fail("review-policy-bpf", "unrecognized BPF opcode")
    return instructions

def interpret_bpf(program, data):
    instructions = decode_bpf(program)
    if len(data) != 64:
        fail("review-policy-bpf", "seccomp_data size changed")
    accumulator = 0
    pc = 0
    for _ in range(len(instructions) * 8 + 1):
        code, jt, jf, k = instructions[pc]
        if code == BPF_LD_W_ABS:
            accumulator = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif code == BPF_JA:
            pc += 1 + k
        elif code in (BPF_JEQ_K, BPF_JGT_K, BPF_JGE_K, BPF_JSET_K):
            if code == BPF_JEQ_K:
                matched = accumulator == k
            elif code == BPF_JGT_K:
                matched = accumulator > k
            elif code == BPF_JGE_K:
                matched = accumulator >= k
            else:
                matched = accumulator & k != 0
            pc += 1 + (jt if matched else jf)
        elif code == BPF_AND_K:
            accumulator &= k
            pc += 1
        elif code == BPF_RET_K:
            return k
        else:
            fail("review-policy-bpf", "BPF interpreter reached unknown opcode")
        if pc >= len(instructions):
            fail("review-policy-bpf", "BPF interpreter left program")
    fail("review-policy-bpf", "BPF interpreter did not terminate")

def socketpair_data(family, sock_type, protocol, address):
    data = bytearray(64)
    struct.pack_into("<I", data, 0, 53)
    struct.pack_into("<I", data, 4, AUDIT_ARCH_X86_64)
    for index, value in enumerate((family, sock_type, protocol, address)):
        struct.pack_into("<Q", data, 16 + index * 8, value)
    return bytes(data)

def assert_bpf_policy(program):
    decode_bpf(program)
    allow = SECCOMP_RET_ALLOW
    errno_eprem = SECCOMP_RET_ERRNO | 1
    pointer = 0x123456789
    def expect(label, family, sock_type, protocol, address, result):
        actual = interpret_bpf(program, socketpair_data(family, sock_type, protocol, address))
        if actual != result:
            fail("review-policy-bpf", f"{label} returned {actual:#x}, expected {result:#x}")
    expect("accepted AF_UNIX seqpacket cloexec", 1, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pointer, allow)
    expect("nonzero protocol", 1, SOCK_SEQPACKET | SOCK_CLOEXEC, 1, pointer, errno_eprem)
    expect("stream", 1, 1 | SOCK_CLOEXEC, 0, pointer, errno_eprem)
    expect("dgram", 1, 2 | SOCK_CLOEXEC, 0, pointer, errno_eprem)
    expect("missing cloexec", 1, SOCK_SEQPACKET, 0, pointer, errno_eprem)
    expect("wrong family", 2, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pointer, errno_eprem)
    expect("null address remains filter-allowed", 1, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, 0, allow)
def fail(label, message):
    raise SystemExit(f"{label}: {message}")

def read_children():
    try:
        raw = os.pread(children_fd, 65536, 0)
    except OSError:
        fail("containment", "could not read exact children file")
    if not raw:
        return []
    values = raw.split()
    if len(values) > 4097 or any(not item.isdigit() or item.startswith(b"0") for item in values):
        fail("containment", "noncanonical children file")
    pids = [int(item) for item in values]
    if any(pid <= 0 or pid > 2**31 - 1 for pid in pids) or len(set(pids)) != len(pids):
        fail("containment", "invalid children identity")
    return pids

def proc_stat(pid, retain=False):
    pid_fd = os.open(str(pid), os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=proc_fd)
    keep_fd = False
    try:
        first_stat = os.fstat(pid_fd)
        first_identity = (first_stat.st_dev, first_stat.st_ino)
        stat_fd = os.open("stat", os.O_RDONLY | os.O_CLOEXEC, dir_fd=pid_fd)
        try:
            raw = os.pread(stat_fd, 65536, 0)
        finally:
            os.close(stat_fd)
        close = raw.rfind(b")")
        if close < 0:
            fail("containment", "malformed proc stat")
        try:
            actual_pid = int(raw.split(b" ", 1)[0])
        except (ValueError, IndexError):
            fail("containment", "malformed proc pid")
        if actual_pid != pid:
            fail("containment", "proc pid changed")
        fields = raw[close + 2:].split()
        if len(fields) < 22:
            fail("containment", "short proc stat")
        state = fields[0]
        if state not in (b"R", b"S", b"D", b"Z", b"T", b"t", b"W", b"X", b"x", b"K", b"P"):
            fail("containment", "invalid proc state")
        result = (actual_pid, int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19]))
        if result[1] <= 0 or result[2] <= 0 or result[3] <= 0 or result[4] <= 0:
            fail("containment", "invalid proc identity fields")
        second_stat = os.fstat(pid_fd)
        second_identity = (second_stat.st_dev, second_stat.st_ino)
        if first_identity != second_identity:
            fail("containment", "proc directory identity changed")
        keep_fd = retain
        return result + (first_identity, pid_fd)
    finally:
        if not keep_fd:
            os.close(pid_fd)

def contain(deadline, expected_session=None, expected_pgrp=None):
    seen = set()
    while time.monotonic() < deadline:
        pids = read_children()
        if not pids:
            try:
                os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            continue
        for pid in pids:
            if pid in seen or len(seen) >= 4097:
                fail("containment", "adopted PID cap exceeded")
            seen.add(pid)
            try:
                pfd = os.pidfd_open(pid)
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    seen.remove(pid)
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
                    continue
                fail("containment", "pidfd_open failed")
            try:
                actual_pid, ppid, pgrp, session, _start, proc_identity, proc_dir_fd = proc_stat(pid, retain=True)
                try:
                    if actual_pid != pid or ppid != driver_pid or (expected_session is not None and session != expected_session) or (expected_pgrp is not None and pgrp != expected_pgrp):
                        fail("containment", "held proc identity mismatch")
                    signal.pidfd_send_signal(pfd, signal.SIGKILL)
                    while time.monotonic() < deadline:
                        waited, _ = os.waitpid(pid, os.WNOHANG)
                        if waited == pid:
                            break
                        time.sleep(0.001)
                    else:
                        fail("containment", "child reap deadline expired")
                    held_stat = os.fstat(proc_dir_fd)
                    if (held_stat.st_dev, held_stat.st_ino) != proc_identity:
                        fail("containment", "held proc identity changed")
                finally:
                    os.close(proc_dir_fd)
            finally:
                os.close(pfd)
    fail("containment", "five-second adopted-child deadline expired")

def prove_clean(deadline):
    while time.monotonic() < deadline:
        if read_children():
            fail("containment", "child remained after successful outcome")
        try:
            waited, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if waited:
            fail("containment", "unlisted child was reaped")
        time.sleep(0.001)
    fail("containment", "clean-closure deadline expired")

def identity(fd):
    item = os.fstat(fd)
    return (item.st_dev, item.st_ino, item.st_uid, item.st_gid,
            stat.S_IMODE(item.st_mode), item.st_nlink, item.st_size)

def watchdog(data, case, collector_pid):
    if len(data) != 24 or data[:8] != b"P11S9WD\0" or data[8:10] != b"\1\0":
        fail(case, "invalid watchdog record")
    kind = struct.unpack_from("<H", data, 10)[0]
    flags = struct.unpack_from("<I", data, 12)[0]
    pgid = struct.unpack_from("<Q", data, 16)[0]
    if kind not in (0, 1) or flags != 0 or pgid > 2**31 - 1:
        fail(case, "noncanonical watchdog record")
    if kind == 0 and pgid != 0:
        fail(case, "no-root watchdog carried PGID")
    if kind == 1 and (pgid <= 0 or pgid > 2**31 - 1):
        fail(case, "owned-root watchdog identity mismatch")
    if case not in KERNEL_CASES and kind != 0:
        fail(case, "simulation reported a root")
    if case in KERNEL_CASES and kind != 1:
        fail(case, "kernel case omitted root")
    if kind == 0:
        return kind, pgid, None, None, None
    root_dir_fd = None
    try:
        root_pidfd = os.pidfd_open(pgid)
        signal.pidfd_send_signal(root_pidfd, 0)
    except OSError:
        fail(case, "reported root pidfd unavailable")
    try:
        actual_pid, ppid, pgrp, session, start, root_identity, root_dir_fd = proc_stat(pgid, retain=True)
        if actual_pid != pgid or ppid != collector_pid or pgrp != pgid or session != collector_pid:
            fail(case, "reported root process identity mismatch")
        return kind, pgid, root_pidfd, root_dir_fd, root_identity
    except BaseException:
        os.close(root_pidfd)
        if root_dir_fd is not None:
            os.close(root_dir_fd)
        raise

def invoke(case, output_fd, watchdog_fd, watchdog_read_fd, args=None, timeout=15):
    argv = [binary, "self-test", case, str(output_fd), str(watchdog_fd)] if args is None else [binary] + args
    stream_fds = []
    stream_paths = []
    stdin_fd = None
    child = None
    pidfd = None
    root_pidfd = None
    root_dir_fd = None
    root_identity = None
    reported_pgid = None
    watchdog_bytes = bytearray()
    watchdog_eof = False
    timed_out = False
    try:
        stdin_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        stdin_metadata = os.fstat(stdin_fd)
        null_metadata = os.stat("/dev/null")
        if (not stat.S_ISCHR(stdin_metadata.st_mode)
                or (stdin_metadata.st_dev, stdin_metadata.st_ino) != (null_metadata.st_dev, null_metadata.st_ino)):
            fail(case, "stdin is not /dev/null")
        for prefix in ("s9-stdout-", "s9-stderr-"):
            fd, path = tempfile.mkstemp(prefix=prefix, dir=os.environ.get("TMPDIR"))
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
                fail(case, "standard stream custody is not a private regular file")
            stream_fds.append(fd)
            stream_paths.append(path)
        flags = fcntl.fcntl(watchdog_read_fd, fcntl.F_GETFL)
        fcntl.fcntl(watchdog_read_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        child = subprocess.Popen(argv, close_fds=True, pass_fds=(output_fd, watchdog_fd),
                                 stdin=stdin_fd, stdout=stream_fds[0], stderr=stream_fds[1],
                                 start_new_session=True)
        os.close(watchdog_fd)
        watchdog_fd = None
        os.close(stdin_fd)
        stdin_fd = None
        for fd in stream_fds:
            os.close(fd)
        stream_fds = []
        pidfd = os.pidfd_open(child.pid)
        deadline = time.monotonic() + timeout
        while True:
            try:
                chunk = os.read(watchdog_read_fd, 4096)
                if chunk:
                    watchdog_bytes.extend(chunk)
                    if len(watchdog_bytes) > 24:
                        fail(case, "watchdog record exceeded 24 bytes")
                    if len(watchdog_bytes) == 24:
                        kind, reported_pgid, root_pidfd, root_dir_fd, root_identity = watchdog(bytes(watchdog_bytes), case, child.pid)
                else:
                    watchdog_eof = True
            except BlockingIOError:
                pass
            rc = child.poll()
            if rc is not None and watchdog_eof:
                break
            if time.monotonic() >= deadline:
                timed_out = True
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                reap_deadline = time.monotonic() + 5
                while child.poll() is None and time.monotonic() < reap_deadline:
                    time.sleep(0.001)
                if child.poll() is None:
                    fail(case, "collector kill/reap deadline expired")
                contain(time.monotonic() + 5, child.pid, reported_pgid)
                watchdog_drain_deadline = time.monotonic() + 5
                while not watchdog_eof:
                    if time.monotonic() >= watchdog_drain_deadline:
                        fail(case, "watchdog EOF drain deadline expired")
                    try:
                        chunk = os.read(watchdog_read_fd, 4096)
                    except BlockingIOError:
                        time.sleep(0.001)
                        continue
                    if chunk:
                        watchdog_bytes.extend(chunk)
                        if len(watchdog_bytes) > 24:
                            fail(case, "watchdog record exceeded 24 bytes")
                    else:
                        watchdog_eof = True
                break
            time.sleep(0.001)
        rc = child.returncode
        streams = []
        for path in stream_paths:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                stream_size = os.fstat(fd).st_size
                if stream_size > 1 << 20:
                    fail(case, "standard stream exceeded 1 MiB")
                stream = os.pread(fd, stream_size, 0)
                if len(stream) != stream_size:
                    fail(case, "standard stream read was short")
                streams.append(stream)
            finally:
                os.close(fd)
        if args is None and len(watchdog_bytes) != 24:
            fail(case, "watchdog record missing")
        if root_dir_fd is not None:
            held_root = os.fstat(root_dir_fd)
            if (held_root.st_dev, held_root.st_ino) != root_identity:
                fail(case, "held root proc identity changed")
        return rc, bytes(watchdog_bytes), streams[0], streams[1], timed_out, child.pid, reported_pgid
    finally:
        if watchdog_fd is not None:
            os.close(watchdog_fd)
        if pidfd is not None:
            os.close(pidfd)
        if root_pidfd is not None:
            os.close(root_pidfd)
        if root_dir_fd is not None:
            os.close(root_dir_fd)
        if child is not None and child.poll() is None:
            try:
                orphan_pidfd = os.pidfd_open(child.pid)
                try:
                    signal.pidfd_send_signal(orphan_pidfd, signal.SIGKILL)
                finally:
                    os.close(orphan_pidfd)
                reap_deadline = time.monotonic() + 5
                while child.poll() is None and time.monotonic() < reap_deadline:
                    time.sleep(0.001)
                if child.poll() is not None:
                    contain(time.monotonic() + 5, child.pid, reported_pgid)
            except BaseException:
                raise
        if stdin_fd is not None:
            os.close(stdin_fd)
        for fd in stream_fds:
            os.close(fd)
        for path in stream_paths:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

def valid_case(case):
    out_fd = wd_read = wd_write = None
    out_path = None
    session_id = None
    reported_pgid = None
    try:
        out_fd, out_path = tempfile.mkstemp(prefix="s9-out-", dir=os.environ.get("TMPDIR"))
        output_metadata = os.fstat(out_fd)
        if (not stat.S_ISREG(output_metadata.st_mode) or output_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(output_metadata.st_mode) != 0o600 or output_metadata.st_nlink != 1):
            fail(case, "output custody is not a private regular file")
        start_flags = fcntl.fcntl(out_fd, fcntl.F_GETFL)
        if start_flags & os.O_ACCMODE != os.O_RDWR or start_flags & os.O_APPEND:
            fail(case, "output flags are not O_RDWR without O_APPEND")
        os.lseek(out_fd, 37, os.SEEK_SET)
        start_identity = identity(out_fd)
        start_offset = os.lseek(out_fd, 0, os.SEEK_CUR)
        wd_read, wd_write = os.pipe2(os.O_CLOEXEC)
        rc, watchdog_bytes, stdout, stderr, timed_out, session_id, reported_pgid = invoke(case, out_fd, wd_write, wd_read)
        if timed_out:
            fail(case, "collector timed out")
        if rc == 0:
            if stdout != f"bs2b-s9-native-self-test-ok:{case}\n".encode() or stderr:
                fail(case, "success stream contract mismatch")
        elif rc == 77 and case in KERNEL_CASES:
            if stdout or stderr not in tuple((token + "\n").encode() for token in UNRUN):
                fail(case, "UNRUN stream contract mismatch")
            with open(os.path.join(evidence, case + ".unrun"), "wb") as stream:
                stream.write(stderr)
        else:
            fail(case, f"unexpected exit {rc}")
        if os.fstat(out_fd).st_size > 128 * 1024 * 1024:
            fail(case, "raw output exceeded 128 MiB")
        if case == "review-policy-bpf":
            raw = os.pread(out_fd, 1 << 20, 0)
            if not raw or len(raw) % 8 or len(raw) // 8 > 4096:
                fail(case, "BPF export is empty, unaligned, or over bound")
            assert_bpf_policy(raw)
            digest = hashlib.sha256(raw).hexdigest()
            with open(os.path.join(evidence, case + ".bpf"), "wb") as stream:
                stream.write(raw)
            with open(os.path.join(evidence, case + ".bpf.meta"), "w", encoding="ascii") as stream:
                stream.write(f"length={len(raw)}\ncount={len(raw) // 8}\nsha256={digest}\n")
        elif rc == 0 and case not in SIMULATION_NEGATIVE:
            calls = []
            original = module._parse_raw
            def parse_once(fd):
                calls.append(fd)
                return original(fd)
            module._parse_raw = parse_once
            try:
                rows = module._parse_raw(out_fd)
            finally:
                module._parse_raw = original
            if len(calls) != 1 or rows != EXPECTED_ROWS.get(case, {}):
                fail(case, "Python _parse_raw bridge mismatch")
            raw = os.pread(out_fd, 128 * 1024 * 1024, 0)
            with open(os.path.join(evidence, case + ".raw"), "wb") as stream:
                stream.write(raw)
        elif os.fstat(out_fd).st_size != 0:
            fail(case, "rejection or UNRUN wrote raw output")
        if identity(out_fd)[:6] != start_identity[:6] or fcntl.fcntl(out_fd, fcntl.F_GETFL) != start_flags:
            fail(case, "output identity or flags changed")
        if os.lseek(out_fd, 0, os.SEEK_CUR) != start_offset:
            fail(case, "caller offset changed")
        try:
            prove_clean(time.monotonic() + 5)
        except BaseException:
            contain(time.monotonic() + 5, session_id, reported_pgid)
            raise
    except BaseException:
        try:
            prove_clean(time.monotonic() + 5)
        except BaseException:
            contain(time.monotonic() + 5, session_id, reported_pgid)
        raise
    finally:
        for fd in (wd_read, wd_write, out_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if out_path is not None:
            try:
                os.unlink(out_path)
            except FileNotFoundError:
                pass

def refusal(label, output_mode="rw", watchdog_mode="write", args=None, case=None):
    out_fd = wd_read = wd_write = passed_watchdog = None
    out_path = watchdog_path = None
    session_id = None
    reported_pgid = None
    try:
        base_fd, out_path = tempfile.mkstemp(prefix="s9-refuse-", dir=os.environ.get("TMPDIR"))
        os.close(base_fd)
        output_flags = {"rw": os.O_RDWR, "ro": os.O_RDONLY, "wo": os.O_WRONLY, "append": os.O_RDWR | os.O_APPEND}[output_mode]
        out_fd = os.open(out_path, output_flags | os.O_CLOEXEC)
        output_metadata = os.fstat(out_fd)
        if (not stat.S_ISREG(output_metadata.st_mode) or output_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(output_metadata.st_mode) != 0o600 or output_metadata.st_nlink != 1):
            fail(label, "refusal output custody is not a private regular file")
        before = identity(out_fd)
        before_flags = fcntl.fcntl(out_fd, fcntl.F_GETFL)
        os.lseek(out_fd, 19, os.SEEK_SET)
        before_offset = os.lseek(out_fd, 0, os.SEEK_CUR)
        if output_mode == "rw":
            if before_flags & os.O_ACCMODE != os.O_RDWR or before_flags & os.O_APPEND:
                fail(label, "refusal output flags are not O_RDWR without O_APPEND")
        elif output_mode == "ro":
            if before_flags & os.O_ACCMODE != os.O_RDONLY:
                fail(label, "refusal output is not read-only")
        elif output_mode == "wo":
            if before_flags & os.O_ACCMODE != os.O_WRONLY:
                fail(label, "refusal output is not write-only")
        elif not before_flags & os.O_APPEND:
            fail(label, "refusal output is not append-only")
        wd_read, wd_write = os.pipe2(os.O_CLOEXEC)
        passed_watchdog = wd_write
        if watchdog_mode == "read":
            passed_watchdog = os.dup(wd_read)
        elif watchdog_mode == "regular":
            watchdog_base, watchdog_path = tempfile.mkstemp(prefix="s9-watchdog-", dir=os.environ.get("TMPDIR"))
            os.close(watchdog_base)
            passed_watchdog = os.open(watchdog_path, os.O_RDONLY | os.O_CLOEXEC)
        elif watchdog_mode == "alias":
            passed_watchdog = os.dup(out_fd)
        if watchdog_mode == "regular":
            watchdog_identity = identity(passed_watchdog)
            if watchdog_identity[:2] == before[:2]:
                fail(label, "nonpipe watchdog reused output identity")
        actual_args = args if args is not None else ["self-test", case or "sim-event-first", str(out_fd), str(out_fd if watchdog_mode == "alias" else passed_watchdog)]
        if watchdog_mode != "write":
            os.close(wd_write)
            wd_write = -1
        rc, watchdog_bytes, stdout, stderr, timed_out, session_id, reported_pgid = invoke("refusal", out_fd, passed_watchdog, wd_read, args=actual_args)
        if timed_out or rc != 77 or stdout or stderr or watchdog_bytes or os.fstat(out_fd).st_size:
            fail(label, "refusal mutated output, watchdog, or streams")
        if (identity(out_fd) != before
                or fcntl.fcntl(out_fd, fcntl.F_GETFL) != before_flags
                or os.lseek(out_fd, 0, os.SEEK_CUR) != before_offset):
            fail(label, "refusal changed output identity")
        try:
            prove_clean(time.monotonic() + 5)
        except BaseException:
            contain(time.monotonic() + 5, session_id, reported_pgid)
            raise
    except BaseException:
        try:
            prove_clean(time.monotonic() + 5)
        except BaseException:
            contain(time.monotonic() + 5, session_id, reported_pgid)
        raise
    finally:
        for fd in (wd_read, wd_write, out_fd, passed_watchdog):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if out_path is not None:
            try:
                os.unlink(out_path)
            except FileNotFoundError:
                pass
        if watchdog_path is not None:
            try:
                os.unlink(watchdog_path)
            except FileNotFoundError:
                pass

for args in ([], ["--help"], ["produce"], ["capture"], ["check"], ["unknown"],
             ["self-test", "sim-event-first", "3", "4"],
             ["self-test", "sim-event-first", "-1", "4"],
             ["self-test", "sim-event-first", "03", "4"],
             ["self-test", "sim-event-first", "3", "+4"],
             ["self-test", "sim-event-first", "", "4"],
             ["self-test", "sim-event-first", "3", "2147483648"],
             ["self-test", "sim-event-first", "3", "4", "extra"],
             ["self-test", "unknown", "3", "4"],
             ["internal-workload", "unknown"],
             ["internal-workload", "kernel-cleanup-signal"],
             ["internal-workload", "kernel-fork", "extra"]):
    refusal("refusal-" + "-".join(args or ["empty"]), args=args)
refusal("refusal-read-only-output", output_mode="ro")
refusal("refusal-write-only-output", output_mode="wo")
refusal("refusal-append-output", output_mode="append")
refusal("refusal-nonpipe-watchdog", watchdog_mode="regular")
refusal("refusal-read-end-watchdog", watchdog_mode="read")
refusal("refusal-aliased-watchdog", watchdog_mode="alias")
refusal("refusal-retired-cleanup-signal", case="kernel-cleanup-signal")
for case in CASES:
    valid_case(case)
print("bs2b-s9-native-ptrace-lifecycle-ok")
"#;
    let output = Command::new("/usr/bin/python3")
        .args([
            "-c",
            driver,
            binary.to_str().expect("binary path is UTF-8"),
            experiment.to_str().expect("experiment path is UTF-8"),
            evidence.to_str().expect("evidence path is UTF-8"),
        ])
        .current_dir(repo)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env("TMPDIR", &temp_root)
        .output()
        .expect("run RED2 native lifecycle oracle");
    assert_inputs_unchanged();
    assert!(
        output.status.success(),
        "RED2 native lifecycle oracle failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"bs2b-s9-native-ptrace-lifecycle-ok\n");
    assert!(output.stderr.is_empty(), "RED2 oracle wrote to stderr");

    let simulation_evidence = ["sim-event-first", "sim-stop-first", "sim-tid-reuse"];
    for case in simulation_evidence {
        assert!(evidence.join(format!("{case}.raw")).is_file());
    }
    assert!(evidence.join("review-policy-bpf.bpf").is_file());
    assert!(evidence.join("review-policy-bpf.bpf.meta").is_file());
    for case in [
        "kernel-bootstrap",
        "kernel-fork",
        "kernel-clone",
        "kernel-vfork",
        "kernel-nonleader-exec",
        "kernel-signal-ignored",
        "kernel-signal-caught",
    ] {
        let raw = evidence.join(format!("{case}.raw"));
        let unrun = evidence.join(format!("{case}.unrun"));
        assert_ne!(
            raw.is_file(),
            unrun.is_file(),
            "RED2 case evidence is ambiguous"
        );
    }

    let bpf_path = evidence.join("review-policy-bpf.bpf");
    let bpf_meta_path = evidence.join("review-policy-bpf.bpf.meta");
    assert!(bpf_path.is_file(), "RED2 BPF bytes evidence missing");
    assert!(
        bpf_meta_path.is_file(),
        "RED2 BPF metadata evidence missing"
    );
    let bpf_bytes = fs::read(&bpf_path).expect("read RED2 BPF bytes evidence");
    assert!(!bpf_bytes.is_empty(), "RED2 BPF evidence is empty");
    assert_eq!(
        bpf_bytes.len() % 8,
        0,
        "RED2 BPF instruction alignment changed"
    );
    assert!(
        bpf_bytes.len() / 8 <= 4096,
        "RED2 BPF instruction bound changed"
    );
    let digest = Command::new("/usr/bin/sha256sum")
        .arg(&bpf_path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .output()
        .expect("hash RED2 BPF evidence");
    assert!(digest.status.success(), "RED2 BPF digest failed");
    let digest = String::from_utf8_lossy(&digest.stdout);
    let digest = digest.split_whitespace().next().expect("BPF digest");
    let metadata = fs::read_to_string(&bpf_meta_path).expect("read RED2 BPF metadata");
    assert_eq!(
        metadata,
        format!(
            "length={}\ncount={}\nsha256={digest}\n",
            bpf_bytes.len(),
            bpf_bytes.len() / 8
        ),
        "RED2 BPF byte metadata changed"
    );
    fs::remove_file(&bpf_path).expect("remove RED2 BPF bytes evidence");
    fs::remove_file(&bpf_meta_path).expect("remove RED2 BPF metadata");

    for entry in fs::read_dir(&evidence).expect("read RED2 evidence directory") {
        let path = entry.expect("read RED2 evidence entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("RED2 evidence filename is UTF-8");
        let bytes = fs::read(&path).expect("read RED2 raw evidence");
        if name.ends_with(".unrun") {
            assert!(name.starts_with("kernel-"), "simulation was marked UNRUN");
            assert!(
                matches!(
                    bytes.as_slice(),
                    b"bs2b-s9-native-unrun:linux-x86-64-required\n"
                        | b"bs2b-s9-native-unrun:ptrace-seize-unsupported\n"
                        | b"bs2b-s9-native-unrun:ptrace-seize-denied\n"
                ),
                "RED2 UNRUN reason is not exact"
            );
            fs::remove_file(path).expect("remove RED2 UNRUN evidence");
            continue;
        }
        assert!(name.ends_with(".raw"), "unknown RED2 evidence artifact");
        let case = name.strip_suffix(".raw").expect("RED2 raw case name");
        assert!(!bytes.is_empty(), "RED2 raw evidence is empty");
        assert_eq!(bytes.len() % 128, 0, "RED2 raw ABI alignment changed");
        let allowed_kinds = [
            HEADER,
            ROOT,
            CREATE_ENTRY,
            CREATE_EVENT,
            CREATE_EXIT,
            CHILD_JOIN,
            VFORK_DONE,
            EXEC_EVENT,
            EXIT_EVENT,
            FINAL_WIF,
            SIGNAL_DELIVERY,
            SYSCALL_CANCEL,
            FCNTL_ENTRY,
            FCNTL_EXIT,
        ];
        let mut counts = std::collections::BTreeMap::<u16, usize>::new();
        let mut exit_statuses = std::collections::BTreeMap::<u64, u32>::new();
        let mut wif_statuses = std::collections::BTreeMap::<u64, u32>::new();
        let mut exec_superseded = BTreeSet::new();
        for (index, record) in bytes.chunks_exact(128).enumerate() {
            assert_eq!(&record[..8], b"P11S9R1\0", "RED2 journal magic changed");
            assert_eq!(
                &record[8..10],
                &1u16.to_le_bytes(),
                "RED2 journal version changed"
            );
            assert_eq!(&record[12..16], &[0, 0, 0, 0], "RED2 journal flags changed");
            let sequence = u64::from_le_bytes(record[16..24].try_into().unwrap());
            assert_eq!(sequence, index as u64, "RED2 physical sequence changed");
            let kind = u16::from_le_bytes(record[10..12].try_into().unwrap());
            assert!(allowed_kinds.contains(&kind), "RED2 journal kind changed");
            *counts.entry(kind).or_default() += 1;
            let payload_end = match kind {
                HEADER | ROOT => 32,
                CREATE_ENTRY | CREATE_EVENT => 42,
                CREATE_EXIT => 44,
                CHILD_JOIN => 58,
                VFORK_DONE => 48,
                EXEC_EVENT => 50,
                EXIT_EVENT | FINAL_WIF | SIGNAL_DELIVERY => 36,
                SYSCALL_CANCEL => 40,
                FCNTL_ENTRY => 88,
                FCNTL_EXIT => 48,
                _ => unreachable!(),
            };
            assert!(
                record[payload_end..].iter().all(|byte| *byte == 0),
                "RED2 kind-specific padding changed"
            );
            if kind != HEADER && kind != ROOT {
                let ordinal = u64::from_le_bytes(record[24..32].try_into().unwrap());
                assert!(
                    (1..=4096).contains(&ordinal),
                    "RED2 private ordinal bound changed"
                );
            }
            match kind {
                CREATE_ENTRY => assert!(
                    (1..=4).contains(&u16::from_le_bytes(record[40..42].try_into().unwrap())),
                    "RED2 creation syscall kind changed"
                ),
                CREATE_EVENT => assert!(
                    (1..=3).contains(&u16::from_le_bytes(record[40..42].try_into().unwrap())),
                    "RED2 creation event kind changed"
                ),
                CREATE_EXIT => {
                    let outcome = u16::from_le_bytes(record[40..42].try_into().unwrap());
                    let errno = u16::from_le_bytes(record[42..44].try_into().unwrap());
                    assert!(
                        (outcome == 1 && errno == 0)
                            || (outcome == 0 && (1..=4095).contains(&errno)),
                        "RED2 creation outcome changed"
                    );
                }
                CHILD_JOIN => assert!(
                    (1..=3).contains(&u16::from_le_bytes(record[56..58].try_into().unwrap())),
                    "RED2 child event kind changed"
                ),
                VFORK_DONE => assert_ne!(
                    u64::from_le_bytes(record[40..48].try_into().unwrap()),
                    0,
                    "RED2 VFORK_DONE child changed"
                ),
                EXEC_EVENT => {
                    let class = u16::from_le_bytes(record[48..50].try_into().unwrap());
                    assert!((1..=2).contains(&class), "RED2 exec class changed");
                    if class == 2 {
                        exec_superseded
                            .insert(u64::from_le_bytes(record[32..40].try_into().unwrap()));
                    }
                }
                SIGNAL_DELIVERY => {
                    let signal = u32::from_le_bytes(record[32..36].try_into().unwrap());
                    assert!(
                        (1..=64).contains(&signal)
                            && match case {
                                "kernel-signal-ignored" => signal == 10,
                                "kernel-signal-caught" => signal == 12,
                                _ => true,
                            },
                        "RED2 signal field changed"
                    );
                }
                FCNTL_ENTRY => assert_eq!(
                    [
                        u64::from_le_bytes(record[40..48].try_into().unwrap()),
                        u64::from_le_bytes(record[48..56].try_into().unwrap()),
                        u64::from_le_bytes(record[56..64].try_into().unwrap()),
                    ],
                    [2, 1, 0],
                    "RED2 fcntl source/command/argument changed"
                ),
                SYSCALL_CANCEL => assert_ne!(
                    u64::from_le_bytes(record[32..40].try_into().unwrap()),
                    72,
                    "RED2 fcntl cancellation changed"
                ),
                EXIT_EVENT | FINAL_WIF => {
                    let status = u32::from_le_bytes(record[32..36].try_into().unwrap());
                    if case != "kernel-clone" {
                        let signal = status & 0x7f;
                        let normal = status & 0xff == 0;
                        let signaled = (1..=64).contains(&signal) && (status & !0xff) == 0;
                        assert!(
                            status <= 0xffff && (normal || signaled),
                            "RED2 terminal wait status changed"
                        );
                    }
                }
                _ => {}
            }
            if kind == EXIT_EVENT {
                assert!(
                    exit_statuses
                        .insert(
                            u64::from_le_bytes(record[24..32].try_into().unwrap()),
                            u32::from_le_bytes(record[32..36].try_into().unwrap()),
                        )
                        .is_none(),
                    "RED2 duplicate EXIT_EVENT changed"
                );
            }
            if kind == FINAL_WIF {
                let generation = u64::from_le_bytes(record[24..32].try_into().unwrap());
                let status = u32::from_le_bytes(record[32..36].try_into().unwrap());
                assert!(
                    wif_statuses.insert(generation, status).is_none(),
                    "RED2 duplicate WIF changed"
                );
            }
        }
        if case == "kernel-clone" {
            assert_eq!(
                exit_statuses.get(&1),
                Some(&0),
                "RED2 clone root EXIT_EVENT status changed"
            );
            assert_eq!(
                wif_statuses,
                BTreeMap::from([(1, 0), (2, 9)]),
                "RED2 clone FINAL_WIF statuses changed"
            );
            assert!(
                exit_statuses == BTreeMap::from([(1, 0)])
                    || exit_statuses == BTreeMap::from([(1, 0), (2, 9)]),
                "RED2 clone EXIT_EVENT statuses changed"
            );
        }
        if case == "sim-event-first" {
            assert_eq!(
                wif_statuses.get(&4),
                Some(&9),
                "RED2 simulated clone FINAL_WIF status changed"
            );
            assert!(
                !exit_statuses.contains_key(&4),
                "RED2 simulated clone EXIT_EVENT was synthesized"
            );
        }
        assert_eq!(
            u16::from_le_bytes(bytes[10..12].try_into().unwrap()),
            HEADER,
            "RED2 journal envelope is not first"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            128,
            "RED2 journal record size changed"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
            0x0102_0304,
            "RED2 journal endian discriminator changed"
        );
        assert_eq!(
            u16::from_le_bytes(bytes[128 + 10..128 + 12].try_into().unwrap()),
            ROOT,
            "RED2 root record is not second"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[128 + 24..128 + 32].try_into().unwrap()),
            1,
            "RED2 root generation changed"
        );
        assert_eq!(
            u16::from_le_bytes(bytes[256 + 10..256 + 12].try_into().unwrap()),
            EXEC_EVENT,
            "RED2 bootstrap exec record is not third"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[256 + 24..256 + 32].try_into().unwrap()),
            1,
            "RED2 bootstrap execing generation changed"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[256 + 32..256 + 40].try_into().unwrap()),
            0,
            "RED2 bootstrap displaced generation changed"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[256 + 40..256 + 48].try_into().unwrap()),
            1,
            "RED2 bootstrap thread group changed"
        );
        assert_eq!(
            u16::from_le_bytes(bytes[256 + 48..256 + 50].try_into().unwrap()),
            1,
            "RED2 bootstrap exec class changed"
        );
        assert!(counts.contains_key(&ROOT), "RED2 bootstrap record missing");
        let required = match case {
            "sim-event-first" | "sim-stop-first" | "sim-tid-reuse" => &[
                HEADER,
                ROOT,
                EXEC_EVENT,
                CREATE_ENTRY,
                CREATE_EVENT,
                CREATE_EXIT,
                CHILD_JOIN,
                EXIT_EVENT,
                FINAL_WIF,
            ][..],
            "kernel-bootstrap" => &[HEADER, ROOT, EXEC_EVENT, EXIT_EVENT, FINAL_WIF][..],
            "kernel-fork" | "kernel-clone" => &[
                HEADER,
                ROOT,
                CREATE_ENTRY,
                CREATE_EVENT,
                CREATE_EXIT,
                CHILD_JOIN,
                EXEC_EVENT,
                EXIT_EVENT,
                FINAL_WIF,
                FCNTL_ENTRY,
                FCNTL_EXIT,
            ][..],
            "kernel-vfork" => &[
                HEADER,
                ROOT,
                CREATE_ENTRY,
                CREATE_EVENT,
                CREATE_EXIT,
                CHILD_JOIN,
                VFORK_DONE,
                EXEC_EVENT,
                EXIT_EVENT,
                FINAL_WIF,
                FCNTL_ENTRY,
                FCNTL_EXIT,
            ][..],
            "kernel-nonleader-exec" => &[
                HEADER,
                ROOT,
                EXEC_EVENT,
                EXIT_EVENT,
                FINAL_WIF,
                FCNTL_ENTRY,
                FCNTL_EXIT,
            ][..],
            "kernel-signal-ignored" | "kernel-signal-caught" => &[
                HEADER,
                ROOT,
                EXEC_EVENT,
                EXIT_EVENT,
                FINAL_WIF,
                SIGNAL_DELIVERY,
                FCNTL_ENTRY,
                FCNTL_EXIT,
            ][..],
            _ => &[][..],
        };
        for kind in required {
            assert!(
                counts.contains_key(kind),
                "RED2 required lifecycle kind missing"
            );
        }
        if case != "kernel-clone" {
            for (generation, status) in &wif_statuses {
                if case == "sim-event-first" && *generation == 4 {
                    continue;
                }
                assert_eq!(
                    exit_statuses.get(generation),
                    Some(status),
                    "RED2 EXIT/WIF status changed"
                );
            }
            for (generation, status) in &exit_statuses {
                if exec_superseded.contains(generation) {
                    assert!(
                        !wif_statuses.contains_key(generation),
                        "RED2 superseded generation received WIF"
                    );
                } else {
                    assert_eq!(
                        wif_statuses.get(generation),
                        Some(status),
                        "RED2 live generation lost WIF"
                    );
                }
            }
        }
        if case == "sim-event-first" {
            assert_eq!(
                counts.get(&EXIT_EVENT).copied().unwrap_or_default() + 1,
                counts.get(&FINAL_WIF).copied().unwrap_or_default() + exec_superseded.len(),
                "RED2 simulated direct-WIF terminal equation changed"
            );
        } else if case == "kernel-clone" {
            assert!(
                (1..=2).contains(&counts.get(&EXIT_EVENT).copied().unwrap_or_default()),
                "RED2 clone EXIT_EVENT count changed"
            );
        } else {
            assert_eq!(
                counts.get(&EXIT_EVENT).copied().unwrap_or_default(),
                counts.get(&FINAL_WIF).copied().unwrap_or_default() + exec_superseded.len(),
                "RED2 terminal generation equation changed"
            );
        }
        assert_eq!(
            exec_superseded.len(),
            if case == "kernel-nonleader-exec" {
                1
            } else {
                0
            },
            "RED2 exec-superseded exception changed"
        );
        let count = |kind: u16| counts.get(&kind).copied().unwrap_or_default();
        let expected_kind_counts: &[(u16, usize)] = match case {
            "sim-event-first" => &[
                (EXEC_EVENT, 1),
                (CREATE_ENTRY, 3),
                (CREATE_EVENT, 3),
                (CREATE_EXIT, 3),
                (CHILD_JOIN, 3),
                (EXIT_EVENT, 3),
                (FINAL_WIF, 4),
            ],
            "kernel-bootstrap" => &[(EXEC_EVENT, 1)],
            "kernel-fork" => &[
                (CREATE_EVENT, 1),
                (CREATE_EXIT, 1),
                (CHILD_JOIN, 1),
                (EXEC_EVENT, 1),
                (EXIT_EVENT, 2),
                (FINAL_WIF, 2),
                (FCNTL_ENTRY, 2),
                (FCNTL_EXIT, 2),
            ],
            "kernel-clone" => &[
                (CREATE_EVENT, 1),
                (CREATE_EXIT, 1),
                (CHILD_JOIN, 1),
                (EXEC_EVENT, 1),
                (FINAL_WIF, 2),
                (FCNTL_ENTRY, 2),
                (FCNTL_EXIT, 2),
            ],
            "kernel-vfork" => &[
                (CREATE_EVENT, 1),
                (CREATE_EXIT, 1),
                (CHILD_JOIN, 1),
                (VFORK_DONE, 1),
                (EXEC_EVENT, 2),
                (EXIT_EVENT, 2),
                (FINAL_WIF, 2),
                (FCNTL_ENTRY, 2),
                (FCNTL_EXIT, 2),
            ],
            "kernel-nonleader-exec" => &[
                (EXEC_EVENT, 2),
                (EXIT_EVENT, 2),
                (FINAL_WIF, 1),
                (FCNTL_ENTRY, 1),
                (FCNTL_EXIT, 1),
            ],
            "kernel-signal-ignored" => &[
                (EXEC_EVENT, 1),
                (SIGNAL_DELIVERY, 1),
                (EXIT_EVENT, 1),
                (FINAL_WIF, 1),
                (FCNTL_ENTRY, 1),
                (FCNTL_EXIT, 1),
            ],
            "kernel-signal-caught" => &[
                (EXEC_EVENT, 1),
                (SIGNAL_DELIVERY, 1),
                (EXIT_EVENT, 1),
                (FINAL_WIF, 1),
                (FCNTL_ENTRY, 2),
                (FCNTL_EXIT, 2),
            ],
            _ => &[],
        };
        for (kind, expected) in expected_kind_counts {
            assert_eq!(count(*kind), *expected, "RED2 per-case kind count changed");
        }
        if matches!(
            case,
            "sim-event-first" | "sim-stop-first" | "kernel-fork" | "kernel-clone" | "kernel-vfork"
        ) {
            assert_eq!(
                count(CREATE_EXIT),
                count(CREATE_EVENT),
                "RED2 creation event/result equation changed"
            );
            assert_eq!(
                count(CHILD_JOIN),
                count(CREATE_EVENT),
                "RED2 join equation changed"
            );
        }
        if case == "kernel-vfork" {
            assert_eq!(count(VFORK_DONE), 1, "RED2 VFORK_DONE count changed");
        }
        if case == "kernel-nonleader-exec" {
            assert_eq!(count(EXEC_EVENT), 2, "RED2 exec-event count changed");
            assert_eq!(
                count(EXIT_EVENT),
                count(FINAL_WIF) + exec_superseded.len(),
                "RED2 sole exec supersede changed"
            );
        } else if case != "sim-event-first" && case != "kernel-clone" {
            assert_eq!(
                count(EXIT_EVENT),
                count(FINAL_WIF),
                "RED2 EXIT/WIF equation changed"
            );
        }
        if matches!(case, "kernel-signal-ignored" | "kernel-signal-caught") {
            assert_eq!(
                count(SIGNAL_DELIVERY),
                1,
                "RED2 signal-delivery count changed"
            );
        }
        if matches!(case, "kernel-fork" | "kernel-clone" | "kernel-vfork") {
            assert_eq!(
                count(FCNTL_ENTRY),
                count(FCNTL_EXIT),
                "RED2 fcntl entry/exit equation changed"
            );
        }
        if matches!(case, "sim-event-first" | "sim-stop-first") {
            let clone_entries = bytes
                .chunks_exact(128)
                .filter(|record| {
                    u16::from_le_bytes(record[10..12].try_into().unwrap()) == CREATE_ENTRY
                        && u16::from_le_bytes(record[40..42].try_into().unwrap()) == 4
                })
                .count();
            let clone_events = bytes
                .chunks_exact(128)
                .filter(|record| {
                    u16::from_le_bytes(record[10..12].try_into().unwrap()) == CREATE_EVENT
                        && u16::from_le_bytes(record[40..42].try_into().unwrap()) == 3
                })
                .count();
            let clone_joins = bytes
                .chunks_exact(128)
                .filter(|record| {
                    u16::from_le_bytes(record[10..12].try_into().unwrap()) == CHILD_JOIN
                        && u64::from_le_bytes(record[40..48].try_into().unwrap()) != 1
                })
                .count();
            assert_eq!(
                clone_entries,
                if case == "sim-event-first" { 2 } else { 1 },
                "RED2 clone3 entry count changed"
            );
            assert_eq!(
                clone_events,
                if case == "sim-event-first" { 2 } else { 1 },
                "RED2 clone3 event count changed"
            );
            assert_eq!(
                clone_joins,
                if case == "sim-event-first" { 3 } else { 2 },
                "RED2 clone3 join count changed"
            );
        }
        if case == "sim-event-first" {
            let read_u16 = |record: &[u8], offset| {
                u16::from_le_bytes(record[offset..offset + 2].try_into().unwrap())
            };
            let read_u64 = |record: &[u8], offset| {
                u64::from_le_bytes(record[offset..offset + 8].try_into().unwrap())
            };
            let find = |kind, ordinal| {
                bytes.chunks_exact(128).enumerate().find(|(_, record)| {
                    read_u16(record, 10) == kind && read_u64(record, 24) == ordinal
                })
            };
            let (clone_entry, entry) =
                find(CREATE_ENTRY, 3).expect("RED2 simulated clone entry missing");
            assert_eq!(
                read_u64(entry, 32),
                1,
                "RED2 simulated clone entry parent changed"
            );
            assert_eq!(
                read_u16(entry, 40),
                4,
                "RED2 simulated clone syscall changed"
            );
            let (clone_event, event) =
                find(CREATE_EVENT, 3).expect("RED2 simulated clone event missing");
            assert_eq!(
                read_u64(event, 32),
                1,
                "RED2 simulated clone event parent changed"
            );
            assert_eq!(
                read_u16(event, 40),
                3,
                "RED2 simulated clone event kind changed"
            );
            let (clone_exit, exit) =
                find(CREATE_EXIT, 3).expect("RED2 simulated clone result missing");
            assert_eq!(
                read_u64(exit, 32),
                1,
                "RED2 simulated clone result parent changed"
            );
            assert_eq!(
                &exit[40..44],
                &[1, 0, 0, 0],
                "RED2 simulated clone result changed"
            );
            let (clone_join, join) =
                find(CHILD_JOIN, 3).expect("RED2 simulated clone join missing");
            assert_eq!(
                read_u64(join, 32),
                1,
                "RED2 simulated clone join parent changed"
            );
            assert_eq!(
                read_u64(join, 40),
                4,
                "RED2 simulated clone child generation changed"
            );
            assert_eq!(
                read_u64(join, 48),
                1,
                "RED2 simulated clone thread group changed"
            );
            assert_eq!(
                read_u16(join, 56),
                3,
                "RED2 simulated clone join kind changed"
            );
            let (clone_wif, wif) =
                find(FINAL_WIF, 4).expect("RED2 simulated clone FINAL_WIF missing");
            assert_eq!(
                read_u64(wif, 24),
                4,
                "RED2 simulated clone generation changed"
            );
            assert_eq!(
                u32::from_le_bytes(wif[32..36].try_into().unwrap()),
                9,
                "RED2 simulated clone FINAL_WIF status changed"
            );
            assert!(
                clone_entry < clone_event
                    && clone_event < clone_exit
                    && clone_exit < clone_join
                    && clone_join < clone_wif,
                "RED2 simulated clone lifecycle order changed"
            );
        }
        if case == "sim-stop-first" {
            let find = |kind, ordinal| {
                bytes.chunks_exact(128).position(|record| {
                    u16::from_le_bytes(record[10..12].try_into().unwrap()) == kind
                        && u64::from_le_bytes(record[24..32].try_into().unwrap()) == ordinal
                })
            };
            for ordinal in [1, 2] {
                let entry = find(CREATE_ENTRY, ordinal).expect("RED2 creation entry missing");
                let event = find(CREATE_EVENT, ordinal).expect("RED2 creation event missing");
                let join = find(CHILD_JOIN, ordinal).expect("RED2 creation join missing");
                let exit = find(CREATE_EXIT, ordinal).expect("RED2 creation result missing");
                assert!(
                    entry < event && event < join && join < exit,
                    "RED2 simulated stop-first creation lifecycle order changed"
                );
            }
        }
        fs::remove_file(path).expect("remove RED2 raw evidence");
    }
    fs::remove_dir(&evidence).expect("remove RED2 evidence directory");
    fs::remove_file(&binary).expect("remove RED2 temporary binary");
    fs::remove_dir(&temp_root).expect("remove RED2 temporary directory");
    assert_inputs_unchanged();
}
