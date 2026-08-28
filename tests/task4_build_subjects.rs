use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
fn input_v1_ledger_round_trip_and_encoder_rejects_invalid_vectors() {
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
import hashlib
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

digest = hashlib.sha256(b"abc").hexdigest()
encoder_negatives = {
    "boolean-sequence": [
        module.InputRecord(False, "repo", "read", "present", 0o644, 3, digest, "repo:/bool-seq")
    ],
    "boolean-size": [
        module.InputRecord(0, "repo", "read", "present", 0o644, True, digest, "repo:/bool-size")
    ],
    "invalid-directory-mode": [
        module.InputRecord(
            0,
            "directory",
            "probe",
            "present",
            0o10000,
            0,
            hashlib.sha256(b"").hexdigest(),
            "repo:/dir",
        )
    ],
    "invalid-symlink-mode": [
        module.InputRecord(
            0,
            "symlink",
            "probe",
            "present",
            0o10000,
            1,
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            "repo:/link",
        )
    ],
}
for name, vector in encoder_negatives.items():
    try:
        module.encode_ledger(vector)
    except module.FormatError:
        continue
    raise SystemExit(f"{name}: encoder accepted an invalid programmatic record")

long_component = "x" * 255
oversized_records = [
    module.InputRecord(
        index,
        "tool",
        "read",
        "present",
        0o644,
        0,
        hashlib.sha256(b"").hexdigest(),
        f"external:/{index:04d}/" + "/".join([long_component] * 15),
    )
    for index in range(4096)
]
try:
    module.encode_ledger(oversized_records)
except module.FormatError:
    pass
else:
    raise SystemExit("oversized-programmatic-ledger: encoder accepted >4 MiB output")
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
        "input-v1 ledger contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "successful ledger driver wrote to stderr"
    );
    assert_eq!(
        output.stdout, b"input-v1-ok\n",
        "input-v1 ledger driver did not complete"
    );
}

#[test]
fn input_v1_discovery_api_is_candidate_only() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-build-subject.py");
    let driver = r#"
import importlib.util
import inspect
import sys

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

discover = getattr(module, "discover_input_v1", None)
if not callable(discover):
    raise SystemExit("discover_input_v1 is missing or not callable")

parameters = list(inspect.signature(discover).parameters.values())
required = [
    "trace",
    "root_pid",
    "initial_cwd",
    "repo_root",
    "vendor_relative",
    "build_root",
    "stable_sysroot_root",
    "nightly_sysroot_root",
]
if [parameter.name for parameter in parameters] != required:
    raise SystemExit("discover_input_v1 signature drifted")
if parameters[0].kind is not inspect.Parameter.POSITIONAL_OR_KEYWORD:
    raise SystemExit("discover_input_v1 trace is not positional")
if any(parameter.kind is not inspect.Parameter.KEYWORD_ONLY for parameter in parameters[1:]):
    raise SystemExit("discover_input_v1 roots are not keyword-only")
if any(
    parameter.kind in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
    for parameter in parameters
):
    raise SystemExit("discover_input_v1 accepts variadic arguments")
if any(parameter.default is not inspect.Parameter.empty for parameter in parameters):
    raise SystemExit("discover_input_v1 arguments are not all required")

kwargs = dict(
    root_pid=1,
    initial_cwd="/",
    repo_root="/",
    vendor_relative="vendor",
    build_root="/tmp/build",
    stable_sysroot_root="/tmp/stable",
    nightly_sysroot_root="/tmp/nightly",
)
for name in ("expected", "production"):
    try:
        discover(b"", **kwargs, **{name: b""})
    except TypeError:
        continue
    raise SystemExit(f"discover_input_v1 accepted forbidden {name}= keyword")
print("input-v1-api-ok")
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
        "input-v1 discovery API contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "discovery API driver wrote to stderr"
    );
    assert_eq!(
        output.stdout, b"input-v1-api-ok\n",
        "discovery API driver did not complete"
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
    ("repo", "read", "present", "0600", "1", "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", "repo:/hard-a"),
    ("repo", "read", "present", "0600", "1", "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", "repo:/hard-b"),
    ("symlink", "probe", "present", "0777", "5", "4437e55da8273b6a2a433c93548a08cdab55f3e2cba9e08cc080dfdd67d04959", "repo:/link1"),
    ("symlink", "probe", "present", "0777", "19", "21eec616add1a571e58aba55d5f1b9504205384b72a6b40976a4749a3e840b80", "repo:/link2"),
    ("directory", "probe", "present", "0700", "0", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "repo:/probe"),
    ("absent", "probe", "ENOENT", "-", "-", "-", "repo:/probe/missing"),
    ("directory", "probe", "present", "0755", "11", "69342b35fbb91e72cda5d95b052b88fad5f0b111afd2dbb718f45e5778641aa3", "repo:/sub"),
    ("repo", "read", "present", "0644", "1", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "repo:/sub/café.rs"),
    ("vendor", "read", "present", "0700", "4", "0eb9e3089dc8479fdc76d897a20c1555c51505d9f13cc97a868af3ef5988dc87", "vendor:/pkg/tool.bin"),
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
    "input-v1\t2\trepo\tread\tpresent\t0644\t4\t"
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
