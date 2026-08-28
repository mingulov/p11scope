use std::collections::BTreeSet;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

const INPUT_LEDGER_MAX_SIZE: &str = concat!(
    "input-v1\t0\ttool\tread\tpresent\t0644\t4294967296\t",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "\texternal:/opt/rust/bin/rustc-max\n",
);

const INPUT_LEDGER_OVERSIZE: &str = concat!(
    "input-v1\t0\ttool\tread\tpresent\t0644\t4294967297\t",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "\texternal:/opt/rust/bin/rustc-oversize\n",
);

const INPUT_LEDGER_SPECIAL_CLASSES: &str = concat!(
    "input-v1\t0\thost-config\tread\tpresent\t0644\t17\t",
    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    "\texternal:/config\n",
    "input-v1\t1\tlane09-base\tread\tpresent\t0644\t23\t",
    "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
    "\texternal:/lane09-base\n",
    "input-v1\t2\tlane09-package\tread\tpresent\t0644\t29\t",
    "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7",
    "\texternal:/lane09-package\n",
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
maximum = os.environ["TASK4_MAX_SIZE"].encode("ascii")
maximum_records = module.parse_ledger(maximum)
if module.encode_ledger(maximum_records) != maximum:
    raise SystemExit("input-v1 parse/encode changed the maximum-size bytes")
special_classes = os.environ["TASK4_SPECIAL_CLASSES"].encode("ascii")
special_records = module.parse_ledger(special_classes)
if module.encode_ledger(special_records) != special_classes:
    raise SystemExit("input-v1 parse/encode changed the special-class bytes")
oversize = os.environ["TASK4_OVERSIZE"].encode("ascii")
try:
    module.parse_ledger(oversize)
except module.FormatError:
    pass
else:
    raise SystemExit("input-v1 parser accepted size 4294967297")

digest = hashlib.sha256(b"abc").hexdigest()
boundary_locator = "external:/" + "/".join(["a" * 255] * 15 + ["b" * 246])
if len(boundary_locator.encode("ascii")) != 4096:
    raise SystemExit("4096-byte locator fixture has the wrong length")
boundary_record = module.InputRecord(
    0, "tool", "read", "present", 0o644, 0, digest, boundary_locator
)
boundary_bytes = module.encode_ledger([boundary_record])
if module.parse_ledger(boundary_bytes) != [boundary_record]:
    raise SystemExit("4096-byte locator did not round-trip")
locator_4097 = "external:/" + "/".join(["a" * 255] * 15 + ["b" * 247])
if len(locator_4097.encode("ascii")) != 4097:
    raise SystemExit("4097-byte locator fixture has the wrong length")
locator_256 = "external:/" + "c" * 256
for name, raw in {
    "4097-byte locator": (
        f"input-v1\t0\ttool\tread\tpresent\t0644\t0\t{digest}\t{locator_4097}\n"
    ).encode("ascii"),
    "256-byte component": (
        f"input-v1\t0\ttool\tread\tpresent\t0644\t0\t{digest}\t{locator_256}\n"
    ).encode("ascii"),
}.items():
    try:
        module.parse_ledger(raw)
    except module.FormatError:
        continue
    raise SystemExit(f"{name}: input-v1 parser accepted an invalid locator")
for name, locator in {
    "size 4294967297": "external:/oversize",
    "4097-byte locator": locator_4097,
    "256-byte component": locator_256,
}.items():
    size = 4294967297 if name == "size 4294967297" else 0
    try:
        module.encode_ledger(
            [module.InputRecord(0, "tool", "read", "present", 0o644, size, digest, locator)]
        )
    except module.FormatError:
        continue
    raise SystemExit(f"{name}: input-v1 encoder accepted an invalid record")
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
        .env("TASK4_MAX_SIZE", INPUT_LEDGER_MAX_SIZE)
        .env("TASK4_OVERSIZE", INPUT_LEDGER_OVERSIZE)
        .env("TASK4_SPECIAL_CLASSES", INPUT_LEDGER_SPECIAL_CLASSES)
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
    let produce = Command::new("/usr/bin/python3")
        .args(["scripts/task4-build-subject.py", "produce"])
        .current_dir(&project)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run deferred task4 build-subject producer");
    assert_eq!(
        produce.status.code(),
        Some(77),
        "produce must remain deferred"
    );
    assert!(
        produce.stdout.is_empty(),
        "deferred producer wrote to stdout"
    );
    assert!(
        produce.stderr.len() <= 4096,
        "deferred producer diagnostics exceeded 4096 bytes"
    );
    assert_eq!(
        snapshot_exact_tree(&project),
        project_before,
        "deferred producer changed the isolated project tree"
    );
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
for name in ("reconcile_input_v1", "run_reconciled_build"):
    if callable(getattr(module, name, None)):
        raise SystemExit(f"{name} is callable on the candidate-only module")

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
    let script = repo.join("scripts/task4-build-subject.py");
    let driver = r#"
import importlib.util
import copy
import sys

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def expect_format(label, operation, absent_tids=()):
    before = {
        tid: copy.deepcopy(state.snapshot(tid=tid))
        for tid in (100, 101, 102, 103, 104, 105)
    }
    try:
        operation()
    except BaseException as exc:
        if type(exc) is not module.FormatError:
            raise SystemExit(
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}"
            ) from exc
        after = {
            tid: copy.deepcopy(state.snapshot(tid=tid))
            for tid in (100, 101, 102, 103, 104, 105)
        }
        if after != before:
            raise SystemExit(f"{label}: rejected operation mutated semantic state")
        for tid in absent_tids:
            try:
                state.snapshot(tid=tid)
            except BaseException as snapshot_exc:
                if type(snapshot_exc) is not module.FormatError:
                    raise SystemExit(
                        f"{label}: absent TID {tid} returned "
                        f"{type(snapshot_exc).__name__}: {snapshot_exc}"
                    ) from snapshot_exc
            else:
                raise SystemExit(f"{label}: rejected operation created TID {tid}")
    else:
        raise SystemExit(f"{label}: accepted invalid operation")


state = module._SemanticTraceState(
    root_tid=100,
    cwd="repo-node",
    root="root-node",
    umask=0o022,
    fds={
        3: ("source-description", False),
        4: ("tool-description", True),
    },
)
state.map_file(
    tid=100,
    start=0x1000,
    length=0x1000,
    node="source-node",
    offset=0,
    prot="r",
    shared=False,
)
state.spawn(
    parent_tid=100,
    child_tid=101,
    share_files=True,
    share_fs=True,
    share_vm=True,
    thread_group=True,
)
state.spawn(
    parent_tid=100,
    child_tid=102,
    share_files=False,
    share_fs=False,
    share_vm=False,
    thread_group=False,
)
state.spawn(
    parent_tid=100,
    child_tid=103,
    share_files=True,
    share_fs=False,
    share_vm=False,
    thread_group=False,
)
state.spawn(
    parent_tid=100,
    child_tid=104,
    share_files=False,
    share_fs=True,
    share_vm=False,
    thread_group=False,
)
state.spawn(
    parent_tid=100,
    child_tid=105,
    share_files=False,
    share_fs=False,
    share_vm=True,
    thread_group=False,
)

initial_root = {
    "tgid": 100,
    "fds": {
        3: ("source-description", False),
        4: ("tool-description", True),
    },
    "cwd": "repo-node",
    "root": "root-node",
    "umask": 0o022,
    "maps": {
        0x1000: (0x1000, "source-node", 0, "r", False),
    },
}
initial_thread = dict(initial_root, tgid=100)
initial_fork = dict(initial_root, tgid=102)
if state.snapshot(tid=100) != initial_root:
    raise SystemExit("root snapshot did not preserve the seeded state")
if state.snapshot(tid=101) != initial_thread:
    raise SystemExit("thread-like child did not initially share the seeded state")
if state.snapshot(tid=102) != initial_fork:
    raise SystemExit("fork-like child did not initially copy the seeded state")

state.dup2(tid=101, source_fd=3, target_fd=8)
state.set_cwd(tid=101, node="thread-node")
state.set_umask(tid=101, value=0o077)
state.map_file(
    tid=101,
    start=0x3000,
    length=0x1000,
    node="thread-node",
    offset=0x1000,
    prot="rw",
    shared=True,
)
state.close(tid=101, fd=4)
state.dup2(tid=103, source_fd=3, target_fd=10)
if state.snapshot(tid=100)["fds"] != {
    3: ("source-description", False),
    8: ("source-description", False),
    10: ("source-description", False),
} or state.snapshot(tid=103)["fds"] != state.snapshot(tid=100)["fds"]:
    raise SystemExit("share_files did not expose the FD mutation only through the shared table")
if state.snapshot(tid=104)["fds"] != {
    3: ("source-description", False),
    4: ("tool-description", True),
} or state.snapshot(tid=105)["fds"] != state.snapshot(tid=104)["fds"]:
    raise SystemExit("share_files mutation leaked into copied FD tables")

state.set_cwd(tid=104, node="fs-node")
if state.snapshot(tid=100)["cwd"] != "fs-node" or state.snapshot(tid=101)["cwd"] != "fs-node":
    raise SystemExit("share_fs did not expose the cwd mutation through the shared context")
if state.snapshot(tid=104)["umask"] != 0o077:
    raise SystemExit("share_fs child did not observe the shared umask")
if state.snapshot(tid=103)["cwd"] != "repo-node" or state.snapshot(tid=105)["cwd"] != "repo-node":
    raise SystemExit("share_fs mutation leaked into copied FS contexts")
if state.snapshot(tid=103)["umask"] != 0o022 or state.snapshot(tid=105)["umask"] != 0o022:
    raise SystemExit("share_fs child mutation changed copied umasks")

state.map_file(
    tid=105,
    start=0x5000,
    length=0x1000,
    node="vm-node",
    offset=0,
    prot="r",
    shared=False,
)
if 0x5000 not in state.snapshot(tid=100)["maps"] or 0x5000 not in state.snapshot(tid=101)["maps"]:
    raise SystemExit("share_vm did not expose the mapping mutation through the shared table")
if 0x5000 in state.snapshot(tid=103)["maps"] or 0x5000 in state.snapshot(tid=104)["maps"]:
    raise SystemExit("share_vm mutation leaked into copied mapping tables")

shared_state = {
    "tgid": 100,
    "fds": {
        3: ("source-description", False),
        8: ("source-description", False),
        10: ("source-description", False),
    },
    "cwd": "fs-node",
    "root": "root-node",
    "umask": 0o077,
    "maps": {
        0x1000: (0x1000, "source-node", 0, "r", False),
        0x3000: (0x1000, "thread-node", 0x1000, "rw", True),
        0x5000: (0x1000, "vm-node", 0, "r", False),
    },
}
if state.snapshot(tid=100) != shared_state:
    raise SystemExit("shared child mutations were not visible in the root")
if state.snapshot(tid=101) != shared_state:
    raise SystemExit("shared child snapshot diverged from the root")

state.dup2(tid=102, source_fd=4, target_fd=4)
if state.snapshot(tid=102)["fds"][4] != ("tool-description", True):
    raise SystemExit("dup2(fd, fd) did not preserve CLOEXEC")
state.dup2(tid=102, source_fd=4, target_fd=11)
if state.snapshot(tid=102)["fds"][11] != ("tool-description", False):
    raise SystemExit("dup2 did not clear CLOEXEC on a distinct target")
state.close(tid=102, fd=11)
state.dup2(tid=102, source_fd=3, target_fd=4)
if state.snapshot(tid=102)["fds"][4] != ("source-description", False):
    raise SystemExit("dup2 did not atomically replace an existing target")
state.dup2(tid=102, source_fd=3, target_fd=9)
state.close(tid=102, fd=4)
state.set_cwd(tid=102, node="fork-node")
state.set_umask(tid=102, value=0o027)
state.map_file(
    tid=102,
    start=0x2000,
    length=0x1000,
    node="adjacent-node",
    offset=0,
    prot="r",
    shared=False,
)
state.map_file(
    tid=102,
    start=0x7000,
    length=0x1000,
    node="fork-node",
    offset=0,
    prot="r",
    shared=False,
)

fork_state = {
    "tgid": 102,
    "fds": {
        3: ("source-description", False),
        9: ("source-description", False),
    },
    "cwd": "fork-node",
    "root": "root-node",
    "umask": 0o027,
    "maps": {
        0x1000: (0x1000, "source-node", 0, "r", False),
        0x2000: (0x1000, "adjacent-node", 0, "r", False),
        0x7000: (0x1000, "fork-node", 0, "r", False),
    },
}
if state.snapshot(tid=102) != fork_state:
    raise SystemExit("fork-like child mutations changed the expected copied state")
if state.snapshot(tid=100) != shared_state:
    raise SystemExit("fork-like child mutations leaked into the root")

expect_format(
    "unknown parent",
    lambda: state.spawn(
        parent_tid=999,
        child_tid=106,
        share_files=False,
        share_fs=False,
        share_vm=False,
        thread_group=False,
    ),
    absent_tids=(106,),
)
expect_format("unknown task", lambda: state.snapshot(tid=999), absent_tids=(999,))
expect_format(
    "duplicate child TID",
    lambda: state.spawn(
        parent_tid=100,
        child_tid=101,
        share_files=False,
        share_fs=False,
        share_vm=False,
        thread_group=False,
    ),
)
expect_format("unknown dup2 source FD", lambda: state.dup2(tid=102, source_fd=99, target_fd=10))
expect_format("closed dup2 source FD", lambda: state.dup2(tid=102, source_fd=4, target_fd=10))
expect_format("umask bool", lambda: state.set_umask(tid=100, value=True))
expect_format("umask float", lambda: state.set_umask(tid=100, value=1.0))
expect_format("umask below range", lambda: state.set_umask(tid=100, value=-1))
expect_format("umask above range", lambda: state.set_umask(tid=100, value=0o1000))
for label, start, length, offset in (
    ("zero mapping length", 0x8000, 0, 0),
    ("negative mapping length", 0x8000, -1, 0),
    ("negative mapping start", -1, 1, 0),
    ("negative mapping offset", 0x8000, 1, -1),
    ("overlap starts inside", 0x1800, 1, 0),
    ("overlap starts before and ends inside", 0x0800, 0x1000, 0),
    ("overlap encloses", 0x0800, 0x2800, 0),
):
    expect_format(
        label,
        lambda start=start, length=length, offset=offset: state.map_file(
            tid=100,
            start=start,
            length=length,
            node="bad-node",
            offset=offset,
            prot="r",
            shared=False,
        ),
    )

print("bs2b-semantic-state-topology-ok")
"#;
    let output = Command::new("/usr/bin/python3")
        .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run BS2b semantic state topology contract");
    assert!(
        output.status.success(),
        "BS2b semantic state topology contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "BS2b semantic state topology driver wrote to stderr"
    );
    assert_eq!(
        output.stdout, b"bs2b-semantic-state-topology-ok\n",
        "BS2b semantic state topology driver did not complete"
    );
}

#[test]
fn semantic_trace_v1_private_exec_event_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-build-subject.py");
    let driver = r#"
import copy
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class DictSubclass(dict):
    pass


class TupleSubclass(tuple):
    pass


def success_state():
    retained_description = object()
    closing_description = object()
    old_node = object()
    old_protection = object()
    state = module._SemanticTraceState(
        root_tid=100,
        cwd="exec-cwd",
        root="exec-root",
        umask=0o027,
        fds={3: (retained_description, False), 4: (closing_description, True)},
    )
    state.map_file(
        tid=100,
        start=0x1000,
        length=0x1000,
        node=old_node,
        offset=0x40,
        prot=old_protection,
        shared=False,
    )
    state.spawn(
        parent_tid=100,
        child_tid=101,
        share_files=True,
        share_fs=True,
        share_vm=True,
        thread_group=False,
    )
    state.spawn(
        parent_tid=100,
        child_tid=102,
        share_files=False,
        share_fs=False,
        share_vm=False,
        thread_group=False,
    )
    return state, {
        "retained_description": retained_description,
        "closing_description": closing_description,
        "old_node": old_node,
        "old_protection": old_protection,
    }


state, tokens = success_state()
replacement_node = object()
replacement_protection = object()
replacement = {
    0x2000: (0x1000, replacement_node, 0x200, replacement_protection, True),
    0x3000: (0x800, object(), 0, object(), False),
}
expected_replacement = dict(replacement)
if state.exec_event(tid=100, mappings=replacement) is not None:
    raise SystemExit("successful exec_event did not return None")
root = state.snapshot(tid=100)
peer = state.snapshot(tid=101)
copied_fs_peer = state.snapshot(tid=102)
if root["tgid"] != 100:
    raise SystemExit("exec changed the execing task TGID")
if root["fds"] != {3: (tokens["retained_description"], False)}:
    raise SystemExit("exec did not retain exactly the non-CLOEXEC FD")
if root["fds"][3][0] is not tokens["retained_description"]:
    raise SystemExit("exec did not preserve retained description identity")
if peer["fds"] != {
    3: (tokens["retained_description"], False),
    4: (tokens["closing_description"], True),
}:
    raise SystemExit("FD-sharing peer did not retain the old FD table")
if peer["fds"][3][0] is not tokens["retained_description"] or peer["fds"][4][0] is not tokens["closing_description"]:
    raise SystemExit("FD-sharing peer changed description identity")
if peer["maps"] != {
    0x1000: (0x1000, tokens["old_node"], 0x40, tokens["old_protection"], False),
}:
    raise SystemExit("VM-sharing peer did not retain the old mapping table")
if peer["maps"][0x1000][1] is not tokens["old_node"] or peer["maps"][0x1000][3] is not tokens["old_protection"]:
    raise SystemExit("VM-sharing peer changed old mapping token identity")
if root["maps"] != expected_replacement or 0x1000 in root["maps"]:
    raise SystemExit("exec did not replace the mapping table exactly")
if root["maps"][0x2000][1] is not replacement_node or root["maps"][0x2000][3] is not replacement_protection:
    raise SystemExit("exec did not preserve replacement token identity")
if root["cwd"] != "exec-cwd" or root["root"] != "exec-root" or root["umask"] != 0o027:
    raise SystemExit("exec did not preserve the FS context values")
if copied_fs_peer["cwd"] != "exec-cwd" or copied_fs_peer["root"] != "exec-root" or copied_fs_peer["umask"] != 0o027:
    raise SystemExit("copied-FS peer did not retain its initial FS values")

replacement[0x2000] = (1, object(), 0, object(), False)
replacement[0x4000] = (1, object(), 0, object(), False)
if state.snapshot(tid=100)["maps"] != expected_replacement:
    raise SystemExit("caller mutation changed the defensive replacement map copy")

state.dup2(tid=100, source_fd=3, target_fd=8)
if state.snapshot(tid=100)["fds"] != {
    3: (tokens["retained_description"], False),
    8: (tokens["retained_description"], False),
}:
    raise SystemExit("execing FD mutation was not retained")
if state.snapshot(tid=101)["fds"] != {
    3: (tokens["retained_description"], False),
    4: (tokens["closing_description"], True),
}:
    raise SystemExit("execing FD mutation crossed into the old shared table")
state.close(tid=101, fd=4)
if state.snapshot(tid=101)["fds"] != {3: (tokens["retained_description"], False)}:
    raise SystemExit("peer FD mutation was not retained")
if state.snapshot(tid=100)["fds"] != {
    3: (tokens["retained_description"], False),
    8: (tokens["retained_description"], False),
}:
    raise SystemExit("peer FD mutation crossed into the execing table")

state.map_file(
    tid=100,
    start=0x4000,
    length=0x1000,
    node=object(),
    offset=0,
    prot=object(),
    shared=False,
)
if 0x4000 not in state.snapshot(tid=100)["maps"] or 0x4000 in state.snapshot(tid=101)["maps"]:
    raise SystemExit("execing mapping mutation crossed into the old VM table")
state.map_file(
    tid=101,
    start=0x5000,
    length=0x1000,
    node=object(),
    offset=0,
    prot=object(),
    shared=True,
)
if 0x5000 not in state.snapshot(tid=101)["maps"] or 0x5000 in state.snapshot(tid=100)["maps"]:
    raise SystemExit("peer mapping mutation crossed into the execing VM table")
if 0x4000 in state.snapshot(tid=102)["maps"] or 0x5000 in state.snapshot(tid=102)["maps"]:
    raise SystemExit("mapping mutation leaked into a copied VM table")

state.set_cwd(tid=100, node="exec-cwd-after")
state.set_umask(tid=100, value=0o077)
if state.snapshot(tid=101)["cwd"] != "exec-cwd-after" or state.snapshot(tid=101)["umask"] != 0o077:
    raise SystemExit("execing FS mutation did not cross the shared FS context")
if state.snapshot(tid=102)["cwd"] != "exec-cwd" or state.snapshot(tid=102)["umask"] != 0o027:
    raise SystemExit("execing FS mutation leaked into copied FS context")
state.set_cwd(tid=101, node="peer-cwd-after")
state.set_umask(tid=101, value=0o037)
if state.snapshot(tid=100)["cwd"] != "peer-cwd-after" or state.snapshot(tid=100)["umask"] != 0o037:
    raise SystemExit("peer FS mutation did not cross the shared FS context")
if state.snapshot(tid=102)["cwd"] != "exec-cwd" or state.snapshot(tid=102)["umask"] != 0o027:
    raise SystemExit("peer FS mutation leaked into copied FS context")
if state.snapshot(tid=100)["root"] != "exec-root" or state.snapshot(tid=101)["root"] != "exec-root":
    raise SystemExit("exec changed the root FS node")


def exec_with_replacement():
    fresh, tokens = success_state()
    if fresh.exec_event(
        tid=100,
        mappings={0x2000: (1, object(), 0, object(), False)},
    ) is not None:
        raise SystemExit("fresh successful exec_event did not return None")
    return fresh, tokens


fresh, fresh_tokens = exec_with_replacement()
fresh.close(tid=100, fd=3)
if fresh.snapshot(tid=100)["fds"] != {}:
    raise SystemExit("closing the retained FD did not affect the execing table")
if fresh.snapshot(tid=101)["fds"] != {
    3: (fresh_tokens["retained_description"], False),
    4: (fresh_tokens["closing_description"], True),
}:
    raise SystemExit("execing close crossed into the old shared FD table")
fresh, fresh_tokens = exec_with_replacement()
fresh.close(tid=101, fd=4)
if fresh.snapshot(tid=101)["fds"] != {3: (fresh_tokens["retained_description"], False)}:
    raise SystemExit("closing the peer CLOEXEC FD did not affect its old table")
if fresh.snapshot(tid=100)["fds"] != {3: (fresh_tokens["retained_description"], False)}:
    raise SystemExit("peer close crossed into the execing FD table")


def accepted_mappings(label, mappings):
    fresh, _ = success_state()
    if fresh.exec_event(tid=100, mappings=mappings) is not None:
        raise SystemExit(f"{label}: successful exec_event did not return None")
    if fresh.snapshot(tid=100)["maps"] != mappings:
        raise SystemExit(f"{label}: accepted mapping payload was not installed exactly")


accepted_mappings("empty map", {})
adjacent_node = object()
adjacent_protection = object()
accepted_mappings(
    "adjacent ranges",
    {
        0x2000: (1, adjacent_node, 0, adjacent_protection, False),
        0x2001: (1, object(), 0, object(), True),
    },
)
accepted_mappings(
    "u64 final byte",
    {2**64 - 4: (4, object(), 0, object(), False)},
)


def fresh_rejection(root_tid=100):
    state = module._SemanticTraceState(
        root_tid=root_tid,
        cwd="reject-cwd",
        root="reject-root",
        umask=0o022,
        fds={3: ("retained", False), 4: ("closing", True)},
    )
    state.map_file(
        tid=root_tid,
        start=0x1000,
        length=0x1000,
        node="old-node",
        offset=0x10,
        prot="old-protection",
        shared=False,
    )
    state.spawn(
        parent_tid=root_tid,
        child_tid=101,
        share_files=True,
        share_fs=True,
        share_vm=True,
        thread_group=False,
    )
    state.spawn(
        parent_tid=root_tid,
        child_tid=102,
        share_files=False,
        share_fs=False,
        share_vm=False,
        thread_group=False,
    )
    return state


def literal_snapshot(tgid):
    return {
        "tgid": tgid,
        "fds": {3: ("retained", False), 4: ("closing", True)},
        "cwd": "reject-cwd",
        "root": "reject-root",
        "umask": 0o022,
        "maps": {0x1000: (0x1000, "old-node", 0x10, "old-protection", False)},
    }


def expected_initial(root_tid, tids):
    expected = {
        root_tid: literal_snapshot(root_tid),
        101: literal_snapshot(101),
        102: literal_snapshot(102),
    }
    if 103 in tids:
        expected[103] = literal_snapshot(root_tid)
    return {tid: expected[tid] for tid in tids}


def fd_fingerprint(table):
    if isinstance(table, dict):
        return (
            type(table),
            tuple((type(key), key, type(value), value) for key, value in table.items()),
        )
    return (type(table), repr(table))


def prove_aliases(label, state, root_tid, valid_fd):
    copied_before = copy.deepcopy(state.snapshot(tid=102))
    state.set_cwd(tid=root_tid, node=f"{label}-cwd")
    state.set_umask(tid=root_tid, value=0o071)
    state.map_file(
        tid=root_tid,
        start=0x2000,
        length=1,
        node=f"{label}-node",
        offset=0,
        prot=f"{label}-protection",
        shared=False,
    )
    shared_after = state.snapshot(tid=101)
    copied_after = state.snapshot(tid=102)
    if shared_after["cwd"] != f"{label}-cwd" or shared_after["umask"] != 0o071:
        raise SystemExit(f"{label}: shared FS alias was lost after rejection")
    if shared_after["maps"].get(0x2000) != (1, f"{label}-node", 0, f"{label}-protection", False):
        raise SystemExit(f"{label}: shared VM alias was lost after rejection")
    if copied_after["cwd"] != copied_before["cwd"] or copied_after["umask"] != copied_before["umask"]:
        raise SystemExit(f"{label}: copied FS peer observed a rejected-call probe")
    if 0x2000 in copied_after["maps"]:
        raise SystemExit(f"{label}: copied VM peer observed a rejected-call probe")
    if valid_fd:
        state.dup2(tid=root_tid, source_fd=3, target_fd=8)
        if state.snapshot(tid=101)["fds"].get(8) != ("retained", False):
            raise SystemExit(f"{label}: shared FD alias was lost after rejection")
        if 8 in state.snapshot(tid=102)["fds"]:
            raise SystemExit(f"{label}: copied FD peer observed a rejected-call probe")


def expect_format(
    label,
    operation,
    *,
    root_tid=100,
    tids=(100, 101, 102),
    inject_fd=None,
    add_sibling=False,
):
    state = fresh_rejection(root_tid=root_tid)
    if add_sibling:
        state.spawn(
            parent_tid=root_tid,
            child_tid=103,
            share_files=False,
            share_fs=False,
            share_vm=False,
            thread_group=True,
        )
    before = {
        tid: copy.deepcopy(state.snapshot(tid=tid))
        for tid in tids
    }
    if before != expected_initial(root_tid, tids):
        raise SystemExit(f"{label}: rejection fixture did not start from its literal state")
    if inject_fd is not None:
        inject_fd(state)
        corrupt_before = fd_fingerprint(state._task(root_tid)["fds"])
        try:
            injected_target = state.snapshot(tid=root_tid)
        except BaseException:
            injected_target_non_fd = None
        else:
            injected_target.pop("fds")
            injected_target_non_fd = copy.deepcopy(injected_target)
    try:
        operation(state)
    except BaseException as exc:
        if type(exc) is not module.FormatError:
            raise SystemExit(
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}"
            ) from exc
        if inject_fd is not None:
            if fd_fingerprint(state._task(root_tid)["fds"]) != corrupt_before:
                raise SystemExit(f"{label}: corrupt FD table changed after rejection")
            if injected_target_non_fd is not None:
                target_after = state.snapshot(tid=root_tid)
                target_after.pop("fds")
                if copy.deepcopy(target_after) != injected_target_non_fd:
                    raise SystemExit(f"{label}: non-FD target state changed after rejection")
            normal_tids = tuple(tid for tid in tids if tid != root_tid)
        else:
            normal_tids = tids
        for tid in normal_tids:
            after = copy.deepcopy(state.snapshot(tid=tid))
            if after != before[tid]:
                raise SystemExit(f"{label}: rejected operation mutated TID {tid}")
        prove_aliases(label, state, root_tid, inject_fd is None)
    else:
        raise SystemExit(f"{label}: accepted invalid operation")


expect_format("unknown TID", lambda state: state.exec_event(tid=999, mappings={}))
expect_format("float TID", lambda state: state.exec_event(tid=100.0, mappings={}))
expect_format(
    "boolean TID does not alias root 1",
    lambda state: state.exec_event(tid=True, mappings={}),
    root_tid=1,
    tids=(1, 101, 102),
)
expect_format(
    "nonleader exec",
    lambda state: state.exec_event(tid=103, mappings={}),
    tids=(100, 101, 102, 103),
    add_sibling=True,
)
expect_format(
    "leader with retained sibling",
    lambda state: state.exec_event(tid=100, mappings={}),
    tids=(100, 101, 102, 103),
    add_sibling=True,
)


def inject_table(table):
    def inject(state):
        state._task(100)["fds"] = table
    return inject


def inject_fd_value(key, value):
    def inject(state):
        table = dict(state._task(100)["fds"])
        table[key] = value
        state._task(100)["fds"] = table
    return inject


expect_format(
    "FD table list",
    lambda state: state.exec_event(tid=100, mappings={}),
    inject_fd=inject_table([]),
)
expect_format(
    "FD table dict subclass",
    lambda state: state.exec_event(tid=100, mappings={}),
    inject_fd=inject_table(DictSubclass({3: ("retained", False), 4: ("closing", True)})),
)
for label, key in (
    ("negative FD key", -1),
    ("boolean FD key", True),
    ("non-integer FD key", "fd"),
    ("float FD key", 5.0),
):
    expect_format(
        label,
        lambda state: state.exec_event(tid=100, mappings={}),
        inject_fd=inject_fd_value(key, ("bad", False)),
    )
for label, value in (
    ("FD value list", ["bad", False]),
    ("FD value tuple subclass", TupleSubclass(("bad", False))),
    ("FD value one-item tuple", ("bad",)),
    ("FD value three-item tuple", ("bad", False, "extra")),
    ("FD CLOEXEC integer", ("bad", 1)),
    ("FD CLOEXEC None", ("bad", None)),
):
    expect_format(
        label,
        lambda state: state.exec_event(tid=100, mappings={}),
        inject_fd=inject_fd_value(5, value),
    )


opaque_node = object()
opaque_protection = object()


def mapping(length=1, offset=0, shared=False):
    return (length, opaque_node, offset, opaque_protection, shared)


expect_format(
    "mappings dict subclass",
    lambda state: state.exec_event(tid=100, mappings=DictSubclass({})),
)
for label, payload in (
    ("mappings list", []),
    ("mapping value list", {0x2000: [1, opaque_node, 0, opaque_protection, False]}),
    ("mapping value tuple subclass", {0x2000: TupleSubclass(mapping())}),
    ("mapping value four-item tuple", {0x2000: (1, opaque_node, 0, opaque_protection)}),
    ("mapping value six-item tuple", {0x2000: (1, opaque_node, 0, opaque_protection, False, "extra")}),
):
    expect_format(label, lambda state, payload=payload: state.exec_event(tid=100, mappings=payload))
for label, start in (
    ("boolean mapping start", True),
    ("non-integer mapping start", "start"),
    ("float mapping start", 1.0),
    ("negative mapping start", -1),
):
    expect_format(label, lambda state, start=start: state.exec_event(tid=100, mappings={start: mapping()}))
for label, length in (
    ("boolean mapping length", True),
    ("non-integer mapping length", "length"),
    ("float mapping length", 1.0),
    ("zero mapping length", 0),
    ("negative mapping length", -1),
):
    expect_format(label, lambda state, length=length: state.exec_event(tid=100, mappings={0x2000: mapping(length=length)}))
for label, offset in (
    ("boolean mapping offset", True),
    ("non-integer mapping offset", "offset"),
    ("float mapping offset", 1.0),
    ("negative mapping offset", -1),
):
    expect_format(label, lambda state, offset=offset: state.exec_event(tid=100, mappings={0x2000: mapping(offset=offset)}))
for label, shared in (
    ("integer shared flag", 1),
    ("None shared flag", None),
):
    expect_format(label, lambda state, shared=shared: state.exec_event(tid=100, mappings={0x2000: mapping(shared=shared)}))
expect_format(
    "mapping start at u64 limit",
    lambda state: state.exec_event(tid=100, mappings={2**64: mapping()}),
)
expect_format(
    "mapping range overflows u64",
    lambda state: state.exec_event(tid=100, mappings={2**64 - 1: mapping(length=2)}),
)
expect_format(
    "overlapping mapping ranges",
    lambda state: state.exec_event(
        tid=100,
        mappings={0x2000: mapping(length=0x10), 0x200F: mapping()},
    ),
)

print("bs2b-semantic-exec-event-ok")
"#;
    let output = Command::new("/usr/bin/python3")
        .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run BS2b semantic exec-event contract");
    assert!(
        output.status.success(),
        "BS2b semantic exec-event contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "BS2b semantic exec-event driver wrote to stderr"
    );
    assert_eq!(
        output.stdout, b"bs2b-semantic-exec-event-ok\n",
        "BS2b semantic exec-event driver did not complete"
    );
}

#[test]
fn semantic_trace_v1_private_syscall_lifecycle_contracts() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/task4-build-subject.py");
    let driver = r#"
import copy
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("task4_build_subject", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("could not import task4 build-subject script")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class IntSubclass(int):
    pass


class StringSubclass(str):
    pass


class TupleSubclass(tuple):
    pass


PRODUCT_CATEGORIES = (
    "path",
    "fd",
    "mapping",
    "data",
    "lifecycle",
    "cwd_root",
    "exec",
    "mutation",
)
ALL_CATEGORIES = ("pure",) + PRODUCT_CATEGORIES
BASE_ARGS = (1, 2, 3, 4, 5, 6)
MAX_U64 = 2**64 - 1


def operation(category, name="C_Test", args=BASE_ARGS):
    return (name, category, args)


def new_state(root_tid=100):
    state = module._SemanticTraceState(
        root_tid=root_tid,
        cwd="initial-cwd",
        root="initial-root",
        umask=0o022,
        fds={
            3: ("shared-description", False),
            4: ("closing-description", True),
        },
    )
    state.map_file(
        tid=root_tid,
        start=0x1000,
        length=0x1000,
        node="initial-node",
        offset=0,
        prot="r",
        shared=False,
    )
    state.spawn(
        parent_tid=root_tid,
        child_tid=101,
        share_files=True,
        share_fs=True,
        share_vm=True,
        thread_group=False,
    )
    state.spawn(
        parent_tid=root_tid,
        child_tid=102,
        share_files=False,
        share_fs=False,
        share_vm=False,
        thread_group=False,
    )
    snapshots = {tid: state.snapshot(tid=tid) for tid in (root_tid, 101, 102)}
    if snapshots[root_tid]["tgid"] != root_tid or snapshots[101]["tgid"] != 101:
        raise SystemExit("peer must have a different TGID")
    if snapshots[102]["tgid"] != 102:
        raise SystemExit("copied peer must have its own TGID")
    if snapshots[root_tid] != snapshots[101] | {"tgid": root_tid}:
        raise SystemExit("shared peer fixture changed the root topology")
    return state


def begin_pair(state, root_category="pure", peer_category="pure", root_tid=100):
    root_operation = operation(root_category, "C_Root")
    peer_operation = operation(peer_category, "C_Peer")
    if state.begin_syscall(tid=root_tid, operation=root_operation) is not None:
        raise SystemExit("begin_syscall returned a non-None result")
    if state.begin_syscall(tid=101, operation=peer_operation) is not None:
        raise SystemExit("independent begin_syscall returned a non-None result")
    if state._pending[root_tid] is not root_operation:
        raise SystemExit("root pending tuple identity was not retained")
    if state._pending[101] is not peer_operation:
        raise SystemExit("peer pending tuple identity was not retained")
    return root_operation, peer_operation


def pending_refs(state):
    return {tid: state._pending[tid] for tid in state._pending}


def assert_pending(label, state, refs):
    if set(state._pending) != set(refs):
        raise SystemExit(f"{label}: pending TID set changed")
    for tid, expected in refs.items():
        if state._pending[tid] is not expected:
            raise SystemExit(f"{label}: pending tuple identity changed for TID {tid}")


def topology(state, root_tid=100):
    return {tid: copy.deepcopy(state.snapshot(tid=tid)) for tid in (root_tid, 101, 102)}


def prove_shared_aliases(label, state, root_tid=100):
    copied_before = copy.deepcopy(state.snapshot(tid=102))
    state.dup2(tid=root_tid, source_fd=3, target_fd=8)
    if state.snapshot(tid=101)["fds"].get(8) != ("shared-description", False):
        raise SystemExit(f"{label}: FD alias was not shared after rejection")
    if 8 in state.snapshot(tid=102)["fds"]:
        raise SystemExit(f"{label}: copied FD table changed after rejection")
    state.set_cwd(tid=root_tid, node=f"{label}-cwd")
    if state.snapshot(tid=101)["cwd"] != f"{label}-cwd":
        raise SystemExit(f"{label}: FS alias was not shared after rejection")
    if state.snapshot(tid=102)["cwd"] != copied_before["cwd"]:
        raise SystemExit(f"{label}: copied FS context changed after rejection")
    state.map_file(
        tid=root_tid,
        start=0x2000,
        length=1,
        node=f"{label}-node",
        offset=0,
        prot=f"{label}-protection",
        shared=False,
    )
    if 0x2000 not in state.snapshot(tid=101)["maps"]:
        raise SystemExit(f"{label}: VM alias was not shared after rejection")
    if 0x2000 in state.snapshot(tid=102)["maps"]:
        raise SystemExit(f"{label}: copied VM table changed after rejection")


def expect_rejected_state(label, state, invoke, refs=None, root_tid=100):
    if refs is None:
        refs = pending_refs(state)
    before = topology(state, root_tid)
    try:
        invoke()
    except BaseException as exc:
        if type(exc) is not module.FormatError:
            raise SystemExit(
                f"{label}: expected FormatError, got {type(exc).__name__}: {exc}"
            ) from exc
    else:
        raise SystemExit(f"{label}: accepted invalid lifecycle call")
    if topology(state, root_tid) != before:
        raise SystemExit(f"{label}: rejected lifecycle call changed topology")
    assert_pending(label, state, refs)
    prove_shared_aliases(label, state, root_tid)


def expect_rejected(
    label,
    invoke,
    root_category="pure",
    peer_category="pure",
    root_tid=100,
):
    state = new_state(root_tid)
    begin_pair(state, root_category, peer_category, root_tid)
    expect_rejected_state(label, state, lambda: invoke(state), root_tid=root_tid)


def expect_rejected_begin_tid(label, tid, root_tid=100):
    state = new_state(root_tid)
    peer_operation = operation("pure", "C_Peer")
    if state.begin_syscall(tid=101, operation=peer_operation) is not None:
        raise SystemExit(f"{label}: peer begin returned a non-None result")
    expect_rejected_state(
        label,
        state,
        lambda: state.begin_syscall(tid=tid, operation=operation("pure")),
        {101: peer_operation},
        root_tid,
    )


def expect_rejected_finish_tid(label, tid, root_tid=100):
    state = new_state(root_tid)
    root_operation, peer_operation = begin_pair(state, root_tid=root_tid)
    expect_rejected_state(
        label,
        state,
        lambda: state.finish_syscall(tid=tid, outcome="success"),
        {root_tid: root_operation, 101: peer_operation},
        root_tid,
    )


for label, tid in (
    ("unknown TID", 999),
    ("boolean false TID", False),
    ("string TID", "100"),
    ("StringSubclass TID", StringSubclass("100")),
    ("None TID", None),
    ("zero TID", 0),
    ("negative TID", -1),
):
    expect_rejected(
        label,
        lambda state, tid=tid: state.begin_syscall(
            tid=tid,
            operation=operation("pure"),
        ),
    )

expect_rejected_begin_tid("boolean true TID", True, root_tid=1)
expect_rejected_begin_tid("float TID", 100.0)
expect_rejected_begin_tid("IntSubclass TID", IntSubclass(100))

for label, tid in (
    ("orphan unknown finish TID", 999),
    ("orphan boolean false finish TID", False),
    ("orphan string finish TID", "100"),
    ("orphan StringSubclass finish TID", StringSubclass("100")),
    ("orphan None finish TID", None),
    ("orphan zero finish TID", 0),
    ("orphan negative finish TID", -1),
):
    expect_rejected_finish_tid(label, tid)
expect_rejected_finish_tid("orphan boolean true finish TID", True, root_tid=1)
expect_rejected_finish_tid("orphan float finish TID", 100.0)
expect_rejected_finish_tid("orphan IntSubclass finish TID", IntSubclass(100))


for label, bad_operation in (
    ("operation list", []),
    ("operation None", None),
    ("operation tuple subclass", TupleSubclass(operation("pure"))),
    ("operation two-item tuple", ("C_Test", "pure")),
    ("operation four-item tuple", ("C_Test", "pure", BASE_ARGS, "extra")),
):
    expect_rejected(
        label,
        lambda state, bad_operation=bad_operation: state.begin_syscall(
            tid=102,
            operation=bad_operation,
        ),
    )


for label, bad_name in (
    ("empty name", ""),
    ("None name", None),
    ("bytes name", b"C_Test"),
    ("StringSubclass name", StringSubclass("C_Test")),
):
    expect_rejected(
        label,
        lambda state, bad_name=bad_name: state.begin_syscall(
            tid=102,
            operation=operation("pure", name=bad_name),
        ),
    )


for label, bad_category in (
    ("unknown category", "unknown"),
    ("None category", None),
    ("bytes category", b"pure"),
    ("StringSubclass category", StringSubclass("pure")),
):
    expect_rejected(
        label,
        lambda state, bad_category=bad_category: state.begin_syscall(
            tid=102,
            operation=operation(bad_category),
        ),
    )


for label, bad_arguments in (
    ("arguments list", []),
    ("arguments None", None),
    ("arguments tuple subclass", TupleSubclass(BASE_ARGS)),
    ("five arguments", BASE_ARGS[:5]),
    ("seven arguments", BASE_ARGS + (7,)),
):
    expect_rejected(
        label,
        lambda state, bad_arguments=bad_arguments: state.begin_syscall(
            tid=102,
            operation=operation("pure", args=bad_arguments),
        ),
    )


for label, bad_value in (
    ("boolean argument", True),
    ("float argument", 1.0),
    ("IntSubclass argument", IntSubclass(1)),
    ("string argument", "1"),
    ("None argument", None),
    ("negative argument", -1),
    ("u64 overflow argument", 2**64),
):
    for position in range(6):
        args = list(BASE_ARGS)
        args[position] = bad_value
        expect_rejected(
            f"{label} at position {position}",
            lambda state, args=tuple(args): state.begin_syscall(
                tid=102,
                operation=operation("pure", args=args),
            ),
        )


for boundary in (0, MAX_U64):
    for position in range(6):
        args = list(BASE_ARGS)
        args[position] = boundary
        state = new_state()
        candidate = operation("pure", args=tuple(args))
        if state.begin_syscall(tid=100, operation=candidate) is not None:
            raise SystemExit("valid boundary begin returned a non-None result")
        if state._pending[100] is not candidate:
            raise SystemExit("valid boundary tuple identity was not retained")
        if state.finish_syscall(tid=100, outcome="success") is not None:
            raise SystemExit("valid boundary finish returned a non-None result")
        if 100 in state._pending:
            raise SystemExit("valid boundary pure finish did not clear pending")


state = new_state()
root_operation, peer_operation = begin_pair(state)
expect_rejected_state(
    "duplicate begin",
    state,
    lambda: state.begin_syscall(
        tid=100,
        operation=operation("pure", name="C_Replacement"),
    ),
    {100: root_operation, 101: peer_operation},
)


for category in ALL_CATEGORIES:
    state = new_state()
    root_operation, peer_operation = begin_pair(state, category, category)
    before = topology(state)
    if state.finish_syscall(tid=100, outcome="restart") is not None:
        raise SystemExit(f"{category}: restart returned a non-None result")
    if topology(state) != before:
        raise SystemExit(f"{category}: restart changed topology")
    assert_pending(
        f"{category}: restart",
        state,
        {100: root_operation, 101: peer_operation},
    )
    prove_shared_aliases(f"{category}: restart", state)
    assert_pending(
        f"{category}: restart after alias probe",
        state,
        {100: root_operation, 101: peer_operation},
    )
    if state.finish_syscall(tid=101, outcome="restart") is not None:
        raise SystemExit(f"{category}: peer restart returned a non-None result")
    assert_pending(f"{category}: peer restart", state, {100: root_operation, 101: peer_operation})


for outcome in ("success", "failure"):
    state = new_state()
    root_operation, peer_operation = begin_pair(state, "pure", "pure")
    before = topology(state)
    if state.finish_syscall(tid=100, outcome=outcome) is not None:
        raise SystemExit(f"pure {outcome}: finish returned a non-None result")
    if 100 in state._pending or state._pending.get(101) is not peer_operation:
        raise SystemExit(f"pure {outcome}: cleared the wrong pending tuple")
    if topology(state) != before:
        raise SystemExit(f"pure {outcome}: changed topology")
    prove_shared_aliases(f"pure {outcome}", state)
    assert_pending(
        f"pure {outcome}: after alias probe",
        state,
        {101: peer_operation},
    )
    if state.finish_syscall(tid=101, outcome=outcome) is not None:
        raise SystemExit(f"peer pure {outcome}: finish returned a non-None result")
    if state._pending:
        raise SystemExit(f"pure {outcome}: did not clear the matching tuple")


for category in PRODUCT_CATEGORIES:
    for outcome in ("success", "failure"):
        state = new_state()
        root_operation, peer_operation = begin_pair(state, category, category)
        expect_rejected_state(
            f"{category} {outcome}",
            state,
            lambda outcome=outcome: state.finish_syscall(tid=100, outcome=outcome),
            {100: root_operation, 101: peer_operation},
        )


for label, outcome in (
    ("unknown outcome", "unknown"),
    ("None outcome", None),
    ("StringSubclass outcome", StringSubclass("success")),
):
    expect_rejected(
        label,
        lambda state, outcome=outcome: state.finish_syscall(
            tid=100,
            outcome=outcome,
        ),
    )


state = new_state()
root_operation, peer_operation = begin_pair(state)
expect_rejected_state(
    "orphan finish",
    state,
    lambda: state.finish_syscall(tid=102, outcome="success"),
    {100: root_operation, 101: peer_operation},
)

state = new_state()
root_operation, peer_operation = begin_pair(state)
if state.finish_syscall(tid=100, outcome="success") is not None:
    raise SystemExit("initial finish before duplicate check returned a result")
expect_rejected_state(
    "duplicate finish",
    state,
    lambda: state.finish_syscall(tid=100, outcome="success"),
    {101: peer_operation},
)

print("bs2b-semantic-syscall-lifecycle-ok")
"#;
    let output = Command::new("/usr/bin/python3")
        .args(["-c", driver, script.to_str().expect("script path is UTF-8")])
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run BS2b semantic syscall lifecycle contract");
    assert!(
        output.status.success(),
        "BS2b semantic syscall lifecycle contract failed:\nstdout={:?}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "BS2b semantic syscall lifecycle driver wrote to stderr"
    );
    assert_eq!(
        output.stdout, b"bs2b-semantic-syscall-lifecycle-ok\n",
        "BS2b semantic syscall lifecycle driver did not complete"
    );
}
