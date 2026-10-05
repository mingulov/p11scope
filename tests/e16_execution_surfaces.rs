//! SPDX-License-Identifier: GPL-3.0-or-later
//! E16 execution surfaces: unprivileged userspace discovery characterization.
//!
//! One owned fixture per E16 shape, each run under the single hold protocol
//! of `tests/fixtures/e16/e16_protocol.h`: the driver resolves its endpoint,
//! publishes `ready` with the exact endpoint address, waits for `G`, makes
//! its calls, publishes `done`, and holds for `X`. Every test joins the
//! driver's independent ledger (`call` lines, in order, every `rv=0`) to the
//! discovery result, and the driver's exit status is checked on release.
//!
//! Discovery here is `Engine::discover` over the held child only (`--pid`
//! plus a `--module` hint): it builds the attach plan, it loads no BPF and
//! attaches nothing. Live counts are the privileged runner's job
//! (`scripts/qualify-e16-surfaces.py`). Identity is compared like-for-like:
//! the module's `{dev, ino}` against the child's own `/proc/<pid>/maps`
//! rendering of the endpoint mapping, never against `fstat`.
//!
//! The internal no-table vocabulary is pinned literally (`scan.rs`
//! `NO_TABLE_FOUND_MARKER` is crate-private): a rewording fails here until
//! the qualification document is updated with it.

use p11scope::attach::{BackendSelection, Scope};
use p11scope::cli::{CaptureArgs, Kind, ScopeArg};
use p11scope::discovery::engine::Engine;
use p11scope::discovery::hooks::HookRegistry;
use p11scope::process::{ProcessView, ProcessViewId};
use sha2::{Digest as _, Sha256};
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdin, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[allow(dead_code)]
mod support;

const NO_TABLE_MARKER: &str = "no function table was found in its file-backed data";
const REGISTRY_FACTORIES: [&str; 5] = [
    "C_GetFunctionList",
    "C_GetInterfaceList",
    "C_GetInterface",
    "NSC_GetFunctionList",
    "FC_GetFunctionList",
];
const PROTOCOL_DEADLINE: Duration = Duration::from_secs(20);
const TRANSCRIPT_LIMIT: usize = 64 * 1024;

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("e16-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// `gcc -std=c11 -O2 -Wall -Wextra -Werror <flags> -o <output> <inputs>`.
fn gcc(flags: &[&str], output: &Path, inputs: &[PathBuf], libraries: &[&str]) -> PathBuf {
    let mut args: Vec<OsString> = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
        .iter()
        .chain(flags)
        .map(OsString::from)
        .collect();
    args.push("-o".into());
    args.push(output.into());
    args.extend(inputs.iter().map(OsString::from));
    args.extend(libraries.iter().map(OsString::from));
    let status = Command::new("gcc").args(&args).status().unwrap();
    assert!(status.success(), "gcc {args:?}: {status}");
    output.to_path_buf()
}

fn build_shared(dir: &Path, name: &str, source: &str) -> PathBuf {
    gcc(
        &["-fPIC", "-shared", "-Wl,-z,defs"],
        &dir.join(format!("{name}.so")),
        &[fixture(&format!("e16/{source}"))],
        &[],
    )
}

/// The supported-shape control: the reviewed live-discovery provider with
/// exported tables and all three standard factories.
fn build_control(dir: &Path) -> PathBuf {
    gcc(
        &[
            "-fPIC",
            "-shared",
            "-DP11SCOPE_EXPORT_TABLES=1",
            "-Wl,-z,defs",
        ],
        &dir.join("e16-control.so"),
        &[fixture("live-discovery-provider.c")],
        &[],
    )
}

fn build_driver(dir: &Path) -> PathBuf {
    gcc(
        &[],
        &dir.join("e16-driver"),
        &[fixture("e16/e16_driver.c")],
        &["-ldl"],
    )
}

/// Static surface: the provider object is linked into the driver executable
/// without `-rdynamic`, so its factory exists but is not dynamically exported.
fn build_static_driver(dir: &Path) -> PathBuf {
    let object = gcc(
        &["-fPIC", "-c"],
        &dir.join("e16-static-provider.o"),
        &[fixture("e16/e16_static_provider.c")],
        &[],
    );
    gcc(
        &[],
        &dir.join("e16-static-driver"),
        &[fixture("e16/e16_static_driver.c"), object],
        &[],
    )
}

fn build_jit_driver(dir: &Path) -> PathBuf {
    gcc(
        &[],
        &dir.join("e16-jit-driver"),
        &[fixture("e16/e16_jit_driver.c")],
        &[],
    )
}

fn sha256_file(path: &Path) -> String {
    Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

/// Build self-check: whether `symbol` is in the object's `.dynsym` (or, with
/// `table = "--syms"`, its full `.symtab`).
fn has_symbol(path: &Path, table: &str, symbol: &str) -> bool {
    let output = Command::new("readelf")
        .args([table, "-W"])
        .arg(path)
        .output()
        .expect("readelf must run where gcc built the fixture");
    assert!(
        output.status.success(),
        "readelf {table} {}",
        path.display()
    );
    String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        line.split_whitespace()
            .nth(7)
            .is_some_and(|name| name.split('@').next() == Some(symbol))
    })
}

fn assert_dynsym(path: &Path, symbol: &str, present: bool) {
    assert_eq!(
        has_symbol(path, "--dyn-syms", symbol),
        present,
        "dynsym contract for {symbol} in {}",
        path.display()
    );
}

/// One `/proc/<pid>/maps` row, in the kernel's own rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mapping {
    start: u64,
    end: u64,
    perms: String,
    offset: u64,
    dev: (u64, u64),
    ino: u64,
    path: String,
}

/// The single executable mapping containing `address` in `pid`.
fn executable_mapping(pid: u32, address: u64) -> Mapping {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    let rows: Vec<Mapping> = maps
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.splitn(6, ' ').collect();
            let (start, end) = fields[0].split_once('-').unwrap();
            let (major, minor) = fields[3].split_once(':').unwrap();
            Mapping {
                start: u64::from_str_radix(start, 16).unwrap(),
                end: u64::from_str_radix(end, 16).unwrap(),
                perms: fields[1].to_string(),
                offset: u64::from_str_radix(fields[2], 16).unwrap(),
                dev: (
                    u64::from_str_radix(major, 16).unwrap(),
                    u64::from_str_radix(minor, 16).unwrap(),
                ),
                ino: fields[4].parse().unwrap(),
                path: fields.get(5).map_or("", |rest| rest.trim()).to_string(),
            }
        })
        .filter(|row| row.start <= address && address < row.end && row.perms.contains('x'))
        .collect();
    assert_eq!(rows.len(), 1, "0x{address:x} in pid {pid}: {maps}");
    rows.into_iter().next().unwrap()
}

fn file_offset(mapping: &Mapping, address: u64) -> u64 {
    address - mapping.start + mapping.offset
}

#[derive(Debug)]
struct Ready {
    pid: u32,
    endpoint: u64,
    image: u64,
    calls: u64,
}

fn parse_ready(line: &str) -> Ready {
    let rest = line
        .strip_prefix("P11SCOPE_E16 ready ")
        .unwrap_or_else(|| panic!("expected a ready line, got {line:?}"));
    let fields: Vec<(&str, &str)> = rest
        .split(' ')
        .map(|field| field.split_once('=').unwrap())
        .collect();
    let keys: Vec<&str> = fields.iter().map(|(key, _)| *key).collect();
    assert_eq!(
        keys,
        ["pid", "starttime", "endpoint", "image", "calls"],
        "{line}"
    );
    let hex = |value: &str| u64::from_str_radix(value.strip_prefix("0x").unwrap(), 16).unwrap();
    let starttime: u64 = fields[1].1.parse().unwrap();
    assert!(starttime > 0, "{line}");
    Ready {
        pid: fields[0].1.parse().unwrap(),
        endpoint: hex(fields[2].1),
        image: hex(fields[3].1),
        calls: fields[4].1.parse().unwrap(),
    }
}

/// A driver running under `P11SCOPE_E16_HOLD=1`, with its whole stderr
/// transcript retained for failure messages.
struct HeldDriver {
    guard: support::ChildGuard,
    stdin: Option<ChildStdin>,
    stderr: ChildStderr,
    transcript: Vec<u8>,
    ready: Ready,
    /// Provider witness lines (`P11SCOPE_E16 provider <kind> <name>`).
    witnesses: Vec<String>,
}

impl HeldDriver {
    fn spawn(program: &Path, args: &[&str]) -> Self {
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .env("P11SCOPE_E16_HOLD", "1")
            // The control provider's own marker vocabulary is not E16's.
            .env("P11SCOPE_FIXTURE_QUIET", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut guard = support::ChildGuard::new(command.spawn().unwrap());
        let stdin = guard.child.stdin.take();
        let stderr = guard.child.stderr.take().unwrap();
        let mut driver = Self {
            guard,
            stdin,
            stderr,
            transcript: Vec::new(),
            ready: Ready {
                pid: 0,
                endpoint: 0,
                image: 0,
                calls: 0,
            },
            witnesses: Vec::new(),
        };
        let line = driver.protocol_line();
        driver.ready = parse_ready(&line);
        assert_eq!(driver.ready.pid, driver.guard.child.id(), "{line}");
        driver
    }

    fn transcript(&self) -> String {
        String::from_utf8_lossy(&self.transcript).into_owned()
    }

    /// The next whole line, bounded in bytes and time.
    fn line(&mut self) -> String {
        let deadline = Instant::now() + PROTOCOL_DEADLINE;
        let mut line = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero() && self.transcript.len() < TRANSCRIPT_LIMIT,
                "driver protocol deadline or size bound: {}",
                self.transcript()
            );
            assert!(
                support::poll_fd(self.stderr.as_raw_fd(), remaining).unwrap(),
                "driver silent past the protocol deadline: {}",
                self.transcript()
            );
            let mut byte = [0];
            let read = self.stderr.read(&mut byte).unwrap();
            assert_eq!(read, 1, "driver EOF mid-protocol: {}", self.transcript());
            self.transcript.push(byte[0]);
            if byte[0] == b'\n' {
                return String::from_utf8(line).unwrap();
            }
            line.push(byte[0]);
        }
    }

    /// The next protocol line; provider witness lines are collected aside.
    fn protocol_line(&mut self) -> String {
        loop {
            let line = self.line();
            match line.strip_prefix("P11SCOPE_E16 provider ") {
                Some(witness) => self.witnesses.push(witness.to_string()),
                None => return line,
            }
        }
    }

    fn send(&mut self, byte: u8) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        stdin.write_all(&[byte]).unwrap();
        stdin.flush().unwrap();
    }

    /// Release GO and return the ledger: every call line, checked to be
    /// `label 0..n-1 rv=0` in order, closed by `done calls=n`.
    fn go(&mut self, label: &str) -> u64 {
        self.send(b'G');
        for index in 0..self.ready.calls {
            let line = self.protocol_line();
            assert_eq!(
                line,
                format!("P11SCOPE_E16 call {label} {index} rv=0"),
                "{}",
                self.transcript()
            );
        }
        let done = self.protocol_line();
        assert_eq!(
            done,
            format!("P11SCOPE_E16 done calls={}", self.ready.calls),
            "{}",
            self.transcript()
        );
        self.ready.calls
    }

    fn witness_count(&self, witness: &str) -> usize {
        self.witnesses
            .iter()
            .filter(|line| *line == witness)
            .count()
    }

    /// Wait for the exit status, bounded.
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + PROTOCOL_DEADLINE;
        loop {
            if let Some(status) = self.guard.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "driver did not exit: {}",
                self.transcript()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Release the post-call hold and require a clean exit.
    fn release(mut self) {
        self.send(b'X');
        let status = self.wait();
        let mut rest = Vec::new();
        self.stderr.read_to_end(&mut rest).unwrap();
        self.transcript.extend_from_slice(&rest);
        assert_eq!(status.code(), Some(0), "{status}: {}", self.transcript());
    }
}

fn args_for(pid: u32, hint: &Path) -> CaptureArgs {
    CaptureArgs {
        kind: Kind::Profile,
        modules: vec![hint.to_path_buf()],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: ScopeArg::Pid(pid),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        max_scan_pids: None,
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    }
}

/// `--pid <held child> --module <hint>` discovery: plan only, no BPF.
fn discover(pid: u32, hint: &Path) -> Engine {
    let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
    Engine::discover(&args_for(pid, hint), &Scope::Pid(pid), Some(view)).unwrap()
}

/// The endpoint's module is a discovered module whose `{dev, ino}` is the
/// kernel's rendering of the executing mapping and whose digest is the
/// fixture's bytes; the plan attaches the exact endpoint offset, count-only.
fn assert_endpoint_admitted(engine: &Engine, mapping: &Mapping, endpoint: u64, object: &Path) {
    let name = file_name(object);
    assert!(mapping.path.ends_with(&name), "{mapping:?}");
    let module = engine
        .discovery()
        .modules
        .iter()
        .find(|module| module.path.ends_with(&name))
        .unwrap_or_else(|| panic!("{name} must be a discovered module"));
    assert_eq!((module.dev, module.ino), (mapping.dev, mapping.ino));
    assert_eq!(module.sha256.as_deref(), Some(sha256_file(object).as_str()));
    assert!(
        module
            .objects
            .iter()
            .any(|object| matches!(object.identity_source, "mountinfo" | "stat")),
        "identity must be compared, not unpinned: {:?}",
        module.objects
    );
    let offset = file_offset(mapping, endpoint);
    let endpoint_slots: Vec<_> = engine
        .plan()
        .slots
        .iter()
        .filter(|slot| slot.object_path.ends_with(&name) && slot.file_offset == offset)
        .collect();
    assert_eq!(
        endpoint_slots.len(),
        1,
        "the executed endpoint (file offset 0x{offset:x}) is one planned slot"
    );
    assert!(
        engine
            .plan()
            .slots
            .iter()
            .all(|slot| !slot.semantic_authorized),
        "scan-found slots never authorize semantics"
    );
    assert!(
        !engine
            .plan()
            .skipped
            .iter()
            .any(|skip| { skip.subject.contains(&name) && skip.reason.contains(NO_TABLE_MARKER) }),
        "an admitted object carries no no-table record: {:?}",
        engine.plan().skipped
    );
}

/// The 104 standard-layout endpoints of one object: count-only, unnamed.
fn assert_count_only_table(engine: &Engine, object: &Path) {
    let name = file_name(object);
    let owned: Vec<_> = engine
        .plan()
        .slots
        .iter()
        .filter(|slot| slot.object_path.ends_with(&name))
        .collect();
    assert_eq!(owned.len(), 104, "standard table has 104 endpoints");
    for slot in owned {
        assert_eq!(slot.names, ["unknown"], "{slot:?}");
        assert!(!slot.semantic_authorized, "{slot:?}");
        assert_eq!(slot.descriptor_index, 0, "count-only descriptor: {slot:?}");
    }
}

/// The explicit no-table record for `object`, from the held child's own view.
fn assert_no_table_record(engine: &Engine, object: &Path) {
    let name = file_name(object);
    assert!(
        engine
            .plan()
            .skipped
            .iter()
            .any(|skip| skip.subject.contains(&name) && skip.reason.contains(NO_TABLE_MARKER)),
        "{name} is owed an explicit no-table record: {:?}",
        engine.plan().skipped
    );
    assert!(
        !engine
            .plan()
            .slots
            .iter()
            .any(|slot| slot.object_path.ends_with(&name)),
        "{name} has no table to attach"
    );
}

/// Supported-shape control: a file-backed provider with standard factories
/// and an exported table. The executed table endpoint is admitted at its
/// exact offset in the object the child maps.
#[test]
fn e16_control_file_backed_provider_is_admitted_with_validated_identity() {
    let dir = scratch("control");
    let provider = build_control(&dir);
    for factory in &REGISTRY_FACTORIES[..3] {
        assert_dynsym(&provider, factory, true);
    }
    let driver = build_driver(&dir);
    let provider_arg = provider.to_str().unwrap();
    let mut held = HeldDriver::spawn(
        &driver,
        &["table", provider_arg, "C_GetFunctionList", "0", "3"],
    );
    let mapping = executable_mapping(held.ready.pid, held.ready.endpoint);
    let engine = discover(held.ready.pid, &provider);
    assert_eq!(held.go("table[0]"), 3);
    assert_endpoint_admitted(&engine, &mapping, held.ready.endpoint, &provider);
    let name = file_name(&provider);
    assert!(
        engine
            .plan()
            .slots
            .iter()
            .all(|slot| slot.object_path.ends_with(&name)),
        "every planned slot attaches into the control provider"
    );
    held.release();
}

/// Direct exports with no factory and no table: the executed code is
/// file-backed in the hinted object, and discovery leaves it explicitly
/// unknown (a no-table record), never silently absent.
#[test]
fn e16_direct_exports_without_table_are_explicitly_unknown() {
    let dir = scratch("direct");
    let provider = build_shared(&dir, "e16-direct", "e16_direct_exports.c");
    assert_dynsym(&provider, "C_GenerateRandom", true);
    for factory in REGISTRY_FACTORIES {
        assert_dynsym(&provider, factory, false);
    }
    let driver = build_driver(&dir);
    let provider_arg = provider.to_str().unwrap();
    let mut held = HeldDriver::spawn(&driver, &["call", provider_arg, "C_GenerateRandom", "3"]);
    let mapping = executable_mapping(held.ready.pid, held.ready.endpoint);
    assert!(
        mapping.ino != 0 && mapping.path.ends_with(&file_name(&provider)),
        "the direct export executes from the provider file: {mapping:?}"
    );
    let engine = discover(held.ready.pid, &provider);
    assert_eq!(held.go("C_GenerateRandom"), 3);
    assert_eq!(held.witness_count("direct C_GenerateRandom"), 3);
    assert_no_table_record(&engine, &provider);
    held.release();
}

/// Statically linked provider: the factory exists in `.symtab` but not in
/// `.dynsym`. Scan admission is count-only and pinned to the executable's
/// identity; the missing dynamic export does not erase its table.
#[test]
fn e16_static_linked_surface_is_count_only_and_identity_pinned() {
    let dir = scratch("static");
    let driver = build_static_driver(&dir);
    assert!(has_symbol(&driver, "--syms", "C_GetFunctionList"));
    for factory in REGISTRY_FACTORIES {
        assert_dynsym(&driver, factory, false);
    }
    let mut held = HeldDriver::spawn(&driver, &["3"]);
    let mapping = executable_mapping(held.ready.pid, held.ready.endpoint);
    assert_eq!(
        mapping,
        executable_mapping(held.ready.pid, held.ready.image),
        "the static endpoint executes inside the driver image"
    );
    let engine = discover(held.ready.pid, &driver);
    assert_eq!(held.go("table[0]"), 3);
    assert_eq!(held.witness_count("static E16_C_Initialize"), 3);
    assert_count_only_table(&engine, &driver);
    assert_endpoint_admitted(&engine, &mapping, held.ready.endpoint, &driver);
    held.release();
}

/// Anonymous executable mappings are outside the file-backed candidate
/// universe: the JIT shape admits nothing. The driver image's own no-table
/// record is a separate fact about the image, not an observation of the
/// anonymous calls; that boundary is published in the qualification doc.
#[test]
fn e16_jit_anonymous_code_is_not_admitted() {
    let dir = scratch("jit");
    let driver = build_jit_driver(&dir);
    let mut held = HeldDriver::spawn(&driver, &["3"]);
    let endpoint = executable_mapping(held.ready.pid, held.ready.endpoint);
    assert!(
        endpoint.ino == 0 && endpoint.dev == (0, 0) && endpoint.path.is_empty(),
        "the trampoline is anonymous executable memory: {endpoint:?}"
    );
    let image = executable_mapping(held.ready.pid, held.ready.image);
    assert!(image.ino != 0 && image.path.ends_with(&file_name(&driver)));
    let engine = discover(held.ready.pid, &driver);
    assert_eq!(held.go("jit_trampoline"), 3);
    assert!(
        engine.plan().slots.is_empty(),
        "anonymous code must not produce attach slots: {:?}",
        engine
            .plan()
            .slots
            .iter()
            .map(|slot| &slot.object_path)
            .collect::<Vec<_>>()
    );
    assert!(
        engine
            .discovery()
            .modules
            .iter()
            .all(|module| module.ino != 0),
        "no anonymous mapping becomes a module"
    );
    assert_no_table_record(&engine, &driver);
    held.release();
}

/// A synthetic client-side HSM proxy: a standard, file-backed table whose
/// entries forward over an owned socketpair. Discovery admits the client
/// surface like the control; nothing server-side exists or is claimed.
#[test]
fn e16_synthetic_hsm_proxy_client_surface_is_admitted_like_control() {
    let dir = scratch("proxy");
    let provider = build_shared(&dir, "e16-proxy", "e16_hsm_proxy.c");
    for factory in &REGISTRY_FACTORIES[..3] {
        assert_dynsym(&provider, factory, true);
    }
    let driver = build_driver(&dir);
    let provider_arg = provider.to_str().unwrap();
    let mut held = HeldDriver::spawn(
        &driver,
        &["table", provider_arg, "C_GetFunctionList", "0", "2"],
    );
    let sockets = std::fs::read_dir(format!("/proc/{}/fd", held.ready.pid))
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.unwrap().path()).ok())
        .filter(|target| target.to_string_lossy().starts_with("socket:["))
        .count();
    assert!(
        sockets >= 2,
        "the proxy transport is a socketpair the client owns"
    );
    let mapping = executable_mapping(held.ready.pid, held.ready.endpoint);
    let engine = discover(held.ready.pid, &provider);
    assert_eq!(held.go("table[0]"), 2);
    assert_eq!(held.witness_count("proxy E16_C_Initialize"), 2);
    assert_endpoint_admitted(&engine, &mapping, held.ready.endpoint, &provider);
    let name = file_name(&provider);
    assert!(
        engine
            .plan()
            .slots
            .iter()
            .all(|slot| slot.object_path.ends_with(&name)),
        "every planned slot attaches into the proxy provider"
    );
    held.release();
}

/// A vendor-named factory publishing a standard-layout table: identity-pinned
/// count-only admission of all 104 endpoints, with no vendor semantics
/// invented from the factory name.
#[test]
fn e16_vendor_only_factory_surface_is_count_only_and_identity_pinned() {
    let dir = scratch("vendor");
    let provider = build_shared(&dir, "e16-vendor", "e16_vendor_only.c");
    assert_dynsym(&provider, "Vendor_GetFunctionList", true);
    for factory in REGISTRY_FACTORIES {
        assert_dynsym(&provider, factory, false);
    }
    let driver = build_driver(&dir);
    let provider_arg = provider.to_str().unwrap();
    let mut held = HeldDriver::spawn(
        &driver,
        &["table", provider_arg, "Vendor_GetFunctionList", "0", "3"],
    );
    let mapping = executable_mapping(held.ready.pid, held.ready.endpoint);
    let engine = discover(held.ready.pid, &provider);
    assert_eq!(held.go("table[0]"), 3);
    assert_eq!(held.witness_count("vendor E16_C_Initialize"), 3);
    assert_count_only_table(&engine, &provider);
    assert_endpoint_admitted(&engine, &mapping, held.ready.endpoint, &provider);
    held.release();
}

/// The one hold protocol fails closed: no GO byte, a wrong release byte, EOF
/// at either gate and a malformed count each exit with their documented code,
/// and without `P11SCOPE_E16_HOLD=1` the driver never reads stdin.
#[test]
fn e16_drivers_fail_closed_on_hold_protocol_violations() {
    let dir = scratch("protocol");
    let driver = build_jit_driver(&dir);
    let run = |hold: bool, input: &[u8], args: &[&str]| -> (ExitStatus, String) {
        let mut command = Command::new(&driver);
        command
            .args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if hold {
            command.env("P11SCOPE_E16_HOLD", "1");
        }
        let mut child = command.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input).unwrap();
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        (
            output.status,
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    for (hold, input, args, code, calls) in [
        (true, &b""[..], &["2"][..], 92, 0),
        (true, b"Y", &["2"], 92, 0),
        (true, b"G", &["2"], 93, 2),
        (true, b"GY", &["2"], 93, 2),
        (true, b"GX", &["2"], 0, 2),
        (false, b"", &["2"], 0, 2),
        (false, b"", &["0"], 2, 0),
        (false, b"", &["2x"], 2, 0),
        (false, b"", &[], 2, 0),
    ] {
        let (status, stderr) = run(hold, input, args);
        assert_eq!(status.signal(), None, "{stderr}");
        assert_eq!(
            status.code(),
            Some(code),
            "hold={hold} input={input:?} {args:?}: {stderr}"
        );
        assert_eq!(
            stderr.matches("P11SCOPE_E16 call jit_trampoline ").count(),
            calls,
            "{stderr}"
        );
        assert_eq!(
            stderr.contains("P11SCOPE_E16 done calls=2\n"),
            calls == 2,
            "{stderr}"
        );
    }
}
