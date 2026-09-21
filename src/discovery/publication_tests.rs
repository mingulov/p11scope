//! SPDX-License-Identifier: GPL-3.0-or-later
//! Task 1.5: publication-driven admission — heap wrappers + backend
//! forwarding (option A). Nine cases asserting exact target sets +
//! workload counts against the owned multi-wrapper fixture (plus the
//! legacy-static fixture for case 9):
//!
//! 1. `no_active_wrappers_admits_only_templates_and_published_legacy`
//! 2. `holes_admit_index_17_despite_free_0_to_3`
//! 3. `five_active_wrappers_admit_all_closure_sets`
//! 4. `two_processes_union_indices_of_one_inode`
//! 5. `direct_backend_forwarding_admits_cross_object_targets`
//! 6. `reuse_during_capture_retains_history_and_costs_exactly`
//! 7. `pre_capture_publication_stays_unresolved`
//! 8. `unknown_build_admits_by_publication_without_layout`
//! 9. `legacy_static_table_scan_manifest_and_live`
//!
//! Each case drives real factory calls in a live child (the `stage` REPL
//! or `lshold`), builds the discovery records a probe would capture from
//! the child's own printed bytes, feeds them through a real scan +
//! scripted live drain, and asserts the exact admitted slot set, table
//! inventory with provenance, budget cardinality, and oracle workload
//! coverage. Cases 7 and 9 are guards that also pass pre-fix (honest
//! refusal must survive the fix); the rest fail until heap-wrapper
//! lowering lands.
//!
//! Task 1.6 appends the broad-admission experiment cases, reusing the same
//! stage driver and oracles:
//!
//! 10. `broad_fixed_pool_admits_all_validated_templates`
//! 11. `broad_stripped_build_adds_nothing_beyond_selected`
//! 12. `broad_refuses_whole_when_validated_set_exceeds_budget`
use super::session_fixture::ScriptedSession;
use super::*;
use crate::discovery::identity::{ManifestStaleReason, pin_manifest_objects_deferred};
use p11scope_ebpf_common::{
    DISCOVERY_INTERFACES, DISCOVERY_KIND_FUNCTION_LIST_RETURN,
    DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN, DISCOVERY_NAME_NA, DISCOVERY_NAME_OTHER,
    valid_discovery_record,
};
use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
use p11scope_manifest::manifest::{
    Acquisition, FunctionRecord, ObjectRecord, ProvenanceObject, Resolution, SCHEMA, SurfaceRecord,
    SurfaceSource, Version, WalkOutcome,
};
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

const EX_ORDS: [u32; 6] = [0, 5, 13, 18, 43, 44];
const EX_NAMES: [&str; 6] = [
    "C_Initialize",
    "C_GetSlotList",
    "C_OpenSession",
    "C_Login",
    "C_Sign",
    "C_SignUpdate",
];

fn ex_ord(func: &str) -> u32 {
    EX_NAMES
        .iter()
        .position(|name| *name == func)
        .map(|pos| EX_ORDS[pos])
        .unwrap_or_else(|| panic!("unknown exercised func {func}"))
}

/// Fixture members shared by every publication test, built once.
#[derive(Clone)]
struct PubBuild {
    backend: PathBuf,
    provider: PathBuf,
    stripped: PathBuf,
    workload: PathBuf,
    ls_provider: PathBuf,
    lshold: PathBuf,
}

fn pub_build() -> PubBuild {
    static LOCK: Mutex<()> = Mutex::new(());
    static DONE: OnceLock<PubBuild> = OnceLock::new();
    let _guard = LOCK.lock().unwrap();
    DONE.get_or_init(|| {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi-wrapper");
        let legacy = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-static");
        let base =
            std::option_env!("CARGO_TARGET_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let dir = base.join(format!("pub15-shared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ls_dir = dir.join("ls");
        std::fs::create_dir_all(&ls_dir).unwrap();
        let backend = dir.join("backend.so");
        let provider = dir.join("provider.so");
        let stripped = dir.join("provider-stripped.so");
        let workload = dir.join("workload");
        let ls_provider = ls_dir.join("provider.so");
        let lshold = ls_dir.join("lshold");
        let common = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC"];
        let mut shared: Vec<std::ffi::OsString> =
            common.iter().map(std::ffi::OsString::from).collect();
        shared.extend(["-shared".into(), "-Wl,-z,defs".into(), "-o".into()]);
        let mut args = shared.clone();
        args.extend([backend.clone().into(), fixture.join("backend.c").into()]);
        pub_gcc(&args);
        let mut args = shared.clone();
        args.extend([
            provider.clone().into(),
            fixture.join("provider.c").into(),
            backend.clone().into(),
        ]);
        pub_gcc(&args);
        let mut args = shared.clone();
        args.push("-DSTRIPPED_VARIANT=1".into());
        args.extend([
            stripped.clone().into(),
            fixture.join("provider.c").into(),
            backend.clone().into(),
        ]);
        // Same detail as the oracle build: the define must precede the
        // output flag group, so splice it right after the -fPIC prefix.
        let mut ordered: Vec<std::ffi::OsString> =
            common.iter().map(std::ffi::OsString::from).collect();
        ordered.push("-DSTRIPPED_VARIANT=1".into());
        ordered.extend(["-shared".into(), "-Wl,-z,defs".into(), "-o".into()]);
        ordered.extend([
            stripped.clone().into(),
            fixture.join("provider.c").into(),
            backend.clone().into(),
        ]);
        let _ = args;
        pub_gcc(&ordered);
        let output = Command::new("strip")
            .arg("--strip-all")
            .arg(&stripped)
            .output()
            .expect("spawn strip");
        assert!(
            output.status.success(),
            "strip failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut args: Vec<std::ffi::OsString> =
            common.iter().map(std::ffi::OsString::from).collect();
        args.extend([
            "-o".into(),
            workload.clone().into(),
            fixture.join("workload.c").into(),
            "-ldl".into(),
        ]);
        pub_gcc(&args);
        let mut args = shared.clone();
        args.extend([
            ls_provider.clone().into(),
            legacy.join("provider.c").into(),
            backend.clone().into(),
        ]);
        pub_gcc(&args);
        let mut args: Vec<std::ffi::OsString> =
            common.iter().map(std::ffi::OsString::from).collect();
        args.extend([
            "-o".into(),
            lshold.clone().into(),
            legacy.join("hold.c").into(),
            "-ldl".into(),
        ]);
        pub_gcc(&args);
        PubBuild {
            backend,
            provider,
            stripped,
            workload,
            ls_provider,
            lshold,
        }
    })
    .clone()
}

fn pub_gcc(args: &[std::ffi::OsString]) {
    let rest: Vec<&std::ffi::OsStr> = args.iter().map(AsRef::as_ref).collect();
    let output = Command::new("gcc").args(&rest).output().expect("spawn gcc");
    assert!(
        output.status.success(),
        "gcc failed ({rest:?}): {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn pub_tmp(name: &str) -> PathBuf {
    let base =
        std::option_env!("CARGO_TARGET_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let dir = base.join(format!("pub15-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One printed table: version word plus every entry pointer + symbol.
#[derive(Debug, Clone)]
struct TablePrint {
    index: i64,
    addr: u64,
    major: u8,
    minor: u8,
    nentry: usize,
    entries: Vec<(u64, String)>,
}

#[derive(Debug)]
struct PublishBlock {
    legacy: TablePrint,
    elements: Vec<TablePrint>,
}

fn parse_hex_addr(text: &str) -> u64 {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    assert_ne!(text, "(nil)", "fixture tables never print NULL addresses");
    u64::from_str_radix(digits, 16).expect("hex address")
}

fn parse_keyed(line: &str, key: &str) -> String {
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(key))
        .unwrap_or_else(|| panic!("{line:?} has no {key} field"))
        .to_string()
}

fn read_table_print(lines: &mut impl Iterator<Item = String>) -> TablePrint {
    let head = lines.next().expect("TABLE line");
    assert!(head.starts_with("TABLE "), "expected TABLE, got {head:?}");
    let index = parse_keyed(&head, "index=").parse().expect("index");
    let addr = parse_hex_addr(&parse_keyed(&head, "addr="));
    let major = parse_keyed(&head, "major=").parse().expect("major");
    let minor = parse_keyed(&head, "minor=").parse().expect("minor");
    let nentry = parse_keyed(&head, "nentry=").parse().expect("nentry");
    let mut entries = Vec::with_capacity(nentry);
    for ord in 0..nentry {
        let line = lines.next().expect("E line");
        assert!(line.starts_with("E "), "expected E, got {line:?}");
        let got: usize = parse_keyed(&line, "ord=").parse().expect("ord");
        assert_eq!(got, ord, "entries print in ordinal order");
        entries.push((
            parse_hex_addr(&parse_keyed(&line, "addr=")),
            parse_keyed(&line, "sym="),
        ));
    }
    TablePrint {
        index,
        addr,
        major,
        minor,
        nentry,
        entries,
    }
}

/// A live `workload stage` child: real factory calls, printed bytes.
struct StageChild {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<std::process::ChildStdout>,
    pid: u32,
}

impl StageChild {
    fn spawn(workload: &Path, provider: &Path) -> Self {
        let mut child = Command::new(workload)
            .arg(provider)
            .arg("stage")
            .arg("0")
            .arg("/dev/null")
            .arg("/dev/null")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn workload stage");
        let stdin = child.stdin.take().expect("piped stdin");
        let mut out = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut hello = String::new();
        out.read_line(&mut hello).expect("STAGE hello");
        let pid: u32 = parse_keyed(hello.trim(), "pid=")
            .parse()
            .expect("stage pid");
        assert_eq!(pid, child.id(), "staged pid must be the child");
        Self {
            child,
            stdin,
            out,
            pid,
        }
    }

    fn command(&mut self, line: &str) {
        self.stdin
            .write_all(line.as_bytes())
            .expect("write stage command");
        self.stdin.write_all(b"\n").expect("write newline");
        self.stdin.flush().expect("flush stage command");
    }

    fn line(&mut self) -> String {
        let mut text = String::new();
        let read = self.out.read_line(&mut text).expect("read stage reply");
        assert!(read > 0, "stage child exited mid-protocol");
        assert!(!text.starts_with("ERROR"), "stage child reported: {text:?}");
        text.trim_end().to_string()
    }

    fn alloc(&mut self, fwd: i32, fail: i32) -> (i64, u64) {
        self.command(&format!("A {fwd} {fail}"));
        let reply = self.line();
        assert!(reply.starts_with("ALLOC "), "expected ALLOC, got {reply:?}");
        (
            parse_keyed(&reply, "idx=").parse().expect("idx"),
            parse_hex_addr(&parse_keyed(&reply, "table=")),
        )
    }

    fn free(&mut self, idx: i64) {
        self.command(&format!("F {idx}"));
        let reply = self.line();
        assert_eq!(reply, format!("FREED idx={idx}"));
    }

    fn publish(&mut self) -> PublishBlock {
        self.command("P");
        let begin = self.line();
        assert!(
            begin.starts_with("PUBLISH begin "),
            "expected PUBLISH begin, got {begin:?}"
        );
        let count: usize = parse_keyed(&begin, "count=").parse().expect("count");
        let mut raw = Vec::new();
        loop {
            let text = self.line();
            if text == "PUBLISH end" {
                break;
            }
            raw.push(text);
        }
        let mut lines = raw.into_iter();
        let legacy = read_table_print(&mut lines);
        assert_eq!(legacy.index, -1, "first publish is C_GetFunctionList");
        let mut elements = Vec::new();
        for _ in 0..count {
            elements.push(read_table_print(&mut lines));
        }
        assert!(lines.next().is_none(), "publish block has no tail");
        assert_eq!(elements.len(), count);
        // The list's legacy element and the direct C_GetFunctionList return
        // are the same table, printed twice.
        let listed = elements
            .iter()
            .find(|table| table.index == -1)
            .expect("list carries the legacy element");
        assert_eq!(listed.addr, legacy.addr, "one legacy table, two routes");
        assert_eq!(listed.entries, legacy.entries);
        PublishBlock { legacy, elements }
    }

    fn backend_addrs(&mut self) -> std::collections::BTreeMap<u32, u64> {
        self.command("B");
        let mut addrs = std::collections::BTreeMap::new();
        loop {
            let text = self.line();
            if text == "BACKEND end" {
                break;
            }
            assert!(
                text.starts_with("BACKEND "),
                "expected BACKEND, got {text:?}"
            );
            addrs.insert(
                parse_keyed(&text, "ord=").parse().expect("ord"),
                parse_hex_addr(&parse_keyed(&text, "addr=")),
            );
        }
        assert_eq!(addrs.len(), 6, "six backend entries");
        addrs
    }

    /// The dormant template pool, or `None` when the build hides it.
    fn templates(&mut self) -> Option<Vec<TablePrint>> {
        self.command("T");
        let first = self.line();
        if first == "TEMPLATE unknown" {
            return None;
        }
        let mut raw = vec![first];
        loop {
            let text = self.line();
            if text == "TEMPLATE end" {
                break;
            }
            raw.push(text);
        }
        let mut lines = raw.into_iter();
        let mut tables = Vec::new();
        for idx in 0..64 {
            let table = read_table_print(&mut lines);
            assert_eq!(table.index, idx, "templates print pool order");
            tables.push(table);
        }
        assert!(lines.next().is_none(), "template block has no tail");
        Some(tables)
    }
}

impl Drop for StageChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A live `lshold` child for the legacy-static provider.
struct LsChild {
    child: Child,
    stdin: ChildStdin,
    publish: PublishBlock,
    calls: Vec<(u32, u64)>,
    pid: u32,
}

impl LsChild {
    fn spawn(lshold: &Path, provider: &Path, log: &Path, ords: &str) -> Self {
        let mut child = Command::new(lshold)
            .arg(provider)
            .arg(log)
            .arg(ords)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn lshold");
        let stdin = child.stdin.take().expect("piped stdin");
        let mut out = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut next = move || {
            let mut text = String::new();
            let read = out.read_line(&mut text).expect("read lshold reply");
            assert!(read > 0, "lshold exited mid-protocol");
            text.trim_end().to_string()
        };
        let hello = next();
        let pid: u32 = parse_keyed(&hello, "pid=").parse().expect("lshold pid");
        assert_eq!(pid, child.id(), "held pid must be the child");
        let begin = next();
        assert_eq!(begin, "PUBLISH begin count=1");
        let mut raw = Vec::new();
        loop {
            let text = next();
            if text == "PUBLISH end" {
                break;
            }
            raw.push(text);
        }
        let mut lines = raw.into_iter();
        let legacy = read_table_print(&mut lines);
        assert_eq!(legacy.index, -1);
        assert!(lines.next().is_none());
        let mut calls = Vec::new();
        loop {
            let text = next();
            if text == "READY" {
                break;
            }
            assert!(text.starts_with("CALL "), "expected CALL, got {text:?}");
            calls.push((
                parse_keyed(&text, "ord=").parse().expect("ord"),
                parse_keyed(&text, "rv=").parse().expect("rv"),
            ));
        }
        Self {
            child,
            stdin,
            publish: PublishBlock {
                legacy,
                elements: Vec::new(),
            },
            calls,
            pid,
        }
    }

    fn release(mut self) {
        let _ = self.stdin.write_all(b"X\n");
        let _ = self.stdin.flush();
        let status = self.child.wait().expect("wait lshold");
        assert!(status.success(), "lshold must exit cleanly");
    }
}

impl Drop for LsChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Hand-rolled `/proc/<pid>/maps` parse: the tests' independent
/// address-to-file-offset authority (no engine maps code on this path).
#[derive(Debug, Clone)]
struct MapLite {
    start: u64,
    end: u64,
    perms: String,
    offset: u64,
    dev_major: u64,
    dev_minor: u64,
    ino: u64,
    path: String,
}

impl MapLite {
    fn snapshot(pid: u32) -> Vec<Self> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("read maps");
        let mut maps = Vec::new();
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let range = fields.next().expect("maps range");
            let perms = fields.next().expect("maps perms").to_string();
            let offset = u64::from_str_radix(fields.next().expect("maps offset"), 16).expect("off");
            let dev = fields.next().expect("maps dev");
            let (major, minor) = dev.split_once(':').expect("dev major:minor");
            let ino = fields.next().expect("maps ino").parse().expect("ino");
            let path = fields.next().unwrap_or_default().to_string();
            let (start, end) = range.split_once('-').expect("start-end");
            maps.push(Self {
                start: u64::from_str_radix(start, 16).expect("start"),
                end: u64::from_str_radix(end, 16).expect("end"),
                perms,
                offset,
                dev_major: u64::from_str_radix(major, 16).expect("major"),
                dev_minor: u64::from_str_radix(minor, 16).expect("minor"),
                ino,
                path,
            });
        }
        assert!(!maps.is_empty(), "maps snapshot is never empty");
        maps
    }

    fn containing(maps: &[Self], addr: u64) -> Option<&Self> {
        maps.iter()
            .find(|mapping| mapping.start <= addr && addr < mapping.end)
    }

    /// File offset + identity for a file-backed address.
    fn file_target(maps: &[Self], addr: u64) -> (String, u64, (u64, u64, u64)) {
        let mapping =
            Self::containing(maps, addr).unwrap_or_else(|| panic!("{addr:#x} is unmapped"));
        assert_ne!(mapping.ino, 0, "{addr:#x} must be file-backed");
        assert_eq!(
            mapping.perms.as_bytes().first(),
            Some(&b'r'),
            "{addr:#x} must be readable"
        );
        assert!(
            !mapping.path.is_empty() && !mapping.path.starts_with('['),
            "{addr:#x} must have a usable path, not {:?}",
            mapping.path
        );
        (
            mapping.path.clone(),
            mapping.offset + (addr - mapping.start),
            (mapping.dev_major, mapping.dev_minor, mapping.ino),
        )
    }
}

/// What the probe captures for a `C_GetFunctionList` return: the full
/// table prefix. `entries` are the child's own printed entry addresses.
fn gfl_record(pid: u32, table: &TablePrint, hooks: &HookRegistry) -> DiscoveryRecord {
    assert!(table.nentry <= p11scope_ebpf_common::DISCOVERY_POINTERS);
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_FUNCTION_LIST_RETURN;
    record.pid_tgid = (u64::from(pid) << 32) | u64::from(pid);
    record.hook_ts_ns = crate::attach::monotonic_ns().unwrap_or(0);
    record.table_ptr = table.addr;
    record.version_major = table.major;
    record.version_minor = table.minor;
    record.symbol_id = hooks.id("C_GetFunctionList").expect("builtin hook id");
    record.name_class = DISCOVERY_NAME_NA;
    for (slot, (addr, _)) in record.pointers.iter_mut().zip(table.entries.iter()) {
        *slot = *addr;
    }
    record.pointers_attempted = u8::try_from(table.nentry).expect("nentry fits");
    record.completed_prefix = record.pointers_attempted;
    record.usable_n = record.pointers_attempted;
    assert!(
        valid_discovery_record(&record),
        "synthetic gfl record must satisfy the transport contract"
    );
    record
}

/// What the probe captures for one `C_GetInterfaceList` element with a
/// nonstandard name: the table address only, never the bytes (the
/// transport contract forbids a prefix unless the name is exact-standard).
fn element_record(
    pid: u32,
    table_addr: u64,
    element_index: u8,
    announced: u32,
    hooks: &HookRegistry,
) -> DiscoveryRecord {
    assert!(element_index < DISCOVERY_INTERFACES);
    assert!(announced > u32::from(element_index));
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN;
    record.pid_tgid = (u64::from(pid) << 32) | u64::from(pid);
    record.hook_ts_ns = crate::attach::monotonic_ns().unwrap_or(0);
    record.table_ptr = table_addr;
    record.interface_index = element_index;
    record.announced_count = announced;
    record.name_class = DISCOVERY_NAME_OTHER;
    record.symbol_id = hooks.id("C_GetInterfaceList").expect("builtin hook id");
    assert!(
        valid_discovery_record(&record),
        "synthetic element record must satisfy the transport contract"
    );
    record
}

/// Element records for one publish block in list order: wrappers in
/// ascending index order, the legacy element last.
fn publish_records(pid: u32, publish: &PublishBlock, hooks: &HookRegistry) -> Vec<DiscoveryRecord> {
    let announced = u32::try_from(publish.elements.len()).expect("few elements");
    publish
        .elements
        .iter()
        .enumerate()
        .map(|(position, table)| {
            element_record(
                pid,
                table.addr,
                u8::try_from(position).expect("few elements"),
                announced,
                hooks,
            )
        })
        .collect()
}

/// A real scan of the live children, no manifests: initial discovery.
fn engine_over_pids(pids: &[u32]) -> Engine {
    engine_over_pids_broad(pids, false)
}

/// Task 1.6: same scan with broad admission enabled — the pool pass runs at
/// scan time and the merge lifts the heuristic cap with fit-or-refuse-whole.
fn engine_over_pids_broad(pids: &[u32], broad_admit: bool) -> Engine {
    let mut engine = scan_engine_over_pids(pids, broad_admit);
    rebuild_discovered(&mut engine).expect("rebuild after scan");
    engine
}

/// Scan without the rebuild, so the A2 probe can observe a broad total
/// refusal as evidence instead of an expect panic.
fn scan_engine_over_pids(pids: &[u32], broad_admit: bool) -> Engine {
    let hooks = HookRegistry::builtin();
    let mut engine = Engine::empty();
    engine.hooks = hooks.clone();
    engine.broad_admit = broad_admit;
    for pid in pids {
        let id = engine.allocate_view_id().expect("view id");
        let view = ProcessView::open(id, *pid).expect("retain child view");
        engine.retain_view_id(id).expect("retain view id");
        let mut counters = DiscoveryCounters::default();
        let broad = engine.broad_admit;
        let (found, pins) =
            scan_and_pin(&view, &[], &hooks, &mut engine.budget, &mut counters, broad)
                .expect("scan live child");
        engine.scan_inputs.insert(
            view.id(),
            ScanInput {
                modules: found,
                pins,
                counters,
            },
        );
        engine.views.push(view);
    }
    engine
}

fn drain_records(engine: &mut Engine, records: Vec<DiscoveryRecord>) -> ScriptedSession {
    let mut session = ScriptedSession::with_records(records, 0);
    engine
        .drain_discovery_from(&mut session)
        .expect("live drain applies");
    session
}

/// `(object path, file offset)` for every plan slot, via pinned summaries.
fn slot_targets(engine: &Engine) -> std::collections::BTreeSet<(String, u64)> {
    engine
        .plan()
        .slots
        .iter()
        .map(|slot| {
            let summary = engine
                .pinned()
                .summary(slot.object)
                .expect("slot object is pinned");
            (summary.path.to_string(), slot.file_offset)
        })
        .collect()
}

/// Pinned `(device, inode)` per slot object path.
fn slot_object_keys(engine: &Engine) -> std::collections::BTreeMap<String, (u64, u64, u64)> {
    let mut keys = std::collections::BTreeMap::new();
    for slot in &engine.plan().slots {
        let summary = engine
            .pinned()
            .summary(slot.object)
            .expect("slot object is pinned");
        keys.insert(
            summary.path.to_string(),
            (
                summary.key.device.major,
                summary.key.device.minor,
                summary.key.inode,
            ),
        );
    }
    keys
}

/// Expected `(object path, file offset)` from printed tables + maps.
fn printed_targets(
    maps: &[MapLite],
    tables: &[TablePrint],
) -> std::collections::BTreeSet<(String, u64)> {
    tables
        .iter()
        .flat_map(|table| &table.entries)
        .map(|(addr, _)| {
            let (path, offset, _) = MapLite::file_target(maps, *addr);
            (path, offset)
        })
        .collect()
}

/// Mirrors `decoded_occurrence_count`'s target arm: occurrence-distinct
/// `(name, object, offset)` records across pieces.
fn occurrence_distinct(pieces: &[Vec<(String, String, u64)>]) -> usize {
    let mut seen = std::collections::BTreeSet::new();
    for piece in pieces {
        let mut occurrences = std::collections::BTreeMap::new();
        for record in piece {
            let occurrence = occurrences.entry(record.clone()).or_insert(0usize);
            seen.insert((record.0.clone(), record.1.clone(), record.2, *occurrence));
            *occurrence += 1;
        }
    }
    seen.len()
}

/// Ordinal labels for one printed table, via the shared catalog — the
/// same authority the scan decoder names entries with.
fn table_piece(table: &TablePrint, maps: &[MapLite]) -> Vec<(String, String, u64)> {
    table
        .entries
        .iter()
        .enumerate()
        .map(|(ord, (addr, _))| {
            let (path, offset, _) = MapLite::file_target(maps, *addr);
            (
                pkcs11_module::function_name(ord)
                    .expect("catalog covers every fixture ordinal")
                    .to_string(),
                path,
                offset,
            )
        })
        .collect()
}

/// Run one standard workload scenario; returns the parsed oracle JSON.
fn run_oracle(
    build: &PubBuild,
    provider: &Path,
    scenario: &str,
    seed: u64,
    dir: &Path,
) -> serde_json::Value {
    let log = dir.join(format!("{scenario}.log"));
    let oracle_path = dir.join(format!("{scenario}.oracle.json"));
    let output = Command::new(&build.workload)
        .arg(provider)
        .arg(scenario)
        .arg(seed.to_string())
        .arg(&log)
        .arg(&oracle_path)
        .output()
        .expect("spawn workload");
    assert!(
        output.status.success(),
        "workload {scenario} seed {seed} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(&oracle_path).expect("read oracle");
    serde_json::from_str(&text).expect("parse oracle JSON")
}

/// Parsed oracle call: `(layer, func, idx, via, rv)`.
fn oracle_calls(oracle: &serde_json::Value) -> Vec<(String, String, u64, String, u64)> {
    oracle["expected"]
        .as_array()
        .expect("oracle expected")
        .iter()
        .map(|line| {
            let parts: Vec<&str> = line.as_str().expect("line").split_whitespace().collect();
            assert_eq!(parts.len(), 7, "log line shape");
            (
                parts[2].to_string(),
                parts[3].to_string(),
                parts[4].parse().expect("idx"),
                parts[5].to_string(),
                parts[6].parse().expect("rv"),
            )
        })
        .collect()
}

/// Fixture-contract symbol for one wrapper-table entry: the name the
/// stage print must carry (non-stripped builds only).
fn contract_sym(nentry: usize, ord: usize, idx: i64, fwd_mask: i32) -> String {
    if nentry == 68 {
        return "mw_legacy".to_string();
    }
    assert_eq!(nentry, 104);
    if ord == 65 {
        return "mw_shared_status".to_string();
    }
    if ord == 66 {
        return "mw_shared_cancel".to_string();
    }
    if let Some(ex) = EX_ORDS
        .iter()
        .position(|candidate| *candidate as usize == ord)
    {
        if fwd_mask & (1 << ex) != 0 {
            return format!("mw_backend_{ord}");
        }
        return format!("mw_closure_{ord}_{idx}");
    }
    "mw_shared".to_string()
}

/// Every printed entry carries its contract symbol: the print path and
/// the provider agree exactly. `fwds` maps wrapper index to fwd mask.
fn assert_contract_syms(publish: &PublishBlock, fwds: &[(i64, i32)]) {
    for table in std::iter::once(&publish.legacy).chain(publish.elements.iter()) {
        let fwd = fwds
            .iter()
            .find(|(idx, _)| *idx == table.index)
            .map_or(0, |(_, fwd)| *fwd);
        for (ord, (_, sym)) in table.entries.iter().enumerate() {
            assert_eq!(
                *sym,
                contract_sym(table.nentry, ord, table.index, fwd),
                "table {} ord {ord}",
                table.index
            );
        }
    }
}

/// Coverage split: wrapper-layer calls plus direct backend calls must
/// land on admitted slots; nested backend calls are out of publication
/// reach (no published table names them) and are reported separately so
/// the gap is explicit, never silent.
struct Coverage {
    admitted: std::collections::BTreeSet<(String, u64)>,
    nested_backend: std::collections::BTreeSet<(String, u64)>,
}

fn split_coverage(
    maps: &[MapLite],
    publish: &PublishBlock,
    backends: &std::collections::BTreeMap<u32, u64>,
    oracle: &serde_json::Value,
) -> Coverage {
    let by_index: std::collections::BTreeMap<i64, &TablePrint> = publish
        .elements
        .iter()
        .map(|table| (table.index, table))
        .collect();
    let mut covered = Coverage {
        admitted: std::collections::BTreeSet::new(),
        nested_backend: std::collections::BTreeSet::new(),
    };
    for (layer, func, idx, via, rv) in oracle_calls(oracle) {
        assert_eq!(rv, 0, "none of the nine scenarios fails a call");
        assert_ne!(layer, "shared", "no shared-layer calls here");
        assert_ne!(layer, "legacy", "legacy is never called here");
        let table = by_index
            .get(&(idx as i64))
            .unwrap_or_else(|| panic!("oracle calls unpublished index {idx}"));
        let ord = ex_ord(&func);
        let (addr, _) = &table.entries[ord as usize];
        // Forwarding is an address fact (backend.so mapping), never a
        // symbol fact: stripped builds print no symbols.
        let forwarded = MapLite::containing(maps, *addr)
            .unwrap_or_else(|| panic!("{func} {idx}: entry unmapped"))
            .path
            .ends_with("backend.so");
        match layer.as_str() {
            "wrapper" => {
                assert!(!forwarded, "{func} {idx}: wrapper calls never forward");
                assert_eq!(via, "direct");
                let (path, offset, _) = MapLite::file_target(maps, *addr);
                covered.admitted.insert((path, offset));
            }
            "backend" if via == "direct" => {
                assert!(forwarded, "{func} {idx}: direct backend is forwarded");
                let (path, offset, _) = MapLite::file_target(maps, *addr);
                covered.admitted.insert((path, offset));
            }
            "backend" => {
                assert_eq!(via, "nested");
                assert!(!forwarded, "{func} {idx}: nested backend is not forwarded");
                let addr = backends.get(&ord).expect("backend addr");
                let (path, offset, _) = MapLite::file_target(maps, *addr);
                covered.nested_backend.insert((path, offset));
            }
            other => panic!("unknown layer {other}"),
        }
    }
    covered
}

/// Full-lifetime costing assertions shared by every case: the whole
/// bracket stays inside its independent ceilings, and wall time is
/// measured, never assumed.
fn assert_costing(engine: &Engine, wall: std::time::Duration, label: &str) {
    let limits = engine.budget.limits();
    assert_eq!(
        limits.total_bytes,
        512 * 1024 * 1024,
        "{label}: capture cap"
    );
    assert!(
        engine.budget.attempted_io_bytes() < limits.total_bytes,
        "{label}: I/O {} bytes inside the capture cap",
        engine.budget.attempted_io_bytes()
    );
    assert!(
        engine.budget.work_units_count() <= 16 * 1024 * 1024,
        "{label}: work inside the 16 Mi ceiling"
    );
    assert!(
        engine.budget.table_candidates_count() <= 512,
        "{label}: table candidates inside the 512 ceiling"
    );
    assert!(
        engine.budget.decoded_table_entries_count() <= 512 * 104,
        "{label}: decoded entries inside the 53,248 ceiling"
    );
    assert!(
        engine.budget.interface_records_count() <= 512,
        "{label}: interface records inside the 512 ceiling"
    );
    assert!(
        wall < std::time::Duration::from_secs(120),
        "{label}: wall time {wall:?} is bounded"
    );
    eprintln!(
        "{label}: io={} work={} candidates={} entries={} interfaces={} wall={wall:?}",
        engine.budget.attempted_io_bytes(),
        engine.budget.work_units_count(),
        engine.budget.table_candidates_count(),
        engine.budget.decoded_table_entries_count(),
        engine.budget.interface_records_count(),
    );
}

/// Count-only treatment: no publication evidence ever authorizes
/// semantics on its own.
fn assert_count_only(engine: &Engine) {
    assert!(
        engine
            .plan()
            .slots
            .iter()
            .all(|slot| !slot.semantic_authorized && slot.descriptor_index == 0),
        "publication admits count-only targets, never semantic authority"
    );
}

/// Templates the file-backed sweep can see: printed pool tables whose
/// full extent (version word plus every entry slot) sits in file-backed
/// mappings. A version word alone proves nothing — decode needs all
/// 104 pointers in-snapshot.
fn file_backed_templates<'a>(maps: &[MapLite], templates: &'a [TablePrint]) -> Vec<&'a TablePrint> {
    templates
        .iter()
        .filter(|table| {
            let extent = table.addr..table.addr + 8 + 8 * table.nentry as u64;
            extent
                .clone()
                .all(|addr| MapLite::containing(maps, addr).is_some_and(|mapping| mapping.ino != 0))
        })
        .collect()
}

/// Expected slot names from printed claimants. Mirrors the plan merge:
/// every claimant's ordinal label, `unknown` only when no claimant
/// authorizes the target.
fn expected_slot_names(
    maps: &[MapLite],
    claimants: &[(&TablePrint, bool)],
) -> std::collections::BTreeMap<(String, u64), Vec<String>> {
    let mut names: std::collections::BTreeMap<(String, u64), std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for (table, authorized) in claimants {
        for (ord, (addr, _)) in table.entries.iter().enumerate() {
            let (path, offset, _) = MapLite::file_target(maps, *addr);
            let label = if *authorized {
                pkcs11_module::function_name(ord)
                    .expect("catalog covers every fixture ordinal")
                    .to_string()
            } else {
                "unknown".to_string()
            };
            names.entry((path, offset)).or_default().insert(label);
        }
    }
    names
        .into_iter()
        .map(|(target, mut labels)| {
            if labels.len() > 1 {
                labels.remove("unknown");
            }
            (target, labels.into_iter().collect())
        })
        .collect()
}

fn actual_slot_names(engine: &Engine) -> std::collections::BTreeMap<(String, u64), Vec<String>> {
    engine
        .plan()
        .slots
        .iter()
        .map(|slot| {
            let summary = engine
                .pinned()
                .summary(slot.object)
                .expect("slot object is pinned");
            (
                (summary.path.to_string(), slot.file_offset),
                slot.names.clone(),
            )
        })
        .collect()
}

/// `(address, version, live_return, manifest_supported)` for every
/// unlocated (heap/anonymous) table instance, sorted by address.
fn live_instances(engine: &Engine) -> Vec<(u64, (u8, u8), bool, bool)> {
    let mut live: Vec<(u64, (u8, u8), bool, bool)> = engine
        .modules
        .iter()
        .flat_map(|module| &module.scanned.tables)
        .filter(|table| table.file_offset.is_none())
        .map(|table| {
            (
                table.address,
                table.version,
                table.live_return,
                table.manifest_supported,
            )
        })
        .collect();
    live.sort();
    live
}

fn sorted_live(
    mut instances: Vec<(u64, (u8, u8), bool, bool)>,
) -> Vec<(u64, (u8, u8), bool, bool)> {
    instances.sort();
    instances
}

/// Instance fidelity: exactly one admitted instance carries the
/// printed table's address with exactly its normalized entries — never
/// stale bytes after address reuse, never a lookalike template's.
fn assert_instance_entries(
    engine: &Engine,
    maps: &[MapLite],
    printed: &TablePrint,
    expect_live_return: bool,
) {
    let expected: Vec<(String, u64)> = printed
        .entries
        .iter()
        .map(|(addr, _)| {
            let (path, offset, _) = MapLite::file_target(maps, *addr);
            (path, offset)
        })
        .collect();
    let mut matches = engine
        .modules
        .iter()
        .flat_map(|module| &module.scanned.tables)
        .filter(|table| {
            table.address == printed.addr
                && table.version == (printed.major, printed.minor)
                && table.live_return == expect_live_return
                && table.null_entries.is_empty()
                && table.unpinned.is_empty()
                && table.entries.len() == expected.len()
                && table
                    .entries
                    .iter()
                    .zip(&expected)
                    .all(|(entry, (path, offset))| {
                        &entry.object_path == path && entry.file_offset == *offset
                    })
        });
    assert!(
        matches.next().is_some(),
        "no admitted instance carries {:#x} with the printed entries",
        printed.addr
    );
    assert!(
        matches.next().is_none(),
        "the printed content admits exactly once at {:#x}",
        printed.addr
    );
}

/// Plan linkage per template version-word offset: pins the sweep's own
/// interface triples (1.3 behavior) apart from publication evidence.
fn template_linkage(engine: &Engine) -> std::collections::BTreeMap<u64, &'static str> {
    engine
        .plan()
        .modules
        .iter()
        .flat_map(|module| &module.tables)
        .filter(|table| table.version == (3, 2) && table.entries == 104)
        .filter_map(|table| table.file_offset.map(|offset| (offset, table.linkage)))
        .collect()
}

/// Case 1: no active wrappers. Only the legacy table is published; the
/// heap path stays empty, templates stay heuristic inventory, and the
/// anonymous-but-published legacy table admits with authorized names.
#[test]
fn no_active_wrappers_admits_only_templates_and_published_legacy() {
    let build = pub_build();
    let dir = pub_tmp("t1-none");
    let mut stage = StageChild::spawn(&build.workload, &build.provider);
    let maps = MapLite::snapshot(stage.pid);
    let templates = stage.templates().expect("normal build shows its pool");
    let publish = stage.publish();
    assert_eq!(publish.elements.len(), 1, "legacy list element only");
    assert_contract_syms(&publish, &[]);
    let visible = file_backed_templates(&maps, &templates);
    let visible_indices: Vec<i64> = visible.iter().map(|table| table.index).collect();
    assert_eq!(
        visible_indices,
        vec![0, 1, 2, 3],
        "the sweep sees the file tail of the pool, nothing else"
    );

    let oracle = run_oracle(&build, &build.provider, "legacy", 0, &dir);
    assert_eq!(oracle["total"].as_u64().unwrap(), 0);
    assert!(oracle["legacy"]["published"].as_bool().unwrap());

    let started = Instant::now();
    let mut engine = engine_over_pids(&[stage.pid]);
    assert_eq!(
        engine.plan().slots.len(),
        27,
        "scan-only baseline: four heuristic templates"
    );
    let hooks = HookRegistry::builtin();
    let mut records = publish_records(stage.pid, &publish, &hooks);
    records.push(gfl_record(stage.pid, &publish.legacy, &hooks));
    let session = drain_records(&mut engine, records);
    let wall = started.elapsed();

    // Exact target set: the published legacy table plus the four
    // sweep-visible templates — 1 legacy + 4x6 closures + 3 shared.
    let mut printed = vec![publish.legacy.clone()];
    printed.extend(visible.iter().map(|table| (*table).clone()));
    assert_eq!(slot_targets(&engine), printed_targets(&maps, &printed));
    assert_eq!(engine.plan().slots.len(), 28);
    assert_eq!(slot_object_keys(&engine).len(), 1, "provider only");
    assert!(
        engine.modules.iter().all(|module| module
            .scanned
            .tables
            .iter()
            .all(|table| table.file_offset.is_some() || table.version != (3, 2))),
        "no heap wrapper tables exist, none admit"
    );

    // Provenance: the legacy instance carries the live return; nothing
    // else does.
    assert_eq!(
        live_instances(&engine),
        vec![(publish.legacy.addr, (2, 40), true, false)]
    );
    assert_instance_entries(&engine, &maps, &publish.legacy, true);
    let linkage: std::collections::BTreeMap<Option<u64>, Vec<&str>> = {
        let mut by_offset: std::collections::BTreeMap<Option<u64>, Vec<&str>> =
            std::collections::BTreeMap::new();
        for module in &engine.plan().modules {
            for table in &module.tables {
                by_offset
                    .entry(table.file_offset)
                    .or_default()
                    .push(table.linkage);
            }
        }
        by_offset
    };
    assert_eq!(linkage.get(&None).map(Vec::len), Some(1));
    assert_eq!(linkage[&None], vec!["live_return"]);
    // The sweep's own triples are pinned, not widened: template[0]'s
    // unreadable-name link (Task 1.4 concern 1) keeps its 1.3 reading.
    let template_offsets: Vec<u64> = visible
        .iter()
        .map(|table| MapLite::file_target(&maps, table.addr).1)
        .collect();
    assert_eq!(
        template_linkage(&engine),
        template_offsets
            .iter()
            .zip(["interface", "heuristic", "heuristic", "heuristic"])
            .map(|(offset, linkage)| (*offset, linkage))
            .collect::<std::collections::BTreeMap<_, _>>(),
    );

    // Names: the published legacy table authorizes all 68 ordinal
    // labels on its one slot; heuristic-only closures stay unknown.
    let template_auth = |index: i64| index == 0;
    let mut claimants: Vec<(&TablePrint, bool)> = vec![(&publish.legacy, true)];
    claimants.extend(
        visible
            .iter()
            .map(|table| (*table, template_auth(table.index))),
    );
    assert_eq!(
        actual_slot_names(&engine),
        expected_slot_names(&maps, &claimants)
    );
    let unknown: Vec<(String, u64)> = actual_slot_names(&engine)
        .iter()
        .filter(|(_, names)| **names == vec!["unknown".to_string()])
        .map(|(target, _)| target.clone())
        .collect();
    assert_eq!(unknown.len(), 18, "heuristic-only idx1-3 closures");

    assert_eq!(engine.plan().uncorroborated_candidates, 0);
    assert!(engine.plan().skipped.is_empty());
    assert!(engine.plan().modules_skipped.is_empty());
    assert_eq!(engine.plan().modules.len(), 1);
    let piece: Vec<(String, String, u64)> = printed
        .iter()
        .flat_map(|table| table_piece(table, &maps))
        .collect();
    assert_eq!(engine.plan().entries_seen, occurrence_distinct(&[piece]));
    assert_eq!(engine.plan().entries_seen, 484);

    // Cardinality: 4 scan candidates + 1 published legacy (the gfl and
    // element records deduplicate on one runtime identity).
    assert_eq!(engine.budget.table_candidates_count(), 5);
    assert_eq!(engine.budget.decoded_table_entries_count(), 484);
    // The sweep's template[0] triple plus the live list element.
    assert_eq!(engine.budget.interface_records_count(), 2);
    assert_eq!(
        session.attached_slots.iter().sum::<usize>(),
        engine.plan().slots.len() - 27,
        "publication attaches exactly its new slots"
    );
    assert_count_only(&engine);
    assert_costing(&engine, wall, "t1-none");
}

/// Case 2: index 17 active with 0–3 free. The K=4 heuristic window
/// covers templates 0–3 only; publication must admit index 17's exact
/// closure set — the inversion Task 1.4 proved.
#[test]
fn holes_admit_index_17_despite_free_0_to_3() {
    let build = pub_build();
    let dir = pub_tmp("t2-holes");
    let mut stage = StageChild::spawn(&build.workload, &build.provider);
    for want in 0..18 {
        let (idx, _) = stage.alloc(0, -1);
        assert_eq!(idx, want, "first-free allocation order");
    }
    for idx in 0..17 {
        stage.free(idx);
    }
    let maps = MapLite::snapshot(stage.pid);
    let backends = stage.backend_addrs();
    let templates = stage.templates().expect("normal build shows its pool");
    let publish = stage.publish();
    let heap_indices: Vec<i64> = publish
        .elements
        .iter()
        .filter(|table| table.index >= 0)
        .map(|table| table.index)
        .collect();
    assert_eq!(heap_indices, vec![17], "only index 17 is published");
    assert_eq!(publish.elements.len(), 2, "heap 17 + legacy element");
    assert_contract_syms(&publish, &[]);

    let oracle = run_oracle(&build, &build.provider, "holes", 0, &dir);
    assert_eq!(oracle["total"].as_u64().unwrap(), 26);
    let free: Vec<i64> = oracle["free_at_call"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_i64().unwrap())
        .collect();
    for idx in 0..4 {
        assert!(free.contains(&idx), "index {idx} is free at call time");
    }
    assert_eq!(
        oracle["occupied_at_call"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_i64().unwrap())
            .collect::<Vec<_>>(),
        vec![17]
    );

    let started = Instant::now();
    let mut engine = engine_over_pids(&[stage.pid]);
    assert_eq!(engine.plan().slots.len(), 27, "scan-only baseline");
    let hooks = HookRegistry::builtin();
    let mut records = publish_records(stage.pid, &publish, &hooks);
    records.push(gfl_record(stage.pid, &publish.legacy, &hooks));
    let session = drain_records(&mut engine, records);
    let wall = started.elapsed();

    // Exact target set: heap 17 + legacy + the four visible templates.
    let visible = file_backed_templates(&maps, &templates);
    assert_eq!(visible.len(), 4);
    let heap17 = publish
        .elements
        .iter()
        .find(|table| table.index == 17)
        .expect("heap 17 published");
    let mut printed = vec![publish.legacy.clone(), heap17.clone()];
    printed.extend(visible.iter().map(|table| (*table).clone()));
    assert_eq!(slot_targets(&engine), printed_targets(&maps, &printed));
    assert_eq!(engine.plan().slots.len(), 34);
    assert_eq!(slot_object_keys(&engine).len(), 1, "provider only");

    // Provenance: both published tables carry live returns and authorize
    // names; the live element interfaces link nothing (no widening).
    assert_eq!(
        live_instances(&engine),
        sorted_live(vec![
            (publish.legacy.addr, (2, 40), true, false),
            (heap17.addr, (3, 2), true, false),
        ])
    );
    assert_instance_entries(&engine, &maps, heap17, true);
    assert_instance_entries(&engine, &maps, &publish.legacy, true);
    let unlinked_live = engine
        .modules
        .iter()
        .flat_map(|module| &module.scanned.interfaces)
        .filter(|interface| interface.table.is_none())
        .count();
    assert_eq!(unlinked_live, 2, "both live elements stay unlinked");
    let linkage_none: Vec<&str> = engine
        .plan()
        .modules
        .iter()
        .flat_map(|module| &module.tables)
        .filter(|table| table.file_offset.is_none())
        .map(|table| table.linkage)
        .collect();
    assert_eq!(linkage_none, vec!["live_return", "live_return"]);

    // Names: heap 17's closures authorize their ordinal labels.
    let template_auth = |index: i64| index == 0;
    let mut claimants: Vec<(&TablePrint, bool)> = vec![(&publish.legacy, true), (heap17, true)];
    claimants.extend(
        visible
            .iter()
            .map(|table| (*table, template_auth(table.index))),
    );
    assert_eq!(
        actual_slot_names(&engine),
        expected_slot_names(&maps, &claimants)
    );

    // Workload counts: all 26 oracle calls resolve; the 13 wrapper calls
    // land on admitted slots, the 13 nested backend calls are the
    // explicit out-of-publication gap.
    let coverage = split_coverage(&maps, &publish, &backends, &oracle);
    assert_eq!(coverage.admitted.len(), 6, "six idx17 closures called");
    assert!(
        coverage
            .admitted
            .iter()
            .all(|target| slot_targets(&engine).contains(target)),
        "every wrapper call is admitted"
    );
    assert_eq!(
        coverage.nested_backend.len(),
        6,
        "six nested backend targets"
    );
    assert!(
        coverage
            .nested_backend
            .iter()
            .all(|target| !slot_targets(&engine).contains(target)),
        "nested backend stays unadmitted: no publication names it"
    );

    assert_eq!(engine.plan().uncorroborated_candidates, 0);
    assert!(engine.plan().skipped.is_empty());
    let piece: Vec<(String, String, u64)> = printed
        .iter()
        .flat_map(|table| table_piece(table, &maps))
        .collect();
    assert_eq!(engine.plan().entries_seen, occurrence_distinct(&[piece]));
    assert_eq!(engine.plan().entries_seen, 588);

    assert_eq!(engine.budget.table_candidates_count(), 6);
    assert_eq!(engine.budget.decoded_table_entries_count(), 588);
    // The sweep's triple plus two live list elements.
    assert_eq!(engine.budget.interface_records_count(), 3);
    assert_eq!(
        session.attached_slots.iter().sum::<usize>(),
        engine.plan().slots.len() - 27,
        "publication attaches exactly its new slots"
    );
    assert_count_only(&engine);
    assert_costing(&engine, wall, "t2-holes");
}

/// Case 3: five active wrappers. Index 4 sits beyond the K=4 heuristic
/// window; publication must admit all five closure sets exactly.
#[test]
fn five_active_wrappers_admit_all_closure_sets() {
    let build = pub_build();
    let dir = pub_tmp("t3-five");
    let mut stage = StageChild::spawn(&build.workload, &build.provider);
    for want in 0..5 {
        let (idx, _) = stage.alloc(0, -1);
        assert_eq!(idx, want, "first-free allocation order");
    }
    let maps = MapLite::snapshot(stage.pid);
    let backends = stage.backend_addrs();
    let templates = stage.templates().expect("normal build shows its pool");
    let publish = stage.publish();
    let heap_indices: Vec<i64> = publish
        .elements
        .iter()
        .filter(|table| table.index >= 0)
        .map(|table| table.index)
        .collect();
    assert_eq!(heap_indices, vec![0, 1, 2, 3, 4]);
    assert_eq!(publish.elements.len(), 6, "five heaps + legacy element");
    assert_contract_syms(&publish, &[]);

    let oracle = run_oracle(&build, &build.provider, "five", 0, &dir);
    assert_eq!(oracle["total"].as_u64().unwrap(), 120);

    let started = Instant::now();
    let mut engine = engine_over_pids(&[stage.pid]);
    assert_eq!(engine.plan().slots.len(), 27, "scan-only baseline");
    let hooks = HookRegistry::builtin();
    let mut records = publish_records(stage.pid, &publish, &hooks);
    records.push(gfl_record(stage.pid, &publish.legacy, &hooks));
    let session = drain_records(&mut engine, records);
    let wall = started.elapsed();

    // Exact target set: five heaps + legacy + visible templates. The
    // templates alias heaps 0–3, so only index 4 adds new closures.
    let visible = file_backed_templates(&maps, &templates);
    assert_eq!(visible.len(), 4);
    let mut printed = vec![publish.legacy.clone()];
    printed.extend(
        publish
            .elements
            .iter()
            .filter(|table| table.index >= 0)
            .cloned(),
    );
    printed.extend(visible.iter().map(|table| (*table).clone()));
    assert_eq!(slot_targets(&engine), printed_targets(&maps, &printed));
    assert_eq!(engine.plan().slots.len(), 34);
    assert_eq!(slot_object_keys(&engine).len(), 1, "provider only");

    // Index 4's closures — beyond the heuristic window — are admitted
    // with authorized names.
    let heap4 = publish
        .elements
        .iter()
        .find(|table| table.index == 4)
        .expect("heap 4 published");
    for ord in EX_ORDS {
        let (addr, sym) = &heap4.entries[ord as usize];
        assert_eq!(*sym, format!("mw_closure_{ord}_4"));
        let (path, offset, _) = MapLite::file_target(&maps, *addr);
        let names = &actual_slot_names(&engine)[&(path.clone(), offset)];
        assert_eq!(
            *names,
            vec![
                pkcs11_module::function_name(ord as usize)
                    .unwrap()
                    .to_string()
            ],
            "idx4 ord{ord} is authorized, never unknown"
        );
    }

    let mut expected_live = vec![(publish.legacy.addr, (2, 40), true, false)];
    expected_live.extend(
        publish
            .elements
            .iter()
            .filter(|table| table.index >= 0)
            .map(|table| (table.addr, (3, 2), true, false)),
    );
    assert_eq!(live_instances(&engine), sorted_live(expected_live));
    for table in publish.elements.iter().filter(|table| table.index >= 0) {
        assert_instance_entries(&engine, &maps, table, true);
    }
    assert_instance_entries(&engine, &maps, &publish.legacy, true);
    let linkage_none: Vec<&str> = engine
        .plan()
        .modules
        .iter()
        .flat_map(|module| &module.tables)
        .filter(|table| table.file_offset.is_none())
        .map(|table| table.linkage)
        .collect();
    assert_eq!(linkage_none, vec!["live_return"; 6]);

    let template_auth = |index: i64| index == 0;
    let mut claimants: Vec<(&TablePrint, bool)> = vec![(&publish.legacy, true)];
    claimants.extend(
        publish
            .elements
            .iter()
            .filter(|table| table.index >= 0)
            .map(|table| (table, true)),
    );
    claimants.extend(
        visible
            .iter()
            .map(|table| (*table, template_auth(table.index))),
    );
    assert_eq!(
        actual_slot_names(&engine),
        expected_slot_names(&maps, &claimants)
    );

    // Workload counts: 60 wrapper calls land on admitted slots; the 60
    // nested backend calls are the explicit gap.
    let coverage = split_coverage(&maps, &publish, &backends, &oracle);
    assert_eq!(coverage.admitted.len(), 30, "five indices x six closures");
    assert!(
        coverage
            .admitted
            .iter()
            .all(|target| slot_targets(&engine).contains(target)),
        "every wrapper call is admitted"
    );
    assert_eq!(coverage.nested_backend.len(), 6, "six backend entry points");
    assert!(
        coverage
            .nested_backend
            .iter()
            .all(|target| !slot_targets(&engine).contains(target)),
        "nested backend stays unadmitted"
    );

    assert_eq!(engine.plan().uncorroborated_candidates, 0);
    assert!(engine.plan().skipped.is_empty());
    let piece: Vec<(String, String, u64)> = printed
        .iter()
        .flat_map(|table| table_piece(table, &maps))
        .collect();
    assert_eq!(engine.plan().entries_seen, occurrence_distinct(&[piece]));
    assert_eq!(engine.plan().entries_seen, 416 + 5 * 104 + 68);

    assert_eq!(engine.budget.table_candidates_count(), 10);
    assert_eq!(
        engine.budget.decoded_table_entries_count(),
        416 + 5 * 104 + 68
    );
    // The sweep's triple plus six live list elements.
    assert_eq!(engine.budget.interface_records_count(), 7);
    assert_eq!(
        session.attached_slots.iter().sum::<usize>(),
        engine.plan().slots.len() - 27,
        "publication attaches exactly its new slots"
    );
    assert_count_only(&engine);
    assert_costing(&engine, wall, "t3-five");
}

/// Case 4: two processes use different indices of one inode. Occupancy
/// is process-local: the admitted set is the union across validated
/// views, pinned to one shared object identity.
#[test]
fn two_processes_union_indices_of_one_inode() {
    let build = pub_build();
    let dir = pub_tmp("t4-pair");
    let metadata = std::fs::metadata(&build.provider).unwrap();
    let ino = metadata.ino();

    // Pair A: indices {0,1}. Pair B: indices {5,6}.
    let mut stage_a = StageChild::spawn(&build.workload, &build.provider);
    for want in 0..2 {
        let (idx, _) = stage_a.alloc(0, -1);
        assert_eq!(idx, want);
    }
    let mut stage_b = StageChild::spawn(&build.workload, &build.provider);
    for want in 0..7 {
        let (idx, _) = stage_b.alloc(0, -1);
        assert_eq!(idx, want);
    }
    for idx in 0..5 {
        stage_b.free(idx);
    }
    assert_ne!(stage_a.pid, stage_b.pid, "two distinct processes");
    let maps_a = MapLite::snapshot(stage_a.pid);
    let maps_b = MapLite::snapshot(stage_b.pid);
    let backends_a = stage_a.backend_addrs();
    let backends_b = stage_b.backend_addrs();
    let publish_a = stage_a.publish();
    let publish_b = stage_b.publish();
    let indices_a: Vec<i64> = publish_a
        .elements
        .iter()
        .filter(|table| table.index >= 0)
        .map(|table| table.index)
        .collect();
    let indices_b: Vec<i64> = publish_b
        .elements
        .iter()
        .filter(|table| table.index >= 0)
        .map(|table| table.index)
        .collect();
    assert_eq!(indices_a, vec![0, 1]);
    assert_eq!(indices_b, vec![5, 6]);
    assert_contract_syms(&publish_a, &[]);
    assert_contract_syms(&publish_b, &[]);
    let templates = stage_a.templates().expect("normal build shows its pool");
    let visible = file_backed_templates(&maps_a, &templates);
    assert_eq!(visible.len(), 4);

    let oracle_a = run_oracle(&build, &build.provider, "pair_a", 0, &dir);
    let oracle_b = run_oracle(&build, &build.provider, "pair_b", 0, &dir);
    assert_eq!(oracle_a["total"].as_u64().unwrap(), 52);
    assert_eq!(oracle_b["total"].as_u64().unwrap(), 52);

    let started = Instant::now();
    let mut engine = engine_over_pids(&[stage_a.pid, stage_b.pid]);
    assert_eq!(engine.plan().slots.len(), 27, "scan-only baseline");
    assert_eq!(engine.modules.len(), 2, "one reconciled module per view");
    // Same inode under both views: capture-local identity agrees.
    let keys: Vec<(u64, u64, u64)> = engine
        .modules
        .iter()
        .map(|module| {
            (
                module.scanned.key.device.major,
                module.scanned.key.device.minor,
                module.scanned.key.inode,
            )
        })
        .collect();
    assert_eq!(keys[0], keys[1], "one inode across views");
    assert_eq!(keys[0].2, ino, "the fixture provider inode");
    // The engine's maps parse agrees with the test's independent parse for
    // the provider mapping in each child. st_dev is deliberately not
    // compared: on btrfs subvolumes the kernel reports a different
    // anonymous device via stat than via /proc/pid/maps for the same file,
    // so only the inode ties the two worlds together.
    for (label, maps) in [("a", &maps_a), ("b", &maps_b)] {
        let mapping = maps
            .iter()
            .find(|mapping| mapping.path == build.provider.to_string_lossy())
            .unwrap_or_else(|| panic!("child {label} maps the fixture provider"));
        assert_eq!(mapping.ino, ino, "child {label} maps the built inode");
        assert_eq!(
            (keys[0].0, keys[0].1),
            (mapping.dev_major, mapping.dev_minor),
            "child {label}: engine maps parse agrees with the independent parse",
        );
    }
    let hooks = HookRegistry::builtin();
    let mut records = publish_records(stage_a.pid, &publish_a, &hooks);
    records.push(gfl_record(stage_a.pid, &publish_a.legacy, &hooks));
    records.extend(publish_records(stage_b.pid, &publish_b, &hooks));
    records.push(gfl_record(stage_b.pid, &publish_b.legacy, &hooks));
    let session = drain_records(&mut engine, records);
    let wall = started.elapsed();

    // Union: idx0,1,5,6 heaps + one legacy + shared templates —
    // 36 closures + 3 shared + 1 legacy.
    let mut printed_a = vec![publish_a.legacy.clone()];
    printed_a.extend(
        publish_a
            .elements
            .iter()
            .filter(|table| table.index >= 0)
            .cloned(),
    );
    let mut printed_b = vec![publish_b.legacy.clone()];
    printed_b.extend(
        publish_b
            .elements
            .iter()
            .filter(|table| table.index >= 0)
            .cloned(),
    );
    let visible_owned: Vec<TablePrint> = visible.iter().map(|table| (*table).clone()).collect();
    let mut expected = printed_targets(&maps_a, &printed_a);
    expected.extend(printed_targets(&maps_b, &printed_b));
    expected.extend(printed_targets(&maps_a, &visible_owned));
    assert_eq!(slot_targets(&engine), expected);
    assert_eq!(engine.plan().slots.len(), 40);
    assert_eq!(engine.plan().modules.len(), 1, "one inode, one module");
    assert_eq!(slot_object_keys(&engine).len(), 1, "provider only");

    // Per-view provenance: each view's heaps carry their own returns.
    let mut expected_live = vec![
        (publish_a.legacy.addr, (2, 40), true, false),
        (publish_b.legacy.addr, (2, 40), true, false),
    ];
    for table in publish_a
        .elements
        .iter()
        .chain(publish_b.elements.iter())
        .filter(|table| table.index >= 0)
    {
        expected_live.push((table.addr, (3, 2), true, false));
    }
    assert_eq!(live_instances(&engine), sorted_live(expected_live));

    // Names from both views' claimants (template offsets coincide).
    let template_auth = |index: i64| index == 0;
    let mut names_a = expected_slot_names(&maps_a, &{
        let mut claimants_a: Vec<(&TablePrint, bool)> = vec![(&publish_a.legacy, true)];
        claimants_a.extend(
            publish_a
                .elements
                .iter()
                .filter(|table| table.index >= 0)
                .map(|table| (table, true)),
        );
        claimants_a.extend(
            visible
                .iter()
                .map(|table| (*table, template_auth(table.index))),
        );
        claimants_a
    });
    let names_b = expected_slot_names(&maps_b, &{
        let mut claimants_b: Vec<(&TablePrint, bool)> = vec![(&publish_b.legacy, true)];
        claimants_b.extend(
            publish_b
                .elements
                .iter()
                .filter(|table| table.index >= 0)
                .map(|table| (table, true)),
        );
        claimants_b
    });
    for (target, labels) in names_b {
        let entry = names_a.entry(target).or_default();
        for label in labels {
            if !entry.contains(&label) {
                entry.push(label);
            }
        }
        entry.sort();
        if entry.len() > 1 {
            entry.retain(|label| label != "unknown");
        }
    }
    assert_eq!(actual_slot_names(&engine), names_a);

    // Workload counts per process: 26 + 26 wrapper calls admitted, the
    // nested halves explicit.
    for (maps, publish, backends, oracle) in [
        (&maps_a, &publish_a, &backends_a, &oracle_a),
        (&maps_b, &publish_b, &backends_b, &oracle_b),
    ] {
        let coverage = split_coverage(maps, publish, backends, oracle);
        assert_eq!(coverage.admitted.len(), 12, "two indices x six closures");
        assert!(
            coverage
                .admitted
                .iter()
                .all(|target| slot_targets(&engine).contains(target)),
            "every wrapper call is admitted"
        );
        assert!(
            coverage
                .nested_backend
                .iter()
                .all(|target| !slot_targets(&engine).contains(target)),
            "nested backend stays unadmitted"
        );
    }

    assert_eq!(engine.plan().uncorroborated_candidates, 0);
    assert!(engine.plan().skipped.is_empty());
    // Template (name, path, offset) triples are view-independent: one
    // inode, one layout.
    let template_piece: Vec<(String, String, u64)> = visible
        .iter()
        .flat_map(|table| table_piece(table, &maps_a))
        .collect();
    let piece_a: Vec<(String, String, u64)> = printed_a
        .iter()
        .flat_map(|table| table_piece(table, &maps_a))
        .chain(template_piece.clone())
        .collect();
    let piece_b: Vec<(String, String, u64)> = printed_b
        .iter()
        .flat_map(|table| table_piece(table, &maps_b))
        .chain(template_piece)
        .collect();
    assert_eq!(
        engine.plan().entries_seen,
        occurrence_distinct(&[piece_a, piece_b])
    );

    // Cardinality: the second view's scan repeats deduplicate on file
    // identity (4 scan charges total); each view's heap tables charge
    // their own runtime identities.
    assert_eq!(engine.budget.table_candidates_count(), 10);
    // 416 scan + 416 live heaps + 136 live legacy (one per view).
    assert_eq!(engine.budget.decoded_table_entries_count(), 416 + 416 + 136);
    // Two sweep triples (one per view) plus six live list elements.
    assert_eq!(engine.budget.interface_records_count(), 8);
    assert_eq!(
        session.attached_slots.iter().sum::<usize>(),
        engine.plan().slots.len() - 27,
        "publication attaches exactly its new slots"
    );
    assert_count_only(&engine);
    assert_costing(&engine, wall, "t4-pair");
}

/// Case 5: direct backend forwarding. The published heap table's
/// ordinals 5 and 43 point into backend.so — a different object than
/// the publishing provider — and both must admit with exact identity.
#[test]
fn direct_backend_forwarding_admits_cross_object_targets() {
    let build = pub_build();
    let dir = pub_tmp("t5-forward");
    let mut stage = StageChild::spawn(&build.workload, &build.provider);
    let mask = (1 << 1) | (1 << 4); // ordinals 5 and 43
    let (idx, _) = stage.alloc(mask, -1);
    assert_eq!(idx, 0);
    let maps = MapLite::snapshot(stage.pid);
    let backends = stage.backend_addrs();
    let templates = stage.templates().expect("normal build shows its pool");
    let publish = stage.publish();
    assert_eq!(publish.elements.len(), 2, "heap 0 + legacy element");
    assert_contract_syms(&publish, &[(0, mask)]);
    let heap0 = publish
        .elements
        .iter()
        .find(|table| table.index == 0)
        .expect("heap 0 published");

    let oracle = run_oracle(&build, &build.provider, "forward", 0, &dir);
    assert_eq!(oracle["total"].as_u64().unwrap(), 20);

    let started = Instant::now();
    let mut engine = engine_over_pids(&[stage.pid]);
    assert_eq!(engine.plan().slots.len(), 27, "scan-only baseline");
    let hooks = HookRegistry::builtin();
    let mut records = publish_records(stage.pid, &publish, &hooks);
    records.push(gfl_record(stage.pid, &publish.legacy, &hooks));
    let session = drain_records(&mut engine, records);
    let wall = started.elapsed();

    let visible = file_backed_templates(&maps, &templates);
    assert_eq!(visible.len(), 4);
    let mut printed = vec![publish.legacy.clone(), heap0.clone()];
    printed.extend(visible.iter().map(|table| (*table).clone()));
    assert_eq!(slot_targets(&engine), printed_targets(&maps, &printed));
    assert_eq!(engine.plan().slots.len(), 30);
    assert_eq!(engine.plan().modules.len(), 1, "provider module only");

    // Cross-object identity: the two forwarded targets pin backend.so,
    // a different object than the publishing provider.
    let keys = slot_object_keys(&engine);
    assert_eq!(keys.len(), 2, "provider + backend objects");
    assert!(
        keys.contains_key(&build.backend.to_string_lossy().to_string()),
        "backend.so pins the exact fixture file"
    );
    let backend_key = keys
        .iter()
        .find(|(path, _)| path.ends_with("backend.so"))
        .expect("backend.so slots exist")
        .1;
    let provider_key = keys
        .iter()
        .find(|(path, _)| path.ends_with("provider.so"))
        .expect("provider.so slots exist")
        .1;
    assert_ne!(backend_key, provider_key, "distinct pinned objects");
    let backend_slots: Vec<u64> = engine
        .plan()
        .slots
        .iter()
        .filter(|slot| {
            engine
                .pinned()
                .summary(slot.object)
                .is_some_and(|summary| summary.path.ends_with("backend.so"))
        })
        .map(|slot| slot.file_offset)
        .collect();
    let mut expected_backend: Vec<u64> = [5u32, 43]
        .iter()
        .map(|ord| MapLite::file_target(&maps, heap0.entries[*ord as usize].0).1)
        .collect();
    expected_backend.sort();
    let mut backend_slots_sorted = backend_slots.clone();
    backend_slots_sorted.sort();
    assert_eq!(backend_slots_sorted, expected_backend);
    assert_eq!(backend_slots.len(), 2, "exactly the forwarded ordinals");

    assert_eq!(
        live_instances(&engine),
        sorted_live(vec![
            (publish.legacy.addr, (2, 40), true, false),
            (heap0.addr, (3, 2), true, false),
        ])
    );
    assert_instance_entries(&engine, &maps, heap0, true);
    assert_instance_entries(&engine, &maps, &publish.legacy, true);

    let template_auth = |index: i64| index == 0;
    let mut claimants: Vec<(&TablePrint, bool)> = vec![(&publish.legacy, true), (heap0, true)];
    claimants.extend(
        visible
            .iter()
            .map(|table| (*table, template_auth(table.index))),
    );
    assert_eq!(
        actual_slot_names(&engine),
        expected_slot_names(&maps, &claimants)
    );

    // Workload counts: 7 wrapper + 6 direct backend calls admitted; the
    // 7 nested backend calls are the explicit gap.
    let coverage = split_coverage(&maps, &publish, &backends, &oracle);
    assert_eq!(coverage.admitted.len(), 6, "four closures + two backend");
    assert!(
        coverage
            .admitted
            .iter()
            .all(|target| slot_targets(&engine).contains(target)),
        "every wrapper and direct call is admitted"
    );
    assert_eq!(coverage.nested_backend.len(), 4, "four nested entry points");
    assert!(
        coverage
            .nested_backend
            .iter()
            .all(|target| !slot_targets(&engine).contains(target)),
        "nested backend stays unadmitted"
    );

    assert_eq!(engine.plan().uncorroborated_candidates, 0);
    assert!(engine.plan().skipped.is_empty());
    let piece: Vec<(String, String, u64)> = printed
        .iter()
        .flat_map(|table| table_piece(table, &maps))
        .collect();
    assert_eq!(engine.plan().entries_seen, occurrence_distinct(&[piece]));
    assert_eq!(engine.plan().entries_seen, 588);

    assert_eq!(engine.budget.table_candidates_count(), 6);
    assert_eq!(engine.budget.decoded_table_entries_count(), 588);
    // The sweep's triple plus two live list elements.
    assert_eq!(engine.budget.interface_records_count(), 3);
    assert_eq!(
        session.attached_slots.iter().sum::<usize>(),
        engine.plan().slots.len() - 27,
        "publication attaches exactly its new slots"
    );
    assert_count_only(&engine);
    assert_costing(&engine, wall, "t5-forward");
}

/// Case 6: allocation, free, and reuse during capture. Index 17
/// publishes, is freed, and index 0 reuses its allocation; both
/// generations admit (historical allocations are retained), the reused
/// address decodes to its new content, and the second legacy
/// publication deduplicates on its runtime identity.
#[test]
fn reuse_during_capture_retains_history_and_costs_exactly() {
    let build = pub_build();
    let dir = pub_tmp("t6-reuse");
    let mut stage = StageChild::spawn(&build.workload, &build.provider);
    for want in 0..18 {
        let (idx, _) = stage.alloc(0, -1);
        assert_eq!(idx, want);
    }
    for idx in 0..17 {
        stage.free(idx);
    }
    let maps_a = MapLite::snapshot(stage.pid);
    let backends = stage.backend_addrs();
    let templates = stage.templates().expect("normal build shows its pool");
    let publish_a = stage.publish();
    let heap17 = publish_a
        .elements
        .iter()
        .find(|table| table.index == 17)
        .expect("heap 17 published")
        .clone();

    let started = Instant::now();
    let mut engine = engine_over_pids(&[stage.pid]);
    assert_eq!(engine.plan().slots.len(), 27, "scan-only baseline");
    let hooks = HookRegistry::builtin();
    let mut batch1 = publish_records(stage.pid, &publish_a, &hooks);
    batch1.push(gfl_record(stage.pid, &publish_a.legacy, &hooks));
    let session1 = drain_records(&mut engine, batch1);
    assert_eq!(engine.plan().slots.len(), 34, "heap 17 admitted");
    assert_eq!(engine.budget.table_candidates_count(), 6);
    let slots_batch1 = slot_targets(&engine);

    // Free 17, reuse the allocation for index 0, publish again.
    stage.free(17);
    let (reused, _) = stage.alloc(0, -1);
    assert_eq!(reused, 0, "first free index wins");
    let maps_b = MapLite::snapshot(stage.pid);
    // Mapping stability across the free + realloc between snapshots:
    // every template classifies identically under both.
    for table in &templates {
        let file_backed = |maps: &[MapLite]| {
            MapLite::containing(maps, table.addr).is_some_and(|mapping| mapping.ino != 0)
        };
        assert_eq!(
            file_backed(&maps_a),
            file_backed(&maps_b),
            "template {} is stably placed",
            table.index
        );
    }
    let publish_b = stage.publish();
    let heap0 = publish_b
        .elements
        .iter()
        .find(|table| table.index == 0)
        .expect("heap 0 published")
        .clone();
    assert_contract_syms(&publish_b, &[]);
    eprintln!(
        "t6-reuse: heap17 addr {:#x}, heap0 addr {:#x}, reused={}",
        heap17.addr,
        heap0.addr,
        heap17.addr == heap0.addr
    );
    let mut batch2 = publish_records(stage.pid, &publish_b, &hooks);
    batch2.push(gfl_record(stage.pid, &publish_b.legacy, &hooks));
    let session2 = drain_records(&mut engine, batch2);
    let wall = started.elapsed();

    // History is retained: batch-1 slots survive, and index 0's
    // instance carries its new content even where the address was
    // reused (its targets alias template 0, so no new slots join).
    let visible = file_backed_templates(&maps_b, &templates);
    assert_eq!(visible.len(), 4);
    let mut printed = vec![publish_a.legacy.clone(), heap17.clone(), heap0.clone()];
    printed.extend(visible.iter().map(|table| (*table).clone()));
    assert_eq!(slot_targets(&engine), printed_targets(&maps_b, &printed));
    assert_eq!(engine.plan().slots.len(), 34);
    assert!(
        slots_batch1
            .iter()
            .all(|target| slot_targets(&engine).contains(target)),
        "batch-1 allocations are retained, never returned"
    );
    assert_instance_entries(&engine, &maps_b, &heap0, true);
    assert_instance_entries(&engine, &maps_b, &heap17, true);
    assert_instance_entries(&engine, &maps_b, &publish_a.legacy, true);
    assert_eq!(
        live_instances(&engine),
        sorted_live(vec![
            (publish_a.legacy.addr, (2, 40), true, false),
            (heap17.addr, (3, 2), true, false),
            (heap0.addr, (3, 2), true, false),
        ])
    );

    // The second legacy publication (same view, address, content)
    // deduplicates: only heap 0 charges a new candidate.
    assert_eq!(engine.budget.table_candidates_count(), 7);
    assert_eq!(
        engine.budget.decoded_table_entries_count(),
        588 + 104,
        "batch1 588 + heap 0"
    );
    // The sweep's triple plus four live list elements across batches.
    assert_eq!(engine.budget.interface_records_count(), 5);
    assert_eq!(
        session1.attached_slots.iter().sum::<usize>(),
        34 - 27,
        "batch 1 attaches its new slots"
    );
    assert_eq!(
        session2.attached_slots.iter().sum::<usize>(),
        0,
        "batch 2 adds an aliased instance: nothing new to attach"
    );

    // Workload counts from the reuse scenario: index 17's calls plus
    // the single index-0 call, all on admitted slots.
    let oracle = run_oracle(&build, &build.provider, "reuse", 0, &dir);
    assert_eq!(oracle["total"].as_u64().unwrap(), 28);
    assert_eq!(oracle["reused"].as_i64().unwrap(), 0);
    let mut combined_elements = publish_a.elements.clone();
    combined_elements.push(heap0.clone());
    let combined = PublishBlock {
        legacy: publish_a.legacy.clone(),
        elements: combined_elements,
    };
    let coverage = split_coverage(&maps_b, &combined, &backends, &oracle);
    assert!(
        coverage
            .admitted
            .iter()
            .all(|target| slot_targets(&engine).contains(target)),
        "every wrapper call is admitted"
    );

    assert_eq!(engine.plan().uncorroborated_candidates, 0);
    assert_count_only(&engine);
    assert_costing(&engine, wall, "t6-reuse");
}

/// Case 7: a table published before capture. Publication the capture
/// never observes must stay unresolved inventory: heuristic templates
/// only, no heap tables, no legacy, no live returns anywhere — the
/// honest gap Task 1.6 starts from. A guard: passes pre- and post-fix.
#[test]
fn pre_capture_publication_stays_unresolved() {
    let build = pub_build();
    let dir = pub_tmp("t7-precapture");
    let mut stage = StageChild::spawn(&build.workload, &build.provider);
    for want in 0..5 {
        let (idx, _) = stage.alloc(0, -1);
        assert_eq!(idx, want);
    }
    // Publication happens BEFORE the capture starts.
    let maps = MapLite::snapshot(stage.pid);
    let templates = stage.templates().expect("normal build shows its pool");
    let publish = stage.publish();
    assert_eq!(
        publish
            .elements
            .iter()
            .filter(|table| table.index >= 0)
            .count(),
        5,
        "five heap tables really were published"
    );

    let oracle = run_oracle(&build, &build.provider, "five", 0, &dir);
    assert_eq!(oracle["total"].as_u64().unwrap(), 120);

    // The capture starts now and observes no live records at all.
    let started = Instant::now();
    let engine = engine_over_pids(&[stage.pid]);
    let wall = started.elapsed();

    let visible = file_backed_templates(&maps, &templates);
    assert_eq!(visible.len(), 4);
    let owned: Vec<TablePrint> = visible.iter().map(|table| (*table).clone()).collect();
    assert_eq!(slot_targets(&engine), printed_targets(&maps, &owned));
    assert_eq!(engine.plan().slots.len(), 27);
    assert!(
        engine
            .modules
            .iter()
            .flat_map(|module| &module.scanned.tables)
            .all(|table| table.file_offset.is_some()),
        "every instance is sweep-decoded; nothing published admits"
    );
    assert!(
        engine
            .plan()
            .modules
            .iter()
            .flat_map(|module| &module.tables)
            .all(|table| table.linkage == "interface" || table.linkage == "heuristic"),
        "no live-return linkage without observed publication"
    );
    // The missed legacy publication is a concrete gap: its slot is absent.
    let (_, legacy_offset, _) = MapLite::file_target(&maps, publish.legacy.entries[0].0);
    assert!(
        engine
            .plan()
            .slots
            .iter()
            .all(|slot| slot.file_offset != legacy_offset),
        "unobserved legacy publication admits nothing"
    );
    // Index 4's closures (beyond the window, unpublished-to-us) miss;
    // indices 0–3 observe through their aliasing templates.
    let heap4 = publish
        .elements
        .iter()
        .find(|table| table.index == 4)
        .expect("heap 4 published");
    for ord in EX_ORDS {
        let (path, offset, _) = MapLite::file_target(&maps, heap4.entries[ord as usize].0);
        assert!(
            !slot_targets(&engine).contains(&(path, offset)),
            "idx4 ord{ord} misses without publication"
        );
    }
    for idx in 0..4 {
        let heap = publish
            .elements
            .iter()
            .find(|table| table.index == idx)
            .expect("heap published");
        for ord in EX_ORDS {
            let (path, offset, _) = MapLite::file_target(&maps, heap.entries[ord as usize].0);
            assert!(
                slot_targets(&engine).contains(&(path, offset)),
                "idx{idx} ord{ord} observes via its template"
            );
        }
    }

    assert_eq!(engine.plan().uncorroborated_candidates, 0);
    assert_eq!(engine.plan().entries_seen, 416);
    assert_eq!(engine.budget.table_candidates_count(), 4);
    assert_eq!(engine.budget.decoded_table_entries_count(), 416);
    // The sweep's own interface triple (template[0]'s link) charges one
    // interface record; no live records were observed.
    assert_eq!(engine.budget.interface_records_count(), 1);
    assert_count_only(&engine);
    assert_costing(&engine, wall, "t7-precapture");
}

/// Case 8: an unknown p11-kit build. The stripped provider hides its
/// pool symbol and packs occupancy as a bitmap — publication-driven
/// admission needs neither, and admits the identical target set.
#[test]
fn unknown_build_admits_by_publication_without_layout() {
    let build = pub_build();
    let dir = pub_tmp("t8-stripped");
    let mut stage = StageChild::spawn(&build.workload, &build.stripped);
    for want in 0..5 {
        let (idx, _) = stage.alloc(0, -1);
        assert_eq!(idx, want);
    }
    let maps = MapLite::snapshot(stage.pid);
    let backends = stage.backend_addrs();
    assert!(
        stage.templates().is_none(),
        "stripped build hides its layout"
    );
    let publish = stage.publish();
    let heap_indices: Vec<i64> = publish
        .elements
        .iter()
        .filter(|table| table.index >= 0)
        .map(|table| table.index)
        .collect();
    assert_eq!(heap_indices, vec![0, 1, 2, 3, 4]);
    assert!(
        publish
            .elements
            .iter()
            .flat_map(|table| &table.entries)
            .all(|(_, sym)| sym == "-"),
        "stripped builds print no entry symbols"
    );

    let oracle = run_oracle(&build, &build.stripped, "five", 0, &dir);
    assert_eq!(oracle["total"].as_u64().unwrap(), 120);
    assert_eq!(oracle["build_variant"].as_str().unwrap(), "stripped");
    assert!(!oracle["layout_known"].as_bool().unwrap());
    let normal = run_oracle(&build, &build.provider, "five", 0, &dir);
    assert_eq!(
        oracle["counts"], normal["counts"],
        "counts are build-invariant"
    );

    let started = Instant::now();
    let mut engine = engine_over_pids(&[stage.pid]);
    let scan_baseline = engine.plan().slots.len();
    let baseline_targets = slot_targets(&engine);
    eprintln!("t8-stripped: scan-only baseline is {scan_baseline} slots");
    // Link-order accident, pinned loudly: the stripped build packs the
    // static legacy table into the last file page (the normal build spills
    // it past the file page into anonymous BSS), so the sweep decodes it
    // and the live return merges onto the scan instance instead of
    // admitting a heap instance. If a toolchain relayouts this, the merge
    // assertions below name what to re-derive.
    let legacy_extent =
        publish.legacy.addr..publish.legacy.addr + 8 + 8 * publish.legacy.nentry as u64;
    assert!(
        legacy_extent
            .clone()
            .all(|addr| MapLite::containing(&maps, addr).is_some_and(|mapping| mapping.ino != 0)),
        "stripped legacy sits in the file page; re-derive the merge arm if this moves"
    );
    let (legacy_path, legacy_offset, _) = MapLite::file_target(&maps, publish.legacy.entries[0].0);
    assert_eq!(
        scan_baseline, 1,
        "the sweep sees the file-backed legacy only"
    );
    assert_eq!(
        baseline_targets,
        std::collections::BTreeSet::from([(legacy_path, legacy_offset)]),
        "baseline is the one legacy target"
    );
    let hooks = HookRegistry::builtin();
    let mut records = publish_records(stage.pid, &publish, &hooks);
    records.push(gfl_record(stage.pid, &publish.legacy, &hooks));
    let session = drain_records(&mut engine, records);
    let wall = started.elapsed();

    // The published set is layout-independent and exact; the heuristic
    // template remainder is whatever this layout's file tail decodes.
    let mut published = vec![publish.legacy.clone()];
    published.extend(
        publish
            .elements
            .iter()
            .filter(|table| table.index >= 0)
            .cloned(),
    );
    let published_targets = printed_targets(&maps, &published);
    assert_eq!(published_targets.len(), 34, "five heaps + legacy, exact");
    assert!(
        published_targets
            .iter()
            .all(|target| slot_targets(&engine).contains(target)),
        "every published target admits without layout knowledge"
    );
    // No extras: every slot is published-derived or decoded by the
    // sweep from this layout's file tail (the unknown part).
    let mut scan_derived = std::collections::BTreeSet::new();
    for table in engine
        .modules
        .iter()
        .flat_map(|module| &module.scanned.tables)
        .filter(|table| table.file_offset.is_some())
    {
        for entry in &table.entries {
            scan_derived.insert((entry.object_path.clone(), entry.file_offset));
        }
    }
    let mut union = published_targets.clone();
    union.extend(scan_derived);
    assert_eq!(slot_targets(&engine), union, "no unaccounted slots");
    assert_eq!(
        engine.plan().uncorroborated_candidates,
        0,
        "the merged legacy bypasses; nothing heuristic spills"
    );
    eprintln!(
        "t8-stripped: {} slots, {} sweep-decoded tables, spill {}",
        engine.plan().slots.len(),
        engine
            .modules
            .iter()
            .flat_map(|module| &module.scanned.tables)
            .filter(|table| table.file_offset.is_some())
            .count(),
        engine.plan().uncorroborated_candidates,
    );
    // Index 4's closures admit with authorized ordinal names.
    let heap4 = publish
        .elements
        .iter()
        .find(|table| table.index == 4)
        .expect("heap 4 published");
    for ord in EX_ORDS {
        let (path, offset, _) = MapLite::file_target(&maps, heap4.entries[ord as usize].0);
        let names = &actual_slot_names(&engine)[&(path, offset)];
        assert_eq!(
            *names,
            vec![
                pkcs11_module::function_name(ord as usize)
                    .unwrap()
                    .to_string()
            ],
            "stripped idx4 ord{ord} is authorized, never unknown"
        );
    }
    // The file-backed legacy merges (scan + live are one instance with
    // the live return unioned on), so the heap-instance list carries the
    // five wrappers only.
    let at_legacy: Vec<&ScannedTable> = engine
        .modules
        .iter()
        .flat_map(|module| &module.scanned.tables)
        .filter(|table| table.address == publish.legacy.addr)
        .collect();
    assert_eq!(
        at_legacy.len(),
        1,
        "scan and live instances of one static table merge"
    );
    assert!(at_legacy[0].live_return);
    assert!(at_legacy[0].file_offset.is_some());
    assert_instance_entries(&engine, &maps, &publish.legacy, true);
    let expected_live: Vec<(u64, (u8, u8), bool, bool)> = publish
        .elements
        .iter()
        .filter(|table| table.index >= 0)
        .map(|table| (table.addr, (3, 2), true, false))
        .collect();
    assert_eq!(live_instances(&engine), sorted_live(expected_live));
    for table in publish.elements.iter().filter(|table| table.index >= 0) {
        assert_instance_entries(&engine, &maps, table, true);
    }

    // Workload counts resolve exactly as on the normal build.
    let coverage = split_coverage(&maps, &publish, &backends, &oracle);
    assert_eq!(coverage.admitted.len(), 30);
    assert!(
        coverage
            .admitted
            .iter()
            .all(|target| slot_targets(&engine).contains(target)),
        "every wrapper call is admitted"
    );

    // Six live list elements plus whatever sweep triples this layout
    // decoded (layout-unknown, so read the sweep's own count).
    let sweep_triples: usize = engine
        .modules
        .iter()
        .flat_map(|module| &module.scanned.interfaces)
        .filter(|interface| interface.table.is_some())
        .count();
    assert_eq!(engine.budget.interface_records_count(), 6 + sweep_triples);
    assert!(
        session.attached_slots.iter().sum::<usize>() == engine.plan().slots.len() - scan_baseline,
        "publication attaches exactly its new slots"
    );
    assert_count_only(&engine);
    assert_costing(&engine, wall, "t8-stripped");
}

/// A manifest that structurally agrees with the legacy-static tables
/// but records a stale identity, forcing the exact-target fallback
/// proof (and `manifest_supported`) rather than direct admission.
fn stale_ls_manifest(
    path: &str,
    entries: &[(String, u64)],
    device: (u64, u64),
    inode: u64,
) -> Manifest {
    let stale_identity = ObjectIdentity {
        kind: IdentityKind::GnuBuildId,
        value: Some("00".into()),
        sha256: Some("00".repeat(32)),
        reusable: true,
        note: None,
    };
    Manifest {
        schema: SCHEMA.to_string(),
        module_path: path.to_string(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.to_string(),
            identity: stale_identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path: path.to_string(),
            device_major: device.0,
            device_minor: device.1,
            inode,
            identity: stale_identity,
        }],
        interface_list: Acquisition::Absent,
        // One legacy surface: the manifest schema allows no more. It
        // binds the first covering table; that table bypasses K=4 while
        // the other four fit the heuristic cap — spill 1 becomes 0.
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: Some(Version {
                major: 2,
                minor: 40,
            }),
            walk: WalkOutcome::Full,
            functions: entries
                .iter()
                .map(|(name, offset)| FunctionRecord {
                    name: name.clone(),
                    resolution: Resolution::Resolved {
                        object: 0,
                        file_offset: *offset,
                    },
                })
                .collect(),
        }],
        vendor_interfaces: vec![],
        alias_groups: vec![],
        selection_evidence: Default::default(),
    }
}

/// Case 9: a non-p11-kit legacy static table. Five file-backed static
/// tables: scan-only spills one past K=4 with unknown names; a stale
/// manifest's exact-target fallback binds one table (bypass + authorized
/// names + linkage "manifest"); a live return merges with the scan
/// instance (bypass + linkage "live_return").
/// Guards: static behavior that must survive the heap work.
#[test]
fn legacy_static_table_scan_manifest_and_live() {
    let build = pub_build();
    let dir = pub_tmp("t9-ls");
    let log = dir.join("ls.log");
    let holder = LsChild::spawn(&build.lshold, &build.ls_provider, &log, "0,1,2,0,43");
    assert_eq!(
        holder.calls,
        vec![(0, 0), (1, 0), (2, 0), (0, 0), (43, 0)],
        "scripted calls return CKR_OK"
    );
    let log_lines: Vec<String> = std::fs::read_to_string(&log)
        .expect("read call log")
        .lines()
        .map(str::to_string)
        .collect();
    let expected_log: Vec<String> = [0, 1, 2, 0, 43]
        .iter()
        .map(|ord| format!("{} {} legacy L{ord} 0 direct 0", holder.pid, holder.pid))
        .collect();
    assert_eq!(log_lines, expected_log, "exact call bytes");
    let maps = MapLite::snapshot(holder.pid);
    let table0 = holder.publish.legacy.clone();
    assert_eq!(table0.nentry, 68);
    for (ord, (_, sym)) in table0.entries.iter().enumerate() {
        assert_eq!(*sym, format!("ls_fn_{ord}"), "distinct entry points");
    }
    let ls_entries: Vec<(String, u64)> = table0
        .entries
        .iter()
        .enumerate()
        .map(|(ord, (addr, _))| {
            (
                pkcs11_module::function_name(ord)
                    .expect("catalog covers legacy ordinals")
                    .to_string(),
                MapLite::file_target(&maps, *addr).1,
            )
        })
        .collect();

    // 9a: scan-only. Five heuristic tables, one spills past K=4.
    let started = Instant::now();
    let engine_a = engine_over_pids(&[holder.pid]);
    assert_eq!(engine_a.modules.len(), 1);
    let scan_tables = &engine_a.modules[0].scanned.tables;
    assert_eq!(scan_tables.len(), 5, "all five static tables decode");
    for table in scan_tables {
        assert_eq!(table.version, (2, 40));
        assert_eq!(table.entries.len(), 68);
        assert!(table.file_offset.is_some(), "file-backed placement");
        assert!(!table.live_return);
        assert!(!table.manifest_supported);
    }
    let mut scan_addrs: Vec<u64> = scan_tables.iter().map(|table| table.address).collect();
    scan_addrs.sort();
    scan_addrs.dedup();
    assert_eq!(scan_addrs.len(), 5, "five distinct instances");
    assert_eq!(engine_a.plan().slots.len(), 68);
    assert_eq!(
        slot_targets(&engine_a),
        printed_targets(&maps, &[table0.clone()])
    );
    assert!(
        engine_a
            .plan()
            .slots
            .iter()
            .all(|slot| slot.names.as_slice() == ["unknown"]),
        "scan-only heuristic tables stay unknown"
    );
    let linkage_a: Vec<&str> = engine_a.plan().modules[0]
        .tables
        .iter()
        .map(|table| table.linkage)
        .collect();
    assert_eq!(linkage_a, vec!["heuristic"; 5], "no sweep triples here");
    assert_eq!(
        engine_a.plan().uncorroborated_candidates,
        1,
        "the fifth heuristic table spills past K=4"
    );
    assert_eq!(engine_a.plan().entries_seen, 5 * 68);
    assert_eq!(engine_a.budget.table_candidates_count(), 5);
    assert_eq!(engine_a.budget.decoded_table_entries_count(), 5 * 68);
    // The scripted calls land on admitted slots.
    for ord in [0, 1, 2, 43] {
        let (path, offset, _) = MapLite::file_target(&maps, table0.entries[ord].0);
        assert!(
            slot_targets(&engine_a).contains(&(path, offset)),
            "called ordinal {ord} is admitted"
        );
    }
    assert_count_only(&engine_a);

    // 9b: a stale manifest's exact-target fallback supports all five.
    let mut engine_b = engine_over_pids(&[holder.pid]);
    let scanned_key = engine_b.modules[0].scanned.key;
    let metadata = std::fs::metadata(&build.ls_provider).unwrap();
    assert_eq!(
        scanned_key.inode,
        metadata.ino(),
        "rendered inode is st_ino"
    );
    let manifest = stale_ls_manifest(
        &build.ls_provider.to_string_lossy(),
        &ls_entries,
        (scanned_key.device.major, scanned_key.device.minor),
        scanned_key.inode,
    );
    let pinning = pin_manifest_objects_deferred(&manifest).expect("manifest pins");
    assert_eq!(pinning.stale.len(), 1, "one stale object");
    assert!(
        matches!(
            pinning.stale[0].reason,
            ManifestStaleReason::IdentityMismatch
        ),
        "stale by identity, not by locator"
    );
    engine_b.manifest_inputs.push(ManifestInput {
        path: PathBuf::from("ls-stale.json"),
        manifest,
        pins: pinning.pins,
        stale: pinning.stale,
    });
    rebuild_discovered(&mut engine_b).expect("fallback proof completes");
    let supported: Vec<u64> = engine_b.modules[0]
        .scanned
        .tables
        .iter()
        .filter(|table| table.manifest_supported)
        .map(|table| table.address)
        .collect();
    assert_eq!(
        supported.len(),
        1,
        "the single surface binds exactly one table"
    );
    assert!(
        engine_b.modules[0]
            .scanned
            .tables
            .iter()
            .all(|table| !table.live_return),
        "no live evidence was observed"
    );
    let mut linkage_b: Vec<&str> = engine_b.plan().modules[0]
        .tables
        .iter()
        .map(|table| table.linkage)
        .collect();
    linkage_b.sort();
    assert_eq!(
        linkage_b,
        vec![
            "heuristic",
            "heuristic",
            "heuristic",
            "heuristic",
            "manifest"
        ],
        "manifest is the strongest evidence on the bound table"
    );
    assert_eq!(
        engine_b.plan().uncorroborated_candidates,
        0,
        "manifest support bypasses K=4"
    );
    assert_eq!(engine_b.plan().slots.len(), 68);
    for slot in &engine_b.plan().slots {
        assert_eq!(slot.names.len(), 1, "one ordinal label per target");
        assert_ne!(slot.names[0], "unknown", "manifest authorizes names");
    }
    assert_eq!(engine_b.counters.manifest_fallbacks.len(), 1);
    assert_count_only(&engine_b);

    // 9c: a live return merges with its scan instance and bypasses.
    let mut engine_c = engine_over_pids(&[holder.pid]);
    let hooks = HookRegistry::builtin();
    let session_c = drain_records(&mut engine_c, vec![gfl_record(holder.pid, &table0, &hooks)]);
    let wall = started.elapsed();
    let at_published: Vec<&ScannedTable> = engine_c.modules[0]
        .scanned
        .tables
        .iter()
        .filter(|table| table.address == table0.addr)
        .collect();
    assert_eq!(
        at_published.len(),
        1,
        "scan and live instances of one static table merge"
    );
    assert!(at_published[0].live_return);
    assert!(at_published[0].file_offset.is_some());
    assert_eq!(engine_c.modules[0].scanned.tables.len(), 5);
    let mut linkage_c: Vec<&str> = engine_c.plan().modules[0]
        .tables
        .iter()
        .map(|table| table.linkage)
        .collect();
    linkage_c.sort();
    assert_eq!(
        linkage_c,
        vec![
            "heuristic",
            "heuristic",
            "heuristic",
            "heuristic",
            "live_return"
        ],
        "the published table bypasses; the rest stay heuristic"
    );
    assert_eq!(engine_c.plan().uncorroborated_candidates, 0);
    assert_eq!(engine_c.plan().slots.len(), 68);
    for slot in &engine_c.plan().slots {
        assert_eq!(slot.names.len(), 1);
        assert_ne!(slot.names[0], "unknown", "the live return authorizes names");
    }
    assert_eq!(
        engine_c.budget.table_candidates_count(),
        5,
        "the live lower deduplicates on the scan's file identity"
    );
    assert_eq!(
        session_c.attached_slots.iter().sum::<usize>(),
        0,
        "the merge adds no new slots to attach"
    );
    assert_count_only(&engine_c);
    assert_costing(&engine_c, wall, "t9-ls");

    holder.release();
}

/// Case 10 (Task 1.6): broad admission on the recognized fixed-family
/// build. Same pre-capture setup as case 7 — five wrappers published
/// before the capture, no live records observed — but broad attaches
/// every validated fixed-family target: the sweep's 4 file-backed
/// templates stay covered, and the 60 anonymous pool tables validate
/// through the shared bracketed reader and admit. Index 4's closures
/// (case 7's honest miss) are admitted here; names stay unauthorized
/// except the sweep's own template[0] interface link.
#[test]
fn broad_fixed_pool_admits_all_validated_templates() {
    let build = pub_build();
    let mut stage = StageChild::spawn(&build.workload, &build.provider);
    for want in 0..5 {
        let (idx, _) = stage.alloc(0, -1);
        assert_eq!(idx, want);
    }
    // Publication happens BEFORE the capture starts.
    let maps = MapLite::snapshot(stage.pid);
    let templates = stage.templates().expect("normal build shows its pool");
    assert_eq!(templates.len(), 64);
    let publish = stage.publish();
    assert_eq!(
        publish
            .elements
            .iter()
            .filter(|table| table.index >= 0)
            .count(),
        5,
        "five heap tables really were published"
    );

    // The capture starts now and observes no live records at all.
    let started = Instant::now();
    let engine = engine_over_pids_broad(&[stage.pid], true);
    let wall = started.elapsed();

    assert_eq!(engine.modules.len(), 1);
    let scanned = &engine.modules[0].scanned;
    assert_eq!(
        scanned.tables.len(),
        64,
        "4 swept templates + 60 validated pool tables"
    );
    assert!(
        scanned.tables.iter().all(|table| table.version == (3, 2)),
        "every instance is a fixed-family table"
    );
    // Identity shape (pinned loudly like t8's link order): the pool
    // crosses the file-tail/anonymous-BSS VMA split inside table 4, so
    // tables 0-4 resolve a file identity (0-3 swept, 4 spanning-read)
    // while tables 5-63 are honestly anonymous (cross-view dedup falls
    // back to slot-level union, exact all the same).
    for (index, printed) in templates.iter().enumerate() {
        if index < 5 {
            let (_, expected_offset, _) = MapLite::file_target(&maps, printed.addr);
            let found = scanned
                .tables
                .iter()
                .find(|table| {
                    table.address == printed.addr || table.file_offset == Some(expected_offset)
                })
                .unwrap_or_else(|| panic!("pool table {index} was validated"));
            assert!(
                found.file_offset.is_some(),
                "pool table {index} resolves a file identity"
            );
        } else {
            let found = scanned
                .tables
                .iter()
                .find(|table| table.address == printed.addr)
                .unwrap_or_else(|| panic!("pool table {index} was validated"));
            assert!(
                found.file_offset.is_none(),
                "pool table {index} is honestly anonymous"
            );
        }
    }
    assert!(
        scanned.tables.iter().all(|table| !table.live_return),
        "no live returns were observed"
    );
    // Distinct physical targets: 6 exercised ordinals x 64 per-index
    // closures, plus the 3 implementations every table shares.
    assert_eq!(slot_targets(&engine), printed_targets(&maps, &templates));
    assert_eq!(engine.plan().slots.len(), 384 + 3);
    assert_eq!(engine.plan().uncorroborated_candidates, 0);
    assert_eq!(engine.plan().entries_seen, 64 * 104);
    // Case 7's miss is admitted here: every published heap wrapper's
    // exercised closures resolve to admitted slots.
    for table in publish.elements.iter().filter(|table| table.index >= 0) {
        for ord in EX_ORDS {
            let (path, offset, _) = MapLite::file_target(&maps, table.entries[ord as usize].0);
            assert!(
                slot_targets(&engine).contains(&(path, offset)),
                "heap {} ord{ord} admits under broad",
                table.index,
            );
        }
    }
    // Names: only the sweep's own template[0] interface link authorizes;
    // the 60 pool tables are unlinked heuristic evidence (`unknown`).
    let claimants: Vec<(&TablePrint, bool)> = templates
        .iter()
        .enumerate()
        .map(|(index, table)| (table, index == 0))
        .collect();
    assert_eq!(
        actual_slot_names(&engine),
        expected_slot_names(&maps, &claimants)
    );
    assert_count_only(&engine);
    assert_costing(&engine, wall, "t10-broad");
}

/// Case 11 (Task 1.6): the unknown-layout build is broad's composition
/// boundary. The stripped provider hides `p11scope_fixed`, so the pool
/// pass recognizes nothing and broad admits exactly the selected set —
/// no more, no less. Publication (case 8) stays the only path in.
#[test]
fn broad_stripped_build_adds_nothing_beyond_selected() {
    let build = pub_build();
    let mut stage = StageChild::spawn(&build.workload, &build.stripped);
    for want in 0..5 {
        let (idx, _) = stage.alloc(0, -1);
        assert_eq!(idx, want);
    }
    let publish = stage.publish();
    assert_eq!(
        publish
            .elements
            .iter()
            .filter(|table| table.index >= 0)
            .count(),
        5,
        "five heap tables really were published"
    );
    assert!(
        stage.templates().is_none(),
        "stripped build hides its layout"
    );

    let started = Instant::now();
    let broad = engine_over_pids_broad(&[stage.pid], true);
    let wall = started.elapsed();
    let selected = engine_over_pids(&[stage.pid]);

    assert_eq!(broad.modules.len(), 1);
    assert_eq!(
        broad.modules[0].scanned.tables.len(),
        selected.modules[0].scanned.tables.len(),
        "broad recognizes no pool without the symbol"
    );
    assert_eq!(slot_targets(&broad), slot_targets(&selected));
    assert_eq!(
        broad.plan().slots.len(),
        selected.plan().slots.len(),
        "broad admits exactly the selected set on unknown layouts"
    );
    assert_count_only(&broad);
    assert_costing(&broad, wall, "t11-broad-stripped");
}

/// Case 12 (Task 1.6): broad is fit-or-refuse-whole. Six validated
/// heuristic tables x 100 distinct targets exceed the 512 slot ceiling:
/// selected admission takes the strongest-evidence prefix (4 tables) and
/// spills 2; broad refuses the module whole with zero spill — a prefix
/// would break the dormant-activation promise without forcing PARTIAL.
#[test]
fn broad_refuses_whole_when_validated_set_exceeds_budget() {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::metadata("/proc/self/ns/mnt").expect("mount namespace");
    let namespace = crate::process::MountNamespaceId {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let key = ObjectKey {
        device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
        inode: 42,
    };
    let object = PinnedObjectId(7);
    let tables: Vec<ScannedTable> = (0..6u32)
        .map(|table| ScannedTable {
            version: (3, 2),
            walk: "full",
            entries: (0..100u32)
                .map(|entry| ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/pool.so".into(),
                    file_offset: u64::from(table * 100 + entry),
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7000 + u64::from(table),
            file_offset: Some(0x3000 + u64::from(table) * 0x400),
            live_return: false,
            manifest_supported: false,
        })
        .collect();
    let module = ReconciledModule {
        scanned: ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: namespace,
            key,
            path: "/pool.so".into(),
            decoder_abi: Some(ElfAbi::Lp64),
            exports: vec!["C_GetFunctionList".into()],
            tables,
            interfaces: vec![],
        },
        object,
        entry_objects: vec![vec![object; 100]; 6],
    };
    let mut selected_counters = DiscoveryCounters::default();
    let selected = build_current_plan(
        std::slice::from_ref(&module),
        &[],
        &PinnedObjects::empty(),
        &mut selected_counters,
        &BTreeSet::new(),
        0,
        0,
        false,
    )
    .expect("selected plan builds");
    assert_eq!(selected.slots.len(), 400);
    assert_eq!(selected.uncorroborated_candidates, 2);
    assert!(selected.modules_skipped.is_empty());

    // Alone, the oversized module refuses everything: the plan fails
    // closed with the whole-module refusal verbatim.
    let mut broad_counters = DiscoveryCounters::default();
    let error = build_current_plan(
        std::slice::from_ref(&module),
        &[],
        &PinnedObjects::empty(),
        &mut broad_counters,
        &BTreeSet::new(),
        0,
        0,
        true,
    )
    .expect_err("broad refuses the oversized module whole");
    let text = format!("{error:?}");
    assert!(
        text.contains("/pool.so") && text.contains("refusing to attach a prefix"),
        "total refusal carries the honest whole-module shape: {text}"
    );

    // Alongside a fitting module, the plan builds: the fitting module
    // admits, the oversized one is skipped whole, and broad spills
    // nothing — never a silent prefix.
    let small_object = PinnedObjectId(8);
    let small = ReconciledModule {
        scanned: ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: namespace,
            key,
            path: "/small.so".into(),
            decoder_abi: Some(ElfAbi::Lp64),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: (0..10u32)
                    .map(|entry| ScannedEntry {
                        name: "C_Sign",
                        object: key,
                        object_path: "/small.so".into(),
                        file_offset: 0x8000 + u64::from(entry),
                    })
                    .collect(),
                null_entries: vec![],
                unpinned: vec![],
                address: 0x9000,
                file_offset: Some(0x9000),
                live_return: false,
                manifest_supported: false,
            }],
            interfaces: vec![],
        },
        object: small_object,
        entry_objects: vec![vec![small_object; 10]],
    };
    let mut mixed_counters = DiscoveryCounters::default();
    let mixed = build_current_plan(
        &[module, small],
        &[],
        &PinnedObjects::empty(),
        &mut mixed_counters,
        &BTreeSet::new(),
        0,
        0,
        true,
    )
    .expect("broad plan builds around the refusal");
    assert_eq!(mixed.slots.len(), 10);
    assert_eq!(mixed.uncorroborated_candidates, 0, "broad never spills");
    assert_eq!(mixed.modules_skipped.len(), 1);
    assert_eq!(mixed.modules_skipped[0].subject, "/pool.so");
}

/// Case 13 (Task 1.6, manual A2 probe): real-p11-kit admission
/// arithmetic. Holds the host libp11-kit mapped-but-dormant in a
/// descendant (python3 + ctypes, no calls) and prints selected-vs-broad
/// admission for the report. Run filtered, alone in the process:
/// `cargo test -p p11scope --lib broad_p11kit -- --ignored --nocapture`.
/// Asserts only host-robust invariants (broad never spills; a total
/// refusal carries the whole-module shape); the exact printed numbers
/// are recorded by hand into the Task 1.6 report.
#[test]
#[ignore = "manual: needs host libp11-kit + python3; run filtered with --ignored --nocapture"]
fn broad_p11kit_admission_arithmetic() {
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(
            "import ctypes, time; \
             ctypes.CDLL('libp11-kit.so.0'); \
             print('READY', flush=True); \
             time.sleep(180)",
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("python3 holds libp11-kit");
    let mut ready = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.as_mut().expect("child stdout")),
        &mut ready,
    )
    .expect("READY line");
    assert_eq!(ready.trim(), "READY");
    let pid = child.id();

    let selected = engine_over_pids(std::slice::from_ref(&pid));
    let selected_tables: usize = selected
        .modules
        .iter()
        .map(|module| module.scanned.tables.len())
        .sum();
    println!(
        "A2 selected: {} module(s) {} table(s) {} slot(s) spill={} refused={}",
        selected.modules.len(),
        selected_tables,
        selected.plan().slots.len(),
        selected.plan().uncorroborated_candidates,
        selected.plan().modules_skipped.len(),
    );
    assert!(
        !selected.plan().slots.is_empty(),
        "selected admits something on a real provider"
    );

    let mut broad = scan_engine_over_pids(std::slice::from_ref(&pid), true);
    match rebuild_discovered(&mut broad) {
        Ok(()) => {
            let broad_tables: usize = broad
                .modules
                .iter()
                .map(|module| module.scanned.tables.len())
                .sum();
            println!(
                "A2 broad: {} module(s) {} table(s) {} slot(s) spill={} refused={}",
                broad.modules.len(),
                broad_tables,
                broad.plan().slots.len(),
                broad.plan().uncorroborated_candidates,
                broad.plan().modules_skipped.len(),
            );
            assert_eq!(
                broad.plan().uncorroborated_candidates,
                0,
                "broad never spills"
            );
        }
        Err(error) => {
            let text = format!("{error:?}");
            println!("A2 broad: total refusal: {text}");
            assert!(
                text.contains("refusing to attach a prefix"),
                "a broad total refusal carries the whole-module shape: {text}"
            );
        }
    }

    child.kill().expect("reap the holder");
    child.wait().expect("reap the holder");
}
