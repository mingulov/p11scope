//! SPDX-License-Identifier: GPL-3.0-or-later
//! D3d identity-backend integration: bounded real-CLI sweep cells.
//!
//! Every behavior is asserted through the public `p11scope inventory`
//! command over owned fixtures, reading the public JSON independently:
//! the userspace sweep cell proves the exact ledgered process/provider
//! edges with zero false edges (byte-identical different-file and
//! data-only negatives included); auto without proof stays
//! userspace/null without loading; forced kernel either proves the full
//! ledgered set through the kernel backend (byte-identical and data-only
//! negatives, all module edges enumerated, per-range coverage over a
//! proof-requiring btrfs fixture) or refuses with its named line before
//! any sink exists; explicit selection outside `--system` is a usage
//! error; `--pid` carries no identity key; stdout and `-o` bytes agree.
//! The ignored `kernel_identity_positive_cell_rejects_refusal` runs the
//! same sweep as a positive-required campaign cell: a refusal fails it,
//! so test success there always means kernel-positive proof.
//!
//! System sweep fixtures run under `inventory-identity-observe.sh`,
//! which execs the observer as their parent: under ptrace_scope=1
//! only a descendant's map_files are readable, so sweep proof
//! requires the observer to be an ancestor of every fixture.
//!
//! `P11SCOPE_IDENTITY_FIXTURE_DIR`, when set, pins the per-cell fixture
//! roots (binaries, providers, READY markers, observer stdout) under it
//! instead of `$CARGO_TARGET_TMPDIR`; the kernel-positive cell asserts
//! that root is a proof-requiring (btrfs) filesystem before its edge,
//! coverage and disclosure assertions can pass.
//!
//! D3a ABBA performance gate (measured 2026-10-10, small sweep cells,
//! forced kernel vs forced userspace on the same host): kernel pass p95
//! is roughly 80% slower than the matched userspace pass, which blocks
//! default-kernel progression under the over-5% rule. Automatic
//! threshold gating is unaffected (below-threshold segments stay
//! userspace by policy, not by timing). No D3a-named artifact path
//! exists for performance gates; this cell file records the outcome.
//!
//! D3d brief item 6 native-lane coverage: pending (scan lane only).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

fn serial_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Sweep-cell fixture root: `$P11SCOPE_IDENTITY_FIXTURE_DIR/<name>` when
/// the caller pins fixtures to a proof-requiring filesystem, else a fresh
/// `$CARGO_TARGET_TMPDIR/<name>`. Only the per-cell subdir is cleaned.
fn fixture_dir(name: &str) -> PathBuf {
    let dir = match std::env::var_os("P11SCOPE_IDENTITY_FIXTURE_DIR") {
        Some(root) => PathBuf::from(root).join(name),
        None => PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name),
    };
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Whether `dir` lives on btrfs (statfs magic): the proof-requiring
/// filesystem the kernel-positive cell demands for its fixtures.
fn dir_is_btrfs(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: statfs writes the whole struct on success.
    let rc = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
    assert_eq!(rc, 0, "statfs {}", dir.display());
    // SAFETY: success above initialized it.
    let stat = unsafe { stat.assume_init() };
    stat.f_type as u64 == BTRFS_SUPER_MAGIC
}

/// A tempdir the report trust check accepts under any umask.
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn gcc(dir: &Path, out: &str, source: &Path, args: &[&str], libs: &[&str]) -> PathBuf {
    let bin = dir.join(out);
    let mut cmd = Command::new("gcc");
    cmd.args(args).arg("-o").arg(&bin).arg(source).args(libs);
    assert!(
        cmd.status().unwrap().success(),
        "gcc failed for {out}: {cmd:?}"
    );
    bin
}

fn fixture_source(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn matrix_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/discover/tests/fixture/version_matrix.c")
}

/// Kill owned fixture PIDs (reaped by init after the observer exits).
fn kill_pids(pids: &[u32]) {
    for &pid in pids {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    for &pid in pids {
        while std::fs::metadata(format!("/proc/{pid}")).is_ok() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn ready_pid(ready_dir: &Path, name: &str) -> u32 {
    let text = std::fs::read_to_string(ready_dir.join(format!("{name}.ready"))).unwrap();
    text.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// Independent ground truth: executable mappings of `provider` in `pid`
/// from /proc, read without the observer.
fn exec_ranges_for(pid: u32, provider: &Path) -> Vec<(u64, u64)> {
    fixture_ranges_for(pid, provider)
        .into_iter()
        .filter(|range| range.permissions[2] == b'x')
        .map(|range| (range.start, range.end))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FixtureRole {
    H1,
    H2,
    H3,
    Copy,
    DataOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FixtureFileId {
    dev: u64,
    ino: u64,
}

impl FixtureFileId {
    fn from_file(file: &std::fs::File) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

#[derive(Debug, Clone)]
struct FixtureRange {
    start: u64,
    end: u64,
    file_offset: u64,
    permissions: [u8; 4],
}

fn fixture_ranges_for(pid: u32, provider: &Path) -> Vec<FixtureRange> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    parse_fixture_ranges(&maps, provider).expect("valid independent fixture mappings")
}

fn parse_fixture_ranges(maps: &str, provider: &Path) -> Result<Vec<FixtureRange>, String> {
    let target = provider.to_str().ok_or("non-UTF8 fixture path")?;
    let mut ranges = Vec::new();
    for line in maps.lines() {
        let mut remaining = line;
        let mut fields = [""; 5];
        for field in &mut fields {
            remaining = remaining.trim_start();
            let end = remaining
                .find(char::is_whitespace)
                .unwrap_or(remaining.len());
            *field = &remaining[..end];
            remaining = &remaining[end..];
        }
        if remaining.trim_start() != target {
            continue;
        }
        let (low, high) = fields[0].split_once('-').ok_or("invalid fixture range")?;
        let start = u64::from_str_radix(low, 16).map_err(|_| "invalid fixture range start")?;
        let end = u64::from_str_radix(high, 16).map_err(|_| "invalid fixture range end")?;
        let len = end
            .checked_sub(start)
            .filter(|len| *len > 0)
            .ok_or("empty or reversed fixture range")?;
        let permissions: [u8; 4] = fields[1]
            .as_bytes()
            .try_into()
            .map_err(|_| "invalid fixture permissions")?;
        if !matches!(
            permissions,
            [b'r' | b'-', b'w' | b'-', b'x' | b'-', b'p' | b's']
        ) {
            return Err("invalid fixture permissions".into());
        }
        let file_offset =
            u64::from_str_radix(fields[2], 16).map_err(|_| "invalid fixture file offset")?;
        file_offset
            .checked_add(len)
            .ok_or("fixture file extent overflow")?;
        ranges.push(FixtureRange {
            start,
            end,
            file_offset,
            permissions,
        });
    }
    Ok(ranges)
}

fn callers_for(doc: &Value, pid: u64) -> Vec<&Value> {
    doc["callers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|caller| caller["pid"] == pid)
        .collect()
}

fn module_for(doc: &Value, so_name: &str) -> Value {
    let found: Vec<&Value> = doc["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|module| {
            module["paths"]
                .as_array()
                .unwrap()
                .iter()
                .any(|path| path.as_str().unwrap().rsplit('/').next().unwrap() == so_name)
        })
        .collect();
    assert_eq!(found.len(), 1, "expected exactly one module for {so_name}");
    found[0].clone()
}

/// Deep-scanned PIDs from the observer's progress lines (independent
/// of the document): `deep-scanning i/n (pid X)...` lines only — swept
/// holders that prove also appear in `admitted (pid X)` lines, which
/// must not count as selected.
fn selected_pids(stderr: &str) -> BTreeSet<u32> {
    let mut selected = BTreeSet::new();
    for line in stderr.lines() {
        if !line.contains("deep-scanning") {
            continue;
        }
        if let Some(rest) = line.split("(pid ").nth(1)
            && let Some(pid) = rest.split(')').next()
            && let Ok(pid) = pid.parse::<u32>()
        {
            selected.insert(pid);
        }
    }
    selected
}

struct BuiltFixtures {
    dir: PathBuf,
    driver: PathBuf,
    dataonly: PathBuf,
    provider: PathBuf,
    copy: PathBuf,
    provider_file: std::fs::File,
    copy_file: std::fs::File,
    provider_id: FixtureFileId,
    copy_id: FixtureFileId,
}

fn build_fixtures(name: &str, minor: u32, so_name: &str) -> BuiltFixtures {
    let dir = fixture_dir(name);
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let dataonly = gcc(
        &dir,
        "dataonly",
        &fixture_source("identity-dataonly.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &[],
    );
    let minor_flag = format!("-DLEGACY_MINOR={minor}");
    let provider = gcc(
        &dir,
        so_name,
        &matrix_source(),
        &["-shared", "-fPIC", &minor_flag],
        &[],
    );
    let copy = dir.join("id-copy.so");
    std::fs::copy(&provider, &copy).unwrap();
    assert_eq!(
        std::fs::read(&provider).unwrap(),
        std::fs::read(&copy).unwrap(),
        "byte-identical copy"
    );
    assert_ne!(
        std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&provider).unwrap()),
        std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&copy).unwrap()),
        "different file"
    );
    let provider_file = std::fs::File::open(&provider).unwrap();
    let copy_file = std::fs::File::open(&copy).unwrap();
    let provider_id = FixtureFileId::from_file(&provider_file).unwrap();
    let copy_id = FixtureFileId::from_file(&copy_file).unwrap();
    assert_ne!(provider_id, copy_id, "distinct held physical files");
    BuiltFixtures {
        dir,
        driver,
        dataonly,
        provider,
        copy,
        provider_file,
        copy_file,
        provider_id,
        copy_id,
    }
}

struct ObserveOutcome {
    doc: Value,
    selected: BTreeSet<u32>,
    holder_pids: Vec<u32>,
    copy_pid: Option<u32>,
    dataonly_pid: Option<u32>,
    /// Independent ground truth per holder: executable provider ranges
    /// from /proc while the holders live (established before coverage).
    holder_ranges: Vec<Vec<(u64, u64)>>,
    role_pids: BTreeMap<FixtureRole, u32>,
    role_ranges: BTreeMap<FixtureRole, Vec<FixtureRange>>,
}

/// One sweep attempt: fresh fixtures under the observer-as-parent
/// helper, ground truth from /proc while holders live, fixtures
/// reaped before returning. Returns `None` when the observer itself
/// fails (the forced-kernel refusal arm inspects that path).
fn attempt_observe(
    fixtures: &BuiltFixtures,
    attempt: &str,
    set: &str,
    observer_args: &[String],
    cap: usize,
    report_dir: &Path,
) -> Option<ObserveOutcome> {
    let ready = fixtures.dir.join(format!("ready-{attempt}"));
    let _ = std::fs::remove_dir_all(&ready);
    let out_file = fixtures.dir.join(format!("out-{attempt}.json"));
    let _ = std::fs::remove_file(&out_file);
    let report = report_dir.join(format!("report-{attempt}.json"));
    let mut args: Vec<String> = observer_args.to_vec();
    args.push("--json".to_string());
    args.push("-o".to_string());
    args.push(report.to_str().unwrap().to_string());
    let mut cmd = Command::new("sh");
    cmd.arg(fixture_source("inventory-identity-observe.sh"))
        .args(&args)
        .env("INV_DRIVER", &fixtures.driver)
        .env("INV_DATAONLY", &fixtures.dataonly)
        .env("INV_SET", set)
        .env("INV_P1", &fixtures.provider)
        .env("INV_COPY", &fixtures.copy)
        .env("INV_READY", &ready)
        .env("INV_OUT", &out_file)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd.spawn().unwrap().wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    // Fixture PIDs from READY files (observer output plays no role).
    let mut pids = Vec::new();
    let mut holders = Vec::new();
    for name in ["H1", "H2", "H3"] {
        let pid = ready_pid(&ready, name);
        holders.push(pid);
        pids.push(pid);
    }
    let (copy_pid, dataonly_pid) = if set == "sweep" {
        let copy = ready_pid(&ready, "C");
        let data = ready_pid(&ready, "D");
        pids.push(copy);
        pids.push(data);
        (Some(copy), Some(data))
    } else {
        (None, None)
    };
    // Ground truth while holders live (mappings are static sleeps).
    let mut holder_ranges = Vec::new();
    for pid in &holders {
        let ranges = exec_ranges_for(*pid, &fixtures.provider);
        assert!(
            !ranges.is_empty(),
            "holder {pid} maps the provider exec (cap {cap})"
        );
        holder_ranges.push(ranges);
    }
    let mut role_pids = BTreeMap::from([
        (FixtureRole::H1, holders[0]),
        (FixtureRole::H2, holders[1]),
        (FixtureRole::H3, holders[2]),
    ]);
    if let (Some(copy), Some(dataonly)) = (copy_pid, dataonly_pid) {
        role_pids.insert(FixtureRole::Copy, copy);
        role_pids.insert(FixtureRole::DataOnly, dataonly);
    }
    let role_ranges = role_pids
        .iter()
        .map(|(&role, &pid)| {
            let path = if role == FixtureRole::Copy {
                &fixtures.copy
            } else {
                &fixtures.provider
            };
            (role, fixture_ranges_for(pid, path))
        })
        .collect();
    kill_pids(&pids);
    if !output.status.success() {
        // Refusal arm: no document, but the stderr line and the
        // missing sink are the assertions. Stash stderr for them.
        std::fs::write(fixtures.dir.join(format!("refused-{attempt}.txt")), &stderr).unwrap();
        return None;
    }
    assert!(output.stdout.is_empty(), "helper stdout stays empty");
    let stdout = std::fs::read(&out_file).unwrap();
    let file = std::fs::read(&report).unwrap();
    assert_eq!(file, stdout, "stdout and -o bytes agree (cap {cap})");
    let doc: Value = serde_json::from_slice(&file).unwrap();
    let selected = selected_pids(&stderr);
    assert!(
        stderr.contains("process maps (cap "),
        "cap {cap} must force sweep proof"
    );
    Some(ObserveOutcome {
        doc,
        selected,
        holder_pids: holders,
        copy_pid,
        dataonly_pid,
        holder_ranges,
        role_pids,
        role_ranges,
    })
}

/// Ground-truth exec range counts, established from /proc before any
/// coverage claim: every holder maps the provider exec (a zero-range
/// holder would make its edge vacuous), and the same provider through
/// the same loader maps the same count everywhere (measured: 1 per
/// holder on this toolchain). A positive edge proves every caller range
/// or no edge at all (`prove_match` over `is_caller_range`), so each
/// edged holder below covers its whole ground-truth set.
fn ground_truth_range_counts(observed: &ObserveOutcome) -> Vec<usize> {
    let counts: Vec<usize> = observed.holder_ranges.iter().map(Vec::len).collect();
    assert_eq!(
        counts.len(),
        observed.holder_pids.len(),
        "one ground-truth set per holder"
    );
    for (pid, count) in observed.holder_pids.iter().zip(&counts) {
        assert!(*count >= 1, "holder {pid} maps no provider exec range");
    }
    assert!(
        counts.iter().all(|count| *count == counts[0]),
        "uniform provider layout across holders: {counts:?}"
    );
    counts
}

type D4ExecutableRange = (FixtureRole, FixtureFileId, u64, u64, [u8; 4]);

#[derive(Debug)]
struct D4Projection {
    backend: &'static str,
    provider: FixtureFileId,
    edges: BTreeSet<FixtureRole>,
    executable_ranges: Vec<D4ExecutableRange>,
}

// This is an acceptance oracle over public output and independent fixture
// inputs. Its range rows are not a transcript of backend proof verdicts.
fn d4_projection(
    fixtures: &BuiltFixtures,
    observed: Option<&ObserveOutcome>,
    backend: &str,
) -> Result<D4Projection, String> {
    let backend = match backend {
        "userspace" => "userspace",
        "kernel" => "kernel",
        _ => return Err("invalid requested identity backend".into()),
    };
    let observed = observed.ok_or("command refused or failed")?;
    if fixtures.provider_id == fixtures.copy_id
        || FixtureFileId::from_file(&fixtures.provider_file)? != fixtures.provider_id
        || FixtureFileId::from_file(&fixtures.copy_file)? != fixtures.copy_id
    {
        return Err("fixture physical file identity changed or aliases the copy".into());
    }
    let doc = &observed.doc;
    let observation = doc["observation"]
        .as_object()
        .ok_or("missing observation")?;
    let identity = observation
        .get("identity")
        .and_then(Value::as_object)
        .ok_or("missing identity result")?;
    if doc["schema"] != "p11scope/inventory/v1"
        || doc["scope"] != "system"
        || identity.get("backend").and_then(Value::as_str) != Some(backend)
        || identity.get("fallback") != Some(&Value::Null)
        || observation.get("usage_feed") != Some(&Value::Bool(false))
        || observation.contains_key("lane")
    {
        return Err("required scan backend refused, fell back or changed observation mode".into());
    }
    let expected_roles = BTreeSet::from([
        FixtureRole::H1,
        FixtureRole::H2,
        FixtureRole::H3,
        FixtureRole::Copy,
        FixtureRole::DataOnly,
    ]);
    if observed.role_pids.keys().copied().collect::<BTreeSet<_>>() != expected_roles
        || observed
            .role_ranges
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != expected_roles
        || observed.role_pids.values().any(|pid| *pid == 0)
        || observed.role_pids.values().collect::<BTreeSet<_>>().len() != expected_roles.len()
    {
        return Err("incomplete or duplicate independent fixture roles".into());
    }
    let expected_holders =
        [FixtureRole::H1, FixtureRole::H2, FixtureRole::H3].map(|role| observed.role_pids[&role]);
    if observed.holder_pids != expected_holders
        || observed.copy_pid != Some(observed.role_pids[&FixtureRole::Copy])
        || observed.dataonly_pid != Some(observed.role_pids[&FixtureRole::DataOnly])
    {
        return Err("independent role ledger disagrees with owned process population".into());
    }
    let mut executable_ranges = Vec::new();
    for (&role, ranges) in &observed.role_ranges {
        if ranges.is_empty() {
            return Err(format!("{role:?} has no independent live mapping"));
        }
        let mut executable = 0;
        for range in ranges {
            let len = range
                .end
                .checked_sub(range.start)
                .filter(|len| *len > 0)
                .ok_or("empty or reversed independent fixture range")?;
            range
                .file_offset
                .checked_add(len)
                .ok_or("independent fixture extent overflow")?;
            if !matches!(
                range.permissions,
                [b'r' | b'-', b'w' | b'-', b'x' | b'-', b'p' | b's']
            ) {
                return Err("invalid independent fixture permissions".into());
            }
            if range.permissions[2] == b'x' {
                executable += 1;
                let file = if role == FixtureRole::Copy {
                    fixtures.copy_id
                } else {
                    fixtures.provider_id
                };
                executable_ranges.push((role, file, range.file_offset, len, range.permissions));
            }
        }
        if (role == FixtureRole::DataOnly && executable != 0)
            || (role != FixtureRole::DataOnly && executable == 0)
        {
            return Err(format!(
                "{role:?} has the wrong independent executable population"
            ));
        }
    }
    // Sort a Vec, not a set: two equal file-relative mappings stay two inputs.
    executable_ranges.sort_unstable();
    let callers = doc["callers"].as_array().ok_or("missing callers")?;
    let mut caller_pids = BTreeMap::new();
    for caller in callers {
        let id = caller["id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("invalid caller ID")?;
        let pid = caller["pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or("invalid caller PID")?;
        if caller_pids.insert(id, pid).is_some() {
            return Err("duplicate public caller ID".into());
        }
    }
    let mut caller_roles = BTreeMap::new();
    for (&role, &pid) in &observed.role_pids {
        let ids: Vec<_> = caller_pids
            .iter()
            .filter(|(_, actual_pid)| **actual_pid == pid)
            .map(|(&id, _)| id)
            .collect();
        if ids.len() > 1 || (role != FixtureRole::DataOnly && ids.len() != 1) {
            return Err(format!(
                "{role:?} is missing or ambiguous in public callers"
            ));
        }
        if let Some(id) = ids.first() {
            caller_roles.insert(*id, role);
        }
    }
    let modules = doc["modules"].as_array().ok_or("missing modules")?;
    let path = fixtures.provider.to_str().ok_or("non-UTF8 fixture path")?;
    let mut module_ids = BTreeSet::new();
    let mut original = None;
    for module in modules {
        let id = module["id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("invalid module ID")?;
        if !module_ids.insert(id) {
            return Err("duplicate public module ID".into());
        }
        let paths = module["paths"].as_array().ok_or("missing module paths")?;
        if paths
            .iter()
            .any(|candidate| candidate.as_str() == Some(path))
            && original.replace(id).is_some()
        {
            return Err("ambiguous original-provider module row".into());
        }
    }
    let original = original.ok_or("missing original-provider module row")?;
    let mut edges = BTreeSet::new();
    for edge in doc["edges"].as_array().ok_or("missing edges")? {
        if !edge["entries"]["observation"]
            .as_str()
            .is_some_and(|value| value.starts_with("unknown"))
            || edge["entries"]["coverage"]["state"] != "unknown"
        {
            return Err("scan-only edge invents usage coverage".into());
        }
        if edge["module"].as_str() != Some(original) {
            continue;
        }
        let caller = edge["caller"].as_str().ok_or("missing edge caller")?;
        let role = caller_roles
            .get(caller)
            .ok_or("foreign original-provider edge")?;
        if !matches!(role, FixtureRole::H1 | FixtureRole::H2 | FixtureRole::H3)
            || edge["mapping"]["state"] != "mapped"
            || !edges.insert(*role)
        {
            return Err("wrong, uncertain or duplicate original-provider edge".into());
        }
    }
    if edges != BTreeSet::from([FixtureRole::H1, FixtureRole::H2, FixtureRole::H3]) {
        return Err("incomplete original-provider edge set".into());
    }
    Ok(D4Projection {
        backend,
        provider: fixtures.provider_id,
        edges,
        executable_ranges,
    })
}

fn d4_pair(userspace: &D4Projection, kernel: &D4Projection) -> Result<(), String> {
    if userspace.backend != "userspace"
        || kernel.backend != "kernel"
        || userspace.provider != kernel.provider
        || userspace.edges != kernel.edges
        || userspace.executable_ranges != kernel.executable_ranges
    {
        return Err("backend legs differ in physical provider, exact edges or input ranges".into());
    }
    Ok(())
}

type FixtureFileStamp = (FixtureFileId, u64, i64, i64);

fn d4_fixture_stamps(fixtures: &BuiltFixtures) -> Result<[FixtureFileStamp; 2], String> {
    use std::os::unix::fs::MetadataExt as _;
    let stamp = |file: &std::fs::File| -> Result<FixtureFileStamp, String> {
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        Ok((
            FixtureFileId {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        ))
    };
    Ok([stamp(&fixtures.provider_file)?, stamp(&fixtures.copy_file)?])
}

fn d4_capture_leg(
    fixtures: &BuiltFixtures,
    backend: &str,
    report_dir: &Path,
) -> Result<D4Projection, String> {
    for cap in [8usize, 32, 128] {
        let mut args = forced_kernel_args(fixtures, cap);
        let index = args
            .iter()
            .position(|arg| arg == "--identity-backend")
            .unwrap();
        args[index + 1] = backend.to_owned();
        let attempt = format!("d4-{backend}-{cap}");
        let observed = attempt_observe(fixtures, &attempt, "sweep", &args, cap, report_dir);
        // A refusal/fallback/wrong edge fails immediately, including an attempt
        // whose deep-scan versus swept population was not the selected shape.
        let projection = d4_projection(fixtures, observed.as_ref(), backend)?;
        if sweep_selection_qualifies(observed.as_ref().expect("validated observation")) {
            return Ok(projection);
        }
    }
    Err("no cap retained one selected supplier and two swept holders".into())
}

/// Functional Btrfs scan baseline only: fresh PIDs and public IDs normalize
/// through independent roles, held file identities and file-relative inputs.
/// Public edges do not enumerate live proof rows; complete-range acceptance is
/// separately covered at the actual kernel adapter/attribution seam. This does
/// not close D4 collision/rollover/overlay, native, remote or performance gates.
#[test]
#[ignore = "development-host Btrfs/privileged lane; gcc-builds fixtures and rejects every refusal"]
fn d4_btrfs_scan_backends_match_exact_fixture_population() {
    let _guard = serial_guard();
    let fixtures = build_fixtures("inventory-identity-d4-paired", 42, "id-d4.so");
    assert!(
        dir_is_btrfs(&fixtures.dir),
        "paired baseline requires actual Btrfs fixtures"
    );
    let report_dir = private_dir();
    let held = d4_fixture_stamps(&fixtures).unwrap();
    let userspace = d4_capture_leg(&fixtures, "userspace", report_dir.path()).unwrap();
    assert_eq!(
        d4_fixture_stamps(&fixtures).unwrap(),
        held,
        "files changed in userspace leg"
    );
    let kernel = d4_capture_leg(&fixtures, "kernel", report_dir.path()).unwrap();
    assert_eq!(
        d4_fixture_stamps(&fixtures).unwrap(),
        held,
        "files changed in kernel leg"
    );
    d4_pair(&userspace, &kernel).unwrap();
}

/// D3d bounded userspace sweep cell: three holders dlopen the complete
/// provider ELF through the normal loader under a sweep-forcing cap
/// (deep-scan cannot bypass sweep proof); at least two holders stay
/// unselected while a separate selected holder supplies the held
/// provider pins; the ledger names the expected holder/provider edges;
/// a byte-identical different file and a data-only mapping are
/// negatives. Swept holders prove only where the host lets the
/// observer read map_files (privileged here); elsewhere they stay
/// honest unknowns, never false edges — the full three-edge proof is
/// the privileged production cell.
#[test]
fn d3d_userspace_sweep_cell_proves_exact_ledgered_edges() {
    let _guard = serial_guard();
    let fixtures = build_fixtures("inventory-identity-userspace", 40, "id-p1.so");
    let report_dir = private_dir();
    let mut outcome = None;
    for (attempt, cap) in ["a", "b", "c"].into_iter().zip([8usize, 32, 128]) {
        let observed = attempt_observe(
            &fixtures,
            attempt,
            "sweep",
            &[
                "--system".to_string(),
                "--capture".to_string(),
                "scan".to_string(),
                "--identity-backend".to_string(),
                "userspace".to_string(),
                "--module".to_string(),
                fixtures.provider.to_str().unwrap().to_string(),
                "--max-scan-pids".to_string(),
                cap.to_string(),
            ],
            cap,
            report_dir.path(),
        )
        .expect("userspace sweep observes");
        let selected_holders = observed
            .holder_pids
            .iter()
            .filter(|pid| observed.selected.contains(pid))
            .count();
        if selected_holders >= 1 && observed.holder_pids.len() - selected_holders >= 2 {
            outcome = Some(observed);
            break;
        }
    }
    let observed = outcome.expect("a cap with a selected supplier and two swept holders");

    // The selected supplier always proves (deep scan needs no
    // map_files); swept holders prove where the host allows and stay
    // honest unknowns otherwise. No holder ever edges falsely.
    let module = module_for(&observed.doc, "id-p1.so");
    let module_id = module["id"].as_str().unwrap();
    let mut edge_callers = BTreeSet::new();
    for edge in observed.doc["edges"].as_array().unwrap() {
        if edge["module"] == module_id {
            edge_callers.insert(edge["caller"].as_str().unwrap().to_string());
        }
    }
    assert!(
        !edge_callers.is_empty(),
        "nonempty expected edge set (the supplier proves)"
    );
    let mut swept_proved = 0;
    let mut proved = Vec::new();
    for pid in &observed.holder_pids {
        let callers = callers_for(&observed.doc, u64::from(*pid));
        let caller_id = callers.first().map(|caller| caller["id"].as_str().unwrap());
        let edged = caller_id.is_some_and(|id| edge_callers.contains(id));
        if observed.selected.contains(pid) {
            assert_eq!(callers.len(), 1, "selected holder {pid} is one caller");
            assert!(edged, "selected holder {pid} proves its edge");
        } else if edged {
            swept_proved += 1;
        }
        proved.push(edged);
    }
    if swept_proved < 2 {
        // Honest degradation: the gaps name map_files_unavailable for
        // the unproved swept holders, never silence or false edges.
        let gaps = observed.doc["gaps"].as_array().unwrap();
        assert!(
            gaps.iter().any(|gap| gap["subject"] == "maps attribution"
                && gap["reason"]
                    .as_str()
                    .unwrap()
                    .contains("map_files_unavailable")),
            "unproved sweep stays an honest map_files gap"
        );
    }
    // Per-range coverage: the ground-truth sets are established above
    // (nonempty, uniform); each proved holder covers its whole set (an
    // edge is all caller ranges or nothing), so the covered count is the
    // proved holders' full ground truth — at least the supplier — and
    // every unproved swept range stays gap-disclosed, never silent.
    let counts = ground_truth_range_counts(&observed);
    let covered: usize = proved
        .iter()
        .zip(&counts)
        .map(|(edged, count)| usize::from(*edged) * count)
        .sum();
    assert!(
        covered >= counts[0],
        "at least the supplier is fully covered: {covered} of {}",
        counts.iter().sum::<usize>()
    );
    // Every edge to the provider comes from a ledgered holder: zero
    // false edges, whatever the host proved.
    for caller_id in &edge_callers {
        let pid = observed.doc["callers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|caller| caller["id"] == *caller_id)
            .unwrap()["pid"]
            .as_u64()
            .unwrap() as u32;
        assert!(
            observed.holder_pids.contains(&pid),
            "edge caller {caller_id} (pid {pid}) is a ledgered holder"
        );
    }
    for (pid, why) in [
        (observed.copy_pid.unwrap(), "byte-identical different file"),
        (observed.dataonly_pid.unwrap(), "data-only mapping"),
    ] {
        for caller in callers_for(&observed.doc, u64::from(pid)) {
            let caller_id = caller["id"].as_str().unwrap();
            assert!(
                !edge_callers.contains(caller_id),
                "{why} (pid {pid}) must not edge to the original provider"
            );
        }
    }

    // Disclosure: userspace with no fallback; scan lane only with
    // honest scan-only unknowns (no lane key, no usage feed, unknown
    // per-edge usage observations).
    let identity = &observed.doc["observation"]["identity"];
    assert_eq!(identity["backend"], "userspace");
    assert_eq!(identity["fallback"], Value::Null);
    assert_eq!(identity.as_object().unwrap().len(), 2);
    assert!(observed.doc["observation"].get("lane").is_none());
    assert_eq!(observed.doc["observation"]["usage_feed"], false);
    for edge in observed.doc["edges"].as_array().unwrap() {
        assert!(
            edge["entries"]["observation"]
                .as_str()
                .unwrap()
                .starts_with("unknown"),
            "scan-only edge stays unknown: {}",
            edge["entries"]["observation"]
        );
    }
}

/// D3d auto without proof: the default selection over a complete scan
/// (no sweep) loads nothing and reports userspace/null.
#[test]
fn d3d_auto_without_proof_reports_userspace_null() {
    let _guard = serial_guard();
    let fixtures = build_fixtures("inventory-identity-auto-noproof", 41, "id-a1.so");
    let report_dir = private_dir();
    let ready = fixtures.dir.join("ready-auto");
    let out_file = fixtures.dir.join("out-auto.json");
    let report = report_dir.path().join("report-auto.json");
    let output = Command::new("sh")
        .arg(fixture_source("inventory-identity-observe.sh"))
        .arg("--system")
        .arg("--capture")
        .arg("scan")
        .arg("--module")
        .arg(&fixtures.provider)
        .arg("--max-scan-pids")
        .arg("65536")
        .arg("--json")
        .arg("-o")
        .arg(&report)
        .env("INV_DRIVER", &fixtures.driver)
        .env("INV_DATAONLY", &fixtures.dataonly)
        .env("INV_SET", "trio")
        .env("INV_P1", &fixtures.provider)
        .env("INV_COPY", &fixtures.copy)
        .env("INV_READY", &ready)
        .env("INV_OUT", &out_file)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "{stderr}");
    let holders: Vec<u32> = ["H1", "H2", "H3"]
        .iter()
        .map(|n| ready_pid(&ready, n))
        .collect();
    for pid in &holders {
        assert!(!exec_ranges_for(*pid, &fixtures.provider).is_empty());
    }
    kill_pids(&holders);
    let stdout = std::fs::read(&out_file).unwrap();
    let file = std::fs::read(&report).unwrap();
    assert_eq!(file, stdout);
    let doc: Value = serde_json::from_slice(&file).unwrap();
    let identity = &doc["observation"]["identity"];
    assert_eq!(identity["backend"], "userspace");
    assert_eq!(identity["fallback"], Value::Null);
    let module = module_for(&doc, "id-a1.so");
    for pid in &holders {
        let callers = callers_for(&doc, u64::from(*pid));
        assert_eq!(callers.len(), 1);
        let caller_id = callers[0]["id"].as_str().unwrap();
        let edges: Vec<&Value> = doc["edges"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|edge| edge["caller"] == caller_id && edge["module"] == module["id"])
            .collect();
        assert_eq!(edges.len(), 1, "holder {pid} keeps its edge without sweep");
    }
}

/// Forced-kernel sweep arguments over the owned provider fixture.
fn forced_kernel_args(fixtures: &BuiltFixtures, cap: usize) -> Vec<String> {
    vec![
        "--system".to_string(),
        "--capture".to_string(),
        "scan".to_string(),
        "--identity-backend".to_string(),
        "kernel".to_string(),
        "--module".to_string(),
        fixtures.provider.to_str().unwrap().to_string(),
        "--max-scan-pids".to_string(),
        cap.to_string(),
    ]
}

/// A sweep attempt qualifies when a selected supplier stays swept
/// beside two unselected holders; otherwise a wider cap is tried.
fn sweep_selection_qualifies(observed: &ObserveOutcome) -> bool {
    let selected = observed
        .holder_pids
        .iter()
        .filter(|pid| observed.selected.contains(pid))
        .count();
    selected >= 1 && observed.holder_pids.len() - selected >= 2
}

/// The one kernel-positive bar both forced-kernel tests share: exact
/// three holder/provider edges, zero false edges over all enumerated
/// module edges, both negatives un-edged, and per-range coverage of
/// every owned requested exec range over a proof-requiring btrfs
/// fixture. A successful empty capture never satisfies this gate.
fn assert_forced_kernel_positive(fixtures: &BuiltFixtures, observed: &ObserveOutcome) {
    // A kernel-positive claim needs a proof-requiring filesystem:
    // no-proof fast paths cannot satisfy this gate.
    assert!(
        dir_is_btrfs(&fixtures.dir),
        "kernel-positive cell requires its fixtures on btrfs; set \
         P11SCOPE_IDENTITY_FIXTURE_DIR to a btrfs dir (got {})",
        fixtures.dir.display()
    );
    let identity = &observed.doc["observation"]["identity"];
    assert_eq!(identity["backend"], "kernel");
    assert_eq!(
        identity["fallback"],
        Value::Null,
        "a forced proof cell admits no fallback"
    );
    let module = module_for(&observed.doc, "id-k1.so");
    let module_id = module["id"].as_str().unwrap();
    // All module edges enumerated: every edge to the provider comes
    // from a ledgered holder (zero false edges), and every holder
    // keeps exactly one kernel edge.
    let mut edge_callers = BTreeSet::new();
    for edge in observed.doc["edges"].as_array().unwrap() {
        if edge["module"] == module_id {
            edge_callers.insert(edge["caller"].as_str().unwrap().to_string());
        }
    }
    assert_eq!(edge_callers.len(), 3, "complete expected edge set");
    for pid in &observed.holder_pids {
        let callers = callers_for(&observed.doc, u64::from(*pid));
        assert_eq!(callers.len(), 1, "holder {pid} is one caller");
        let caller_id = callers[0]["id"].as_str().unwrap();
        assert!(
            edge_callers.contains(caller_id),
            "holder {pid} keeps its kernel edge"
        );
    }
    for caller_id in &edge_callers {
        let pid = observed.doc["callers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|caller| caller["id"] == *caller_id)
            .unwrap()["pid"]
            .as_u64()
            .unwrap() as u32;
        assert!(
            observed.holder_pids.contains(&pid),
            "edge caller {caller_id} (pid {pid}) is a ledgered holder"
        );
    }
    // Full ledger negatives: the byte-identical different file and
    // the data-only mapping never edge to the original provider. The
    // copy holder is inventoried (a nonempty caller set), so its
    // negative is never vacuous.
    assert!(
        !callers_for(&observed.doc, u64::from(observed.copy_pid.unwrap())).is_empty(),
        "copy holder is an inventoried caller"
    );
    for (pid, why) in [
        (observed.copy_pid.unwrap(), "byte-identical different file"),
        (observed.dataonly_pid.unwrap(), "data-only mapping"),
    ] {
        for caller in callers_for(&observed.doc, u64::from(pid)) {
            let caller_id = caller["id"].as_str().unwrap();
            assert!(
                !edge_callers.contains(caller_id),
                "{why} (pid {pid}) must not edge to the original provider"
            );
        }
    }
    // Per-range coverage: the ground-truth sets are established from
    // /proc (nonempty, uniform), and all three holders edge — an edge
    // is all caller ranges or nothing, so every owned requested exec
    // range is covered.
    let counts = ground_truth_range_counts(observed);
    let total: usize = counts.iter().sum();
    assert!(
        total >= observed.holder_pids.len(),
        "nonempty covered range set: {total}"
    );
}

/// D3d forced kernel through the real command: either the kernel
/// backend proves the full ledgered set on a proof-requiring btrfs
/// fixture (privileged capable host) or the refusal names its finite
/// reason before any sink exists (anything else). The positive arm is
/// the shared [`assert_forced_kernel_positive`] bar.
#[test]
fn d3d_forced_kernel_proves_or_refuses_before_sinks() {
    let _guard = serial_guard();
    let fixtures = build_fixtures("inventory-identity-forced", 42, "id-k1.so");
    let report_dir = private_dir();
    for (attempt, cap) in ["a", "b", "c"].into_iter().zip([8usize, 32, 128]) {
        let observed = attempt_observe(
            &fixtures,
            attempt,
            "sweep",
            &forced_kernel_args(&fixtures, cap),
            cap,
            report_dir.path(),
        );
        let Some(observed) = observed else {
            let stderr =
                std::fs::read_to_string(fixtures.dir.join(format!("refused-{attempt}.txt")))
                    .unwrap();
            assert!(
                stderr.contains("--identity-backend kernel: kernel identity is unavailable: "),
                "named refusal: {stderr}"
            );
            let reason = stderr
                .split("--identity-backend kernel: kernel identity is unavailable: ")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .trim_matches(|c| c == '\'' || c == '"' || c == '\n');
            assert!(
                [
                    "no_btf",
                    "kernel_fix_missing",
                    "no_task_iter_pidfd",
                    "numbering_mismatch",
                    "numbering_unknown",
                    "permission_denied",
                    "load_failed",
                    "probe_failed",
                ]
                .contains(&reason),
                "finite reason: {reason}"
            );
            assert!(!reason.contains('/'), "no raw paths: {reason}");
            assert!(
                !report_dir
                    .path()
                    .join(format!("report-{attempt}.json"))
                    .exists(),
                "no sink is created before refusal"
            );
            return;
        };
        // Success: only a cap with a selected supplier and two swept
        // holders satisfies this gate; otherwise try a wider cap.
        if !sweep_selection_qualifies(&observed) {
            continue;
        }
        assert_forced_kernel_positive(&fixtures, &observed);
        return;
    }
    panic!("no cap left a selected supplier with two swept holders");
}

/// G28 positive-required campaign cell: the same forced-kernel sweep
/// as [`d3d_forced_kernel_proves_or_refuses_before_sinks`], but an
/// intentional refusal or fallback fails instead of satisfying the
/// test. Test success here always means kernel-positive proof over the
/// shared bar, never a classified refusal. Run explicitly in the
/// privileged capable lane with btrfs fixtures.
#[test]
#[ignore = "privileged capable lane with btrfs fixtures; fails on any kernel refusal"]
fn kernel_identity_positive_cell_rejects_refusal() {
    let _guard = serial_guard();
    let fixtures = build_fixtures("inventory-identity-forced", 42, "id-k1.so");
    let report_dir = private_dir();
    for (attempt, cap) in ["a", "b", "c"].into_iter().zip([8usize, 32, 128]) {
        let observed = attempt_observe(
            &fixtures,
            attempt,
            "sweep",
            &forced_kernel_args(&fixtures, cap),
            cap,
            report_dir.path(),
        );
        let Some(observed) = observed else {
            let stderr =
                std::fs::read_to_string(fixtures.dir.join(format!("refused-{attempt}.txt")))
                    .unwrap();
            panic!("kernel-positive cell refused instead of proving: {stderr}");
        };
        if !sweep_selection_qualifies(&observed) {
            continue;
        }
        assert_forced_kernel_positive(&fixtures, &observed);
        return;
    }
    panic!("no cap left a selected supplier with two swept holders");
}

/// D3d: explicit identity selection outside `--system` is a usage
/// error; duplicate, missing and invalid values are usage errors.
#[test]
fn d3d_identity_selection_outside_system_is_a_usage_error() {
    for args in [
        vec!["--pid", "1", "--identity-backend", "kernel"],
        vec!["--pid", "1", "--identity-backend", "userspace"],
        vec![
            "--cgroup",
            "/sys/fs/cgroup/owned.scope",
            "--identity-backend",
            "kernel",
        ],
        vec!["--system", "--identity-backend", "both"],
        vec![
            "--system",
            "--identity-backend",
            "kernel",
            "--identity-backend",
            "auto",
        ],
        vec!["--system", "--identity-backend"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
            .arg("inventory")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "args {args:?}");
        assert!(output.stdout.is_empty(), "args {args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(
            stderr.contains("--identity-backend"),
            "args {args:?}: {stderr}"
        );
    }
}

/// An owned provider-mapping fixture process for the `--pid` cell
/// (sibling observation needs no map_files).
struct PidFixture {
    child: Option<std::process::Child>,
    pid: u32,
}

impl Drop for PidFixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// D3d: a dashboard run with identity carries the backend disclosure
/// in its final document through the real interactive path: pty stdout
/// and stdin, the alternate-screen takeover (never the degraded pipe
/// path), a duration end, and the `-o` report.
#[test]
fn d3d_dashboard_run_with_identity_discloses_backend() {
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;
    let _guard = serial_guard();
    let dir = fixture_dir("inventory-identity-dashboard");
    let provider = gcc(
        &dir,
        "id-d1.so",
        &matrix_source(),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=44"],
        &[],
    );
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let ready = dir.join("d.ready");
    let mut holder = PidFixture {
        child: None,
        pid: 0,
    };
    holder.child = Some(
        Command::new(&driver)
            .arg("--ready")
            .arg(&ready)
            .arg("--sleep")
            .arg("120")
            .arg(&provider)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    holder.pid = loop {
        if let Ok(text) = std::fs::read_to_string(&ready)
            && let Some(pid) = text.split_whitespace().nth(1)
        {
            break pid.parse::<u32>().unwrap();
        }
        assert!(Instant::now() < deadline, "holder never became ready");
        std::thread::sleep(Duration::from_millis(50));
    };
    // The dashboard's terminal: stdout and stdin are the slave (live
    // keys, no input sent — the duration ends the run); a drainer owns
    // the only master handle so frames never block the run.
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `openpty` writes two fresh fds; the other pointers may be null.
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    };
    assert_eq!(opened, 0, "openpty");
    // SAFETY: fresh descriptors owned from here on.
    let (master_file, slave_file) = unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    };
    let mut drain_master = master_file.try_clone().unwrap();
    drop(master_file);
    let drainer = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let mut chunk = [0u8; 65536];
        while let Ok(read) = drain_master.read(&mut chunk) {
            if read == 0 {
                break;
            }
            seen.extend_from_slice(&chunk[..read]);
        }
        seen
    });
    let out_dir = private_dir();
    let report = out_dir.path().join("dashboard.json");
    let mut observer = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .arg("inventory")
        .arg("--system")
        .arg("--capture")
        .arg("scan")
        .arg("--module")
        .arg(&provider)
        .arg("--identity-backend")
        .arg("userspace")
        .arg("--json")
        .arg("--dashboard")
        .arg("--duration")
        .arg("8s")
        .arg("-o")
        .arg(&report)
        .stdin(slave_file.try_clone().unwrap())
        .stdout(slave_file)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = observer.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = observer.kill();
            panic!("dashboard run never ended");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "dashboard run: {status}");
    // The writer is gone: buffered stderr drains, then EOF, promptly.
    let mut err = Vec::new();
    observer
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut err)
        .unwrap();
    let seen = drainer.join().unwrap();
    // The real interactive path took over the terminal (alternate
    // screen), never the degraded pipe path.
    assert!(
        seen.windows(8).any(|window| window == b"\x1b[?1049h"),
        "dashboard took over the terminal"
    );
    let stderr = String::from_utf8_lossy(&err).to_string();
    assert!(!stderr.contains("degraded"), "{stderr}");
    let doc: Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    let identity = &doc["observation"]["identity"];
    assert_eq!(identity["backend"], "userspace");
    assert_eq!(identity["fallback"], Value::Null);
    assert_eq!(identity.as_object().unwrap().len(), 2);
}

/// D3d: `--pid` carries no identity key (implicit default loads
/// nothing); stdout and `-o` bytes still agree.
#[test]
fn d3d_pid_carries_no_identity_key() {
    let _guard = serial_guard();
    let dir = tmp("inventory-identity-pid");
    let provider = gcc(
        &dir,
        "id-pid.so",
        &matrix_source(),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=43"],
        &[],
    );
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let ready = dir.join("p.ready");
    let mut holder = PidFixture {
        child: None,
        pid: 0,
    };
    holder.child = Some(
        Command::new(&driver)
            .arg("--ready")
            .arg(&ready)
            .arg("--sleep")
            .arg("120")
            .arg(&provider)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let pid = loop {
        if let Ok(text) = std::fs::read_to_string(&ready)
            && let Some(pid) = text.split_whitespace().nth(1)
        {
            break pid.parse::<u32>().unwrap();
        }
        assert!(Instant::now() < deadline, "holder never became ready");
        std::thread::sleep(Duration::from_millis(50));
    };
    holder.pid = pid;
    let out_dir = private_dir();
    let out = out_dir.path().join("pid.json");
    let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .arg("inventory")
        .arg("--pid")
        .arg(pid.to_string())
        .arg("--capture")
        .arg("scan")
        .arg("--json")
        .arg("-o")
        .arg(&out)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "{stderr}");
    let file = std::fs::read(&out).unwrap();
    assert_eq!(file, output.stdout);
    let doc: Value = serde_json::from_slice(&file).unwrap();
    assert!(
        doc["observation"].get("identity").is_none(),
        "{}",
        doc["observation"]
    );
}

// D4 controls exercise the same strict evaluator used by the paired CLI cell.
// The owned files and independent role/range inputs do not execute a provider.
fn d4_control_fixtures() -> (tempfile::TempDir, BuiltFixtures) {
    use std::os::unix::fs::MetadataExt as _;

    let dir = private_dir();
    let provider = dir.path().join("id-d4.so");
    let copy = dir.path().join("id-copy.so");
    std::fs::write(&provider, b"same bytes, separate physical fixture files\n").unwrap();
    std::fs::copy(&provider, &copy).unwrap();
    let provider_file = std::fs::File::open(&provider).unwrap();
    let copy_file = std::fs::File::open(&copy).unwrap();
    let provider_metadata = provider_file.metadata().unwrap();
    let copy_metadata = copy_file.metadata().unwrap();
    let fixtures = BuiltFixtures {
        dir: dir.path().to_path_buf(),
        driver: dir.path().join("unused-driver"),
        dataonly: dir.path().join("unused-dataonly"),
        provider,
        copy,
        provider_id: FixtureFileId {
            dev: provider_metadata.dev(),
            ino: provider_metadata.ino(),
        },
        copy_id: FixtureFileId {
            dev: copy_metadata.dev(),
            ino: copy_metadata.ino(),
        },
        provider_file,
        copy_file,
    };
    assert_ne!(fixtures.provider_id, fixtures.copy_id);
    (dir, fixtures)
}

fn d4_control_observation(fixtures: &BuiltFixtures, backend: &str, epoch: u32) -> ObserveOutcome {
    let roles = [
        FixtureRole::H1,
        FixtureRole::H2,
        FixtureRole::H3,
        FixtureRole::Copy,
        FixtureRole::DataOnly,
    ];
    let role_pids: BTreeMap<_, _> = roles
        .into_iter()
        .enumerate()
        .map(|(index, role)| (role, 10_000 + epoch * 10 + index as u32))
        .collect();
    let address = 0x1000_0000 + u64::from(epoch) * 0x1000_0000;
    let holder_inputs = vec![
        FixtureRange {
            start: address,
            end: address + 0x2000,
            file_offset: 0x1000,
            permissions: *b"r-xp",
        },
        FixtureRange {
            start: address + 0x4000,
            end: address + 0x5000,
            file_offset: 0x5000,
            permissions: *b"r-xp",
        },
    ];
    let mut role_ranges = BTreeMap::from([
        (FixtureRole::H1, holder_inputs.clone()),
        (FixtureRole::H2, holder_inputs.clone()),
        (FixtureRole::H3, holder_inputs.clone()),
        (FixtureRole::Copy, vec![holder_inputs[0].clone()]),
    ]);
    role_ranges.insert(
        FixtureRole::DataOnly,
        vec![FixtureRange {
            start: address + 0x8000,
            end: address + 0x10_000,
            file_offset: 0,
            permissions: *b"r--p",
        }],
    );
    // Reuse a complete public scan document, changing only the owned population.
    let mut doc: Value =
        serde_json::from_str(include_str!("fixtures/inventory-diff/scan-current.json")).unwrap();
    let caller = doc["callers"][0].clone();
    let edge = doc["edges"][0].clone();
    let module_id = format!("module-{epoch}");
    let callers: Vec<Value> = roles
        .into_iter()
        .enumerate()
        .map(|(index, role)| {
            let mut row = caller.clone();
            row["id"] = serde_json::json!(format!("caller-{epoch}-{index}"));
            row["pid"] = serde_json::json!(role_pids[&role]);
            row
        })
        .collect();
    let edges: Vec<Value> = (0..3)
        .map(|index| {
            let mut row = edge.clone();
            row["caller"] = callers[index]["id"].clone();
            row["module"] = serde_json::json!(module_id);
            row["mapping"]["evidence"] = serde_json::json!(if index == 0 {
                "deep_scan"
            } else {
                "maps_match"
            });
            row
        })
        .collect();
    doc["scope"] = serde_json::json!("system");
    doc["callers"] = serde_json::json!(callers);
    doc["edges"] = serde_json::json!(edges);
    doc["modules"][0]["id"] = serde_json::json!(module_id);
    doc["modules"][0]["paths"] = serde_json::json!([fixtures.provider]);
    doc["observation"]["identity"] = serde_json::json!({
        "backend": backend,
        "fallback": null,
    });
    doc["gaps"] = serde_json::json!([]);
    doc["budgets"]["callers"]["occupied"] = serde_json::json!(5);
    doc["budgets"]["edges"]["occupied"] = serde_json::json!(3);
    let holder_pids = vec![
        role_pids[&FixtureRole::H1],
        role_pids[&FixtureRole::H2],
        role_pids[&FixtureRole::H3],
    ];
    ObserveOutcome {
        doc,
        selected: BTreeSet::from([holder_pids[0]]),
        holder_ranges: vec![
            vec![
                (address, address + 0x2000),
                (address + 0x4000, address + 0x5000)
            ];
            3
        ],
        holder_pids,
        copy_pid: Some(role_pids[&FixtureRole::Copy]),
        dataonly_pid: Some(role_pids[&FixtureRole::DataOnly]),
        role_pids,
        role_ranges,
    }
}

#[test]
fn d4_parity_normalizes_fresh_pids_ids_and_virtual_addresses() {
    let (_dir, fixtures) = d4_control_fixtures();
    let userspace = d4_control_observation(&fixtures, "userspace", 1);
    let kernel = d4_control_observation(&fixtures, "kernel", 2);
    assert_ne!(userspace.holder_pids, kernel.holder_pids);
    assert_ne!(
        userspace.doc["modules"][0]["id"],
        kernel.doc["modules"][0]["id"]
    );
    assert_ne!(userspace.holder_ranges, kernel.holder_ranges);
    let userspace = d4_projection(&fixtures, Some(&userspace), "userspace").unwrap();
    let kernel = d4_projection(&fixtures, Some(&kernel), "kernel").unwrap();
    assert_eq!(userspace.provider, fixtures.provider_id);
    assert_eq!(
        userspace.edges,
        BTreeSet::from([FixtureRole::H1, FixtureRole::H2, FixtureRole::H3])
    );
    assert_eq!(
        userspace.executable_ranges,
        vec![
            (
                FixtureRole::H1,
                fixtures.provider_id,
                0x1000,
                0x2000,
                *b"r-xp"
            ),
            (
                FixtureRole::H1,
                fixtures.provider_id,
                0x5000,
                0x1000,
                *b"r-xp"
            ),
            (
                FixtureRole::H2,
                fixtures.provider_id,
                0x1000,
                0x2000,
                *b"r-xp"
            ),
            (
                FixtureRole::H2,
                fixtures.provider_id,
                0x5000,
                0x1000,
                *b"r-xp"
            ),
            (
                FixtureRole::H3,
                fixtures.provider_id,
                0x1000,
                0x2000,
                *b"r-xp"
            ),
            (
                FixtureRole::H3,
                fixtures.provider_id,
                0x5000,
                0x1000,
                *b"r-xp"
            ),
            (
                FixtureRole::Copy,
                fixtures.copy_id,
                0x1000,
                0x2000,
                *b"r-xp"
            ),
        ]
    );
    d4_pair(&userspace, &kernel).unwrap();
}

#[test]
fn d4_parity_rejects_wrong_duplicate_missing_and_foreign_edges() {
    let (_dir, fixtures) = d4_control_fixtures();
    for backend in ["userspace", "kernel"] {
        let mut observation = d4_control_observation(&fixtures, backend, 1);
        let healthy = observation.doc.clone();
        let mut missing = healthy.clone();
        missing["edges"].as_array_mut().unwrap().remove(1);
        let mut compensated = healthy.clone();
        compensated["edges"][1]["caller"] = compensated["callers"][3]["id"].clone();
        let mut duplicate = healthy.clone();
        let repeated = duplicate["edges"][0].clone();
        duplicate["edges"].as_array_mut().unwrap().push(repeated);
        let mut foreign = healthy.clone();
        let mut row = foreign["callers"][0].clone();
        row["id"] = serde_json::json!("foreign-caller");
        row["pid"] = serde_json::json!(77_777);
        foreign["callers"].as_array_mut().unwrap().push(row);
        foreign["edges"][1]["caller"] = serde_json::json!("foreign-caller");
        let mut dataonly = healthy.clone();
        dataonly["edges"][1]["caller"] = dataonly["callers"][4]["id"].clone();
        let mut empty = healthy.clone();
        empty["edges"] = serde_json::json!([]);
        for (name, bad) in [
            ("missing H2 even if both legs omit it", missing),
            ("same total with copy replacing H2", compensated),
            ("duplicate H1", duplicate),
            ("same total with foreign caller replacing H2", foreign),
            ("data-only mapper replacing H2", dataonly),
            ("empty edges", empty),
        ] {
            observation.doc = bad;
            assert!(
                d4_projection(&fixtures, Some(&observation), backend).is_err(),
                "{backend} accepted {name}"
            );
            observation.doc = healthy.clone();
            assert!(d4_projection(&fixtures, Some(&observation), backend).is_ok());
        }
    }
}

#[test]
fn d4_parity_rejects_refusal_fallback_and_partial_legs() {
    let (_dir, fixtures) = d4_control_fixtures();
    assert!(d4_projection(&fixtures, None, "kernel").is_err());
    assert!(d4_projection(&fixtures, None, "userspace").is_err());
    let mut kernel = d4_control_observation(&fixtures, "kernel", 1);
    kernel.doc["observation"]["identity"]["fallback"] = serde_json::json!("stream_invalid");
    assert!(d4_projection(&fixtures, Some(&kernel), "kernel").is_err());
    kernel.doc["observation"]["identity"]["fallback"] = Value::Null;
    assert!(d4_projection(&fixtures, Some(&kernel), "kernel").is_ok());
    kernel.doc["observation"]["identity"]["backend"] = serde_json::json!("userspace");
    assert!(d4_projection(&fixtures, Some(&kernel), "kernel").is_err());
    let mut userspace = d4_control_observation(&fixtures, "userspace", 2);
    let healthy = userspace.doc.clone();
    userspace.doc["edges"].as_array_mut().unwrap().remove(1);
    userspace.doc["gaps"] = serde_json::json!([{
        "subject": "maps attribution", "reason": "map_files_unavailable",
        "caller": null, "module": null, "pid": userspace.holder_pids[1],
        "budget": null, "repeats": 1,
    }]);
    assert!(d4_projection(&fixtures, Some(&userspace), "userspace").is_err());
    userspace.doc = healthy.clone();
    userspace.doc["observation"]["usage_feed"] = serde_json::json!(true);
    assert!(d4_projection(&fixtures, Some(&userspace), "userspace").is_err());
    userspace.doc = healthy.clone();
    userspace.doc["edges"][0]["entries"]["observation"] = serde_json::json!("observed");
    assert!(d4_projection(&fixtures, Some(&userspace), "userspace").is_err());
    userspace.doc = healthy;
    assert!(d4_projection(&fixtures, Some(&userspace), "userspace").is_ok());
}

#[test]
fn d4_parity_rejects_changed_physical_file_and_input_ranges() {
    let (_dir, fixtures) = d4_control_fixtures();
    let (_other_dir, other_files) = d4_control_fixtures();
    assert_eq!(
        std::fs::read(&fixtures.provider).unwrap(),
        std::fs::read(&other_files.provider).unwrap()
    );
    assert_ne!(fixtures.provider_id, other_files.provider_id);
    let userspace = d4_control_observation(&fixtures, "userspace", 1);
    let first = d4_projection(&fixtures, Some(&userspace), "userspace").unwrap();
    let other = d4_control_observation(&other_files, "kernel", 2);
    let other = d4_projection(&other_files, Some(&other), "kernel").unwrap();
    assert!(
        d4_pair(&first, &other).is_err(),
        "equal bytes joined different physical files"
    );
    for mutation in [
        "offset",
        "missing",
        "duplicate",
        "empty",
        "missing-negative",
        "executable-negative",
    ] {
        let mut kernel = d4_control_observation(&fixtures, "kernel", 2);
        match mutation {
            "offset" => {
                kernel.role_ranges.get_mut(&FixtureRole::H2).unwrap()[0].file_offset += 0x1000
            }
            "missing" => {
                kernel.role_ranges.get_mut(&FixtureRole::H2).unwrap().pop();
            }
            "duplicate" => {
                let rows = kernel.role_ranges.get_mut(&FixtureRole::H2).unwrap();
                rows.push(rows[0].clone());
            }
            "empty" => kernel
                .role_ranges
                .get_mut(&FixtureRole::H2)
                .unwrap()
                .clear(),
            "missing-negative" => {
                kernel.role_pids.remove(&FixtureRole::DataOnly);
            }
            "executable-negative" => {
                kernel.role_ranges.get_mut(&FixtureRole::DataOnly).unwrap()[0].permissions =
                    *b"r-xp"
            }
            _ => unreachable!(),
        }
        assert!(
            d4_projection(&fixtures, Some(&kernel), "kernel")
                .and_then(|second| d4_pair(&first, &second))
                .is_err(),
            "accepted {mutation} input ranges"
        );
        let restored = d4_control_observation(&fixtures, "kernel", 2);
        let restored = d4_projection(&fixtures, Some(&restored), "kernel").unwrap();
        d4_pair(&first, &restored).unwrap();
    }
}

#[test]
fn d4_fixture_range_parser_keeps_offsets_permissions_and_multiplicity() {
    let provider = Path::new("/owned/id-d4.so");
    let maps = "1000-3000 r-xp 00001000 00:23 42 /owned/id-d4.so\n\
                5000-7000 r-xp 00001000 00:23 42 /owned/id-d4.so\n\
                9000-a000 r--p 00000000 00:23 42 /owned/id-d4.so\n\
                b000-c000 r-xp 00009000 00:23 43 /owned/id-copy.so\n";
    let rows = parse_fixture_ranges(maps, provider).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(
        (
            rows[0].start,
            rows[0].end,
            rows[0].file_offset,
            rows[0].permissions
        ),
        (0x1000, 0x3000, 0x1000, *b"r-xp")
    );
    assert_eq!(
        (
            rows[1].start,
            rows[1].end,
            rows[1].file_offset,
            rows[1].permissions
        ),
        (0x5000, 0x7000, 0x1000, *b"r-xp")
    );
    assert_eq!(
        (
            rows[2].start,
            rows[2].end,
            rows[2].file_offset,
            rows[2].permissions
        ),
        (0x9000, 0xa000, 0, *b"r--p")
    );
    for bad in [
        "1000-1000 r-xp 00001000 00:23 42 /owned/id-d4.so\n",
        "3000-1000 r-xp 00001000 00:23 42 /owned/id-d4.so\n",
        "1000-3000 r-xp bad-offset 00:23 42 /owned/id-d4.so\n",
    ] {
        assert!(
            parse_fixture_ranges(bad, provider).is_err(),
            "accepted {bad:?}"
        );
        assert_eq!(parse_fixture_ranges(maps, provider).unwrap().len(), 3);
    }
}
