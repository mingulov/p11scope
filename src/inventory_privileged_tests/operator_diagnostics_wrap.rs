//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned32-pair indexed physical entry-count gate. No semantic/API/104-slot claim.
//! Prebuilt-only, paired normal/default diagnostics; no recorder injection.
use super::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

const TARGETS: u64 = 32;
const COUNTED: u64 = 400;
const SHARED: u64 = 258;
const RUN_SECONDS: u64 = 900;
const INPUT_LIMIT: u64 = 16 * 1024 * 1024;

/// Parameterized wrap schedule: `counted` A rounds, `shared` shared rounds,
/// then the fence/proof pair. The G21 gate always runs `FULL_SCHEDULE`
/// (400/258/900s); the short full-transition pilot runs `PILOT_SCHEDULE`
/// (32/4/540s) at default cadence and default diagnostic capacities. The
/// pilot makes no wrap claim: it measures settling, gap shapes and footer
/// production. Every validator that depends on the schedule takes these
/// values as arguments; the `COUNTED`/`SHARED` consts below only anchor the
/// full-gate wrappers, which keep reading the bare consts so a schedule
/// slip cannot silently reshape the gate.
struct WrapSchedule {
    counted: u64,
    shared: u64,
    run_seconds: u64,
    deadline_ms: u64,
}
const PILOT_SCHEDULE: WrapSchedule = WrapSchedule {
    counted: 32,
    shared: 4,
    run_seconds: 540,
    deadline_ms: 590_000,
};

/// Workload trailing CLI arguments `[NONCE, DEADLINE_MS, COUNTED, SHARED]`
/// for a schedule, with the fixture binary's own bounds enforced first
/// (deadline 1..=900_000, counted 1..=400, shared 1..=258) plus the
/// harness/fixture lifetime coordination: the workload's own deadline
/// must cover the harness run budget, or the fixture would self-cancel
/// mid-leg. Pure so unit tests pin the coordination without a fixture.
fn schedule_args(schedule: &WrapSchedule) -> Result<Vec<String>> {
    ensure!(
        schedule.deadline_ms >= schedule.run_seconds * 1000,
        "workload deadline {}ms does not cover the {}s run budget",
        schedule.deadline_ms,
        schedule.run_seconds
    );
    ensure!(
        (1..=900_000).contains(&schedule.deadline_ms),
        "workload deadline out of range 1..=900000: {}",
        schedule.deadline_ms
    );
    ensure!(
        (1..=COUNTED).contains(&schedule.counted),
        "counted rounds out of range 1..={COUNTED}: {}",
        schedule.counted
    );
    ensure!(
        (1..=SHARED).contains(&schedule.shared),
        "shared rounds out of range 1..={SHARED}: {}",
        schedule.shared
    );
    Ok(vec![
        "0123456789abcdef0123456789abcdef".to_owned(),
        schedule.deadline_ms.to_string(),
        schedule.counted.to_string(),
        schedule.shared.to_string(),
    ])
}

struct WrapWorkload {
    process: LedgerProcess,
    control: std::fs::File,
    dir: tempfile::TempDir,
}
impl WrapWorkload {
    fn spawn() -> Result<Self> {
        Self::spawn_profile(false)
    }
    fn spawn_profile(probe: bool) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let source = std::env::var_os("P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR")
            .context("supply the controller-verified prebuilt32-object fixture directory")?;
        let dir = tempfile::tempdir()?;
        copy_wrap_prebuilt(Path::new(&source), dir.path())?;
        let fifo = dir.path().join("control");
        ensure!(
            Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&fifo)
                .status()?
                .success()
        );
        let out = dir.path().join("workload.out");
        let child = Command::new(dir.path().join("workload"))
            .args([
                dir.path().to_path_buf(),
                fifo.clone(),
                dir.path().join("calls.jsonl"),
            ])
            .args(if probe {
                vec![
                    "0123456789abcdef0123456789abcdef",
                    "90000",
                    "3",
                    "1",
                    "probe",
                ]
            } else {
                vec!["0123456789abcdef0123456789abcdef", "900000", "400", "258"]
            })
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out)?)
            .stderr(std::fs::File::create(dir.path().join("workload.err"))?)
            .spawn()?;
        let process = LedgerProcess { child, out };
        process.wait_for("{\"event\":\"prepared\",", Duration::from_secs(5))?;
        let control = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(fifo)?;
        Ok(Self {
            process,
            control,
            dir,
        })
    }
    /// Spawn the full-transition workload (A, shared, fence, proof) under
    /// an explicit schedule. The bounds mirror the fixture binary's own
    /// `number()` limits (`diagnostics-wrap-ledger.c`), so a bad schedule
    /// is refused here with its values, never as a workload exit-2.
    fn spawn_schedule(schedule: &WrapSchedule) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let args = schedule_args(schedule)?;
        let source = std::env::var_os("P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR")
            .context("supply the controller-verified prebuilt32-object fixture directory")?;
        let dir = tempfile::tempdir()?;
        copy_wrap_prebuilt(Path::new(&source), dir.path())?;
        let fifo = dir.path().join("control");
        ensure!(
            Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&fifo)
                .status()?
                .success()
        );
        let out = dir.path().join("workload.out");
        let child = Command::new(dir.path().join("workload"))
            .args([
                dir.path().to_path_buf(),
                fifo.clone(),
                dir.path().join("calls.jsonl"),
            ])
            .args(args)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out)?)
            .stderr(std::fs::File::create(dir.path().join("workload.err"))?)
            .spawn()?;
        let process = LedgerProcess { child, out };
        process.wait_for("{\"event\":\"prepared\",", Duration::from_secs(5))?;
        let control = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(fifo)?;
        Ok(Self {
            process,
            control,
            dir,
        })
    }
    fn check_mapping(&self, name: &str) -> Result<()> {
        use crate::discovery::identity::{map_files_identity, self_mapped_identity};
        use std::os::unix::ffi::OsStrExt;
        let path = self.dir.path().join(name);
        let file = std::fs::File::open(&path)?;
        let held = self_mapped_identity(&file).map_err(anyhow::Error::msg)?;
        let maps = p11scope_manifest::maps::parse_maps(&std::fs::read(format!(
            "/proc/{}/maps",
            self.process.pid()
        ))?)
        .map_err(anyhow::Error::msg)?;
        let loaded = maps
            .iter()
            .find(|entry| {
                entry.permissions[2] == b'x'
                    && entry.raw_path.as_deref() == Some(path.as_os_str().as_bytes())
            })
            .context(format!("{name} has no owned executable mapping"))?;
        let target = map_files_identity(self.process.pid(), loaded.start, loaded.end)?;
        ensure!(
            held == target,
            "held and loaded fixture file differ: {name}"
        );
        Ok(())
    }
    fn command(&self, command: &str, event: &str, round: u64) -> Result<()> {
        writeln!(&self.control, "{command}")?;
        self.process.wait_for(
            &format!("{{\"event\":\"{event}\",\"round\":{round},"),
            Duration::from_secs(5),
        )
    }
    fn check_commons(&self) -> Result<()> {
        for index in 0..32 {
            self.check_mapping(&format!("libdemotion-common-{index:02}.so"))?;
        }
        Ok(())
    }
    fn check_providers(&self, side: char) -> Result<()> {
        for index in 0..32 {
            self.check_mapping(&format!("provider-{side}-{index:02}.so"))?;
        }
        Ok(())
    }
}

/// Read only newly complete JSONL lines. A partial last line remains at the old
/// file offset and cannot masquerade as a committed capture milestone.
fn new_lines(path: &Path, offset: &mut u64) -> Result<Vec<serde_json::Value>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    new_lines_from(&mut file, offset)
}

/// Read newly complete JSONL lines from an already-open file. Split from
/// [`new_lines`] so the live-file reader can fstat the same handle it reads
/// (no rotate-between-stat-and-open window).
fn new_lines_from(file: &mut std::fs::File, offset: &mut u64) -> Result<Vec<serde_json::Value>> {
    file.seek(SeekFrom::Start(*offset))?;
    let mut bytes = Vec::new();
    file.take(INPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= INPUT_LIMIT,
        "owned JSONL delta exceeds16MiB"
    );
    let Some(end) = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|at| at + 1)
    else {
        return Ok(Vec::new());
    };
    let rows = bytes[..end]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    *offset += end as u64;
    Ok(rows)
}

/// Parse the provider index from an owned module path. Only the exact
/// indexed suffixes (`provider-A-%02d.so`, `provider-B-%02d.so`) identify a
/// wrap edge; anything else is foreign to this gate.
fn provider_index(path: &str, side: char) -> Option<u32> {
    let file = path.rsplit('/').next().unwrap_or(path);
    let prefix = if side == 'A' {
        "provider-A-"
    } else {
        "provider-B-"
    };
    let index: u32 = file
        .strip_prefix(prefix)?
        .strip_suffix(".so")?
        .parse()
        .ok()?;
    (u64::from(index) < TARGETS).then_some(index)
}

/// Rotated event-segment sequence numbers (`events.jsonl.N`) present next
/// to the live file, ascending. The engine names rotations sequentially
/// and never rewrites a rotated segment, so each is read whole exactly once.
fn rotated_segment_seqs(live: &Path) -> Vec<u64> {
    let live_name = live
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let mut seqs = Vec::new();
    let Some(parent) = live.parent() else {
        return seqs;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return seqs;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(suffix) = name
            .strip_prefix(live_name)
            .and_then(|rest| rest.strip_prefix('.'))
        else {
            continue;
        };
        if let Ok(seq) = suffix.parse::<u64>() {
            seqs.push(seq);
        }
    }
    seqs.sort_unstable();
    seqs
}

#[derive(Default)]
struct PassView {
    consumed_segments: BTreeSet<u64>,
    segment_offsets: BTreeMap<u64, u64>,
    live_offset: u64,
    live_id: Option<(u64, u64)>,
    last_seq: Option<u64>,
    a: BTreeMap<u32, serde_json::Value>,
    b: BTreeMap<u32, serde_json::Value>,
    evidence: Vec<GapEvidence>,
    evidence_index: HashMap<(Option<String>, Option<String>, String, String), usize>,
    caller_id: Option<String>,
    module_a: BTreeMap<u32, String>,
    module_b: BTreeMap<u32, String>,
    commits: u64,
}
impl PassView {
    /// All 32 A-edge counts in index order, or `None` while any edge is
    /// still unobserved. Milestones gate on the full set, never a prefix.
    fn a_counts(&self) -> Option<Vec<u64>> {
        (0..TARGETS as u32)
            .map(|index| self.a.get(&index)?.get("entries")?.get("count")?.as_u64())
            .collect()
    }
    /// All 32 B-edge counts in index order, or `None` while any edge is
    /// still unobserved.
    fn b_counts(&self) -> Option<Vec<u64>> {
        (0..TARGETS as u32)
            .map(|index| self.b.get(&index)?.get("entries")?.get("count")?.as_u64())
            .collect()
    }
    /// All 32 A module ids in index order, or `None` while any is unknown.
    fn modules_a(&self) -> Option<Vec<String>> {
        (0..TARGETS as u32)
            .map(|index| self.module_a.get(&index).cloned())
            .collect()
    }
    /// All 32 B module ids in index order, or `None` while any is unknown.
    fn modules_b(&self) -> Option<Vec<String>> {
        (0..TARGETS as u32)
            .map(|index| self.module_b.get(&index).cloned())
            .collect()
    }
    fn side_armed(side: &BTreeMap<u32, serde_json::Value>) -> bool {
        side.len() == TARGETS as usize
            && side
                .values()
                .all(|edge| edge["capture"] == "armed" && edge["presence"] == "mapped")
    }
    /// (observed edges, min count, max count) for timeout diagnostics.
    fn side_summary(side: &BTreeMap<u32, serde_json::Value>) -> (usize, Option<u64>, Option<u64>) {
        let mut counts: Vec<u64> = side
            .values()
            .filter_map(|edge| edge["entries"]["count"].as_u64())
            .collect();
        counts.sort_unstable();
        (side.len(), counts.first().copied(), counts.last().copied())
    }
    fn refresh(&mut self, path: &Path, pid: u32) -> Result<bool> {
        // Rotation-aware incremental delta: whole not-yet-consumed rotated
        // segments (each read once, from its tracked offset) plus only the
        // live file's new bytes since the last tick, merged by global
        // sequence. Already-seen rows (live content re-read from its rotated
        // segment) drop out by sequence, and a sequence gap (evidence evicted
        // before reading) fails loudly instead of validating on a partial
        // stream. The live byte offset resets when the file's identity
        // changes (rotation replaced it) or it shrank (truncation); the
        // identity is fstat'd on the read handle, so a rotate racing the
        // tick cannot silently skip rows.
        let live_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let mut fresh = Vec::new();
        for seq in rotated_segment_seqs(path) {
            if self.consumed_segments.contains(&seq) {
                continue;
            }
            let segment = path.with_file_name(format!("{live_name}.{seq}"));
            let offset = self.segment_offsets.entry(seq).or_insert(0);
            fresh.extend(new_lines(&segment, offset)?);
            self.consumed_segments.insert(seq);
        }
        match std::fs::File::open(path) {
            Ok(mut live) => {
                let meta = live.metadata()?;
                let id = (meta.dev(), meta.ino());
                if self.live_id != Some(id) || meta.len() < self.live_offset {
                    self.live_offset = 0;
                }
                self.live_id = Some(id);
                fresh.extend(new_lines_from(&mut live, &mut self.live_offset)?);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        fresh.sort_by_key(|row| row["seq"].as_u64().unwrap_or(u64::MAX));
        let mut rows = Vec::new();
        for row in fresh {
            let seq = row["seq"].as_u64().context("event sequence number")?;
            match self.last_seq {
                None => rows.push((seq, row)),
                Some(last) if seq <= last => continue,
                Some(_) => rows.push((seq, row)),
            }
        }
        if let (Some(last), Some((first, _))) = (self.last_seq, rows.first()) {
            ensure!(
                *first <= last + 1,
                "event evidence evicted before reading: last seq {last}, next seq {first}"
            );
        }
        let mut moved = false;
        for (seq, row) in &rows {
            self.last_seq = Some(self.last_seq.map_or(*seq, |last| last.max(*seq)));
            let event = &row["event"];
            if row["kind"] == "edge_observed" && event["identity_context"]["caller"]["pid"] == pid {
                if let Some(id) = event["identity_context"]["caller"]["id"].as_str() {
                    self.caller_id = Some(id.to_owned());
                    moved = true;
                }
                if let Some(path) = event["identity_context"]["module"]["path"].as_str() {
                    let module = event["identity_context"]["module"]["id"]
                        .as_str()
                        .map(str::to_owned);
                    if let Some(index) = provider_index(path, 'A') {
                        self.a.insert(index, event.clone());
                        moved = true;
                        if let Some(module) = module.clone() {
                            self.module_a.insert(index, module);
                        }
                    }
                    if let Some(index) = provider_index(path, 'B') {
                        self.b.insert(index, event.clone());
                        moved = true;
                        if let Some(module) = module {
                            self.module_b.insert(index, module);
                        }
                    }
                }
            }
            if row["kind"] == "gap_recorded" {
                let (Some(subject), Some(reason)) =
                    (event["subject"].as_str(), event["reason"].as_str())
                else {
                    continue;
                };
                let candidate = GapEvidence {
                    caller: event["caller"].as_str().map(str::to_owned),
                    module: event["module"].as_str().map(str::to_owned),
                    subject: subject.to_owned(),
                    reason: reason.to_owned(),
                    repeats: 1,
                };
                let key = (
                    candidate.caller.clone(),
                    candidate.module.clone(),
                    candidate.subject.clone(),
                    candidate.reason.clone(),
                );
                if !self.evidence_index.contains_key(&key) {
                    self.evidence_index.insert(key, self.evidence.len());
                    self.evidence.push(candidate);
                    moved = true;
                }
            }
            if row["kind"] == "gap_repeated"
                && let (Some(index), Some(repeats)) =
                    (event["index"].as_u64(), event["repeats"].as_u64())
                && let Some(known) = self.evidence.get_mut(index as usize)
            {
                known.repeats = repeats;
                moved = true;
            }
        }
        // Validation trigger: the trailing commit (a full pass landed) or
        // any view-changing row (edge/gap evidence moved mid-pass). A
        // commit-only gate skips validation when a read lands between a
        // pass's rows and its commit marker; every trigger re-checks the
        // current view through the stale/predicate gates, so extra triggers
        // re-affirm instead of double-issuing.
        self.commits += rows
            .iter()
            .filter(|(_, row)| row["kind"] == "pass_committed")
            .count() as u64;
        Ok(moved
            || rows
                .last()
                .is_some_and(|(_, row)| row["kind"] == "pass_committed"))
    }
}

/// One observed `gap_recorded` identity plus its stream-tracked repeats.
/// Mid-run `gap_repeated` values are lower bounds (emitted at power-of-two
/// crossings with the current cumulative count, so 19/21/26/29 all occur);
/// the pre-`ended` flush makes the last value per index exact. Round-2
/// validation goes through the startup gate, which treats mid-run values
/// as bounds, never as finals.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GapEvidence {
    caller: Option<String>,
    module: Option<String>,
    subject: String,
    reason: String,
    repeats: u64,
}

/// Parse a retirement range `(base, absolute]` from a gap reason.
/// Requires `base < absolute` and a consistent `(N unattributed calls)` N.
fn retirement_range(reason: &str) -> Option<(u64, u64)> {
    let open = reason.find("absolute count range (")? + "absolute count range ".len();
    let comma = reason[open..].find(',')? + open;
    let close = reason[comma..].find(']')? + comma;
    let base: u64 = reason[open + 1..comma].trim().parse().ok()?;
    let absolute: u64 = reason[comma + 1..close].trim().parse().ok()?;
    if base >= absolute {
        return None;
    }
    let growth = absolute - base;
    if !reason.contains(&format!("({growth} unattributed calls)")) {
        return None;
    }
    Some((base, absolute))
}

/// Repeats of caller-bound retirement gaps for one exact range, or 0.
/// Only `rejected demoted count` gaps bound to exactly `caller` count.
fn range_gap_repeats(gaps: &[GapEvidence], caller: &str, base: u64, absolute: u64) -> u64 {
    gaps.iter()
        .filter(|gap| {
            gap.subject == "rejected demoted count"
                && gap.caller.as_deref() == Some(caller)
                && gap.module.is_none()
                && retirement_range(&gap.reason) == Some((base, absolute))
        })
        .map(|gap| gap.repeats)
        .sum()
}

/// Retirement withholding has no proven current module. Each issued shared
/// unit has one caller-bound public identity, folded across the 32 physical
/// pairs. Its repeats establish multiplicity only; the bounded pilot checks
/// the independent per-pair diagnostic lineage as well.
fn check_retirement_shared_checkpoint(
    gaps: &[GapEvidence],
    caller: &str,
    counted: u64,
    completed_shared: u64,
) -> Result<()> {
    ensure!(
        (3..=COUNTED).contains(&counted) && (1..=SHARED).contains(&completed_shared),
        "invalid retirement checkpoint C={counted} S={completed_shared}"
    );
    let end = counted + completed_shared;
    let mut units = BTreeMap::new();
    for gap in gaps
        .iter()
        .filter(|gap| gap.caller.as_deref() == Some(caller))
    {
        let Some((base, absolute)) = retirement_range(&gap.reason) else {
            continue;
        };
        if absolute <= counted || base >= end {
            continue;
        }
        ensure!(
            gap.module.is_none()
                && gap.subject == "rejected demoted count"
                && gap.reason.starts_with(
                    "the current physical owner is not proven for absolute count range ("
                )
                && base >= counted
                && absolute == base + 1
                && absolute <= end
                && gap.repeats == TARGETS,
            "invalid shared retirement disclosure for {caller} ({base},{absolute}]: {gap:?}"
        );
        ensure!(
            units.insert(absolute, gap.repeats).is_none(),
            "duplicate shared retirement identity ({base},{absolute}]"
        );
    }
    for absolute in counted + 1..=end {
        ensure!(
            units.get(&absolute) == Some(&TARGETS),
            "shared retirement ({},{}] needs one caller-bound identity repeated32 for {caller}",
            absolute - 1,
            absolute
        );
    }
    Ok(())
}

/// Repeats of the caller-bound startup-fence gap `(1, 2]`, or 0 when absent.
fn startup_fence_repeats(gaps: &[GapEvidence], caller: &str) -> u64 {
    range_gap_repeats(gaps, caller, 1, 2)
}

/// Repeats of the caller-bound post-retirement fence gap
/// `(counted + shared, counted + shared + 1]` (`(658, 659]` on the full
/// schedule, `(36, 37]` on the pilot schedule).
fn fence_gap_repeats_as(gaps: &[GapEvidence], caller: &str, counted: u64, shared: u64) -> u64 {
    range_gap_repeats(gaps, caller, counted + shared, counted + shared + 1)
}

/// Full-gate fence gap repeats (`(658, 659]`).
fn fence_gap_repeats(gaps: &[GapEvidence], caller: &str) -> u64 {
    fence_gap_repeats_as(gaps, caller, COUNTED, SHARED)
}

/// Expected published A-edge projection after `round` issued A rounds with
/// `k` startup-fenced pairs (Sol pinned trajectory), applied per edge: each
/// pair's growth installs on its own A edge only, so every A edge reads the
/// same ordinary/fenced value. Ordinary reads 1, 2, 3 after rounds 1-3 and
/// 400 after round 400; all-32-fenced reads 1, 1, 2 and 399. Only `k == 0`
/// and `k == 32` are valid dispositions; anything else is rejected by the
/// caller, never by a silently interpolated value here.
fn expected_a(round: u64, k: u64) -> u64 {
    if k == 0 {
        round
    } else if round <= 1 {
        1
    } else {
        round - 1
    }
}

/// Validate one observed A-phase round against caller-bound gap evidence,
/// across all 32 A edges, under an explicit counted-round budget. Every
/// edge must read the pinned per-edge value: mixed milestones wait out in
/// the driver, so anything non-unanimous here is a genuine divergence,
/// never a transient. Returns the validated fence count `k`. Round 1 never
/// fences; round 2 establishes `k` (0 ordinary, 32 fenced); later rounds
/// require exact 1-increments with stable `k`.
fn check_startup_round_as(
    round: u64,
    observed_a: &[u64],
    gaps: &[GapEvidence],
    caller: &str,
    prior_k: Option<u64>,
    counted: u64,
) -> Result<u64> {
    ensure!(
        (1..=counted).contains(&round),
        "A round out of range 1..={counted}: {round}"
    );
    ensure!(
        observed_a.len() == TARGETS as usize,
        "need all32 A edges, got {}",
        observed_a.len()
    );
    ensure!(
        observed_a.iter().all(|count| *count == observed_a[0]),
        "A edges disagree at round-{round}: {observed_a:?}"
    );
    let observed = observed_a[0];
    let k = startup_fence_repeats(gaps, caller);
    if round == 1 {
        ensure!(prior_k.is_none(), "round 1 takes no prior disposition");
        ensure!(
            k == 0 && observed == expected_a(1, 0),
            "round 1 never fences: A={observed} k={k}"
        );
        return Ok(0);
    }
    if round == 2 {
        ensure!(prior_k == Some(0), "round 2 follows an unfenced round 1");
        ensure!(
            k == 0 || k == TARGETS,
            "round 2 fences all pairs or none: k={k}"
        );
        ensure!(
            observed == expected_a(2, k),
            "round-2 A={observed} contradicts fence evidence k={k}"
        );
        return Ok(k);
    }
    ensure!(
        prior_k == Some(k),
        "startup disposition changed mid-run: prior={prior_k:?} now={k}"
    );
    ensure!(
        observed == expected_a(round, k),
        "round-{round} A={observed} breaks the pinned projection chain (k={k})"
    );
    Ok(k)
}

/// Full-gate startup-round check (400 counted rounds).
fn check_startup_round(
    round: u64,
    observed_a: &[u64],
    gaps: &[GapEvidence],
    caller: &str,
    prior_k: Option<u64>,
) -> Result<u64> {
    check_startup_round_as(round, observed_a, gaps, caller, prior_k, COUNTED)
}

/// Consecutive identical partial-k commits before the round-2 gate calls a
/// genuine partial fence instead of a still-climbing lower bound. Live climbs
/// finish in 2-4 passes with at most 1-pass pauses; 8 stalls fail loudly with
/// the trajectory, never silently and never as a timeout.
const FENCE_STALL_CAP: u32 = 8;

/// Round-2 fence verdict from one observation batch.
enum StartupGateAction {
    /// Not decided yet: stay in round 2, re-poll on the next trigger.
    Wait,
    /// Fence count is final: run `check_startup_round` now.
    Validate,
    /// Same partial k too long: genuine partial fence, fail loudly.
    Stalled { k: u64, trajectory: Vec<u64> },
    /// An A edge advanced past round 2 with no fence: impossible, fail loudly.
    Overadvanced { a: u64 },
}

/// Round-2 fence gate over all 32 A edges. Mid-run `gap_repeated` values
/// are lower bounds (the emitter reports the current cumulative count on
/// power-of-two crossings), so the first non-stale sight of k cannot latch:
/// 1/8/16/19/21/26 all precede 32 on healthy fenced runs. The gate is
/// asymmetric because the bounds are: k == 32 validates immediately (a
/// lower bound of 32 over 32 pairs is exact, and the terminal exact replay
/// backstops any over-count), while k == 0 needs the unanimous ordinary
/// (all A == 2) state on two consecutive triggers (fence recordings can lag
/// the edges, and mid-pass batches land edge-by-edge). Partial counts wait
/// out the climb; only a stalled partial fails, loudly with its trajectory.
/// Round 1 never fences and rounds 3+ keep the immediate prior chain: the
/// (1, 2] decision window is rounds 1-3, so later arrivals are prior-chain
/// violations.
struct StartupGate {
    last: Option<(Vec<u64>, u64)>,
    runs: u32,
    trajectory: Vec<u64>,
}

impl StartupGate {
    fn new() -> Self {
        Self {
            last: None,
            runs: 0,
            trajectory: Vec::new(),
        }
    }

    fn poll_round2(
        &mut self,
        observed_a: &[u64],
        gaps: &[GapEvidence],
        caller: &str,
    ) -> StartupGateAction {
        let k = startup_fence_repeats(gaps, caller);
        self.trajectory.push(k);
        if self.trajectory.len() > 24 {
            self.trajectory.remove(0);
        }
        if observed_a.iter().any(|count| *count > expected_a(2, 0)) {
            let max = observed_a.iter().max().copied().unwrap_or(0);
            return StartupGateAction::Overadvanced { a: max };
        }
        if k == TARGETS {
            self.last = Some((observed_a.to_vec(), k));
            self.runs = 1;
            return StartupGateAction::Validate;
        }
        if self.last == Some((observed_a.to_vec(), k)) {
            self.runs += 1;
        } else {
            self.last = Some((observed_a.to_vec(), k));
            self.runs = 1;
        }
        if k == 0 {
            if observed_a.iter().all(|count| *count == expected_a(2, 0)) && self.runs >= 2 {
                StartupGateAction::Validate
            } else {
                StartupGateAction::Wait
            }
        } else if self.runs >= FENCE_STALL_CAP {
            StartupGateAction::Stalled {
                k,
                trajectory: self.trajectory.clone(),
            }
        } else {
            StartupGateAction::Wait
        }
    }
}

/// Round-2 readiness through the startup gate; every other round validates
/// immediately. Returns false while the gate waits out a climbing lower
/// bound; bails loudly on a stalled partial or an impossible advance.
fn startup_round_ready(
    gate: &RefCell<StartupGate>,
    round: u64,
    observed_a: &[u64],
    evidence: &[GapEvidence],
    caller: &str,
) -> Result<bool> {
    if round != 2 {
        return Ok(true);
    }
    match gate.borrow_mut().poll_round2(observed_a, evidence, caller) {
        StartupGateAction::Wait => Ok(false),
        StartupGateAction::Validate => Ok(true),
        StartupGateAction::Stalled { k, trajectory } => bail!(
            "startup fence disposition stalled at partial k={k} (k trajectory: {trajectory:?})"
        ),
        StartupGateAction::Overadvanced { a } => {
            bail!("round-2 A={a} advanced past the issued rounds with no fence evidence")
        }
    }
}

/// Validate the terminal fence/proof pair set: 32 distinct pairs under one
/// caller, each with a fence `(658, 659]` withheld prefix (absolute 659,
/// retained observation) and a proof placement (base 659, absolute 660,
/// staged 1) on its own recovered B module. Every proof must project
/// `edge_total == 1` on its own pair edge (partition-independent: each B
/// edge carries exactly its pair's proof, with no batching premise) and
/// recover through a strictly later read (`baseline_post < pre`). No B
/// placement may overlap a withheld interval, and each B module must carry
/// exactly its pair's proof (no early/foreign attribution, no shared
/// recovery edge). Returns aggregate (fence-absolute sum, proof-absolute
/// sum, staged sum) after asserting the exact 21,088/21,120/32
/// reconciliation.
fn check_terminal_pairs(
    records: &[serde_json::Value],
    b_modules: &BTreeSet<String>,
) -> Result<(u64, u64, u64)> {
    check_terminal_pairs_as(records, b_modules, None)
}

/// `check_terminal_pairs` with the terminal caller identity pinned to
/// the live-observed owned caller (system cell) and an explicit schedule.
/// `None` keeps the single-caller consistency check unpinned (PID cell).
/// The fence/proof shapes scale with the schedule: fence
/// `(counted + shared, counted + shared + 1]` withheld prefix and proof
/// placement `(base counted + shared + 1, absolute counted + shared + 2,
/// staged 1)` — `(658, 659]`/`(659, 660]` on the full schedule,
/// `(36, 37]`/`(37, 38]` on the pilot schedule.
fn check_terminal_pairs_schedule(
    records: &[serde_json::Value],
    b_modules: &BTreeSet<String>,
    expected_caller: Option<&str>,
    counted: u64,
    shared: u64,
) -> Result<(u64, u64, u64)> {
    ensure!(
        b_modules.len() == TARGETS as usize,
        "need all32 B module ids, got {}",
        b_modules.len()
    );
    let mut placements = BTreeSet::new();
    let mut proof_abs_sum = 0u64;
    let mut staged_sum = 0u64;
    let mut proof_modules = BTreeSet::new();
    let mut fence = BTreeSet::new();
    let mut fence_abs_sum = 0u64;
    let mut caller: Option<String> = None;
    let mut b_placements = 0u64;
    let mut per_module = BTreeMap::new();
    for row in records {
        let on_b = row["module_id"]
            .as_str()
            .is_some_and(|module| b_modules.contains(module));
        if row["kind"] == "publication" && row["decision"] == "placed" && on_b {
            b_placements += 1;
            let module = row["module_id"].as_str().unwrap_or_default().to_owned();
            *per_module.entry(module).or_insert(0u64) += 1;
            let base = row["base"].as_u64().unwrap_or(u64::MAX);
            let absolute = row["absolute"].as_u64().unwrap_or(0);
            let is_proof_shape = base == counted + shared + 1
                && absolute == counted + shared + 2
                && row["staged"] == 1;
            if !is_proof_shape && base < counted + shared + 1 && absolute > counted + shared {
                bail!("B placement overlaps the withheld fence interval: {row}");
            }
        }
        if row["kind"] == "publication"
            && row["decision"] == "placed"
            && on_b
            && row["base"] == counted + shared + 1
            && row["absolute"] == counted + shared + 2
            && row["staged"] == 1
            && row["edge_total"] == 1
            && row["observation_ref"]["status"] == "retained"
            && row["observation_ref"]["seq"].as_u64().is_some()
        {
            let (Some(baseline_post), Some(pre)) =
                (row["baseline_post"].as_u64(), row["pre"].as_u64())
            else {
                bail!("proof lacks a genuine recovery window: {row}");
            };
            ensure!(
                baseline_post < pre,
                "proof recovery is not strictly later than its fence: {row}"
            );
            let pair = row["pair"].as_str().context("placed pair")?.to_owned();
            let row_caller = row["caller"].as_str().context("placed caller")?.to_owned();
            match &caller {
                None => caller = Some(row_caller),
                Some(expected) => ensure!(
                    expected == &row_caller,
                    "terminal proofs span callers: {expected} vs {row_caller}"
                ),
            }
            if placements.insert(pair) {
                proof_abs_sum += row["absolute"].as_u64().context("proof absolute")?;
                staged_sum += row["staged"].as_u64().context("proof staged")?;
                proof_modules.insert(
                    row["module_id"]
                        .as_str()
                        .context("proof module")?
                        .to_owned(),
                );
            }
        }
        if row["kind"] == "count_decision"
            && row["decision"] == "withheld"
            && row["reason"] == "awaiting_fence"
            && row["after"] == counted + shared
            && row["through"] == counted + shared + 1
            && row["absolute"] == counted + shared + 1
            && row["observation_ref"]["status"] == "retained"
            && row["observation_ref"]["seq"].as_u64().is_some()
        {
            let pair = row["pair"].as_str().context("withheld pair")?.to_owned();
            let row_caller = row["caller"]
                .as_str()
                .context("withheld caller")?
                .to_owned();
            match &caller {
                None => caller = Some(row_caller),
                Some(expected) => ensure!(
                    expected == &row_caller,
                    "terminal fence spans callers: {expected} vs {row_caller}"
                ),
            }
            if fence.insert(pair) {
                fence_abs_sum += row["through"].as_u64().context("fence through")?;
            }
        }
    }
    ensure!(
        b_placements == 32,
        "B must carry exactly the 32 terminal proofs, found {b_placements} placements"
    );
    ensure!(
        per_module.len() == TARGETS as usize && per_module.values().all(|count| *count == 1),
        "each B module carries exactly its pair's proof: {per_module:?}"
    );
    ensure!(
        placements.len() == 32 && fence == placements,
        "all32 real pairs need recent withheld-prefix/recovery on B"
    );
    ensure!(
        proof_modules == *b_modules,
        "terminal proofs must span all32 B modules exactly once"
    );
    ensure!(
        fence_abs_sum == 32 * (counted + shared + 1)
            && proof_abs_sum == 32 * (counted + shared + 2)
            && staged_sum == 32,
        "terminal sums differ from per-pair {}/ {}/1 (counted={counted} shared={shared}): fence={fence_abs_sum} proof={proof_abs_sum} staged={staged_sum}",
        counted + shared + 1,
        counted + shared + 2,
    );
    if let Some(expected) = expected_caller {
        ensure!(
            caller.as_deref() == Some(expected),
            "terminal pairs bind caller {caller:?}, not the owned {expected}"
        );
    }
    Ok((fence_abs_sum, proof_abs_sum, staged_sum))
}

/// Full-gate terminal pairs (400 counted, 258 shared rounds).
fn check_terminal_pairs_as(
    records: &[serde_json::Value],
    b_modules: &BTreeSet<String>,
    expected_caller: Option<&str>,
) -> Result<(u64, u64, u64)> {
    check_terminal_pairs_schedule(records, b_modules, expected_caller, COUNTED, SHARED)
}

/// Complete bounded-pilot proof, never an all-history claim after ring wrap.
/// Expected units come from the independently checked native schedule; opaque
/// diagnostic pairs acquire their indexed lineage from A, then must keep it
/// through every shared unit, their original fence and the matching B proof.
fn check_shared_pair_dispositions(
    records: &[serde_json::Value],
    caller: &str,
    modules_a: &[String],
    modules_b: &[String],
    counted: u64,
    shared: u64,
    k: u64,
) -> Result<()> {
    ensure!(
        (3..=COUNTED).contains(&counted) && (1..=SHARED).contains(&shared),
        "invalid bounded pair schedule C={counted} S={shared}"
    );
    ensure!(k == 0 || k == TARGETS, "invalid startup disposition k={k}");
    let a_ids: BTreeSet<_> = modules_a.iter().cloned().collect();
    let b_ids: BTreeSet<_> = modules_b.iter().cloned().collect();
    ensure!(
        modules_a.len() == TARGETS as usize
            && modules_b.len() == TARGETS as usize
            && a_ids.len() == TARGETS as usize
            && b_ids.len() == TARGETS as usize
            && a_ids.is_disjoint(&b_ids),
        "need32 distinct indexed A/B module pairs"
    );
    check_terminal_pairs_schedule(records, &b_ids, Some(caller), counted, shared)?;
    let mut by_seq = BTreeMap::new();
    for row in records {
        if let Some(seq) = row["seq"].as_u64() {
            ensure!(
                by_seq.insert(seq, row).is_none(),
                "duplicate diagnostic seq {seq}"
            );
        }
    }
    let read = |row: &serde_json::Value, require_caller: bool| -> Result<(u64, u64)> {
        ensure!(
            row["caller"] == caller,
            "decision has foreign caller: {row}"
        );
        ensure!(
            row["observation_ref"]["status"] == "retained",
            "bounded read is not retained: {row}"
        );
        let seq = row["seq"].as_u64().context("decision seq")?;
        let observation_seq = row["observation_ref"]["seq"]
            .as_u64()
            .context("observation ref seq")?;
        let observation = by_seq
            .get(&observation_seq)
            .context("referenced original read missing")?;
        let pre = row["pre"].as_u64().context("read PRE")?;
        let post = row["post"].as_u64().context("read POST")?;
        ensure!(
            observation_seq < seq
                && observation["kind"] == "count_observation"
                && observation["pair"] == row["pair"]
                && observation["absolute"] == row["absolute"]
                && observation["pre"] == pre
                && observation["post"] == post
                && pre <= post
                && (observation["caller"] == caller
                    || !require_caller && observation["caller"].is_null()),
            "decision does not retain its original pair/caller/read interval: {row}"
        );
        Ok((pre, post))
    };
    let mut pairs = BTreeMap::new();
    let mut pair_for_index = vec![None; TARGETS as usize];
    let mut a_units = vec![BTreeMap::new(); TARGETS as usize];
    for row in records
        .iter()
        .filter(|row| row["kind"] == "publication" && row["decision"] == "placed")
    {
        let Some(index) = modules_a
            .iter()
            .position(|module| row["module_id"] == module.as_str())
        else {
            continue;
        };
        let pair = row["pair"].as_str().context("A pair")?.to_owned();
        let known = pairs.entry(pair.clone()).or_insert(index);
        ensure!(*known == index, "one physical pair spans A modules: {pair}");
        let lineage = pair_for_index[index].get_or_insert(pair.clone());
        ensure!(
            *lineage == pair,
            "A module has multiple physical pairs: {index}"
        );
        let absolute = row["absolute"].as_u64().context("A absolute")?;
        ensure!(
            (1..=counted).contains(&absolute)
                && !(k == TARGETS && absolute == 2)
                && row["base"] == absolute - 1
                && row["staged"] == 1
                && row["edge_total"] == expected_a(absolute, k),
            "A placement differs from its issued unit: {row}"
        );
        let interval = read(row, false)?;
        ensure!(
            a_units[index].insert(absolute, interval).is_none(),
            "duplicate A unit on pair {pair}"
        );
    }
    ensure!(
        pairs.len() == TARGETS as usize,
        "need32 distinct A pair lineages"
    );
    for units in &a_units {
        for absolute in 1..=counted {
            if !(k == TARGETS && absolute == 2) {
                ensure!(units.contains_key(&absolute), "missing A unit {absolute}");
            }
        }
    }
    let mut observations = vec![BTreeMap::new(); TARGETS as usize];
    let mut startup = BTreeSet::new();
    let mut shared_units = vec![BTreeMap::new(); TARGETS as usize];
    let mut fences = vec![None; TARGETS as usize];
    let mut proofs = vec![None; TARGETS as usize];
    for row in records {
        let pair = row["pair"].as_str().unwrap_or_default();
        if row["kind"] == "count_observation"
            && let Some(absolute) = row["absolute"].as_u64().filter(|absolute| *absolute > 0)
        {
            let index = *pairs.get(pair).context("read has no original A pair")?;
            ensure!(
                absolute <= counted + shared + 2
                    && row["reason"].is_null()
                    && (row["caller"] == caller || row["caller"].is_null())
                    && observations[index].insert(absolute, row).is_none(),
                "extra, foreign or invalid native unit read: {row}"
            );
        }
        if row["kind"] == "publication"
            && row["decision"] == "placed"
            && (row["caller"] == caller || pairs.contains_key(pair))
        {
            let index = *pairs
                .get(pair)
                .context("placement has no original A pair")?;
            if row["module_id"] == modules_a[index] {
                continue;
            }
            ensure!(
                row["module_id"] == modules_b[index]
                    && row["base"] == counted + shared + 1
                    && row["absolute"] == counted + shared + 2
                    && row["staged"] == 1
                    && row["edge_total"] == 1,
                "pair crossed module lineage or placed withheld growth: {row}"
            );
            let interval = read(row, true)?;
            ensure!(
                proofs[index]
                    .replace((
                        interval,
                        row["baseline_pre"].as_u64(),
                        row["baseline_post"].as_u64()
                    ))
                    .is_none(),
                "duplicate B proof for pair {pair}"
            );
        }
        if row["kind"] != "count_decision" || row["decision"] != "withheld" {
            continue;
        }
        let after = row["after"].as_u64();
        let through = row["through"].as_u64();
        let shared_interval = after
            .zip(through)
            .is_some_and(|(after, through)| after < counted + shared && through > counted);
        if row["reason"] == "shared_owner" || shared_interval {
            let index = *pairs
                .get(pair)
                .context("shared decision has no original A pair")?;
            let (after, through) = after.zip(through).context("shared interval missing")?;
            ensure!(
                row["reason"] == "shared_owner"
                    && row["module_id"].is_null()
                    && after >= counted
                    && after.checked_add(1) == Some(through)
                    && through <= counted + shared
                    && row["absolute"] == through,
                "shared pair interval differs from its issued unit: {row}"
            );
            let interval = read(row, true)?;
            ensure!(
                shared_units[index].insert(through, interval).is_none(),
                "duplicate shared unit for pair {pair}"
            );
        } else if row["reason"] == "awaiting_fence" && through == Some(2) {
            let index = *pairs
                .get(pair)
                .context("startup fence has no original A pair")?;
            ensure!(
                k == TARGETS
                    && after == Some(1)
                    && row["absolute"] == 2
                    && row["module_id"].is_null()
                    && startup.insert(index),
                "startup fence differs from the validated all-pair disposition: {row}"
            );
            read(row, false)?;
        } else if row["reason"] == "awaiting_fence"
            && through.is_some_and(|through| through > counted + shared)
        {
            let index = *pairs.get(pair).context("fence has no original A pair")?;
            ensure!(
                after == Some(counted + shared)
                    && through == Some(counted + shared + 1)
                    && row["absolute"] == counted + shared + 1
                    && row["module_id"].is_null(),
                "fence interval differs from its issued unit: {row}"
            );
            ensure!(
                fences[index].replace(read(row, true)?).is_none(),
                "duplicate fence for pair {pair}"
            );
        }
    }
    ensure!(startup.len() as u64 == k, "missing per-pair startup fence");
    for (index, units) in a_units.iter().enumerate() {
        for absolute in 1..=counted + shared + 2 {
            ensure!(
                observations[index].contains_key(&absolute),
                "pair {index} lacks issued native read {absolute}"
            );
        }
        let mut last_post = units.get(&counted).context("terminal A read missing")?.1;
        for absolute in counted + 1..=counted + shared {
            let (pre, post) = shared_units[index]
                .get(&absolute)
                .context("pair lacks an issued shared unit")?;
            ensure!(
                last_post < *pre,
                "shared original reads overlap or reverse on pair {index}"
            );
            last_post = *post;
        }
        let fence = fences[index].context("pair lacks its original fence")?;
        let (proof, baseline_pre, baseline_post) =
            proofs[index].context("pair lacks its B proof")?;
        ensure!(
            last_post < fence.0
                && fence.1 < proof.0
                && baseline_pre == Some(fence.0)
                && baseline_post == Some(fence.1),
            "pair {index} proof substituted or overlapped its original fence"
        );
    }
    Ok(())
}

/// Validate the 32 native targets against 32 genuinely distinct physical
/// objects: slot `4+i` must live in `libdemotion-common-{i:02}.so` under
/// `dir`, each file distinct by kernel maps key with the offset in range.
/// Returns the 32 per-slot file keys. Offsets within one file are one pair,
/// never 32: shared inodes are rejected.
fn native_target_files(
    targets: &[&serde_json::Value],
    dir: &Path,
) -> Result<Vec<p11scope_manifest::maps::ObjectKey>> {
    use p11scope_manifest::identity::{UnboundedProbeBudget, kernel_maps_key_for};
    ensure!(targets.len() == 32, "need exactly32 native targets");
    let slots: BTreeSet<_> = targets
        .iter()
        .filter_map(|row| row["slot"].as_u64())
        .collect();
    ensure!(
        slots == (4..36).collect(),
        "native target slots must be4..35"
    );
    let mut keys = Vec::with_capacity(32);
    for row in targets {
        let slot = row["slot"].as_u64().context("target slot")?;
        let path = dir.join(format!("libdemotion-common-{:02}.so", slot - 4));
        let file = std::fs::File::open(&path)?;
        let key = kernel_maps_key_for(&file, &mut UnboundedProbeBudget)
            .context("target file kernel maps key")?;
        let length = file.metadata()?.len();
        ensure!(
            row["ino"] == key.inode
                && row["dev_major"] == key.device.major
                && row["dev_minor"] == key.device.minor
                && row["offset"].as_u64().is_some_and(|offset| offset < length),
            "native target slot{slot} differs from its held object file"
        );
        keys.push(key);
    }
    ensure!(
        keys.iter().collect::<BTreeSet<_>>().len() == 32,
        "32 offsets in fewer than32 objects are not32 pairs"
    );
    Ok(keys)
}

/// Repeats of the module-bound shared-owner ambiguity gap for `module`.
fn ambiguity_repeats(gaps: &[GapEvidence], module: &str) -> u64 {
    gaps.iter()
        .filter(|gap| {
            gap.subject == "rejected demoted count"
                && gap.module.as_deref() == Some(module)
                && gap.reason.contains("after sharing appeared")
        })
        .map(|gap| gap.repeats)
        .sum()
}

/// Ordinary immutable pending-count rejection control, distinct from the
/// retirement path: at power-of-two rounds the folded
/// ambiguity gaps are mid-run exact and must read exactly `round` on each
/// of the 64 sharer modules (one pair per module, one disclosure per
/// round). Between checkpoints any value passes (power-of-two lower bounds
/// cannot gate); the pre-`ended` flush verifies the exact final 258 per
/// module retrospectively.
fn check_shared_checkpoint(
    round: u64,
    gaps: &[GapEvidence],
    modules_a: &[String],
    modules_b: &[String],
) -> Result<()> {
    ensure!(
        modules_a.len() == TARGETS as usize && modules_b.len() == TARGETS as usize,
        "need all64 sharer module ids"
    );
    if !round.is_power_of_two() {
        return Ok(());
    }
    for module in modules_a.iter().chain(modules_b.iter()) {
        let repeats = ambiguity_repeats(gaps, module);
        ensure!(
            repeats == round,
            "shared round{round} needs exactly{round} ambiguity disclosures on {module}, found {repeats}"
        );
    }
    Ok(())
}

/// Native ledger check under an explicit schedule: the exact per-slot
/// call ledger plus phase ACKs for `counted` A rounds, `shared` shared
/// rounds, then fence and proof.
fn check_native_ledger_schedule(workload: &WrapWorkload, counted: u64, shared: u64) -> Result<()> {
    check_native_schedule(
        workload,
        &[
            ("a", counted),
            ("shared", shared),
            ("fence", 1),
            ("proof", 1),
        ],
    )
}

fn check_native_ledger(workload: &WrapWorkload) -> Result<()> {
    check_native_ledger_schedule(workload, COUNTED, SHARED)
}

fn check_native_target_mapping(
    targets: &[&serde_json::Value],
    expected: p11scope_manifest::maps::ObjectKey,
    length: u64,
) -> Result<()> {
    ensure!(
        targets.iter().all(|row| {
            row["ino"] == expected.inode
                && row["dev_major"] == expected.device.major
                && row["dev_minor"] == expected.device.minor
                && row["offset"].as_u64().is_some_and(|offset| offset < length)
        }),
        "native ledger targets differ from held-FD kernel maps key {expected:?}: {targets:?}"
    );
    Ok(())
}

#[test]
fn operator_diagnostics_native_target_mapping_uses_kernel_maps_key() -> Result<()> {
    use p11scope_manifest::identity::{UnboundedProbeBudget, kernel_maps_key_for};
    use std::os::unix::fs::MetadataExt;
    let mut file = tempfile::tempfile()?;
    file.write_all(&[0u8; 64])?;
    let metadata = file.metadata()?;
    let expected = kernel_maps_key_for(&file, &mut UnboundedProbeBudget)
        .context("actual held-FD kernel maps key")?;
    let rows: Vec<_> = (0..32)
        .map(|offset| {
            serde_json::json!({
        "dev_major":expected.device.major,"dev_minor":expected.device.minor,
        "ino":expected.inode,"offset":offset})
        })
        .collect();
    let refs: Vec<_> = rows.iter().collect();
    check_native_target_mapping(&refs, expected, metadata.len())?;
    for field in ["dev_major", "dev_minor", "ino", "offset"] {
        let mut changed = rows.clone();
        changed[0][field] = if field == "offset" {
            metadata.len()
        } else {
            changed[0][field].as_u64().context("identity field")? + 1
        }
        .into();
        let changed_refs: Vec<_> = changed.iter().collect();
        ensure!(
            check_native_target_mapping(&changed_refs, expected, metadata.len()).is_err(),
            "foreign native target field accepted: {field}"
        );
    }
    let stat_device = p11scope_manifest::maps::Device {
        major: u64::from(libc::major(metadata.dev())),
        minor: u64::from(libc::minor(metadata.dev())),
    };
    if stat_device != expected.device {
        let wrong_domain = p11scope_manifest::maps::ObjectKey {
            device: stat_device,
            inode: expected.inode,
        };
        ensure!(check_native_target_mapping(&refs, wrong_domain, metadata.len()).is_err());
    }
    eprintln!("G21_NATIVE_TARGET_KEY maps={expected:?} stat_device={stat_device:?}");
    Ok(())
}

fn check_native_schedule(workload: &WrapWorkload, schedule: &[(&str, u64)]) -> Result<()> {
    let rows = jsonl_records(&workload.dir.path().join("calls.jsonl"))?;
    let identity = rows.first().context("native identity missing")?;
    ensure!(identity["kind"] == "identity" && identity["pid"] == workload.process.pid());
    ensure!(identity["nonce"] == "0123456789abcdef0123456789abcdef");
    let targets: Vec<_> = rows.iter().filter(|row| row["kind"] == "target").collect();
    let slots: BTreeSet<_> = targets
        .iter()
        .filter_map(|row| row["slot"].as_u64())
        .collect();
    let addresses: BTreeSet<_> = targets
        .iter()
        .map(|row| {
            (
                row["dev_major"].as_u64(),
                row["dev_minor"].as_u64(),
                row["ino"].as_u64(),
                row["offset"].as_u64(),
            )
        })
        .collect();
    ensure!(targets.len() == 32 && slots == (4..36).collect() && addresses.len() == 32);
    // The native fixture reports lexical /proc/maps device identity. A
    // map_files stat (self_mapped_identity) is the separate opened-file domain
    // and can have a different per-subvolume device on Btrfs.
    native_target_files(&targets, workload.dir.path())?;
    let calls: Vec<_> = rows.iter().filter(|row| row["kind"] == "call").collect();
    ensure!(
        calls.len() as u64
            == schedule
                .iter()
                .map(|(_, rounds)| rounds * TARGETS)
                .sum::<u64>()
    );
    let acknowledgements = jsonl_records(&workload.process.out)?;
    let mut sequence = 0usize;
    let mut previous = identity["ready_ns"]
        .as_u64()
        .context("native ready clock")?;
    for (phase, rounds) in schedule.iter().copied() {
        let event = match phase {
            "a" => "a-done",
            "shared" => "shared-done",
            "fence" => "fence-done",
            _ => "final-calls",
        };
        for round in 1..=rounds {
            for slot in 4..36 {
                let call = calls[sequence];
                sequence += 1;
                ensure!(
                    call["sequence"] == sequence as u64
                        && call["phase"] == phase
                        && call["round"] == round
                        && call["slot"] == slot
                );
                let before = call["before_call_ns"].as_u64().context("native entry")?;
                let after = call["after_return_ns"].as_u64().context("native return")?;
                ensure!(previous <= before && before < after && call["return_status"] == 0);
                previous = after;
            }
            let ack: Vec<_> = acknowledgements
                .iter()
                .filter(|row| row["event"] == event && row["round"] == round)
                .collect();
            ensure!(
                ack.len() == 1
                    && ack[0]["calls"] == sequence as u64
                    && ack[0]["t"].as_u64().is_some_and(|stamp| stamp >= previous)
            );
        }
    }
    let terminal = rows.last().context("native terminal missing")?;
    ensure!(
        terminal["kind"] == "complete"
            && terminal["complete"] == true
            && terminal["calls"] == sequence as u64
    );
    Ok(())
}

fn check_wrap_records(
    records: &[serde_json::Value],
    bytes: u64,
    b_modules: &BTreeSet<String>,
    pid: u32,
) -> Result<()> {
    let header = records.first().context("diagnostic header missing")?;
    ensure!(header["scope"] == "pid" && header["mode"] == "native" && header["pid_filter"] == pid);
    check_wrap_records_core(records, bytes, b_modules, None)
}

/// Scope-free wrap-export contract: envelope, limits, both-ring wrap,
/// footer reconciliation, truthful references and the terminal pairs.
/// The caller pins the scope header first; `expected_caller` pins the
/// terminal caller identity (system cell) or leaves the single-caller
/// consistency check unpinned (PID cell).
fn check_wrap_records_core(
    records: &[serde_json::Value],
    bytes: u64,
    b_modules: &BTreeSet<String>,
    expected_caller: Option<&str>,
) -> Result<()> {
    let header = records.first().context("diagnostic header missing")?;
    let footer = records.last().context("diagnostic footer missing")?;
    ensure!(
        header["kind"] == "header"
            && footer["kind"] == "footer"
            && footer["diagnostics_complete"] == true
    );
    ensure!(
        header["limits"]["ordinary_records"] == 24576
            && header["limits"]["exceptional_records"] == 8192
    );
    ensure!(
        header["limits"]["heap_bytes"]
            .as_u64()
            .is_some_and(|heap| heap + 8192 <= 16 * 1024 * 1024)
    );
    ensure!(
        bytes <= 64 * 1024 * 1024
            && footer["bytes_written"] == bytes
            && footer["records_written"] == records.len() as u64 - 2
    );
    let kinds = footer["kinds"]
        .as_array()
        .context("diagnostic kind totals missing")?;
    ensure!(
        kinds.len() == 5
            && kinds
                .iter()
                .all(|kind| kind["omitted"] == 0 && kind["filtered"] == 0)
    );
    ensure!(
        footer["counter_overflow"] == false
            && footer["sequence_exhausted"] == false
            && footer["oversized_records"] == 0
    );
    const KIND_NAMES: [&str; 5] = [
        "count_observation",
        "ownership_transition",
        "count_decision",
        "publication",
        "capture_health",
    ];
    let mut observed = [0u64; 5];
    let mut occupancy = [0u64; 2];
    for row in &records[1..records.len() - 1] {
        let name = row["kind"]
            .as_str()
            .context("diagnostic row kind missing")?;
        let index = KIND_NAMES
            .iter()
            .position(|known| *known == name)
            .context("unknown diagnostic row kind")?;
        observed[index] += 1;
        ensure!(
            row["decision"].is_null()
                || matches!(
                    row["decision"].as_str(),
                    Some("staged" | "placed" | "rejected" | "withheld" | "pending")
                ),
            "unknown diagnostic decision"
        );
        let exceptional = matches!(name, "ownership_transition" | "capture_health")
            || matches!(
                row["decision"].as_str(),
                Some("rejected" | "withheld" | "pending")
            );
        occupancy[usize::from(exceptional)] += 1;
    }
    ensure!(
        occupancy[0] <= 24576 && occupancy[1] <= 8192,
        "retained default ring capacity exceeded"
    );
    ensure!(
        observed.iter().sum::<u64>()
            == footer["records_written"]
                .as_u64()
                .context("export row count")?
    );
    for (index, kind) in kinds.iter().enumerate() {
        let keys: BTreeSet<_> = kind
            .as_object()
            .context("kind counters must be an object")?
            .keys()
            .map(String::as_str)
            .collect();
        ensure!(
            keys == BTreeSet::from(["produced", "retained", "evicted", "filtered", "omitted"]),
            "unexpected footer counter vocabulary/order"
        );
        ensure!(
            kind["retained"].as_u64() == Some(observed[index]),
            "footer retained count differs from actual {} rows",
            KIND_NAMES[index]
        );
    }
    for kind in kinds {
        let total = |name: &str| kind[name].as_u64().context("diagnostic kind counter");
        ensure!(
            total("produced")?
                == total("retained")? + total("evicted")? + total("filtered")? + total("omitted")?
        );
    }
    // CountObservation is always ordinary. OwnershipTransition/CaptureHealth
    // are always exceptional. Their actual evictions prove each default ring
    // really filled; CountDecision totals alone cannot distinguish the rings.
    let ordinary_evicted = kinds[0]["evicted"]
        .as_u64()
        .context("ordinary eviction total")?;
    let exceptional_evicted = kinds[1]["evicted"]
        .as_u64()
        .context("transition eviction total")?
        + kinds[4]["evicted"]
            .as_u64()
            .context("health eviction total")?;
    ensure!(
        ordinary_evicted > 0 && exceptional_evicted > 0,
        "both default rings must actually wrap"
    );
    ensure!(
        occupancy == [24576, 8192],
        "wrapped default rings must retain their complete capacities without omissions"
    );
    let produced: u64 = kinds
        .iter()
        .map(|kind| kind["produced"].as_u64().unwrap_or(0))
        .sum();
    ensure!(produced > 24576 + 8192);
    let sequences: BTreeSet<_> = records
        .iter()
        .filter_map(|row| row["seq"].as_u64())
        .collect();
    ensure!(sequences.len() == records.len() - 2);
    let mut previous = 0;
    let mut missing_context = false;
    for row in &records[1..records.len() - 1] {
        let seq = row["seq"].as_u64().context("diagnostic sequence")?;
        ensure!(seq > previous);
        previous = seq;
        for field in ["observation_ref", "transition_ref"] {
            if !row[field].is_null() {
                let reference = row[field]["seq"].as_u64().context("reference sequence")?;
                ensure!(reference < seq);
                match row[field]["status"].as_str() {
                    Some("retained") => ensure!(sequences.contains(&reference)),
                    Some("not_retained") => {
                        ensure!(
                            !sequences.contains(&reference) && row["history_complete"] == false
                        );
                        missing_context = true;
                    }
                    _ => bail!("diagnostic reference invented an unknown retention status"),
                }
            }
        }
    }
    let (fence_sum, proof_sum, staged_sum) =
        check_terminal_pairs_as(records, b_modules, expected_caller)?;
    ensure!(
        missing_context,
        "wrapped export needs truthful lost-history context"
    );
    eprintln!(
        "G21_WRAP ordinary_produced_lower_bound={} exceptional_produced_lower_bound={} records={} fence_abs_sum={fence_sum} proof_abs_sum={proof_sum} staged_sum={staged_sum}",
        24576 + ordinary_evicted,
        8192 + exceptional_evicted,
        records.len() - 2
    );
    Ok(())
}

/// Validate a bounded-system wrap export (cell 3): header `scope:
/// "system"` with an explicit null PID filter, every pid-bearing row
/// owned, and the terminal pairs bound to the live-observed owned
/// caller. Otherwise the full PID wrap contract applies unchanged.
/// Production stamps caller identity (with the adapter PID) on every
/// non-health record and leaves global health rows pid-less, so any
/// foreign or pid-less data row fails closed here.
fn check_wrap_records_system(
    records: &[serde_json::Value],
    bytes: u64,
    b_modules: &BTreeSet<String>,
    owned_pid: u32,
    owned_caller: &str,
) -> Result<()> {
    let header = records.first().context("diagnostic header missing")?;
    ensure!(
        header["kind"] == "header"
            && header["scope"] == "system"
            && header["mode"] == "native"
            && header.get("pid_filter") == Some(&serde_json::Value::Null),
        "system wrap needs an unfiltered native system header: {header}"
    );
    for row in &records[1..records.len() - 1] {
        if row["kind"] == "capture_health" {
            ensure!(
                row["pid"].is_null(),
                "global health row carries a pid: {row}"
            );
        } else {
            ensure!(
                row["pid"] == owned_pid,
                "system export carries a non-owned row: {row}"
            );
        }
    }
    check_wrap_records_core(records, bytes, b_modules, Some(owned_caller))
}

fn time_shape(value: &serde_json::Value, field: &str) -> Result<bool> {
    let stamp = value
        .get(field)
        .with_context(|| format!("missing temporal field {field}"))?;
    ensure!(
        stamp.is_null() || stamp.as_u64().is_some(),
        "invalid temporal field {field}"
    );
    Ok(!stamp.is_null())
}

fn primary_facts(document: &serde_json::Value, pid: u32, k: u64) -> Result<serde_json::Value> {
    let caller = primary_pid_caller(document, pid)?;
    Ok(primary_facts_core(document, pid, k, caller)?.0)
}

/// PID capture admits exactly the owned workload: one caller entry, the
/// owned PID, mapped and unretired.
fn primary_pid_caller(document: &serde_json::Value, pid: u32) -> Result<&serde_json::Value> {
    let callers = document["callers"].as_array().context("primary callers")?;
    ensure!(
        callers.len() == 1
            && callers[0]["pid"] == pid
            && callers[0]["lifecycle"] == "mapped"
            && callers[0]["retired"] == false
    );
    Ok(&callers[0])
}

/// System capture admits the machine: the owned caller must appear
/// exactly once, mapped and unretired. Foreign-only presence is allowed
/// here; borrowing owned modules is rejected separately.
fn primary_system_caller(
    document: &serde_json::Value,
    owned_pid: u32,
) -> Result<&serde_json::Value> {
    let callers = document["callers"].as_array().context("primary callers")?;
    let owned: Vec<_> = callers
        .iter()
        .filter(|caller| caller["pid"] == owned_pid)
        .collect();
    ensure!(
        owned.len() == 1,
        "system capture must admit the owned caller exactly once: pid={owned_pid}"
    );
    ensure!(
        owned[0]["lifecycle"] == "mapped" && owned[0]["retired"] == false,
        "owned caller is not an active mapping: {}",
        owned[0]["id"]
    );
    Ok(owned[0])
}

/// No foreign caller may carry an edge on an owned module: the fixture
/// providers exist only in the owned workload, so any such edge is
/// misattribution, never system-capture honesty.
fn check_owned_module_exclusivity(
    document: &serde_json::Value,
    owned_pid: u32,
    owned_modules: &BTreeSet<String>,
) -> Result<()> {
    let owned_ids: BTreeSet<&str> = document["callers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|caller| caller["pid"] == owned_pid)
        .filter_map(|caller| caller["id"].as_str())
        .collect();
    for edge in document["edges"].as_array().into_iter().flatten() {
        if edge["module"]
            .as_str()
            .is_some_and(|module| owned_modules.contains(module))
        {
            ensure!(
                edge["caller"]
                    .as_str()
                    .is_some_and(|id| owned_ids.contains(id)),
                "foreign caller borrows an owned module edge: {edge}"
            );
        }
    }
    Ok(())
}

/// Owned provider label from a module's paths: exactly one indexed
/// `provider-A-%02d.so` / `provider-B-%02d.so` suffix match. Returns the
/// label with whether it is an A-side provider.
fn provider_label(module: &serde_json::Value) -> Result<(String, bool)> {
    let mut labels = BTreeSet::new();
    if let Some(paths) = module["paths"].as_array() {
        for path in paths.iter().filter_map(|path| path.as_str()) {
            for side in ['A', 'B'] {
                if let Some(index) = provider_index(path, side) {
                    labels.insert((format!("provider-{side}-{index:02}.so"), side == 'A'));
                }
            }
        }
    }
    ensure!(
        labels.len() == 1,
        "owned module must identify exactly one expected indexed provider"
    );
    labels.into_iter().next().context("indexed provider label")
}

/// Shared owned-population core: loss-free native observation plus the
/// pinned indexed A/B edges for the validated caller. Returns the primary
/// facts with the owned module ids for exclusivity checks.
fn primary_facts_core(
    document: &serde_json::Value,
    pid: u32,
    k: u64,
    caller: &serde_json::Value,
) -> Result<(serde_json::Value, BTreeSet<String>)> {
    primary_facts_core_schedule(document, pid, k, caller, COUNTED)
}

fn primary_facts_core_schedule(
    document: &serde_json::Value,
    pid: u32,
    k: u64,
    caller: &serde_json::Value,
    counted: u64,
) -> Result<(serde_json::Value, BTreeSet<String>)> {
    ensure!(
        (3..=COUNTED).contains(&counted),
        "invalid primary counted schedule"
    );
    ensure!(
        k == 0 || k == TARGETS,
        "startup disposition is all pairs or none: k={k}"
    );
    let observation = &document["observation"];
    ensure!(
        observation["lane"] == "native"
            && observation["settlement"] == "unsettled"
            && observation["retirement"] == "closed"
            && !ab_lifecycle_loss_detected(document),
        "expected loss-free native observation, closed retirement and explicitly unsettled capture"
    );
    let lifecycle = &observation["lifecycle"];
    for field in ["ring_loss", "malformed", "failed_quanta"] {
        ensure!(
            lifecycle[field].as_u64() == Some(0),
            "lifecycle failure or unavailable counter: {field}"
        );
    }
    ensure!(
        lifecycle["records"].as_u64().is_some() && lifecycle["recovery_rescans"].as_u64().is_some()
    );
    let witnesses = &observation["native_witnesses"];
    ensure!(witnesses["integrity"].as_u64() == Some(0) && witnesses["pending"].as_u64().is_some());
    let reasons = witnesses["unbound_reasons"]
        .as_object()
        .context("native unbound reasons missing")?;
    ensure!(reasons.values().all(|count| count.as_u64().is_some()));
    for field in ["ambiguous", "unresolved"] {
        ensure!(witnesses["placement"][field].as_u64().is_some());
    }
    let edges = doc_edges(document, pid);
    ensure!(
        edges.len() == 2 * TARGETS as usize,
        "need all64 owned edges, got {}",
        edges.len()
    );
    let modules = document["modules"].as_array().context("primary modules")?;
    let mut facts = BTreeMap::new();
    let mut module_ids = BTreeSet::new();
    let mut a_sum = 0u64;
    let mut b_sum = 0u64;
    for edge in edges {
        let matching: Vec<_> = modules
            .iter()
            .filter(|module| module["id"] == edge["module"])
            .collect();
        ensure!(matching.len() == 1, "edge module must be unique");
        let module = matching[0];
        ensure!(module_ids.insert(edge["module"].as_str().context("module ID")?.to_owned()));
        let (label, a) = provider_label(module)?;
        // Per-edge expectations come from the independently issued schedule.
        // Full cells keep400/399 on A and1 on each B; the short pilot keeps
        // its declared C projection. Diagnostics never supply these totals.
        let expected = if a { expected_a(counted, k) } else { 1 };
        let entries = &edge["entries"];
        let coverage = &entries["coverage"];
        ensure!(
            entries["count"] == expected
                && entries["observation"] == "observed"
                && entries["saturated"] == false
                && entries["in_flight"] == false
                && entries["cap"].as_u64().is_some()
        );
        // Snapshot edges carry mapping/module lifecycle, never the
        // event-only `presence`/`capture` presentation states.
        let expected_mapping = if a { "ended" } else { "mapped" };
        let expected_lifecycle = if a { "unloaded" } else { "mapped" };
        ensure!(
            edge["mapping"]["state"] == expected_mapping
                && module["lifecycle"] == expected_lifecycle
        );
        ensure!(module["unloaded_observed"].is_boolean());
        let state = coverage["state"].as_str().context("coverage state")?;
        ensure!(matches!(
            state,
            "counted" | "witnessed" | "watched_no_use" | "unknown"
        ));
        ensure!(
            coverage.get("reason").is_some()
                && coverage.get("detail").is_some()
                && coverage.get("lossy").is_some()
        );
        ensure!(
            (coverage["reason"].is_null() || coverage["reason"].is_string())
                && (coverage["detail"].is_null() || coverage["detail"].is_string())
                && (coverage["lossy"].is_null() || coverage["lossy"].is_boolean())
        );
        ensure!(
            coverage["reason"] != "loss" && coverage["lossy"] != true,
            "a genuine observation loss cannot qualify useful-count parity"
        );
        if !a {
            ensure!(state == "counted" && coverage["lossy"] == false);
        }
        let coverage_facts = serde_json::json!({"state":coverage["state"],
            "lossy":coverage["lossy"],"reason":coverage["reason"],"detail":coverage["detail"],
            "has_since":time_shape(coverage,"since_ns")?,"has_until":time_shape(coverage,"until_ns")?,
            "has_first":time_shape(coverage,"first_ns")?});
        let mapping = &edge["mapping"];
        let value = serde_json::json!({"mapping_state":mapping["state"],"mapping_evidence":mapping["evidence"],
            "mapping_reason":mapping["reason"],"mapping_interruptions":mapping["interruptions"],
            "has_mapping_first":time_shape(mapping,"first_seen_ns")?,"has_mapping_last":time_shape(mapping,"last_seen_ns")?,
            "count":entries["count"],"observation":entries["observation"],"saturated":entries["saturated"],
            "in_flight":entries["in_flight"],"cap":entries["cap"],
            "has_entry_first":time_shape(entries,"first_seen_ns")?,"has_entry_last":time_shape(entries,"last_seen_ns")?,
            "coverage":coverage_facts,"module_lifecycle":module["lifecycle"],
            "module_unloaded_observed":module["unloaded_observed"]});
        if a {
            a_sum += entries["count"].as_u64().context("A edge count")?;
        } else {
            b_sum += entries["count"].as_u64().context("B edge count")?;
        }
        ensure!(
            facts.insert(label, value).is_none(),
            "duplicate provider label"
        );
    }
    ensure!(
        facts.len() == 2 * TARGETS as usize
            && (0..TARGETS).all(|index| {
                facts.contains_key(&format!("provider-A-{index:02}.so"))
                    && facts.contains_key(&format!("provider-B-{index:02}.so"))
            }),
        "need one facts entry per indexed provider"
    );
    // Independently fixed totals; full cells retain12,800-k on A and32 on B.
    ensure!(
        a_sum == TARGETS * expected_a(counted, k),
        "A total {a_sum} differs from declared C={counted} k={k}"
    );
    ensure!(b_sum == TARGETS, "B total {b_sum} != 32");
    Ok((
        serde_json::json!({"edges":facts,"lane":observation["lane"],"settlement":observation["settlement"],
        "retirement":observation["retirement"],"caller_lifecycle":caller["lifecycle"],
        "caller_lifecycle_reason":caller["lifecycle_reason"],"caller_retired":caller["retired"],
        "lifecycle_failures":{"ring_loss":lifecycle["ring_loss"],"malformed":lifecycle["malformed"],
            "failed_quanta":lifecycle["failed_quanta"],"recovery_rescans":lifecycle["recovery_rescans"]},
        "native_failure_facts":{"integrity":witnesses["integrity"],"pending":witnesses["pending"],
            "unbound_reasons":witnesses["unbound_reasons"],"ambiguous":witnesses["placement"]["ambiguous"],
            "unresolved":witnesses["placement"]["unresolved"]}}),
        module_ids,
    ))
}

/// Extract owned primary facts from a bounded-system capture (cell 3):
/// the owned caller exactly once with the pinned A/B edges, and no
/// foreign caller borrowing an owned module. Foreign-only activity is
/// system-capture honesty, never owned evidence.
fn primary_facts_system(
    document: &serde_json::Value,
    owned_pid: u32,
    k: u64,
) -> Result<serde_json::Value> {
    let caller = primary_system_caller(document, owned_pid)?;
    let (facts, modules) = primary_facts_core(document, owned_pid, k, caller)?;
    check_owned_module_exclusivity(document, owned_pid, &modules)?;
    Ok(facts)
}

/// Post-run exact gap verification on the live-accumulated evidence (the
/// pre-`ended` flush makes repeats exact) under an explicit schedule:
/// startup `(1,2]` repeats must equal the live-validated `k`, each issued
/// shared unit needs exactly32 caller-bound retirement disclosures,
/// and the fence `(counted + shared, counted + shared + 1]` repeats must
/// be 32. Live accumulation — not a post-run file replay — because rotated
/// segments beyond retention are evicted: the refresh loop observes every
/// gap record exactly once (a sequence gap fails loudly), so its evidence
/// is the complete exact record including the flush rows.
fn verify_final_gaps_as(
    gaps: &[GapEvidence],
    caller: &str,
    modules_a: &[String],
    modules_b: &[String],
    k: u64,
    counted: u64,
    shared: u64,
) -> Result<()> {
    ensure!(
        modules_a.len() == TARGETS as usize && modules_b.len() == TARGETS as usize,
        "need all64 sharer module ids"
    );
    ensure!(k == 0 || k == TARGETS, "invalid startup disposition k={k}");
    let startup = startup_fence_repeats(gaps, caller);
    ensure!(
        startup == k,
        "final startup-fence repeats {startup} != live k={k}"
    );
    check_retirement_shared_checkpoint(gaps, caller, counted, shared)?;
    let fence = fence_gap_repeats_as(gaps, caller, counted, shared);
    ensure!(fence == TARGETS, "final fence repeats {fence} != 32");
    eprintln!(
        "G21_WRAP_GAPS caller={caller} k={k} startup={startup} shared_ranges={shared} repeats_per_range={TARGETS} fence={fence}"
    );
    Ok(())
}

/// Full-gate final gap verification (400 counted, 258 shared rounds).
fn verify_final_gaps(
    gaps: &[GapEvidence],
    caller: &str,
    modules_a: &[String],
    modules_b: &[String],
    k: u64,
) -> Result<()> {
    verify_final_gaps_as(gaps, caller, modules_a, modules_b, k, COUNTED, SHARED)
}

/// Consume terminal flush rows before checking exact repetitions. Stop
/// callbacks stop refreshing at proof completion, before the final writer flush.
fn verify_final_view_gaps(
    view: &mut PassView,
    events: &Path,
    pid: u32,
    k: u64,
    counted: u64,
    shared: u64,
) -> Result<()> {
    view.refresh(events, pid)?;
    verify_final_gaps_as(
        &view.evidence,
        view.caller_id.as_deref().context("final caller missing")?,
        &view.modules_a().context("final A module ids missing")?,
        &view.modules_b().context("final B module ids missing")?,
        k,
        counted,
        shared,
    )
}

/// The 32 owned B module ids from a primary document, matched by indexed
/// provider path suffix. Independent of the count oracle: the export
/// validator needs the module set even where counts already passed.
fn wrap_b_modules(document: &serde_json::Value, pid: u32) -> Result<BTreeSet<String>> {
    let modules = document["modules"].as_array().context("primary modules")?;
    let mut found = BTreeMap::new();
    for edge in doc_edges(document, pid) {
        let matching: Vec<_> = modules
            .iter()
            .filter(|module| module["id"] == edge["module"])
            .collect();
        if matching.len() != 1 {
            continue;
        }
        let module = matching[0];
        let id = edge["module"]
            .as_str()
            .context("edge module id")?
            .to_owned();
        if let Some(paths) = module["paths"].as_array() {
            for path in paths.iter().filter_map(|path| path.as_str()) {
                if let Some(index) = provider_index(path, 'B') {
                    found.insert(index, id.clone());
                }
            }
        }
    }
    ensure!(
        found.len() == TARGETS as usize,
        "need all32 B edges in the primary document, found {}",
        found.len()
    );
    Ok(found.into_values().collect())
}

/// G21 wrap cell shape: the PID wrap pair (cell 2) filters diagnostics
/// to the owned workload; the bounded system wrap pair (cell 3) captures
/// system-wide without a diagnostics PID filter, and the validators scope
/// every owned-population check to the owned caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WrapCell {
    Pid,
    System,
}

/// Validated wrap capture scope: a PID leg always carries the owned PID
/// as its diagnostics filter; a system leg is always unfiltered
/// (`pid_filter: None`, header `scope: "system"`, `pid_filter: null`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WrapScope {
    Pid { pid: u32 },
    System { owned_pid: u32 },
}

impl WrapScope {
    /// Select the validated wrap scope for one capture leg. The owned
    /// workload PID anchors both shapes: a PID leg must filter to exactly
    /// it, and a system leg must carry no filter at all. Anything else —
    /// a PID-shaped filter on a system leg, a missing/mismatched filter
    /// on a PID leg, or a zero owner — is refused, never normalized.
    fn select(scope: InspectScope, pid_filter: Option<u32>, owned_pid: u32) -> Result<Self> {
        ensure!(owned_pid != 0, "the wrap owner must be a real process");
        match (scope, pid_filter) {
            (InspectScope::Pid(pid), Some(filter)) if pid == filter && pid == owned_pid => {
                Ok(WrapScope::Pid { pid })
            }
            (InspectScope::System, None) => Ok(WrapScope::System { owned_pid }),
            (InspectScope::System, Some(_)) => {
                bail!("system wrap is unfiltered: a PID-shaped filter changes the cell")
            }
            (InspectScope::Pid(_), _) => {
                bail!("PID wrap must filter to exactly the owned workload")
            }
        }
    }

    fn owned_pid(&self) -> u32 {
        match *self {
            WrapScope::Pid { pid } => pid,
            WrapScope::System { owned_pid } => owned_pid,
        }
    }

    fn inspect_scope(&self) -> InspectScope {
        match *self {
            WrapScope::Pid { pid } => InspectScope::Pid(pid),
            WrapScope::System { .. } => InspectScope::System,
        }
    }

    fn diagnostics_pid_filter(&self) -> Option<u32> {
        match *self {
            WrapScope::Pid { pid } => Some(pid),
            WrapScope::System { .. } => None,
        }
    }
}

impl WrapCell {
    /// Resolve this cell to its validated capture scope for the owned
    /// workload PID. The PID cell filters diagnostics to the owner; the
    /// system cell captures unfiltered.
    fn scope(&self, owned_pid: u32) -> Result<WrapScope> {
        match self {
            WrapCell::Pid => {
                WrapScope::select(InspectScope::Pid(owned_pid), Some(owned_pid), owned_pid)
            }
            WrapCell::System => WrapScope::select(InspectScope::System, None, owned_pid),
        }
    }
}

fn run_wrap(enabled: bool) -> Result<(serde_json::Value, u64)> {
    run_wrap_cell(enabled, WrapCell::Pid)
}

fn run_wrap_system(enabled: bool) -> Result<(serde_json::Value, u64)> {
    run_wrap_cell(enabled, WrapCell::System)
}

/// One wrap leg under the given cell: the identical issued schedule,
/// milestone driver and owned-population checks; only the capture scope
/// (PID-filtered vs unfiltered system) and its validators differ.
fn run_wrap_cell(enabled: bool, cell: WrapCell) -> Result<(serde_json::Value, u64)> {
    let mut workload = WrapWorkload::spawn()?;
    workload.check_providers('A')?;
    workload.check_commons()?;
    let events = workload.dir.path().join("events.jsonl");
    let diagnostics = workload.dir.path().join("diagnostics.jsonl");
    let pid = workload.process.pid();
    let scope = cell.scope(pid)?;
    let start = Instant::now();
    let state = Cell::new((0u8, 0u64));
    let fence_k = Cell::new(0u64);
    let view = RefCell::new(PassView::default());
    let failure = RefCell::new(None::<anyhow::Error>);
    let gate = RefCell::new(StartupGate::new());
    let stop = || {
        let advance = || -> Result<bool> {
            if failure.borrow().is_some() {
                return Ok(true);
            }
            if start.elapsed() >= Duration::from_secs(RUN_SECONDS) {
                let view = view.borrow();
                bail!(
                    "G21 wrap exceeded900s, phase={:?} k={} A={:?} B={:?} gate_traj={:?} evidence={:?}",
                    state.get(),
                    fence_k.get(),
                    PassView::side_summary(&view.a),
                    PassView::side_summary(&view.b),
                    gate.borrow().trajectory,
                    view.evidence,
                );
            }
            if state.get().0 == 7 {
                return Ok(true);
            }
            let mut view = view.borrow_mut();
            if !view.refresh(&events, pid)? {
                return Ok(false);
            }
            let caller = view.caller_id.clone().unwrap_or_default();
            match state.get() {
                (0, _) => {
                    // Wait for all 32 A edges armed, then issue round 1.
                    // Both startup dispositions are greenable under per-edge
                    // arithmetic, so no settle dodges any fence.
                    if !PassView::side_armed(&view.a) {
                        return Ok(false);
                    }
                    workload.command("ready", "ready", 0)?;
                    workload.command("count", "a-done", 1)?;
                    eprintln!(
                        "G21_WRAP_ROUND enabled={enabled} phase=a round=1 issued caller={caller}"
                    );
                    state.set((1, 1));
                }
                (1, round) => {
                    // Wait for all 32 A edges at each milestone; apply the
                    // ordinary/fenced arithmetic per edge. Stale batches
                    // still show the prior milestone on some edges with no
                    // new gap evidence: wait. Anything outside the prior and
                    // target milestones fails here, never stalls into the
                    // timeout.
                    let Some(counts) = view.a_counts() else {
                        return Ok(false);
                    };
                    let k_now = startup_fence_repeats(&view.evidence, &caller);
                    let prev = if round == 1 {
                        0
                    } else {
                        expected_a(round - 1, fence_k.get())
                    };
                    if round == 2 {
                        let stale =
                            counts.iter().all(|count| *count == prev) && k_now == fence_k.get();
                        if stale
                            || !startup_round_ready(&gate, round, &counts, &view.evidence, &caller)?
                        {
                            return Ok(false);
                        }
                        let k = check_startup_round(
                            round,
                            &counts,
                            &view.evidence,
                            &caller,
                            Some(fence_k.get()),
                        )?;
                        fence_k.set(k);
                        eprintln!(
                            "G21_WRAP_ROUND enabled={enabled} phase=a round=2 A={} k={k}",
                            counts[0]
                        );
                        workload.command("count", "a-done", 3)?;
                        state.set((1, 3));
                    } else {
                        let target = expected_a(round, fence_k.get());
                        if !counts.iter().all(|count| *count == target) {
                            ensure!(
                                counts
                                    .iter()
                                    .all(|count| *count == prev || *count == target),
                                "A edge left the issued rounds at round-{round}: {counts:?} k_now={k_now}"
                            );
                            if round == 1 {
                                ensure!(k_now == 0, "round 1 fenced: k_now={k_now}");
                            } else {
                                ensure!(
                                    k_now == fence_k.get(),
                                    "startup disposition changed mid-run: k_now={k_now} validated={}",
                                    fence_k.get()
                                );
                            }
                            return Ok(false);
                        }
                        let prior = if round == 1 {
                            None
                        } else {
                            Some(fence_k.get())
                        };
                        let k =
                            check_startup_round(round, &counts, &view.evidence, &caller, prior)?;
                        fence_k.set(k);
                        if round <= 3 || round % 50 == 0 || round == COUNTED {
                            eprintln!(
                                "G21_WRAP_ROUND enabled={enabled} phase=a round={round} A={target} k={k}"
                            );
                        }
                        if round < COUNTED {
                            workload.command("count", "a-done", round + 1)?;
                            state.set((1, round + 1));
                        } else {
                            workload.command("load-b", "b-ready", 0)?;
                            workload.check_providers('B')?;
                            eprintln!(
                                "G21_WRAP_ROUND enabled={enabled} phase=a done A={target} k={k}"
                            );
                            state.set((2, 0));
                        }
                    }
                }
                (2, _) if PassView::side_armed(&view.b) => {
                    workload.command("shared", "shared-done", 1)?;
                    eprintln!(
                        "G21_WRAP_ROUND enabled={enabled} phase=shared round=1 issued k={}",
                        fence_k.get()
                    );
                    state.set((3, 1));
                }
                // The 32 pairs fold into one caller/range identity for each
                // issued unit. Wait for its repeat32 checkpoint before the
                // next round; module ambiguity gaps cannot replace it.
                (3, round) => {
                    let k = fence_k.get();
                    let a_counts = view.a_counts().context("A edges missing in shared phase")?;
                    let b_counts = view.b_counts().context("B edges missing in shared phase")?;
                    ensure!(
                        a_counts
                            .iter()
                            .all(|count| *count == expected_a(COUNTED, k))
                            && b_counts.iter().all(|count| *count == 0),
                        "shared calls escaped withholding: A={a_counts:?} B={b_counts:?} k={k}"
                    );
                    if !shared_round_floor(round, &view.evidence, &caller, COUNTED) {
                        return Ok(false);
                    }
                    if round < SHARED {
                        workload.command("shared", "shared-done", round + 1)?;
                        state.set((3, round + 1));
                    } else {
                        workload.command("unload-a", "a-unmapped", 0)?;
                        eprintln!(
                            "G21_WRAP_ROUND enabled={enabled} phase=shared done rounds={SHARED} k={k}"
                        );
                        state.set((4, 0));
                    }
                }
                (4, _)
                    if view.a.len() == TARGETS as usize
                        && view.a.values().all(|edge| edge["presence"] == "unloaded") =>
                {
                    workload.command("fence", "fence-done", 1)?;
                    eprintln!("G21_WRAP_ROUND enabled={enabled} phase=fence issued");
                    state.set((5, 0));
                }
                (5, _) => {
                    let b_counts = view.b_counts().context("B edges missing in fence phase")?;
                    ensure!(
                        b_counts.iter().all(|count| *count == 0),
                        "the fence was attributed: B={b_counts:?}"
                    );
                    if fence_gap_repeats(&view.evidence, &caller) == TARGETS {
                        workload.command("proof", "final-calls", 1)?;
                        eprintln!("G21_WRAP_ROUND enabled={enabled} phase=proof issued");
                        state.set((6, 0));
                    }
                }
                (6, _) => {
                    let k = fence_k.get();
                    let a_counts = view.a_counts().context("A edges missing in proof phase")?;
                    let b_counts = view.b_counts().context("B edges missing in proof phase")?;
                    ensure!(
                        a_counts
                            .iter()
                            .all(|count| *count == expected_a(COUNTED, k)),
                        "A history changed during proof: A={a_counts:?} k={k}"
                    );
                    // Each B edge reaches exactly 1 on its own pair's proof,
                    // independently: edges arrive as their pair recovers, so
                    // mixed 0/1 batches wait out. No batching premise — the
                    // terminal validator pins one proof per B module instead.
                    if b_counts.iter().all(|count| *count == 1) {
                        eprintln!("G21_WRAP_ROUND enabled={enabled} phase=proof done B=1x32 k={k}");
                        state.set((7, 0));
                    } else {
                        ensure!(
                            b_counts.iter().all(|count| *count <= 1),
                            "B recovered the wrong count: B={b_counts:?}"
                        );
                    }
                }
                _ => {}
            }
            Ok(state.get().0 == 7)
        };
        match advance() {
            Ok(done) => done,
            Err(error) => {
                if failure.borrow().is_none() {
                    *failure.borrow_mut() = Some(error);
                }
                true
            }
        }
    };
    let mut stdout = Vec::new();
    let code = run_with_terminal_diagnostics(
        scope.inspect_scope(),
        &[],
        &HookRegistry::builtin(),
        true,
        None,
        None,
        Some(Duration::from_secs(RUN_SECONDS)),
        None,
        false,
        Some(&events),
        None,
        None,
        CaptureMode::Native,
        crate::attach::BackendSelection::Auto,
        None,
        &stop,
        &|| {},
        false,
        &mut WriterStdout(&mut stdout),
        &DashboardIo::stdio(),
        DiagnosticRequest {
            path: enabled.then_some(diagnostics.as_path()),
            pid_filter: scope.diagnostics_pid_filter(),
            second_signal: &|| false,
        },
        None,
    )?;
    if let Some(error) = failure.into_inner() {
        return Err(error);
    }
    ensure!(
        code == 0 && state.get().0 == 7,
        "G21 phase incomplete: exit={code}, phase={:?}",
        state.get()
    );
    workload.command("stop", "done", 0)?;
    ensure!(workload.process.child.wait()?.success());
    check_native_ledger(&workload)?;
    // The `ended` row is the run's last write, so it always sits in the
    // live file (rotations only move earlier rows aside).
    let mut from_start = 0;
    let terminal_events = new_lines(&events, &mut from_start)?;
    ensure!(
        terminal_events
            .last()
            .is_some_and(|row| row["kind"] == "ended"),
        "public event stream lacks terminal end"
    );
    let k = fence_k.get();
    verify_final_view_gaps(&mut view.borrow_mut(), &events, pid, k, COUNTED, SHARED)?;
    let document: serde_json::Value = serde_json::from_slice(&stdout)?;
    let facts = match scope {
        WrapScope::Pid { pid } => primary_facts(&document, pid, k)?,
        WrapScope::System { owned_pid } => primary_facts_system(&document, owned_pid, k)?,
    };
    if enabled {
        let b_modules = wrap_b_modules(&document, pid)?;
        let length = std::fs::metadata(&diagnostics)?.len();
        let mut bytes = Vec::new();
        std::fs::File::open(&diagnostics)?
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 64 * 1024 * 1024 && bytes.len() as u64 == length);
        let records = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(serde_json::from_slice)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        match scope {
            WrapScope::Pid { pid } => check_wrap_records(&records, length, &b_modules, pid)?,
            WrapScope::System { owned_pid } => {
                let owned_caller = view
                    .borrow()
                    .caller_id
                    .clone()
                    .context("owned caller id never observed")?;
                check_wrap_records_system(&records, length, &b_modules, owned_pid, &owned_caller)?;
            }
        }
    } else {
        ensure!(!diagnostics.exists());
    }
    eprintln!(
        "G21_PAIRED enabled={enabled} elapsed_ms={} calls={} A_total={} B_total={} k={k} eligible_a={} withheld={} stdout_bytes={}",
        start.elapsed().as_millis(),
        (COUNTED + SHARED + 2) * TARGETS,
        TARGETS * expected_a(COUNTED, k),
        TARGETS,
        COUNTED * TARGETS - k,
        (SHARED + 1) * TARGETS + k,
        stdout.len()
    );
    Ok((facts, k))
}

// ---------------------------------------------------------------------------
// Short full-transition pilot (C=32/S=4): a bounded transition gate. It
// runs A -> Shared -> fence -> B proof at default cadence with default
// diagnostic capacities, retaining the native ledger and unanimity checks,
// and timestamps every round and pass. It makes no wrap claim. Retirement
// range, per-pair, fence and proof deviations fail qualification; the leg
// stops with a bounded report. The recorder footer is
// exported (read and logged) on every exit path, including phase failures.
// ---------------------------------------------------------------------------

/// Passes observed since the pilot issued shared round N before its
/// evidence is characterized as a deviation instead of waited out. A
/// healthy shared round should settle in a handful of passes; 24 covers
/// even a stalled A-like round without burning the run budget.
const PILOT_SHARED_ROUND_PASS_BOUND: u64 = 24;
/// Pass bound for the single fence round and the single proof round.
const PILOT_FENCE_PASS_BOUND: u64 = 60;
const PILOT_PROOF_PASS_BOUND: u64 = 60;

/// One observer pass as seen by the pilot: cumulative pass count, run
/// elapsed time, and harness stop-callback invocations since the previous
/// sample. Each sleep-loop iteration invokes the stop callback twice
/// (`ending` plus `stop_requested`) around exactly one native service turn
/// (`lane.tick` plus `on_native_service`), so stop invocations per pass
/// track native service frequency without touching product code.
#[derive(Clone)]
struct PilotPassSample {
    passes: u64,
    elapsed_ms: u128,
    stop_calls: u64,
    batch: u64,
}

/// One issued or validated pilot round: phase tag, round, elapsed time,
/// cumulative passes and stop calls.
#[derive(Clone)]
struct PilotRoundSample {
    phase: &'static str,
    round: u64,
    elapsed_ms: u128,
    passes: u64,
    stop_calls: u64,
}

/// How the pilot leg ended. Deviation outcomes preserve bounded failure
/// detail; only ProofReached with strict final validation qualifies. Immediate
/// count/ledger/timeout failures return `Err` instead.
enum PilotOutcome {
    /// B reached unanimous 1 on all 32 edges: full A->Shared->fence->B proof.
    ProofReached,
    /// Shared evidence deviated from the caller/range oracle within the
    /// pass bound: the leg stopped with expected-vs-observed detail.
    SharedOracleDeviation { round: u64, detail: String },
    /// Fence evidence never reached 32 repeats within the pass bound.
    FenceOracleDeviation { detail: String },
    /// B never reached unanimous 1 within the pass bound.
    ProofUnreached { detail: String },
}

impl PilotOutcome {
    fn tag(&self) -> &'static str {
        match self {
            PilotOutcome::ProofReached => "proof-reached",
            PilotOutcome::SharedOracleDeviation { .. } => "shared-oracle-deviation",
            PilotOutcome::FenceOracleDeviation { .. } => "fence-oracle-deviation",
            PilotOutcome::ProofUnreached { .. } => "proof-unreached",
        }
    }
}

struct PilotReport {
    outcome: PilotOutcome,
    k: u64,
    passes: u64,
    stop_calls: u64,
    elapsed_ms: u128,
    rounds: Vec<PilotRoundSample>,
    pass_samples: Vec<PilotPassSample>,
    footer: Option<serde_json::Value>,
    ledger_summary: String,
    engine_passes: Option<u64>,
}

/// Record one issued/validated pilot round sample (and log it).
fn pilot_note_round(
    samples: &RefCell<Vec<PilotRoundSample>>,
    phase: &'static str,
    round: u64,
    start: &Instant,
    passes: u64,
    stop_calls: u64,
) {
    let elapsed_ms = start.elapsed().as_millis();
    eprintln!(
        "G21_PILOT_ROUND phase={phase} round={round} elapsed_ms={elapsed_ms} passes={passes} stop_calls={stop_calls}"
    );
    samples.borrow_mut().push(PilotRoundSample {
        phase,
        round,
        elapsed_ms,
        passes,
        stop_calls,
    });
}

/// Readiness for the next issued round. Each unit's 32 repetitions reaches
/// an exact power-of-two checkpoint even when the round ordinal is not a
/// power of two. Missing/partial evidence waits; final verification is strict.
fn shared_round_floor(round: u64, gaps: &[GapEvidence], caller: &str, counted: u64) -> bool {
    check_retirement_shared_checkpoint(gaps, caller, counted, round).is_ok()
}

/// Bounded failure detail: expected caller/range multiplicity, observed
/// ranges, ordinary module ambiguity histogram and other gap subjects.
fn describe_shared_evidence(
    gaps: &[GapEvidence],
    modules_a: &[String],
    modules_b: &[String],
    round: u64,
    caller: &str,
    counted: u64,
) -> String {
    let mut histogram = BTreeMap::new();
    let mut deviating = Vec::new();
    for module in modules_a.iter().chain(modules_b.iter()) {
        let repeats = ambiguity_repeats(gaps, module);
        *histogram.entry(repeats).or_insert(0u64) += 1;
        if repeats != round && deviating.len() < 8 {
            deviating.push(format!("{module}={repeats}"));
        }
    }
    let mut caller_ranges = Vec::new();
    let mut other_subjects = BTreeMap::new();
    for gap in gaps {
        // Module-bound ordinary pending rejections remain visible, without
        // contributing to the retirement checkpoint.
        let is_caller_range =
            gap.subject == "rejected demoted count" && gap.caller.is_some() && gap.module.is_none();
        let is_ambiguity = gap.subject == "rejected demoted count"
            && gap.module.is_some()
            && gap.reason.contains("after sharing appeared");
        if is_caller_range {
            let range = gap
                .reason
                .split("absolute count range")
                .nth(1)
                .and_then(|rest| rest.split(';').next())
                .map(str::trim)
                .unwrap_or("?");
            if caller_ranges.len() < 40 {
                caller_ranges.push(format!(
                    "{}:{}x{}",
                    gap.caller.as_deref().unwrap_or("?"),
                    range,
                    gap.repeats
                ));
            }
        } else if !is_ambiguity {
            let key = format!(
                "caller={:?} module={:?} subject={:?} reason={:.80}",
                gap.caller, gap.module, gap.subject, gap.reason
            );
            *other_subjects.entry(key).or_insert(0u64) += 1;
        }
    }
    format!(
        "expected caller={caller} shared_ranges=({counted},{}] repeats_per_range={TARGETS}; observed module_ambiguity={histogram:?} module_deviating=[{}] caller_ranges=[{}] other_subjects={other_subjects:?} evidence_total={}",
        counted + round,
        deviating.join(","),
        caller_ranges.join(","),
        gaps.len(),
    )
}

/// Full gap-evidence dump (capped): every identity with its repeats.
/// Reasons truncate to 160 chars; entries past 64 fold into a count.
fn describe_gap_evidence(gaps: &[GapEvidence]) -> String {
    let mut entries = Vec::new();
    for gap in gaps.iter().take(64) {
        let reason: String = gap.reason.chars().take(160).collect();
        entries.push(format!(
            "caller={:?} module={:?} subject={:?} repeats={} reason={:?}",
            gap.caller, gap.module, gap.subject, gap.repeats, reason
        ));
    }
    format!(
        "total={} [{}]{}",
        gaps.len(),
        entries.join(" | "),
        if gaps.len() > 64 {
            format!(" ...and {} more", gaps.len() - 64)
        } else {
            String::new()
        }
    )
}

/// Partial-or-complete native ledger summary from the workload's call rows
/// and stdout ACKs: per-phase call counts, the terminal row, and the ACK
/// sequence (capped). Pure so unit tests pin it without a fixture.
fn pilot_ledger_summary(calls: &[serde_json::Value], acks: &[serde_json::Value]) -> String {
    let mut phases = BTreeMap::new();
    for row in calls {
        if row["kind"] == "call" {
            *phases
                .entry(row["phase"].as_str().unwrap_or("?").to_owned())
                .or_insert(0u64) += 1;
        }
    }
    let terminal = calls.last().map(|row| {
        format!(
            "kind={} complete={} calls={}",
            row["kind"].as_str().unwrap_or("?"),
            row["complete"].as_bool().unwrap_or(false),
            row["calls"].as_u64().unwrap_or(0)
        )
    });
    let ack_list: Vec<String> = acks
        .iter()
        .take(48)
        .map(|row| {
            format!(
                "{}/{}",
                row["event"].as_str().unwrap_or("?"),
                row["round"].as_u64().unwrap_or(0)
            )
        })
        .collect();
    format!(
        "call_rows={} phases={phases:?} terminal=[{}] acks=[{}]{}",
        calls.iter().filter(|row| row["kind"] == "call").count(),
        terminal.unwrap_or_else(|| "none".to_owned()),
        ack_list.join(","),
        if acks.len() > 48 {
            format!(" ...and {} more", acks.len() - 48)
        } else {
            String::new()
        }
    )
}

/// One instrumented full-transition leg under an explicit schedule (PID
/// cell, diagnostics always enabled). The A phase is strict: unanimous
/// milestones, the pinned per-edge trajectory and the startup gate, exactly
/// as in `run_wrap_cell`, plus per-round/pass timestamps and
/// stop-calls-per-pass counts. Shared, fence and proof phases keep strict
/// count facts (withholding, attribution bounds) and retain bounded deviation
/// detail before the caller fails qualification. The recorder footer is read and logged
/// on every exit path before any error returns.
fn run_transition_pilot(schedule: &WrapSchedule) -> Result<PilotReport> {
    let counted = schedule.counted;
    let shared = schedule.shared;
    let mut workload = WrapWorkload::spawn_schedule(schedule)?;
    workload.check_providers('A')?;
    workload.check_commons()?;
    let events = workload.dir.path().join("events.jsonl");
    let diagnostics = workload.dir.path().join("diagnostics.jsonl");
    let pid = workload.process.pid();
    let start = Instant::now();
    let state = Cell::new((0u8, 0u64));
    let fence_k = Cell::new(0u64);
    let view = RefCell::new(PassView::default());
    let failure = RefCell::new(None::<anyhow::Error>);
    let outcome = RefCell::new(None::<PilotOutcome>);
    let gate = RefCell::new(StartupGate::new());
    let stop_calls = Cell::new(0u64);
    let last_sample_turns = Cell::new(0u64);
    let pass_samples = RefCell::new(Vec::<PilotPassSample>::new());
    let round_samples = RefCell::new(Vec::<PilotRoundSample>::new());
    let phase_enter_pass = Cell::new(0u64);
    let stop = || {
        let advance = || -> Result<bool> {
            stop_calls.set(stop_calls.get() + 1);
            if failure.borrow().is_some() {
                return Ok(true);
            }
            if outcome.borrow().is_some() {
                return Ok(true);
            }
            if start.elapsed() >= Duration::from_secs(schedule.run_seconds) {
                let view = view.borrow();
                let rounds = round_samples.borrow();
                bail!(
                    "G21 pilot exceeded{}s, phase={:?} k={} A={:?} B={:?} passes={} stop_calls={} gate_traj={:?} rounds_validated={} evidence={:?}",
                    schedule.run_seconds,
                    state.get(),
                    fence_k.get(),
                    PassView::side_summary(&view.a),
                    PassView::side_summary(&view.b),
                    view.commits,
                    stop_calls.get(),
                    gate.borrow().trajectory,
                    rounds.len(),
                    view.evidence,
                );
            }
            if state.get().0 == 7 {
                return Ok(true);
            }
            let mut view = view.borrow_mut();
            let commits_before = view.commits;
            let advanced = view.refresh(&events, pid)?;
            let new_commits = view.commits - commits_before;
            if new_commits > 0 {
                let calls = stop_calls.get();
                let turns = calls - last_sample_turns.get();
                last_sample_turns.set(calls);
                let elapsed_ms = start.elapsed().as_millis();
                eprintln!(
                    "G21_PILOT_PASS passes={} elapsed_ms={elapsed_ms} turns_since_last={turns} batch={new_commits}",
                    view.commits
                );
                pass_samples.borrow_mut().push(PilotPassSample {
                    passes: view.commits,
                    elapsed_ms,
                    stop_calls: turns,
                    batch: new_commits,
                });
            }
            if !advanced {
                return Ok(false);
            }
            let caller = view.caller_id.clone().unwrap_or_default();
            let passes = view.commits;
            let calls = stop_calls.get();
            match state.get() {
                (0, _) => {
                    // Wait for all 32 A edges armed, then issue round 1.
                    if !PassView::side_armed(&view.a) {
                        return Ok(false);
                    }
                    workload.command("ready", "ready", 0)?;
                    workload.command("count", "a-done", 1)?;
                    pilot_note_round(&round_samples, "a-issued", 1, &start, passes, calls);
                    state.set((1, 1));
                }
                (1, round) => {
                    // Strict A milestones, as in the gate: unanimous edges,
                    // pinned per-edge trajectory, stable fence disposition.
                    let Some(counts) = view.a_counts() else {
                        return Ok(false);
                    };
                    let k_now = startup_fence_repeats(&view.evidence, &caller);
                    let prev = if round == 1 {
                        0
                    } else {
                        expected_a(round - 1, fence_k.get())
                    };
                    if round == 2 {
                        let stale =
                            counts.iter().all(|count| *count == prev) && k_now == fence_k.get();
                        if stale
                            || !startup_round_ready(&gate, round, &counts, &view.evidence, &caller)?
                        {
                            return Ok(false);
                        }
                        let k = check_startup_round_as(
                            round,
                            &counts,
                            &view.evidence,
                            &caller,
                            Some(fence_k.get()),
                            counted,
                        )?;
                        fence_k.set(k);
                        pilot_note_round(&round_samples, "a-validated", 2, &start, passes, calls);
                        workload.command("count", "a-done", 3)?;
                        pilot_note_round(&round_samples, "a-issued", 3, &start, passes, calls);
                        state.set((1, 3));
                    } else {
                        let target = expected_a(round, fence_k.get());
                        if !counts.iter().all(|count| *count == target) {
                            ensure!(
                                counts
                                    .iter()
                                    .all(|count| *count == prev || *count == target),
                                "pilot A edge left the issued rounds at round-{round}: {counts:?} k_now={k_now}"
                            );
                            if round == 1 {
                                ensure!(k_now == 0, "pilot round 1 fenced: k_now={k_now}");
                            } else {
                                ensure!(
                                    k_now == fence_k.get(),
                                    "pilot startup disposition changed mid-run: k_now={k_now} validated={}",
                                    fence_k.get()
                                );
                            }
                            return Ok(false);
                        }
                        let prior = if round == 1 {
                            None
                        } else {
                            Some(fence_k.get())
                        };
                        let k = check_startup_round_as(
                            round,
                            &counts,
                            &view.evidence,
                            &caller,
                            prior,
                            counted,
                        )?;
                        fence_k.set(k);
                        pilot_note_round(
                            &round_samples,
                            "a-validated",
                            round,
                            &start,
                            passes,
                            calls,
                        );
                        if round < counted {
                            workload.command("count", "a-done", round + 1)?;
                            pilot_note_round(
                                &round_samples,
                                "a-issued",
                                round + 1,
                                &start,
                                passes,
                                calls,
                            );
                            state.set((1, round + 1));
                        } else {
                            workload.command("load-b", "b-ready", 0)?;
                            workload.check_providers('B')?;
                            phase_enter_pass.set(passes);
                            state.set((2, 0));
                        }
                    }
                }
                (2, _) if PassView::side_armed(&view.b) => {
                    workload.command("shared", "shared-done", 1)?;
                    pilot_note_round(&round_samples, "shared-issued", 1, &start, passes, calls);
                    phase_enter_pass.set(passes);
                    state.set((3, 1));
                }
                // Each issued unit waits for exactly32 caller/range
                // disclosures. Per-pair identity and retained original
                // reads are checked on the complete bounded final export.
                (3, round) => {
                    let k = fence_k.get();
                    let a_counts = view
                        .a_counts()
                        .context("pilot A edges missing in shared phase")?;
                    let b_counts = view
                        .b_counts()
                        .context("pilot B edges missing in shared phase")?;
                    ensure!(
                        a_counts
                            .iter()
                            .all(|count| *count == expected_a(counted, k))
                            && b_counts.iter().all(|count| *count == 0),
                        "pilot shared calls escaped withholding: A={a_counts:?} B={b_counts:?} k={k}"
                    );
                    let modules_a = view.modules_a().context("pilot A module ids missing")?;
                    let modules_b = view.modules_b().context("pilot B module ids missing")?;
                    let checkpoint =
                        check_retirement_shared_checkpoint(&view.evidence, &caller, counted, round);
                    let checkpoint_text = match &checkpoint {
                        Ok(()) => "ok".to_owned(),
                        Err(error) => format!("err {error:#}"),
                    };
                    if checkpoint.is_ok() {
                        pilot_note_round(
                            &round_samples,
                            "shared-validated",
                            round,
                            &start,
                            passes,
                            calls,
                        );
                        if round < shared {
                            workload.command("shared", "shared-done", round + 1)?;
                            pilot_note_round(
                                &round_samples,
                                "shared-issued",
                                round + 1,
                                &start,
                                passes,
                                calls,
                            );
                            phase_enter_pass.set(passes);
                            state.set((3, round + 1));
                        } else {
                            workload.command("unload-a", "a-unmapped", 0)?;
                            phase_enter_pass.set(passes);
                            state.set((4, 0));
                        }
                    } else if passes - phase_enter_pass.get() > PILOT_SHARED_ROUND_PASS_BOUND {
                        let detail = describe_shared_evidence(
                            &view.evidence,
                            &modules_a,
                            &modules_b,
                            round,
                            &caller,
                            counted,
                        );
                        eprintln!(
                            "G21_PILOT_SHARED_DEVIATION round={round} elapsed_ms={} passes={passes} checkpoint={checkpoint_text} {detail}",
                            start.elapsed().as_millis(),
                        );
                        *outcome.borrow_mut() =
                            Some(PilotOutcome::SharedOracleDeviation { round, detail });
                        state.set((7, 0));
                    }
                }
                (4, _)
                    if view.a.len() == TARGETS as usize
                        && view.a.values().all(|edge| edge["presence"] == "unloaded") =>
                {
                    workload.command("fence", "fence-done", 1)?;
                    pilot_note_round(&round_samples, "fence-issued", 1, &start, passes, calls);
                    phase_enter_pass.set(passes);
                    state.set((5, 0));
                }
                (5, _) => {
                    // The fence must not be attributed (strict count fact);
                    // its gap evidence shape characterizes on deviation.
                    let b_counts = view
                        .b_counts()
                        .context("pilot B edges missing in fence phase")?;
                    ensure!(
                        b_counts.iter().all(|count| *count == 0),
                        "pilot fence was attributed: B={b_counts:?}"
                    );
                    if fence_gap_repeats_as(&view.evidence, &caller, counted, shared) == TARGETS {
                        pilot_note_round(
                            &round_samples,
                            "fence-validated",
                            1,
                            &start,
                            passes,
                            calls,
                        );
                        workload.command("proof", "final-calls", 1)?;
                        pilot_note_round(&round_samples, "proof-issued", 1, &start, passes, calls);
                        phase_enter_pass.set(passes);
                        state.set((6, 0));
                    } else if passes - phase_enter_pass.get() > PILOT_FENCE_PASS_BOUND {
                        let detail = describe_gap_evidence(&view.evidence);
                        eprintln!(
                            "G21_PILOT_FENCE_DEVIATION elapsed_ms={} passes={passes} {detail}",
                            start.elapsed().as_millis()
                        );
                        *outcome.borrow_mut() = Some(PilotOutcome::FenceOracleDeviation { detail });
                        state.set((7, 0));
                    }
                }
                (6, _) => {
                    let k = fence_k.get();
                    let a_counts = view
                        .a_counts()
                        .context("pilot A edges missing in proof phase")?;
                    let b_counts = view
                        .b_counts()
                        .context("pilot B edges missing in proof phase")?;
                    ensure!(
                        a_counts
                            .iter()
                            .all(|count| *count == expected_a(counted, k)),
                        "pilot A history changed during proof: A={a_counts:?} k={k}"
                    );
                    if b_counts.iter().all(|count| *count == 1) {
                        pilot_note_round(
                            &round_samples,
                            "proof-validated",
                            1,
                            &start,
                            passes,
                            calls,
                        );
                        *outcome.borrow_mut() = Some(PilotOutcome::ProofReached);
                        state.set((7, 0));
                    } else {
                        ensure!(
                            b_counts.iter().all(|count| *count <= 1),
                            "pilot B recovered the wrong count: B={b_counts:?}"
                        );
                        if passes - phase_enter_pass.get() > PILOT_PROOF_PASS_BOUND {
                            let detail =
                                format!("B={b_counts:?} {}", describe_gap_evidence(&view.evidence));
                            eprintln!(
                                "G21_PILOT_PROOF_UNREACHED elapsed_ms={} passes={passes} {detail}",
                                start.elapsed().as_millis()
                            );
                            *outcome.borrow_mut() = Some(PilotOutcome::ProofUnreached { detail });
                            state.set((7, 0));
                        }
                    }
                }
                _ => {}
            }
            Ok(state.get().0 == 7)
        };
        match advance() {
            Ok(done) => done,
            Err(error) => {
                if failure.borrow().is_none() {
                    *failure.borrow_mut() = Some(error);
                }
                true
            }
        }
    };
    let mut stdout = Vec::new();
    let code = run_with_terminal_diagnostics(
        InspectScope::Pid(pid),
        &[],
        &HookRegistry::builtin(),
        true,
        None,
        None,
        Some(Duration::from_secs(schedule.run_seconds)),
        None,
        false,
        Some(&events),
        None,
        None,
        CaptureMode::Native,
        crate::attach::BackendSelection::Auto,
        None,
        &stop,
        &|| {},
        false,
        &mut WriterStdout(&mut stdout),
        &DashboardIo::stdio(),
        DiagnosticRequest {
            path: Some(&diagnostics),
            pid_filter: Some(pid),
            second_signal: &|| false,
        },
        None,
    )?;
    // The footer exports on every exit path: read and log it before any
    // error below returns.
    let (records, footer_note, parsed_complete) = read_pilot_records(&diagnostics);
    let footer = records
        .last()
        .cloned()
        .filter(|row| row["kind"] == "footer");
    eprintln!(
        "G21_PILOT_FOOTER exit={code} records={} footer={} note={footer_note}",
        records.len(),
        footer
            .as_ref()
            .map(std::string::ToString::to_string)
            .unwrap_or_else(|| "none".to_owned()),
    );
    let engine_passes = serde_json::from_slice::<serde_json::Value>(&stdout)
        .ok()
        .and_then(|document| document["observation"]["passes"].as_u64());
    let build_report = |outcome: PilotOutcome, ledger_summary: String| PilotReport {
        outcome,
        k: fence_k.get(),
        passes: view.borrow().commits,
        stop_calls: stop_calls.get(),
        elapsed_ms: start.elapsed().as_millis(),
        rounds: round_samples.borrow().clone(),
        pass_samples: pass_samples.borrow().clone(),
        footer: footer.clone(),
        ledger_summary,
        engine_passes,
    };
    if let Some(error) = failure.borrow_mut().take() {
        let cancel = pilot_cancel_workload(&mut workload);
        let ledger_summary = read_pilot_ledger_summary(&workload);
        let report = build_report(
            PilotOutcome::ProofUnreached {
                detail: format!("pilot failed: {error:#}"),
            },
            ledger_summary,
        );
        eprintln!(
            "G21_PILOT_REPORT outcome=failed k={} passes={} stop_calls={} elapsed_ms={} engine_passes={:?} stats=[{}] workload=[{cancel}] ledger=[{}]",
            report.k,
            report.passes,
            report.stop_calls,
            report.elapsed_ms,
            report.engine_passes,
            pilot_summary_stats(&report),
            report.ledger_summary,
        );
        return Err(error);
    }
    ensure!(
        code == 0 && state.get().0 == 7,
        "G21 pilot phase incomplete: exit={code}, phase={:?}",
        state.get()
    );
    match outcome.borrow_mut().take() {
        Some(PilotOutcome::ProofReached) => {
            workload.command("stop", "done", 0)?;
            ensure!(workload.process.child.wait()?.success());
            check_native_ledger_schedule(&workload, counted, shared)?;
            // The `ended` row is the run's last write, so it always sits
            // in the live file (rotations only move earlier rows aside).
            let mut from_start = 0;
            let terminal_events = new_lines(&events, &mut from_start)?;
            ensure!(
                terminal_events
                    .last()
                    .is_some_and(|row| row["kind"] == "ended"),
                "pilot public event stream lacks terminal end"
            );
            let k = fence_k.get();
            verify_final_view_gaps(&mut view.borrow_mut(), &events, pid, k, counted, shared)?;
            {
                let view = view.borrow();
                let caller = view.caller_id.as_deref().context("pilot caller missing")?;
                let modules_a = view.modules_a().context("pilot A module ids missing")?;
                let modules_b = view.modules_b().context("pilot B module ids missing")?;
                ensure!(
                    parsed_complete,
                    "pilot diagnostic parsing incomplete: {footer_note}"
                );
                let length = std::fs::metadata(&diagnostics)?.len();
                check_bounded_pilot_export(&records, length, pid)?;
                check_shared_pair_dispositions(
                    &records, caller, &modules_a, &modules_b, counted, shared, k,
                )?;
                let document: serde_json::Value = serde_json::from_slice(&stdout)?;
                let primary_caller = primary_pid_caller(&document, pid)?;
                ensure!(
                    primary_caller["id"] == caller,
                    "pilot primary caller changed"
                );
                primary_facts_core_schedule(&document, pid, k, primary_caller, counted)?;
                let b_modules = wrap_b_modules(&document, pid)?;
                ensure!(
                    b_modules == modules_b.into_iter().collect(),
                    "pilot final B module ids differ from live indexed identities"
                );
            }
            let ledger_summary = read_pilot_ledger_summary(&workload);
            let report = build_report(PilotOutcome::ProofReached, ledger_summary);
            eprintln!(
                "G21_PILOT_REPORT outcome=proof-reached k={} passes={} stop_calls={} elapsed_ms={} engine_passes={:?} stats=[{}] ledger=[{}]",
                report.k,
                report.passes,
                report.stop_calls,
                report.elapsed_ms,
                report.engine_passes,
                pilot_summary_stats(&report),
                report.ledger_summary,
            );
            Ok(report)
        }
        Some(outcome) => {
            let tag = outcome.tag().to_owned();
            let cancel = pilot_cancel_workload(&mut workload);
            let ledger_summary = read_pilot_ledger_summary(&workload);
            let report = build_report(outcome, ledger_summary);
            eprintln!(
                "G21_PILOT_REPORT outcome={tag} k={} passes={} stop_calls={} elapsed_ms={} engine_passes={:?} stats=[{}] workload=[{cancel}] ledger=[{}]",
                report.k,
                report.passes,
                report.stop_calls,
                report.elapsed_ms,
                report.engine_passes,
                pilot_summary_stats(&report),
                report.ledger_summary,
            );
            Ok(report)
        }
        None => bail!(
            "G21 pilot finished without an outcome at phase {:?}",
            state.get()
        ),
    }
}

/// A complete short pilot uses the default capacities without any evicted,
/// filtered or omitted history. This does not substitute for the full wrap
/// contract, which separately requires both rings to have actually evicted.
fn check_bounded_pilot_export(records: &[serde_json::Value], bytes: u64, pid: u32) -> Result<()> {
    let header = records.first().context("pilot header missing")?;
    let footer = records.last().context("pilot footer missing")?;
    ensure!(
        header["kind"] == "header"
            && header["scope"] == "pid"
            && header["mode"] == "native"
            && header["pid_filter"] == pid
            && header["limits"]["ordinary_records"] == 24576
            && header["limits"]["exceptional_records"] == 8192
            && header["limits"]["heap_bytes"]
                .as_u64()
                .is_some_and(|heap| heap <= 16 * 1024 * 1024 - 8192),
        "pilot must use the bounded default native PID recorder"
    );
    ensure!(
        records.len() >= 2
            && bytes <= 64 * 1024 * 1024
            && footer["kind"] == "footer"
            && footer["diagnostics_complete"] == true
            && footer["counter_overflow"] == false
            && footer["sequence_exhausted"] == false
            && footer["oversized_records"] == 0
            && footer["records_written"] == records.len() as u64 - 2
            && footer["bytes_written"] == bytes,
        "pilot diagnostic export is incomplete"
    );
    let names = [
        "count_observation",
        "ownership_transition",
        "count_decision",
        "publication",
        "capture_health",
    ];
    let mut observed = [0u64; 5];
    for (index, row) in records[1..records.len() - 1].iter().enumerate() {
        ensure!(
            row["seq"] == index as u64 + 1,
            "pilot diagnostic history has a sequence hole"
        );
        let kind = names
            .iter()
            .position(|name| row["kind"] == *name)
            .context("unknown pilot record kind")?;
        observed[kind] += 1;
    }
    let kinds = footer["kinds"].as_array().context("pilot kind counters")?;
    ensure!(kinds.len() == names.len(), "pilot kind counters missing");
    for (kind, retained) in kinds.iter().zip(observed) {
        let keys: BTreeSet<_> = kind
            .as_object()
            .context("pilot kind counters object")?
            .keys()
            .map(String::as_str)
            .collect();
        ensure!(
            keys == BTreeSet::from(["produced", "retained", "evicted", "filtered", "omitted"])
                && kind["produced"] == retained
                && kind["retained"] == retained
                && kind["evicted"] == 0
                && kind["filtered"] == 0
                && kind["omitted"] == 0,
            "complete bounded pilot requires all actual kind history: {kind}"
        );
    }
    Ok(())
}

/// Read the pilot diagnostics export tolerantly: every parseable line is
/// kept, unparseable lines only count into the note. The pilot export is
/// small (no wrap), so a full read is cheap on every exit path. The boolean
/// prevents the tolerant failure report from qualifying a malformed export.
fn read_pilot_records(path: &Path) -> (Vec<serde_json::Value>, String, bool) {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return (Vec::new(), format!("open failed: {error}"), false),
    };
    let mut bytes = Vec::new();
    if file
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return (Vec::new(), "read failed".to_owned(), false);
    }
    if bytes.len() > 64 * 1024 * 1024 {
        return (
            Vec::new(),
            format!("{} bytes exceed 64MiB", bytes.len()),
            false,
        );
    }
    let mut records = Vec::new();
    let mut skipped = 0u64;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        match serde_json::from_slice(line) {
            Ok(row) => records.push(row),
            Err(_) => skipped += 1,
        }
    }
    (
        records,
        format!("bytes={} skipped_lines={skipped}", bytes.len()),
        skipped == 0,
    )
}

/// Native ledger summary for the pilot's workload tempdir, tolerating a
/// cancelled (partial) ledger: only complete lines are read, so a torn
/// tail row cannot fail the summary.
fn read_pilot_ledger_summary(workload: &WrapWorkload) -> String {
    let mut offset = 0;
    let calls =
        new_lines(&workload.dir.path().join("calls.jsonl"), &mut offset).unwrap_or_default();
    let mut offset = 0;
    let acks = new_lines(&workload.process.out, &mut offset).unwrap_or_default();
    pilot_ledger_summary(&calls, &acks)
}

/// Cancel a mid-schedule pilot workload: SIGTERM first so the fixture's
/// `wait_command` fails through its normal cancel path (writing the
/// `complete:false` terminal row), SIGKILL only if it does not exit.
fn pilot_cancel_workload(workload: &mut WrapWorkload) -> String {
    let pid = workload.process.pid();
    // SAFETY: kill sends a signal to the owned workload PID only; the
    // return code is recorded, and exit is always reaped below.
    let term = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    let mut waited = None;
    for _ in 0..100 {
        match workload.process.child.try_wait() {
            Ok(Some(status)) => {
                waited = Some(format!("{status}"));
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => {
                waited = Some(format!("wait-error {error}"));
                break;
            }
        }
    }
    if waited.is_none() {
        let _ = workload.process.child.kill();
        waited = Some(format!(
            "SIGKILL fallback: {:?}",
            workload.process.child.wait()
        ));
    }
    format!(
        "sigterm_rc={term} exit={}",
        waited.unwrap_or_else(|| "unknown".to_owned())
    )
}

/// Pilot cadence summary from the round/pass samples: A-round pass costs
/// overall and steady-state (rounds 4..=counted, past startup transients),
/// mean seconds/pass and stop-calls/pass, and the worst A round. Pure so
/// unit tests pin the arithmetic without a live run.
fn pilot_summary_stats(report: &PilotReport) -> String {
    let validated: Vec<&PilotRoundSample> = report
        .rounds
        .iter()
        .filter(|sample| sample.phase == "a-validated")
        .collect();
    let mut pass_deltas = Vec::new();
    let mut steady_passes = 0u64;
    let mut steady_ms = 0u128;
    let mut steady_turns = 0u64;
    let mut steady_rounds = 0u64;
    let mut worst = (0u64, 0u64);
    for pair in validated.windows(2) {
        let passes = pair[1].passes - pair[0].passes;
        let ms = pair[1].elapsed_ms - pair[0].elapsed_ms;
        pass_deltas.push(passes);
        if passes > worst.0 {
            worst = (passes, pair[1].round);
        }
        if pair[1].round >= 4 {
            steady_passes += passes;
            steady_ms += ms;
            steady_turns += pair[1].stop_calls - pair[0].stop_calls;
            steady_rounds += 1;
        }
    }
    let mean = |total: u64, count: usize| {
        if count == 0 {
            "none".to_owned()
        } else {
            format!("{:.2}", total as f64 / count as f64)
        }
    };
    let (sec_per_pass, turns_per_pass) =
        match (report.pass_samples.first(), report.pass_samples.last()) {
            (Some(first), Some(last)) if last.passes > first.passes => {
                let passes = last.passes - first.passes;
                let sec = (last.elapsed_ms - first.elapsed_ms) as f64 / 1000.0 / passes as f64;
                let turns: u64 = report
                    .pass_samples
                    .iter()
                    .map(|sample| sample.stop_calls)
                    .sum();
                let batches: u64 = report.pass_samples.iter().map(|sample| sample.batch).sum();
                (
                    format!("{sec:.3}"),
                    if batches == 0 {
                        "none".to_owned()
                    } else {
                        format!("{:.1}", turns as f64 / batches as f64)
                    },
                )
            }
            _ => ("none".to_owned(), "none".to_owned()),
        };
    format!(
        "a_rounds={} passes_per_round_all={} steady_rounds={steady_rounds} passes_per_round_steady={} sec_per_round_steady={} sec_per_pass={sec_per_pass} turns_per_pass={turns_per_pass} turns_per_round_steady={} worst_round={}@{}passes",
        validated.len(),
        mean(pass_deltas.iter().sum(), pass_deltas.len()),
        mean(steady_passes, steady_rounds as usize),
        if steady_rounds == 0 {
            "none".to_owned()
        } else {
            format!("{:.2}", steady_ms as f64 / 1000.0 / steady_rounds as f64)
        },
        mean(steady_turns, steady_rounds as usize),
        worst.1,
        worst.0,
    )
}

/// Footer per-kind counters for the final pilot line (the full footer is
/// already logged by `G21_PILOT_FOOTER` on every exit path).
fn pilot_footer_kinds(footer: &Option<serde_json::Value>) -> String {
    footer
        .as_ref()
        .and_then(|row| row.get("kinds"))
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| "none".to_owned())
}

/// Short full-transition pilot (C=32/S=4, PID cell, diagnostics enabled):
/// measures current-tip settling (passes/round, sec/pass, stop-calls per
/// pass), strict retirement/per-pair conservation, and footer production at
/// default cadence and default diagnostic capacities. Makes no wrap claim;
/// a deviation retains its bounded report and fails qualification.
#[test]
#[ignore = "root-owned BPF lane; parameterized C=32/S=4 full-transition pilot at default cadence, bounded540s"]
fn privileged_native_lane_pid_diagnostics_transition_pilot_lp64() -> Result<()> {
    let report = run_transition_pilot(&PILOT_SCHEDULE)?;
    eprintln!(
        "G21_PILOT_FINAL outcome={} k={} passes={} stop_calls={} elapsed_ms={} engine_passes={:?} stats=[{}] footer_kinds={} ledger=[{}]",
        report.outcome.tag(),
        report.k,
        report.passes,
        report.stop_calls,
        report.elapsed_ms,
        report.engine_passes,
        pilot_summary_stats(&report),
        pilot_footer_kinds(&report.footer),
        report.ledger_summary,
    );
    match &report.outcome {
        PilotOutcome::SharedOracleDeviation { round, detail } => {
            eprintln!("G21_PILOT_FINAL_SHARED round={round} {detail}");
        }
        PilotOutcome::FenceOracleDeviation { detail } | PilotOutcome::ProofUnreached { detail } => {
            eprintln!("G21_PILOT_FINAL_DETAIL {detail}");
        }
        PilotOutcome::ProofReached => {}
    }
    ensure!(
        matches!(&report.outcome, PilotOutcome::ProofReached),
        "G21 short transition did not qualify: {}",
        report.outcome.tag()
    );
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_pilot_shared_floor() -> Result<()> {
    let gaps_at = |rounds: u64| -> Vec<GapEvidence> {
        (1..=rounds)
            .map(|round| twin_range_gap("c0", 32 + round - 1, 32 + round, TARGETS))
            .collect()
    };
    ensure!(shared_round_floor(1, &gaps_at(1), "c0", 32));
    ensure!(shared_round_floor(3, &gaps_at(3), "c0", 32));
    ensure!(!shared_round_floor(2, &gaps_at(1), "c0", 32));
    let mut short = gaps_at(4);
    short[3].repeats = 16;
    ensure!(!shared_round_floor(4, &short, "c0", 32));
    ensure!(!shared_round_floor(4, &gaps_at(4), "foreign", 32));
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_pilot_describe_shared() -> Result<()> {
    let modules_a: Vec<String> = (0..32).map(|index| format!("mA-{index:02}")).collect();
    let modules_b: Vec<String> = (0..32).map(|index| format!("mB-{index:02}")).collect();
    // A partial caller/range repeat must stay visible alongside ordinary
    // module fanout, which cannot complete the retirement unit.
    let mut gaps = vec![twin_range_gap("c0", 32, 33, 4)];
    gaps.extend(
        modules_a
            .iter()
            .chain(modules_b.iter())
            .map(|module| twin_ambiguity_gap(module, 0)),
    );
    let detail = describe_shared_evidence(&gaps, &modules_a, &modules_b, 1, "c0", 32);
    ensure!(
        detail.contains("expected caller=c0 shared_ranges=(32,33] repeats_per_range=32")
            && detail.contains("module_ambiguity=")
            && detail.contains("c0:(32, 33]")
            && detail.contains("evidence_total=65"),
        "mismatch characterization lost its shapes: {detail}"
    );
    // The ordinary module histogram remains diagnostic context.
    let mut matched: Vec<GapEvidence> = modules_a
        .iter()
        .chain(modules_b.iter())
        .map(|module| twin_ambiguity_gap(module, 4))
        .collect();
    matched.push(twin_range_gap("c0", 32, 33, 32));
    let detail = describe_shared_evidence(&matched, &modules_a, &modules_b, 4, "c0", 32);
    ensure!(
        detail.contains("4: 64")
            && detail.contains("c0:(32, 33]")
            && detail.contains("shared_ranges=(32,36]"),
        "matching round misdescribed: {detail}"
    );
    // A module-bound rejected gap with a non-ambiguity reason is neither
    // histogram evidence nor a caller range: it must stay visible.
    let mut foreign = matched.clone();
    foreign.push(GapEvidence {
        caller: None,
        module: Some("mA-00".to_owned()),
        subject: "rejected demoted count".to_owned(),
        reason: "some other module-level refusal".to_owned(),
        repeats: 2,
    });
    let detail = describe_shared_evidence(&foreign, &modules_a, &modules_b, 4, "c0", 32);
    ensure!(
        detail.contains("some other module-level refusal"),
        "non-ambiguity module gap hidden: {detail}"
    );
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_pilot_ledger_summary() -> Result<()> {
    let calls = vec![
        serde_json::json!({"kind":"identity"}),
        serde_json::json!({"kind":"call","phase":"a","round":1}),
        serde_json::json!({"kind":"call","phase":"shared","round":1}),
        serde_json::json!({"kind":"complete","complete":false,"calls":2}),
    ];
    let acks = vec![
        serde_json::json!({"event":"a-done","round":1}),
        serde_json::json!({"event":"shared-done","round":1}),
    ];
    let summary = pilot_ledger_summary(&calls, &acks);
    ensure!(
        summary.contains("call_rows=2")
            && summary.contains("\"a\": 1")
            && summary.contains("complete=false")
            && summary.contains("a-done/1"),
        "partial ledger summary lost its counts: {summary}"
    );
    ensure!(
        pilot_ledger_summary(&[], &[]).contains("call_rows=0"),
        "empty ledger summary failed"
    );
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_pilot_summary_stats() -> Result<()> {
    // Four validated A rounds at 4 passes and 5.2s each, 37 stop calls
    // per pass: the steady window (rounds 4+) covers one delta here.
    let report = PilotReport {
        outcome: PilotOutcome::ProofReached,
        k: 0,
        passes: 16,
        stop_calls: 592,
        elapsed_ms: 20_800,
        rounds: (1..=4)
            .map(|round| PilotRoundSample {
                phase: "a-validated",
                round,
                elapsed_ms: round as u128 * 5200,
                passes: round * 4,
                stop_calls: round * 148,
            })
            .collect(),
        pass_samples: (1..=16)
            .map(|passes| PilotPassSample {
                passes,
                elapsed_ms: passes as u128 * 1300,
                stop_calls: 37,
                batch: 1,
            })
            .collect(),
        footer: None,
        ledger_summary: String::new(),
        engine_passes: Some(16),
    };
    let stats = pilot_summary_stats(&report);
    ensure!(
        stats.contains("a_rounds=4")
            && stats.contains("passes_per_round_all=4.00")
            && stats.contains("steady_rounds=1")
            && stats.contains("passes_per_round_steady=4.00")
            && stats.contains("sec_per_round_steady=5.20")
            && stats.contains("sec_per_pass=1.300")
            && stats.contains("turns_per_pass=37.0")
            && stats.contains("turns_per_round_steady=148.00"),
        "summary stats arithmetic drifted: {stats}"
    );
    let empty = PilotReport {
        outcome: PilotOutcome::ProofReached,
        k: 0,
        passes: 0,
        stop_calls: 0,
        elapsed_ms: 0,
        rounds: Vec::new(),
        pass_samples: Vec::new(),
        footer: None,
        ledger_summary: String::new(),
        engine_passes: None,
    };
    ensure!(
        pilot_summary_stats(&empty).contains("a_rounds=0"),
        "empty summary failed"
    );
    Ok(())
}

/// One wrap-pair edge rendered through the actual snapshot serializer, so
/// the host fixture cannot drift from installed output again (the G21
/// oracle failure: the old fixture invented event-only `presence`/
/// `capture` keys the renderer never emits).
fn fixture_edge_json(
    caller: crate::discovery::caller_registry::CallerId,
    module: crate::discovery::caller_registry::ModuleId,
    shift: u64,
    is_a: bool,
) -> serde_json::Value {
    fixture_edge_json_k(caller, module, shift, is_a, 0)
}

fn fixture_edge_json_k(
    caller: crate::discovery::caller_registry::CallerId,
    module: crate::discovery::caller_registry::ModuleId,
    shift: u64,
    is_a: bool,
    k: u64,
) -> serde_json::Value {
    use crate::discovery::caller_registry::{
        MappingEvidence, MappingState, SEMANTIC_UNKNOWN, UnknownReason, UseCoverage,
    };
    use crate::inventory_present::{Activity, Capture, EdgeSemanticsView, EdgeView, Presence};
    crate::inventory::edge_json(&EdgeView {
        caller,
        module,
        mapping: if is_a {
            MappingState::Ended
        } else {
            MappingState::Mapped
        },
        mapping_reason: None,
        mapping_evidence: MappingEvidence::DeepScan,
        mapping_first_seen_ns: 100 + shift,
        mapping_last_seen_ns: 200 + shift,
        mapping_interruptions: 0,
        entry_count: if is_a { expected_a(COUNTED, k) } else { 1 },
        entry_saturated: false,
        entry_first_seen_ns: Some(120 + shift),
        entry_last_seen_ns: Some(180 + shift),
        entry_in_flight: false,
        entry_observation: "observed",
        coverage: if is_a {
            UseCoverage::Unknown(UnknownReason::NotAttached)
        } else {
            UseCoverage::Counted {
                since_ns: 110 + shift,
                lossy: false,
            }
        },
        presence: if is_a {
            Presence::Unloaded
        } else {
            Presence::Mapped
        },
        capture: if is_a {
            Capture::Retired
        } else {
            Capture::Armed
        },
        activity: if is_a {
            Activity::Unknown
        } else {
            Activity::RecentlyObserved
        },
        semantics: EdgeSemanticsView {
            label: SEMANTIC_UNKNOWN,
            mechanisms: Vec::new(),
            operations: None,
        },
    })
}

/// Host-only validator documents. These do not constitute installed capture or
/// wrap evidence; the ignored gate always reads the actual product output.
fn primary_validator_fixture(pid: u32, shift: u64) -> serde_json::Value {
    primary_validator_fixture_k(pid, shift, 0)
}

fn primary_validator_fixture_k(pid: u32, shift: u64, k: u64) -> serde_json::Value {
    use crate::discovery::caller_registry::{CallerId, ModuleId};
    let caller = CallerId(shift as u32);
    let mut modules = Vec::new();
    let mut edges = Vec::new();
    for index in 0..TARGETS as u32 {
        let module = ModuleId(shift as u32 + 1 + index * 2);
        modules.push(serde_json::json!({"id":module.label(),
            "paths":[format!("/owned/provider-A-{index:02}.so")],
            "lifecycle":"unloaded","unloaded_observed":true}));
        edges.push(fixture_edge_json_k(
            caller,
            module,
            shift + u64::from(index),
            true,
            k,
        ));
    }
    for index in 0..TARGETS as u32 {
        let module = ModuleId(shift as u32 + 2 + index * 2);
        modules.push(serde_json::json!({"id":module.label(),
            "paths":[format!("/owned/provider-B-{index:02}.so")],
            "lifecycle":"mapped","unloaded_observed":false}));
        edges.push(fixture_edge_json(
            caller,
            module,
            shift + 100 + u64::from(index),
            false,
        ));
    }
    serde_json::json!({
        "observation":{"lane":"native","settlement":"unsettled","retirement":"closed",
            "lifecycle":{"records":shift+10,"ring_loss":0,"malformed":0,"failed_quanta":0,"recovery_rescans":0},
            "native_witnesses":{"rows":shift+20,"bound":shift+20,"unbound":0,"pending":0,"integrity":0,
                "unbound_reasons":{},"placement":{"edge":shift+20,"module":0,"ambiguous":0,"unresolved":0}}},
        "callers":[{"id":caller.label(),"pid":pid,"lifecycle":"mapped","retired":false,"lifecycle_reason":null}],
        "modules":modules,"edges":edges,"gaps":[]
    })
}

/// Primary facts with a validated startup disposition `k`: A must read
/// exactly the pinned edge (`expected_a(400, k)`, 400 ordinary or 399
/// fenced) and B must read exactly 1.
fn primary_facts_k(document: &serde_json::Value, pid: u32, k: u64) -> Result<serde_json::Value> {
    primary_facts(document, pid, k)
}

#[test]
fn operator_diagnostics_wrap_primary_validator_preserves_meaningful_facts() -> Result<()> {
    let healthy = primary_validator_fixture(123, 0);
    let expected = primary_facts(&healthy, 123, 0)?;
    ensure!(
        expected == primary_facts(&primary_validator_fixture(456, 500), 456, 0)?,
        "only identities, actual times and benign record totals may normalize"
    );
    for change in [
        "reason",
        "detail",
        "temporal_shape",
        "recovery_rescans",
        "unbound_reason",
        "caller_reason",
    ] {
        let mut altered = healthy.clone();
        match change {
            "reason" => {
                altered["edges"][0]["entries"]["coverage"]["reason"] =
                    "retired_before_coverage".into()
            }
            "detail" => {
                altered["edges"][0]["entries"]["coverage"]["detail"] =
                    "changed unknown context".into()
            }
            "temporal_shape" => altered["edges"][0]["entries"]["coverage"]["until_ns"] = 300.into(),
            "recovery_rescans" => {
                altered["observation"]["lifecycle"]["recovery_rescans"] = 1.into()
            }
            "unbound_reason" => {
                altered["observation"]["native_witnesses"]["unbound_reasons"]["cookie_unavailable"] =
                    1.into()
            }
            _ => altered["callers"][0]["lifecycle_reason"] = "changed caller context".into(),
        }
        ensure!(
            primary_facts(&altered, 123, 0)? != expected,
            "discarded meaningful primary fact: {change}"
        );
    }
    for change in [
        "retirement",
        "missing_settlement",
        "malformed",
        "failed_quanta",
        "ring_loss",
        "integrity",
        "duplicate_label",
        "missing_label",
        "duplicate_module",
        "count",
        "mapping_state",
        "module_lifecycle",
        "loss",
        "lossy",
    ] {
        let mut altered = healthy.clone();
        match change {
            "retirement" => altered["observation"]["retirement"] = "unsettled".into(),
            "missing_settlement" => {
                altered["observation"]
                    .as_object_mut()
                    .unwrap()
                    .remove("settlement");
            }
            "malformed" | "failed_quanta" | "ring_loss" => {
                altered["observation"]["lifecycle"][change] = 1.into()
            }
            "integrity" => altered["observation"]["native_witnesses"]["integrity"] = 1.into(),
            "duplicate_label" => {
                let mut duplicate = altered["edges"][32].clone();
                duplicate["module"] = altered["modules"][33]["id"].clone();
                altered["edges"][33] = duplicate;
                altered["modules"][33]["paths"] = serde_json::json!(["/owned/provider-B-00.so"]);
                altered["modules"][33]["lifecycle"] = "mapped".into();
                altered["modules"][33]["unloaded_observed"] = false.into();
            }
            "missing_label" => {
                altered["modules"][33]["paths"] = serde_json::json!(["/owned/other.so"])
            }
            "duplicate_module" => {
                let duplicate = altered["modules"][32]["id"].clone();
                altered["modules"][33]["id"] = duplicate;
            }
            "count" => altered["edges"][0]["entries"]["count"] = 1.into(),
            "mapping_state" => altered["edges"][0]["mapping"]["state"] = "mapped".into(),
            "module_lifecycle" => altered["modules"][0]["lifecycle"] = "mapped".into(),
            "loss" => altered["edges"][0]["entries"]["coverage"]["reason"] = "loss".into(),
            _ => altered["edges"][32]["entries"]["coverage"]["lossy"] = true.into(),
        }
        ensure!(
            primary_facts(&altered, 123, 0).is_err(),
            "invalid primary capture accepted: {change}"
        );
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_fixture_edges_match_snapshot_renderer_shape() -> Result<()> {
    // Meta-fix for the G21 oracle failure: pin the snapshot/event shape
    // contract both ways so the host fixture can never again invent
    // event-only keys the renderer does not emit.
    //
    // The reference MUST come straight from production edge_json on an
    // independently built EdgeView, never via fixture_edge_json (which also
    // builds the fixture side below): anything invented inside that helper
    // would otherwise pass on both sides. The construction duplication is
    // deliberate independence, not dead weight.
    use crate::discovery::caller_registry::{
        CallerId, MappingEvidence, MappingState, ModuleId, SEMANTIC_UNKNOWN, UseCoverage,
    };
    use crate::inventory_present::{Activity, Capture, EdgeSemanticsView, EdgeView, Presence};
    let rendered = crate::inventory::edge_json(&EdgeView {
        caller: CallerId(0),
        module: ModuleId(1),
        mapping: MappingState::Mapped,
        mapping_reason: None,
        mapping_evidence: MappingEvidence::DeepScan,
        mapping_first_seen_ns: 100,
        mapping_last_seen_ns: 200,
        mapping_interruptions: 0,
        entry_count: 1,
        entry_saturated: false,
        entry_first_seen_ns: Some(120),
        entry_last_seen_ns: Some(180),
        entry_in_flight: false,
        entry_observation: "observed",
        coverage: UseCoverage::Counted {
            since_ns: 110,
            lossy: false,
        },
        presence: Presence::Mapped,
        capture: Capture::Armed,
        activity: Activity::RecentlyObserved,
        semantics: EdgeSemanticsView {
            label: SEMANTIC_UNKNOWN,
            mechanisms: Vec::new(),
            operations: None,
        },
    });
    let renderer_keys: BTreeSet<&str> = rendered
        .as_object()
        .context("renderer edge object")?
        .keys()
        .map(String::as_str)
        .collect();
    for key in ["caller", "module", "mapping", "entries"] {
        ensure!(
            renderer_keys.contains(key),
            "renderer dropped oracle-read key: {key}"
        );
    }
    for key in ["presence", "capture"] {
        ensure!(
            !renderer_keys.contains(key),
            "renderer leaks event-only key: {key}"
        );
    }
    for shift in [0, 500] {
        let fixture = primary_validator_fixture(123, shift);
        let edges = fixture["edges"].as_array().context("fixture edges")?;
        ensure!(edges.len() == 2 * TARGETS as usize);
        for edge in edges {
            for key in edge.as_object().context("fixture edge object")?.keys() {
                ensure!(
                    renderer_keys.contains(key.as_str()),
                    "fixture edge key diverged from renderer shape: {key}"
                );
            }
        }
    }
    Ok(())
}

fn seal_validator_fixture(records: &mut [serde_json::Value]) -> u64 {
    let last = records.len() - 1;
    records[last]["records_written"] = ((last - 1) as u64).into();
    loop {
        let bytes = records
            .iter()
            .map(|row| serde_json::to_vec(row).unwrap().len() as u64 + 1)
            .sum::<u64>();
        if records[last]["bytes_written"] == bytes {
            return bytes;
        }
        records[last]["bytes_written"] = bytes.into();
    }
}

fn diagnostic_validator_fixture() -> (Vec<serde_json::Value>, u64) {
    let mut records = vec![
        serde_json::json!({"kind":"header","scope":"pid","mode":"native","pid_filter":123,
        "limits":{"ordinary_records":24576,"exceptional_records":8192,"heap_bytes":8*1024*1024}}),
    ];
    let mut sequence = 100u64;
    let mut push = |mut row: serde_json::Value| {
        row["seq"] = sequence.into();
        sequence += 1;
        records.push(row);
    };
    for _ in 0..24543 {
        push(serde_json::json!({"kind":"count_observation"}));
    }
    push(serde_json::json!({"kind":"ownership_transition"}));
    push(serde_json::json!({"kind":"capture_health"}));
    push(serde_json::json!({"kind":"publication"}));
    for index in 0..8190 {
        let mut row = serde_json::json!({"kind":"count_decision","decision":"withheld"});
        if index < 32 {
            row["pair"] = format!("p{index}").into();
            row["reason"] = "awaiting_fence".into();
            row["after"] = (COUNTED + SHARED).into();
            row["through"] = (COUNTED + SHARED + 1).into();
            row["absolute"] = (COUNTED + SHARED + 1).into();
            row["caller"] = "c0".into();
            row["pre"] = 7000.into();
            row["post"] = 7010.into();
            row["observation_ref"] = serde_json::json!({"seq":24642,"status":"retained"});
        }
        push(row);
    }
    for index in 0..32 {
        push(
            serde_json::json!({"kind":"publication","decision":"placed","module_id":format!("mB-{index:02}"),
        "pair":format!("p{index}"),"base":COUNTED+SHARED+1,"absolute":COUNTED+SHARED+2,"staged":1,
        "edge_total":1,"caller":"c0","pre":7020,"post":7030,
        "baseline_pre":7000,"baseline_post":7010,
        "observation_ref":{"seq":24642,"status":"retained"},
        "transition_ref":{"seq":1,"status":"not_retained"},"history_complete":false}),
        );
    }
    let retained = [24543u64, 1, 8190, 33, 1];
    let evicted = [1u64, 1, 0, 0, 0];
    let kinds: Vec<_> = retained.into_iter().zip(evicted).map(|(retained,evicted)|
        serde_json::json!({"produced":retained+evicted,"retained":retained,"evicted":evicted,"filtered":0,"omitted":0})).collect();
    records.push(serde_json::json!({"kind":"footer","diagnostics_complete":true,"kinds":kinds,
        "counter_overflow":false,"sequence_exhausted":false,"oversized_records":0,"records_written":0,"bytes_written":0}));
    let bytes = seal_validator_fixture(&mut records);
    (records, bytes)
}

/// Twin helper: the 32 indexed B module ids `mB-00..31`.
fn twin_b_modules() -> BTreeSet<String> {
    (0..32).map(|index| format!("mB-{index:02}")).collect()
}

#[test]
fn operator_diagnostics_wrap_retained_validator_checks_actual_rows() -> Result<()> {
    let (healthy, bytes) = diagnostic_validator_fixture();
    check_wrap_records(&healthy, bytes, &twin_b_modules(), 123)?;
    for change in [
        "remove_row",
        "retained_lie",
        "swap_entries",
        "duplicate_entry",
        "extra_kind_label",
        "unknown_kind",
        "capacity",
        "retained_reference",
        "not_retained_reference",
        "missing_pair",
    ] {
        let mut altered = healthy.clone();
        let last = altered.len() - 1;
        match change {
            "remove_row" => {
                altered.remove(1);
            }
            "retained_lie" => {
                altered[last]["kinds"][0]["retained"] = 24544.into();
                altered[last]["kinds"][0]["produced"] = 24545.into();
            }
            "swap_entries" => altered[last]["kinds"].as_array_mut().unwrap().swap(0, 1),
            "duplicate_entry" => {
                let duplicate = altered[last]["kinds"][0].clone();
                altered[last]["kinds"][1] = duplicate;
            }
            "extra_kind_label" => altered[last]["kinds"][0]["kind"] = "count_observation".into(),
            "unknown_kind" => altered[1]["kind"] = "invented_record".into(),
            "capacity" => {
                let row = altered
                    .iter_mut()
                    .rfind(|row| row["kind"] == "count_decision")
                    .unwrap();
                row["kind"] = "count_observation".into();
                row["decision"] = serde_json::Value::Null;
                altered[last]["kinds"][0]["retained"] = 24544.into();
                altered[last]["kinds"][0]["produced"] = 24545.into();
                altered[last]["kinds"][2]["retained"] = 8189.into();
                altered[last]["kinds"][2]["produced"] = 8189.into();
            }
            "retained_reference" => {
                altered[last - 1]["transition_ref"]["status"] = "retained".into()
            }
            "not_retained_reference" => altered[last - 1]["transition_ref"]["seq"] = 100.into(),
            _ => altered[last - 1]["pair"] = "p0".into(),
        }
        let bytes = seal_validator_fixture(&mut altered);
        ensure!(
            check_wrap_records(&altered, bytes, &twin_b_modules(), 123).is_err(),
            "retained-output corruption passed: {change}"
        );
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_reads_only_new_complete_lines() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("events");
    std::fs::write(&path, b"{\"kind\":\"started\"}\n{\"kind\":")?;
    let mut offset = 0;
    let rows = new_lines(&path, &mut offset)?;
    ensure!(rows.len() == 1 && rows[0]["kind"] == "started");
    ensure!(new_lines(&path, &mut offset)?.is_empty());
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)?
        .write_all(b"\"pass_committed\"}\n")?;
    let rows = new_lines(&path, &mut offset)?;
    ensure!(rows.len() == 1 && rows[0]["kind"] == "pass_committed");
    ensure!(new_lines(&path, &mut offset)?.is_empty());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_refresh_triggers_on_view_change() -> Result<()> {
    // The validation trigger is the trailing commit or any view-changing
    // row: an edge-only or gap-only batch (a read landing between a pass's
    // rows and its commit marker) must still validate, never skip.
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("events");
    let edge = "{\"seq\":0,\"kind\":\"edge_observed\",\"event\":{\"identity_context\":{\"caller\":{\"pid\":7,\"id\":\"c0\"},\"module\":{\"path\":\"/x/provider-A-07.so\",\"id\":\"m7\"}},\"entries\":{\"count\":4}}}\n";
    let gap = "{\"seq\":0,\"kind\":\"gap_recorded\",\"event\":{\"caller\":\"c0\",\"subject\":\"s\",\"reason\":\"r\"}}\n";
    let commit = "{\"seq\":0,\"kind\":\"pass_committed\",\"event\":{}}\n";
    let other = "{\"seq\":0,\"kind\":\"caller_event\",\"event\":{}}\n";
    // Edge-only batch: view moved (A edge + caller), no commit yet.
    let mut view = PassView::default();
    std::fs::write(&path, edge)?;
    ensure!(view.refresh(&path, 7)?);
    ensure!(view.a.contains_key(&7) && view.caller_id.as_deref() == Some("c0"));
    ensure!(view.module_a.get(&7).is_some_and(|id| id == "m7"));
    // Gap-only batch: evidence moved, no commit yet.
    let mut view = PassView::default();
    std::fs::write(&path, gap)?;
    ensure!(view.refresh(&path, 7)?);
    ensure!(view.evidence.len() == 1);
    // Foreign-pid edge batch: view untouched, no commit, no trigger.
    let mut view = PassView::default();
    std::fs::write(&path, edge.replace("\"pid\":7", "\"pid\":8"))?;
    ensure!(!view.refresh(&path, 7)?);
    ensure!(view.a.is_empty());
    // Unrelated-kind batch: nothing moved, no trigger.
    let mut view = PassView::default();
    std::fs::write(&path, other)?;
    ensure!(!view.refresh(&path, 7)?);
    // Trailing commit still triggers on its own.
    let mut view = PassView::default();
    std::fs::write(&path, commit)?;
    ensure!(view.refresh(&path, 7)?);
    // Empty delta never triggers.
    ensure!(!view.refresh(&path, 7)?);
    Ok(())
}

/// Sum of one side's 32 indexed edge counts in primary facts.
fn facts_side_total(facts: &serde_json::Value, side: char) -> Result<u64> {
    let mut total = 0u64;
    for index in 0..TARGETS {
        let label = format!("provider-{side}-{index:02}.so");
        total += facts["edges"][label.as_str()]["count"]
            .as_u64()
            .with_context(|| format!("{label} count missing"))?;
    }
    Ok(total)
}

/// Strict paired off/on comparison (Sol): both legs run the identical
/// deterministic issued schedule with milestone gating (the matched
/// prelude), so they must validate the same startup disposition and their
/// owned primary facts must compare exactly equal. No count replacement:
/// replacing counts before comparison proves conditional agreement only,
/// and different legitimate dispositions each pass their own oracle without
/// proving literal count equality. Expected counts come from the issued
/// schedule plus observed startup gaps, never from reported diagnostics.
fn check_paired_parity(
    disabled: &serde_json::Value,
    dk: u64,
    enabled: &serde_json::Value,
    ek: u64,
) -> Result<()> {
    for index in 0..TARGETS {
        let a_label = format!("provider-A-{index:02}.so");
        let b_label = format!("provider-B-{index:02}.so");
        ensure!(
            disabled["edges"][a_label.as_str()]["count"] == expected_a(COUNTED, dk)
                && enabled["edges"][a_label.as_str()]["count"] == expected_a(COUNTED, ek),
            "leg A-{index:02} contradicts its validated disposition: dk={dk} ek={ek}"
        );
        ensure!(
            disabled["edges"][b_label.as_str()]["count"] == 1
                && enabled["edges"][b_label.as_str()]["count"] == 1,
            "leg B-{index:02} is not exactly its pair's proof"
        );
    }
    ensure!(
        facts_side_total(disabled, 'A')? == TARGETS * expected_a(COUNTED, dk)
            && facts_side_total(enabled, 'A')? == TARGETS * expected_a(COUNTED, ek)
            && facts_side_total(disabled, 'B')? == TARGETS
            && facts_side_total(enabled, 'B')? == TARGETS,
        "paired legs disagree with the fixed 12,800-k/32 totals: dk={dk} ek={ek}"
    );
    ensure!(
        dk == ek,
        "paired legs disagree on startup disposition: dk={dk} ek={ek}"
    );
    ensure!(
        disabled == enabled,
        "diagnostics changed primary count/coverage/loss facts: off={disabled}, on={enabled}, dk={dk}, ek={ek}"
    );
    eprintln!("G21_PARITY dk={dk} ek={ek} match=true");
    Ok(())
}

#[test]
#[ignore = "root-owned BPF lane; prebuilt32-object fixture, paired default-ring wrap (~22min)"]
fn privileged_native_lane_pid_diagnostics_wrap_and_primary_parity_lp64() -> Result<()> {
    let (disabled, dk) = run_wrap(false)?;
    let (enabled, ek) = run_wrap(true)?;
    check_paired_parity(&disabled, dk, &enabled, ek)
}

/// Bounded system wrap pair (cell 3): the identical 32-object schedule
/// under unfiltered system capture, with owned-caller validators and
/// the same strict paired off/on parity.
#[test]
#[ignore = "root-owned BPF lane; prebuilt32-object fixture, bounded system default-ring wrap pair (~22min+)"]
fn privileged_native_lane_system_diagnostics_wrap_and_primary_parity_lp64() -> Result<()> {
    let (disabled, dk) = run_wrap_system(false)?;
    let (enabled, ek) = run_wrap_system(true)?;
    check_paired_parity(&disabled, dk, &enabled, ek)
}

/// Validate the small probe's actual dispositions independently of its progress
/// predicates: 32 genuinely distinct pairs, each advancing one unit per
/// round on its own A module, with exactly `k` fenced pairs withholding
/// round 2.
fn check_startup_probe_records(
    records: &[serde_json::Value],
    public_counts: &[u64],
    pid: u32,
    modules: &BTreeSet<String>,
    calls: &[(u64, u64)],
    k: u64,
) -> Result<serde_json::Value> {
    ensure!(calls.len() == 3);
    ensure!(
        modules.len() == TARGETS as usize,
        "probe needs all32 A module ids, got {}",
        modules.len()
    );
    ensure!(
        public_counts.len() == TARGETS as usize,
        "probe needs all32 public A counts, got {}",
        public_counts.len()
    );
    ensure!(
        k == 0 || k == TARGETS,
        "probe disposition is all pairs or none: k={k}"
    );
    let header = records.first().context("startup diagnostics header")?;
    let footer = records.last().context("startup diagnostics footer")?;
    ensure!(
        header["kind"] == "header"
            && header["scope"] == "pid"
            && header["mode"] == "native"
            && header["pid_filter"] == pid
    );
    ensure!(
        header["limits"]["ordinary_records"] == 24576
            && header["limits"]["exceptional_records"] == 8192
    );
    ensure!(
        footer["kind"] == "footer"
            && footer["diagnostics_complete"] == true
            && footer["counter_overflow"] == false
            && footer["sequence_exhausted"] == false
            && footer["oversized_records"] == 0
            && footer["records_written"] == records.len() as u64 - 2
    );
    let kinds = footer["kinds"]
        .as_array()
        .context("startup kind counters")?;
    ensure!(
        kinds.len() == 5
            && kinds
                .iter()
                .all(|kind| kind["evicted"] == 0 && kind["filtered"] == 0 && kind["omitted"] == 0)
    );
    let names = [
        "count_observation",
        "ownership_transition",
        "count_decision",
        "publication",
        "capture_health",
    ];
    let mut observed = [0u64; 5];
    let mut previous = 0;
    for row in &records[1..records.len() - 1] {
        let index = names
            .iter()
            .position(|name| row["kind"] == *name)
            .context("unknown short-probe record kind")?;
        observed[index] += 1;
        let sequence = row["seq"].as_u64().context("probe record sequence")?;
        ensure!(sequence > previous);
        previous = sequence;
    }
    for (kind, retained) in kinds.iter().zip(observed) {
        let keys: BTreeSet<_> = kind
            .as_object()
            .context("probe kind counters object")?
            .keys()
            .map(String::as_str)
            .collect();
        ensure!(keys == BTreeSet::from(["produced", "retained", "evicted", "filtered", "omitted"]));
        ensure!(
            kind["retained"] == retained && kind["produced"] == retained,
            "short-probe footer must reconcile to each actual kind"
        );
    }
    let observations: Vec<_> = records
        .iter()
        .filter(|row| {
            row["kind"] == "count_observation" && row["absolute"].as_u64().is_some_and(|n| n > 0)
        })
        .collect();
    ensure!(
        observations.len() == 96,
        "probe needs exactly three changing native observations per pair"
    );
    let mut by_pair: BTreeMap<String, BTreeMap<u64, &serde_json::Value>> = BTreeMap::new();
    for row in &observations {
        ensure!(row["pid"] == pid);
        let pair = row["pair"].as_str().context("probe pair")?.to_owned();
        let absolute = row["absolute"].as_u64().context("probe absolute")?;
        ensure!(
            by_pair
                .entry(pair)
                .or_default()
                .insert(absolute, row)
                .is_none(),
            "duplicate changing observation for one pair and absolute"
        );
    }
    ensure!(by_pair.len() == 32, "probe needs exactly32 physical pairs");
    let mut seq_by_pair_absolute = BTreeMap::new();
    for (pair, absolutes) in &by_pair {
        ensure!(
            absolutes.keys().copied().collect::<Vec<_>>() == vec![1, 2, 3],
            "pair {pair} needs exactly absolutes 1, 2, 3"
        );
        for (absolute, row) in absolutes {
            let index = (*absolute - 1) as usize;
            let pre = row["pre"].as_u64().context("actual read PRE")?;
            let post = row["post"].as_u64().context("actual read POST")?;
            ensure!(
                calls[index].1 <= pre && pre <= post,
                "the quiescent native round must finish before the actual read PRE"
            );
            if index + 1 < calls.len() {
                ensure!(
                    post < calls[index + 1].0,
                    "next issued round must follow actual prior read"
                );
            }
            seq_by_pair_absolute.insert(
                (pair.clone(), *absolute),
                row["seq"].as_u64().context("probe observation seq")?,
            );
        }
    }
    let pairs: BTreeSet<_> = records
        .iter()
        .filter_map(|row| row["pair"].as_str())
        .collect();
    ensure!(
        pairs == by_pair.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        "every diagnostic pair must be one of the32 observed physical pairs"
    );
    let placed = |pair: &str, absolute: u64, base: u64| -> Vec<&serde_json::Value> {
        records
            .iter()
            .filter(|row| {
                row["kind"] == "publication"
                    && row["decision"] == "placed"
                    && row["pair"] == pair
                    && row["module_id"]
                        .as_str()
                        .is_some_and(|module| modules.contains(module))
                    && row["absolute"] == absolute
                    && row["base"] == base
                    && row["staged"] == 1
                    && row["reason"] == "sole_owner"
                    && row["observation_ref"]["seq"]
                        == seq_by_pair_absolute[&(pair.to_owned(), absolute)]
                    && row["observation_ref"]["status"] == "retained"
            })
            .collect()
    };
    // Exact pair/module correspondence: each pair's publications sit on
    // exactly one A module, and the 32 pairs span all 32 A modules.
    let mut pair_modules: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for row in records.iter().filter(|row| {
        row["kind"] == "publication"
            && row["decision"] == "placed"
            && row["module_id"]
                .as_str()
                .is_some_and(|module| modules.contains(module))
    }) {
        let pair = row["pair"].as_str().context("probe publication pair")?;
        let module = row["module_id"]
            .as_str()
            .context("probe publication module")?;
        pair_modules.entry(pair).or_default().insert(module);
    }
    ensure!(
        pair_modules.len() == TARGETS as usize && pair_modules.values().all(|ids| ids.len() == 1),
        "each probe pair publishes on exactly one A module: {pair_modules:?}"
    );
    let used: BTreeSet<&str> = pair_modules.values().flatten().copied().collect();
    ensure!(
        used == modules.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        "probe pairs must span all32 A modules exactly once"
    );
    for pair in pairs.iter() {
        ensure!(
            placed(pair, 1, 0).len() == 1,
            "first unit must remain actual published history on {pair}"
        );
    }
    // Only the startup-fence disposition counts toward k: shutdown-frozen
    // third units (withheld/capture_stopped) are stop residue, asserted
    // absent below, never fence evidence.
    let fences: Vec<_> = records
        .iter()
        .filter(|row| {
            row["kind"] == "count_decision"
                && row["decision"] == "withheld"
                && row["reason"] == "awaiting_fence"
        })
        .collect();
    ensure!(
        fences.len() as u64 == k,
        "probe needs exactly the k validated startup fences"
    );
    let fenced_pairs: BTreeSet<_> = fences
        .iter()
        .filter_map(|row| row["pair"].as_str())
        .collect();
    ensure!(
        fenced_pairs.len() as u64 == k,
        "startup fences must sit on distinct pairs"
    );
    for fence in &fences {
        let pair = fence["pair"].as_str().context("fence pair")?;
        ensure!(
            fence["reason"] == "awaiting_fence"
                && fence["after"] == 1
                && fence["through"] == 2
                && fence["absolute"] == 2
                && fence["observation_ref"]["seq"] == seq_by_pair_absolute[&(pair.to_owned(), 2)]
                && fence["observation_ref"]["status"] == "retained",
            "the second unit requires an explicit actual startup fence disposition on {pair}"
        );
        ensure!(
            placed(pair, 2, 1).is_empty(),
            "withheld second round cannot also be placed on {pair}"
        );
        let recovered = placed(pair, 3, 2);
        ensure!(
            recovered.len() == 1,
            "fenced {pair} must recover its third unit"
        );
        ensure!(
            recovered[0]["baseline_pre"] == by_pair[pair][&2]["pre"]
                && recovered[0]["baseline_post"] == by_pair[pair][&2]["post"],
            "recovery must retain the genuine second-read fence window on {pair}"
        );
    }
    for pair in pairs.difference(&fenced_pairs) {
        ensure!(
            placed(pair, 2, 1).len() == 1 && placed(pair, 3, 2).len() == 1,
            "ordinary path must place all three unit advances on {pair}"
        );
    }
    let frozen: Vec<_> = records
        .iter()
        .filter(|row| {
            row["kind"] == "count_decision" && row["decision"] == "withheld" && row["absolute"] == 3
        })
        .collect();
    ensure!(
        frozen.is_empty(),
        "stop incomplete: {} third units still withheld at stop",
        frozen.len()
    );
    // Terminal projection per path: ordinary edges read 3 (all three units
    // placed); fenced edges read 2 (units 1 and 3 placed, unit 2 permanently
    // withheld by the startup fence). There is no drain: each pair's growth
    // installs on its own edge only, so no later publication carries one
    // pair's edge past another's installs.
    let terminal = if k == 0 { 3 } else { 2 };
    ensure!(
        public_counts.iter().all(|count| *count == terminal),
        "only the exact terminal probe projection ({terminal} on every edge) is qualified"
    );
    let path = if k == 0 { "ordinary" } else { "startup_fence" };
    Ok(
        serde_json::json!({"path":path,"physical_pairs":32,"calls":96,
        "published":terminal,"withheld":k,"fenced_pairs":k,
        "observations":observations,"fences":fences}),
    )
}

/// Short actual native control before any revised long wrap schedule. The two
/// accepted paths are distinguished by real dispositions, never by elapsed sleep.
/// Terminals are per-path (ordinary 3, fenced 2 on every edge): the milestone
/// gate already waits for all 32 unanimous edges, so round 3 validated is
/// terminal — no drain follows.
#[test]
#[ignore = "root-owned BPF lane; source-matched prebuilt3-round probe, bounded90s"]
fn privileged_native_lane_pid_diagnostics_three_round_startup_probe_lp64() -> Result<()> {
    let mut workload = WrapWorkload::spawn_profile(true)?;
    workload.check_providers('A')?;
    workload.check_commons()?;
    let pid = workload.process.pid();
    let events = workload.dir.path().join("probe-events.jsonl");
    let diagnostics = workload.dir.path().join("probe-diagnostics.jsonl");
    let started = Instant::now();
    let state = Cell::new(0u8);
    let fence_k = Cell::new(0u64);
    let first_mapping = Cell::new(0u64);
    let view = RefCell::new(PassView::default());
    let failure = RefCell::new(None::<anyhow::Error>);
    let gate = RefCell::new(StartupGate::new());
    let stop = || {
        let advance = || -> Result<bool> {
            if failure.borrow().is_some() {
                return Ok(true);
            }
            if started.elapsed() >= Duration::from_secs(90) {
                let view = view.borrow();
                let caller = view.caller_id.clone().unwrap_or_default();
                bail!(
                    "startup probe exceeded90s at phase{} A={:?} k_now={} gate_traj={:?}",
                    state.get(),
                    PassView::side_summary(&view.a),
                    startup_fence_repeats(&view.evidence, &caller),
                    gate.borrow().trajectory,
                );
            }
            if state.get() == 5 {
                return Ok(true);
            }
            let mut view = view.borrow_mut();
            if !view.refresh(&events, pid)? {
                return Ok(false);
            }
            let caller = view.caller_id.clone().unwrap_or_default();
            match state.get() {
                0 if PassView::side_armed(&view.a) => {
                    workload.command("ready", "ready", 0)?;
                    workload.command("count", "a-done", 1)?;
                    state.set(1);
                }
                awaiting @ 1..=3 => {
                    let round = u64::from(awaiting);
                    let Some(counts) = view.a_counts() else {
                        return Ok(false);
                    };
                    let k_now = startup_fence_repeats(&view.evidence, &caller);
                    let prev = if round == 1 {
                        0
                    } else {
                        expected_a(round - 1, fence_k.get())
                    };
                    let ready = if round == 2 {
                        let stale =
                            counts.iter().all(|count| *count == prev) && k_now == fence_k.get();
                        !stale
                            && startup_round_ready(&gate, round, &counts, &view.evidence, &caller)?
                    } else {
                        let target = expected_a(round, fence_k.get());
                        if !counts.iter().all(|count| *count == target) {
                            ensure!(
                                counts
                                    .iter()
                                    .all(|count| *count == prev || *count == target),
                                "probe A edge left the issued rounds at round-{round}: {counts:?}"
                            );
                            if round == 1 {
                                ensure!(k_now == 0, "probe round 1 fenced: k_now={k_now}");
                            } else {
                                ensure!(
                                    k_now == fence_k.get(),
                                    "probe disposition changed mid-run: k_now={k_now}"
                                );
                            }
                            return Ok(false);
                        }
                        true
                    };
                    if ready {
                        let prior = if round == 1 {
                            None
                        } else {
                            Some(fence_k.get())
                        };
                        let k =
                            check_startup_round(round, &counts, &view.evidence, &caller, prior)?;
                        fence_k.set(k);
                        if round == 1 {
                            first_mapping.set(
                                view.a
                                    .get(&0)
                                    .and_then(|edge| edge["mapping"]["last_seen_ns"].as_u64())
                                    .context("first published mapping clock")?,
                            );
                        }
                        eprintln!(
                            "G21_STARTUP_PROBE_ROUND round={round} A={} k={k} caller={caller}",
                            counts[0]
                        );
                        if round < 3 {
                            workload.command("count", "a-done", round + 1)?;
                            state.set(awaiting + 1);
                        } else {
                            // Round 3 validated on all 32 unanimous edges is
                            // terminal (ordinary 3, fenced 2): the milestone
                            // gate already waited out every pair's installs.
                            state.set(5);
                        }
                    }
                }
                _ => {}
            }
            Ok(state.get() == 5)
        };
        match advance() {
            Ok(done) => done,
            Err(error) => {
                if failure.borrow().is_none() {
                    *failure.borrow_mut() = Some(error);
                }
                true
            }
        }
    };
    let mut stdout = Vec::new();
    let code = run_with_terminal_diagnostics(
        InspectScope::Pid(pid),
        &[],
        &HookRegistry::builtin(),
        true,
        None,
        None,
        Some(Duration::from_secs(90)),
        None,
        false,
        Some(&events),
        None,
        None,
        CaptureMode::Native,
        crate::attach::BackendSelection::Auto,
        None,
        &stop,
        &|| {},
        false,
        &mut WriterStdout(&mut stdout),
        &DashboardIo::stdio(),
        DiagnosticRequest {
            path: Some(&diagnostics),
            pid_filter: Some(pid),
            second_signal: &|| false,
        },
        None,
    )?;
    if let Some(error) = failure.into_inner() {
        return Err(error);
    }
    ensure!(
        code == 0 && state.get() == 5,
        "short probe failed without complete actual milestones"
    );
    workload.command("stop", "done", 0)?;
    ensure!(workload.process.child.wait()?.success());
    check_native_schedule(&workload, &[("a", 3)])?;
    let ledger = jsonl_records(&workload.dir.path().join("calls.jsonl"))?;
    let mut intervals = Vec::new();
    for round in 1..=3 {
        let calls: Vec<_> = ledger
            .iter()
            .filter(|row| row["kind"] == "call" && row["phase"] == "a" && row["round"] == round)
            .collect();
        ensure!(calls.len() == 32);
        intervals.push((
            calls[0]["before_call_ns"].as_u64().context("first entry")?,
            calls[31]["after_return_ns"]
                .as_u64()
                .context("last return")?,
        ));
    }
    let document: serde_json::Value = serde_json::from_slice(&stdout)?;
    let observation = &document["observation"];
    ensure!(
        observation["lane"] == "native"
            && observation["retirement"] == "closed"
            && observation["settlement"] == "unsettled"
            && !ab_lifecycle_loss_detected(&document)
    );
    for field in ["ring_loss", "malformed", "failed_quanta"] {
        ensure!(observation["lifecycle"][field] == 0);
    }
    ensure!(observation["native_witnesses"]["integrity"] == 0);
    let edges = doc_edges(&document, pid);
    if edges.len() != TARGETS as usize
        || edges
            .iter()
            .any(|edge| edge["mapping"]["state"] != "mapped")
    {
        // The private fixture directory is removed on return. Keep bounded
        // actual output in the failing test log before rejecting its shape;
        // these diagnostics never replace the acceptance predicate below.
        let mut diagnostic_bytes = Vec::new();
        std::fs::File::open(&diagnostics)?
            .take(128 * 1024 + 1)
            .read_to_end(&mut diagnostic_bytes)?;
        eprintln!(
            "G21_STARTUP_PROBE_REJECTED cadence_ms={} elapsed_ms={} phase={} k={} first_public_mapping_last_seen_ns={} intervals={intervals:?} document_bytes={} diagnostics_bytes={}",
            inventory_test_poll_interval().as_millis(),
            started.elapsed().as_millis(),
            state.get(),
            fence_k.get(),
            first_mapping.get(),
            stdout.len(),
            diagnostic_bytes.len(),
        );
        if stdout.len() <= 128 * 1024 {
            eprintln!("G21_STARTUP_PROBE_ACTUAL_DOCUMENT={document}");
        }
        if diagnostic_bytes.len() <= 128 * 1024 {
            eprintln!(
                "G21_STARTUP_PROBE_ACTUAL_DIAGNOSTICS={}",
                std::str::from_utf8(&diagnostic_bytes)?
            );
        }
    }
    ensure!(
        edges.len() == TARGETS as usize
            && edges
                .iter()
                .all(|edge| edge["mapping"]["state"] == "mapped"),
        "actual final caller edge shape differs from the probe's 32 mapped providers"
    );
    let modules: BTreeSet<String> = edges
        .iter()
        .filter_map(|edge| edge["module"].as_str().map(str::to_owned))
        .collect();
    ensure!(
        modules.len() == TARGETS as usize,
        "probe needs 32 distinct A modules"
    );
    let mut public = Vec::new();
    for edge in &edges {
        public.push(edge["entries"]["count"].as_u64().context("final A count")?);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&diagnostics)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024 * 1024);
    let records = bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let k = fence_k.get();
    let facts = check_startup_probe_records(&records, &public, pid, &modules, &intervals, k)?;
    ensure!(
        (facts["path"] == "startup_fence") == (k == TARGETS) && facts["fenced_pairs"] == k,
        "live gate k={k} contradicts diagnostic dispositions: {facts}"
    );
    eprintln!(
        "G21_STARTUP_PROBE cadence_ms={} elapsed_ms={} passes={} k={k} first_public_mapping_last_seen_ns={} actual_kind_totals={} facts={facts}",
        inventory_test_poll_interval().as_millis(),
        started.elapsed().as_millis(),
        observation["passes"],
        first_mapping.get(),
        records.last().context("actual probe footer")?["kinds"],
    );
    Ok(())
}

fn startup_probe_validator_fixture(fenced: bool) -> Vec<serde_json::Value> {
    let mut rows = vec![
        serde_json::json!({"kind":"header","scope":"pid","mode":"native",
        "pid_filter":123,"limits":{"ordinary_records":24576,"exceptional_records":8192}}),
    ];
    let mut seq = 0u64;
    for round in 1..=3u64 {
        for pair in 0..32 {
            let name = format!("p{pair}");
            let module = format!("mA-{pair:02}");
            seq += 1;
            let obs_seq = seq;
            rows.push(
                serde_json::json!({"kind":"count_observation","pid":123,"pair":name,
                "seq":obs_seq,"absolute":round,"pre":round*40+70,"post":round*40+80}),
            );
            seq += 1;
            if fenced && round == 2 {
                rows.push(
                    serde_json::json!({"kind":"count_decision","decision":"withheld",
                    "pair":name,"seq":seq,"reason":"awaiting_fence","after":1,
                    "through":2,"absolute":2,
                    "observation_ref":{"seq":obs_seq,"status":"retained"}}),
                );
            } else {
                rows.push(
                    serde_json::json!({"kind":"publication","decision":"placed","reason":"sole_owner",
                    "pair":name,"seq":seq,"module_id":module,"absolute":round,"base":round-1,
                    "staged":1,"observation_ref":{"seq":obs_seq,"status":"retained"},
                    "baseline_pre":150,"baseline_post":160}),
                );
            }
        }
    }
    let names = [
        "count_observation",
        "ownership_transition",
        "count_decision",
        "publication",
        "capture_health",
    ];
    let kinds: Vec<_> = names.iter().map(|name| {
        let count = rows.iter().filter(|row| row["kind"] == *name).count();
        serde_json::json!({"produced":count,"retained":count,"evicted":0,"filtered":0,"omitted":0})
    }).collect();
    let written = rows.len() as u64 - 1;
    rows.push(
        serde_json::json!({"kind":"footer","diagnostics_complete":true,
        "counter_overflow":false,"sequence_exhausted":false,"oversized_records":0,
        "records_written":written,"kinds":kinds}),
    );
    rows
}

/// Twin helper: the 32 indexed probe A module ids `mA-00..31`.
fn twin_probe_modules() -> BTreeSet<String> {
    (0..32).map(|index| format!("mA-{index:02}")).collect()
}

#[test]
fn operator_diagnostics_three_round_probe_checks_fence_and_physical_pair() -> Result<()> {
    let calls = [(90, 110), (130, 150), (170, 190)];
    let modules = twin_probe_modules();
    let ordinary = startup_probe_validator_fixture(false);
    let fenced = startup_probe_validator_fixture(true);
    let terminal_ordinary = vec![3u64; 32];
    let terminal_fenced = vec![2u64; 32];
    let ordinary_facts =
        check_startup_probe_records(&ordinary, &terminal_ordinary, 123, &modules, &calls, 0)?;
    ensure!(ordinary_facts["path"] == "ordinary" && ordinary_facts["fenced_pairs"] == 0);
    ensure!(ordinary_facts["published"] == 3);
    let fenced_facts =
        check_startup_probe_records(&fenced, &terminal_fenced, 123, &modules, &calls, 32)?;
    ensure!(fenced_facts["path"] == "startup_fence" && fenced_facts["fenced_pairs"] == 32);
    ensure!(fenced_facts["published"] == 2);
    // Crossed terminals fail: ordinary never reads 2, fenced never reads 3.
    let mut ordinary_short = terminal_ordinary.clone();
    ordinary_short[11] = 2;
    ensure!(
        check_startup_probe_records(&ordinary, &ordinary_short, 123, &modules, &calls, 0).is_err()
    );
    // Round-grouped layout: header 0; round 1 rows 1..64 (p0 obs/pub at
    // 1/2, p1 pub at 4); round 2 rows 65..128 (first fence at 66); round 3
    // rows 129..192 (first recovery at 130); footer 193.
    for change in [
        "second_pair",
        "wrong_absolute",
        "false_fence_reason",
        "false_fence_range",
        "missing_recovery",
        "wrong_baseline",
        "wrong_reference",
        "wrong_primary",
        "wrong_k",
        "raw_before_call",
        "kind_counter_lie",
        "read_starts_before_return",
        "fence_reason_stopped",
        "shared_module",
        "foreign_module",
    ] {
        let mut changed = fenced.clone();
        let mut primary = vec![2u64; 32];
        let mut k = 32;
        match change {
            "second_pair" => changed[1]["pair"] = "p32".into(),
            "wrong_absolute" => changed[1]["absolute"] = 99.into(),
            "false_fence_reason" => changed[66]["reason"] = "identity_changed".into(),
            "false_fence_range" => changed[66]["after"] = 0.into(),
            "missing_recovery" => changed[130]["decision"] = "staged".into(),
            "wrong_baseline" => changed[130]["baseline_post"] = 159.into(),
            "wrong_reference" => changed[66]["observation_ref"]["seq"] = 1.into(),
            "wrong_primary" => primary[7] = 3,
            "wrong_k" => k = 0,
            "raw_before_call" => changed[65]["post"] = 180.into(),
            "read_starts_before_return" => changed[1]["pre"] = 109.into(),
            "fence_reason_stopped" => changed[66]["reason"] = "capture_stopped".into(),
            "shared_module" => changed[4]["module_id"] = "mA-00".into(),
            "foreign_module" => changed[2]["module_id"] = "mX".into(),
            _ => changed[193]["kinds"][0]["retained"] = 95.into(),
        }
        ensure!(
            check_startup_probe_records(&changed, &primary, 123, &modules, &calls, k).is_err(),
            "false startup-fence evidence accepted: {change}"
        );
    }
    Ok(())
}

/// Actual engine/BPF at a declared test-local cadence, not default CLI cost.
/// The pilot's real wall time and exported per-kind production are the input to
/// any later long schedule; no synthetic clock or record multiplier is used.
#[test]
#[ignore = "root-owned BPF lane; real3-round accelerated10ms cadence pilot, bounded90s"]
fn privileged_native_lane_pid_diagnostics_three_round_accelerated_pilot_lp64() -> Result<()> {
    with_inventory_test_poll_interval(
        Duration::from_millis(10),
        privileged_native_lane_pid_diagnostics_three_round_startup_probe_lp64,
    )
}

/// S-lever gate lane: the same real 3-round probe at the gate-configured
/// cadence (`P11SCOPE_G21_POLL_INTERVAL_MS`, unset = production default),
/// through the same scoped override as the pilot. The run declares its
/// cadence up front; any cost claim needs that cadence label.
#[test]
#[ignore = "root-owned BPF lane; real3-round gate-cadence probe, bounded90s"]
fn privileged_native_lane_pid_diagnostics_three_round_gate_cadence_probe_lp64() -> Result<()> {
    with_gate_poll_interval(privileged_native_lane_pid_diagnostics_three_round_startup_probe_lp64)?
}

/// Default-cadence cost/control lane (honest S split): the same probe pinned
/// to the production cadence however the gate variable is set. Accelerated
/// legs may qualify wrap; default CLI cost is measured here.
#[test]
#[ignore = "root-owned BPF lane; real3-round default-cadence control, bounded90s"]
fn privileged_native_lane_pid_diagnostics_three_round_default_cadence_control_lp64() -> Result<()> {
    with_gate_poll_interval_value(
        None,
        privileged_native_lane_pid_diagnostics_three_round_startup_probe_lp64,
    )?
}

/// Twin helper: a caller-bound startup-fence gap `(1, 2]` with `repeats`.
fn twin_startup_gap(caller: &str, repeats: u64) -> GapEvidence {
    GapEvidence {
        caller: Some(caller.to_owned()),
        module: None,
        subject: "rejected demoted count".to_owned(),
        reason: "the current physical owner is not proven for absolute count range (1, 2] (1 unattributed calls); historical counts remain and no witness or module-level use is recorded".to_owned(),
        repeats,
    }
}

/// Twin helper: all 32 A edges reading `count`.
fn twin_edge_counts(count: u64) -> Vec<u64> {
    vec![count; TARGETS as usize]
}

#[test]
fn operator_diagnostics_wrap_twin_startup_ordinary_pass() -> Result<()> {
    ensure!(retirement_range("absolute count range (1, 2] (1 unattributed calls)") == Some((1, 2)));
    ensure!(
        retirement_range("absolute count range (658, 659] (1 unattributed calls)")
            == Some((658, 659))
    );
    ensure!(retirement_range("no range here") == None);
    ensure!(retirement_range("absolute count range (2, 1] (0 unattributed calls)") == None);
    let gaps: Vec<GapEvidence> = Vec::new();
    ensure!(startup_fence_repeats(&gaps, "c0") == 0);
    // Pinned per-edge trajectory (Sol): every ordinary A edge reads 1, 2, 3
    // after rounds 1-3 and 400 after round 400 — never 32 per round.
    ensure!(expected_a(1, 0) == 1 && expected_a(2, 0) == 2 && expected_a(3, 0) == 3);
    ensure!(expected_a(400, 0) == 400);
    ensure!(check_startup_round(1, &twin_edge_counts(1), &gaps, "c0", None)? == 0);
    ensure!(check_startup_round(2, &twin_edge_counts(2), &gaps, "c0", Some(0))? == 0);
    ensure!(check_startup_round(3, &twin_edge_counts(3), &gaps, "c0", Some(0))? == 0);
    ensure!(check_startup_round(400, &twin_edge_counts(400), &gaps, "c0", Some(0))? == 0);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_fenced_pass() -> Result<()> {
    // Fenced path (Sol pinned trajectory): exact (1, 2] gap bound to this
    // caller on all 32 pairs; every A edge reads 1, 1, 2 after rounds 1-3
    // and 399 after round 400, alongside the ordinary twin's 1, 2, 3/400.
    let gaps = vec![twin_startup_gap("c0", 32)];
    ensure!(startup_fence_repeats(&gaps, "c0") == 32);
    ensure!(expected_a(2, 32) == 1 && expected_a(3, 32) == 2);
    ensure!(expected_a(400, 32) == 399);
    let no_gap: Vec<GapEvidence> = Vec::new();
    ensure!(check_startup_round(1, &twin_edge_counts(1), &no_gap, "c0", None)? == 0);
    ensure!(check_startup_round(2, &twin_edge_counts(1), &gaps, "c0", Some(0))? == 32);
    ensure!(check_startup_round(3, &twin_edge_counts(2), &gaps, "c0", Some(32))? == 32);
    ensure!(check_startup_round(4, &twin_edge_counts(3), &gaps, "c0", Some(32))? == 32);
    ensure!(check_startup_round(400, &twin_edge_counts(399), &gaps, "c0", Some(32))? == 32);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_underdelivery_fail() -> Result<()> {
    // Valid startup gap but wrong round-3 edges (1 or 3 instead of the
    // pinned 2) must FAIL; so must any other deficit or surplus, and the
    // old summed values (64/96/12768/12800) must FAIL as over-delivery.
    let gaps = vec![twin_startup_gap("c0", 32)];
    let empty: Vec<GapEvidence> = Vec::new();
    for (round, count, gaps, prior) in [
        (3, 1, &gaps, Some(32)),
        (3, 3, &gaps, Some(32)),
        (3, 2, &empty, Some(0)),
        (3, 4, &empty, Some(0)),
        (3, 64, &gaps, Some(32)),
        (3, 96, &empty, Some(0)),
        (2, 0, &gaps, Some(0)),
        (2, 2, &gaps, Some(0)),
        (400, 398, &gaps, Some(32)),
        (400, 400, &gaps, Some(32)),
        (400, 399, &empty, Some(0)),
        (400, 12768, &gaps, Some(32)),
        (400, 12800, &empty, Some(0)),
    ] {
        ensure!(
            check_startup_round(round, &twin_edge_counts(count), gaps, "c0", prior).is_err(),
            "wrong round-{round} edge accepted: {count}"
        );
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_mixed_edges_fail() -> Result<()> {
    // Mixed milestones wait out in the driver, so anything non-unanimous
    // here is a genuine divergence and must FAIL — as must a short vector.
    let gaps: Vec<GapEvidence> = Vec::new();
    let mut mixed = twin_edge_counts(2);
    mixed[7] = 1;
    ensure!(check_startup_round(2, &mixed, &gaps, "c0", Some(0)).is_err());
    ensure!(check_startup_round(2, &twin_edge_counts(2)[..31], &gaps, "c0", Some(0)).is_err());
    ensure!(check_startup_round(2, &[], &gaps, "c0", Some(0)).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_missing_gap_fail() -> Result<()> {
    // A short round-2 count with no gap evidence must FAIL (never inferred).
    let gaps: Vec<GapEvidence> = Vec::new();
    ensure!(startup_fence_repeats(&gaps, "c0") == 0);
    ensure!(check_startup_round(2, &twin_edge_counts(1), &gaps, "c0", Some(0)).is_err());
    ensure!(check_startup_round(2, &twin_edge_counts(2), &gaps, "c0", Some(0))? == 0);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_misbound_gap_fail() -> Result<()> {
    // A (1, 2] gap bound to another caller, or to no caller, is not this
    // caller's fence evidence and must FAIL alongside the short count.
    let foreign = vec![twin_startup_gap("c9", 32)];
    ensure!(startup_fence_repeats(&foreign, "c0") == 0);
    ensure!(check_startup_round(2, &twin_edge_counts(1), &foreign, "c0", Some(0)).is_err());
    let mut unbound = twin_startup_gap("c0", 32);
    unbound.caller = None;
    ensure!(startup_fence_repeats(&[unbound], "c0") == 0);
    ensure!(
        check_startup_round(
            2,
            &twin_edge_counts(1),
            &[twin_startup_gap("c9", 32)],
            "c0",
            Some(0)
        )
        .is_err()
    );
    // A gap with the wrong subject is not fence evidence either.
    let mut wrong_subject = twin_startup_gap("c0", 32);
    wrong_subject.subject = "native witness without mapping evidence".to_owned();
    ensure!(startup_fence_repeats(&[wrong_subject], "c0") == 0);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_wrong_range_fail() -> Result<()> {
    // Only the exact (1, 2] startup range counts; other ranges and partial
    // repeats must FAIL.
    let mut wrong_range = twin_startup_gap("c0", 32);
    wrong_range.reason = wrong_range.reason.replace("(1, 2]", "(0, 2]");
    ensure!(startup_fence_repeats(&[wrong_range.clone()], "c0") == 0);
    ensure!(check_startup_round(2, &twin_edge_counts(1), &[wrong_range], "c0", Some(0)).is_err());
    let partial = vec![twin_startup_gap("c0", 16)];
    ensure!(check_startup_round(2, &twin_edge_counts(1), &partial, "c0", Some(0)).is_err());
    ensure!(check_startup_round(2, &twin_edge_counts(2), &partial, "c0", Some(0)).is_err());
    // Unstable fence count between rounds must FAIL.
    let full = vec![twin_startup_gap("c0", 32)];
    ensure!(check_startup_round(3, &twin_edge_counts(2), &full, "c0", Some(0)).is_err());
    ensure!(check_startup_round(3, &twin_edge_counts(3), &full, "c0", Some(32)).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_startup_gate_accepts_full_fence_immediately() -> Result<()> {
    // A lower bound of 32 over 32 pairs is exact: first sight validates.
    let gaps = vec![twin_startup_gap("c0", 32)];
    let mut gate = StartupGate::new();
    ensure!(matches!(
        gate.poll_round2(&twin_edge_counts(1), &gaps, "c0"),
        StartupGateAction::Validate
    ));
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_startup_gate_waits_out_partial_climb() -> Result<()> {
    // Live wave12 probe-0 climb 1 -> 8 -> 21 -> 32: waits, then validates.
    let mut gate = StartupGate::new();
    for repeats in [1, 8, 21] {
        let gaps = vec![twin_startup_gap("c0", repeats)];
        ensure!(matches!(
            gate.poll_round2(&twin_edge_counts(1), &gaps, "c0"),
            StartupGateAction::Wait
        ));
    }
    let gaps = vec![twin_startup_gap("c0", 32)];
    ensure!(matches!(
        gate.poll_round2(&twin_edge_counts(1), &gaps, "c0"),
        StartupGateAction::Validate
    ));
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_startup_gate_requires_stable_ordinary() -> Result<()> {
    // k == 0 validates only on the second consecutive unanimous ordinary
    // trigger; pre-observation (all A == 1), mixed mid-pass batches and
    // first-sight ordinary all wait.
    let gaps: Vec<GapEvidence> = Vec::new();
    let mut gate = StartupGate::new();
    ensure!(matches!(
        gate.poll_round2(&twin_edge_counts(1), &gaps, "c0"),
        StartupGateAction::Wait
    ));
    let mut mixed = twin_edge_counts(2);
    mixed[7] = 1;
    ensure!(matches!(
        gate.poll_round2(&mixed, &gaps, "c0"),
        StartupGateAction::Wait
    ));
    ensure!(matches!(
        gate.poll_round2(&twin_edge_counts(2), &gaps, "c0"),
        StartupGateAction::Wait
    ));
    ensure!(matches!(
        gate.poll_round2(&twin_edge_counts(2), &gaps, "c0"),
        StartupGateAction::Validate
    ));
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_startup_gate_fails_stalled_partial_loud() -> Result<()> {
    // A partial k frozen for FENCE_STALL_CAP triggers is a genuine partial
    // fence and fails loudly with its trajectory; flapping never trips it.
    let gaps = vec![twin_startup_gap("c0", 16)];
    let mut gate = StartupGate::new();
    for _ in 0..FENCE_STALL_CAP - 1 {
        ensure!(matches!(
            gate.poll_round2(&twin_edge_counts(1), &gaps, "c0"),
            StartupGateAction::Wait
        ));
    }
    match gate.poll_round2(&twin_edge_counts(1), &gaps, "c0") {
        StartupGateAction::Stalled { k, trajectory } => {
            ensure!(k == 16);
            ensure!(trajectory.len() == FENCE_STALL_CAP as usize);
            ensure!(trajectory.iter().all(|seen| *seen == 16));
        }
        _ => bail!("a stalled partial fence must fail loudly"),
    }
    let mut flap = StartupGate::new();
    for repeats in [16, 17, 16, 17, 16, 17, 16, 17, 16] {
        let gaps = vec![twin_startup_gap("c0", repeats)];
        ensure!(matches!(
            flap.poll_round2(&twin_edge_counts(1), &gaps, "c0"),
            StartupGateAction::Wait
        ));
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_startup_gate_rejects_overadvanced_ordinary() -> Result<()> {
    // Past round 2 with no fence is impossible (rounds are driver-issued),
    // on one edge or all of them.
    let gaps: Vec<GapEvidence> = Vec::new();
    let mut gate = StartupGate::new();
    ensure!(matches!(
        gate.poll_round2(&twin_edge_counts(3), &gaps, "c0"),
        StartupGateAction::Overadvanced { a: 3 }
    ));
    let mut mixed = twin_edge_counts(2);
    mixed[7] = 3;
    ensure!(matches!(
        gate.poll_round2(&mixed, &gaps, "c0"),
        StartupGateAction::Overadvanced { a: 3 }
    ));
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_shared_edge_publication_partitioning() -> Result<()> {
    // Sol round-3 retained behavior: the shared-edge publication recurrence,
    // pinned deterministically on the real registry without live capture.
    // One edge, observations supplied directly: initial edge 1; publish one
    // recovered (2,3] segment -> 2; then publish another pair's (2,4]
    // alongside (3,4] -> union width 2 over base 2 -> 4. The (2,3] portion
    // was already held, so the stale-base union re-adds held growth: the
    // live 2->4 jump against the pinned 3. An unchanged reread (zero
    // growth) adds nothing, while restaged demoted segments re-add across
    // publications (the merge is publication-local): the same two segments
    // again -> 6. The indexed live gate avoids this recurrence by giving
    // each pair its own edge; this test pins the recurrence itself so a
    // shared-edge premise can never silently return.
    use crate::discovery::caller_registry::{
        AdmissionState, CallerId, CallerRegistry, ModuleInfo, ModuleKey, RegistryLimits,
    };
    let mut registry = CallerRegistry::new(RegistryLimits::default_limits());
    let key = ModuleKey::physical(8, 1, 11, Some("sha0011".into()), "/lib/a.so");
    registry.note_mapping(
        CallerId(0),
        50,
        ModuleInfo {
            path: "/lib/a.so".into(),
            key: key.clone(),
            double_loaded: false,
            build_id: None,
            identity_source: Some("mountinfo".into()),
            admission: AdmissionState::Admitted,
            admission_class: Some("exact".into()),
            admission_endpoints: Some(3),
            admission_reasons: Vec::new(),
        },
        100,
    );
    registry.publish();
    let edge_count = |registry: &CallerRegistry| {
        let id = registry.module_id_for(&key).expect("module retained");
        registry
            .edge(CallerId(0), id)
            .expect("edge retained")
            .entry_count
    };
    registry.note_counted_use(CallerId(0), &key, 1, 100, 200, 0);
    registry.publish();
    ensure!(edge_count(&registry) == 1);
    registry.note_counted_use(CallerId(0), &key, 1, 300, 400, 2);
    registry.publish();
    ensure!(edge_count(&registry) == 2);
    registry.note_counted_use(CallerId(0), &key, 2, 500, 600, 2);
    registry.note_counted_use(CallerId(0), &key, 1, 510, 610, 3);
    registry.publish();
    ensure!(edge_count(&registry) == 4);
    registry.note_counted_use(CallerId(0), &key, 0, 700, 800, 4);
    registry.publish();
    ensure!(edge_count(&registry) == 4);
    registry.note_counted_use(CallerId(0), &key, 2, 900, 910, 2);
    registry.note_counted_use(CallerId(0), &key, 1, 920, 930, 3);
    registry.publish();
    ensure!(edge_count(&registry) == 6);
    Ok(())
}

/// Twin helper: terminal proof/fence records for 32 distinct pairs under
/// an explicit schedule, with the full retained boundary premise: caller
/// identity, fence absolute, per-edge edge_total, retained observation
/// refs and a strictly later recovery window (fence POST 7010 < proof
/// PRE 7020). Fence/proof shapes are `(counted + shared, counted + shared
/// + 1]`/`(counted + shared + 1, counted + shared + 2]`.
fn twin_terminal_records_as(counted: u64, shared: u64) -> Vec<serde_json::Value> {
    let mut records = Vec::new();
    for index in 0..32 {
        records.push(
            serde_json::json!({"kind":"count_decision","decision":"withheld",
            "pair":format!("p{index}"),"reason":"awaiting_fence",
            "after":counted+shared,"through":counted+shared+1,"absolute":counted+shared+1,
            "caller":"c0","pre":7000,"post":7010,
            "observation_ref":{"seq":1000+index,"status":"retained"}}),
        );
        records.push(serde_json::json!({"kind":"publication","decision":"placed",
            "module_id":format!("mB-{index:02}"),"pair":format!("p{index}"),
            "base":counted+shared+1,"absolute":counted+shared+2,"staged":1,"edge_total":1,
            "caller":"c0","pre":7020,"post":7030,
            "baseline_pre":7000,"baseline_post":7010,
            "observation_ref":{"seq":2000+index,"status":"retained"}}));
    }
    records
}

/// Twin helper: terminal proof/fence records under the full schedule
/// (fence 659, proof 660, staged 1 per pair).
fn twin_terminal_records() -> Vec<serde_json::Value> {
    twin_terminal_records_as(COUNTED, SHARED)
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_32pair_pass() -> Result<()> {
    // Unit correction (Sol correction 2): 32 genuinely distinct pairs with
    // per-pair fence/proof 659/660/1; aggregates recover Sol's 21,088/21,120
    // fence/proof absolutes with staged growth 32.
    let records = twin_terminal_records();
    let (fence_sum, proof_sum, staged_sum) = check_terminal_pairs(&records, &twin_b_modules())?;
    ensure!(fence_sum == 21088 && proof_sum == 21120 && staged_sum == 32);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_single_pair_rejected() -> Result<()> {
    // A single pair carrying Sol's single-fixture absolutes (21,088/21,120,
    // staged 32) cannot wrap the default rings: 32 distinct pairs required.
    let single = vec![
        serde_json::json!({"kind":"count_decision","decision":"withheld",
            "pair":"p0","reason":"awaiting_fence","after":21088,"through":21120}),
        serde_json::json!({"kind":"publication","decision":"placed",
            "module_id":"mB","pair":"p0","base":21088,"absolute":21120,"staged":32}),
    ];
    ensure!(check_terminal_pairs(&single, &twin_b_modules()).is_err());
    // 31 pairs are not 32.
    let mut short = twin_terminal_records();
    short.truncate(62);
    ensure!(check_terminal_pairs(&short, &twin_b_modules()).is_err());
    // Duplicated pair identity is not distinctness.
    let mut dup = twin_terminal_records();
    dup[62]["pair"] = serde_json::json!("p0");
    dup[63]["pair"] = serde_json::json!("p0");
    ensure!(check_terminal_pairs(&dup, &twin_b_modules()).is_err());
    // Wrong per-pair values rejected.
    let mut wrong = twin_terminal_records();
    wrong[1]["staged"] = serde_json::json!(2);
    ensure!(check_terminal_pairs(&wrong, &twin_b_modules()).is_err());
    let mut wrong_base = twin_terminal_records();
    wrong_base[1]["base"] = serde_json::json!(658);
    ensure!(check_terminal_pairs(&wrong_base, &twin_b_modules()).is_err());
    // Wrong module set rejected: proofs on mB-* never match an mA-* set.
    let other_module = twin_terminal_records();
    let wrong_set: BTreeSet<String> = (0..32).map(|index| format!("mA-{index:02}")).collect();
    ensure!(check_terminal_pairs(&other_module, &wrong_set).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_requires_distinct_b_modules() -> Result<()> {
    // Two pairs sharing one B module is the old collapsed topology and must
    // FAIL: each B module carries exactly its pair's proof.
    let mut shared = twin_terminal_records();
    shared[3]["module_id"] = serde_json::json!("mB-00");
    ensure!(check_terminal_pairs(&shared, &twin_b_modules()).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_requires_unit_projection() -> Result<()> {
    // Each B edge carries exactly its pair's proof, so every proof must
    // project edge_total == 1 on its own edge (partition-independent: no
    // batching premise). A wrong projection (edge_total 2) or a missing
    // one must FAIL.
    let mut split = twin_terminal_records();
    for row in split.iter_mut().skip(1).step_by(2) {
        row["edge_total"] = serde_json::json!(2);
    }
    // skip(1).step_by(2) hits odd indices (proofs): verify the premise.
    ensure!(split[1]["edge_total"] == 2 && split[3]["edge_total"] == 2);
    ensure!(split[0].get("edge_total").is_none());
    ensure!(check_terminal_pairs(&split, &twin_b_modules()).is_err());
    let mut missing = twin_terminal_records();
    for row in missing.iter_mut().skip(1).step_by(2) {
        row.as_object_mut().unwrap().remove("edge_total");
    }
    ensure!(missing[1].get("edge_total").is_none());
    ensure!(check_terminal_pairs(&missing, &twin_b_modules()).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_requires_retained_refs() -> Result<()> {
    // Retained boundary observations must back every fence and proof: a
    // lost or missing observation ref must FAIL, never pass silently.
    let mut lost_proof = twin_terminal_records();
    lost_proof[1]["observation_ref"]["status"] = serde_json::json!("not_retained");
    ensure!(check_terminal_pairs(&lost_proof, &twin_b_modules()).is_err());
    let mut lost_fence = twin_terminal_records();
    lost_fence[0]["observation_ref"]["status"] = serde_json::json!("not_retained");
    ensure!(check_terminal_pairs(&lost_fence, &twin_b_modules()).is_err());
    let mut missing = twin_terminal_records();
    missing[1]
        .as_object_mut()
        .unwrap()
        .remove("observation_ref");
    ensure!(check_terminal_pairs(&missing, &twin_b_modules()).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_requires_later_recovery() -> Result<()> {
    // Recovery needs a strictly later advancing read: the proof window
    // must open after the fence window closes (baseline_post < pre).
    let mut simultaneous = twin_terminal_records();
    simultaneous[1]["baseline_post"] = serde_json::json!(7020);
    ensure!(check_terminal_pairs(&simultaneous, &twin_b_modules()).is_err());
    let mut backwards = twin_terminal_records();
    backwards[1]["baseline_post"] = serde_json::json!(7035);
    ensure!(check_terminal_pairs(&backwards, &twin_b_modules()).is_err());
    let mut missing = twin_terminal_records();
    missing[1].as_object_mut().unwrap().remove("baseline_post");
    ensure!(check_terminal_pairs(&missing, &twin_b_modules()).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_rejects_overlapping_placement() -> Result<()> {
    // No B placement may overlap a withheld fence interval: a (658,660]
    // double-placement on p0 must FAIL even though the exact proof exists.
    let mut doubled = twin_terminal_records();
    doubled.push(serde_json::json!({"kind":"publication","decision":"placed",
        "module_id":"mB-00","pair":"p0","base":658,"absolute":660,"staged":2,
        "edge_total":2,"caller":"c0","pre":7020,"post":7030,
        "baseline_pre":7000,"baseline_post":7010,
        "observation_ref":{"seq":2000,"status":"retained"}}));
    ensure!(check_terminal_pairs(&doubled, &twin_b_modules()).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_rejects_extra_b_placement() -> Result<()> {
    // B must carry exactly the 32 proofs: any extra placement, even outside
    // the fence interval, must FAIL (early or foreign attribution).
    let mut extra = twin_terminal_records();
    extra.push(serde_json::json!({"kind":"publication","decision":"placed",
        "module_id":"mB-00","pair":"p0","base":660,"absolute":661,"staged":1,
        "edge_total":2,"caller":"c0","pre":7040,"post":7050,
        "baseline_pre":7020,"baseline_post":7030,
        "observation_ref":{"seq":2000,"status":"retained"}}));
    ensure!(check_terminal_pairs(&extra, &twin_b_modules()).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_requires_caller_identity() -> Result<()> {
    // All 32 fences and proofs must share one caller: a foreign proof and
    // a fence with the wrong absolute must FAIL.
    let mut foreign = twin_terminal_records();
    foreign[1]["caller"] = serde_json::json!("c9");
    ensure!(check_terminal_pairs(&foreign, &twin_b_modules()).is_err());
    let mut wrong_absolute = twin_terminal_records();
    wrong_absolute[0]["absolute"] = serde_json::json!(660);
    ensure!(check_terminal_pairs(&wrong_absolute, &twin_b_modules()).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_rejects_compensating_absolutes() -> Result<()> {
    // Per-pair exactness, not aggregate sums: one proof at 659 and another
    // at 661 keeps the 21,120 sum but must FAIL.
    let mut compensating = twin_terminal_records();
    compensating[1]["absolute"] = serde_json::json!(659);
    compensating[3]["absolute"] = serde_json::json!(661);
    ensure!(check_terminal_pairs(&compensating, &twin_b_modules()).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_one_ring_wrap_fails() -> Result<()> {
    // Both default rings must really wrap: an export with ordinary
    // evictions but zero exceptional evictions must FAIL.
    let (mut healthy, _) = diagnostic_validator_fixture();
    let last = healthy.len() - 1;
    healthy[last]["kinds"][1]["evicted"] = serde_json::json!(0);
    healthy[last]["kinds"][1]["produced"] = serde_json::json!(1);
    let bytes = seal_validator_fixture(&mut healthy);
    ensure!(check_wrap_records(&healthy, bytes, &twin_b_modules(), 123).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_probe_double_placed_fence_fails() -> Result<()> {
    // A fenced pair's withheld second unit cannot also be placed: adding a
    // placed (2,1) publication alongside the p0 fence must FAIL.
    let calls = [(90, 110), (130, 150), (170, 190)];
    let modules = twin_probe_modules();
    let mut fenced = startup_probe_validator_fixture(true);
    let obs_seq = fenced
        .iter()
        .find(|row| {
            row["kind"] == "count_observation" && row["pair"] == "p0" && row["absolute"] == 2
        })
        .and_then(|row| row["seq"].as_u64())
        .context("p0 second observation")?;
    let footer = fenced.pop().context("probe footer")?;
    let max_seq = fenced
        .iter()
        .filter_map(|row| row["seq"].as_u64())
        .max()
        .context("max probe seq")?;
    fenced.push(
        serde_json::json!({"kind":"publication","decision":"placed","reason":"sole_owner",
        "pair":"p0","seq":max_seq+1,"module_id":"mA-00","absolute":2,"base":1,
        "staged":1,"observation_ref":{"seq":obs_seq,"status":"retained"},
        "baseline_pre":150,"baseline_post":160}),
    );
    let mut footer = footer;
    footer["records_written"] = serde_json::json!(fenced.len() as u64 - 1);
    // Publication is kinds[3] (count_observation, ownership_transition,
    // count_decision, publication, capture_health).
    let before = footer["kinds"][3]["retained"]
        .as_u64()
        .context("pub retained")?;
    footer["kinds"][3]["retained"] = serde_json::json!(before + 1);
    footer["kinds"][3]["produced"] = serde_json::json!(before + 1);
    fenced.push(footer);
    let terminal = vec![2u64; 32];
    ensure!(check_startup_probe_records(&fenced, &terminal, 123, &modules, &calls, 32).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_three_round_probe_rejects_frozen_third_unit() -> Result<()> {
    // Frozen third units alongside full recovery and an exact fence count
    // must fail stop-completeness even when every other assertion passes.
    let calls = [(90, 110), (130, 150), (170, 190)];
    let modules = twin_probe_modules();
    let mut rows = startup_probe_validator_fixture(true);
    let footer = rows.pop().context("probe footer")?;
    rows.push(
        serde_json::json!({"kind":"count_decision","decision":"withheld",
        "pair":"p0","seq":1000,"reason":"capture_stopped","after":2,
        "through":3,"absolute":3,
        "observation_ref":{"seq":130,"status":"retained"}}),
    );
    let mut footer = footer;
    footer["records_written"] = serde_json::json!(rows.len() as u64);
    let before = footer["kinds"][2]["retained"]
        .as_u64()
        .context("decision retained")?;
    footer["kinds"][2]["retained"] = serde_json::json!(before + 1);
    footer["kinds"][2]["produced"] = serde_json::json!(before + 1);
    rows.push(footer);
    let terminal = vec![2u64; 32];
    ensure!(check_startup_probe_records(&rows, &terminal, 123, &modules, &calls, 32).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_primary_facts_rejects_wrong_b() -> Result<()> {
    // Each B edge is exactly 1 (its own pair's proof): 0, 2 and the old
    // summed 32 must FAIL under both dispositions, on any B edge.
    for k in [0, 32] {
        for wrong in [0, 2, 32] {
            for edge in [32, 63] {
                let mut altered = primary_validator_fixture_k(123, 0, k);
                altered["edges"][edge]["entries"]["count"] = serde_json::json!(wrong);
                ensure!(
                    primary_facts_k(&altered, 123, k).is_err(),
                    "wrong B accepted: k={k} B={wrong} edge={edge}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_paired_parity_matched_pass() -> Result<()> {
    // Identical owned primary facts under the same validated disposition
    // pass, including across runs (identities and times normalize inside
    // primary_facts, never by count replacement here).
    for k in [0, 32] {
        let leg = primary_facts_k(&primary_validator_fixture_k(123, 0, k), 123, k)?;
        check_paired_parity(&leg, k, &leg.clone(), k)?;
    }
    let off = primary_facts_k(&primary_validator_fixture_k(123, 0, 0), 123, 0)?;
    let on = primary_facts_k(&primary_validator_fixture_k(456, 500, 0), 456, 0)?;
    check_paired_parity(&off, 0, &on, 0)?;
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_paired_parity_disposition_mismatch_fail() -> Result<()> {
    // Different legitimate dispositions each pass their own oracle but do
    // not prove literal count equality: dk != ek must FAIL, never
    // normalize into agreement.
    let ordinary = primary_facts_k(&primary_validator_fixture_k(123, 0, 0), 123, 0)?;
    let fenced = primary_facts_k(&primary_validator_fixture_k(123, 0, 32), 123, 32)?;
    ensure!(check_paired_parity(&ordinary, 0, &fenced, 32).is_err());
    ensure!(check_paired_parity(&fenced, 32, &ordinary, 0).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_paired_parity_altered_primary_fail() -> Result<()> {
    // Altering any owned primary count fails, even where a normalized
    // comparison would still pass; a leg contradicting its own validated
    // disposition fails before comparison.
    let off = primary_facts_k(&primary_validator_fixture_k(123, 0, 0), 123, 0)?;
    for (edge, count) in [
        ("provider-A-00.so", 399),
        ("provider-A-31.so", 401),
        ("provider-B-00.so", 0),
        ("provider-B-31.so", 2),
    ] {
        let mut on = off.clone();
        on["edges"][edge]["count"] = serde_json::json!(count);
        ensure!(
            check_paired_parity(&off, 0, &on, 0).is_err(),
            "altered primary accepted: {edge}={count}"
        );
    }
    let mut bad = off.clone();
    bad["edges"]["provider-A-00.so"]["count"] = serde_json::json!(399);
    ensure!(check_paired_parity(&bad, 0, &off, 0).is_err());
    ensure!(check_paired_parity(&off, 0, &bad, 0).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_schedule_requires_32_objects() -> Result<()> {
    use p11scope_manifest::identity::{UnboundedProbeBudget, kernel_maps_key_for};
    let dir = tempfile::tempdir()?;
    // 32 genuinely distinct objects.
    let mut keys = Vec::new();
    for index in 0..32 {
        let path = dir.path().join(format!("libdemotion-common-{index:02}.so"));
        std::fs::write(&path, vec![index as u8; 64])?;
        let file = std::fs::File::open(&path)?;
        keys.push(kernel_maps_key_for(&file, &mut UnboundedProbeBudget).context("twin file key")?);
    }
    let rows: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            serde_json::json!({
                "slot": 4 + index as u64,
                "dev_major": key.device.major, "dev_minor": key.device.minor,
                "ino": key.inode, "offset": index as u64,
            })
        })
        .collect();
    let refs: Vec<_> = rows.iter().collect();
    let validated = native_target_files(&refs, dir.path())?;
    ensure!(validated.len() == 32);
    ensure!(
        validated.iter().collect::<BTreeSet<_>>().len() == 32,
        "per-slot file keys must be pairwise distinct"
    );
    // 32 offsets within ONE file are one pair, never 32: rejected.
    let single_rows: Vec<_> = (0..32)
        .map(|offset| {
            serde_json::json!({
                "slot": 4 + offset,
                "dev_major": keys[0].device.major, "dev_minor": keys[0].device.minor,
                "ino": keys[0].inode, "offset": offset,
            })
        })
        .collect();
    let single_refs: Vec<_> = single_rows.iter().collect();
    ensure!(native_target_files(&single_refs, dir.path()).is_err());
    // Slot/file mismatch rejected (slot 4 in file 01).
    let mut swapped = rows.clone();
    swapped[0] = serde_json::json!({
        "slot": 4,
        "dev_major": keys[1].device.major, "dev_minor": keys[1].device.minor,
        "ino": keys[1].inode, "offset": 0,
    });
    let swapped_refs: Vec<_> = swapped.iter().collect();
    ensure!(native_target_files(&swapped_refs, dir.path()).is_err());
    // Out-of-range offset rejected.
    let mut long = rows.clone();
    long[0]["offset"] = 64.into();
    let long_refs: Vec<_> = long.iter().collect();
    ensure!(native_target_files(&long_refs, dir.path()).is_err());
    Ok(())
}

/// Twin helper: a module-bound ambiguity gap with `repeats`.
fn twin_ambiguity_gap(module: &str, repeats: u64) -> GapEvidence {
    GapEvidence {
        caller: None,
        module: Some(module.to_owned()),
        subject: "rejected demoted count".to_owned(),
        reason: "a native witness endpoint is shared by 2 admitted modules (re-resolved with 1 unattributed calls after sharing appeared): which module was used is ambiguous, so no edge and no module-level use is recorded".to_owned(),
        repeats,
    }
}

#[test]
fn operator_diagnostics_wrap_twin_shared_checkpoint() -> Result<()> {
    let modules_a: Vec<String> = (0..32).map(|index| format!("mA-{index:02}")).collect();
    let modules_b: Vec<String> = (0..32).map(|index| format!("mB-{index:02}")).collect();
    let gaps_at = |repeats: u64| -> Vec<GapEvidence> {
        modules_a
            .iter()
            .chain(modules_b.iter())
            .map(|module| twin_ambiguity_gap(module, repeats))
            .collect()
    };
    ensure!(ambiguity_repeats(&gaps_at(4), "mA-00") == 4);
    ensure!(ambiguity_repeats(&gaps_at(4), "mB-31") == 4);
    ensure!(ambiguity_repeats(&gaps_at(4), "mX") == 0);
    // Power-of-two rounds gate every sharer module exactly at the round.
    check_shared_checkpoint(4, &gaps_at(4), &modules_a, &modules_b)?;
    check_shared_checkpoint(1, &gaps_at(1), &modules_a, &modules_b)?;
    // Short repeats fail at checkpoints.
    ensure!(check_shared_checkpoint(4, &gaps_at(2), &modules_a, &modules_b).is_err());
    // One asymmetric module fails.
    let mut asymmetric = gaps_at(4);
    asymmetric[7].repeats = 2;
    ensure!(check_shared_checkpoint(4, &asymmetric, &modules_a, &modules_b).is_err());
    // One missing module fails.
    let mut missing = gaps_at(4);
    missing.remove(40);
    ensure!(check_shared_checkpoint(4, &missing, &modules_a, &modules_b).is_err());
    // Non-power rounds pass through (mid-run lower bounds cannot gate).
    check_shared_checkpoint(3, &gaps_at(0), &modules_a, &modules_b)?;
    check_shared_checkpoint(258, &gaps_at(4), &modules_a, &modules_b)?;
    // Short module lists fail before any checkpoint read.
    ensure!(check_shared_checkpoint(4, &gaps_at(4), &modules_a[..31], &modules_b).is_err());
    Ok(())
}

/// Replay a complete event stream's gap events to exact final repeats:
/// each `gap_recorded` opens an identity (index order), each `gap_repeated`
/// sets its exact count. The pre-`ended` flush makes the last value exact.
fn replay_gap_repeats(rows: &[serde_json::Value]) -> Vec<GapEvidence> {
    let mut evidence = Vec::new();
    for row in rows {
        let event = &row["event"];
        if row["kind"] == "gap_recorded" {
            let (Some(subject), Some(reason)) =
                (event["subject"].as_str(), event["reason"].as_str())
            else {
                continue;
            };
            evidence.push(GapEvidence {
                caller: event["caller"].as_str().map(str::to_owned),
                module: event["module"].as_str().map(str::to_owned),
                subject: subject.to_owned(),
                reason: reason.to_owned(),
                repeats: 1,
            });
        } else if row["kind"] == "gap_repeated"
            && let (Some(index), Some(repeats)) =
                (event["index"].as_u64(), event["repeats"].as_u64())
            && let Some(known) = evidence.get_mut(index as usize)
        {
            known.repeats = repeats;
        }
    }
    evidence
}

#[test]
fn operator_diagnostics_wrap_twin_primary_facts_disposition() -> Result<()> {
    // The validated startup disposition carries into final primary facts:
    // every A edge reads exactly the pinned per-edge value (400 ordinary,
    // 399 fenced), every B edge reads exactly 1, and the totals are
    // independently fixed at 12,800-k and 32.
    let ordinary = primary_facts_k(&primary_validator_fixture_k(123, 0, 0), 123, 0)?;
    ensure!(ordinary["edges"]["provider-A-00.so"]["count"] == 400);
    ensure!(ordinary["edges"]["provider-A-31.so"]["count"] == 400);
    ensure!(ordinary["edges"]["provider-B-00.so"]["count"] == 1);
    ensure!(ordinary["edges"]["provider-B-31.so"]["count"] == 1);
    ensure!(facts_side_total(&ordinary, 'A')? == 12800);
    ensure!(facts_side_total(&ordinary, 'B')? == 32);
    let fenced = primary_facts_k(&primary_validator_fixture_k(123, 0, 32), 123, 32)?;
    ensure!(fenced["edges"]["provider-A-00.so"]["count"] == 399);
    ensure!(fenced["edges"]["provider-A-31.so"]["count"] == 399);
    ensure!(fenced["edges"]["provider-B-00.so"]["count"] == 1);
    ensure!(facts_side_total(&fenced, 'A')? == 12768);
    ensure!(facts_side_total(&fenced, 'B')? == 32);
    // Crossed dispositions fail: neither leg may borrow the other's count.
    ensure!(primary_facts_k(&primary_validator_fixture_k(123, 0, 32), 123, 0).is_err());
    ensure!(primary_facts_k(&primary_validator_fixture_k(123, 0, 0), 123, 32).is_err());
    // Loss counters and lossy coverage fail under both dispositions.
    for k in [0, 32] {
        let mut loss = primary_validator_fixture_k(123, 0, k);
        loss["observation"]["lifecycle"]["ring_loss"] = 1.into();
        ensure!(primary_facts_k(&loss, 123, k).is_err());
        let mut lossy = primary_validator_fixture_k(123, 0, k);
        lossy["edges"][32]["entries"]["coverage"]["lossy"] = true.into();
        ensure!(primary_facts_k(&lossy, 123, k).is_err());
        let mut integrity = primary_validator_fixture_k(123, 0, k);
        integrity["observation"]["native_witnesses"]["integrity"] = 1.into();
        ensure!(primary_facts_k(&integrity, 123, k).is_err());
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_passview_gap_evidence() -> Result<()> {
    // PassView must capture full gap payloads (caller/module binding plus
    // stream-tracked repeats), never bare reason strings.
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("events.jsonl");
    let edge_a = serde_json::json!({"seq":0,"kind":"edge_observed","event":{
        "entries":{"count":1},"presence":"mapped","capture":"armed",
        "identity_context":{"caller":{"id":"c0","pid":123},
            "module":{"id":"m1","path":"/owned/provider-A-01.so"}}}});
    let gap = serde_json::json!({"seq":1,"kind":"gap_recorded","event":{
        "index":0,"caller":"c0","module":null,"pid":null,
        "subject":"rejected demoted count",
        "reason":"the current physical owner is not proven for absolute count range (1, 2] (1 unattributed calls); x",
        "budget":null}});
    let repeated =
        serde_json::json!({"seq":2,"kind":"gap_repeated","event":{"index":0,"repeats":32}});
    let committed = serde_json::json!({"seq":3,"kind":"pass_committed","event":{"pass":1}});
    std::fs::write(&path, format!("{edge_a}\n{gap}\n{repeated}\n{committed}\n"))?;
    let mut view = PassView::default();
    ensure!(view.refresh(&path, 123)?);
    ensure!(view.a.contains_key(&1));
    ensure!(view.caller_id.as_deref() == Some("c0"));
    ensure!(view.module_a.get(&1).is_some_and(|id| id == "m1"));
    ensure!(view.a_counts().is_none());
    ensure!(view.modules_a().is_none());
    ensure!(view.evidence.len() == 1);
    let observed = &view.evidence[0];
    ensure!(observed.caller.as_deref() == Some("c0"));
    ensure!(observed.subject == "rejected demoted count");
    ensure!(observed.repeats == 32);
    ensure!(startup_fence_repeats(&view.evidence, "c0") == 32);
    // No new rows: quiet, stable evidence.
    ensure!(!view.refresh(&path, 123)?);
    ensure!(view.evidence.len() == 1 && view.evidence[0].repeats == 32);
    // Out-of-range repeat index is ignored, never a crash.
    // (append after the consumed offset)
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
    writeln!(
        file,
        "{}",
        serde_json::json!({"seq":4,"kind":"gap_repeated","event":{"index":9,"repeats":99}})
    )?;
    writeln!(
        file,
        "{}",
        serde_json::json!({"seq":5,"kind":"pass_committed","event":{"pass":3}})
    )?;
    ensure!(view.refresh(&path, 123)?);
    ensure!(view.evidence.len() == 1 && view.evidence[0].repeats == 32);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_replay_gap_repeats() -> Result<()> {
    let rows = vec![
        serde_json::json!({"kind":"gap_recorded","event":{
            "index":0,"caller":"c0","module":null,"subject":"rejected demoted count",
            "reason":"r0","budget":null}}),
        serde_json::json!({"kind":"gap_recorded","event":{
            "index":1,"caller":null,"module":"m0","subject":"rejected demoted count",
            "reason":"r1","budget":null}}),
        serde_json::json!({"kind":"gap_repeated","event":{"index":0,"repeats":4}}),
        serde_json::json!({"kind":"gap_repeated","event":{"index":1,"repeats":128}}),
        serde_json::json!({"kind":"gap_repeated","event":{"index":0,"repeats":32}}),
        serde_json::json!({"kind":"pass_committed","event":{"pass":1}}),
    ];
    let replayed = replay_gap_repeats(&rows);
    ensure!(replayed.len() == 2);
    ensure!(replayed[0].repeats == 32 && replayed[0].caller.as_deref() == Some("c0"));
    ensure!(replayed[1].repeats == 128 && replayed[1].module.as_deref() == Some("m0"));
    // Non-gap rows are ignored; empty replays to empty.
    ensure!(replay_gap_repeats(&[]).is_empty());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_provider_index_parsing() -> Result<()> {
    // Only exact indexed suffixes identify a wrap edge.
    ensure!(provider_index("/tmp/x/provider-A-00.so", 'A') == Some(0));
    ensure!(provider_index("/tmp/x/provider-A-31.so", 'A') == Some(31));
    ensure!(provider_index("/tmp/x/provider-B-07.so", 'B') == Some(7));
    ensure!(provider_index("provider-B-00.so", 'B') == Some(0));
    ensure!(provider_index("/tmp/x/provider-A-07.so", 'B').is_none());
    ensure!(provider_index("/tmp/x/provider-B-07.so", 'A').is_none());
    ensure!(provider_index("/tmp/x/provider-A.so", 'A').is_none());
    ensure!(provider_index("/tmp/x/provider-A-32.so", 'A').is_none());
    ensure!(provider_index("/tmp/x/provider-A-7.so", 'A') == Some(7));
    ensure!(provider_index("/tmp/x/other.so", 'A').is_none());
    ensure!(provider_index("/tmp/x/provider-A-07.so.1", 'A').is_none());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_wrap_b_modules() -> Result<()> {
    // The export validator's B module set comes from the primary document
    // by indexed suffix, independent of counts.
    let document = primary_validator_fixture_k(123, 0, 0);
    let found = wrap_b_modules(&document, 123)?;
    ensure!(found.len() == 32);
    let expected: BTreeSet<String> = document["modules"]
        .as_array()
        .context("fixture modules")?
        .iter()
        .filter(|module| {
            module["paths"][0]
                .as_str()
                .is_some_and(|path| path.contains("provider-B-"))
        })
        .filter_map(|module| module["id"].as_str().map(str::to_owned))
        .collect();
    ensure!(found == expected);
    // A missing B edge fails, as does a duplicated B index.
    let mut short = document.clone();
    short["modules"][33]["paths"] = serde_json::json!(["/owned/other.so"]);
    ensure!(wrap_b_modules(&short, 123).is_err());
    let mut dup = document.clone();
    dup["modules"][34]["paths"] = serde_json::json!(["/owned/provider-B-01.so"]);
    ensure!(wrap_b_modules(&dup, 123).is_err());
    Ok(())
}

/// Twin helper: one exact final gap stream — startup k, one caller-bound
/// identity repeated32 for each issued shared unit, and32 terminal fences.
fn twin_final_gap_rows(startup: u64, fence: u64) -> Vec<serde_json::Value> {
    let mut rows = vec![
        serde_json::json!({"kind":"gap_recorded","event":{
            "caller":"c0","module":null,"subject":"rejected demoted count",
            "reason":"the current physical owner is not proven for absolute count range (1, 2] (1 unattributed calls); x"}}),
        serde_json::json!({"kind":"gap_repeated","event":{"index":0,"repeats":startup}}),
    ];
    let mut index = 1u64;
    for absolute in COUNTED + 1..=COUNTED + SHARED {
        rows.push(serde_json::json!({"kind":"gap_recorded","event":{
            "caller":"c0","module":null,"subject":"rejected demoted count",
            "reason":format!("the current physical owner is not proven for absolute count range ({}, {absolute}] (1 unattributed calls); x",absolute-1)}}));
        rows.push(
            serde_json::json!({"kind":"gap_repeated","event":{"index":index,"repeats":TARGETS}}),
        );
        index += 1;
    }
    rows.push(serde_json::json!({"kind":"gap_recorded","event":{
        "caller":"c0","module":null,"subject":"rejected demoted count",
        "reason":"the current physical owner is not proven for absolute count range (658, 659] (1 unattributed calls); x"}}));
    rows.push(serde_json::json!({"kind":"gap_repeated","event":{"index":index,"repeats":fence}}));
    rows
}

#[test]
fn operator_diagnostics_wrap_twin_verify_final_gaps() -> Result<()> {
    let modules_a: Vec<String> = (0..32).map(|index| format!("mA-{index:02}")).collect();
    let modules_b: Vec<String> = (0..32).map(|index| format!("mB-{index:02}")).collect();
    // The validator takes the live-accumulated evidence (replayed here from
    // fixture rows): rotated segments beyond retention are evicted, so a
    // post-run file replay would be incomplete.
    let exact = |startup: u64, fence: u64| replay_gap_repeats(&twin_final_gap_rows(startup, fence));
    verify_final_gaps(&exact(32, 32), "c0", &modules_a, &modules_b, 32)?;
    verify_final_gaps(&exact(0, 32), "c0", &modules_a, &modules_b, 0)?;
    // Wrong startup, fence, or one shared caller/range multiplicity fails.
    ensure!(verify_final_gaps(&exact(0, 32), "c0", &modules_a, &modules_b, 32).is_err());
    ensure!(verify_final_gaps(&exact(32, 31), "c0", &modules_a, &modules_b, 32).is_err());
    let mut short = twin_final_gap_rows(32, 32);
    short[3]["event"]["repeats"] = serde_json::json!(TARGETS - 1);
    ensure!(
        verify_final_gaps(
            &replay_gap_repeats(&short),
            "c0",
            &modules_a,
            &modules_b,
            32
        )
        .is_err()
    );
    ensure!(verify_final_gaps(&exact(32, 32), "c0", &modules_a[..31], &modules_b, 32).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_final_gap_flush_consumed() -> Result<()> {
    let modules_a: Vec<_> = (0..32).map(|index| format!("mA-{index:02}")).collect();
    let modules_b: Vec<_> = (0..32).map(|index| format!("mB-{index:02}")).collect();
    let dir = tempfile::tempdir()?;
    let events = dir.path().join("events.jsonl");
    let mut rows = twin_final_gap_rows(0, TARGETS);
    rows[3]["event"]["repeats"] = 16.into();
    let mut file = std::fs::File::create(&events)?;
    for (seq, row) in rows.iter_mut().enumerate() {
        row["seq"] = seq.into();
        writeln!(file, "{row}")?;
    }
    let mut view = PassView {
        caller_id: Some("c0".into()),
        module_a: modules_a
            .iter()
            .enumerate()
            .map(|(index, id)| (index as u32, id.clone()))
            .collect(),
        module_b: modules_b
            .iter()
            .enumerate()
            .map(|(index, id)| (index as u32, id.clone()))
            .collect(),
        ..PassView::default()
    };
    view.refresh(&events, 123)?;
    ensure!(verify_final_gaps(&view.evidence, "c0", &modules_a, &modules_b, 0).is_err());
    let seq = rows.len();
    writeln!(
        file,
        "{}",
        serde_json::json!({"seq":seq,"kind":"gap_repeated","event":{"index":1,"repeats":32}})
    )?;
    writeln!(
        file,
        "{}",
        serde_json::json!({"seq":seq+1,"kind":"ended","event":{}})
    )?;
    verify_final_view_gaps(&mut view, &events, 123, 0, COUNTED, SHARED)?;
    ensure!(view.last_seq == Some((seq + 1) as u64));
    // A late excess cannot hide behind the previously qualifying checkpoint.
    writeln!(
        file,
        "{}",
        serde_json::json!({"seq":seq+2,"kind":"gap_repeated","event":{"index":1,"repeats":33}})
    )?;
    ensure!(verify_final_view_gaps(&mut view, &events, 123, 0, COUNTED, SHARED).is_err());
    Ok(())
}

/// Twin helper: a caller-bound range gap `(base, absolute]` with `repeats`.
fn twin_range_gap(caller: &str, base: u64, absolute: u64, repeats: u64) -> GapEvidence {
    GapEvidence {
        caller: Some(caller.to_owned()),
        module: None,
        subject: "rejected demoted count".to_owned(),
        reason: format!(
            "the current physical owner is not proven for absolute count range ({base}, {absolute}] ({} unattributed calls); x",
            absolute - base
        ),
        repeats,
    }
}

#[test]
fn operator_diagnostics_wrap_twin_retirement_shared_ranges() -> Result<()> {
    let modules_a: Vec<String> = (0..32).map(|index| format!("mA-{index:02}")).collect();
    let modules_b: Vec<String> = (0..32).map(|index| format!("mB-{index:02}")).collect();
    for (counted, shared) in [(32, 4), (COUNTED, SHARED)] {
        let exact: Vec<_> = (1..=shared)
            .map(|round| twin_range_gap("c0", counted + round - 1, counted + round, TARGETS))
            .collect();
        // Exercise the current live shared gate first: caller-bound retirement
        // dispositions must qualify without inventing per-sharer module gaps.
        let check = |gaps: &[GapEvidence], completed: u64| {
            check_retirement_shared_checkpoint(gaps, "c0", counted, completed)
        };
        check(&exact[..1], 1)?;
        check(&exact, shared)?;
        for mutation in [
            "missing",
            "duplicate",
            "short",
            "excess",
            "caller",
            "module",
            "range",
            "growth",
            "subject",
        ] {
            let mut changed = exact.clone();
            match mutation {
                "missing" => {
                    changed.remove(0);
                }
                "duplicate" => changed.push(exact[0].clone()),
                "short" => changed[0].repeats = TARGETS - 1,
                "excess" => changed[0].repeats = TARGETS + 1,
                "caller" => changed[0].caller = Some("foreign".into()),
                "module" => changed[0].module = Some(modules_a[0].clone()),
                "range" => changed[0] = twin_range_gap("c0", counted - 1, counted, TARGETS),
                "growth" => {
                    changed[0].reason = changed[0]
                        .reason
                        .replace("1 unattributed", "2 unattributed")
                }
                "subject" => changed[0].subject = "another disclosure".into(),
                _ => unreachable!(),
            }
            ensure!(
                check(&changed, shared).is_err(),
                "accepted retirement mutation {mutation}"
            );
        }
        let mut compensated = exact.clone();
        compensated[0].repeats -= 1;
        compensated.extend(
            modules_a
                .iter()
                .chain(&modules_b)
                .map(|module| twin_ambiguity_gap(module, shared)),
        );
        ensure!(
            check(&compensated, shared).is_err(),
            "module disclosures cannot replace a caller retirement unit"
        );
    }
    Ok(())
}

/// A complete bounded diagnostic input, independent of observed count totals.
/// Each pair has its own initial A placement, four issued shared units and
/// its own final B proof. Native topology/ledger checks remain separate.
fn twin_shared_pair_records() -> Vec<serde_json::Value> {
    twin_shared_pair_records_as(0)
}

fn twin_shared_pair_records_as(k: u64) -> Vec<serde_json::Value> {
    let mut records = Vec::new();
    let mut seq = 1u64;
    for index in 0..32 {
        let pair = format!("p{index}");
        for absolute in 1..=32 {
            records.push(serde_json::json!({"kind":"count_observation","seq":seq,
                "caller":"c0","pair":pair,"absolute":absolute,"pre":1000+10*absolute,"post":1001+10*absolute}));
            let mut decision = serde_json::json!({"kind":"publication","decision":"placed",
                "seq":seq+1,"caller":"c0","pair":pair,"module_id":format!("mA-{index:02}"),
                "base":absolute-1,"absolute":absolute,"staged":1,"edge_total":expected_a(absolute,k),
                "pre":1000+10*absolute,"post":1001+10*absolute,
                "observation_ref":{"seq":seq,"status":"retained"}});
            if k == TARGETS && absolute == 2 {
                decision["kind"] = "count_decision".into();
                decision["decision"] = "withheld".into();
                decision["reason"] = "awaiting_fence".into();
                decision["module_id"] = serde_json::Value::Null;
                decision["after"] = 1.into();
                decision["through"] = 2.into();
            }
            records.push(decision);
            seq += 2;
        }
        for round in 1..=4 {
            let absolute = 32 + round;
            records.push(serde_json::json!({"kind":"count_observation","seq":seq,
                "caller":"c0","pair":pair,"absolute":absolute,"pre":1000+10*absolute,"post":1001+10*absolute}));
            records.push(serde_json::json!({"kind":"count_decision","seq":seq+1,
                "caller":"c0","pair":pair,"decision":"withheld","reason":"shared_owner",
                "after":absolute-1,"through":absolute,"absolute":absolute,
                "pre":1000+10*absolute,"post":1001+10*absolute,
                "observation_ref":{"seq":seq,"status":"retained"}}));
            seq += 2;
        }
        for absolute in [37, 38] {
            records.push(serde_json::json!({"kind":"count_observation","seq":seq,
                "caller":"c0","pair":pair,"absolute":absolute,"pre":1000+10*absolute,"post":1001+10*absolute}));
            let mut row = serde_json::json!({"seq":seq+1,"caller":"c0","pair":pair,
                "absolute":absolute,"pre":1000+10*absolute,"post":1001+10*absolute,
                "observation_ref":{"seq":seq,"status":"retained"}});
            if absolute == 37 {
                row["kind"] = "count_decision".into();
                row["decision"] = "withheld".into();
                row["reason"] = "awaiting_fence".into();
                row["after"] = 36.into();
                row["through"] = 37.into();
            } else {
                row["kind"] = "publication".into();
                row["decision"] = "placed".into();
                row["module_id"] = format!("mB-{index:02}").into();
                row["base"] = 37.into();
                row["staged"] = 1.into();
                row["edge_total"] = 1.into();
                row["baseline_pre"] = 1370.into();
                row["baseline_post"] = 1371.into();
            }
            records.push(row);
            seq += 2;
        }
    }
    records
}

#[test]
fn operator_diagnostics_wrap_twin_shared_pairs_no_compensation() -> Result<()> {
    let exact = twin_shared_pair_records();
    let modules_a: Vec<String> = (0..32).map(|index| format!("mA-{index:02}")).collect();
    let modules_b: Vec<String> = (0..32).map(|index| format!("mB-{index:02}")).collect();
    let check = |records: &[serde_json::Value]| {
        check_shared_pair_dispositions(records, "c0", &modules_a, &modules_b, 32, 4, 0)
    };
    check(&exact)?;
    let mut fenced = twin_shared_pair_records_as(TARGETS);
    check_shared_pair_dispositions(&fenced, "c0", &modules_a, &modules_b, 32, 4, TARGETS)?;
    let startup = fenced
        .iter_mut()
        .find(|row| row["reason"] == "awaiting_fence" && row["through"] == 2)
        .unwrap();
    startup["pair"] = "p1".into();
    ensure!(
        check_shared_pair_dispositions(&fenced, "c0", &modules_a, &modules_b, 32, 4, TARGETS)
            .is_err()
    );
    for mutation in [
        "duplicate_pair",
        "missing",
        "overlap",
        "range",
        "caller",
        "observation",
        "reference",
        "placement",
        "module_pair",
        "crossed_b",
        "raw_pair",
        "raw_extra",
        "interval",
        "fence_duplicate",
        "fence_reference",
        "proof_baseline",
        "a_missing",
        "a_compensation",
    ] {
        let mut changed = exact.clone();
        let at = changed
            .iter()
            .position(|row| row["decision"] == "withheld" && row["reason"] == "shared_owner")
            .unwrap();
        match mutation {
            "duplicate_pair" => {
                for row in &mut changed {
                    if row["pair"] == "p0" && row["reason"] == "shared_owner" {
                        row["pair"] = "p1".into();
                    }
                }
            }
            "missing" => {
                changed.remove(at);
            }
            "overlap" => changed.push(changed[at].clone()),
            "range" => {
                changed[at]["after"] = 31.into();
                changed[at]["through"] = 33.into();
            }
            "caller" => changed[at]["caller"] = "foreign".into(),
            "observation" => changed[at]["absolute"] = 34.into(),
            "reference" => changed[at]["observation_ref"]["seq"] = 999_999.into(),
            "placement" => {
                changed[at]["kind"] = "publication".into();
                changed[at]["decision"] = "placed".into();
                changed[at]["module_id"] = "mA-00".into();
            }
            "module_pair" => changed[1]["module_id"] = "mA-01".into(),
            "crossed_b" => {
                for row in &mut changed {
                    if row["kind"] == "publication" && row["module_id"] == "mB-00" {
                        row["module_id"] = "mB-01".into();
                    } else if row["kind"] == "publication" && row["module_id"] == "mB-01" {
                        row["module_id"] = "mB-00".into();
                    }
                }
            }
            "raw_pair" => changed[at - 1]["pair"] = "foreign".into(),
            "raw_extra" => changed.push(
                serde_json::json!({"kind":"count_observation","seq":1_000_000,
                "caller":"c0","pair":"foreign","absolute":33,"pre":1330,"post":1331}),
            ),
            "interval" => changed[at]["pre"] = 1332.into(),
            "fence_duplicate" => {
                let fence = changed
                    .iter()
                    .find(|row| row["reason"] == "awaiting_fence")
                    .unwrap()
                    .clone();
                changed.push(fence);
            }
            "fence_reference" => {
                let fence = changed
                    .iter_mut()
                    .find(|row| row["reason"] == "awaiting_fence")
                    .unwrap();
                fence["observation_ref"]["seq"] = 999_999.into();
            }
            "proof_baseline" => {
                let proof = changed
                    .iter_mut()
                    .find(|row| row["module_id"] == "mB-00")
                    .unwrap();
                proof["baseline_post"] = 1361.into();
            }
            "a_missing" => {
                changed.remove(1);
            }
            "a_compensation" => {
                changed[1]["staged"] = 2.into();
                changed.remove(3);
            }
            _ => unreachable!(),
        }
        ensure!(
            check(&changed).is_err(),
            "accepted compensating shared-pair mutation {mutation}"
        );
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_pilot_complete_export() -> Result<()> {
    let mut exact = vec![
        serde_json::json!({"kind":"header","scope":"pid","mode":"native","pid_filter":123,
        "limits":{"ordinary_records":24576,"exceptional_records":8192,"heap_bytes":8*1024*1024}}),
    ];
    exact.extend(twin_shared_pair_records());
    let names = [
        "count_observation",
        "ownership_transition",
        "count_decision",
        "publication",
        "capture_health",
    ];
    let kinds: Vec<_> = names.iter().map(|name| {
        let count = exact.iter().filter(|row| row["kind"] == *name).count();
        serde_json::json!({"produced":count,"retained":count,"evicted":0,"filtered":0,"omitted":0})
    }).collect();
    exact.push(
        serde_json::json!({"kind":"footer","diagnostics_complete":true,"counter_overflow":false,
        "sequence_exhausted":false,"oversized_records":0,"kinds":kinds}),
    );
    let bytes = seal_validator_fixture(&mut exact);
    check_bounded_pilot_export(&exact, bytes, 123)?;
    for mutation in [
        "seq", "evicted", "filtered", "omitted", "produced", "limits", "bytes", "footer",
    ] {
        let mut changed = exact.clone();
        let last = changed.len() - 1;
        match mutation {
            "seq" => changed[1]["seq"] = 3.into(),
            "evicted" | "filtered" | "omitted" => changed[last]["kinds"][0][mutation] = 1.into(),
            "produced" => changed[last]["kinds"][0]["produced"] = 0.into(),
            "limits" => changed[0]["limits"]["ordinary_records"] = 100.into(),
            "bytes" => changed[last]["bytes_written"] = 1.into(),
            "footer" => changed[last]["diagnostics_complete"] = false.into(),
            _ => unreachable!(),
        }
        ensure!(
            check_bounded_pilot_export(&changed, bytes, 123).is_err(),
            "accepted incomplete pilot export {mutation}"
        );
    }
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("diagnostics.jsonl");
    std::fs::write(
        &path,
        "{\"kind\":\"header\"}\nmalformed\n{\"kind\":\"footer\"}\n",
    )?;
    let (rows, note, complete) = read_pilot_records(&path);
    ensure!(!complete && rows.len() == 2 && note.contains("skipped_lines=1"));
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_pilot_primary_schedule() -> Result<()> {
    for k in [0, TARGETS] {
        let mut document = primary_validator_fixture_k(123, 0, k);
        for edge in document["edges"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .take(TARGETS as usize)
        {
            edge["entries"]["count"] = expected_a(32, k).into();
        }
        let caller = primary_pid_caller(&document, 123)?;
        primary_facts_core_schedule(&document, 123, k, caller, 32)?;
        ensure!(
            primary_facts(&document, 123, k).is_err(),
            "short pilot cannot replace full counts"
        );
        for mutation in ["a", "b", "loss", "retirement"] {
            let mut changed = document.clone();
            match mutation {
                "a" => changed["edges"][0]["entries"]["count"] = (expected_a(32, k) + 1).into(),
                "b" => changed["edges"][32]["entries"]["count"] = 2.into(),
                "loss" => changed["observation"]["lifecycle"]["ring_loss"] = 1.into(),
                "retirement" => changed["observation"]["retirement"] = "open".into(),
                _ => unreachable!(),
            }
            let caller = primary_pid_caller(&changed, 123)?;
            ensure!(
                primary_facts_core_schedule(&changed, 123, k, caller, 32).is_err(),
                "accepted pilot primary mutation {mutation}"
            );
        }
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_schedule_args_pilot() -> Result<()> {
    let args = schedule_args(&PILOT_SCHEDULE)?;
    ensure!(
        args == vec!["0123456789abcdef0123456789abcdef", "590000", "32", "4"],
        "pilot workload arguments drifted: {args:?}"
    );
    let full = WrapSchedule {
        counted: COUNTED,
        shared: SHARED,
        run_seconds: RUN_SECONDS,
        deadline_ms: 900_000,
    };
    let args = schedule_args(&full)?;
    ensure!(
        args[1..] == ["900000", "400", "258"],
        "full workload arguments drifted: {args:?}"
    );
    for schedule in [
        WrapSchedule {
            counted: 0,
            shared: 4,
            run_seconds: 540,
            deadline_ms: 590_000,
        },
        WrapSchedule {
            counted: 401,
            shared: 4,
            run_seconds: 540,
            deadline_ms: 590_000,
        },
        WrapSchedule {
            counted: 32,
            shared: 0,
            run_seconds: 540,
            deadline_ms: 590_000,
        },
        WrapSchedule {
            counted: 32,
            shared: 259,
            run_seconds: 540,
            deadline_ms: 590_000,
        },
        WrapSchedule {
            counted: 32,
            shared: 4,
            run_seconds: 540,
            deadline_ms: 0,
        },
        WrapSchedule {
            counted: 32,
            shared: 4,
            run_seconds: 540,
            deadline_ms: 900_001,
        },
        WrapSchedule {
            counted: 32,
            shared: 4,
            run_seconds: 600,
            deadline_ms: 590_000,
        },
    ] {
        ensure!(
            schedule_args(&schedule).is_err(),
            "out-of-range schedule accepted: {} {} {}",
            schedule.counted,
            schedule.shared,
            schedule.deadline_ms
        );
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_round_schedule() -> Result<()> {
    // Pilot budget (32 counted): rounds 1-3 follow the pinned per-edge
    // trajectory on both paths, round 32 is terminal, round 33 is out of
    // range even with unanimous edges.
    let empty: Vec<GapEvidence> = Vec::new();
    let fenced = vec![twin_startup_gap("c0", 32)];
    ensure!(check_startup_round_as(1, &twin_edge_counts(1), &empty, "c0", None, 32)? == 0);
    ensure!(check_startup_round_as(2, &twin_edge_counts(2), &empty, "c0", Some(0), 32)? == 0);
    ensure!(check_startup_round_as(3, &twin_edge_counts(3), &empty, "c0", Some(0), 32)? == 0);
    ensure!(check_startup_round_as(32, &twin_edge_counts(32), &empty, "c0", Some(0), 32)? == 0);
    ensure!(check_startup_round_as(2, &twin_edge_counts(1), &fenced, "c0", Some(0), 32)? == 32);
    ensure!(check_startup_round_as(32, &twin_edge_counts(31), &fenced, "c0", Some(32), 32)? == 32);
    ensure!(check_startup_round_as(33, &twin_edge_counts(33), &empty, "c0", Some(0), 32).is_err());
    ensure!(check_startup_round_as(0, &twin_edge_counts(0), &empty, "c0", None, 32).is_err());
    ensure!(
        check_startup_round_as(32, &twin_edge_counts(32), &fenced, "c0", Some(32), 32).is_err()
    );
    // The full budget still ends at 400, not 32.
    ensure!(check_startup_round_as(400, &twin_edge_counts(400), &empty, "c0", Some(0), 400)? == 0);
    ensure!(check_startup_round_as(32, &twin_edge_counts(32), &empty, "c0", Some(0), 400)? == 0);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_fence_gap_schedule() -> Result<()> {
    // Pilot fence is (36, 37]; the full fence is (658, 659]. Each
    // schedule sees only its own range.
    let pilot = vec![twin_range_gap("c0", 36, 37, 32)];
    ensure!(fence_gap_repeats_as(&pilot, "c0", 32, 4) == 32);
    ensure!(fence_gap_repeats(&pilot, "c0") == 0);
    let full = vec![twin_range_gap("c0", 658, 659, 32)];
    ensure!(fence_gap_repeats(&full, "c0") == 32);
    ensure!(fence_gap_repeats_as(&full, "c0", 32, 4) == 0);
    // Wrong growth in the reason text is not a range at all.
    let broken = vec![GapEvidence {
        caller: Some("c0".to_owned()),
        module: None,
        subject: "rejected demoted count".to_owned(),
        reason: "absolute count range (36, 37] (2 unattributed calls)".to_owned(),
        repeats: 32,
    }];
    ensure!(fence_gap_repeats_as(&broken, "c0", 32, 4) == 0);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_pairs_schedule() -> Result<()> {
    // Pilot terminal sums: fence 32x37, proof 32x38, staged 32.
    let pilot = twin_terminal_records_as(32, 4);
    ensure!(
        check_terminal_pairs_schedule(&pilot, &twin_b_modules(), None, 32, 4)?
            == (32 * 37, 32 * 38, 32)
    );
    // Full terminal sums are unchanged: 32x659, 32x660, 32.
    let full = twin_terminal_records_as(COUNTED, SHARED);
    ensure!(check_terminal_pairs_as(&full, &twin_b_modules(), None)? == (32 * 659, 32 * 660, 32));
    // Crossed schedules fail both ways: the shapes are budget-pinned.
    ensure!(
        check_terminal_pairs_schedule(&pilot, &twin_b_modules(), None, COUNTED, SHARED).is_err()
    );
    ensure!(check_terminal_pairs_schedule(&full, &twin_b_modules(), None, 32, 4).is_err());
    // A non-unit staged proof fails under its own schedule (records
    // interleave fence/proof per pair, so index 1 is the first proof).
    let mut altered = pilot.clone();
    altered[1]["staged"] = 2.into();
    ensure!(check_terminal_pairs_schedule(&altered, &twin_b_modules(), None, 32, 4).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_verify_final_gaps_schedule() -> Result<()> {
    let modules_a: Vec<String> = (0..32).map(|index| format!("mA-{index:02}")).collect();
    let modules_b: Vec<String> = (0..32).map(|index| format!("mB-{index:02}")).collect();
    let pilot_gaps = |startup: u64| {
        let mut gaps = vec![twin_startup_gap("c0", startup)];
        gaps.extend((1..=4).map(|round| twin_range_gap("c0", 32 + round - 1, 32 + round, TARGETS)));
        gaps.push(twin_range_gap("c0", 36, 37, 32));
        gaps
    };
    verify_final_gaps_as(&pilot_gaps(32), "c0", &modules_a, &modules_b, 32, 32, 4)?;
    verify_final_gaps_as(&pilot_gaps(0), "c0", &modules_a, &modules_b, 0, 32, 4)?;
    // One short shared range, a full-shape fence, or a mismatched k fails.
    let mut short = pilot_gaps(32);
    short[1].repeats = 3;
    ensure!(verify_final_gaps_as(&short, "c0", &modules_a, &modules_b, 32, 32, 4).is_err());
    let mut crossed = pilot_gaps(32);
    crossed.pop();
    crossed.push(twin_range_gap("c0", 658, 659, 32));
    ensure!(verify_final_gaps_as(&crossed, "c0", &modules_a, &modules_b, 32, 32, 4).is_err());
    ensure!(verify_final_gaps_as(&pilot_gaps(0), "c0", &modules_a, &modules_b, 32, 32, 4).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_refresh_follows_rotation() -> Result<()> {
    // A mid-run rotation (live renamed to events.jsonl.1, fresh live with a
    // marker) loses no rows and duplicates none: the merge is by global
    // sequence, so live content re-read from its rotated segment drops out.
    let dir = tempfile::tempdir()?;
    let live = dir.path().join("events.jsonl");
    let edge = |seq: u64, count: u64| {
        format!(
            "{}\n",
            serde_json::json!({"seq":seq,"kind":"edge_observed","event":{
                "identity_context":{"caller":{"pid":7,"id":"c0"},
                    "module":{"path":"/x/provider-A-07.so","id":"m7"}},
                "entries":{"count":count}}})
        )
    };
    let commit = |seq: u64| {
        format!(
            "{}\n",
            serde_json::json!({"seq":seq,"kind":"pass_committed","event":{}})
        )
    };
    std::fs::write(&live, format!("{}{}", edge(0, 1), commit(1)))?;
    let mut view = PassView::default();
    ensure!(view.refresh(&live, 7)?);
    ensure!(view.last_seq == Some(1));
    ensure!(view.commits == 1);
    // Rotate: live content moves to events.jsonl.1; the new live starts
    // with the marker (higher seq, written first) plus fresh rows.
    std::fs::rename(&live, dir.path().join("events.jsonl.1"))?;
    std::fs::write(
        &live,
        format!(
            "{}\n{}{}",
            serde_json::json!({"seq":3,"kind":"rotated","event":{}}),
            edge(2, 2),
            commit(4)
        ),
    )?;
    ensure!(view.refresh(&live, 7)?);
    ensure!(view.last_seq == Some(4));
    ensure!(view.commits == 2);
    ensure!(
        view.a
            .get(&7)
            .and_then(|edge| edge["entries"]["count"].as_u64())
            == Some(2)
    );
    // A second rotation is followed the same way; eviction of the consumed
    // first segment is harmless.
    std::fs::rename(&live, dir.path().join("events.jsonl.2"))?;
    std::fs::remove_file(dir.path().join("events.jsonl.1"))?;
    std::fs::write(&live, format!("{}{}", edge(5, 3), commit(6)))?;
    ensure!(view.refresh(&live, 7)?);
    ensure!(view.last_seq == Some(6));
    ensure!(view.commits == 3);
    ensure!(
        view.a
            .get(&7)
            .and_then(|edge| edge["entries"]["count"].as_u64())
            == Some(3)
    );
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_refresh_rejects_eviction_hole() -> Result<()> {
    // Evidence evicted before reading (a sequence gap) fails loudly instead
    // of validating on a partial stream.
    let dir = tempfile::tempdir()?;
    let live = dir.path().join("events.jsonl");
    std::fs::write(
        &live,
        "{\"seq\":0,\"kind\":\"pass_committed\",\"event\":{}}\n",
    )?;
    let mut view = PassView::default();
    ensure!(view.refresh(&live, 7)?);
    std::fs::write(
        &live,
        "{\"seq\":0,\"kind\":\"pass_committed\",\"event\":{}}\n{\"seq\":5,\"kind\":\"pass_committed\",\"event\":{}}\n",
    )?;
    ensure!(view.refresh(&live, 7).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_refresh_incremental_live_offset() -> Result<()> {
    // Incremental live reads: a quiet tick consumes no new bytes, a partial
    // trailing line waits for its newline, and a replaced live file restarts
    // from byte 0 even when the old offset lands exactly on a line boundary
    // (identity reset, never a silent skip). A re-recorded gap identity with
    // a fresh sequence stays deduplicated, exactly as the linear scan did.
    let dir = tempfile::tempdir()?;
    let live = dir.path().join("events.jsonl");
    let commit = |seq: u64| {
        format!(
            "{}\n",
            serde_json::json!({"seq":seq,"kind":"pass_committed","event":{}})
        )
    };
    let gap = |seq: u64| {
        format!(
            "{}\n",
            serde_json::json!({"seq":seq,"kind":"gap_recorded","event":{
                "index":0,"caller":"c0","module":null,
                "subject":"rejected demoted count","reason":"r"}})
        )
    };
    std::fs::write(&live, format!("{}{}", commit(0), gap(1)))?;
    let mut view = PassView::default();
    ensure!(view.refresh(&live, 7)?);
    ensure!(view.last_seq == Some(1));
    ensure!(view.evidence.len() == 1 && view.evidence_index.len() == 1);
    let len = std::fs::metadata(&live)?.len();
    ensure!(view.live_offset == len);
    // Quiet tick: no new bytes, no movement, stable offset.
    ensure!(!view.refresh(&live, 7)?);
    ensure!(view.live_offset == len && view.last_seq == Some(1));
    // Partial trailing line: deferred, not parsed, offset held.
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(&live)?;
        let full = commit(2);
        file.write_all(&full.as_bytes()[..full.len() - 1])?;
    }
    ensure!(!view.refresh(&live, 7)?);
    ensure!(view.live_offset == len && view.last_seq == Some(1));
    // Completing newline: the row lands exactly once.
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(&live)?;
        file.write_all(b"\n")?;
    }
    ensure!(view.refresh(&live, 7)?);
    ensure!(view.last_seq == Some(2) && view.commits == 2);
    // Replaced live file whose old offset is an exact line boundary: the
    // identity change restarts from 0 instead of skipping the first row.
    // (Rename, not remove+create, so the new live provably has a fresh
    // inode; the rotated segment's rows drop out by sequence.)
    let boundary = view.live_offset;
    let mut pad = String::new();
    let first = loop {
        let row = serde_json::json!({"seq":3,"kind":"pass_committed","event":{"pad":pad}});
        let line = format!("{row}\n");
        if line.len() == boundary as usize {
            break line;
        }
        ensure!(line.len() < boundary as usize, "pad overshoot");
        pad.push('x');
    };
    std::fs::rename(&live, dir.path().join("events.jsonl.9"))?;
    std::fs::write(&live, format!("{first}{}{}", gap(4), commit(5)))?;
    ensure!(view.refresh(&live, 7)?);
    ensure!(view.last_seq == Some(5));
    ensure!(view.commits == 4);
    ensure!(view.evidence.len() == 1 && view.evidence_index.len() == 1);
    Ok(())
}

/// The wrap fixture's 97 prebuilt inputs: 32 distinct common objects plus
/// the 64 indexed providers and the workload driver.
fn wrap_prebuilt_files() -> Vec<String> {
    (0..32)
        .map(|index| format!("libdemotion-common-{index:02}.so"))
        .chain((0..32).map(|index| format!("provider-A-{index:02}.so")))
        .chain((0..32).map(|index| format!("provider-B-{index:02}.so")))
        .chain(["workload".to_owned()])
        .collect()
}

/// Wrap-only prebuilt copy (the shared four-file helper cannot carry 32
/// distinct objects): validates every input before making private copies.
fn copy_wrap_prebuilt(source: &Path, destination: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        source.is_absolute(),
        "prebuilt wrap directory must be absolute"
    );
    let mut inputs = Vec::new();
    for name in wrap_prebuilt_files() {
        let path = source.join(&name);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading prebuilt wrap input {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "prebuilt wrap input must be a regular nonsymlink file: {}",
            path.display()
        );
        ensure!(
            name != "workload" || metadata.permissions().mode() & 0o111 != 0,
            "prebuilt wrap workload must be executable"
        );
        inputs.push((path, name, metadata.permissions()));
    }
    for (path, name, permissions) in inputs {
        let target = destination.join(&name);
        std::fs::copy(&path, &target)
            .with_context(|| format!("copying prebuilt wrap input {}", path.display()))?;
        std::fs::set_permissions(target, permissions)?;
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_wrap_prebuilt_copies_97_files() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let files = wrap_prebuilt_files();
    ensure!(files.len() == 97);
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    for name in &files {
        let path = source.path().join(name);
        std::fs::write(&path, name.as_bytes())?;
        let mode = if name == "workload" { 0o750 } else { 0o640 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    copy_wrap_prebuilt(source.path(), destination.path())?;
    for name in &files {
        let path = destination.path().join(name);
        ensure!(std::fs::read(&path)? == name.as_bytes());
        let mode = if name == "workload" { 0o750 } else { 0o640 };
        ensure!(std::fs::metadata(path)?.permissions().mode() & 0o777 == mode);
    }
    // Missing inputs refuse.
    ensure!(copy_wrap_prebuilt(source.path(), tempfile::tempdir()?.path()).is_ok());
    std::fs::remove_file(source.path().join(&files[0]))?;
    ensure!(copy_wrap_prebuilt(source.path(), tempfile::tempdir()?.path()).is_err());
    ensure!(copy_wrap_prebuilt(Path::new("relative"), destination.path()).is_err());
    Ok(())
}

/// Twin helper: the PID validator export re-headed to `scope: "system"`
/// with an explicit null filter, every non-health row stamped with the
/// owned PID and caller, and the footer resealed. Production stamps
/// caller identity (with the adapter PID) on every non-health record and
/// leaves global health rows pid-less.
fn diagnostic_validator_fixture_system(
    owned_pid: u32,
    caller: &str,
) -> (Vec<serde_json::Value>, u64) {
    let (mut records, _) = diagnostic_validator_fixture();
    let last = records.len() - 1;
    records[0]["scope"] = serde_json::json!("system");
    records[0]["pid_filter"] = serde_json::Value::Null;
    for row in records.iter_mut().take(last).skip(1) {
        if row["kind"] == "capture_health" {
            row.as_object_mut().unwrap().remove("pid");
        } else {
            row["pid"] = serde_json::json!(owned_pid);
            row["caller"] = serde_json::json!(caller);
        }
    }
    let bytes = seal_validator_fixture(&mut records);
    (records, bytes)
}

/// Twin helper: indexes of the placed terminal-proof publications.
fn twin_system_proof_positions(records: &[serde_json::Value]) -> Vec<usize> {
    records
        .iter()
        .enumerate()
        .filter(|(_, row)| row["kind"] == "publication" && row["decision"] == "placed")
        .map(|(index, _)| index)
        .collect()
}

/// Twin helper: the PID primary document plus one idle foreign caller
/// with a foreign-only module and edge. System capture honestly
/// observes the machine; foreign-only activity must not disturb the
/// owned population or borrow owned modules.
fn primary_validator_fixture_system(owned_pid: u32, shift: u64, k: u64) -> serde_json::Value {
    use crate::discovery::caller_registry::{CallerId, ModuleId};
    let mut document = primary_validator_fixture_k(owned_pid, shift, k);
    let caller = CallerId(shift as u32 + 100);
    let module = ModuleId(shift as u32 + 101);
    document["callers"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": caller.label(), "pid": 999, "lifecycle": "mapped",
            "retired": false, "lifecycle_reason": null,
        }));
    document["modules"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": module.label(), "paths": ["/foreign/other.so"],
            "lifecycle": "mapped", "unloaded_observed": false,
        }));
    document["edges"]
        .as_array_mut()
        .unwrap()
        .push(fixture_edge_json(caller, module, shift + 700, false));
    document
}

#[test]
fn operator_diagnostics_wrap_twin_system_scope_pid_pass() -> Result<()> {
    // The PID cell filters diagnostics to exactly the owned workload.
    ensure!(
        WrapScope::select(InspectScope::Pid(123), Some(123), 123)? == WrapScope::Pid { pid: 123 }
    );
    ensure!(WrapCell::Pid.scope(123)? == WrapScope::Pid { pid: 123 });
    ensure!(WrapScope::Pid { pid: 123 }.owned_pid() == 123);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_scope_system_pass() -> Result<()> {
    // The system cell captures unfiltered and anchors on the owned PID.
    let scope = WrapScope::select(InspectScope::System, None, 123)?;
    ensure!(scope == WrapScope::System { owned_pid: 123 });
    ensure!(scope.owned_pid() == 123);
    ensure!(WrapCell::System.scope(123)? == WrapScope::System { owned_pid: 123 });
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_scope_rejects_pid_shaped_input() -> Result<()> {
    // A system leg must never carry a PID filter, and a PID scope never
    // validates as a system scope.
    ensure!(WrapScope::select(InspectScope::System, Some(123), 123).is_err());
    ensure!(WrapScope::select(InspectScope::System, Some(456), 123).is_err());
    ensure!(
        WrapScope::select(InspectScope::Pid(123), Some(123), 123)?
            != WrapScope::System { owned_pid: 123 }
    );
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_scope_rejects_mismatched_filter() -> Result<()> {
    // A PID leg needs its exact filter; a zero owner is no process.
    ensure!(WrapScope::select(InspectScope::Pid(123), None, 123).is_err());
    ensure!(WrapScope::select(InspectScope::Pid(123), Some(456), 123).is_err());
    ensure!(WrapScope::select(InspectScope::Pid(123), Some(123), 456).is_err());
    ensure!(WrapScope::select(InspectScope::System, None, 0).is_err());
    ensure!(WrapScope::select(InspectScope::Pid(0), Some(0), 0).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_export_pass() -> Result<()> {
    // The healthy system export validates: system header, explicit null
    // filter, owned rows, terminal pairs on the owned caller, both rings
    // wrapped.
    let (records, bytes) = diagnostic_validator_fixture_system(123, "c0");
    ensure!(twin_system_proof_positions(&records).len() == 32);
    check_wrap_records_system(&records, bytes, &twin_b_modules(), 123, "c0")?;
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_export_rejects_pid_shaped_header() -> Result<()> {
    // A PID-shaped header never validates as a system export: neither
    // scope pid, nor any present filter, nor a missing filter key, nor a
    // non-native mode.
    let (mut pid_scope, _) = diagnostic_validator_fixture_system(123, "c0");
    pid_scope[0]["scope"] = serde_json::json!("pid");
    pid_scope[0]["pid_filter"] = serde_json::json!(123);
    let bytes = seal_validator_fixture(&mut pid_scope);
    ensure!(check_wrap_records_system(&pid_scope, bytes, &twin_b_modules(), 123, "c0").is_err());
    let (mut filtered, _) = diagnostic_validator_fixture_system(123, "c0");
    filtered[0]["pid_filter"] = serde_json::json!(123);
    let bytes = seal_validator_fixture(&mut filtered);
    ensure!(check_wrap_records_system(&filtered, bytes, &twin_b_modules(), 123, "c0").is_err());
    let (mut missing, _) = diagnostic_validator_fixture_system(123, "c0");
    missing[0].as_object_mut().unwrap().remove("pid_filter");
    let bytes = seal_validator_fixture(&mut missing);
    ensure!(check_wrap_records_system(&missing, bytes, &twin_b_modules(), 123, "c0").is_err());
    let (mut mode, _) = diagnostic_validator_fixture_system(123, "c0");
    mode[0]["mode"] = serde_json::json!("auto");
    let bytes = seal_validator_fixture(&mut mode);
    ensure!(check_wrap_records_system(&mode, bytes, &twin_b_modules(), 123, "c0").is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_export_rejects_foreign_pid() -> Result<()> {
    // Owned-caller validation: any pid-bearing row outside the owned PID
    // fails — on ordinary rows and on terminal proofs alike — as does a
    // missing PID on a non-health row or a PID on the global health row.
    let modules = twin_b_modules();
    let (records, _) = diagnostic_validator_fixture_system(123, "c0");
    let proofs = twin_system_proof_positions(&records);
    ensure!(proofs.len() == 32);
    let mut foreign_row = records.clone();
    foreign_row[1]["pid"] = serde_json::json!(999);
    let bytes = seal_validator_fixture(&mut foreign_row);
    ensure!(check_wrap_records_system(&foreign_row, bytes, &modules, 123, "c0").is_err());
    let mut foreign_proof = records.clone();
    foreign_proof[proofs[0]]["pid"] = serde_json::json!(999);
    let bytes = seal_validator_fixture(&mut foreign_proof);
    ensure!(check_wrap_records_system(&foreign_proof, bytes, &modules, 123, "c0").is_err());
    let mut missing_pid = records.clone();
    missing_pid[1].as_object_mut().unwrap().remove("pid");
    let bytes = seal_validator_fixture(&mut missing_pid);
    ensure!(check_wrap_records_system(&missing_pid, bytes, &modules, 123, "c0").is_err());
    let health = records
        .iter()
        .position(|row| row["kind"] == "capture_health")
        .context("health row")?;
    let mut health_pid = records.clone();
    health_pid[health]["pid"] = serde_json::json!(123);
    let bytes = seal_validator_fixture(&mut health_pid);
    ensure!(check_wrap_records_system(&health_pid, bytes, &modules, 123, "c0").is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_export_rejects_foreign_caller() -> Result<()> {
    // Terminal proofs must bind the live-observed owned caller id: a
    // consistently foreign caller fails the owned pin even with the owned
    // PID, while the matching pin passes the same export.
    let modules = twin_b_modules();
    let (foreign, bytes) = diagnostic_validator_fixture_system(123, "c9");
    ensure!(check_wrap_records_system(&foreign, bytes, &modules, 123, "c0").is_err());
    check_wrap_records_system(&foreign, bytes, &modules, 123, "c9")?;
    // A single foreign proof among owned ones fails on consistency too.
    let (mut mixed, _) = diagnostic_validator_fixture_system(123, "c0");
    let proofs = twin_system_proof_positions(&mixed);
    ensure!(proofs.len() == 32);
    mixed[proofs[0]]["caller"] = serde_json::json!("c9");
    let bytes = seal_validator_fixture(&mut mixed);
    ensure!(check_wrap_records_system(&mixed, bytes, &modules, 123, "c0").is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_export_requires_wrap_properties() -> Result<()> {
    // The system validator inherits every fail-closed wrap property:
    // unit per-edge proofs, retained references, advancing
    // recovery windows, and a real both-ring wrap.
    let modules = twin_b_modules();
    let (records, _) = diagnostic_validator_fixture_system(123, "c0");
    let proofs = twin_system_proof_positions(&records);
    ensure!(proofs.len() == 32);
    for change in [
        "wrong_projection",
        "lost_reference",
        "stale_window",
        "one_ring_wrap",
    ] {
        let mut altered = records.clone();
        match change {
            "wrong_projection" => {
                for index in proofs.iter() {
                    altered[*index]["edge_total"] = serde_json::json!(2);
                }
            }
            "lost_reference" => {
                altered[proofs[0]]["observation_ref"]["status"] = serde_json::json!("not_retained");
            }
            "stale_window" => {
                altered[proofs[0]]["baseline_post"] = altered[proofs[0]]["pre"].clone();
            }
            _ => {
                let last = altered.len() - 1;
                altered[last]["kinds"][1]["evicted"] = serde_json::json!(0);
                altered[last]["kinds"][1]["produced"] = serde_json::json!(1);
            }
        }
        let bytes = seal_validator_fixture(&mut altered);
        ensure!(
            check_wrap_records_system(&altered, bytes, &modules, 123, "c0").is_err(),
            "broken wrap property accepted: {change}"
        );
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_primary_pass() -> Result<()> {
    // The pinned A/B projections apply unchanged under system capture,
    // and the owned facts equal the PID validator's on the same
    // population — foreign-only presence changes nothing.
    for k in [0, 32] {
        let facts = primary_facts_system(&primary_validator_fixture_system(123, 0, k), 123, k)?;
        ensure!(facts["edges"]["provider-A-00.so"]["count"] == expected_a(COUNTED, k));
        ensure!(facts["edges"]["provider-A-31.so"]["count"] == expected_a(COUNTED, k));
        ensure!(facts["edges"]["provider-B-00.so"]["count"] == 1);
        ensure!(facts["edges"]["provider-B-31.so"]["count"] == 1);
        let pid_facts = primary_facts(&primary_validator_fixture_k(123, 0, k), 123, k)?;
        ensure!(facts == pid_facts);
    }
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_primary_rejects_foreign_caller() -> Result<()> {
    // Owned-caller validation: a foreign caller borrowing an owned
    // module fails, as do a missing or duplicated owned caller.
    let mut borrowed = primary_validator_fixture_system(123, 0, 0);
    borrowed["edges"][64]["module"] = borrowed["modules"][33]["id"].clone();
    ensure!(primary_facts_system(&borrowed, 123, 0).is_err());
    let mut missing = primary_validator_fixture_system(123, 0, 0);
    missing["callers"].as_array_mut().unwrap().remove(0);
    ensure!(primary_facts_system(&missing, 123, 0).is_err());
    let mut duplicated = primary_validator_fixture_system(123, 0, 0);
    let owned_entry = duplicated["callers"][0].clone();
    duplicated["callers"]
        .as_array_mut()
        .unwrap()
        .push(owned_entry);
    ensure!(primary_facts_system(&duplicated, 123, 0).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_primary_rejects_wrong_counts() -> Result<()> {
    // The pinned edge projections bind under system capture too.
    let mut wrong_a = primary_validator_fixture_system(123, 0, 0);
    wrong_a["edges"][0]["entries"]["count"] = serde_json::json!(399);
    ensure!(primary_facts_system(&wrong_a, 123, 0).is_err());
    let mut wrong_b = primary_validator_fixture_system(123, 0, 32);
    wrong_b["edges"][32]["entries"]["count"] = serde_json::json!(2);
    ensure!(primary_facts_system(&wrong_b, 123, 32).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_paired_parity_dispositions() -> Result<()> {
    // System owned facts flow through the strict paired comparison:
    // matched legs pass across runs, differing dispositions fail.
    let off = primary_facts_system(&primary_validator_fixture_system(123, 0, 0), 123, 0)?;
    let on = primary_facts_system(&primary_validator_fixture_system(456, 500, 0), 456, 0)?;
    check_paired_parity(&off, 0, &on, 0)?;
    let fenced = primary_facts_system(&primary_validator_fixture_system(123, 0, 32), 123, 32)?;
    ensure!(check_paired_parity(&off, 0, &fenced, 32).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_scope_round_trip() -> Result<()> {
    // A validated scope reproduces its capture inputs exactly: the PID
    // leg scopes and filters to the owner, the system leg scopes wide
    // with no filter.
    let pid = WrapScope::select(InspectScope::Pid(123), Some(123), 123)?;
    ensure!(pid.inspect_scope() == InspectScope::Pid(123));
    ensure!(pid.diagnostics_pid_filter() == Some(123));
    let system = WrapScope::select(InspectScope::System, None, 123)?;
    ensure!(system.inspect_scope() == InspectScope::System);
    ensure!(system.diagnostics_pid_filter().is_none());
    Ok(())
}
