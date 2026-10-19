//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned32-object physical entry-count gate. No semantic/API/104-slot claim.
//! Prebuilt-only, paired normal/default diagnostics; no recorder injection.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};

const TARGETS: u64 = 32;
const COUNTED: u64 = 400;
const SHARED: u64 = 258;
const RUN_SECONDS: u64 = 900;
const INPUT_LIMIT: u64 = 16 * 1024 * 1024;

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
                dir.path().join("provider-A.so"),
                dir.path().join("provider-B.so"),
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
}

/// Read only newly complete JSONL lines. A partial last line remains at the old
/// file offset and cannot masquerade as a committed capture milestone.
fn new_lines(path: &Path, offset: &mut u64) -> Result<Vec<serde_json::Value>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
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

#[derive(Default)]
struct PassView {
    offset: u64,
    a: Option<serde_json::Value>,
    b: Option<serde_json::Value>,
    evidence: Vec<GapEvidence>,
    caller_id: Option<String>,
    module_a: Option<String>,
    module_b: Option<String>,
}
impl PassView {
    fn refresh(&mut self, path: &Path, pid: u32) -> Result<bool> {
        let rows = new_lines(path, &mut self.offset)?;
        for row in &rows {
            let event = &row["event"];
            if row["kind"] == "edge_observed" && event["identity_context"]["caller"]["pid"] == pid {
                if let Some(id) = event["identity_context"]["caller"]["id"].as_str() {
                    self.caller_id = Some(id.to_owned());
                }
                if let Some(path) = event["identity_context"]["module"]["path"].as_str() {
                    let module = event["identity_context"]["module"]["id"]
                        .as_str()
                        .map(str::to_owned);
                    if path.ends_with("provider-A.so") {
                        self.a = Some(event.clone());
                        if module.is_some() {
                            self.module_a = module.clone();
                        }
                    }
                    if path.ends_with("provider-B.so") {
                        self.b = Some(event.clone());
                        if module.is_some() {
                            self.module_b = module;
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
                if !self.evidence.iter().any(|known| {
                    known.caller == candidate.caller
                        && known.module == candidate.module
                        && known.subject == candidate.subject
                        && known.reason == candidate.reason
                }) {
                    self.evidence.push(candidate);
                }
            }
            if row["kind"] == "gap_repeated"
                && let (Some(index), Some(repeats)) =
                    (event["index"].as_u64(), event["repeats"].as_u64())
                && let Some(known) = self.evidence.get_mut(index as usize)
            {
                known.repeats = repeats;
            }
        }
        Ok(rows
            .last()
            .is_some_and(|row| row["kind"] == "pass_committed"))
    }
}

/// One observed `gap_recorded` identity plus its stream-tracked repeats.
/// Repeats ride `gap_repeated` mid-run (power-of-two crossings only) and
/// become exact at the pre-`ended` flush; the gate only relies on exact
/// values (absence, or a reached power of two).
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
                && retirement_range(&gap.reason) == Some((base, absolute))
        })
        .map(|gap| gap.repeats)
        .sum()
}

/// Repeats of the caller-bound startup-fence gap `(1, 2]`, or 0 when absent.
fn startup_fence_repeats(gaps: &[GapEvidence], caller: &str) -> u64 {
    range_gap_repeats(gaps, caller, 1, 2)
}

/// Repeats of the caller-bound post-retirement fence gap `(658, 659]`.
fn fence_gap_repeats(gaps: &[GapEvidence], caller: &str) -> u64 {
    range_gap_repeats(gaps, caller, COUNTED + SHARED, COUNTED + SHARED + 1)
}

/// Expected published A-edge projection after `round` issued A rounds with
/// `k` startup-fenced pairs (Sol pinned trajectory). The edge is
/// max-accepting with per-(caller, module) overlap merge, not a per-pair
/// sum: ordinary reads 1, 2, 3 after rounds 1-3 and 400 after round 400;
/// all-32-fenced reads 1, 1, 2 and 399. Only `k == 0` and `k == 32` are
/// valid dispositions; anything else is rejected by the caller, never by
/// a silently interpolated value here.
fn expected_a(round: u64, k: u64) -> u64 {
    if k == 0 {
        round
    } else if round <= 1 {
        1
    } else {
        round - 1
    }
}

/// Validate one observed A-phase round against caller-bound gap evidence.
/// Returns the validated fence count `k`. Round 1 never fences; round 2
/// establishes `k` (0 ordinary, 32 fenced); later rounds require exact
/// 1-increments of the max-accepting projection with stable `k`.
fn check_startup_round(
    round: u64,
    observed_a: u64,
    gaps: &[GapEvidence],
    caller: &str,
    prior_k: Option<u64>,
) -> Result<u64> {
    ensure!(
        (1..=COUNTED).contains(&round),
        "A round out of range: {round}"
    );
    let k = startup_fence_repeats(gaps, caller);
    if round == 1 {
        ensure!(prior_k.is_none(), "round 1 takes no prior disposition");
        ensure!(
            k == 0 && observed_a == expected_a(1, 0),
            "round 1 never fences: A={observed_a} k={k}"
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
            observed_a == expected_a(2, k),
            "round-2 A={observed_a} contradicts fence evidence k={k}"
        );
        return Ok(k);
    }
    ensure!(
        prior_k == Some(k),
        "startup disposition changed mid-run: prior={prior_k:?} now={k}"
    );
    ensure!(
        observed_a == expected_a(round, k),
        "round-{round} A={observed_a} breaks the pinned projection chain (k={k})"
    );
    Ok(k)
}

/// Validate the terminal fence/proof pair set: 32 distinct pairs under one
/// caller, each with a fence `(658, 659]` withheld prefix (absolute 659,
/// retained observation) and a proof placement (base 659, absolute 660,
/// staged 1) on the recovered B module. Every proof must project
/// `edge_total == 1` (the single-publication batching premise behind B=1;
/// a split recovery projects 2..32) and recover through a strictly later
/// read (`baseline_post < pre`). No B placement may overlap a withheld
/// interval, and B must carry exactly the 32 proofs (no early/foreign
/// attribution). Returns aggregate (fence-absolute sum, proof-absolute sum,
/// staged sum) after asserting the exact 21,088/21,120/32 reconciliation.
fn check_terminal_pairs(
    records: &[serde_json::Value],
    b_module: &serde_json::Value,
) -> Result<(u64, u64, u64)> {
    check_terminal_pairs_as(records, b_module, None)
}

/// `check_terminal_pairs` with the terminal caller identity pinned to
/// the live-observed owned caller (system cell). `None` keeps the
/// single-caller consistency check unpinned (PID cell).
fn check_terminal_pairs_as(
    records: &[serde_json::Value],
    b_module: &serde_json::Value,
    expected_caller: Option<&str>,
) -> Result<(u64, u64, u64)> {
    let mut placements = BTreeSet::new();
    let mut proof_abs_sum = 0u64;
    let mut staged_sum = 0u64;
    let mut fence = BTreeSet::new();
    let mut fence_abs_sum = 0u64;
    let mut caller: Option<String> = None;
    let mut b_placements = 0u64;
    for row in records {
        if row["kind"] == "publication"
            && row["decision"] == "placed"
            && row["module_id"] == *b_module
        {
            b_placements += 1;
            let base = row["base"].as_u64().unwrap_or(u64::MAX);
            let absolute = row["absolute"].as_u64().unwrap_or(0);
            let is_proof_shape = base == COUNTED + SHARED + 1
                && absolute == COUNTED + SHARED + 2
                && row["staged"] == 1;
            if !is_proof_shape && base < COUNTED + SHARED + 1 && absolute > COUNTED + SHARED {
                bail!("B placement overlaps the withheld fence interval: {row}");
            }
        }
        if row["kind"] == "publication"
            && row["decision"] == "placed"
            && row["module_id"] == *b_module
            && row["base"] == COUNTED + SHARED + 1
            && row["absolute"] == COUNTED + SHARED + 2
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
            }
        }
        if row["kind"] == "count_decision"
            && row["decision"] == "withheld"
            && row["reason"] == "awaiting_fence"
            && row["after"] == COUNTED + SHARED
            && row["through"] == COUNTED + SHARED + 1
            && row["absolute"] == COUNTED + SHARED + 1
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
        placements.len() == 32 && fence == placements,
        "all32 real pairs need recent withheld-prefix/recovery on B"
    );
    ensure!(
        fence_abs_sum == 32 * (COUNTED + SHARED + 1)
            && proof_abs_sum == 32 * (COUNTED + SHARED + 2)
            && staged_sum == 32,
        "terminal sums differ from per-pair 659/660/1: fence={fence_abs_sum} proof={proof_abs_sum} staged={staged_sum}"
    );
    if let Some(expected) = expected_caller {
        ensure!(
            caller.as_deref() == Some(expected),
            "terminal pairs bind caller {caller:?}, not the owned {expected}"
        );
    }
    Ok((fence_abs_sum, proof_abs_sum, staged_sum))
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

/// Verify a shared-phase checkpoint: at power-of-two rounds the folded
/// ambiguity gaps are mid-run exact and must read exactly `32*round` on
/// both sharer modules. Between checkpoints any value passes (power-of-two
/// lower bounds cannot gate); the pre-`ended` flush verifies the exact
/// final 8256 retrospectively.
fn check_shared_checkpoint(
    round: u64,
    gaps: &[GapEvidence],
    module_a: &str,
    module_b: &str,
) -> Result<()> {
    if !round.is_power_of_two() {
        return Ok(());
    }
    let expected = round * TARGETS;
    let a = ambiguity_repeats(gaps, module_a);
    let b = ambiguity_repeats(gaps, module_b);
    ensure!(
        a == expected && b == expected,
        "shared round{round} needs exactly{expected} ambiguity disclosures per sharer (A={a} B={b})"
    );
    Ok(())
}

fn check_native_ledger(workload: &WrapWorkload) -> Result<()> {
    check_native_schedule(
        workload,
        &[
            ("a", COUNTED),
            ("shared", SHARED),
            ("fence", 1),
            ("proof", 1),
        ],
    )
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
    b_module: &serde_json::Value,
    pid: u32,
) -> Result<()> {
    let header = records.first().context("diagnostic header missing")?;
    ensure!(header["scope"] == "pid" && header["mode"] == "native" && header["pid_filter"] == pid);
    check_wrap_records_core(records, bytes, b_module, None)
}

/// Scope-free wrap-export contract: envelope, limits, both-ring wrap,
/// footer reconciliation, truthful references and the terminal pairs.
/// The caller pins the scope header first; `expected_caller` pins the
/// terminal caller identity (system cell) or leaves the single-caller
/// consistency check unpinned (PID cell).
fn check_wrap_records_core(
    records: &[serde_json::Value],
    bytes: u64,
    b_module: &serde_json::Value,
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
        check_terminal_pairs_as(records, b_module, expected_caller)?;
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
    b_module: &serde_json::Value,
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
    check_wrap_records_core(records, bytes, b_module, Some(owned_caller))
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

/// Shared owned-population core: loss-free native observation plus the
/// pinned A/B edges for the validated caller. Returns the primary facts
/// with the owned module ids for exclusivity checks.
fn primary_facts_core(
    document: &serde_json::Value,
    pid: u32,
    k: u64,
    caller: &serde_json::Value,
) -> Result<(serde_json::Value, BTreeSet<String>)> {
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
    ensure!(edges.len() == 2);
    let modules = document["modules"].as_array().context("primary modules")?;
    let mut facts = BTreeMap::new();
    let mut module_ids = BTreeSet::new();
    for edge in edges {
        let matching: Vec<_> = modules
            .iter()
            .filter(|module| module["id"] == edge["module"])
            .collect();
        ensure!(matching.len() == 1, "edge module must be unique");
        let module = matching[0];
        ensure!(module_ids.insert(edge["module"].as_str().context("module ID")?.to_owned()));
        let labels: Vec<_> = ["provider-A.so", "provider-B.so"]
            .into_iter()
            .filter(|suffix| {
                module["paths"].as_array().is_some_and(|paths| {
                    paths
                        .iter()
                        .any(|path| path.as_str().is_some_and(|path| path.ends_with(suffix)))
                })
            })
            .collect();
        ensure!(
            labels.len() == 1,
            "owned module must identify exactly one expected provider"
        );
        let label = labels[0];
        let a = label == "provider-A.so";
        // Pinned edge projections (Sol): A is the max-accepting 400/399,
        // B is exactly 1 (32 overlapping proof units published together).
        // Per-pair physical sums (12,800; 21,120; staged 32) are reconciled
        // separately from the schedule plus ledger, never from this edge.
        let expected = if a { expected_a(COUNTED, k) } else { 1 };
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
        ensure!(
            facts.insert(label, value).is_none(),
            "duplicate provider label"
        );
    }
    ensure!(
        facts.len() == 2
            && facts.contains_key("provider-A.so")
            && facts.contains_key("provider-B.so")
    );
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

/// Post-run exact gap verification on the complete event stream (the
/// pre-`ended` flush makes repeats exact): startup `(1,2]` repeats must
/// equal the live-validated `k`, both sharers' ambiguity disclosures must
/// total exactly `32*SHARED`, and the fence `(658,659]` repeats must be 32.
fn verify_final_gaps(
    rows: &[serde_json::Value],
    caller: &str,
    module_a: &str,
    module_b: &str,
    k: u64,
) -> Result<()> {
    let gaps = replay_gap_repeats(rows);
    let startup = startup_fence_repeats(&gaps, caller);
    ensure!(
        startup == k,
        "final startup-fence repeats {startup} != live k={k}"
    );
    let expected = SHARED * TARGETS;
    for module in [module_a, module_b] {
        let repeats = ambiguity_repeats(&gaps, module);
        ensure!(
            repeats == expected,
            "final ambiguity disclosures for {module}: {repeats} != {expected}"
        );
    }
    let fence = fence_gap_repeats(&gaps, caller);
    ensure!(fence == TARGETS, "final fence repeats {fence} != 32");
    eprintln!(
        "G21_WRAP_GAPS caller={caller} k={k} startup={startup} ambiguity={expected} fence={fence}"
    );
    Ok(())
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
    workload.check_mapping("provider-A.so")?;
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
    let stop = || {
        let advance = || -> Result<bool> {
            if start.elapsed() >= Duration::from_secs(RUN_SECONDS) {
                let view = view.borrow();
                bail!(
                    "G21 wrap exceeded900s, phase={:?} k={} A={:?} B={:?} evidence={:?}",
                    state.get(),
                    fence_k.get(),
                    view.a
                        .as_ref()
                        .and_then(|edge| edge["entries"]["count"].as_u64()),
                    view.b
                        .as_ref()
                        .and_then(|edge| edge["entries"]["count"].as_u64()),
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
            let armed = |edge: Option<&serde_json::Value>| {
                edge.is_some_and(|edge| edge["capture"] == "armed" && edge["presence"] == "mapped")
            };
            let a_count = view
                .a
                .as_ref()
                .and_then(|edge| edge["entries"]["count"].as_u64());
            let b_count = view
                .b
                .as_ref()
                .and_then(|edge| edge["entries"]["count"].as_u64());
            match state.get() {
                (0, _) if armed(view.a.as_ref()) => {
                    workload.command("ready", "ready", 0)?;
                    workload.command("count", "a-done", 1)?;
                    eprintln!(
                        "G21_WRAP_ROUND enabled={enabled} phase=a round=1 issued caller={caller}"
                    );
                    state.set((1, 1));
                }
                (1, round) => {
                    let count = a_count.context("A edge count missing in A phase")?;
                    let k_now = startup_fence_repeats(&view.evidence, &caller);
                    // Stale passes still show the prior milestone with no new
                    // gap evidence: wait. Anything else validates strictly
                    // (deficits fail here, never stall into the timeout).
                    let stale = round == 1 && count == 0 && k_now == 0
                        || round > 1
                            && count == expected_a(round - 1, fence_k.get())
                            && k_now == fence_k.get();
                    if !stale {
                        let prior = if round == 1 {
                            None
                        } else {
                            Some(fence_k.get())
                        };
                        let k = check_startup_round(round, count, &view.evidence, &caller, prior)?;
                        fence_k.set(k);
                        if round <= 3 || round % 50 == 0 || round == COUNTED {
                            eprintln!(
                                "G21_WRAP_ROUND enabled={enabled} phase=a round={round} A={count} k={k}"
                            );
                        }
                        if round < COUNTED {
                            workload.command("count", "a-done", round + 1)?;
                            state.set((1, round + 1));
                        } else {
                            workload.command("load-b", "b-ready", 0)?;
                            workload.check_mapping("provider-B.so")?;
                            eprintln!(
                                "G21_WRAP_ROUND enabled={enabled} phase=a done A={count} k={k}"
                            );
                            state.set((2, 0));
                        }
                    }
                }
                (2, _) if armed(view.b.as_ref()) => {
                    workload.command("shared", "shared-done", 1)?;
                    eprintln!(
                        "G21_WRAP_ROUND enabled={enabled} phase=shared round=1 issued k={}",
                        fence_k.get()
                    );
                    state.set((3, 1));
                }
                // Shared rounds serialize one per observer pass (the stop
                // callback issues strictly before each pass's collect, so
                // every new pass observes exactly one new round). Folded
                // ambiguity gaps cannot gate per-round mid-run; power-of-two
                // checkpoints plus the post-run exact replay verify the
                // 1:1 cadence instead. Withholding itself is exact on
                // every pass.
                (3, round) => {
                    let k = fence_k.get();
                    ensure!(
                        a_count == Some(expected_a(COUNTED, k)) && b_count == Some(0),
                        "shared calls escaped withholding: A={a_count:?} B={b_count:?} k={k}"
                    );
                    let module_a = view.module_a.clone().context("A module id missing")?;
                    let module_b = view.module_b.clone().context("B module id missing")?;
                    check_shared_checkpoint(round, &view.evidence, &module_a, &module_b)?;
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
                    if view
                        .a
                        .as_ref()
                        .is_some_and(|edge| edge["presence"] == "unloaded") =>
                {
                    workload.command("fence", "fence-done", 1)?;
                    eprintln!("G21_WRAP_ROUND enabled={enabled} phase=fence issued");
                    state.set((5, 0));
                }
                (5, _) => {
                    ensure!(
                        b_count == Some(0),
                        "the fence was attributed: B={b_count:?}"
                    );
                    if fence_gap_repeats(&view.evidence, &caller) == TARGETS {
                        workload.command("proof", "final-calls", 1)?;
                        eprintln!("G21_WRAP_ROUND enabled={enabled} phase=proof issued");
                        state.set((6, 0));
                    }
                }
                (6, _) => {
                    let k = fence_k.get();
                    ensure!(
                        a_count == Some(expected_a(COUNTED, k)),
                        "A history changed during proof: A={a_count:?} k={k}"
                    );
                    // B is exactly 1: the 32 terminal proofs overlap in one
                    // publication. The batching premise is asserted on the
                    // exported Publication records (edge_total == 1 on all
                    // 32); a split recovery would project 2..32 instead.
                    if b_count == Some(1) {
                        eprintln!("G21_WRAP_ROUND enabled={enabled} phase=proof done B=1 k={k}");
                        state.set((7, 0));
                    } else {
                        ensure!(
                            b_count == Some(0),
                            "B recovered the wrong count: B={b_count:?}"
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
                *failure.borrow_mut() = Some(error);
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
    let mut event_offset = view.borrow().offset;
    let terminal_events = new_lines(&events, &mut event_offset)?;
    ensure!(
        terminal_events
            .last()
            .is_some_and(|row| row["kind"] == "ended"),
        "public event stream lacks terminal end"
    );
    let k = fence_k.get();
    let full_stream = jsonl_records(&events)?;
    {
        let view = view.borrow();
        verify_final_gaps(
            &full_stream,
            view.caller_id.as_deref().unwrap_or_default(),
            view.module_a.as_deref().unwrap_or_default(),
            view.module_b.as_deref().unwrap_or_default(),
            k,
        )?;
    }
    let document: serde_json::Value = serde_json::from_slice(&stdout)?;
    let facts = match scope {
        WrapScope::Pid { pid } => primary_facts(&document, pid, k)?,
        WrapScope::System { owned_pid } => primary_facts_system(&document, owned_pid, k)?,
    };
    if enabled {
        let b = doc_edges(&document, pid)
            .into_iter()
            .find(|edge| edge["entries"]["count"] == 1)
            .context("recovered B edge")?;
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
            WrapScope::Pid { pid } => check_wrap_records(&records, length, &b["module"], pid)?,
            WrapScope::System { owned_pid } => {
                let owned_caller = view
                    .borrow()
                    .caller_id
                    .clone()
                    .context("owned caller id never observed")?;
                check_wrap_records_system(
                    &records,
                    length,
                    &b["module"],
                    owned_pid,
                    &owned_caller,
                )?;
            }
        }
    } else {
        ensure!(!diagnostics.exists());
    }
    eprintln!(
        "G21_PAIRED enabled={enabled} elapsed_ms={} calls={} A={} B={} k={k} eligible_a={} withheld={} stdout_bytes={}",
        start.elapsed().as_millis(),
        (COUNTED + SHARED + 2) * TARGETS,
        expected_a(COUNTED, k),
        1,
        COUNTED * TARGETS - k,
        (SHARED + 1) * TARGETS + k,
        stdout.len()
    );
    Ok((facts, k))
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
    let a = ModuleId(shift as u32 + 1);
    let b = ModuleId(shift as u32 + 2);
    serde_json::json!({
        "observation":{"lane":"native","settlement":"unsettled","retirement":"closed",
            "lifecycle":{"records":shift+10,"ring_loss":0,"malformed":0,"failed_quanta":0,"recovery_rescans":0},
            "native_witnesses":{"rows":shift+20,"bound":shift+20,"unbound":0,"pending":0,"integrity":0,
                "unbound_reasons":{},"placement":{"edge":shift+20,"module":0,"ambiguous":0,"unresolved":0}}},
        "callers":[{"id":caller.label(),"pid":pid,"lifecycle":"mapped","retired":false,"lifecycle_reason":null}],
        "modules":[{"id":a.label(),"paths":["/owned/provider-A.so"],"lifecycle":"unloaded","unloaded_observed":true},
            {"id":b.label(),"paths":["/owned/provider-B.so"],"lifecycle":"mapped","unloaded_observed":false}],
        "edges":[fixture_edge_json_k(caller,a,shift,true,k),fixture_edge_json(caller,b,shift,false)],"gaps":[]
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
                let mut duplicate = altered["edges"][0].clone();
                duplicate["module"] = altered["modules"][1]["id"].clone();
                altered["edges"][1] = duplicate;
                altered["modules"][1]["paths"] = serde_json::json!(["/owned/provider-A.so"]);
                altered["modules"][1]["lifecycle"] = "unloaded".into();
                altered["modules"][1]["unloaded_observed"] = true.into();
            }
            "missing_label" => {
                altered["modules"][1]["paths"] = serde_json::json!(["/owned/other.so"])
            }
            "duplicate_module" => {
                let duplicate = altered["modules"][0]["id"].clone();
                altered["modules"][1]["id"] = duplicate;
            }
            "count" => altered["edges"][0]["entries"]["count"] = 1.into(),
            "mapping_state" => altered["edges"][0]["mapping"]["state"] = "mapped".into(),
            "module_lifecycle" => altered["modules"][0]["lifecycle"] = "mapped".into(),
            "loss" => altered["edges"][0]["entries"]["coverage"]["reason"] = "loss".into(),
            _ => altered["edges"][1]["entries"]["coverage"]["lossy"] = true.into(),
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
        ensure!(edges.len() == 2);
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
            serde_json::json!({"kind":"publication","decision":"placed","module_id":"mB",
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

#[test]
fn operator_diagnostics_wrap_retained_validator_checks_actual_rows() -> Result<()> {
    let (healthy, bytes) = diagnostic_validator_fixture();
    check_wrap_records(&healthy, bytes, &serde_json::json!("mB"), 123)?;
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
            check_wrap_records(&altered, bytes, &serde_json::json!("mB"), 123).is_err(),
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

/// Strict paired off/on comparison (Sol): both legs run the identical
/// deterministic issued schedule with milestone gating (the matched
/// prelude), so they must validate the same startup disposition and their
/// owned primary facts must compare exactly equal. No count replacement:
/// replacing both A counts before comparison proves conditional agreement
/// only, and different legitimate dispositions each pass their own oracle
/// without proving literal count equality. Expected counts come from the
/// issued schedule plus observed startup gaps, never from reported
/// diagnostics.
fn check_paired_parity(
    disabled: &serde_json::Value,
    dk: u64,
    enabled: &serde_json::Value,
    ek: u64,
) -> Result<()> {
    ensure!(
        disabled["edges"]["provider-A.so"]["count"] == expected_a(COUNTED, dk)
            && enabled["edges"]["provider-A.so"]["count"] == expected_a(COUNTED, ek),
        "leg A contradicts its validated disposition: dk={dk} ek={ek}"
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
/// round, with exactly `k` fenced pairs withholding round 2.
fn check_startup_probe_records(
    records: &[serde_json::Value],
    public_count: u64,
    pid: u32,
    module: &serde_json::Value,
    calls: &[(u64, u64)],
    k: u64,
) -> Result<serde_json::Value> {
    ensure!(calls.len() == 3);
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
                    && row["module_id"] == *module
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
    for pair in pairs.iter() {
        ensure!(
            placed(pair, 1, 0).len() == 1,
            "first unit must remain actual published history on {pair}"
        );
    }
    let fences: Vec<_> = records
        .iter()
        .filter(|row| row["decision"] == "withheld")
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
    ensure!(
        public_count == expected_a(3, k),
        "only the exact pinned probe projection (ordinary 3, startup-fence 2) is qualified"
    );
    let path = if k == 0 { "ordinary" } else { "startup_fence" };
    Ok(
        serde_json::json!({"path":path,"physical_pairs":32,"calls":96,
        "published":public_count,"withheld":k,"fenced_pairs":k,
        "observations":observations,"fences":fences}),
    )
}

/// Short actual native control before any revised long wrap schedule. The two
/// accepted paths are distinguished by real dispositions, never by elapsed sleep.
#[test]
#[ignore = "root-owned BPF lane; source-matched prebuilt3-round probe, bounded90s"]
fn privileged_native_lane_pid_diagnostics_three_round_startup_probe_lp64() -> Result<()> {
    let mut workload = WrapWorkload::spawn_profile(true)?;
    workload.check_mapping("provider-A.so")?;
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
    let stop = || {
        let advance = || -> Result<bool> {
            ensure!(
                started.elapsed() < Duration::from_secs(90),
                "startup probe exceeded90s at phase{}",
                state.get()
            );
            if state.get() == 4 {
                return Ok(true);
            }
            let mut view = view.borrow_mut();
            if !view.refresh(&events, pid)? {
                return Ok(false);
            }
            let caller = view.caller_id.clone().unwrap_or_default();
            let a = view.a.as_ref();
            let count = a.and_then(|edge| edge["entries"]["count"].as_u64());
            match state.get() {
                0 if a.is_some_and(|edge| {
                    edge["capture"] == "armed" && edge["presence"] == "mapped"
                }) =>
                {
                    workload.command("ready", "ready", 0)?;
                    workload.command("count", "a-done", 1)?;
                    state.set(1);
                }
                awaiting @ 1..=3 => {
                    let round = u64::from(awaiting);
                    let observed = count.context("probe A edge count missing")?;
                    let k_now = startup_fence_repeats(&view.evidence, &caller);
                    let stale = round == 1 && observed == 0 && k_now == 0
                        || round > 1
                            && observed == expected_a(round - 1, fence_k.get())
                            && k_now == fence_k.get();
                    if !stale {
                        let prior = if round == 1 {
                            None
                        } else {
                            Some(fence_k.get())
                        };
                        let k =
                            check_startup_round(round, observed, &view.evidence, &caller, prior)?;
                        fence_k.set(k);
                        if round == 1 {
                            first_mapping.set(
                                a.unwrap()["mapping"]["last_seen_ns"]
                                    .as_u64()
                                    .context("first published mapping clock")?,
                            );
                        }
                        eprintln!(
                            "G21_STARTUP_PROBE_ROUND round={round} A={observed} k={k} caller={caller}"
                        );
                        if round < 3 {
                            workload.command("count", "a-done", round + 1)?;
                            state.set(awaiting + 1);
                        } else {
                            state.set(4);
                        }
                    }
                }
                _ => {}
            }
            Ok(state.get() == 4)
        };
        match advance() {
            Ok(done) => done,
            Err(error) => {
                *failure.borrow_mut() = Some(error);
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
        code == 0 && state.get() == 4,
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
    if edges.len() != 1 || edges[0]["mapping"]["state"] != "mapped" {
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
        edges.len() == 1 && edges[0]["mapping"]["state"] == "mapped",
        "actual final caller edge shape differs from the probe's one mapped provider"
    );
    let module = &edges[0]["module"];
    let public = edges[0]["entries"]["count"]
        .as_u64()
        .context("final A count")?;
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
    let facts = check_startup_probe_records(&records, public, pid, module, &intervals, k)?;
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
                    "pair":name,"seq":seq,"module_id":"mA","absolute":round,"base":round-1,
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

#[test]
fn operator_diagnostics_three_round_probe_checks_fence_and_physical_pair() -> Result<()> {
    let calls = [(90, 110), (130, 150), (170, 190)];
    let module = serde_json::json!("mA");
    let ordinary = startup_probe_validator_fixture(false);
    let fenced = startup_probe_validator_fixture(true);
    let ordinary_facts = check_startup_probe_records(&ordinary, 3, 123, &module, &calls, 0)?;
    ensure!(ordinary_facts["path"] == "ordinary" && ordinary_facts["fenced_pairs"] == 0);
    let fenced_facts = check_startup_probe_records(&fenced, 2, 123, &module, &calls, 32)?;
    ensure!(fenced_facts["path"] == "startup_fence" && fenced_facts["fenced_pairs"] == 32);
    // Round-grouped layout: header 0; round 1 rows 1..64; round 2 rows
    // 65..128 (first fence at 66); round 3 rows 129..192 (first recovery
    // at 130); footer 193.
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
    ] {
        let mut changed = fenced.clone();
        let mut primary = 2;
        let mut k = 32;
        match change {
            "second_pair" => changed[1]["pair"] = "p32".into(),
            "wrong_absolute" => changed[1]["absolute"] = 99.into(),
            "false_fence_reason" => changed[66]["reason"] = "identity_changed".into(),
            "false_fence_range" => changed[66]["after"] = 0.into(),
            "missing_recovery" => changed[130]["decision"] = "staged".into(),
            "wrong_baseline" => changed[130]["baseline_post"] = 159.into(),
            "wrong_reference" => changed[66]["observation_ref"]["seq"] = 1.into(),
            "wrong_primary" => primary = 3,
            "wrong_k" => k = 0,
            "raw_before_call" => changed[65]["post"] = 180.into(),
            "read_starts_before_return" => changed[1]["pre"] = 109.into(),
            _ => changed[193]["kinds"][0]["retained"] = 95.into(),
        }
        ensure!(
            check_startup_probe_records(&changed, primary, 123, &module, &calls, k).is_err(),
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
    // Pinned max-accepting trajectory (Sol): ordinary A is 1, 2, 3 after
    // rounds 1-3 and 400 after round 400 — never 32 per round.
    ensure!(expected_a(1, 0) == 1 && expected_a(2, 0) == 2 && expected_a(3, 0) == 3);
    ensure!(expected_a(400, 0) == 400);
    ensure!(check_startup_round(1, 1, &gaps, "c0", None)? == 0);
    ensure!(check_startup_round(2, 2, &gaps, "c0", Some(0))? == 0);
    ensure!(check_startup_round(3, 3, &gaps, "c0", Some(0))? == 0);
    ensure!(check_startup_round(400, 400, &gaps, "c0", Some(0))? == 0);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_fenced_pass() -> Result<()> {
    // Fenced path (Sol pinned trajectory): exact (1, 2] gap bound to this
    // caller on all 32 pairs; A reads 1, 1, 2 after rounds 1-3 and 399
    // after round 400, alongside the ordinary twin's 1, 2, 3 and 400.
    let gaps = vec![twin_startup_gap("c0", 32)];
    ensure!(startup_fence_repeats(&gaps, "c0") == 32);
    ensure!(expected_a(2, 32) == 1 && expected_a(3, 32) == 2);
    ensure!(expected_a(400, 32) == 399);
    let no_gap: Vec<GapEvidence> = Vec::new();
    ensure!(check_startup_round(1, 1, &no_gap, "c0", None)? == 0);
    ensure!(check_startup_round(2, 1, &gaps, "c0", Some(0))? == 32);
    ensure!(check_startup_round(3, 2, &gaps, "c0", Some(32))? == 32);
    ensure!(check_startup_round(4, 3, &gaps, "c0", Some(32))? == 32);
    ensure!(check_startup_round(400, 399, &gaps, "c0", Some(32))? == 32);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_underdelivery_fail() -> Result<()> {
    // Valid startup gap but a wrong round-3 edge (1 or 3 instead of the
    // pinned 2) must FAIL; so must any other deficit or surplus, and the
    // old summed values (64/96/12768/12800) must FAIL as over-delivery.
    let gaps = vec![twin_startup_gap("c0", 32)];
    ensure!(check_startup_round(3, 1, &gaps, "c0", Some(32)).is_err());
    ensure!(check_startup_round(3, 3, &gaps, "c0", Some(32)).is_err());
    ensure!(check_startup_round(3, 2, &[], "c0", Some(0)).is_err());
    ensure!(check_startup_round(3, 4, &[], "c0", Some(0)).is_err());
    ensure!(check_startup_round(3, 64, &gaps, "c0", Some(32)).is_err());
    ensure!(check_startup_round(3, 96, &[], "c0", Some(0)).is_err());
    ensure!(check_startup_round(2, 0, &gaps, "c0", Some(0)).is_err());
    ensure!(check_startup_round(2, 2, &gaps, "c0", Some(0)).is_err());
    ensure!(check_startup_round(400, 398, &gaps, "c0", Some(32)).is_err());
    ensure!(check_startup_round(400, 400, &gaps, "c0", Some(32)).is_err());
    ensure!(check_startup_round(400, 399, &[], "c0", Some(0)).is_err());
    ensure!(check_startup_round(400, 12768, &gaps, "c0", Some(32)).is_err());
    ensure!(check_startup_round(400, 12800, &[], "c0", Some(0)).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_missing_gap_fail() -> Result<()> {
    // A short round-2 count with no gap evidence must FAIL (never inferred).
    let gaps: Vec<GapEvidence> = Vec::new();
    ensure!(startup_fence_repeats(&gaps, "c0") == 0);
    ensure!(check_startup_round(2, 1, &gaps, "c0", Some(0)).is_err());
    ensure!(check_startup_round(2, 2, &gaps, "c0", Some(0))? == 0);
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_startup_misbound_gap_fail() -> Result<()> {
    // A (1, 2] gap bound to another caller, or to no caller, is not this
    // caller's fence evidence and must FAIL alongside the short count.
    let foreign = vec![twin_startup_gap("c9", 32)];
    ensure!(startup_fence_repeats(&foreign, "c0") == 0);
    ensure!(check_startup_round(2, 1, &foreign, "c0", Some(0)).is_err());
    let mut unbound = twin_startup_gap("c0", 32);
    unbound.caller = None;
    ensure!(startup_fence_repeats(&[unbound], "c0") == 0);
    ensure!(check_startup_round(2, 1, &[twin_startup_gap("c9", 32)], "c0", Some(0)).is_err());
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
    ensure!(check_startup_round(2, 1, &[wrong_range], "c0", Some(0)).is_err());
    let partial = vec![twin_startup_gap("c0", 16)];
    ensure!(check_startup_round(2, 1, &partial, "c0", Some(0)).is_err());
    ensure!(check_startup_round(2, 2, &partial, "c0", Some(0)).is_err());
    // Unstable fence count between rounds must FAIL.
    let full = vec![twin_startup_gap("c0", 32)];
    ensure!(check_startup_round(3, 2, &full, "c0", Some(0)).is_err());
    ensure!(check_startup_round(3, 3, &full, "c0", Some(32)).is_err());
    Ok(())
}

/// Twin helper: terminal proof/fence records for 32 distinct pairs, with
/// the full retained boundary premise: caller identity, fence absolute,
/// single-publication edge_total, retained observation refs and a strictly
/// later recovery window (fence POST 7010 < proof PRE 7020).
fn twin_terminal_records() -> Vec<serde_json::Value> {
    let mut records = Vec::new();
    for index in 0..32 {
        records.push(
            serde_json::json!({"kind":"count_decision","decision":"withheld",
            "pair":format!("p{index}"),"reason":"awaiting_fence",
            "after":658,"through":659,"absolute":659,
            "caller":"c0","pre":7000,"post":7010,
            "observation_ref":{"seq":1000+index,"status":"retained"}}),
        );
        records.push(serde_json::json!({"kind":"publication","decision":"placed",
            "module_id":"mB","pair":format!("p{index}"),
            "base":659,"absolute":660,"staged":1,"edge_total":1,
            "caller":"c0","pre":7020,"post":7030,
            "baseline_pre":7000,"baseline_post":7010,
            "observation_ref":{"seq":2000+index,"status":"retained"}}));
    }
    records
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_32pair_pass() -> Result<()> {
    // Unit correction (Sol correction 2): 32 genuinely distinct pairs with
    // per-pair fence/proof 659/660/1; aggregates recover Sol's 21,088/21,120
    // fence/proof absolutes with staged growth 32.
    let records = twin_terminal_records();
    let (fence_sum, proof_sum, staged_sum) =
        check_terminal_pairs(&records, &serde_json::json!("mB"))?;
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
    ensure!(check_terminal_pairs(&single, &serde_json::json!("mB")).is_err());
    // 31 pairs are not 32.
    let mut short = twin_terminal_records();
    short.truncate(62);
    ensure!(check_terminal_pairs(&short, &serde_json::json!("mB")).is_err());
    // Duplicated pair identity is not distinctness.
    let mut dup = twin_terminal_records();
    dup[62]["pair"] = serde_json::json!("p0");
    dup[63]["pair"] = serde_json::json!("p0");
    ensure!(check_terminal_pairs(&dup, &serde_json::json!("mB")).is_err());
    // Wrong per-pair values rejected.
    let mut wrong = twin_terminal_records();
    wrong[1]["staged"] = serde_json::json!(2);
    ensure!(check_terminal_pairs(&wrong, &serde_json::json!("mB")).is_err());
    let mut wrong_base = twin_terminal_records();
    wrong_base[1]["base"] = serde_json::json!(658);
    ensure!(check_terminal_pairs(&wrong_base, &serde_json::json!("mB")).is_err());
    // Wrong module rejected.
    let other_module = twin_terminal_records();
    ensure!(check_terminal_pairs(&other_module, &serde_json::json!("mA")).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_requires_single_publication() -> Result<()> {
    // The B=1 projection is sound only if all 32 proofs overlap in one
    // publication (edge_total == 1 on every proof). A split recovery
    // (edge_total 2) or a missing projection must FAIL.
    let mut split = twin_terminal_records();
    for row in split.iter_mut().skip(1).step_by(2) {
        row["edge_total"] = serde_json::json!(2);
    }
    // skip(1).step_by(2) hits odd indices (proofs): verify the premise.
    ensure!(split[1]["edge_total"] == 2 && split[3]["edge_total"] == 2);
    ensure!(split[0].get("edge_total").is_none());
    ensure!(check_terminal_pairs(&split, &serde_json::json!("mB")).is_err());
    let mut missing = twin_terminal_records();
    for row in missing.iter_mut().skip(1).step_by(2) {
        row.as_object_mut().unwrap().remove("edge_total");
    }
    ensure!(missing[1].get("edge_total").is_none());
    ensure!(check_terminal_pairs(&missing, &serde_json::json!("mB")).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_requires_retained_refs() -> Result<()> {
    // Retained boundary observations must back every fence and proof: a
    // lost or missing observation ref must FAIL, never pass silently.
    let mut lost_proof = twin_terminal_records();
    lost_proof[1]["observation_ref"]["status"] = serde_json::json!("not_retained");
    ensure!(check_terminal_pairs(&lost_proof, &serde_json::json!("mB")).is_err());
    let mut lost_fence = twin_terminal_records();
    lost_fence[0]["observation_ref"]["status"] = serde_json::json!("not_retained");
    ensure!(check_terminal_pairs(&lost_fence, &serde_json::json!("mB")).is_err());
    let mut missing = twin_terminal_records();
    missing[1]
        .as_object_mut()
        .unwrap()
        .remove("observation_ref");
    ensure!(check_terminal_pairs(&missing, &serde_json::json!("mB")).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_requires_later_recovery() -> Result<()> {
    // Recovery needs a strictly later advancing read: the proof window
    // must open after the fence window closes (baseline_post < pre).
    let mut simultaneous = twin_terminal_records();
    simultaneous[1]["baseline_post"] = serde_json::json!(7020);
    ensure!(check_terminal_pairs(&simultaneous, &serde_json::json!("mB")).is_err());
    let mut backwards = twin_terminal_records();
    backwards[1]["baseline_post"] = serde_json::json!(7035);
    ensure!(check_terminal_pairs(&backwards, &serde_json::json!("mB")).is_err());
    let mut missing = twin_terminal_records();
    missing[1].as_object_mut().unwrap().remove("baseline_post");
    ensure!(check_terminal_pairs(&missing, &serde_json::json!("mB")).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_rejects_overlapping_placement() -> Result<()> {
    // No B placement may overlap a withheld fence interval: a (658,660]
    // double-placement on p0 must FAIL even though the exact proof exists.
    let mut doubled = twin_terminal_records();
    doubled.push(serde_json::json!({"kind":"publication","decision":"placed",
        "module_id":"mB","pair":"p0","base":658,"absolute":660,"staged":2,
        "edge_total":2,"caller":"c0","pre":7020,"post":7030,
        "baseline_pre":7000,"baseline_post":7010,
        "observation_ref":{"seq":2000,"status":"retained"}}));
    ensure!(check_terminal_pairs(&doubled, &serde_json::json!("mB")).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_rejects_extra_b_placement() -> Result<()> {
    // B must carry exactly the 32 proofs: any extra placement, even outside
    // the fence interval, must FAIL (early or foreign attribution).
    let mut extra = twin_terminal_records();
    extra.push(serde_json::json!({"kind":"publication","decision":"placed",
        "module_id":"mB","pair":"p0","base":660,"absolute":661,"staged":1,
        "edge_total":2,"caller":"c0","pre":7040,"post":7050,
        "baseline_pre":7020,"baseline_post":7030,
        "observation_ref":{"seq":2000,"status":"retained"}}));
    ensure!(check_terminal_pairs(&extra, &serde_json::json!("mB")).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_requires_caller_identity() -> Result<()> {
    // All 32 fences and proofs must share one caller: a foreign proof and
    // a fence with the wrong absolute must FAIL.
    let mut foreign = twin_terminal_records();
    foreign[1]["caller"] = serde_json::json!("c9");
    ensure!(check_terminal_pairs(&foreign, &serde_json::json!("mB")).is_err());
    let mut wrong_absolute = twin_terminal_records();
    wrong_absolute[0]["absolute"] = serde_json::json!(660);
    ensure!(check_terminal_pairs(&wrong_absolute, &serde_json::json!("mB")).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_terminal_rejects_compensating_absolutes() -> Result<()> {
    // Per-pair exactness, not aggregate sums: one proof at 659 and another
    // at 661 keeps the 21,120 sum but must FAIL.
    let mut compensating = twin_terminal_records();
    compensating[1]["absolute"] = serde_json::json!(659);
    compensating[3]["absolute"] = serde_json::json!(661);
    ensure!(check_terminal_pairs(&compensating, &serde_json::json!("mB")).is_err());
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
    ensure!(check_wrap_records(&healthy, bytes, &serde_json::json!("mB"), 123).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_probe_double_placed_fence_fails() -> Result<()> {
    // A fenced pair's withheld second unit cannot also be placed: adding a
    // placed (2,1) publication alongside the p0 fence must FAIL.
    let calls = [(90, 110), (130, 150), (170, 190)];
    let module = serde_json::json!("mA");
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
        "pair":"p0","seq":max_seq+1,"module_id":"mA","absolute":2,"base":1,
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
    ensure!(check_startup_probe_records(&fenced, 2, 123, &module, &calls, 32).is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_primary_facts_rejects_wrong_b() -> Result<()> {
    // B is exactly 1 (32 overlapping proofs in one publication): 0, 2 and
    // the old summed 32 must FAIL under both dispositions.
    for k in [0, 32] {
        for wrong in [0, 2, 32] {
            let mut altered = primary_validator_fixture_k(123, 0, k);
            altered["edges"][1]["entries"]["count"] = serde_json::json!(wrong);
            ensure!(
                primary_facts_k(&altered, 123, k).is_err(),
                "wrong B accepted: k={k} B={wrong}"
            );
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
        ("provider-A.so", 399),
        ("provider-A.so", 401),
        ("provider-B.so", 0),
        ("provider-B.so", 2),
    ] {
        let mut on = off.clone();
        on["edges"][edge]["count"] = serde_json::json!(count);
        ensure!(
            check_paired_parity(&off, 0, &on, 0).is_err(),
            "altered primary accepted: {edge}={count}"
        );
    }
    let mut bad = off.clone();
    bad["edges"]["provider-A.so"]["count"] = serde_json::json!(399);
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
    let gaps = vec![twin_ambiguity_gap("m0", 128), twin_ambiguity_gap("m1", 128)];
    ensure!(ambiguity_repeats(&gaps, "m0") == 128);
    ensure!(ambiguity_repeats(&gaps, "m1") == 128);
    ensure!(ambiguity_repeats(&gaps, "m2") == 0);
    // Power-of-two rounds gate exactly.
    check_shared_checkpoint(4, &gaps, "m0", "m1")?;
    check_shared_checkpoint(
        1,
        &[twin_ambiguity_gap("m0", 32), twin_ambiguity_gap("m1", 32)],
        "m0",
        "m1",
    )?;
    // Short or asymmetric repeats fail at checkpoints.
    ensure!(
        check_shared_checkpoint(
            4,
            &[twin_ambiguity_gap("m0", 64), twin_ambiguity_gap("m1", 64)],
            "m0",
            "m1"
        )
        .is_err()
    );
    ensure!(check_shared_checkpoint(4, &[twin_ambiguity_gap("m0", 128)], "m0", "m1").is_err());
    ensure!(
        check_shared_checkpoint(
            4,
            &[twin_ambiguity_gap("m0", 128), twin_ambiguity_gap("m1", 64)],
            "m0",
            "m1"
        )
        .is_err()
    );
    // Non-power rounds pass through (mid-run lower bounds cannot gate).
    check_shared_checkpoint(3, &gaps, "m0", "m1")?;
    check_shared_checkpoint(258, &gaps, "m0", "m1")?;
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
    // A reads exactly the pinned edge (400 ordinary, 399 fenced) and B
    // reads exactly 1 (32 overlapping proof units published together).
    let ordinary = primary_facts_k(&primary_validator_fixture_k(123, 0, 0), 123, 0)?;
    ensure!(ordinary["edges"]["provider-A.so"]["count"] == 400);
    ensure!(ordinary["edges"]["provider-B.so"]["count"] == 1);
    let fenced = primary_facts_k(&primary_validator_fixture_k(123, 0, 32), 123, 32)?;
    ensure!(fenced["edges"]["provider-A.so"]["count"] == 399);
    ensure!(fenced["edges"]["provider-B.so"]["count"] == 1);
    // Crossed dispositions fail: neither leg may borrow the other's count.
    ensure!(primary_facts_k(&primary_validator_fixture_k(123, 0, 32), 123, 0).is_err());
    ensure!(primary_facts_k(&primary_validator_fixture_k(123, 0, 0), 123, 32).is_err());
    // Loss counters and lossy coverage fail under both dispositions.
    for k in [0, 32] {
        let mut loss = primary_validator_fixture_k(123, 0, k);
        loss["observation"]["lifecycle"]["ring_loss"] = 1.into();
        ensure!(primary_facts_k(&loss, 123, k).is_err());
        let mut lossy = primary_validator_fixture_k(123, 0, k);
        lossy["edges"][1]["entries"]["coverage"]["lossy"] = true.into();
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
    let edge_a = serde_json::json!({"kind":"edge_observed","event":{
        "entries":{"count":1},"presence":"mapped","capture":"armed",
        "identity_context":{"caller":{"id":"c0","pid":123},
            "module":{"id":"m1","path":"/owned/provider-A.so"}}}});
    let gap = serde_json::json!({"kind":"gap_recorded","event":{
        "index":0,"caller":"c0","module":null,"pid":null,
        "subject":"rejected demoted count",
        "reason":"the current physical owner is not proven for absolute count range (1, 2] (1 unattributed calls); x",
        "budget":null}});
    let repeated = serde_json::json!({"kind":"gap_repeated","event":{"index":0,"repeats":32}});
    let committed = serde_json::json!({"kind":"pass_committed","event":{"pass":1}});
    std::fs::write(&path, format!("{edge_a}\n{gap}\n{repeated}\n{committed}\n"))?;
    let mut view = PassView::default();
    ensure!(view.refresh(&path, 123)?);
    ensure!(view.a.is_some());
    ensure!(view.caller_id.as_deref() == Some("c0"));
    ensure!(view.module_a.as_deref() == Some("m1"));
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
        serde_json::json!({"kind":"gap_repeated","event":{"index":9,"repeats":99}})
    )?;
    writeln!(
        file,
        "{}",
        serde_json::json!({"kind":"pass_committed","event":{"pass":3}})
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

/// The wrap fixture's 35 prebuilt inputs: 32 distinct common objects plus
/// the two providers and the workload driver.
fn wrap_prebuilt_files() -> Vec<String> {
    (0..32)
        .map(|index| format!("libdemotion-common-{index:02}.so"))
        .chain([
            "provider-A.so".to_owned(),
            "provider-B.so".to_owned(),
            "workload".to_owned(),
        ])
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
fn operator_diagnostics_wrap_twin_wrap_prebuilt_copies_35_files() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let files = wrap_prebuilt_files();
    ensure!(files.len() == 35);
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
    check_wrap_records_system(&records, bytes, &serde_json::json!("mB"), 123, "c0")?;
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
    ensure!(
        check_wrap_records_system(&pid_scope, bytes, &serde_json::json!("mB"), 123, "c0").is_err()
    );
    let (mut filtered, _) = diagnostic_validator_fixture_system(123, "c0");
    filtered[0]["pid_filter"] = serde_json::json!(123);
    let bytes = seal_validator_fixture(&mut filtered);
    ensure!(
        check_wrap_records_system(&filtered, bytes, &serde_json::json!("mB"), 123, "c0").is_err()
    );
    let (mut missing, _) = diagnostic_validator_fixture_system(123, "c0");
    missing[0].as_object_mut().unwrap().remove("pid_filter");
    let bytes = seal_validator_fixture(&mut missing);
    ensure!(
        check_wrap_records_system(&missing, bytes, &serde_json::json!("mB"), 123, "c0").is_err()
    );
    let (mut mode, _) = diagnostic_validator_fixture_system(123, "c0");
    mode[0]["mode"] = serde_json::json!("auto");
    let bytes = seal_validator_fixture(&mut mode);
    ensure!(check_wrap_records_system(&mode, bytes, &serde_json::json!("mB"), 123, "c0").is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_export_rejects_foreign_pid() -> Result<()> {
    // Owned-caller validation: any pid-bearing row outside the owned PID
    // fails — on ordinary rows and on terminal proofs alike — as does a
    // missing PID on a non-health row or a PID on the global health row.
    let module = serde_json::json!("mB");
    let (records, _) = diagnostic_validator_fixture_system(123, "c0");
    let proofs = twin_system_proof_positions(&records);
    ensure!(proofs.len() == 32);
    let mut foreign_row = records.clone();
    foreign_row[1]["pid"] = serde_json::json!(999);
    let bytes = seal_validator_fixture(&mut foreign_row);
    ensure!(check_wrap_records_system(&foreign_row, bytes, &module, 123, "c0").is_err());
    let mut foreign_proof = records.clone();
    foreign_proof[proofs[0]]["pid"] = serde_json::json!(999);
    let bytes = seal_validator_fixture(&mut foreign_proof);
    ensure!(check_wrap_records_system(&foreign_proof, bytes, &module, 123, "c0").is_err());
    let mut missing_pid = records.clone();
    missing_pid[1].as_object_mut().unwrap().remove("pid");
    let bytes = seal_validator_fixture(&mut missing_pid);
    ensure!(check_wrap_records_system(&missing_pid, bytes, &module, 123, "c0").is_err());
    let health = records
        .iter()
        .position(|row| row["kind"] == "capture_health")
        .context("health row")?;
    let mut health_pid = records.clone();
    health_pid[health]["pid"] = serde_json::json!(123);
    let bytes = seal_validator_fixture(&mut health_pid);
    ensure!(check_wrap_records_system(&health_pid, bytes, &module, 123, "c0").is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_export_rejects_foreign_caller() -> Result<()> {
    // Terminal proofs must bind the live-observed owned caller id: a
    // consistently foreign caller fails the owned pin even with the owned
    // PID, while the matching pin passes the same export.
    let module = serde_json::json!("mB");
    let (foreign, bytes) = diagnostic_validator_fixture_system(123, "c9");
    ensure!(check_wrap_records_system(&foreign, bytes, &module, 123, "c0").is_err());
    check_wrap_records_system(&foreign, bytes, &module, 123, "c9")?;
    // A single foreign proof among owned ones fails on consistency too.
    let (mut mixed, _) = diagnostic_validator_fixture_system(123, "c0");
    let proofs = twin_system_proof_positions(&mixed);
    ensure!(proofs.len() == 32);
    mixed[proofs[0]]["caller"] = serde_json::json!("c9");
    let bytes = seal_validator_fixture(&mut mixed);
    ensure!(check_wrap_records_system(&mixed, bytes, &module, 123, "c0").is_err());
    Ok(())
}

#[test]
fn operator_diagnostics_wrap_twin_system_export_requires_wrap_properties() -> Result<()> {
    // The system validator inherits every fail-closed wrap property:
    // single-publication proofs, retained references, advancing
    // recovery windows, and a real both-ring wrap.
    let module = serde_json::json!("mB");
    let (records, _) = diagnostic_validator_fixture_system(123, "c0");
    let proofs = twin_system_proof_positions(&records);
    ensure!(proofs.len() == 32);
    for change in [
        "split_publication",
        "lost_reference",
        "stale_window",
        "one_ring_wrap",
    ] {
        let mut altered = records.clone();
        match change {
            "split_publication" => {
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
            check_wrap_records_system(&altered, bytes, &module, 123, "c0").is_err(),
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
        ensure!(facts["edges"]["provider-A.so"]["count"] == expected_a(COUNTED, k));
        ensure!(facts["edges"]["provider-B.so"]["count"] == 1);
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
    borrowed["edges"][2]["module"] = borrowed["modules"][1]["id"].clone();
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
    wrong_b["edges"][1]["entries"]["count"] = serde_json::json!(2);
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
