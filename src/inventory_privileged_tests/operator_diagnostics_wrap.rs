// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned32-body physical entry-count gate. No semantic/API/104-slot claim.
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
        use std::os::unix::fs::OpenOptionsExt;
        let source = std::env::var_os("P11SCOPE_DIAGNOSTICS_WRAP_PREBUILT_DIR")
            .context("supply the controller-verified prebuilt32-body fixture directory")?;
        let dir = tempfile::tempdir()?;
        copy_demotion_prebuilt(Path::new(&source), dir.path())?;
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
                dir.path().join("libdemotion-common.so"),
                fifo.clone(),
                dir.path().join("calls.jsonl"),
            ])
            .args(["0123456789abcdef0123456789abcdef", "900000", "400", "258"])
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
    gaps: BTreeSet<String>,
}
impl PassView {
    fn refresh(&mut self, path: &Path, pid: u32) -> Result<bool> {
        let rows = new_lines(path, &mut self.offset)?;
        for row in &rows {
            let event = &row["event"];
            if row["kind"] == "edge_observed" && event["identity_context"]["caller"]["pid"] == pid {
                if let Some(path) = event["identity_context"]["module"]["path"].as_str() {
                    if path.ends_with("provider-A.so") {
                        self.a = Some(event.clone());
                    }
                    if path.ends_with("provider-B.so") {
                        self.b = Some(event.clone());
                    }
                }
            }
            if row["kind"] == "gap_recorded"
                && event["subject"] == "rejected demoted count"
                && let Some(reason) = event["reason"].as_str()
            {
                self.gaps.insert(reason.to_owned());
            }
        }
        Ok(rows
            .last()
            .is_some_and(|row| row["kind"] == "pass_committed"))
    }
    fn withheld_through(&self, absolute: u64) -> bool {
        self.gaps
            .iter()
            .any(|reason| reason.contains(&format!(", {absolute}]")))
    }
}

fn check_native_ledger(workload: &WrapWorkload) -> Result<()> {
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
    let common_file = std::fs::File::open(workload.dir.path().join("libdemotion-common.so"))?;
    let mapped = crate::discovery::identity::self_mapped_identity(&common_file)
        .map_err(anyhow::Error::msg)?;
    let common = common_file.metadata()?;
    use std::os::unix::fs::MetadataExt;
    ensure!(targets.iter().all(|row| {
        row["ino"] == common.ino()
            && row["dev_major"] == u64::from(libc::major(mapped.dev))
            && row["dev_minor"] == u64::from(libc::minor(mapped.dev))
            && row["offset"]
                .as_u64()
                .is_some_and(|offset| offset < common.len())
    }));
    let calls: Vec<_> = rows.iter().filter(|row| row["kind"] == "call").collect();
    ensure!(calls.len() as u64 == (COUNTED + SHARED + 2) * TARGETS);
    let schedule = [
        ("a", COUNTED),
        ("shared", SHARED),
        ("fence", 1),
        ("proof", 1),
    ];
    let acknowledgements = jsonl_records(&workload.process.out)?;
    let mut sequence = 0usize;
    let mut previous = identity["ready_ns"]
        .as_u64()
        .context("native ready clock")?;
    for (phase, rounds) in schedule {
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
    ensure!(header["scope"] == "pid" && header["mode"] == "native" && header["pid_filter"] == pid);
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
    let mut placements = BTreeSet::new();
    let mut fence_withheld = BTreeSet::new();
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
        if row["decision"] == "placed"
            && row["module_id"] == *b_module
            && row["base"] == COUNTED + SHARED + 1
            && row["absolute"] == COUNTED + SHARED + 2
            && row["staged"] == 1
        {
            placements.insert(row["pair"].as_str().context("placed pair")?.to_owned());
        }
        if row["decision"] == "withheld"
            && row["reason"] == "awaiting_fence"
            && row["after"] == COUNTED + SHARED
            && row["through"] == COUNTED + SHARED + 1
        {
            fence_withheld.insert(row["pair"].as_str().context("withheld pair")?.to_owned());
        }
    }
    ensure!(
        placements.len() == 32 && fence_withheld == placements && missing_context,
        "all32 real pairs need recent withheld-prefix/recovery and truthful lost-history context"
    );
    eprintln!(
        "G21_WRAP ordinary_produced_lower_bound={} exceptional_produced_lower_bound={} records={}",
        24576 + ordinary_evicted,
        8192 + exceptional_evicted,
        records.len() - 2
    );
    Ok(())
}

fn primary_facts(document: &serde_json::Value, pid: u32) -> Result<serde_json::Value> {
    ensure!(document["observation"]["lane"] == "native" && !ab_lifecycle_loss_detected(document));
    let edges = doc_edges(document, pid);
    ensure!(edges.len() == 2);
    let modules = document["modules"].as_array().context("primary modules")?;
    let mut facts = BTreeMap::new();
    for edge in edges {
        let module = modules
            .iter()
            .find(|module| module["id"] == edge["module"])
            .context("edge module")?;
        let label = ["provider-A.so", "provider-B.so"]
            .into_iter()
            .find(|suffix| {
                module["paths"].as_array().is_some_and(|paths| {
                    paths
                        .iter()
                        .any(|path| path.as_str().is_some_and(|path| path.ends_with(suffix)))
                })
            })
            .context("owned module label")?;
        let expected = if label == "provider-A.so" {
            COUNTED * TARGETS
        } else {
            TARGETS
        };
        ensure!(edge["entries"]["count"] == expected);
        if label == "provider-B.so" {
            ensure!(
                edge["entries"]["coverage"]["state"] == "counted"
                    && edge["entries"]["coverage"]["lossy"] == false
            );
        }
        facts.insert(label, serde_json::json!({"presence":edge["presence"], "capture":edge["capture"],
            "count":edge["entries"]["count"], "observation":edge["entries"]["observation"],
            "saturated":edge["entries"]["saturated"], "in_flight":edge["entries"]["in_flight"],
            "cap":edge["entries"]["cap"],
            "coverage_state":edge["entries"]["coverage"]["state"], "lossy":edge["entries"]["coverage"]["lossy"]}));
    }
    Ok(
        serde_json::json!({"edges":facts,"lane":document["observation"]["lane"],"settlement":document["observation"]["settlement"]}),
    )
}

fn run_wrap(enabled: bool) -> Result<serde_json::Value> {
    let mut workload = WrapWorkload::spawn()?;
    workload.check_mapping("provider-A.so")?;
    workload.check_mapping("libdemotion-common.so")?;
    let events = workload.dir.path().join("events.jsonl");
    let diagnostics = workload.dir.path().join("diagnostics.jsonl");
    let pid = workload.process.pid();
    let start = Instant::now();
    let state = Cell::new((0u8, 0u64));
    let view = RefCell::new(PassView::default());
    let failure = RefCell::new(None::<anyhow::Error>);
    let stop = || {
        let advance = || -> Result<bool> {
            ensure!(
                start.elapsed() < Duration::from_secs(RUN_SECONDS),
                "G21 wrap exceeded900s, phase={:?}",
                state.get()
            );
            if state.get().0 == 7 {
                return Ok(true);
            }
            let mut view = view.borrow_mut();
            if !view.refresh(&events, pid)? {
                return Ok(false);
            }
            let armed = |edge: Option<&serde_json::Value>| {
                edge.is_some_and(|edge| edge["capture"] == "armed" && edge["presence"] == "mapped")
            };
            match state.get() {
                (0, _) if armed(view.a.as_ref()) => {
                    workload.command("ready", "ready", 0)?;
                    workload.command("count", "a-done", 1)?;
                    state.set((1, 1));
                }
                (1, round)
                    if view
                        .a
                        .as_ref()
                        .is_some_and(|edge| edge["entries"]["count"] == round * TARGETS) =>
                {
                    if round < COUNTED {
                        workload.command("count", "a-done", round + 1)?;
                        state.set((1, round + 1));
                    } else {
                        workload.command("load-b", "b-ready", 0)?;
                        workload.check_mapping("provider-B.so")?;
                        state.set((2, 0));
                    }
                }
                (2, _) if armed(view.b.as_ref()) => {
                    workload.command("shared", "shared-done", 1)?;
                    state.set((3, 1));
                }
                (3, round) if view.withheld_through(COUNTED + round) => {
                    ensure!(
                        view.a
                            .as_ref()
                            .is_some_and(|edge| edge["entries"]["count"] == COUNTED * TARGETS)
                            && view
                                .b
                                .as_ref()
                                .is_some_and(|edge| edge["entries"]["count"] == 0),
                        "shared calls escaped withholding"
                    );
                    if round < SHARED {
                        workload.command("shared", "shared-done", round + 1)?;
                        state.set((3, round + 1));
                    } else {
                        workload.command("unload-a", "a-unmapped", 0)?;
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
                    state.set((5, 0));
                }
                (5, _) if view.withheld_through(COUNTED + SHARED + 1) => {
                    workload.command("proof", "final-calls", 1)?;
                    state.set((6, 0));
                }
                (6, _)
                    if view
                        .b
                        .as_ref()
                        .is_some_and(|edge| edge["entries"]["count"] == TARGETS) =>
                {
                    state.set((7, 0))
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
        InspectScope::Pid(pid),
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
            pid_filter: Some(pid),
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
    let document: serde_json::Value = serde_json::from_slice(&stdout)?;
    let facts = primary_facts(&document, pid)?;
    if enabled {
        let b = doc_edges(&document, pid)
            .into_iter()
            .find(|edge| edge["entries"]["count"] == TARGETS)
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
        check_wrap_records(&records, length, &b["module"], pid)?;
    } else {
        ensure!(!diagnostics.exists());
    }
    eprintln!(
        "G21_PAIRED enabled={enabled} elapsed_ms={} calls={} A={} B={} withheld={} stdout_bytes={}",
        start.elapsed().as_millis(),
        (COUNTED + SHARED + 2) * TARGETS,
        COUNTED * TARGETS,
        TARGETS,
        (SHARED + 1) * TARGETS,
        stdout.len()
    );
    Ok(facts)
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
#[ignore = "root-owned BPF lane; prebuilt32-body fixture, paired default-ring wrap (~22min)"]
fn privileged_native_lane_pid_diagnostics_wrap_and_primary_parity_lp64() -> Result<()> {
    let disabled = run_wrap(false)?;
    let enabled = run_wrap(true)?;
    ensure!(
        disabled == enabled,
        "diagnostics changed primary count/coverage/loss facts: off={disabled}, on={enabled}"
    );
    Ok(())
}
