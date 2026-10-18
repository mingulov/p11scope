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
        Self::spawn_profile(false)
    }
    fn spawn_profile(probe: bool) -> Result<Self> {
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
    let common_file = std::fs::File::open(workload.dir.path().join("libdemotion-common.so"))?;
    // The native fixture reports lexical /proc/maps device identity. A
    // map_files stat (self_mapped_identity) is the separate opened-file domain
    // and can have a different per-subvolume device on Btrfs.
    let mapped = p11scope_manifest::identity::kernel_maps_key_for(
        &common_file,
        &mut p11scope_manifest::identity::UnboundedProbeBudget,
    )
    .context("held common fixture kernel maps key")?;
    check_native_target_mapping(&targets, mapped, common_file.metadata()?.len())?;
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

fn primary_facts(document: &serde_json::Value, pid: u32) -> Result<serde_json::Value> {
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
    let callers = document["callers"].as_array().context("primary callers")?;
    ensure!(
        callers.len() == 1
            && callers[0]["pid"] == pid
            && callers[0]["lifecycle"] == "mapped"
            && callers[0]["retired"] == false
    );
    let caller = &callers[0];
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
        let expected = if a { COUNTED * TARGETS } else { TARGETS };
        let entries = &edge["entries"];
        let coverage = &entries["coverage"];
        ensure!(
            entries["count"] == expected
                && entries["observation"] == "observed"
                && entries["saturated"] == false
                && entries["in_flight"] == false
                && entries["cap"].as_u64().is_some()
        );
        let expected_presence = if a { "unloaded" } else { "mapped" };
        let expected_capture = if a { "retired" } else { "armed" };
        ensure!(
            edge["presence"] == expected_presence
                && edge["capture"] == expected_capture
                && module["lifecycle"] == expected_presence
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
        let value = serde_json::json!({"presence":edge["presence"],"capture":edge["capture"],
            "mapping_state":mapping["state"],"mapping_evidence":mapping["evidence"],
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
    Ok(
        serde_json::json!({"edges":facts,"lane":observation["lane"],"settlement":observation["settlement"],
        "retirement":observation["retirement"],"caller_lifecycle":caller["lifecycle"],
        "caller_lifecycle_reason":caller["lifecycle_reason"],"caller_retired":caller["retired"],
        "lifecycle_failures":{"ring_loss":lifecycle["ring_loss"],"malformed":lifecycle["malformed"],
            "failed_quanta":lifecycle["failed_quanta"],"recovery_rescans":lifecycle["recovery_rescans"]},
        "native_failure_facts":{"integrity":witnesses["integrity"],"pending":witnesses["pending"],
            "unbound_reasons":witnesses["unbound_reasons"],"ambiguous":witnesses["placement"]["ambiguous"],
            "unresolved":witnesses["placement"]["unresolved"]}}),
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

/// Host-only validator documents. These do not constitute installed capture or
/// wrap evidence; the ignored gate always reads the actual product output.
fn primary_validator_fixture(pid: u32, shift: u64) -> serde_json::Value {
    let caller = format!("c{shift}");
    let a = format!("m{}", shift + 1);
    let b = format!("m{}", shift + 2);
    let edge = |module: &str, is_a: bool| {
        serde_json::json!({
            "caller":caller,"module":module,
            "presence":if is_a {"unloaded"} else {"mapped"},
            "capture":if is_a {"retired"} else {"armed"},
            "mapping":{"state":if is_a {"ended"} else {"mapped"},"evidence":"deep_scan", "reason":null,
                "interruptions":0,"first_seen_ns":100+shift,"last_seen_ns":200+shift},
            "entries":{"count":if is_a {COUNTED*TARGETS} else {TARGETS},"saturated":false,
                "cap":u64::MAX,"in_flight":false,"observation":"observed",
                "first_seen_ns":120+shift,"last_seen_ns":180+shift,
                "coverage":{"state":if is_a {"unknown"} else {"counted"},
                    "reason":if is_a {serde_json::json!("not_attached")} else {serde_json::Value::Null},
                    "detail":null,"lossy":if is_a {serde_json::Value::Null} else {serde_json::json!(false)},
                    "since_ns":if is_a {serde_json::Value::Null} else {serde_json::json!(110+shift)},
                    "until_ns":null,"first_ns":null}}
        })
    };
    serde_json::json!({
        "observation":{"lane":"native","settlement":"unsettled","retirement":"closed",
            "lifecycle":{"records":shift+10,"ring_loss":0,"malformed":0,"failed_quanta":0,"recovery_rescans":0},
            "native_witnesses":{"rows":shift+20,"bound":shift+20,"unbound":0,"pending":0,"integrity":0,
                "unbound_reasons":{},"placement":{"edge":shift+20,"module":0,"ambiguous":0,"unresolved":0}}},
        "callers":[{"id":caller,"pid":pid,"lifecycle":"mapped","retired":false,"lifecycle_reason":null}],
        "modules":[{"id":a,"paths":["/owned/provider-A.so"],"lifecycle":"unloaded","unloaded_observed":true},
            {"id":b,"paths":["/owned/provider-B.so"],"lifecycle":"mapped","unloaded_observed":false}],
        "edges":[edge(&a,true),edge(&b,false)],"gaps":[]
    })
}

#[test]
fn operator_diagnostics_wrap_primary_validator_preserves_meaningful_facts() -> Result<()> {
    let healthy = primary_validator_fixture(123, 0);
    let expected = primary_facts(&healthy, 123)?;
    ensure!(
        expected == primary_facts(&primary_validator_fixture(456, 500), 456)?,
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
            primary_facts(&altered, 123)? != expected,
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
        "presence",
        "capture",
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
            "presence" => altered["edges"][0]["presence"] = "mapped".into(),
            "capture" => altered["edges"][0]["capture"] = "armed".into(),
            "loss" => altered["edges"][0]["entries"]["coverage"]["reason"] = "loss".into(),
            _ => altered["edges"][1]["entries"]["coverage"]["lossy"] = true.into(),
        }
        ensure!(
            primary_facts(&altered, 123).is_err(),
            "invalid primary capture accepted: {change}"
        );
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
        }
        push(row);
    }
    for index in 0..32 {
        push(
            serde_json::json!({"kind":"publication","decision":"placed","module_id":"mB",
        "pair":format!("p{index}"),"base":COUNTED+SHARED+1,"absolute":COUNTED+SHARED+2,"staged":1,
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

/// Validate the small probe's actual dispositions independently of its progress
/// predicates. Offset diversity is not pair diversity: this fixture has ONE pair.
fn check_startup_probe_records(
    records: &[serde_json::Value],
    public_count: u64,
    pid: u32,
    module: &serde_json::Value,
    calls: &[(u64, u64)],
) -> Result<serde_json::Value> {
    ensure!(calls.len() == 3);
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
        observations.len() == 3,
        "probe needs exactly three changing native observations"
    );
    let pair = observations[0]["pair"].as_str().context("probe pair")?;
    let pairs: BTreeSet<_> = records
        .iter()
        .filter_map(|row| row["pair"].as_str())
        .collect();
    ensure!(
        pairs == BTreeSet::from([pair]),
        "32 offsets must remain one physical pair"
    );
    for (index, row) in observations.iter().enumerate() {
        ensure!(row["pid"] == pid && row["absolute"] == (index as u64 + 1) * 32);
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
    }
    let placed = |absolute: u64, base: u64| -> Vec<&serde_json::Value> {
        records
            .iter()
            .filter(|row| {
                row["kind"] == "publication"
                    && row["decision"] == "placed"
                    && row["pair"] == pair
                    && row["module_id"] == *module
                    && row["absolute"] == absolute
                    && row["base"] == base
                    && row["staged"] == 32
                    && row["reason"] == "sole_owner"
                    && row["observation_ref"]["seq"]
                        == observations[(absolute / 32 - 1) as usize]["seq"]
                    && row["observation_ref"]["status"] == "retained"
            })
            .collect()
    };
    ensure!(
        placed(32, 0).len() == 1,
        "first32 must remain actual published history"
    );
    let fences: Vec<_> = records
        .iter()
        .filter(|row| row["decision"] == "withheld" && row["pair"] == pair)
        .collect();
    let path = if public_count == 96 {
        ensure!(
            fences.is_empty() && placed(64, 32).len() == 1 && placed(96, 64).len() == 1,
            "ordinary path must place all three32-call advances"
        );
        "ordinary"
    } else {
        ensure!(
            public_count == 64 && fences.len() == 1,
            "only exact ordinary96 or startup-fence64 is a qualified probe result"
        );
        let fence = fences[0];
        ensure!(
            fence["reason"] == "awaiting_fence"
                && fence["after"] == 32
                && fence["through"] == 64
                && fence["absolute"] == 64,
            "the second32 calls require an explicit actual startup fence disposition"
        );
        ensure!(
            placed(64, 32).is_empty(),
            "withheld second round cannot also be placed"
        );
        let recovered = placed(96, 64);
        ensure!(recovered.len() == 1 && recovered[0]["edge_total"] == 64);
        ensure!(
            fence["observation_ref"]["seq"] == observations[1]["seq"]
                && fence["observation_ref"]["status"] == "retained"
                && recovered[0]["observation_ref"]["seq"] == observations[2]["seq"]
                && recovered[0]["observation_ref"]["status"] == "retained"
                && recovered[0]["baseline_pre"] == observations[1]["pre"]
                && recovered[0]["baseline_post"] == observations[1]["post"],
            "recovery must retain the genuine second-read fence and third observation"
        );
        "startup_fence"
    };
    Ok(
        serde_json::json!({"path":path,"physical_pairs":1,"calls":96,
        "published":public_count,"withheld":96-public_count,
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
    workload.check_mapping("libdemotion-common.so")?;
    let pid = workload.process.pid();
    let events = workload.dir.path().join("probe-events.jsonl");
    let diagnostics = workload.dir.path().join("probe-diagnostics.jsonl");
    let started = Instant::now();
    let state = Cell::new(0u8);
    let fenced = Cell::new(false);
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
            let a = view.a.as_ref();
            let count = a.and_then(|edge| edge["entries"]["count"].as_u64());
            let exact_second_gap = view
                .gaps
                .iter()
                .any(|reason| reason.contains("absolute count range (32, 64]"));
            match state.get() {
                0 if a.is_some_and(|edge| {
                    edge["capture"] == "armed" && edge["presence"] == "mapped"
                }) =>
                {
                    workload.command("ready", "ready", 0)?;
                    workload.command("count", "a-done", 1)?;
                    state.set(1);
                }
                1 if count == Some(32) => {
                    first_mapping.set(
                        a.unwrap()["mapping"]["last_seen_ns"]
                            .as_u64()
                            .context("first published mapping clock")?,
                    );
                    workload.command("count", "a-done", 2)?;
                    state.set(2);
                }
                2 if count == Some(64) || exact_second_gap => {
                    fenced.set(exact_second_gap);
                    workload.command("count", "a-done", 3)?;
                    state.set(3);
                }
                3 if count == Some(if fenced.get() { 64 } else { 96 }) => state.set(4),
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
    if edges.len() != 1 || edges[0]["presence"] != "mapped" {
        // The private fixture directory is removed on return. Keep bounded
        // actual output in the failing test log before rejecting its shape;
        // these diagnostics never replace the acceptance predicate below.
        let mut diagnostic_bytes = Vec::new();
        std::fs::File::open(&diagnostics)?
            .take(128 * 1024 + 1)
            .read_to_end(&mut diagnostic_bytes)?;
        eprintln!(
            "G21_STARTUP_PROBE_REJECTED cadence_ms={} elapsed_ms={} phase={} fenced={} first_public_mapping_last_seen_ns={} intervals={intervals:?} document_bytes={} diagnostics_bytes={}",
            inventory_test_poll_interval().as_millis(),
            started.elapsed().as_millis(),
            state.get(),
            fenced.get(),
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
        edges.len() == 1 && edges[0]["presence"] == "mapped",
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
    let facts = check_startup_probe_records(&records, public, pid, module, &intervals)?;
    ensure!((facts["path"] == "startup_fence") == fenced.get());
    eprintln!(
        "G21_STARTUP_PROBE cadence_ms={} elapsed_ms={} passes={} first_public_mapping_last_seen_ns={} actual_kind_totals={} facts={facts}",
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
    for round in 1..=3u64 {
        let absolute = round * 32;
        let seq = round * 2 - 1;
        rows.push(
            serde_json::json!({"kind":"count_observation","pid":123,"pair":"p0",
            "seq":seq,"absolute":absolute,"pre":round*40+70,"post":round*40+80}),
        );
        if fenced && round == 2 {
            rows.push(
                serde_json::json!({"kind":"count_decision","decision":"withheld",
                "pair":"p0","seq":seq+1,"reason":"awaiting_fence","after":32,
                "through":64,"absolute":64,"observation_ref":{"seq":seq,"status":"retained"}}),
            );
        } else {
            rows.push(
                serde_json::json!({"kind":"publication","decision":"placed","reason":"sole_owner",
                "pair":"p0","seq":seq+1,"module_id":"mA","absolute":absolute,"base":absolute-32,
                "staged":32,"edge_total":if fenced && round==3 {64} else {absolute},
                "observation_ref":{"seq":seq,"status":"retained"},
                "baseline_pre":150,"baseline_post":160}),
            );
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
    rows.push(
        serde_json::json!({"kind":"footer","diagnostics_complete":true,
        "counter_overflow":false,"sequence_exhausted":false,"oversized_records":0,
        "records_written":6,"kinds":kinds}),
    );
    rows
}

#[test]
fn operator_diagnostics_three_round_probe_checks_fence_and_physical_pair() -> Result<()> {
    let calls = [(90, 110), (130, 150), (170, 190)];
    let module = serde_json::json!("mA");
    let ordinary = startup_probe_validator_fixture(false);
    let fenced = startup_probe_validator_fixture(true);
    ensure!(
        check_startup_probe_records(&ordinary, 96, 123, &module, &calls)?["path"] == "ordinary"
    );
    ensure!(
        check_startup_probe_records(&fenced, 64, 123, &module, &calls)?["path"] == "startup_fence"
    );
    for change in [
        "second_pair",
        "wrong_absolute",
        "false_fence_reason",
        "false_fence_range",
        "missing_recovery",
        "wrong_baseline",
        "wrong_reference",
        "wrong_primary",
        "raw_before_call",
        "kind_counter_lie",
        "read_starts_before_return",
    ] {
        let mut changed = fenced.clone();
        let mut primary = 64;
        match change {
            "second_pair" => changed[3]["pair"] = "p1".into(),
            "wrong_absolute" => changed[3]["absolute"] = 2.into(),
            "false_fence_reason" => changed[4]["reason"] = "identity_changed".into(),
            "false_fence_range" => changed[4]["after"] = 0.into(),
            "missing_recovery" => changed[6]["decision"] = "staged".into(),
            "wrong_baseline" => changed[6]["baseline_post"] = 159.into(),
            "wrong_reference" => changed[4]["observation_ref"]["seq"] = 1.into(),
            "wrong_primary" => primary = 96,
            "raw_before_call" => changed[5]["post"] = 180.into(),
            "read_starts_before_return" => changed[1]["pre"] = 109.into(),
            _ => changed[7]["kinds"][0]["retained"] = 2.into(),
        }
        ensure!(
            check_startup_probe_records(&changed, primary, 123, &module, &calls).is_err(),
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
