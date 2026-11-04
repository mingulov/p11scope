//! SPDX-License-Identifier: GPL-3.0-or-later
//! WP-7 stop-after-last-waiter cell: request the Joint finish 0, 1, 5 and
//! 20 ms after the refresh that resolves the last waiter, and pin
//! Published-then-WoundDown, the at-Q stash publication, and the abandon
//! naming lines. Root BPF lane, run serially. The held-call fixture below
//! is duplicated from `privileged_tests.rs` (same revision): that file is
//! owned by another lane and its helpers are private, so this cell carries
//! its own copies (each provenance-noted); crate-visible production APIs
//! are shared, never copied.

use super::*;
use crate::attach::capture::{
    CaptureScopeCoverage, CaptureTargets, CleanupSummary, CookieQuery, DiscoveryBatch,
    ExtendReceipt, ExtendWindow, NativeDomainId, ReadWindow, WitnessBatch,
};
use crate::discovery::inventory_attach_set::TargetDelta;
use crate::inventory_capture::{CaptureLane, Stopped};
use anyhow::ensure;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Held-call fixture, duplicated from `privileged_tests.rs`
// (task/v060-wp7-stop-races base f939a5873; spans noted per item).
// ---------------------------------------------------------------------------

// --- spans 23-44: softhsm probe + ledger source ---
/// SoftHSM2 provider layouts across hosts and guest images (Debian
/// multiarch, the /usr/lib layout of the vng guests, Fedora /usr/lib64).
/// The first present one wins; the Debian path is named when none is.
fn softhsm() -> &'static str {
    static FOUND: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    FOUND.get_or_init(|| {
        const CANDIDATES: &[&str] = &[
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib64/pkcs11/libsofthsm2.so",
        ];
        CANDIDATES
            .iter()
            .copied()
            .find(|path| Path::new(path).is_file())
            .unwrap_or(CANDIDATES[0])
    })
}

// --- spans 46-193: Workload build + LedgerProcess ---
/// A private directory with one initialized SoftHSM2 token. Trimmed from
/// the original `Workload`: this cell's processes are all live-joint, so
/// the inventory-ledger binaries and their spawn helper stay behind.
struct Workload {
    dir: tempfile::TempDir,
    conf: PathBuf,
}

impl Workload {
    fn build() -> Result<Self> {
        ensure!(
            Path::new(softhsm()).exists(),
            "SoftHSM2 provider {} is missing",
            softhsm()
        );
        let dir = tempfile::tempdir()?;
        let tokens = dir.path().join("tokens");
        std::fs::create_dir(&tokens)?;
        let conf = dir.path().join("softhsm2.conf");
        std::fs::write(
            &conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                tokens.display()
            ),
        )?;
        let status = Command::new("softhsm2-util")
            .args(["--init-token", "--free", "--label", "c51"])
            .args(["--so-pin", "5678", "--pin", "1234"])
            .env("SOFTHSM2_CONF", &conf)
            .stdout(Stdio::null())
            .status()
            .context("running softhsm2-util")?;
        ensure!(status.success(), "softhsm2-util --init-token failed");
        Ok(Self { dir, conf })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

struct LedgerProcess {
    child: Child,
    out: PathBuf,
}

impl LedgerProcess {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn has(&self, prefix: &str) -> bool {
        std::fs::read_to_string(&self.out)
            .is_ok_and(|text| text.lines().any(|line| line.starts_with(prefix)))
    }

    fn wait_for(&self, prefix: &str, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        while !self.has(prefix) {
            ensure!(
                Instant::now() < deadline,
                "ledger {} never printed {prefix:?}",
                self.out.display()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
}

impl Drop for LedgerProcess {
    fn drop(&mut self) {
        if let Ok(Some(_)) = self.child.try_wait() {
            return;
        }
        // SIGTERM lets a --hold ledger tear its session down; then reap.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// --- spans 1742-1752: monotonic clock ---
fn monotonic_ns() -> u64 {
    let mut stamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut stamp) },
        0
    );
    stamp.tv_sec as u64 * 1_000_000_000 + stamp.tv_nsec as u64
}

// --- spans 3911-4010: live-joint source + JointWorkload + soft functions ---
fn live_joint_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/object-journal/live-joint.c")
}

/// The R1.6 workload: the standard token setup plus the live-joint fixture
/// workload, its held provider and a private SoftHSM copy. Nothing else on
/// the host maps the copies, so System scope observes exactly these owners.
struct JointWorkload {
    workload: Workload,
    joint: PathBuf,
    held: PathBuf,
    soft_copy: PathBuf,
}

impl JointWorkload {
    fn build() -> Result<Self> {
        let workload = Workload::build()?;
        let joint = workload.path("live-joint");
        let held = workload.path("live-joint-held.so");
        let gcc = |args: &[&str], out: &Path| -> Result<()> {
            let status = Command::new("gcc")
                .args(args)
                .arg("-o")
                .arg(out)
                .arg(live_joint_source())
                .arg("-ldl")
                .status()
                .context("running gcc")?;
            ensure!(status.success(), "gcc {args:?} failed");
            Ok(())
        };
        gcc(&["-O1", "-Wall", "-Wextra", "-Werror"], &joint)?;
        gcc(
            &[
                "-O1",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-shared",
                "-fPIC",
                "-DLIVE_JOINT_HELD_PROVIDER",
            ],
            &held,
        )?;
        let soft_copy = workload.path("soft-copy.so");
        std::fs::copy(softhsm(), &soft_copy).context("copying SoftHSM2")?;
        Ok(Self {
            workload,
            joint,
            held,
            soft_copy,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.workload.path(name)
    }

    /// One live-joint process; its stdout is the ledger file `<cell>.out`.
    /// Reuses the owned-child/deadline helper shape (`LedgerProcess`).
    fn spawn(
        &self,
        cell: &str,
        args: &[&str],
        extra_env: &[(&str, &Path)],
    ) -> Result<LedgerProcess> {
        let out = self.path(&format!("{cell}.out"));
        let mut command = Command::new(&self.joint);
        command
            .args(args)
            .env("SOFTHSM2_CONF", &self.workload.conf)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out)?)
            .stderr(std::fs::File::create(self.path(&format!("{cell}.err")))?);
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let child = command.spawn().context("spawning live-joint")?;
        let process = LedgerProcess { child, out };
        process.wait_for("READY ", Duration::from_secs(30))?;
        Ok(process)
    }
}

/// The fixed SoftHSM call script's functions (every call the b/exec
/// modes make is observed; the CALLS ledger carries the adaptive counts).
const JOINT_SOFT_FUNCTIONS: &[&str] = &[
    "C_Initialize",
    "C_Finalize",
    "C_GetSlotList",
    "C_GetTokenInfo",
    "C_OpenSession",
    "C_CloseSession",
    "C_Login",
    "C_Logout",
    "C_DigestInit",
    "C_Digest",
    "C_SignInit",
    "C_Sign",
    "C_GenerateKey",
];

// --- spans 4012-4106: provider manifest ---

/// A Joint manifest for any owned provider: the live joint-finish cell's
/// recipe (file identity + mapping key + ELF offsets for the named
/// functions), parameterized by provider. That cell's helper is untouched.
fn provider_joint_manifest(
    dir: &Path,
    provider: &Path,
    functions: &[&str],
    file_name: &str,
) -> Result<PathBuf> {
    use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
    use p11scope_manifest::manifest::*;
    ensure!(
        provider.exists(),
        "provider {} is missing",
        provider.display()
    );
    let file = open_object(provider).map_err(anyhow::Error::msg)?;
    let inspected = inspect_file(&file).map_err(anyhow::Error::msg)?;
    let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
    let elf = std::fs::File::open(provider)?;
    let snapshot = p11scope_manifest::elf::ElfSnapshot::read(&elf).map_err(anyhow::Error::msg)?;
    let mut offsets = Vec::new();
    for name in functions {
        let fact = snapshot
            .defined_symbol(name)
            .map_err(anyhow::Error::msg)?
            .with_context(|| format!("{} exports no {name}", provider.display()))?;
        offsets.push(fact.file_offset);
    }
    let functions = match pkcs11_module::tables_for(pkcs11_module::Surface::LegacyFunctionList {
        version: cryptoki_sys::CK_VERSION {
            major: 2,
            minor: 40,
        },
    }) {
        pkcs11_module::TableSet::Walk(spans) => spans
            .iter()
            .flat_map(|span| span.fields())
            .map(|field| {
                let resolution = functions
                    .iter()
                    .position(|name| *name == field.name)
                    .map_or(Resolution::NullPointer, |at| Resolution::Resolved {
                        object: 0,
                        file_offset: offsets[at],
                    });
                FunctionRecord {
                    name: field.name.into(),
                    resolution,
                }
            })
            .collect(),
        _ => anyhow::bail!("2.40 is a full standard table"),
    };
    let path = provider.to_str().context("provider path")?.to_string();
    let manifest = Manifest {
        schema: SCHEMA.into(),
        module_path: path.clone(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.clone(),
            identity: inspected.identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path,
            device_major: mapping.device_major,
            device_minor: mapping.device_minor,
            inode: mapping.inode,
            identity: inspected.identity,
        }],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: Some(Version {
                major: 2,
                minor: 40,
            }),
            walk: WalkOutcome::Full,
            functions,
        }],
        vendor_interfaces: Vec::new(),
        alias_groups: Vec::new(),
        selection_evidence: Default::default(),
    };
    ensure!(
        crate::manifest_input::validate_structure(&manifest).is_empty(),
        "the {} manifest is well-formed",
        provider.display()
    );
    let manifest_path = dir.join(file_name);
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    Ok(manifest_path)
}

// --- spans 4108-4588: coordinator, drive, lane, service, ledger, snapshot, reconcile ---
fn system_joint_coordinator(modules: &[PathBuf]) -> Result<InventoryCoordinator<OsProcessSource>> {
    InventoryCoordinator::new(
        Scope::System,
        HookRegistry::builtin(),
        modules.to_vec(),
        OsProcessSource,
        RegistryLimits::default_limits(),
    )
}

/// Native discovery passes until `done` says stop (adapter records and
/// mapped edges for the owned processes, the Joint machine's binding
/// input). The native lane stops afterwards; its records persist in the
/// coordinator.
fn drive_native_passes_until(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    done: &mut dyn FnMut(u64) -> Result<bool>,
) -> Result<()> {
    let probe = Probe::new(FacadeLane::prepare(
        crate::attach::capture::CaptureScope::System,
        coordinator.attach_set().budget(),
        crate::attach::BackendSelection::Auto,
    )?);
    let lane = NativeLane::start(probe, coordinator, LaneWindows::PROVISIONAL, None)
        .map_err(|(_, reason)| anyhow::anyhow!("{reason}"))?;
    drive(coordinator, InspectScope::System, lane, done)?;
    Ok(())
}

/// Native discovery until every listed pid has a mapped edge (bounded:
/// at most ten short drives; each drive stops its own lane while the
/// coordinator's records accumulate).
fn drive_until_mapped(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    pids: &[u32],
) -> Result<()> {
    for round in 0..10 {
        if pids.iter().all(|pid| has_mapped_edge(coordinator, *pid)) {
            return Ok(());
        }
        drive_native_passes_until(coordinator, &mut |passes| Ok(passes >= 4))?;
        let mapped = pids
            .iter()
            .filter(|pid| has_mapped_edge(coordinator, **pid))
            .count();
        eprintln!(
            "JOINT_R16 r16-map round={round} mapped={}/{}",
            mapped,
            pids.len()
        );
    }
    ensure!(
        pids.iter().all(|pid| has_mapped_edge(coordinator, *pid)),
        "every owner maps before attach"
    );
    Ok(())
}

fn caller_of(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    pid: u32,
) -> Result<crate::discovery::caller_registry::CallerId> {
    coordinator
        .adapter()
        .live_id(pid)
        .with_context(|| format!("pid {pid} was never admitted"))
}

fn module_of(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    substr: &str,
) -> Result<crate::discovery::caller_registry::ModuleId> {
    coordinator
        .registry()
        .modules()
        .find(|module| module.paths.iter().any(|path| path.contains(substr)))
        .map(|module| module.id)
        .with_context(|| format!("no module matching {substr:?}"))
}

fn has_mapped_edge(coordinator: &InventoryCoordinator<OsProcessSource>, pid: u32) -> bool {
    let Some(id) = coordinator.adapter().live_id(pid) else {
        return false;
    };
    coordinator
        .registry()
        .edges_of(id)
        .any(|edge| edge.mapping == crate::discovery::caller_registry::MappingState::Mapped)
}

/// Start the production semantic lane over the manifests and initialize
/// its Joint machine, before any lane tick (initialization refuses once
/// ticks or stashed refresh exist).
fn start_joint_lane(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    manifests: Vec<PathBuf>,
) -> Result<crate::inventory_semantics::AttestedSemanticLane> {
    coordinator.set_semantic_manifests(manifests);
    let attach_subset = coordinator
        .prepare_semantic_subset()
        .subset
        .context("the attach subset prepares")?;
    let convert_subset = coordinator
        .prepare_semantic_subset()
        .subset
        .context("the conversion subset prepares")?;
    let scope = Scope::System;
    let mut lane = crate::inventory_semantics::AttestedSemanticLane::start_live(
        attach_subset,
        convert_subset,
        &scope,
        crate::attach::BackendSelection::Auto,
        None,
    )
    .map_err(|refusal| anyhow::anyhow!("live lane attaches: {refusal}"))?;
    ensure!(lane.is_live(), "the lane owns its live session");
    lane.initialize_joint(coordinator)
        .map_err(|refusal| anyhow::anyhow!("the joint machine initializes: {refusal}"))?;
    ensure!(lane.has_joint_machine(), "the machine initializes live");
    joint_drive_line(&lane, coordinator, "r16-lane", "started");
    Ok(lane)
}

/// One JOINT_R16 drive-state line: the lane gates plus the machine's
/// retained phase/demand, before every driven step (and after a
/// refusal, where the retained phase names the exact failing step).
fn joint_drive_line(
    lane: &crate::inventory_semantics::AttestedSemanticLane,
    coordinator: &InventoryCoordinator<OsProcessSource>,
    tag: &str,
    step: &str,
) {
    let (live, gated, finished, ticks, phase, demand, work, base, staging) =
        lane.joint_drive_state_for_test();
    let work = work.map_or_else(
        || "-".to_string(),
        |(attempted, pending)| format!("{attempted}/{pending}"),
    );
    let staging = staging.map_or_else(|| "-".to_string(), |detail| detail.to_string());
    let stuck = lane.joint_stuck_diagnostic_for_test();
    let stuck = stuck.as_deref().unwrap_or("-");
    let trip = lane.joint_guard_trip_for_test().unwrap_or("-");
    eprintln!(
        "JOINT_R16 {tag} step={step} live={} gated={} finished={} ticks={ticks} \
         phase={phase} demand={demand} work={work} base={base} staging={staging} \
         revision={} feeds={} stuck={stuck} trip={trip}",
        u8::from(live),
        u8::from(gated),
        u8::from(finished),
        coordinator.registry().published_revision(),
        coordinator.registry().joint_feeds(),
    );
}

/// Drive one Running transaction to publication through the real lane
/// APIs (the future on-tick path, called directly): one begin, bounded
/// service/poll slices, exactly one published revision.
fn service_to_published(
    lane: &mut crate::inventory_semantics::AttestedSemanticLane,
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    engine_changed: bool,
    tag: &str,
) -> Result<u64> {
    use crate::inventory_semantics::{JointServiceMode, JointWorkBudget};
    joint_drive_line(lane, coordinator, tag, "begin");
    lane.begin_joint_commit(engine_changed).map_err(|refusal| {
        let reason = match refusal {
            crate::inventory_semantics::JointCommitRefusal::NotInitialized => "not initialized",
            crate::inventory_semantics::JointCommitRefusal::OutstandingRequest => {
                "outstanding request"
            }
            crate::inventory_semantics::JointCommitRefusal::DispositionRequired => {
                "disposition required"
            }
        };
        anyhow::anyhow!("{tag}: begin refused: {reason}")
    })?;
    let revision_before = coordinator.registry().published_revision();
    let started = Instant::now();
    let mut polls = 0u64;
    loop {
        // The drive line prints before the budget starts: the 10 ms
        // service slice covers the service work, never the logging
        // latency (a slow log, e.g. 9p in a guest, would otherwise
        // exhaust the slice and every service would no-op).
        joint_drive_line(lane, coordinator, tag, &format!("service{polls}"));
        let mut budget = JointWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        lane.service_joint(&mut *coordinator, JointServiceMode::Running, &mut budget)
            .map_err(|reason| {
                joint_drive_line(lane, coordinator, tag, "service-FAILED");
                anyhow::anyhow!(
                    "{tag}: service refused: {reason} waiters={:?}",
                    lane.joint_stuck_diagnostic_for_test(),
                )
            })?;
        joint_drive_line(lane, coordinator, tag, &format!("poll{polls}"));
        let mut budget = JointWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        let commit = lane
            .poll_joint_commit(&mut *coordinator, &mut budget)
            .map_err(|reason| {
                joint_drive_line(lane, coordinator, tag, "poll-FAILED");
                anyhow::anyhow!(
                    "{tag}: commit poll refused: {reason} waiters={:?}",
                    lane.joint_stuck_diagnostic_for_test(),
                )
            })?;
        polls += 1;
        if matches!(
            commit,
            crate::discovery::engine::inventory_coordinator::JointCommitProgress::Published(_)
        ) {
            let revision_after = coordinator.registry().published_revision();
            ensure!(
                revision_after == revision_before + 1,
                "{tag}: one published revision per transaction: \
                 {revision_before} -> {revision_after}"
            );
            return Ok(polls);
        }
        let scan_bound =
            crate::semantic_capture::TickLimits::default().pending_for + Duration::from_secs(3);
        ensure!(
            started.elapsed() < scan_bound,
            "{tag}: unpublished after {} polls ({} ms, bound {} ms); \
             stuck audit={:?} h3={:?} waiters={:?}",
            polls,
            started.elapsed().as_millis(),
            scan_bound.as_millis(),
            lane.joint_audit_diagnostic_for_test(),
            coordinator.reference_h3_audit_state(),
            lane.joint_stuck_diagnostic_for_test(),
        );
        ensure!(
            started.elapsed() < Duration::from_secs(120),
            "{tag}: unpublished after 120 s; stuck audit={:?} h3={:?} waiters={:?}",
            lane.joint_audit_diagnostic_for_test(),
            coordinator.reference_h3_audit_state(),
            lane.joint_stuck_diagnostic_for_test(),
        );
    }
}

/// The fixture's CALLS ledger: per-function entered counts, total entered,
/// total failed. The observer's exact populations are checked against
/// these, never against hardcoded counts.
fn ledger_calls(out: &Path) -> Result<(BTreeMap<String, u64>, u64, u64)> {
    let text = std::fs::read_to_string(out)?;
    let mut per_function = BTreeMap::new();
    let mut total = 0u64;
    let mut bad = 0u64;
    for line in text.lines().filter(|line| line.starts_with("CALLS ")) {
        let mut function = None;
        let mut entered = None;
        let mut failed = None;
        for token in line.split_whitespace() {
            if let Some(name) = token.strip_prefix("fn=") {
                function = Some(name.to_string());
            } else if let Some(count) = token.strip_prefix("n=") {
                entered = Some(count.parse::<u64>()?);
            } else if let Some(count) = token.strip_prefix("bad=") {
                failed = Some(count.parse::<u64>()?);
            }
        }
        let (Some(function), Some(entered), Some(failed)) = (function, entered, failed) else {
            anyhow::bail!("unparsable CALLS line: {line:?}")
        };
        *per_function.entry(function).or_insert(0) += entered;
        total += entered;
        bad += failed;
    }
    Ok((per_function, total, bad))
}

/// The first `t=` stamp on a ledger line with the given prefix.
fn ledger_stamp(out: &Path, prefix: &str) -> Result<u64> {
    let text = std::fs::read_to_string(out)?;
    for line in text.lines().filter(|line| line.starts_with(prefix)) {
        for token in line.split_whitespace() {
            if let Some(stamp) = token.strip_prefix("t=") {
                return Ok(stamp.parse::<u64>()?);
            }
        }
    }
    anyhow::bail!("no {prefix:?} stamp in {}", out.display())
}

/// One semantic edge's observable populations.
struct JointEdgeSnapshot {
    api_returns: Option<u64>,
    reduced: u64,
    joint: bool,
    started: Option<u64>,
    completed: Option<u64>,
    /// S1 mechanism rows as (mechanism, attributed calls, errors), by id.
    mechanisms: Vec<(u64, u64, u64)>,
}

fn joint_edge_snapshot(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    pid: u32,
    module_substr: &str,
) -> Result<JointEdgeSnapshot> {
    let caller = caller_of(coordinator, pid)?;
    let module = module_of(coordinator, module_substr)?;
    let record = coordinator
        .registry()
        .instance_semantic_edges()
        .find(|record| record.caller == caller && record.module == module)
        .with_context(|| format!("no semantic edge for pid {pid} on {module_substr:?}"))?;
    let mut mechanisms: Vec<(u64, u64, u64)> = record
        .semantics
        .as_ref()
        .map(|edge| {
            edge.mechanisms()
                .iter()
                .map(|(id, row)| (*id, row.calls, row.errors))
                .collect()
        })
        .unwrap_or_default();
    mechanisms.sort();
    Ok(JointEdgeSnapshot {
        api_returns: record.api_returns,
        reduced: record.feed.reduced(),
        joint: record.feed.mode() == crate::semantics_key_use::FeedMode::Joint,
        started: record.semantics.as_ref().map(|edge| edge.started()),
        completed: record.semantics.as_ref().map(|edge| edge.completed()),
        mechanisms,
    })
}

/// Split a CALLS ledger's entered calls into the semantically admitted
/// population (`api_returns`/`reduced`) and the count-only population.
/// Conversion refuses COUNT_ONLY slots, so the observer's exact semantic
/// populations are the semantic side, never the raw ledger total. Unknown
/// names count as count-only: without a descriptor they have no slot and
/// are never observed.
fn ledger_semantic_split(per_function: &BTreeMap<String, u64>) -> (u64, u64) {
    let mut semantic = 0u64;
    let mut count_only = 0u64;
    for (function, entered) in per_function {
        let admitted = crate::kinds::descriptor(function).is_some_and(|descriptor| {
            descriptor != p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        });
        if admitted {
            semantic = semantic.saturating_add(*entered);
        } else {
            count_only = count_only.saturating_add(*entered);
        }
    }
    (semantic, count_only)
}

/// Count registry gaps with an exact subject/reason/caller triple,
/// summing repeat counts: the registry publishes one gap row per run
/// and bumps repeats, so identical refusals share a row. This is the
/// disclosed side of an expected refusal (count-only slot, no-receipt
/// admission).
fn count_disclosed_gaps(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    subject: &str,
    reason: &str,
    caller: Option<crate::discovery::caller_registry::CallerId>,
) -> u64 {
    let registry = coordinator.registry();
    registry
        .gaps()
        .iter()
        .zip(registry.gap_repeats().iter())
        .filter(|(gap, _)| gap.subject == subject && gap.reason == reason && gap.caller == caller)
        .map(|(_, repeats)| *repeats)
        .fold(0u64, |total, repeats| total.saturating_add(repeats))
}

/// Entries (not repeats) of caller-less gaps with one subject: the
/// unrouted-shed disclosure beside the lane shed counter, and the
/// capacity shed that has no counter.
fn count_callerless_gap_entries(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    subject: &str,
) -> usize {
    coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.caller.is_none() && gap.subject == subject)
        .count()
}

/// Trusted Joint-branch selector. `journal_linked` latches from the
/// drain producers on the birth path, so it still reads the test
/// default (true) when zero births flowed (total shed). Joint
/// installs prove a real linked world; a latched false proves the
/// latch ran (births flowed, producers unlinked); linked-true with
/// zero installs is the unattributed default.
enum JointBranch {
    Linked,
    S1,
    Unattributed,
}

fn joint_branch(coordinator: &InventoryCoordinator<OsProcessSource>) -> JointBranch {
    if coordinator.registry().joint_feeds() > 0 {
        JointBranch::Linked
    } else if !coordinator.registry().journal_linked() {
        JointBranch::S1
    } else {
        JointBranch::Unattributed
    }
}

/// Uniform semantic reconciliation (release-path §4.3): every entered
/// fixture call is attributed on its edge (`api`), refused at input
/// as count-only (`slot`), refused before application for an unproven
/// or unbound instance (`inst`, counted per call), or shed in the
/// named caller-less route-loss gap whose total the lane counts
/// (`shed`). Only fixtures call into the providers, so the lane shed
/// total is all fixture calls. Per-owner api/slot never exceed their
/// ledger splits (no over-attribution, no over-refusal); the global
/// entered equation then subsumes strict per-owner exactness when
/// nothing sheds, and accepts exactly the disclosed outcome
/// otherwise. A silent drop breaks the equation. Capacity shed has
/// no counter, so any capacity gap fails; shed without a printed
/// named gap (or with suppressed disclosure) fails too.
///
/// Owners are (name, sem, count_only, entered, api, slot, inst).
fn assert_semantic_reconciled(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    lane_shed: u64,
    tag: &str,
    owners: &[(&str, u64, u64, u64, u64, u64, u64)],
) -> Result<()> {
    let mut parts = Vec::new();
    let (mut entered_sum, mut api_sum, mut slot_sum, mut inst_sum) = (0u64, 0u64, 0u64, 0u64);
    for (name, sem, count_only, entered, api, slot, inst) in owners {
        ensure!(
            api <= sem,
            "{tag}: {name} never over-attributes: api {api} <= sem {sem}"
        );
        ensure!(
            slot <= count_only,
            "{tag}: {name} never over-refuses: slot {slot} <= count-only {count_only}"
        );
        parts.push(format!(
            "{name}(entered={entered} sem={sem} api={api} co={count_only} slot={slot} inst={inst})"
        ));
        entered_sum += entered;
        api_sum += api;
        slot_sum += slot;
        inst_sum += inst;
    }
    let unrouted_entries = count_callerless_gap_entries(coordinator, "semantic calls unrouted");
    let capacity_entries =
        count_callerless_gap_entries(coordinator, "semantic call outcome capacity");
    let suppressed = coordinator.registry().gaps_suppressed();
    eprintln!(
        "JOINT_R16 {tag}-reconcile {} shed={lane_shed} \
         unrouted_entries={unrouted_entries} capacity_entries={capacity_entries} \
         suppressed={suppressed}",
        parts.join(" ")
    );
    ensure!(
        capacity_entries == 0,
        "{tag}: no capacity shed without a counter: {capacity_entries} entries"
    );
    ensure!(
        lane_shed == 0 || (unrouted_entries > 0 && suppressed == 0),
        "{tag}: shed calls are disclosed in a printed named gap: shed {lane_shed}, \
         entries {unrouted_entries}, suppressed {suppressed}"
    );
    ensure!(
        entered_sum == api_sum + lane_shed + slot_sum + inst_sum,
        "{tag}: every entered call is attributed, slot-refused, instance-refused or disclosed-shed: \
         entered {entered_sum} vs api {api_sum} + shed {lane_shed} + slot {slot_sum} + inst {inst_sum}"
    );
    Ok(())
}

// --- spans 4969-5019: joint finish driver ---
fn joint_finish_driver<'a>(
    coordinator: &'a mut InventoryCoordinator<OsProcessSource>,
    lane: crate::inventory_semantics::AttestedSemanticLane,
) -> ClassicDriver<'a> {
    ClassicDriver {
        coordinator,
        inventory_scope: Some(InventoryScope::System),
        scope: InspectScope::System.into(),
        cgroup: None,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline: None,
        attach_backend: crate::attach::BackendSelection::Auto,
        display: None,
        semantic: Some(lane),
        semantic_staged: false,
        seated_summary: None,
        second_signal: None,
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        identity: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        prearm_stop_probe: None,
        prearm_probe_stop: None,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
    }
}

// ---------------------------------------------------------------------------
// --- spans 195-203: ReadStamp ---
/// One witness read as the probe saw it. The field readers live in the
/// original file's C5.1 cells; here the seam only records.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ReadStamp {
    before_ns: u64,
    after_ns: u64,
    health_read_ns: u64,
    rows_read_ns: u64,
    max_recorded_ns: Option<u64>,
}

// --- spans 205-341: Probe recording seam ---
/// The production capture behind a recording seam: the activation instant,
/// the exec-coverage stamp, every read's stamps and every row's tgid. It can
/// raise SIGINT inside the activating extend.
struct Probe<L> {
    inner: L,
    raise_sigint_on_activation: bool,
    activation_began_ns: Option<u64>,
    exec_coverage_ns: Option<u64>,
    reads: Vec<ReadStamp>,
    row_tgids: Vec<u32>,
    stop_began: Option<Instant>,
    /// Begin-stop to retired: the measured kernel detach time.
    retired_after: Option<Duration>,
    /// Endpoints attached so far, shared with the pass callback.
    attached: Rc<Cell<usize>>,
    /// Summed attach wall time over every extend.
    attach_ns: u64,
    /// The longest single attach (one link: an entry or a group).
    attach_ns_max: u64,
    /// The longest one extend spent attaching.
    extend_attach_ns_max: u64,
    /// The kernel links the capture held when the stop began.
    links_at_stop: Option<usize>,
}

impl<L> Probe<L> {
    fn new(inner: L) -> Self {
        Self {
            inner,
            raise_sigint_on_activation: false,
            activation_began_ns: None,
            exec_coverage_ns: None,
            reads: Vec::new(),
            row_tgids: Vec::new(),
            stop_began: None,
            retired_after: None,
            attached: Rc::default(),
            attach_ns: 0,
            attach_ns_max: 0,
            extend_attach_ns_max: 0,
            links_at_stop: None,
        }
    }
}

impl<L: CaptureLane<PidPin>> NativeIdentity<PidPin> for Probe<L> {
    fn owner_image(&mut self, pid: u32) -> Option<crate::discovery::native_binding::BoundImage> {
        self.inner.owner_image(pid)
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        self.inner.query_cookie(domain, pin)
    }
}

impl<L: CaptureLane<PidPin>> CaptureLane<PidPin> for Probe<L> {
    fn domain(&self) -> NativeDomainId {
        self.inner.domain()
    }

    fn backend(&self) -> crate::inventory_capture::LaneBackend {
        self.inner.backend()
    }

    fn live_links(&self) -> Option<usize> {
        self.inner.live_links()
    }

    fn scope_coverage(&self) -> CaptureScopeCoverage {
        self.inner.scope_coverage()
    }

    fn extend(
        &mut self,
        delta: TargetDelta,
        targets: &dyn CaptureTargets,
        window: ExtendWindow,
    ) -> ExtendReceipt {
        if self.activation_began_ns.is_none() {
            self.activation_began_ns = Some(now_ns());
            if self.raise_sigint_on_activation {
                // SAFETY: raising a signal whose handler is installed.
                unsafe {
                    libc::raise(libc::SIGINT);
                }
            }
        }
        let receipt = self.inner.extend(delta, targets, window);
        self.attached
            .set(self.attached.get() + receipt.attached.len());
        self.attach_ns += receipt.attach_ns_total;
        self.attach_ns_max = self.attach_ns_max.max(receipt.attach_ns_max);
        self.extend_attach_ns_max = self.extend_attach_ns_max.max(receipt.attach_ns_total);
        if let Some(coverage) = receipt.exec_coverage {
            self.exec_coverage_ns = Some(coverage.start_ns());
        }
        receipt
    }

    fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
        self.inner.service_discovery(window)
    }

    fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
        let before_ns = now_ns();
        let batch = self.inner.read_witnesses(window);
        let after_ns = now_ns();
        self.row_tgids
            .extend(batch.rows.iter().map(|row| row.host_tgid));
        self.reads.push(ReadStamp {
            before_ns,
            after_ns,
            health_read_ns: batch.health_read_ns,
            rows_read_ns: batch.rows_read_ns,
            max_recorded_ns: batch.rows.iter().map(|row| row.recorded_at_ns).max(),
        });
        batch
    }

    fn begin_stop(&mut self) {
        self.links_at_stop = self.inner.live_links();
        self.stop_began = Some(Instant::now());
        self.inner.begin_stop();
    }

    fn poll_retirement(&mut self, deadline: Instant) -> Result<bool> {
        let retired = self.inner.poll_retirement(deadline);
        if matches!(retired, Ok(true)) && self.retired_after.is_none() {
            self.retired_after = self.stop_began.map(|began| began.elapsed());
        }
        retired
    }

    fn cleanup(&self) -> Option<CleanupSummary> {
        self.inner.cleanup()
    }
}

// --- spans 385-476: classic-loop drive ---
/// Drives the production classic loop (`ClassicDriver` + `run_classic`) over
/// `lane`: `on_pass(pass)` runs after every committed pass and says whether
/// to stop.
fn drive<L: CaptureLane<PidPin>>(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    scope: InspectScope,
    lane: NativeLane<L>,
    on_pass: &mut dyn FnMut(u64) -> Result<bool>,
) -> Result<Stopped<L>> {
    let inventory_scope = match scope {
        InspectScope::Pid(pid) => InventoryScope::Pid(pid),
        InspectScope::System => InventoryScope::System,
    };
    let deadline = Some(Instant::now() + Duration::from_secs(120));
    let mut driver = ClassicDriver {
        coordinator,
        inventory_scope: Some(inventory_scope),
        scope: scope.into(),
        cgroup: None,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline,
        attach_backend: crate::attach::BackendSelection::Auto,
        display: None,
        semantic: None,
        semantic_staged: false,
        seated_summary: None,
        second_signal: None,
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        identity: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        prearm_stop_probe: None,
        prearm_probe_stop: None,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
    };
    let stop = Cell::new(false);
    let stop_now = || stop.get();
    let clock = LoopClock {
        deadline,
        stop: &stop_now,
        now: &Instant::now,
        interval: Duration::from_millis(300),
        tick: SERVICE_TICK,
        collection_tick: SERVICE_TICK,
    };
    let stopped = run_classic(
        &mut driver,
        Some(lane),
        &clock,
        &mut |driver: &mut ClassicDriver<'_>, point| {
            if let Publish::Pass { .. } = point {
                stop.set(on_pass(driver.coordinator.passes())?);
            }
            Ok(())
        },
    )
    .map_err(|outcome| {
        assert!(
            outcome.retained.is_none(),
            "this semantic:None test driver is synchronous: {outcome:?}"
        );
        outcome
            .error
            .expect("a synchronous loop failure has its error")
    })?;
    stopped.context("a native run stops its lane")
}

// WP-7 stop-after-last-waiter cell.
// ---------------------------------------------------------------------------

/// Collected terminal state of one stop-offset sub-case. Every finish loop
/// is bounded and every outcome is collected, never ensured mid-drive, so
/// a wedged finish reports its full state instead of hanging the cell.
struct StopOutcome {
    offset_ms: u64,
    begin: String,
    finish_polls: u64,
    finish: String,
    first_error: Option<String>,
    latched: bool,
    latch_code: Option<String>,
    h0_stop: String,
    wound: String,
    wound_polls: u64,
    taken: bool,
    minted: bool,
    stash_floor: Option<u64>,
    stop_counts: (u64, u64, u64, u64),
    api_a: u64,
    a_semantic: u64,
    lane_shed: u64,
    reconciled: bool,
    reconcile_detail: String,
    abandon_gap: Option<String>,
    branch: String,
}

impl std::fmt::Display for StopOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "offset={} begin={} finish={} ({} polls) first_error={:?} latched={} latch={:?} \
             h0={} wound={} ({} polls) taken={} minted={} stash={:?} \
             stop_counts={:?} api_a={} a_sem={} shed={} reconciled={} abandon_gap={:?} branch={}",
            self.offset_ms,
            self.begin,
            self.finish,
            self.finish_polls,
            self.first_error,
            self.latched,
            self.latch_code,
            self.h0_stop,
            self.wound,
            self.wound_polls,
            self.taken,
            self.minted,
            self.stash_floor,
            self.stop_counts,
            self.api_a,
            self.a_semantic,
            self.lane_shed,
            self.reconciled,
            self.abandon_gap,
            self.branch,
        )
    }
}

/// How much of the post-release q2 flow runs before the stop: raw
/// service slices, interleaved service+poll slices, or the full q2.
#[derive(Debug, Clone, Copy)]
enum Prep {
    Services(u32),
    ServicesPolls(u32, u32),
    FullQ2,
}

/// One stop offset: held-call setup, q1 with A retained, release, then the
/// prep flow; sleep the offset; drive the production finish to terminal.
fn run_stop_offset(
    workload: &JointWorkload,
    soft_manifest: &Path,
    held_manifest: &Path,
    prep: Prep,
    offset_ms: u64,
    index: usize,
) -> Result<StopOutcome> {
    use crate::inventory_promotion::lifecycle::NativeCompletionSource as _;
    let tag = format!("wp7-stop{index}");
    let release = workload.path(&format!("release{index}"));
    let go = workload.path(&format!("go{index}"));
    let _ = std::fs::remove_file(&release);
    let release_c = std::ffi::CString::new(release.to_str().context("release path")?)
        .context("release path holds NUL")?;
    let mkfifo_rc = unsafe { libc::mkfifo(release_c.as_ptr(), 0o600) };
    ensure!(
        mkfifo_rc == 0,
        "mkfifo {}: {}",
        release.display(),
        std::io::Error::last_os_error()
    );
    let go_arg = go.to_str().context("go path")?.to_string();
    let release_arg = release.to_str().context("release path")?.to_string();
    let held_path = workload.held.to_str().context("held path")?.to_string();
    let mut coordinator =
        system_joint_coordinator(&[workload.soft_copy.clone(), workload.held.clone()])?;
    let mut lane = start_joint_lane(
        &mut coordinator,
        vec![soft_manifest.to_path_buf(), held_manifest.to_path_buf()],
    )?;
    let process_a = workload.spawn(
        &format!("A{index}"),
        &[
            "a",
            "--cell",
            "A",
            "--module",
            &held_path,
            "--go",
            &go_arg,
            "--release",
            &release_arg,
            "--hold",
        ],
        &[],
    )?;
    let soft_path = workload
        .soft_copy
        .to_str()
        .context("soft-copy path")?
        .to_string();
    let process_b = workload.spawn(
        &format!("B{index}"),
        &[
            "b", "--cell", "B", "--module", &soft_path, "--go", &go_arg, "--iters", "2", "--hold",
        ],
        &[],
    )?;
    drive_until_mapped(&mut coordinator, &[process_a.pid(), process_b.pid()])?;
    std::fs::write(&go, "go\n").context("releasing the live-joint gate")?;
    process_a.wait_for("HELD ", Duration::from_secs(60))?;
    process_b.wait_for("DONE ", Duration::from_secs(120))?;
    let q1_polls = service_to_published(&mut lane, &mut coordinator, true, &format!("{tag}-q1"))?;
    let q1_end_ns = monotonic_ns();
    let t_enter = ledger_stamp(&process_a.out, "HELD ")?;
    ensure!(
        t_enter < q1_end_ns,
        "{tag}: the held call entered before q1 ended: {t_enter} < {q1_end_ns}"
    );
    eprintln!("JOINT_STOP {tag}: q1 published in {q1_polls} polls; releasing the held call");
    {
        let _release = std::fs::File::create(&release)?;
    }
    process_a.wait_for("RETURNED ", Duration::from_secs(60))?;
    // Prep flow with full state prints: drive state, stuck audit, stash.
    eprintln!(
        "JOINT_STOP {tag}: post-release baseline: drive={:?} stash={:?} stuck={:?}",
        lane.joint_drive_state_for_test(),
        lane.stash_pending_floor(),
        lane.joint_stuck_diagnostic_for_test(),
    );
    {
        use crate::inventory_semantics::{JointServiceMode, JointWorkBudget};
        match prep {
            Prep::Services(n) => {
                lane.begin_joint_commit(false)
                    .map_err(|refusal| anyhow::anyhow!("{tag}: begin refused: {refusal:?}"))?;
                for slice in 0..n {
                    let mut budget = JointWorkBudget {
                        remaining_actions: 1024,
                        deadline: Instant::now() + Duration::from_millis(10),
                    };
                    lane.service_joint(&mut coordinator, JointServiceMode::Running, &mut budget)
                        .map_err(|reason| anyhow::anyhow!("{tag}: service refused: {reason}"))?;
                    eprintln!(
                        "JOINT_STOP {tag}: service{slice}: drive={:?} stash={:?} stuck={:?}",
                        lane.joint_drive_state_for_test(),
                        lane.stash_pending_floor(),
                        lane.joint_stuck_diagnostic_for_test(),
                    );
                }
            }
            Prep::ServicesPolls(services, polls) => {
                lane.begin_joint_commit(false)
                    .map_err(|refusal| anyhow::anyhow!("{tag}: begin refused: {refusal:?}"))?;
                for slice in 0..services.max(polls) {
                    if slice < services {
                        let mut budget = JointWorkBudget {
                            remaining_actions: 1024,
                            deadline: Instant::now() + Duration::from_millis(10),
                        };
                        lane.service_joint(
                            &mut coordinator,
                            JointServiceMode::Running,
                            &mut budget,
                        )
                        .map_err(|reason| anyhow::anyhow!("{tag}: service refused: {reason}"))?;
                    }
                    if slice < polls {
                        let mut budget = JointWorkBudget {
                            remaining_actions: 1024,
                            deadline: Instant::now() + Duration::from_millis(10),
                        };
                        let progress = lane
                            .poll_joint_commit(&mut coordinator, &mut budget)
                            .map_err(|reason| anyhow::anyhow!("{tag}: poll refused: {reason}"))?;
                        eprintln!("JOINT_STOP {tag}: poll{slice}: progress={progress:?}");
                    }
                    eprintln!(
                        "JOINT_STOP {tag}: slice{slice}: drive={:?} stash={:?} stuck={:?}",
                        lane.joint_drive_state_for_test(),
                        lane.stash_pending_floor(),
                        lane.joint_stuck_diagnostic_for_test(),
                    );
                }
            }
            Prep::FullQ2 => {
                let q2_polls =
                    service_to_published(&mut lane, &mut coordinator, false, &format!("{tag}-q2"))?;
                eprintln!(
                    "JOINT_STOP {tag}: q2 published in {q2_polls} polls: drive={:?} stash={:?} \
                     stuck={:?}",
                    lane.joint_drive_state_for_test(),
                    lane.stash_pending_floor(),
                    lane.joint_stuck_diagnostic_for_test(),
                );
            }
        }
    }
    eprintln!("JOINT_STOP {tag}: prep={prep:?} done; stopping in {offset_ms} ms");
    // The wedge needs Joint births, which need the journal build: only a
    // session whose loaded object carries both journal roots seals linked.
    // Default builds stage S1 directly and can never wedge (the full
    // matrix passes pre-fix on S1), so running on would be a dry pass.
    // Fail loudly with the branch tag instead.
    if !matches!(joint_branch(&coordinator), JointBranch::Linked) {
        eprintln!("P11SCOPE_CELL_BRANCH={tag}:s1-precluded");
        anyhow::bail!(
            "{tag}: no joint feeds: the wedge needs a journal-build libtest \
             (P11SCOPE_JOURNAL=1 P11SCOPE_BIRTH_MARKER=1); not attempted"
        );
    }
    eprintln!("P11SCOPE_CELL_BRANCH={tag}:linked");
    std::thread::sleep(Duration::from_millis(offset_ms));
    // Stop through the production finish driver; every loop is bounded.
    let mut driver = joint_finish_driver(&mut coordinator, lane);
    driver.begin_final_joint_finish();
    let begin = match &driver.joint_finish {
        JointFinishDriver::Polling => "polling",
        JointFinishDriver::Published => "published-at-begin",
        JointFinishDriver::Abandoned => "abandoned-at-begin",
        JointFinishDriver::NotBegun => "not-begun",
    }
    .to_string();
    let mut finish_polls = 0u64;
    let finish = if !matches!(driver.joint_finish, JointFinishDriver::Polling) {
        match &driver.joint_finish {
            JointFinishDriver::Published => "published".to_string(),
            JointFinishDriver::Abandoned => "abandoned".to_string(),
            JointFinishDriver::NotBegun => "not-begun".to_string(),
            JointFinishDriver::Polling => unreachable!(),
        }
    } else {
        let started = Instant::now();
        loop {
            if finish_polls >= 1000 || started.elapsed() > Duration::from_secs(120) {
                break "unpublished".to_string();
            }
            {
                let (coordinator, semantic, joint_finish, first_error) = (
                    &mut *driver.coordinator,
                    &mut driver.semantic,
                    &mut driver.joint_finish,
                    &mut driver.joint_first_error,
                );
                let _step = ClassicDriver::step_begun_joint_finish(
                    semantic,
                    joint_finish,
                    coordinator,
                    first_error,
                );
            }
            finish_polls += 1;
            match &driver.joint_finish {
                JointFinishDriver::Published => break "published".to_string(),
                JointFinishDriver::Abandoned => break "abandoned".to_string(),
                JointFinishDriver::Polling | JointFinishDriver::NotBegun => {}
            }
        }
    };
    let first_error = driver.joint_first_error.clone();
    let lane_ref = driver.semantic.as_ref().expect("lane");
    let latched = lane_ref.joint_finish_disposition_required();
    let latch_code = lane_ref
        .joint_disposition_reason()
        .map(|reason| reason.code().to_string());
    eprintln!(
        "JOINT_STOP {tag}: finish={finish} after {finish_polls} polls; \
         first_error={first_error:?} latched={latched} latch={latch_code:?}"
    );
    let h0_stop = {
        let (coordinator, semantic) = (&mut *driver.coordinator, &mut driver.semantic);
        let lane = semantic.as_mut().expect("lane");
        match lane.finish_semantic_stop() {
            Some(batch) => {
                coordinator.stage_semantic_batch(batch);
                lane.note_semantic_staged();
                match commit_semantic_finish(coordinator, lane) {
                    Ok(()) => {
                        lane.note_semantic_published();
                        if lane.is_finished() {
                            "committed".to_string()
                        } else {
                            "committed-unfinished".to_string()
                        }
                    }
                    Err(error) => format!("commit-refused:{error}"),
                }
            }
            None => {
                if lane.is_finished() {
                    "no-batch-finished".to_string()
                } else {
                    "no-batch-unfinished".to_string()
                }
            }
        }
    };
    let mut wound_polls = 0u64;
    let wound = loop {
        if wound_polls >= 600 {
            break "unwound".to_string();
        }
        let (coordinator, semantic) = (&mut *driver.coordinator, &mut driver.semantic);
        let lane = semantic.as_mut().expect("lane");
        match lane.poll_wound_down(coordinator, &mut std::io::sink()) {
            Ok(true) => break "joined".to_string(),
            Ok(false) => {}
            Err(refusal) => break format!("wound-refused:{refusal}"),
        }
        wound_polls += 1;
        std::thread::sleep(Duration::from_millis(10));
    };
    let domain = driver.semantic.as_ref().expect("lane").domain();
    let take = driver
        .semantic
        .as_mut()
        .expect("lane")
        .take_joined_session();
    let taken = matches!(&take, Ok(Some(_)));
    let mut minted = false;
    if let Ok(Some(session)) = take {
        let mut minter = crate::attach::NativeCompletionMinter::new();
        minter.note_wound_down(domain, session);
        let started = Instant::now();
        loop {
            if let Some(completion) = minter.poll_completion(domain) {
                if completion.domain() == domain && minter.take_first_failure().is_none() {
                    minted = true;
                }
                break;
            }
            if started.elapsed() >= Duration::from_secs(30) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let lane_ref = driver.semantic.as_ref().expect("lane");
    let stash_floor = lane_ref.stash_pending_floor();
    let counts = lane_ref.semantic_stop_call_counts();
    let lane_shed = lane_ref.shed_calls_disclosed();
    let edge_a = joint_edge_snapshot(driver.coordinator, process_a.pid(), "live-joint-held.so")?;
    let edge_b = joint_edge_snapshot(driver.coordinator, process_b.pid(), "soft-copy.so")?;
    for (name, edge) in [("a", &edge_a), ("b", &edge_b)] {
        eprintln!(
            "JOINT_STOP {tag}: edge_{name} joint={} reduced={} started={:?} completed={:?} \
             mechanisms={}",
            edge.joint,
            edge.reduced,
            edge.started,
            edge.completed,
            edge.mechanisms.len(),
        );
    }
    let (per_function_a, _, _) = ledger_calls(&process_a.out)?;
    let (a_semantic, a_count_only) = ledger_semantic_split(&per_function_a);
    let (per_function_b, _, _) = ledger_calls(&process_b.out)?;
    let (b_semantic, b_count_only) = ledger_semantic_split(&per_function_b);
    let caller_a = caller_of(driver.coordinator, process_a.pid())?;
    let caller_b = caller_of(driver.coordinator, process_b.pid())?;
    let api_b = edge_b.api_returns.unwrap_or(0);
    let slot_a = count_disclosed_gaps(
        driver.coordinator,
        "semantic input refused",
        "slot",
        Some(caller_a),
    );
    let slot_b = count_disclosed_gaps(
        driver.coordinator,
        "semantic input refused",
        "slot",
        Some(caller_b),
    );
    let inst_a = driver
        .coordinator
        .registry()
        .instance_calls_refused(caller_a);
    let inst_b = driver
        .coordinator
        .registry()
        .instance_calls_refused(caller_b);
    let reconcile = assert_semantic_reconciled(
        driver.coordinator,
        lane_shed,
        &format!("{tag}-stop"),
        &[
            (
                "a",
                a_semantic,
                a_count_only,
                a_semantic + a_count_only,
                edge_a.api_returns.unwrap_or(0),
                slot_a,
                inst_a,
            ),
            (
                "b",
                b_semantic,
                b_count_only,
                b_semantic + b_count_only,
                api_b,
                slot_b,
                inst_b,
            ),
        ],
    );
    let (reconciled, reconcile_detail) = match reconcile {
        Ok(()) => (true, "reconciled".to_string()),
        Err(error) => (false, format!("{error:?}")),
    };
    let abandon_gap = driver
        .coordinator
        .registry()
        .gaps()
        .iter()
        .find(|gap| {
            gap.subject == "unfinished joint publication abandoned"
                || gap.subject == "for exit"
                || gap.subject == "for lane stop"
        })
        .map(|gap| format!("{}: {}", gap.subject, gap.reason));
    let branch = match joint_branch(driver.coordinator) {
        JointBranch::Linked => "linked",
        JointBranch::S1 => "s1",
        JointBranch::Unattributed => "unattributed",
    }
    .to_string();
    for gap in driver.coordinator.registry().gaps().iter() {
        eprintln!(
            "JOINT_STOP {tag}: gap {:?} {:?} caller={:?}",
            gap.subject, gap.reason, gap.caller
        );
    }
    Ok(StopOutcome {
        offset_ms,
        begin,
        finish_polls,
        finish,
        first_error,
        latched,
        latch_code,
        h0_stop,
        wound,
        wound_polls,
        taken,
        minted,
        stash_floor,
        stop_counts: counts,
        api_a: edge_a.api_returns.unwrap_or(0),
        a_semantic,
        lane_shed,
        reconciled,
        reconcile_detail,
        abandon_gap,
        branch,
    })
}

/// WP-7 S3: stop the Joint finish 0, 1, 5 and 20 ms after the refresh
/// that resolves the last waiter, across three prep shapes (one service
/// slice, one service+poll slice, the full q2). Every combination must
/// reach Published, then WoundDown; the at-Q tick publishes the stashed
/// calls; a latched machine names its code in both the abandon gap and
/// the run error; and a finish that abandons with resolved calls still
/// in the lane stash counts them or gaps them, never silently. Run the
/// journal flavor (`P11SCOPE_JOURNAL=1 P11SCOPE_BIRTH_MARKER=1`):
/// default builds seal S1 and fail loudly with the s1-precluded branch
/// tag instead of passing dry.
/// `WP7_STOP_PREPS` / `WP7_STOP_OFFSETS` (comma-separated indices,
/// default all) narrow the matrix for exploration.
#[test]
#[ignore = "privileged: live Joint stop after the last waiter resolves"]
fn privileged_joint_stop_after_last_waiter_resolves_publishes_final_lp64() -> Result<()> {
    let workload = JointWorkload::build()?;
    let soft_manifest = provider_joint_manifest(
        workload.workload.dir.path(),
        &workload.soft_copy,
        JOINT_SOFT_FUNCTIONS,
        "wp7-soft.dr37.json",
    )?;
    let held_manifest = provider_joint_manifest(
        workload.workload.dir.path(),
        &workload.held,
        &["C_SignInit", "C_Sign"],
        "wp7-held.dr37.json",
    )?;
    // Full matrix: three prep shapes times four stop offsets, with
    // the full assert set on every combination; the first failure ends
    // the cell. The journal-build run narrows this to the wedging prep
    // once the matrix shows which prep wedges.
    const PREPS: [Prep; 3] = [Prep::Services(1), Prep::ServicesPolls(1, 1), Prep::FullQ2];
    const OFFSETS_MS: [u64; 4] = [0, 1, 5, 20];
    let want_preps = stop_matrix_selector("WP7_STOP_PREPS", PREPS.len())?;
    let want_offsets = stop_matrix_selector("WP7_STOP_OFFSETS", OFFSETS_MS.len())?;
    for (prep_index, prep) in PREPS.iter().enumerate() {
        if !want_preps.contains(&prep_index) {
            continue;
        }
        for (offset_index, offset) in OFFSETS_MS.iter().enumerate() {
            if !want_offsets.contains(&offset_index) {
                continue;
            }
            run_stop_case(
                &workload,
                &soft_manifest,
                &held_manifest,
                *prep,
                *offset,
                prep_index * OFFSETS_MS.len() + offset_index,
            )?;
        }
    }
    Ok(())
}

/// Comma-separated index selector for the stop matrix; unset or empty
/// means every index. A bad value fails the cell, never narrows it.
fn stop_matrix_selector(name: &str, len: usize) -> Result<Vec<usize>> {
    let raw = std::env::var(name).unwrap_or_default();
    if raw.trim().is_empty() {
        return Ok((0..len).collect());
    }
    raw.split(',')
        .map(|part| {
            let index: usize = part
                .trim()
                .parse()
                .with_context(|| format!("bad {name}: {raw:?}"))?;
            ensure!(
                index < len,
                "bad {name}: {raw:?} (want an index below {len})"
            );
            Ok(index)
        })
        .collect()
}

/// One prep times one offset: run the stop and check the full assert set.
fn run_stop_case(
    workload: &JointWorkload,
    soft_manifest: &Path,
    held_manifest: &Path,
    prep: Prep,
    offset_ms: u64,
    index: usize,
) -> Result<()> {
    let outcome = run_stop_offset(
        workload,
        soft_manifest,
        held_manifest,
        prep,
        offset_ms,
        index,
    )?;
    eprintln!("JOINT_STOP outcome: {outcome}");
    eprintln!(
        "P11SCOPE_CELL_BRANCH=offset{offset_ms}:{}:{}",
        if outcome.latched {
            "latched"
        } else {
            "no-latch"
        },
        outcome.finish,
    );
    // (b) The at-Q tick publishes the stashed calls: A's resolved
    // calls reach its edge, or the equation discloses shed loudly.
    if outcome.api_a == outcome.a_semantic {
        eprintln!("JOINT_STOP offset={offset_ms}: at-Q published (api_a == a_semantic)");
    } else if outcome.reconciled && outcome.lane_shed > 0 {
        eprintln!(
            "JOINT_STOP offset={offset_ms}: SHED-SKIPPED (equation holds, shed {}): {}",
            outcome.lane_shed, outcome.reconcile_detail,
        );
    } else {
        anyhow::bail!(
            "offset {offset_ms}: the at-Q tick did not publish the stashed calls: {outcome}"
        );
    }
    // (a) A latched machine names its code twice: abandon gap and run
    // error. A clean finish holds no first error at all.
    if outcome.latched {
        let code = outcome
            .latch_code
            .clone()
            .with_context(|| format!("offset {offset_ms}: latched without a code: {outcome}"))?;
        let gap = outcome.abandon_gap.clone().with_context(|| {
            format!("offset {offset_ms}: latched without an abandon gap: {outcome}")
        })?;
        ensure!(
            gap.contains(&code),
            "offset {offset_ms}: the abandon gap names the latch code {code}: {outcome}"
        );
        let error = outcome.first_error.clone().with_context(|| {
            format!("offset {offset_ms}: latched without a run error: {outcome}")
        })?;
        ensure!(
            error.contains(&code),
            "offset {offset_ms}: the run error names the latch code {code}: {outcome}"
        );
    } else {
        ensure!(
            outcome.first_error.is_none(),
            "offset {offset_ms}: no latch yet a run error: {outcome}"
        );
        eprintln!("JOINT_STOP offset={offset_ms}: no latch (clean finish path)");
    }
    // (c) An abandon with resolved calls still in the lane stash is
    // counted in the stop or named in a gap, never silent; and no
    // abandon gap appears without an abandonment.
    let abandoned = outcome.finish.contains("abandoned") || outcome.begin.contains("abandoned");
    if abandoned && outcome.stash_floor.is_some() {
        ensure!(
            outcome.api_a == outcome.a_semantic || outcome.abandon_gap.is_some(),
            "offset {offset_ms}: abandon with a stashed resolve is counted or gapped: {outcome}"
        );
    } else {
        ensure!(
            outcome.abandon_gap.is_none(),
            "offset {offset_ms}: abandon gap without abandonment: {outcome}"
        );
        eprintln!(
            "JOINT_STOP offset={offset_ms}: no abandon-with-stash \
                 (finish={} stash={:?})",
            outcome.finish, outcome.stash_floor,
        );
    }
    // Primary: the finish reaches Published, then WoundDown.
    ensure!(
        outcome.finish == "published" && outcome.wound == "joined" && outcome.taken,
        "offset {offset_ms}: the finish must reach Published then WoundDown: {outcome}"
    );
    Ok(())
}
