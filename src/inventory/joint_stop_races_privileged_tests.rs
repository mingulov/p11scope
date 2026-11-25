//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! WP-7 linked-stop cell (12-case prep/offset matrix): request the Joint
//! finish 0, 1, 5 and 20 ms after the post-release prep flow, and pin
//! Published-then-WoundDown, the at-Q stash publication, and the abandon
//! naming lines. Root BPF lane, run serially. A live last waiter before
//! stop is unreachable (collected ticks resolve waiters same tick), so
//! the matrix stands as linked stop coverage; the last-waiter invariant
//! is carried by the machine twins named on the test cell.
//! The held-call fixture below
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
        getters: Vec::new(),
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
        vec![],
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
    // The wedge needs Joint births, which need the linked journal
    // session; `None` would seal S1 and every case would preclude below.
    let journal = crate::attach::journal::JournalSpec { key_sizes: false };
    let mut lane = crate::inventory_semantics::AttestedSemanticLane::start_live(
        attach_subset,
        convert_subset,
        &scope,
        crate::attach::BackendSelection::Auto,
        Some(&journal),
    )
    .map_err(|refusal| anyhow::anyhow!("live lane attaches: {refusal}"))?;
    ensure!(lane.is_live(), "the lane owns its live session");
    lane.initialize_joint(coordinator)
        .map_err(|refusal| anyhow::anyhow!("the joint machine initializes: {refusal}"))?;
    ensure!(lane.has_joint_machine(), "the machine initializes live");
    joint_drive_line(&lane, coordinator, "r16-lane", "started");
    Ok(lane)
}

/// Flag-on variant of [`start_joint_lane`], duplicated from
/// `privileged_tests.rs` (`start_joint_lane_with_journal`): the lane
/// starts with a journal request, so on a journal build the session
/// seals linked. The seal-pending cell needs linked births; the
/// stop-after-last-waiter matrix above keeps its S1 starter.
fn start_joint_lane_with_journal(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    manifests: Vec<PathBuf>,
) -> Result<crate::inventory_semantics::AttestedSemanticLane> {
    ensure!(
        env!("P11SCOPE_JOURNAL_ENABLED") == "1",
        "a linked lane requires P11SCOPE_JOURNAL=1"
    );
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
    let spec = crate::attach::journal::JournalSpec;
    let mut lane = crate::inventory_semantics::AttestedSemanticLane::start_live(
        attach_subset,
        convert_subset,
        &scope,
        crate::attach::BackendSelection::Auto,
        Some(&spec),
    )
    .map_err(|refusal| anyhow::anyhow!("linked live lane attaches: {refusal}"))?;
    ensure!(lane.is_live(), "the lane owns its live session");
    lane.initialize_joint(coordinator)
        .map_err(|refusal| anyhow::anyhow!("the joint machine initializes: {refusal}"))?;
    ensure!(lane.has_joint_machine(), "the machine initializes live");
    joint_drive_line(&lane, coordinator, "r16-lane", "started-linked");
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
    eprintln!(
        "JOINT_R16 {tag} step={step} {}",
        joint_drive_text(lane, coordinator)
    );
}

/// The drive-state fields of one JOINT_R16 line (also the no-feed
/// probe's `drive`).
fn joint_drive_text(
    lane: &crate::inventory_semantics::AttestedSemanticLane,
    coordinator: &InventoryCoordinator<OsProcessSource>,
) -> String {
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
    format!(
        "live={} gated={} finished={} ticks={ticks} \
         phase={phase} demand={demand} work={work} base={base} staging={staging} \
         revision={} feeds={} stuck={stuck} trip={trip}",
        u8::from(live),
        u8::from(gated),
        u8::from(finished),
        coordinator.registry().published_revision(),
        coordinator.registry().joint_feeds(),
    )
}

/// What the cell sampled when a case produced no Joint feeds: the two
/// branch inputs, the unlinked-backstop count, the first birth
/// capacity refusal, the drive state and every registry gap by
/// (subject, reason) with its count (repeats included, like the typed
/// counters below). Carried in the verdict record so a no-feed refusal
/// names its evidence instead of "unexplained".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct NoFeedProbe {
    joint_feeds: u64,
    journal_linked: bool,
    backstop_routed: u64,
    birth_capacity: Option<String>,
    drive: String,
    gaps: Vec<NoFeedGap>,
    /// Typed no-feed causes, each counted with repeats: the held
    /// caller's `no_receipt` deferrals, the caller-less `partition`
    /// receipt refusals, the lane's disclosed shed split into calls not
    /// proven foreign (`shed`) and calls proven foreign
    /// (`foreign_shed`), and the Joint feeds that fell back to S1
    /// (`fallback`, the `joint_fallback_*` endings).
    no_receipt: u64,
    partition: u64,
    shed: u64,
    foreign_shed: u64,
    fallback: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct NoFeedGap {
    subject: String,
    reason: String,
    count: u64,
}

fn no_feed_probe(
    lane: &crate::inventory_semantics::AttestedSemanticLane,
    coordinator: &InventoryCoordinator<OsProcessSource>,
    held: crate::discovery::caller_registry::CallerId,
) -> NoFeedProbe {
    let registry = coordinator.registry();
    let starved = receipt_starvation(coordinator, held);
    let shed = lane_shed_split(coordinator, lane.shed_calls_disclosed());
    NoFeedProbe {
        joint_feeds: registry.joint_feeds() as u64,
        journal_linked: registry.journal_linked(),
        backstop_routed: registry.joint_backstop_routed(),
        birth_capacity: registry
            .first_birth_capacity()
            .map(|latch| format!("{latch:?}")),
        drive: joint_drive_text(lane, coordinator),
        gaps: no_feed_gaps_from(
            registry
                .gaps()
                .iter()
                .zip(registry.gap_repeats().iter())
                .map(|(gap, repeats)| (gap.subject.as_str(), gap.reason.as_str(), *repeats)),
        ),
        no_receipt: starved.no_receipt,
        partition: starved.partition,
        shed: shed.unproven,
        foreign_shed: shed.foreign,
        fallback: joint_fallbacks(coordinator),
    }
}

/// Every gap by (subject, reason), summing repeats, so a row's count is
/// the same unit as the typed counters (never one per registry entry).
fn no_feed_gaps_from<'a>(gaps: impl Iterator<Item = (&'a str, &'a str, u64)>) -> Vec<NoFeedGap> {
    let mut counts: BTreeMap<(String, String), u64> = BTreeMap::new();
    for (subject, reason, repeats) in gaps {
        let count = counts
            .entry((subject.to_string(), reason.to_string()))
            .or_default();
        *count = count.saturating_add(repeats);
    }
    counts
        .into_iter()
        .map(|((subject, reason), count)| NoFeedGap {
            subject,
            reason,
            count,
        })
        .collect()
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
/// capacity shed that has no counter, and the foreign shed that must be
/// absent in a fixture-only run.
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

/// Whether a shed breakdown label names a producer route-loss reason:
/// the finite router vocabulary plus the pending-join state. Both
/// counted producers disclose only these names.
fn is_shed_label(label: &str) -> bool {
    matches!(
        label,
        "foreign_domain"
            | "authority_exhausted"
            | "invalid_image"
            | "unstamped"
            | "no_file"
            | "shared_mm"
            | "overflow"
            | "local_fault"
            | "straddle"
            | "fault_era"
            | "sticky"
            | "coverage_fault"
            | "unobserved"
            | "evicted"
            | "ip_outside"
            | "not_executable"
            | "offset_mismatch"
            | "unpartitionable"
            | "instance_capacity"
            | "range_capacity"
            | "pending_capacity"
            | "binding_capacity"
            | "retired"
            | "pending"
    )
}

/// Whether a dropped-batch word names a producer batch: the five
/// stash/drop sites that disclose through the dropped template.
fn is_drop_word(word: &str) -> bool {
    matches!(
        word,
        "ended_domain" | "backpressure" | "abandoned" | "no_lane" | "oversized"
    )
}

/// Parse one counted shed reason to its disclosed total, requiring an
/// exact producer template, a canonical binding count, and named
/// recognized breakdown entries that sum to the total. Accepts only the
/// two counted templates for `semantic calls unrouted`: the aggregated
/// `{total} calls shed without a route ({labels}) with {N} bindings`
/// and the dropped-batch `{total} calls shed from a dropped {drop}
/// batch ({labels}) with {N} bindings`. Returns None on any other
/// shape, an unparsable or non-canonical count, an empty or unknown
/// label, a duplicate label, an unknown drop word, or a breakdown
/// mismatch.
fn parse_unrouted_gap_total(reason: &str) -> Option<u64> {
    let (total_str, rest) = reason.split_once(" calls shed ")?;
    let total: u64 = total_str.parse().ok()?;
    if total == 0 || total_str != total.to_string() {
        return None;
    }
    let (labels_part, bindings_part) = if let Some(after) = rest.strip_prefix("without a route (") {
        let (labels, after_labels) = after.split_once(") with ")?;
        (labels, after_labels)
    } else {
        let after = rest.strip_prefix("from a dropped ")?;
        let (drop, after_drop) = after.split_once(" batch (")?;
        if !is_drop_word(drop) {
            return None;
        }
        let (labels, after_labels) = after_drop.split_once(") with ")?;
        (labels, after_labels)
    };
    let bindings_str = bindings_part.strip_suffix(" bindings")?;
    let bindings: usize = bindings_str.parse().ok()?;
    if bindings_str != bindings.to_string() {
        return None;
    }
    if labels_part.is_empty() || labels_part != labels_part.trim() || labels_part.contains("  ") {
        return None;
    }
    let mut sum = 0u64;
    let mut seen = std::collections::BTreeSet::new();
    for part in labels_part.split(' ') {
        let (label, count_str) = part.split_once('=')?;
        if label.is_empty() || count_str.is_empty() || count_str.contains('=') {
            return None;
        }
        if !is_shed_label(label) {
            return None;
        }
        let count: u64 = count_str.parse().ok()?;
        if count == 0 || count_str != count.to_string() {
            return None;
        }
        if !seen.insert(label) {
            return None;
        }
        sum = sum.saturating_add(count);
    }
    if seen.is_empty() || sum != total {
        return None;
    }
    Some(total)
}

/// Summed disclosed total across every caller-less `semantic calls
/// unrouted` row, multiplying each row's parsed total by its repeats.
/// Fails naming the offending reason when any row does not parse.
fn sum_unrouted_disclosed(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    tag: &str,
) -> Result<u64> {
    let registry = coordinator.registry();
    let mut total = 0u64;
    for (gap, repeats) in registry.gaps().iter().zip(registry.gap_repeats().iter()) {
        if gap.caller.is_some() || gap.subject != "semantic calls unrouted" {
            continue;
        }
        let parsed = parse_unrouted_gap_total(&gap.reason);
        ensure!(
            parsed.is_some(),
            "{tag}: every unrouted gap carries a counted total with a matching breakdown: {:?}",
            gap.reason
        );
        total = total.saturating_add(parsed.unwrap_or(0).saturating_mul(*repeats));
    }
    Ok(total)
}

/// A parsed unrouted-shed gap: (total calls, per-cause counts, bindings).
type UnroutedShedCounts = (u64, Vec<(String, u64)>, usize);

/// Parse an aggregated unrouted reason (`{total} calls shed without a
/// route ({label}={count} ...) with {bindings} bindings`) into
/// (total, labels, bindings). Strict: any shape mismatch errors
/// loudly, so a template change updates the verdict instead of
/// slipping past it. The seal cell's shed branch pins the counts
/// exactly (total against the lane shed counter, bindings against
/// the two fixture callers, label counts summing to the total) while
/// the label names stay diagnostic (they name the load's fault mode,
/// which the test does not control).
fn parse_unrouted_reason(reason: &str) -> Result<UnroutedShedCounts> {
    let (head, bindings) = reason
        .rsplit_once(" with ")
        .context("an unrouted reason ends with ' with {N} bindings'")?;
    let bindings = bindings
        .strip_suffix(" bindings")
        .context("an unrouted reason ends with ' bindings'")?
        .parse::<usize>()
        .context("unrouted bindings parse")?;
    let (total, labels) = head
        .split_once(" calls shed without a route (")
        .context("an unrouted reason starts with '{total} calls shed without a route ('")?;
    let total = total.parse::<u64>().context("unrouted total parses")?;
    let labels = labels
        .strip_suffix(')')
        .context("an unrouted reason closes its label list")?;
    let mut parsed = Vec::new();
    for pair in labels.split_whitespace() {
        let (label, count) = pair
            .split_once('=')
            .with_context(|| format!("unrouted label pair {pair:?}"))?;
        ensure!(!label.is_empty(), "unrouted label {pair:?} names its cause");
        parsed.push((
            label.to_string(),
            count
                .parse::<u64>()
                .context("unrouted label count parses")?,
        ));
    }
    ensure!(!parsed.is_empty(), "an unrouted shed names its causes");
    Ok((total, parsed, bindings))
}

/// Trusted Joint-branch selector. `journal_linked` latches from the
/// drain producers on the birth path, so it still reads the test
/// default (true) when zero births flowed (total shed). Joint
/// installs prove a real linked world; a latched false proves the
/// latch ran (births flowed, producers unlinked); linked-true with
/// zero installs is unattributed unless a typed cause is present: feeds
/// that installed during the join and then all fell back, else a
/// starved birth receipt (the held caller's `no_receipt` deferral or a
/// caller-less `partition` refusal), else calls not proven foreign
/// that the lane shed without a route. Each is its own failing cause.
enum JointBranch {
    Linked,
    S1,
    FellBack,
    ReceiptStarved,
    CallsShed,
    Unattributed,
}

/// The branch of the session as it stands, given the join that ran
/// before it: `held` is the held caller (its own deferrals count),
/// `lane_shed` the lane's disclosed shed count (the proven-foreign
/// share never names fixture loss).
fn joint_branch(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    lane_shed: u64,
    held: crate::discovery::caller_registry::CallerId,
    join: &StopJoin,
) -> JointBranch {
    let starved = receipt_starvation(coordinator, held);
    joint_branch_from(
        coordinator.registry().joint_feeds(),
        coordinator.registry().journal_linked(),
        join.feeds > 0,
        starved.no_receipt + starved.partition > 0,
        lane_shed_split(coordinator, lane_shed).unproven > 0,
    )
}

/// Pure branch decision over the registry inputs: installs prove a
/// linked world, a latched-unlinked seal proves S1, zero installs on a
/// linked session names its typed cause (feeds seen at the join's end
/// that fell back first, then a starved birth receipt, then shed
/// calls), and only no typed cause is unattributed (never S1).
fn joint_branch_from(
    joint_feeds: usize,
    journal_linked: bool,
    join_fed: bool,
    receipt_starved: bool,
    calls_shed: bool,
) -> JointBranch {
    if joint_feeds > 0 {
        JointBranch::Linked
    } else if !journal_linked {
        JointBranch::S1
    } else if join_fed {
        JointBranch::FellBack
    } else if receipt_starved {
        JointBranch::ReceiptStarved
    } else if calls_shed {
        JointBranch::CallsShed
    } else {
        JointBranch::Unattributed
    }
}

/// Quanta the cell keeps servicing after q1, while the call is still
/// held, before it judges a linked session that has no Joint feed yet.
/// On a busy host the first quantum fills with ~1024 rows of system
/// traffic before the held caller's birth binds, and the feeds arrive
/// on the next quantum (~40 ms later). A deferred admission
/// (`no_receipt`) or a refused receipt (`partition`) is retried only on
/// the next discovery pass, so the join also runs passes (see
/// `STOP_JOIN_PASS_EVERY`). 32 quanta with 4 passes is a wide margin
/// over the observed need (saved runs joined after one quantum; no
/// saved run has yet shown a pass curing a deferred receipt) and still
/// ends a real starvation in bounded time. An unlinked session does
/// not wait.
const STOP_JOIN_QUANTA: u64 = 32;

/// One discovery pass before the 2nd, 10th, 18th and 26th join
/// quantum: the first extra quantum catches a birth that missed q1's
/// full quantum; each pass offers a deferred or refused receipt its
/// retry, followed by quanta to bind it.
const STOP_JOIN_PASS_EVERY: u64 = 8;

/// Pure pass schedule: a discovery pass is due before quantum
/// `quanta + 1` when `quanta % STOP_JOIN_PASS_EVERY == 1`.
fn stop_join_pass_due(quanta: u64) -> bool {
    quanta % STOP_JOIN_PASS_EVERY == 1
}

/// Passes the schedule runs over a join of `quanta` quanta.
fn stop_join_passes_for(quanta: u64) -> u64 {
    (quanta + STOP_JOIN_PASS_EVERY - 2) / STOP_JOIN_PASS_EVERY
}

/// Pure join decision: keep servicing while the session is linked,
/// has no Joint feed and the bound is not spent.
fn stop_join_continues(joint_feeds: usize, journal_linked: bool, quanta: u64) -> bool {
    joint_feeds == 0 && journal_linked && quanta < STOP_JOIN_QUANTA
}

/// One step of the join, decided before it runs: stop, service one
/// quantum, or drive a discovery pass and then service the quantum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JoinStep {
    Stop,
    Quantum,
    PassThenQuantum,
}

/// Pure step decision the drive's join loop follows verbatim.
fn stop_join_step(joint_feeds: usize, journal_linked: bool, quanta: u64) -> JoinStep {
    if !stop_join_continues(joint_feeds, journal_linked, quanta) {
        JoinStep::Stop
    } else if stop_join_pass_due(quanta) {
        JoinStep::PassThenQuantum
    } else {
        JoinStep::Quantum
    }
}

/// What the join spent and saw: quanta serviced after q1, discovery
/// passes driven, and the Joint feeds installed when it ended (a
/// nonzero count that is gone at the linkage decision fell back).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StopJoin {
    quanta: u64,
    passes: u64,
    feeds: u64,
}

/// The typed birth-receipt starvation evidence: registry gaps counted
/// with their repeats by exact (subject, reason) code and binding. The
/// codes are the product's frozen gap vocabulary:
/// `AdmissionPreparationError::NoReceipt` (a deferral recorded for its
/// caller; only the held caller's count) and
/// `CurrentReceiptRefusal::Partition` (recorded caller-less, so it
/// names the session, never a caller).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ReceiptStarvation {
    no_receipt: u64,
    partition: u64,
}

fn receipt_starvation(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    held: crate::discovery::caller_registry::CallerId,
) -> ReceiptStarvation {
    let registry = coordinator.registry();
    receipt_starvation_from(
        held,
        registry
            .gaps()
            .iter()
            .zip(registry.gap_repeats().iter())
            .map(|(gap, repeats)| {
                (
                    gap.caller,
                    gap.subject.as_str(),
                    gap.reason.as_str(),
                    *repeats,
                )
            }),
    )
}

fn receipt_starvation_from<'a, C: PartialEq>(
    held: C,
    gaps: impl Iterator<Item = (Option<C>, &'a str, &'a str, u64)>,
) -> ReceiptStarvation {
    let mut starved = ReceiptStarvation::default();
    for (caller, subject, reason, repeats) in gaps {
        match (subject, reason) {
            ("semantic admission deferred", "semantic_unavailable:no_receipt")
                if caller.as_ref() == Some(&held) =>
            {
                starved.no_receipt = starved.no_receipt.saturating_add(repeats);
            }
            ("semantic receipt refused", "partition") if caller.is_none() => {
                starved.partition = starved.partition.saturating_add(repeats);
            }
            _ => {}
        }
    }
    starved
}

/// The lane's disclosed shed split by proof: `foreign` is the share the
/// registry proved came from callers other than the bound ones; the
/// rest (`unproven`) is the bound callers' shed plus any dropped-batch
/// shed nobody was proven to own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LaneShedSplit {
    unproven: u64,
    foreign: u64,
}

fn lane_shed_split(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    lane_shed: u64,
) -> LaneShedSplit {
    lane_shed_split_from(lane_shed, coordinator.registry().foreign_unrouted_calls())
}

fn lane_shed_split_from(lane_shed: u64, foreign: u64) -> LaneShedSplit {
    LaneShedSplit {
        unproven: lane_shed.saturating_sub(foreign),
        foreign,
    }
}

/// Joint feeds that ended in an ordered fallback to S1, counted with
/// repeats from their named `joint_fallback_<cause>` endings.
fn joint_fallbacks(coordinator: &InventoryCoordinator<OsProcessSource>) -> u64 {
    let registry = coordinator.registry();
    joint_fallbacks_from(
        registry
            .gaps()
            .iter()
            .zip(registry.gap_repeats().iter())
            .map(|(gap, repeats)| (gap.subject.as_str(), gap.reason.as_str(), *repeats)),
    )
}

fn joint_fallbacks_from<'a>(gaps: impl Iterator<Item = (&'a str, &'a str, u64)>) -> u64 {
    gaps.filter(|(subject, reason, _)| {
        *subject == crate::inventory_present::JOINT_RETAINED_S1_SUBJECT
            && reason.starts_with("joint_fallback_")
    })
    .fold(0u64, |total, (_, _, repeats)| total.saturating_add(repeats))
}

/// Branch tag printed for a stop case that produced no Joint feeds.
/// S1 keeps its proven environmental tag; the unattributed default
/// gets its own tag so the suite cannot mistake an unexplained
/// absence of feeds for a proven preclusion. Linked runs no tag.
fn no_feed_branch_tag(branch: &JointBranch) -> Option<&'static str> {
    match branch {
        JointBranch::Linked => None,
        JointBranch::S1 => Some("s1-precluded"),
        JointBranch::FellBack => Some("no-feeds-fell-back"),
        JointBranch::ReceiptStarved => Some("no-feeds-receipt-starved"),
        JointBranch::CallsShed => Some("no-feeds-calls-shed"),
        JointBranch::Unattributed => Some("no-feeds-unattributed"),
    }
}

/// Reason fragment for a stop case that produced no Joint feeds,
/// reporting what the cell sampled: the latched producer linkage
/// and the installed-feed count behind the branch decision.
fn no_feed_reason(branch: &JointBranch) -> Option<&'static str> {
    match branch {
        JointBranch::Linked => None,
        JointBranch::S1 => Some("no joint feeds with S1 seal (producers unlinked, zero installs)"),
        JointBranch::FellBack => Some(
            "no joint feeds from the linked session: feeds installed during the join and \
             none remained; endings in gaps (ordered fallbacks counted in fallback)",
        ),
        JointBranch::ReceiptStarved => Some(
            "no joint feeds from the linked session: the held caller's birth admission was \
             deferred (no_receipt) or a session birth receipt was refused (partition, \
             caller-less) and no later birth bound",
        ),
        JointBranch::CallsShed => Some(
            "no joint feeds from the linked session: calls not proven foreign were shed \
             without a route (counted in shed, foreign shed apart) and no birth bound",
        ),
        JointBranch::Unattributed => {
            Some("no joint feeds without S1 seal (producers linked, zero installs unexplained)")
        }
    }
}

/// Uniform semantic reconciliation (release-path §4.3): every entered
/// fixture call is attributed on its edge (`api`), refused at input
/// as count-only (`slot`), refused before application for an unproven
/// or unbound instance (`inst`, counted per call), or shed in the
/// named caller-less route-loss gap whose total the lane counts
/// (`shed`). Only fixtures call into the providers, so the lane shed
/// total is all fixture calls. Each caller's api/slot/inst never
/// exceed its ledger splits (no over-attribution, no over-refusal);
/// each caller's residual deficit is then nonnegative, so no
/// caller's surplus can hide another caller's loss. With no shed
/// every deficit is zero; with shed the deficits sum to the counted,
/// disclosed shed, and the retained unrouted rows disclose that same
/// total with a matching label breakdown. An instance refusal needs
/// its retained per-call reason (`instance_unproven`/`caller_unbound`)
/// for that caller's edge with no registration refusal on the caller
/// (the per-call counter carries the arithmetic per R-59; gap rows
/// only prove disclosure, never count calls). A silent drop breaks
/// its caller's equation. Capacity shed has no counter, so any
/// capacity gap fails; foreign shed must be absent in a fixture-only
/// run; shed without a printed counted gap, a gap without the lane
/// count, an unparsable total, or any suppression fails too.
///
/// One owner's measured populations for stop reconciliation: the ledger
/// splits (`sem`/`count_only`/`entered`), the edge attribution (`api`),
/// the disclosed slot refusals (`slot`), and the per-call instance
/// refusals (`inst`, R-59). `caller`/`module` identify the fixture edge
/// whose retained gap rows disclose the instance refusals.
struct StopOwnerLedger {
    name: &'static str,
    caller: crate::discovery::caller_registry::CallerId,
    module: crate::discovery::caller_registry::ModuleId,
    sem: u64,
    count_only: u64,
    entered: u64,
    api: u64,
    slot: u64,
    inst: u64,
}

fn assert_semantic_reconciled(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    lane_shed: u64,
    tag: &str,
    owners: &[StopOwnerLedger],
) -> Result<()> {
    ensure!(
        owners.len() == 2,
        "{tag}: reconciliation covers exactly the two fixture owners, never a subset: got {}",
        owners.len()
    );
    ensure!(
        owners[0].caller != owners[1].caller,
        "{tag}: the two owners name distinct callers"
    );
    let mut parts = Vec::new();
    let (mut deficit_sum, mut slot_sum) = (0u64, 0u64);
    for owner in owners {
        let StopOwnerLedger {
            name,
            caller,
            module,
            sem,
            count_only,
            entered,
            api,
            slot,
            inst,
        } = owner;
        ensure!(
            api <= sem,
            "{tag}: {name} never over-attributes: api {api} <= sem {sem}"
        );
        ensure!(
            slot <= count_only,
            "{tag}: {name} never over-refuses: slot {slot} <= count-only {count_only}"
        );
        let sem_remaining = sem.saturating_sub(*api);
        ensure!(
            inst <= &sem_remaining,
            "{tag}: {name} never over-refuses instances: inst {inst} <= sem-api {sem_remaining} \
             (sem {sem} api {api})"
        );
        let accounted = api.saturating_add(*slot).saturating_add(*inst);
        ensure!(
            &accounted <= entered,
            "{tag}: {name} never over-accounts: api {api} + slot {slot} + inst {inst} <= entered {entered}"
        );
        ensure!(
            !coordinator.registry().registration_refused(*caller),
            "{tag}: {name} has no refused registration to hide behind a call gap: \
             caller {caller:?}"
        );
        let other_input = coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "semantic input refused"
                && gap.caller == Some(*caller)
                && gap.reason != "slot"
        });
        ensure!(
            !other_input,
            "{tag}: {name} carries only slot input refusals, never another conversion cause: \
             caller {caller:?}"
        );
        let edge_gaps: Vec<_> = coordinator
            .registry()
            .gaps()
            .iter()
            .filter(|gap| {
                gap.subject == "instance semantics refused"
                    && gap.caller == Some(*caller)
                    && gap.module == Some(*module)
            })
            .collect();
        if *inst > 0 {
            let disclosed = edge_gaps
                .iter()
                .any(|gap| gap.reason == "instance_unproven" || gap.reason == "caller_unbound");
            ensure!(
                disclosed,
                "{tag}: {name} instance refusals carry a retained per-call reason for their edge: \
                 inst {inst} caller {caller:?} module {module:?}"
            );
            let foreign = edge_gaps
                .iter()
                .any(|gap| gap.reason != "instance_unproven" && gap.reason != "caller_unbound");
            ensure!(
                !foreign,
                "{tag}: {name} carries only per-call instance reasons, never a registration cause: \
                 caller {caller:?} module {module:?}"
            );
        } else {
            ensure!(
                edge_gaps.is_empty(),
                "{tag}: {name} carries no instance gap without a refused call: \
                 caller {caller:?} module {module:?}"
            );
        }
        let deficit = entered.saturating_sub(accounted);
        parts.push(format!(
            "{name}(entered={entered} sem={sem} api={api} co={count_only} slot={slot} \
             inst={inst} deficit={deficit})"
        ));
        deficit_sum = deficit_sum.saturating_add(deficit);
        slot_sum = slot_sum.saturating_add(*slot);
    }
    let unrouted_total = sum_unrouted_disclosed(coordinator, tag)?;
    let capacity_entries =
        count_callerless_gap_entries(coordinator, "semantic call outcome capacity");
    let foreign_entries =
        count_callerless_gap_entries(coordinator, "semantic calls unrouted from other callers");
    let foreign_calls = coordinator.registry().foreign_unrouted_calls();
    let suppressed = coordinator.registry().gaps_suppressed();
    eprintln!(
        "JOINT_R16 {tag}-reconcile {} shed={lane_shed} deficits={deficit_sum} \
         unrouted_total={unrouted_total} capacity_entries={capacity_entries} \
         foreign_entries={foreign_entries} foreign_calls={foreign_calls} \
         suppressed={suppressed}",
        parts.join(" ")
    );
    ensure!(
        capacity_entries == 0,
        "{tag}: no capacity shed without a counter: {capacity_entries} entries"
    );
    ensure!(
        foreign_entries == 0 && foreign_calls == 0,
        "{tag}: no foreign shed in a fixture-only run: entries {foreign_entries}, \
         calls {foreign_calls}"
    );
    ensure!(
        suppressed == 0,
        "{tag}: no suppressed disclosure while reconciling: suppressed {suppressed}, \
         slot {slot_sum}, deficits {deficit_sum}, shed {lane_shed}"
    );
    ensure!(
        unrouted_total == lane_shed,
        "{tag}: the retained unrouted total equals the lane shed count: \
         disclosed {unrouted_total} vs shed {lane_shed}"
    );
    if lane_shed == 0 {
        ensure!(
            deficit_sum == 0,
            "{tag}: every entered call is attributed or refused on its own caller with no shed: \
             caller deficits sum {deficit_sum}"
        );
    } else {
        ensure!(
            deficit_sum == lane_shed,
            "{tag}: nonnegative caller deficits sum to the disclosed shed: \
             deficits {deficit_sum} vs shed {lane_shed}"
        );
    }
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
        seal_scope: Scope::System,
        cgroup: None,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline: None,
        attach_backend: crate::attach::BackendSelection::Auto,
        display: None,
        semantic: Some(lane),
        scan_seal_pending: false,
        scan_seal_last_sets: None,
        scan_seal_stable_runs: 0,
        scan_seal_waited: 0,
        scan_seal_changed: false,
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
        seal_scope: Scope::from(scope),
        cgroup: None,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline,
        attach_backend: crate::attach::BackendSelection::Auto,
        display: None,
        semantic: None,
        scan_seal_pending: false,
        scan_seal_last_sets: None,
        scan_seal_stable_runs: 0,
        scan_seal_waited: 0,
        scan_seal_changed: false,
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

// WP-7 linked-stop cell (a live last waiter before stop is unreachable;
// the matrix stands as linked stop coverage, see the cell doc).
// ---------------------------------------------------------------------------

/// Collected terminal state of one stop-offset sub-case. Every finish loop
/// is bounded and every outcome is collected, never ensured mid-drive, so
/// a wedged finish reports its full state instead of hanging the cell.
/// It serializes field for field into the cell's verdict record.
#[derive(serde::Serialize)]
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
    case: &mut StopCaseRecord,
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
    // A linked session whose first quantum filled before the held
    // caller's birth bound gets its feeds on a following quantum, and a
    // deferred or refused birth receipt is retried on the next
    // discovery pass: service a bounded number more quanta with
    // scheduled passes, still holding the call.
    let mut join = StopJoin::default();
    loop {
        let step = stop_join_step(
            coordinator.registry().joint_feeds(),
            coordinator.registry().journal_linked(),
            join.quanta,
        );
        if step == JoinStep::Stop {
            break;
        }
        if step == JoinStep::PassThenQuantum {
            drive_native_passes_until(&mut coordinator, &mut |passes| Ok(passes >= 1))?;
            join.passes += 1;
        }
        join.quanta += 1;
        service_to_published(
            &mut lane,
            &mut coordinator,
            false,
            &format!("{tag}-join{}", join.quanta),
        )?;
    }
    join.feeds = coordinator.registry().joint_feeds() as u64;
    eprintln!(
        "JOINT_STOP {tag}: q1 published in {q1_polls} polls, joined after {} more quanta and \
         {} passes with {} feeds; releasing the held call",
        join.quanta, join.passes, join.feeds
    );
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
    // The wedge needs Joint births, which need the linked journal
    // session: only a session whose loaded object carries both journal
    // roots seals linked. An S1 seal can never wedge (the full matrix
    // passes pre-fix on S1), so running on would be a dry pass. Fail
    // loudly with the branch tag instead: S1 keeps its proven
    // environmental tag, while the unattributed default (zero feeds,
    // no latched seal) gets its own tag and cause.
    let held = caller_of(&coordinator, process_a.pid())?;
    let branch = joint_branch(&coordinator, lane.shed_calls_disclosed(), held, &join);
    case.link(&branch, join);
    if no_feed_reason(&branch).is_some() {
        case.note_no_feed(no_feed_probe(&lane, &coordinator, held));
    }
    if let Some(reason) = no_feed_reason(&branch) {
        let feed_tag = no_feed_branch_tag(&branch).expect("a reason implies a tag");
        eprintln!("P11SCOPE_CELL_BRANCH={tag}:{feed_tag}");
        anyhow::bail!("{tag}: {reason}; not attempted");
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
    let module_a = module_of(driver.coordinator, "live-joint-held.so")?;
    let module_b = module_of(driver.coordinator, "soft-copy.so")?;
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
            StopOwnerLedger {
                name: "a",
                caller: caller_a,
                module: module_a,
                sem: a_semantic,
                count_only: a_count_only,
                entered: a_semantic + a_count_only,
                api: edge_a.api_returns.unwrap_or(0),
                slot: slot_a,
                inst: inst_a,
            },
            StopOwnerLedger {
                name: "b",
                caller: caller_b,
                module: module_b,
                sem: b_semantic,
                count_only: b_count_only,
                entered: b_semantic + b_count_only,
                api: api_b,
                slot: slot_b,
                inst: inst_b,
            },
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
    let branch = match joint_branch(driver.coordinator, lane_shed, caller_a, &join) {
        JointBranch::Linked => "linked",
        JointBranch::S1 => "s1",
        JointBranch::FellBack => "fell-back",
        JointBranch::ReceiptStarved => "receipt-starved",
        JointBranch::CallsShed => "calls-shed",
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

/// WP-7 S3, curated as linked Joint stop coverage: stop the Joint finish
/// 0, 1, 5 and 20 ms after the post-release prep flow, across three prep
/// shapes (one service slice, one service+poll slice, the full q2). Every
/// combination must reach Published, then WoundDown; the at-Q tick
/// publishes the stashed calls; a latched machine names its code in both
/// the abandon gap and the run error; and a finish that abandons with
/// resolved calls still in the lane stash counts them or gaps them, never
/// silently. The lane requests the production journal session (builds that
/// omit the journal object refuse at lane start); an S1 seal fails loudly
/// with the s1-precluded branch tag instead of passing dry, while a
/// feed-less run with no latched seal fails with its typed cause's tag
/// (no-feeds-fell-back, no-feeds-receipt-starved, no-feeds-calls-shed)
/// or, with none, the distinct no-feeds-unattributed tag.
/// Last-waiter disposition: a live last waiter before stop is unreachable
/// (collected ticks resolve waiters same tick; 1,390 slice samples,
/// 0 waiters: 352 linked plus 1,038 micro-slice no-feed probe with
/// unresolved seal, whose historical tag covered S1 and unattributed
/// alike), so this matrix never stages the twins' refresh-to-stash
/// handoff. The
/// invariant is carried by the machine twins
/// `joint_machine_finish_after_pass_refresh_resolution_publishes_linked`,
/// `joint_machine_finish_after_pass_refresh_resolution_publishes_unlinked`
/// and `joint_machine_finish_at_q_expiry_storage_refusal_still_latches`.
/// `WP7_STOP_PREPS` / `WP7_STOP_OFFSETS` (comma-separated indices,
/// default all) narrow the matrix for exploration; a narrowed run is
/// never qualified.
///
/// The test owns its verdict: whatever happens (pass, preclusion, wedge
/// or any other failure), it ends by printing exactly one
/// `P11SCOPE_STOP_VERDICT=<json>` line built from its own case ledger
/// (see `StopVerdictRecord`), and the qualifying entries (the long
/// campaign runner and the S3 suite, through
/// scripts/ci/joint_stop_verdict.py) judge only that record, the exit
/// status and the libtest summary. A panic prints no record and
/// therefore never qualifies.
#[test]
#[ignore = "privileged: linked Joint stop coverage (12-case matrix)"]
fn privileged_joint_stop_after_last_waiter_resolves_publishes_final_lp64() -> Result<()> {
    let mut ledger = StopLedger::default();
    let result = run_stop_matrix(&mut ledger);
    let record = ledger.finish(&result);
    // The leading newline keeps the record on its own line even when
    // single-threaded libtest left `test NAME ... ` unterminated.
    eprintln!("\n{}", stop_verdict_line(&record));
    result
}

/// Full matrix: three prep shapes times four stop offsets, with the full
/// assert set on every combination; the first failure ends the cell.
const STOP_PREPS: [Prep; 3] = [Prep::Services(1), Prep::ServicesPolls(1, 1), Prep::FullQ2];
const STOP_OFFSETS_MS: [u64; 4] = [0, 1, 5, 20];
const STOP_CASES: usize = STOP_PREPS.len() * STOP_OFFSETS_MS.len();
/// Line marker of the cell's single verdict record.
const STOP_VERDICT_MARKER: &str = "P11SCOPE_STOP_VERDICT=";
/// Schema identifier of the record; scripts/ci/joint_stop_verdict.py
/// accepts exactly this version.
const STOP_VERDICT_SCHEMA: &str = "p11scope.joint-stop-verdict/1";
/// The record names its cell, so a record from another cell (or a
/// renamed one) never qualifies this one.
const STOP_CELL: &str = "inventory::joint_stop_races_privileged_tests::\
     privileged_joint_stop_after_last_waiter_resolves_publishes_final_lp64";

fn run_stop_matrix(ledger: &mut StopLedger) -> Result<()> {
    let want_preps = stop_matrix_selector("WP7_STOP_PREPS", STOP_PREPS.len())?;
    let want_offsets = stop_matrix_selector("WP7_STOP_OFFSETS", STOP_OFFSETS_MS.len())?;
    ledger.select(want_preps.clone(), want_offsets.clone());
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
    for (prep_index, prep) in STOP_PREPS.iter().enumerate() {
        if !want_preps.contains(&prep_index) {
            continue;
        }
        for (offset_index, offset) in STOP_OFFSETS_MS.iter().enumerate() {
            if !want_offsets.contains(&offset_index) {
                continue;
            }
            let index = prep_index * STOP_OFFSETS_MS.len() + offset_index;
            let case = ledger.open(index);
            run_stop_case(
                &workload,
                &soft_manifest,
                &held_manifest,
                *prep,
                *offset,
                index,
                case,
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

/// One prep times one offset: run the stop, collect its outcome into the
/// case record and judge it there. The case is completed only by
/// `StopCaseRecord::judge` after the full assert set passed.
fn run_stop_case(
    workload: &JointWorkload,
    soft_manifest: &Path,
    held_manifest: &Path,
    prep: Prep,
    offset_ms: u64,
    index: usize,
    case: &mut StopCaseRecord,
) -> Result<()> {
    let outcome = run_stop_offset(
        workload,
        soft_manifest,
        held_manifest,
        prep,
        offset_ms,
        index,
        case,
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
    case.collect(outcome);
    case.judge()
}

/// The stop checks in their order. A wedge is a case whose first
/// failing check is `Terminal` (the finish did not reach Published,
/// then WoundDown, while the earlier checks held).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum StopCheck {
    AtQ,
    Latch,
    Abandon,
    Terminal,
    Reconcile,
}

/// Full assert set for one stop case, over its collected outcome: the
/// at-Q publication (or disclosed shed), the latch double-naming, the
/// abandon accounting and the Published-then-WoundDown terminal. The
/// two-owner reconciliation must hold on every passing case: A-side
/// publication alone cannot excuse a B-side silent loss.
fn check_stop_outcome(outcome: &StopOutcome, offset_ms: u64) -> Result<()> {
    match stop_check_failure(outcome, offset_ms) {
        None => Ok(()),
        Some((_, error)) => Err(error),
    }
}

/// The first failing stop check and its error, or `None` when the case
/// passes every check.
fn stop_check_failure(outcome: &StopOutcome, offset_ms: u64) -> Option<(StopCheck, anyhow::Error)> {
    type Check = fn(&StopOutcome, u64) -> Result<()>;
    const CHECKS: [(StopCheck, Check); 5] = [
        (StopCheck::AtQ, check_stop_at_q),
        (StopCheck::Latch, check_stop_latch),
        (StopCheck::Abandon, check_stop_abandon),
        (StopCheck::Terminal, check_stop_terminal),
        (StopCheck::Reconcile, check_stop_reconcile),
    ];
    CHECKS
        .into_iter()
        .find_map(|(check, run)| run(outcome, offset_ms).err().map(|error| (check, error)))
}

/// (b) The at-Q tick publishes the stashed calls: A's resolved calls
/// reach its edge, or the equation discloses shed loudly.
fn check_stop_at_q(outcome: &StopOutcome, offset_ms: u64) -> Result<()> {
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
    Ok(())
}

/// (a) A latched machine names its code twice: abandon gap and run
/// error. A clean finish holds no first error at all.
fn check_stop_latch(outcome: &StopOutcome, offset_ms: u64) -> Result<()> {
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
    Ok(())
}

/// (c) An abandon with resolved calls still in the lane stash is counted
/// in the stop or named in a gap, never silent; and no abandon gap
/// appears without an abandonment.
fn check_stop_abandon(outcome: &StopOutcome, offset_ms: u64) -> Result<()> {
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
    Ok(())
}

/// Primary: the finish reaches Published, then WoundDown.
fn check_stop_terminal(outcome: &StopOutcome, offset_ms: u64) -> Result<()> {
    ensure!(
        stop_reached_wound_down(outcome),
        "offset {offset_ms}: the finish must reach Published then WoundDown: {outcome}"
    );
    Ok(())
}

fn stop_reached_wound_down(outcome: &StopOutcome) -> bool {
    outcome.finish == "published" && outcome.wound == "joined" && outcome.taken
}

/// (d) The two-owner reconciliation holds on every passing case: every
/// entered call on both edges is attributed, refused or disclosed-shed,
/// never silently lost. After the terminal check so a wedged finish
/// keeps its wedge diagnostic.
fn check_stop_reconcile(outcome: &StopOutcome, offset_ms: u64) -> Result<()> {
    ensure!(
        outcome.reconciled,
        "offset {offset_ms}: two-owner reconciliation failed: {}",
        outcome.reconcile_detail,
    );
    Ok(())
}

/// The cell's single verdict record, built only from the test's own
/// case ledger (never from log text): the selection, every opened case
/// with its collected outcome and completion, and one typed terminal.
#[derive(serde::Serialize)]
struct StopVerdictRecord {
    schema: &'static str,
    cell: &'static str,
    /// `None` when the selectors themselves were refused.
    selection: Option<StopSelection>,
    cases: Vec<StopCaseRecord>,
    terminal: StopTerminal,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize)]
struct StopSelection {
    preps: Vec<usize>,
    offsets: Vec<usize>,
}

/// One opened case. `branch` is set once at the linkage decision
/// (`linked`, or the no-feed tag), `outcome` once after a linked drive,
/// and `completed` only by `judge` after every stop check passed.
#[derive(serde::Serialize)]
struct StopCaseRecord {
    name: String,
    index: usize,
    prep: usize,
    offset_ms: u64,
    branch: Option<&'static str>,
    /// Quanta serviced after q1 before the linkage decision (set with
    /// `branch`); a linked no-feed verdict other than fell-back spends
    /// all `STOP_JOIN_QUANTA` (the validator refuses one that did not).
    join_quanta: Option<u64>,
    /// Discovery passes the join ran (`stop_join_passes_for` its quanta).
    join_passes: Option<u64>,
    /// Joint feeds installed when the join ended (set with `branch`).
    join_feeds: Option<u64>,
    outcome: Option<StopOutcome>,
    /// Set exactly on a no-feed case: the evidence behind its branch.
    no_feed: Option<NoFeedProbe>,
    completed: bool,
    #[serde(skip)]
    failed_check: Option<StopCheck>,
}

/// How the cell ended. The variants are built only by
/// `StopLedger::finish`, which asserts the combinations that cannot
/// describe a real run: a preclusion is the first case's S1 tag with
/// nothing linked or collected; a wedge is a linked, collected case
/// whose first failing check is the terminal one (never a success).
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum StopTerminal {
    /// Every case of the full selection completed.
    Qualified,
    /// Every selected case completed, but the selection was narrowed.
    Narrowed,
    /// Case 0 sealed S1 before anything was linked: environmental.
    Precluded {
        case: usize,
        cause: &'static str,
        receipt: &'static str,
    },
    /// Any other no-feed case (a linked session's typed cause or
    /// unattributed, or S1 after a linked case).
    NoFeed {
        case: usize,
        cause: &'static str,
        receipt: &'static str,
    },
    /// The last case failed exactly at the Published-then-WoundDown check.
    Wedge { case: usize },
    /// Any other failure; `case` is `None` before the first case opened.
    CaseFailed {
        case: Option<usize>,
        stage: &'static str,
        check: Option<StopCheck>,
        error: String,
    },
}

#[derive(Default)]
struct StopLedger {
    selection: Option<StopSelection>,
    cases: Vec<StopCaseRecord>,
}

impl StopLedger {
    fn select(&mut self, preps: Vec<usize>, offsets: Vec<usize>) {
        assert!(self.selection.is_none(), "the matrix selects once");
        self.selection = Some(StopSelection { preps, offsets });
    }

    /// Open case `index`; only after the previous case completed, in
    /// matrix order.
    fn open(&mut self, index: usize) -> &mut StopCaseRecord {
        assert!(index < STOP_CASES, "case {index} is outside the matrix");
        assert!(
            self.cases
                .last()
                .is_none_or(|last| last.completed && last.index < index),
            "case {index} opens only after the previous case completed"
        );
        self.cases.push(StopCaseRecord {
            name: format!("wp7-stop{index}"),
            index,
            prep: index / STOP_OFFSETS_MS.len(),
            offset_ms: STOP_OFFSETS_MS[index % STOP_OFFSETS_MS.len()],
            branch: None,
            join_quanta: None,
            join_passes: None,
            join_feeds: None,
            outcome: None,
            no_feed: None,
            completed: false,
            failed_check: None,
        });
        self.cases.last_mut().expect("just pushed")
    }

    fn full_selection(&self) -> bool {
        self.selection.as_ref().is_some_and(|selection| {
            selection.preps == (0..STOP_PREPS.len()).collect::<Vec<_>>()
                && selection.offsets == (0..STOP_OFFSETS_MS.len()).collect::<Vec<_>>()
        })
    }

    fn finish(self, result: &Result<()>) -> StopVerdictRecord {
        let terminal = match result {
            Ok(()) => {
                assert!(
                    self.cases.iter().all(|case| case.completed),
                    "a passing matrix completed every opened case"
                );
                if self.full_selection() && self.cases.len() == STOP_CASES {
                    StopTerminal::Qualified
                } else {
                    StopTerminal::Narrowed
                }
            }
            Err(error) => self.failure_terminal(error),
        };
        StopVerdictRecord {
            schema: STOP_VERDICT_SCHEMA,
            cell: STOP_CELL,
            selection: self.selection,
            cases: self.cases,
            terminal,
        }
    }

    fn failure_terminal(&self, error: &anyhow::Error) -> StopTerminal {
        let error = format!("{error:#}");
        let Some(last) = self.cases.last() else {
            return StopTerminal::CaseFailed {
                case: None,
                stage: "setup",
                check: None,
                error,
            };
        };
        assert!(!last.completed, "a failing matrix fails in its open case");
        match (last.branch, &last.outcome, last.failed_check) {
            (None, _, _) => {
                assert!(last.outcome.is_none(), "no outcome before linkage");
                StopTerminal::CaseFailed {
                    case: Some(last.index),
                    stage: "setup",
                    check: None,
                    error,
                }
            }
            (Some("linked"), None, _) => StopTerminal::CaseFailed {
                case: Some(last.index),
                stage: "drive",
                check: None,
                error,
            },
            (Some("linked"), Some(outcome), Some(StopCheck::Terminal)) => {
                assert!(
                    !stop_reached_wound_down(outcome),
                    "a wedge never describes a finish that reached WoundDown"
                );
                StopTerminal::Wedge { case: last.index }
            }
            (Some("linked"), Some(_), check) => {
                assert!(check.is_some(), "a collected case fails only in a check");
                StopTerminal::CaseFailed {
                    case: Some(last.index),
                    stage: "check",
                    check,
                    error,
                }
            }
            (Some(tag), outcome, check) => {
                assert!(
                    outcome.is_none() && check.is_none(),
                    "a no-feed case is never driven"
                );
                assert!(
                    last.no_feed.is_some(),
                    "a no-feed case carries the evidence it sampled"
                );
                let receipt = no_feed_receipt(tag);
                let first_and_full =
                    self.cases.len() == 1 && last.index == 0 && self.full_selection();
                if tag == "s1-precluded" && first_and_full {
                    StopTerminal::Precluded {
                        case: last.index,
                        cause: tag,
                        receipt,
                    }
                } else {
                    StopTerminal::NoFeed {
                        case: last.index,
                        cause: tag,
                        receipt,
                    }
                }
            }
        }
    }
}

impl StopCaseRecord {
    /// Record the linkage decision, once, before anything is driven.
    /// Record the linkage decision and the join behind it. The join
    /// loop alone fixes its quanta and passes, so their bound and
    /// schedule are asserted; the feeds come from the product, so how
    /// they relate to the branch is recorded, never asserted (the
    /// validator's `join-bound` check refuses an inconsistent record
    /// and the record still prints).
    fn link(&mut self, branch: &JointBranch, join: StopJoin) {
        assert!(self.branch.is_none(), "{}: linked once", self.name);
        assert!(
            join.quanta <= STOP_JOIN_QUANTA,
            "{}: the join spends at most {STOP_JOIN_QUANTA} quanta",
            self.name
        );
        assert_eq!(
            join.passes,
            stop_join_passes_for(join.quanta),
            "{}: the join runs its scheduled discovery passes",
            self.name
        );
        self.branch = Some(no_feed_branch_tag(branch).unwrap_or("linked"));
        self.join_quanta = Some(join.quanta);
        self.join_passes = Some(join.passes);
        self.join_feeds = Some(join.feeds);
    }

    /// Record what a no-feed case sampled, once, after its linkage.
    fn note_no_feed(&mut self, probe: NoFeedProbe) {
        assert!(
            self.branch.is_some_and(|branch| branch != "linked"),
            "{}: only a no-feed case carries a no-feed probe",
            self.name
        );
        assert!(self.no_feed.is_none(), "{}: one probe per case", self.name);
        self.no_feed = Some(probe);
    }

    /// Record the collected outcome of a linked drive, once.
    fn collect(&mut self, outcome: StopOutcome) {
        assert_eq!(
            self.branch,
            Some("linked"),
            "{}: only a linked case collects an outcome",
            self.name
        );
        assert!(
            self.outcome.is_none(),
            "{}: one outcome per case",
            self.name
        );
        assert_eq!(
            outcome.offset_ms, self.offset_ms,
            "{}: the outcome belongs to the case's offset",
            self.name
        );
        self.outcome = Some(outcome);
    }

    /// Run the full assert set; the case completes only when every
    /// check passes.
    fn judge(&mut self) -> Result<()> {
        let outcome = self
            .outcome
            .as_ref()
            .expect("a case is judged after its outcome is collected");
        match stop_check_failure(outcome, self.offset_ms) {
            None => {
                self.completed = true;
                Ok(())
            }
            Some((check, error)) => {
                self.failed_check = Some(check);
                Err(error)
            }
        }
    }
}

/// The receipt text of a no-feed tag (the cause the case's error names).
fn no_feed_receipt(tag: &str) -> &'static str {
    let branch = match tag {
        "s1-precluded" => JointBranch::S1,
        "no-feeds-fell-back" => JointBranch::FellBack,
        "no-feeds-receipt-starved" => JointBranch::ReceiptStarved,
        "no-feeds-calls-shed" => JointBranch::CallsShed,
        "no-feeds-unattributed" => JointBranch::Unattributed,
        other => panic!("not a no-feed tag: {other}"),
    };
    no_feed_reason(&branch).expect("a no-feed branch names its cause")
}

/// The single record line: the marker, then the compact JSON (which
/// escapes every control character, so the record is one line).
fn stop_verdict_line(record: &StopVerdictRecord) -> String {
    let json = serde_json::to_string(record).expect("the verdict record serializes");
    format!("{STOP_VERDICT_MARKER}{json}")
}

/// The stop cell must evaluate on the linked journal session: pin the
/// journal request in `start_joint_lane`, so a revert to `None` (which
/// would seal S1 and preclude every case) fails here instead of
/// passing dry anywhere. The pin reads the helper above its own body
/// (never its own literals) and checks the actual `start_live` call's
/// journal argument, so a comment mentioning the marker cannot
/// satisfy it.
#[test]
fn joint_lane_requests_the_linked_journal_session() {
    let source = include_str!("joint_stop_races_privileged_tests.rs");
    let head = source
        .split_once("fn joint_lane_requests_the_linked_journal_session(")
        .expect("the pin keeps its name")
        .0;
    assert_eq!(
        head.matches("fn start_joint_lane(").count(),
        1,
        "the joint lane starter is defined once above the pin"
    );
    let body = head
        .split_once("fn start_joint_lane(")
        .expect("the joint lane starter keeps its name")
        .1
        .split_once("\n}\n")
        .expect("top-level fns close at column 0")
        .0;
    assert!(
        body.contains("JournalSpec { key_sizes: false }"),
        "the lane builds a journal spec: {body}"
    );
    let call = body
        .split_once("start_live(")
        .expect("the lane starts its session")
        .1;
    let mut depth = 1u32;
    let mut end = None;
    for (at, byte) in call.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(at);
                    break;
                }
            }
            _ => {}
        }
    }
    let args = &call[..end.expect("the start_live call closes")];
    let last = args
        .split(',')
        .map(str::trim)
        .rfind(|part| !part.is_empty())
        .expect("the call takes arguments");
    assert_eq!(
        last, "Some(&journal)",
        "the lane requests the linked session: {body}"
    );
}

/// Healthy stop outcome for the oracle twins: Published then WoundDown,
/// A's calls published, the two-owner equation reconciled.
fn healthy_stop_outcome() -> StopOutcome {
    StopOutcome {
        offset_ms: 5,
        begin: "polling".to_string(),
        finish_polls: 3,
        finish: "published".to_string(),
        first_error: None,
        latched: false,
        latch_code: None,
        h0_stop: "committed".to_string(),
        wound: "joined".to_string(),
        wound_polls: 1,
        taken: true,
        minted: true,
        stash_floor: None,
        stop_counts: (2, 0, 0, 0),
        api_a: 2,
        a_semantic: 2,
        lane_shed: 0,
        reconciled: true,
        reconcile_detail: "reconciled".to_string(),
        abandon_gap: None,
        branch: "linked".to_string(),
    }
}

#[test]
fn stop_outcome_accepts_the_healthy_published_case() {
    let outcome = healthy_stop_outcome();
    check_stop_outcome(&outcome, outcome.offset_ms)
        .expect("the healthy Published/WoundDown case passes");
}

#[test]
fn stop_outcome_refuses_a_b_side_silent_loss() {
    let mut outcome = healthy_stop_outcome();
    // B loses one call with no matching named gap: the equation names
    // the shortfall, while A and the stop state stay healthy.
    outcome.reconciled = false;
    outcome.reconcile_detail =
        "wp7-stop0-stop: every entered call is attributed or refused on its own \
         caller with no shed: caller deficits sum 1"
            .to_string();
    let error = check_stop_outcome(&outcome, outcome.offset_ms)
        .expect_err("a B-side silent loss must fail the case");
    let text = format!("{error:?}");
    assert!(
        text.contains("reconciliation"),
        "the failure names reconciliation: {text}"
    );
    assert!(
        text.contains("caller deficits sum 1"),
        "the failure carries the equation diagnostic: {text}"
    );
}

#[test]
fn stop_outcome_accepts_a_counted_and_disclosed_shed() {
    let mut outcome = healthy_stop_outcome();
    // One call shed in the named caller-less gap: the equation holds
    // and the shed is disclosed, so the case still passes.
    outcome.api_a = 1;
    outcome.lane_shed = 1;
    outcome.reconciled = true;
    outcome.reconcile_detail = "reconciled".to_string();
    check_stop_outcome(&outcome, outcome.offset_ms).expect("a counted and disclosed shed passes");
}

fn healthy_stop_outcome_at(offset_ms: u64) -> StopOutcome {
    let mut outcome = healthy_stop_outcome();
    outcome.offset_ms = offset_ms;
    outcome
}

fn full_stop_ledger() -> StopLedger {
    let mut ledger = StopLedger::default();
    ledger.select(
        (0..STOP_PREPS.len()).collect(),
        (0..STOP_OFFSETS_MS.len()).collect(),
    );
    ledger
}

/// The join of a linked case whose feeds installed during q1.
const LINKED_JOIN: StopJoin = StopJoin {
    quanta: 0,
    passes: 0,
    feeds: 1,
};

/// The join a fell-back case ended: feeds installed after three quanta.
const FELL_BACK_JOIN: StopJoin = StopJoin {
    quanta: 3,
    passes: 1,
    feeds: 2,
};

/// The join a linked no-feed case spends: the whole bound, no feed.
const SPENT_JOIN: StopJoin = StopJoin {
    quanta: STOP_JOIN_QUANTA,
    passes: 4,
    feeds: 0,
};

/// Open `index`, link it, collect `outcome` and judge it.
fn judge_stop_case(ledger: &mut StopLedger, index: usize, outcome: StopOutcome) -> Result<()> {
    let case = ledger.open(index);
    case.link(&JointBranch::Linked, LINKED_JOIN);
    case.collect(outcome);
    case.judge()
}

fn completed_stop_cases(ledger: &mut StopLedger, count: usize) {
    for index in 0..count {
        let offset = STOP_OFFSETS_MS[index % STOP_OFFSETS_MS.len()];
        judge_stop_case(ledger, index, healthy_stop_outcome_at(offset))
            .expect("a healthy case completes");
    }
}

/// Link `case` to a no-feed branch with a sampled probe, as the drive does.
fn link_no_feed(case: &mut StopCaseRecord, branch: JointBranch) {
    let linked = !matches!(branch, JointBranch::S1);
    let fell_back = matches!(branch, JointBranch::FellBack);
    let starved = matches!(branch, JointBranch::ReceiptStarved);
    let shed = matches!(branch, JointBranch::CallsShed);
    let join = match branch {
        JointBranch::S1 => StopJoin::default(),
        JointBranch::FellBack => FELL_BACK_JOIN,
        _ => SPENT_JOIN,
    };
    case.link(&branch, join);
    case.note_no_feed(NoFeedProbe {
        joint_feeds: 0,
        journal_linked: linked,
        backstop_routed: 0,
        birth_capacity: None,
        drive: "live=1".to_string(),
        gaps: vec![NoFeedGap {
            subject: "s".to_string(),
            reason: "r".to_string(),
            count: 1,
        }],
        no_receipt: u64::from(starved),
        partition: u64::from(starved),
        shed: 17 * u64::from(shed),
        foreign_shed: 0,
        fallback: 2 * u64::from(fell_back),
    });
}

fn stop_terminal_of(ledger: StopLedger, result: Result<()>) -> StopTerminal {
    ledger.finish(&result).terminal
}

#[test]
fn stop_case_completes_only_after_every_check_passes() {
    let mut ledger = full_stop_ledger();
    judge_stop_case(&mut ledger, 0, healthy_stop_outcome_at(0)).expect("healthy");
    assert!(ledger.cases[0].completed, "a passing case completes");
    let mut failed = healthy_stop_outcome_at(1);
    failed.reconciled = false;
    failed.reconcile_detail = "caller deficits sum 1".to_string();
    let error = judge_stop_case(&mut ledger, 1, failed).expect_err("a failed check");
    assert!(
        format!("{error:?}").contains("reconciliation"),
        "the case error carries the check error: {error:?}"
    );
    assert!(!ledger.cases[1].completed, "a failed case never completes");
    assert_eq!(ledger.cases[1].failed_check, Some(StopCheck::Reconcile));
}

#[test]
fn stop_check_failure_names_the_first_failing_check() {
    let offset = 5;
    assert!(stop_check_failure(&healthy_stop_outcome_at(offset), offset).is_none());
    let mut at_q = healthy_stop_outcome_at(offset);
    at_q.api_a = 1;
    at_q.finish = "unpublished".to_string();
    assert_eq!(
        stop_check_failure(&at_q, offset).map(|failure| failure.0),
        Some(StopCheck::AtQ),
        "an at-Q failure precedes the terminal check"
    );
    let mut latch = healthy_stop_outcome_at(offset);
    latch.first_error = Some("boom".to_string());
    assert_eq!(
        stop_check_failure(&latch, offset).map(|failure| failure.0),
        Some(StopCheck::Latch)
    );
    let mut abandon = healthy_stop_outcome_at(offset);
    abandon.abandon_gap = Some("for lane stop: x".to_string());
    assert_eq!(
        stop_check_failure(&abandon, offset).map(|failure| failure.0),
        Some(StopCheck::Abandon)
    );
    let mut wedge = healthy_stop_outcome_at(offset);
    wedge.wound = "unwound".to_string();
    assert_eq!(
        stop_check_failure(&wedge, offset).map(|failure| failure.0),
        Some(StopCheck::Terminal)
    );
    let mut reconcile = healthy_stop_outcome_at(offset);
    reconcile.reconciled = false;
    assert_eq!(
        stop_check_failure(&reconcile, offset).map(|failure| failure.0),
        Some(StopCheck::Reconcile)
    );
}

/// One shared record pins both sides: the Rust ledger serializes a
/// healthy full matrix to exactly the fixture the Python validator
/// table builds its rows from.
#[test]
fn stop_verdict_record_matches_the_shared_qualified_fixture() {
    let mut ledger = full_stop_ledger();
    completed_stop_cases(&mut ledger, STOP_CASES);
    let record = ledger.finish(&Ok(()));
    assert_eq!(record.terminal, StopTerminal::Qualified);
    let line = stop_verdict_line(&record);
    assert!(!line.contains('\n'), "the record is one line");
    let json = line
        .strip_prefix(STOP_VERDICT_MARKER)
        .expect("the line opens with the marker");
    let produced: serde_json::Value = serde_json::from_str(json).expect("the record is JSON");
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/joint-stop-verdict-qualified.json"
    ))
    .expect("the fixture is JSON");
    assert_eq!(
        produced, fixture,
        "the record drifts from the shared fixture"
    );
}

#[test]
fn stop_verdict_qualifies_only_the_full_selection() {
    let mut ledger = StopLedger::default();
    ledger.select(vec![0], (0..STOP_OFFSETS_MS.len()).collect());
    completed_stop_cases(&mut ledger, STOP_OFFSETS_MS.len());
    assert_eq!(stop_terminal_of(ledger, Ok(())), StopTerminal::Narrowed);
}

#[test]
fn stop_verdict_precludes_only_a_first_case_s1_seal() {
    let not_attempted = || Err(anyhow::anyhow!("wp7-stopN: no joint feeds; not attempted"));
    let mut ledger = full_stop_ledger();
    link_no_feed(ledger.open(0), JointBranch::S1);
    assert_eq!(
        stop_terminal_of(ledger, not_attempted()),
        StopTerminal::Precluded {
            case: 0,
            cause: "s1-precluded",
            receipt: "no joint feeds with S1 seal (producers unlinked, zero installs)",
        }
    );
    // S1 after a linked case is a failure, not an environment.
    let mut ledger = full_stop_ledger();
    completed_stop_cases(&mut ledger, 1);
    link_no_feed(ledger.open(1), JointBranch::S1);
    assert!(matches!(
        stop_terminal_of(ledger, not_attempted()),
        StopTerminal::NoFeed {
            case: 1,
            cause: "s1-precluded",
            ..
        }
    ));
    // A narrowed run's first case is not the matrix's first case.
    let mut ledger = StopLedger::default();
    ledger.select(vec![0], vec![0]);
    link_no_feed(ledger.open(0), JointBranch::S1);
    assert!(matches!(
        stop_terminal_of(ledger, not_attempted()),
        StopTerminal::NoFeed { case: 0, .. }
    ));
    // The unattributed default never precludes.
    let mut ledger = full_stop_ledger();
    link_no_feed(ledger.open(0), JointBranch::Unattributed);
    assert!(matches!(
        stop_terminal_of(ledger, not_attempted()),
        StopTerminal::NoFeed {
            case: 0,
            cause: "no-feeds-unattributed",
            ..
        }
    ));
}

#[test]
fn stop_verdict_wedge_is_only_a_terminal_check_failure() {
    let mut ledger = full_stop_ledger();
    completed_stop_cases(&mut ledger, 2);
    let mut wedged = healthy_stop_outcome_at(5);
    wedged.finish = "unpublished".to_string();
    let result = judge_stop_case(&mut ledger, 2, wedged);
    assert_eq!(
        stop_terminal_of(ledger, result),
        StopTerminal::Wedge { case: 2 }
    );
    // An earlier failing check is a case failure even when the finish
    // also wedged.
    let mut ledger = full_stop_ledger();
    let mut at_q = healthy_stop_outcome_at(0);
    at_q.api_a = 1;
    at_q.finish = "unpublished".to_string();
    let result = judge_stop_case(&mut ledger, 0, at_q);
    assert!(matches!(
        stop_terminal_of(ledger, result),
        StopTerminal::CaseFailed {
            case: Some(0),
            stage: "check",
            check: Some(StopCheck::AtQ),
            ..
        }
    ));
}

#[test]
fn stop_verdict_names_setup_and_drive_failures() {
    let error = || Err(anyhow::anyhow!("setup broke"));
    assert!(matches!(
        stop_terminal_of(StopLedger::default(), error()),
        StopTerminal::CaseFailed {
            case: None,
            stage: "setup",
            check: None,
            ..
        }
    ));
    let mut ledger = full_stop_ledger();
    ledger.open(0);
    assert!(matches!(
        stop_terminal_of(ledger, error()),
        StopTerminal::CaseFailed {
            case: Some(0),
            stage: "setup",
            ..
        }
    ));
    let mut ledger = full_stop_ledger();
    ledger.open(0).link(&JointBranch::Linked, LINKED_JOIN);
    match stop_terminal_of(ledger, error()) {
        StopTerminal::CaseFailed {
            case: Some(0),
            stage: "drive",
            check: None,
            error,
        } => assert_eq!(error, "setup broke"),
        other => panic!("a linked case without an outcome failed in its drive: {other:?}"),
    }
}

#[test]
#[should_panic(expected = "opens only after the previous case completed")]
fn stop_ledger_refuses_a_case_after_an_unfinished_one() {
    let mut ledger = full_stop_ledger();
    ledger.open(0).link(&JointBranch::Linked, LINKED_JOIN);
    ledger.open(1);
}

#[test]
#[should_panic(expected = "only a linked case collects an outcome")]
fn stop_ledger_refuses_an_outcome_on_a_no_feed_case() {
    let mut ledger = full_stop_ledger();
    let case = ledger.open(0);
    case.link(&JointBranch::S1, StopJoin::default());
    case.collect(healthy_stop_outcome_at(0));
}

#[test]
#[should_panic(expected = "the outcome belongs to the case's offset")]
fn stop_ledger_refuses_an_outcome_from_another_offset() {
    let mut ledger = full_stop_ledger();
    let case = ledger.open(0);
    case.link(&JointBranch::Linked, LINKED_JOIN);
    case.collect(healthy_stop_outcome_at(20));
}

#[test]
#[should_panic(expected = "carries the evidence it sampled")]
fn stop_ledger_refuses_a_no_feed_terminal_without_its_probe() {
    let mut ledger = full_stop_ledger();
    ledger.open(0).link(&JointBranch::Unattributed, SPENT_JOIN);
    let _ = stop_terminal_of(ledger, Err(anyhow::anyhow!("not attempted")));
}

#[test]
#[should_panic(expected = "only a no-feed case carries a no-feed probe")]
fn stop_ledger_refuses_a_probe_on_a_linked_case() {
    let mut ledger = full_stop_ledger();
    let case = ledger.open(0);
    case.link(&JointBranch::Linked, LINKED_JOIN);
    case.note_no_feed(NoFeedProbe {
        joint_feeds: 0,
        journal_linked: true,
        backstop_routed: 0,
        birth_capacity: None,
        drive: String::new(),
        gaps: Vec::new(),
        no_receipt: 0,
        partition: 0,
        shed: 0,
        foreign_shed: 0,
        fallback: 0,
    });
}

#[test]
#[should_panic(expected = "linked once")]
fn stop_ledger_refuses_a_second_linkage_decision() {
    let mut ledger = full_stop_ledger();
    let case = ledger.open(0);
    case.link(&JointBranch::Linked, LINKED_JOIN);
    case.link(&JointBranch::S1, StopJoin::default());
}

/// The matrix cell prints its record on every return path: the body
/// runs the matrix into a result (no `?`), builds the record from the
/// ledger, prints its line, then returns the result. The pin reads the
/// cell above its own body and strips line comments.
#[test]
fn stop_cell_prints_its_record_before_returning() {
    let source = include_str!("joint_stop_races_privileged_tests.rs");
    let head = source
        .split_once("fn stop_cell_prints_its_record_before_returning(")
        .expect("the pin keeps its name")
        .0;
    let body = head
        .split_once("fn privileged_joint_stop_after_last_waiter_resolves_publishes_final_lp64(")
        .expect("the cell keeps its name")
        .1
        .split_once("\n}\n")
        .expect("top-level fns close at column 0")
        .0;
    let code: Vec<&str> = body
        .lines()
        .map(|line| line.split("//").next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(
        code,
        [
            ") -> Result<()> {",
            "let mut ledger = StopLedger::default();",
            "let result = run_stop_matrix(&mut ledger);",
            "let record = ledger.finish(&result);",
            "eprintln!(\"\\n{}\", stop_verdict_line(&record));",
            "result",
        ],
        "the cell prints its record on every path"
    );
}

#[test]
fn joint_branch_splits_s1_from_the_unattributed_default() {
    for fed in [false, true] {
        for starved in [false, true] {
            for shed in [false, true] {
                assert!(matches!(
                    joint_branch_from(2, true, fed, starved, shed),
                    JointBranch::Linked
                ));
                assert!(matches!(
                    joint_branch_from(0, false, fed, starved, shed),
                    JointBranch::S1
                ));
                assert!(matches!(
                    joint_branch_from(0, true, true, starved, shed),
                    JointBranch::FellBack
                ));
            }
        }
    }
    assert!(matches!(
        joint_branch_from(0, true, false, false, false),
        JointBranch::Unattributed
    ));
    assert!(matches!(
        joint_branch_from(0, true, false, true, false),
        JointBranch::ReceiptStarved
    ));
    assert!(matches!(
        joint_branch_from(0, true, false, true, true),
        JointBranch::ReceiptStarved
    ));
    assert!(matches!(
        joint_branch_from(0, true, false, false, true),
        JointBranch::CallsShed
    ));
}

#[test]
fn no_feed_tags_name_each_branch_cause() {
    assert_eq!(no_feed_branch_tag(&JointBranch::Linked), None);
    assert_eq!(no_feed_branch_tag(&JointBranch::S1), Some("s1-precluded"));
    assert_eq!(
        no_feed_branch_tag(&JointBranch::Unattributed),
        Some("no-feeds-unattributed")
    );
    assert_eq!(no_feed_reason(&JointBranch::Linked), None);
    assert_eq!(
        no_feed_reason(&JointBranch::S1),
        Some("no joint feeds with S1 seal (producers unlinked, zero installs)")
    );
    assert_eq!(
        no_feed_branch_tag(&JointBranch::ReceiptStarved),
        Some("no-feeds-receipt-starved")
    );
    let starved = no_feed_reason(&JointBranch::ReceiptStarved).expect("a cause");
    assert!(
        starved.contains("no_receipt") && starved.contains("partition"),
        "the starved cause names its typed gaps: {starved}"
    );
    assert_eq!(no_feed_receipt("no-feeds-receipt-starved"), starved);
    assert_eq!(
        no_feed_branch_tag(&JointBranch::CallsShed),
        Some("no-feeds-calls-shed")
    );
    let shed = no_feed_reason(&JointBranch::CallsShed).expect("a cause");
    assert!(shed.contains("shed"), "the shed cause names it: {shed}");
    assert_eq!(no_feed_receipt("no-feeds-calls-shed"), shed);
    assert_eq!(
        no_feed_branch_tag(&JointBranch::FellBack),
        Some("no-feeds-fell-back")
    );
    let fell_back = no_feed_reason(&JointBranch::FellBack).expect("a cause");
    assert!(
        fell_back.contains("none remained") && fell_back.contains("fallback"),
        "the fell-back cause names its count: {fell_back}"
    );
    assert_eq!(no_feed_receipt("no-feeds-fell-back"), fell_back);
    assert!(
        starved.contains("held caller") && starved.contains("caller-less"),
        "the starved cause binds no_receipt to the held caller and partition to \
         the session: {starved}"
    );
    assert!(
        shed.contains("not proven foreign"),
        "the shed cause never claims foreign shed: {shed}"
    );
    let unattributed = no_feed_reason(&JointBranch::Unattributed).expect("a cause");
    assert!(
        unattributed.contains("producers linked, zero installs unexplained"),
        "the unattributed cause reports what the cell sampled: {unattributed}"
    );
}

/// The join keeps a linked, feedless session serviced for exactly the
/// bound, never an unlinked one, and stops as soon as a feed installs.
#[test]
fn stop_join_services_a_linked_session_until_its_feed_or_the_bound() {
    assert!(
        stop_join_continues(0, true, 0),
        "one quantum is not a verdict"
    );
    assert!(stop_join_continues(0, true, STOP_JOIN_QUANTA - 1));
    assert!(!stop_join_continues(0, true, STOP_JOIN_QUANTA), "bounded");
    assert!(!stop_join_continues(1, true, 0), "a feed ends the join");
    assert!(!stop_join_continues(0, false, 0), "an S1 latch never waits");
    let mut quanta = 0;
    while stop_join_continues(0, true, quanta) {
        quanta += 1;
    }
    assert_eq!(quanta, STOP_JOIN_QUANTA);
}

/// A deferred admission or refused receipt is retried only on a
/// discovery pass: the join runs passes before the 2nd, 10th, 18th and
/// 26th quantum, never before the first, and four over the full bound.
#[test]
fn stop_join_runs_discovery_passes_on_its_schedule() {
    let due: Vec<u64> = (0..STOP_JOIN_QUANTA)
        .filter(|quanta| stop_join_pass_due(*quanta))
        .collect();
    assert_eq!(due, [1, 9, 17, 25]);
    for quanta in 0..=STOP_JOIN_QUANTA {
        assert_eq!(
            stop_join_passes_for(quanta),
            (0..quanta).filter(|q| stop_join_pass_due(*q)).count() as u64,
            "the pass count of a {quanta}-quantum join"
        );
    }
    assert_eq!(
        stop_join_passes_for(1),
        0,
        "a one-quantum join runs no pass"
    );
    assert_eq!(stop_join_passes_for(2), 1);
    assert_eq!(stop_join_passes_for(STOP_JOIN_QUANTA), 4);
}

/// The drive's join loop follows `stop_join_step` verbatim: a linked,
/// feedless session runs the full bound with its four passes; a feed
/// arriving after quantum `k` stops the join at `k` with the schedule's
/// passes; an unlinked latch never steps.
#[test]
fn stop_join_steps_until_a_feed_or_the_bound() {
    fn run(feed_after: Option<u64>, linked: bool) -> (u64, u64) {
        let (mut quanta, mut passes) = (0u64, 0u64);
        loop {
            let feeds = usize::from(feed_after.is_some_and(|k| quanta >= k));
            match stop_join_step(feeds, linked, quanta) {
                JoinStep::Stop => return (quanta, passes),
                JoinStep::PassThenQuantum => passes += 1,
                JoinStep::Quantum => {}
            }
            quanta += 1;
        }
    }
    assert_eq!(run(None, true), (STOP_JOIN_QUANTA, 4));
    assert_eq!(run(None, false), (0, 0));
    assert_eq!(run(Some(0), true), (0, 0));
    for k in 1..=STOP_JOIN_QUANTA {
        assert_eq!(
            run(Some(k), true),
            (k, stop_join_passes_for(k)),
            "feed after {k}"
        );
    }
    assert_eq!(stop_join_step(0, true, 0), JoinStep::Quantum);
    assert_eq!(stop_join_step(0, true, 1), JoinStep::PassThenQuantum);
    assert_eq!(stop_join_step(0, true, STOP_JOIN_QUANTA), JoinStep::Stop);
    assert_eq!(stop_join_step(1, true, 1), JoinStep::Stop);
    assert_eq!(stop_join_step(0, false, 1), JoinStep::Stop);
}

/// Shed proven foreign never names fixture loss: only the unproven
/// rest selects the calls-shed cause.
#[test]
fn lane_shed_split_separates_proven_foreign_shed() {
    assert_eq!(
        lane_shed_split_from(18, 1),
        LaneShedSplit {
            unproven: 17,
            foreign: 1
        }
    );
    assert_eq!(
        lane_shed_split_from(5, 5),
        LaneShedSplit {
            unproven: 0,
            foreign: 5
        },
        "foreign-only shed is not a calls-shed cause"
    );
    assert_eq!(lane_shed_split_from(0, 0), LaneShedSplit::default());
}

/// A no-feed probe's gap rows count repeats, the unit of its typed
/// counters: two registry entries of one (subject, reason) with 1 and 2
/// repeats are one row of 3.
#[test]
fn no_feed_gaps_sum_repeats_per_subject_and_reason() {
    let gaps = [
        ("semantic receipt refused", "partition", 1),
        ("semantic receipt refused", "partition", 2),
        ("semantic receipt refused", "domain", 4),
    ];
    assert_eq!(
        no_feed_gaps_from(gaps.into_iter()),
        vec![
            NoFeedGap {
                subject: "semantic receipt refused".to_string(),
                reason: "domain".to_string(),
                count: 4,
            },
            NoFeedGap {
                subject: "semantic receipt refused".to_string(),
                reason: "partition".to_string(),
                count: 3,
            },
        ]
    );
}

/// The fallback count reads only the named `joint_fallback_*`
/// endings of retained-S1 Joint feeds, with repeats.
#[test]
fn joint_fallbacks_count_only_their_named_endings() {
    let subject = crate::inventory_present::JOINT_RETAINED_S1_SUBJECT;
    let gaps = [
        (subject, "joint_fallback_unsealable", 2),
        (subject, "joint_fallback_no_owner", 3),
        (subject, "joint_seal_refused", 5),
        ("semantic receipt refused", "joint_fallback_unsealable", 7),
    ];
    assert_eq!(joint_fallbacks_from(gaps.into_iter()), 5);
    assert_eq!(joint_fallbacks_from(std::iter::empty()), 0);
}

#[test]
#[should_panic(expected = "the join runs its scheduled discovery passes")]
fn stop_ledger_refuses_a_no_feed_verdict_without_discovery_passes() {
    let mut ledger = full_stop_ledger();
    ledger.open(0).link(
        &JointBranch::ReceiptStarved,
        StopJoin {
            passes: 0,
            ..SPENT_JOIN
        },
    );
}

/// The join's pass is a real discovery pass, driven before the quantum
/// it is scheduled for; the pin reads the drive above its own body and
/// strips line comments.
#[test]
fn stop_join_drives_a_discovery_pass_when_due() {
    let source = include_str!("joint_stop_races_privileged_tests.rs");
    let head = source
        .split_once("fn stop_join_drives_a_discovery_pass_when_due(")
        .expect("the pin keeps its name")
        .0;
    let drive = head
        .split_once("fn run_stop_offset(")
        .expect("the drive keeps its name")
        .1;
    let code: String = drive
        .lines()
        .map(|line| line.split("//").next().unwrap_or("").trim())
        .collect();
    assert!(
        code.contains(concat!(
            "let mut join = StopJoin::default();",
            "loop {",
            "let step = stop_join_step(",
            "coordinator.registry().joint_feeds(),",
            "coordinator.registry().journal_linked(),",
            "join.quanta,",
            ");",
            "if step == JoinStep::Stop {",
            "break;",
            "}",
            "if step == JoinStep::PassThenQuantum {",
            "drive_native_passes_until(&mut coordinator, &mut |passes| Ok(passes >= 1))?;",
            "join.passes += 1;",
            "}",
            "join.quanta += 1;",
            "service_to_published(",
            "&mut lane,",
            "&mut coordinator,",
            "false,",
            "&format!(\"{tag}-join{}\", join.quanta),",
            ")?;",
            "}",
            "join.feeds = coordinator.registry().joint_feeds() as u64;",
        )),
        "the join follows stop_join_step: stops when it says, drives a discovery pass \
         before its scheduled quantum, and records the feeds it ended with"
    );
}

/// Feeds that install during the join and then all fall back before
/// the linkage decision are product behavior, not a ledger bug: the
/// case links to its own fell-back cause, records the join it ended
/// (early, with feeds) and prints a failing no-feed terminal instead
/// of panicking.
#[test]
fn stop_ledger_records_feeds_that_fell_back_after_the_join() {
    assert!(matches!(
        joint_branch_from(0, true, true, false, false),
        JointBranch::FellBack
    ));
    let mut ledger = full_stop_ledger();
    completed_stop_cases(&mut ledger, 1);
    link_no_feed(ledger.open(1), JointBranch::FellBack);
    let case = &ledger.cases[1];
    assert_eq!(
        (
            case.branch,
            case.join_quanta,
            case.join_passes,
            case.join_feeds
        ),
        (Some("no-feeds-fell-back"), Some(3), Some(1), Some(2))
    );
    assert!(matches!(
        stop_terminal_of(ledger, Err(anyhow::anyhow!("not attempted"))),
        StopTerminal::NoFeed {
            case: 1,
            cause: "no-feeds-fell-back",
            ..
        }
    ));
}

/// A full-spend cause on a join that ended early is impossible in
/// the drive (the loop ends early only on a feed or an unlinked
/// latch), but its inputs are product state: the ledger records the
/// join as it was so the validator's `join-bound` check refuses the
/// record by name, never a panic that prints no record.
#[test]
fn stop_ledger_records_an_early_join_for_every_linked_no_feed_cause() {
    for branch in [
        JointBranch::ReceiptStarved,
        JointBranch::CallsShed,
        JointBranch::Unattributed,
    ] {
        let mut ledger = full_stop_ledger();
        let case = ledger.open(0);
        case.link(
            &branch,
            StopJoin {
                quanta: 1,
                passes: 0,
                feeds: 0,
            },
        );
        assert_eq!(
            (case.join_quanta, case.join_passes, case.join_feeds),
            (Some(1), Some(0), Some(0))
        );
    }
}

#[test]
#[should_panic(expected = "the join spends at most")]
fn stop_ledger_refuses_a_join_past_its_bound() {
    let mut ledger = full_stop_ledger();
    ledger.open(0).link(
        &JointBranch::Linked,
        StopJoin {
            quanta: STOP_JOIN_QUANTA + 1,
            ..SPENT_JOIN
        },
    );
}

/// The starvation cause counts the exact frozen codes with repeats and
/// nothing else; a starved case is a failing no-feed terminal.
#[test]
fn receipt_starvation_counts_only_its_typed_codes() {
    const HELD: u32 = 1;
    const OTHER: u32 = 2;
    let gaps = [
        (
            Some(HELD),
            "semantic admission deferred",
            "semantic_unavailable:no_receipt",
            3,
        ),
        (None, "semantic receipt refused", "partition", 2),
        (Some(HELD), "semantic receipt refused", "domain", 5),
        (
            Some(HELD),
            "semantic admission deferred",
            "semantic_unavailable:other",
            7,
        ),
        (None, "semantic calls unrouted", "partition", 11),
    ];
    assert_eq!(
        receipt_starvation_from(HELD, gaps.into_iter()),
        ReceiptStarvation {
            no_receipt: 3,
            partition: 2
        }
    );
    assert_eq!(
        receipt_starvation_from(HELD, std::iter::empty()),
        ReceiptStarvation::default()
    );
    // Another caller's deferral, a caller-less deferral and a partition
    // bound to a caller never name the held caller's receipt.
    let foreign = [
        (
            Some(OTHER),
            "semantic admission deferred",
            "semantic_unavailable:no_receipt",
            4,
        ),
        (
            None,
            "semantic admission deferred",
            "semantic_unavailable:no_receipt",
            6,
        ),
        (Some(HELD), "semantic receipt refused", "partition", 8),
    ];
    assert_eq!(
        receipt_starvation_from(HELD, foreign.into_iter()),
        ReceiptStarvation::default()
    );
    let mut ledger = full_stop_ledger();
    completed_stop_cases(&mut ledger, 2);
    link_no_feed(ledger.open(2), JointBranch::ReceiptStarved);
    assert!(matches!(
        stop_terminal_of(ledger, Err(anyhow::anyhow!("not attempted"))),
        StopTerminal::NoFeed {
            case: 2,
            cause: "no-feeds-receipt-starved",
            ..
        }
    ));
    let mut ledger = full_stop_ledger();
    link_no_feed(ledger.open(0), JointBranch::CallsShed);
    assert!(matches!(
        stop_terminal_of(ledger, Err(anyhow::anyhow!("not attempted"))),
        StopTerminal::NoFeed {
            case: 0,
            cause: "no-feeds-calls-shed",
            ..
        }
    ));
}

/// Empty coordinator for the reconciliation twins: the equation reads
/// only the registry gaps and the suppression counter, so no live
/// lane is needed.
fn reconciliation_test_coordinator() -> InventoryCoordinator<OsProcessSource> {
    InventoryCoordinator::new(
        Scope::Pid(std::process::id()),
        HookRegistry::builtin(),
        Vec::new(),
        vec![],
        OsProcessSource,
        RegistryLimits::default_limits(),
    )
    .expect("a test coordinator builds")
}

/// Twin owner ledger: `counts` is (sem, count_only, api, slot, inst).
fn stop_owner(name: &'static str, caller: u32, module: u32, counts: [u64; 5]) -> StopOwnerLedger {
    use crate::discovery::caller_registry::{CallerId, ModuleId};
    let [sem, count_only, api, slot, inst] = counts;
    StopOwnerLedger {
        name,
        caller: CallerId(caller),
        module: ModuleId(module),
        sem,
        count_only,
        entered: sem + count_only,
        api,
        slot,
        inst,
    }
}

fn record_test_gap(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    caller: Option<u32>,
    module: Option<u32>,
    subject: &str,
    reason: &str,
) {
    use crate::discovery::caller_registry::{CallerId, ModuleId, RegistryGap};
    coordinator.registry_mut().record_gap(RegistryGap {
        caller: caller.map(CallerId),
        module: module.map(ModuleId),
        pid: None,
        subject: subject.to_string(),
        reason: reason.to_string(),
        budget: None,
    });
    coordinator.registry_mut().publish();
}

#[test]
fn stop_reconciliation_accepts_healthy_two_owner_counts() {
    let coordinator = reconciliation_test_coordinator();
    assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect("healthy A=2/2 and B=15+1/16 reconcile");
}

#[test]
fn stop_reconciliation_refuses_cross_caller_compensation() {
    // An extra instance refusal charged to A must not hide a missing
    // B call: the pooled sums match (18 entered vs 16 api + 1 slot +
    // 1 inst) but per-caller A over-refuses and B under-accounts.
    let coordinator = reconciliation_test_coordinator();
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 1]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect_err("an A-side extra refusal hiding a B-side loss must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains('a') || text.contains('b'),
        "the failure names the offending caller: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_a_b_side_silent_loss_without_refusals() {
    // B loses one call with no refusal anywhere: no cap trips, so
    // only the caller-deficit equation can catch the shortfall.
    let coordinator = reconciliation_test_coordinator();
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect_err("a B-side silent loss with no refusals must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("deficit"),
        "the failure names the caller deficit: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_instance_refusal_without_retained_reason() {
    // A's counts balance only through its instance refusal, but no
    // retained gap row discloses that refusal for A's edge.
    let coordinator = reconciliation_test_coordinator();
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 1, 0, 1]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("an undisclosed instance refusal must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("instance"),
        "the failure names the instance disclosure: {text}"
    );
}

#[test]
fn stop_reconciliation_accepts_instance_refusal_with_retained_reason() {
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        Some(1),
        Some(1),
        "instance semantics refused",
        "instance_unproven",
    );
    assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 1, 0, 1]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect("a disclosed instance refusal reconciles");
}

#[test]
fn stop_reconciliation_accepts_disclosed_shed_per_caller() {
    // B is one call short and the lane shed counts and discloses it
    // in the named caller-less gap: each caller's deficit is
    // nonnegative and the deficits sum to the shed.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "1 calls shed without a route (unobserved=1) with 2 bindings",
    );
    assert_semantic_reconciled(
        &coordinator,
        1,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect("a counted and disclosed shed reconciles per caller");
}

#[test]
fn stop_reconciliation_refuses_instance_refusal_when_disclosure_suppressed() {
    // The instance reason row is retained for A, but another distinct
    // gap overflowed the bound: with suppression nonzero the lane
    // cannot prove no instance disclosure was dropped.
    let mut coordinator = InventoryCoordinator::new(
        Scope::Pid(std::process::id()),
        HookRegistry::builtin(),
        Vec::new(),
        vec![],
        OsProcessSource,
        RegistryLimits::new(8, 8, 8, 1, 8, 8).expect("a one-gap bound"),
    )
    .expect("a test coordinator builds");
    record_test_gap(
        &mut coordinator,
        Some(1),
        Some(1),
        "instance semantics refused",
        "instance_unproven",
    );
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "other subject",
        "other reason",
    );
    assert_eq!(
        coordinator.registry().gaps_suppressed(),
        1,
        "the second distinct gap suppresses"
    );
    assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 1, 0, 1]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("a suppressed disclosure with instance refusals must fail");
}

#[test]
fn stop_reconciliation_accepts_caller_unbound_with_retained_reason() {
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        Some(1),
        Some(1),
        "instance semantics refused",
        "caller_unbound",
    );
    assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 1, 0, 1]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect("a disclosed caller_unbound refusal reconciles");
}

#[test]
fn stop_reconciliation_refuses_registration_only_reason_for_a_call_refusal() {
    // A's per-call refusal carries inst=1, but its only retained row
    // names a registration-only cause: the call disclosure is missing.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        Some(1),
        Some(1),
        "instance semantics refused",
        "negative_state_capacity",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 1, 0, 1]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("a registration-only reason must not disclose a call refusal");
    let text = format!("{error:?}");
    assert!(
        text.contains("per-call"),
        "the failure names the per-call reason class: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_shared_reason_when_registration_refused() {
    // The retained row names a per-call reason, but the caller also
    // refused a registration: the row could be the registration's,
    // so the call disclosure is unproven.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        Some(1),
        Some(1),
        "instance semantics refused",
        "instance_unproven",
    );
    coordinator
        .registry_mut()
        .note_registration_refused(crate::discovery::caller_registry::CallerId(1));
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 1, 0, 1]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("a shared reason with a refused registration must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("registration"),
        "the failure names the registration refusal: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_two_shed_with_one_disclosed() {
    // Two calls shed and missing, but the retained row accounts for
    // one: the deficits match the lane count while the disclosure
    // covers half the loss.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "1 calls shed without a route (unobserved=1) with 2 bindings",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        2,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 13, 1, 0]),
        ],
    )
    .expect_err("a half-disclosed shed must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("unrouted total"),
        "the failure names the unrouted total: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_shed_without_a_gap() {
    // The lane counts one shed call and B is one short, but no
    // retained row discloses it.
    let coordinator = reconciliation_test_coordinator();
    let error = assert_semantic_reconciled(
        &coordinator,
        1,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect_err("a shed count without a gap must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("unrouted total"),
        "the failure names the unrouted total: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_gap_without_a_shed_count() {
    // Healthy counts with no shed, but a retained row discloses one
    // shed call: a gap without the lane count.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "1 calls shed without a route (unobserved=1) with 2 bindings",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("a gap without a shed count must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("unrouted total"),
        "the failure names the unrouted total: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_an_unparsable_unrouted_total() {
    // The retained row names the shed subject but carries no counted
    // total: the oracle cannot verify the amount.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "shed happened",
    );
    assert_semantic_reconciled(
        &coordinator,
        1,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect_err("an unparsable unrouted total must fail");
}

#[test]
fn stop_reconciliation_refuses_a_breakdown_mismatch() {
    // The row claims two shed calls but its labels sum to one.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "2 calls shed without a route (unobserved=1) with 2 bindings",
    );
    assert_semantic_reconciled(
        &coordinator,
        2,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 13, 1, 0]),
        ],
    )
    .expect_err("a breakdown mismatch must fail");
}

#[test]
fn stop_reconciliation_refuses_capacity_shed() {
    // Capacity shed has no lane counter, so any capacity row fails
    // even when the per-caller counts balance.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic call outcome capacity",
        "1 calls refused at the bounded finalization limit",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("a capacity gap must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("capacity"),
        "the failure names capacity: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_foreign_shed() {
    // Only fixtures call in this cell: a foreign-shed row names loss
    // outside the two owners.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted from other callers",
        "1 calls shed without a route (unobserved=1) from callers other than the 2 bound callers",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("a foreign shed row must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("foreign"),
        "the failure names foreign shed: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_a_non_slot_conversion_cause() {
    // A coverage input refusal for A is not a count-only slot
    // refusal: it must fail rather than hide in the deficit.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        Some(1),
        None,
        "semantic input refused",
        "coverage",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("a non-slot conversion cause must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("slot"),
        "the failure names the slot-only rule: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_an_instance_gap_without_a_refused_call() {
    // A retained per-call row with inst=0 is a gap without a count.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        Some(1),
        Some(1),
        "instance semantics refused",
        "instance_unproven",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("an instance gap without a refused call must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("without a refused call"),
        "the failure names the gap-without-count: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_suppressed_slot_disclosure() {
    // B's slot refusal balances its counts, but another distinct gap
    // overflowed the bound: the slot count is unproven.
    let mut coordinator = InventoryCoordinator::new(
        Scope::Pid(std::process::id()),
        HookRegistry::builtin(),
        Vec::new(),
        vec![],
        OsProcessSource,
        RegistryLimits::new(8, 8, 8, 1, 8, 8).expect("a one-gap bound"),
    )
    .expect("a test coordinator builds");
    record_test_gap(
        &mut coordinator,
        Some(2),
        None,
        "semantic input refused",
        "slot",
    );
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "other subject",
        "other reason",
    );
    assert_eq!(
        coordinator.registry().gaps_suppressed(),
        1,
        "the second distinct gap suppresses"
    );
    assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("a suppressed slot disclosure must fail");
}

#[test]
fn stop_reconciliation_refuses_a_missing_owner() {
    // One owner cannot reconcile two callers: B's loss would be
    // invisible.
    let coordinator = reconciliation_test_coordinator();
    assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[stop_owner("a", 1, 1, [2, 0, 2, 0, 0])],
    )
    .expect_err("a single owner must fail");
}

#[test]
fn stop_reconciliation_refuses_duplicate_owners() {
    // Two ledgers for one caller leave the other caller uncovered.
    let coordinator = reconciliation_test_coordinator();
    assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("a2", 1, 1, [2, 0, 2, 0, 0]),
        ],
    )
    .expect_err("duplicate owners must fail");
}

#[test]
fn stop_reconciliation_refuses_over_attribution() {
    // A attributes more calls than its semantic ledger holds.
    let coordinator = reconciliation_test_coordinator();
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 3, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("over-attribution must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("over-attributes"),
        "the failure names over-attribution: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_over_refused_slots() {
    // A refuses more slots than its count-only ledger holds.
    let coordinator = reconciliation_test_coordinator();
    let error = assert_semantic_reconciled(
        &coordinator,
        0,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 1, 0]),
            stop_owner("b", 2, 2, [15, 1, 15, 1, 0]),
        ],
    )
    .expect_err("over-refused slots must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("over-refuses"),
        "the failure names over-refusal: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_a_blank_shed_cause() {
    // Otherwise balanced (one disclosed shed, B one short), but the
    // retained row leaves the cause blank: a counted shed with no
    // named reason is not disclosed loss.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "1 calls shed without a route (=1) with 2 bindings",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        1,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect_err("a blank shed cause must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("counted total"),
        "the failure names the unparsable row: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_an_unknown_shed_cause() {
    // Otherwise balanced, but the cause names no route-loss reason:
    // only the producer vocabulary discloses shed.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "1 calls shed without a route (test=1) with 2 bindings",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        1,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect_err("an unknown shed cause must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("counted total"),
        "the failure names the unparsable row: {text}"
    );
}

#[test]
fn stop_reconciliation_accepts_a_dropped_batch_shed() {
    // The second producer template discloses the same balanced shed:
    // one call from a dropped batch with a named cause.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "1 calls shed from a dropped abandoned batch (unobserved=1) with 2 bindings",
    );
    assert_semantic_reconciled(
        &coordinator,
        1,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect("a dropped-batch shed with a named cause reconciles");
}

#[test]
fn stop_reconciliation_refuses_a_blank_dropped_batch_cause() {
    // Dropped-batch shape with a blank cause: balanced counts do not
    // excuse an unnamed reason.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "1 calls shed from a dropped abandoned batch (=1) with 2 bindings",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        1,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect_err("a blank dropped-batch cause must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("counted total"),
        "the failure names the unparsable row: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_a_shed_row_with_an_unparsable_binding_count() {
    // Named cause and balanced counts, but the binding count is not
    // a number: the row matches neither producer template.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "1 calls shed without a route (unobserved=1) with two bindings",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        1,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect_err("an unparsable binding count must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("counted total"),
        "the failure names the unparsable row: {text}"
    );
}

#[test]
fn stop_reconciliation_refuses_a_shed_row_with_an_unknown_drop_word() {
    // Named cause and balanced counts, but the drop word names no
    // producer batch: the row matches neither template.
    let mut coordinator = reconciliation_test_coordinator();
    record_test_gap(
        &mut coordinator,
        None,
        None,
        "semantic calls unrouted",
        "1 calls shed from a dropped bogus batch (unobserved=1) with 2 bindings",
    );
    let error = assert_semantic_reconciled(
        &coordinator,
        1,
        "wp7-stop0-stop",
        &[
            stop_owner("a", 1, 1, [2, 0, 2, 0, 0]),
            stop_owner("b", 2, 2, [15, 1, 14, 1, 0]),
        ],
    )
    .expect_err("an unknown drop word must fail");
    let text = format!("{error:?}");
    assert!(
        text.contains("counted total"),
        "the failure names the unparsable row: {text}"
    );
}

/// Seal pending across stop, live (stop-time seal stall): the Finish
/// holds its seal take with the test seam (partition contention,
/// pending) across the production stop. The Finish is the single
/// stop (FinishStop runs the H0 stop inside the Finish drive; no
/// direct capture stop, no q2 Running quantum): its quantum collects
/// the complete return, stops H0, then its seal holds while the hold
/// masks the Stopped latch. Clearing the hold lets the take hit its
/// final Stopped refusal (no retry). The feed falls back at once, and
/// its calls land in one named capture-ended gap with their exact
/// count. The Finish then publishes, winds down, and hands off with
/// no latch, no trip, no abandon and no semantic_unavailable. Before
/// the fix the stopped take read as partition contention and every
/// delivery retried forever (the live s12b/s12c finish stall).
#[test]
#[ignore = "privileged: live Joint seal pending across stop falls back with named loss"]
fn privileged_joint_seal_pending_across_stop_falls_back_live_lp64() -> Result<()> {
    use crate::inventory_promotion::lifecycle::NativeCompletionSource as _;
    use crate::semantics_objects::journal::SealBootstrapCounts;
    use crate::semantics_objects::journal::joint_audit::{
        CAPTURE_ENDED_SUBJECT, capture_ended_reason,
    };

    const INDEX: usize = 100;
    let tag = format!("wp7-seal-stop{INDEX}");
    let workload = JointWorkload::build()?;
    let soft_manifest = provider_joint_manifest(
        workload.workload.dir.path(),
        &workload.soft_copy,
        JOINT_SOFT_FUNCTIONS,
        "wp7-seal-soft.dr37.json",
    )?;
    let held_manifest = provider_joint_manifest(
        workload.workload.dir.path(),
        &workload.held,
        &["C_SignInit", "C_Sign"],
        "wp7-seal-held.dr37.json",
    )?;
    let release = workload.path(&format!("release{INDEX}"));
    let go = workload.path(&format!("go{INDEX}"));
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
    if env!("P11SCOPE_JOURNAL_ENABLED") != "1" {
        eprintln!("P11SCOPE_CELL_BRANCH={tag}:s1-precluded");
        anyhow::bail!("{tag}: no journal build: the seal needs P11SCOPE_JOURNAL=1; not attempted");
    }
    let mut lane = start_joint_lane_with_journal(
        &mut coordinator,
        vec![soft_manifest.to_path_buf(), held_manifest.to_path_buf()],
    )?;
    let process_a = workload.spawn(
        &format!("A{INDEX}"),
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
        &format!("B{INDEX}"),
        &[
            "b", "--cell", "B", "--module", &soft_path, "--go", &go_arg, "--iters", "2", "--hold",
        ],
        &[],
    )?;
    drive_until_mapped(&mut coordinator, &[process_a.pid(), process_b.pid()])?;
    std::fs::write(&go, "go\n").context("releasing the live-joint gate")?;
    process_a.wait_for("HELD ", Duration::from_secs(60))?;
    process_b.wait_for("DONE ", Duration::from_secs(120))?;
    // q1 installs both Joint feeds (A held, B done). On a loaded host a
    // first quantum can shed and publish with 0 feeds; retry boundedly
    // until both install, so the seal below has staged history to fall
    // back. Each retry is another Running transaction, still before any
    // release, so the held entry stays in flight.
    let mut q1_polls = 0u64;
    let mut q1_feeds = 0;
    for attempt in 0..4 {
        q1_polls += service_to_published(
            &mut lane,
            &mut coordinator,
            attempt == 0,
            &format!("{tag}-q1a{attempt}"),
        )?;
        let feeds = coordinator.registry().joint_feeds();
        let seal = coordinator.joint_seal_bootstrap_diagnosis();
        eprintln!(
            "JOINT_STOP {tag}: q1 attempt {attempt} feeds={feeds} takes={:?} gaps={} shed={} \
             reverify={:?} covers={} pin={} other={}",
            seal.take_failed,
            coordinator.registry().gaps().len(),
            lane.shed_calls_disclosed(),
            seal.reverify_failed,
            seal.covers_failed,
            seal.pin_failed,
            seal.other_failed,
        );
        q1_feeds = feeds;
        if feeds == 2 {
            break;
        }
    }
    let q1_end_ns = monotonic_ns();
    let t_enter = ledger_stamp(&process_a.out, "HELD ")?;
    ensure!(
        t_enter < q1_end_ns,
        "{tag}: the held call entered before q1 ended: {t_enter} < {q1_end_ns}"
    );
    // Shed branch (busy host): q1 never installed both feeds. The shed
    // is acceptable only as a counted, named gap (partial, never
    // stop): the held call stays in flight across the production
    // Finish (same skeleton as the full branch, minus the hold: with
    // no feeds there is no seal to hold), the Finish publishes, and
    // the verdict pins the exact shed records plus the end-state
    // equation. Silent shedding, or a Finish that abandons, is red.
    if q1_feeds != 2 {
        let seal = coordinator.joint_seal_bootstrap_diagnosis();
        eprintln!(
            "JOINT_STOP {tag}: SHED feeds={q1_feeds} linked={} takes={:?} reverify={:?} \
             covers={} pin={} other={} shed={} merge_refused={}",
            coordinator.registry().journal_linked(),
            seal.take_failed,
            seal.reverify_failed,
            seal.covers_failed,
            seal.pin_failed,
            seal.other_failed,
            lane.shed_calls_disclosed(),
            lane.merge_refused_births(),
        );
        for gap in coordinator.registry().gaps().iter() {
            eprintln!(
                "JOINT_STOP {tag}: SHED gap {:?} {:?} caller={:?} module={:?} pid={:?} \
                 budget={:?}",
                gap.subject, gap.reason, gap.caller, gap.module, gap.pid, gap.budget,
            );
        }
        for gap in coordinator.registry().staged_gaps_for_test() {
            eprintln!(
                "JOINT_STOP {tag}: SHED staged {:?} {:?} caller={:?}",
                gap.subject, gap.reason, gap.caller,
            );
        }
        for (name, pid, module) in [
            ("a", process_a.pid(), "live-joint-held.so"),
            ("b", process_b.pid(), "soft-copy.so"),
        ] {
            match joint_edge_snapshot(&coordinator, pid, module) {
                Ok(edge) => eprintln!(
                    "JOINT_STOP {tag}: SHED edge_{name} joint={} reduced={} api={:?} \
                     started={:?} completed={:?} mechanisms={:?}",
                    edge.joint,
                    edge.reduced,
                    edge.api_returns,
                    edge.started,
                    edge.completed,
                    edge.mechanisms,
                ),
                Err(error) => eprintln!("JOINT_STOP {tag}: SHED edge_{name} missing: {error:#}"),
            }
            let out = if name == "a" {
                &process_a.out
            } else {
                &process_b.out
            };
            match ledger_calls(out) {
                Ok((per_function, total, bad)) => eprintln!(
                    "JOINT_STOP {tag}: SHED ledger_{name} total={total} bad={bad} \
                     per_function={per_function:?}",
                ),
                Err(error) => {
                    eprintln!("JOINT_STOP {tag}: SHED ledger_{name} unreadable: {error:#}")
                }
            }
        }
        if matches!(joint_branch(&coordinator), JointBranch::S1) {
            eprintln!("P11SCOPE_CELL_BRANCH={tag}:s1-precluded");
            anyhow::bail!(
                "{tag}: SHED: no journal feed: the cell needs a journal-build libtest \
                 (P11SCOPE_JOURNAL=1 P11SCOPE_BIRTH_MARKER=1); not attempted"
            );
        }
        ensure!(
            q1_feeds == 0,
            "{tag}: SHED: a partial install (1 feed) needs its own verdict, \
             not the 0-feed shed verdict (got {q1_feeds} feeds)"
        );
        {
            use crate::semantics_objects::journal::SealBootstrapCounts as Counts;
            let seal = coordinator.joint_seal_bootstrap_diagnosis();
            ensure!(
                seal.take_failed_total() == 0
                    && seal.reverify_failed.iter().all(|count| *count == 0)
                    && seal.covers_failed == 0
                    && seal.pin_failed == 0
                    && seal.other_failed == 0,
                "{tag}: SHED: control: the shed runs no seal (got takes={:?} \
                 reverify={:?} covers={} pin={} other={})",
                seal.take_failed,
                seal.reverify_failed,
                seal.covers_failed,
                seal.pin_failed,
                seal.other_failed,
            );
            let _ = Counts::take_index(crate::attach::BirthObservationRefusal::Stopped);
        }
        eprintln!(
            "JOINT_STOP {tag}: SHED: q1 shed in {q1_polls} polls; \
             the held call stays in flight across the stop"
        );
        // The production stop (no hold: no feeds, no seal to hold).
        // Every loop below is bounded.
        let mut driver = joint_finish_driver(&mut coordinator, lane);
        driver.begin_final_joint_finish();
        let begin = match &driver.joint_finish {
            JointFinishDriver::Polling => "polling",
            JointFinishDriver::Published => "published-at-begin",
            JointFinishDriver::Abandoned => "abandoned-at-begin",
            JointFinishDriver::NotBegun => "not-begun",
        }
        .to_string();
        ensure!(
            begin == "polling",
            "{tag}: SHED: the shed finish begins polling (got {begin}; \
             first_error={:?})",
            driver.joint_first_error,
        );
        let mut finish_polls = 0u64;
        let finish = {
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
                {
                    let seal = driver.coordinator.joint_seal_bootstrap_diagnosis();
                    let drive = driver
                        .semantic
                        .as_ref()
                        .map(|lane| format!("{:?}", lane.joint_drive_state_for_test()));
                    eprintln!(
                        "JOINT_STOP {tag}: SHED finish poll {finish_polls}: state={:?} \
                         drive={:?} takes_total={} shed={}",
                        driver.joint_finish,
                        drive,
                        seal.take_failed_total(),
                        driver
                            .semantic
                            .as_ref()
                            .map_or(u64::MAX, |lane| lane.shed_calls_disclosed()),
                    );
                }
                match &driver.joint_finish {
                    JointFinishDriver::Published => break "published".to_string(),
                    JointFinishDriver::Abandoned => break "abandoned".to_string(),
                    JointFinishDriver::Polling | JointFinishDriver::NotBegun => {}
                }
            }
        };
        let first_error = driver.joint_first_error.clone();
        ensure!(
            finish == "published",
            "{tag}: SHED: partial, never stop: the shed finish publishes \
             (got {finish} after {finish_polls} polls; first_error={first_error:?})"
        );
        let lane_ref = driver.semantic.as_ref().expect("lane");
        let latched = lane_ref.joint_finish_disposition_required();
        let latch_code = lane_ref
            .joint_disposition_reason()
            .map(|reason| reason.code().to_string());
        let finish_trip = lane_ref
            .joint_finish_no_progress_trip()
            .map(|trip| (trip.polls, trip.stalled.as_secs()));
        let audit_trip = lane_ref
            .joint_audit_no_progress_trip()
            .map(|trip| (trip.polls, trip.stalled.as_secs()));
        eprintln!(
            "JOINT_STOP {tag}: SHED finish={finish} after {finish_polls} polls; \
             first_error={first_error:?} latched={latched} latch={latch_code:?} \
             finish_trip={finish_trip:?} audit_trip={audit_trip:?}"
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
        // The held call stayed in flight across the stop; release it now
        // so it exits cleanly and flushes its ledger (its post-stop
        // return is never collected: the call itself was already counted
        // at entry).
        {
            let _release = std::fs::File::create(&release)?;
        }
        process_a.wait_for("DONE ", Duration::from_secs(60))?;
        // Shed verdict: the exact shed records plus the end-state
        // equation. Every entered call is attributed, slot-refused,
        // instance-refused, disclosed-shed, or pregrant-history-lost;
        // a silent drop breaks the equation.
        let seal = driver.coordinator.joint_seal_bootstrap_diagnosis();
        let lane_shed = driver
            .semantic
            .as_ref()
            .expect("lane")
            .shed_calls_disclosed();
        eprintln!(
            "JOINT_STOP {tag}: SHED end: takes={:?} reverify={:?} covers={} pin={} other={} \
             shed={lane_shed}",
            seal.take_failed,
            seal.reverify_failed,
            seal.covers_failed,
            seal.pin_failed,
            seal.other_failed,
        );
        let caller_a = caller_of(driver.coordinator, process_a.pid())?;
        let caller_b = caller_of(driver.coordinator, process_b.pid())?;
        let edge_a =
            joint_edge_snapshot(driver.coordinator, process_a.pid(), "live-joint-held.so")?;
        let edge_b = joint_edge_snapshot(driver.coordinator, process_b.pid(), "soft-copy.so")?;
        let (per_function_a, total_a, bad_a) = ledger_calls(&process_a.out)?;
        let (per_function_b, total_b, bad_b) = ledger_calls(&process_b.out)?;
        let (a_semantic, a_count_only) = ledger_semantic_split(&per_function_a);
        let (b_semantic, b_count_only) = ledger_semantic_split(&per_function_b);
        eprintln!(
            "JOINT_STOP {tag}: SHED end: ledger_a total={total_a} bad={bad_a} sem={a_semantic} \
             co={a_count_only} api={:?} | ledger_b total={total_b} bad={bad_b} sem={b_semantic} \
             co={b_count_only} api={:?}",
            edge_a.api_returns, edge_b.api_returns,
        );
        for gap in driver.coordinator.registry().gaps().iter() {
            eprintln!(
                "JOINT_STOP {tag}: SHED end gap {:?} {:?} caller={:?}",
                gap.subject, gap.reason, gap.caller
            );
        }
        let unrouted = driver
            .coordinator
            .registry()
            .gaps()
            .iter()
            .cloned()
            .chain(driver.coordinator.registry().staged_gaps_for_test())
            .filter(|gap| gap.subject == "semantic calls unrouted")
            .collect::<Vec<_>>();
        let history_subject = crate::inventory_present::JOINT_RETAINED_S1_SUBJECT.to_string();
        let history = driver
            .coordinator
            .registry()
            .gaps()
            .iter()
            .cloned()
            .chain(driver.coordinator.registry().staged_gaps_for_test())
            .filter(|gap| gap.subject == history_subject)
            .collect::<Vec<_>>();
        ensure!(
            matches!(joint_branch(driver.coordinator), JointBranch::Unattributed),
            "{tag}: SHED: zero installs with the default link latch \
             (feeds={} journal_linked={})",
            driver.coordinator.registry().joint_feeds(),
            driver.coordinator.registry().journal_linked(),
        );
        ensure!(
            finish == "published",
            "{tag}: SHED: the shed finish publishes (got {finish} after {finish_polls} polls)"
        );
        ensure!(
            wound == "joined",
            "{tag}: SHED: the published lane winds down (got {wound} after {wound_polls} polls)"
        );
        ensure!(
            taken,
            "{tag}: SHED: the wound-down lane hands off its session"
        );
        ensure!(
            first_error.is_none(),
            "{tag}: SHED: no first error (got {first_error:?})"
        );
        ensure!(
            !latched,
            "{tag}: SHED: no latched disposition (got {latch_code:?})"
        );
        ensure!(
            finish_trip.is_none(),
            "{tag}: SHED: no finish no-progress trip (got {finish_trip:?})"
        );
        ensure!(
            audit_trip.is_none(),
            "{tag}: SHED: no audit no-progress trip (got {audit_trip:?})"
        );
        ensure!(
            begin == "polling",
            "{tag}: SHED: the finish begins polling (got {begin})"
        );
        ensure!(
            seal.take_failed_total() == 0
                && seal.reverify_failed.iter().all(|count| *count == 0)
                && seal.covers_failed == 0
                && seal.pin_failed == 0
                && seal.other_failed == 0,
            "{tag}: SHED: the shed still runs no seal (got takes={:?} reverify={:?} \
             covers={} pin={} other={})",
            seal.take_failed,
            seal.reverify_failed,
            seal.covers_failed,
            seal.pin_failed,
            seal.other_failed,
        );
        ensure!(
            unrouted.len() == 1,
            "{tag}: SHED: exactly one unrouted-shed gap (got {unrouted:?})"
        );
        let gap = &unrouted[0];
        ensure!(
            gap.caller.is_none()
                && gap.module.is_none()
                && gap.pid.is_none()
                && gap.budget.is_none(),
            "{tag}: SHED: the unrouted gap is caller-less (got {gap:?})"
        );
        let (total, labels, bindings) = parse_unrouted_reason(&gap.reason)?;
        ensure!(
            total == lane_shed,
            "{tag}: SHED: the gap counts the lane shed exactly \
             (gap {total} vs lane {lane_shed})"
        );
        ensure!(
            bindings == 2,
            "{tag}: SHED: the shed binds exactly the two fixture callers (got {bindings})"
        );
        let labelled: u64 = labels.iter().map(|(_, count)| count).sum();
        ensure!(
            labelled == total,
            "{tag}: SHED: every shed call names its cause exactly once \
             (labels {labels:?} sum {labelled} vs total {total})"
        );
        ensure!(
            history.len() == 1,
            "{tag}: SHED: exactly one pregrant history-loss gap (got {history:?})"
        );
        let expected_history = crate::discovery::caller_registry::RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: history_subject,
            reason: "joint_pregrant_nonadmission_history_loss calls=1".to_string(),
            budget: None,
        };
        ensure!(
            history[0] == expected_history,
            "{tag}: SHED: the history-loss gap is exact (got {:?})",
            history[0],
        );
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
        let api_a = edge_a.api_returns.unwrap_or(0);
        let api_b = edge_b.api_returns.unwrap_or(0);
        ensure!(
            api_a <= a_semantic,
            "{tag}: SHED: a never over-attributes: api {api_a} <= sem {a_semantic}"
        );
        ensure!(
            api_b <= b_semantic,
            "{tag}: SHED: b never over-attributes: api {api_b} <= sem {b_semantic}"
        );
        ensure!(
            slot_a <= a_count_only,
            "{tag}: SHED: a never over-refuses: slot {slot_a} <= count-only {a_count_only}"
        );
        ensure!(
            slot_b <= b_count_only,
            "{tag}: SHED: b never over-refuses: slot {slot_b} <= count-only {b_count_only}"
        );
        let unrouted_entries =
            count_callerless_gap_entries(driver.coordinator, "semantic calls unrouted");
        let capacity_entries =
            count_callerless_gap_entries(driver.coordinator, "semantic call outcome capacity");
        let suppressed = driver.coordinator.registry().gaps_suppressed();
        ensure!(
            capacity_entries == 0,
            "{tag}: SHED: no capacity shed without a counter: {capacity_entries} entries"
        );
        ensure!(
            lane_shed == 0 || (unrouted_entries > 0 && suppressed == 0),
            "{tag}: SHED: shed calls are disclosed in a printed named gap: shed {lane_shed}, \
             entries {unrouted_entries}, suppressed {suppressed}"
        );
        let entered = total_a + total_b;
        ensure!(
            entered == api_a + api_b + lane_shed + slot_a + slot_b + inst_a + inst_b + 1,
            "{tag}: SHED: every entered call is attributed, slot-refused, instance-refused, \
             disclosed-shed or pregrant-history-lost: entered {entered} (a {total_a} + b \
             {total_b}) vs api {} + shed {lane_shed} + slot {} + inst {} + history 1",
            api_a + api_b,
            slot_a + slot_b,
            inst_a + inst_b,
        );
        let ended = driver
            .coordinator
            .registry()
            .gaps()
            .iter()
            .cloned()
            .chain(driver.coordinator.registry().staged_gaps_for_test())
            .filter(|gap| gap.subject == CAPTURE_ENDED_SUBJECT)
            .collect::<Vec<_>>();
        ensure!(
            ended.is_empty(),
            "{tag}: SHED: no capture-ended gap without a seal (got {ended:?})"
        );
        let unavailable = driver
            .coordinator
            .registry()
            .gaps()
            .iter()
            .cloned()
            .chain(driver.coordinator.registry().staged_gaps_for_test())
            .filter(|gap| gap.reason.contains("semantic_unavailable"))
            .collect::<Vec<_>>();
        ensure!(
            unavailable.is_empty(),
            "{tag}: SHED: no semantic_unavailable (got {unavailable:?})"
        );
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
        ensure!(
            abandon_gap.is_none(),
            "{tag}: SHED: no abandon gap without abandonment (got {abandon_gap:?})"
        );
        eprintln!(
            "P11SCOPE_CELL_BRANCH={tag}:shed:published:{finish_polls}:{wound_polls}:{}:{}",
            u8::from(taken),
            u8::from(minted),
        );
        eprintln!(
            "JOINT_STOP {tag}: SHED h0={h0_stop} taken={taken} minted={minted} \
             shed={lane_shed} entered={entered}"
        );
        return Ok(());
    }
    eprintln!(
        "JOINT_STOP {tag}: q1 published in {q1_polls} polls; \
         the held call stays in flight across the stop"
    );
    eprintln!(
        "JOINT_STOP {tag}: pre-finish baseline: drive={:?} stash={:?} stuck={:?}",
        lane.joint_drive_state_for_test(),
        lane.stash_pending_floor(),
        lane.joint_stuck_diagnostic_for_test(),
    );
    // Hold the seal take across the stop with the test seam, then stop
    // through the PRODUCTION sequencing: the Finish is the single stop
    // (no direct capture stop, no q2 Running quantum), with the held
    // call still in flight. The Finish quantum runs the H0 stop
    // inside FinishStop, then its seal takes for the staged entry
    // hold as partition contention (retry, pending) while the hold
    // masks the Stopped latch; clearing the hold lets the take hit
    // its final Stopped refusal (no retry), falling back with
    // counted loss. Deterministic: the hold flag pins the seal
    // pending by construction, and the phase order (FinishStop
    // before the seal) puts the production stop before the first
    // take. Only an S1 build precludes the cell here (no journal
    // feed at all).
    if matches!(joint_branch(&coordinator), JointBranch::S1) {
        eprintln!("P11SCOPE_CELL_BRANCH={tag}:s1-precluded");
        anyhow::bail!(
            "{tag}: no journal feed: the seal needs a journal-build libtest \
             (P11SCOPE_JOURNAL=1 P11SCOPE_BIRTH_MARKER=1); not attempted"
        );
    }
    {
        use crate::semantics_objects::journal::SealBootstrapCounts as Counts;
        let counts_q1 = coordinator.joint_seal_bootstrap_diagnosis();
        ensure!(
            counts_q1.take_failed_total() == 0,
            "{tag}: control: q1 took nothing (got {:?})",
            counts_q1.take_failed,
        );
        let _ = Counts::take_index(crate::attach::BirthObservationRefusal::Stopped);
    }
    lane.live_capture_mut()
        .expect("live capture")
        .set_hold_takes_for_test(true);
    // The production stop: begin the Finish (it owns the H0 stop via
    // FinishStop). Every loop below is bounded.
    let mut driver = joint_finish_driver(&mut coordinator, lane);
    driver.begin_final_joint_finish();
    let begin = match &driver.joint_finish {
        JointFinishDriver::Polling => "polling",
        JointFinishDriver::Published => "published-at-begin",
        JointFinishDriver::Abandoned => "abandoned-at-begin",
        JointFinishDriver::NotBegun => "not-begun",
    }
    .to_string();
    ensure!(
        begin == "polling",
        "{tag}: the seal-pending finish begins polling (got {begin}; \
         first_error={:?})",
        driver.joint_first_error,
    );
    // Held Finish polls: drive the begun Finish until its seal holds
    // (the first contention take), proving the seal is pending across
    // the production stop. The hold clears at once, so no trip can
    // arm on the held stall.
    let held_polls = {
        use crate::semantics_objects::journal::SealBootstrapCounts as Counts;
        let current = Counts::take_index(crate::attach::BirthObservationRefusal::CurrentPartition);
        let stopped = Counts::take_index(crate::attach::BirthObservationRefusal::Stopped);
        let started = Instant::now();
        let mut held_polls = 0u64;
        loop {
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
            held_polls += 1;
            ensure!(
                matches!(driver.joint_finish, JointFinishDriver::Polling),
                "{tag}: the held finish stays polling (got {:?} after {held_polls} polls; \
                 first_error={:?})",
                driver.joint_finish,
                driver.joint_first_error,
            );
            let counts = driver.coordinator.joint_seal_bootstrap_diagnosis();
            if counts.take_failed[current] >= 1 {
                eprintln!(
                    "JOINT_STOP {tag}: seal held after {held_polls} polls: current={} stopped={} \
                     all={:?}",
                    counts.take_failed[current], counts.take_failed[stopped], counts.take_failed,
                );
                break;
            }
            ensure!(
                held_polls < 1000 && started.elapsed() < Duration::from_secs(120),
                "{tag}: the seal never held after {held_polls} polls"
            );
        }
        let counts = driver.coordinator.joint_seal_bootstrap_diagnosis();
        ensure!(
            counts.take_failed[stopped] == 0,
            "{tag}: the hold masks the stop (got {:?})",
            counts.take_failed,
        );
        held_polls
    };
    driver
        .semantic
        .as_mut()
        .expect("lane")
        .live_capture_mut()
        .expect("live capture")
        .set_hold_takes_for_test(false);
    eprintln!(
        "JOINT_STOP {tag}: hold cleared after {held_polls} polls; \
         the pending seal now hits Stopped"
    );
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
    // Abandon forensics, printed on every run so a red finish stays
    // diagnosable (the lane holds the lane shell for exit, hiding it).
    {
        let seal = driver.coordinator.joint_seal_bootstrap_diagnosis();
        eprintln!(
            "JOINT_STOP {tag}: FORENSIC finish={finish} polls={finish_polls} \
             first_error={first_error:?} takes={:?} reverify={:?} covers={} pin={} other={} \
             shed={} merge_refused={}",
            seal.take_failed,
            seal.reverify_failed,
            seal.covers_failed,
            seal.pin_failed,
            seal.other_failed,
            driver
                .semantic
                .as_ref()
                .map_or(u64::MAX, |lane| lane.shed_calls_disclosed()),
            driver
                .semantic
                .as_ref()
                .map_or(u64::MAX, |lane| lane.merge_refused_births()),
        );
        if let Some(lane) = driver.semantic.as_ref() {
            eprintln!(
                "JOINT_STOP {tag}: FORENSIC latched={} latch={:?} audit={:?} stuck={:?} \
                 drive={:?} branch feeds={} linked={}",
                lane.joint_finish_disposition_required(),
                lane.joint_disposition_reason().map(|reason| reason.code()),
                lane.joint_audit_diagnostic_for_test(),
                lane.joint_stuck_diagnostic_for_test(),
                lane.joint_drive_state_for_test(),
                driver.coordinator.registry().joint_feeds(),
                driver.coordinator.registry().journal_linked(),
            );
        }
        // Map the forensic caller ids to the fixture processes, so
        // the finish's gap owners resolve.
        match (
            caller_of(driver.coordinator, process_a.pid()),
            caller_of(driver.coordinator, process_b.pid()),
        ) {
            (Ok(caller_a), Ok(caller_b)) => {
                let edge_a =
                    joint_edge_snapshot(driver.coordinator, process_a.pid(), "live-joint-held.so")
                        .map(|edge| (edge.joint, edge.reduced, edge.api_returns, edge.mechanisms));
                let edge_b =
                    joint_edge_snapshot(driver.coordinator, process_b.pid(), "soft-copy.so")
                        .map(|edge| (edge.joint, edge.reduced, edge.api_returns, edge.mechanisms));
                eprintln!(
                    "JOINT_STOP {tag}: FORENSIC callers a={caller_a:?} b={caller_b:?} \
                     edge_a={edge_a:?} edge_b={edge_b:?}"
                );
            }
            (caller_a, caller_b) => eprintln!(
                "JOINT_STOP {tag}: FORENSIC callers unresolved: {caller_a:?} {caller_b:?}"
            ),
        }
        for gap in driver.coordinator.registry().gaps().iter() {
            eprintln!(
                "JOINT_STOP {tag}: FORENSIC gap {:?} {:?} caller={:?}",
                gap.subject, gap.reason, gap.caller
            );
        }
        for gap in driver.coordinator.registry().staged_gaps_for_test() {
            eprintln!(
                "JOINT_STOP {tag}: FORENSIC staged {:?} {:?} caller={:?}",
                gap.subject, gap.reason, gap.caller
            );
        }
    }
    // Fail gracefully (not panic) when the finish abandons and holds
    // the lane for exit: the ensures below report the red state.
    ensure!(
        finish == "published",
        "{tag}: the seal-pending finish publishes (got {finish} after {finish_polls} polls; \
         first_error={first_error:?})"
    );
    // The production stop ran inside the finish (a publish without
    // it would mean the stop never sequenced).
    ensure!(
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .live_capture_mut()
            .expect("live capture")
            .capture_stopped_for_test(),
        "{tag}: the finish ran the production stop"
    );
    let lane_ref = driver.semantic.as_ref().expect("lane");
    let latched = lane_ref.joint_finish_disposition_required();
    let latch_code = lane_ref
        .joint_disposition_reason()
        .map(|reason| reason.code().to_string());
    let finish_trip = lane_ref
        .joint_finish_no_progress_trip()
        .map(|trip| (trip.polls, trip.stalled.as_secs()));
    let audit_trip = lane_ref
        .joint_audit_no_progress_trip()
        .map(|trip| (trip.polls, trip.stalled.as_secs()));
    eprintln!(
        "JOINT_STOP {tag}: finish={finish} after {finish_polls} polls; \
         first_error={first_error:?} latched={latched} latch={latch_code:?} \
         finish_trip={finish_trip:?} audit_trip={audit_trip:?}"
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
    // The held call stayed in flight across the stop; release it now
    // so it exits cleanly (its post-stop return is never collected:
    // the call itself was already counted at entry).
    {
        let _release = std::fs::File::create(&release)?;
    }
    process_a.wait_for("DONE ", Duration::from_secs(60))?;
    // Typed records: the final Stopped refusal, the named stop-loss gap
    // with its exact count, exit 0, no semantic_unavailable. The holds
    // above already counted as contention; the final Stopped is the
    // Finish's only new take after the hold clears.
    let counts = driver.coordinator.joint_seal_bootstrap_diagnosis();
    let stopped_index =
        SealBootstrapCounts::take_index(crate::attach::BirthObservationRefusal::Stopped);
    let current_index =
        SealBootstrapCounts::take_index(crate::attach::BirthObservationRefusal::CurrentPartition);
    let stopped_takes = counts.take_failed[stopped_index];
    let current_takes = counts.take_failed[current_index];
    let total_takes = counts.take_failed_total();
    eprintln!(
        "JOINT_STOP {tag}: take_failed stopped={stopped_takes} current={current_takes} \
         total={total_takes} all={:?}",
        counts.take_failed,
    );
    let caller_a = caller_of(driver.coordinator, process_a.pid())?;
    let caller_b = caller_of(driver.coordinator, process_b.pid())?;
    let edge_a = joint_edge_snapshot(driver.coordinator, process_a.pid(), "live-joint-held.so")?;
    let edge_b = joint_edge_snapshot(driver.coordinator, process_b.pid(), "soft-copy.so")?;
    let (per_function_a, total_a, bad_a) = ledger_calls(&process_a.out)?;
    let (per_function_b, total_b, bad_b) = ledger_calls(&process_b.out)?;
    let (a_semantic, a_count_only) = ledger_semantic_split(&per_function_a);
    let (b_semantic, b_count_only) = ledger_semantic_split(&per_function_b);
    let lane_shed = driver
        .semantic
        .as_ref()
        .expect("lane")
        .shed_calls_disclosed();
    eprintln!(
        "JOINT_STOP {tag}: end: ledger_a total={total_a} bad={bad_a} sem={a_semantic} \
         co={a_count_only} api={:?} | ledger_b total={total_b} bad={bad_b} sem={b_semantic} \
         co={b_count_only} api={:?} shed={lane_shed}",
        edge_a.api_returns, edge_b.api_returns,
    );
    let history_subject = crate::inventory_present::JOINT_RETAINED_S1_SUBJECT.to_string();
    let mut ended = driver
        .coordinator
        .registry()
        .gaps()
        .iter()
        .cloned()
        .chain(driver.coordinator.registry().staged_gaps_for_test())
        .filter(|gap| gap.subject == CAPTURE_ENDED_SUBJECT)
        .collect::<Vec<_>>();
    ended.sort_by_key(|gap| gap.caller);
    let mut feed_endings = driver
        .coordinator
        .registry()
        .gaps()
        .iter()
        .cloned()
        .chain(driver.coordinator.registry().staged_gaps_for_test())
        .filter(|gap| {
            gap.subject == history_subject && gap.reason == "joint_seal_bootstrap_mismatch_fallback"
        })
        .collect::<Vec<_>>();
    feed_endings.sort_by_key(|gap| gap.caller);
    for gap in driver.coordinator.registry().gaps().iter() {
        eprintln!(
            "JOINT_STOP {tag}: gap {:?} {:?} caller={:?}",
            gap.subject, gap.reason, gap.caller
        );
    }
    // Exit 0: the finish publishes, winds down and hands off with no
    // latch, no trip and no first error. The post-finish branch fell
    // back (q1's two installed feeds sealed across the stop, then
    // closed to S1Only at their Stopped takes; the link latch held).
    ensure!(
        driver.coordinator.registry().joint_feeds() == 0
            && driver.coordinator.registry().journal_linked(),
        "{tag}: the seal fell back after running linked (feeds={} journal_linked={})",
        driver.coordinator.registry().joint_feeds(),
        driver.coordinator.registry().journal_linked(),
    );
    ensure!(
        finish == "published",
        "{tag}: the seal-pending finish publishes (got {finish} after {finish_polls} polls)"
    );
    ensure!(
        wound == "joined",
        "{tag}: the published lane winds down (got {wound} after {wound_polls} polls)"
    );
    ensure!(taken, "{tag}: the wound-down lane hands off its session");
    ensure!(
        first_error.is_none(),
        "{tag}: no first error (got {first_error:?})"
    );
    ensure!(
        !latched,
        "{tag}: no latched disposition (got {latch_code:?})"
    );
    ensure!(
        finish_trip.is_none(),
        "{tag}: no finish no-progress trip (got {finish_trip:?})"
    );
    ensure!(
        audit_trip.is_none(),
        "{tag}: no audit no-progress trip (got {audit_trip:?})"
    );
    ensure!(
        begin == "polling",
        "{tag}: the finish begins polling (got {begin})"
    );
    // The final Stopped refusal: one seal take per installed feed
    // hits it (the stop latches every take: A's held call and B's
    // drained-but-revisited consumer). The holds above counted as
    // contention (at least one, budget-dependent); nothing else
    // fails a take.
    ensure!(
        stopped_takes == 2,
        "{tag}: one seal take per feed hits Stopped (got {stopped_takes}, total {total_takes})"
    );
    ensure!(
        current_takes >= 1,
        "{tag}: the hold pinned contention takes (got {current_takes}: {:?})",
        counts.take_failed,
    );
    ensure!(
        total_takes == stopped_takes + current_takes,
        "{tag}: no take failure besides the holds and the final Stopped \
         (got total {total_takes}: {:?})",
        counts.take_failed,
    );
    // The named stop-loss gaps with their exact counts: A's held
    // call lands with 1 call; B's drained consumer falls back with
    // 0 lost (its Stopped take still records the fallback). Pinned
    // text, sorted by caller.
    let expected_reason_a =
        capture_ended_reason(crate::attach::BirthObservationRefusal::Stopped, 1);
    let expected_reason_b =
        capture_ended_reason(crate::attach::BirthObservationRefusal::Stopped, 0);
    ensure!(
        expected_reason_a
            == "the capture ended before the seal could take its birth evidence \
                 (Stopped); fell back with counted loss (1 calls)",
        "{tag}: control: the reason renders the refusal and the count"
    );
    ensure!(
        expected_reason_b
            == "the capture ended before the seal could take its birth evidence \
                 (Stopped); fell back with counted loss (0 calls)",
        "{tag}: control: the empty fallback renders zero loss"
    );
    let expected = vec![
        crate::discovery::caller_registry::RegistryGap {
            caller: Some(caller_a),
            module: None,
            pid: None,
            subject: CAPTURE_ENDED_SUBJECT.to_string(),
            reason: expected_reason_a,
            budget: None,
        },
        crate::discovery::caller_registry::RegistryGap {
            caller: Some(caller_b),
            module: None,
            pid: None,
            subject: CAPTURE_ENDED_SUBJECT.to_string(),
            reason: expected_reason_b,
            budget: None,
        },
    ];
    let mut expected_sorted = expected;
    expected_sorted.sort_by_key(|gap| gap.caller);
    ensure!(
        ended == expected_sorted,
        "{tag}: capture-ended gaps for both callers with exact counts (got {ended:?})"
    );
    // Both feeds name their endings: one fallback gap per caller,
    // pinned text, sorted by caller.
    let expected_endings: Vec<crate::discovery::caller_registry::RegistryGap> =
        [caller_a, caller_b]
            .iter()
            .map(|caller| crate::discovery::caller_registry::RegistryGap {
                caller: Some(*caller),
                module: None,
                pid: None,
                subject: history_subject.clone(),
                reason: "joint_seal_bootstrap_mismatch_fallback".to_string(),
                budget: None,
            })
            .collect();
    let mut expected_endings_sorted = expected_endings;
    expected_endings_sorted.sort_by_key(|gap| gap.caller);
    ensure!(
        feed_endings == expected_endings_sorted,
        "{tag}: fallback feed endings for both callers (got {feed_endings:?})"
    );
    // End-state equation: every entered call is attributed,
    // slot-refused, instance-refused, disclosed-shed, or named in
    // the capture-ended gaps (A: 1, B: 0, pinned above). A silent
    // drop breaks the equation.
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
    let api_a = edge_a.api_returns.unwrap_or(0);
    let api_b = edge_b.api_returns.unwrap_or(0);
    ensure!(
        api_a <= a_semantic,
        "{tag}: a never over-attributes: api {api_a} <= sem {a_semantic}"
    );
    ensure!(
        api_b <= b_semantic,
        "{tag}: b never over-attributes: api {api_b} <= sem {b_semantic}"
    );
    ensure!(
        slot_a <= a_count_only,
        "{tag}: a never over-refuses: slot {slot_a} <= count-only {a_count_only}"
    );
    ensure!(
        slot_b <= b_count_only,
        "{tag}: b never over-refuses: slot {slot_b} <= count-only {b_count_only}"
    );
    let entered = total_a + total_b;
    ensure!(
        entered == api_a + api_b + lane_shed + slot_a + slot_b + inst_a + inst_b + 1,
        "{tag}: every entered call is attributed, slot-refused, instance-refused, \
         disclosed-shed or capture-ended: entered {entered} (a {total_a} + b \
         {total_b}) vs api {} + shed {lane_shed} + slot {} + inst {} + ended 1",
        api_a + api_b,
        slot_a + slot_b,
        inst_a + inst_b,
    );
    // No semantic_unavailable: the lane never stops with loss, and no
    // abandon gap appears without an abandonment.
    let unavailable = driver
        .coordinator
        .registry()
        .gaps()
        .iter()
        .cloned()
        .chain(driver.coordinator.registry().staged_gaps_for_test())
        .filter(|gap| gap.reason.contains("semantic_unavailable"))
        .collect::<Vec<_>>();
    ensure!(
        unavailable.is_empty(),
        "{tag}: no semantic_unavailable (got {unavailable:?})"
    );
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
    ensure!(
        abandon_gap.is_none(),
        "{tag}: no abandon gap without abandonment (got {abandon_gap:?})"
    );
    eprintln!(
        "P11SCOPE_CELL_BRANCH={tag}:fallback:published:{finish_polls}:{wound_polls}:{}:{}",
        u8::from(taken),
        u8::from(minted),
    );
    eprintln!(
        "JOINT_STOP {tag}: h0={h0_stop} taken={taken} minted={minted} \
         stopped={stopped_takes} ended={ended:?}"
    );
    Ok(())
}
