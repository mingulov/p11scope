//! SPDX-License-Identifier: GPL-3.0-or-later
//! The native lane over a scripted facade and a real coordinator (scripted
//! process source, scripted catalogs): the exact call order of startup,
//! passes and stop, and what each ordering rule buys end to end.

use super::*;
use crate::attach::capture::{
    AttachedEndpoint, CallerCountUpdate, CaptureHealth, CapturePhase, DomainCookie, ExecCoverage,
    WitnessRow,
};
use crate::discovery::caller_registry::tests::ScriptedSource;
use crate::discovery::caller_registry::{CallerId, ExeIdentity, RegistryLimits, UseCoverage};
use crate::discovery::engine::inventory::UnavailableImageGuard;
use crate::discovery::hooks::HookRegistry;
use crate::discovery::inventory_attach_set::AttachEndpoint;
use crate::discovery::inventory_attach_set::tests as fx;
use crate::discovery::native_binding::UnboundReason;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;

type Pin = (u32, u64);
type Log = Rc<RefCell<Vec<String>>>;

const PID: u32 = 7;
const START: u64 = 500;
const TICKET: u64 = 41;
/// A failure bound only: a gated collection that is never serviced fails
/// after this instead of hanging.
const GATE_TIMEOUT: Duration = Duration::from_secs(5);
/// No collection tick fires in the exact-order tests: their collections
/// return at once.
const NO_COLLECTION_TICK: Duration = Duration::from_secs(3600);

/// The existing scripted capture through the real PID-pin runtime seam.
/// It supplies no kernel identity or privileged capture evidence.
pub(crate) fn cgroup_runtime_lane() -> (
    impl CaptureLane<crate::process::PidPin>,
    Rc<RefCell<Vec<String>>>,
) {
    cgroup_runtime_lane_with_exec(None)
}

pub(crate) fn cgroup_runtime_exec_lane(
    pid: u32,
) -> (
    impl CaptureLane<crate::process::PidPin>,
    Rc<RefCell<Vec<String>>>,
) {
    cgroup_runtime_lane_with_exec(Some(pid))
}

fn cgroup_runtime_lane_with_exec(
    pid: Option<u32>,
) -> (
    impl CaptureLane<crate::process::PidPin>,
    Rc<RefCell<Vec<String>>>,
) {
    struct OsLane(ScriptedLane, Option<u32>, u64);
    impl NativeIdentity<crate::process::PidPin> for OsLane {
        fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
            None
        }
        fn query_cookie(
            &mut self,
            domain: NativeDomainId,
            pin: &crate::process::PidPin,
        ) -> CookieQuery {
            if domain == self.0.domain && self.1 == Some(pin.pid()) {
                CookieQuery::Cookie(DomainCookie::scripted(domain, TICKET))
            } else {
                CookieQuery::NoCookie
            }
        }
    }
    impl CaptureLane<crate::process::PidPin> for OsLane {
        fn domain(&self) -> NativeDomainId {
            self.0.domain()
        }
        fn scope_coverage(&self) -> CaptureScopeCoverage {
            self.0.scope_coverage()
        }
        fn extend(
            &mut self,
            delta: TargetDelta,
            targets: &dyn CaptureTargets,
            window: ExtendWindow,
        ) -> ExtendReceipt {
            self.0.extend(delta, targets, window)
        }
        fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
            self.0.service_discovery(window)
        }
        fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
            let mut batch = self.0.read_witnesses(window);
            if let Some(pid) = self.1
                && let Some(endpoint) = self.0.attached.first()
            {
                self.2 = self.2.saturating_add(1);
                // Each new image row needs a later empty read's health
                // horizon, alongside a later lifecycle drain, before binding.
                let exec = match self.2 {
                    1 => Some(1),
                    3 => Some(2),
                    _ => None,
                };
                if let Some(exec) = exec {
                    batch.rows.push(WitnessRow::scripted(
                        self.0.domain,
                        TICKET,
                        exec,
                        endpoint.object,
                        endpoint.id,
                        pid,
                        batch.rows_read_ns,
                    ));
                }
            }
            batch
        }
        fn begin_stop(&mut self) {
            self.0.begin_stop();
        }
        fn poll_retirement(&mut self, deadline: Instant) -> Result<bool> {
            self.0.poll_retirement(deadline)
        }
        fn cleanup(&self) -> Option<CleanupSummary> {
            self.0.cleanup()
        }
    }
    let log = Log::default();
    let mut lane = ScriptedLane::new(&log);
    lane.scope_coverage = CaptureScopeCoverage::Cgroup;
    (OsLane(lane, pid, 0), log)
}

/// Strictly increasing CLOCK_MONOTONIC stamps: each facade batch follows
/// the one before it, and every stamp follows the real clock.
#[derive(Default)]
struct Stamps(u64);

impl Stamps {
    fn next(&mut self) -> u64 {
        self.0 = now_ns().max(self.0 + 1);
        self.0
    }
}

/// One row the scripted capture reports: the attached endpoint's index (in
/// attach order), the caller tgid, and its ticket.
#[derive(Clone, Copy)]
struct RowSpec {
    endpoint: usize,
    tgid: u32,
    ticket: u64,
}

/// One refreshed count the scripted capture reports: the attached endpoint's
/// index (for its object), the caller image, and the re-read count.
#[derive(Clone, Copy)]
struct CountSpec {
    endpoint: usize,
    ticket: u64,
    exec: u64,
    count: u64,
}

/// A scripted facade: records every call, activates on the first extend,
/// attaches what it is given (minus a scripted deferral), reports scripted
/// rows per read, answers scripted cookies, and retires after a scripted
/// number of polls (never, when `None`).
struct ScriptedLane {
    log: Log,
    scope_coverage: CaptureScopeCoverage,
    domain: NativeDomainId,
    stamps: Stamps,
    activated: bool,
    refuse_activation: bool,
    /// Endpoints the next non-activating extend defers (from the end).
    defer_next: usize,
    attached: Vec<AttachEndpoint>,
    reads: VecDeque<Vec<RowSpec>>,
    /// Refreshed counts per read, popped in read order like `reads`.
    refreshes: VecDeque<Vec<CountSpec>>,
    /// Health instants of every read, in order.
    read_stamps: Vec<u64>,
    cookies: HashMap<Pin, u64>,
    stopping: bool,
    polls: u32,
    retire_after: Option<u32>,
    retired: bool,
    /// The first this many reads cannot prove health.
    unproven_reads: usize,
    /// Reads (1-based) that stop mid-sweep.
    partial_reads: HashSet<usize>,
    /// Reads (1-based) whose count-refresh sweep does not complete.
    partial_refresh_reads: HashSet<usize>,
    /// Reads (1-based) whose count-refresh sweep completes with gaps.
    gappy_refresh_reads: HashSet<usize>,
    /// How long each read takes.
    read_delay: Duration,
    /// After this many reads, the next `.1` discovery quanta stop at their
    /// record bound (the ring still holds records).
    undrained_after_reads: Option<(usize, usize)>,
    /// The start of the last complete lifecycle drain (the facade's
    /// `lifecycle_proven_ns`).
    drained_ns: u64,
    /// Signalled on every discovery service (the collection gate's tap).
    serviced: Option<mpsc::Sender<()>>,
    /// Every serviced quantum's start stamp, in drain order.
    service_stamps: Rc<RefCell<Vec<u64>>>,
    /// Records each discovery quantum returns (non-exec, binder-neutral).
    records_per_service: usize,
    /// The DISCOVERY ring-loss counter each read reports, in read order
    /// (the last one repeats; empty: 0).
    ring_loss: VecDeque<u64>,
    /// The malformed-record count each read reports, as `ring_loss`.
    malformed: VecDeque<u64>,
    /// Discovery services (1-based) whose quantum fails on an undecodable
    /// record.
    failed_services: HashSet<usize>,
    /// The drain high-water each discovery quantum reports, by service
    /// (1-based: the first entry is the first service); `None` past it.
    drain_high_water_bytes: Vec<Option<u64>>,
    services: usize,
}

impl Drop for ScriptedLane {
    fn drop(&mut self) {
        self.note("drop");
    }
}

impl ScriptedLane {
    fn new(log: &Log) -> Self {
        let mut cookies = HashMap::new();
        cookies.insert((PID, START), TICKET);
        Self {
            log: Rc::clone(log),
            scope_coverage: CaptureScopeCoverage::System,
            domain: NativeDomainId::mint(),
            stamps: Stamps::default(),
            activated: false,
            refuse_activation: false,
            defer_next: 0,
            attached: Vec::new(),
            reads: VecDeque::new(),
            refreshes: VecDeque::new(),
            read_stamps: Vec::new(),
            cookies,
            stopping: false,
            polls: 0,
            retire_after: Some(1),
            retired: false,
            unproven_reads: 0,
            partial_reads: HashSet::new(),
            partial_refresh_reads: HashSet::new(),
            gappy_refresh_reads: HashSet::new(),
            read_delay: Duration::ZERO,
            undrained_after_reads: None,
            drained_ns: 0,
            serviced: None,
            service_stamps: Rc::default(),
            records_per_service: 0,
            ring_loss: VecDeque::new(),
            malformed: VecDeque::new(),
            failed_services: HashSet::new(),
            drain_high_water_bytes: Vec::new(),
            services: 0,
        }
    }

    fn note(&self, entry: impl Into<String>) {
        self.log.borrow_mut().push(entry.into());
    }

    fn custody(&self) -> ScopeCustody {
        match self.scope_coverage {
            CaptureScopeCoverage::System => ScopeCustody::System,
            CaptureScopeCoverage::Pid(_) => ScopeCustody::PidHeld,
            CaptureScopeCoverage::Cgroup => ScopeCustody::CgroupHeld,
        }
    }
}

impl NativeIdentity<Pin> for ScriptedLane {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &Pin) -> CookieQuery {
        if domain != self.domain {
            return CookieQuery::Unavailable("another domain".into());
        }
        match self.cookies.get(pin) {
            Some(ticket) => CookieQuery::Cookie(DomainCookie::scripted(domain, *ticket)),
            None => CookieQuery::NoCookie,
        }
    }
}

impl CaptureLane<Pin> for ScriptedLane {
    fn domain(&self) -> NativeDomainId {
        self.domain
    }

    fn scope_coverage(&self) -> CaptureScopeCoverage {
        self.scope_coverage
    }

    fn extend(
        &mut self,
        mut delta: TargetDelta,
        _: &dyn CaptureTargets,
        _: ExtendWindow,
    ) -> ExtendReceipt {
        let ids: Vec<String> = delta
            .endpoints
            .iter()
            .map(|endpoint| endpoint.id.0.to_string())
            .collect();
        self.note(format!("extend[{}]", ids.join(",")));
        let mut receipt = ExtendReceipt {
            custody: Some(self.custody()),
            ..ExtendReceipt::default()
        };
        if !self.activated {
            if self.refuse_activation {
                receipt.refused = Some("scripted activation refusal".into());
                receipt.deferred = delta;
                return receipt;
            }
            self.activated = true;
            receipt.activated_roots = true;
            receipt.exec_coverage = Some(ExecCoverage::scripted(self.domain, self.stamps.next()));
        }
        let keep = delta.endpoints.len().saturating_sub(self.defer_next);
        if self.defer_next > 0 && !delta.endpoints.is_empty() {
            receipt.deferred.endpoints = delta.endpoints.split_off(keep);
            self.defer_next = 0;
        }
        for endpoint in delta.endpoints {
            receipt.attached.push(AttachedEndpoint {
                id: endpoint.id,
                object: endpoint.object,
                at_ns: self.stamps.next(),
            });
            self.attached.push(endpoint);
        }
        receipt
    }

    fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
        self.note("service");
        self.services += 1;
        // SAFETY: `DiscoveryRecord` is a plain `repr(C)` integer record; all
        // zeroes is a valid value (kind 0: no exec, the binder ignores it).
        let records = (0..self.records_per_service.min(window.max_rows()))
            .map(|_| unsafe { std::mem::zeroed::<p11scope_ebpf_common::DiscoveryRecord>() })
            .collect();
        let mut batch = DiscoveryBatch::scripted(self.domain, records, self.stamps.next());
        batch.drain_high_water_bytes = self
            .drain_high_water_bytes
            .get(self.services - 1)
            .copied()
            .flatten();
        // A quantum that fills its window stops at its record bound.
        batch.record_bound_reached = self.records_per_service >= window.max_rows();
        if self.failed_services.contains(&self.services) {
            batch.failure = Some("scripted undecodable record".into());
        }
        self.service_stamps.borrow_mut().push(batch.started_ns);
        if let Some(serviced) = &self.serviced {
            let _ = serviced.send(());
        }
        if let Some((after, left)) = self.undrained_after_reads.as_mut()
            && self.read_stamps.len() >= *after
            && *left > 0
        {
            *left -= 1;
            batch.record_bound_reached = true;
        }
        if batch.drained() {
            self.drained_ns = batch.started_ns;
        }
        batch
    }

    fn read_witnesses(&mut self, _: ReadWindow) -> WitnessBatch {
        self.note("read");
        std::thread::sleep(self.read_delay);
        let health_read_ns = self.stamps.next();
        self.read_stamps.push(health_read_ns);
        let rows = self
            .reads
            .pop_front()
            .unwrap_or_default()
            .into_iter()
            .map(|spec| {
                let endpoint = self.attached[spec.endpoint];
                WitnessRow::scripted(
                    self.domain,
                    spec.ticket,
                    1,
                    endpoint.object,
                    endpoint.id,
                    spec.tgid,
                    health_read_ns,
                )
            })
            .collect();
        let counts = self
            .refreshes
            .pop_front()
            .unwrap_or_default()
            .into_iter()
            .map(|spec| {
                let endpoint = self.attached[spec.endpoint];
                CallerCountUpdate {
                    image: ImageIdentity {
                        task_cookie: spec.ticket,
                        exec_id: spec.exec,
                    },
                    object: endpoint.object,
                    count: spec.count,
                }
            })
            .collect();
        let rows_read_ns = self.stamps.next();
        let health_unproven = (self.read_stamps.len() <= self.unproven_reads)
            .then(|| "scripted unreadable health".to_string());
        let scripted = |counts: &mut VecDeque<u64>| match counts.len() {
            0 => 0,
            1 => counts[0],
            _ => counts.pop_front().unwrap(),
        };
        let ring_loss = scripted(&mut self.ring_loss);
        let malformed = scripted(&mut self.malformed);
        WitnessBatch {
            domain: self.domain,
            phase: if self.stopping {
                CapturePhase::Retiring
            } else {
                CapturePhase::Active
            },
            rows,
            integrity: Vec::new(),
            integrity_total: 0,
            visited: 0,
            sweep_completed: !self.partial_reads.contains(&self.read_stamps.len()),
            sweeps_completed: 1,
            row_bound_reached: false,
            deadline_reached: false,
            read_failures: Vec::new(),
            unrecorded_rows: 0,
            sweep_gaps: false,
            counts,
            refresh_sweep_completed: !self.partial_refresh_reads.contains(&self.read_stamps.len()),
            refresh_sweep_gaps: self.gappy_refresh_reads.contains(&self.read_stamps.len()),
            refresh_deadline_reached: false,
            refresh_sweeps_completed: 1,
            seen_rows: 0,
            pair_limit: 64,
            lifecycle_loss: None,
            lifecycle_proven_ns: self.drained_ns,
            health: CaptureHealth {
                discovery_counters: Some([ring_loss, 0, 0, 0, 0]),
                malformed_discovery: malformed,
                ..CaptureHealth::default()
            },
            health_regression: None,
            health_unproven,
            health_baseline_ns: 0,
            health_read_ns,
            rows_anchor_ns: rows_read_ns,
            rows_read_ns,
            counts_read_ns: rows_read_ns,
            changed_objects: Vec::new(),
            custody: self.custody(),
            custody_proven_ns: None,
            unsettled: self.stopping,
        }
    }

    fn begin_stop(&mut self) {
        self.note("begin_stop");
        self.stopping = true;
    }

    fn poll_retirement(&mut self, _: Instant) -> Result<bool> {
        self.note("poll");
        self.polls += 1;
        if self.retire_after.is_some_and(|after| self.polls >= after) {
            self.retired = true;
        }
        Ok(self.retired)
    }

    fn cleanup(&self) -> Option<CleanupSummary> {
        self.retired.then(|| CleanupSummary {
            attempted: self.attached.len() + 2,
            closed: self.attached.len() + 2,
            failures: Vec::new(),
            retained_links: 0,
        })
    }
}

/// A real coordinator over a scripted process source (pid 7, start 500,
/// mapping one two-endpoint provider) that records every call the lane and
/// the loop make on it.
struct Scene {
    _dir: tempfile::TempDir,
    path: PathBuf,
    source: ScriptedSource,
    coordinator: InventoryCoordinator<ScriptedSource>,
    log: Log,
    /// The loop's per-tick hook notes `display` (C5.3: the dashboard).
    display_ticks: bool,
    /// A second caller (pid, start) that maps the provider from this scan
    /// (1-based) on.
    joiner: Option<(u32, u64, usize)>,
    scans: usize,
    /// The first collection waits for this many discovery services (C5.7
    /// threading boundary): it cannot finish unless the loop services the
    /// ring while it runs.
    collect_gate: Option<(mpsc::Receiver<()>, usize)>,
    /// Every staged lifecycle quantum's start stamp, in staging order.
    staged_lifecycle: Vec<u64>,
    /// Every staged witness batch's refreshed-count size, in staging order.
    staged_counts: Vec<usize>,
}

impl Scene {
    fn new(log: &Log) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = fx::provider(&dir, "a.so", "provider-a");
        let source = ScriptedSource::default();
        source.spawn(PID, START);
        let coordinator = InventoryCoordinator::new(
            crate::attach::Scope::System,
            HookRegistry::builtin(),
            Vec::new(),
            source.clone(),
            RegistryLimits::default_limits(),
        )
        .unwrap();
        Self {
            _dir: dir,
            path,
            source,
            coordinator,
            log: Rc::clone(log),
            display_ticks: false,
            joiner: None,
            scans: 0,
            collect_gate: None,
            staged_lifecycle: Vec::new(),
            staged_counts: Vec::new(),
        }
    }

    fn note(&self, entry: impl Into<String>) {
        self.log.borrow_mut().push(entry.into());
    }

    /// The pass's catalog: pid 7 maps the provider, plus the Inventory
    /// lowering the attach set absorbs.
    fn catalog(&self) -> crate::inspect_system::Catalog {
        let pins = fx::pass_pins(&[(&self.path, "sha-a")]);
        let module = fx::module(&pins, &self.path, &fx::offsets(2));
        let policy =
            crate::plan::AdmissionPolicy::Inventory(self.coordinator.attach_set().budget());
        let plan = fx::lower_named(std::slice::from_ref(&module), &pins, policy);
        let path = self.path.to_str().unwrap().to_string();
        let mut members = vec![(PID, START)];
        if let Some((pid, start, from)) = self.joiner
            && self.scans >= from
        {
            members.push((pid, start));
        }
        let (key, sha256) = {
            let summary = pins.pinned().find(|summary| summary.path == path).unwrap();
            (summary.key, summary.sha256.to_string())
        };
        let object = crate::inspect_system::CatalogObject {
            path: path.clone(),
            key,
            sha256: Some(sha256),
            build_id: None,
            identity_source: Some("mountinfo"),
            note: None,
            mappings: Vec::new(),
            observations: members
                .iter()
                .map(|(pid, _)| crate::inspect_system::Observation {
                    pid: *pid,
                    path: path.clone(),
                    exports: Vec::new(),
                    tables: Vec::new(),
                    interfaces: Vec::new(),
                    double_loaded: false,
                    evidence: crate::inspect_system::ObservationEvidence::DeepScan,
                })
                .collect(),
            admission: crate::inspect_system::AdmissionRecord::Admitted {
                class: "exact",
                endpoints: 2,
            },
        };
        crate::inspect_system::Catalog {
            scan_status: "complete",
            lowering: Some(crate::inspect_system::CatalogLowering { plan, pins }),
            enumerated: 1,
            selected: 1,
            scanned: 1,
            maps_matched: 0,
            unexamined: 0,
            unexamined_objects: 0,
            snapshots_unavailable: 0,
            attribution_losses: std::collections::BTreeMap::new(),
            cap: 1,
            scan_ms: 0,
            processes: members
                .iter()
                .map(|(pid, start)| crate::inspect_system::ProcessRecord {
                    application: crate::inspect_identity::InspectApplicationResult::Unknown(
                        crate::inspect_identity::InspectIdentityUnknown::NotExamined,
                    ),
                    complete_scan: None,
                    pid: *pid,
                    status: crate::inspect_system::MemberStatus::Scanned,
                    objects: vec![0],
                    generation: Some(crate::inspect_system::MemberGeneration {
                        start_time: Some(*start),
                        exe: Some(ExeIdentity {
                            dev: 1,
                            ino: 100,
                            mtime_secs: 10,
                            mtime_nanos: 0,
                            path: Some("/bin/driver".into()),
                        }),
                    }),
                })
                .collect(),
            objects: vec![object],
            relationships: Vec::new(),
            admission: crate::inspect_system::AdmissionSummary {
                uncorroborated_candidates: 0,
                module_ambiguous: 0,
                admitted: 1,
                refused: 0,
                unresolved: 0,
            },
            skipped: Vec::new(),
            notes: Vec::new(),
            explanation: None,
            stage_timings: crate::timing::StageTimings::new(),
        }
    }

    fn caller(&self, pid: u32) -> CallerId {
        self.coordinator
            .adapter()
            .records()
            .find(|record| record.pid == pid)
            .map(|record| record.id)
            .expect("the pid was admitted")
    }

    fn coverage(&self) -> UseCoverage {
        self.coverage_of(PID)
    }

    fn coverage_of(&self, pid: u32) -> UseCoverage {
        let caller = self.caller(pid);
        let registry = self.coordinator.registry();
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("pid 7 has its edge");
        registry.coverage(edge)
    }

    fn gap_subjects(&self) -> Vec<String> {
        self.coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect()
    }
}

impl LaneHost<Pin> for Scene {
    fn begin_capture_coverage(&mut self, scope: CaptureScopeCoverage) {
        self.note("begin_capture_coverage");
        self.coordinator.begin_capture_coverage(scope);
    }

    fn abandon_capture_coverage(&mut self) {
        self.note("abandon_capture_coverage");
        self.coordinator.abandon_capture_coverage();
    }

    fn note_extend_receipt(&mut self, receipt: &ExtendReceipt) {
        self.note(if receipt.exec_coverage.is_some() {
            "note_extend_receipt(activating)"
        } else {
            "note_extend_receipt"
        });
        self.coordinator.note_extend_receipt(receipt);
    }

    fn note_capture_custody(&mut self, custody: &ScopeCustody) {
        self.note("note_capture_custody");
        self.coordinator.note_capture_custody(custody);
    }

    fn take_target_delta(&mut self) -> TargetDelta {
        self.note("take_target_delta");
        self.coordinator.take_target_delta()
    }

    fn capture_targets(&self) -> &dyn CaptureTargets {
        self.coordinator.attach_set()
    }

    fn stage_native(
        &mut self,
        batch: NativeBatch,
        identity: &mut dyn NativeIdentity<Pin>,
        now_ns: u64,
    ) -> NativeReceipt {
        self.note(match &batch {
            NativeBatch::Witness(_) => "stage:witness",
            NativeBatch::Lifecycle(_) => "stage:lifecycle",
            NativeBatch::Finish { .. } => "stage:finish",
            NativeBatch::Semantic(_) => "stage:semantic",
        });
        if let NativeBatch::Lifecycle(lifecycle) = &batch {
            self.staged_lifecycle.push(lifecycle.started_ns);
        }
        if let NativeBatch::Witness(witness) = &batch {
            self.staged_counts.push(witness.counts.len());
        }
        self.coordinator.stage_native(batch, identity, now_ns)
    }

    fn end_capture_coverage(&mut self, at_ns: u64) {
        self.note("end_capture_coverage");
        self.coordinator.end_capture_coverage(at_ns);
    }

    fn note_native_lane(&mut self) {
        self.note("note_native_lane");
        LaneHost::<Pin>::note_native_lane(&mut self.coordinator);
    }

    fn note_scope_gap(&mut self, subject: String, reason: String) {
        self.note(format!("gap:{subject}"));
        self.coordinator.note_scope_gap(subject, reason);
    }

    fn note_refresh_loss(&mut self, reason: String) {
        self.note(format!("refresh-loss:{reason}"));
        self.coordinator.note_refresh_loss(reason);
    }
}

impl PassDriver<Pin> for Scene {
    type Host = Self;

    fn host(&mut self) -> &mut Self {
        self
    }

    fn collector(&mut self) -> CollectJob {
        self.note("collect");
        self.scans += 1;
        let catalog = self.catalog();
        let gate = self.collect_gate.take();
        CollectJob::Legacy(Box::new(move || {
            if let Some((serviced, wanted)) = gate {
                for _ in 0..wanted {
                    serviced
                        .recv_timeout(GATE_TIMEOUT)
                        .map_err(|_| anyhow!("the ring was not serviced during the collection"))?;
                }
            }
            Ok(catalog)
        }))
    }

    fn apply(
        &mut self,
        collected: CollectedPass,
        identity: &mut dyn NativeIdentity<Pin>,
        now_ns: u64,
    ) -> Result<PassReport> {
        self.note("scan");
        Ok(self.coordinator.apply_catalog(
            collected.legacy()?,
            &mut UnavailableImageGuard,
            identity,
            u64::MAX,
            now_ns,
        ))
    }

    fn commit(&mut self, engine_changed: bool) -> Result<()> {
        self.note("commit");
        self.coordinator.commit_batch(engine_changed).map(|_| ())
    }

    fn on_tick(&mut self) {
        if self.display_ticks {
            self.note("display");
        }
    }
}

fn windows() -> LaneWindows {
    LaneWindows {
        retirement_base: Duration::from_millis(200),
        retirement_per_link: Duration::from_millis(50),
        ..LaneWindows::PROVISIONAL
    }
}

/// Runs `passes` passes (no pause between them), then the stop.
fn run(
    scene: &mut Scene,
    lane: ScriptedLane,
    passes: usize,
) -> (Stopped<ScriptedLane>, Vec<CallerEvent>) {
    run_ticking(scene, lane, passes, NO_COLLECTION_TICK)
}

/// `run` with a collection tick.
fn run_ticking(
    scene: &mut Scene,
    lane: ScriptedLane,
    passes: usize,
    collection_tick: Duration,
) -> (Stopped<ScriptedLane>, Vec<CallerEvent>) {
    let log = Rc::clone(&scene.log);
    let started = NativeLane::start(lane, scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let scans = move || log.borrow().iter().filter(|entry| *entry == "scan").count();
    let stop = move || scans() >= passes;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick,
    };
    let mut published = Vec::new();
    let stopped = run_classic(
        scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, point| {
            match point {
                Publish::Pass { report, .. } => {
                    scene.note("publish:pass");
                    published.extend(report.events.iter().cloned());
                }
                Publish::Retiring {
                    attached, budget, ..
                } => {
                    scene.note(format!(
                        "publish:retiring {attached} {}",
                        budget.as_millis()
                    ));
                }
                Publish::Stop { events, .. } => {
                    scene.note("publish:stop");
                    published.extend(events.iter().cloned());
                }
            }
            Ok(())
        },
    )
    .unwrap()
    .expect("a native run stops its lane");
    (stopped, published)
}

fn entries(log: &Log) -> Vec<String> {
    log.borrow().clone()
}

const STARTUP: [&str; 4] = [
    "begin_capture_coverage",
    "extend[]",
    "note_extend_receipt(activating)",
    "note_native_lane",
];

fn pass(extend: &str) -> Vec<String> {
    [
        "collect",
        "scan",
        "take_target_delta",
        extend,
        "note_extend_receipt",
        "service",
        "stage:lifecycle",
        "read",
        "stage:witness",
        "commit",
        "publish:pass",
    ]
    .map(String::from)
    .to_vec()
}

const STOP: [&str; 15] = [
    // Two endpoints: the 200 ms base and 50 ms for each.
    "publish:retiring 2 300",
    // A complete lifecycle drain right before the terminal read.
    "service",
    "stage:lifecycle",
    "read",
    "stage:witness",
    "end_capture_coverage",
    "begin_stop",
    "poll",
    "service",
    "stage:lifecycle",
    "read",
    "stage:witness",
    "stage:finish",
    "commit",
    "publish:stop",
];

/// Invariants 1, 2 and 4 as one exact call sequence: activation before the
/// first scan with its receipt forwarded at once, then per pass scan →
/// delta → extend → receipt → lifecycle → witness → commit → publish, then
/// the terminal read before the coverage ends, retirement under service, one
/// more read, Finish, commit.
#[test]
fn the_lane_follows_the_contract_order_from_startup_through_stop() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let (stopped, _) = run(&mut scene, lane, 2);
    let mut expected: Vec<String> = STARTUP.map(String::from).to_vec();
    expected.extend(pass("extend[0,1]"));
    expected.extend(pass("extend[]"));
    expected.extend(STOP.map(String::from));
    assert_eq!(entries(&log), expected);
    assert_eq!(stopped.summary.passes, 2);
    assert_eq!(stopped.summary.attached, 2);
    assert!(matches!(stopped.summary.retirement, Retirement::Closed(_)));
}

#[test]
fn cgroup_lane_startup_and_terminal_reads_preserve_explicit_coverage() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.scope_coverage = CaptureScopeCoverage::Cgroup;
    let (stopped, _) = run(&mut scene, lane, 2);
    assert_eq!(
        scene.coverage(),
        UseCoverage::Unknown(UnknownReason::ScopeMembershipUnproven)
    );
    assert_eq!(
        stopped.capture.scope_coverage(),
        CaptureScopeCoverage::Cgroup
    );
    assert!(matches!(stopped.summary.retirement, Retirement::Closed(_)));
}

/// The stop summary carries the run's drain high-water (the terminal
/// sweep folds in with every pass drain); a lane that sampled nothing
/// reports none.
#[test]
fn the_stop_summary_carries_the_drain_high_water() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // The largest fill comes first and a smaller one after it, so only a
    // maximum (not the last report) reads 777.
    lane.drain_high_water_bytes = vec![Some(777), None, Some(50)];
    let (stopped, _) = run(&mut scene, lane, 1);
    let services = log
        .borrow()
        .iter()
        .filter(|entry| *entry == "service")
        .count();
    assert!(services >= 3, "the script must be consumed: {services}");
    assert_eq!(stopped.summary.lifecycle_high_water_bytes, Some(777));

    let log = Log::default();
    let mut scene = Scene::new(&log);
    let (stopped, _) = run(&mut scene, ScriptedLane::new(&log), 1);
    assert_eq!(stopped.summary.lifecycle_high_water_bytes, None);
}

/// Invariant 1 end to end: the roots activate before the first scan and
/// the activating receipt is forwarded, so the caller the first pass admits
/// is inside exec coverage and its first-pass row binds at stop. Activating
/// after the scan, or dropping the activating receipt, leaves the row an
/// `exec_coverage_gap` instead.
#[test]
fn a_row_of_the_first_pass_binds_because_activation_precedes_the_scan() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.reads.push_back(vec![RowSpec {
        endpoint: 0,
        tgid: PID,
        ticket: TICKET,
    }]);
    let (_, _) = run(&mut scene, lane, 1);
    let census = scene.coordinator.registry().witness_census().clone();
    assert_eq!(
        (census.rows, census.bound, census.pending),
        (1, 1, 0),
        "{census:?}"
    );
    assert_eq!(census.unbound.get(&UnboundReason::ExecCoverageGap), None);
    // C7 C4: the scripted row carries a first-sight count, so the
    // bound edge reads `counted`.
    assert!(
        matches!(scene.coverage(), UseCoverage::Counted { .. }),
        "{:?}",
        scene.coverage()
    );
}

/// P1-2: live publication is stamped after refresh+commit: a count that
/// rose during the pass reads RecentlyObserved at its own pass's
/// publication, never Quiet from a presentation clock older than the
/// read. Driven through the actual loop with the production publish
/// timestamp (no artificial presentation time); the read delay separates
/// scan-start from rows-read by milliseconds, deterministically.
#[test]
fn a_rising_count_reads_recently_observed_at_its_own_pass_publication() {
    use crate::inventory_present::{Activity, Presentation};
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // Pass 1 witnesses the row (first-sight count 1); pass 2's refresh
    // raises it to 6.
    lane.reads.push_back(vec![RowSpec {
        endpoint: 0,
        tgid: PID,
        ticket: TICKET,
    }]);
    lane.reads.push_back(Vec::new());
    lane.refreshes.push_back(Vec::new());
    lane.refreshes.push_back(vec![CountSpec {
        endpoint: 0,
        ticket: TICKET,
        exec: 1,
        count: 6,
    }]);
    lane.read_delay = Duration::from_millis(2);
    let started_ns = now_ns();
    let pass_log = Rc::clone(&scene.log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let scans = move || {
        pass_log
            .borrow()
            .iter()
            .filter(|entry| *entry == "scan")
            .count()
    };
    let stop = move || scans() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let mut observed: Vec<(u64, Option<u64>, Activity)> = Vec::new();
    run_classic(
        &mut scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, point| {
            if let Publish::Pass { now_ns, .. } = point {
                let presentation = Presentation::capture(
                    &scene.coordinator,
                    "s",
                    started_ns,
                    now_ns,
                    scene.coordinator.passes(),
                );
                let caller = scene.caller(PID);
                let edge = presentation
                    .edges
                    .iter()
                    .find(|edge| edge.caller == caller)
                    .expect("pid 7 has its edge");
                observed.push((now_ns, edge.entry_last_seen_ns, edge.activity));
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(observed.len(), 2, "{observed:?}");
    // Pass 1's row is still horizon-pending at its publication (both
    // horizons must strictly cover the read): no entry last-seen yet.
    assert_eq!(observed[0].1, None, "{:?}", observed[0]);
    // Pass 2 decides the row and stages the rise to 6: production
    // ordering (publication at or after the read) and a rise that reads
    // recently observed at its own publication.
    let (publish_ns, last_seen, activity) = &observed[1];
    let last_seen = last_seen.expect("the decided rise has an entry last-seen");
    assert!(
        *publish_ns >= last_seen,
        "publication {publish_ns} precedes its read {last_seen}"
    );
    assert_eq!(
        *activity,
        Activity::RecentlyObserved,
        "a rise during the pass reads recently observed at its publication"
    );
}

/// Invariant 4.2: the terminal read is staged before the coverage ends, so a
/// watch runs until that read's clean instant (capped at the terminal
/// drain's start), not the pass before.
#[test]
fn a_watch_ends_at_the_terminal_read_staged_before_coverage_ends() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let (stopped, _) = run(&mut scene, lane, 2);
    // Reads: pass 1, pass 2, terminal, last.
    let stamps = stopped.capture.read_stamps.clone();
    assert_eq!(stamps.len(), 4, "{stamps:?}");
    let UseCoverage::WatchedNoUse { since_ns, until_ns } = scene.coverage() else {
        panic!("{:?}", scene.coverage());
    };
    assert!(since_ns < stamps[1], "watched from the attaches on");
    // The terminal read's clean instant, capped at the start of the full
    // lifecycle drain right before it (`lifecycle_proven_ns`): past the
    // pass-2 read, never past the terminal read.
    let until = until_ns.expect("frozen");
    assert!(
        stamps[1] < until && until <= stamps[2],
        "{until} {stamps:?}"
    );
}

/// Invariant 4.6: Finish decides what the last read left waiting (no later
/// lifecycle drain covers it): nothing stays pending, and the row reads
/// `evidence_incomplete`, never bound.
#[test]
fn finish_decides_the_rows_the_last_read_reported() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // Pass 1 and the terminal read report nothing; the last read one row.
    lane.reads.extend([
        Vec::new(),
        Vec::new(),
        vec![RowSpec {
            endpoint: 1,
            tgid: PID,
            ticket: TICKET,
        }],
    ]);
    run(&mut scene, lane, 1);
    let census = scene.coordinator.registry().witness_census().clone();
    assert_eq!((census.rows, census.pending), (1, 0), "{census:?}");
    assert_eq!(
        census.unbound.get(&UnboundReason::EvidenceIncomplete),
        Some(&1),
        "{census:?}"
    );
}

/// Invariant 2.3: what an extend deferred is resubmitted ahead of the next
/// delta, so the module is attached on the next pass and then watched.
#[test]
fn deferred_endpoints_are_resubmitted_on_the_next_pass() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.defer_next = 1;
    let (stopped, _) = run(&mut scene, lane, 3);
    let extends: Vec<String> = entries(&log)
        .into_iter()
        .filter(|entry| entry.starts_with("extend["))
        .collect();
    assert_eq!(
        extends,
        ["extend[]", "extend[0,1]", "extend[1]", "extend[]"]
    );
    assert_eq!(stopped.summary.attached, 2);
    assert!(
        matches!(scene.coverage(), UseCoverage::WatchedNoUse { .. }),
        "{:?}",
        scene.coverage()
    );
}

/// Invariant 4.1: a stop requested before the first pass (a signal during
/// activation) still gets one full pass after activation.
#[test]
fn a_stop_requested_during_startup_still_runs_one_full_pass() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &|| true,
        interval: Duration::from_secs(600),
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let stopped = run_classic(&mut scene, Some(started), &clock, &mut |_, _| Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(stopped.summary.passes, 1);
    let log = entries(&log);
    let scan = log
        .iter()
        .position(|entry| entry == "scan")
        .expect("one scan");
    let end = log
        .iter()
        .position(|entry| entry == "end_capture_coverage")
        .unwrap();
    assert!(scan < end, "{log:?}");
    assert_eq!(log.iter().filter(|entry| *entry == "scan").count(), 1);
    assert_eq!(scene.coordinator.passes(), 1);
}

/// Invariant 5: retirement past its budget reads unsettled with a gap; the
/// read, Finish and commit still run, and the capture is handed back for a
/// drop after the output.
#[test]
fn a_missed_retirement_budget_reads_unsettled_with_a_gap() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.retire_after = None;
    let (stopped, _) = run(&mut scene, lane, 1);
    let Retirement::Unsettled(reason) = &stopped.summary.retirement else {
        panic!("{:?}", stopped.summary.retirement);
    };
    // Two endpoints attached: the 200 ms base and 50 ms for each.
    assert_eq!(stopped.summary.attached, 2);
    assert!(reason.contains("did not detach within 300 ms"), "{reason}");
    assert_eq!(stopped.summary.retirement.label(), "unsettled");
    assert!(
        scene
            .gap_subjects()
            .contains(&"native capture retirement unsettled".to_string()),
        "{:?}",
        scene.gap_subjects()
    );
    let log = entries(&log);
    let tail: Vec<&str> = log.iter().rev().take(5).rev().map(String::as_str).collect();
    assert_eq!(
        tail,
        [
            "stage:witness",
            "stage:finish",
            "gap:native capture retirement unsettled",
            "commit",
            "publish:stop"
        ]
    );
    assert!(!stopped.capture.retired);
}

/// The entries between the retiring notice and the end of coverage: the
/// terminal reads.
fn terminal_reads(log: &[String]) -> Vec<&str> {
    let from = log
        .iter()
        .position(|e| e.starts_with("publish:retiring"))
        .unwrap();
    let to = log
        .iter()
        .position(|e| e == "end_capture_coverage")
        .unwrap();
    log[from + 1..to]
        .iter()
        .map(String::as_str)
        .filter(|e| *e != "service" && *e != "stage:lifecycle")
        .collect()
}

/// C5.2 closure I-1: stop drains the lifecycle ring completely right
/// before the terminal read and forwards each quantum before the coverage
/// ends, so a loss still in the ring is seen before the watch freezes.
#[test]
fn a_stop_drains_the_lifecycle_ring_before_the_terminal_read() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // The pass reads once; then two quanta stop at their record bound.
    lane.undrained_after_reads = Some((1, 2));
    run(&mut scene, lane, 1);
    let log = entries(&log);
    let from = log
        .iter()
        .position(|e| e.starts_with("publish:retiring"))
        .unwrap();
    let to = log
        .iter()
        .position(|e| e == "end_capture_coverage")
        .unwrap();
    assert_eq!(
        log[from + 1..to]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "service",
            "stage:lifecycle",
            "service",
            "stage:lifecycle",
            "service",
            "stage:lifecycle",
            "read",
            "stage:witness"
        ]
    );
}

/// C5.1 carry (C5.2 review): a bounded terminal read that stops mid-sweep
/// proves no clean instant, so stop keeps reading (each read staged before
/// the coverage ends) until a CALLER_USE sweep completes.
#[test]
fn a_stop_keeps_reading_until_the_terminal_sweep_completes() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // Read 1 is the pass's; reads 2 and 3 stop mid-sweep, read 4 completes.
    lane.partial_reads.extend([2, 3]);
    let (stopped, _) = run(&mut scene, lane, 1);
    assert_eq!(
        terminal_reads(&entries(&log)),
        [
            "read",
            "stage:witness",
            "read",
            "stage:witness",
            "read",
            "stage:witness"
        ]
    );
    assert_eq!(stopped.capture.read_stamps.len(), 5);
}

/// 2-C3: the terminal count refresh happens after `begin_stop`: stop keeps
/// reading (each read staged) until a refresh sweep completes without gaps,
/// so every witnessed row's count gets its last word.
#[test]
fn a_stop_refreshes_counts_after_begin_stop_until_exact() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // Read 1 is the pass's; read 2 is the pre-stop terminal sweep; reads 3
    // and 4 (after begin_stop) leave the refresh incomplete and gappy, and
    // read 5 exacts it.
    lane.partial_refresh_reads.extend([3]);
    lane.gappy_refresh_reads.extend([4]);
    let count = |count| CountSpec {
        endpoint: 0,
        ticket: TICKET,
        exec: 1,
        count,
    };
    lane.refreshes
        .extend([vec![], vec![], vec![count(9)], vec![count(12)], vec![]]);
    let (stopped, _) = run(&mut scene, lane, 1);
    assert_eq!(stopped.capture.read_stamps.len(), 5);
    let log = entries(&log);
    let stopped_at = log.iter().position(|entry| entry == "begin_stop").unwrap();
    let after: Vec<&str> = log[stopped_at..]
        .iter()
        .map(String::as_str)
        .filter(|entry| *entry == "read" || *entry == "stage:witness")
        .collect();
    assert_eq!(
        after,
        [
            "read",
            "stage:witness",
            "read",
            "stage:witness",
            "read",
            "stage:witness"
        ]
    );
    assert_eq!(scene.staged_counts, [0, 0, 1, 1, 0]);
}

/// 2-C3: the terminal refresh is bounded: a refresh that never completes
/// stops reading at the budget and the stop goes on.
#[test]
fn a_terminal_refresh_that_never_completes_is_bounded() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // 10 ms reads, partial up to read 300: the 500 ms budget allows ~50.
    lane.partial_refresh_reads.extend(3..=300);
    lane.read_delay = Duration::from_millis(10);
    let (stopped, _) = run(&mut scene, lane, 1);
    let log = entries(&log);
    let stopped_at = log.iter().position(|entry| entry == "begin_stop").unwrap();
    let reads = log[stopped_at..]
        .iter()
        .filter(|entry| *entry == "read")
        .count();
    assert!((1..150).contains(&reads), "{reads}");
    assert!(matches!(stopped.summary.retirement, Retirement::Closed(_)));
}

/// P1-4: when the terminal refresh budget expires without a gap-free
/// sweep, the stop reports the incomplete refresh: witnessed counts
/// keep their last read as a lower bound, never a fresh terminal word.
/// P1-5 terminal-first: the retained count demotes to lossy, so the
/// terminal observation withholds quiet (a scope gap alone would leave
/// the edge loss-free).
#[test]
fn a_terminal_refresh_that_never_completes_is_reported() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.reads.push_back(vec![RowSpec {
        endpoint: 0,
        tgid: PID,
        ticket: TICKET,
    }]);
    lane.partial_refresh_reads.extend(3..=300);
    lane.read_delay = Duration::from_millis(10);
    let _ = run(&mut scene, lane, 1);
    let log = entries(&log);
    assert!(
        log.iter()
            .any(|entry| entry.contains("terminal count refresh incomplete")),
        "the stop reports its incomplete terminal refresh: {log:?}"
    );
    assert!(
        matches!(scene.coverage(), UseCoverage::Counted { lossy: true, .. }),
        "the incomplete terminal refresh demotes the retained count: {:?}",
        scene.coverage()
    );
}

/// The terminal sweep is bounded: a sweep that never completes stops
/// reading at the budget and the stop goes on (its reads are not clean).
#[test]
fn a_terminal_sweep_that_never_completes_is_bounded() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // 10 ms reads, partial up to read 300: the 500 ms budget allows ~50.
    lane.partial_reads.extend(2..=300);
    lane.read_delay = Duration::from_millis(10);
    let (stopped, _) = run(&mut scene, lane, 1);
    let reads = terminal_reads(&entries(&log)).len() / 2;
    assert!((1..150).contains(&reads), "{reads}");
    assert!(matches!(stopped.summary.retirement, Retirement::Closed(_)));
}

/// Each Singles link pays its own kernel detach (about 73 ms on host 7.0,
/// 68 links in 4.9 s), so the budget grows with the attached endpoints —
/// but the report never waits more than `PRE_OUTPUT_RETIREMENT_WAIT`
/// (R-C51-4); the rest of the detach runs after the report.
#[test]
fn the_retirement_budget_grows_with_the_attached_endpoints_up_to_its_cap() {
    let windows = LaneWindows::PROVISIONAL;
    let singles = |links| RetirementLoad {
        backend: AttachBackend::Singles,
        links,
        endpoints: links,
    };
    assert_eq!(PRE_OUTPUT_RETIREMENT_WAIT, Duration::from_secs(10));
    assert_eq!(
        windows.retirement_budget(singles(0)),
        Duration::from_secs(5)
    );
    assert_eq!(
        windows.retirement_budget(singles(8)),
        Duration::from_millis(6_200)
    );
    assert_eq!(
        windows.retirement_budget(singles(68)),
        PRE_OUTPUT_RETIREMENT_WAIT
    );
    assert_eq!(
        windows.retirement_budget(singles(usize::MAX)),
        PRE_OUTPUT_RETIREMENT_WAIT
    );
}

/// C5.11: Multi's share is per group link plus each member's walk, so a
/// system scope of hundreds of endpoints in a few groups budgets seconds,
/// not the cap; the same endpoints as Singles links reach the cap.
#[test]
fn the_multi_retirement_budget_counts_group_links_and_member_walks() {
    let windows = LaneWindows::PROVISIONAL;
    let multi = RetirementLoad {
        backend: AttachBackend::Multi,
        links: 12,
        endpoints: 400,
    };
    // 5 s + 12 x 100 ms + 400 x 10 ms = 10.2 s, capped.
    assert_eq!(windows.retirement_budget(multi), PRE_OUTPUT_RETIREMENT_WAIT);
    let small = RetirementLoad {
        backend: AttachBackend::Multi,
        links: 3,
        endpoints: 68,
    };
    assert_eq!(
        windows.retirement_budget(small),
        Duration::from_millis(5_000 + 300 + 680)
    );
    let as_singles = RetirementLoad {
        backend: AttachBackend::Singles,
        links: 70,
        endpoints: 68,
    };
    assert_eq!(
        windows.retirement_budget(as_singles),
        PRE_OUTPUT_RETIREMENT_WAIT
    );
}

/// R-C51-4: the report is written first, the immediate exit on a second
/// signal is armed next, and only then does an unsettled retirement's
/// blocking detach run, between two progress lines.
#[test]
fn the_report_is_written_before_the_blocking_detach() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.retire_after = None;
    let (stopped, _) = run(&mut scene, lane, 1);
    assert_eq!(stopped.summary.retirement.label(), "unsettled");
    log.borrow_mut().clear();
    let note = |entry: &str| log.borrow_mut().push(entry.to_string());
    let code = finish_native(
        Some(stopped),
        |summary| {
            assert_eq!(summary.unwrap().retirement.label(), "unsettled");
            note("report");
            7
        },
        &|| note("armed"),
        &mut |line| {
            note(if line.contains("detached") {
                "progress:done"
            } else {
                "progress:start"
            })
        },
    );
    assert_eq!(code, 7);
    assert_eq!(
        entries(&log),
        ["report", "armed", "progress:start", "drop", "progress:done"]
    );
}

/// A pass callback failure still gets one bounded native stop and terminal
/// read. Later stop-publication failures cannot replace the first error or
/// drop the unsettled capture before the caller's final sinks.
#[test]
fn failed_pass_publication_retains_native_stop_for_final_sinks() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.retire_after = None;
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let clock = LoopClock {
        deadline: None,
        stop: &|| false,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let mut publications = Vec::new();
    let outcome =
        run_classic_finalizing(&mut scene, Some(started), &clock, None, &mut |_, point| {
            let stage = match point {
                Publish::Pass { .. } => "pass",
                Publish::Retiring { .. } => "retiring",
                Publish::Stop { .. } => "stop",
            };
            publications.push(stage);
            Err(anyhow!("{stage} publication failed"))
        });
    assert_eq!(
        outcome.error.unwrap().to_string(),
        "pass publication failed"
    );
    assert_eq!(publications, ["pass", "retiring", "stop"]);
    let captured = entries(&log);
    assert_eq!(captured.iter().filter(|entry| *entry == "scan").count(), 1);
    assert_eq!(
        captured
            .iter()
            .filter(|entry| *entry == "begin_stop")
            .count(),
        1
    );
    assert!(captured.iter().any(|entry| entry == "stage:finish"));
    assert!(!captured.iter().any(|entry| entry == "drop"));
    let stopped = outcome
        .stopped
        .expect("native ownership survives the error");
    log.borrow_mut().clear();
    finish_native(
        Some(stopped),
        |_| {
            log.borrow_mut().push("report".into());
            log.borrow_mut().push("diagnostics".into());
        },
        &|| log.borrow_mut().push("armed".into()),
        &mut |_| {},
    );
    assert_eq!(entries(&log), ["report", "diagnostics", "armed", "drop"]);
}

#[test]
fn failed_pass_application_still_reads_terminal_state_and_keeps_first_error() {
    struct FailedDriver<'a>(&'a mut Scene);
    impl PassDriver<Pin> for FailedDriver<'_> {
        type Host = Scene;
        fn host(&mut self) -> &mut Scene {
            self.0
        }
        fn collector(&mut self) -> CollectJob {
            self.0.collector()
        }
        fn apply(
            &mut self,
            _: CollectedPass,
            _: &mut dyn NativeIdentity<Pin>,
            _: u64,
        ) -> Result<PassReport> {
            self.0.note("apply:failed");
            Err(anyhow!("first application error"))
        }
        fn commit(&mut self, _: bool) -> Result<()> {
            self.0.note("commit:failed");
            Err(anyhow!("later terminal commit error"))
        }
        fn on_tick(&mut self) {}
    }
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let clock = LoopClock {
        deadline: None,
        stop: &|| false,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let outcome = run_classic_finalizing(
        &mut FailedDriver(&mut scene),
        Some(started),
        &clock,
        None,
        &mut |_, _| Ok(()),
    );
    assert_eq!(
        outcome.error.unwrap().to_string(),
        "first application error"
    );
    assert!(outcome.stopped.is_some());
    let captured = entries(&log);
    assert_eq!(
        captured
            .iter()
            .filter(|entry| *entry == "apply:failed")
            .count(),
        1
    );
    assert_eq!(
        captured
            .iter()
            .filter(|entry| *entry == "commit:failed")
            .count(),
        1
    );
    assert!(captured.iter().any(|entry| entry == "stage:finish"));
    assert!(!captured.iter().any(|entry| entry == "drop"));
}

#[test]
#[should_panic(expected = "stop before any pass after activation")]
fn zero_pass_successful_stop_keeps_the_full_pass_guard() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let started = NativeLane::start(ScriptedLane::new(&log), &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    started.stop(&mut scene);
}

#[test]
fn zero_pass_prologue_failure_still_finishes_terminal_reads() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let started = NativeLane::start(ScriptedLane::new(&log), &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let clock = LoopClock {
        deadline: None,
        stop: &|| false,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let mut publications = Vec::new();
    let outcome = run_classic_finalizing(
        &mut scene,
        Some(started),
        &clock,
        Some(anyhow!("started append failure")),
        &mut |_, point| {
            publications.push(match point {
                Publish::Retiring { .. } => "retiring",
                Publish::Stop { .. } => "stop",
                Publish::Pass { .. } => "pass",
            });
            Ok(())
        },
    );
    assert_eq!(outcome.error.unwrap().to_string(), "started append failure");
    assert_eq!(publications, ["retiring", "stop"]);
    let stopped = outcome.stopped.unwrap();
    assert_eq!(stopped.summary.passes, 0);
    let captured = entries(&log);
    assert!(
        !captured
            .iter()
            .any(|entry| entry == "collect" || entry == "scan")
    );
    assert!(captured.iter().any(|entry| entry == "stage:finish"));
    assert!(!captured.iter().any(|entry| entry == "drop"));
    log.borrow_mut().clear();
    finish_native(
        Some(stopped),
        |_| log.borrow_mut().push("outputs".into()),
        &|| log.borrow_mut().push("armed".into()),
        &mut |_| {},
    );
    assert_eq!(entries(&log), ["outputs", "armed", "drop"]);
}

#[test]
fn failed_output_attempt_arms_escape_before_detach() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.retire_after = None;
    let (stopped, _) = run(&mut scene, lane, 1);
    log.borrow_mut().clear();
    let result = finish_native(
        Some(stopped),
        |_| {
            log.borrow_mut().push("output:failed".into());
            Err::<(), _>("sink failed")
        },
        &|| log.borrow_mut().push("armed".into()),
        &mut |line| log.borrow_mut().push(line),
    );
    assert_eq!(result, Err("sink failed"));
    let entries = entries(&log);
    assert_eq!(&entries[..2], ["output:failed", "armed"]);
    assert!(
        !entries
            .iter()
            .any(|line| line.contains("report written") || line.contains("report saved")),
        "{entries:?}"
    );
    assert!(entries[2].contains("detaching"));
    assert_eq!(entries[3], "drop");
    assert!(entries[4].contains("detached"));
}

/// Exercise the real native stop publication, then the shared output
/// finalizer: a final-pass append failure retires only its event writer.
#[test]
fn stop_event_failure_keeps_native_cleanup_report_and_stdout() {
    use crate::inventory::{EventLogState, StreamState, emit_stop_events, finish_output};
    use crate::inventory_events::{EventFault, EventWriter, started_payload};
    use crate::inventory_present::Presentation;
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let events = dir.path().join("events.jsonl");
    let report = dir.path().join("report.json");
    let mut writer = EventWriter::create(&events, 1 << 20, 2).unwrap();
    let attempts = Rc::new(RefCell::new(Vec::new()));
    writer.fault = Some(EventFault {
        kind: "pass_committed",
        final_pass_only: true,
        after_ended: false,
        attempts: attempts.clone(),
    });
    let now = now_ns();
    let initial = Presentation::capture(&scene.coordinator, "system", now, now, 0);
    writer
        .append("started", started_payload("system", now, &initial), now)
        .unwrap();
    let mut stream = EventLogState::new(Some(writer));
    let mut state = StreamState::new();
    let scans = log.clone();
    let stop = || scans.borrow().iter().any(|entry| entry == "scan");
    let clock = LoopClock {
        deadline: None,
        stop: &stop,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let stopped = run_classic(
        &mut scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, point| {
            if let Publish::Stop { events, now_ns } = point {
                scene.note("publish:stop");
                let view = Presentation::capture(
                    &scene.coordinator,
                    "system",
                    now,
                    now_ns,
                    scene.coordinator.passes(),
                );
                let error = stream.attempt("stop publication", |writer| {
                    emit_stop_events(
                        writer,
                        &mut state,
                        events,
                        scene.coordinator.passes(),
                        &view,
                        now_ns,
                    )
                });
                assert!(error.unwrap().contains("event log stop publication"));
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(stream.first_error().is_some());
    assert!(
        stream
            .attempt("must stay retired", |_| panic!(
                "retired event writer reused"
            ))
            .is_none()
    );
    let view = Presentation::capture(
        &scene.coordinator,
        "system",
        now,
        now_ns(),
        scene.coordinator.passes(),
    );
    let mut stdout = Vec::new();
    let outcome = finish_native(
        stopped,
        |summary| {
            finish_output(
                Some(crate::output::AtomicFile::create(&report).unwrap()),
                &mut stream,
                &mut state,
                &view,
                true,
                false,
                &mut crate::inventory_output::WriterStdout(&mut stdout),
                summary,
            )
        },
        &|| log.borrow_mut().push("armed".into()),
        &mut |_| {},
    );
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(std::fs::read(report).unwrap(), stdout);
    assert!(log.borrow().iter().any(|entry| entry == "publish:stop"));
    let entries = entries(&log);
    assert!(
        entries.iter().position(|entry| entry == "armed").unwrap()
            < entries.iter().position(|entry| entry == "drop").unwrap()
    );
    assert_eq!(
        attempts
            .borrow()
            .iter()
            .filter(|kind| *kind == "pass_committed")
            .count(),
        1
    );
    assert!(!attempts.borrow().iter().any(|kind| kind == "ended"));
}

/// A closed retirement has nothing left to detach: no progress lines.
#[test]
fn a_closed_retirement_reports_without_a_detach_phase() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let (stopped, _) = run(&mut scene, lane, 1);
    log.borrow_mut().clear();
    let note = |entry: &str| log.borrow_mut().push(entry.to_string());
    finish_native(
        Some(stopped),
        |_| note("report"),
        &|| note("armed"),
        &mut |_| note("progress"),
    );
    assert_eq!(entries(&log), ["report", "armed", "drop"]);
}

/// The child half of the second-signal test: inert unless its parent sets
/// the environment.
#[test]
fn stop_flag_child_exits_on_the_armed_signal() {
    if std::env::var_os("P11SCOPE_STOPFLAG_CHILD").is_none() {
        return;
    }
    let flag = crate::inventory_dashboard::StopFlag::install();
    // SAFETY: raising a signal whose handler is installed.
    unsafe { libc::raise(libc::SIGINT) };
    // Positive control: before arming, a signal only requests the stop.
    assert!(flag.stopped());
    println!("FIRST_SIGNAL_STOPPED");
    flag.exit_on_next_signal();
    // SAFETY: as above.
    unsafe { libc::raise(libc::SIGTERM) };
    println!("SURVIVED_SECOND_SIGNAL");
    std::process::exit(0);
}

/// R-C51-4: once the report is written, a second SIGINT/SIGTERM ends the
/// process at once (128 + signal), whatever the drop is still doing.
#[test]
fn after_the_report_a_second_signal_exits_at_once() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "inventory_capture::tests::stop_flag_child_exits_on_the_armed_signal",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("P11SCOPE_STOPFLAG_CHILD", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FIRST_SIGNAL_STOPPED"), "{stdout}");
    assert!(!stdout.contains("SURVIVED_SECOND_SIGNAL"), "{stdout}");
    assert_eq!(
        output.status.code(),
        Some(128 + libc::SIGTERM),
        "{output:?}"
    );
}

/// The actual generic loop and finalizer consume the same Retiring action as
/// the production classic/dashboard callbacks. A delivery inside that action
/// must not be absorbed by a boundary captured after native stop returns.
fn native_output_boundary_control(
    dashboard: bool,
    key_stop: bool,
    before: usize,
    during: bool,
    with_sinks: bool,
) {
    use crate::inventory::{
        EventLogState, StreamState, begin_scan_stdout, finish_output, retiring_stdout,
    };
    use crate::inventory_output::{FdStdout, FinalStdout, StdoutResult};
    use std::cell::Cell;
    use std::os::fd::AsRawFd;
    struct Recorded<'a> {
        inner: FdStdout<'a>,
        log: Log,
        sinks: Option<(std::path::PathBuf, std::path::PathBuf)>,
    }
    impl FinalStdout for Recorded<'_> {
        fn begin_finalization(&mut self) {
            self.log.borrow_mut().push("stdout:begin".into());
            self.inner.begin_finalization();
        }
        fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
            self.log.borrow_mut().push("stdout:attempt".into());
            if let Some((report, events)) = &self.sinks {
                assert_eq!(
                    std::fs::read(report).unwrap(),
                    bytes,
                    "requested report was not committed before stdout cancellation/acquisition"
                );
                assert!(
                    std::fs::read_to_string(events)
                        .unwrap()
                        .lines()
                        .any(
                            |line| serde_json::from_str::<serde_json::Value>(line).unwrap()["kind"]
                                == "ended"
                        ),
                    "requested event completion was not attempted before stdout"
                );
            }
            self.inner.write_document(bytes)
        }
    }
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.retire_after = None;
    let lane = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let delivered = Cell::new(0);
    let key = Cell::new(false);
    let stop = || delivered.get() > 0 || key.get();
    let clock = LoopClock {
        deadline: (!key_stop && before == 0).then(Instant::now),
        stop: &stop,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let file = tempfile::NamedTempFile::new().unwrap();
    let count = || delivered.get();
    let sinks = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        sinks.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let report = sinks.path().join("report.json");
    let events = sinks.path().join("events.jsonl");
    let mut stdout = Recorded {
        inner: FdStdout::new(file.as_raw_fd(), &count),
        log: log.clone(),
        sinks: with_sinks.then(|| (report.clone(), events.clone())),
    };
    let stopped = run_classic(
        &mut scene,
        Some(lane),
        &clock,
        &mut |scene: &mut Scene, point| {
            match point {
                Publish::Pass { .. } => {
                    delivered.set(before);
                    key.set(key_stop);
                    scene.note("publish:pass");
                }
                Publish::Retiring { .. } => {
                    scene.note("publish:retiring");
                    retiring_stdout(&mut stdout, || {
                        scene.note(if dashboard {
                            "restore"
                        } else {
                            "classic-notice"
                        });
                        if during {
                            delivered.set(1);
                            scene.note("delivery:acknowledged-1");
                        }
                    });
                }
                Publish::Stop { .. } => {
                    scene.note("publish:stop");
                    assert_eq!(delivered.get(), if during { 1 } else { before });
                }
            }
            Ok(())
        },
    )
    .unwrap();
    begin_scan_stdout(&mut stdout, stopped.is_some());
    let now = now_ns();
    let view =
        crate::inventory_present::Presentation::capture(&scene.coordinator, "system", now, now, 1);
    let sink = with_sinks.then(|| crate::output::AtomicFile::create(&report).unwrap());
    let writer = with_sinks
        .then(|| crate::inventory_events::EventWriter::create(&events, 1 << 20, 2).unwrap());
    let outcome = finish_native(
        stopped,
        |summary| {
            let outcome = finish_output(
                sink,
                &mut EventLogState::new(writer),
                &mut StreamState::new(),
                &view,
                true,
                false,
                &mut stdout,
                summary,
            );
            log.borrow_mut().push("output:result".into());
            outcome
        },
        &|| log.borrow_mut().push("armed".into()),
        &mut |_| {},
    );
    let cancelled = during || before == 2;
    assert_eq!(
        outcome.exit_code(),
        i32::from(cancelled),
        "{outcome:?}; {:?}",
        entries(&log)
    );
    assert_eq!(outcome.stdout_cancelled(), cancelled, "{outcome:?}");
    let bytes = std::fs::read(file.path()).unwrap();
    if cancelled {
        assert!(
            bytes.is_empty(),
            "cancelled output accepted a late document"
        );
    } else {
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["observation"]["lane"], "native");
    }
    let entries = entries(&log);
    let at = |name| entries.iter().position(|entry| entry == name).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.as_str() == "stdout:begin")
            .count(),
        1
    );
    assert!(
        at("stdout:begin")
            < at(if dashboard {
                "restore"
            } else {
                "classic-notice"
            })
    );
    assert!(at("stdout:begin") < at("begin_stop"));
    assert!(at("begin_stop") < at("publish:stop"));
    assert!(at("publish:stop") < at("stdout:attempt"));
    assert!(at("output:result") < at("armed") && at("armed") < at("drop"));
}

#[test]
fn native_signal_during_retiring_cancels_stdout() {
    for dashboard in [false, true] {
        for key in [false, true] {
            native_output_boundary_control(dashboard, key, 0, true, false);
        }
    }
}

#[test]
fn native_first_capture_stop_signal_preserves_stdout() {
    for dashboard in [false, true] {
        native_output_boundary_control(dashboard, false, 1, false, false);
    }
}

#[test]
fn native_second_delivery_before_retiring_cancels_stdout() {
    for dashboard in [false, true] {
        native_output_boundary_control(dashboard, false, 2, false, false);
    }
}

#[test]
fn native_retiring_signal_preserves_requested_event_and_report() {
    for dashboard in [false, true] {
        for key in [false, true] {
            native_output_boundary_control(dashboard, key, 0, true, true);
        }
        native_output_boundary_control(dashboard, false, 1, false, true);
    }
}

#[test]
fn stop_flag_counts_distinct_deliveries_child() {
    if std::env::var_os("P11SCOPE_COUNT_CHILD").is_none() {
        return;
    }
    let flag = crate::inventory_dashboard::StopFlag::install();
    assert_eq!(flag.signal_count(), 0);
    for (signal, expected) in [(libc::SIGINT, 1), (libc::SIGTERM, 2), (libc::SIGHUP, 2)] {
        unsafe {
            libc::raise(signal);
        }
        assert_eq!(
            flag.signal_count(),
            expected,
            "delivered-handler count lost a distinct signal"
        );
        assert!(flag.stopped());
    }
}

#[test]
fn distinct_stop_deliveries_saturate_without_arming_force_exit() {
    struct Owned(std::process::Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut child = Owned(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inventory_capture::tests::stop_flag_counts_distinct_deliveries_child",
                "--nocapture",
            ])
            .env("P11SCOPE_COUNT_CHILD", "1")
            .spawn()
            .unwrap(),
    );
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            panic!("owned signal-count child watchdog");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(status.success(), "delivered-count child failed: {status}");
}

/// The auto fallback seam: a refused activation hands the capture back and
/// the coordinator forgets the coverage, so the run is the scan lane again.
#[test]
fn a_refused_activation_hands_back_the_capture_and_forgets_coverage() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.refuse_activation = true;
    let Err((mut lane, reason)) = NativeLane::start(lane, &mut scene, windows(), None) else {
        panic!("a refused activation must not start the lane");
    };
    assert!(reason.contains("scripted activation refusal"), "{reason}");
    assert_eq!(
        entries(&log),
        [
            "begin_capture_coverage",
            "extend[]",
            "abandon_capture_coverage"
        ]
    );
    retire_refused(&mut lane, Duration::from_millis(50));
    assert!(lane.retired);
    let clock = LoopClock {
        deadline: None,
        stop: &|| false,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let none: Option<NativeLane<ScriptedLane>> = None;
    run_classic(&mut scene, none, &clock, &mut |_, _| Ok(())).unwrap();
    assert_eq!(
        scene.coverage(),
        UseCoverage::Unknown(UnknownReason::ScanOnly)
    );
}

/// The scan lane runs the same loop with no native call at all.
#[test]
fn the_scan_lane_makes_no_native_call() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let clock = LoopClock {
        deadline: None,
        stop: &|| false,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let none: Option<NativeLane<ScriptedLane>> = None;
    let stopped = run_classic(&mut scene, none, &clock, &mut |scene: &mut Scene, _| {
        scene.note("publish");
        Ok(())
    })
    .unwrap();
    assert!(stopped.is_none());
    assert_eq!(entries(&log), ["collect", "scan", "commit", "publish"]);
}

/// Invariant 3: between passes each tick drains one discovery quantum and
/// stages it at once.
#[test]
fn ticks_between_passes_stage_each_discovery_quantum() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let scans = {
        let log = Rc::clone(&log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        interval: Duration::from_millis(40),
        tick: Duration::from_millis(5),
        collection_tick: NO_COLLECTION_TICK,
    };
    run_classic(
        &mut scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, _| {
            scene.note("publish:pass");
            Ok(())
        },
    )
    .unwrap();
    let log = entries(&log);
    let first = log
        .iter()
        .position(|entry| entry == "publish:pass")
        .unwrap();
    let second = log.iter().rposition(|entry| entry == "collect").unwrap();
    let between = &log[first + 1..second];
    assert!(between.len() >= 4, "{between:?}");
    for pair in between.chunks(2) {
        assert_eq!(pair, ["service", "stage:lifecycle"], "{between:?}");
    }
}

/// C5.3: the dashboard draws on the loop's own service ticks, each after
/// the lane's quantum is staged, so the native lane runs under the
/// dashboard exactly as on the classic path: the passes and the stop keep
/// the contract order, and every tick still services the ring first.
#[test]
fn the_display_ticks_after_each_lane_service_without_reordering_it() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.display_ticks = true;
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let scans = {
        let log = Rc::clone(&log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        interval: Duration::from_millis(40),
        tick: Duration::from_millis(5),
        collection_tick: NO_COLLECTION_TICK,
    };
    run_classic(
        &mut scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, point| {
            match point {
                Publish::Pass { .. } => scene.note("publish:pass"),
                Publish::Retiring {
                    attached, budget, ..
                } => scene.note(format!(
                    "publish:retiring {attached} {}",
                    budget.as_millis()
                )),
                Publish::Stop { .. } => scene.note("publish:stop"),
            }
            Ok(())
        },
    )
    .unwrap();
    let log = entries(&log);
    let first = log
        .iter()
        .position(|entry| entry == "publish:pass")
        .unwrap();
    let second = log.iter().rposition(|entry| entry == "scan").unwrap();
    // A pass's collection entry (C5.7) belongs to the pass, not the ticks.
    let between: Vec<&str> = log[first + 1..second]
        .iter()
        .map(String::as_str)
        .filter(|entry| *entry != "collect")
        .collect();
    assert!(between.len() >= 6, "{between:?}");
    for tick in between.chunks(3) {
        assert_eq!(
            tick,
            ["service", "stage:lifecycle", "display"],
            "{between:?}"
        );
    }
    // Without the display's entries the run is the classic contract order.
    let classic: Vec<String> = log
        .iter()
        .filter(|entry| !matches!(entry.as_str(), "display" | "service" | "stage:lifecycle"))
        .cloned()
        .collect();
    let mut expected: Vec<String> = STARTUP.map(String::from).to_vec();
    for extend in ["extend[0,1]", "extend[]"] {
        expected.extend(pass(extend));
    }
    expected.extend(STOP.map(String::from));
    expected.push("drop".into());
    expected.retain(|entry| !matches!(entry.as_str(), "service" | "stage:lifecycle"));
    assert_eq!(classic, expected);
    // The stop never draws: the display is given back before it.
    let retiring = log
        .iter()
        .position(|entry| entry.starts_with("publish:retiring"))
        .unwrap();
    assert!(!log[retiring..].iter().any(|entry| entry == "display"));
}

/// The scan lane's dashboard still draws on every tick.
#[test]
fn the_display_ticks_in_the_scan_lane_too() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.display_ticks = true;
    let scans = {
        let log = Rc::clone(&log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        interval: Duration::from_millis(30),
        tick: Duration::from_millis(5),
        collection_tick: NO_COLLECTION_TICK,
    };
    let none: Option<NativeLane<ScriptedLane>> = None;
    run_classic(&mut scene, none, &clock, &mut |scene: &mut Scene, _| {
        scene.note("publish");
        Ok(())
    })
    .unwrap();
    let log = entries(&log);
    let first = log.iter().position(|entry| entry == "publish").unwrap();
    let second = log.iter().rposition(|entry| entry == "scan").unwrap();
    // A pass's collection entry (C5.7) belongs to the pass, not the ticks.
    let between: Vec<&str> = log[first + 1..second]
        .iter()
        .map(String::as_str)
        .filter(|entry| *entry != "collect")
        .collect();
    assert!(between.len() >= 2, "{log:?}");
    assert!(between.iter().all(|entry| *entry == "display"), "{log:?}");
}

/// C5.3 with C5.7: while a pass collects, each collection tick services the
/// lifecycle ring first and only then lets the dashboard draw.
#[test]
fn the_ring_is_serviced_before_the_display_while_a_pass_collects() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.display_ticks = true;
    let mut lane = ScriptedLane::new(&log);
    let (serviced, gate) = mpsc::channel();
    lane.serviced = Some(serviced);
    scene.collect_gate = Some((gate, 3));
    run_ticking(&mut scene, lane, 1, Duration::from_millis(1));
    let log = entries(&log);
    let collect = log.iter().position(|entry| entry == "collect").unwrap();
    let scan = log.iter().position(|entry| entry == "scan").unwrap();
    let during = &log[collect + 1..scan];
    assert!(during.len() >= 6, "{log:?}");
    for tick in during.chunks(2) {
        assert_eq!(tick, ["service", "display"], "{log:?}");
    }
}

/// C5.3: the tick schedule is fixed-rate: a tick's own work (the draw after
/// the ring's service) does not move the next tick later, and a tick that
/// overran a whole period makes the next one due at once.
#[test]
fn a_tick_schedule_keeps_its_rate_through_the_work_of_a_tick() {
    let start = Instant::now();
    let period = Duration::from_millis(10);
    let mut schedule = TickSchedule::starting(start, period);
    assert_eq!(schedule.wait(start), period);
    // The tick due at 10 ms ran until 13 ms: the next is due at 20 ms.
    schedule.advance(start + Duration::from_millis(13));
    assert_eq!(
        schedule.wait(start + Duration::from_millis(13)),
        Duration::from_millis(7)
    );
    // The tick due at 20 ms ran until 45 ms: the next is due at once.
    schedule.advance(start + Duration::from_millis(45));
    assert_eq!(
        schedule.wait(start + Duration::from_millis(45)),
        Duration::ZERO
    );
    // And the one after keeps the period from there.
    schedule.advance(start + Duration::from_millis(46));
    assert_eq!(
        schedule.wait(start + Duration::from_millis(46)),
        Duration::from_millis(9)
    );
}

/// C5.3: a slow draw inside each collection tick (15 ms of a 20 ms tick)
/// does not slow the ring's service cadence: over a 400 ms collection the
/// ring is serviced about every 20 ms (about 19 times), not every 35 ms
/// (about 11 times) as a schedule restarted after each tick's work would.
#[test]
fn a_slow_draw_never_delays_the_ring_service_while_a_pass_collects() {
    let mut starts = Vec::new();
    collect_off_thread(
        || std::thread::sleep(Duration::from_millis(400)),
        Duration::from_millis(20),
        &mut || {
            starts.push(Instant::now());
            // The draw that follows the ring's service.
            std::thread::sleep(Duration::from_millis(15));
        },
    );
    // Judge the typical spacing between services, not the count: a loaded
    // host can oversleep any single tick, but only a schedule restarted
    // after each tick's work spaces services by the period plus the draw
    // (about 35 ms) as a rule. The fixed-rate schedule keeps about 20 ms.
    assert!(
        starts.len() >= 5,
        "the ring was serviced {} times",
        starts.len()
    );
    let mut gaps: Vec<Duration> = starts.windows(2).map(|w| w[1] - w[0]).collect();
    gaps.sort();
    let median = gaps[gaps.len() / 2];
    assert!(
        median < Duration::from_millis(30),
        "median service spacing {median:?} over {} services",
        starts.len()
    );
}

/// Ruling D1: a run whose watches cannot be proven (a foreign PID
/// namespace) marks coverage unproven from activation on: witnesses still
/// bind, but no edge ever reads watched.
#[test]
fn a_lossy_start_never_claims_a_watch() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(
        lane,
        &mut scene,
        windows(),
        Some("scripted foreign pid namespace".into()),
    )
    .map_err(|(_, reason)| reason)
    .unwrap();
    let scans = {
        let log = Rc::clone(&log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    run_classic(&mut scene, Some(started), &clock, &mut |_, _| Ok(())).unwrap();
    assert!(
        matches!(
            scene.coverage(),
            UseCoverage::Unknown(UnknownReason::Loss(ref reason))
                if reason.contains("scripted foreign pid namespace")
        ),
        "{:?}",
        scene.coverage()
    );
    assert!(entries(&log).contains(&"note_capture_custody".to_string()));
}

/// The native lane's uncovered reason: an edge no coverage note reached (its
/// first projection fell in a pass whose health was unproven) reads
/// `not_attached`, never `scan_only`.
#[test]
fn an_edge_no_coverage_note_reached_reads_not_attached_in_the_native_lane() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.source.spawn(8, 800);
    scene.joiner = Some((8, 800, 2));
    let mut lane = ScriptedLane::new(&log);
    lane.unproven_reads = 1;
    run(&mut scene, lane, 2);
    assert_eq!(
        scene.coverage_of(8),
        UseCoverage::Unknown(UnknownReason::NotAttached)
    );
}

/// C5.7 (ruling D8), the threading boundary: the pass's collection runs on
/// a worker while the loop services the lifecycle ring. The gated
/// collection cannot finish until the ring was serviced three times while
/// it ran (servicing only between passes fails it). Nothing is staged
/// while it runs; the held quanta stage after the scan applied and the
/// extend receipt, ahead of the pass's own quantum, and every quantum ever
/// drained stages exactly once, in drain order.
#[test]
fn the_ring_is_serviced_while_a_pass_collects_and_staged_after_its_scan() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    let (serviced, gate) = mpsc::channel();
    lane.serviced = Some(serviced);
    scene.collect_gate = Some((gate, 3));
    let drained = Rc::clone(&lane.service_stamps);
    run_ticking(&mut scene, lane, 1, Duration::from_millis(1));
    let log = entries(&log);
    let collect = log.iter().position(|entry| entry == "collect").unwrap();
    let scan = log.iter().position(|entry| entry == "scan").unwrap();
    let during = &log[collect + 1..scan];
    assert!(during.len() >= 3, "{log:?}");
    assert!(during.iter().all(|entry| entry == "service"), "{log:?}");
    let after_scan = &log[scan..];
    let mut expected: Vec<String> = [
        "scan",
        "take_target_delta",
        "extend[0,1]",
        "note_extend_receipt",
    ]
    .map(String::from)
    .to_vec();
    expected.extend(std::iter::repeat_n(
        "stage:lifecycle".to_string(),
        during.len(),
    ));
    expected.extend(["service", "stage:lifecycle", "read"].map(String::from));
    assert_eq!(
        &after_scan[..expected.len()],
        expected.as_slice(),
        "{log:?}"
    );
    assert_eq!(scene.staged_lifecycle, *drained.borrow());
}

/// C5.7: collection ticks hold at most `held_records` drained records, a
/// strict bound: each quantum is capped at the room left, and past the
/// bound they drain nothing (the ring keeps the rest, and the kernel counts
/// what it cannot hold). The held quanta stage with the pass, which frees
/// the bound.
#[test]
fn collection_ticks_hold_at_most_the_record_bound() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.records_per_service = 2;
    let windows = LaneWindows {
        held_records: 3,
        ..windows()
    };
    let mut started = NativeLane::start(lane, &mut scene, windows, None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    for _ in 0..5 {
        started.collecting_tick();
        assert!(started.held_records <= 3, "{}", started.held_records);
    }
    let services = |log: &Log| {
        log.borrow()
            .iter()
            .filter(|entry| *entry == "service")
            .count()
    };
    // Two records, then the one record of room left, then nothing.
    assert_eq!(services(&log), 2);
    assert_eq!(started.held_records, 3);
    assert!(!entries(&log).contains(&"stage:lifecycle".to_string()));
    started.after_pass(&mut scene);
    assert_eq!(scene.staged_lifecycle.len(), 3, "two held, one serviced");
    // Staging frees the bound.
    started.collecting_tick();
    assert_eq!(services(&log), 4);
}

/// C5.7: one collection tick drains quantum after quantum while each stops
/// at its record bound (the ring still holds more), until the held bound
/// stops it; the last quantum takes only the room left.
#[test]
fn a_collection_tick_drains_full_quanta_until_the_held_bound() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.records_per_service = 1000;
    let windows = LaneWindows {
        held_records: 600,
        ..windows()
    };
    let mut started = NativeLane::start(lane, &mut scene, windows, None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    started.collecting_tick();
    // 256 + 256 + the 88 records of room left.
    let services = entries(&log)
        .iter()
        .filter(|entry| *entry == "service")
        .count();
    assert_eq!(services, 3);
    assert_eq!((started.held_records, started.tally.records), (600, 600));
}

/// C5.7 (review M-1): collection-time drains are counted like any other:
/// their records, a failed quantum (which also grants a recovery rescan),
/// and they stage with the pass. `observation.lifecycle` is public, so
/// each field is pinned.
#[test]
fn collection_time_drains_are_counted_and_a_failed_one_grants_a_rescan() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.records_per_service = 3;
    lane.failed_services = HashSet::from([2]);
    let mut started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    // Service 1 drains 3 records; service 2 fails (its 3 records still
    // count as dequeued) and ends the tick; service 3 drains 3 more.
    started.collecting_tick();
    started.collecting_tick();
    started.collecting_tick();
    assert_eq!(
        started.tally,
        LifecycleTally {
            records: 9,
            failed_quanta: 1,
            ..LifecycleTally::default()
        }
    );
    assert!(started.take_recovery_rescan(), "a failed quantum is a loss");
    started.after_pass(&mut scene);
    assert_eq!(scene.staged_lifecycle.len(), 4, "three held, one serviced");
}

/// FB-R5 (review M-1): a malformed-record rise is a loss: counted, and it
/// grants a recovery rescan; an unchanged count grants nothing.
#[test]
fn a_malformed_record_rise_is_counted_and_grants_a_rescan() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.malformed = VecDeque::from([0, 2, 2]);
    let mut started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    started.after_pass(&mut scene);
    assert!(!started.take_recovery_rescan());
    started.after_pass(&mut scene);
    assert_eq!(started.tally.malformed, 2);
    assert!(started.take_recovery_rescan());
    started.after_pass(&mut scene);
    assert!(
        !started.take_recovery_rescan(),
        "no rescan follows a rescan"
    );
    started.after_pass(&mut scene);
    assert!(!started.take_recovery_rescan(), "no new loss, no new grant");
    assert_eq!(started.tally.malformed, 2);
}

/// Runs the scripted lane under `clock`; the stop is `stop_after` scans.
fn run_clocked(
    scene: &mut Scene,
    lane: ScriptedLane,
    stop_after: usize,
    interval: Duration,
    deadline: Duration,
) -> Stopped<ScriptedLane> {
    let started = NativeLane::start(lane, scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let scans = {
        let log = Rc::clone(&scene.log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= stop_after;
    let clock = LoopClock {
        deadline: Some(Instant::now() + deadline),
        stop: &stop,
        interval,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    run_classic(scene, Some(started), &clock, &mut |_, _| Ok(()))
        .unwrap()
        .unwrap()
}

/// FB-R5: a lifecycle loss starts the next pass at once (a recovery
/// rescan) instead of waiting out the interval; the tally counts the loss
/// and the rescan. Without the rescan the hour-long interval holds the
/// second pass past the deadline.
#[test]
fn a_lifecycle_loss_starts_the_next_pass_at_once() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.ring_loss = VecDeque::from([4]);
    let stopped = run_clocked(
        &mut scene,
        lane,
        2,
        Duration::from_secs(3600),
        Duration::from_secs(3),
    );
    assert_eq!(stopped.summary.passes, 2);
    let tally = stopped.summary.lifecycle;
    assert_eq!(
        (tally.ring_loss, tally.recovery_rescans),
        (4, 1),
        "{tally:?}"
    );
    // Every quantum the lane drained is counted (none carried records).
    assert_eq!(tally.records, 0);
}

/// FB-R5 (review M-1 N1): one loss grants one rescan for the whole run; a
/// steady loss count never re-arms it, so later passes keep the interval.
#[test]
fn one_loss_grants_one_recovery_rescan_for_the_run() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.ring_loss = VecDeque::from([4]);
    let stopped = run_clocked(
        &mut scene,
        lane,
        5,
        Duration::ZERO,
        Duration::from_secs(600),
    );
    assert_eq!(stopped.summary.passes, 5);
    let tally = stopped.summary.lifecycle;
    assert_eq!(
        (tally.ring_loss, tally.recovery_rescans),
        (4, 1),
        "{tally:?}"
    );
}

/// Review L-2: `recovery_rescans` counts passes that started; a rescan
/// granted just before the stop never ran and is not counted.
#[test]
fn a_rescan_granted_before_the_stop_is_not_counted() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.ring_loss = VecDeque::from([4]);
    let stopped = run_clocked(
        &mut scene,
        lane,
        1,
        Duration::from_secs(3600),
        Duration::from_secs(600),
    );
    assert_eq!(stopped.summary.passes, 1);
    let tally = stopped.summary.lifecycle;
    assert_eq!(
        (tally.ring_loss, tally.recovery_rescans),
        (4, 0),
        "{tally:?}"
    );
}

/// FB-R5, the bound: a recovery rescan is never followed by another, so a
/// host that loses records on every pass rescans early at most every
/// second pass; a later loss after a normal pass is granted again.
#[test]
fn recovery_rescans_never_follow_each_other() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.ring_loss = VecDeque::from([1, 2, 3, 4, 5]);
    lane.records_per_service = 2;
    let mut started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let mut granted = Vec::new();
    for _ in 0..5 {
        started.after_pass(&mut scene);
        let grant = started.take_recovery_rescan();
        if grant {
            started.begin_recovery_rescan();
        }
        granted.push(grant);
    }
    assert_eq!(granted, [true, false, true, false, true]);
    let stopped = started.stop(&mut scene);
    let tally = stopped.summary.lifecycle;
    assert_eq!(
        (tally.ring_loss, tally.recovery_rescans),
        (5, 3),
        "{tally:?}"
    );
    let services = entries(&log)
        .iter()
        .filter(|entry| *entry == "service")
        .count() as u64;
    assert_eq!(tally.records, 2 * services);
    assert_eq!((tally.malformed, tally.failed_quanta), (0, 0));
}

/// C5.7: a worker that panics resumes its panic on the loop's thread
/// (never a silent empty pass), and its value otherwise crosses back.
#[test]
fn the_collection_worker_hands_back_its_value_or_its_panic() {
    let mut ticks = 0;
    assert_eq!(
        collect_off_thread(|| 7, Duration::from_millis(1), &mut || ticks += 1),
        7
    );
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        collect_off_thread(
            || -> u32 { panic!("scripted collection panic") },
            Duration::from_millis(1),
            &mut || {},
        )
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>().copied(),
        Some("scripted collection panic")
    );
}

// ---- C5.11: backend selection and disclosure --------------------------------

mod cgroup_backend_selection {
    use super::*;
    use crate::inventory_capture::{MultiScopeProbe, prepare_scoped_on_backend};
    use std::sync::Arc;

    #[test]
    fn cgroup_multi_retry_uses_general_probe_and_the_same_retained_root() {
        let tree = tempfile::tempdir().unwrap();
        let selected = tree.path().join("selected");
        std::fs::create_dir(&selected).unwrap();
        let saved = crate::scope::cgroup(&selected).unwrap();
        let crate::attach::Scope::Cgroup { dir: original, .. } = &saved else {
            unreachable!()
        };
        let original = Arc::clone(original);
        let scope = CaptureScope::cgroup(saved).unwrap();
        let tried = RefCell::new(Vec::new());
        let probes = RefCell::new(Vec::new());
        let (prepared, chosen) = prepare_scoped_on_backend(
            BackendSelection::Auto,
            &scope,
            |probe| {
                probes.borrow_mut().push(probe);
                assert_eq!(probe, MultiScopeProbe::General);
                Ok(())
            },
            |attempt, backend| {
                let CaptureScope::Cgroup(cgroup) = attempt else {
                    panic!("scope changed")
                };
                assert!(Arc::ptr_eq(&original, cgroup.root()));
                tried.borrow_mut().push(backend);
                if backend == AttachBackend::Multi {
                    std::fs::rename(&selected, tree.path().join("held-original")).unwrap();
                    std::fs::create_dir(&selected).unwrap();
                    return Err(anyhow!("scripted Multi refusal"));
                }
                Ok(cgroup)
            },
        )
        .unwrap();
        assert_eq!(probes.into_inner(), [MultiScopeProbe::General]);
        assert_eq!(
            tried.into_inner(),
            [AttachBackend::Multi, AttachBackend::Singles]
        );
        assert!(Arc::ptr_eq(&original, prepared.root()));
        assert_eq!(chosen.scope_filter.label(), Some("bpf-cgroup"));
        assert_eq!(chosen.backend, AttachBackend::Singles);
    }

    #[test]
    fn cgroup_singles_does_not_probe_and_keeps_cgroup_filter() {
        let tree = tempfile::tempdir().unwrap();
        let scope = CaptureScope::cgroup(crate::scope::cgroup(tree.path()).unwrap()).unwrap();
        let (_, chosen) = prepare_scoped_on_backend(
            BackendSelection::Singles,
            &scope,
            |_| panic!("Singles must not probe"),
            |attempt, backend| {
                assert_eq!(backend, AttachBackend::Singles);
                assert_eq!(attempt.scope_coverage(), CaptureScopeCoverage::Cgroup);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(chosen.scope_filter, ScopeFilter::BpfCgroup);
    }

    #[test]
    fn cgroup_forced_multi_never_tries_singles_after_refusal() {
        let tree = tempfile::tempdir().unwrap();
        let scope = CaptureScope::cgroup(crate::scope::cgroup(tree.path()).unwrap()).unwrap();
        let tried = RefCell::new(Vec::new());
        let outcome = prepare_scoped_on_backend(
            BackendSelection::Multi,
            &scope,
            |probe| {
                assert_eq!(probe, MultiScopeProbe::General);
                Ok(())
            },
            |attempt, backend| {
                assert_eq!(attempt.scope_coverage(), CaptureScopeCoverage::Cgroup);
                tried.borrow_mut().push(backend);
                Err::<(), _>(anyhow!("scripted forced refusal"))
            },
        );
        assert!(outcome.is_err());
        assert_eq!(tried.into_inner(), [AttachBackend::Multi]);
    }
}

mod backend_selection {
    use crate::attach::{AttachBackend, BackendSelection};
    use crate::inventory_capture::{LaneBackend, prepare_on_backend};
    use anyhow::anyhow;
    use std::cell::RefCell;

    /// Runs the resolution with a scripted probe and preparation, and
    /// returns the outcome plus every backend a preparation was tried on.
    fn resolve(
        selection: BackendSelection,
        probe: Result<(), &str>,
        multi_prepares: bool,
    ) -> (anyhow::Result<LaneBackend>, Vec<AttachBackend>, bool) {
        let tried = RefCell::new(Vec::new());
        let probed = RefCell::new(false);
        let outcome = prepare_on_backend(
            selection,
            || {
                *probed.borrow_mut() = true;
                probe.map_err(String::from)
            },
            |backend| {
                tried.borrow_mut().push(backend);
                if backend == AttachBackend::Multi && !multi_prepares {
                    return Err(anyhow!("multi load refused"));
                }
                Ok(backend)
            },
        )
        .map(|(prepared, chosen)| {
            assert_eq!(
                prepared, chosen.backend,
                "the prepared backend is disclosed"
            );
            chosen
        });
        (outcome, tried.into_inner(), probed.into_inner())
    }

    #[test]
    fn auto_on_a_multi_kernel_attaches_multi_after_a_linking_probe() {
        let (chosen, tried, probed) = resolve(BackendSelection::Auto, Ok(()), true);
        let chosen = chosen.unwrap();
        assert_eq!(chosen.backend, AttachBackend::Multi);
        assert_eq!(chosen.mechanism(), "uprobe-multi");
        assert_eq!(chosen.selection_label(), "auto");
        assert_eq!(chosen.fallback, None);
        assert!(probed);
        assert_eq!(
            tried,
            [AttachBackend::Multi],
            "no Singles object was loaded"
        );
    }

    #[test]
    fn auto_falls_back_to_singles_for_the_whole_capture_when_the_probe_fails() {
        let (chosen, tried, _) = resolve(BackendSelection::Auto, Err("EOPNOTSUPP"), true);
        let chosen = chosen.unwrap();
        assert_eq!(chosen.backend, AttachBackend::Singles);
        assert_eq!(chosen.mechanism(), "per-offset");
        assert!(
            chosen
                .fallback
                .as_deref()
                .is_some_and(|reason| reason.contains("functional probe failed: EOPNOTSUPP")),
            "{chosen:?}"
        );
        assert_eq!(tried, [AttachBackend::Singles], "Multi was never loaded");
    }

    #[test]
    fn auto_retries_a_failed_multi_preparation_once_on_singles() {
        let (chosen, tried, _) = resolve(BackendSelection::Auto, Ok(()), false);
        let chosen = chosen.unwrap();
        assert_eq!(chosen.backend, AttachBackend::Singles);
        assert!(
            chosen
                .fallback
                .as_deref()
                .is_some_and(|reason| reason.contains("multi load refused"))
        );
        assert_eq!(tried, [AttachBackend::Multi, AttachBackend::Singles]);
    }

    /// The owner directive: a capability probe, never the kernel version,
    /// decides; `auto` always asks the probe.
    #[test]
    fn auto_always_asks_the_probe_whatever_the_kernel_version() {
        let (_, _, probed) = resolve(BackendSelection::Auto, Ok(()), true);
        assert!(probed);
        let (chosen, tried, probed) = resolve(BackendSelection::Auto, Err("EINVAL"), true);
        assert!(probed);
        assert_eq!(chosen.unwrap().backend, AttachBackend::Singles);
        assert_eq!(tried, [AttachBackend::Singles]);
    }

    #[test]
    fn forced_multi_surfaces_the_refusal_and_never_falls_back() {
        let (chosen, tried, _) = resolve(BackendSelection::Multi, Err("ENOSYS"), true);
        let error = chosen.unwrap_err();
        assert!(
            format!("{error:#}").contains("--attach-backend multi") && tried.is_empty(),
            "{error:#} {tried:?}"
        );
        let (chosen, tried, _) = resolve(BackendSelection::Multi, Ok(()), false);
        assert!(chosen.is_err());
        assert_eq!(
            tried,
            [AttachBackend::Multi],
            "forced Multi never tries Singles"
        );
        let (chosen, _, _) = resolve(BackendSelection::Multi, Ok(()), true);
        assert_eq!(chosen.unwrap().backend, AttachBackend::Multi);
    }

    #[test]
    fn forced_singles_never_probes() {
        let (chosen, tried, probed) = resolve(BackendSelection::Singles, Ok(()), true);
        assert_eq!(chosen.unwrap().backend, AttachBackend::Singles);
        assert!(!probed);
        assert_eq!(tried, [AttachBackend::Singles]);
    }

    /// The security review's rule at the facade: a PID-scoped Multi
    /// capture needs the proven kernel pid filter. Unprivileged, the probe
    /// cannot run, so the refusal names the filter before anything loads.
    #[test]
    fn a_pid_scoped_multi_capture_needs_the_proven_kernel_pid_filter() {
        use crate::attach::capture::{CaptureScope, InventoryCapture, caller_budget};
        if crate::attach::kernel_multi_pid_filter().is_ok() {
            return; // privileged on a fixed kernel: the privileged cells cover it
        }
        let budget = crate::capacity::InventoryBudget::new(4, 32).unwrap();
        let pin = crate::process::PidPin::open(std::process::id()).unwrap();
        let error = InventoryCapture::prepare(
            CaptureScope::Pid(pin),
            budget,
            caller_budget(budget, 2).unwrap(),
            AttachBackend::Multi,
        )
        .err()
        .expect("a PID-scoped Multi capture was prepared without the pid filter");
        assert!(
            format!("{error:#}").contains("kernel pid filter"),
            "{error:#}"
        );
    }
}
