//! SPDX-License-Identifier: GPL-3.0-or-later
//! The native lane over a scripted facade and a real coordinator (scripted
//! process source, scripted catalogs): the exact call order of startup,
//! passes and stop, and what each ordering rule buys end to end.

use super::*;
use crate::attach::capture::{
    AttachedEndpoint, CaptureHealth, CapturePhase, DomainCookie, ExecCoverage, WitnessRow,
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

type Pin = (u32, u64);
type Log = Rc<RefCell<Vec<String>>>;

const PID: u32 = 7;
const START: u64 = 500;
const TICKET: u64 = 41;

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

/// A scripted facade: records every call, activates on the first extend,
/// attaches what it is given (minus a scripted deferral), reports scripted
/// rows per read, answers scripted cookies, and retires after a scripted
/// number of polls (never, when `None`).
struct ScriptedLane {
    log: Log,
    domain: NativeDomainId,
    stamps: Stamps,
    activated: bool,
    refuse_activation: bool,
    /// Endpoints the next non-activating extend defers (from the end).
    defer_next: usize,
    attached: Vec<AttachEndpoint>,
    reads: VecDeque<Vec<RowSpec>>,
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
    /// How long each read takes.
    read_delay: Duration,
    /// After this many reads, the next `.1` discovery quanta stop at their
    /// record bound (the ring still holds records).
    undrained_after_reads: Option<(usize, usize)>,
    /// The start of the last complete lifecycle drain (the facade's
    /// `lifecycle_proven_ns`).
    drained_ns: u64,
}

impl ScriptedLane {
    fn new(log: &Log) -> Self {
        let mut cookies = HashMap::new();
        cookies.insert((PID, START), TICKET);
        Self {
            log: Rc::clone(log),
            domain: NativeDomainId::mint(),
            stamps: Stamps::default(),
            activated: false,
            refuse_activation: false,
            defer_next: 0,
            attached: Vec::new(),
            reads: VecDeque::new(),
            read_stamps: Vec::new(),
            cookies,
            stopping: false,
            polls: 0,
            retire_after: Some(1),
            retired: false,
            unproven_reads: 0,
            partial_reads: HashSet::new(),
            read_delay: Duration::ZERO,
            undrained_after_reads: None,
            drained_ns: 0,
        }
    }

    fn note(&self, entry: impl Into<String>) {
        self.log.borrow_mut().push(entry.into());
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

    fn incarnation(&self) -> Option<ScopeIncarnation> {
        None
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
            custody: Some(ScopeCustody::System),
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

    fn service_discovery(&mut self, _: ReadWindow) -> DiscoveryBatch {
        self.note("service");
        let mut batch = DiscoveryBatch::scripted(self.domain, Vec::new(), self.stamps.next());
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
        let rows_read_ns = self.stamps.next();
        let health_unproven = (self.read_stamps.len() <= self.unproven_reads)
            .then(|| "scripted unreadable health".to_string());
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
            seen_rows: 0,
            pair_limit: 64,
            lifecycle_loss: None,
            lifecycle_proven_ns: self.drained_ns,
            health: CaptureHealth {
                discovery_counters: Some([0; 5]),
                ..CaptureHealth::default()
            },
            health_regression: None,
            health_unproven,
            health_baseline_ns: 0,
            health_read_ns,
            rows_read_ns,
            changed_objects: Vec::new(),
            custody: ScopeCustody::System,
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
    /// A second caller (pid, start) that maps the provider from this scan
    /// (1-based) on.
    joiner: Option<(u32, u64, usize)>,
    scans: usize,
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
            joiner: None,
            scans: 0,
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
    fn begin_capture_coverage(&mut self, scope: Option<ScopeIncarnation>) {
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
        });
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
}

impl PassDriver<Pin> for Scene {
    type Host = Self;

    fn host(&mut self) -> &mut Self {
        self
    }

    fn scan(&mut self, identity: &mut dyn NativeIdentity<Pin>, now_ns: u64) -> Result<PassReport> {
        self.note("scan");
        self.scans += 1;
        let catalog = self.catalog();
        Ok(self.coordinator.apply_catalog(
            catalog,
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
}

fn windows() -> LaneWindows {
    LaneWindows {
        retirement_base: Duration::from_millis(200),
        retirement_per_endpoint: Duration::from_millis(50),
        ..LaneWindows::PROVISIONAL
    }
}

/// Runs `passes` passes (no pause between them), then the stop.
fn run(
    scene: &mut Scene,
    lane: ScriptedLane,
    passes: usize,
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
                Publish::Retiring { attached, budget } => {
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
    assert!(scene.coverage().is_witnessed(), "{:?}", scene.coverage());
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
/// 68 links in 4.9 s), so the budget grows with the attached endpoints up
/// to a cap.
#[test]
fn the_retirement_budget_grows_with_the_attached_endpoints_up_to_its_cap() {
    let windows = LaneWindows::PROVISIONAL;
    assert_eq!(windows.retirement_budget(0), Duration::from_secs(5));
    assert_eq!(
        windows.retirement_budget(68),
        Duration::from_millis(5_000 + 68 * 250)
    );
    assert!(windows.retirement_budget(68) > Duration::from_millis(68 * 73 * 3));
    assert_eq!(windows.retirement_budget(100_000), Duration::from_secs(120));
    assert_eq!(
        windows.retirement_budget(usize::MAX),
        Duration::from_secs(120)
    );
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
    };
    let none: Option<NativeLane<ScriptedLane>> = None;
    let stopped = run_classic(&mut scene, none, &clock, &mut |scene: &mut Scene, _| {
        scene.note("publish");
        Ok(())
    })
    .unwrap();
    assert!(stopped.is_none());
    assert_eq!(entries(&log), ["scan", "commit", "publish"]);
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
    let second = log.iter().rposition(|entry| entry == "scan").unwrap();
    let between = &log[first + 1..second];
    assert!(between.len() >= 4, "{between:?}");
    for pair in between.chunks(2) {
        assert_eq!(pair, ["service", "stage:lifecycle"], "{between:?}");
    }
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
