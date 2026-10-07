//! SPDX-License-Identifier: GPL-3.0-or-later
//! The I3/I4b inventory coordinator: owns the I4a scan window, drives
//! scan→reconcile→publish, revalidates every prepared candidate at its
//! publication boundary, and commits through the explicit seam.
//!
//! Two lanes share the caller adapter, the caller registry, and the batch
//! boundary:
//!
//! - native: exact image authority through the inventory core — open,
//!   lease, windowed scan, prepare, revalidate-at-commit, publish. Used
//!   when the caller supplies BPF image identity (privileged) or a
//!   scripted guard over owned fixtures (tests).
//! - scan: unprivileged catalog collection with pidfd/start-time
//!   incarnations. Exact-image authority is unavailable here, so every
//!   record reads `scan_pinned` and the gaps say why.
//!
//! I3/I4 mapping: the coordinator owns the I4a window (`begin_window`
//! per scan, monotonically increasing IDs, lease held across the scan);
//! preparation never implies publication (`commit` revalidates after any
//! gap since preparation); the I4b batch is `commit_batch`, which runs
//! the engine tail and the registry publish as one synchronous step, so
//! inventory facts publish through the same batch boundary the Phase 2
//! ordering test pins.

use super::inventory::{
    ExecProof, ImageGuard, InventoryCommit, InventoryDiscoveryConfig, InventoryOwnerLimits,
    RefreshCause, ScanReceipt,
};
use super::*;
use crate::attach::capture::{
    CallerCountUpdate, DiscoveryBatch, DomainCookie, ExtendReceipt, LifecycleLoss, NativeDomainId,
    ScopeCustody, ScopeIncarnation, WitnessBatch, WitnessRow,
};
use crate::capacity::InventoryBudget;
use crate::discovery::caller_registry::{
    AdmissionState, BudgetRefusal, CallerAdapter, CallerEvent, CallerId, CallerRegistry,
    CoverageNote, EdgeRecord, ImageAuthority, MappingState, ModuleInfo, ModuleKey,
    PendingCountOutcome, ProcessSource, RegistryGap, RegistryLimits, UnknownReason, UseCoverage,
};
use crate::discovery::inventory_attach_set::{
    AttachModuleKey, AttachObjectId, AttachVerdict, ENDPOINT_RESOURCE, EndpointId,
    InventoryAttachSet, MEMBERSHIP_RESOURCE, ModuleMembers, TargetDelta,
};
use crate::discovery::native_binding::{
    BinderLimits, Binding, Decision, ExecTransition, NativeBinder, NativeIdentity, UnboundReason,
};
use crate::discovery::scan::{
    InventoryDiscoveryLimits, InventoryRetainedLimits, InventoryWindowLimits, WindowId,
};
use crate::discovery::sweep_attribution::AttributionLoss;
use p11scope_ebpf_common::inventory_callers::CallerEvidence;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

/// What one inventory pass scans: one named process, or the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InventoryScope {
    Pid(u32),
    System,
}

/// What one scan pass concluded. Registry mutations staged by the pass
/// stay invisible until `commit_batch` publishes them.
#[derive(Debug, Clone)]
pub(crate) struct PassReport {
    pub pass: u64,
    /// Members observed this pass: deep-scanned plus maps-matched.
    pub scanned: usize,
    /// Of `scanned`, the members attributed by exact maps identity (C1b).
    pub maps_matched: usize,
    pub native_callers: usize,
    pub scan_callers: usize,
    pub engine_changed: bool,
    pub pending_refresh: Vec<CallerId>,
    pub events: Vec<CallerEvent>,
    /// Per-stage wall time of the pass: the catalog collection's stages
    /// plus reconcile, native scans, and projection.
    pub timings: crate::timing::StageTimings,
}

/// What one batch commit published: both revisions, which the ordering
/// test pins as advanced synchronously with the commit return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BatchReceipt {
    pub engine_facts: u64,
    pub engine_published: u64,
    pub registry_facts: u64,
    pub registry_published: u64,
    pub registry_applied: usize,
}

/// Static reason carried when a scan defers past its deadline. The
/// refresh request stays pending (no commit ran), so the next pass with
/// a fresh deadline retries the same owner.
const DEADLINE_DEFERRED: &str = "inventory scan deadline passed; the scan defers to the next pass";

/// O1 endpoint evidence: failed endpoints make their module undercount.
/// Pinned verbatim: the oracle matches this subject.
const PARTIAL_ATTACH_SUBJECT: &str = "native endpoint attach failed";

/// Per-pid authority resolution with a native open attempt: the open is
/// the check, so the native path is attempted honestly on every pass
/// and the scan lane is a recorded fallback, not a compile-time fork.
struct AuthorityResolver<'a, Pin> {
    engine: &'a mut Engine,
    pending: &'a mut BTreeMap<u32, ProcessViewId>,
    guard: &'a mut dyn ImageGuard,
    identity: &'a mut dyn NativeIdentity<Pin>,
    native_failures: Vec<(u32, String)>,
    scan_pinned: usize,
}

impl<Pin> AuthorityResolver<'_, Pin> {
    fn resolve(&mut self, pid: u32) -> ImageAuthority {
        match self
            .identity
            .owner_image(pid)
            .filter(|image| image.task_cookie != 0)
        {
            Some(image) => match self
                .engine
                .open_inventory_owner(pid, image, &mut *self.guard)
            {
                Ok(owner) => {
                    self.pending.insert(pid, owner);
                    ImageAuthority::NativeExact {
                        task_cookie: image.task_cookie,
                        exec_id: image.exec_id,
                    }
                }
                Err(error) => {
                    self.native_failures.push((pid, format!("{error:#}")));
                    ImageAuthority::ScanPinned
                }
            },
            None => {
                self.scan_pinned += 1;
                ImageAuthority::ScanPinned
            }
        }
    }

    fn finish(self) -> (Vec<(u32, String)>, usize) {
        (self.native_failures, self.scan_pinned)
    }
}

/// The coordinator: an Inventory-policy engine, the caller adapter, and
/// the caller registry behind one batch boundary, plus the attach set the
/// catalog's Inventory lowering feeds every pass.
pub(crate) struct InventoryCoordinator<Source: ProcessSource> {
    engine: Engine,
    adapter: CallerAdapter<Source>,
    registry: CallerRegistry,
    attach_set: InventoryAttachSet,
    /// Endpoints and objects the attach set added since the capture facade
    /// last took them. Bounded by the endpoint budget: every endpoint
    /// enters exactly once.
    pending_targets: TargetDelta,
    /// What the capture facade's receipts say per endpoint, once native
    /// capture runs (Task 6 C3); `None` in the scan lane.
    capture: Option<CaptureCoverage>,
    /// The native witness binder (Task 6 C4): every native row enters
    /// through `stage_native`.
    binder: NativeBinder,
    /// The latest known count per witnessed pair (C7 C4): first-sight
    /// and refresh counts merge here (the maximum wins, with its
    /// observing read) and stage to the edge once the pair binds. One
    /// entry per CALLER_USE row at most.
    pair_counts: HashMap<PairKey, PairCount>,
    /// Decided pairs (C7 C4): bound pairs stage their counts to one
    /// edge, dropped pairs (binder-unbound, ambiguous, or edgeless)
    /// never publish — DR-C51-PREADMIT stays out. One entry per
    /// decided row at most.
    pair_targets: HashMap<PairKey, PairTarget>,
    /// Outstanding publication-time count placements (P3): each staged
    /// pending count's opaque handle back to its pair. Drained with the
    /// publication's decisions; one entry per staged pending count.
    pending_ids: HashMap<u64, PairKey>,
    /// The next pending-count handle (P3): minted in staging order.
    next_pending_id: u64,
    owners: BTreeMap<CallerId, ProcessViewId>,
    pending_owners: BTreeMap<u32, ProcessViewId>,
    scanned_owners: BTreeSet<ProcessViewId>,
    churned_owners: BTreeSet<ProcessViewId>,
    next_window: u64,
    passes: u64,
    authority_gap_recorded: bool,
    /// The run's lifecycle-ring high-water: the maximum fill any staged
    /// drain reported. Timings telemetry only (the stage-timings pass
    /// lines), never schema.
    lifecycle_high_water_bytes: Option<u64>,
}

/// The capture-lifetime Inventory endpoint budget: the engine's admission
/// policy and the attach set's bound are this one value.
fn default_inventory_budget() -> Result<InventoryBudget> {
    InventoryBudget::new(4096, 4096 * 8).map_err(anyhow::Error::msg)
}

fn default_inventory_config() -> Result<InventoryDiscoveryConfig> {
    let window = InventoryWindowLimits::new(16 << 20, 1 << 20, 4096, 32768, 4096)
        .map_err(anyhow::Error::msg)?;
    let retained = InventoryRetainedLimits::new(8192, 32768, 8192, 128, 128, 16 << 20)
        .map_err(anyhow::Error::msg)?;
    let work =
        InventoryDiscoveryLimits::new(8 << 20, window, retained).map_err(anyhow::Error::msg)?;
    Ok(InventoryDiscoveryConfig::new(
        work,
        InventoryOwnerLimits::new(1024, 8, 32768).map_err(anyhow::Error::msg)?,
        default_inventory_budget()?,
    ))
}

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    pub(crate) fn new(
        scope: Scope,
        hooks: HookRegistry,
        hints: Vec<PathBuf>,
        source: Source,
        registry_limits: RegistryLimits,
    ) -> Result<Self> {
        let mut adapter = CallerAdapter::new(source);
        // One caller budget, enforced where incarnations are minted; the
        // registry's caller cap stands behind it as a backstop.
        adapter.set_max_callers(registry_limits.max_callers);
        Ok(Self {
            engine: Engine::inventory(default_inventory_config()?, scope, hooks, hints)?,
            adapter,
            registry: CallerRegistry::new(registry_limits),
            attach_set: InventoryAttachSet::new(default_inventory_budget()?),
            pending_targets: TargetDelta::default(),
            capture: None,
            binder: NativeBinder::new(BinderLimits::default()),
            pair_counts: HashMap::new(),
            pair_targets: HashMap::new(),
            pending_ids: HashMap::new(),
            next_pending_id: 0,
            owners: BTreeMap::new(),
            pending_owners: BTreeMap::new(),
            scanned_owners: BTreeSet::new(),
            churned_owners: BTreeSet::new(),
            next_window: 0,
            passes: 0,
            authority_gap_recorded: false,
            lifecycle_high_water_bytes: None,
        })
    }

    /// The run's lifecycle-ring high-water so far, for the stage-timings
    /// pass lines. `None` until a native drain stages (the scan lane).
    pub(crate) fn lifecycle_high_water_bytes(&self) -> Option<u64> {
        self.lifecycle_high_water_bytes
    }

    pub(crate) fn adapter(&self) -> &CallerAdapter<Source> {
        &self.adapter
    }

    /// Mutable adapter access for the workload harness (scripted
    /// reconciles over programmed pids) and tests. The production
    /// command never mutates the adapter except through `scan_pass`.
    // Test-only seam: the cfg(test) harness and unit tests pin it.
    #[cfg(test)]
    pub(crate) fn adapter_mut(&mut self) -> &mut CallerAdapter<Source> {
        &mut self.adapter
    }

    pub(crate) fn registry(&self) -> &CallerRegistry {
        &self.registry
    }

    /// Stages one scope-level gap (no caller, module or PID) that
    /// publishes with the next pass: the run-wide PID-numbering mismatch
    /// (`pidns::numbering_gap`, review F4) is the only producer.
    pub(crate) fn note_scope_gap(&mut self, subject: String, reason: String) {
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject,
            reason,
            budget: None,
        });
    }

    /// Stages one pass-wide count-refresh loss boundary from the lane
    /// itself (P1-5 terminal-first): an incomplete terminal refresh
    /// demotes the retained counts to lower bounds exactly like a
    /// failed live read — a scope gap alone would leave them
    /// loss-free. The loss is a gap too, never silent loss.
    pub(crate) fn note_refresh_loss(&mut self, reason: String) {
        self.registry.note_refresh_loss(reason);
    }

    // Test seam: production stages only through `scan_pass` (and, from
    // Task 6 C5, the native staging call).
    #[cfg(test)]
    pub(crate) fn registry_mut(&mut self) -> &mut CallerRegistry {
        &mut self.registry
    }

    /// The run's attach set (read side): presentation reports its
    /// endpoint budget and occupancy.
    pub(crate) fn attach_set(&self) -> &InventoryAttachSet {
        &self.attach_set
    }

    /// Takes what the attach set added since the last take: new endpoints
    /// in ID order plus newly retained objects, never a whole plan. The
    /// capture facade (Task 6 C3) is the production consumer; until it
    /// lands only tests take.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn take_target_delta(&mut self) -> TargetDelta {
        std::mem::take(&mut self.pending_targets)
    }

    /// Native capture starts: from now on each scan projection stages a
    /// coverage note per mapped edge from the capture's attach receipts.
    /// `scope` is the capture's PID incarnation (`None` for the machine):
    /// only a caller of that pid whose start time matches, and the first
    /// such caller (image) only, is in scope — a reused pid never is.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 starts native capture.
    pub(crate) fn begin_capture_coverage(&mut self, scope: Option<ScopeIncarnation>) {
        self.capture = Some(CaptureCoverage {
            scope,
            bound: None,
            attached_at: BTreeMap::new(),
            failed: BTreeSet::new(),
            unproven: None,
            changed_objects: BTreeSet::new(),
            health_unproven: None,
            pairs_unproven: None,
            pairs_uncounted: None,
            last_clean_ns: None,
            sweep_began_ns: None,
            preadmission: PreadmissionStash::new(PREADMISSION_STASH_LIMIT),
            stopped: false,
        });
    }

    /// Forgets a capture coverage whose capture never activated (the
    /// `--capture auto` fallback): the run is the scan lane again.
    pub(crate) fn abandon_capture_coverage(&mut self) {
        self.capture = None;
    }

    /// The reason an edge no coverage note reached reads (`scan_only` by
    /// default; the native lane sets `not_attached`).
    pub(crate) fn set_uncovered_reason(&mut self, reason: UnknownReason) {
        self.registry.set_uncovered_reason(reason);
    }

    /// Absorbs one extend receipt: attached endpoints with their instants,
    /// failed endpoints (sticky), and the scope custody.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 forwards receipts.
    pub(crate) fn note_extend_receipt(&mut self, receipt: &ExtendReceipt) {
        // Exec coverage is the binder's, whatever capture coverage holds.
        if let Some(coverage) = receipt.exec_coverage {
            self.binder.note_exec_coverage(coverage);
        }
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        for attached in &receipt.attached {
            capture.attached_at.insert(attached.id, attached.at_ns);
        }
        for failed in &receipt.failed {
            capture.attached_at.remove(&failed.id);
            capture.failed.insert(failed.id);
        }
        self.note_partial_attach(receipt);
        if let Some(custody) = &receipt.custody {
            self.note_capture_custody(custody);
        }
    }

    /// O1 endpoint evidence: one gap per module with new failures or
    /// deferrals in this receipt. Failed endpoints are sticky (never
    /// retried — bounded: every failed endpoint lands in exactly one
    /// receipt); deferred endpoints are retried, but the deferral
    /// window's calls never come back, so the gap is sticky too even
    /// when a later receipt attaches the endpoint. Failed or deferred
    /// members make the module undercount, so its counted uses are
    /// lower bounds; the oracle withholds COUNT-EXACT over it
    /// (explicitly nonqualifying). Endpoints no module claims (evicted
    /// before the receipt) report run-wide. The subject and reason
    /// shapes are pinned verbatim: the oracle matches them.
    fn note_partial_attach(&mut self, receipt: &ExtendReceipt) {
        // Deferred endpoints dedupe: a receipt may carry the same
        // endpoint twice across its defer calls.
        let deferred: BTreeSet<EndpointId> = receipt
            .deferred
            .endpoints
            .iter()
            .map(|endpoint| endpoint.id)
            .collect();
        if receipt.failed.is_empty() && deferred.is_empty() {
            return;
        }
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        let mut by_module: BTreeMap<AttachModuleKey, (usize, usize)> = BTreeMap::new();
        let mut unclaimed = (0usize, 0usize);
        for failed in &receipt.failed {
            let owners: Vec<AttachModuleKey> = self
                .attach_set
                .modules_with_member(failed.id)
                .cloned()
                .collect();
            if owners.is_empty() {
                unclaimed.0 += 1;
            } else {
                for key in owners {
                    by_module.entry(key).or_default().0 += 1;
                }
            }
        }
        for id in &deferred {
            let owners: Vec<AttachModuleKey> =
                self.attach_set.modules_with_member(*id).cloned().collect();
            if owners.is_empty() {
                unclaimed.1 += 1;
            } else {
                for key in owners {
                    by_module.entry(key).or_default().1 += 1;
                }
            }
        }
        for (key, (failed_here, deferred_here)) in by_module {
            let (total, failed_total) = match self.attach_set.module_members(&key) {
                Some(ModuleMembers::Known(members)) => (
                    members.len(),
                    members
                        .iter()
                        .filter(|id| capture.failed.contains(id))
                        .count(),
                ),
                // Unrecorded membership: no cumulative total exists, so
                // the reason carries this receipt's new failures.
                _ => (0, failed_here),
            };
            let registry_key = ModuleKey::physical(
                key.object.device.major,
                key.object.device.minor,
                key.object.inode,
                Some(key.sha256.clone()),
                "",
            );
            let module = self.registry.module_id_for(&registry_key);
            let mut parts = Vec::new();
            if failed_total > 0 {
                if total > 0 {
                    parts.push(format!(
                        "{failed_total} of {total} endpoints failed to attach (sticky, never retried)"
                    ));
                } else {
                    parts.push(format!(
                        "{failed_total} endpoints failed to attach (sticky, never retried)"
                    ));
                }
            }
            if deferred_here > 0 {
                parts.push(format!(
                    "{deferred_here} endpoint(s) still deferred when the receipt closed"
                ));
            }
            parts.push("counted uses are lower bounds".to_string());
            self.registry.record_gap(RegistryGap {
                caller: None,
                module,
                pid: None,
                subject: PARTIAL_ATTACH_SUBJECT.into(),
                reason: parts.join("; "),
                budget: None,
            });
        }
        if unclaimed.0 > 0 || unclaimed.1 > 0 {
            let mut parts = Vec::new();
            if unclaimed.0 > 0 {
                parts.push(format!(
                    "{} endpoint(s) with no recorded module failed to attach (sticky, never retried)",
                    unclaimed.0
                ));
            }
            if unclaimed.1 > 0 {
                parts.push(format!(
                    "{} endpoint(s) with no recorded module still deferred when the receipt closed",
                    unclaimed.1
                ));
            }
            parts.push("counted uses are lower bounds".to_string());
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: PARTIAL_ATTACH_SUBJECT.into(),
                reason: parts.join("; "),
                budget: None,
            });
        }
    }

    /// Absorbs the capture's scope custody (`InventoryCapture::custody`,
    /// receipts, witness batches). The first unproven or lost custody ends
    /// every watch before stop (C5.2 D2): each ongoing interval freezes at
    /// `min(custody at_ns, last clean read)` — watches staged earlier in
    /// the same batch freeze with the rest, and one no clean read proved
    /// reads unknown — the loss is a gap, and no watch starts after.
    /// After stop it stages nothing: ended intervals are frozen facts.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 forwards custody.
    pub(crate) fn note_capture_custody(&mut self, custody: &ScopeCustody) {
        let Some(capture) = self.capture.as_mut().filter(|capture| !capture.stopped) else {
            return;
        };
        let (at_ns, reason) = match custody {
            ScopeCustody::System | ScopeCustody::PidHeld => return,
            ScopeCustody::PidUnproven { at_ns, reason } => (*at_ns, reason.clone()),
            ScopeCustody::PidLost { at_ns, reason } => (*at_ns, reason.clone()),
        };
        if capture.unproven.is_some() {
            return;
        }
        capture.unproven = Some(reason.clone());
        let until = capture.last_clean_ns.map_or(0, |clean| clean.min(at_ns));
        self.registry.note_watch_end(
            format!(
                "no clean read proved the watch before native capture scope custody became unproven: {reason}"
            ),
            until,
        );
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "native capture scope custody unproven".into(),
            reason: format!(
                "{reason}; every watched no-use interval ends at the earlier of the custody instant and the last clean read; a watch starting at or after that instant reads unknown, and no watch starts again"
            ),
            budget: None,
        });
    }

    /// Absorbs one witness batch's health and custody: a counter rise
    /// demotes every watch (dated at the batch's health baseline, the
    /// earliest instant of the drop) and lets a new watch start only from
    /// the detecting read on; an unproven health withholds watches until a
    /// batch proves it again; changed objects make their modules unknown
    /// from now on. The pair precondition (`pair_precondition_failure`,
    /// sticky) withholds every watch without demoting one. A batch that
    /// completes a gap-free CALLER_USE sweep with proven health, the pair
    /// precondition intact, no rise, and held custody is the latest
    /// proven-clean instant: the `health_read_ns` of the batch that sweep
    /// began in, but never past its custody proof (`custody_proven_ns`, the
    /// last held poll) or its lifecycle drain horizon (`lifecycle_proven_ns`:
    /// any lifecycle loss found later dates at or after it, so it never
    /// falls inside an interval — what makes "nothing after stop" sound).
    /// A system-scope lifecycle loss is a sticky demotion (C5.2 D4): see
    /// `note_lifecycle_loss`; a batch carrying one is never clean.
    /// A batch that leaves a stamped row pending is never clean either:
    /// the row's use is undecided, so the proven-clean instant is not
    /// extended over it (DR-LIVE-LABEL-LAG). `stage_native` absorbs the
    /// batch before this runs, so this batch's rows are already pending.
    /// After stop the watch half stages nothing (forward the terminal
    /// read before `end_capture_coverage`), but count freshness still
    /// consumes: the post-stop terminal refresh stages through this
    /// same call, and a failure beginning there demotes the retained
    /// counts exactly like a live one (P1-5 terminal-first).
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 forwards batches.
    pub(crate) fn note_witness_batch(&mut self, batch: &WitnessBatch) {
        self.note_count_freshness(batch);
        let Some(capture) = self.capture.as_mut().filter(|capture| !capture.stopped) else {
            return;
        };
        capture.health_unproven = batch.health_unproven.clone();
        if capture.pairs_unproven.is_none() {
            capture.pairs_unproven = pair_precondition_failure(batch);
        }
        // C7 C4: a pair insert failure is sticky evidence that some
        // pair has use but no row. First sight only: the map never
        // deletes, so the first failure voids no-use for the capture.
        let uncounted_new = capture.pairs_uncounted.is_none();
        if uncounted_new && let Some(evidence) = batch.health.caller_evidence {
            let index = CallerEvidence::PairInsertFailure.counter_index() as usize;
            if let Some(&failed) = evidence.get(index)
                && failed > 0
            {
                capture.pairs_uncounted = Some(
                    format!(
                        "CALLER_EVIDENCE[{index}] PairInsertFailure showed {failed} failed pair insert(s)"
                    )
                    .into(),
                );
            }
        }
        capture
            .changed_objects
            .extend(batch.changed_objects.iter().copied());
        let custody_held = matches!(batch.custody, ScopeCustody::System | ScopeCustody::PidHeld);
        // Only a completed, gap-free CALLER_USE sweep has visited every row
        // present when it began, so it proves that sweep's first health
        // read; a bounded read that stopped mid-sweep proves nothing.
        let sweep_began_ns = *capture.sweep_began_ns.get_or_insert(batch.health_read_ns);
        if batch.sweep_completed {
            capture.sweep_began_ns = None;
        }
        if batch.sweep_completed
            && !batch.sweep_gaps
            && batch.health_unproven.is_none()
            && capture.pairs_unproven.is_none()
            && batch.health_regression.is_none()
            && custody_held
            && batch.lifecycle_loss.is_none()
            && capture.unproven.is_none()
            && !self.binder.has_stamped_pending()
        {
            let clean_ns = sweep_began_ns
                .min(batch.custody_proven_ns.unwrap_or(u64::MAX))
                .min(batch.lifecycle_proven_ns);
            capture.last_clean_ns = Some(
                capture
                    .last_clean_ns
                    .map_or(clean_ns, |last| last.max(clean_ns)),
            );
        }
        // The pair evidence demotes before the coincident loss demotion
        // (a PairInsertFailure rise is a watch-counter rise): demotions
        // only touch ongoing watches, so the first reason wins and
        // `uncounted` stands while both gaps stay recorded.
        if uncounted_new && let Some(reason) = capture.pairs_uncounted.clone() {
            self.registry
                .note_pairs_uncounted(reason, batch.health_baseline_ns);
        }
        if let Some(reason) = &batch.health_regression {
            self.registry.note_health_regression(
                reason.clone(),
                batch.health_baseline_ns,
                batch.health_read_ns,
            );
        }
        if let Some(loss) = &batch.lifecycle_loss {
            self.note_lifecycle_loss(loss);
        }
        self.note_capture_custody(&batch.custody);
    }

    /// Consumes one witness batch's count freshness (C7 C4 refresh
    /// loss): the batch's refresh failures, a completed-with-gaps
    /// refresh sweep, and a deadline-starved refresh sweep are count
    /// freshness, never silent: observed counts stand as lower bounds
    /// while every counted column reads lossy, withholding quiet.
    /// Bounded: one reason per batch (the first failure plus the
    /// count), memoized into gap repeats by the registry. Runs before
    /// AND after stop: a terminal-first failure demotes exactly like a
    /// live one (P1-5).
    fn note_count_freshness(&mut self, batch: &WitnessBatch) {
        let refresh_failures: Vec<&String> = batch
            .read_failures
            .iter()
            .filter(|failure| crate::attach::capture::is_refresh_failure(failure))
            .collect();
        // F1: a starved refresh (the window deadline hit before the
        // sweep completed) leaves tracked rows unvisited with no
        // failures or gaps — their counts may be stale, so quiet is
        // withheld exactly like a failed read.
        let starved = batch.refresh_deadline_reached && !batch.refresh_sweep_completed;
        if !refresh_failures.is_empty() || batch.refresh_sweep_gaps || starved {
            let mut reason = match refresh_failures.as_slice() {
                [] if starved && !batch.refresh_sweep_gaps => {
                    "the count-refresh sweep was starved by the window deadline before completing; \
                     tracked rows went unvisited and their counts may be stale"
                        .to_string()
                }
                [] => "a count-refresh sweep skipped a tracked row".to_string(),
                [first] => format!("1 count-refresh read failure: {first}"),
                [first, ..] => format!(
                    "{} count-refresh read failures (first: {first})",
                    refresh_failures.len()
                ),
            };
            if batch.refresh_sweep_gaps && !refresh_failures.is_empty() {
                reason.push_str("; the sweep skipped a tracked row");
            }
            if starved && (!refresh_failures.is_empty() || batch.refresh_sweep_gaps) {
                reason.push_str("; the refresh sweep was also starved by the window deadline");
            }
            self.registry.note_refresh_loss(reason);
        }
    }

    /// System scope: lifecycle evidence was lost (C5.2 D4). A lost exec or
    /// exit record may belong to any watched caller and cannot be
    /// localized, so every watch interval reaching past `at_ns` demotes to
    /// unknown, the loss is a gap, and — sticky — no watch starts again in
    /// this capture. Only the first loss stages anything.
    fn note_lifecycle_loss(&mut self, loss: &LifecycleLoss) {
        let Some(capture) = self.capture.as_mut().filter(|capture| !capture.stopped) else {
            return;
        };
        if capture.unproven.is_some() {
            return;
        }
        capture.unproven = Some(loss.reason.clone());
        self.registry.note_watch_demotion(
            "native capture lifecycle evidence lost",
            loss.reason.clone(),
            loss.at_ns,
        );
    }

    /// Native capture stops (stop begins or producers detach): no watch
    /// starts afterwards, and every ongoing watch ends at the last
    /// proven-clean witness read — its interval stays a frozen fact
    /// (`WatchedNoUse{since, until}`). A watch no clean read proved after
    /// its start reads unknown. A terminal read with unproven health is
    /// not clean, so it never extends an interval.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 stops native capture.
    pub(crate) fn end_capture_coverage(&mut self, at_ns: u64) {
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        if capture.stopped {
            return;
        }
        capture.stopped = true;
        let until = capture.last_clean_ns.map_or(0, |clean| clean.min(at_ns));
        self.registry.note_watch_end(
            "native capture stopped before a clean health read proved the watch",
            until,
        );
    }

    /// Whether `caller` (at `pid`) is the capture's scope incarnation.
    /// Binds the first matching caller.
    fn capture_scope_verdict(&mut self, caller: CallerId, pid: u32) -> ScopeVerdict {
        let Some(capture) = self.capture.as_mut() else {
            return ScopeVerdict::Outside;
        };
        let Some(scope) = capture.scope else {
            return ScopeVerdict::Inside;
        };
        if scope.pid != pid {
            return ScopeVerdict::Outside;
        }
        let start_time = self
            .adapter
            .record(caller)
            .and_then(|record| record.start_time);
        match (scope.start_time, start_time) {
            (Some(expected), Some(actual)) if expected != actual => return ScopeVerdict::Outside,
            (Some(_), Some(_)) => {}
            _ => return ScopeVerdict::Unproven,
        }
        match capture.bound {
            None => {
                capture.bound = Some(caller);
                ScopeVerdict::Inside
            }
            Some(bound) if bound == caller => ScopeVerdict::Inside,
            // Same incarnation, later image: an exec the entries may not
            // follow (custody reports it too).
            Some(_) => ScopeVerdict::LaterImage,
        }
    }

    /// The coverage note one mapped observation earns from the capture's
    /// receipts, or `None` (no native capture, the caller is outside the
    /// capture's scope, the module is not admitted — the registry then
    /// derives the edge's unknown reason itself — or health is unproven
    /// this pass, which withholds a watch without demoting one).
    ///
    /// `Watched` needs every endpoint the attach set admitted for the
    /// module attached, none failed, no member object modified in place, a
    /// whole (not partial) admission, scope custody intact, and the
    /// capture not stopped; `since` is the last of those attaches.
    fn capture_coverage_note(
        &self,
        scope: ScopeVerdict,
        key: &AttachModuleKey,
        verdict: Option<&AttachVerdict>,
    ) -> Option<CoverageNote> {
        let capture = self.capture.as_ref()?;
        let Some(AttachVerdict::Admitted { reasons, .. }) = verdict else {
            return None;
        };
        let unknown = |reason| Some(CoverageNote::Unknown(reason));
        let loss = |reason: &str| unknown(UnknownReason::Loss(reason.into()));
        match scope {
            ScopeVerdict::Outside => return None,
            ScopeVerdict::Unproven => return unknown(UnknownReason::IdentityUnavailable),
            ScopeVerdict::LaterImage => {
                return loss(
                    "a later image of the PID target: its scope custody covers the first image only",
                );
            }
            ScopeVerdict::Inside => {}
        }
        if let Some(reason) = &capture.unproven {
            return loss(reason);
        }
        if capture.stopped {
            // Ended watches are frozen facts: stage nothing over them.
            return None;
        }
        if !reasons.is_empty() {
            return if reasons
                .iter()
                .any(|reason| crate::plan::growth_omitted_count(reason).is_some())
            {
                unknown(UnknownReason::CapacityLimited(ENDPOINT_RESOURCE))
            } else {
                unknown(UnknownReason::NotAttached)
            };
        }
        let members = match self.attach_set.module_members(key) {
            Some(ModuleMembers::Known(members)) => members,
            Some(ModuleMembers::Unrecorded) => {
                return unknown(UnknownReason::CapacityLimited(MEMBERSHIP_RESOURCE));
            }
            // The verdict came from this set, so it holds the module.
            None => return unknown(UnknownReason::NotAttached),
        };
        if members.iter().any(|member| capture.failed.contains(member)) {
            return unknown(UnknownReason::AttachFailed);
        }
        if members.iter().any(|member| {
            self.attach_set
                .endpoint(*member)
                .is_some_and(|endpoint| capture.changed_objects.contains(&endpoint.object))
        }) {
            return loss("the provider was modified in place after it was attached");
        }
        let mut since_ns: Option<u64> = None;
        for member in members {
            let Some(&at_ns) = capture.attached_at.get(member) else {
                // Admitted, not attached yet (deferred to a later extend).
                return unknown(UnknownReason::NotAttached);
            };
            since_ns = Some(since_ns.map_or(at_ns, |since| since.max(at_ns)));
        }
        // C7 C4: pair-insert evidence voids no-use for good — the edge
        // reads `uncounted`, sticky, whatever this pass proves.
        if since_ns.is_some()
            && let Some(reason) = &capture.pairs_uncounted
        {
            return unknown(UnknownReason::Uncounted(reason.clone()));
        }
        match since_ns {
            Some(_) if capture.health_unproven.is_some() || capture.pairs_unproven.is_some() => {
                None
            }
            Some(since_ns) => Some(CoverageNote::Watched { since_ns }),
            // Admitted with no endpoint: nothing could observe its use.
            None => unknown(UnknownReason::NotAttached),
        }
    }

    /// Stages the capture coverage note for one mapped edge, right after
    /// its mapping note (so the edge exists when the batch applies it).
    fn stage_capture_coverage(
        &mut self,
        caller: CallerId,
        pid: u32,
        key: &ModuleKey,
        attach_key: Option<&AttachModuleKey>,
        verdict: Option<&AttachVerdict>,
    ) {
        let Some(attach_key) = attach_key else {
            return;
        };
        if self.capture.is_none() {
            return;
        }
        let scope = self.capture_scope_verdict(caller, pid);
        if let Some(loss) = self.preadmission_holds(caller, pid, key) {
            self.downgrade(caller, Some(key.clone()), loss);
            return;
        }
        if let Some(note) = self.capture_coverage_note(scope, attach_key, verdict) {
            self.registry.note_coverage(caller, key, note);
        }
    }

    /// The edge's coverage as presented: the staged coverage, except a
    /// watched edge reads unknown while the binder holds a pending row of
    /// its caller's pid on its module (DR-LIVE-LABEL-LAG). The row is a
    /// first use that may belong to this caller, so the watch cannot
    /// claim quiet; the staged watch is untouched and resumes once the
    /// row binds elsewhere. Positives, staged unknowns, and edges no
    /// pending row matches read as staged. Every consumer (JSON, the
    /// event stream, dashboard frames) presents through this.
    pub(crate) fn presented_coverage(&self, edge: &EdgeRecord) -> UseCoverage {
        let staged = self.registry.coverage(edge);
        if !matches!(staged, UseCoverage::WatchedNoUse { .. }) {
            return staged;
        }
        let pid = self.adapter.record(edge.caller).map(|record| record.pid);
        let key = self.registry.module(edge.module).map(|record| &record.key);
        let (Some(pid), Some(key)) = (pid, key) else {
            return staged;
        };
        let pending = self.binder.pending_rows().any(|row| {
            row.host_tgid == pid
                && self
                    .witness_modules(row)
                    .is_ok_and(|modules| modules.contains(key))
        });
        if pending {
            UseCoverage::Unknown(UnknownReason::PendingFirstUse)
        } else {
            staged
        }
    }

    #[cfg(test)]
    pub(crate) fn owner_of(&self, caller: CallerId) -> Option<ProcessViewId> {
        self.owners.get(&caller).copied()
    }

    /// Owned-fixture growth path: open one native owner through the real
    /// engine call, admit its caller, and bind the two — the same three
    /// steps `scan_pass` performs per pid, without a scope collection.
    /// Scale tests drive this over owned sleepers; admission failure
    /// after a successful open keeps the owner retained (no removal API
    /// exists) and says so in the error.
    #[cfg(test)]
    pub(crate) fn test_open_native_owner(
        &mut self,
        pid: u32,
        image: p11scope_ebpf_common::ImageIdentity,
        guard: &mut dyn super::inventory::ImageGuard,
        now_ns: u64,
    ) -> Result<CallerId> {
        let owner = self.engine.open_inventory_owner(pid, image, guard)?;
        let authority = ImageAuthority::NativeExact {
            task_cookie: image.task_cookie,
            exec_id: image.exec_id,
        };
        match self.adapter.admit(pid, authority, now_ns) {
            Ok(caller) => {
                self.owners.insert(caller, owner);
                Ok(caller)
            }
            Err(error) => Err(anyhow::anyhow!(
                "{error:#} (the native owner opened and stays retained)"
            )),
        }
    }

    pub(crate) fn passes(&self) -> u64 {
        self.passes
    }

    /// One scan pass: collect the scope, reconcile caller incarnations
    /// (attempting a native owner per newly admitted pid), scan every
    /// native owner through the core, and project scan-lane mappings.
    /// Every staged fact publishes at the next `commit_batch`, never
    /// before. `identity` supplies the owner lane's exact image per pid, or
    /// none (the scan lane: `ScanOnlyIdentity`). Hints and hooks are the
    /// engine's, fixed for the run. Production collects through
    /// `collector` (C5.7) and applies with `apply_catalog`.
    #[cfg(test)]
    pub(crate) fn scan_pass(
        &mut self,
        scope: &InventoryScope,
        max_scan_pids: Option<usize>,
        guard: &mut dyn ImageGuard,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        deadline_ns: u64,
        now_ns: u64,
    ) -> Result<PassReport> {
        let catalog = self.collector(*scope, max_scan_pids)()?;
        Ok(self.apply_catalog(catalog, guard, identity, deadline_ns, now_ns))
    }

    /// The pass's collection as an owned job (Task 6 C5.7): it reads
    /// `/proc` only, over its own copies of the run's fixed hints and hooks,
    /// and hands back its catalog. It borrows nothing of the coordinator, so
    /// it can run on a worker thread while the caller keeps servicing the
    /// native capture; every registry and binder mutation stays with
    /// `apply_catalog` on the caller's thread.
    pub(crate) fn collector(
        &self,
        scope: InventoryScope,
        max_scan_pids: Option<usize>,
    ) -> impl FnOnce() -> Result<crate::inspect_system::Catalog> + Send + 'static {
        // The catalog lowers its admission under the Inventory policy and
        // budget the attach set enforces, never the Detailed slot ceiling
        // `inspect` reports.
        let policy = crate::plan::AdmissionPolicy::Inventory(self.attach_set.budget());
        let hints = self.engine.module_hints.clone();
        let hooks = self.engine.hooks.clone();
        move || match scope {
            InventoryScope::Pid(pid) => {
                crate::inspect_system::collect_pid(pid, &hints, &hooks, policy)
            }
            InventoryScope::System => {
                crate::inspect_system::collect(&hints, &hooks, max_scan_pids, policy)
            }
        }
    }

    /// The pass after collection: absorb the lowering into the attach set,
    /// reconcile caller incarnations over every attributable member
    /// (deep-scanned or maps-matched), scan native owners, and project the
    /// catalog. Split from collection so scripted catalogs drive the same
    /// path (the workload harness).
    pub(crate) fn apply_catalog(
        &mut self,
        mut catalog: crate::inspect_system::Catalog,
        guard: &mut dyn ImageGuard,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        deadline_ns: u64,
        now_ns: u64,
    ) -> PassReport {
        let mut timings = std::mem::take(&mut catalog.stage_timings);
        // Absorb at once: the aggregate pins and their fds drop here, never
        // living across reconcile or the native owner scans below.
        let absorb_start = crate::attach::monotonic_ns();
        let verdicts = self.absorb_lowering(catalog.lowering.take());
        // Mapper counts size uprobe-multi links (C5.11 review M1), from a
        // whole-system view only (review R4).
        self.attach_set.note_mappers(
            self.engine.sees_whole_system(),
            catalog
                .objects
                .iter()
                .map(|object| (&object.key, object.mappings.len())),
        );
        timings.span(
            crate::timing::StageKind::Plan,
            "absorb",
            absorb_start,
            crate::attach::monotonic_ns(),
        );
        // Maps-matched members register exactly like deep-scanned ones:
        // same authority resolution (native owners included), same
        // incarnation pin. Their projection joins the generation below.
        let observed: BTreeSet<u32> = catalog
            .processes
            .iter()
            .filter(|process| process.status.attributable())
            .map(|process| process.pid)
            .collect();
        let scanned = observed.len();
        let maps_matched = catalog
            .processes
            .iter()
            .filter(|process| process.status == crate::inspect_system::MemberStatus::MapsMatched)
            .count();
        let mut resolver = AuthorityResolver {
            engine: &mut self.engine,
            pending: &mut self.pending_owners,
            guard,
            identity,
            native_failures: Vec::new(),
            scan_pinned: 0,
        };
        let reconcile_start = crate::attach::monotonic_ns();
        let mut events =
            self.adapter
                .reconcile(&observed, &mut |pid| resolver.resolve(pid), now_ns);
        let (native_failures, scan_pinned) = resolver.finish();
        self.apply_reconcile_events(&events, now_ns);
        self.record_authority_gaps(native_failures, scan_pinned);
        events.extend(self.revalidate_for_exec_coverage(identity, now_ns));
        timings.span(
            crate::timing::StageKind::Projection,
            "reconcile",
            reconcile_start,
            crate::attach::monotonic_ns(),
        );
        // Native scans for live native callers, through the core.
        let mut pending_refresh = Vec::new();
        let mut engine_changed = false;
        let native: Vec<(CallerId, ProcessViewId)> = self
            .owners
            .iter()
            .filter(|(caller, _)| {
                self.adapter
                    .record(**caller)
                    .is_some_and(|record| !record.retired)
            })
            .map(|(caller, owner)| (*caller, *owner))
            .collect();
        for (caller, owner) in &native {
            match self.scan_owner(*owner, guard, deadline_ns, now_ns) {
                Ok(commit) => {
                    engine_changed |= commit.changed;
                    if commit.refresh_pending {
                        pending_refresh.push(*caller);
                    }
                    self.project_native_commit(*caller, *owner, &commit, &verdicts, now_ns);
                }
                Err(error) => {
                    self.registry.record_gap(RegistryGap {
                        caller: Some(*caller),
                        module: None,
                        pid: self.adapter.record(*caller).map(|record| record.pid),
                        subject: "native inventory scan failed".into(),
                        reason: format!("{error:#}"),
                        budget: None,
                    });
                }
            }
        }
        // Scan-lane projection for every inventoried member, including
        // native callers (the catalog carries admission verdicts the
        // registry needs either way).
        let project_start = crate::attach::monotonic_ns();
        self.project_catalog(&catalog, &verdicts, now_ns);
        timings.span(
            crate::timing::StageKind::Projection,
            "project",
            project_start,
            crate::attach::monotonic_ns(),
        );
        // Owners that never committed a complete receipt cannot back
        // absence claims: absences for their callers stay uncertain, and
        // the gap says so.
        for (caller, owner) in &native {
            match self.engine.inventory_last_complete(*owner) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    self.registry.record_gap(RegistryGap {
                        caller: Some(*caller),
                        module: None,
                        pid: self.adapter.record(*caller).map(|record| record.pid),
                        subject: "no complete inventory scan".into(),
                        reason: "only partial receipts committed for this owner; absences for its caller are uncertain"
                            .into(),
                        budget: None,
                    });
                }
                Err(error) => {
                    self.registry.record_gap(RegistryGap {
                        caller: Some(*caller),
                        module: None,
                        pid: self.adapter.record(*caller).map(|record| record.pid),
                        subject: "native owner lost".into(),
                        reason: format!("{error:#}"),
                        budget: None,
                    });
                }
            }
        }
        let native_callers = native.len();
        let pass = self.passes;
        self.passes += 1;
        PassReport {
            pass,
            scanned,
            maps_matched,
            native_callers,
            scan_callers: observed.len().saturating_sub(native_callers),
            engine_changed,
            pending_refresh,
            events,
            timings,
        }
    }

    /// One pass with no scan behind it: the collection failed after at
    /// least one successful pass (a `--pid` target that exited
    /// mid-observation, a transient enumeration loss). Lifecycle still
    /// reconciles — pins and exit proofs need no scan — while live
    /// callers become unscanned-uncertain and the failure is a gap.
    /// Never a silent skip, and never a reason to drop the run.
    pub(crate) fn observe_empty_pass(
        &mut self,
        guard: &mut dyn ImageGuard,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        reason: &str,
        now_ns: u64,
    ) -> PassReport {
        let mut resolver = AuthorityResolver {
            engine: &mut self.engine,
            pending: &mut self.pending_owners,
            guard,
            identity,
            native_failures: Vec::new(),
            scan_pinned: 0,
        };
        let mut events =
            self.adapter
                .reconcile(&BTreeSet::new(), &mut |pid| resolver.resolve(pid), now_ns);
        let (native_failures, scan_pinned) = resolver.finish();
        self.apply_reconcile_events(&events, now_ns);
        self.record_authority_gaps(native_failures, scan_pinned);
        events.extend(self.revalidate_for_exec_coverage(identity, now_ns));
        let live: Vec<CallerId> = self
            .adapter
            .records()
            .filter(|record| !record.retired)
            .map(|record| record.id)
            .collect();
        for caller in &live {
            self.registry.note_member_unscanned(*caller);
        }
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "scan pass produced no observation".into(),
            reason: reason.to_string(),
            budget: None,
        });
        let native_callers = live
            .iter()
            .filter(|caller| self.owners.contains_key(caller))
            .count();
        let pass = self.passes;
        self.passes += 1;
        PassReport {
            pass,
            scanned: 0,
            maps_matched: 0,
            native_callers,
            scan_callers: live.len().saturating_sub(native_callers),
            engine_changed: false,
            pending_refresh: Vec::new(),
            events,
            timings: crate::timing::StageTimings::new(),
        }
    }

    /// Stage retirements for reconciled events, bind freshly opened
    /// native owners to their callers, and gap admission failures. The
    /// workload harness reuses this after scripted reconciles so staged
    /// facts follow the same path as scanned ones.
    pub(crate) fn apply_reconcile_events(&mut self, events: &[CallerEvent], now_ns: u64) {
        let mut failed: Vec<(u32, &str, Option<BudgetRefusal>)> = Vec::new();
        for event in events {
            let id = match event {
                CallerEvent::Admitted { id }
                | CallerEvent::ExecRetired { new: id, .. }
                | CallerEvent::Reused { new: id, .. } => *id,
                CallerEvent::Exited { id, .. } => {
                    self.retire_caller_in_registry(*id, now_ns);
                    continue;
                }
                CallerEvent::AdmitFailed {
                    pid,
                    reason,
                    budget,
                } => {
                    if self.pending_owners.remove(pid).is_some() {
                        // The native owner opened but the caller pin
                        // failed (an exit raced admission): no removal
                        // API exists, so the owner stays retained under
                        // the owner cap and the gap says so.
                        self.registry.record_gap(RegistryGap {
                            caller: None,
                            module: None,
                            pid: Some(*pid),
                            subject: "native owner without caller".into(),
                            reason: format!(
                                "the native owner opened but caller admission failed ({reason}); the owner stays retained"
                            ),
                            budget: None,
                        });
                    }
                    failed.push((*pid, reason.as_str(), *budget));
                    continue;
                }
            };
            if let CallerEvent::ExecRetired { old, .. } | CallerEvent::Reused { old, .. } = event {
                self.retire_caller_in_registry(*old, now_ns);
            }
            let pid = self.adapter.record(id).map(|record| record.pid);
            if let Some(pid) = pid
                && let Some(owner) = self.pending_owners.remove(&pid)
            {
                self.owners.insert(id, owner);
            }
        }
        self.record_admission_failures(&failed);
    }

    /// Admission failures, one gap per pass and kind rather than one per
    /// pid per pass (C1b ruling 4): at system scale a full caller budget
    /// refuses every new caller every pass. A single failure keeps its
    /// exact per-pid record; several aggregate with a count — budget
    /// refusals carry the budget (the highest occupancy requested), pin
    /// failures name the first.
    fn record_admission_failures(&mut self, failed: &[(u32, &str, Option<BudgetRefusal>)]) {
        let (refused, unpinned): (Vec<_>, Vec<_>) =
            failed.iter().partition(|(_, _, budget)| budget.is_some());
        for group in [refused, unpinned] {
            match group.as_slice() {
                [] => {}
                [(pid, reason, budget)] => self.registry.record_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: Some(*pid),
                    subject: "caller admission failed".into(),
                    reason: (*reason).to_string(),
                    budget: *budget,
                }),
                [(first_pid, first_reason, _), ..] => {
                    let budget = group
                        .iter()
                        .filter_map(|(_, _, budget)| *budget)
                        .max_by_key(|budget| budget.requested);
                    let reason = match budget {
                        Some(budget) => format!(
                            "{} admissions refused this pass: caller budget exhausted: the \
                             registry retains at most {} callers; the admissions were refused",
                            group.len(),
                            budget.limit
                        ),
                        None => format!(
                            "{} pids could not be admitted this pass; first: pid {first_pid}: \
                             {first_reason}",
                            group.len()
                        ),
                    };
                    self.registry.record_gap(RegistryGap {
                        caller: None,
                        module: None,
                        pid: None,
                        subject: "caller admission failed".into(),
                        reason,
                        budget,
                    });
                }
            }
        }
    }

    fn retire_caller_in_registry(&mut self, id: CallerId, now_ns: u64) {
        let reason = self
            .adapter
            .record(id)
            .and_then(|record| record.lifecycle_reason.clone())
            .unwrap_or_else(|| "caller retired".into());
        self.registry.retire_caller(id, reason, now_ns);
    }

    /// Authority gaps: per-caller where a native open was attempted and
    /// failed (a real signal), once per run where no native identity
    /// exists at all (the scan lane).
    fn record_authority_gaps(&mut self, native_failures: Vec<(u32, String)>, scan_pinned: usize) {
        for (pid, reason) in native_failures {
            self.registry.record_gap(RegistryGap {
                caller: self.adapter.live_id(pid),
                module: None,
                pid: Some(pid),
                subject: "native inventory owner unavailable".into(),
                reason: format!("{reason}; scan-lane incarnation by pidfd/start-time"),
                budget: None,
            });
        }
        if scan_pinned > 0 && !self.authority_gap_recorded {
            self.authority_gap_recorded = true;
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "exact image authority unavailable".into(),
                reason: "no BPF image identity; scan-lane incarnations by pidfd/start-time with exe-identity exec detection"
                    .into(),
                budget: None,
            });
        }
    }

    /// One native owner through the core: refresh request, lease, I4a
    /// window, scan, prepare, commit (which revalidates at the
    /// publication boundary). The lease releases on every path.
    fn scan_owner(
        &mut self,
        owner: ProcessViewId,
        guard: &mut dyn ImageGuard,
        deadline_ns: u64,
        now_ns: u64,
    ) -> Result<InventoryCommit> {
        let cause = if !self.scanned_owners.contains(&owner) {
            // Admission scan: scope membership was verified at open;
            // re-verify it at the first scan boundary.
            RefreshCause::ScopeRecheck
        } else if self.churned_owners.remove(&owner) {
            // The previous pass observed mapping churn for this owner:
            // a post-hoc loader hint, honestly labeled.
            RefreshCause::LoaderHint
        } else {
            RefreshCause::Periodic
        };
        self.engine.request_inventory_refresh(owner, cause)?;
        if deadline_ns <= now_ns {
            // The pass ran out of time before this owner: defer through
            // the receipt vocabulary, so preparation refuses with the
            // canonical reason and the refresh request stays pending.
            let receipt = ScanReceipt::Deferred {
                owner,
                reason: DEADLINE_DEFERRED,
            };
            let prepared = self
                .engine
                .prepare_inventory_reconciliation(receipt, guard)?;
            return self.engine.commit_inventory_reconciliation(prepared, guard);
        }
        let lease = self.engine.acquire_inventory_scan(owner)?;
        let result = (|| {
            let id = self.next_window;
            self.next_window = self.next_window.saturating_add(1);
            let window = self
                .engine
                .budget
                .begin_window(WindowId::new(id), deadline_ns)
                .map_err(anyhow::Error::msg)?;
            let checkpoint = self
                .engine
                .budget
                .checkpoint(window.clone())
                .map_err(anyhow::Error::msg)?;
            let receipt = self.engine.scan_inventory_owner(&lease, guard)?;
            self.engine
                .budget
                .finish_scan(checkpoint)
                .map_err(anyhow::Error::msg)?;
            self.engine
                .budget
                .finish_window(window)
                .map_err(anyhow::Error::msg)?;
            let prepared = self
                .engine
                .prepare_inventory_reconciliation(receipt, guard)?;
            // I3: commit revalidates after the synchronous gap above;
            // preparation alone grants nothing.
            self.engine.commit_inventory_reconciliation(prepared, guard)
        })();
        let release = self.engine.release_inventory_scan(&lease);
        match (result, release) {
            (Ok(commit), Ok(())) => {
                self.scanned_owners.insert(owner);
                Ok(commit)
            }
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    /// Project one native commit into the registry: committed modules of
    /// this owner become mapping evidence; previously mapped edges the
    /// commit no longer shows become absences (authoritative only when
    /// the receipt was complete).
    fn project_native_commit(
        &mut self,
        caller: CallerId,
        owner: ProcessViewId,
        commit: &InventoryCommit,
        verdicts: &BTreeMap<AttachModuleKey, AttachVerdict>,
        now_ns: u64,
    ) {
        let pid = self
            .adapter
            .record(caller)
            .map(|record| record.pid)
            .unwrap_or(0);
        let modules: Vec<(ModuleKey, ModuleInfo, AttachModuleKey)> = self
            .engine
            .modules
            .iter()
            .filter(|module| module.scanned.view == owner)
            .filter_map(|module| {
                let summary = self.engine.pinned.summary(module.object)?;
                let sha256 = summary.sha256.to_string();
                let attach_key = AttachModuleKey {
                    object: module.scanned.key,
                    sha256: sha256.clone(),
                };
                let verdict = verdicts.get(&attach_key);
                let key = ModuleKey::physical(
                    module.scanned.key.device.major,
                    module.scanned.key.device.minor,
                    module.scanned.key.inode,
                    Some(sha256),
                    &module.scanned.path,
                );
                Some((
                    key.clone(),
                    native_module_info(&self.engine, module, key, verdict),
                    attach_key,
                ))
            })
            .collect();
        for (key, info, attach_key) in &modules {
            self.registry
                .note_mapping(caller, pid, info.clone(), now_ns);
            let verdict = verdicts.get(attach_key);
            self.stage_capture_coverage(caller, pid, key, Some(attach_key), verdict);
        }
        // Absences are evaluated against the last published snapshot:
        // edges the commit no longer shows, for this caller only.
        let committed: BTreeSet<ModuleKey> =
            modules.iter().map(|(key, _, _)| key.clone()).collect();
        let mut absent = false;
        for edge in self
            .registry
            .edges_of(caller)
            .filter(|edge| matches!(edge.mapping, MappingState::Mapped | MappingState::Uncertain))
            .map(|edge| (edge.module, edge.mapping))
            .collect::<Vec<_>>()
        {
            let shown = self
                .registry
                .module(edge.0)
                .is_some_and(|module| committed.contains(&module.key));
            if !shown {
                self.registry
                    .note_module_absent(caller, edge.0, commit.complete, now_ns);
                absent = commit.complete && edge.1 == MappingState::Mapped;
            }
        }
        if absent {
            // Mapping churn observed: the next pass scans this owner
            // under a loader hint.
            self.churned_owners.insert(owner);
        }
    }

    /// The attach set absorbs one pass's Inventory lowering: its delta
    /// joins the pending targets, its gaps stage in the registry, and its
    /// verdicts return for the catalog projection. The lowering — the
    /// aggregate pins and their fds included — drops on return; the set
    /// keeps only the objects it retained.
    fn absorb_lowering(
        &mut self,
        lowering: Option<crate::inspect_system::CatalogLowering>,
    ) -> BTreeMap<AttachModuleKey, AttachVerdict> {
        let Some(lowering) = lowering else {
            return BTreeMap::new();
        };
        let absorbed = self.attach_set.absorb(&lowering.plan, &lowering.pins);
        drop(lowering);
        self.pending_targets.append(absorbed.delta);
        for gap in absorbed.gaps {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: gap.subject,
                reason: gap.reason,
                budget: gap
                    .budget
                    .map(|(resource, limit, requested)| BudgetRefusal {
                        resource,
                        limit,
                        requested,
                    }),
            });
        }
        absorbed.verdicts
    }

    /// Project one catalog pass into the registry, per member: its
    /// mappings (deep-scanned or maps-matched) carrying the attach set's
    /// admission verdicts, its absences (authoritative only for a complete
    /// deep scan — never for a maps match), unscanned-member uncertainty,
    /// and the catalog gaps. A member projects only when the generation it
    /// was collected under joins the caller incarnation reconcile holds
    /// for its pid (start time, both present; and the exe identity), so a
    /// reused pid or a later exec never inherits mappings. Each caller's
    /// edges come from a per-caller range query, never a scan of all edges.
    fn project_catalog(
        &mut self,
        catalog: &crate::inspect_system::Catalog,
        verdicts: &BTreeMap<AttachModuleKey, AttachVerdict>,
        now_ns: u64,
    ) {
        use crate::inspect_system::{MemberStatus, ObservationEvidence};
        let mut by_pid: BTreeMap<u32, Vec<(usize, usize)>> = BTreeMap::new();
        for (object_index, object) in catalog.objects.iter().enumerate() {
            for (observation_index, observation) in object.observations.iter().enumerate() {
                by_pid
                    .entry(observation.pid)
                    .or_default()
                    .push((object_index, observation_index));
            }
        }
        let mut join_losses: BTreeMap<AttributionLoss, usize> = BTreeMap::new();
        for process in &catalog.processes {
            let Some(caller) = self.adapter.live_id(process.pid) else {
                continue;
            };
            if !process.status.attributable() {
                self.registry.note_member_unscanned(caller);
                continue;
            }
            if let Err(loss) = self.generation_join(caller, process) {
                *join_losses.entry(loss).or_default() += 1;
                // The collected mappings belong to another generation or
                // image: they neither confirm nor refute this caller's.
                self.registry.note_member_unscanned(caller);
                continue;
            }
            // One mapping note per observation (not per object path):
            // aliased objects are observed under several paths and the
            // registry accumulates every spelling.
            for &(object_index, observation_index) in by_pid.get(&process.pid).into_iter().flatten()
            {
                let object = &catalog.objects[object_index];
                let observation = &object.observations[observation_index];
                let attach_key = object.sha256.as_ref().map(|sha256| AttachModuleKey {
                    object: object.key,
                    sha256: sha256.clone(),
                });
                let verdict = attach_key.as_ref().and_then(|key| verdicts.get(key));
                let mut info = catalog_module_info(object, verdict);
                info.path = observation.path.clone();
                info.double_loaded = observation.double_loaded;
                let key = info.key.clone();
                match observation.evidence {
                    ObservationEvidence::DeepScan => {
                        self.registry
                            .note_mapping(caller, process.pid, info, now_ns);
                    }
                    ObservationEvidence::MapsMatch => {
                        self.registry
                            .note_maps_match(caller, process.pid, info, now_ns);
                    }
                }
                self.stage_capture_coverage(
                    caller,
                    process.pid,
                    &key,
                    attach_key.as_ref(),
                    verdict,
                );
            }
            // Only a complete deep scan makes absence authoritative: a
            // maps match decoded nothing, so its absences read uncertain.
            let complete = matches!(process.status, MemberStatus::Scanned);
            let shown: BTreeSet<ModuleKey> = process
                .objects
                .iter()
                .filter_map(|index| catalog.objects.get(*index))
                .map(catalog_module_key)
                .collect();
            let mut absent = false;
            for (module, mapping) in self
                .registry
                .edges_of(caller)
                .filter(|edge| {
                    matches!(edge.mapping, MappingState::Mapped | MappingState::Uncertain)
                })
                .map(|edge| (edge.module, edge.mapping))
                .collect::<Vec<_>>()
            {
                let shown = self
                    .registry
                    .module(module)
                    .is_some_and(|record| shown.contains(&record.key));
                if !shown {
                    self.registry
                        .note_module_absent(caller, module, complete, now_ns);
                    absent = complete && mapping == MappingState::Mapped;
                }
            }
            if absent && let Some(owner) = self.owners.get(&caller).copied() {
                self.churned_owners.insert(owner);
            }
        }
        if !join_losses.is_empty() {
            let parts: Vec<String> = join_losses
                .iter()
                .map(|(loss, count)| format!("{count} {}", loss.label()))
                .collect();
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "caller generation join refused".into(),
                reason: format!(
                    "members whose collected generation is not the admitted caller incarnation \
                     were not projected (their edges read uncertain): {}",
                    parts.join(", ")
                ),
                budget: None,
            });
        }
        for gap in catalog.skipped.iter().chain(catalog.notes.iter()) {
            self.registry.record_gap(RegistryGap {
                caller: gap.pid.and_then(|pid| self.adapter.live_id(pid)),
                module: None,
                pid: gap.pid,
                subject: gap.subject.clone(),
                reason: gap.reason.clone(),
                budget: None,
            });
        }
    }

    /// Whether a member's collected generation is the caller incarnation
    /// reconcile holds: equal start times, both present (both lanes); for a
    /// maps match also equal exe identities, both present; for a deep scan
    /// unequal exe identities refuse when both were read.
    fn generation_join(
        &self,
        caller: CallerId,
        process: &crate::inspect_system::ProcessRecord,
    ) -> Result<(), AttributionLoss> {
        let record = self
            .adapter
            .record(caller)
            .ok_or(AttributionLoss::GenerationChanged)?;
        let generation = process
            .generation
            .as_ref()
            .ok_or(AttributionLoss::GenerationChanged)?;
        match (generation.start_time, record.start_time) {
            (Some(collected), Some(admitted)) if collected == admitted => {}
            _ => return Err(AttributionLoss::GenerationChanged),
        }
        let matched = process.status == crate::inspect_system::MemberStatus::MapsMatched;
        match (&generation.exe, &record.exe) {
            (Some(collected), Some(admitted)) if collected != admitted => {
                Err(AttributionLoss::ExecChanged)
            }
            (Some(_), Some(_)) => Ok(()),
            _ if matched => Err(AttributionLoss::ConfirmUnreadable),
            _ => Ok(()),
        }
    }

    /// The one native staging call (plan §3.6): witness reads, lifecycle
    /// quanta and the final flush all enter here, before `commit_batch`.
    /// A witness read also forwards its health and custody to capture
    /// coverage (`note_witness_batch`); after `end_capture_coverage` that
    /// half stages nothing, while witnessed use — a positive fact — still
    /// binds and stages. Rows are decided by the binder (§3.3); decided
    /// rows stage as edge witnesses or module-level unbound use, and a
    /// proven exec transition retires its incarnation and admits the
    /// successor (the receipt carries those events). The binder census is
    /// staged with every call.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 drives native capture.
    pub(crate) fn stage_native(
        &mut self,
        batch: NativeBatch,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        now_ns: u64,
    ) -> NativeReceipt {
        match batch {
            NativeBatch::Witness(batch) => {
                // The binder absorbs before the batch's health is noted:
                // the clean-read decision must see this batch's undecided
                // rows (a stamped pending row withholds the proven-clean
                // instant). Absorption stages no registry mutation, so
                // staging order is unchanged.
                self.binder
                    .absorb_witnesses(&batch, &self.adapter, &mut *identity);
                self.note_witness_batch(&batch);
                self.record_witness_integrity(&batch);
                // Counts merge before the binder's decisions stage, so a
                // row that binds in this batch stages with its refresh.
                self.absorb_pair_counts(&batch);
            }
            NativeBatch::Lifecycle(batch) => {
                self.lifecycle_high_water_bytes = self
                    .lifecycle_high_water_bytes
                    .max(batch.drain_high_water_bytes);
                self.binder.absorb_lifecycle(&batch)
            }
            NativeBatch::Finish { domain } => self.binder.finish(domain),
        }
        self.stage_binder_output(identity, now_ns)
    }

    /// The exec-coverage revalidation (C1 ruling): for every domain whose
    /// coverage began no later than this pass started (`pass_start_ns`),
    /// the incarnations admitted before that coverage that this pass —
    /// after its reconcile — still finds unchanged. Rows of the others
    /// become `exec_coverage_gap`. Only the first qualifying pass counts.
    /// Returns the incarnation events of rows the pass released.
    fn revalidate_for_exec_coverage(
        &mut self,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        pass_start_ns: u64,
    ) -> Vec<CallerEvent> {
        let due = self.binder.revalidation_due(pass_start_ns);
        if due.is_empty() {
            return Vec::new();
        }
        for (domain, coverage_start) in due {
            let revalidated = self.adapter.revalidate_admitted_before(coverage_start);
            self.binder
                .note_revalidation(domain, pass_start_ns, revalidated);
        }
        self.stage_binder_output(identity, pass_start_ns).events
    }

    /// Stages what the binder decided since the last call: decided rows,
    /// then proven exec transitions, then the census.
    fn stage_binder_output(
        &mut self,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        now_ns: u64,
    ) -> NativeReceipt {
        let decisions = self.binder.take_decisions();
        let decided = decisions.len();
        let mut unresolved: Vec<String> = Vec::new();
        for decision in decisions {
            if let Err(reason) = self.stage_witness(decision) {
                self.registry.note_unresolved_witness();
                unresolved.push(reason);
            }
        }
        if let Some(first) = unresolved.first() {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "native witness without a module".into(),
                reason: format!(
                    "{} witness row(s) named no admitted module this batch (first: {first}); \
                     their use is object-level only and is not shown",
                    unresolved.len()
                ),
                budget: None,
            });
        }
        let mut events = Vec::new();
        for transition in self.binder.take_transitions() {
            events.extend(self.apply_exec_transition(transition, &mut *identity, now_ns));
        }
        self.apply_reconcile_events(&events, now_ns);
        self.registry
            .note_witness_census(self.binder.census().clone());
        NativeReceipt { events, decided }
    }

    /// One witness read's integrity rows: never bound, never dropped
    /// silently — one gap per read that had any.
    fn record_witness_integrity(&mut self, batch: &WitnessBatch) {
        let Some(first) = batch.integrity.first() else {
            return;
        };
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "native witness rows failed validation".into(),
            reason: format!(
                "{} CALLER_USE row(s) failed validation in this read (first: {}); {} so far \
                 this capture; they are integrity evidence and never bind",
                batch.integrity.len(),
                first.reason,
                batch.integrity_total
            ),
            budget: None,
        });
    }

    /// Merges one witness read's counts (C7 C4): each row's first-sight
    /// `entry_count` and each refresh count join their pair by maximum
    /// (with the observing read), and bound pairs whose count advanced
    /// past the registry stage — after re-resolving their placement
    /// (F7). Counts for dropped pairs never merge: the row persists in
    /// the map, so its refresh would otherwise hold memory for a pair
    /// that never publishes. Runs after stop too: a count is a
    /// positive fact, like its witness.
    fn absorb_pair_counts(&mut self, batch: &WitnessBatch) {
        for row in &batch.rows {
            let key = PairKey::of(row);
            if matches!(self.pair_targets.get(&key), Some(PairTarget::Dropped)) {
                continue;
            }
            let held = self.pair_counts.entry(key).or_insert(PairCount {
                count: 0,
                first_ns: row.recorded_at_ns,
                last_ns: batch.rows_read_ns,
            });
            // The row sets its first record whatever arrived before: a
            // refresh can only precede it in a scripted batch.
            held.first_ns = row.recorded_at_ns;
            if row.entry_count > held.count {
                held.count = row.entry_count;
                held.last_ns = batch.rows_read_ns;
            }
        }
        let mut recheck = Vec::new();
        let mut retry = Vec::new();
        for update in &batch.counts {
            let key = PairKey::of_update(batch.domain, update);
            if matches!(self.pair_targets.get(&key), Some(PairTarget::Dropped)) {
                continue;
            }
            let held = {
                let held = self.pair_counts.entry(key).or_insert(PairCount {
                    count: 0,
                    first_ns: batch.rows_read_ns,
                    last_ns: batch.rows_read_ns,
                });
                if update.count > held.count {
                    held.count = update.count;
                    held.last_ns = batch.rows_read_ns;
                }
                *held
            };
            match self.pair_targets.get(&key) {
                Some(PairTarget::Bound {
                    caller,
                    module,
                    endpoint,
                    base,
                }) => recheck.push((
                    key,
                    *caller,
                    module.clone(),
                    *endpoint,
                    update.object,
                    held,
                    *base,
                )),
                Some(PairTarget::Pending {
                    caller,
                    modules,
                    staged,
                    base,
                    ..
                }) => retry.push((key, *caller, modules.clone(), held, *staged, *base)),
                _ => {}
            }
        }
        // Pending pairs never resolve against the pre-publish
        // committed snapshot here (P3): a mapping staged in this same
        // window is invisible to it, and a later mapping must not
        // promote a count whose witness already went module-level. An
        // advance past what is staged re-stages pending; the publication
        // decides, and its decisions finalize the target.
        for (key, caller, modules, count, staged, base) in retry {
            if count.count > staged {
                self.stage_pending_count(key, caller, &modules, rebased_count(count, base));
                if let Some(PairTarget::Pending { staged: was, .. }) =
                    self.pair_targets.get_mut(&key)
                {
                    *was = count.count;
                }
            }
        }
        // Bound pairs re-resolve (F7): sharing that appeared after the
        // pair bound makes further growth ambiguous, so the pair
        // re-resolves pending at publication instead of staging to its
        // cached edge. Staging compares against the registry, not a
        // coordinator copy: only an advance past the staged count
        // stages, so a repeated refresh is free and several reads per
        // commit stay sound.
        for (key, caller, module, endpoint, object, count, base) in recheck {
            let admitted = self.update_modules_for_endpoint(endpoint, object);
            let confirmed = match &admitted {
                Ok(modules) => {
                    // The admitted set itself must be exactly the cached
                    // module (round 3, F3-01): an admitted-but-unpublished
                    // sharer (its mapping stages, no commit yet) reads
                    // edged == [cached] against the committed snapshot,
                    // and confirming there would stage up to one pass's
                    // shared growth to the cached arm. Anything else
                    // re-resolves pending and lets publication decide.
                    if modules.len() != 1 || modules[0] != module {
                        false
                    } else {
                        let mut edged = modules.iter().filter(|key| {
                            self.registry
                                .module_id_for(key)
                                .is_some_and(|id| self.registry.edge(caller, id).is_some())
                        });
                        matches!((edged.next(), edged.next()), (Some(only), None) if *only == module)
                    }
                }
                Err(()) => false,
            };
            let staged = self
                .registry
                .module_id_for(&module)
                .and_then(|id| self.registry.edge(caller, id))
                .map(|edge| edge.entry_count)
                .unwrap_or(0);
            if confirmed {
                let growth = rebased_count(count, base);
                if growth.count > staged {
                    self.stage_pair_count(caller, &module, growth);
                }
                continue;
            }
            let modules = admitted.unwrap_or_default();
            // The demoted total stays behind (F3-03): history attributed
            // so far — the old base plus the bound edge's count — is the
            // new base, so only post-demotion growth ever stages
            // elsewhere; the stale edge keeps exactly its history.
            let new_base = base.saturating_add(staged);
            self.pair_targets.insert(
                key,
                PairTarget::Pending {
                    caller,
                    modules: modules.clone(),
                    staged: new_base,
                    endpoint,
                    base: new_base,
                },
            );
            if count.count > new_base {
                self.stage_pending_count(key, caller, &modules, rebased_count(count, new_base));
                if let Some(PairTarget::Pending { staged: was, .. }) =
                    self.pair_targets.get_mut(&key)
                {
                    *was = count.count;
                }
            }
        }
    }

    /// The admitted modules a count update's endpoint resolves to (F7):
    /// the update-side twin of [`Self::witness_modules`] — the
    /// endpoint must be in the attach set and name the update's
    /// object. `Err` fails closed (the pair re-resolves pending with
    /// no modules and finalizes dropped).
    fn update_modules_for_endpoint(
        &self,
        endpoint: EndpointId,
        object: AttachObjectId,
    ) -> Result<Vec<ModuleKey>, ()> {
        let entry = self.attach_set.endpoint(endpoint).ok_or(())?;
        if entry.object != object {
            return Err(());
        }
        self.admitted_modules_for_endpoint(endpoint).map_err(|_| ())
    }

    /// Stages one pair's count to its edge (C7 C4): the (base-rebased,
    /// growth-only past demotion — absolute for an unbased pair) count
    /// plus the counting-feed note, so the edge reads `counted`. Only
    /// for admitted modules and counts ≥ 1 — anything else leaves the
    /// witness standing, and the staging self-heals on the next
    /// refresh after admission.
    fn stage_pair_count(&mut self, caller: CallerId, module: &ModuleKey, count: PairCount) {
        if count.count == 0 {
            return;
        }
        let admitted = self
            .registry
            .module_id_for(module)
            .and_then(|id| self.registry.module(id))
            .is_some_and(|record| record.admission == AdmissionState::Admitted);
        if !admitted {
            return;
        }
        self.registry
            .note_counted_use(caller, module, count.count, count.first_ns, count.last_ns);
        self.registry.note_coverage(
            caller,
            module,
            CoverageNote::Counted {
                since_ns: count.first_ns,
            },
        );
    }

    /// Records one bound row's pair target (P3): the pair always
    /// starts pending — placement resolves at publication, together
    /// with the witness, against the mappings the publication commits
    /// (including this same window's). Nothing here reads the
    /// pre-publish committed snapshot: a single committed edge proves
    /// nothing while a second mapping stages, and caching `Bound` from
    /// it would attribute the count where the witness reads ambiguous.
    /// The held count (first sight merged with any refresh) stages
    /// pending with the bind; the publication's decisions finalize the
    /// target as `Bound` or `Dropped`.
    fn bind_pair_count(&mut self, row: &WitnessRow, caller: CallerId, modules: &[ModuleKey]) {
        let key = PairKey::of(row);
        self.pair_targets.insert(
            key,
            PairTarget::Pending {
                caller,
                modules: modules.to_vec(),
                staged: 0,
                endpoint: row.endpoint,
                base: 0,
            },
        );
        if let Some(count) = self.pair_counts.get(&key).copied()
            && count.count > 0
        {
            self.stage_pending_count(key, caller, modules, count);
            if let Some(PairTarget::Pending { staged, .. }) = self.pair_targets.get_mut(&key) {
                *staged = count.count;
            }
        }
    }

    /// Stages one pending pair's held count for publication-time
    /// placement (P3): the (base-rebased, growth-only past demotion —
    /// absolute for an unbased pair) count, only for counts ≥ 1 —
    /// anything else leaves the witness standing, and a later advance
    /// re-stages. The minted handle maps the publication's decision
    /// back to the pair.
    fn stage_pending_count(
        &mut self,
        key: PairKey,
        caller: CallerId,
        modules: &[ModuleKey],
        count: PairCount,
    ) {
        if count.count == 0 {
            return;
        }
        let pending_id = self.next_pending_id;
        self.next_pending_id = self.next_pending_id.wrapping_add(1);
        self.pending_ids.insert(pending_id, key);
        self.registry.note_pending_count(
            pending_id,
            caller,
            modules.to_vec(),
            count.count,
            count.first_ns,
            count.last_ns,
        );
    }

    /// Finalizes pending pair placements from the publication's
    /// decisions (P3): a placed pair caches `Bound` — only now, after
    /// the publication decided — so later advances stage to its edge; a
    /// rejected pair (ambiguity, no edge) finalizes `Dropped` with its
    /// held count removed, so a later mapping can never promote a count
    /// whose witness already went module-level. An unadmitted single
    /// stays pending and re-resolves on the next advance. Unknown
    /// handles (a pair re-bound after its decision staged) are ignored:
    /// the newer bind's own decision finalizes it.
    fn finalize_pending_counts(&mut self) {
        for decision in self.registry.take_pending_count_decisions() {
            let Some(key) = self.pending_ids.remove(&decision.pending_id) else {
                continue;
            };
            match decision.outcome {
                PendingCountOutcome::Placed { module } => {
                    if let Some(PairTarget::Pending {
                        caller,
                        endpoint,
                        base,
                        ..
                    }) = self.pair_targets.get(&key)
                    {
                        let (caller, endpoint, base) = (*caller, *endpoint, *base);
                        self.pair_targets.insert(
                            key,
                            PairTarget::Bound {
                                caller,
                                module,
                                endpoint,
                                base,
                            },
                        );
                    }
                }
                PendingCountOutcome::Rejected { .. } => {
                    if matches!(
                        self.pair_targets.get(&key),
                        Some(PairTarget::Pending { .. })
                    ) {
                        self.pair_targets.insert(key, PairTarget::Dropped);
                        self.pair_counts.remove(&key);
                    }
                }
                PendingCountOutcome::Unadmitted { .. } => {}
            }
        }
    }

    /// Drops one pair's counts (C7 C4): binder-unbound, or no module at
    /// all — held and later counts never publish.
    fn drop_pair_count(&mut self, row: &WitnessRow) {
        let key = PairKey::of(row);
        self.pair_targets.insert(key, PairTarget::Dropped);
        self.pair_counts.remove(&key);
    }

    /// Stages one decided row against the modules its witness endpoint is
    /// admitted for. `Err` names a row whose endpoint resolves to no
    /// module.
    fn stage_witness(&mut self, decision: Decision) -> Result<(), String> {
        let Decision { row, binding } = decision;
        let modules = match self.witness_modules(&row) {
            Ok(modules) => modules,
            Err(reason) => {
                self.drop_pair_count(&row);
                if let Binding::Unbound(unbound) = binding {
                    self.note_preadmission(row.host_tgid, &[None], unbound);
                }
                return Err(reason);
            }
        };
        match binding {
            Binding::Bound(caller) => {
                self.bind_pair_count(&row, caller, &modules);
                self.registry
                    .note_bound_witness(caller, modules, row.recorded_at_ns)
            }
            Binding::Unbound(reason) => {
                self.drop_pair_count(&row);
                let keys: Vec<Option<ModuleKey>> = modules.iter().cloned().map(Some).collect();
                self.note_preadmission(row.host_tgid, &keys, reason);
                self.registry
                    .note_unbound_witness(modules, row.recorded_at_ns, reason)
            }
        }
        Ok(())
    }

    /// R-C51-1 (fail-safe): an unbound CALLER_USE row of `pid` — refused
    /// as `before_admission` or unmatched for any other reason — is the
    /// pair's only row ever (BPF inserts it `NOEXIST` and never deletes
    /// it), so a later use of that module by `pid` leaves no row and no
    /// watch of it can be a fact. Every caller record of `pid` (live or
    /// retired: a reused pid also downgrades, failing safe) reads
    /// `use_before_admission` on those modules, and so does any caller
    /// admitted with `pid` later (`stage_capture_coverage`) unless both
    /// start times are known and differ. Entries of exited or reused pids
    /// are pruned (R-C51-5) before the stash may overflow. Past the
    /// stash bound every caller of the scope reads it, with a gap. A row
    /// left unbound by lifecycle loss downgrades the same way but reads
    /// `loss` (R-C51-3): the loss, not an early use, is what it shows.
    fn note_preadmission(
        &mut self,
        pid: u32,
        modules: &[Option<ModuleKey>],
        unbound: UnboundReason,
    ) {
        let loss = unbound == UnboundReason::LifecycleLoss;
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        let stash = &mut capture.preadmission;
        if stash.overflowed {
            stash.refused += modules.len() as u64;
            return;
        }
        let source = self.adapter.source();
        // An entry of an earlier holder of this pid no longer applies.
        stash.prune_pid(pid, source);
        let mut fresh: Vec<Option<ModuleKey>> = Vec::new();
        for module in modules {
            let held = stash.entries.get(&pid).is_some_and(|entry| {
                entry.modules.contains_key(module) || entry.modules.contains_key(&None)
            });
            if held {
                continue;
            }
            if stash.len >= stash.limit {
                stash.prune(source);
            }
            if stash.len >= stash.limit {
                stash.overflowed = true;
                stash.refused += 1;
                self.registry.record_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: None,
                    subject: "native pre-admission rows past their bound".into(),
                    reason: format!(
                        "more than {} (pid, module) pairs of unbound CALLER_USE rows: a caller's \
                         use before its admission can no longer be told apart, so every watch \
                         of this capture reads unknown use_before_admission",
                        stash.limit
                    ),
                    budget: None,
                });
                let callers: Vec<CallerId> =
                    self.adapter.records().map(|record| record.id).collect();
                for caller in callers {
                    self.registry.note_use_before_admission(caller, None);
                }
                return;
            }
            let entry = stash
                .entries
                .entry(pid)
                .or_insert_with(|| PreadmissionEntry {
                    start_time: source.start_time(pid),
                    modules: BTreeMap::new(),
                });
            entry.modules.insert(module.clone(), loss);
            stash.len += 1;
            fresh.push(module.clone());
        }
        if fresh.is_empty() {
            return;
        }
        let callers: Vec<CallerId> = self
            .adapter
            .records()
            .filter(|record| record.pid == pid)
            .map(|record| record.id)
            .collect();
        for caller in callers {
            for module in &fresh {
                self.downgrade(caller, module.clone(), loss);
            }
        }
    }

    fn downgrade(&mut self, caller: CallerId, module: Option<ModuleKey>, loss: bool) {
        if loss {
            self.registry
                .note_unbound_row_loss(caller, module, UNBOUND_ROW_LOSS);
        } else {
            self.registry.note_use_before_admission(caller, module);
        }
    }

    /// Whether R-C51-1 downgrades `caller`'s edge on `key`: `Some(loss)`.
    /// An entry stashed under another process's start time does not apply
    /// (R-C51-5); liveness is not consulted here — a caller that exits
    /// right after its maps were read still owes its downgrade.
    fn preadmission_holds(&self, caller: CallerId, pid: u32, key: &ModuleKey) -> Option<bool> {
        let stash = &self.capture.as_ref()?.preadmission;
        if stash.overflowed {
            return Some(false);
        }
        let entry = stash.entries.get(&pid)?;
        let caller_start = self
            .adapter
            .record(caller)
            .and_then(|record| record.start_time);
        if matches!(
            (entry.start_time, caller_start),
            (Some(stashed), Some(own)) if stashed != own
        ) {
            return None;
        }
        entry
            .modules
            .get(&None)
            .or_else(|| entry.modules.get(&Some(key.clone())))
            .copied()
    }

    /// The pre-admission stash's counters (R-C51-5), `None` without a
    /// native capture.
    pub(crate) fn preadmission_counters(&self) -> Option<PreadmissionCounters> {
        self.capture
            .as_ref()
            .map(|capture| capture.preadmission.counters())
    }

    /// The registry modules a row witnesses: every admitted module whose
    /// recorded membership holds the row's endpoint (the same endpoint set
    /// a watch negates). The endpoint must be the attach set's, in the
    /// row's object. No key equality is joined here: endpoints and their
    /// memberships come from the attach set's retained pins.
    fn witness_modules(&self, row: &WitnessRow) -> Result<Vec<ModuleKey>, String> {
        let endpoint = self
            .attach_set
            .endpoint(row.endpoint)
            .ok_or_else(|| format!("endpoint {} is not in the attach set", row.endpoint.0))?;
        if endpoint.object != row.object {
            return Err(format!(
                "endpoint {} belongs to another attach object than the row names",
                row.endpoint.0
            ));
        }
        self.admitted_modules_for_endpoint(row.endpoint)
    }

    /// The admitted modules recording `endpoint` as a member: distinct
    /// registry keys — one module never counts as two sharers. Shared
    /// by witness rows ([`Self::witness_modules`]) and count updates
    /// ([`Self::update_modules_for_endpoint`]).
    fn admitted_modules_for_endpoint(
        &self,
        endpoint: EndpointId,
    ) -> Result<Vec<ModuleKey>, String> {
        let modules: BTreeSet<ModuleKey> = self
            .attach_set
            .modules_with_member(endpoint)
            .filter(|key| {
                key.object.device.major != 0
                    || key.object.device.minor != 0
                    || key.object.inode != 0
            })
            .map(|key| {
                ModuleKey::physical(
                    key.object.device.major,
                    key.object.device.minor,
                    key.object.inode,
                    Some(key.sha256.clone()),
                    "",
                )
            })
            .collect();
        if modules.is_empty() {
            return Err(format!(
                "no admitted module records endpoint {} as a member",
                endpoint.0
            ));
        }
        Ok(modules.into_iter().collect())
    }

    /// A proven exec transition: the incarnation's image ended. A still
    /// live incarnation retires (exec-retired) and its successor is
    /// admitted; one the scan lane already retired needs nothing. A native
    /// owner gets the `ExecProof` the transition carries.
    fn apply_exec_transition(
        &mut self,
        transition: ExecTransition,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        now_ns: u64,
    ) -> Vec<CallerEvent> {
        let caller = transition.caller();
        // The binder emits a transition only for the live incarnation that
        // held the row's tgid, so the pid matches by construction; whether
        // that incarnation is still live is what may have changed since.
        let live = self
            .adapter
            .record(caller)
            .is_some_and(|record| !record.retired);
        if !live {
            return Vec::new();
        }
        if let Some(owner) = self.owners.get(&caller).copied()
            && let Err(error) = self.engine.request_inventory_refresh(
                owner,
                RefreshCause::ValidatedExec(ExecProof::from_transition(owner, transition)),
            )
        {
            self.registry.record_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: Some(transition.pid()),
                subject: "native exec proof not applied".into(),
                reason: format!("{error:#}; the caller incarnation still retires"),
                budget: None,
            });
        }
        let mut resolver = AuthorityResolver {
            engine: &mut self.engine,
            pending: &mut self.pending_owners,
            guard: &mut super::inventory::UnavailableImageGuard,
            identity,
            native_failures: Vec::new(),
            scan_pinned: 0,
        };
        let events = self
            .adapter
            .exec_transition(caller, &mut |pid| resolver.resolve(pid), now_ns);
        let (native_failures, scan_pinned) = resolver.finish();
        self.record_authority_gaps(native_failures, scan_pinned);
        events
    }

    /// The I4b batch: the engine tail and the registry publish as one
    /// synchronous step. Facts from every scan since the last commit are
    /// invisible before this returns and visible after — the ordering
    /// the Phase 2 test pins, extended to caller/edge facts.
    pub(crate) fn commit_batch(&mut self, engine_changed: bool) -> Result<BatchReceipt> {
        self.engine.publish_batch_tail(engine_changed)?;
        let registry_applied = self.registry.publish();
        self.finalize_pending_counts();
        Ok(BatchReceipt {
            engine_facts: self.engine.facts_revision,
            engine_published: self.engine.published_facts_revision,
            registry_facts: self.registry.facts_revision(),
            registry_published: self.registry.published_revision(),
            registry_applied,
        })
    }
}

/// One native input for `stage_native` (plan §3.6). S2/S3 add an object
/// fact variant here.
#[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 constructs them.
pub(crate) enum NativeBatch {
    /// One witness read of a capture domain (rows, health, custody).
    Witness(Box<WitnessBatch>),
    /// One lifecycle quantum, tagged by the facade with the domain it was
    /// drained from and stamped with its own drain instants (the binder
    /// orders evidence by those stamps, never by call order).
    Lifecycle(DiscoveryBatch),
    /// No later lifecycle or health evidence will arrive for `domain` (its
    /// capture retired): every row of that domain still waiting is decided
    /// unbound. Pass the retired facade's `domain()`.
    Finish { domain: NativeDomainId },
}

/// What one `stage_native` call did.
#[derive(Debug, Default)]
#[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 reads it.
pub(crate) struct NativeReceipt {
    /// Incarnation changes the native lane made (exec transitions), for the
    /// event stream; already staged in the registry.
    pub events: Vec<CallerEvent>,
    /// Rows decided by this call.
    pub decided: usize,
}

/// One CALLER_USE pair (C7 C4): the image that owns the row plus the
/// object it names. A row and its refresh counts join on this: the
/// cookie is domain-tagged (tickets are per-domain), the exec sequence
/// disambiguates the ticket's images, and the object is the map key's
/// (`u32`: `AttachObjectId` has no hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PairKey {
    image: DomainCookie,
    exec: u64,
    object: u32,
}

impl PairKey {
    fn of(row: &WitnessRow) -> Self {
        Self {
            image: row.cookie(),
            exec: row.exec_id(),
            object: row.object.index(),
        }
    }

    fn of_update(domain: NativeDomainId, update: &CallerCountUpdate) -> Self {
        Self {
            image: DomainCookie::new(domain, update.image.task_cookie),
            exec: update.image.exec_id,
            object: update.object.index(),
        }
    }
}

/// The latest known count of one pair (C7 C4): an absolute saturating
/// lower bound since the pair's first record, with the read that
/// observed it. First-sight `entry_count` and refresh counts merge by
/// maximum, so any arrival order stages the same count.
#[derive(Debug, Clone, Copy)]
struct PairCount {
    count: u64,
    first_ns: u64,
    last_ns: u64,
}

/// Rebase one held absolute count past `base` (F3-03): what stages is
/// only growth previous owners do not already carry. The first sight
/// travels with the base: an unbased count keeps the pair's first
/// record, while rebased growth starts at the observing read — a new
/// owner never inherits the pair's backdated history.
fn rebased_count(count: PairCount, base: u64) -> PairCount {
    PairCount {
        count: count.count.saturating_sub(base),
        first_ns: if base == 0 {
            count.first_ns
        } else {
            count.last_ns
        },
        last_ns: count.last_ns,
    }
}

/// Where one decided pair's counts go (C7 C4).
#[derive(Debug, Clone)]
enum PairTarget {
    /// The pair bound to `caller` and its witness resolved to exactly
    /// one edged module: counts stage there — after re-resolving the
    /// endpoint's placement (F7), since sharing that appeared after
    /// the pair bound makes further growth ambiguous. `base` is the
    /// absolute count previous owners already carry (0 for a
    /// first-bound pair): only growth past it ever stages, so a
    /// re-resolved pair never duplicates history elsewhere (F3-03).
    Bound {
        caller: CallerId,
        module: ModuleKey,
        endpoint: EndpointId,
        base: u64,
    },
    /// The pair bound to `caller` and waiting on its publication-time
    /// placement: counts stage pending and resolve at publication,
    /// together with the witness. `staged` is the absolute count
    /// staged so far, so only advances re-stage; `base` is the
    /// absolute count previous owners already carry (0 for a
    /// first-sight pair, the demoted total for a re-resolved one):
    /// only growth past it stages. The publication's decisions
    /// finalize it as [`Self::Bound`] or [`Self::Dropped`]; an
    /// unadmitted single stays pending and re-resolves on the next
    /// advance.
    Pending {
        caller: CallerId,
        modules: Vec<ModuleKey>,
        staged: u64,
        endpoint: EndpointId,
        base: u64,
    },
    /// The pair never publishes: binder-unbound, or no module at all.
    /// Held and later counts drop.
    Dropped,
}

/// Per-endpoint attach state from the capture facade's receipts. Bounded by
/// the endpoint budget N: each endpoint is attached or failed at most once.
struct CaptureCoverage {
    scope: Option<ScopeIncarnation>,
    /// The first caller proven to be the scope incarnation.
    bound: Option<CallerId>,
    attached_at: BTreeMap<EndpointId, u64>,
    /// Sticky: a failed endpoint is never retried, so its modules never
    /// read watched.
    failed: BTreeSet<EndpointId>,
    /// Sticky: coverage is unproven from here on (PID custody lost, an
    /// exec or leader exit of the PID target, lifecycle loss — PID or
    /// system scope).
    unproven: Option<String>,
    /// Sticky: objects modified in place after they were attached.
    changed_objects: BTreeSet<AttachObjectId>,
    /// The last witness batch's unproven health (not sticky).
    health_unproven: Option<String>,
    /// Sticky: the WatchedNoUse pair precondition failed (the seen set is
    /// full, or a row went unrecorded): no read proves no-use again, so
    /// no watch starts and no read extends one (C5.2).
    pairs_unproven: Option<String>,
    /// Sticky: CALLER_EVIDENCE showed a pair insert failure (C7 C4), so
    /// some pair has use but no row and absence proves nothing: edges
    /// without positive history read `uncounted` and no watch starts
    /// again. The map never deletes, so a full map stays full.
    pairs_uncounted: Option<Arc<str>>,
    /// The latest witness read with proven health, no rise, and held
    /// custody: where a watch ends at stop.
    last_clean_ns: Option<u64>,
    /// The health read of the batch the open CALLER_USE sweep began in
    /// (`None`: the next batch begins one).
    sweep_began_ns: Option<u64>,
    /// Pids of unbound CALLER_USE rows (R-C51-1): their callers' watches
    /// on the rows' modules read `use_before_admission`, whichever is
    /// staged first, the row or the caller's admission.
    preadmission: PreadmissionStash,
    stopped: bool,
}

/// The loss detail of an edge whose caller's use row lifecycle loss left
/// unbound (R-C51-3).
const UNBOUND_ROW_LOSS: &str =
    "lifecycle evidence was lost before this caller's use row could bind";

/// (pid, module) pairs the stash holds before it overflows.
const PREADMISSION_STASH_LIMIT: usize = 4096;

/// The (pid, module) pairs of every unbound CALLER_USE row, bounded. A
/// `None` module is a row whose endpoint resolved to no module: every
/// module of that pid. Past the bound the whole scope reads
/// `use_before_admission` (sticky).
#[derive(Debug)]
struct PreadmissionStash {
    entries: BTreeMap<u32, PreadmissionEntry>,
    len: usize,
    limit: usize,
    overflowed: bool,
    /// (pid, module) pairs dropped because their process exited or the
    /// pid now names another process (R-C51-5).
    pruned: u64,
    /// (pid, module) notes refused once the stash overflowed.
    refused: u64,
}

/// The unbound rows of one pid: the process's start time when the first
/// row was stashed (`None`: unreadable then — kept until the pid is gone,
/// failing safe), and module -> whether lifecycle loss left the row
/// unbound.
#[derive(Debug, Default)]
struct PreadmissionEntry {
    start_time: Option<u64>,
    modules: BTreeMap<Option<ModuleKey>, bool>,
}

/// The stash's counters (R-C51-5), published under
/// `observation.native_witnesses.preadmission`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PreadmissionCounters {
    pub held: usize,
    pub limit: usize,
    pub pruned: u64,
    pub refused: u64,
}

impl PreadmissionStash {
    fn new(limit: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            len: 0,
            limit,
            overflowed: false,
            pruned: 0,
            refused: 0,
        }
    }

    /// The entry can no longer matter (R-C51-5): its process is gone (a
    /// dead pid is never admitted again), or the pid now names a process
    /// with another start time. Each fork or exec writes rows under its
    /// own image key, so a later holder's use leaves rows of its own.
    fn stale<S: ProcessSource>(entry: &PreadmissionEntry, pid: u32, source: &S) -> bool {
        source.gone(pid)
            || matches!(
                (entry.start_time, source.start_time(pid)),
                (Some(stashed), Some(now)) if stashed != now
            )
    }

    fn prune_pid<S: ProcessSource>(&mut self, pid: u32, source: &S) {
        if self
            .entries
            .get(&pid)
            .is_some_and(|entry| Self::stale(entry, pid, source))
        {
            let entry = self.entries.remove(&pid).expect("checked above");
            self.len -= entry.modules.len();
            self.pruned += entry.modules.len() as u64;
        }
    }

    fn prune<S: ProcessSource>(&mut self, source: &S) {
        let pids: Vec<u32> = self.entries.keys().copied().collect();
        for pid in pids {
            self.prune_pid(pid, source);
        }
    }

    fn counters(&self) -> PreadmissionCounters {
        PreadmissionCounters {
            held: self.len,
            limit: self.limit,
            pruned: self.pruned,
            refused: self.refused,
        }
    }
}

/// The WatchedNoUse pair precondition (C3 open item, C5.2): the userspace
/// seen set below its bound and no row unrecorded past it. A full set
/// cannot report a later first use, and an unrecorded row is a use nobody
/// will ever bind, so no-use is no longer provable.
///
/// Withholding (not demoting) is sound only because the seen-set bound
/// equals the capacity of the insert-only CALLER_USE map
/// (`attach::inventory::callers::seen_limit`, pinned by a test): the set
/// fills exactly when the map does, so every first use before saturation
/// was reported, and every later one either was too or failed its insert
/// into CALLER_EVIDENCE, whose rise demotes every watch.
fn pair_precondition_failure(batch: &WitnessBatch) -> Option<String> {
    if batch.unrecorded_rows > 0 {
        Some(format!(
            "{} CALLER_USE row(s) went unrecorded past the pair limit {}: no-use is unprovable",
            batch.unrecorded_rows, batch.pair_limit
        ))
    } else if batch.seen_rows >= batch.pair_limit {
        Some(format!(
            "the CALLER_USE seen set is full ({}/{} pairs): a later first use could go unrecorded",
            batch.seen_rows, batch.pair_limit
        ))
    } else {
        None
    }
}

/// Whether one mapped caller is the capture's scope incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeVerdict {
    Inside,
    /// Another process (a different pid, or a reused one).
    Outside,
    /// The pid matches but a start time is unreadable: unprovable.
    Unproven,
    /// The scope incarnation's later image (after an exec).
    LaterImage,
}

/// The run's attach set is the ONE admission source the inventory output
/// shows (Task 6 C2 review I1): its verdict replaces any other, and an
/// object it never judged has no admitted verdict. `None` here means "not
/// judged".
fn attach_admission(
    verdict: Option<&AttachVerdict>,
) -> Option<(AdmissionState, Option<usize>, Vec<String>)> {
    match verdict? {
        AttachVerdict::Admitted { endpoints, reasons } => {
            Some((AdmissionState::Admitted, Some(*endpoints), reasons.clone()))
        }
        AttachVerdict::Refused { reason } => {
            Some((AdmissionState::Refused, None, vec![reason.clone()]))
        }
    }
}

const UNJUDGED_REASON: &str = "the inventory attach set did not judge this object (no comparable \
     pin or digest in this pass's lowering); it is not instrumented";

/// One natively committed module's registry record. Admission comes only
/// from the attach set's verdict for the same physical module; the
/// engine's own plan is never an admission source (it is lowered for the
/// native owner lane, not for what this run instruments). Unjudged reads
/// unresolved.
fn native_module_info(
    engine: &Engine,
    module: &ReconciledModule,
    key: ModuleKey,
    verdict: Option<&AttachVerdict>,
) -> ModuleInfo {
    let (admission, endpoints, reasons) = attach_admission(verdict).unwrap_or_else(|| {
        (
            AdmissionState::Unresolved,
            None,
            vec![UNJUDGED_REASON.to_string()],
        )
    });
    let summary = engine.pinned.summary(module.object);
    ModuleInfo {
        path: module.scanned.path.clone(),
        key,
        double_loaded: module.scanned.double_loaded,
        build_id: summary.and_then(|summary| summary.build_id.map(str::to_string)),
        identity_source: summary.map(|summary| summary.identity_source.to_string()),
        admission,
        admission_class: None,
        admission_endpoints: endpoints,
        admission_reasons: reasons,
    }
}

fn catalog_module_key(object: &crate::inspect_system::CatalogObject) -> ModuleKey {
    ModuleKey::physical(
        object.key.device.major,
        object.key.device.minor,
        object.key.inode,
        object.sha256.clone(),
        &object.path,
    )
}

/// One catalog object's registry record. `verdict` is the attach set's
/// Inventory verdict and is the admission source. An object the attach set
/// did not judge keeps the catalog's refusal or unresolved verdict (true:
/// nothing attaches), but never its `admitted` — that object is not
/// instrumented, so it reads unresolved.
fn catalog_module_info(
    object: &crate::inspect_system::CatalogObject,
    verdict: Option<&AttachVerdict>,
) -> ModuleInfo {
    let (admission, endpoints, reasons) =
        attach_admission(verdict).unwrap_or_else(|| match object.admission.state() {
            "refused" => (AdmissionState::Refused, None, object.admission.reasons()),
            "admitted" => (
                AdmissionState::Unresolved,
                None,
                vec![UNJUDGED_REASON.to_string()],
            ),
            _ => {
                let mut reasons = object.admission.reasons();
                reasons.push(UNJUDGED_REASON.to_string());
                (AdmissionState::Unresolved, None, reasons)
            }
        });
    ModuleInfo {
        path: object.path.clone(),
        key: catalog_module_key(object),
        // Per-observation evidence: the projection loop below
        // overwrites this with the observing member's verdict.
        double_loaded: false,
        build_id: object.build_id.clone(),
        identity_source: object.identity_source.map(str::to_string),
        admission,
        // The catalog class describes its own lowering; without an attach-set
        // verdict it would contradict the `unresolved` admission above.
        admission_class: verdict.and(object.admission.class()).map(str::to_string),
        admission_endpoints: endpoints,
        admission_reasons: reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::super::inventory::{ImageCheck, UnavailableImageGuard};
    use super::*;
    use crate::discovery::caller_registry::OsProcessSource;
    use crate::discovery::native_binding::{OwnerImages, ScanOnlyIdentity};
    use p11scope_ebpf_common::ImageIdentity;
    use std::cell::Cell;

    // Only the native query is scripted. This never purports to read the
    // host's task-storage identity map or qualify a running capture.
    struct FixtureImages;

    fn fixture_image(pid: u32) -> Option<ImageIdentity> {
        Some(ImageIdentity {
            task_cookie: u64::from(pid) + 1,
            exec_id: 7,
        })
    }

    impl ImageGuard for FixtureImages {
        fn check(&mut self, view: &ProcessView, expected: ImageIdentity) -> ImageCheck {
            assert_eq!(expected.task_cookie, u64::from(view.pid()) + 1);
            ImageCheck::Exact
        }
    }

    fn coordinator() -> InventoryCoordinator<OsProcessSource> {
        InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap()
    }

    /// E-test-style fixture build: compile one C source with gcc into the
    /// test tmp dir.
    fn gcc(
        dir: &std::path::Path,
        out: &str,
        source: &std::path::Path,
        args: &[&str],
        libs: &[&str],
    ) -> PathBuf {
        let bin = dir.join(out);
        let mut cmd = std::process::Command::new("gcc");
        cmd.args(args).arg("-o").arg(&bin).arg(source).args(libs);
        assert!(
            cmd.status().unwrap().success(),
            "gcc failed for {out}: {cmd:?}"
        );
        bin
    }

    /// Poll for a driver ready file, like the observe helpers.
    fn wait_ready(ready: &std::path::Path) {
        for _ in 0..300 {
            if std::fs::metadata(ready).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("fixture driver never became ready: {}", ready.display());
    }

    /// Kills the owned fixture child on drop, so a failed assert cannot
    /// leak a sleeper.
    struct ChildReaper(std::process::Child);

    impl Drop for ChildReaper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn native_pass_over_self_commits_and_publishes_through_one_batch() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(pid),
                None,
                &mut FixtureImages,
                &mut OwnerImages(fixture_image),
                u64::MAX,
                crate::discovery::caller_registry::now_ns(),
            )
            .unwrap();
        assert_eq!(report.pass, 0);
        assert_eq!(report.scanned, 1);
        assert_eq!(report.native_callers, 1);
        assert!(report.pending_refresh.is_empty());
        let caller = coordinator.adapter().live_id(pid).unwrap();
        let record = coordinator.adapter().record(caller).unwrap();
        assert!(matches!(
            record.authority,
            ImageAuthority::NativeExact { .. }
        ));
        assert!(coordinator.owner_of(caller).is_some());
        // Staged: the registry snapshot is empty until the batch commits.
        assert_eq!(coordinator.registry().modules().count(), 0);
        let receipt = coordinator.commit_batch(true).unwrap();
        assert_eq!(receipt.engine_facts, receipt.engine_published);
        assert_eq!(receipt.registry_facts, receipt.registry_published);
        assert!(receipt.registry_facts > 1);
        // The engine tail ran through the same boundary.
        assert!(coordinator.engine.tail_publishes > 0);
        // The owner closed its serviced epoch with nothing pending.
        let owner = coordinator.owner_of(caller).unwrap();
        let epochs = coordinator.engine.inventory_owner_epochs(owner).unwrap();
        assert_eq!(epochs.serviced, 1);
        assert_eq!(epochs.requested, 1);
        assert_eq!(epochs.dirty, 0);
    }

    #[test]
    fn staged_lifecycle_batches_fold_their_high_water_maximum() {
        let mut coordinator = coordinator();
        assert_eq!(coordinator.lifecycle_high_water_bytes(), None);
        let domain = NativeDomainId::mint();
        let now = crate::discovery::caller_registry::now_ns();
        // The maximum is staged before smaller and absent reports, so only
        // a maximum (not the last report) reads 300.
        for high_water in [Some(100), Some(300), None, Some(50)] {
            let mut batch = DiscoveryBatch::scripted(domain, Vec::new(), now);
            batch.drain_high_water_bytes = high_water;
            coordinator.stage_native(NativeBatch::Lifecycle(batch), &mut ScanOnlyIdentity, now);
        }
        assert_eq!(coordinator.lifecycle_high_water_bytes(), Some(300));
    }

    #[test]
    fn unavailable_guard_falls_back_to_scan_lane_with_an_authority_gap() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(pid),
                None,
                &mut UnavailableImageGuard,
                &mut ScanOnlyIdentity,
                u64::MAX,
                crate::discovery::caller_registry::now_ns(),
            )
            .unwrap();
        assert_eq!(report.native_callers, 0);
        assert_eq!(report.scan_callers, 1);
        let caller = coordinator.adapter().live_id(pid).unwrap();
        assert_eq!(
            coordinator.adapter().record(caller).unwrap().authority,
            ImageAuthority::ScanPinned
        );
        assert!(coordinator.owner_of(caller).is_none());
        coordinator.commit_batch(false).unwrap();
        assert!(
            coordinator
                .registry()
                .gaps()
                .iter()
                .any(|gap| gap.subject == "exact image authority unavailable"),
            "scan-lane fallback must record why: {:?}",
            coordinator.registry().gaps()
        );
    }

    #[test]
    fn commit_revalidates_after_prepare_and_refuses_changed_images() {
        struct FlipGuard {
            exact: Cell<bool>,
        }
        impl ImageGuard for FlipGuard {
            fn check(&mut self, _: &ProcessView, _: ImageIdentity) -> ImageCheck {
                if self.exact.get() {
                    ImageCheck::Exact
                } else {
                    ImageCheck::Changed
                }
            }
        }
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let image = fixture_image(pid).unwrap();
        let mut guard = FlipGuard {
            exact: Cell::new(true),
        };
        let owner = coordinator
            .engine
            .open_inventory_owner(pid, image, &mut guard)
            .unwrap();
        let lease = coordinator.engine.acquire_inventory_scan(owner).unwrap();
        let window = coordinator
            .engine
            .budget
            .begin_window(WindowId::new(0), u64::MAX)
            .unwrap();
        let checkpoint = coordinator
            .engine
            .budget
            .checkpoint(window.clone())
            .unwrap();
        let receipt = coordinator
            .engine
            .scan_inventory_owner(&lease, &mut guard)
            .unwrap();
        coordinator.engine.budget.finish_scan(checkpoint).unwrap();
        coordinator.engine.budget.finish_window(window).unwrap();
        coordinator.engine.release_inventory_scan(&lease).unwrap();
        let prepared = coordinator
            .engine
            .prepare_inventory_reconciliation(receipt, &mut guard)
            .unwrap();
        // Asynchronous gap: the image changes after preparation. I3
        // revalidates at commit and refuses; existing claims are retained.
        guard.exact.set(false);
        let modules_before = coordinator.engine.modules.len();
        assert!(
            coordinator
                .engine
                .commit_inventory_reconciliation(prepared, &mut guard)
                .is_err()
        );
        assert_eq!(coordinator.engine.modules.len(), modules_before);
        assert_eq!(
            coordinator
                .engine
                .inventory_owner_epochs(owner)
                .unwrap()
                .image_state,
            ImageCheck::Changed
        );
    }

    #[test]
    fn expired_deadline_defers_and_keeps_the_refresh_pending() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(pid),
                None,
                &mut FixtureImages,
                &mut OwnerImages(fixture_image),
                1,
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.native_callers, 1);
        let caller = coordinator.adapter().live_id(pid).unwrap();
        let owner = coordinator.owner_of(caller).unwrap();
        // No commit ran: the refresh request stays pending for the next
        // pass with a fresh deadline.
        let epochs = coordinator.engine.inventory_owner_epochs(owner).unwrap();
        assert_eq!(epochs.requested, 1);
        assert_eq!(epochs.serviced, 0);
        assert_ne!(epochs.dirty, 0);
        coordinator.commit_batch(false).unwrap();
        assert!(
            coordinator.registry().gaps().iter().any(|gap| {
                gap.subject == "native inventory scan failed" && gap.reason.contains("defer")
            }),
            "deferral must surface as a gap: {:?}",
            coordinator.registry().gaps()
        );
    }

    #[test]
    fn empty_pass_reconciles_exits_without_a_scan() {
        use crate::discovery::caller_registry::CallerLifecycle;
        use std::process::{Command, Stdio};

        struct Exiter(std::process::Child);
        impl Drop for Exiter {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        // An owned sleeper, reaped before the empty pass: the pin dies
        // and the pid names nothing, so lifecycle needs no scan.
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut exiter = Exiter(child);
        let mut coordinator = InventoryCoordinator::new(
            Scope::System,
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let now = crate::discovery::caller_registry::now_ns();
        let mut observed = BTreeSet::new();
        observed.insert(pid);
        let events = coordinator.adapter_mut().reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            now,
        );
        assert_eq!(events.len(), 1);
        let caller = coordinator.adapter().live_id(pid).unwrap();
        exiter.0.kill().unwrap();
        exiter.0.wait().unwrap();
        let report = coordinator.observe_empty_pass(
            &mut UnavailableImageGuard,
            &mut ScanOnlyIdentity,
            "boom",
            now + 1,
        );
        assert_eq!(report.scanned, 0);
        assert!(report.events.iter().any(|event| matches!(
            event,
            CallerEvent::Exited { id, .. } if *id == caller
        )));
        coordinator.commit_batch(false).unwrap();
        let record = coordinator.adapter().record(caller).unwrap();
        assert_eq!(record.lifecycle, CallerLifecycle::Exited);
        assert!(record.retired);
        assert!(
            coordinator
                .registry()
                .gaps()
                .iter()
                .any(|gap| gap.subject == "scan pass produced no observation"
                    && gap.reason == "boom"),
            "empty passes gap their reason: {:?}",
            coordinator.registry().gaps()
        );
    }

    #[test]
    fn batch_publishes_registry_edges_synchronously_with_the_return() {
        // Sibling: scripted_entries_flow_from_a_scan_built_edge_through_commit_to_json
        // pins the same batch boundary for entry counts through render_json.
        let mut coordinator = coordinator();
        let key = ModuleKey::physical(8, 1, 11, Some("sha0011".into()), "/lib/a.so");
        coordinator.registry_mut().note_mapping(
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
                admission_endpoints: Some(2),
                admission_reasons: Vec::new(),
            },
            100,
        );
        coordinator
            .registry_mut()
            .observe_entries(CallerId(0), &key, 3, 110);
        // Invisible before the batch returns.
        assert!(coordinator.registry().module_id_for(&key).is_none());
        let tails_before = coordinator.engine.tail_publishes;
        let receipt = coordinator.commit_batch(false).unwrap();
        // Visible after: the batch return already carries the arrival,
        // on both revisions at once.
        let id = coordinator.registry().module_id_for(&key).unwrap();
        let edge = coordinator.registry().edge(CallerId(0), id).unwrap();
        assert_eq!(edge.entry_count, 3);
        assert_eq!(receipt.registry_facts, receipt.registry_published);
        assert_eq!(receipt.engine_facts, receipt.engine_published);
        assert!(coordinator.engine.tail_publishes > tails_before || receipt.engine_facts > 1);
    }

    #[test]
    fn scripted_entries_flow_from_a_scan_built_edge_through_commit_to_json() {
        // Sibling: batch_publishes_registry_edges_synchronously_with_the_return
        // pins the same batch boundary for mapping edges.
        use crate::discovery::caller_registry::{MAX_EDGE_ENTRY_COUNT, ModuleId};

        fn rendered_edge(
            document: &serde_json::Value,
            caller: CallerId,
            module: ModuleId,
        ) -> &serde_json::Value {
            document["edges"]
                .as_array()
                .unwrap()
                .iter()
                .find(|edge| edge["caller"] == caller.label() && edge["module"] == module.label())
                .unwrap()
        }

        // Owned fixture, E1-style: a driver child mapping a version-matrix
        // provider. Hints name the provider, so the scan lane projects the
        // edge deterministically (empty hints only keep objects exporting a
        // registry symbol, which a bare self scan has none of).
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join("coordinator-entry-flow");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let provider = gcc(
            &dir,
            "f1-p1.so",
            &manifest.join("crates/discover/tests/fixture/version_matrix.c"),
            &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
            &[],
        );
        let driver = gcc(
            &dir,
            "f1-driver",
            &manifest.join("tests/fixtures/catalog-driver.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        );
        let ready = dir.join("A.ready");
        let child = std::process::Command::new(&driver)
            .arg("--ready")
            .arg(&ready)
            .arg(&provider)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let driver_pid = child.id();
        let _reaper = ChildReaper(child);
        wait_ready(&ready);
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(driver_pid),
            HookRegistry::builtin(),
            vec![provider.clone()],
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let started = crate::discovery::caller_registry::now_ns();
        let scope = format!("pid:{driver_pid}");
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(driver_pid),
                None,
                &mut UnavailableImageGuard,
                &mut ScanOnlyIdentity,
                u64::MAX,
                started,
            )
            .unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.scan_callers, 1);
        coordinator.commit_batch(false).unwrap();
        let caller = coordinator.adapter().live_id(driver_pid).unwrap();
        // The edge under test is scan-built: the pass projected it, so no
        // hand-staged mapping stands in for the staging path.
        let provider_name = provider.file_name().unwrap().to_string_lossy().into_owned();
        let module = coordinator
            .registry()
            .edges()
            .filter(|edge| edge.caller == caller)
            .map(|edge| edge.module)
            .find(|module| {
                coordinator
                    .registry()
                    .module(*module)
                    .is_some_and(|record| {
                        record
                            .paths
                            .iter()
                            .any(|path| path.contains(&provider_name))
                    })
            })
            .expect("the hinted scan maps the fixture provider");
        let key = coordinator.registry().module(module).unwrap().key.clone();

        // Scripted entries (+ in-flight) stage behind the batch boundary:
        // the pre-commit render still shows the quiet edge.
        let t1 = started.saturating_add(10);
        coordinator
            .registry_mut()
            .observe_entries(caller, &key, 7, t1);
        coordinator.registry_mut().set_in_flight(caller, &key, true);
        let staged = crate::inventory::render_json(&coordinator, &scope, started, t1, 1);
        assert_eq!(
            rendered_edge(&staged, caller, module)["entries"]["count"],
            0
        );
        let receipt = coordinator.commit_batch(false).unwrap();
        assert_eq!(receipt.registry_facts, receipt.registry_published);
        let document = crate::inventory::render_json(&coordinator, &scope, started, t1, 1);
        let edge = rendered_edge(&document, caller, module);
        assert_eq!(edge["entries"]["count"], 7);
        assert_eq!(edge["entries"]["observation"], "observed");
        assert!(edge["entries"]["in_flight"].as_bool().unwrap());
        assert_eq!(edge["entries"]["saturated"], false);
        assert_eq!(edge["entries"]["last_seen_ns"], t1);

        // Fill to MAX - 1, then +5 overflows: the count stops at the cap
        // with the saturation flag set while recency keeps advancing.
        let t2 = t1 + 10;
        let t3 = t2 + 10;
        coordinator
            .registry_mut()
            .observe_entries(caller, &key, MAX_EDGE_ENTRY_COUNT - 1 - 7, t2);
        coordinator
            .registry_mut()
            .observe_entries(caller, &key, 5, t3);
        let receipt = coordinator.commit_batch(false).unwrap();
        assert_eq!(receipt.registry_facts, receipt.registry_published);
        let document = crate::inventory::render_json(&coordinator, &scope, started, t3, 1);
        let edge = rendered_edge(&document, caller, module);
        assert_eq!(edge["entries"]["count"], u64::MAX);
        assert!(edge["entries"]["saturated"].as_bool().unwrap());
        assert_eq!(edge["entries"]["observation"], "observed");
        assert_eq!(edge["entries"]["last_seen_ns"], t3);
        assert_eq!(edge["entries"]["first_seen_ns"], t1);
        assert!(edge["entries"]["in_flight"].as_bool().unwrap());
    }

    #[test]
    fn scan_passes_feed_the_attach_set_once_under_the_inventory_budget() {
        // Owned fixture: a driver child mapping the NSS-shaped provider,
        // whose 8 interface-linked tables of 68 distinct targets are 544
        // endpoints — past the Detailed 512-slot ceiling, inside the
        // 4096-endpoint Inventory budget.
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join("coordinator-attach-set");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let provider = gcc(
            &dir,
            "as-nss.so",
            &manifest.join("tests/fixtures/catalog-nss/provider.c"),
            &[
                "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
            ],
            &[],
        );
        let driver = gcc(
            &dir,
            "as-driver",
            &manifest.join("tests/fixtures/catalog-driver.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        );
        let ready = dir.join("A.ready");
        let child = std::process::Command::new(&driver)
            .arg("--ready")
            .arg(&ready)
            .arg(&provider)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let driver_pid = child.id();
        let _reaper = ChildReaper(child);
        wait_ready(&ready);
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(driver_pid),
            HookRegistry::builtin(),
            vec![provider.clone()],
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        for pass in 0..2u64 {
            coordinator
                .scan_pass(
                    &InventoryScope::Pid(driver_pid),
                    None,
                    &mut UnavailableImageGuard,
                    &mut ScanOnlyIdentity,
                    u64::MAX,
                    crate::discovery::caller_registry::now_ns(),
                )
                .unwrap();
            coordinator.commit_batch(false).unwrap();
            let delta = coordinator.take_target_delta();
            if pass == 0 {
                assert_eq!(
                    delta
                        .endpoints
                        .iter()
                        .map(|endpoint| endpoint.id.0)
                        .collect::<Vec<_>>(),
                    (0..544).collect::<Vec<u32>>()
                );
                assert_eq!(delta.objects.len(), 1, "one physical provider object");
            } else {
                assert!(delta.is_empty(), "a rescan adds nothing: {delta:?}");
            }
            assert_eq!(coordinator.attach_set().len(), 544);
        }
        let provider_name = provider.file_name().unwrap().to_string_lossy().into_owned();
        let record = coordinator
            .registry()
            .modules()
            .find(|module| {
                module
                    .paths
                    .iter()
                    .any(|path| path.ends_with(&provider_name))
            })
            .expect("the hinted scan maps the fixture provider");
        assert_eq!(record.admission, AdmissionState::Admitted);
        assert_eq!(record.admission_endpoints, Some(544));
        assert!(record.admission_reasons.is_empty());
        assert!(
            !coordinator
                .registry()
                .gaps()
                .iter()
                .any(|gap| gap.subject.starts_with("inventory attach")),
            "{:?}",
            coordinator.registry().gaps()
        );
    }

    #[test]
    fn native_and_catalog_projections_take_admission_only_from_the_attach_set() {
        // I1 (review): the engine plan admits `a`, the run's attach set
        // refused it. Both projections note the module each pass; the
        // attach set is the one admission source, so the module reads
        // refused — never a false `refused->admitted` rise.
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let pins = fx::pass_pins(&[(&a, "sha-a")]);
        let module = fx::module(&pins, &a, &fx::offsets(3));
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        coordinator.engine.plan = fx::lower_named(std::slice::from_ref(&module), &pins, policy);
        assert_eq!(
            coordinator.engine.plan.refused_modules().count(),
            0,
            "the engine plan admits the module"
        );
        let refused = AttachVerdict::Refused {
            reason: "a.so needs 3 more endpoints; the attach set is full".into(),
        };
        let path = a.to_str().unwrap();
        let key = ModuleKey::physical(
            module.scanned.key.device.major,
            module.scanned.key.device.minor,
            module.scanned.key.inode,
            Some("sha-a".into()),
            path,
        );
        let object = crate::inspect_system::CatalogObject {
            path: path.into(),
            key: module.scanned.key,
            sha256: Some("sha-a".into()),
            build_id: None,
            identity_source: Some("mountinfo"),
            note: None,
            mappings: Vec::new(),
            observations: Vec::new(),
            admission: crate::inspect_system::AdmissionRecord::Admitted {
                class: "exact",
                endpoints: 3,
            },
        };
        let pid = std::process::id();
        let caller = coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 100)
            .unwrap();
        for pass in 0..2u64 {
            let native =
                native_module_info(&coordinator.engine, &module, key.clone(), Some(&refused));
            let catalog = catalog_module_info(&object, Some(&refused));
            assert_eq!(native.admission, AdmissionState::Refused, "native note");
            assert_eq!(catalog.admission, AdmissionState::Refused, "catalog note");
            // scan_pass order: the native projection first, then the catalog.
            coordinator
                .registry
                .note_mapping(caller, pid, native, 100 + pass);
            coordinator
                .registry
                .note_mapping(caller, pid, catalog, 100 + pass);
            coordinator.registry.publish();
        }
        let id = coordinator.registry.module_id_for(&key).unwrap();
        let record = coordinator.registry.module(id).unwrap();
        assert_eq!(record.admission, AdmissionState::Refused);
        assert!(
            record.admission_history.is_empty(),
            "{:?}",
            record.admission_history
        );
        assert!(
            !coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "module admission changed"),
            "{:?}",
            coordinator.registry.gaps()
        );
        // An object the attach set never judged: the native note has no
        // opinion and the catalog's own `admitted` is not taken over —
        // both read unresolved, never admitted.
        let native = native_module_info(&coordinator.engine, &module, key.clone(), None);
        assert_eq!(native.admission, AdmissionState::Unresolved);
        let catalog = catalog_module_info(&object, None);
        assert_eq!(catalog.admission, AdmissionState::Unresolved);
        assert_eq!(catalog.admission_endpoints, None);
        // No attach-set verdict: no catalog class either, matching the
        // native note, so the class cannot flip within one pass.
        assert_eq!(catalog.admission_class, None);
        assert_eq!(native.admission_class, None);
        assert!(
            catalog.admission_reasons[0].contains("did not judge"),
            "{:?}",
            catalog.admission_reasons
        );
        // A catalog refusal the attach set did not judge stays a refusal.
        let refused_object = crate::inspect_system::CatalogObject {
            admission: crate::inspect_system::AdmissionRecord::Refused {
                class: "closure-array",
                reason: "closure arrays are not attached".into(),
            },
            ..object
        };
        let catalog = catalog_module_info(&refused_object, None);
        assert_eq!(catalog.admission, AdmissionState::Refused);
        assert_eq!(catalog.admission_class, None);
    }

    /// One catalog object per path, each observed by `pid`, plus that
    /// member's complete scan record.
    fn capture_catalog(
        pins: &crate::discovery::identity::PinnedObjects,
        paths: &[&std::path::Path],
        pid: u32,
        generation: Option<crate::inspect_system::MemberGeneration>,
    ) -> crate::inspect_system::Catalog {
        let objects = paths
            .iter()
            .map(|path| {
                let summary = pins
                    .pinned()
                    .find(|summary| summary.path == path.to_str().unwrap())
                    .unwrap();
                crate::inspect_system::CatalogObject {
                    path: summary.path.to_string(),
                    key: summary.key,
                    sha256: Some(summary.sha256.to_string()),
                    build_id: None,
                    identity_source: Some("mountinfo"),
                    note: None,
                    mappings: Vec::new(),
                    observations: vec![crate::inspect_system::Observation {
                        pid,
                        path: summary.path.to_string(),
                        exports: Vec::new(),
                        tables: Vec::new(),
                        interfaces: Vec::new(),
                        double_loaded: false,
                        evidence: crate::inspect_system::ObservationEvidence::DeepScan,
                    }],
                    admission: crate::inspect_system::AdmissionRecord::Admitted {
                        class: "exact",
                        endpoints: 3,
                    },
                }
            })
            .collect::<Vec<_>>();
        crate::inspect_system::Catalog {
            scan_status: "complete",
            lowering: None,
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
            processes: vec![crate::inspect_system::ProcessRecord {
                pid,
                status: crate::inspect_system::MemberStatus::Scanned,
                objects: (0..objects.len()).collect(),
                generation,
            }],
            objects,
            relationships: Vec::new(),
            admission: crate::inspect_system::AdmissionSummary {
                uncorroborated_candidates: 0,
                module_ambiguous: 0,
                admitted: paths.len(),
                refused: 0,
                unresolved: 0,
            },
            skipped: Vec::new(),
            notes: Vec::new(),
            explanation: None,
            stage_timings: crate::timing::StageTimings::new(),
        }
    }

    /// Review R3/R4: a pass notes the catalog's mapper counts into the
    /// attach set (which sizes uprobe-multi links), from a whole-system
    /// view only; a PID-scoped pass marks the counts scope-limited.
    #[test]
    fn a_pass_notes_mapper_counts_from_a_system_view_only() {
        use crate::attach::capture::MapperEstimate;
        use crate::discovery::inventory_attach_set::tests as fx;
        let pid = std::process::id();
        for (scope, expected) in [
            (Scope::System, MapperEstimate::System(3)),
            (Scope::Pid(pid), MapperEstimate::ScopeLimited),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let a = fx::provider(&dir, "a.so", "provider-a");
            let pins = fx::pass_pins(&[(&a, "sha-a")]);
            let modules = [fx::module(&pins, &a, &fx::offsets(3))];
            let mut coordinator = InventoryCoordinator::new(
                scope,
                HookRegistry::builtin(),
                Vec::new(),
                OsProcessSource,
                RegistryLimits::default_limits(),
            )
            .unwrap();
            let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
            let plan = fx::lower_named(&modules, &pins, policy);
            let object = coordinator.attach_set.absorb(&plan, &pins).delta.endpoints[0].object;
            assert_eq!(
                coordinator.attach_set.mappers(object),
                MapperEstimate::Unknown
            );
            let mut catalog = capture_catalog(&pins, &[&a], pid, None);
            catalog.objects[0].mappings = vec![(pid, None), (pid + 1, None), (pid + 2, None)];
            coordinator.apply_catalog(
                catalog,
                &mut UnavailableImageGuard,
                &mut ScanOnlyIdentity,
                u64::MAX,
                100,
            );
            assert_eq!(coordinator.attach_set.mappers(object), expected);
        }
    }

    #[test]
    fn capture_receipts_stage_watched_only_for_completely_attached_modules() {
        use crate::attach::capture::{AttachedEndpoint, EndpointFailure, ExtendReceipt};
        use crate::discovery::caller_registry::UseCoverage;
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let b = fx::provider(&dir, "b.so", "provider-b");
        let c = fx::provider(&dir, "c.so", "provider-c");
        let pins = fx::pass_pins(&[(&a, "sha-a"), (&b, "sha-b"), (&c, "sha-c")]);
        let modules = [
            fx::module(&pins, &a, &fx::offsets(3)),
            fx::module(&pins, &b, &fx::offsets(2)),
            fx::module(&pins, &c, &fx::offsets(1)),
        ];
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        let plan = fx::lower_named(&modules, &pins, policy);
        let absorbed = coordinator.attach_set.absorb(&plan, &pins);
        let ids: Vec<u32> = absorbed.delta.endpoints.iter().map(|e| e.id.0).collect();
        assert_eq!(ids, [0, 1, 2, 3, 4, 5]);
        let verdicts = absorbed.verdicts;
        let pid = std::process::id();
        let caller = coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        // The generation collection reads for this (live) process.
        let generation = Some(crate::inspect_system::MemberGeneration {
            start_time: crate::process::process_start_time(pid).ok(),
            exe: crate::discovery::caller_registry::read_exe_identity(pid),
        });
        let catalog = capture_catalog(&pins, &[&a, &b, &c], pid, generation);
        let coverage_of = |coordinator: &InventoryCoordinator<_>, path: &std::path::Path| {
            let edge = coordinator
                .registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && coordinator
                            .registry
                            .module(edge.module)
                            .is_some_and(|module| module.paths.contains(path.to_str().unwrap()))
                })
                .unwrap();
            coordinator.registry.coverage(edge)
        };

        // Scan lane: no capture, every edge stays scan-only.
        coordinator.project_catalog(&catalog, &verdicts, 60);
        coordinator.registry.publish();
        assert_eq!(
            coverage_of(&coordinator, &a),
            UseCoverage::Unknown(UnknownReason::ScanOnly)
        );

        // A capture scoped to another process stages nothing for this one.
        coordinator.begin_capture_coverage(Some(ScopeIncarnation {
            pid: pid + 1,
            start_time: crate::process::process_start_time(pid).ok(),
        }));
        coordinator.project_catalog(&catalog, &verdicts, 70);
        coordinator.registry.publish();
        assert_eq!(
            coverage_of(&coordinator, &a),
            UseCoverage::Unknown(UnknownReason::ScanOnly)
        );

        coordinator.begin_capture_coverage(Some(ScopeIncarnation {
            pid,
            start_time: crate::process::process_start_time(pid).ok(),
        }));
        let endpoint = |id: u32| absorbed.delta.endpoints[id as usize];
        let attached = |id: u32, at_ns: u64| AttachedEndpoint {
            id: endpoint(id).id,
            object: endpoint(id).object,
            at_ns,
        };
        // a.so complete (0..2), b.so one failed (3) one attached (4),
        // c.so (5) deferred.
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![attached(0, 100), attached(2, 120), attached(4, 130)],
            failed: vec![EndpointFailure {
                id: endpoint(3).id,
                object: endpoint(3).object,
                reason: "kernel refused".into(),
                link_retained: false,
            }],
            ..ExtendReceipt::default()
        });
        coordinator.project_catalog(&catalog, &verdicts, 140);
        coordinator.registry.publish();
        assert_eq!(
            coverage_of(&coordinator, &a),
            UseCoverage::Unknown(UnknownReason::NotAttached),
            "one of a.so's endpoints is not attached yet"
        );
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![attached(1, 110)],
            ..ExtendReceipt::default()
        });
        coordinator.project_catalog(&catalog, &verdicts, 150);
        coordinator.registry.publish();
        assert_eq!(
            coverage_of(&coordinator, &a),
            UseCoverage::WatchedNoUse {
                since_ns: 120,
                until_ns: None
            },
            "since is the last of the module's attaches"
        );
        assert_eq!(
            coverage_of(&coordinator, &b),
            UseCoverage::Unknown(UnknownReason::AttachFailed)
        );
        assert_eq!(
            coverage_of(&coordinator, &c),
            UseCoverage::Unknown(UnknownReason::NotAttached)
        );

        // An exec of the PID target makes coverage unproven, sticky.
        coordinator.note_capture_custody(&ScopeCustody::PidUnproven {
            at_ns: 160,
            reason: "an exec of the PID target was observed".into(),
        });
        coordinator.note_capture_custody(&ScopeCustody::PidHeld);
        coordinator.project_catalog(&catalog, &verdicts, 170);
        coordinator.registry.publish();
        assert!(
            matches!(
                coverage_of(&coordinator, &a),
                UseCoverage::Unknown(UnknownReason::Loss(ref reason)) if reason.contains("exec")
            ),
            "{:?}",
            coverage_of(&coordinator, &a)
        );
    }

    #[test]
    fn failed_endpoints_stage_a_partial_attach_gap_per_module() {
        // O1 endpoint evidence (fix round 1): failed endpoints are sticky
        // (never retried), so a module with failed members undercounts —
        // its counted uses are lower bounds. Each receipt with new
        // failures stages one gap per affected module (bounded: every
        // failed endpoint lands in exactly one receipt): the oracle
        // withholds COUNT-EXACT over it. The subject and reason shapes
        // are pinned verbatim: the oracle matches them.
        use crate::attach::capture::{AttachedEndpoint, EndpointFailure, ExtendReceipt};
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let pins = fx::pass_pins(&[(&a, "sha-a")]);
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        let absorbed = coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&pins, &a, &fx::offsets(3))),
                &pins,
                policy,
            ),
            &pins,
        );
        let verdicts = absorbed.verdicts;
        let pid = std::process::id();
        let _caller = coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let generation = Some(crate::inspect_system::MemberGeneration {
            start_time: crate::process::process_start_time(pid).ok(),
            exe: crate::discovery::caller_registry::read_exe_identity(pid),
        });
        let catalog = capture_catalog(&pins, &[&a], pid, generation);
        coordinator.begin_capture_coverage(None);
        coordinator.project_catalog(&catalog, &verdicts, 60);
        coordinator.registry.publish();
        let endpoint = |id: u32| absorbed.delta.endpoints[id as usize];
        let failed = |id: u32| EndpointFailure {
            id: endpoint(id).id,
            object: endpoint(id).object,
            reason: "kernel refused".into(),
            link_retained: false,
        };
        // One attached, one failed: partial attach.
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![AttachedEndpoint {
                id: endpoint(0).id,
                object: endpoint(0).object,
                at_ns: 100,
            }],
            failed: vec![failed(1)],
            ..ExtendReceipt::default()
        });
        // A second failure for the same module: a second gap with the
        // cumulative count.
        coordinator.note_extend_receipt(&ExtendReceipt {
            failed: vec![failed(2)],
            ..ExtendReceipt::default()
        });
        // An endpoint no module claims: unattributed, run-wide.
        coordinator.note_extend_receipt(&ExtendReceipt {
            failed: vec![EndpointFailure {
                id: crate::discovery::inventory_attach_set::EndpointId(9999),
                object: endpoint(0).object,
                reason: "kernel refused".into(),
                link_retained: false,
            }],
            ..ExtendReceipt::default()
        });
        coordinator.commit_batch(false).unwrap();
        let gaps: Vec<_> = coordinator
            .registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == PARTIAL_ATTACH_SUBJECT)
            .collect();
        assert_eq!(
            gaps.len(),
            3,
            "one gap per module per failure receipt, plus the unattributed one: {:?}",
            coordinator.registry.gaps()
        );
        assert_eq!(
            gaps[0].reason,
            "1 of 3 endpoints failed to attach (sticky, never retried); counted uses are lower bounds"
        );
        assert_eq!(
            gaps[1].reason,
            "2 of 3 endpoints failed to attach (sticky, never retried); counted uses are lower bounds"
        );
        assert!(
            gaps[0].module.is_some() && gaps[1].module.is_some(),
            "attributed to the failed module: {:?}",
            gaps[0].module
        );
        assert_eq!(
            gaps[2].module, None,
            "the unclaimed endpoint reports run-wide"
        );
    }

    #[test]
    fn deferred_endpoints_stage_a_partial_attach_gap() {
        // O1 endpoint evidence (fix round 2, F3): attachment deferred
        // past the receipt leaves the endpoint's calls uncounted, so a
        // module with deferred members undercounts exactly like one
        // with failed members — its counted uses are lower bounds and
        // the oracle withholds COUNT-EXACT over it. The gap is sticky
        // even when a later receipt attaches the endpoint: calls made
        // while it was unattached never come back.
        use crate::attach::capture::{AttachedEndpoint, ExtendReceipt};
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let pins = fx::pass_pins(&[(&a, "sha-a")]);
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        let absorbed = coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&pins, &a, &fx::offsets(3))),
                &pins,
                policy,
            ),
            &pins,
        );
        let verdicts = absorbed.verdicts;
        let pid = std::process::id();
        let _caller = coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let generation = Some(crate::inspect_system::MemberGeneration {
            start_time: crate::process::process_start_time(pid).ok(),
            exe: crate::discovery::caller_registry::read_exe_identity(pid),
        });
        let catalog = capture_catalog(&pins, &[&a], pid, generation);
        coordinator.begin_capture_coverage(None);
        coordinator.project_catalog(&catalog, &verdicts, 60);
        coordinator.registry.publish();
        let endpoint = |id: u32| absorbed.delta.endpoints[id as usize];
        let deferred = |id: u32| crate::discovery::inventory_attach_set::TargetDelta {
            endpoints: vec![endpoint(id)],
            objects: vec![endpoint(id).object],
        };
        // One attached, one deferred: partial attach.
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![AttachedEndpoint {
                id: endpoint(0).id,
                object: endpoint(0).object,
                at_ns: 100,
            }],
            deferred: deferred(1),
            ..ExtendReceipt::default()
        });
        // A retry attaches the deferred endpoint: no new gap, but the
        // earlier one stands (the deferral window's calls are lost).
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![AttachedEndpoint {
                id: endpoint(1).id,
                object: endpoint(1).object,
                at_ns: 200,
            }],
            ..ExtendReceipt::default()
        });
        coordinator.commit_batch(false).unwrap();
        let gaps: Vec<_> = coordinator
            .registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == PARTIAL_ATTACH_SUBJECT)
            .collect();
        assert_eq!(
            gaps.len(),
            1,
            "the deferred receipt stages one gap, the clean retry none: {:?}",
            coordinator.registry.gaps()
        );
        assert!(
            gaps[0].module.is_some(),
            "attributed to the deferred module: {:?}",
            gaps[0].module
        );
        assert!(
            gaps[0].reason.contains("still deferred"),
            "the reason names the deferral: {}",
            gaps[0].reason
        );
    }

    #[test]
    fn partial_or_unrecorded_admission_is_never_watched() {
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let pins = fx::pass_pins(&[(&a, "sha-a")]);
        let module = fx::module(&pins, &a, &fx::offsets(2));
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        let absorbed = coordinator.attach_set.absorb(
            &fx::lower_named(std::slice::from_ref(&module), &pins, policy),
            &pins,
        );
        let key = absorbed.verdicts.keys().next().unwrap().clone();
        coordinator.begin_capture_coverage(None);
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: absorbed
                .delta
                .endpoints
                .iter()
                .map(|endpoint| crate::attach::capture::AttachedEndpoint {
                    id: endpoint.id,
                    object: endpoint.object,
                    at_ns: 10,
                })
                .collect(),
            ..ExtendReceipt::default()
        });
        let whole = AttachVerdict::Admitted {
            endpoints: 2,
            reasons: Vec::new(),
        };
        assert_eq!(
            coordinator.capture_coverage_note(ScopeVerdict::Inside, &key, Some(&whole)),
            Some(CoverageNote::Watched { since_ns: 10 })
        );
        let partial = AttachVerdict::Admitted {
            endpoints: 2,
            reasons: vec![
                "admitted module needs 3 more; the set is full — 3 endpoints not added; kept its 2 retained endpoints"
                    .into(),
            ],
        };
        assert_eq!(
            coordinator.capture_coverage_note(ScopeVerdict::Inside, &key, Some(&partial)),
            Some(CoverageNote::Unknown(UnknownReason::CapacityLimited(
                ENDPOINT_RESOURCE
            )))
        );
        let refused = AttachVerdict::Refused {
            reason: "no".into(),
        };
        assert_eq!(
            coordinator.capture_coverage_note(ScopeVerdict::Inside, &key, Some(&refused)),
            None
        );
        assert_eq!(
            coordinator.capture_coverage_note(ScopeVerdict::Inside, &key, None),
            None
        );
    }

    // ---- C3 review fixes: incarnation-scoped, demotable capture coverage ----

    /// A coordinator over a scripted process source, its attach set holding
    /// one provider with `endpoints` entries, and that provider's catalog
    /// for `pid`.
    struct CaptureScene {
        _dir: tempfile::TempDir,
        source: crate::discovery::caller_registry::tests::ScriptedSource,
        coordinator: InventoryCoordinator<crate::discovery::caller_registry::tests::ScriptedSource>,
        delta: TargetDelta,
        verdicts: BTreeMap<AttachModuleKey, AttachVerdict>,
        pins: crate::discovery::identity::PinnedObjects,
        path: PathBuf,
    }

    impl CaptureScene {
        fn new(endpoints: u64) -> Self {
            use crate::discovery::inventory_attach_set::tests as fx;
            let dir = tempfile::tempdir().unwrap();
            let path = fx::provider(&dir, "a.so", "provider-a");
            let pins = fx::pass_pins(&[(&path, "sha-a")]);
            let module = fx::module(&pins, &path, &fx::offsets(endpoints));
            let source = crate::discovery::caller_registry::tests::ScriptedSource::default();
            let mut coordinator = InventoryCoordinator::new(
                Scope::Pid(std::process::id()),
                HookRegistry::builtin(),
                Vec::new(),
                source.clone(),
                RegistryLimits::default_limits(),
            )
            .unwrap();
            let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
            let absorbed = coordinator.attach_set.absorb(
                &fx::lower_named(std::slice::from_ref(&module), &pins, policy),
                &pins,
            );
            Self {
                _dir: dir,
                source,
                coordinator,
                delta: absorbed.delta,
                verdicts: absorbed.verdicts,
                pins,
                path,
            }
        }

        fn attach_all(&mut self, at_ns: u64, custody: ScopeCustody) {
            let receipt = ExtendReceipt {
                attached: self
                    .delta
                    .endpoints
                    .iter()
                    .map(|endpoint| crate::attach::capture::AttachedEndpoint {
                        id: endpoint.id,
                        object: endpoint.object,
                        at_ns,
                    })
                    .collect(),
                custody: Some(custody),
                ..ExtendReceipt::default()
            };
            self.coordinator.note_extend_receipt(&receipt);
        }

        fn project(&mut self, pid: u32, now_ns: u64) {
            let path = self.path.clone();
            self.project_paths(pid, &[&path], now_ns);
        }

        fn project_paths(&mut self, pid: u32, paths: &[&std::path::Path], now_ns: u64) {
            // Collected under the incarnation reconcile holds for the pid.
            let generation = self
                .coordinator
                .adapter
                .live_id(pid)
                .and_then(|caller| self.coordinator.adapter.record(caller))
                .map(|record| crate::inspect_system::MemberGeneration {
                    start_time: record.start_time,
                    exe: record.exe.clone(),
                });
            let catalog = capture_catalog(&self.pins, paths, pid, generation);
            self.coordinator
                .project_catalog(&catalog, &self.verdicts, now_ns);
        }

        fn coverage(&self, caller: CallerId) -> crate::discovery::caller_registry::UseCoverage {
            let registry = &self.coordinator.registry;
            let edge = registry
                .edges()
                .find(|edge| edge.caller == caller)
                .expect("the caller has an edge");
            registry.coverage(edge)
        }
    }

    fn watched(coverage: &crate::discovery::caller_registry::UseCoverage) -> bool {
        matches!(
            coverage,
            crate::discovery::caller_registry::UseCoverage::WatchedNoUse { .. }
        )
    }

    fn lost_with(coverage: &crate::discovery::caller_registry::UseCoverage, needle: &str) -> bool {
        matches!(
            coverage,
            crate::discovery::caller_registry::UseCoverage::Unknown(UnknownReason::Loss(reason))
                if reason.contains(needle)
        )
    }

    fn incarnation(pid: u32, start_time: u64) -> Option<ScopeIncarnation> {
        Some(ScopeIncarnation {
            pid,
            start_time: Some(start_time),
        })
    }

    fn witness_batch() -> WitnessBatch {
        WitnessBatch {
            domain: crate::attach::capture::NativeDomainId::mint(),
            phase: crate::attach::capture::CapturePhase::Active,
            rows: Vec::new(),
            integrity: Vec::new(),
            integrity_total: 0,
            visited: 0,
            sweep_completed: true,
            sweeps_completed: 1,
            row_bound_reached: false,
            deadline_reached: false,
            read_failures: Vec::new(),
            unrecorded_rows: 0,
            sweep_gaps: false,
            counts: Vec::new(),
            refresh_sweep_completed: true,
            refresh_sweep_gaps: false,
            refresh_deadline_reached: false,
            refresh_sweeps_completed: 1,
            seen_rows: 0,
            pair_limit: 64,
            health: crate::attach::capture::CaptureHealth::default(),
            health_regression: None,
            health_unproven: None,
            health_baseline_ns: 0,
            health_read_ns: 150,
            rows_read_ns: 151,
            changed_objects: Vec::new(),
            custody: ScopeCustody::PidHeld,
            custody_proven_ns: None,
            lifecycle_proven_ns: u64::MAX,
            lifecycle_loss: None,
            unsettled: false,
        }
    }

    #[test]
    fn pid_reuse_within_a_pass_is_never_watched_and_demotes_the_original() {
        // I2/M10: coverage is scoped by incarnation (pid + start time), and
        // a custody loss ends watches already staged in the same batch (no
        // clean read proved them, so they read unknown; C5.2 D2).
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let original = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(7, 500));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(7, 120);
        scene.coordinator.registry.publish();
        assert_eq!(
            scene.coverage(original),
            crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
                since_ns: 100,
                until_ns: None
            }
        );

        // Within the next pass the original exits and pid 7 is reused.
        scene.source.kill(7);
        scene.source.spawn(7, 600);
        let observed: BTreeSet<u32> = [7].into();
        let events = scene.coordinator.adapter.reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            130,
        );
        let reused = match events.as_slice() {
            [crate::discovery::caller_registry::CallerEvent::Reused { old, new }] => {
                assert_eq!(*old, original);
                *new
            }
            other => panic!("expected one reuse, got {other:?}"),
        };
        // The pass stages the reused pid's edge, then (later in the same
        // batch) the facade's custody poll reports the loss.
        scene.project(7, 140);
        assert_eq!(
            scene.coordinator.capture_scope_verdict(reused, 7),
            ScopeVerdict::Outside,
            "a reused pid is another incarnation"
        );
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidLost {
                at_ns: 125,
                reason: "PID custody lost: the PID target exited".into(),
            });
        scene.coordinator.registry.publish();
        assert!(
            !watched(&scene.coverage(reused)),
            "{:?}",
            scene.coverage(reused)
        );
        assert!(
            lost_with(&scene.coverage(original), "PID target exited"),
            "{:?}",
            scene.coverage(original)
        );
        assert!(
            scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "native capture scope custody unproven"),
        );
        // A later pass still never watches the reused incarnation.
        scene.project(7, 160);
        scene.coordinator.registry.publish();
        assert!(!watched(&scene.coverage(reused)));
    }

    #[test]
    fn a_nonleader_exec_before_the_first_pass_never_reads_watched() {
        // I2/M10: the exec record arrives after the first projection staged
        // a watch in the same batch; the custody end wins (no clean read
        // proved the watch), and every later pass reads the exec loss.
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(9, 700);
        scene.source.exec(9, 200, "/bin/successor");
        let caller = scene
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(9, 700));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(9, 120);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidUnproven {
                at_ns: 90,
                reason: "an exec of the PID target was observed".into(),
            });
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "exec"),
            "{:?}",
            scene.coverage(caller)
        );
        scene.project(9, 140);
        scene.coordinator.registry.publish();
        assert!(lost_with(&scene.coverage(caller), "exec"));
        // A start time that cannot be proven never matches either.
        let mut blind = CaptureScene::new(1);
        blind.source.spawn(11, 800);
        let other = blind
            .coordinator
            .adapter
            .admit(11, ImageAuthority::ScanPinned, 50)
            .unwrap();
        blind
            .coordinator
            .begin_capture_coverage(Some(ScopeIncarnation {
                pid: 11,
                start_time: None,
            }));
        assert_eq!(
            blind.coordinator.capture_scope_verdict(other, 11),
            ScopeVerdict::Unproven
        );
    }

    #[test]
    fn a_second_image_of_the_scope_incarnation_is_not_the_bound_caller() {
        let mut scene = CaptureScene::new(1);
        scene.source.spawn(5, 300);
        let first = scene
            .coordinator
            .adapter
            .admit(5, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(5, 300));
        assert_eq!(
            scene.coordinator.capture_scope_verdict(first, 5),
            ScopeVerdict::Inside
        );
        scene.source.exec(5, 201, "/bin/next");
        let observed: BTreeSet<u32> = [5].into();
        let events =
            scene
                .coordinator
                .adapter
                .reconcile(&observed, &mut |_| ImageAuthority::ScanPinned, 60);
        let [crate::discovery::caller_registry::CallerEvent::ExecRetired { new, .. }] =
            events.as_slice()
        else {
            panic!("expected an exec retirement: {events:?}");
        };
        assert_eq!(
            scene.coordinator.capture_scope_verdict(*new, 5),
            ScopeVerdict::LaterImage
        );
    }

    #[test]
    fn health_and_changed_objects_withhold_demote_or_restart_watches() {
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(7, 500));
        // I5: unproven health withholds the first watch; it is not sticky.
        let mut unproven = witness_batch();
        unproven.health_unproven = Some("native capture health was unreadable".into());
        scene.coordinator.note_witness_batch(&unproven);
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(7, 120);
        scene.coordinator.registry.publish();
        assert!(!watched(&scene.coverage(caller)));
        scene.coordinator.note_witness_batch(&witness_batch());
        scene.project(7, 130);
        scene.coordinator.registry.publish();
        assert!(watched(&scene.coverage(caller)));
        // Closure 2: a rise demotes the interval (dated at the baseline);
        // a new interval starts only from the detecting read.
        let mut rose = witness_batch();
        rose.health_regression =
            Some("native capture health counters rose: EVIDENCE[3] 0->1".into());
        rose.health_baseline_ns = 125;
        rose.health_read_ns = 160;
        scene.coordinator.note_witness_batch(&rose);
        scene.coordinator.registry.publish();
        assert!(lost_with(&scene.coverage(caller), "EVIDENCE[3]"));
        scene.project(7, 170);
        scene.coordinator.registry.publish();
        assert_eq!(
            scene.coverage(caller),
            crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
                since_ns: 160,
                until_ns: None
            },
            "the restarted watch never covers the baseline..detection window"
        );
        // M8: a provider modified in place makes its module unknown.
        let mut changed = witness_batch();
        changed.changed_objects = vec![scene.delta.endpoints[0].object];
        scene.coordinator.note_witness_batch(&changed);
        scene.project(7, 180);
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "modified in place"),
            "{:?}",
            scene.coverage(caller)
        );
    }

    #[test]
    fn stop_freezes_watches_at_the_last_clean_read() {
        // Closure 1/4: stop never wipes no-use; each watch ends at the last
        // proven-clean read, an unproven terminal read never extends it,
        // and a watch no clean read proved reads unknown.
        let mut scene = CaptureScene::new(1);
        scene.source.spawn(8, 510);
        let caller = scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(8, 510));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(8, 120);
        let mut clean = witness_batch();
        clean.health_read_ns = 200;
        scene.coordinator.note_witness_batch(&clean);
        let mut terminal = witness_batch();
        terminal.health_read_ns = 280;
        terminal.health_unproven = Some("native capture health was unreadable".into());
        terminal.unsettled = true;
        scene.coordinator.note_witness_batch(&terminal);
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        let frozen = crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
            since_ns: 100,
            until_ns: Some(200),
        };
        assert_eq!(scene.coverage(caller), frozen);
        scene.project(8, 320);
        scene.coordinator.registry.publish();
        assert_eq!(
            scene.coverage(caller),
            frozen,
            "nothing restarts after stop"
        );

        let mut unproved = CaptureScene::new(1);
        unproved.source.spawn(9, 520);
        let caller = unproved
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 50)
            .unwrap();
        unproved
            .coordinator
            .begin_capture_coverage(incarnation(9, 520));
        unproved.attach_all(100, ScopeCustody::PidHeld);
        unproved.project(9, 120);
        unproved.coordinator.end_capture_coverage(300);
        unproved.coordinator.registry.publish();
        assert!(
            lost_with(&unproved.coverage(caller), "clean health read"),
            "{:?}",
            unproved.coverage(caller)
        );
    }

    /// A scene with one caller watched since 100 and a clean read at 200.
    fn watched_scene(pid: u32, start: u64) -> (CaptureScene, CallerId) {
        let mut scene = CaptureScene::new(1);
        scene.source.spawn(pid, start);
        let caller = scene
            .coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(pid, start));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(pid, 120);
        let mut clean = witness_batch();
        clean.health_read_ns = 200;
        scene.coordinator.note_witness_batch(&clean);
        (scene, caller)
    }

    fn last_clean(scene: &CaptureScene) -> Option<u64> {
        scene.coordinator.capture.as_ref().unwrap().last_clean_ns
    }

    #[test]
    fn nothing_noted_after_stop_touches_a_frozen_interval() {
        // Closure 2 I-1: the normal end of a --pid run. The target exits
        // after stop; the terminal batch carries the lost custody, dated
        // at the last held poll (before the clean read's stamp).
        let (mut scene, caller) = watched_scene(7, 500);
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        let frozen = crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
            since_ns: 100,
            until_ns: Some(200),
        };
        assert_eq!(scene.coverage(caller), frozen);
        let mut terminal = witness_batch();
        terminal.health_read_ns = 310;
        terminal.health_regression =
            Some("native capture health counters rose: EVIDENCE[0] 0->1".into());
        terminal.health_baseline_ns = 150;
        terminal.custody = ScopeCustody::PidLost {
            at_ns: 199,
            reason: "PID custody lost: the PID target exited".into(),
        };
        scene.coordinator.note_witness_batch(&terminal);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidUnproven {
                at_ns: 150,
                reason: "an exec of the PID target was observed".into(),
            });
        scene.coordinator.note_extend_receipt(&ExtendReceipt {
            custody: Some(ScopeCustody::PidLost {
                at_ns: 199,
                reason: "PID custody lost".into(),
            }),
            ..ExtendReceipt::default()
        });
        scene.project(7, 320);
        scene.coordinator.registry.publish();
        assert_eq!(scene.coverage(caller), frozen, "a post-stop note wiped it");
        assert_eq!(last_clean(&scene), Some(200));
    }

    #[test]
    fn a_clean_read_never_claims_past_its_custody_proof() {
        // Closure 2 I-1(b): the custody poll precedes the health stamp.
        let (mut scene, _) = watched_scene(7, 500);
        let mut read = witness_batch();
        read.health_read_ns = 260;
        read.custody_proven_ns = Some(240);
        scene.coordinator.note_witness_batch(&read);
        assert_eq!(last_clean(&scene), Some(240));
    }

    #[test]
    fn each_clean_read_gate_blocks_the_clean_instant() {
        // Closure 2 M-1: unproven health, a rise, unheld custody, and an
        // already-unproven capture each keep the last clean instant.
        let gated: [fn(&mut WitnessBatch); 3] = [
            |batch| batch.health_unproven = Some("unreadable".into()),
            |batch| batch.health_regression = Some("EVIDENCE[1] 0->1".into()),
            |batch| {
                batch.custody = ScopeCustody::PidUnproven {
                    at_ns: 250,
                    reason: "leader exited".into(),
                }
            },
        ];
        for gate in gated {
            let (mut scene, _) = watched_scene(7, 500);
            let mut read = witness_batch();
            read.health_read_ns = 260;
            gate(&mut read);
            scene.coordinator.note_witness_batch(&read);
            assert_eq!(last_clean(&scene), Some(200), "{read:?}");
        }
        let (mut scene, _) = watched_scene(7, 500);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidUnproven {
                at_ns: 210,
                reason: "ring loss".into(),
            });
        let mut read = witness_batch();
        read.health_read_ns = 260;
        scene.coordinator.note_witness_batch(&read);
        assert_eq!(
            last_clean(&scene),
            Some(200),
            "an unproven capture is never clean again"
        );
    }

    // ---- Task 6 C5.2: settle native reads at stop ----

    fn frozen(since_ns: u64, until_ns: u64) -> crate::discovery::caller_registry::UseCoverage {
        crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
            since_ns,
            until_ns: Some(until_ns),
        }
    }

    #[test]
    fn a_custody_loss_before_stop_freezes_watches_at_the_last_clean_read() {
        // C5.2 D2: watch at 100, clean read at 200, custody lost at 250,
        // stop at 300 → `WatchedNoUse{100, Some(200)}`, not a demotion.
        let (mut scene, caller) = watched_scene(7, 500);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidLost {
                at_ns: 250,
                reason: "PID custody lost: the PID target exited".into(),
            });
        scene.coordinator.registry.publish();
        assert_eq!(scene.coverage(caller), frozen(100, 200));
        assert!(
            scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "native capture scope custody unproven"
                    && gap.reason.contains("PID target exited")
                    && gap
                        .reason
                        .contains("earlier of the custody instant and the last clean read")),
            "the custody loss is disclosed with what it ends"
        );
        scene.project(7, 280);
        scene.coordinator.end_capture_coverage(300);
        scene.project(7, 320);
        scene.coordinator.registry.publish();
        assert_eq!(scene.coverage(caller), frozen(100, 200), "stop keeps it");

        // A loss dated before the last clean read (an exec record serviced
        // after that read) ends the interval at the loss.
        let (mut scene, caller) = watched_scene(9, 510);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidUnproven {
                at_ns: 150,
                reason: "an exec of the PID target was observed".into(),
            });
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        assert_eq!(scene.coverage(caller), frozen(100, 150));

        // Review fix 1: an undecodable record dated at the last proven
        // drain (60, before the watch) leaves no clean interval at all.
        let (mut scene, caller) = watched_scene(11, 520);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidUnproven {
                at_ns: 60,
                reason: "a lifecycle record was lost: short DISCOVERY record".into(),
            });
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "short DISCOVERY record")
                && lost_with(
                    &scene.coverage(caller),
                    "no clean read proved the watch before native capture scope custody became unproven"
                ),
            "{:?}",
            scene.coverage(caller)
        );
    }

    #[test]
    fn a_clean_read_never_claims_past_the_lifecycle_drain_horizon() {
        // C5.2 closure I-1: drained at 1000, a record reserved at 1010,
        // clean terminal read at 1020, stop at 1030: the interval ends at
        // 1000, so the loss found after stop (dated >= 1000) is outside it.
        let (mut scene, caller) = watched_scene(7, 500);
        let mut terminal = witness_batch();
        terminal.health_read_ns = 1020;
        terminal.lifecycle_proven_ns = 1000;
        scene.coordinator.note_witness_batch(&terminal);
        assert_eq!(last_clean(&scene), Some(1000));
        scene.coordinator.end_capture_coverage(1030);
        scene.coordinator.registry.publish();
        assert_eq!(scene.coverage(caller), frozen(100, 1000));

        // D2, PID: the only clean read is capped at a drain at 60, before
        // the watch began, so a later exit at 200 never freezes {100, 200}.
        let mut scene = CaptureScene::new(1);
        scene.source.spawn(9, 510);
        let caller = scene
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(9, 510));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(9, 120);
        let mut read = witness_batch();
        read.health_read_ns = 200;
        read.lifecycle_proven_ns = 60;
        scene.coordinator.note_witness_batch(&read);
        assert_eq!(last_clean(&scene), Some(60));
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidLost {
                at_ns: 200,
                reason: "PID custody lost: the PID target exited".into(),
            });
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "PID target exited"),
            "{:?}",
            scene.coverage(caller)
        );
    }

    #[test]
    fn a_system_lifecycle_loss_is_a_sticky_demotion() {
        // C5.2 D4: DISCOVERY loss in system scope may hide an exec or exit
        // of any watched caller: every watch demotes, and none restarts.
        let mut scene = CaptureScene::new(1);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene.coordinator.begin_capture_coverage(None);
        scene.attach_all(100, ScopeCustody::System);
        scene.project(7, 120);
        let mut clean = witness_batch();
        clean.custody = ScopeCustody::System;
        clean.health_read_ns = 200;
        scene.coordinator.note_witness_batch(&clean);
        scene.coordinator.registry.publish();
        assert!(watched(&scene.coverage(caller)));
        let mut lost = witness_batch();
        lost.custody = ScopeCustody::System;
        lost.health_read_ns = 260;
        lost.lifecycle_loss = Some(crate::attach::capture::LifecycleLoss {
            at_ns: 200,
            reason: "the lifecycle ring lost records (DISCOVERY ring loss 0 -> 3)".into(),
        });
        scene.coordinator.note_witness_batch(&lost);
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "ring loss"),
            "{:?}",
            scene.coverage(caller)
        );
        assert_eq!(last_clean(&scene), Some(200), "a lossy read is not clean");
        assert!(
            scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(
                    |gap| gap.subject == "native capture lifecycle evidence lost"
                        && gap.reason.contains("no watch starts again in this capture")
                        && !gap.reason.contains("may start")
                ),
            "{:?}",
            scene.coordinator.registry.gaps()
        );
        // Sticky: a later clean read and projection never restart a watch.
        let mut later = witness_batch();
        later.custody = ScopeCustody::System;
        later.health_read_ns = 280;
        scene.coordinator.note_witness_batch(&later);
        scene.project(7, 290);
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "ring loss"),
            "{:?}",
            scene.coverage(caller)
        );
    }

    #[test]
    fn a_saturated_pair_set_withholds_the_watch() {
        // C5.2 pair precondition: once the seen set is full, or a row went
        // unrecorded, no read proves no-use: no watch starts and no read
        // extends one.
        let saturations: [fn(&mut WitnessBatch); 2] = [
            |batch| batch.seen_rows = batch.pair_limit,
            |batch| batch.unrecorded_rows = 1,
        ];
        for saturate in saturations {
            let (mut scene, caller) = watched_scene(7, 500);
            let mut read = witness_batch();
            read.health_read_ns = 260;
            saturate(&mut read);
            scene.coordinator.note_witness_batch(&read);
            assert_eq!(last_clean(&scene), Some(200), "{read:?}");
            scene.coordinator.end_capture_coverage(300);
            scene.coordinator.registry.publish();
            assert_eq!(scene.coverage(caller), frozen(100, 200), "{read:?}");

            let mut scene = CaptureScene::new(1);
            scene.source.spawn(8, 510);
            let caller = scene
                .coordinator
                .adapter
                .admit(8, ImageAuthority::ScanPinned, 50)
                .unwrap();
            scene
                .coordinator
                .begin_capture_coverage(incarnation(8, 510));
            let mut read = witness_batch();
            saturate(&mut read);
            scene.coordinator.note_witness_batch(&read);
            scene.attach_all(100, ScopeCustody::PidHeld);
            scene.project(8, 120);
            scene.coordinator.registry.publish();
            assert!(
                !watched(&scene.coverage(caller)),
                "{read:?}: {:?}",
                scene.coverage(caller)
            );
        }
    }

    // ---- Task 6 C4: native witness binding through the coordinator ----

    type ScriptedPin = (u32, u64);

    /// Scripted cookie answers per (pin, domain); never a host read.
    #[derive(Default)]
    struct ScriptedCookies {
        answers: std::collections::HashMap<(ScriptedPin, NativeDomainId), CookieQuery>,
    }

    impl NativeIdentity<ScriptedPin> for ScriptedCookies {
        fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
            None
        }

        fn query_cookie(&mut self, domain: NativeDomainId, pin: &ScriptedPin) -> CookieQuery {
            self.answers
                .get(&(*pin, domain))
                .cloned()
                .unwrap_or(CookieQuery::NoCookie)
        }
    }

    use crate::attach::capture::{CookieQuery, DomainCookie, ExecCoverage};
    use crate::discovery::caller_registry::{UnboundUse, UseCoverage};

    /// Facade stamps for scripted native batches: strictly increasing, so
    /// each batch follows the one staged before it.
    struct Stamps(std::cell::Cell<u64>);

    impl Stamps {
        fn from(start: u64) -> Self {
            Self(std::cell::Cell::new(start))
        }

        fn tick(&self) -> u64 {
            let at = self.0.get() + 10;
            self.0.set(at);
            at
        }

        /// One readable witness read of `domain`: health at the stamp, rows
        /// read just after it.
        fn read(&self, domain: NativeDomainId, rows: Vec<WitnessRow>) -> NativeBatch {
            let at = self.tick();
            let mut read = witness_batch();
            read.domain = domain;
            read.rows = rows;
            read.health.discovery_counters = Some([0; 5]);
            read.health_read_ns = at;
            read.rows_read_ns = at + 1;
            NativeBatch::Witness(Box::new(read))
        }

        /// One complete lifecycle drain of `domain`.
        fn drain(&self, domain: NativeDomainId) -> NativeBatch {
            NativeBatch::Lifecycle(DiscoveryBatch::scripted(domain, Vec::new(), self.tick()))
        }
    }

    struct NativeScene {
        scene: CaptureScene,
        domain: NativeDomainId,
        cookies: ScriptedCookies,
        stamps: Stamps,
    }

    impl NativeScene {
        /// One provider with two endpoints in the attach set, pid 7
        /// spawned (start 500) and admitted at 50 and mapped.
        fn new() -> (Self, CallerId) {
            let mut scene = CaptureScene::new(2);
            scene.source.spawn(7, 500);
            let caller = scene
                .coordinator
                .adapter
                .admit(7, ImageAuthority::ScanPinned, 50)
                .unwrap();
            scene.project(7, 60);
            scene.coordinator.commit_batch(false).unwrap();
            (Self::over(scene, 0), caller)
        }

        /// A native lane over `scene` whose exec coverage began at
        /// `coverage_ns`, forwarded the way C5 forwards it: through the
        /// activating extend receipt.
        fn over(mut scene: CaptureScene, coverage_ns: u64) -> Self {
            let domain = NativeDomainId::mint();
            scene.coordinator.note_extend_receipt(&ExtendReceipt {
                activated_roots: true,
                exec_coverage: Some(ExecCoverage::scripted(domain, coverage_ns)),
                ..ExtendReceipt::default()
            });
            Self {
                scene,
                domain,
                cookies: ScriptedCookies::default(),
                stamps: Stamps::from(1_000),
            }
        }

        fn answer(&mut self, pid: u32, start: u64, ticket: u64) {
            self.cookies.answers.insert(
                ((pid, start), self.domain),
                CookieQuery::Cookie(DomainCookie::scripted(self.domain, ticket)),
            );
        }

        fn row(&self, ticket: u64, exec: u64, tgid: u32, t0: u64, member: usize) -> WitnessRow {
            let endpoint = self.scene.delta.endpoints[member];
            WitnessRow::scripted(
                self.domain,
                ticket,
                exec,
                endpoint.object,
                endpoint.id,
                tgid,
                t0,
            )
        }

        fn stage(&mut self, batch: NativeBatch) -> NativeReceipt {
            let now = self.stamps.tick();
            self.scene
                .coordinator
                .stage_native(batch, &mut self.cookies, now)
        }

        fn read(&mut self, rows: Vec<WitnessRow>) -> NativeReceipt {
            let batch = self.stamps.read(self.domain, rows);
            self.stage(batch)
        }

        /// One witness read carrying `counts` (C4): each `(ticket, exec,
        /// member, count)` names the image, the member's object, and the
        /// re-read count. `rows` ride along: a read may carry both.
        fn counts_read(
            &mut self,
            rows: Vec<WitnessRow>,
            counts: Vec<(u64, u64, usize, u64)>,
        ) -> NativeReceipt {
            let at = self.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = self.domain;
            batch.rows = rows;
            batch.counts = counts
                .into_iter()
                .map(
                    |(ticket, exec, member, count)| crate::attach::capture::CallerCountUpdate {
                        image: p11scope_ebpf_common::ImageIdentity {
                            task_cookie: ticket,
                            exec_id: exec,
                        },
                        object: self.scene.delta.endpoints[member].object,
                        count,
                    },
                )
                .collect();
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            self.stage(NativeBatch::Witness(Box::new(batch)))
        }

        fn drain(&mut self) -> NativeReceipt {
            let batch = self.stamps.drain(self.domain);
            self.stage(batch)
        }

        /// Read `rows`, then both horizons, then publish.
        fn witness(&mut self, rows: Vec<WitnessRow>) -> Vec<CallerEvent> {
            let mut events = self.read(rows).events;
            events.extend(self.drain().events);
            events.extend(self.read(Vec::new()).events);
            self.scene.coordinator.commit_batch(false).unwrap();
            events
        }

        fn module_unbound(&self) -> Option<UnboundUse> {
            self.scene
                .coordinator
                .registry
                .modules()
                .next()
                .and_then(|module| module.unbound_use.clone())
        }

        fn preadmission(&self) -> PreadmissionCounters {
            self.scene.coordinator.preadmission_counters().unwrap()
        }

        fn gap_subjects(&self) -> Vec<String> {
            self.scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .map(|gap| gap.subject.clone())
                .collect()
        }
    }

    #[test]
    fn a_bound_row_marks_its_edge_counted() {
        // C7 C4: the scripted row carries a first-sight count of one, so
        // the bound edge reads `counted`.
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
        assert_eq!(native.module_unbound(), None);
        let census = native.scene.coordinator.registry.witness_census();
        assert_eq!((census.rows, census.bound, census.pending), (1, 1, 0));
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 1);
        // Counted needs a count ≥ 1: a bound row reporting zero (only
        // scripted rows do) stays witnessed.
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 0;
        native.witness(vec![row]);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Witnessed { first_ns: 100 }
        );
    }

    #[test]
    fn exit_before_the_poll_is_module_level_use_with_a_named_gap() {
        let (mut native, caller) = NativeScene::new();
        // The row's process (tgid 9) exited before the poll; nothing holds
        // its tgid.
        let row = native.row(41, 1, 9, 100, 1);
        native.witness(vec![row]);
        let unbound = native.module_unbound().expect("module-level positive");
        assert_eq!(unbound.first_ns, 100);
        assert_eq!(unbound.rows, 1);
        assert_eq!(unbound.reasons.get("no_live_caller"), Some(&1));
        assert!(
            native
                .gap_subjects()
                .contains(&"used by an unidentified caller image".to_string()),
            "{:?}",
            native.gap_subjects()
        );
        assert!(
            !native.scene.coverage(caller).is_witnessed(),
            "another caller never inherits it"
        );
    }

    #[test]
    fn a_reused_pid_never_inherits_a_witness_by_pid() {
        let (mut native, caller) = NativeScene::new();
        // pid 7 now holds ticket 99; the row's ticket 41 was its previous
        // owner's.
        native.answer(7, 500, 99);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        assert!(!native.scene.coverage(caller).is_witnessed());
        let unbound = native.module_unbound().unwrap();
        assert_eq!(unbound.reasons.get("cookie_mismatch"), Some(&1));
        let census = native.scene.coordinator.registry.witness_census();
        assert_eq!(census.unbound.get(&UnboundReason::CookieMismatch), Some(&1));
    }

    #[test]
    fn a_proven_exec_transition_retires_the_caller_and_admits_its_successor() {
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let first = native.row(41, 1, 7, 100, 0);
        native.witness(vec![first]);
        let later = native.row(41, 2, 7, 1_100, 1);
        let events = native.witness(vec![later]);
        let [CallerEvent::ExecRetired { old, new }] = events.as_slice() else {
            panic!("{events:?}");
        };
        assert_eq!(*old, caller);
        let adapter = &native.scene.coordinator.adapter;
        assert!(adapter.record(caller).unwrap().retired);
        assert_eq!(adapter.live_id(7), Some(*new));
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            },
            "the old image keeps its count"
        );
        assert_eq!(
            native
                .module_unbound()
                .unwrap()
                .reasons
                .get("exec_transition"),
            Some(&1)
        );
    }

    #[test]
    fn a_bound_caller_without_a_mapping_edge_stays_module_level() {
        let (mut native, _) = NativeScene::new();
        native.scene.source.spawn(8, 600);
        native
            .scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 70)
            .unwrap();
        native.answer(8, 600, 55);
        let row = native.row(55, 1, 8, 100, 0);
        native.witness(vec![row]);
        let unbound = native.module_unbound().unwrap();
        assert_eq!(unbound.reasons.get("no_mapping_edge"), Some(&1));
        assert!(
            native
                .gap_subjects()
                .contains(&"native witness without mapping evidence".to_string())
        );
        assert_eq!(
            native.scene.coordinator.registry.edge_count(),
            1,
            "a witness never invents a mapping"
        );
    }

    #[test]
    fn counted_use_still_binds_after_capture_coverage_ended() {
        // C7 C4: a count is a positive fact like its witness, so it
        // stages after stop too.
        let (mut native, caller) = NativeScene::new();
        native.scene.coordinator.begin_capture_coverage(None);
        native.scene.coordinator.end_capture_coverage(90);
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
    }

    #[test]
    fn a_bound_row_publishes_its_first_sight_count() {
        // C7 C4: bound to an admitted caller incarnation with a count ≥
        // 1, the edge reads `counted` — the count, first record, and
        // pass-resolution recency publish together.
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 3;
        native.witness(vec![row]);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 3);
        assert_eq!(edge.entry_first_seen_ns, Some(100));
        assert_eq!(edge.entry_last_seen_ns, Some(1011));
        assert_eq!(
            registry.entry_observation(edge),
            crate::discovery::caller_registry::EntryObservation::Observed
        );
    }

    #[test]
    fn refresh_counts_advance_the_published_count_at_pass_resolution() {
        // Recency names the read that observed the rise (1011, then
        // 1071) — never the first record, never the commit. The
        // wrong-pass mutation restamps this and fails here.
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 10)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 10);
        assert_eq!(edge.entry_first_seen_ns, Some(100));
        assert_eq!(edge.entry_last_seen_ns, Some(1071));
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
        // A stale refresh (below the staged count) moves nothing.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 7)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 10);
        assert_eq!(edge.entry_last_seen_ns, Some(1071));
    }

    #[test]
    fn counts_for_a_pending_row_stage_when_it_binds() {
        // The refresh arrives while the row waits for its horizons: the
        // edge reads pending-unknown with no count, and binds with the
        // maximum of first sight and refresh once the horizons arrive.
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 2;
        native.read(vec![row]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 0, "nothing stages while pending");
        assert_eq!(
            native.scene.coordinator.presented_coverage(edge),
            UseCoverage::Unknown(UnknownReason::PendingFirstUse)
        );
        native.drain();
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 5);
        assert_eq!(edge.entry_first_seen_ns, Some(100));
        assert_eq!(edge.entry_last_seen_ns, Some(1031));
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
    }

    #[test]
    fn counts_for_an_unbound_row_never_publish() {
        // R-C51-1 and DR-C51-PREADMIT: the row never binds, so its
        // first-sight count, its refreshes, and any later refresh all
        // drop — the edge keeps `use_before_admission` with a zero no
        // consumer reads as fact.
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 99);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 7;
        native.read(vec![row]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 9)]);
        native.drain();
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        native.counts_read(Vec::new(), vec![(41, 1, 0, 20)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Unknown(UnknownReason::UseBeforeAdmission)
        );
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 0);
        assert_eq!(edge.entry_first_seen_ns, None);
        assert_eq!(edge.entry_last_seen_ns, None);
        assert_eq!(
            native
                .module_unbound()
                .unwrap()
                .reasons
                .get("cookie_mismatch"),
            Some(&1)
        );
    }

    #[test]
    fn counted_use_for_a_refused_module_stages_no_count() {
        // Counted needs an admitted module: the backstop drops the
        // count (the witness stands); the absolute staging self-heals
        // on the next refresh after admission.
        let (mut native, caller) = NativeScene::new();
        let refused = ModuleKey::physical(8, 1, 77, Some("sha0077".into()), "/lib/r.so");
        let info = ModuleInfo {
            path: "/lib/r.so".into(),
            key: refused.clone(),
            double_loaded: false,
            build_id: None,
            identity_source: None,
            admission: AdmissionState::Refused,
            admission_class: None,
            admission_endpoints: None,
            admission_reasons: Vec::new(),
        };
        native
            .scene
            .coordinator
            .registry_mut()
            .note_mapping(caller, 7, info, 60);
        native.scene.coordinator.commit_batch(false).unwrap();
        native.scene.coordinator.stage_pair_count(
            caller,
            &refused,
            PairCount {
                count: 5,
                first_ns: 100,
                last_ns: 200,
            },
        );
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let id = registry.module_id_for(&refused).expect("edge retained");
        let edge = registry.edge(caller, id).expect("edge retained");
        assert_eq!(edge.entry_count, 0);
        assert_eq!(
            registry.coverage(edge),
            UseCoverage::Unknown(UnknownReason::NotAdmitted)
        );
    }

    #[test]
    fn a_pair_insert_failure_reads_absent_pairs_uncounted() {
        // C7 C4: CALLER_EVIDENCE[2] fires, so some pair has use but no
        // row — absence proves nothing. The edge reads `uncounted`
        // (never 0), the uncounted reason wins over the coincident
        // loss demotion, and no later pass starts a watch.
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(7, 500));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(7, 120);
        scene.coordinator.registry.publish();
        assert!(watched(&scene.coverage(caller)));
        let mut bad = witness_batch();
        bad.health.caller_evidence = Some([0, 0, 1, 0]);
        bad.health_regression =
            Some("native capture health counters rose: CALLER_EVIDENCE[2] 0->1".into());
        bad.health_baseline_ns = 120;
        bad.health_read_ns = 160;
        scene.coordinator.note_witness_batch(&bad);
        scene.coordinator.registry.publish();
        match scene.coverage(caller) {
            UseCoverage::Unknown(UnknownReason::Uncounted(evidence)) => {
                assert!(
                    evidence.contains("PairInsertFailure"),
                    "points at the evidence: {evidence}"
                );
            }
            other => panic!("an absent pair reads uncounted, got {other:?}"),
        }
        let registry = &scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 0);
        assert_eq!(
            registry.entry_observation(edge),
            crate::discovery::caller_registry::EntryObservation::UnknownUnavailable,
            "a zero under uncounted is never observed"
        );
        assert!(
            registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "usage coverage pair insert failure"),
            "{:?}",
            registry.gaps()
        );
        // A later pass withholds the watch: still uncounted, not watched.
        scene.project(7, 170);
        scene.coordinator.registry.publish();
        assert!(
            matches!(
                scene.coverage(caller),
                UseCoverage::Unknown(UnknownReason::Uncounted(_))
            ),
            "{:?}",
            scene.coverage(caller)
        );
    }

    #[test]
    fn a_rising_count_reads_recent_on_the_dashboard_display_while_in_window() {
        // Dashboard display only: a counted edge reads recently-observed
        // on screen while its rise is in the trailing window, quiet once
        // stale — and a fresh rise always beats quiet. (Each capture is
        // an independent snapshot; only the stamps order them. The
        // recorded signal is per-pass; see
        // `per_pass_activity_reads_a_rise_then_quiet_on_unchanged_passes`.)
        use crate::inventory_present::{Activity, Presentation};
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        let activity_at = |native: &NativeScene, now_ns: u64, window_ns: u64| {
            Presentation::capture_dashboard(
                &native.scene.coordinator,
                "s",
                0,
                now_ns,
                1,
                now_ns,
                window_ns,
            )
            .edges
            .into_iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge")
            .activity
        };
        assert_eq!(activity_at(&native, 1500, 1000), Activity::RecentlyObserved);
        assert_eq!(
            activity_at(&native, 3000, 1000),
            Activity::Quiet,
            "stale with no fresh rise"
        );
        native.counts_read(Vec::new(), vec![(41, 1, 0, 6)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            activity_at(&native, 1571, 1000),
            Activity::RecentlyObserved,
            "the rise at 1071 beats quiet"
        );
    }

    #[test]
    fn a_late_mapped_module_keeps_its_first_use_count() {
        // P1-3: a caller already bound through module A loads module B;
        // the pass that stages B's mapping also reads B's first-use row
        // (bound at once through the cached caller identity) before
        // committing the mapping. The witness resolves onto the committed
        // edge — and so must the count: later refreshes advance it,
        // never skip a permanently dropped pair.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        // Bound through A first: the image's identity is cached.
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        assert!(
            matches!(native.scene.coverage(caller), UseCoverage::Counted { .. }),
            "the A edge is counted: {:?}",
            native.scene.coverage(caller)
        );
        // The late module: absorbed (attach set knows it at once, like
        // the scan's absorb_lowering) but mapped only in the same
        // staging window as its first-use row.
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &b, &fx::offsets(2))),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        let endpoint_b = absorbed_b.delta.endpoints[0];
        native.scene.verdicts.extend(absorbed_b.verdicts);
        // One staging window, no commit between: project A+B (B's mapping
        // stages, uncommitted) then read B's first-use row (immediate
        // bind through the cached identity).
        native.scene.project_paths(7, &[&a_path, &b], 200);
        let row_b = WitnessRow::scripted(
            native.domain,
            41,
            1,
            endpoint_b.object,
            endpoint_b.id,
            7,
            210,
        );
        native.read(vec![row_b]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_b = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            let edge = registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry
                            .module(edge.module)
                            .is_some_and(|module| module.paths.iter().any(|p| p.contains("b.so")))
                })
                .expect("the caller has its B edge");
            (edge.entry_count, registry.coverage(edge))
        };
        // Premise: the witness resolved onto the committed edge.
        assert!(
            matches!(
                edge_b(&native).1,
                UseCoverage::Witnessed { .. } | UseCoverage::Counted { .. }
            ),
            "the B witness resolved: {:?}",
            edge_b(&native).1
        );
        // A later count increase must advance the edge, not skip it.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: endpoint_b.object,
            count: 9,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let (count, coverage) = edge_b(&native);
        assert_eq!(count, 9, "the B edge advanced to 9");
        assert!(
            matches!(coverage, UseCoverage::Counted { .. }),
            "the B edge reads counted: {coverage:?}"
        );
    }

    #[test]
    fn a_count_never_lands_where_its_witness_reads_ambiguous() {
        // P3 commit-visibility (astra#1, round 2 F7): the caller is
        // already cached — bound through a DIFFERENT physical object
        // (C) whose edge is committed — then B's mapping stages in the
        // same window as the shared object's ACTUAL FIRST-EVER row
        // (production delivers first sights once: the reader skips
        // seen rows and sends rises as count updates, never a second
        // first sight). The witness resolves ambiguous at publication
        // — and so must the count: a Bound(A) cached from the
        // pre-publish committed snapshot would attribute the shared
        // use to A.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        // Cache the caller through C, a separate physical object with
        // its own endpoint: C's edge commits with its first-sight
        // count before the shared object is ever seen.
        let c = fx::provider(&native.scene._dir, "c.so", "provider-c");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&c, "sha-c")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_c = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &c, &fx::offsets(1))),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_c.verdicts);
        let endpoint_c = absorbed_c.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &c], 140);
        let row_c = WitnessRow::scripted(
            native.domain,
            41,
            1,
            endpoint_c.object,
            endpoint_c.id,
            7,
            150,
        );
        native.witness(vec![row_c]);
        // B shares A's first endpoint: its table targets A's object.
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&c, "sha-c"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        let members: Vec<_> = native
            .scene
            .coordinator
            .attach_set
            .modules_with_member(shared.id)
            .collect();
        assert_eq!(
            members.len(),
            2,
            "A and B share the witnessed endpoint: {members:?}"
        );
        // One staging window, no commit between: project A+B+C (B's
        // mapping stages, uncommitted — the committed snapshot sees A
        // and C only) then read the shared endpoint's first-ever row
        // with a risen first-sight count.
        native.scene.project_paths(7, &[&a_path, &b, &c], 200);
        let mut row = WitnessRow::scripted(native.domain, 41, 1, shared.object, shared.id, 7, 210);
        row.entry_count = 9;
        native.read(vec![row]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // Premise: the witness resolved ambiguous at publication.
        let placement = native.scene.coordinator.registry.witness_placement();
        assert_eq!(
            placement.ambiguous, 1,
            "the shared-endpoint witness reads ambiguous: {placement:?}"
        );
        let counts = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            let mut counts: Vec<(String, u64)> = registry
                .edges()
                .filter(|edge| edge.caller == caller)
                .map(|edge| {
                    let path = registry
                        .module(edge.module)
                        .map(|module| module.paths.iter().next().cloned().unwrap_or_default())
                        .unwrap_or_default();
                    (path, edge.entry_count)
                })
                .collect();
            counts.sort();
            counts
        };
        let counts = counts(&native);
        assert_eq!(counts.len(), 3, "all three edges exist: {counts:?}");
        assert!(
            counts.iter().all(|(_, count)| *count <= 1),
            "no edge carries the ambiguous use's count: {counts:?}"
        );
        assert_eq!(
            counts
                .iter()
                .find(|(path, _)| path.contains("c.so"))
                .map(|(_, count)| *count),
            Some(1),
            "C keeps only its own first-sight count: {counts:?}"
        );
        assert_eq!(
            counts
                .iter()
                .find(|(path, _)| path.contains("a.so"))
                .map(|(_, count)| *count),
            Some(0),
            "the shared use's count never lands on A: {counts:?}"
        );
    }

    #[test]
    fn count_only_growth_after_sharing_appears_is_withheld() {
        // P3 sharing (round 2, F7/S5): the pair binds to A while A is
        // the sole owner and commits Bound(A) with its history; then B
        // appears sharing the endpoint and commits. A
        // production-shaped count-only update (the reader skips the
        // seen row — rises ride as updates, never a second first
        // sight) preserves history while withholding attribution of
        // the now-ambiguous growth.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        // Sharing appears and commits: B's edge exists alongside A's.
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_count = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(edge_count(&native, "a.so"), Some(1), "history stands");
        assert_eq!(edge_count(&native, "b.so"), Some(0), "B starts unused");
        // Production-shaped count-only growth: no rows (seen), only
        // the risen count — twice, so stickiness is pinned too.
        for count in [9u64, 20] {
            let at = native.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = native.domain;
            batch.counts = vec![crate::attach::capture::CallerCountUpdate {
                image: p11scope_ebpf_common::ImageIdentity {
                    task_cookie: 41,
                    exec_id: 1,
                },
                object: shared.object,
                count,
            }];
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            native.stage(NativeBatch::Witness(Box::new(batch)));
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        assert_eq!(
            edge_count(&native, "a.so"),
            Some(1),
            "history is preserved while ambiguous growth is withheld"
        );
        assert_eq!(
            edge_count(&native, "b.so"),
            Some(0),
            "ambiguous growth never lands on B either"
        );
    }

    #[test]
    fn staged_but_unpublished_sharer_withholds_count_only_growth() {
        // P3 sharing window (round 3, F3-01): the pair binds to A while
        // A is the sole owner and commits Bound(A) with its history;
        // then B is admitted (extend) and its mapping stages but does
        // NOT commit before a production-shaped count-only update
        // arrives in the same window. Admitted [A, B] but edged [A]:
        // the cached arm must NOT confirm — the growth withholds from
        // A and the publication (which commits B's mapping alongside)
        // resolves the pair ambiguous.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        // One staging window, no commit between: B's mapping stages
        // (admitted, uncommitted — the committed snapshot still sees A
        // only), then the risen count arrives.
        native.scene.project_paths(7, &[&a_path, &b], 200);
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 20,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_count = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(
            edge_count(&native, "a.so"),
            Some(1),
            "staged-but-unpublished sharing withholds the window's growth from the cached edge"
        );
        assert_eq!(
            edge_count(&native, "b.so"),
            Some(0),
            "the window's growth never lands on B either"
        );
    }

    #[test]
    fn ownership_transfer_forwards_only_post_demotion_growth() {
        // P3 ownership transfer (round 3, F3-03): the pair binds to A
        // while A is the sole owner and builds history; then B shares
        // the endpoint and commits edged, and A's endpoint membership
        // is removed (per-pass re-lowering re-records A memberless)
        // while B stays the sole admitted member. The next count
        // advance demotes: B must carry only post-demotion growth and
        // A keeps exactly its history — never `Placed`-elsewhere with
        // the absolute count (duplication plus backdated `first_ns`).
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        // History while A is the sole owner.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        // Sharing appears and commits: B's edge exists alongside A's.
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        // A's membership is removed (re-record memberless); B stays
        // the sole admitted member, edged.
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        let members: Vec<_> = native
            .scene
            .coordinator
            .attach_set
            .modules_with_member(shared.id)
            .collect();
        assert_eq!(
            members.len(),
            1,
            "B is the sole admitted member after A's membership is removed: {members:?}"
        );
        // One advance past the history.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 6,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_of = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| (edge.entry_count, edge.entry_first_seen_ns))
        };
        let (a_count, _) = edge_of(&native, "a.so").expect("A keeps its edge");
        assert_eq!(a_count, 5, "A keeps exactly its history");
        let (b_count, b_first) = edge_of(&native, "b.so").expect("B keeps its edge");
        assert_eq!(b_count, 1, "B carries only post-demotion growth");
        assert_eq!(
            a_count + b_count,
            6,
            "no duplication: the edges sum to the pair's absolute count"
        );
        assert_eq!(
            b_first,
            Some(at + 1),
            "B's first sight is the demoting read, never the pair's backdated history"
        );
    }

    #[test]
    fn a_rejected_count_is_never_promoted_by_a_later_mapping() {
        // P3 finalization (sol#2): a bound row with no mapping edge
        // places its witness module-level and rejects its count; the
        // rejection finalizes — a mapping that appears later must not
        // promote the held count onto the new edge.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        // B is known to the attach set (admitted) but never projected:
        // no mapping edge exists for it.
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &b, &fx::offsets(2))),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        let endpoint_b = absorbed_b.delta.endpoints[0];
        native.scene.verdicts.extend(absorbed_b.verdicts);
        // B's first-use row binds through the cached identity with no
        // mapping staged at all.
        let row_b = WitnessRow::scripted(
            native.domain,
            41,
            1,
            endpoint_b.object,
            endpoint_b.id,
            7,
            210,
        );
        native.read(vec![row_b]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // Premise: the witness went module-level (no edge to place on).
        let placement = native.scene.coordinator.registry.witness_placement();
        assert_eq!(
            (placement.edge, placement.module + placement.unresolved),
            (1, 1),
            "A's witness took its edge, B's went module-level: {placement:?}"
        );
        // The mapping appears later and the count advances: the rejected
        // count must not promote onto the new edge.
        native.scene.project_paths(7, &[&a_path, &b], 300);
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: endpoint_b.object,
            count: 9,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge_b = registry
            .edges()
            .find(|edge| {
                edge.caller == caller
                    && registry
                        .module(edge.module)
                        .is_some_and(|module| module.paths.iter().any(|p| p.contains("b.so")))
            })
            .expect("the later mapping created the B edge");
        assert_eq!(
            edge_b.entry_count, 0,
            "the rejected count never promotes onto the later edge"
        );
        assert!(
            !matches!(registry.coverage(edge_b), UseCoverage::Counted { .. }),
            "the B edge never reads counted: {:?}",
            registry.coverage(edge_b)
        );
    }

    #[test]
    fn an_ambiguous_count_finalizes_dropped_and_stays_there() {
        // P3 finalization (sol#2): a shared-endpoint use both edges hold
        // reads ambiguous — its count finalizes Dropped with its held
        // count removed, so later advances can never attribute it.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        // B shares A's first endpoint; both mappings commit up front,
        // so the committed snapshot itself reads ambiguous.
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        // The shared use with a risen first-sight count.
        let mut row = WitnessRow::scripted(native.domain, 41, 1, shared.object, shared.id, 7, 210);
        row.entry_count = 9;
        let key = PairKey::of(&row);
        native.read(vec![row]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // Premise: the witness read ambiguous.
        let placement = native.scene.coordinator.registry.witness_placement();
        assert_eq!(
            placement.ambiguous, 1,
            "the shared-endpoint witness reads ambiguous: {placement:?}"
        );
        // The rejection finalizes: Dropped, held count removed.
        assert!(
            matches!(
                native.scene.coordinator.pair_targets.get(&key),
                Some(PairTarget::Dropped)
            ),
            "the ambiguous pair finalizes Dropped: {:?}",
            native.scene.coordinator.pair_targets.get(&key)
        );
        assert!(
            !native.scene.coordinator.pair_counts.contains_key(&key),
            "the rejected held count is removed"
        );
        // Permanence: a later advance attributes nowhere.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 12,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        for edge in registry.edges().filter(|edge| edge.caller == caller) {
            let path = registry
                .module(edge.module)
                .map(|module| module.paths.iter().next().cloned().unwrap_or_default())
                .unwrap_or_default();
            let count = edge.entry_count;
            if path.contains("a.so") {
                assert_eq!(count, 1, "A keeps only its own first-sight count");
            } else {
                assert_eq!(count, 0, "B never carries the ambiguous use: {path}");
            }
        }
    }

    #[test]
    fn persistent_refresh_failure_keeps_the_lower_bound_but_withholds_quiet() {
        // P1-5: after a successful positive read, persistent refresh
        // failures keep the observed count as a lower bound while the
        // coverage reads lossy — live AND terminal output withhold a
        // quiet claim over the stale count.
        use crate::inventory_present::{Activity, Presentation};
        let (mut native, caller) = NativeScene::new();
        // Production order: capture coverage begins before the reads, so
        // witness batches run the coverage half (health, freshness).
        native.scene.coordinator.begin_capture_coverage(None);
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        let edge_of = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            let edge = registry
                .edges()
                .find(|edge| edge.caller == caller)
                .expect("the caller has its edge");
            (
                edge.entry_count,
                edge.entry_last_seen_ns,
                registry.coverage(edge),
            )
        };
        assert!(
            matches!(
                edge_of(&native).2,
                UseCoverage::Counted { lossy: false, .. }
            ),
            "a clean positive read is loss-free: {:?}",
            edge_of(&native).2
        );
        // Persistent refresh failures: reads carrying only the failure.
        for _ in 0..2 {
            let at = native.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = native.domain;
            batch.read_failures = vec!["count refresh: lookup of cookie 41 failed".into()];
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            native.stage(NativeBatch::Witness(Box::new(batch)));
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        let (count, last_seen, coverage) = edge_of(&native);
        assert_eq!(count, 1, "the observed lower bound stands");
        assert!(
            matches!(coverage, UseCoverage::Counted { lossy: true, .. }),
            "failed refreshes publish lossy freshness: {coverage:?}"
        );
        // Live: the per-pass signal withholds quiet over the stale
        // count, window-free.
        let last_seen = last_seen.expect("the positive read left a last-seen");
        let live = Presentation::capture(&native.scene.coordinator, "s", 0, last_seen, 1);
        let activity = live
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has its edge")
            .activity;
        assert_eq!(
            activity,
            Activity::Lossy,
            "a stale count under failed refresh withholds quiet"
        );
        // Terminal: the loss survives the stop; the document keeps the
        // lower bound with lossy freshness, never quiet.
        let end_ns = last_seen + 2000;
        native.scene.coordinator.end_capture_coverage(end_ns);
        let document = crate::inventory::render_json(&native.scene.coordinator, "s", 0, end_ns, 1);
        assert_eq!(document["edges"][0]["entries"]["count"], 1);
        assert_eq!(
            document["edges"][0]["entries"]["coverage"]["lossy"], true,
            "{}",
            document["edges"][0]["entries"]["coverage"]
        );
        assert_ne!(
            document["edges"][0]["activity"], "quiet",
            "{}",
            document["edges"][0]
        );
    }

    #[test]
    fn repeated_refresh_starvation_keeps_the_lower_bound_but_withholds_quiet() {
        // F1: after a successful positive read, repeated deadline
        // starvation of the refresh — no failures, no gaps, no sweep —
        // keeps the observed count as a lower bound while the coverage
        // reads lossy, so live output withholds a quiet claim over the
        // stale count.
        use crate::inventory_present::{Activity, Presentation};
        let (mut native, caller) = NativeScene::new();
        native.scene.coordinator.begin_capture_coverage(None);
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        let edge_of = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            let edge = registry
                .edges()
                .find(|edge| edge.caller == caller)
                .expect("the caller has its edge");
            (
                edge.entry_count,
                edge.entry_last_seen_ns,
                registry.coverage(edge),
            )
        };
        assert!(
            matches!(
                edge_of(&native).2,
                UseCoverage::Counted { lossy: false, .. }
            ),
            "a clean positive read is loss-free: {:?}",
            edge_of(&native).2
        );
        // Repeated starvation: reads carrying only the starved flag.
        for _ in 0..2 {
            let at = native.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = native.domain;
            batch.refresh_deadline_reached = true;
            batch.refresh_sweep_completed = false;
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            native.stage(NativeBatch::Witness(Box::new(batch)));
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        let (count, last_seen, coverage) = edge_of(&native);
        assert_eq!(count, 1, "the observed lower bound stands");
        assert!(
            matches!(coverage, UseCoverage::Counted { lossy: true, .. }),
            "starved refreshes publish lossy freshness: {coverage:?}"
        );
        let last_seen = last_seen.expect("the positive read left a last-seen");
        let live = Presentation::capture(&native.scene.coordinator, "s", 0, last_seen, 1);
        let activity = live
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has its edge")
            .activity;
        assert_eq!(
            activity,
            Activity::Lossy,
            "a stale count under starved refresh withholds quiet"
        );
    }

    #[test]
    fn a_refresh_failure_beginning_after_stop_withholds_quiet() {
        // P1-5 terminal-first (sol#1 + astra#2): reads succeed while
        // live, then stop begins, and only the post-stop terminal
        // refresh fails. The stale count must demote to lossy — quiet
        // is withheld even though no live loss was ever recorded.
        use crate::inventory_present::{Activity, Presentation};
        let (mut native, caller) = NativeScene::new();
        native.scene.coordinator.begin_capture_coverage(None);
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        let edge_of = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            let edge = registry
                .edges()
                .find(|edge| edge.caller == caller)
                .expect("the caller has its edge");
            (
                edge.entry_count,
                edge.entry_last_seen_ns,
                registry.coverage(edge),
            )
        };
        assert!(
            matches!(
                edge_of(&native).2,
                UseCoverage::Counted { lossy: false, .. }
            ),
            "live reads succeed loss-free: {:?}",
            edge_of(&native).2
        );
        // Stop begins (production order: the coverage ends before the
        // post-stop terminal refresh, inventory_capture.rs).
        let live_last_seen = edge_of(&native)
            .1
            .expect("the positive read left a last-seen");
        let end_ns = live_last_seen + 2000;
        native.scene.coordinator.end_capture_coverage(end_ns);
        // The terminal refresh fails after stop: reads carrying only
        // the failure, staged the way the terminal loop stages them.
        for _ in 0..2 {
            let at = native.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = native.domain;
            batch.read_failures = vec!["count refresh: lookup of cookie 41 failed".into()];
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            native.stage(NativeBatch::Witness(Box::new(batch)));
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        let (count, _, coverage) = edge_of(&native);
        assert_eq!(count, 1, "the observed lower bound stands");
        assert!(
            matches!(coverage, UseCoverage::Counted { lossy: true, .. }),
            "a terminal-first refresh failure publishes lossy freshness: {coverage:?}"
        );
        // Terminal: the stale count withholds quiet.
        let live = Presentation::capture(&native.scene.coordinator, "s", 0, end_ns, 1);
        let activity = live
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has its edge")
            .activity;
        assert_eq!(
            activity,
            Activity::Lossy,
            "a stale count under failed terminal refresh withholds quiet"
        );
        let document = crate::inventory::render_json(&native.scene.coordinator, "s", 0, end_ns, 1);
        assert_eq!(document["edges"][0]["entries"]["count"], 1);
        assert_eq!(
            document["edges"][0]["entries"]["coverage"]["lossy"], true,
            "{}",
            document["edges"][0]["entries"]["coverage"]
        );
        assert_ne!(
            document["edges"][0]["activity"], "quiet",
            "{}",
            document["edges"][0]
        );
    }

    #[test]
    fn per_pass_activity_reads_a_rise_then_quiet_on_unchanged_passes() {
        // ACT (Choice 3 re-rule): activity is per-pass ("rose since
        // previous pass"), pinned with production clock ordering: a rise
        // reads recently observed; following unchanged passes read quiet
        // (never a window echo); unreadable refreshes read lossy; a later
        // rise reads recently observed again.
        use crate::inventory_present::{Activity, Presentation};
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        // Production ordering: passes commit in stamp order, and every
        // presentation reads the pass it presents after it committed.
        // The signal is per-pass (window-free): only the pass sequence
        // orders it.
        let activity_of = |native: &NativeScene| {
            Presentation::capture(&native.scene.coordinator, "s", 0, 0, 1)
                .edges
                .into_iter()
                .find(|edge| edge.caller == caller)
                .expect("the caller has its edge")
                .activity
        };
        // Rising: first sight, then an advance.
        native.witness(vec![native.row(41, 1, 7, 100, 0)]);
        assert_eq!(
            activity_of(&native),
            Activity::RecentlyObserved,
            "first sight rose"
        );
        native.counts_read(Vec::new(), vec![(41, 1, 0, 6)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            activity_of(&native),
            Activity::RecentlyObserved,
            "the advance rose"
        );
        // Unchanged, then stale: quiet, whatever any window covers.
        for _ in 0..2 {
            native.read(Vec::new());
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        assert_eq!(
            activity_of(&native),
            Activity::Quiet,
            "unchanged passes read quiet, never a window echo"
        );
        // The dashboard display keeps its window: the stale rise still
        // reads recently observed on screen while in the trailing
        // window, quiet once past it.
        let display_of = |native: &NativeScene, now_ns: u64| {
            Presentation::capture_dashboard(
                &native.scene.coordinator,
                "s",
                0,
                now_ns,
                1,
                now_ns,
                crate::inventory_present::DASHBOARD_ACTIVITY_WINDOW_NS,
            )
            .edges
            .into_iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has its edge")
            .activity
        };
        let last_seen = native
            .scene
            .coordinator
            .registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has its edge")
            .entry_last_seen_ns
            .expect("the rise left a last-seen");
        assert_eq!(
            display_of(&native, last_seen + 1_000),
            Activity::RecentlyObserved,
            "the display keeps window recency"
        );
        assert_eq!(
            display_of(
                &native,
                last_seen + crate::inventory_present::DASHBOARD_ACTIVITY_WINDOW_NS + 1
            ),
            Activity::Quiet,
            "the display goes quiet past its window"
        );
        // Unreadable: the refresh fails persistently.
        native.scene.coordinator.begin_capture_coverage(None);
        for _ in 0..2 {
            let at = native.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = native.domain;
            batch.read_failures = vec!["count refresh: lookup of cookie 41 failed".into()];
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            native.stage(NativeBatch::Witness(Box::new(batch)));
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        assert_eq!(
            activity_of(&native),
            Activity::Lossy,
            "unreadable refreshes withhold quiet"
        );
        // A later rise beats lossy.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 12)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            activity_of(&native),
            Activity::RecentlyObserved,
            "a fresh rise beats lossy"
        );
    }

    #[test]
    fn native_counts_render_identically_in_json_jsonl_and_dashboard() {
        // C7 C4 three-consumer equality: a natively counted edge —
        // count, coverage, observation, activity — reads the same in
        // the JSON document, the JSONL edge event, the pager snapshot,
        // and the dashboard frame.
        use crate::inventory_dashboard::{
            DashboardState, DisplayFrame, LogTail, Viewport, render_frame,
        };
        use crate::inventory_present::{
            Presentation, coverage_label, entries_display, render_snapshot,
        };
        let (mut native, _) = NativeScene::new();
        native.answer(7, 500, 41);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 4;
        native.witness(vec![row]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 9)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let presentation = Presentation::capture(&native.scene.coordinator, "native", 0, 2000, 1);
        let document =
            crate::inventory::render_json(&native.scene.coordinator, "native", 0, 2000, 1);
        assert_eq!(presentation.edges.len(), 1);
        let edge = &presentation.edges[0];
        let edge_json = &document["edges"][0];
        assert_eq!(edge_json["entries"]["count"], 9);
        assert_eq!(edge_json["entries"]["coverage"]["state"], "counted");
        assert_eq!(edge_json["entries"]["coverage"]["since_ns"], 100);
        assert_eq!(edge_json["entries"]["coverage"]["lossy"], false);
        assert_eq!(edge_json["entries"]["observation"], "observed");
        assert_eq!(edge_json["entries"]["last_seen_ns"], 1071);
        assert_eq!(edge.activity.label(), "recently observed");
        assert_eq!(edge.capture.label(), "armed");
        // JSONL: the edge event carries the JSON edge verbatim.
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let path = dir.path().join("events.jsonl");
        let mut writer = crate::inventory_events::EventWriter::create(&path, 1 << 20, 5).unwrap();
        crate::inventory_events::emit_snapshot_as_events(&mut writer, &presentation, 1).unwrap();
        drop(writer);
        let body = std::fs::read_to_string(&path).unwrap();
        let events: Vec<serde_json::Value> = body
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|line| line["kind"] == "edge_observed")
            .map(|line| line["event"].clone())
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["entries"], edge_json["entries"]);
        assert_eq!(events[0]["activity"], "recently observed");
        assert_eq!(events[0]["capture"], "armed");
        // Pager snapshot and dashboard frame: the same labels.
        let snapshot = render_snapshot(&presentation);
        let label = coverage_label(&edge.coverage);
        let line = snapshot
            .lines()
            .find(|line| {
                line.starts_with(&format!(
                    "edge {} -> {} ",
                    edge.caller.label(),
                    edge.module.label()
                ))
            })
            .unwrap();
        assert!(line.contains(&format!("coverage {label}")), "{line}");
        assert_eq!(entries_display(edge), "9");
        let mut tail = LogTail::bounded();
        tail.push("p11scope: pass 1: 1 scanned (1 native, 0 scan-pinned)");
        // The frame reads the dashboard display's windowed view.
        let display = Presentation::capture_dashboard(
            &native.scene.coordinator,
            "native",
            0,
            2000,
            1,
            2000,
            crate::inventory_present::DASHBOARD_ACTIVITY_WINDOW_NS,
        );
        let frame = DisplayFrame {
            presentation: std::sync::Arc::new(display),
            log: tail.snapshot(),
        };
        let text = String::from_utf8(render_frame(
            &frame,
            Viewport {
                width: 200,
                height: 120,
            },
            &DashboardState::new(),
        ))
        .unwrap()
        .replace("\x1b[H", "")
        .replace("\x1b[K", "");
        assert!(text.contains("entries 9"), "{text}");
        assert!(text.contains("activity recently observed"), "{text}");
        assert!(text.contains("capture armed"), "{text}");
    }

    #[test]
    fn integrity_rows_and_unresolved_endpoints_are_gaps() {
        let (mut native, _) = NativeScene::new();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.health.discovery_counters = Some([0; 5]);
        batch.integrity_total = 1;
        batch
            .integrity
            .push(crate::attach::capture::WitnessIntegrity {
                key: p11scope_ebpf_common::inventory_callers::CallerObjectKey {
                    image: ImageIdentity {
                        task_cookie: 1,
                        exec_id: 1,
                    },
                    object_id: 0,
                    reserved: 0,
                },
                value: None,
                reason: "scripted".into(),
            });
        // An endpoint the attach set never admitted.
        batch.rows.push(WitnessRow::scripted(
            native.domain,
            41,
            1,
            native.scene.delta.endpoints[0].object,
            EndpointId(9),
            9,
            100,
        ));
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.drain();
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        let subjects = native.gap_subjects();
        assert!(subjects.contains(&"native witness rows failed validation".to_string()));
        assert!(subjects.contains(&"native witness without a module".to_string()));
        assert_eq!(native.module_unbound(), None);
        assert_eq!(
            native.scene.coordinator.registry.witness_census().integrity,
            1
        );
        // M3/M4: the unresolved row is counted where it went, the counts
        // reconcile with the census, and no gap reads as attribution.
        let registry = &native.scene.coordinator.registry;
        let census = registry.witness_census();
        let placement = registry.witness_placement();
        assert_eq!(placement.unresolved, 1);
        assert_eq!(placement.total(), census.bound + census.unbound_total());
        assert!(registry.gaps().iter().all(|gap| gap.pid.is_none()));
    }

    #[test]
    fn finish_decides_every_waiting_row_unbound() {
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.read(vec![row]);
        let receipt = native.stage(NativeBatch::Finish {
            domain: native.domain,
        });
        assert_eq!(receipt.decided, 1);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(!native.scene.coverage(caller).is_witnessed());
        assert_eq!(
            native
                .module_unbound()
                .unwrap()
                .reasons
                .get("evidence_incomplete"),
            Some(&1)
        );
    }

    /// Answers one ticket for every pin of one domain (self-process tests).
    struct OneTicket {
        domain: NativeDomainId,
        ticket: u64,
    }

    impl NativeIdentity<crate::process::PidPin> for OneTicket {
        fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
            None
        }

        fn query_cookie(
            &mut self,
            domain: NativeDomainId,
            _: &crate::process::PidPin,
        ) -> CookieQuery {
            if domain == self.domain {
                CookieQuery::Cookie(DomainCookie::scripted(domain, self.ticket))
            } else {
                CookieQuery::Unavailable("another domain".into())
            }
        }
    }

    #[test]
    fn a_native_owner_gets_the_exec_proof_and_its_caller_still_retires() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let now = crate::discovery::caller_registry::now_ns();
        let caller = coordinator
            .test_open_native_owner(pid, fixture_image(pid).unwrap(), &mut FixtureImages, now)
            .unwrap();
        let domain = NativeDomainId::mint();
        let mut identity = OneTicket { domain, ticket: 41 };
        let object = crate::discovery::inventory_attach_set::AttachObjectId::scripted(0);
        let stamps = Stamps::from(now);
        coordinator
            .binder
            .note_exec_coverage(ExecCoverage::scripted(domain, 0));
        let mut stage = |coordinator: &mut InventoryCoordinator<OsProcessSource>,
                         rows: Vec<WitnessRow>| {
            let mut events = Vec::new();
            for batch in [
                stamps.read(domain, rows),
                stamps.drain(domain),
                stamps.read(domain, Vec::new()),
            ] {
                events.extend(
                    coordinator
                        .stage_native(batch, &mut identity, now + 10)
                        .events,
                );
            }
            events
        };
        let bound = WitnessRow::scripted(domain, 41, 1, object, EndpointId(0), pid, now + 1);
        assert!(stage(&mut coordinator, vec![bound]).is_empty());
        let later = WitnessRow::scripted(domain, 41, 2, object, EndpointId(1), pid, now + 2);
        let events = stage(&mut coordinator, vec![later]);
        assert!(
            matches!(events.as_slice(), [CallerEvent::ExecRetired { old, .. }] if *old == caller),
            "{events:?}"
        );
        coordinator.commit_batch(false).unwrap();
        let proof_gap = coordinator
            .registry()
            .gaps()
            .iter()
            .find(|gap| gap.subject == "native exec proof not applied")
            .expect("the owner lane refuses the proof until its adapter exists");
        assert!(
            proof_gap.reason.contains("native lifecycle adapter"),
            "{proof_gap:?}"
        );
        assert!(coordinator.adapter().record(caller).unwrap().retired);
    }

    #[test]
    fn a_row_naming_another_object_for_its_endpoint_never_stages() {
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let endpoint = native.scene.delta.endpoints[0];
        let row = WitnessRow::scripted(
            native.domain,
            41,
            1,
            crate::discovery::inventory_attach_set::AttachObjectId::scripted(
                endpoint.object.index() + 1,
            ),
            endpoint.id,
            7,
            100,
        );
        native.witness(vec![row]);
        assert!(!native.scene.coverage(caller).is_witnessed());
        assert_eq!(native.module_unbound(), None);
        assert!(
            native
                .gap_subjects()
                .contains(&"native witness without a module".to_string())
        );
    }

    #[test]
    fn a_transition_for_a_caller_the_scan_lane_already_retired_changes_nothing() {
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let first = native.row(41, 1, 7, 100, 0);
        native.witness(vec![first]);
        // The later image's row is read while the caller is still live ...
        let later = native.row(41, 2, 7, 1_100, 1);
        native.read(vec![later]);
        // ... then the scan lane sees the exe change and splits first.
        native.scene.source.exec(7, 200, "/bin/other");
        let observed: BTreeSet<u32> = [7].into_iter().collect();
        let events = native.scene.coordinator.adapter.reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            1_200,
        );
        let [CallerEvent::ExecRetired { new: successor, .. }] = events.as_slice() else {
            panic!("{events:?}");
        };
        let successor = *successor;
        let mut native_events = native.drain().events;
        native_events.extend(native.read(Vec::new()).events);
        assert!(native_events.is_empty(), "{native_events:?}");
        let adapter = &native.scene.coordinator.adapter;
        assert!(adapter.record(caller).unwrap().retired);
        assert_eq!(adapter.live_id(7), Some(successor));
        assert_eq!(adapter.len(), 2, "no extra incarnation was minted");
    }

    #[test]
    fn an_owner_whose_caller_already_retired_gets_no_exec_proof() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let now = crate::discovery::caller_registry::now_ns();
        let caller = coordinator
            .test_open_native_owner(pid, fixture_image(pid).unwrap(), &mut FixtureImages, now)
            .unwrap();
        let domain = NativeDomainId::mint();
        let mut identity = OneTicket { domain, ticket: 41 };
        let object = crate::discovery::inventory_attach_set::AttachObjectId::scripted(0);
        let stamps = Stamps::from(now);
        coordinator
            .binder
            .note_exec_coverage(ExecCoverage::scripted(domain, 0));
        let read = |rows: Vec<WitnessRow>| stamps.read(domain, rows);
        let drain = || stamps.drain(domain);
        let bound = WitnessRow::scripted(domain, 41, 1, object, EndpointId(0), pid, now + 1);
        for batch in [read(vec![bound]), drain(), read(Vec::new())] {
            coordinator.stage_native(batch, &mut identity, now + 10);
        }
        // The later image's row is read while the caller is live; then the
        // caller retires before the row's horizon arrives.
        let later = WitnessRow::scripted(domain, 41, 2, object, EndpointId(1), pid, now + 2);
        coordinator.stage_native(read(vec![later]), &mut identity, now + 10);
        coordinator.adapter_mut().exec_transition(
            caller,
            &mut |_| ImageAuthority::ScanPinned,
            now + 11,
        );
        let mut events = Vec::new();
        for batch in [drain(), read(Vec::new())] {
            events.extend(
                coordinator
                    .stage_native(batch, &mut identity, now + 12)
                    .events,
            );
        }
        assert!(events.is_empty(), "{events:?}");
        coordinator.commit_batch(false).unwrap();
        assert!(
            !coordinator
                .registry()
                .gaps()
                .iter()
                .any(|gap| gap.subject == "native exec proof not applied"),
            "a retired incarnation's owner is never sent a proof"
        );
    }

    /// A scene whose pid 7 (start 500) was admitted and mapped at 100,
    /// before the native lane's exec coverage began at 200.
    fn pre_activation_scene() -> (NativeScene, CallerId) {
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 100)
            .unwrap();
        scene.project(7, 110);
        scene.coordinator.commit_batch(false).unwrap();
        (NativeScene::over(scene, 200), caller)
    }

    fn empty_pass(native: &mut NativeScene, start_ns: u64) -> PassReport {
        let report = native.scene.coordinator.observe_empty_pass(
            &mut UnavailableImageGuard,
            &mut native.cookies,
            "scripted pass",
            start_ns,
        );
        native.scene.coordinator.commit_batch(false).unwrap();
        report
    }

    /// C1 (C4 review), end to end: X admitted at 100 (foo maps M); T execs
    /// bar at 150, unrecorded; coverage begins at 200; bar's row at 210
    /// answers X's ticket. It waits for the revalidation pass, which sees
    /// bar's exe: the row is a coverage gap and nothing joins X.
    #[test]
    fn a_caller_that_exec_d_before_coverage_never_joins_through_the_coordinator() {
        let (mut native, caller) = pre_activation_scene();
        native.scene.source.exec(7, 200, "/bin/bar");
        native.answer(7, 500, 41);
        let row = native.row(41, 2, 7, 210, 0);
        native.witness(vec![row]);
        let census = native.scene.coordinator.registry.witness_census().clone();
        assert_eq!((census.pending, census.bound), (1, 0), "waits for the pass");

        // A pass that started before the coverage start does not qualify,
        // even though its reconcile already retired X as exec'd.
        let report = empty_pass(&mut native, 150);
        assert!(
            report.events.iter().any(
                |event| matches!(event, CallerEvent::ExecRetired { old, .. } if *old == caller)
            ),
            "{:?}",
            report.events
        );
        assert_eq!(native.scene.coordinator.binder.census().pending, 1);

        empty_pass(&mut native, 250);
        let census = native.scene.coordinator.registry.witness_census().clone();
        assert_eq!((census.pending, census.bound), (0, 0));
        assert_eq!(
            census.unbound.get(&UnboundReason::ExecCoverageGap),
            Some(&1)
        );
        assert!(!native.scene.coverage(caller).is_witnessed());
        let unbound = native.module_unbound().expect("module-level positive use");
        assert_eq!(unbound.reasons.get("exec_coverage_gap"), Some(&1));
    }

    /// C1 named boundary, end to end: without an exe change the pass
    /// revalidates X, and the row binds to it.
    #[test]
    fn a_caller_unchanged_since_before_coverage_binds_after_the_pass() {
        let (mut native, caller) = pre_activation_scene();
        native.answer(7, 500, 41);
        let row = native.row(41, 2, 7, 210, 0);
        native.witness(vec![row]);
        assert!(!native.scene.coverage(caller).is_witnessed());
        let report = empty_pass(&mut native, 250);
        assert!(report.events.is_empty(), "{:?}", report.events);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 210,
                lossy: false
            }
        );
    }

    /// The revalidation also runs on a full scan pass (`apply_catalog`),
    /// not only on an observation-less one.
    #[test]
    fn a_full_scan_pass_revalidates_a_caller_from_before_coverage() {
        let (mut native, caller) = pre_activation_scene();
        native.answer(7, 500, 41);
        let row = native.row(41, 2, 7, 210, 0);
        native.witness(vec![row]);
        assert!(!native.scene.coverage(caller).is_witnessed());
        let generation = native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .map(|record| crate::inspect_system::MemberGeneration {
                start_time: record.start_time,
                exe: record.exe.clone(),
            });
        let catalog = capture_catalog(&native.scene.pins, &[&native.scene.path], 7, generation);
        let report = native.scene.coordinator.apply_catalog(
            catalog,
            &mut UnavailableImageGuard,
            &mut native.cookies,
            u64::MAX,
            250,
        );
        assert!(report.events.is_empty(), "{:?}", report.events);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 210,
                lossy: false
            }
        );
    }

    /// C5.1 carry (C5.2 review): a read proves a clean instant only when it
    /// completes a gap-free CALLER_USE sweep, and that instant is the health
    /// read of the batch the sweep began in — a bounded read that stopped
    /// mid-sweep may have left a use dated before its stamp unvisited.
    #[test]
    fn only_a_completed_gap_free_sweep_proves_a_clean_read() {
        let (mut scene, caller) = watched_scene(7, 500);
        assert_eq!(last_clean(&scene), Some(200));
        // A sweep begins at 250 and stops at its row bound.
        let mut partial = witness_batch();
        partial.health_read_ns = 250;
        partial.sweep_completed = false;
        partial.row_bound_reached = true;
        scene.coordinator.note_witness_batch(&partial);
        assert_eq!(last_clean(&scene), Some(200));
        // It completes at 280: every row present at 250 was visited.
        let mut rest = witness_batch();
        rest.health_read_ns = 280;
        scene.coordinator.note_witness_batch(&rest);
        assert_eq!(last_clean(&scene), Some(250));
        // A sweep that completes with skipped rows proves nothing.
        let mut gaps = witness_batch();
        gaps.health_read_ns = 290;
        gaps.sweep_gaps = true;
        scene.coordinator.note_witness_batch(&gaps);
        assert_eq!(last_clean(&scene), Some(250));
        // A terminal read that stopped mid-sweep never extends the interval.
        let mut terminal = witness_batch();
        terminal.health_read_ns = 295;
        terminal.sweep_completed = false;
        terminal.deadline_reached = true;
        scene.coordinator.note_witness_batch(&terminal);
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        assert_eq!(
            scene.coverage(caller),
            crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
                since_ns: 100,
                until_ns: Some(250),
            }
        );
    }

    // ---- DR-LIVE-LABEL-LAG: a pending first-use row reads unknown ----

    /// The shared presentation over a native scene's coordinator: the one
    /// view JSON and the event stream read (per-pass activity signal).
    fn presented(native: &NativeScene) -> crate::inventory_present::Presentation {
        crate::inventory_present::Presentation::capture(
            &native.scene.coordinator,
            "system",
            0,
            3_000,
            3,
        )
    }

    /// While the binder holds a pending row of the watched caller's pid
    /// on the edge's module, the edge presents unknown (`activity
    /// unknown`, `entries ?`); the staged watch is untouched, so the row
    /// still binds and counts the same edge once decided.
    #[test]
    fn a_pending_first_use_row_presents_the_edge_as_unknown_until_it_binds() {
        use crate::discovery::caller_registry::EntryObservation;
        use crate::inventory_present::{Activity, entries_display};
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 200, 0);
        native.read(vec![row]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let census = native.scene.coordinator.registry.witness_census().clone();
        assert_eq!((census.pending, census.bound), (1, 0));
        // The staged watch stands: the overlay is presentation only.
        assert!(watched(&native.scene.coverage(caller)));
        let presentation = presented(&native);
        let edge = presentation
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has a presented edge");
        assert_eq!(
            edge.coverage,
            UseCoverage::Unknown(UnknownReason::PendingFirstUse)
        );
        assert_eq!(edge.activity, Activity::Unknown);
        assert_eq!(entries_display(edge), "?");
        assert_eq!(
            edge.entry_observation,
            EntryObservation::UnknownUnavailable.label()
        );
        let payload = crate::inventory::edge_json(edge);
        assert_eq!(payload["entries"]["coverage"]["state"], "unknown");
        assert_eq!(
            payload["entries"]["coverage"]["reason"],
            "pending_first_use"
        );
        // The horizons arrive: the row binds and the edge is counted.
        native.drain();
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        let census = native.scene.coordinator.registry.witness_census().clone();
        assert_eq!((census.pending, census.bound), (0, 1));
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 200,
                lossy: false
            }
        );
        let presentation = presented(&native);
        let edge = presentation
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has a presented edge");
        assert_eq!(
            edge.coverage,
            UseCoverage::Counted {
                since_ns: 200,
                lossy: false
            }
        );
        assert_eq!(edge.activity, Activity::RecentlyObserved);
    }

    /// A row still pending at finish unbinds and downgrades the watch, as
    /// today: the edge presents the staged unknown, never the transient one.
    #[test]
    fn a_row_unbound_at_finish_presents_the_staged_unknown() {
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 200, 0);
        native.read(vec![row]);
        let receipt = native.stage(NativeBatch::Finish {
            domain: native.domain,
        });
        assert_eq!(receipt.decided, 1);
        native.scene.coordinator.commit_batch(false).unwrap();
        let census = native.scene.coordinator.registry.witness_census().clone();
        assert_eq!(census.pending, 0);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Unknown(UnknownReason::UseBeforeAdmission)
        );
        let presentation = presented(&native);
        let edge = presentation
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has a presented edge");
        assert_eq!(
            edge.coverage,
            UseCoverage::Unknown(UnknownReason::UseBeforeAdmission)
        );
    }

    /// A batch that leaves a stamped row pending never extends the
    /// proven-clean instant; once the row decides, clean batches extend
    /// it again.
    #[test]
    fn a_pending_row_withholds_the_proven_clean_instant_until_it_decides() {
        let (mut native, _) = watched_native();
        native.answer(7, 500, 41);
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(last_clean(&native.scene), Some(1_010));
        let row = native.row(41, 1, 7, 200, 0);
        native.read(vec![row]);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coordinator.registry.witness_census().pending,
            1
        );
        assert_eq!(
            last_clean(&native.scene),
            Some(1_010),
            "a stamped pending row withholds the clean instant"
        );
        native.drain();
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coordinator.registry.witness_census().pending,
            0
        );
        assert!(
            last_clean(&native.scene).is_some_and(|clean| clean > 1_010),
            "a decided row releases the clean instant: {:?}",
            last_clean(&native.scene)
        );
    }

    /// An unstamped pending row never decides before the finish flush, so
    /// it never stalls the proven-clean instant — but the edge still
    /// presents unknown while the row waits.
    #[test]
    fn an_unstamped_pending_row_does_not_stall_the_proven_clean_instant() {
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 200, 0);
        let mut batch = native.stamps.read(native.domain, vec![row]);
        let NativeBatch::Witness(read) = &mut batch else {
            panic!("a witness read stages a witness batch");
        };
        read.rows_read_ns = u64::MAX;
        native.stage(batch);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coordinator.registry.witness_census().pending,
            1
        );
        assert_eq!(
            last_clean(&native.scene),
            Some(1_010),
            "the clean instant extends through an undecidable row"
        );
        let presentation = presented(&native);
        let edge = presentation
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has a presented edge");
        assert_eq!(
            edge.coverage,
            UseCoverage::Unknown(UnknownReason::PendingFirstUse)
        );
    }

    // ---- R-C51-1: an unbound row of a watched caller's pid ----

    /// A system-scope native lane with pid 7 (start 500) admitted at 50,
    /// every endpoint attached at 100, and its edge watched since 120.
    fn watched_native() -> (NativeScene, CallerId) {
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene.coordinator.begin_capture_coverage(None);
        let mut native = NativeScene::over(scene, 0);
        native.scene.attach_all(100, ScopeCustody::System);
        native.scene.project(7, 120);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(watched(&native.scene.coverage(caller)));
        (native, caller)
    }

    fn use_before_admission(coverage: &UseCoverage) -> bool {
        matches!(
            coverage,
            UseCoverage::Unknown(UnknownReason::UseBeforeAdmission)
        )
    }

    #[test]
    fn a_row_from_before_admission_downgrades_the_watch_for_good() {
        // Read after the admission: the row predates it (t0 40 < 50).
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 40, 0);
        native.witness(vec![row]);
        let census = native.scene.coordinator.registry.witness_census();
        assert_eq!(
            census.unbound.get(&UnboundReason::BeforeAdmission),
            Some(&1)
        );
        assert!(
            use_before_admission(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
        // Sticky: later passes and the stop never restore a watch.
        native.scene.project(7, 2_000);
        native.scene.coordinator.commit_batch(false).unwrap();
        native.scene.coordinator.end_capture_coverage(3_000);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(use_before_admission(&native.scene.coverage(caller)));
    }

    #[test]
    fn a_row_read_before_its_callers_admission_downgrades_the_later_watch() {
        // Read before the admission: pid 9 holds no caller yet.
        let (mut native, _) = watched_native();
        let row = native.row(77, 1, 9, 1_000, 1);
        native.witness(vec![row]);
        native.scene.source.spawn(9, 900);
        let later = native
            .scene
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 1_500)
            .unwrap();
        native.scene.project(9, 1_600);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            use_before_admission(&native.scene.coverage(later)),
            "{:?}",
            native.scene.coverage(later)
        );
    }

    #[test]
    fn a_full_preadmission_stash_degrades_the_scope_with_a_gap() {
        let (mut native, caller) = watched_native();
        native
            .scene
            .coordinator
            .capture
            .as_mut()
            .unwrap()
            .preadmission
            .limit = 1;
        // Live writers: pruning cannot make room (R-C51-5).
        native.scene.source.spawn(9, 90);
        native.scene.source.spawn(11, 110);
        let rows = vec![
            native.row(77, 1, 9, 1_000, 0),
            native.row(78, 1, 11, 1_000, 0),
        ];
        native.witness(rows);
        assert_eq!(
            native.preadmission(),
            PreadmissionCounters {
                held: 1,
                limit: 1,
                pruned: 0,
                refused: 1,
            }
        );
        assert!(
            native
                .gap_subjects()
                .contains(&"native pre-admission rows past their bound".to_string()),
            "{:?}",
            native.gap_subjects()
        );
        // pid 7 had no unbound row, yet its watch degrades with the scope.
        assert!(
            use_before_admission(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
        native.scene.project(7, 2_000);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(use_before_admission(&native.scene.coverage(caller)));
        // A caller admitted after the overflow, with no row of its own.
        native.scene.source.spawn(13, 1_300);
        let later = native
            .scene
            .coordinator
            .adapter
            .admit(13, ImageAuthority::ScanPinned, 2_100)
            .unwrap();
        native.scene.project(13, 2_200);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            use_before_admission(&native.scene.coverage(later)),
            "{:?}",
            native.scene.coverage(later)
        );
    }

    fn stash_limit(native: &mut NativeScene, limit: usize) {
        native
            .scene
            .coordinator
            .capture
            .as_mut()
            .unwrap()
            .preadmission
            .limit = limit;
    }

    #[test]
    fn an_exited_writer_is_pruned_before_the_stash_overflows() {
        let (mut native, caller) = watched_native();
        stash_limit(&mut native, 1);
        native.scene.source.spawn(9, 90);
        native.scene.source.spawn(11, 110);
        let row = native.row(77, 1, 9, 1_000, 0);
        native.witness(vec![row]);
        // pid 9 exits unadmitted: its entry can never apply again.
        native.scene.source.kill(9);
        let row = native.row(78, 1, 11, 1_010, 0);
        native.witness(vec![row]);
        assert!(
            !native
                .gap_subjects()
                .contains(&"native pre-admission rows past their bound".to_string()),
            "{:?}",
            native.gap_subjects()
        );
        assert_eq!(
            native.preadmission(),
            PreadmissionCounters {
                held: 1,
                limit: 1,
                pruned: 1,
                refused: 0,
            }
        );
        let document =
            crate::inventory::render_json(&native.scene.coordinator, "system", 0, 1_020, 1);
        assert_eq!(
            document["budgets"]["native_preadmission"],
            serde_json::json!({"limit": 1, "occupied": 1, "refused": 0, "pruned": 1})
        );
        assert!(!use_before_admission(&native.scene.coverage(caller)));
        // pid 11's entry stays and still downgrades its later admission.
        let later = native
            .scene
            .coordinator
            .adapter
            .admit(11, ImageAuthority::ScanPinned, 1_500)
            .unwrap();
        native.scene.project(11, 1_600);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(use_before_admission(&native.scene.coverage(later)));
    }

    #[test]
    fn a_reused_pid_drops_the_earlier_holders_entry() {
        let (mut native, _) = watched_native();
        stash_limit(&mut native, 1);
        native.scene.source.spawn(9, 90);
        let row = native.row(77, 1, 9, 1_000, 0);
        native.witness(vec![row]);
        // pid 9 now names another process, admitted with no row of its own.
        native.scene.source.kill(9);
        native.scene.source.spawn(9, 950);
        let reused = native
            .scene
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 1_500)
            .unwrap();
        native.scene.project(9, 1_600);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            !use_before_admission(&native.scene.coverage(reused)),
            "{:?}",
            native.scene.coverage(reused)
        );
        // A full stash prunes the stale entry instead of overflowing.
        native.scene.source.spawn(11, 110);
        let row = native.row(78, 1, 11, 1_700, 0);
        native.witness(vec![row]);
        assert_eq!(
            native.preadmission(),
            PreadmissionCounters {
                held: 1,
                limit: 1,
                pruned: 1,
                refused: 0,
            }
        );
        assert!(!use_before_admission(&native.scene.coverage(reused)));
    }

    #[test]
    fn an_entry_with_an_unreadable_start_is_held_while_its_pid_lives() {
        // Fail safe: with no start time to compare, only exit releases it.
        let (mut native, _) = watched_native();
        stash_limit(&mut native, 1);
        native.scene.source.spawn(9, 90);
        native.scene.source.blind(9);
        native.scene.source.spawn(11, 110);
        let row = native.row(77, 1, 9, 1_000, 0);
        native.witness(vec![row]);
        let row = native.row(78, 1, 11, 1_010, 0);
        native.witness(vec![row]);
        assert!(
            native
                .gap_subjects()
                .contains(&"native pre-admission rows past their bound".to_string())
        );
        assert_eq!(native.preadmission().pruned, 0);
    }

    /// A row whose endpoint resolves to no module still names its pid:
    /// every module of that pid's callers downgrades (the `None` entry).
    #[test]
    fn an_unresolved_row_downgrades_every_module_of_its_pid() {
        let (mut native, caller) = watched_native();
        let mut row = native.row(77, 1, 7, 1_000, 0);
        row.endpoint = EndpointId(9_999);
        native.witness(vec![row]);
        assert!(
            use_before_admission(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
    }

    #[test]
    fn an_unresolved_row_downgrades_a_later_admission_of_its_pid() {
        let (mut native, _) = watched_native();
        native.scene.source.spawn(9, 900);
        let mut row = native.row(77, 1, 9, 1_000, 0);
        row.endpoint = EndpointId(9_999);
        native.witness(vec![row]);
        let later = native
            .scene
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 1_500)
            .unwrap();
        native.scene.project(9, 1_600);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            use_before_admission(&native.scene.coverage(later)),
            "{:?}",
            native.scene.coverage(later)
        );
    }

    /// The overflow reaches retained retired callers too: a frozen
    /// `watched_no_use` is no more a fact than a live one.
    #[test]
    fn an_overflow_downgrades_a_retired_callers_frozen_watch() {
        let (mut native, caller) = watched_native();
        native.read(Vec::new());
        native.scene.source.kill(7);
        let events = native.scene.coordinator.adapter.reconcile(
            &BTreeSet::new(),
            &mut |_| ImageAuthority::ScanPinned,
            1_050,
        );
        assert_eq!(events.len(), 1, "{events:?}");
        native
            .scene
            .coordinator
            .registry
            .retire_caller(caller, "exited".into(), 1_050);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            native
                .scene
                .coordinator
                .adapter
                .record(caller)
                .unwrap()
                .retired,
            "the record is retained, retired"
        );
        assert!(
            watched(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
        stash_limit(&mut native, 1);
        native.scene.source.spawn(9, 90);
        native.scene.source.spawn(11, 110);
        let rows = vec![
            native.row(77, 1, 9, 1_100, 0),
            native.row(78, 1, 11, 1_100, 0),
        ];
        native.witness(rows);
        assert!(
            use_before_admission(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
    }

    #[test]
    fn a_bound_row_of_the_same_pid_keeps_the_caller_counted() {
        // Positives stay positives: the rule only replaces a watch.
        // C7 C4: the scripted row carries a count, so the positive is
        // `counted`.
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 200, 0);
        native.witness(vec![row]);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 200,
                lossy: false
            }
        );
        assert!(
            native
                .scene
                .coordinator
                .capture
                .as_ref()
                .unwrap()
                .preadmission
                .entries
                .is_empty()
        );
    }

    #[test]
    fn a_row_decided_after_stop_still_downgrades_a_frozen_watch() {
        let (mut native, caller) = watched_native();
        // A clean read at 1_010, then the stop freezes the watch there.
        native.read(Vec::new());
        native.scene.coordinator.end_capture_coverage(1_100);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(watched(&native.scene.coverage(caller)));
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 40, 0);
        native.witness(vec![row]);
        assert!(
            use_before_admission(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
    }

    /// R-C51-3: a row lifecycle loss left unbound downgrades the same way,
    /// sticky, but the edge reads unknown `loss` — never watched, and not
    /// `use_before_admission`.
    #[test]
    fn a_row_lifecycle_loss_left_unbound_reads_loss() {
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 200, 0);
        let mut batch = native.stamps.read(native.domain, vec![row]);
        let NativeBatch::Witness(read) = &mut batch else {
            unreachable!()
        };
        // The ring lost a record before this read: the binder dates a loss.
        read.health.discovery_counters = Some([1, 0, 0, 0, 0]);
        native.stage(batch);
        native.drain();
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        let census = native.scene.coordinator.registry.witness_census();
        assert_eq!(census.unbound.get(&UnboundReason::LifecycleLoss), Some(&1));
        assert!(
            lost_with(&native.scene.coverage(caller), "use row could bind"),
            "{:?}",
            native.scene.coverage(caller)
        );
        native.scene.project(7, 2_000);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(lost_with(
            &native.scene.coverage(caller),
            "use row could bind"
        ));
    }
}
