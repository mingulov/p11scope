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
    ImageGuard, InventoryCommit, InventoryDiscoveryConfig, InventoryOwnerLimits, RefreshCause,
    ScanReceipt,
};
use super::*;
use crate::capacity::InventoryBudget;
use crate::discovery::caller_registry::{
    AdmissionState, CallerAdapter, CallerEvent, CallerId, CallerRegistry, ImageAuthority,
    MappingState, ModuleInfo, ModuleKey, ProcessSource, RegistryGap, RegistryLimits,
};
use crate::discovery::scan::{
    InventoryDiscoveryLimits, InventoryRetainedLimits, InventoryWindowLimits, WindowId,
};
use p11scope_ebpf_common::ImageIdentity;
use std::path::PathBuf;

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
    pub scanned: usize,
    pub native_callers: usize,
    pub scan_callers: usize,
    pub engine_changed: bool,
    pub pending_refresh: Vec<CallerId>,
    pub events: Vec<CallerEvent>,
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

/// Per-pid authority resolution with a native open attempt: the open is
/// the check, so the native path is attempted honestly on every pass
/// and the scan lane is a recorded fallback, not a compile-time fork.
struct AuthorityResolver<'a> {
    engine: &'a mut Engine,
    pending: &'a mut BTreeMap<u32, ProcessViewId>,
    guard: &'a mut dyn ImageGuard,
    native_image: fn(u32) -> Option<ImageIdentity>,
    native_failures: Vec<(u32, String)>,
    scan_pinned: usize,
}

impl AuthorityResolver<'_> {
    fn resolve(&mut self, pid: u32) -> ImageAuthority {
        match (self.native_image)(pid).filter(|image| image.task_cookie != 0) {
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
/// the caller registry behind one batch boundary.
pub(crate) struct InventoryCoordinator<Source: ProcessSource> {
    engine: Engine,
    adapter: CallerAdapter<Source>,
    registry: CallerRegistry,
    owners: BTreeMap<CallerId, ProcessViewId>,
    pending_owners: BTreeMap<u32, ProcessViewId>,
    scanned_owners: BTreeSet<ProcessViewId>,
    churned_owners: BTreeSet<ProcessViewId>,
    next_window: u64,
    passes: u64,
    authority_gap_recorded: bool,
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
        InventoryBudget::new(4096, 4096 * 8).map_err(anyhow::Error::msg)?,
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
        Ok(Self {
            engine: Engine::inventory(default_inventory_config()?, scope, hooks, hints)?,
            adapter: CallerAdapter::new(source),
            registry: CallerRegistry::new(registry_limits),
            owners: BTreeMap::new(),
            pending_owners: BTreeMap::new(),
            scanned_owners: BTreeSet::new(),
            churned_owners: BTreeSet::new(),
            next_window: 0,
            passes: 0,
            authority_gap_recorded: false,
        })
    }

    pub(crate) fn adapter(&self) -> &CallerAdapter<Source> {
        &self.adapter
    }

    #[cfg(test)]
    pub(crate) fn adapter_mut(&mut self) -> &mut CallerAdapter<Source> {
        &mut self.adapter
    }

    pub(crate) fn registry(&self) -> &CallerRegistry {
        &self.registry
    }

    pub(crate) fn registry_mut(&mut self) -> &mut CallerRegistry {
        &mut self.registry
    }

    #[cfg(test)]
    pub(crate) fn owner_of(&self, caller: CallerId) -> Option<ProcessViewId> {
        self.owners.get(&caller).copied()
    }

    pub(crate) fn passes(&self) -> u64 {
        self.passes
    }

    /// One scan pass: collect the scope, reconcile caller incarnations
    /// (attempting a native owner per newly admitted pid), scan every
    /// native owner through the core, and project scan-lane mappings.
    /// Every staged fact publishes at the next `commit_batch`, never
    /// before. `native_image` supplies BPF image identity per pid, or
    /// `None` where no native identity exists (the scan lane). Hints and
    /// hooks are the engine's, fixed for the run.
    pub(crate) fn scan_pass(
        &mut self,
        scope: &InventoryScope,
        max_scan_pids: Option<usize>,
        guard: &mut dyn ImageGuard,
        native_image: fn(u32) -> Option<ImageIdentity>,
        deadline_ns: u64,
        now_ns: u64,
    ) -> Result<PassReport> {
        let catalog = match scope {
            InventoryScope::Pid(pid) => crate::inspect_system::collect_pid(
                *pid,
                &self.engine.module_hints,
                &self.engine.hooks,
            )?,
            InventoryScope::System => crate::inspect_system::collect(
                &self.engine.module_hints,
                &self.engine.hooks,
                max_scan_pids,
            )?,
        };
        let observed: BTreeSet<u32> = catalog
            .processes
            .iter()
            .filter(|process| process.status.inventoried())
            .map(|process| process.pid)
            .collect();
        let scanned = observed.len();
        let mut resolver = AuthorityResolver {
            engine: &mut self.engine,
            pending: &mut self.pending_owners,
            guard,
            native_image,
            native_failures: Vec::new(),
            scan_pinned: 0,
        };
        let events = self
            .adapter
            .reconcile(&observed, &mut |pid| resolver.resolve(pid), now_ns);
        let (native_failures, scan_pinned) = resolver.finish();
        self.apply_reconcile_events(&events, now_ns);
        self.record_authority_gaps(native_failures, scan_pinned);
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
                    self.project_native_commit(*caller, *owner, &commit, now_ns);
                }
                Err(error) => {
                    self.registry.record_gap(RegistryGap {
                        caller: Some(*caller),
                        module: None,
                        pid: self.adapter.record(*caller).map(|record| record.pid),
                        subject: "native inventory scan failed".into(),
                        reason: format!("{error:#}"),
                    });
                }
            }
        }
        // Scan-lane projection for every inventoried member, including
        // native callers (the catalog carries admission verdicts the
        // registry needs either way).
        self.project_catalog(&catalog, now_ns);
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
                    });
                }
                Err(error) => {
                    self.registry.record_gap(RegistryGap {
                        caller: Some(*caller),
                        module: None,
                        pid: self.adapter.record(*caller).map(|record| record.pid),
                        subject: "native owner lost".into(),
                        reason: format!("{error:#}"),
                    });
                }
            }
        }
        let native_callers = native.len();
        let pass = self.passes;
        self.passes += 1;
        Ok(PassReport {
            pass,
            scanned,
            native_callers,
            scan_callers: observed.len().saturating_sub(native_callers),
            engine_changed,
            pending_refresh,
            events,
        })
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
        native_image: fn(u32) -> Option<ImageIdentity>,
        reason: &str,
        now_ns: u64,
    ) -> PassReport {
        let mut resolver = AuthorityResolver {
            engine: &mut self.engine,
            pending: &mut self.pending_owners,
            guard,
            native_image,
            native_failures: Vec::new(),
            scan_pinned: 0,
        };
        let events =
            self.adapter
                .reconcile(&BTreeSet::new(), &mut |pid| resolver.resolve(pid), now_ns);
        let (native_failures, scan_pinned) = resolver.finish();
        self.apply_reconcile_events(&events, now_ns);
        self.record_authority_gaps(native_failures, scan_pinned);
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
            native_callers,
            scan_callers: live.len().saturating_sub(native_callers),
            engine_changed: false,
            pending_refresh: Vec::new(),
            events,
        }
    }

    /// Stage retirements for reconciled events, bind freshly opened
    /// native owners to their callers, and gap admission failures.
    fn apply_reconcile_events(&mut self, events: &[CallerEvent], now_ns: u64) {
        for event in events {
            let id = match event {
                CallerEvent::Admitted { id }
                | CallerEvent::ExecRetired { new: id, .. }
                | CallerEvent::Reused { new: id, .. } => *id,
                CallerEvent::Exited { id, .. } => {
                    self.retire_caller_in_registry(*id, now_ns);
                    continue;
                }
                CallerEvent::AdmitFailed { pid, reason } => {
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
                        });
                    }
                    self.registry.record_gap(RegistryGap {
                        caller: None,
                        module: None,
                        pid: Some(*pid),
                        subject: "caller admission failed".into(),
                        reason: reason.clone(),
                    });
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
        now_ns: u64,
    ) {
        let pid = self
            .adapter
            .record(caller)
            .map(|record| record.pid)
            .unwrap_or(0);
        let modules: Vec<(ModuleKey, ModuleInfo)> = self
            .engine
            .modules
            .iter()
            .filter(|module| module.scanned.view == owner)
            .filter_map(|module| {
                let summary = self.engine.pinned.summary(module.object)?;
                let sha256 = summary.sha256.to_string();
                let key = ModuleKey::physical(
                    module.scanned.key.device.major,
                    module.scanned.key.device.minor,
                    module.scanned.key.inode,
                    Some(sha256),
                    &module.scanned.path,
                );
                Some((key.clone(), native_module_info(&self.engine, module, key)))
            })
            .collect();
        for (_, info) in &modules {
            self.registry
                .note_mapping(caller, pid, info.clone(), now_ns);
        }
        // Absences are evaluated against the last published snapshot:
        // edges the commit no longer shows, for this caller only.
        let committed: BTreeSet<ModuleKey> = modules.iter().map(|(key, _)| key.clone()).collect();
        let mut absent = false;
        for edge in self
            .registry
            .edges()
            .filter(|edge| {
                edge.caller == caller
                    && matches!(edge.mapping, MappingState::Mapped | MappingState::Uncertain)
            })
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

    /// Project one catalog pass into the registry: per-member mappings,
    /// per-member absences (authoritative only for complete member
    /// scans), unscanned-member uncertainty, and catalog gaps.
    fn project_catalog(&mut self, catalog: &crate::inspect_system::Catalog, now_ns: u64) {
        for object in &catalog.objects {
            // One mapping note per observation (not per object path):
            // aliased objects are observed under several paths and the
            // registry accumulates every spelling.
            for observation in &object.observations {
                let Some(caller) = self.adapter.live_id(observation.pid) else {
                    continue;
                };
                let mut info = catalog_module_info(object);
                info.path = observation.path.clone();
                self.registry
                    .note_mapping(caller, observation.pid, info, now_ns);
            }
        }
        for process in &catalog.processes {
            let Some(caller) = self.adapter.live_id(process.pid) else {
                continue;
            };
            if !process.status.inventoried() {
                self.registry.note_member_unscanned(caller);
                continue;
            }
            let complete = matches!(process.status, crate::inspect_system::MemberStatus::Scanned);
            let shown: BTreeSet<ModuleKey> = process
                .objects
                .iter()
                .filter_map(|index| catalog.objects.get(*index))
                .map(catalog_module_key)
                .collect();
            let mut absent = false;
            for (module, mapping) in self
                .registry
                .edges()
                .filter(|edge| {
                    edge.caller == caller
                        && matches!(edge.mapping, MappingState::Mapped | MappingState::Uncertain)
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
        for gap in catalog.skipped.iter().chain(catalog.notes.iter()) {
            self.registry.record_gap(RegistryGap {
                caller: gap.pid.and_then(|pid| self.adapter.live_id(pid)),
                module: None,
                pid: gap.pid,
                subject: gap.subject.clone(),
                reason: gap.reason.clone(),
            });
        }
    }

    /// The I4b batch: the engine tail and the registry publish as one
    /// synchronous step. Facts from every scan since the last commit are
    /// invisible before this returns and visible after — the ordering
    /// the Phase 2 test pins, extended to caller/edge facts.
    pub(crate) fn commit_batch(&mut self, engine_changed: bool) -> Result<BatchReceipt> {
        self.engine.publish_batch_tail(engine_changed)?;
        let registry_applied = self.registry.publish();
        Ok(BatchReceipt {
            engine_facts: self.engine.facts_revision,
            engine_published: self.engine.published_facts_revision,
            registry_facts: self.registry.facts_revision(),
            registry_published: self.registry.published_revision(),
            registry_applied,
        })
    }
}

/// Admission verdict for one natively committed module, from the
/// committed plan: the same refused/admitted split the catalog reports.
/// Inventory never consults manifests, so the verdict carries the
/// scan-only note like the catalog's.
fn native_module_info(engine: &Engine, module: &ReconciledModule, key: ModuleKey) -> ModuleInfo {
    let refused: BTreeMap<PinnedObjectId, &Skipped> = engine.plan.refused_modules().collect();
    let (admission, class, endpoints, reasons) = match refused.get(&module.object) {
        Some(skip) => (
            AdmissionState::Refused,
            Some("refused".to_string()),
            None,
            vec![skip.reason.clone()],
        ),
        None => {
            let endpoints = engine
                .plan
                .modules
                .iter()
                .find(|summary| summary.object == module.object)
                .map(|summary| {
                    engine
                        .plan
                        .slots
                        .iter()
                        .filter(|slot| {
                            engine.plan.is_active(slot.index)
                                && slot.module_ids.contains(&summary.id)
                        })
                        .count()
                });
            match endpoints {
                Some(count) => (
                    AdmissionState::Admitted,
                    Some("exact".to_string()),
                    Some(count),
                    Vec::new(),
                ),
                None => (
                    AdmissionState::Unresolved,
                    None,
                    None,
                    vec!["object reached no admission verdict".to_string()],
                ),
            }
        }
    };
    let summary = engine.pinned.summary(module.object);
    ModuleInfo {
        path: module.scanned.path.clone(),
        key,
        build_id: summary.and_then(|summary| summary.build_id.map(str::to_string)),
        identity_source: summary.map(|summary| summary.identity_source.to_string()),
        admission,
        admission_class: class,
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

fn catalog_module_info(object: &crate::inspect_system::CatalogObject) -> ModuleInfo {
    let (admission, endpoints) = match object.admission.state() {
        "admitted" => (AdmissionState::Admitted, object.admission.endpoints()),
        "refused" => (AdmissionState::Refused, None),
        _ => (AdmissionState::Unresolved, None),
    };
    ModuleInfo {
        path: object.path.clone(),
        key: catalog_module_key(object),
        build_id: object.build_id.clone(),
        identity_source: object.identity_source.map(str::to_string),
        admission,
        admission_class: object.admission.class().map(str::to_string),
        admission_endpoints: endpoints,
        admission_reasons: object.admission.reasons(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::inventory::{ImageCheck, UnavailableImageGuard};
    use super::*;
    use crate::discovery::caller_registry::OsProcessSource;
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

    #[test]
    fn native_pass_over_self_commits_and_publishes_through_one_batch() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(pid),
                None,
                &mut FixtureImages,
                fixture_image,
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
    fn unavailable_guard_falls_back_to_scan_lane_with_an_authority_gap() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(pid),
                None,
                &mut UnavailableImageGuard,
                |_| None,
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
                fixture_image,
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
        let report =
            coordinator.observe_empty_pass(&mut UnavailableImageGuard, |_| None, "boom", now + 1);
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
        let mut coordinator = coordinator();
        let key = ModuleKey::physical(8, 1, 11, Some("sha0011".into()), "/lib/a.so");
        coordinator.registry_mut().note_mapping(
            CallerId(0),
            50,
            ModuleInfo {
                path: "/lib/a.so".into(),
                key: key.clone(),
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
}
